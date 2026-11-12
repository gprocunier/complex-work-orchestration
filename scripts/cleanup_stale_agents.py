#!/usr/bin/env python3
"""Detect stale local agent sessions and prune stale records from the registry.

No process is signalled. Unless run with ``--dry-run`` or
``--no-prune-state``, cleanup rewrites the session registry and drops records
whose PID is missing, invalid or no longer running.

Recognition is not ownership. The session registry (``sessions.jsonl``) is an
unauthenticated file that any same-user process can write, and argv matching
recognizes any process with an agent name among its arguments. Neither one
identifies a process this harness started, so neither one authorizes a signal.

Termination needs a trusted ownership record written by a controller outside
the lead's control, plus an identity-bound signal handle that cannot target a
reused PID (``cwo_core.process_identity``). No such producer exists yet, so
termination requests are reported as unavailable and no process is signalled.

Detection does not terminate anything, but a non-dry-run invocation still
rewrites the registry to prune records whose processes have exited. Use
``--dry-run`` or ``--no-prune-state`` to leave it untouched.
"""
from __future__ import annotations

import argparse
import json
import math
import os
import shlex
import subprocess
import sys
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cwo_core.process_identity import NoTrustedOwnershipSource, OwnershipSource, PidfdTerminator
from cwo_core.util import atomic_write_text

DEFAULT_WORKSPACE_ROOT = Path.cwd()
DEFAULT_STATE_DIR = DEFAULT_WORKSPACE_ROOT / ".orchestration-agents"
SESSION_FILE = "sessions.jsonl"
DEFAULT_STALE_AFTER_MINUTES = 60
AGENT_COMMAND_NAMES = {"agy", "claude", "claude-code", "codex"}
AGENT_PACKAGE_SEGMENTS = (("@openai", "codex"),)


@dataclass(frozen=True)
class ProcessInfo:
    pid: int
    ppid: int
    elapsed_seconds: int
    stat: str
    command: str
    args: str
    cwd: str | None = None

    @property
    def command_line(self) -> str:
        return self.args.strip() or self.command


def parse_process_line(line: str) -> ProcessInfo | None:
    parts = line.strip().split(None, 5)
    if len(parts) < 5:
        return None
    pid, ppid, elapsed, stat, command = parts[:5]
    args = parts[5] if len(parts) == 6 else ""
    try:
        return ProcessInfo(
            pid=int(pid),
            ppid=int(ppid),
            elapsed_seconds=int(elapsed),
            stat=stat,
            command=command,
            args=args,
        )
    except ValueError:
        return None


def read_proc_ppid(pid: int, proc_root: Path = Path("/proc")) -> int | None:
    stat_path = proc_root / str(pid) / "stat"
    try:
        stat = stat_path.read_text(encoding="utf-8")
    except OSError:
        return None
    try:
        return int(stat.rsplit(") ", 1)[1].split()[1])
    except (IndexError, ValueError):
        return None


def ancestor_pids(pid: int | None = None, proc_root: Path = Path("/proc")) -> set[int]:
    current = int(pid or os.getpid())
    ancestors: set[int] = set()
    while current > 0 and current not in ancestors:
        ancestors.add(current)
        parent = read_proc_ppid(current, proc_root)
        if parent is None or parent == current:
            break
        current = parent
    return ancestors


def process_cwd(pid: int) -> str | None:
    try:
        return os.readlink(f"/proc/{pid}/cwd")
    except OSError:
        return None


def discover_processes() -> list[ProcessInfo]:
    output = subprocess.check_output(
        ["ps", "-u", str(os.getuid()), "-o", "pid=,ppid=,etimes=,stat=,comm=,args="],
        text=True,
    )
    processes: list[ProcessInfo] = []
    for line in output.splitlines():
        process = parse_process_line(line)
        if process is None:
            continue
        processes.append(
            ProcessInfo(
                pid=process.pid,
                ppid=process.ppid,
                elapsed_seconds=process.elapsed_seconds,
                stat=process.stat,
                command=process.command,
                args=process.args,
                cwd=process_cwd(process.pid),
            )
        )
    return processes


def process_command_tokens(process: ProcessInfo) -> list[str]:
    tokens: list[str] = []
    if process.command:
        tokens.append(process.command)
    try:
        tokens.extend(shlex.split(process.command_line))
    except ValueError:
        tokens.extend(process.command_line.split())
    return tokens


def token_contains_package(token: str, package_segments: tuple[str, str]) -> bool:
    parts = [part for part in token.replace("\\", "/").lower().split("/") if part]
    owner, package = package_segments
    for index, part in enumerate(parts[:-1]):
        next_part = parts[index + 1]
        if part == owner and (next_part == package or next_part.startswith(f"{package}@")):
            return True
    return False


def agent_process_match(process: ProcessInfo) -> str | None:
    for token in process_command_tokens(process):
        lowered = token.lower()
        for package_segments in AGENT_PACKAGE_SEGMENTS:
            if token_contains_package(lowered, package_segments):
                return f"package:{'/'.join(package_segments)}"
        basename = Path(lowered).name
        if basename in AGENT_COMMAND_NAMES:
            return f"command:{basename}"
    return None


def is_agent_process(process: ProcessInfo) -> bool:
    return agent_process_match(process) is not None


def is_within_workspace(process: ProcessInfo, workspace_root: Path) -> bool:
    if not process.cwd:
        return False
    try:
        Path(process.cwd).resolve().relative_to(workspace_root.resolve())
        return True
    except (ValueError, OSError, RuntimeError):
        # RuntimeError: Python 3.12 reports a symlink loop this way.
        return False


def is_stale(process: ProcessInfo, stale_after_seconds: int) -> bool:
    return process.elapsed_seconds >= stale_after_seconds


def process_by_pid(processes: list[ProcessInfo]) -> dict[int, ProcessInfo]:
    return {process.pid: process for process in processes}


MAX_RECORD_DEPTH = 32


def _finite_float(text: str) -> float:
    value = float(text)
    if not math.isfinite(value):
        raise ValueError("non-finite number")
    return value


def _reject_constant(name: str) -> Any:
    raise ValueError(f"non-finite constant {name}")


def _shallow(value: Any, limit: int) -> bool:
    stack = [(value, 1)]
    while stack:
        item, depth = stack.pop()
        if depth > limit:
            return False
        if isinstance(item, dict):
            stack.extend((child, depth + 1) for child in item.values())
        elif isinstance(item, list):
            stack.extend((child, depth + 1) for child in item)
    return True


def load_record_lines(state_dir: Path) -> list[tuple[int, dict[str, Any]]]:
    """Registry records with their line numbers.

    A line that is not a strict JSON object (including non-finite numbers and
    non-object values) or nests deeper than MAX_RECORD_DEPTH is kept as an
    invalid record, so reports built from records always serialize as strict
    JSON.
    """
    path = state_dir / SESSION_FILE
    if not path.exists():
        return []
    records: list[tuple[int, dict[str, Any]]] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            record = json.loads(line, parse_float=_finite_float, parse_constant=_reject_constant)
        except (ValueError, RecursionError):
            records.append((line_number, {"invalid": True, "line_number": line_number, "raw": line}))
            continue
        if isinstance(record, dict) and _shallow(record, MAX_RECORD_DEPTH):
            records.append((line_number, record))
        else:
            records.append((line_number, {"invalid": True, "line_number": line_number, "raw": line}))
    return records


def load_records(state_dir: Path) -> list[dict[str, Any]]:
    return [record for _, record in load_record_lines(state_dir)]


def write_records(state_dir: Path, records: list[dict[str, Any]]) -> None:
    path = state_dir / SESSION_FILE
    if not records:
        try:
            path.unlink()
        except FileNotFoundError:
            pass
        return
    state_dir.mkdir(parents=True, exist_ok=True)
    payload = "\n".join(json.dumps(record, sort_keys=True) for record in records) + "\n"
    atomic_write_text(path, payload)


TERMINATION_UNAVAILABLE = "termination-unavailable"
# The registry has no trusted producer: any same-user process can write it.
OWNED_UNAVAILABLE_REASON = "no-trusted-ownership-producer"
# Argv recognition and a broad flag do not identify one exact authorized target.
UNOWNED_UNAVAILABLE_REASON = "no-exact-target-authority"
TERMINATION_UNAVAILABLE_EXIT = 3


# Outcomes that prove the target process is gone, so its record can be pruned.
TERMINATION_SUCCESS = ("terminated", "killed", "already-exited", "exited-before-signal", "exited-during-observation")
TERMINATION_REFUSED_EXIT = 4
STATE_WRITE_FAILED_EXIT = 5
# Linux PID_MAX_LIMIT; a registry PID outside 1..this is invalid.
PID_MAX_LIMIT = 4194304


def record_pid(value: Any) -> int | None:
    """A registry PID: a positive int or ASCII decimal string within PID_MAX_LIMIT."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        pid = value
    elif isinstance(value, str) and value.isascii() and value.isdigit() and len(value) <= len(str(PID_MAX_LIMIT)):
        pid = int(value)
    else:
        return None
    return pid if 0 < pid <= PID_MAX_LIMIT else None


def termination_status(
    owned: bool,
    unowned: bool,
    *,
    owned_reason: str | None = OWNED_UNAVAILABLE_REASON,
    dry_run: bool = False,
    attempts: int = 0,
    refusals: int = 0,
    outcomes: dict[str, int] | None = None,
    signals_sent: int = 0,
    runtime_unavailable: str | None = None,
) -> dict[str, Any]:
    """Describe a termination request from authority, capability and actual outcomes.

    Each requested scope gets its own status: unavailable (no authority, or no
    working mechanism before any call), dry-run, attempted (at least one
    terminator call or refusal) or no-eligible-target. Unowned termination is
    never available: recognition is not a target authority. The overall
    ``status`` is not-requested, unavailable (every requested scope is),
    partially-unavailable (some are) or the owned scope's status.

    ``refusals`` counts targets refused before any terminator call (no trusted
    registration, session mismatch). ``outcomes`` counts terminator results,
    including the terminator's own refusals such as identity-mismatch.
    ``runtime_unavailable`` records a mechanism failure reported by a call
    after the capability probe had passed; the owned scope is then attempted
    but not available.
    """
    requested = {"owned": owned, "unowned": unowned}
    scopes: dict[str, dict[str, Any]] = {}
    if owned:
        if owned_reason:
            scopes["owned"] = {"status": "unavailable", "reason": owned_reason}
        elif dry_run:
            scopes["owned"] = {"status": "dry-run", "reason": None}
        elif attempts or refusals:
            scopes["owned"] = {"status": "attempted", "reason": None}
        else:
            scopes["owned"] = {"status": "no-eligible-target", "reason": None}
        if runtime_unavailable and not owned_reason:
            scopes["owned"]["reason"] = f"mechanism-unavailable-at-runtime: {runtime_unavailable}"
    if unowned:
        scopes["unowned"] = {"status": "unavailable", "reason": UNOWNED_UNAVAILABLE_REASON}
    unavailable = [scope for scope, value in scopes.items() if value["status"] == "unavailable"]
    if not scopes:
        status = "not-requested"
    elif len(unavailable) == len(scopes):
        status = "unavailable"
    elif unavailable:
        status = "partially-unavailable"
    else:
        status = scopes["owned"]["status"]
    reasons = {scope: value["reason"] for scope, value in scopes.items() if value["reason"]}
    return {
        "requested": requested,
        "status": status,
        "scopes": scopes,
        "available": bool(owned and "owned" not in reasons),
        "reasons": reasons,
        "attempts": attempts,
        "refusals": refusals,
        "outcomes": dict(sorted((outcomes or {}).items())),
        "signals_sent": signals_sent,
    }


def termination_unavailable(scope: str, process: ProcessInfo, **extra: Any) -> dict[str, Any]:
    reason = OWNED_UNAVAILABLE_REASON if scope == "owned" else UNOWNED_UNAVAILABLE_REASON
    action = {
        "action": TERMINATION_UNAVAILABLE,
        "scope": scope,
        "reason": reason,
        "pid": process.pid,
        "command": process.command_line,
    }
    action.update(extra)
    return action


def cleanup(
    *,
    processes: list[ProcessInfo],
    state_dir: Path,
    workspace_root: Path,
    stale_after_seconds: int,
    protected_pids: set[int],
    terminate_owned: bool,
    terminate_unowned_codex: bool,
    prune_state: bool,
    dry_run: bool,
    grace_seconds: float,
    ownership_source: OwnershipSource | None = None,
    terminator: PidfdTerminator | None = None,
) -> dict[str, Any]:
    """Report stale sessions; ``terminate_*`` are requests, never authority.

    Owned termination runs only for a stale process whose trusted registration
    comes from ``ownership_source``. The default source has no trusted producer,
    so every request is reported as unavailable and nothing is signalled.
    """
    source = ownership_source or NoTrustedOwnershipSource()
    registrations = source.trusted_registrations() if terminate_owned else None
    trusted_by_pid = {registration.pid: registration for registration in registrations or []}
    effective_terminator = terminator or PidfdTerminator()
    owned_reason: str | None = None
    if terminate_owned:
        if registrations is None:
            owned_reason = OWNED_UNAVAILABLE_REASON
        else:
            supported, support_reason = effective_terminator.supported()
            if not supported:
                owned_reason = f"mechanism-unsupported: {support_reason}"
    owned_available = terminate_owned and owned_reason is None
    signals_sent = 0
    attempts = 0
    refusals = 0
    outcomes: dict[str, int] = {}
    runtime_unavailable: str | None = None
    decided: dict[int, dict[str, Any]] = {}
    numbered = load_record_lines(state_dir)
    records = [record for _, record in numbered]
    live = process_by_pid(processes)
    actions: list[dict[str, Any]] = []
    kept_records: list[dict[str, Any]] = []
    owned_pids: set[int] = set()

    for line_number, record in numbered:
        if record.get("invalid"):
            actions.append({"action": "keep-invalid-record", "line_number": record.get("line_number")})
            kept_records.append(record)
            continue
        pid = record.get("pid")
        pid_int = record_pid(pid)
        if pid_int is None:
            reason = "missing-pid" if pid is None else "invalid-pid"
            actions.append({"action": "prune-record", "reason": reason, "line_number": line_number})
            continue
        owned_pids.add(pid_int)
        process = live.get(pid_int)
        if process is None:
            actions.append({"action": "prune-record", "reason": "dead-process", "pid": pid_int})
            continue
        if pid_int in protected_pids:
            actions.append({"action": "protect", "reason": "current-process-tree", "pid": pid_int})
            kept_records.append(record)
            continue
        if not is_stale(process, stale_after_seconds):
            kept_records.append(record)
            continue
        if owned_available:
            if pid_int in decided:
                # One decision per process per run: a duplicate record never
                # reopens the PID or signals again.
                first = decided[pid_int]
                actions.append({"action": "termination-duplicate-record", "scope": "owned", "pid": pid_int,
                                "same_as": first["action"]})
                if first["keep"]:
                    kept_records.append(record)
                continue
            registration = trusted_by_pid.get(pid_int)
            if registration is None:
                action = {**termination_unavailable("owned", process), "reason": "not-in-trusted-registry"}
            elif record.get("session_id") != registration.session_id:
                action = {**termination_unavailable("owned", process), "reason": "session-mismatch"}
            elif dry_run:
                action = {"action": "termination-dry-run", "scope": "owned", "pid": pid_int, "command": process.command_line}
            else:
                # Age is re-derived from the verified incarnation, not from the
                # discovery snapshot, so a reused PID cannot inherit an old age.
                outcome = effective_terminator.terminate(
                    registration, grace_seconds=grace_seconds, min_age_seconds=stale_after_seconds
                )
                attempts += 1
                outcomes[outcome["outcome"]] = outcomes.get(outcome["outcome"], 0) + 1
                signals_sent += len(outcome.get("signals", []))
                action = {"action": "termination-" + outcome["outcome"], "scope": "owned", "pid": pid_int,
                          "command": process.command_line, "detail": outcome}
                if outcome["outcome"] == "unavailable":
                    runtime_unavailable = runtime_unavailable or str(outcome.get("reason"))
                if "reason" in outcome or "reasons" in outcome:
                    action["reason"] = outcome.get("reason") or ", ".join(outcome.get("reasons", []))
            if action["action"] == TERMINATION_UNAVAILABLE and "detail" not in action:
                refusals += 1
            keep = action["action"] not in {f"termination-{name}" for name in TERMINATION_SUCCESS}
            decided[pid_int] = {"action": action["action"], "keep": keep}
            actions.append(action)
            if keep:
                kept_records.append(record)
            continue
        if terminate_owned:
            actions.append({**termination_unavailable("owned", process), "reason": owned_reason})
        else:
            actions.append({"action": "stale-owned-detected", "pid": pid_int, "command": process.command_line})
        kept_records.append(record)

    for process in processes:
        if process.pid in owned_pids or process.pid in protected_pids:
            continue
        agent_match = agent_process_match(process)
        if not agent_match:
            continue
        if not is_within_workspace(process, workspace_root):
            continue
        if not is_stale(process, stale_after_seconds):
            continue
        if terminate_unowned_codex:
            actions.append(termination_unavailable("unowned", process, agent_match=agent_match))
        else:
            actions.append(
                {
                    "action": "stale-unowned-detected",
                    "pid": process.pid,
                    "command": process.command_line,
                    "agent_match": agent_match,
                }
            )

    persistence: dict[str, Any] = {"status": "skipped"}
    if prune_state and not dry_run:
        # Report a failed rewrite instead of raising: signals may already have
        # been sent, and their outcome must not be lost.
        try:
            write_records(state_dir, kept_records)
            persistence = {"status": "written"}
        except OSError as exc:
            persistence = {"status": "failed", "error": f"{type(exc).__name__}: {exc.strerror or exc}"}

    return {
        "cleanup_result_type": "complex-work-orchestration-stale-agent-cleanup",
        "version": 2,
        "state_dir": str(state_dir),
        "workspace_root": str(workspace_root),
        "stale_after_seconds": stale_after_seconds,
        "termination": termination_status(
            terminate_owned,
            terminate_unowned_codex,
            owned_reason=owned_reason,
            dry_run=dry_run,
            attempts=attempts,
            refusals=refusals,
            outcomes=outcomes,
            signals_sent=signals_sent,
            runtime_unavailable=runtime_unavailable,
        ),
        "dry_run": dry_run,
        "state_persistence": persistence,
        "actions": actions,
        "summary": {
            "actions": len(actions),
            "records_before": len(records),
            "records_after": len(kept_records),
        },
    }


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Detect stale complex-work-orchestration agent sessions and prune registry records with no live PID. No process is signalled."
    )
    parser.add_argument("--state-dir", default=str(DEFAULT_STATE_DIR), help="Agent session registry directory (unauthenticated).")
    parser.add_argument("--workspace-root", default=str(DEFAULT_WORKSPACE_ROOT), help="Workspace root for unowned process matching.")
    parser.add_argument("--stale-after-minutes", type=int, default=DEFAULT_STALE_AFTER_MINUTES)
    parser.add_argument("--dry-run", action="store_true", help="Report actions without rewriting state.")
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON.")
    parser.add_argument(
        "--terminate-owned",
        action="store_true",
        help=f"Request termination of stale registry processes. Reported as unavailable ({OWNED_UNAVAILABLE_REASON}).",
    )
    parser.add_argument(
        "--no-terminate-owned",
        action="store_true",
        help="Compatibility alias. Detection is already the default.",
    )
    parser.add_argument(
        "--terminate-unowned-codex",
        action="store_true",
        help=f"Request termination of recognized unowned agent processes. Reported as unavailable ({UNOWNED_UNAVAILABLE_REASON}).",
    )
    parser.add_argument("--no-prune-state", action="store_true", help="Do not rewrite the session state file.")
    parser.add_argument("--grace-seconds", type=float, default=1.0, help="Accepted for compatibility; unused.")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    state_dir = Path(args.state_dir)
    workspace_root = Path(args.workspace_root)
    result = cleanup(
        processes=discover_processes(),
        state_dir=state_dir,
        workspace_root=workspace_root,
        stale_after_seconds=max(0, args.stale_after_minutes) * 60,
        protected_pids=ancestor_pids(),
        terminate_owned=bool(args.terminate_owned) and not args.no_terminate_owned,
        terminate_unowned_codex=bool(args.terminate_unowned_codex),
        prune_state=not args.no_prune_state,
        dry_run=bool(args.dry_run),
        grace_seconds=max(0.0, float(args.grace_seconds)),
    )
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        summary = result["summary"]
        print(
            "stale agent cleanup: "
            f"{summary['actions']} actions, "
            f"{summary['records_before']} records before, "
            f"{summary['records_after']} records after"
        )
        for action in result["actions"]:
            pid = action.get("pid", "-")
            reason = f" ({action['reason']})" if action.get("reason") else ""
            print(f"- {action.get('action')}{reason}: pid={pid} {action.get('command', '')}".rstrip())
    termination = result["termination"]
    signalled = termination["signals_sent"]
    effect = "no process was signalled" if not signalled else f"{signalled} signal(s) sent"
    if result["state_persistence"]["status"] == "failed":
        if not args.json:
            print(f"session registry was not rewritten ({result['state_persistence']['error']}); {effect}")
        return STATE_WRITE_FAILED_EXIT
    if termination["status"] in {"unavailable", "partially-unavailable"}:
        if not args.json:
            unavailable = ", ".join(
                f"{scope}: {value['reason']}"
                for scope, value in termination["scopes"].items()
                if value["status"] == "unavailable"
            )
            print(f"termination requested but unavailable ({unavailable}); {effect}")
        return TERMINATION_UNAVAILABLE_EXIT
    if termination["status"] == "attempted" and (
        termination["refusals"] or any(name not in TERMINATION_SUCCESS for name in termination["outcomes"])
    ):
        if not args.json:
            print(f"termination attempted with refusals or unfinished targets; {effect}")
        return TERMINATION_REFUSED_EXIT
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
