#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import signal
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cwo_core.util import atomic_write_text

DEFAULT_WORKSPACE_ROOT = Path.cwd()
DEFAULT_STATE_DIR = DEFAULT_WORKSPACE_ROOT / ".orchestration-agents"
SESSION_FILE = "sessions.jsonl"
DEFAULT_STALE_AFTER_MINUTES = 60
AGENT_COMMAND_MARKERS = [
    "/codex",
    " codex ",
    "@openai/codex",
    "claude -p",
    "claude-code",
    " agy ",
    "agy -p",
]


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


def is_agent_process(process: ProcessInfo) -> bool:
    haystack = f" {process.command_line.lower()} "
    return any(marker in haystack for marker in AGENT_COMMAND_MARKERS)


def is_within_workspace(process: ProcessInfo, workspace_root: Path) -> bool:
    if not process.cwd:
        return False
    try:
        Path(process.cwd).resolve().relative_to(workspace_root.resolve())
        return True
    except ValueError:
        return False
    except OSError:
        return False


def is_stale(process: ProcessInfo, stale_after_seconds: int) -> bool:
    return process.elapsed_seconds >= stale_after_seconds


def process_by_pid(processes: list[ProcessInfo]) -> dict[int, ProcessInfo]:
    return {process.pid: process for process in processes}


def load_records(state_dir: Path) -> list[dict[str, Any]]:
    path = state_dir / SESSION_FILE
    if not path.exists():
        return []
    records: list[dict[str, Any]] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            records.append({"invalid": True, "line_number": line_number, "raw": line})
            continue
        if isinstance(record, dict):
            records.append(record)
    return records


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


def terminate_process(pid: int, *, dry_run: bool, grace_seconds: float) -> str:
    if dry_run:
        return "would-terminate"
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        return "already-exited"
    time.sleep(grace_seconds)
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return "terminated"
    try:
        os.kill(pid, signal.SIGKILL)
    except ProcessLookupError:
        return "terminated"
    return "killed"


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
) -> dict[str, Any]:
    records = load_records(state_dir)
    live = process_by_pid(processes)
    actions: list[dict[str, Any]] = []
    kept_records: list[dict[str, Any]] = []
    owned_pids: set[int] = set()

    for record in records:
        if record.get("invalid"):
            actions.append({"action": "keep-invalid-record", "line_number": record.get("line_number")})
            kept_records.append(record)
            continue
        pid = record.get("pid")
        try:
            pid_int = int(pid)
        except (TypeError, ValueError):
            actions.append({"action": "prune-record", "reason": "missing-pid", "record": record})
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
        if terminate_owned:
            result = terminate_process(pid_int, dry_run=dry_run, grace_seconds=grace_seconds)
            actions.append({"action": result, "scope": "owned", "pid": pid_int, "command": process.command_line})
            continue
        actions.append({"action": "stale-owned-detected", "pid": pid_int, "command": process.command_line})
        kept_records.append(record)

    for process in processes:
        if process.pid in owned_pids or process.pid in protected_pids:
            continue
        if not is_agent_process(process):
            continue
        if not is_within_workspace(process, workspace_root):
            continue
        if not is_stale(process, stale_after_seconds):
            continue
        if terminate_unowned_codex:
            result = terminate_process(process.pid, dry_run=dry_run, grace_seconds=grace_seconds)
            actions.append({"action": result, "scope": "unowned", "pid": process.pid, "command": process.command_line})
        else:
            actions.append({"action": "stale-unowned-detected", "pid": process.pid, "command": process.command_line})

    if prune_state and not dry_run:
        write_records(state_dir, kept_records)

    return {
        "cleanup_result_type": "complex-work-orchestration-stale-agent-cleanup",
        "version": 1,
        "state_dir": str(state_dir),
        "workspace_root": str(workspace_root),
        "stale_after_seconds": stale_after_seconds,
        "terminated_unowned_enabled": terminate_unowned_codex,
        "dry_run": dry_run,
        "actions": actions,
        "summary": {
            "actions": len(actions),
            "records_before": len(records),
            "records_after": len(kept_records),
        },
    }


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Clean stale complex-work-orchestration agent sessions.")
    parser.add_argument("--state-dir", default=str(DEFAULT_STATE_DIR), help="Harness-owned agent state directory.")
    parser.add_argument("--workspace-root", default=str(DEFAULT_WORKSPACE_ROOT), help="Workspace root for unowned process matching.")
    parser.add_argument("--stale-after-minutes", type=int, default=DEFAULT_STALE_AFTER_MINUTES)
    parser.add_argument("--dry-run", action="store_true", help="Report actions without terminating processes or rewriting state.")
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON.")
    parser.add_argument("--no-terminate-owned", action="store_true", help="Do not terminate stale harness-owned live processes.")
    parser.add_argument(
        "--terminate-unowned-codex",
        action="store_true",
        help="Also terminate stale unowned Codex/Claude/Agy processes in the workspace. Requires explicit operator intent.",
    )
    parser.add_argument("--no-prune-state", action="store_true", help="Do not rewrite the session state file.")
    parser.add_argument("--grace-seconds", type=float, default=1.0, help="SIGTERM grace period before SIGKILL.")
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
        terminate_owned=not args.no_terminate_owned,
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
            print(f"- {action.get('action')}: pid={pid} {action.get('command', '')}".rstrip())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
