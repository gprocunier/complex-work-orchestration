"""Fail-closed execution for ordered checked-command sequences."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from .checked_command import execute_checked_command, normalize_command_spec

SPEC_TYPE = "cwo-checked-command-sequence-spec"
RESULT_TYPE = "cwo-checked-command-sequence-result"
VERSION = 1
STATUSES = {"running", "passed", "failed", "blocked", "quarantined"}
_SEQUENCE_FIELDS = {
    "spec_type",
    "version",
    "sequence_id",
    "packet_id",
    "work_plan_sha256",
    "workdir",
    "commands",
}
_RESULT_FIELDS = (
    "result_type",
    "version",
    "command_id",
    "spec_sha256",
    "execution_status",
    "exit_code",
    "execution_started",
    "mutation_started",
    "mutated_paths",
    "failure_class",
    "quarantine_required",
    "diagnostics",
)


def _strict_identifier(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be a non-empty string")
    return value


def _sha256_hex(value: Any, field: str) -> str:
    digest = _strict_identifier(value, field)
    if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
        raise ValueError(f"{field} must be a lowercase SHA-256 digest")
    return digest


def _canonical_hash(value: Any) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def normalize_sequence_spec(value: Any) -> dict[str, Any]:
    """Validate and normalize a checked-command sequence v1 specification."""
    if not isinstance(value, Mapping):
        raise ValueError("sequence spec must be a mapping")
    if set(value) != _SEQUENCE_FIELDS:
        raise ValueError(f"sequence spec must contain exact fields {sorted(_SEQUENCE_FIELDS)}")
    if value["spec_type"] != SPEC_TYPE or value["version"] != VERSION:
        raise ValueError("unsupported checked-command sequence type or version")

    sequence_id = _strict_identifier(value["sequence_id"], "sequence_id")
    packet_id = _strict_identifier(value["packet_id"], "packet_id")
    work_plan_sha256 = _sha256_hex(value["work_plan_sha256"], "work_plan_sha256")
    workdir = Path(_strict_identifier(value["workdir"], "workdir")).expanduser().resolve()
    if not workdir.is_dir():
        raise ValueError("workdir must be an existing directory")

    raw_commands = value["commands"]
    if not isinstance(raw_commands, list) or not raw_commands:
        raise ValueError("commands must be a non-empty list")

    commands: list[dict[str, Any]] = []
    command_ids: set[str] = set()
    for index, raw_command in enumerate(raw_commands):
        try:
            command = normalize_command_spec(raw_command)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"commands[{index}] is invalid") from exc
        if command["mode"] != "argv":
            raise ValueError(f"commands[{index}].mode must be argv")
        if Path(command["cwd"]).resolve() != workdir:
            raise ValueError(f"commands[{index}].cwd must match sequence workdir")
        if command["command_id"] in command_ids:
            raise ValueError("command_id values must be unique")
        command_ids.add(command["command_id"])
        commands.append(command)

    return {
        "spec_type": SPEC_TYPE,
        "version": VERSION,
        "sequence_id": sequence_id,
        "packet_id": packet_id,
        "work_plan_sha256": work_plan_sha256,
        "workdir": str(workdir),
        "commands": commands,
    }


def _identity(value: Any) -> dict[str, Any]:
    source = value if isinstance(value, Mapping) else {}
    return {
        "sequence_id": source.get("sequence_id") if isinstance(source.get("sequence_id"), str) else None,
        "packet_id": source.get("packet_id") if isinstance(source.get("packet_id"), str) else None,
        "work_plan_sha256": source.get("work_plan_sha256")
        if isinstance(source.get("work_plan_sha256"), str)
        else None,
        "workdir": source.get("workdir") if isinstance(source.get("workdir"), str) else None,
    }


def _result(
    identity: Mapping[str, Any],
    *,
    spec_sha256: str | None,
    status: str,
    execution_started: bool,
    completed_count: int = 0,
    failed_command_id: str | None = None,
    failure_class: str | None = None,
    command_results: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    if status not in STATUSES:
        raise ValueError("invalid sequence result status")
    return {
        "result_type": RESULT_TYPE,
        "version": VERSION,
        "sequence_id": identity.get("sequence_id"),
        "packet_id": identity.get("packet_id"),
        "work_plan_sha256": identity.get("work_plan_sha256"),
        "spec_sha256": spec_sha256,
        "workdir": identity.get("workdir"),
        "status": status,
        "execution_started": execution_started,
        "completed_count": completed_count,
        "failed_command_id": failed_command_id,
        "failure_class": failure_class,
        "command_results": list(command_results or []),
    }


def _bounded_text(value: Any) -> str:
    return value[:4096] if isinstance(value, str) else ""


def _bounded_command_result(value: Mapping[str, Any]) -> dict[str, Any]:
    bounded = {field: value.get(field) for field in _RESULT_FIELDS}
    paths = value.get("mutated_paths")
    bounded["mutated_paths"] = list(paths[:100]) if isinstance(paths, list) else []
    diagnostics = value.get("diagnostics")
    bounded["diagnostics"] = {
        "stdout": _bounded_text(diagnostics.get("stdout")),
        "stderr": _bounded_text(diagnostics.get("stderr")),
    } if isinstance(diagnostics, Mapping) else {"stdout": "", "stderr": ""}
    return bounded


def _state_target(state_path: Any) -> Path | None:
    if state_path is None:
        return None
    if not isinstance(state_path, str) or not state_path:
        raise ValueError("state_path must be an absolute path")
    target = Path(state_path)
    if not target.is_absolute() or not target.parent.is_dir():
        raise ValueError("state_path must be an absolute path with an existing parent")
    return target


def _atomic_write(target: Path, payload: Mapping[str, Any]) -> None:
    temporary_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=target.parent,
            prefix=f".{target.name}.",
            delete=False,
        ) as handle:
            json.dump(payload, handle, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
            temporary_name = handle.name
        os.replace(temporary_name, target)
    finally:
        if temporary_name and os.path.exists(temporary_name):
            os.unlink(temporary_name)


def _persist(target: Path | None, payload: Mapping[str, Any]) -> bool:
    if target is None:
        return True
    try:
        _atomic_write(target, payload)
    except OSError:
        return False
    return True


def _command_disposition(value: Mapping[str, Any]) -> tuple[str, str | None]:
    quarantine = value.get("quarantine_required")
    if not isinstance(quarantine, bool):
        return "blocked", "invalid-command-result"
    if quarantine or value.get("execution_status") == "quarantined":
        return "quarantined", "command-quarantined"

    status = value.get("execution_status")
    if status == "failed":
        return "failed", "command-failed"
    if status != "passed":
        return "blocked", "invalid-command-result"

    exit_code = value.get("exit_code")
    if isinstance(exit_code, bool) or not isinstance(exit_code, int):
        return "blocked", "invalid-exit-evidence"
    if exit_code != 0:
        return "failed", "nonzero-exit"
    if value.get("failure_class") is not None:
        return "failed", "command-result-failure"
    if value.get("execution_started") is not True:
        return "blocked", "invalid-command-result"
    return "passed", None


def execute_checked_command_sequence(value: Any, *, state_path: str | None = None) -> dict[str, Any]:
    """Execute commands in order and stop before the first unsafe successor."""
    raw_identity = _identity(value)
    try:
        target = _state_target(state_path)
    except ValueError:
        return _result(
            raw_identity,
            spec_sha256=None,
            status="blocked",
            execution_started=False,
            failure_class="invalid-state-path",
        )

    try:
        spec = normalize_sequence_spec(value)
    except (TypeError, ValueError):
        blocked = _result(
            raw_identity,
            spec_sha256=None,
            status="blocked",
            execution_started=False,
            failure_class="invalid-sequence-spec",
        )
        if not _persist(target, blocked):
            blocked["failure_class"] = "state-persistence-failed"
        return blocked

    spec_sha256 = _canonical_hash(spec)
    identity = _identity(spec)
    command_results: list[dict[str, Any]] = []
    completed_count = 0

    for command in spec["commands"]:
        command_id = command["command_id"]
        try:
            raw_result = execute_checked_command(command)
        except Exception:
            terminal = _result(
                identity,
                spec_sha256=spec_sha256,
                status="blocked",
                execution_started=True,
                completed_count=completed_count,
                failed_command_id=command_id,
                failure_class="command-execution-exception",
                command_results=command_results,
            )
            if not _persist(target, terminal):
                terminal["failure_class"] = "state-persistence-failed"
            return terminal

        if not isinstance(raw_result, Mapping):
            terminal = _result(
                identity,
                spec_sha256=spec_sha256,
                status="blocked",
                execution_started=True,
                completed_count=completed_count,
                failed_command_id=command_id,
                failure_class="invalid-command-result",
                command_results=command_results,
            )
            if not _persist(target, terminal):
                terminal["failure_class"] = "state-persistence-failed"
            return terminal

        command_results.append(_bounded_command_result(raw_result))
        status, failure_class = _command_disposition(raw_result)
        if status != "passed":
            terminal = _result(
                identity,
                spec_sha256=spec_sha256,
                status=status,
                execution_started=True,
                completed_count=completed_count,
                failed_command_id=command_id,
                failure_class=failure_class,
                command_results=command_results,
            )
            if not _persist(target, terminal):
                terminal["status"] = "blocked"
                terminal["failure_class"] = "state-persistence-failed"
            return terminal

        completed_count += 1
        running = _result(
            identity,
            spec_sha256=spec_sha256,
            status="running",
            execution_started=True,
            completed_count=completed_count,
            command_results=command_results,
        )
        if not _persist(target, running):
            return _result(
                identity,
                spec_sha256=spec_sha256,
                status="blocked",
                execution_started=True,
                completed_count=completed_count,
                failed_command_id=command_id,
                failure_class="state-persistence-failed",
                command_results=command_results,
            )

    passed = _result(
        identity,
        spec_sha256=spec_sha256,
        status="passed",
        execution_started=True,
        completed_count=completed_count,
        command_results=command_results,
    )
    if not _persist(target, passed):
        passed["status"] = "blocked"
        passed["failure_class"] = "state-persistence-failed"
    return passed
