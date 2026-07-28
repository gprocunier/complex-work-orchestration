"""Strict native session discovery and complete JSONL boundary helpers."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import stat
from typing import Any, Mapping, Sequence

from .native_session import _record_token_snapshot


BOUNDARY_FIELDS = {"record_count", "byte_offset", "boundary_sha256", "token_snapshot"}
SESSION_STORES = ("sessions", "archived_sessions")
TURN_LIFECYCLE_EVENT_TYPES = {
    "task_started",
    "task_complete",
    "turn_aborted",
    "task_failed",
}
TERMINAL_EVENT_STATUSES = {
    "task_complete": "completed",
    "turn_aborted": "interrupted",
    "task_failed": "failed",
}


class NativeSessionBoundaryError(ValueError):
    """Raised when trusted native telemetry cannot be bound unambiguously."""


@dataclass(frozen=True)
class LocatedSession:
    """Internal location plus privacy-safe provenance for one logical session."""

    path: Path
    store: str
    source_identity_sha256: str


def _regular_owner_stat(path: Path) -> os.stat_result:
    """Return a stable stat for one trusted, owner-bound regular file."""

    if path.is_symlink():
        raise NativeSessionBoundaryError("trusted session file is a symlink")
    try:
        current = path.stat(follow_symlinks=False)
    except OSError as exc:
        raise NativeSessionBoundaryError("trusted session file is unavailable") from exc
    if not stat.S_ISREG(current.st_mode):
        raise NativeSessionBoundaryError("trusted session source is not a regular file")
    if current.st_uid != os.geteuid():
        raise NativeSessionBoundaryError("trusted session source owner does not match controller")
    return current


def session_source_identity(path: Path | str, session_id: str) -> str:
    """Hash path-independent filesystem identity for replacement detection."""

    current = _regular_owner_stat(Path(path))
    payload = json.dumps(
        {
            "device": current.st_dev,
            "inode": current.st_ino,
            "mode": stat.S_IMODE(current.st_mode),
            "owner": current.st_uid,
            "session_id": session_id,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(b"cwo:native-session-source:v1\0" + payload).hexdigest()


def _token_snapshot(records: Sequence[Mapping[str, Any]]) -> dict[str, int] | None:
    latest = None
    for record in records:
        snapshot = _record_token_snapshot(dict(record))
        if snapshot is not None:
            latest = {key: int(value) for key, value in snapshot.items()}
    return latest


def capture_boundary(path: Path | str, session_id: str) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Capture one complete, identity-bound JSONL boundary."""

    session_path = Path(path)
    source_before = session_source_identity(session_path, session_id)
    raw = session_path.read_bytes()
    if not raw:
        raise NativeSessionBoundaryError("session file has no complete records")
    if not raw.endswith(b"\n"):
        raise NativeSessionBoundaryError("session file has a trailing partial record")
    records: list[dict[str, Any]] = []
    for number, line in enumerate(raw.splitlines(keepends=True), 1):
        if not line.strip():
            continue
        try:
            value = json.loads(line.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise NativeSessionBoundaryError(f"session record {number} is invalid: {exc}") from exc
        if not isinstance(value, dict):
            raise NativeSessionBoundaryError(f"session record {number} is not an object")
        explicit = value.get("session_id")
        if isinstance(explicit, str) and explicit and explicit != session_id:
            raise NativeSessionBoundaryError("session identity changed inside JSONL boundary")
        if value.get("type") == "session_meta":
            payload = value.get("payload")
            if isinstance(payload, Mapping):
                for field in ("id", "session_id"):
                    current = payload.get(field)
                    if isinstance(current, str) and current and current != session_id:
                        raise NativeSessionBoundaryError(
                            "session_meta identity does not match requested session"
                        )
        records.append(value)
    if not records:
        raise NativeSessionBoundaryError("session file has no complete object records")
    identities = {
        str(payload[field])
        for record in records
        if record.get("type") == "session_meta"
        and isinstance((payload := record.get("payload")), Mapping)
        for field in ("id", "session_id")
        if isinstance(payload.get(field), str) and payload.get(field)
    }
    identities.update(
        str(record["session_id"])
        for record in records
        if isinstance(record.get("session_id"), str) and record.get("session_id")
    )
    if identities != {session_id}:
        raise NativeSessionBoundaryError("trusted session identity is missing from JSONL boundary")
    if session_source_identity(session_path, session_id) != source_before:
        raise NativeSessionBoundaryError("trusted session source changed during boundary capture")
    return (
        {
            "record_count": len(records),
            "byte_offset": len(raw),
            "boundary_sha256": hashlib.sha256(raw).hexdigest(),
            "token_snapshot": _token_snapshot(records),
        },
        records,
    )


def same_boundary(expected: Mapping[str, Any], actual: Mapping[str, Any]) -> bool:
    return all(actual.get(field) == expected.get(field) for field in BOUNDARY_FIELDS)


def assert_prefix_intact(path: Path | str, baseline: Mapping[str, Any]) -> None:
    session_path = Path(path)
    _regular_owner_stat(session_path)
    raw = session_path.read_bytes()
    offset = baseline.get("byte_offset")
    if isinstance(offset, bool) or not isinstance(offset, int) or offset < 0:
        raise NativeSessionBoundaryError("baseline byte offset is invalid")
    if len(raw) < offset:
        raise NativeSessionBoundaryError("session JSONL was truncated below the baseline byte offset")
    if hashlib.sha256(raw[:offset]).hexdigest() != baseline.get("boundary_sha256"):
        raise NativeSessionBoundaryError("session JSONL prefix was rewritten after baseline capture")


def locate_unique_session(
    codex_home: Path | str,
    session_id: str,
    *,
    reported_path: Path | str | None = None,
) -> LocatedSession:
    """Locate exactly one active-or-archived file from initialized codexHome."""

    root = Path(codex_home)
    if not root.is_absolute() or not root.is_dir():
        raise NativeSessionBoundaryError("initialized codexHome is unavailable")
    candidates: dict[Path, str] = {}
    if reported_path is not None:
        reported = Path(reported_path)
        if reported.is_file():
            _regular_owner_stat(reported)
            resolved = reported.resolve()
            try:
                relative = resolved.relative_to(root.resolve())
            except ValueError as exc:
                raise NativeSessionBoundaryError("reported session path is outside codexHome") from exc
            store = relative.parts[0] if relative.parts else "reported"
            candidates[resolved] = store
    for store in SESSION_STORES:
        directory = root / store
        if not directory.is_dir():
            continue
        for path in directory.rglob(f"*{session_id}.jsonl"):
            if path.is_file():
                _regular_owner_stat(path)
                candidates[path.resolve()] = store
    if not candidates:
        raise NativeSessionBoundaryError("trusted session file is missing")
    if len(candidates) != 1:
        raise NativeSessionBoundaryError("duplicate active/archive session files")
    path, store = next(iter(candidates.items()))
    return LocatedSession(
        path=path,
        store=store,
        source_identity_sha256=session_source_identity(path, session_id),
    )


def capture_unique_boundary(
    codex_home: Path | str,
    session_id: str,
    *,
    reported_path: Path | str | None = None,
    baseline: Mapping[str, Any] | None = None,
) -> tuple[LocatedSession, dict[str, Any], list[dict[str, Any]]]:
    located = locate_unique_session(codex_home, session_id, reported_path=reported_path)
    if baseline is not None:
        assert_prefix_intact(located.path, baseline)
    boundary, records = capture_boundary(located.path, session_id)
    if session_source_identity(located.path, session_id) != located.source_identity_sha256:
        raise NativeSessionBoundaryError("trusted session source identity changed")
    return located, boundary, records


def record_indices(records: Sequence[Mapping[str, Any]], record_type: str, payload_type: str | None = None) -> list[int]:
    indices: list[int] = []
    for index, record in enumerate(records):
        if record.get("type") != record_type:
            continue
        payload = record.get("payload")
        if payload_type is not None and (
            not isinstance(payload, Mapping) or payload.get("type") != payload_type
        ):
            continue
        indices.append(index)
    return indices


def trusted_turn_context(
    records: Sequence[Mapping[str, Any]],
    *,
    turn_id: str,
    model: str,
    effort: str,
) -> tuple[int, dict[str, Any]]:
    matches: list[tuple[int, dict[str, Any]]] = []
    for index, record in enumerate(records):
        if record.get("type") != "turn_context" or not isinstance(record.get("payload"), Mapping):
            continue
        payload = dict(record["payload"])
        current_turn = payload.get("turn_id") or payload.get("turnId")
        current_effort = payload.get("effort") or payload.get("reasoning_effort")
        if current_turn == turn_id and payload.get("model") == model and current_effort == effort:
            matches.append((index, payload))
    if len(matches) != 1:
        raise NativeSessionBoundaryError("trusted current-turn model and effort attestation is not singular")
    return matches[0]


def telemetry_markers(records: Sequence[Mapping[str, Any]], *, turn_id: str) -> dict[str, Any]:
    compactions: list[int] = []
    reroutes: list[int] = []
    terminal: list[int] = []
    for index, record in enumerate(records):
        payload = record.get("payload") if isinstance(record.get("payload"), Mapping) else {}
        kind = f"{record.get('type', '')}:{payload.get('type', '')}".lower()
        if "compact" in kind:
            compactions.append(index)
        if "rerout" in kind:
            reroutes.append(index)
        if payload.get("turn_id") == turn_id and payload.get("type") in {
            "task_complete",
            "turn_aborted",
            "task_failed",
        }:
            terminal.append(index)
    return {"compaction_indices": compactions, "reroute_indices": reroutes, "terminal_indices": terminal}


def trusted_terminal_event(
    records: Sequence[Mapping[str, Any]], *, turn_id: str
) -> dict[str, Any] | None:
    """Return the singular exact-turn terminal event for the pinned app-server grammar."""

    terminal: list[dict[str, Any]] = []
    for index, record in enumerate(records):
        if record.get("type") != "event_msg":
            continue
        payload = record.get("payload")
        if not isinstance(payload, Mapping):
            continue
        event_type = payload.get("type")
        if not isinstance(event_type, str):
            continue
        is_lifecycle = event_type.startswith("task_") or event_type.startswith(
            "turn_"
        )
        canonical_turn_id = payload.get("turn_id")
        legacy_turn_id = payload.get("turnId")
        if is_lifecycle and (
            legacy_turn_id == turn_id
            or (canonical_turn_id == turn_id and "turnId" in payload)
        ):
            raise NativeSessionBoundaryError(
                "exact-turn lifecycle attribution is not canonical"
            )
        if canonical_turn_id != turn_id:
            continue
        if (
            is_lifecycle
            and event_type not in TURN_LIFECYCLE_EVENT_TYPES
        ):
            raise NativeSessionBoundaryError(
                f"unknown exact-turn lifecycle event type: {event_type}"
            )
        status = TERMINAL_EVENT_STATUSES.get(event_type)
        if status is not None:
            if event_type == "task_complete" and payload.get("error") is not None:
                status = "failed"
            terminal.append(
                {
                    "record_index": index,
                    "event_type": event_type,
                    "status": status,
                    "count": 1,
                }
            )
    if len(terminal) > 1:
        raise NativeSessionBoundaryError(
            "exact-turn durable terminal event is not singular"
        )
    return terminal[0] if terminal else None
