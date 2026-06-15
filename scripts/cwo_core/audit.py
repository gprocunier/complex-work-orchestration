from __future__ import annotations

import datetime as dt
import json
import os
from pathlib import Path
from typing import Any

from .paths import AUDIT_LOG
from .policy import executor_dispatch_mode, executor_external, load_contracting_controls
from .util import artifact_hash


def iter_audit_events(audit_file: Path | None = None) -> list[dict[str, Any]]:
    audit_file = audit_file or AUDIT_LOG
    if not audit_file.exists():
        return []
    events: list[dict[str, Any]] = []
    for line in audit_file.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            events.append(value)
    return events


def count_audit_events(
    event_type: str,
    epic_id: str | None,
    executor_external: bool,
    *,
    ignore_dispatch_id: str | None = None,
) -> int:
    unique_dispatches: set[str] = set()
    for event in iter_audit_events():
        if event.get("quota_event_type") != event_type:
            continue
        event_epic = event.get("epic_id")
        if epic_id is None:
            if event_epic not in [None, ""]:
                continue
        elif event_epic != epic_id:
            continue
        if bool(event.get("executor_external")) != executor_external:
            continue
        dispatch_id = str(event.get("dispatch_id") or event.get("event_hash") or json.dumps(event, sort_keys=True))
        if ignore_dispatch_id and dispatch_id == ignore_dispatch_id:
            continue
        unique_dispatches.add(dispatch_id)
    return len(unique_dispatches)


def enforce_contracting_quota(
    epic_id: str | None,
    executor: str,
    route: str,
    *,
    dispatch_id: str | None = None,
) -> dict[str, Any]:
    controls = load_contracting_controls()
    quotas = controls.get("quota_policy", {})
    is_external = executor_external(executor)
    dispatch_mode = executor_dispatch_mode(executor)
    if is_external:
        quota_key = "external_manual_dispatches_per_epic"
        quota_event_type = "external_manual_dispatch"
    elif route == "local-worker" or dispatch_mode in {"local_openai_compatible", "local_secure_review"}:
        quota_key = "local_worker_dispatches_per_epic"
        quota_event_type = "local_worker_dispatch"
    else:
        return {
            "quota_checked": False,
            "quota_event_type": None,
            "quota_limit": None,
            "quota_remaining": None,
            "executor_external": is_external,
        }
    limit = int(quotas.get(quota_key, 0))
    if limit <= 0:
        raise SystemExit(f"quota {quota_key} is not configured")
    used = count_audit_events(quota_event_type, epic_id, is_external, ignore_dispatch_id=dispatch_id)
    remaining_before = limit - used
    if remaining_before <= 0:
        scope = epic_id or "global"
        raise SystemExit(f"{quota_key} exhausted for {scope}: used {used} of {limit}")
    return {
        "quota_checked": True,
        "quota_event_type": quota_event_type,
        "quota_limit": limit,
        "quota_remaining": remaining_before - 1,
        "executor_external": is_external,
    }


def record_audit_event(event: dict[str, Any], audit_file: Path | None = None) -> dict[str, Any]:
    audit_file = audit_file or AUDIT_LOG
    audit_file.parent.mkdir(parents=True, exist_ok=True)
    lock_handle, lock_mode = acquire_audit_lock(audit_file)
    try:
        previous_hash = None
        prior_events = iter_audit_events(audit_file)
        if prior_events:
            previous_hash = prior_events[-1].get("event_hash")
        enriched = dict(event)
        enriched.setdefault("timestamp", dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))
        enriched.setdefault("audit_lock_mode", lock_mode)
        if previous_hash:
            enriched.setdefault("previous_event_hash", previous_hash)
        enriched.pop("event_hash", None)
        enriched["event_hash"] = artifact_hash(json.dumps(enriched, sort_keys=True))
        with audit_file.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(enriched, sort_keys=True) + "\n")
        return enriched
    finally:
        release_audit_lock(lock_handle)


def audit_strict_lock_required() -> bool:
    return os.environ.get("CWO_AUDIT_REQUIRE_LOCK", "").strip().lower() in {"1", "true", "yes", "on"}


def acquire_audit_lock(audit_file: Path) -> tuple[Any | None, str]:
    lock_file = audit_file.with_name(audit_file.name + ".lock")
    lock_file.parent.mkdir(parents=True, exist_ok=True)
    handle = lock_file.open("a+", encoding="utf-8")
    try:
        import fcntl  # type: ignore[import-not-found]
    except ImportError:
        handle.close()
        if audit_strict_lock_required():
            raise SystemExit("audit locking is unavailable on this platform and CWO_AUDIT_REQUIRE_LOCK is set")
        return None, "unsupported"
    fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
    return handle, "posix-flock"


def release_audit_lock(lock_handle: Any | None) -> None:
    if lock_handle is None:
        return
    try:
        import fcntl  # type: ignore[import-not-found]

        fcntl.flock(lock_handle.fileno(), fcntl.LOCK_UN)
    finally:
        lock_handle.close()


def audit_event_payload_hash(event: dict[str, Any]) -> str:
    payload = dict(event)
    payload.pop("event_hash", None)
    return artifact_hash(json.dumps(payload, sort_keys=True))


def verify_audit_log(audit_file: Path | None = None) -> dict[str, Any]:
    audit_file = audit_file or AUDIT_LOG
    errors: list[str] = []
    previous_hash: str | None = None
    unlinked_events = 0
    raw_lines = audit_file.read_text(encoding="utf-8").splitlines() if audit_file.exists() else []
    events: list[dict[str, Any]] = []
    for index, line in enumerate(raw_lines, 1):
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError as exc:
            errors.append(f"line {index}: invalid JSON: {exc}")
            continue
        if not isinstance(event, dict):
            errors.append(f"line {index}: event is not an object")
            continue
        events.append(event)
        expected_hash = audit_event_payload_hash(event)
        if event.get("event_hash") != expected_hash:
            errors.append(f"line {index}: event_hash mismatch")
        expected_previous = event.get("previous_event_hash")
        if previous_hash and expected_previous is None:
            unlinked_events += 1
        elif previous_hash and expected_previous != previous_hash:
            errors.append(f"line {index}: previous_event_hash mismatch")
        if not previous_hash and expected_previous:
            errors.append(f"line {index}: first event unexpectedly has previous_event_hash")
        previous_hash = event.get("event_hash")
    return {
        "valid": not errors,
        "errors": errors,
        "event_count": len(events),
        "unlinked_event_count": unlinked_events,
        "last_event_hash": previous_hash,
    }
