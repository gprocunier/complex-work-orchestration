from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
from pathlib import Path
from typing import Any

from .paths import AUDIT_LOG, HOST_AUDIT_LOG
from .policy import executor_dispatch_mode, executor_external, load_contracting_controls
from .telemetry import sanitize_audit_event
from .util import artifact_hash


def _configured_audit_file(audit_file: Path) -> bool:
    from .host_records import configured_store
    return audit_file == HOST_AUDIT_LOG or audit_file == configured_store().audit_file


def iter_audit_events(audit_file: Path | None = None, *, strict: bool = True) -> list[dict[str, Any]]:
    audit_file = audit_file or AUDIT_LOG
    if _configured_audit_file(audit_file):
        from .host_records import configured_store
        return configured_store().audit_events()
    if not audit_file.exists():
        return []
    events: list[dict[str, Any]] = []
    for line_number, line in enumerate(audit_file.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            if strict:
                raise SystemExit(f"{audit_file}: line {line_number}: invalid audit JSON: {exc}") from exc
            continue
        if isinstance(value, dict):
            events.append(value)
        elif strict:
            raise SystemExit(f"{audit_file}: line {line_number}: audit event is not an object")
    return events


def count_audit_events(
    event_type: str,
    epic_id: str | None,
    executor_external: bool,
    *,
    ignore_reserved_dispatch_id: str | None = None,
    ignore_reserved_packet_sha256: str | None = None,
) -> int:
    reserved: set[tuple[str, str]] = set()
    consumed_reserved: set[tuple[str, str]] = set()
    consumed_events: set[str] = set()
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
        packet_sha256 = str(event.get("packet_sha256") or "")
        is_reserved = event.get("quota_stage") == "reserved" or event.get("event_type") == "packet_built"
        if is_reserved:
            if (
                ignore_reserved_dispatch_id
                and dispatch_id == ignore_reserved_dispatch_id
                and (
                    ignore_reserved_packet_sha256 is None
                    or packet_sha256 == ignore_reserved_packet_sha256
                )
            ):
                continue
            reserved.add((dispatch_id, packet_sha256 or str(event.get("event_hash") or "")))
            continue
        if is_pre_submission_browser_failure(event):
            continue
        consumed_events.add(str(event.get("event_hash") or json.dumps(event, sort_keys=True)))
        if packet_sha256:
            consumed_reserved.add((dispatch_id, packet_sha256))
    return len(consumed_events) + len(reserved - consumed_reserved)


def is_pre_submission_browser_failure(event: dict[str, Any]) -> bool:
    if event.get("event_type") != "chatgpt_browser_dispatch":
        return False
    status = str(event.get("telemetry_status") or event.get("status") or "").lower()
    if status != "failed":
        return False
    failure_stage = str(event.get("failure_stage") or "").lower()
    pre_submit_stages = {
        "browser-start",
        "page-load",
        "prompt-ready",
        "model-selection",
        "model-confirmation",
        "prompt-submit",
    }
    if failure_stage not in pre_submit_stages:
        return False
    if event.get("share_url_present"):
        return False
    response_chars = event.get("response_chars")
    return response_chars in (None, 0, "0")


def enforce_contracting_quota(
    epic_id: str | None,
    executor: str,
    route: str,
    *,
    dispatch_id: str | None = None,
    packet_sha256: str | None = None,
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
    used = count_audit_events(
        quota_event_type,
        epic_id,
        is_external,
        ignore_reserved_dispatch_id=dispatch_id,
        ignore_reserved_packet_sha256=packet_sha256,
    )
    remaining_before = limit - used
    if remaining_before <= 0:
        # The epic ID is caller input that no screen has seen yet, so the
        # message names it only by a digest prefix.
        scope = f"epic sha256:{hashlib.sha256(epic_id.encode('utf-8')).hexdigest()[:12]}" if epic_id else "global"
        raise SystemExit(f"{quota_key} exhausted for {scope}: used {used} of {limit}")
    return {
        "quota_checked": True,
        "quota_event_type": quota_event_type,
        "quota_limit": limit,
        "quota_remaining": remaining_before - 1,
        "executor_external": is_external,
    }


def matching_audit_events(
    *,
    event_type: str | None = None,
    dispatch_id: str | None = None,
    bead_id: str | None = None,
    packet_sha256: str | None = None,
    prompt_sha256: str | None = None,
    audit_file: Path | None = None,
) -> list[dict[str, Any]]:
    matches: list[dict[str, Any]] = []
    for event in iter_audit_events(audit_file):
        if event_type is not None and event.get("event_type") != event_type:
            continue
        if dispatch_id is not None and event.get("dispatch_id") != dispatch_id:
            continue
        if bead_id is not None and event.get("bead_id") != bead_id:
            continue
        if packet_sha256 is not None and event.get("packet_sha256") != packet_sha256:
            continue
        if prompt_sha256 is not None and event.get("prompt_sha256") != prompt_sha256:
            continue
        matches.append(event)
    return matches


def require_packet_build_audit(
    *,
    dispatch_id: str,
    bead_id: str | None,
    packet_sha256: str,
    audit_file: Path | None = None,
) -> dict[str, Any]:
    matches = matching_audit_events(
        event_type="packet_built",
        dispatch_id=dispatch_id,
        bead_id=bead_id,
        packet_sha256=packet_sha256,
        audit_file=audit_file,
    )
    if not matches:
        raise SystemExit(
            "packet dispatch requires a matching packet_built audit event "
            f"for dispatch_id={dispatch_id} packet_sha256={packet_sha256}"
        )
    return matches[-1]


def record_audit_event(event: dict[str, Any], audit_file: Path | None = None, *,
                       _directory_fd: int | None = None, _limits: Any = None,
                       _lock_fd: int | None = None) -> dict[str, Any]:
    audit_file = audit_file or AUDIT_LOG
    if _directory_fd is not None:
        return _record_private_audit_event(event, _directory_fd, _limits, _lock_fd=_lock_fd)
    if _configured_audit_file(audit_file):
        from .host_records import configured_store
        return configured_store().record_audit_event(event)
    audit_file.parent.mkdir(parents=True, exist_ok=True)
    lock_handle, lock_mode = acquire_audit_lock(audit_file)
    try:
        previous_hash = None
        prior_events = iter_audit_events(audit_file)
        if prior_events:
            previous_hash = prior_events[-1].get("event_hash")
        enriched = sanitize_audit_event(dict(event))
        enriched.setdefault("timestamp", dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))
        enriched.setdefault("audit_lock_mode", lock_mode)
        if previous_hash:
            enriched.setdefault("previous_event_hash", previous_hash)
        enriched.pop("event_hash", None)
        enriched["event_hash"] = artifact_hash(json.dumps(enriched, sort_keys=True))
        with audit_file.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(enriched, sort_keys=True) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
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
    try:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
    except BaseException:
        handle.close()
        raise
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
    if _configured_audit_file(audit_file):
        return _verify_host_audit()
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
            errors.append(f"line {index}: previous_event_hash missing")
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


def _verify_host_audit() -> dict[str, Any]:
    from .host_records import configured_store, HostRecordError
    try:
        events = configured_store().audit_events()
    except (HostRecordError, OSError) as failure:
        return dict(valid=False, errors=[str(failure)], event_count=0,
                    unlinked_event_count=0, last_event_hash=None)
    return dict(valid=True, errors=[], event_count=len(events), unlinked_event_count=0,
                last_event_hash=events[-1]['event_hash'] if events else None)


def _prepare_private_audit_event(event: dict[str, Any], directory: int, limits: Any,
                                 prior: list[dict[str, Any]] | None = None) -> tuple[dict[str, Any], bytes]:
    """Exact capacity preflight under the audit lock, before record creation."""
    from .host_records import _audit_snapshot
    from .audit_segments import append_plan
    prior = _audit_snapshot(directory, limits) if prior is None else prior
    enriched = sanitize_audit_event(dict(event))
    enriched.setdefault('timestamp', dt.datetime.now(dt.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'))
    enriched.setdefault('audit_lock_mode', 'posix-flock')
    enriched.pop('previous_event_hash', None)
    if prior:
        enriched['previous_event_hash'] = prior[-1]['event_hash']
    enriched.pop('event_hash', None)
    enriched['event_hash'] = audit_event_payload_hash(enriched)
    raw = (json.dumps(enriched, sort_keys=True) + '\n').encode('utf-8')
    append_plan(directory, limits, raw, prior)
    return enriched, raw


def _restore_private_audit(directory: int, fd: int, before: bytes | None,
                           head: bytes | None, limits: Any) -> None:
    from .host_records import _audit_snapshot, _write_at
    os.ftruncate(fd, len(before or b''))
    os.fsync(fd)
    if head is None:
        for name in ('audit.jsonl.head.json', 'audit.jsonl'):
            try:
                os.unlink(name, dir_fd=directory)
            except FileNotFoundError:
                pass
    else:
        _write_at(directory, 'audit.jsonl.head.json', head, replace=True)
    os.fsync(directory)
    _audit_snapshot(directory, limits)


def _record_private_audit_event(event: dict[str, Any], directory: int, limits: Any, *,
                                _lock_fd: int | None = None) -> dict[str, Any]:
    """Append through the shared writer; restore an uncommitted partial append.

    Once the matching event and head verify, retain that committed evidence even
    when confirmation raises. Recovery that cannot be verified reports uncertainty
    and leaves verification closed; it never claims the operation did not occur.
    """
    from .host_records import _audit_lock
    from .audit_segments import recover_rotation
    from .host_record_quarantine import require_no_pending
    lock = _lock_fd if _lock_fd is not None else _audit_lock(directory, create=True, exclusive=True)
    try:
        require_no_pending(directory)
        recover_rotation(directory, limits)
        return _append_private_audit(event, directory, limits)
    finally:
        if _lock_fd is None:
            os.close(lock)


def _append_private_audit(event: dict[str, Any], directory: int, limits: Any) -> dict[str, Any]:
    import stat
    from .host_records import _audit_snapshot, _need
    prior = _audit_snapshot(directory, limits)
    enriched, raw = _prepare_private_audit_event(event, directory, limits, prior)
    from .audit_segments import append_plan, commit_rotation, segment_name
    rotate, head, index, _, before = append_plan(directory, limits, raw, prior)
    if rotate:
        return commit_rotation(directory, limits, enriched, raw, prior)
    before = before if head is not None else None
    fd = os.open(segment_name(index), os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW
                 | os.O_NONBLOCK | os.O_CLOEXEC, 0o600, dir_fd=directory)
    try:
        info = os.fstat(fd)
        _need(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
              and stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1,
              'host audit must be private and regular')
        return _commit_private_append(directory, fd, enriched, raw, before, head, prior, limits)
    finally:
        os.close(fd)


def _verify_uncommitted_append(directory: int, before: bytes | None, head: bytes | None,
                                raw: bytes, limits: Any) -> None:
    """A readable old checkpoint plus exact pending bytes proves noncommit."""
    from .host_records import _need, _read_at
    try:
        from .audit_segments import MAX_HEAD_BYTES
        current_head = _read_at(directory, 'audit.jsonl.head.json', MAX_HEAD_BYTES)
    except FileNotFoundError:
        current_head = None
    _need(current_head == head, 'host audit checkpoint no longer proves an uncommitted append')
    from .audit_segments import layout, segment_name
    current = _read_at(directory, segment_name(layout(head)[0]), limits.max_audit_bytes)
    prefix = before or b''
    _need(current.startswith(prefix) and raw.startswith(current[len(prefix):]),
          'host audit bytes do not prove an uncommitted append')


def _commit_private_append(directory: int, fd: int, enriched: dict[str, Any], raw: bytes,
                            before: bytes | None, head: bytes | None,
                            prior: list[dict[str, Any]], limits: Any) -> dict[str, Any]:
    from .host_records import HostRecordError, _audit_snapshot, _json, _need, _write_at
    try:
        view = memoryview(raw)
        while view:
            count = os.write(fd, view)
            _need(count > 0, 'host audit write did not progress')
            view = view[count:]
        os.fsync(fd)
        from .audit_segments import append_head
        checkpoint = append_head(head, event_count=len(prior) + 1, event_hash=enriched['event_hash'],
                                 byte_count=len(before or b'') + len(raw))
        _write_at(directory, 'audit.jsonl.head.json', _json(checkpoint), replace=True)
    except BaseException as exc:
        try:
            current = _audit_snapshot(directory, limits)
        except (FileNotFoundError, ValueError):
            current = []
        except OSError as verification:
            raise HostRecordError('host audit append outcome uncertain; verification unavailable, evidence preserved') from verification
        if current and current[-1].get('event_hash') == enriched['event_hash']:
            raise HostRecordError('host audit event committed; confirmation interrupted, verify before retry') from exc
        try:
            _verify_uncommitted_append(directory, before, head, raw, limits)
        except (OSError, ValueError) as verification:
            raise HostRecordError('host audit append outcome uncertain; noncommit could not be verified, evidence preserved') from verification
        try:
            _restore_private_audit(directory, fd, before, head, limits)
        except BaseException as recovery:
            raise HostRecordError('host audit append outcome uncertain; recovery could not be verified') from recovery
        raise
    return enriched
