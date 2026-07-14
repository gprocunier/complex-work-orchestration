"""Append-only convergence ledger and closure-pressure primitives."""

from __future__ import annotations

import contextlib
import datetime as dt
import hashlib
import json
import math
import os
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any


RECORD_TYPE = "cwo-epic-convergence-ledger-record"
RECORD_VERSION = 1
CALL_CATEGORIES = (
    "productive",
    "validation",
    "attestation",
    "fit",
    "monitoring",
    "recovery",
    "pm",
    "architect",
    "unknown",
)
CLOSURE_DISPOSITIONS = ("retain", "correct", "quarantine", "defer", "close")
IDENTITY_FIELDS = (
    "epic_id",
    "work_unit_id",
    "bead_id",
    "packet_id",
    "session_id",
    "model",
    "phase",
    "event",
)
USAGE_FIELDS = (
    "tool_calls",
    "runtime_seconds",
    "input_tokens",
    "output_tokens",
    "total_tokens",
    "context_compactions",
    "full_suite_runs",
)
USAGE_INTEGER_FIELDS = frozenset(USAGE_FIELDS) - {"runtime_seconds"}
GRAPH_COUNTER_FIELDS = (
    "beads_total",
    "beads_open",
    "beads_closed",
    "graph_depth",
    "work_units_total",
    "work_units_open",
    "work_units_closed",
    "routine_repair_children",
    "worker_sessions",
)
RECORD_FIELDS = (
    "record_type",
    "version",
    *IDENTITY_FIELDS,
    "call_category",
    "usage",
    "artifact_disposition",
    "graph_counters",
    "timestamp",
    "previous_record_sha256",
    "record_sha256",
)


def _nullable_text(value: Any, path: str) -> str | None:
    if value is None or isinstance(value, str):
        return value
    raise TypeError(f"{path} must be a string or null")


def _nonnegative_number(value: Any, path: str, *, integer: bool) -> int | float | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError(f"{path} must be a non-negative number or null")
    if integer and not isinstance(value, int):
        raise TypeError(f"{path} must be a non-negative integer or null")
    if not math.isfinite(value) or value < 0:
        raise ValueError(f"{path} must be finite and non-negative")
    return value


def _metrics(
    value: Any,
    path: str,
    fields: tuple[str, ...],
    *,
    integer_fields: frozenset[str],
    fill_missing: bool,
) -> dict[str, int | float | None] | None:
    if value is None:
        return None
    if not isinstance(value, Mapping):
        raise TypeError(f"{path} must be an object or null")
    unknown = sorted(set(value) - set(fields))
    if unknown:
        raise ValueError(f"{path} has unknown fields: {', '.join(unknown)}")
    missing = sorted(set(fields) - set(value))
    if missing and not fill_missing:
        raise ValueError(f"{path} is missing fields: {', '.join(missing)}")
    return {
        field: _nonnegative_number(
            value.get(field),
            f"{path}.{field}",
            integer=field in integer_fields,
        )
        for field in fields
    }


def _timestamp(value: Any) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value:
        raise TypeError("timestamp must be a non-empty ISO-8601 string or null")
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("timestamp must be ISO-8601") from exc
    if parsed.tzinfo is None:
        raise ValueError("timestamp must include a timezone")
    return value


def _sha256(value: Any, path: str, *, nullable: bool) -> str | None:
    if value is None and nullable:
        return None
    if not isinstance(value, str) or len(value) != 64:
        raise TypeError(f"{path} must be a lowercase SHA-256 digest")
    if any(char not in "0123456789abcdef" for char in value):
        raise ValueError(f"{path} must be a lowercase SHA-256 digest")
    return value


def canonical_record_sha256(record: Mapping[str, Any]) -> str:
    if not isinstance(record, Mapping):
        raise TypeError("record must be an object")
    payload = dict(record)
    payload.pop("record_sha256", None)
    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _normalize_record(
    record: Mapping[str, Any],
    *,
    require_hash: bool,
    fill_nested_missing: bool,
) -> dict[str, Any]:
    if not isinstance(record, Mapping):
        raise TypeError("record must be an object")
    source = dict(record)
    unknown = sorted(set(source) - set(RECORD_FIELDS))
    if unknown:
        raise ValueError(f"record has unknown fields: {', '.join(unknown)}")
    missing = sorted(set(RECORD_FIELDS) - set(source))
    if missing:
        raise ValueError(f"record is missing fields: {', '.join(missing)}")
    if source["record_type"] != RECORD_TYPE:
        raise ValueError(f"record_type must be {RECORD_TYPE}")
    if isinstance(source["version"], bool) or source["version"] != RECORD_VERSION:
        raise ValueError(f"version must be {RECORD_VERSION}")
    for field in IDENTITY_FIELDS:
        source[field] = _nullable_text(source[field], field)
    category = source["call_category"]
    if category is not None and category not in CALL_CATEGORIES:
        raise ValueError(f"unsupported call_category: {category!r}")
    source["usage"] = _metrics(
        source["usage"],
        "usage",
        USAGE_FIELDS,
        integer_fields=USAGE_INTEGER_FIELDS,
        fill_missing=fill_nested_missing,
    )
    source["artifact_disposition"] = _nullable_text(
        source["artifact_disposition"], "artifact_disposition"
    )
    source["graph_counters"] = _metrics(
        source["graph_counters"],
        "graph_counters",
        GRAPH_COUNTER_FIELDS,
        integer_fields=frozenset(GRAPH_COUNTER_FIELDS),
        fill_missing=fill_nested_missing,
    )
    source["timestamp"] = _timestamp(source["timestamp"])
    source["previous_record_sha256"] = _sha256(
        source["previous_record_sha256"], "previous_record_sha256", nullable=True
    )
    if require_hash:
        source["record_sha256"] = _sha256(
            source["record_sha256"], "record_sha256", nullable=False
        )
        if source["record_sha256"] != canonical_record_sha256(source):
            raise ValueError("record_sha256 does not match the canonical payload")
    elif source["record_sha256"] is not None:
        raise ValueError("unsealed record must not contain record_sha256")
    return source


def build_record(record: Mapping[str, Any]) -> dict[str, Any]:
    source = dict(record)
    source.setdefault("record_type", RECORD_TYPE)
    source.setdefault("version", RECORD_VERSION)
    source.setdefault("previous_record_sha256", None)
    source.setdefault("record_sha256", None)
    required_inputs = set(RECORD_FIELDS) - {
        "record_type",
        "version",
        "previous_record_sha256",
        "record_sha256",
    }
    missing = sorted(required_inputs - set(source))
    if missing:
        raise ValueError(f"builder input is missing fields: {', '.join(missing)}")
    normalized = _normalize_record(
        source,
        require_hash=False,
        fill_nested_missing=True,
    )
    normalized["record_sha256"] = canonical_record_sha256(normalized)
    return validate_record(normalized)


def validate_record(record: Mapping[str, Any]) -> dict[str, Any]:
    return _normalize_record(
        record,
        require_hash=True,
        fill_nested_missing=False,
    )


def validate_chain(records: Iterable[Mapping[str, Any]]) -> bool:
    previous: str | None = None
    for index, record in enumerate(records):
        validated = validate_record(record)
        if validated["previous_record_sha256"] != previous:
            raise ValueError(f"ledger chain breaks at record {index}")
        previous = validated["record_sha256"]
    return True


def load_records(path: str | Path) -> list[dict[str, Any]]:
    ledger = Path(path)
    if not ledger.exists():
        return []
    records: list[dict[str, Any]] = []
    with ledger.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"invalid ledger JSON at line {line_number}") from exc
            try:
                records.append(validate_record(payload))
            except (TypeError, ValueError) as exc:
                raise ValueError(f"invalid ledger record at line {line_number}: {exc}") from exc
    validate_chain(records)
    return records


@contextlib.contextmanager
def _ledger_lock(path: Path):
    try:
        import fcntl
    except ImportError as exc:  # pragma: no cover - non-POSIX fail-closed path
        raise RuntimeError("process locking is unavailable") from exc
    lock_path = path.with_name(f"{path.name}.lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open("a+b") as handle:
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        except OSError as exc:
            raise RuntimeError("could not acquire the convergence-ledger lock") from exc
        try:
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def append_record(path: str | Path, record: Mapping[str, Any]) -> dict[str, Any]:
    ledger = Path(path)
    ledger.parent.mkdir(parents=True, exist_ok=True)
    with _ledger_lock(ledger):
        existing = load_records(ledger)
        predecessor = existing[-1]["record_sha256"] if existing else None
        source = dict(record)
        supplied_predecessor = source.get("previous_record_sha256")
        if supplied_predecessor not in (None, predecessor):
            raise ValueError("supplied predecessor does not match the live ledger tail")
        source["previous_record_sha256"] = predecessor
        source["record_sha256"] = None
        sealed = build_record(source)
        line = json.dumps(
            sealed,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        )
        with ledger.open("a", encoding="utf-8") as handle:
            handle.write(f"{line}\n")
            handle.flush()
            os.fsync(handle.fileno())
        return sealed


def evaluate_closure_pressure(
    active: bool,
    action: str,
    disposition: str | None,
) -> dict[str, Any]:
    if not isinstance(active, bool):
        raise TypeError("active must be boolean")
    if not isinstance(action, str) or not action:
        raise TypeError("action must be a non-empty string")
    if disposition is not None and disposition not in CLOSURE_DISPOSITIONS:
        raise ValueError(f"unsupported closure disposition: {disposition!r}")
    if not active:
        allowed = True
        reason = "closure-pressure-inactive"
    elif disposition is None:
        allowed = False
        reason = "explicit-closure-disposition-required"
    elif action == "create-routine-repair-child":
        allowed = False
        reason = "routine-repair-child-rejected"
    else:
        allowed = True
        reason = "closure-disposition-recorded"
    return {
        "active": active,
        "action": action,
        "disposition": disposition,
        "allowed": allowed,
        "reason": reason,
        "allowed_dispositions": list(CLOSURE_DISPOSITIONS),
    }
