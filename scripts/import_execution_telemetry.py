#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import math
import sys
from pathlib import Path
from typing import Any

from cwo_core.audit import iter_audit_events, record_audit_event
from cwo_core.paths import AUDIT_LOG
from cwo_core.telemetry import SENSITIVE_AUDIT_FIELDS, telemetry_fields
from cwo_core.waivers import add_waiver_reason_argument, require_waiver_reason


NUMERIC_FIELDS = {
    "agent_model_calls",
    "retry_count",
    "retries",
    "input_tokens",
    "output_tokens",
    "total_tokens",
    "active_seconds",
    "elapsed_seconds",
    "prompt_chars",
}
STRING_FIELDS = {
    "dispatch_id",
    "bead_id",
    "executor",
    "executor_key",
    "provider",
    "provider_key",
    "provider_family",
    "provider_retention_class",
    "model",
    "model_label",
    "job_description_label",
    "expert_profile",
    "expert_profile_path",
    "telemetry_missing_reason",
    "telemetry_source",
}
LIST_FIELDS = {"telemetry_missing_reasons"}
ALLOWED_FIELDS = NUMERIC_FIELDS | STRING_FIELDS | LIST_FIELDS | {"usage"}
DISPATCH_EVENT_TYPES = {
    "chatgpt_browser_dispatch",
    "dispatch",
    "dispatch_prepared",
    "external_manual_dispatch",
    "local_worker_dispatch",
    "manual_dispatch",
    "work_dispatched",
}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Import explicit model usage telemetry sidecars into the CWO audit log."
    )
    parser.add_argument("--file", required=True, help="Telemetry sidecar JSON file.")
    parser.add_argument("--audit-file", help="Audit JSONL path. Defaults to .orchestration-audit/audit.jsonl.")
    parser.add_argument("--allow-unmatched", action="store_true", help="Record imports without a matching dispatch audit event.")
    parser.add_argument("--dry-run", action="store_true", help="Validate and render events without appending to the audit log.")
    parser.add_argument("--json", action="store_true", help="Print JSON summary.")
    add_waiver_reason_argument(parser)
    args = parser.parse_args(argv)
    require_waiver_reason(args, ["allow_unmatched"])

    audit_file = Path(args.audit_file) if args.audit_file else AUDIT_LOG
    try:
        records, source_label = load_sidecar(Path(args.file))
        existing_events = iter_audit_events(audit_file) if audit_file.exists() else []
        imports = [
            build_import_event(
                record,
                existing_events,
                source_label=source_label,
                allow_unmatched=args.allow_unmatched,
                waiver_reason=args.waiver_reason,
            )
            for record in records
        ]
        recorded = [] if args.dry_run else [record_audit_event(event, audit_file) for event in imports]
    except (OSError, ValueError, json.JSONDecodeError, SystemExit) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    result = {
        "result_type": "cwo-execution-telemetry-import",
        "dry_run": bool(args.dry_run),
        "audit_file": str(audit_file),
        "imported": len(imports),
        "events": recorded or imports,
    }
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        action = "validated" if args.dry_run else "imported"
        print(f"{action} {len(imports)} telemetry record(s) into {audit_file}")
    return 0


def load_sidecar(path: Path) -> tuple[list[dict[str, Any]], str]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    source_label = str(path)
    if isinstance(payload, dict) and isinstance(payload.get("source_label"), str):
        source_label = payload["source_label"]
    if isinstance(payload, dict) and isinstance(payload.get("records"), list):
        raw_records = payload["records"]
    elif isinstance(payload, list):
        raw_records = payload
    elif isinstance(payload, dict):
        raw_records = [payload]
    else:
        raise ValueError(f"{path}: telemetry sidecar must be an object, array, or object with records")
    records = []
    for index, raw_record in enumerate(raw_records, start=1):
        if not isinstance(raw_record, dict):
            raise ValueError(f"{path}: record {index} must be an object")
        records.append(normalize_import_record(raw_record, path=path, index=index))
    if not records:
        raise ValueError(f"{path}: telemetry sidecar contains no records")
    return records, source_label


def normalize_import_record(record: dict[str, Any], *, path: Path, index: int) -> dict[str, Any]:
    unknown = sorted(set(record) - ALLOWED_FIELDS - {"source_label"})
    sensitive = sorted(key for key in record if key in SENSITIVE_AUDIT_FIELDS)
    if sensitive:
        raise ValueError(f"{path}: record {index} contains sensitive field(s): {', '.join(sensitive)}")
    if unknown:
        raise ValueError(f"{path}: record {index} contains unsupported field(s): {', '.join(unknown)}")

    normalized: dict[str, Any] = {}
    for field in STRING_FIELDS:
        text = _short_text(record.get(field))
        if text is not None:
            normalized[field] = text
    for field in NUMERIC_FIELDS:
        if field in record:
            normalized[field] = _nonnegative_number(record[field], path=path, index=index, field=field)
    for field in LIST_FIELDS:
        if field in record:
            if not isinstance(record[field], list):
                raise ValueError(f"{path}: record {index} field {field} must be an array")
            values = [_short_text(item) for item in record[field]]
            normalized[field] = [item for item in values if item]

    usage = record.get("usage")
    if usage is not None:
        if not isinstance(usage, dict):
            raise ValueError(f"{path}: record {index} field usage must be an object")
        _copy_usage_number(usage, normalized, "input_tokens", ("input_tokens", "prompt_tokens", "input"))
        _copy_usage_number(usage, normalized, "output_tokens", ("output_tokens", "completion_tokens", "output"))
        _copy_usage_number(usage, normalized, "total_tokens", ("total_tokens", "total"))

    if not normalized.get("dispatch_id") and not normalized.get("bead_id"):
        raise ValueError(f"{path}: record {index} must include dispatch_id or bead_id")
    if not any(field in normalized for field in NUMERIC_FIELDS | {"telemetry_missing_reason", "telemetry_missing_reasons"}):
        raise ValueError(f"{path}: record {index} must include telemetry values or missing reasons")
    return normalized


def build_import_event(
    record: dict[str, Any],
    existing_events: list[dict[str, Any]],
    *,
    source_label: str,
    allow_unmatched: bool,
    waiver_reason: str = "",
) -> dict[str, Any]:
    target = resolve_target(record, existing_events)
    if target is None and not allow_unmatched:
        key = record.get("dispatch_id") or record.get("bead_id")
        raise ValueError(f"no matching dispatch audit event for telemetry import {key!r}")

    dispatch_id = record.get("dispatch_id") or (target or {}).get("dispatch_id")
    bead_id = record.get("bead_id") or (target or {}).get("bead_id")
    event = {
        "event_type": "execution_telemetry_import",
        "dispatch_id": dispatch_id,
        "bead_id": bead_id,
        "executor_key": record.get("executor_key") or record.get("executor") or (target or {}).get("executor_key") or (target or {}).get("executor"),
        "provider_key": record.get("provider_key") or record.get("provider") or (target or {}).get("provider_key") or (target or {}).get("provider"),
        "dispatch_mode": (target or {}).get("dispatch_mode"),
        "telemetry_target_event_hash": (target or {}).get("event_hash"),
        "waiver_required": bool(allow_unmatched and target is None),
        "waiver_flags": ["--allow-unmatched"] if allow_unmatched and target is None else [],
        "waiver_reason": waiver_reason if allow_unmatched and target is None else None,
        **telemetry_fields(
            telemetry_kind="usage_import",
            telemetry_status="imported",
            telemetry_source=record.get("telemetry_source") or source_label,
            agent_model_calls=record.get("agent_model_calls"),
            retry_count=record.get("retry_count") if "retry_count" in record else record.get("retries"),
            retries=record.get("retries"),
            input_tokens=record.get("input_tokens"),
            output_tokens=record.get("output_tokens"),
            total_tokens=record.get("total_tokens"),
            active_seconds=record.get("active_seconds"),
            elapsed_seconds=record.get("elapsed_seconds"),
            telemetry_missing_reason=record.get("telemetry_missing_reason"),
            telemetry_missing_reasons=record.get("telemetry_missing_reasons"),
            model=record.get("model"),
            model_label=record.get("model_label"),
            provider_family=record.get("provider_family") or (target or {}).get("provider_family"),
            provider_retention_class=record.get("provider_retention_class") or (target or {}).get("provider_retention_class"),
            job_description_label=record.get("job_description_label") or (target or {}).get("job_description_label"),
            expert_profile=record.get("expert_profile") or (target or {}).get("expert_profile"),
            expert_profile_path=record.get("expert_profile_path") or (target or {}).get("expert_profile_path"),
        ),
    }
    return {key: value for key, value in event.items() if value not in [None, "", []]}


def resolve_target(record: dict[str, Any], existing_events: list[dict[str, Any]]) -> dict[str, Any] | None:
    dispatch_id = record.get("dispatch_id")
    bead_id = record.get("bead_id")
    candidates = [event for event in existing_events if is_dispatch_target(event)]
    if dispatch_id:
        matches = [event for event in candidates if event.get("dispatch_id") == dispatch_id]
        if matches:
            return matches[-1]
    if bead_id:
        matches = [event for event in candidates if event.get("bead_id") == bead_id]
        if len(matches) == 1:
            return matches[0]
        if len(matches) > 1:
            raise ValueError(f"bead_id {bead_id!r} matches multiple dispatch events; provide dispatch_id")
    return None


def is_dispatch_target(event: dict[str, Any]) -> bool:
    event_type = str(event.get("event_type") or "").strip().lower()
    telemetry_kind = str(event.get("telemetry_kind") or "").strip().lower()
    if event_type == "execution_telemetry_import" or telemetry_kind == "usage_import":
        return False
    return event_type in DISPATCH_EVENT_TYPES or event_type.endswith("_dispatch")


def _copy_usage_number(usage: dict[str, Any], normalized: dict[str, Any], target: str, keys: tuple[str, ...]) -> None:
    if target in normalized:
        return
    for key in keys:
        if key in usage:
            normalized[target] = _nonnegative_number(usage[key], path=Path("<usage>"), index=0, field=key)
            return


def _nonnegative_number(value: Any, *, path: Path, index: int, field: str) -> int | float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(float(value)) or value < 0:
        raise ValueError(f"{path}: record {index} field {field} must be a non-negative number")
    return value


def _short_text(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    return " ".join(text.split())


if __name__ == "__main__":
    raise SystemExit(main())
