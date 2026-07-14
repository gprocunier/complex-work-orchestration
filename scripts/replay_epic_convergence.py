"""Replay utility for epic-convergence ledger snapshots."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

from cwo_core import epic_convergence as ec

BASELINE_NONACCEPTED_SEGMENTS = 8
BASELINE_NONACCEPTED_CALLS = 117
MINIMUM_AVOIDED_SEGMENTS = 6
MINIMUM_AVOIDED_CALLS = 90
MINIMUM_CONTROL_PLANE_REDUCTION = 50.0

ACCEPTED_DISPOSITIONS = {"accepted", "retain"}
QUARANTINED_DISPOSITIONS = {
    "quarantine",
    "quarantined",
    "rejected",
    "independent-validation-required",
}

PROTECTED_REASON_TOKENS = (
    "model mismatch",
    "compaction",
    "control loss",
    "security",
    "scope out of scope mutation",
    "out of scope mutation",
    "scope/out-of-scope mutation",
    "mutation attribution",
    "contradictory telemetry",
)


def _load_text(path: str | Path) -> str:
    ledger_path = Path(path)
    with ledger_path.open("r", encoding="utf-8") as handle:
        return handle.read()


def _parse_json_or_jsonl(path: str | Path) -> list[dict[str, Any]]:
    payload = _load_text(path)
    stripped = payload.lstrip()
    if not stripped:
        return []
    try:
        parsed = json.loads(payload)
    except json.JSONDecodeError:
        records = []
        for index, raw_line in enumerate(payload.splitlines(), 1):
            line = raw_line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"invalid JSONL line {index}: {exc}") from exc
            if not isinstance(record, dict):
                raise TypeError(f"JSONL line {index} must be an object")
            records.append(record)
    else:
        if isinstance(parsed, list):
            records = parsed
        elif isinstance(parsed, dict):
            records = [parsed]
        else:
            raise TypeError("top-level JSON input must be an object or list")

    for index, record in enumerate(records, 1):
        if not isinstance(record, dict):
            raise TypeError(f"record {index} must be an object")
    return [dict(record) for record in records]


def _normalize_nested(
    raw: dict[str, Any],
    key: str,
    fields: tuple[str, ...],
) -> dict[str, int | float | None]:
    raw_value = raw.get(key)
    if raw_value is None:
        return {field: None for field in fields}
    if not isinstance(raw_value, dict):
        raise TypeError(f"{key} must be an object when present")
    unknown = set(raw_value) - set(fields)
    if unknown:
        raise ValueError(f"{key} has unknown fields: {', '.join(sorted(unknown))}")
    return {field: raw_value.get(field) for field in fields}


def _coerce_call_count(value: Any, context: str) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{context} must be a non-negative integer or null")
    if value < 0:
        raise ValueError(f"{context} must be non-negative")
    return value


def _extract_tool_calls(record: dict[str, Any]) -> tuple[int | None, str]:
    candidates = []
    usage = record.get("usage")
    if isinstance(usage, dict) and "tool_calls" in usage:
        candidates.append(("usage.tool_calls", usage.get("tool_calls")))
    observed = record.get("observed")
    if isinstance(observed, dict) and "tool_calls" in observed:
        candidates.append(("observed.tool_calls", observed.get("tool_calls")))
    aggregate = record.get("aggregate")
    if isinstance(aggregate, dict) and "tool_calls" in aggregate:
        candidates.append(("aggregate.tool_calls", aggregate.get("tool_calls")))
    if "agent_model_calls" in record:
        candidates.append(("agent_model_calls", record.get("agent_model_calls")))

    explicit = [
        (source, value)
        for source, value in candidates
        if value is not None
    ]
    if len(explicit) > 1:
        values = {value for _, value in explicit}
        if len(values) > 1:
            raise ValueError("multiple explicit tool-call sources found")
        if len(explicit) > 1:
            raise ValueError("multiple explicit tool-call sources found")

    if not explicit:
        return None, "missing"
    source, value = explicit[0]
    return _coerce_call_count(value, source), source


def _classify_category(record: dict[str, Any]) -> str:
    category = record.get("call_category")
    if category is not None:
        if category not in ec.CALL_CATEGORIES:
            raise ValueError(f"unsupported call_category: {category!r}")
        return category

    matches = []
    for field in ("lane", "phase", "event"):
        value = record.get(field)
        if value is not None:
            if not isinstance(value, str):
                raise TypeError(f"{field} must be a string when present")
            if value in ec.CALL_CATEGORIES:
                matches.append(value)

    if len(set(matches)) > 1:
        raise ValueError("contradictory category fallback values")
    if len(matches) == 1:
        return matches[0]
    return "unknown"


def _resolve_disposition(record: dict[str, Any]) -> str | None:
    if record.get("artifact_disposition") is not None:
        value = record.get("artifact_disposition")
        if value is not None and not isinstance(value, str):
            raise TypeError("artifact_disposition must be a string or null")
        return value
    if record.get("session_disposition") is not None:
        value = record.get("session_disposition")
        if value is not None and not isinstance(value, str):
            raise TypeError("session_disposition must be a string or null")
        return value
    return None


def _is_protected_stop(record: dict[str, Any]) -> bool:
    reason = record.get("reason")
    if not isinstance(reason, str):
        return False
    normalized = re.sub(r"\s+", " ", reason.lower())
    for token in PROTECTED_REASON_TOKENS:
        if token in normalized:
            return True
    return False


def _coerce_non_negative_int(value: int, minimum: int, *, name: str) -> int:
    if value < minimum:
        raise ValueError(f"{name} must be >= {minimum}")
    return value


def _coerce_non_negative_float(value: float, minimum: float, *, name: str) -> float:
    if value < minimum:
        raise ValueError(f"{name} must be >= {minimum}")
    return float(value)


def _validate_and_project_records(inputs: list[str]) -> tuple[list[dict[str, Any]], dict[str, int]]:
    records: list[dict[str, Any]] = []
    null_counts = {
        "usage": {field: 0 for field in ec.USAGE_FIELDS},
        "graph_counters": {field: 0 for field in ec.GRAPH_COUNTER_FIELDS},
        "artifact_disposition": 0,
        "call_category": 0,
        "session_id": 0,
        "tool_calls": 0,
    }
    for path in inputs:
        for index, source_record in enumerate(_parse_json_or_jsonl(path), 1):
            if not isinstance(source_record, dict):
                raise TypeError(f"{path}:{index} is not an object")
            category = _classify_category(source_record)
            if category is None:
                null_counts["call_category"] += 1
            usage = _normalize_nested(source_record, "usage", ec.USAGE_FIELDS)
            graph_counters = _normalize_nested(
                source_record,
                "graph_counters",
                ec.GRAPH_COUNTER_FIELDS,
            )
            if source_record.get("call_category") is None:
                null_counts["call_category"] += 1
            call_count, call_source = _extract_tool_calls(source_record)
            if call_source != "missing" and call_count is None:
                null_counts["tool_calls"] += 1
            if call_count is not None:
                usage["tool_calls"] = call_count

            for field in ec.USAGE_FIELDS:
                if usage.get(field) is None:
                    null_counts["usage"][field] += 1
            for field in ec.GRAPH_COUNTER_FIELDS:
                if graph_counters.get(field) is None:
                    null_counts["graph_counters"][field] += 1

            candidate = {
                "record_type": source_record.get("record_type", ec.RECORD_TYPE),
                "version": source_record.get("version", ec.RECORD_VERSION),
                "epic_id": source_record.get("epic_id"),
                "work_unit_id": source_record.get("work_unit_id"),
                "bead_id": source_record.get("bead_id"),
                "packet_id": source_record.get("packet_id"),
                "session_id": source_record.get("session_id"),
                "model": source_record.get("model"),
                "phase": source_record.get("phase"),
                "event": source_record.get("event"),
                "call_category": category,
                "usage": usage,
                "artifact_disposition": _resolve_disposition(source_record),
                "graph_counters": graph_counters,
                "timestamp": source_record.get("timestamp"),
                "previous_record_sha256": source_record.get(
                    "previous_record_sha256",
                    None,
                ),
                "record_sha256": source_record.get("record_sha256"),
            }
            if candidate["artifact_disposition"] is None:
                null_counts["artifact_disposition"] += 1
            if candidate["session_id"] is None:
                null_counts["session_id"] += 1

            if source_record.get("record_sha256") is None:
                validated = ec.build_record(candidate)
            else:
                validated = ec.validate_record(candidate)
            validated["tool_calls"] = call_count
            validated["tool_calls_source"] = call_source
            validated["_session_id"] = source_record.get("session_id")
            validated["_protected_stop"] = _is_protected_stop(source_record)
            records.append(validated)
    return records, null_counts


def _compute_summary(records: list[dict[str, Any]], null_counts: dict[str, Any]) -> dict[str, Any]:
    records_by_category = {category: 0 for category in ec.CALL_CATEGORIES}
    calls_by_category = {category: 0 for category in ec.CALL_CATEGORIES}
    unknown_call_records = 0
    accepted_segments = 0
    nonaccepted_segments = 0
    quarantined_segments = 0
    accepted_calls = 0
    nonaccepted_calls = 0
    quarantined_calls = 0
    protected_stops = 0
    protected_stop_calls = 0
    protected_stop_preserved = 0
    latest_graph_counters: dict[str, int | None] | None = None

    for record in records:
        category = record["call_category"]
        if category == "unknown":
            unknown_call_records += 1
        records_by_category[category] += 1
        calls = record["tool_calls"]
        if calls is not None:
            calls_by_category[category] += calls

        disposition = (
            (record["artifact_disposition"] or "").strip().lower() if record["artifact_disposition"] else ""
        )
        if disposition in ACCEPTED_DISPOSITIONS:
            accepted_segments += 1
            if calls is not None:
                accepted_calls += calls
        else:
            nonaccepted_segments += 1
            if calls is not None:
                nonaccepted_calls += calls

        if disposition in QUARANTINED_DISPOSITIONS:
            quarantined_segments += 1
            if calls is not None:
                quarantined_calls += calls

        if record["_protected_stop"] and disposition not in ACCEPTED_DISPOSITIONS:
            protected_stops += 1
            if calls is not None:
                protected_stop_calls += calls
            protected_stop_preserved += 1

        latest_graph_counters = record["graph_counters"]

    preventable_segments = nonaccepted_segments - protected_stops
    preventable_calls = nonaccepted_calls - protected_stop_calls

    return {
        "record_count": len(records),
        "categories": {
            "record_counts": records_by_category,
            "call_totals": calls_by_category,
        },
        "unknown_call_records": unknown_call_records,
        "accepted": {
            "segments": accepted_segments,
            "calls": accepted_calls,
        },
        "nonaccepted": {
            "segments": nonaccepted_segments,
            "calls": nonaccepted_calls,
        },
        "quarantined": {
            "segments": quarantined_segments,
            "calls": quarantined_calls,
        },
        "preventable": {
            "segments": preventable_segments,
            "calls": preventable_calls,
        },
        "protected_stops": {
            "count": protected_stops,
            "calls": protected_stop_calls,
            "preserved": protected_stop_preserved,
        },
        "latest_graph_counters": latest_graph_counters,
        "historical_null_counts": {
            "call_category": null_counts["call_category"],
            "artifact_disposition": null_counts["artifact_disposition"],
            "tool_calls": null_counts["tool_calls"],
            "usage": null_counts["usage"],
            "graph_counters": null_counts["graph_counters"],
        },
    }


def _apply_targets(summary: dict[str, Any], args: argparse.Namespace) -> dict[str, Any]:
    baseline_segments = _coerce_non_negative_int(
        args.baseline_nonaccepted_segments,
        0,
        name="baseline-nonaccepted-segments",
    )
    baseline_calls = _coerce_non_negative_int(
        args.baseline_nonaccepted_calls,
        0,
        name="baseline-nonaccepted-calls",
    )
    minimum_avoided_segments = _coerce_non_negative_int(
        args.minimum_avoided_segments,
        0,
        name="minimum-avoided-segments",
    )
    minimum_avoided_calls = _coerce_non_negative_int(
        args.minimum_avoided_calls,
        0,
        name="minimum-avoided-calls",
        )
    minimum_control_plane_reduction = _coerce_non_negative_float(
        args.minimum_control_plane_reduction,
        0.0,
        name="minimum-control-plane-reduction",
    )

    current_segments = summary["nonaccepted"]["segments"]
    current_calls = summary["nonaccepted"]["calls"]
    avoided_segments = baseline_segments - current_segments
    avoided_calls = baseline_calls - current_calls
    reduction = 0.0
    if baseline_calls:
        reduction = (avoided_calls / baseline_calls) * 100

    return {
        "baseline": {
            "nonaccepted_segments": baseline_segments,
            "nonaccepted_calls": baseline_calls,
        },
        "minimums": {
            "avoided_segments": minimum_avoided_segments,
            "avoided_calls": minimum_avoided_calls,
            "control_plane_reduction_percent": minimum_control_plane_reduction,
        },
        "results": {
            "current_nonaccepted_segments": current_segments,
            "current_nonaccepted_calls": current_calls,
            "avoided_nonaccepted_segments": avoided_segments,
            "avoided_nonaccepted_calls": avoided_calls,
            "control_plane_reduction_percent": reduction,
            "segments_target_met": avoided_segments >= minimum_avoided_segments,
            "calls_target_met": avoided_calls >= minimum_avoided_calls,
            "control_plane_reduction_target_met": reduction
            >= minimum_control_plane_reduction,
        },
    }


def run(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--input",
        action="append",
        dest="inputs",
        required=True,
        help="input path, repeated",
    )
    parser.add_argument(
        "--baseline-nonaccepted-segments",
        type=int,
        default=BASELINE_NONACCEPTED_SEGMENTS,
    )
    parser.add_argument(
        "--baseline-nonaccepted-calls",
        type=int,
        default=BASELINE_NONACCEPTED_CALLS,
    )
    parser.add_argument(
        "--minimum-avoided-segments",
        type=int,
        default=MINIMUM_AVOIDED_SEGMENTS,
    )
    parser.add_argument(
        "--minimum-avoided-calls",
        type=int,
        default=MINIMUM_AVOIDED_CALLS,
    )
    parser.add_argument(
        "--minimum-control-plane-reduction",
        type=float,
        default=MINIMUM_CONTROL_PLANE_REDUCTION,
    )

    parsed = parser.parse_args(argv)

    if any(value < 0 for value in (
        parsed.baseline_nonaccepted_segments,
        parsed.baseline_nonaccepted_calls,
        parsed.minimum_avoided_segments,
        parsed.minimum_avoided_calls,
        parsed.minimum_control_plane_reduction,
    )):
        raise SystemExit("numeric target overrides must be non-negative")

    records, null_counts = _validate_and_project_records(parsed.inputs)
    summary = _compute_summary(records, null_counts)
    summary["targets"] = _apply_targets(summary, parsed)
    print(json.dumps(summary, sort_keys=True))
    return 0


def main() -> int:
    try:
        return run()
    except (OSError, TypeError, ValueError) as exc:
        raise SystemExit(str(exc))


if __name__ == "__main__":
    raise SystemExit(main())
