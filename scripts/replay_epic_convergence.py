"""Replay utility for epic-convergence ledger snapshots."""

from __future__ import annotations

import argparse
import json
import re
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
    return Path(path).read_text(encoding="utf-8")


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
    for field in ("usage", "observed", "aggregate"):
        container = record.get(field)
        if isinstance(container, dict) and "tool_calls" in container:
            candidates.append((f"{field}.tool_calls", container.get("tool_calls")))
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
    for field in ("artifact_disposition", "session_disposition"):
        value = record.get(field)
        if value is None:
            continue
        if not isinstance(value, str):
            raise TypeError(f"{field} must be a string or null")
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


def _validate_unsealed_record(
    source: dict[str, Any], projection: dict[str, Any], usage: dict[str, Any],
) -> None:
    candidate = {field: source.get(field) for field in ec.RECORD_FIELDS}
    candidate.update(
        record_type=source.get("record_type", ec.RECORD_TYPE),
        version=source.get("version", ec.RECORD_VERSION),
        call_category=projection["call_category"],
        artifact_disposition=projection["artifact_disposition"],
        graph_counters=projection["graph_counters"],
        usage=usage,
    )
    if "delivery_accounting" in source:
        candidate["delivery_accounting"] = source["delivery_accounting"]
    ec.build_record(candidate)


def _validate_and_project_records(inputs: list[str]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
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
        for source_record in _parse_json_or_jsonl(path):
            sealed = source_record.get("record_sha256") is not None
            if sealed:
                ec.validate_record(source_record)
            category = _classify_category(source_record)
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

            for section, metrics in (("usage", usage), ("graph_counters", graph_counters)):
                for field, value in metrics.items():
                    if value is None:
                        null_counts[section][field] += 1

            projection = {
                "call_category": category,
                "tool_calls": call_count,
                "artifact_disposition": _resolve_disposition(source_record),
                "graph_counters": graph_counters,
                "delivery_accounting": source_record.get("delivery_accounting"),
                "_protected_stop": _is_protected_stop(source_record),
            }
            if projection["artifact_disposition"] is None:
                null_counts["artifact_disposition"] += 1
            if source_record.get("session_id") is None:
                null_counts["session_id"] += 1
            if not sealed:
                _validate_unsealed_record(source_record, projection, usage)
            records.append(projection)
    return records, null_counts


def _delivery_accounting_summary(records: list[dict[str, Any]]) -> dict[str, Any]:
    counts = dict.fromkeys(ec.DELIVERY_CLASSIFICATIONS, 0)
    corrective_passes: set[str] = set()
    outcomes: dict[str, set[str]] = {}
    for record in records:
        accounting = record["delivery_accounting"] or {}
        counts[accounting.get("classification", "unknown")] += 1
        if "corrective_pass_id" in accounting:
            corrective_passes.add(accounting["corrective_pass_id"])
        if "original_ref" in accounting:
            attempts = outcomes.setdefault(accounting["original_ref"], set())
            if "first_acceptance_outcome" in accounting:
                attempts.add(accounting["first_acceptance_outcome"])

    missing = sum(not observed for observed in outcomes.values())
    conflicting = sum(len(observed) > 1 for observed in outcomes.values())
    accepted = sum(observed == {"accepted"} for observed in outcomes.values())
    known_deliveries = len(outcomes)
    observed_attempts = known_deliveries - missing - conflicting
    rate = None
    if known_deliveries and observed_attempts == known_deliveries:
        rate = 100.0 * accepted / known_deliveries
    return {
        "record_counts": counts,
        "corrective_passes": len(corrective_passes),
        "first_pass": {
            "known_deliveries": known_deliveries,
            "observed_attempts": observed_attempts,
            "first_attempt_acceptances": accepted,
            "missing_attempts": missing,
            "conflicting_attempts": conflicting,
            "rate_percent": rate,
        },
    }


def _compute_summary(records: list[dict[str, Any]], null_counts: dict[str, Any]) -> dict[str, Any]:
    records_by_category: dict[str, int] = dict.fromkeys(ec.CALL_CATEGORIES, 0)
    calls_by_category: dict[str, int] = dict.fromkeys(ec.CALL_CATEGORIES, 0)
    segments = {
        key: {"segments": 0, "calls": 0} for key in ("accepted", "nonaccepted", "quarantined")
    }
    protected_stops = {"count": 0, "calls": 0, "preserved": 0}
    latest_graph_counters: dict[str, int | None] | None = None

    for record in records:
        category = record["call_category"]
        calls = record["tool_calls"] or 0
        records_by_category[category] += 1
        calls_by_category[category] += calls

        disposition = (record["artifact_disposition"] or "").strip().lower()
        accepted = disposition in ACCEPTED_DISPOSITIONS
        totals = segments["accepted" if accepted else "nonaccepted"]
        totals["segments"] += 1
        totals["calls"] += calls
        if disposition in QUARANTINED_DISPOSITIONS:
            segments["quarantined"]["segments"] += 1
            segments["quarantined"]["calls"] += calls
        if record["_protected_stop"] and not accepted:
            protected_stops["count"] += 1
            protected_stops["calls"] += calls
            protected_stops["preserved"] += 1

        latest_graph_counters = record["graph_counters"]

    return {
        "record_count": len(records),
        "delivery_accounting": _delivery_accounting_summary(records),
        "categories": {
            "record_counts": records_by_category,
            "call_totals": calls_by_category,
        },
        "unknown_call_records": records_by_category["unknown"],
        **segments,
        "preventable": {
            "segments": segments["nonaccepted"]["segments"] - protected_stops["count"],
            "calls": segments["nonaccepted"]["calls"] - protected_stops["calls"],
        },
        "protected_stops": protected_stops,
        "latest_graph_counters": latest_graph_counters,
        "historical_null_counts": {
            field: null_counts[field]
            for field in ("call_category", "artifact_disposition", "tool_calls", "usage", "graph_counters")
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
