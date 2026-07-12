from __future__ import annotations

from typing import Any


def _number(value: Any) -> int | float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return value


def _records(records: list[dict[str, Any]], kind: str, marker: str) -> list[dict[str, Any]]:
    return [record for record in records if str(record.get("telemetry_kind") or "") == kind or marker in record]


def native_progress_summary(records: list[dict[str, Any]]) -> dict[str, Any]:
    selected = _records(records, "native_progress", "native_progress_outcome")
    outcomes = {name: 0 for name in ("continue", "early-warning", "pm-realignment", "protected-stop", "completed")}
    actions = {name: 0 for name in ("packet-refinement", "architect-question", "material-split", "protected-stop")}
    for record in selected:
        outcome = str(record.get("native_progress_outcome") or "")
        action = str(record.get("native_progress_pm_action") or "")
        if outcome in outcomes:
            outcomes[outcome] += 1
        if action in actions:
            actions[action] += 1
    def total(field: str) -> int | float:
        return sum(value for record in selected if (value := _number(record.get(field))) is not None)
    return {
        "records": len(selected),
        "outcomes": outcomes,
        "pm_actions": actions,
        "planned_tool_calls_p90": total("planned_tool_calls_p90"),
        "actual_tool_calls": total("observed_tool_calls"),
        "planned_runtime_seconds_p90": total("planned_runtime_seconds_p90"),
        "actual_runtime_seconds": total("observed_runtime_seconds"),
        "observed_tokens": total("observed_tokens"),
        "context_reads": total("observed_context_reads"),
        "mutations": total("observed_mutations"),
        "tests_run": total("observed_tests_run"),
        "artifacts_completed": total("observed_artifacts_completed"),
        "retained_productive_artifacts": total("retained_productive_artifacts"),
        "pure_waste_records": sum(1 for record in selected if record.get("progress_pure_waste") is True),
        "tool_call_calibration_error": total("tool_call_calibration_error"),
        "runtime_calibration_error_seconds": total("runtime_calibration_error_seconds"),
    }


def checked_command_summary(records: list[dict[str, Any]]) -> dict[str, Any]:
    selected = _records(records, "checked_command", "checked_command_id")
    return {
        "commands": len(selected),
        "preflight_passed": sum(1 for record in selected if record.get("checked_command_preflight_status") == "passed"),
        "construction_failures": sum(1 for record in selected if record.get("checked_command_failure_class") in {"command-construction-failed", "typed-source-required"}),
        "executed": sum(1 for record in selected if record.get("checked_command_execution_started") is True),
        "quarantined": sum(1 for record in selected if record.get("checked_command_quarantine_required") is True),
        "hash_mismatches": sum(1 for record in selected if record.get("checked_command_hash_match") is False),
        "quoting_errors_prevented": sum(1 for record in selected if record.get("checked_command_quoting_error_prevented") is True),
        "avoided_retry_cycles": sum(int(value) for record in selected if (value := _number(record.get("checked_command_avoided_retry_cycles"))) is not None),
        "mutations_started": sum(1 for record in selected if record.get("checked_command_mutation_started") is True),
    }


def native_progress_details(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [dict(record) for record in _records(records, "native_progress", "native_progress_outcome")]


def checked_command_details(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [dict(record) for record in _records(records, "checked_command", "checked_command_id")]
