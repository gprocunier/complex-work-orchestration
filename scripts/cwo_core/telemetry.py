from __future__ import annotations

import math
from typing import Any

from .util import artifact_hash
from .epic_convergence import CALL_CATEGORIES, GRAPH_COUNTER_FIELDS


TELEMETRY_NUMERIC_FIELDS = {
    "agent_model_calls",
    "attempted_model_calls",
    "usable_model_calls",
    "incomplete_model_calls",
    "preflight_attempts",
    "preflight_successes",
    "post_attempts",
    "usable_post_responses",
    "incomplete_post_responses",
    "retry_count",
    "retries",
    "input_tokens",
    "cached_tokens",
    "output_tokens",
    "reasoning_tokens",
    "total_tokens",
    "active_seconds",
    "elapsed_seconds",
    "exit_status",
    "response_chars",
    "failure_reason_chars",
    "share_url_chars",
    "local_status_code",
    "local_response_chars",
    "local_error_body_chars",
    "raw_response_chars",
    "reasoning_chars",
    "final_content_chars",
    "model_preflight_response_chars",
    "model_preflight_observed_model_count",
    "model_preflight_elapsed_ms",
    "preflight_to_post_ms",
    "prompt_chars",
    "included_artifacts_count",
    "selected_snippets_count",
    "selected_snippet_lines",
    "timeout_seconds",
    "max_input_chars",
    "return_language_finding_count",
    "unexpected_script_ratio",
    "planned_tool_calls_hard",
    "interrupt_tool_calls_threshold",
    "observed_tool_calls",
    "planned_runtime_seconds_hard",
    "interrupt_runtime_seconds_threshold",
    "observed_runtime_seconds",
    "observed_context_compactions",
    "observed_full_suite_runs",
    "validation_lineage_attempt",
    "arm_to_dispatch_ms",
    "dispatch_to_first_poll_ms",
    "max_poll_gap_ms",
    "late_poll_count",
    "poll_interval_ms",
    "poll_lag_tolerance_ms",
    "planned_tool_calls_p50",
    "planned_tool_calls_p90",
    "planned_runtime_seconds_p50",
    "planned_runtime_seconds_p90",
    "observed_tokens",
    "planned_context_reads",
    "observed_context_reads",
    "planned_mutations",
    "observed_mutations",
    "observed_tests_run",
    "observed_artifacts_completed",
    "projected_tool_calls",
    "projected_runtime_seconds",
    "planned_read_to_mutation_ratio",
    "actual_read_to_mutation_ratio",
    "retained_productive_artifacts",
    "checked_command_complexity_score",
    "checked_command_exit_code",
    "checked_command_avoided_retry_cycles",
}
TELEMETRY_SIGNED_NUMERIC_FIELDS = {
    "tool_call_calibration_error",
    "runtime_calibration_error_seconds",
}
TELEMETRY_BOOLEAN_FIELDS = {
    "execution_enabled",
    "model_attestation_present",
    "model_attestation_required",
    "share_url_present",
    "expert_profile_included",
    "degraded_packet",
    "disclosure_escalation_approved",
    "allow_private_dns",
    "allow_insecure_tls",
    "tls_verify",
    "tls_ca_bundle_configured",
    "reasoning_stripped",
    "reasoning_malformed",
    "response_truncated",
    "usable_final_content",
    "provider_error_present",
    "review_surface_mismatch",
    "review_surface_required_evidence_missing",
    "master_review_packet_only_go_hold",
    "unicode_normalization_changed",
    "native_supervision_required",
    "control_action_required",
    "control_receipt_confirmed",
    "trailing_partial_record_ignored",
    "monitor_armed_before_dispatch",
    "progress_validation_complete",
    "progress_pure_waste",
    "checked_command_hash_match",
    "checked_command_execution_started",
    "checked_command_mutation_started",
    "checked_command_quarantine_required",
    "checked_command_quoting_error_prevented",
}
TELEMETRY_STRING_FIELDS = {
    "epic_id",
    "work_unit_id",
    "packet_id",
    "phase",
    "call_category",
    "event",
    "telemetry_kind",
    "telemetry_status",
    "telemetry_missing_reason",
    "telemetry_source",
    "telemetry_target_event_hash",
    "model",
    "model_label",
    "provider_family",
    "provider_retention_class",
    "job_description_label",
    "review_surface",
    "source_inspection",
    "sources_inspected",
    "sources_not_inspected",
    "independent_verification",
    "packet_reported_claims",
    "workerbee_planned_mode",
    "workerbee_planned_model",
    "workerbee_actual_mode",
    "workerbee_actual_model",
    "workerbee_delegation_status",
    "workerbee_delegation_source",
    "completion_state",
    "expert_profile",
    "expert_profile_path",
    "access_profile",
    "model_profile",
    "model_attestation_status",
    "reasoning_label",
    "endpoint_path",
    "harness",
    "environment",
    "role",
    "agent",
    "variant",
    "failure_stage",
    "failure_reason_sha256",
    "share_url_sha256",
    "prompt_sha256",
    "local_response_sha256",
    "local_error_body_sha256",
    "raw_response_sha256",
    "reasoning_sha256",
    "final_content_sha256",
    "completion_status",
    "response_model_status",
    "model_preflight_status",
    "model_preflight_required_model",
    "model_preflight_response_sha256",
    "forbidden_response_sha256",
    "provider_error_sha256",
    "packet_output_sha256",
    "tls_verify_source",
    "tls_ca_bundle_env",
    "thinking_parser",
    "response_sanitization",
    "expected_return_language",
    "expected_return_language_source",
    "return_language_status",
    "native_supervision_state_id",
    "native_supervision_decision",
    "native_supervision_status",
    "native_retry_receipt_sha256",
    "control_adapter",
    "control_action",
    "session_id",
    "control_turn_id",
    "submission_id",
    "native_progress_outcome",
    "native_progress_pm_action",
    "checked_command_id",
    "checked_command_spec_sha256",
    "checked_command_mode",
    "checked_command_preflight_status",
    "checked_command_linter",
    "checked_command_execution_status",
    "checked_command_failure_class",
    "checked_command_linted_sha256",
    "checked_command_executed_sha256",
}
TELEMETRY_STRING_LIST_FIELDS = {
    "telemetry_missing_reasons",
    "included_artifact_types",
    "selected_snippet_paths",
    "capability_requirements",
    "finish_reasons",
    "forbidden_response_fields",
    "review_surface_mismatch_reasons",
    "workerbee_planned_lanes",
    "workerbee_actual_lanes",
    "workerbee_delegation_gap_reasons",
    "detected_letter_scripts",
    "native_supervision_reasons",
    "control_receipts",
    "native_progress_reasons",
    "native_progress_warnings",
    "retained_artifacts",
    "checked_command_complexity_reasons",
    "checked_command_mutated_paths",
}

AUDIT_NUMERIC_FIELDS = {
    "acceptance_score",
    "malpractice_score",
    "quota_remaining",
    "sabotage_score",
}
AUDIT_BOOLEAN_FIELDS = {
    "automatic_selection_forbidden",
    "executor_external",
    "human_adjudication_required",
    "implementation_blocked",
    "peer_review_required",
    "provider_external",
    "quarantine_recommended",
    "swimlane_violation",
    "waiver_required",
}
AUDIT_STRING_FIELDS = {
    "audit_lock_mode",
    "bead_id",
    "dispatch_id",
    "dispatch_mode",
    "disclosure_stage",
    "epic_id",
    "event_hash",
    "event_type",
    "executor",
    "executor_key",
    "hold_classification",
    "access_profile",
    "local_profile",
    "opt_in_basis",
    "operator_approval_ref",
    "packet_sha256",
    "peer_review_status",
    "previous_event_hash",
    "provider_key",
    "provider_trust_tier",
    "quota_event_type",
    "quota_stage",
    "recommended_disposition",
    "share_boundary",
    "artifact_disposition",
    "session_disposition",
    "sol_breakfix_expiry",
    "sol_breakfix_incident_kind",
    "sol_breakfix_scope",
    "timestamp",
    "verdict",
    "waiver_reason",
}
AUDIT_STRING_LIST_FIELDS = {
    "hold_reasons",
    "provider_conflict_domains",
    "waiver_flags",
}
AUDIT_OBJECT_FIELDS = {
    "artifact_validation",
    "workspace_mutation",
}
TELEMETRY_OBJECT_FIELDS = {
    "graph_counters",
    "usage",
}
TELEMETRY_CALL_CATEGORY_FIELDS = {"call_category"}
TELEMETRY_USAGE_FIELDS = {
    "tool_calls",
    "runtime_seconds",
    "context_compactions",
    "full_suite_runs",
    "input",
    "input_tokens",
    "prompt_tokens",
    "cached_tokens",
    "output",
    "output_tokens",
    "completion_tokens",
    "reasoning_tokens",
    "total",
    "total_tokens",
}
TELEMETRY_CONVERGENCE_IDENTITY_FIELDS = {
    "epic_id",
    "work_unit_id",
    "packet_id",
    "session_id",
    "phase",
    "event",
}
WORKSPACE_MUTATION_NUMERIC_FIELDS = {
    "version",
}
WORKSPACE_MUTATION_BOOLEAN_FIELDS = {
    "include_untracked",
    "mutation_detected",
    "require_clean",
    "reverted",
    "unexpected_mutation_detected",
}
WORKSPACE_MUTATION_STRING_FIELDS = {
    "status_scope",
    "workspace_mutation_report_type",
}
WORKSPACE_MUTATION_STRING_LIST_FIELDS = {
    "allowed_paths",
}
WORKSPACE_MUTATION_CHANGE_LIST_FIELDS = {
    "allowed_mutations",
    "changes",
    "unexpected_mutations",
}
WORKSPACE_MUTATION_CHANGE_FIELDS = {
    "after",
    "before",
    "path",
}

SENSITIVE_AUDIT_FIELDS = {
    "api_key",
    "authorization",
    "base_url",
    "browser_result",
    "chain_of_thought",
    "chrome_user_data_dir",
    "config",
    "config_path",
    "content",
    "local_response",
    "manual_prompt",
    "messages",
    "model_output",
    "password",
    "prompt",
    "raw",
    "raw_prompt",
    "raw_response",
    "raw_transcript",
    "response",
    "response_body",
    "response_text",
    "secret",
    "selected_snippets",
    "selectors",
    "share_url",
    "transcript",
}


def _sanitize_nullable_short_text(value: Any) -> str | None:
    if value is None or not isinstance(value, str):
        return None
    return normalize_short_text(value)


def _nonnegative_integer_or_null(value: Any, path: str) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{path} must be a non-negative integer or null")
    if value < 0:
        raise ValueError(f"{path} must be non-negative")
    return value


def _sanitize_telemetry_usage(value: Any) -> dict[str, int | float | None] | None:
    if value is None or not isinstance(value, dict):
        return None
    unknown = sorted(set(value) - TELEMETRY_USAGE_FIELDS)
    if unknown:
        return None
    sanitized: dict[str, int | float | None] = {}
    for field, candidate in value.items():
        if candidate is None:
            sanitized[field] = None
            continue
        if field == "runtime_seconds":
            runtime_seconds = normalize_finite_number(candidate)
            if runtime_seconds is None or runtime_seconds < 0:
                return None
            sanitized[field] = runtime_seconds
            continue
        if field in {"tool_calls", "context_compactions", "full_suite_runs"}:
            try:
                sanitized[field] = _nonnegative_integer_or_null(candidate, f"usage.{field}")
            except (TypeError, ValueError):
                return None
            continue
        number = normalize_nonnegative_number(candidate)
        if number is None:
            return None
        sanitized[field] = number
    return sanitized


def _sanitize_graph_counters(value: Any) -> dict[str, int | None] | None:
    if value is None or not isinstance(value, dict):
        return None
    if sorted(set(value) - set(GRAPH_COUNTER_FIELDS)):
        return None
    sanitized: dict[str, int | None] = {}
    for field, candidate in value.items():
        try:
            sanitized[field] = _nonnegative_integer_or_null(candidate, f"graph_counters.{field}")
        except (TypeError, ValueError):
            return None
    return sanitized


def sanitize_audit_event(event: dict[str, Any]) -> dict[str, Any]:
    sanitized: dict[str, Any] = {}
    for key, value in event.items():
        if key in SENSITIVE_AUDIT_FIELDS:
            continue
        if key in TELEMETRY_SIGNED_NUMERIC_FIELDS:
            numeric = normalize_finite_number(value)
            if numeric is not None:
                sanitized[key] = numeric
            continue
        if key in TELEMETRY_NUMERIC_FIELDS:
            numeric = normalize_nonnegative_number(value)
            if numeric is not None:
                sanitized[key] = numeric
            continue
        if key in TELEMETRY_CALL_CATEGORY_FIELDS:
            if isinstance(value, str) and value in CALL_CATEGORIES:
                sanitized[key] = value
            continue
        if key in TELEMETRY_CONVERGENCE_IDENTITY_FIELDS:
            text = _sanitize_nullable_short_text(value)
            if text is not None:
                sanitized[key] = text
            continue
        if key == "usage":
            usage = _sanitize_telemetry_usage(value)
            if usage is not None:
                sanitized[key] = usage
            continue
        if key == "graph_counters":
            graph_counters = _sanitize_graph_counters(value)
            if graph_counters is not None:
                sanitized[key] = graph_counters
            continue
        if key in TELEMETRY_BOOLEAN_FIELDS:
            if isinstance(value, bool):
                sanitized[key] = value
            continue
        if key in TELEMETRY_STRING_FIELDS:
            text = normalize_short_text(value)
            if text is not None:
                sanitized[key] = text
            continue
        if key in TELEMETRY_STRING_LIST_FIELDS:
            strings = normalize_string_list(value)
            if strings:
                sanitized[key] = strings
            continue
        if key in AUDIT_NUMERIC_FIELDS:
            numeric = normalize_nonnegative_number(value)
            if numeric is not None:
                sanitized[key] = numeric
            continue
        if key in AUDIT_BOOLEAN_FIELDS:
            if isinstance(value, bool):
                sanitized[key] = value
            continue
        if key in AUDIT_STRING_FIELDS:
            text = normalize_short_text(value)
            if text is not None:
                sanitized[key] = text
            continue
        if key in AUDIT_STRING_LIST_FIELDS:
            strings = normalize_string_list(value)
            if strings:
                sanitized[key] = strings
            continue
        if key in AUDIT_OBJECT_FIELDS:
            if key == "workspace_mutation":
                workspace_mutation = sanitize_workspace_mutation(value)
                if workspace_mutation is not None:
                    sanitized[key] = workspace_mutation
            elif key == "artifact_validation":
                artifact_validation = sanitize_artifact_validation(value)
                if artifact_validation is not None:
                    sanitized[key] = artifact_validation
            continue

    if "total_tokens" not in sanitized:
        input_tokens = sanitized.get("input_tokens")
        output_tokens = sanitized.get("output_tokens")
        if isinstance(input_tokens, (int, float)) and isinstance(output_tokens, (int, float)):
            sanitized["total_tokens"] = input_tokens + output_tokens
    return sanitized


def sanitize_artifact_validation(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        return None
    eligible = value.get("eligible")
    max_attempts = value.get("max_attempts")
    attempts_used = value.get("attempts_used")
    outcome = value.get("outcome")
    reason = normalize_short_text(value.get("reason"))
    if not isinstance(eligible, bool):
        return None
    if max_attempts != 1 or attempts_used not in {0, 1}:
        return None
    if outcome not in {"not-run", "passed", "failed"} or reason is None:
        return None
    if (attempts_used == 0 and outcome != "not-run") or (
        attempts_used == 1 and (outcome not in {"passed", "failed"} or eligible is not False)
    ):
        return None
    return {
        "eligible": eligible,
        "max_attempts": max_attempts,
        "attempts_used": attempts_used,
        "outcome": outcome,
        "reason": reason,
    }


def telemetry_fields(**values: Any) -> dict[str, Any]:
    return {
        key: value
        for key, value in sanitize_audit_event(values).items()
        if key in TELEMETRY_NUMERIC_FIELDS
        or key in TELEMETRY_BOOLEAN_FIELDS
        or key in TELEMETRY_STRING_FIELDS
        or key in TELEMETRY_OBJECT_FIELDS
        or key in TELEMETRY_STRING_LIST_FIELDS
        or key in TELEMETRY_CALL_CATEGORY_FIELDS
        or key in TELEMETRY_CONVERGENCE_IDENTITY_FIELDS
    }


def normalize_finite_number(value: Any) -> int | float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    number = float(value)
    if not math.isfinite(number):
        return None
    return int(number) if number.is_integer() else number


def normalize_nonnegative_number(value: Any) -> int | float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if value >= 0 else None
    if isinstance(value, float) and math.isfinite(value) and value >= 0:
        return value
    return None


def normalize_short_text(value: Any, *, limit: int = 240) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    text = " ".join(text.split())
    if len(text) > limit:
        return text[: limit - 15] + "...[truncated]"
    return text


def normalize_string_list(value: Any, *, limit: int = 50) -> list[str]:
    if not isinstance(value, list):
        return []
    strings: list[str] = []
    for item in value[:limit]:
        text = normalize_short_text(item)
        if text is not None:
            strings.append(text)
    return strings


def sanitize_workspace_mutation(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        return None
    sanitized: dict[str, Any] = {}
    for key in WORKSPACE_MUTATION_NUMERIC_FIELDS:
        numeric = normalize_nonnegative_number(value.get(key))
        if numeric is not None:
            sanitized[key] = numeric
    for key in WORKSPACE_MUTATION_BOOLEAN_FIELDS:
        candidate = value.get(key)
        if isinstance(candidate, bool):
            sanitized[key] = candidate
    for key in WORKSPACE_MUTATION_STRING_FIELDS:
        text = normalize_short_text(value.get(key))
        if text is not None:
            sanitized[key] = text
    for key in WORKSPACE_MUTATION_STRING_LIST_FIELDS:
        strings = normalize_string_list(value.get(key))
        if strings:
            sanitized[key] = strings
    for key in WORKSPACE_MUTATION_CHANGE_LIST_FIELDS:
        changes = sanitize_workspace_mutation_changes(value.get(key))
        if changes:
            sanitized[key] = changes
    return sanitized or None


def sanitize_workspace_mutation_changes(value: Any) -> list[dict[str, str | None]]:
    if not isinstance(value, list):
        return []
    sanitized: list[dict[str, str | None]] = []
    for item in value:
        if not isinstance(item, dict):
            continue
        change: dict[str, str | None] = {}
        for key in WORKSPACE_MUTATION_CHANGE_FIELDS:
            candidate = item.get(key)
            if candidate is None:
                change[key] = None
                continue
            text = normalize_short_text(candidate)
            if text is not None:
                change[key] = text
        if change:
            sanitized.append(change)
    return sanitized


def safe_text_hash(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value)
    if not text:
        return None
    return artifact_hash(text)
