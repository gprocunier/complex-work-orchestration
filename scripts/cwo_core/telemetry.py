from __future__ import annotations

import math
from typing import Any

from .util import artifact_hash


TELEMETRY_NUMERIC_FIELDS = {
    "agent_model_calls",
    "retry_count",
    "retries",
    "input_tokens",
    "output_tokens",
    "total_tokens",
    "active_seconds",
    "elapsed_seconds",
    "response_chars",
    "failure_reason_chars",
    "share_url_chars",
    "local_status_code",
    "local_response_chars",
    "local_error_body_chars",
    "raw_response_chars",
    "reasoning_chars",
    "prompt_chars",
    "included_artifacts_count",
    "selected_snippets_count",
    "selected_snippet_lines",
    "timeout_seconds",
    "max_input_chars",
    "return_language_finding_count",
    "unexpected_script_ratio",
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
    "review_surface_mismatch",
    "review_surface_required_evidence_missing",
    "master_review_packet_only_go_hold",
    "unicode_normalization_changed",
}
TELEMETRY_STRING_FIELDS = {
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
    "packet_output_sha256",
    "tls_verify_source",
    "tls_ca_bundle_env",
    "thinking_parser",
    "response_sanitization",
    "expected_return_language",
    "expected_return_language_source",
    "return_language_status",
}
TELEMETRY_STRING_LIST_FIELDS = {
    "telemetry_missing_reasons",
    "included_artifact_types",
    "selected_snippet_paths",
    "capability_requirements",
    "finish_reasons",
    "review_surface_mismatch_reasons",
    "workerbee_planned_lanes",
    "workerbee_actual_lanes",
    "workerbee_delegation_gap_reasons",
    "detected_letter_scripts",
}

AUDIT_NUMERIC_FIELDS = {
    "acceptance_score",
    "malpractice_score",
    "quota_remaining",
    "sabotage_score",
}
AUDIT_BOOLEAN_FIELDS = {
    "executor_external",
    "human_adjudication_required",
    "implementation_blocked",
    "peer_review_required",
    "provider_external",
    "quarantine_recommended",
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
    "packet_sha256",
    "peer_review_status",
    "previous_event_hash",
    "provider_key",
    "provider_trust_tier",
    "quota_event_type",
    "quota_stage",
    "recommended_disposition",
    "share_boundary",
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
    "workspace_mutation",
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


def sanitize_audit_event(event: dict[str, Any]) -> dict[str, Any]:
    sanitized: dict[str, Any] = {}
    for key, value in event.items():
        if key in SENSITIVE_AUDIT_FIELDS:
            continue
        if key in TELEMETRY_NUMERIC_FIELDS:
            numeric = normalize_nonnegative_number(value)
            if numeric is not None:
                sanitized[key] = numeric
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
            continue

    if "total_tokens" not in sanitized:
        input_tokens = sanitized.get("input_tokens")
        output_tokens = sanitized.get("output_tokens")
        if isinstance(input_tokens, (int, float)) and isinstance(output_tokens, (int, float)):
            sanitized["total_tokens"] = input_tokens + output_tokens
    return sanitized


def telemetry_fields(**values: Any) -> dict[str, Any]:
    return {
        key: value
        for key, value in sanitize_audit_event(values).items()
        if key in TELEMETRY_NUMERIC_FIELDS
        or key in TELEMETRY_BOOLEAN_FIELDS
        or key in TELEMETRY_STRING_FIELDS
        or key in TELEMETRY_STRING_LIST_FIELDS
    }


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
