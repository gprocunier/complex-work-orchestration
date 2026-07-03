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
    "included_artifacts_count",
    "selected_snippets_count",
    "selected_snippet_lines",
    "timeout_seconds",
    "max_input_chars",
}
TELEMETRY_BOOLEAN_FIELDS = {
    "execution_enabled",
    "model_attestation_present",
    "model_attestation_required",
    "share_url_present",
    "expert_profile_included",
    "degraded_packet",
    "disclosure_escalation_approved",
}
TELEMETRY_STRING_FIELDS = {
    "telemetry_kind",
    "telemetry_status",
    "telemetry_missing_reason",
    "model",
    "model_label",
    "provider_family",
    "provider_retention_class",
    "job_description_label",
    "expert_profile",
    "expert_profile_path",
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
    "local_response_sha256",
    "local_error_body_sha256",
    "packet_output_sha256",
}
TELEMETRY_STRING_LIST_FIELDS = {
    "telemetry_missing_reasons",
    "included_artifact_types",
    "selected_snippet_paths",
    "capability_requirements",
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
        sanitized[key] = value

    if "total_tokens" not in sanitized:
        input_tokens = sanitized.get("input_tokens")
        output_tokens = sanitized.get("output_tokens")
        if isinstance(input_tokens, (int, float)) or isinstance(output_tokens, (int, float)):
            sanitized["total_tokens"] = (input_tokens or 0) + (output_tokens or 0)
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


def safe_text_hash(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value)
    if not text:
        return None
    return artifact_hash(text)
