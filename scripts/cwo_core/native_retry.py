"""Pure bounded retry eligibility and authorization contracts."""

from __future__ import annotations

import copy
import hashlib
import json
from collections.abc import Mapping
from typing import Any


RETRY_AUTHORIZATION_TYPE = "cwo-native-retry-authorization"
RETRY_AUTHORIZATION_VERSION = 1
RETRY_ELIGIBILITY_TYPE = "cwo-native-retry-eligibility"
IMMUTABLE_WORK_FIELDS = (
    "bead_id",
    "lane",
    "requested_model",
    "scope",
    "acceptance_checks",
    "budget",
    "return_contract",
    "work_plan",
)


def _mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{label} must be an object")
    return value


def _nonempty(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _integer(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def canonical_work_payload(packet: Mapping[str, Any]) -> dict[str, Any]:
    source = _mapping(packet, "packet")
    missing = [field for field in IMMUTABLE_WORK_FIELDS if field not in source]
    if missing:
        raise ValueError("packet missing immutable work field(s): " + ", ".join(missing))
    if not _nonempty(source.get("bead_id")) or not _nonempty(source.get("lane")) or not _nonempty(source.get("requested_model")):
        raise ValueError("packet work identity fields must be non-empty strings")
    if not isinstance(source.get("scope"), Mapping):
        raise ValueError("packet.scope must be an object")
    if not isinstance(source.get("acceptance_checks"), list) or not source["acceptance_checks"] or not all(_nonempty(item) for item in source["acceptance_checks"]):
        raise ValueError("packet.acceptance_checks must be non-empty strings")
    if not isinstance(source.get("budget"), Mapping):
        raise ValueError("packet.budget must be an object")
    if not isinstance(source.get("return_contract"), Mapping):
        raise ValueError("packet.return_contract must be an object")
    if not isinstance(source.get("work_plan"), Mapping):
        raise ValueError("packet.work_plan must be an object")
    return copy.deepcopy({field: source[field] for field in IMMUTABLE_WORK_FIELDS})


def canonical_work_sha256(packet: Mapping[str, Any]) -> str:
    return hashlib.sha256(_canonical(canonical_work_payload(packet)).encode("ascii")).hexdigest()


def _usage(source: Mapping[str, Any], label: str) -> dict[str, int]:
    result: dict[str, int] = {}
    for field in ("tool_calls", "runtime_seconds"):
        value = source.get(field, 0)
        if not _number(value) or value < 0:
            raise ValueError(f"{label}.{field} must be a non-negative number")
        result[field] = int(value)
    return result


def evaluate_retry_eligibility(
    packet: Mapping[str, Any],
    supervision_state: Mapping[str, Any],
    workspace_report: Mapping[str, Any],
    semantic_result: Mapping[str, Any],
    recovery_policy: Mapping[str, Any],
) -> dict[str, Any]:
    packet = _mapping(packet, "packet")
    state = _mapping(supervision_state, "supervision_state")
    workspace = _mapping(workspace_report, "workspace_report")
    semantic = _mapping(semantic_result, "semantic_result")
    policy = _mapping(recovery_policy, "recovery_policy")
    reasons: list[str] = []

    if policy.get("enabled") is not True:
        reasons.append("recovery-disabled")
    max_retries = policy.get("max_retries")
    if not _integer(max_retries) or max_retries != 1:
        reasons.append("invalid-retry-policy")
        max_retries = 0
    eligible_statuses = policy.get("eligible_semantic_statuses")
    eligible_reasons = policy.get("eligible_interrupt_reasons")
    if not isinstance(eligible_statuses, list) or not all(_nonempty(item) for item in eligible_statuses):
        reasons.append("invalid-retry-policy")
        eligible_statuses = []
    if not isinstance(eligible_reasons, list) or not all(_nonempty(item) for item in eligible_reasons):
        reasons.append("invalid-retry-policy")
        eligible_reasons = []

    if state.get("decision") != "interrupt":
        reasons.append("supervisor-not-interrupted")
    state_reasons = state.get("reasons")
    if not isinstance(state_reasons, list) or not state_reasons or not all(_nonempty(item) for item in state_reasons):
        reasons.append("invalid-supervisor-reasons")
        state_reasons = []
    elif any(item not in eligible_reasons for item in state_reasons):
        reasons.append("ineligible-interrupt-reason")

    if state.get("requested_model") != packet.get("requested_model"):
        reasons.append("model-mismatch")
    timing = state.get("control_timing")
    if not isinstance(timing, Mapping) or timing.get("monitor_armed_before_dispatch") is not True or timing.get("late_poll_count") != 0:
        reasons.append("control-loss")

    observed = _mapping(state.get("observed", {}), "supervision_state.observed")
    current_usage = _usage(observed, "supervision_state.observed")
    if observed.get("context_compactions") != 0:
        reasons.append("context-compaction")
    if observed.get("full_suite_runs") != 0:
        reasons.append("full-suite-run")

    for field in ("mutation_detected", "unexpected_mutation_detected", "attribution_ambiguous", "incomplete"):
        if workspace.get(field) is not False:
            reasons.append(f"workspace-{field.replace('_', '-')}")
    if semantic.get("trusted") is not True:
        reasons.append("untrusted-semantic-evidence")
    if semantic.get("artifact_accepted") is not False:
        reasons.append("artifact-already-accepted")
    if semantic.get("contradiction") is not False:
        reasons.append("semantic-contradiction")
    if semantic.get("status") not in eligible_statuses:
        reasons.append("ineligible-semantic-status")

    recovery = state.get("recovery", {})
    if not isinstance(recovery, Mapping):
        reasons.append("invalid-recovery-state")
        recovery = {}
    attempt = recovery.get("attempt", 0)
    if not _integer(attempt) or attempt < 0:
        reasons.append("invalid-recovery-attempt")
        attempt = max_retries
    if attempt >= max_retries:
        reasons.append("retry-exhausted")
    cumulative_before = _usage(
        recovery.get("cumulative_usage", {}) if isinstance(recovery.get("cumulative_usage", {}), Mapping) else {},
        "supervision_state.recovery.cumulative_usage",
    )
    cumulative = {
        "tool_calls": cumulative_before["tool_calls"] + current_usage["tool_calls"],
        "runtime_seconds": cumulative_before["runtime_seconds"] + current_usage["runtime_seconds"],
    }

    work_plan = _mapping(packet.get("work_plan"), "packet.work_plan")
    allowance = _mapping(work_plan.get("aggregate_allowance"), "packet.work_plan.aggregate_allowance")
    remaining: dict[str, int] = {}
    for usage_field, allowance_field in (("tool_calls", "tool_calls_hard"), ("runtime_seconds", "runtime_seconds_hard")):
        limit = allowance.get(allowance_field)
        if not _integer(limit) or limit < 0:
            reasons.append("invalid-aggregate-allowance")
            limit = 0
        remaining[usage_field] = int(limit) - cumulative[usage_field]
        if remaining[usage_field] < 0:
            reasons.append("aggregate-allowance-exhausted")

    budget = _mapping(packet.get("budget"), "packet.budget")
    retry_budget = {
        "tool_calls": budget.get("tool_calls_hard"),
        "runtime_seconds": budget.get("runtime_seconds_hard"),
    }
    for field, value in retry_budget.items():
        if not _integer(value) or value < 0:
            reasons.append("invalid-retry-budget")
        elif value > remaining[field]:
            reasons.append("insufficient-aggregate-retry-budget")

    reasons = sorted(set(reasons))
    return {
        "result_type": RETRY_ELIGIBILITY_TYPE,
        "version": RETRY_AUTHORIZATION_VERSION,
        "eligible": not reasons,
        "reasons": reasons,
        "work_sha256": canonical_work_sha256(packet),
        "attempt": attempt,
        "next_attempt": attempt + 1,
        "cumulative_usage": cumulative,
        "remaining_before_retry": remaining,
        "retry_budget": retry_budget,
        "next_action": "spawn-fresh-native-retry" if not reasons else "protected-stop",
    }


def build_retry_authorization(
    parent_packet: Mapping[str, Any],
    retry_packet: Mapping[str, Any],
    supervision_state: Mapping[str, Any],
    workspace_report: Mapping[str, Any],
    semantic_result: Mapping[str, Any],
    recovery_policy: Mapping[str, Any],
    fresh_attestation: Mapping[str, Any],
) -> dict[str, Any]:
    eligibility = evaluate_retry_eligibility(
        parent_packet,
        supervision_state,
        workspace_report,
        semantic_result,
        recovery_policy,
    )
    if not eligibility["eligible"]:
        raise ValueError("retry is ineligible: " + ", ".join(eligibility["reasons"]))
    if canonical_work_sha256(retry_packet) != eligibility["work_sha256"]:
        raise ValueError("retry packet immutable work hash mismatch")

    state = _mapping(supervision_state, "supervision_state")
    parent_packet = _mapping(parent_packet, "parent_packet")
    retry_packet = _mapping(retry_packet, "retry_packet")
    attestation = _mapping(fresh_attestation, "fresh_attestation")
    required_attestation = {
        "session_id",
        "requested_model",
        "attested_model",
        "attestation_source",
        "tool_calls",
        "context_compactions",
        "closure_receipt",
        "tool_surface_id",
    }
    if set(attestation) != required_attestation:
        raise ValueError("fresh_attestation fields do not match the strict contract")
    for field in ("session_id", "requested_model", "attested_model", "attestation_source", "tool_surface_id"):
        if not _nonempty(attestation.get(field)):
            raise ValueError(f"fresh_attestation.{field} must be a non-empty string")
    if attestation["session_id"] == state.get("session_id"):
        raise ValueError("retry requires a fresh session")
    if attestation["requested_model"] != parent_packet.get("requested_model") or attestation["attested_model"] != parent_packet.get("requested_model"):
        raise ValueError("fresh retry model attestation mismatch")
    if attestation["attestation_source"] != "trusted-session-jsonl":
        raise ValueError("fresh retry attestation source is not trusted")
    if attestation["tool_calls"] != 0 or not _integer(attestation["tool_calls"]):
        raise ValueError("fresh retry attestation must use zero tools")
    if attestation["context_compactions"] != 0 or not _integer(attestation["context_compactions"]):
        raise ValueError("fresh retry attestation must have zero compactions")
    if attestation["closure_receipt"] is not True:
        raise ValueError("fresh retry attestation requires closure receipt")

    parent_packet_id = parent_packet.get("packet_id")
    retry_packet_id = retry_packet.get("packet_id")
    if not _nonempty(parent_packet_id) or not _nonempty(retry_packet_id) or parent_packet_id == retry_packet_id:
        raise ValueError("retry packet requires a distinct packet_id")
    body = {
        "receipt_type": RETRY_AUTHORIZATION_TYPE,
        "version": RETRY_AUTHORIZATION_VERSION,
        "parent_packet_id": parent_packet_id,
        "retry_packet_id": retry_packet_id,
        "bead_id": parent_packet["bead_id"],
        "requested_model": parent_packet["requested_model"],
        "attested_model": attestation["attested_model"],
        "parent_session_id": state["session_id"],
        "retry_session_id": attestation["session_id"],
        "tool_surface_id": attestation["tool_surface_id"],
        "attestation_source": attestation["attestation_source"],
        "work_sha256": eligibility["work_sha256"],
        "attempt_from": eligibility["attempt"],
        "attempt_to": eligibility["next_attempt"],
        "cumulative_usage": eligibility["cumulative_usage"],
        "remaining_before_retry": eligibility["remaining_before_retry"],
        "retry_budget": eligibility["retry_budget"],
        "authority": "cwo-native-supervisor-evidence",
        "decision": "authorize-one-fresh-retry",
    }
    body["receipt_sha256"] = hashlib.sha256(_canonical(body).encode("ascii")).hexdigest()
    errors = validate_retry_authorization(body)
    if errors:
        raise ValueError("retry authorization validation failed: " + ", ".join(errors))
    return body


def validate_retry_authorization(receipt: Any) -> list[str]:
    if not isinstance(receipt, Mapping):
        return ["receipt must be an object"]
    required = {
        "receipt_type",
        "version",
        "parent_packet_id",
        "retry_packet_id",
        "bead_id",
        "requested_model",
        "attested_model",
        "parent_session_id",
        "retry_session_id",
        "tool_surface_id",
        "attestation_source",
        "work_sha256",
        "attempt_from",
        "attempt_to",
        "cumulative_usage",
        "remaining_before_retry",
        "retry_budget",
        "authority",
        "decision",
        "receipt_sha256",
    }
    errors: list[str] = []
    if set(receipt) != required:
        errors.append("receipt fields do not match the strict contract")
        return errors
    if receipt.get("receipt_type") != RETRY_AUTHORIZATION_TYPE:
        errors.append("receipt_type mismatch")
    if receipt.get("version") != RETRY_AUTHORIZATION_VERSION:
        errors.append("version mismatch")
    for field in ("parent_packet_id", "retry_packet_id", "bead_id", "requested_model", "attested_model", "parent_session_id", "retry_session_id", "tool_surface_id", "attestation_source", "work_sha256", "authority", "decision", "receipt_sha256"):
        if not _nonempty(receipt.get(field)):
            errors.append(f"{field} must be a non-empty string")
    if receipt.get("parent_packet_id") == receipt.get("retry_packet_id"):
        errors.append("retry_packet_id must differ from parent_packet_id")
    if receipt.get("parent_session_id") == receipt.get("retry_session_id"):
        errors.append("retry_session_id must differ from parent_session_id")
    if receipt.get("requested_model") != receipt.get("attested_model"):
        errors.append("attested_model mismatch")
    if receipt.get("attestation_source") != "trusted-session-jsonl":
        errors.append("attestation_source mismatch")
    if receipt.get("attempt_from") != 0 or receipt.get("attempt_to") != 1:
        errors.append("retry attempt lineage must be 0 to 1")
    if receipt.get("authority") != "cwo-native-supervisor-evidence":
        errors.append("authority mismatch")
    if receipt.get("decision") != "authorize-one-fresh-retry":
        errors.append("decision mismatch")
    for field in ("cumulative_usage", "remaining_before_retry", "retry_budget"):
        value = receipt.get(field)
        if not isinstance(value, Mapping) or set(value) != {"tool_calls", "runtime_seconds"}:
            errors.append(f"{field} must contain tool_calls and runtime_seconds")
            continue
        for item in value.values():
            if not _integer(item) or item < 0:
                errors.append(f"{field} values must be non-negative integers")
                break
    for field in ("work_sha256", "receipt_sha256"):
        value = receipt.get(field)
        if not isinstance(value, str) or len(value) != 64 or any(char not in "0123456789abcdef" for char in value):
            errors.append(f"{field} must be lowercase SHA-256")
    if not errors:
        body = dict(receipt)
        actual = body.pop("receipt_sha256")
        expected = hashlib.sha256(_canonical(body).encode("ascii")).hexdigest()
        if actual != expected:
            errors.append("receipt_sha256 mismatch")
    return errors
