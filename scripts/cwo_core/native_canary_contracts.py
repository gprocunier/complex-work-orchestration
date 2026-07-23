"""Strict contracts for trusted native canary steering and materialization."""

from __future__ import annotations

from contextlib import contextmanager
import datetime as dt
import fcntl
import hashlib
import json
import math
import os
from pathlib import Path
import re
import shlex
from typing import Any, Iterable, Iterator, Mapping
import uuid

from .util import atomic_write_text
from .native_stop_scope import (
    VerifiedScopeAuthority,
    build_stop_metadata,
    continuation_path,
    policy_scope_authority,
    validate_scope_authority,
    verify_operator_scope_directive,
)


STEERING_RECEIPT_TYPE_V1 = "cwo-steering-receipt:v1"
STEERING_RECEIPT_TYPE = "cwo-steering-receipt:v2"
MATERIALIZATION_EVIDENCE_TYPE = "cwo-native-session-materialization-evidence:v4"
CANARY_AUTHORIZATION_TYPE = "cwo-native-canary-authorization-state:v1"
CANARY_AUTHORIZATION_TYPE_V2 = "cwo-native-canary-authorization-state:v2"
STEERING_RECEIPT_SCHEMA_V1 = "schemas/native-steering-receipt.schema.json"
STEERING_RECEIPT_SCHEMA = "schemas/native-steering-receipt-v2.schema.json"
MATERIALIZATION_EVIDENCE_SCHEMA = (
    "schemas/native-session-materialization-evidence.schema.json"
)
CANARY_AUTHORIZATION_SCHEMA = "schemas/native-canary-authorization-state.schema.json"
CANARY_AUTHORIZATION_SCHEMA_V2 = (
    "schemas/native-canary-authorization-state-v2.schema.json"
)
FULL_AUTO_STOP_RESOLUTION_FIELDS = {
    "schema",
    "gate",
    "steering_receipt_canonical_sha256",
    "resolved_findings",
    "unresolved_high_severity_findings",
    "post_resolution_commit",
    "resolution_evidence_sha256",
    "pre_live_reconfirmation_required",
}
FULL_AUTO_FINDING_FIELDS = {"code", "severity", "status"}

HASH_RE = re.compile(r"^[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
ISO_MINIMUM = dt.datetime.min.replace(tzinfo=dt.timezone.utc)
BOUNDARY_FIELDS = {
    "record_count",
    "byte_offset",
    "boundary_sha256",
    "invalid_record_count",
    "trailing_partial",
}
OBSERVATION_FIELDS = {
    "observed_at",
    "boundary",
    "session_source_identity_sha256",
    "connection_epoch_sha256",
    "notification_sequence",
    "notification_received_monotonic_ns",
    "notification_started_at_ms",
    "turn_context_record_index",
    "function_call_record_index",
    "command_item_id_sha256",
    "function_call_id_sha256",
    "rendered_command_sha256",
    "execution_correlation_sha256",
    "notification_command_semantic_match",
    "notification_workspace_match",
    "command_source",
    "command_status",
    "started_event_count",
    "function_call_count",
    "completed_event_count",
    "paired_result_count",
    "competing_call_count",
    "terminal_event_count",
    "failed_event_count",
    "declined_event_count",
    "ambiguous_event_count",
}
CONTROL_OBSERVATION_MAX = 192
CONTROL_OBSERVATION_MAX_GAP_MS = 1000
CONTROL_OBSERVATION_PHASES = (
    "materialization",
    "pre-interrupt",
    "interrupt-confirmation",
    "terminal",
)
CONTROL_OBSERVATION_FIELDS = {
    "ordinal",
    "elapsed_monotonic_ms",
    "phase",
    "projected_status",
    "durable_status",
    "source_identity_sha256",
    "previous_boundary_sha256",
    "boundary",
    "decision",
}
TERMINAL_EVENT_FIELDS = {"record_index", "event_type", "status", "count"}
INTERRUPT_FIELDS = {
    "requested_at",
    "request_accepted_at",
    "confirmed_at",
    "session_id",
    "thread_id",
    "turn_id",
    "request_outcome",
    "outcome",
}
MATERIALIZATION_FIELDS = {
    "evidence_type",
    "version",
    "schema",
    "evidence_id",
    "run_nonce",
    "attempt_nonce",
    "phase_nonce",
    "session_id",
    "thread_id",
    "turn_id",
    "requested_model",
    "attested_model",
    "attested_effort",
    "attestation_source",
    "connection_epoch_sha256",
    "command_sha256",
    "session_source_identity_sha256",
    "baseline",
    "control_observations",
    "liveness_observations",
    "pre_interrupt_observation",
    "interrupt",
    "terminal",
    "terminal_event",
    "status",
    "disposition",
    "evidence_sha256",
}
STEERING_FIELDS_V1 = {
    "schema",
    "gate",
    "bead_id",
    "authorization_id",
    "authorization_sha256",
    "control_turn_id",
    "submission_id",
    "client_user_message_id",
    "session_id",
    "agent",
    "model",
    "effort",
    "attestation_source",
    "model_discovery",
    "input",
    "boundary",
    "observed_activity",
    "guard",
    "opinion",
    "final_response_sha256",
    "started_at",
    "completed_at",
    "closure_outcome",
    "disposition",
    "canonical_receipt_sha256",
}
STEERING_FIELDS = (STEERING_FIELDS_V1 - {"opinion"}) | {
    "steering",
    "stop_scope",
    "authorized_continuation_paths",
    "scope_authority",
}
NEUTRAL_STEERING_FIELDS = {
    "operator_facts",
    "observed_evidence",
    "model_interpretation",
    "recommendation",
    "strongest_counterargument",
    "agent_authored_constraints",
}
OPERATOR_FACT_FIELDS = {"statement", "authority_provenance"}
OBSERVED_EVIDENCE_FIELDS = {
    "code",
    "severity",
    "observation",
    "evidence_sha256",
}
RECOMMENDATION_FIELDS = {
    "outcome",
    "rationale",
    "confidence",
    "confidence_role",
}
AGENT_CONSTRAINT_FIELDS = {"constraint", "origin", "authority"}
STEERING_MODEL_DISCOVERY_FIELDS = {
    "id",
    "model",
    "display_name",
    "default_reasoning_effort",
    "supported_reasoning_efforts_sha256",
    "model_record_sha256",
}
STEERING_INPUT_FIELDS = {
    "brief_sha256",
    "recovery_plan_sha256",
    "pickup_sha256",
}
STEERING_BASELINE_FIELDS = {
    "availability",
    "record_count",
    "byte_offset",
    "boundary_sha256",
    "path_sha256",
    "invalid_record_count",
    "trailing_partial",
}
STEERING_TERMINAL_FIELDS = STEERING_BASELINE_FIELDS - {"availability"}
STEERING_GUARD_FIELDS = {"repo_head", "repo_status_sha256", "primary_diff_sha256"}
AUTHORIZATION_FIELDS = {
    "authorization_type",
    "version",
    "schema",
    "authorization_id",
    "run_nonce",
    "state",
    "sequence",
    "allowed_actions",
    "revoked_actions",
    "updated_at",
    "reason",
    "state_sha256",
}
AUTHORIZATION_FIELDS_V2 = AUTHORIZATION_FIELDS | {"launch_claim_sha256"}
ACTIVE_ACTIONS = {
    "interrupt",
    "close",
    "sanitized-evidence",
    "reserved-steering",
    "beads-update",
    "local-checkpoint",
    "pickup",
    "handoff",
    "retry",
    "replacement",
    "relaunch",
    "tracked-mutation",
    "release-enable",
    "push",
    "install",
    "publish",
}
CONTAINMENT_ACTIONS = {
    "interrupt",
    "close",
    "sanitized-evidence",
    "reserved-steering",
    "beads-update",
    "local-checkpoint",
    "pickup",
    "handoff",
}
TERMINAL_ACTIONS: set[str] = set()
TRANSITIONS = {
    "active": {"containment-only", "complete"},
    "containment-only": {"parked"},
    "complete": set(),
    "parked": set(),
}
PRIVACY_KEY_RE = re.compile(
    r"(^|_)(raw|prompt|command_text|arguments|output|response|reasoning|content|path|path_hash|path_sha256)($|_)",
    re.I,
)


class NativeCanaryContractError(ValueError):
    """Raised when a canary artifact or transition fails closed."""


_OPERATOR_FACT_AUTHORITY_TOKEN = object()


class VerifiedOperatorFactAuthority:
    """Opaque operator authority bound to one exact steering fact statement."""

    __slots__ = ("_action_sha256", "_authority")

    def __init__(
        self,
        authority: VerifiedScopeAuthority,
        action_sha256: str,
        token: object,
    ) -> None:
        if token is not _OPERATOR_FACT_AUTHORITY_TOKEN:
            raise NativeCanaryContractError(
                "operator-fact-authority-construction-forbidden"
            )
        if not isinstance(authority, VerifiedScopeAuthority) or not _is_hash(
            action_sha256
        ):
            raise NativeCanaryContractError("operator-fact-authority-invalid")
        payload = authority.serialize()
        if (
            payload.get("source_type") != "operator-directive"
            or payload.get("actor_role") != "operator"
            or payload.get("verification", {}).get("method")
            != "hmac-sha256-operator-directive-v1"
        ):
            raise NativeCanaryContractError("operator-fact-authority-invalid")
        self._authority = authority
        self._action_sha256 = action_sha256

    @property
    def action_sha256(self) -> str:
        return self._action_sha256

    def serialize(self) -> dict[str, Any]:
        return self._authority.serialize()


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode()


def canonical_sha256(value: Any, *, domain: str) -> str:
    prefix = f"cwo:{domain}:v1\0".encode()
    return hashlib.sha256(prefix + _canonical_bytes(value)).hexdigest()


def operator_fact_action_sha256(statement: str) -> str:
    """Bind a signed operator directive to one exact fact statement."""

    if not isinstance(statement, str) or not statement.strip():
        raise NativeCanaryContractError("operator-fact-statement-invalid")
    return canonical_sha256(
        {"statement": statement}, domain="native-steering-operator-fact"
    )


def verify_operator_fact_authority(
    statement: str,
    receipt: Mapping[str, Any],
    *,
    verification_key: bytes,
    expected_actor_id: str,
    expected_identity_source: str,
) -> VerifiedOperatorFactAuthority:
    """Verify a signed directive for the exact operator fact being asserted."""

    action_sha256 = operator_fact_action_sha256(statement)
    authority = verify_operator_scope_directive(
        receipt,
        verification_key=verification_key,
        expected_actor_id=expected_actor_id,
        expected_identity_source=expected_identity_source,
        expected_action_sha256=action_sha256,
    )
    return VerifiedOperatorFactAuthority(
        authority,
        action_sha256,
        _OPERATOR_FACT_AUTHORITY_TOKEN,
    )


def length_framed_sha256(
    *, domain: str, fields: tuple[tuple[str, str | int], ...]
) -> str:
    """Hash a fixed ordered, typed, length-framed UTF-8 field sequence."""

    if not isinstance(domain, str) or not domain:
        raise NativeCanaryContractError("length-framed-hash-domain-invalid")
    preimage = bytearray(b"cwo-length-framed-sha256:v1\0")

    def append_frame(value: bytes) -> None:
        preimage.extend(len(value).to_bytes(8, "big"))
        preimage.extend(value)

    append_frame(domain.encode("utf-8"))
    preimage.extend(len(fields).to_bytes(8, "big"))
    seen: set[str] = set()
    for label, value in fields:
        if not isinstance(label, str) or not label or label in seen:
            raise NativeCanaryContractError("length-framed-hash-label-invalid")
        seen.add(label)
        append_frame(label.encode("utf-8"))
        if isinstance(value, str):
            preimage.extend(b"s")
            encoded = value.encode("utf-8")
        elif isinstance(value, int) and not isinstance(value, bool) and value >= 0:
            preimage.extend(b"u")
            encoded = str(value).encode("ascii")
        else:
            raise NativeCanaryContractError("length-framed-hash-value-invalid")
        append_frame(encoded)
    return hashlib.sha256(bytes(preimage)).hexdigest()


def validate_capability_rendered_command(rendered: Any, *, raw_command: str) -> str:
    """Accept only the raw command or the one production-proven bash wrapper."""

    if not isinstance(rendered, str) or not rendered:
        raise NativeCanaryContractError("rendered-command-invalid")
    if not isinstance(raw_command, str) or not raw_command:
        raise NativeCanaryContractError("raw-command-invalid")
    allowed = {raw_command, f"/bin/bash -lc {shlex.quote(raw_command)}"}
    if rendered not in allowed:
        raise NativeCanaryContractError("rendered-command-not-exact-wrapper")
    return length_framed_sha256(
        domain="native-capability-rendered-command",
        fields=(("rendered_command", rendered),),
    )


def materialization_execution_correlation(
    *,
    connection_epoch_sha256: str,
    session_id: str,
    thread_id: str,
    turn_id: str,
    command_item_id_sha256: str,
    function_call_id_sha256: str,
    notification_sequence: int,
    notification_received_monotonic_ns: int,
    notification_started_at_ms: int,
    turn_context_record_index: int,
    function_call_record_index: int,
    rendered_command_sha256: str,
    raw_command_sha256: str,
) -> str:
    return length_framed_sha256(
        domain="native-capability-execution-correlation",
        fields=(
            ("connection_epoch_sha256", connection_epoch_sha256),
            ("session_id", session_id),
            ("thread_id", thread_id),
            ("turn_id", turn_id),
            ("command_item_id_sha256", command_item_id_sha256),
            ("function_call_id_sha256", function_call_id_sha256),
            ("notification_sequence", notification_sequence),
            ("notification_received_monotonic_ns", notification_received_monotonic_ns),
            ("notification_started_at_ms", notification_started_at_ms),
            ("turn_context_record_index", turn_context_record_index),
            ("function_call_record_index", function_call_record_index),
            ("rendered_command_sha256", rendered_command_sha256),
            ("raw_command_sha256", raw_command_sha256),
        ),
    )


def _legacy_sha256(value: Any) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _is_hash(value: Any) -> bool:
    return isinstance(value, str) and HASH_RE.fullmatch(value) is not None


def _is_commit(value: Any) -> bool:
    return isinstance(value, str) and COMMIT_RE.fullmatch(value) is not None


def _is_canonical_uuid(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    try:
        parsed = uuid.UUID(value)
    except ValueError:
        return False
    return str(parsed) == value


def _is_valid_resolved_finding(value: Any) -> bool:
    errors: list[str] = []
    finding = _exact_fields(
        value, FULL_AUTO_FINDING_FIELDS, "steering-stop-finding", errors
    )
    if (
        errors
        or not isinstance(finding, dict)
        or set(finding) != FULL_AUTO_FINDING_FIELDS
    ):
        return False
    return (
        finding.get("status") == "resolved"
        and finding.get("severity") in {"high", "medium"}
        and isinstance(finding.get("code"), str)
        and bool(finding.get("code"))
    )


def _parse_time(value: Any, label: str, errors: list[str]) -> dt.datetime:
    if not isinstance(value, str) or not value:
        errors.append(f"{label}-invalid")
        return ISO_MINIMUM
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        errors.append(f"{label}-invalid")
        return ISO_MINIMUM
    if parsed.tzinfo is None:
        errors.append(f"{label}-timezone-missing")
        return ISO_MINIMUM
    return parsed.astimezone(dt.timezone.utc)


def _exact_fields(
    value: Any, expected: set[str], label: str, errors: list[str]
) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        errors.append(f"{label}-not-object")
        return {}
    result = dict(value)
    if set(result) != expected:
        errors.append(f"{label}-fields-invalid")
    return result


def steering_payload(receipt: Mapping[str, Any]) -> Mapping[str, Any]:
    """Return the versioned model-authored payload without granting it authority."""

    field = "steering" if receipt.get("schema") == STEERING_RECEIPT_TYPE else "opinion"
    value = receipt.get(field)
    return value if isinstance(value, Mapping) else {}


def steering_recommendation(receipt: Mapping[str, Any]) -> Any:
    """Read the recommendation outcome across the compatible-read boundary."""

    payload = steering_payload(receipt)
    recommendation = payload.get("recommendation")
    if isinstance(recommendation, Mapping):
        return recommendation.get("outcome")
    return recommendation


def _expected_neutral_stop_metadata(receipt: Mapping[str, Any]) -> dict[str, Any]:
    recommendation = steering_recommendation(receipt)
    if recommendation not in {"go", "conditional-go", "stop"}:
        raise NativeCanaryContractError("steering-scope-recommendation-invalid")
    final_response_sha256 = receipt.get("final_response_sha256")
    if not _is_hash(final_response_sha256):
        raise NativeCanaryContractError("steering-scope-final-response-hash-invalid")
    authority = policy_scope_authority(
        "native-steering-advisory-policy-v2",
        authorized_scope="child",
        source_sha256=canonical_sha256(
            {
                "schema": receipt.get("schema"),
                "gate": receipt.get("gate"),
                "bead_id": receipt.get("bead_id"),
                "authorization_id": receipt.get("authorization_id"),
                "authorization_sha256": receipt.get("authorization_sha256"),
                "control_turn_id": receipt.get("control_turn_id"),
                "submission_id": receipt.get("submission_id"),
                "final_response_sha256": final_response_sha256,
                "recommendation": recommendation,
            },
            domain="native-steering-advisory-policy",
        ),
    )
    paths = []
    if recommendation == "stop":
        paths = [
            continuation_path(
                "retry-child",
                target_id=str(receipt.get("bead_id")),
                conditions=["architect-adjudication", "findings-resolved"],
            ),
        ]
    return build_stop_metadata(
        "child",
        authority=authority,
        authorized_continuation_paths=paths,
    )


def _verified_operator_authorities(
    values: Iterable[VerifiedOperatorFactAuthority] | None,
    errors: list[str],
) -> dict[str, tuple[dict[str, Any], str]]:
    verified: dict[str, tuple[dict[str, Any], str]] = {}
    if values is None:
        return verified
    try:
        candidates = list(values)
    except TypeError:
        errors.append("steering-verified-operator-authorities-invalid")
        return verified
    for value in candidates:
        if not isinstance(value, VerifiedOperatorFactAuthority):
            errors.append("steering-verified-operator-authority-not-opaque")
            continue
        payload = value.serialize()
        authority_hash = payload.get("authority_sha256")
        if (
            payload.get("source_type") != "operator-directive"
            or payload.get("actor_role") != "operator"
            or payload.get("verification", {}).get("method")
            != "hmac-sha256-operator-directive-v1"
            or not _is_hash(authority_hash)
            or not _is_hash(value.action_sha256)
        ):
            errors.append("steering-verified-operator-authority-invalid")
            continue
        verified[str(authority_hash)] = (payload, value.action_sha256)
    return verified


def _validate_neutral_steering(
    receipt: Mapping[str, Any],
    *,
    verified_operator_authorities: Iterable[VerifiedOperatorFactAuthority] | None,
    errors: list[str],
) -> None:
    steering = _exact_fields(
        receipt.get("steering"),
        NEUTRAL_STEERING_FIELDS,
        "steering-neutral-packet",
        errors,
    )
    if steering and receipt.get("final_response_sha256") != _legacy_sha256(steering):
        errors.append("steering-final-response-sha256-mismatch")
    verified = _verified_operator_authorities(verified_operator_authorities, errors)

    operator_facts = steering.get("operator_facts")
    if not isinstance(operator_facts, list):
        errors.append("steering-operator-facts-invalid")
    else:
        for index, value in enumerate(operator_facts):
            fact = _exact_fields(
                value,
                OPERATOR_FACT_FIELDS,
                f"steering-operator-fact-{index}",
                errors,
            )
            if (
                not isinstance(fact.get("statement"), str)
                or not fact.get("statement", "").strip()
            ):
                errors.append(f"steering-operator-fact-{index}-statement-invalid")
            provenance = fact.get("authority_provenance")
            provenance_errors = validate_scope_authority(provenance)
            errors.extend(
                f"steering-operator-fact-{index}-{item}" for item in provenance_errors
            )
            if not isinstance(provenance, Mapping):
                continue
            authority_hash = provenance.get("authority_sha256")
            verified_binding = verified.get(str(authority_hash))
            if (
                provenance.get("source_type") != "operator-directive"
                or provenance.get("actor_role") != "operator"
            ):
                errors.append(
                    f"steering-operator-fact-{index}-operator-provenance-required"
                )
            if (
                not _is_hash(authority_hash)
                or verified_binding is None
                or verified_binding[0] != dict(provenance)
            ):
                errors.append(f"steering-operator-fact-{index}-authority-unverified")
            elif (
                isinstance(fact.get("statement"), str)
                and fact.get("statement", "").strip()
                and verified_binding[1]
                != operator_fact_action_sha256(str(fact["statement"]))
            ):
                errors.append(
                    f"steering-operator-fact-{index}-authority-action-mismatch"
                )

    observed = steering.get("observed_evidence")
    if not isinstance(observed, list) or not observed:
        errors.append("steering-observed-evidence-invalid")
    else:
        seen_codes: set[str] = set()
        for index, value in enumerate(observed):
            evidence = _exact_fields(
                value,
                OBSERVED_EVIDENCE_FIELDS,
                f"steering-observed-evidence-{index}",
                errors,
            )
            code = evidence.get("code")
            if not isinstance(code, str) or not code.strip() or code in seen_codes:
                errors.append(f"steering-observed-evidence-{index}-code-invalid")
            else:
                seen_codes.add(code)
            if evidence.get("severity") not in {"high", "medium", "low", "info"}:
                errors.append(f"steering-observed-evidence-{index}-severity-invalid")
            if (
                not isinstance(evidence.get("observation"), str)
                or not evidence.get("observation", "").strip()
            ):
                errors.append(f"steering-observed-evidence-{index}-observation-invalid")
            if not _is_hash(evidence.get("evidence_sha256")):
                errors.append(f"steering-observed-evidence-{index}-sha256-invalid")

    for field in ("model_interpretation", "strongest_counterargument"):
        if (
            not isinstance(steering.get(field), str)
            or not steering.get(field, "").strip()
        ):
            errors.append(f"steering-{field.replace('_', '-')}-invalid")

    recommendation = _exact_fields(
        steering.get("recommendation"),
        RECOMMENDATION_FIELDS,
        "steering-recommendation",
        errors,
    )
    if recommendation.get("outcome") not in {"go", "conditional-go", "stop"}:
        errors.append("steering-recommendation-invalid")
    if (
        not isinstance(recommendation.get("rationale"), str)
        or not recommendation.get("rationale", "").strip()
    ):
        errors.append("steering-recommendation-rationale-invalid")
    confidence = recommendation.get("confidence")
    if (
        isinstance(confidence, bool)
        or not isinstance(confidence, (int, float))
        or not math.isfinite(confidence)
        or confidence < 0
        or confidence > 1
    ):
        errors.append("steering-confidence-invalid")
    if recommendation.get("confidence_role") != "advisory-only":
        errors.append("steering-confidence-role-invalid")

    constraints = steering.get("agent_authored_constraints")
    if not isinstance(constraints, list):
        errors.append("steering-agent-authored-constraints-invalid")
    else:
        for index, value in enumerate(constraints):
            constraint = _exact_fields(
                value,
                AGENT_CONSTRAINT_FIELDS,
                f"steering-agent-constraint-{index}",
                errors,
            )
            if (
                not isinstance(constraint.get("constraint"), str)
                or not constraint.get("constraint", "").strip()
            ):
                errors.append(f"steering-agent-constraint-{index}-text-invalid")
            if constraint.get("origin") != "agent-authored":
                errors.append(f"steering-agent-constraint-{index}-origin-invalid")
            if constraint.get("authority") != "advisory-only":
                errors.append(f"steering-agent-constraint-{index}-authority-invalid")

    try:
        expected_stop = _expected_neutral_stop_metadata(receipt)
    except (NativeCanaryContractError, ValueError) as exc:
        errors.append(str(exc))
    else:
        for field in ("stop_scope", "authorized_continuation_paths", "scope_authority"):
            if receipt.get(field) != expected_stop[field]:
                errors.append(f"steering-{field.replace('_', '-')}-mismatch")
    expected_disposition = {
        "go": "accepting",
        "conditional-go": "conditional",
        "stop": "rejected",
    }.get(recommendation.get("outcome"))
    if (
        expected_disposition is not None
        and receipt.get("disposition") != expected_disposition
    ):
        errors.append("steering-disposition-mismatch")


def _validate_boundary(value: Any, label: str, errors: list[str]) -> dict[str, Any]:
    boundary = _exact_fields(value, BOUNDARY_FIELDS, label, errors)
    for field in ("record_count", "byte_offset", "invalid_record_count"):
        current = boundary.get(field)
        if isinstance(current, bool) or not isinstance(current, int) or current < 0:
            errors.append(f"{label}-{field}-invalid")
    if not _is_hash(boundary.get("boundary_sha256")):
        errors.append(f"{label}-sha256-invalid")
    if not isinstance(boundary.get("trailing_partial"), bool):
        errors.append(f"{label}-trailing-partial-invalid")
    return boundary


def _privacy_errors(value: Any, *, prefix: str = "artifact") -> list[str]:
    errors: list[str] = []
    if isinstance(value, Mapping):
        for key, child in value.items():
            if PRIVACY_KEY_RE.search(str(key)):
                errors.append(f"{prefix}-privacy-key:{key}")
            errors.extend(_privacy_errors(child, prefix=f"{prefix}.{key}"))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            errors.extend(_privacy_errors(child, prefix=f"{prefix}[{index}]"))
    return errors


def _validate_observation(
    value: Any, label: str, errors: list[str]
) -> tuple[dict[str, Any], dt.datetime]:
    observation = _exact_fields(value, OBSERVATION_FIELDS, label, errors)
    observed = _parse_time(
        observation.get("observed_at"), f"{label}-observed-at", errors
    )
    _validate_boundary(observation.get("boundary"), f"{label}-boundary", errors)
    for field in (
        "notification_sequence",
        "notification_received_monotonic_ns",
        "notification_started_at_ms",
        "turn_context_record_index",
        "function_call_record_index",
        "started_event_count",
        "function_call_count",
        "completed_event_count",
        "paired_result_count",
        "competing_call_count",
        "terminal_event_count",
        "failed_event_count",
        "declined_event_count",
        "ambiguous_event_count",
    ):
        current = observation.get(field)
        if isinstance(current, bool) or not isinstance(current, int) or current < 0:
            errors.append(f"{label}-{field}-invalid")
    for field in (
        "session_source_identity_sha256",
        "connection_epoch_sha256",
        "command_item_id_sha256",
        "function_call_id_sha256",
        "rendered_command_sha256",
        "execution_correlation_sha256",
    ):
        if not _is_hash(observation.get(field)):
            errors.append(f"{label}-{field}-invalid")
    if observation.get("command_source") != "unifiedExecStartup":
        errors.append(f"{label}-command-source-invalid")
    if observation.get("notification_command_semantic_match") is not True:
        errors.append(f"{label}-notification-command-semantic-match-invalid")
    if observation.get("notification_workspace_match") is not True:
        errors.append(f"{label}-notification-workspace-match-invalid")
    if observation.get("command_status") != "inProgress":
        errors.append(f"{label}-command-not-in-progress")
    for field in (
        "completed_event_count",
        "paired_result_count",
        "competing_call_count",
        "terminal_event_count",
        "failed_event_count",
        "declined_event_count",
        "ambiguous_event_count",
    ):
        if observation.get(field) != 0:
            errors.append(f"{label}-{field}-nonzero")
    if observation.get("started_event_count") != 1:
        errors.append(f"{label}-started-event-count-invalid")
    if observation.get("function_call_count") != 1:
        errors.append(f"{label}-function-call-count-invalid")
    return observation, observed


def _validate_control_observation(
    value: Any, label: str, errors: list[str]
) -> dict[str, Any]:
    observation = _exact_fields(value, CONTROL_OBSERVATION_FIELDS, label, errors)
    ordinal = observation.get("ordinal")
    if isinstance(ordinal, bool) or not isinstance(ordinal, int) or ordinal < 0:
        errors.append(f"{label}-ordinal-invalid")
    elapsed = observation.get("elapsed_monotonic_ms")
    if (
        isinstance(elapsed, bool)
        or not isinstance(elapsed, (int, float))
        or not math.isfinite(float(elapsed))
        or elapsed < 0
    ):
        errors.append(f"{label}-elapsed-invalid")
    if observation.get("phase") not in {
        "materialization",
        "pre-interrupt",
        "interrupt-confirmation",
        "terminal",
    }:
        errors.append(f"{label}-phase-invalid")
    if observation.get("projected_status") not in {
        "active",
        "completed",
        "failed",
        "interrupted",
        "missing",
        "unknown",
    }:
        errors.append(f"{label}-projected-status-invalid")
    if observation.get("durable_status") not in {
        None,
        "completed",
        "failed",
        "interrupted",
    }:
        errors.append(f"{label}-durable-status-invalid")
    source_identity = observation.get("source_identity_sha256")
    if source_identity is not None and not _is_hash(source_identity):
        errors.append(f"{label}-source-identity-invalid")
    if not _is_hash(observation.get("previous_boundary_sha256")):
        errors.append(f"{label}-previous-boundary-invalid")
    _validate_boundary(observation.get("boundary"), f"{label}-boundary", errors)
    if observation.get("decision") not in {
        "continue-pending",
        "continue-active",
        "continue-provisional",
        "ready",
        "interrupt-pending",
        "interrupt-confirmed",
        "terminal-accepted",
    }:
        errors.append(f"{label}-decision-invalid")
    return observation


def seal_materialization_evidence(value: Mapping[str, Any]) -> dict[str, Any]:
    body = dict(value)
    body.pop("evidence_sha256", None)
    body["evidence_sha256"] = canonical_sha256(
        body, domain="native-session-materialization"
    )
    return body


def validate_materialization_evidence(
    value: Any, *, require_accepting: bool = False
) -> list[str]:
    errors: list[str] = []
    evidence = _exact_fields(value, MATERIALIZATION_FIELDS, "materialization", errors)
    if evidence.get("evidence_type") != MATERIALIZATION_EVIDENCE_TYPE:
        errors.append("materialization-type-invalid")
    if (
        evidence.get("version") != 4
        or evidence.get("schema") != MATERIALIZATION_EVIDENCE_SCHEMA
    ):
        errors.append("materialization-header-invalid")
    for field in (
        "evidence_id",
        "run_nonce",
        "attempt_nonce",
        "phase_nonce",
        "session_id",
        "thread_id",
        "turn_id",
        "requested_model",
        "attested_model",
        "attested_effort",
        "attestation_source",
    ):
        if not isinstance(evidence.get(field), str) or not evidence.get(field):
            errors.append(f"materialization-{field}-invalid")
    for field in ("run_nonce", "attempt_nonce", "phase_nonce"):
        if not _is_canonical_uuid(evidence.get(field)):
            errors.append(f"materialization-{field}-not-uuid")
    if evidence.get("requested_model") != evidence.get("attested_model"):
        errors.append("materialization-model-mismatch")
    if evidence.get("session_id") != evidence.get("thread_id"):
        errors.append("materialization-session-thread-mismatch")
    for field in (
        "connection_epoch_sha256",
        "command_sha256",
        "session_source_identity_sha256",
    ):
        if not _is_hash(evidence.get(field)):
            errors.append(f"materialization-{field}-invalid")
    baseline = _validate_boundary(
        evidence.get("baseline"), "materialization-baseline", errors
    )
    terminal = _validate_boundary(
        evidence.get("terminal"), "materialization-terminal", errors
    )
    control_observations = evidence.get("control_observations")
    if (
        not isinstance(control_observations, list)
        or not control_observations
        or len(control_observations) > CONTROL_OBSERVATION_MAX
    ):
        errors.append("materialization-control-observations-invalid")
        control_observations = []
    parsed_control = [
        _validate_control_observation(item, f"materialization-control-{index}", errors)
        for index, item in enumerate(control_observations)
    ]
    previous_boundary = baseline
    previous_elapsed = -1.0
    previous_phase_rank: int | None = None
    phase_counts = {phase: 0 for phase in CONTROL_OBSERVATION_PHASES}
    interrupt_confirmation_indexes: list[int] = []
    saw_pre_interrupt = False
    saw_interrupt_confirmed = False
    for index, item in enumerate(parsed_control):
        if item.get("ordinal") != index:
            errors.append("materialization-control-ordinal-not-contiguous")
        elapsed = item.get("elapsed_monotonic_ms")
        if isinstance(elapsed, (int, float)) and not isinstance(elapsed, bool):
            current_elapsed = float(elapsed)
            if current_elapsed < previous_elapsed:
                errors.append("materialization-control-elapsed-regressed")
            if (
                previous_elapsed >= 0
                and current_elapsed - previous_elapsed > CONTROL_OBSERVATION_MAX_GAP_MS
            ):
                errors.append("materialization-control-observation-gap-exceeded")
            previous_elapsed = max(previous_elapsed, current_elapsed)
        boundary = (
            item.get("boundary") if isinstance(item.get("boundary"), Mapping) else {}
        )
        if item.get("previous_boundary_sha256") != previous_boundary.get(
            "boundary_sha256"
        ):
            errors.append("materialization-control-prefix-link-mismatch")
        prior_count = previous_boundary.get("record_count")
        prior_offset = previous_boundary.get("byte_offset")
        current_count = boundary.get("record_count")
        current_offset = boundary.get("byte_offset")
        if (
            isinstance(prior_count, int)
            and isinstance(current_count, int)
            and current_count < prior_count
        ):
            errors.append("materialization-control-record-count-regressed")
        if (
            isinstance(prior_offset, int)
            and isinstance(current_offset, int)
            and current_offset < prior_offset
        ):
            errors.append("materialization-control-byte-offset-regressed")
        if current_offset == prior_offset and (
            current_count != prior_count
            or boundary.get("boundary_sha256")
            != previous_boundary.get("boundary_sha256")
        ):
            errors.append("materialization-control-equal-offset-boundary-changed")
        if boundary:
            previous_boundary = boundary
        source_identity = item.get("source_identity_sha256")
        if source_identity is not None and source_identity != evidence.get(
            "session_source_identity_sha256"
        ):
            errors.append("materialization-control-source-identity-mismatch")
        projected = item.get("projected_status")
        durable = item.get("durable_status")
        decision = item.get("decision")
        phase = item.get("phase")
        if phase in phase_counts:
            phase_counts[phase] += 1
            phase_rank = CONTROL_OBSERVATION_PHASES.index(phase)
            if index == 0 and phase != "materialization":
                errors.append("materialization-control-phase-first-invalid")
            if previous_phase_rank is not None:
                if phase_rank < previous_phase_rank:
                    errors.append("materialization-control-phase-regressed")
                elif phase_rank > previous_phase_rank + 1:
                    errors.append("materialization-control-phase-skipped")
            previous_phase_rank = phase_rank
            if phase == "terminal" and index != len(parsed_control) - 1:
                errors.append("materialization-control-terminal-phase-not-final")
        if (
            phase in {"materialization", "pre-interrupt"}
            and projected in {"completed", "failed", "interrupted"}
            and durable is None
        ):
            if decision != "continue-provisional":
                errors.append("materialization-control-provisional-decision-invalid")
        if durable in {"completed", "failed"}:
            errors.append("materialization-control-losing-terminal-observed")
        if durable == "interrupted" and decision not in {
            "interrupt-confirmed",
            "terminal-accepted",
        }:
            errors.append("materialization-control-interrupted-decision-invalid")
        if phase == "pre-interrupt":
            saw_pre_interrupt = True
            if durable is not None:
                errors.append("materialization-pre-interrupt-durable-terminal-observed")
        if decision == "interrupt-confirmed":
            saw_interrupt_confirmed = True
            interrupt_confirmation_indexes.append(index)
            if phase != "interrupt-confirmation" or durable != "interrupted":
                errors.append("materialization-control-interrupt-confirmation-invalid")
        if decision == "terminal-accepted" and phase != "terminal":
            errors.append("materialization-control-terminal-decision-phase-invalid")
    for phase, count in phase_counts.items():
        if count == 0:
            errors.append(f"materialization-control-phase-missing:{phase}")
    if phase_counts["terminal"] != 1:
        errors.append("materialization-control-terminal-phase-not-singular")
    if len(interrupt_confirmation_indexes) != 1:
        errors.append("materialization-control-interrupt-confirmation-not-singular")
    elif interrupt_confirmation_indexes[0] != len(parsed_control) - 2:
        errors.append(
            "materialization-control-interrupt-confirmation-not-adjacent-terminal"
        )
    if parsed_control:
        final_control = parsed_control[-1]
        if (
            final_control.get("phase") != "terminal"
            or final_control.get("decision") != "terminal-accepted"
            or final_control.get("durable_status") != "interrupted"
            or final_control.get("source_identity_sha256")
            != evidence.get("session_source_identity_sha256")
            or final_control.get("boundary") != terminal
        ):
            errors.append("materialization-control-terminal-observation-invalid")
    if not saw_pre_interrupt:
        errors.append("materialization-control-pre-interrupt-missing")
    if not saw_interrupt_confirmed:
        errors.append("materialization-control-interrupt-confirmation-missing")
    terminal_event = _exact_fields(
        evidence.get("terminal_event"),
        TERMINAL_EVENT_FIELDS,
        "materialization-terminal-event",
        errors,
    )
    record_index = terminal_event.get("record_index")
    if (
        isinstance(record_index, bool)
        or not isinstance(record_index, int)
        or record_index < 0
        or (
            isinstance(terminal.get("record_count"), int)
            and record_index >= terminal.get("record_count", 0)
        )
    ):
        errors.append("materialization-terminal-event-record-index-invalid")
    if terminal_event.get("event_type") != "turn_aborted":
        errors.append("materialization-terminal-event-type-invalid")
    if terminal_event.get("status") != "interrupted":
        errors.append("materialization-terminal-event-status-invalid")
    if terminal_event.get("count") != 1:
        errors.append("materialization-terminal-event-count-invalid")
    observations = evidence.get("liveness_observations")
    if not isinstance(observations, list) or len(observations) != 2:
        errors.append("materialization-liveness-observations-invalid")
        observations = []
    parsed_observations = [
        _validate_observation(item, f"materialization-liveness-{index}", errors)
        for index, item in enumerate(observations)
    ]
    pre_interrupt, pre_time = _validate_observation(
        evidence.get("pre_interrupt_observation"),
        "materialization-pre-interrupt",
        errors,
    )
    if len(parsed_observations) == 2:
        first, first_time = parsed_observations[0]
        second, second_time = parsed_observations[1]
        if (second_time - first_time).total_seconds() < 1.0:
            errors.append("materialization-observation-separation-too-short")
        identity_fields = (
            "session_source_identity_sha256",
            "connection_epoch_sha256",
            "notification_sequence",
            "notification_received_monotonic_ns",
            "notification_started_at_ms",
            "turn_context_record_index",
            "function_call_record_index",
            "command_item_id_sha256",
            "function_call_id_sha256",
            "rendered_command_sha256",
            "execution_correlation_sha256",
        )
        if any(first.get(field) != second.get(field) for field in identity_fields):
            errors.append("materialization-liveness-identity-changed")
        if any(
            second.get(field) != pre_interrupt.get(field) for field in identity_fields
        ):
            errors.append("materialization-pre-interrupt-identity-changed")
        if pre_time < second_time:
            errors.append("materialization-pre-interrupt-precedes-liveness")
        if any(
            item.get("connection_epoch_sha256")
            != evidence.get("connection_epoch_sha256")
            for item, _time in (*parsed_observations, (pre_interrupt, pre_time))
        ):
            errors.append("materialization-connection-epoch-mismatch")
        if any(
            item.get("session_source_identity_sha256")
            != evidence.get("session_source_identity_sha256")
            for item, _time in (*parsed_observations, (pre_interrupt, pre_time))
        ):
            errors.append("materialization-session-source-identity-mismatch")
        materialization_control_hashes = {
            item.get("boundary", {}).get("boundary_sha256")
            for item in parsed_control
            if item.get("phase") == "materialization"
            and item.get("decision") == "ready"
            and isinstance(item.get("boundary"), Mapping)
        }
        if any(
            item.get("boundary", {}).get("boundary_sha256")
            not in materialization_control_hashes
            for item, _time in parsed_observations
        ):
            errors.append("materialization-liveness-control-binding-missing")
        pre_interrupt_control_hashes = {
            item.get("boundary", {}).get("boundary_sha256")
            for item in parsed_control
            if item.get("phase") == "pre-interrupt"
            and item.get("decision") == "ready"
            and isinstance(item.get("boundary"), Mapping)
        }
        if (
            pre_interrupt.get("boundary", {}).get("boundary_sha256")
            not in pre_interrupt_control_hashes
        ):
            errors.append("materialization-pre-interrupt-control-binding-missing")
        for index, (item, _time) in enumerate(
            (*parsed_observations, (pre_interrupt, pre_time))
        ):
            try:
                expected_correlation = materialization_execution_correlation(
                    connection_epoch_sha256=str(item.get("connection_epoch_sha256")),
                    session_id=str(evidence.get("session_id")),
                    thread_id=str(evidence.get("thread_id")),
                    turn_id=str(evidence.get("turn_id")),
                    command_item_id_sha256=str(item.get("command_item_id_sha256")),
                    function_call_id_sha256=str(item.get("function_call_id_sha256")),
                    notification_sequence=item.get("notification_sequence"),
                    notification_received_monotonic_ns=item.get(
                        "notification_received_monotonic_ns"
                    ),
                    notification_started_at_ms=item.get("notification_started_at_ms"),
                    turn_context_record_index=item.get("turn_context_record_index"),
                    function_call_record_index=item.get("function_call_record_index"),
                    rendered_command_sha256=str(item.get("rendered_command_sha256")),
                    raw_command_sha256=str(evidence.get("command_sha256")),
                )
            except NativeCanaryContractError:
                errors.append(
                    f"materialization-observation-{index}-correlation-input-invalid"
                )
            else:
                if item.get("execution_correlation_sha256") != expected_correlation:
                    errors.append(
                        f"materialization-observation-{index}-correlation-mismatch"
                    )
    interrupt = _exact_fields(
        evidence.get("interrupt"), INTERRUPT_FIELDS, "materialization-interrupt", errors
    )
    requested = _parse_time(
        interrupt.get("requested_at"), "materialization-interrupt-requested", errors
    )
    accepted = _parse_time(
        interrupt.get("request_accepted_at"),
        "materialization-interrupt-request-accepted",
        errors,
    )
    confirmed = _parse_time(
        interrupt.get("confirmed_at"), "materialization-interrupt-confirmed", errors
    )
    if (
        interrupt.get("session_id") != evidence.get("session_id")
        or interrupt.get("thread_id") != evidence.get("thread_id")
        or interrupt.get("turn_id") != evidence.get("turn_id")
    ):
        errors.append("materialization-interrupt-identity-mismatch")
    if interrupt.get("request_outcome") != "accepted":
        errors.append("materialization-interrupt-request-outcome-invalid")
    if interrupt.get("outcome") != "interrupt-confirmed":
        errors.append("materialization-interrupt-outcome-invalid")
    if (
        accepted < requested
        or confirmed < accepted
        or (confirmed - requested).total_seconds() > 5.0
    ):
        errors.append("materialization-interrupt-confirmation-deadline-invalid")
    if baseline and terminal:
        if terminal.get("record_count", 0) < baseline.get(
            "record_count", 0
        ) or terminal.get("byte_offset", 0) < baseline.get("byte_offset", 0):
            errors.append("materialization-terminal-boundary-regressed")
    if (
        terminal.get("invalid_record_count") != 0
        or terminal.get("trailing_partial") is not False
    ):
        errors.append("materialization-terminal-boundary-not-clean")
    errors.extend(_privacy_errors(evidence))
    expected_hash = evidence.get("evidence_sha256")
    unsigned = dict(evidence)
    unsigned.pop("evidence_sha256", None)
    if expected_hash != canonical_sha256(
        unsigned, domain="native-session-materialization"
    ):
        errors.append("materialization-evidence-sha256-mismatch")
    accepting = (
        evidence.get("status") == "interrupt-confirmed"
        and evidence.get("disposition") == "accepted"
    )
    if require_accepting and not accepting:
        errors.append("materialization-evidence-not-accepting")
    return sorted(set(errors))


def _validate_steering_v2_envelope(
    receipt: Mapping[str, Any], errors: list[str]
) -> None:
    if receipt.get("gate") not in {"pre-mutation", "pre-live"}:
        errors.append("steering-gate-invalid")

    discovery = _exact_fields(
        receipt.get("model_discovery"),
        STEERING_MODEL_DISCOVERY_FIELDS,
        "steering-model-discovery",
        errors,
    )
    if discovery.get("id") != "gpt-5.6-sol" or discovery.get("model") != (
        "gpt-5.6-sol"
    ):
        errors.append("steering-model-discovery-model-invalid")
    for field in ("display_name", "default_reasoning_effort"):
        if discovery.get(field) is not None and not isinstance(
            discovery.get(field), str
        ):
            errors.append(f"steering-model-discovery-{field}-invalid")
    for field in ("supported_reasoning_efforts_sha256", "model_record_sha256"):
        if not _is_hash(discovery.get(field)):
            errors.append(f"steering-model-discovery-{field}-invalid")

    inputs = _exact_fields(
        receipt.get("input"), STEERING_INPUT_FIELDS, "steering-input", errors
    )
    for field in STEERING_INPUT_FIELDS:
        if not _is_hash(inputs.get(field)):
            errors.append(f"steering-input-{field}-invalid")

    boundaries = _exact_fields(
        receipt.get("boundary"), {"baseline", "terminal"}, "steering-boundary", errors
    )
    baseline = _exact_fields(
        boundaries.get("baseline"),
        STEERING_BASELINE_FIELDS,
        "steering-baseline",
        errors,
    )
    terminal = _exact_fields(
        boundaries.get("terminal"),
        STEERING_TERMINAL_FIELDS,
        "steering-terminal",
        errors,
    )
    if baseline.get("availability") not in {"available", "not-yet-materialized"}:
        errors.append("steering-baseline-availability-invalid")
    for label, boundary, minimum in (
        ("baseline", baseline, 0),
        ("terminal", terminal, 1),
    ):
        for field in ("record_count", "byte_offset"):
            value = boundary.get(field)
            if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
                errors.append(f"steering-{label}-{field}-invalid")
        if not _is_hash(boundary.get("boundary_sha256")):
            errors.append(f"steering-{label}-boundary-sha256-invalid")
        path_sha256 = boundary.get("path_sha256")
        if label == "terminal":
            if not _is_hash(path_sha256):
                errors.append("steering-terminal-path-sha256-invalid")
        elif path_sha256 is not None and not _is_hash(path_sha256):
            errors.append("steering-baseline-path-sha256-invalid")
        if boundary.get("invalid_record_count") != 0:
            errors.append(f"steering-{label}-invalid-record-count-nonzero")
        if boundary.get("trailing_partial") is not False:
            errors.append(f"steering-{label}-trailing-partial-invalid")
    for field in ("record_count", "byte_offset"):
        before = baseline.get(field)
        after = terminal.get(field)
        if (
            isinstance(before, int)
            and not isinstance(before, bool)
            and isinstance(after, int)
            and not isinstance(after, bool)
            and after < before
        ):
            errors.append(f"steering-boundary-{field}-regressed")
    if (
        terminal.get("invalid_record_count") != 0
        or terminal.get("trailing_partial") is not False
    ):
        errors.append("steering-terminal-boundary-not-clean")

    guard = _exact_fields(
        receipt.get("guard"), {"before", "after"}, "steering-guard", errors
    )
    guard_values: dict[str, dict[str, Any]] = {}
    for label in ("before", "after"):
        current = _exact_fields(
            guard.get(label),
            STEERING_GUARD_FIELDS,
            f"steering-guard-{label}",
            errors,
        )
        guard_values[label] = current
        if (
            not isinstance(current.get("repo_head"), str)
            or COMMIT_RE.fullmatch(str(current.get("repo_head"))) is None
        ):
            errors.append(f"steering-guard-{label}-repo-head-invalid")
        for field in ("repo_status_sha256", "primary_diff_sha256"):
            if not _is_hash(current.get(field)):
                errors.append(f"steering-guard-{label}-{field}-invalid")
    if guard_values.get("before") != guard_values.get("after"):
        errors.append("steering-guard-changed")

    started = _parse_time(receipt.get("started_at"), "steering-started-at", errors)
    completed = _parse_time(
        receipt.get("completed_at"), "steering-completed-at", errors
    )
    if started != ISO_MINIMUM and completed != ISO_MINIMUM and completed < started:
        errors.append("steering-time-order-invalid")


def validate_steering_receipt(
    value: Any,
    *,
    architect_adjudication_sha256: str | None = None,
    architect_decision: str | None = None,
    allow_resolved_stop: bool = False,
    resolved_stop_adjudication: Mapping[str, Any] | None = None,
    resolved_stop_post_resolution_commit: str | None = None,
    require_accepting: bool = False,
    require_neutral: bool = False,
    verified_operator_authorities: Iterable[VerifiedOperatorFactAuthority]
    | None = None,
) -> list[str]:
    errors: list[str] = []
    is_v2 = isinstance(value, Mapping) and value.get("schema") == STEERING_RECEIPT_TYPE
    receipt = _exact_fields(
        value,
        STEERING_FIELDS if is_v2 else STEERING_FIELDS_V1,
        "steering",
        errors,
    )
    if receipt.get("schema") not in {STEERING_RECEIPT_TYPE, STEERING_RECEIPT_TYPE_V1}:
        errors.append("steering-schema-invalid")
    elif not is_v2 and require_neutral:
        errors.append("steering-legacy-v1-inspection-only")
    for field in (
        "gate",
        "bead_id",
        "authorization_id",
        "control_turn_id",
        "submission_id",
        "client_user_message_id",
        "session_id",
        "agent",
    ):
        if not isinstance(receipt.get(field), str) or not receipt.get(field):
            errors.append(f"steering-{field}-invalid")
    for field in (
        "authorization_id",
        "submission_id",
        "client_user_message_id",
        "session_id",
    ):
        if not _is_canonical_uuid(receipt.get(field)):
            errors.append(f"steering-{field}-not-canonical-uuid")
    if receipt.get("model") != "gpt-5.6-sol" or receipt.get("effort") != "max":
        errors.append("steering-model-effort-mismatch")
    if (
        receipt.get("attestation_source")
        != "initialized-codex-home-session-jsonl-turn-context"
    ):
        errors.append("steering-attestation-source-invalid")
    for field in (
        "authorization_sha256",
        "final_response_sha256",
        "canonical_receipt_sha256",
    ):
        if not _is_hash(receipt.get(field)):
            errors.append(f"steering-{field}-invalid")
    activity = receipt.get("observed_activity")
    expected_activity = {
        "function_calls": 0,
        "custom_tool_calls": 0,
        "tool_item_types": [],
        "compactions": 0,
        "workspace_mutations": 0,
    }
    if activity != expected_activity:
        errors.append("steering-nonzero-activity")
    if is_v2:
        _validate_steering_v2_envelope(receipt, errors)
        _validate_neutral_steering(
            receipt,
            verified_operator_authorities=verified_operator_authorities,
            errors=errors,
        )
    recommendation = steering_recommendation(receipt)
    if recommendation not in {"go", "conditional-go", "stop"}:
        errors.append("steering-recommendation-invalid")
    if not is_v2 and receipt.get("final_response_sha256") != _legacy_sha256(
        dict(steering_payload(receipt))
    ):
        errors.append("steering-final-response-sha256-mismatch")
    if receipt.get("closure_outcome") != "completed-and-archived":
        errors.append("steering-closure-invalid")
    unsigned = dict(receipt)
    unsigned.pop("canonical_receipt_sha256", None)
    if receipt.get("canonical_receipt_sha256") != _legacy_sha256(unsigned):
        errors.append("steering-canonical-sha256-mismatch")
    architect_go = (
        _is_hash(architect_adjudication_sha256) and architect_decision == "go"
    )
    accepting = recommendation == "go" and (not is_v2 or architect_go)
    if recommendation == "conditional-go":
        accepting = architect_go
    elif recommendation == "stop":
        if allow_resolved_stop:
            stop_errors = []
            if (
                not _is_hash(architect_adjudication_sha256)
                or architect_decision != "go"
            ):
                stop_errors.append("steering-stop-main-adjudication-not-bound-go")
            stop_errors.extend(
                _validate_resolved_pre_mutation_stop_steering_receipt(
                    receipt,
                    resolved_stop_adjudication,
                    resolved_stop_post_resolution_commit=resolved_stop_post_resolution_commit,
                )
            )
            if stop_errors:
                errors.extend(stop_errors)
            else:
                accepting = True
    if require_accepting and not accepting:
        errors.append("steering-receipt-not-accepting")
    return sorted(set(errors))


def seal_neutral_steering_receipt(
    value: Mapping[str, Any],
    *,
    verified_operator_authorities: Iterable[VerifiedOperatorFactAuthority]
    | None = None,
) -> dict[str, Any]:
    """Strict-write a v2 receipt with derived advisory scope and canonical JSON."""

    receipt = dict(value)
    if receipt.get("schema") != STEERING_RECEIPT_TYPE:
        raise NativeCanaryContractError("steering-neutral-schema-required")
    payload = receipt.get("steering")
    if not isinstance(payload, Mapping):
        raise NativeCanaryContractError("steering-neutral-packet-not-object")
    receipt["final_response_sha256"] = _legacy_sha256(dict(payload))
    for field in (
        "stop_scope",
        "authorized_continuation_paths",
        "scope_authority",
        "canonical_receipt_sha256",
    ):
        receipt.pop(field, None)
    receipt.update(_expected_neutral_stop_metadata(receipt))
    receipt["canonical_receipt_sha256"] = _legacy_sha256(receipt)
    errors = validate_steering_receipt(
        receipt,
        require_neutral=True,
        verified_operator_authorities=verified_operator_authorities,
    )
    if errors:
        raise NativeCanaryContractError(
            "steering-neutral-receipt-invalid:" + ";".join(errors)
        )
    return receipt


def neutral_steering_final_text(receipt: Mapping[str, Any]) -> str:
    """Render the only final-response serialization accepted for new receipts."""

    if receipt.get("schema") != STEERING_RECEIPT_TYPE:
        raise NativeCanaryContractError("steering-neutral-schema-required")
    payload = steering_payload(receipt)
    if not payload:
        raise NativeCanaryContractError("steering-neutral-packet-not-object")
    return json.dumps(dict(payload), sort_keys=True, separators=(",", ":"))


def _validate_resolved_pre_mutation_stop_steering_receipt(
    receipt: Mapping[str, Any],
    adjudication: Mapping[str, Any] | None,
    *,
    resolved_stop_post_resolution_commit: str | None = None,
) -> list[str]:
    errors: list[str] = []
    if receipt.get("gate") != "pre-mutation":
        errors.append("steering-stop-receipt-gate-invalid")
        return errors
    if not isinstance(adjudication, Mapping):
        errors.append("steering-stop-adjudication-not-object")
        return errors
    adjudication_value = dict(adjudication)
    if set(adjudication_value) != FULL_AUTO_STOP_RESOLUTION_FIELDS:
        errors.append("steering-stop-adjudication-fields-invalid")
        return errors
    if adjudication_value.get("schema") != "cwo-resolved-stop-adjudication:v1":
        errors.append("steering-stop-adjudication-schema-invalid")
    if adjudication_value.get("gate") != "pre-mutation":
        errors.append("steering-stop-adjudication-gate-invalid")
    if adjudication_value.get("steering_receipt_canonical_sha256") != receipt.get(
        "canonical_receipt_sha256"
    ):
        errors.append("steering-stop-adjudication-receipt-mismatch")
    findings = adjudication_value.get("resolved_findings")
    if not isinstance(findings, list) or not findings:
        errors.append("steering-stop-adjudication-findings-invalid")
    else:
        for item in findings:
            if not _is_valid_resolved_finding(item):
                errors.append("steering-stop-adjudication-finding-invalid")
                break
    if adjudication_value.get("pre_live_reconfirmation_required") is not True:
        errors.append("steering-stop-adjudication-reconfirmation-required-missing")
    if adjudication_value.get("unresolved_high_severity_findings") != []:
        errors.append("steering-stop-adjudication-findings-unresolved")
    if not _is_hash(adjudication_value.get("resolution_evidence_sha256")):
        errors.append("steering-stop-adjudication-evidence-digest-invalid")
    post_commit = adjudication_value.get("post_resolution_commit")
    if not _is_commit(post_commit):
        errors.append("steering-stop-adjudication-post-commit-invalid")
    if not _is_commit(resolved_stop_post_resolution_commit):
        errors.append("steering-stop-adjudication-post-commit-missing")
    elif post_commit != resolved_stop_post_resolution_commit:
        errors.append("steering-stop-adjudication-post-commit-mismatch")
    if errors:
        return errors
    required_code_list = [
        finding.get("code")
        for finding in _extract_findings(receipt)
        if finding.get("severity") in {"high", "medium"}
    ]
    required_codes = set(required_code_list)
    if len(required_codes) != len(required_code_list):
        errors.append("steering-stop-receipt-finding-codes-duplicate")
    resolved_codes = {str(item.get("code")) for item in findings}
    if len(resolved_codes) != len(findings) or required_codes != resolved_codes:
        errors.append("steering-stop-adjudication-finding-codes-mismatch")
    return errors


def _extract_findings(receipt: Mapping[str, Any]) -> list[dict[str, Any]]:
    payload = steering_payload(receipt)
    if receipt.get("schema") == STEERING_RECEIPT_TYPE:
        observed = payload.get("observed_evidence")
        if not isinstance(observed, list):
            return []
        return [
            {
                "code": item["code"],
                "severity": item["severity"],
                "finding": item["observation"],
            }
            for item in observed
            if isinstance(item, Mapping)
            and item.get("severity") in {"high", "medium", "low"}
            and isinstance(item.get("code"), str)
            and isinstance(item.get("observation"), str)
        ]
    findings = payload.get("findings")
    return (
        findings
        if isinstance(findings, list)
        and all(isinstance(item, dict) for item in findings)
        else []
    )


def _private_write(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.parent.chmod(0o700)
    atomic_write_text(
        path, json.dumps(dict(value), sort_keys=True, separators=(",", ":")) + "\n"
    )
    path.chmod(0o600)
    if (
        path.is_symlink()
        or path.stat().st_uid != os.geteuid()
        or path.stat().st_mode & 0o077
    ):
        raise NativeCanaryContractError("private-artifact-permissions-invalid")


@contextmanager
def _exclusive_lock(path: Path) -> Iterator[None]:
    if path.exists() and path.is_symlink():
        raise NativeCanaryContractError("artifact-path-is-symlink")
    lock = path.with_suffix(path.suffix + ".lock")
    if lock.exists() and lock.is_symlink():
        raise NativeCanaryContractError("artifact-lock-is-symlink")
    lock.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with lock.open("a+", encoding="utf-8") as handle:
        os.fchmod(handle.fileno(), 0o600)
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def steering_stop_metadata(receipt: Mapping[str, Any]) -> dict[str, Any]:
    """Return policy-bounded v2 scope without trusting prose or confidence."""

    if receipt.get("schema") != STEERING_RECEIPT_TYPE:
        raise NativeCanaryContractError("steering-legacy-v1-inspection-only")
    expected = _expected_neutral_stop_metadata(receipt)
    for field in ("stop_scope", "authorized_continuation_paths", "scope_authority"):
        if receipt.get(field) != expected[field]:
            raise NativeCanaryContractError(
                f"steering-{field.replace('_', '-')}-mismatch"
            )
    return expected


def consume_steering_receipt(
    receipt: Mapping[str, Any],
    registry_file: Path | str,
    *,
    phase_nonce: str,
    architect_adjudication_sha256: str,
    architect_decision: str,
    allow_resolved_stop: bool = False,
    resolved_stop_adjudication: Mapping[str, Any] | None = None,
    resolved_stop_post_resolution_commit: str | None = None,
    verified_operator_authorities: Iterable[VerifiedOperatorFactAuthority]
    | None = None,
    dry_run: bool = False,
) -> str:
    errors = validate_steering_receipt(
        receipt,
        architect_adjudication_sha256=architect_adjudication_sha256,
        architect_decision=architect_decision,
        allow_resolved_stop=allow_resolved_stop,
        resolved_stop_adjudication=resolved_stop_adjudication,
        resolved_stop_post_resolution_commit=resolved_stop_post_resolution_commit,
        require_accepting=True,
        require_neutral=True,
        verified_operator_authorities=verified_operator_authorities,
    )
    if errors:
        raise NativeCanaryContractError("steering-receipt-invalid:" + ";".join(errors))
    if not _is_canonical_uuid(phase_nonce):
        raise NativeCanaryContractError("phase-nonce-invalid")
    stop_metadata = steering_stop_metadata(receipt)
    path = Path(registry_file).absolute()
    key = canonical_sha256(
        {
            "receipt": receipt["canonical_receipt_sha256"],
            "run": receipt["authorization_id"],
            "attempt": receipt["submission_id"],
            "gate": receipt["gate"],
            "phase_nonce": phase_nonce,
            "adjudication": architect_adjudication_sha256,
            "stop_metadata": stop_metadata,
        },
        domain="steering-receipt-consumption",
    )
    with _exclusive_lock(path):
        if path.exists():
            try:
                registry = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                raise NativeCanaryContractError("steering-registry-unreadable") from exc
        else:
            registry = {"consumed": []}
        if (
            not isinstance(registry, Mapping)
            or set(registry) != {"consumed"}
            or not isinstance(registry.get("consumed"), list)
        ):
            raise NativeCanaryContractError("steering-registry-invalid")
        consumed = list(registry["consumed"])
        receipt_hash = receipt["canonical_receipt_sha256"]
        if any(
            isinstance(item, Mapping)
            and (
                item.get("receipt_sha256") == receipt_hash
                or item.get("consumption_sha256") == key
            )
            for item in consumed
        ):
            raise NativeCanaryContractError("steering-receipt-replay")
        if dry_run:
            return key
        consumed.append(
            {
                "receipt_sha256": receipt_hash,
                "consumption_sha256": key,
                "phase_nonce": phase_nonce,
                **stop_metadata,
            }
        )
        _private_write(path, {"consumed": consumed})
    return key


def seal_authorization_state(value: Mapping[str, Any]) -> dict[str, Any]:
    body = dict(value)
    body.pop("state_sha256", None)
    body["state_sha256"] = canonical_sha256(body, domain="native-canary-authorization")
    return body


def _actions_for(state: str) -> set[str]:
    return (
        ACTIVE_ACTIONS
        if state == "active"
        else CONTAINMENT_ACTIONS
        if state == "containment-only"
        else TERMINAL_ACTIONS
    )


def validate_authorization_state(value: Any) -> list[str]:
    errors: list[str] = []
    is_v2 = (
        isinstance(value, Mapping)
        and value.get("authorization_type") == CANARY_AUTHORIZATION_TYPE_V2
        and value.get("version") == 2
    )
    state = _exact_fields(
        value,
        AUTHORIZATION_FIELDS_V2 if is_v2 else AUTHORIZATION_FIELDS,
        "authorization",
        errors,
    )
    expected_header = (
        (CANARY_AUTHORIZATION_TYPE_V2, 2, CANARY_AUTHORIZATION_SCHEMA_V2)
        if is_v2
        else (CANARY_AUTHORIZATION_TYPE, 1, CANARY_AUTHORIZATION_SCHEMA)
    )
    if (
        state.get("authorization_type"),
        state.get("version"),
        state.get("schema"),
    ) != expected_header:
        errors.append("authorization-header-invalid")
    if is_v2 and not _is_hash(state.get("launch_claim_sha256")):
        errors.append("authorization-launch-claim-sha256-invalid")
    if state.get("state") not in TRANSITIONS:
        errors.append("authorization-state-invalid")
    for field in ("authorization_id", "run_nonce", "reason"):
        if not isinstance(state.get(field), str) or not state.get(field):
            errors.append(f"authorization-{field}-invalid")
    for field in ("authorization_id", "run_nonce"):
        if is_v2 and not _is_canonical_uuid(state.get(field)):
            errors.append(f"authorization-{field}-not-canonical-uuid")
    if (
        isinstance(state.get("sequence"), bool)
        or not isinstance(state.get("sequence"), int)
        or state.get("sequence", -1) < 0
    ):
        errors.append("authorization-sequence-invalid")
    expected_allowed = _actions_for(str(state.get("state")))
    if state.get("allowed_actions") != sorted(expected_allowed):
        errors.append("authorization-allowed-actions-invalid")
    if state.get("revoked_actions") != sorted(ACTIVE_ACTIONS - expected_allowed):
        errors.append("authorization-revoked-actions-invalid")
    _parse_time(state.get("updated_at"), "authorization-updated-at", errors)
    unsigned = dict(state)
    unsigned.pop("state_sha256", None)
    if state.get("state_sha256") != canonical_sha256(
        unsigned, domain="native-canary-authorization"
    ):
        errors.append("authorization-state-sha256-mismatch")
    return sorted(set(errors))


def new_authorization_state(
    *,
    authorization_id: str,
    run_nonce: str,
    now: str,
    launch_claim_sha256: str | None = None,
) -> dict[str, Any]:
    if launch_claim_sha256 is not None and (
        not _is_canonical_uuid(authorization_id) or not _is_canonical_uuid(run_nonce)
    ):
        raise NativeCanaryContractError("authorization-identity-invalid")
    if launch_claim_sha256 is not None and not _is_hash(launch_claim_sha256):
        raise NativeCanaryContractError("authorization-launch-claim-sha256-invalid")
    state = {
        "authorization_type": (
            CANARY_AUTHORIZATION_TYPE_V2
            if launch_claim_sha256 is not None
            else CANARY_AUTHORIZATION_TYPE
        ),
        "version": 2 if launch_claim_sha256 is not None else 1,
        "schema": (
            CANARY_AUTHORIZATION_SCHEMA_V2
            if launch_claim_sha256 is not None
            else CANARY_AUTHORIZATION_SCHEMA
        ),
        "authorization_id": authorization_id,
        "run_nonce": run_nonce,
        "state": "active",
        "sequence": 0,
        "allowed_actions": sorted(ACTIVE_ACTIONS),
        "revoked_actions": [],
        "updated_at": now,
        "reason": "initialized",
    }
    if launch_claim_sha256 is not None:
        state["launch_claim_sha256"] = launch_claim_sha256
    return seal_authorization_state(state)


class CanaryAuthorizationStore:
    """A private, locked, monotonic authorization latch."""

    def __init__(self, path: Path | str) -> None:
        self.path = Path(path).absolute()

    def initialize(self, state: Mapping[str, Any]) -> dict[str, Any]:
        errors = validate_authorization_state(state)
        if errors or state.get("state") != "active" or state.get("sequence") != 0:
            raise NativeCanaryContractError(
                "authorization-initial-state-invalid:" + ";".join(errors)
            )
        with _exclusive_lock(self.path):
            if self.path.exists():
                raise NativeCanaryContractError("authorization-state-already-exists")
            _private_write(self.path, state)
        return dict(state)

    def _load_unlocked(self) -> dict[str, Any]:
        try:
            value = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise NativeCanaryContractError("authorization-state-unreadable") from exc
        errors = validate_authorization_state(value)
        if errors:
            raise NativeCanaryContractError(
                "authorization-state-invalid:" + ";".join(errors)
            )
        return dict(value)

    def load(self) -> dict[str, Any]:
        with _exclusive_lock(self.path):
            return self._load_unlocked()

    def transition(self, target: str, *, reason: str, now: str) -> dict[str, Any]:
        with _exclusive_lock(self.path):
            current = self._load_unlocked()
            if target not in TRANSITIONS[current["state"]]:
                raise NativeCanaryContractError("authorization-transition-forbidden")
            allowed = _actions_for(target)
            updated = seal_authorization_state(
                {
                    **current,
                    "state": target,
                    "sequence": current["sequence"] + 1,
                    "allowed_actions": sorted(allowed),
                    "revoked_actions": sorted(ACTIVE_ACTIONS - allowed),
                    "updated_at": now,
                    "reason": reason,
                }
            )
            _private_write(self.path, updated)
            return updated

    def require_action(self, action: str) -> dict[str, Any]:
        with _exclusive_lock(self.path):
            current = self._load_unlocked()
            if action not in current["allowed_actions"]:
                raise NativeCanaryContractError("authorization-action-revoked")
            return current
