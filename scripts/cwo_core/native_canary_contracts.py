"""Strict contracts for native canary materialization."""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import math
import re
import shlex
from typing import Any, Mapping
import uuid


MATERIALIZATION_EVIDENCE_TYPE = "cwo-native-session-materialization-evidence:v5"
MATERIALIZATION_EVIDENCE_SCHEMA = (
    "schemas/native-session-materialization-evidence.schema.json"
)

HASH_RE = re.compile(r"^[0-9a-f]{64}$")
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
    "correlation_mode",
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
TERMINAL_EXECUTION_CORRELATION_FIELDS = {
    "turn_context_record_index",
    "function_call_record_index",
    "function_call_id_sha256",
    "command_item_id_sha256",
    "notification_sequence",
    "notification_received_monotonic_ns",
    "notification_started_at_ms",
    "rendered_command_sha256",
    "execution_correlation_sha256",
}
NOTIFICATION_SHAPE_EVENT_FIELDS = {
    "sequence",
    "received_monotonic_ns",
    "method",
    "params_keys",
    "item_keys",
    "thread_id_matches",
    "turn_id_matches",
    "item_type",
    "item_status",
    "item_namespace",
    "item_tool",
    "item_id_sha256",
    "payload_digest_sha256",
    "started_at_ms_type",
}
NOTIFICATION_SHAPE_FIELDS = {
    "evidence_type",
    "version",
    "connection_epoch_sha256",
    "thread_id_sha256",
    "turn_id_sha256",
    "event_count",
    "events",
    "evidence_sha256",
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
    "notification_shape",
    "terminal_execution_correlation",
    "interrupt",
    "terminal",
    "terminal_event",
    "status",
    "disposition",
    "evidence_sha256",
}
PRIVACY_KEY_RE = re.compile(
    r"(^|_)(raw|prompt|command_text|arguments|output|response|reasoning|content|path|path_hash|path_sha256)($|_)",
    re.I,
)


class NativeCanaryContractError(ValueError):
    """Raised when a canary artifact or transition fails closed."""


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode()


def canonical_sha256(value: Any, *, domain: str) -> str:
    prefix = f"cwo:{domain}:v1\0".encode()
    return hashlib.sha256(prefix + _canonical_bytes(value)).hexdigest()


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


def materialization_liveness_correlation(
    *,
    connection_epoch_sha256: str,
    session_id: str,
    thread_id: str,
    turn_id: str,
    command_item_id_sha256: str,
    notification_sequence: int,
    notification_received_monotonic_ns: int,
    notification_started_at_ms: int,
    rendered_command_sha256: str,
    raw_command_sha256: str,
) -> str:
    """Bind live stdio liveness without claiming unflushed session records."""

    return length_framed_sha256(
        domain="native-capability-liveness-correlation",
        fields=(
            ("connection_epoch_sha256", connection_epoch_sha256),
            ("session_id", session_id),
            ("thread_id", thread_id),
            ("turn_id", turn_id),
            ("command_item_id_sha256", command_item_id_sha256),
            ("notification_sequence", notification_sequence),
            ("notification_received_monotonic_ns", notification_received_monotonic_ns),
            ("notification_started_at_ms", notification_started_at_ms),
            ("rendered_command_sha256", rendered_command_sha256),
            ("raw_command_sha256", raw_command_sha256),
        ),
    )


def _is_hash(value: Any) -> bool:
    return isinstance(value, str) and HASH_RE.fullmatch(value) is not None


def _is_canonical_uuid(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    try:
        parsed = uuid.UUID(value)
    except ValueError:
        return False
    return str(parsed) == value


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
    correlation_mode = observation.get("correlation_mode")
    if correlation_mode not in {"session-and-notification", "notification-first"}:
        errors.append(f"{label}-correlation-mode-invalid")
    for field in ("turn_context_record_index", "function_call_record_index"):
        current = observation.get(field)
        if correlation_mode == "session-and-notification":
            if isinstance(current, bool) or not isinstance(current, int) or current < 0:
                errors.append(f"{label}-{field}-invalid")
        elif current is not None:
            errors.append(f"{label}-{field}-must-be-null")
    for field in (
        "session_source_identity_sha256",
        "connection_epoch_sha256",
        "command_item_id_sha256",
        "rendered_command_sha256",
        "execution_correlation_sha256",
    ):
        if not _is_hash(observation.get(field)):
            errors.append(f"{label}-{field}-invalid")
    if correlation_mode == "session-and-notification":
        if not _is_hash(observation.get("function_call_id_sha256")):
            errors.append(f"{label}-function-call-id-sha256-invalid")
    elif observation.get("function_call_id_sha256") is not None:
        errors.append(f"{label}-function-call-id-sha256-must-be-null")
    if observation.get("command_source") not in {
        "unifiedExecStartup",
        "namespacedExecStartup",
    }:
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
    expected_function_calls = 1 if correlation_mode == "session-and-notification" else 0
    if observation.get("function_call_count") != expected_function_calls:
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


def _validate_notification_shape(
    value: Any, errors: list[str]
) -> dict[str, Any]:
    shape = _exact_fields(
        value,
        NOTIFICATION_SHAPE_FIELDS,
        "materialization-notification-shape",
        errors,
    )
    if (
        shape.get("evidence_type") != "cwo-app-server-notification-shape:v1"
        or shape.get("version") != 1
    ):
        errors.append("materialization-notification-shape-header-invalid")
    for field in (
        "connection_epoch_sha256",
        "thread_id_sha256",
        "turn_id_sha256",
    ):
        if not _is_hash(shape.get(field)):
            errors.append(f"materialization-notification-shape-{field}-invalid")
    events = shape.get("events")
    if not isinstance(events, list) or not events or len(events) > 16:
        errors.append("materialization-notification-shape-events-invalid")
        events = []
    if shape.get("event_count") != len(events):
        errors.append("materialization-notification-shape-count-invalid")
    previous_sequence = 0
    for index, raw_event in enumerate(events):
        event = _exact_fields(
            raw_event,
            NOTIFICATION_SHAPE_EVENT_FIELDS,
            f"materialization-notification-shape-event-{index}",
            errors,
        )
        sequence = event.get("sequence")
        if (
            isinstance(sequence, bool)
            or not isinstance(sequence, int)
            or sequence <= previous_sequence
        ):
            errors.append(
                f"materialization-notification-shape-event-{index}-sequence-invalid"
            )
        elif isinstance(sequence, int):
            previous_sequence = sequence
        received = event.get("received_monotonic_ns")
        if isinstance(received, bool) or not isinstance(received, int) or received < 0:
            errors.append(
                f"materialization-notification-shape-event-{index}-received-invalid"
            )
        if not isinstance(event.get("method"), str) or not event.get("method"):
            errors.append(
                f"materialization-notification-shape-event-{index}-method-invalid"
            )
        for field in ("params_keys", "item_keys"):
            keys = event.get(field)
            if (
                not isinstance(keys, list)
                or any(not isinstance(item, str) or not item for item in keys)
                or keys != sorted(set(keys))
            ):
                errors.append(
                    f"materialization-notification-shape-event-{index}-{field}-invalid"
                )
        for field in ("thread_id_matches", "turn_id_matches"):
            if event.get(field) is not True:
                errors.append(
                    f"materialization-notification-shape-event-{index}-{field}-invalid"
                )
        for field in ("item_type", "item_status"):
            if not isinstance(event.get(field), str) or not event.get(field):
                errors.append(
                    f"materialization-notification-shape-event-{index}-{field}-invalid"
                )
        for field in ("item_namespace", "item_tool"):
            if event.get(field) is not None and not isinstance(event.get(field), str):
                errors.append(
                    f"materialization-notification-shape-event-{index}-{field}-invalid"
                )
        for field in ("item_id_sha256", "payload_digest_sha256"):
            if not _is_hash(event.get(field)):
                errors.append(
                    f"materialization-notification-shape-event-{index}-{field}-invalid"
                )
        if event.get("started_at_ms_type") not in {"integer", "missing"}:
            errors.append(
                f"materialization-notification-shape-event-{index}-started-type-invalid"
            )
    expected_hash = shape.get("evidence_sha256")
    unsigned = dict(shape)
    unsigned.pop("evidence_sha256", None)
    if expected_hash != canonical_sha256(
        unsigned, domain="native-app-server-notification-shape"
    ):
        errors.append("materialization-notification-shape-sha256-mismatch")
    return shape


def _validate_terminal_execution_correlation(
    value: Any, terminal: Mapping[str, Any], errors: list[str]
) -> dict[str, Any]:
    correlation = _exact_fields(
        value,
        TERMINAL_EXECUTION_CORRELATION_FIELDS,
        "materialization-terminal-execution",
        errors,
    )
    for field in (
        "turn_context_record_index",
        "function_call_record_index",
        "notification_sequence",
        "notification_received_monotonic_ns",
        "notification_started_at_ms",
    ):
        current = correlation.get(field)
        if isinstance(current, bool) or not isinstance(current, int) or current < 0:
            errors.append(f"materialization-terminal-execution-{field}-invalid")
    for field in (
        "function_call_id_sha256",
        "command_item_id_sha256",
        "rendered_command_sha256",
        "execution_correlation_sha256",
    ):
        if not _is_hash(correlation.get(field)):
            errors.append(f"materialization-terminal-execution-{field}-invalid")
    terminal_count = terminal.get("record_count")
    if isinstance(terminal_count, int):
        for field in ("turn_context_record_index", "function_call_record_index"):
            current = correlation.get(field)
            if isinstance(current, int) and current >= terminal_count:
                errors.append(
                    f"materialization-terminal-execution-{field}-out-of-range"
                )
    return correlation


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
        evidence.get("version") != 5
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
    notification_shape = _validate_notification_shape(
        evidence.get("notification_shape"), errors
    )
    terminal_execution = _validate_terminal_execution_correlation(
        evidence.get("terminal_execution_correlation"), terminal, errors
    )
    if notification_shape.get("connection_epoch_sha256") != evidence.get(
        "connection_epoch_sha256"
    ):
        errors.append("materialization-notification-shape-connection-mismatch")
    thread_id = evidence.get("thread_id")
    expected_thread_hash = (
        hashlib.sha256(thread_id.encode("utf-8")).hexdigest()
        if isinstance(thread_id, str)
        else None
    )
    if notification_shape.get("thread_id_sha256") != expected_thread_hash:
        errors.append("materialization-notification-shape-thread-mismatch")
    turn_id = evidence.get("turn_id")
    expected_turn_hash = (
        hashlib.sha256(turn_id.encode("utf-8")).hexdigest()
        if isinstance(turn_id, str)
        else None
    )
    if notification_shape.get("turn_id_sha256") != expected_turn_hash:
        errors.append("materialization-notification-shape-turn-mismatch")
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
            "correlation_mode",
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
                expected_correlation = materialization_liveness_correlation(
                    connection_epoch_sha256=str(item.get("connection_epoch_sha256")),
                    session_id=str(evidence.get("session_id")),
                    thread_id=str(evidence.get("thread_id")),
                    turn_id=str(evidence.get("turn_id")),
                    command_item_id_sha256=str(item.get("command_item_id_sha256")),
                    notification_sequence=item.get("notification_sequence"),
                    notification_received_monotonic_ns=item.get(
                        "notification_received_monotonic_ns"
                    ),
                    notification_started_at_ms=item.get("notification_started_at_ms"),
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
        if any(
            terminal_execution.get(field) != pre_interrupt.get(field)
            for field in (
                "command_item_id_sha256",
                "notification_sequence",
                "notification_received_monotonic_ns",
                "notification_started_at_ms",
                "rendered_command_sha256",
            )
        ):
            errors.append("materialization-terminal-execution-liveness-mismatch")
        if pre_interrupt.get("correlation_mode") == "session-and-notification":
            if any(
                terminal_execution.get(field) != pre_interrupt.get(field)
                for field in (
                    "turn_context_record_index",
                    "function_call_record_index",
                    "function_call_id_sha256",
                )
            ):
                errors.append(
                    "materialization-terminal-execution-session-correlation-mismatch"
                )
        try:
            expected_terminal_correlation = materialization_execution_correlation(
                connection_epoch_sha256=str(evidence.get("connection_epoch_sha256")),
                session_id=str(evidence.get("session_id")),
                thread_id=str(evidence.get("thread_id")),
                turn_id=str(evidence.get("turn_id")),
                command_item_id_sha256=str(
                    terminal_execution.get("command_item_id_sha256")
                ),
                function_call_id_sha256=str(
                    terminal_execution.get("function_call_id_sha256")
                ),
                notification_sequence=terminal_execution.get("notification_sequence"),
                notification_received_monotonic_ns=terminal_execution.get(
                    "notification_received_monotonic_ns"
                ),
                notification_started_at_ms=terminal_execution.get(
                    "notification_started_at_ms"
                ),
                turn_context_record_index=terminal_execution.get(
                    "turn_context_record_index"
                ),
                function_call_record_index=terminal_execution.get(
                    "function_call_record_index"
                ),
                rendered_command_sha256=str(
                    terminal_execution.get("rendered_command_sha256")
                ),
                raw_command_sha256=str(evidence.get("command_sha256")),
            )
        except NativeCanaryContractError:
            errors.append("materialization-terminal-execution-correlation-input-invalid")
        else:
            if (
                terminal_execution.get("execution_correlation_sha256")
                != expected_terminal_correlation
            ):
                errors.append("materialization-terminal-execution-correlation-mismatch")
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
