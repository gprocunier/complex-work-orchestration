"""Strict contracts for trusted native canary steering and materialization."""

from __future__ import annotations

from contextlib import contextmanager
import datetime as dt
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
from typing import Any, Iterator, Mapping
import uuid

from .util import atomic_write_text


STEERING_RECEIPT_TYPE = "cwo-steering-receipt:v1"
MATERIALIZATION_EVIDENCE_TYPE = "cwo-native-session-materialization-evidence:v3"
CANARY_AUTHORIZATION_TYPE = "cwo-native-canary-authorization-state:v1"
STEERING_RECEIPT_SCHEMA = "schemas/native-steering-receipt.schema.json"
MATERIALIZATION_EVIDENCE_SCHEMA = "schemas/native-session-materialization-evidence.schema.json"
CANARY_AUTHORIZATION_SCHEMA = "schemas/native-canary-authorization-state.schema.json"

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
    "baseline",
    "liveness_observations",
    "pre_interrupt_observation",
    "interrupt",
    "terminal",
    "status",
    "disposition",
    "evidence_sha256",
}
STEERING_FIELDS = {
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


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


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


def _legacy_sha256(value: Any) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _is_hash(value: Any) -> bool:
    return isinstance(value, str) and HASH_RE.fullmatch(value) is not None


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


def _exact_fields(value: Any, expected: set[str], label: str, errors: list[str]) -> dict[str, Any]:
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


def _validate_observation(value: Any, label: str, errors: list[str]) -> tuple[dict[str, Any], dt.datetime]:
    observation = _exact_fields(value, OBSERVATION_FIELDS, label, errors)
    observed = _parse_time(observation.get("observed_at"), f"{label}-observed-at", errors)
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


def seal_materialization_evidence(value: Mapping[str, Any]) -> dict[str, Any]:
    body = dict(value)
    body.pop("evidence_sha256", None)
    body["evidence_sha256"] = canonical_sha256(body, domain="native-session-materialization")
    return body


def validate_materialization_evidence(value: Any, *, require_accepting: bool = False) -> list[str]:
    errors: list[str] = []
    evidence = _exact_fields(value, MATERIALIZATION_FIELDS, "materialization", errors)
    if evidence.get("evidence_type") != MATERIALIZATION_EVIDENCE_TYPE:
        errors.append("materialization-type-invalid")
    if evidence.get("version") != 3 or evidence.get("schema") != MATERIALIZATION_EVIDENCE_SCHEMA:
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
        try:
            uuid.UUID(str(evidence.get(field)))
        except ValueError:
            errors.append(f"materialization-{field}-not-uuid")
    if evidence.get("requested_model") != evidence.get("attested_model"):
        errors.append("materialization-model-mismatch")
    if evidence.get("session_id") != evidence.get("thread_id"):
        errors.append("materialization-session-thread-mismatch")
    for field in ("connection_epoch_sha256", "command_sha256"):
        if not _is_hash(evidence.get(field)):
            errors.append(f"materialization-{field}-invalid")
    baseline = _validate_boundary(evidence.get("baseline"), "materialization-baseline", errors)
    terminal = _validate_boundary(evidence.get("terminal"), "materialization-terminal", errors)
    observations = evidence.get("liveness_observations")
    if not isinstance(observations, list) or len(observations) != 2:
        errors.append("materialization-liveness-observations-invalid")
        observations = []
    parsed_observations = [
        _validate_observation(item, f"materialization-liveness-{index}", errors)
        for index, item in enumerate(observations)
    ]
    pre_interrupt, pre_time = _validate_observation(
        evidence.get("pre_interrupt_observation"), "materialization-pre-interrupt", errors
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
        if any(second.get(field) != pre_interrupt.get(field) for field in identity_fields):
            errors.append("materialization-pre-interrupt-identity-changed")
        if pre_time < second_time:
            errors.append("materialization-pre-interrupt-precedes-liveness")
        if any(
            item.get("connection_epoch_sha256") != evidence.get("connection_epoch_sha256")
            for item, _time in (*parsed_observations, (pre_interrupt, pre_time))
        ):
            errors.append("materialization-connection-epoch-mismatch")
        for index, (item, _time) in enumerate((*parsed_observations, (pre_interrupt, pre_time))):
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
                errors.append(f"materialization-observation-{index}-correlation-input-invalid")
            else:
                if item.get("execution_correlation_sha256") != expected_correlation:
                    errors.append(f"materialization-observation-{index}-correlation-mismatch")
    interrupt = _exact_fields(evidence.get("interrupt"), INTERRUPT_FIELDS, "materialization-interrupt", errors)
    requested = _parse_time(interrupt.get("requested_at"), "materialization-interrupt-requested", errors)
    accepted = _parse_time(
        interrupt.get("request_accepted_at"), "materialization-interrupt-request-accepted", errors
    )
    confirmed = _parse_time(interrupt.get("confirmed_at"), "materialization-interrupt-confirmed", errors)
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
    if accepted < requested or confirmed < accepted or (confirmed - requested).total_seconds() > 5.0:
        errors.append("materialization-interrupt-confirmation-deadline-invalid")
    if baseline and terminal:
        if terminal.get("record_count", 0) < baseline.get("record_count", 0) or terminal.get(
            "byte_offset", 0
        ) < baseline.get("byte_offset", 0):
            errors.append("materialization-terminal-boundary-regressed")
    if terminal.get("invalid_record_count") != 0 or terminal.get("trailing_partial") is not False:
        errors.append("materialization-terminal-boundary-not-clean")
    errors.extend(_privacy_errors(evidence))
    expected_hash = evidence.get("evidence_sha256")
    unsigned = dict(evidence)
    unsigned.pop("evidence_sha256", None)
    if expected_hash != canonical_sha256(unsigned, domain="native-session-materialization"):
        errors.append("materialization-evidence-sha256-mismatch")
    accepting = evidence.get("status") == "interrupt-confirmed" and evidence.get("disposition") == "accepted"
    if require_accepting and not accepting:
        errors.append("materialization-evidence-not-accepting")
    return sorted(set(errors))


def validate_steering_receipt(
    value: Any,
    *,
    architect_adjudication_sha256: str | None = None,
    architect_decision: str | None = None,
    require_accepting: bool = False,
) -> list[str]:
    errors: list[str] = []
    receipt = _exact_fields(value, STEERING_FIELDS, "steering", errors)
    if receipt.get("schema") != STEERING_RECEIPT_TYPE:
        errors.append("steering-schema-invalid")
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
    if receipt.get("model") != "gpt-5.6-sol" or receipt.get("effort") != "max":
        errors.append("steering-model-effort-mismatch")
    if receipt.get("attestation_source") != "initialized-codex-home-session-jsonl-turn-context":
        errors.append("steering-attestation-source-invalid")
    for field in ("authorization_sha256", "final_response_sha256", "canonical_receipt_sha256"):
        if not _is_hash(receipt.get(field)):
            errors.append(f"steering-{field}-invalid")
    boundaries = receipt.get("boundary")
    if not isinstance(boundaries, Mapping) or set(boundaries) != {"baseline", "terminal"}:
        errors.append("steering-boundary-fields-invalid")
        terminal: Mapping[str, Any] = {}
    else:
        terminal = boundaries.get("terminal") if isinstance(boundaries.get("terminal"), Mapping) else {}
    if terminal.get("invalid_record_count") != 0 or terminal.get("trailing_partial") is not False:
        errors.append("steering-terminal-boundary-not-clean")
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
    opinion = receipt.get("opinion") if isinstance(receipt.get("opinion"), Mapping) else {}
    recommendation = opinion.get("recommendation")
    if recommendation not in {"go", "conditional-go", "stop"}:
        errors.append("steering-recommendation-invalid")
    if receipt.get("closure_outcome") != "completed-and-archived":
        errors.append("steering-closure-invalid")
    unsigned = dict(receipt)
    unsigned.pop("canonical_receipt_sha256", None)
    if receipt.get("canonical_receipt_sha256") != _legacy_sha256(unsigned):
        errors.append("steering-canonical-sha256-mismatch")
    accepting = recommendation == "go"
    if recommendation == "conditional-go":
        accepting = _is_hash(architect_adjudication_sha256) and architect_decision == "go"
    if require_accepting and not accepting:
        errors.append("steering-receipt-not-accepting")
    return sorted(set(errors))


def _private_write(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.parent.chmod(0o700)
    atomic_write_text(path, json.dumps(dict(value), sort_keys=True, separators=(",", ":")) + "\n")
    path.chmod(0o600)
    if path.is_symlink() or path.stat().st_uid != os.geteuid() or path.stat().st_mode & 0o077:
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


def consume_steering_receipt(
    receipt: Mapping[str, Any],
    registry_file: Path | str,
    *,
    phase_nonce: str,
    architect_adjudication_sha256: str,
    architect_decision: str,
) -> str:
    errors = validate_steering_receipt(
        receipt,
        architect_adjudication_sha256=architect_adjudication_sha256,
        architect_decision=architect_decision,
        require_accepting=True,
    )
    if errors:
        raise NativeCanaryContractError("steering-receipt-invalid:" + ";".join(errors))
    try:
        uuid.UUID(phase_nonce)
    except ValueError as exc:
        raise NativeCanaryContractError("phase-nonce-invalid") from exc
    path = Path(registry_file).absolute()
    key = canonical_sha256(
        {
            "receipt": receipt["canonical_receipt_sha256"],
            "run": receipt["authorization_id"],
            "attempt": receipt["submission_id"],
            "gate": receipt["gate"],
            "phase_nonce": phase_nonce,
            "adjudication": architect_adjudication_sha256,
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
        if not isinstance(registry, Mapping) or set(registry) != {"consumed"} or not isinstance(
            registry.get("consumed"), list
        ):
            raise NativeCanaryContractError("steering-registry-invalid")
        consumed = list(registry["consumed"])
        receipt_hash = receipt["canonical_receipt_sha256"]
        if any(
            isinstance(item, Mapping)
            and (item.get("receipt_sha256") == receipt_hash or item.get("consumption_sha256") == key)
            for item in consumed
        ):
            raise NativeCanaryContractError("steering-receipt-replay")
        consumed.append(
            {
                "receipt_sha256": receipt_hash,
                "consumption_sha256": key,
                "phase_nonce": phase_nonce,
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
    return ACTIVE_ACTIONS if state == "active" else CONTAINMENT_ACTIONS if state == "containment-only" else TERMINAL_ACTIONS


def validate_authorization_state(value: Any) -> list[str]:
    errors: list[str] = []
    state = _exact_fields(value, AUTHORIZATION_FIELDS, "authorization", errors)
    if state.get("authorization_type") != CANARY_AUTHORIZATION_TYPE:
        errors.append("authorization-type-invalid")
    if state.get("version") != 1 or state.get("schema") != CANARY_AUTHORIZATION_SCHEMA:
        errors.append("authorization-header-invalid")
    if state.get("state") not in TRANSITIONS:
        errors.append("authorization-state-invalid")
    for field in ("authorization_id", "run_nonce", "reason"):
        if not isinstance(state.get(field), str) or not state.get(field):
            errors.append(f"authorization-{field}-invalid")
    if isinstance(state.get("sequence"), bool) or not isinstance(state.get("sequence"), int) or state.get(
        "sequence", -1
    ) < 0:
        errors.append("authorization-sequence-invalid")
    expected_allowed = _actions_for(str(state.get("state")))
    if state.get("allowed_actions") != sorted(expected_allowed):
        errors.append("authorization-allowed-actions-invalid")
    if state.get("revoked_actions") != sorted(ACTIVE_ACTIONS - expected_allowed):
        errors.append("authorization-revoked-actions-invalid")
    _parse_time(state.get("updated_at"), "authorization-updated-at", errors)
    unsigned = dict(state)
    unsigned.pop("state_sha256", None)
    if state.get("state_sha256") != canonical_sha256(unsigned, domain="native-canary-authorization"):
        errors.append("authorization-state-sha256-mismatch")
    return sorted(set(errors))


def new_authorization_state(*, authorization_id: str, run_nonce: str, now: str) -> dict[str, Any]:
    return seal_authorization_state(
        {
            "authorization_type": CANARY_AUTHORIZATION_TYPE,
            "version": 1,
            "schema": CANARY_AUTHORIZATION_SCHEMA,
            "authorization_id": authorization_id,
            "run_nonce": run_nonce,
            "state": "active",
            "sequence": 0,
            "allowed_actions": sorted(ACTIVE_ACTIONS),
            "revoked_actions": [],
            "updated_at": now,
            "reason": "initialized",
        }
    )


class CanaryAuthorizationStore:
    """A private, locked, monotonic authorization latch."""

    def __init__(self, path: Path | str) -> None:
        self.path = Path(path).absolute()

    def initialize(self, state: Mapping[str, Any]) -> dict[str, Any]:
        errors = validate_authorization_state(state)
        if errors or state.get("state") != "active" or state.get("sequence") != 0:
            raise NativeCanaryContractError("authorization-initial-state-invalid:" + ";".join(errors))
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
            raise NativeCanaryContractError("authorization-state-invalid:" + ";".join(errors))
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
