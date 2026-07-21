"""Typed evidence for one non-replayable app-server ``turn/start`` request."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import re
from typing import Any, Mapping


TURN_DISPATCH_ARTIFACT_TYPE = "cwo-native-turn-dispatch:v1"
TURN_ABSENCE_PROOF_ARTIFACT_TYPE = "cwo-native-turn-absence-proof:v1"
TURN_ABSENCE_PROOF_MIN_QUIET_WINDOW_MS = 50
TURN_DISPATCH_STATUSES = {
    "prepared",
    "dispatching",
    "acknowledged",
    "failed-contained",
    "failed-ambiguous",
}
TURN_DISPATCH_LEDGER_RESOLUTIONS = {
    "pending",
    "turn-bound",
    "verified-absent",
}
TURN_DISPATCH_FIELDS = {
    "artifact_type",
    "version",
    "thread_id",
    "turn_intent_id",
    "client_user_message_id",
    "request_id",
    "connection_epoch_sha256",
    "notification_cursor",
    "preexisting_turn_ids",
    "ledger_id",
    "ledger_head_entry_sha256",
    "turn_intent_entry_sha256",
    "wire_request_sha256",
    "wire_write_attempt_count",
    "status",
    "ambiguity_reason",
    "exact_response_turn_id",
    "notification_sequences",
    "discovered_turn_ids",
    "interrupt_attempted_turn_ids",
    "interrupt_failed_turn_ids",
    "terminal_status_by_turn",
    "active_turn_ids_at_final_check",
    "query_count",
    "absence_verified",
    "absence_proof_sha256",
    "archived",
    "ledger_resolution",
    "record_sha256",
}
TURN_ABSENCE_PROOF_FIELDS = {
    "artifact_type",
    "version",
    "thread_id",
    "turn_intent_id",
    "ledger_id",
    "turn_intent_entry_sha256",
    "dispatch_record",
    "first_empty_query_count",
    "final_empty_query_count",
    "quiet_window_ms",
    "notification_cursor_before_quiet",
    "notification_cursor_after_final_query",
    "post_query_notification_sequences",
    "final_active_turn_ids",
    "proof_sha256",
}
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)


class NativeTurnDispatchError(ValueError):
    """Raised when turn-dispatch evidence is malformed or contradictory."""


def _canonical_bytes(value: Mapping[str, Any]) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def _record_sha256(value: Mapping[str, Any]) -> str:
    unsigned = {key: item for key, item in value.items() if key != "record_sha256"}
    return hashlib.sha256(
        b"cwo-native-turn-dispatch-record\0" + _canonical_bytes(unsigned)
    ).hexdigest()


def _absence_proof_sha256(value: Mapping[str, Any]) -> str:
    unsigned = {key: item for key, item in value.items() if key != "proof_sha256"}
    return hashlib.sha256(
        b"cwo-native-turn-absence-proof\0" + _canonical_bytes(unsigned)
    ).hexdigest()


def _is_hash(value: Any) -> bool:
    return isinstance(value, str) and _SHA256_RE.fullmatch(value) is not None


def _is_uuid(value: Any) -> bool:
    return isinstance(value, str) and _UUID_RE.fullmatch(value) is not None


def _is_sorted_unique_strings(value: Any) -> bool:
    return (
        isinstance(value, list)
        and all(isinstance(item, str) and item for item in value)
        and value == sorted(set(value))
    )


def _is_sorted_unique_ints(value: Any) -> bool:
    return (
        isinstance(value, list)
        and all(type(item) is int and item >= 1 for item in value)
        and value == sorted(set(value))
    )


def validate_turn_dispatch_record(value: Any) -> list[str]:
    """Return strict validation findings for one dispatch-correlation record."""

    if not isinstance(value, Mapping):
        return ["turn-dispatch-record-must-be-object"]
    errors: list[str] = []
    missing = sorted(TURN_DISPATCH_FIELDS - set(value))
    unknown = sorted(set(value) - TURN_DISPATCH_FIELDS)
    if missing:
        errors.append("turn-dispatch-record-missing-fields:" + ",".join(missing))
    if unknown:
        errors.append("turn-dispatch-record-unknown-fields:" + ",".join(unknown))
    if missing or unknown:
        return errors
    if value.get("artifact_type") != TURN_DISPATCH_ARTIFACT_TYPE:
        errors.append("turn-dispatch-artifact-type-invalid")
    if value.get("version") != 1:
        errors.append("turn-dispatch-version-invalid")
    if not isinstance(value.get("thread_id"), str) or not value["thread_id"]:
        errors.append("turn-dispatch-thread-id-invalid")
    if not _is_uuid(value.get("turn_intent_id")):
        errors.append("turn-dispatch-intent-id-invalid")
    if value.get("client_user_message_id") != value.get("turn_intent_id"):
        errors.append("turn-dispatch-client-message-binding-invalid")
    if type(value.get("request_id")) is not int or value["request_id"] < 1:
        errors.append("turn-dispatch-request-id-invalid")
    if not _is_hash(value.get("connection_epoch_sha256")):
        errors.append("turn-dispatch-connection-epoch-invalid")
    if (
        type(value.get("notification_cursor")) is not int
        or value["notification_cursor"] < 0
    ):
        errors.append("turn-dispatch-notification-cursor-invalid")
    for field in (
        "preexisting_turn_ids",
        "discovered_turn_ids",
        "interrupt_attempted_turn_ids",
        "interrupt_failed_turn_ids",
        "active_turn_ids_at_final_check",
    ):
        if not _is_sorted_unique_strings(value.get(field)):
            errors.append(f"turn-dispatch-{field.replace('_', '-')}-invalid")
    if not _is_sorted_unique_ints(value.get("notification_sequences")):
        errors.append("turn-dispatch-notification-sequences-invalid")
    for field in (
        "ledger_id",
        "ledger_head_entry_sha256",
        "turn_intent_entry_sha256",
    ):
        item = value.get(field)
        if item is not None and (
            not isinstance(item, str)
            or (field == "ledger_id" and not _is_uuid(item))
            or (field != "ledger_id" and not _is_hash(item))
        ):
            errors.append(f"turn-dispatch-{field.replace('_', '-')}-invalid")
    if (
        len(
            {
                value.get("ledger_id") is None,
                value.get("ledger_head_entry_sha256") is None,
                value.get("turn_intent_entry_sha256") is None,
            }
        )
        != 1
    ):
        errors.append("turn-dispatch-ledger-link-incomplete")
    if not _is_hash(value.get("wire_request_sha256")):
        errors.append("turn-dispatch-wire-request-sha256-invalid")
    if value.get("wire_write_attempt_count") not in {0, 1}:
        errors.append("turn-dispatch-wire-write-count-invalid")
    status = value.get("status")
    if status not in TURN_DISPATCH_STATUSES:
        errors.append("turn-dispatch-status-invalid")
    ambiguity_reason = value.get("ambiguity_reason")
    if ambiguity_reason is not None and (
        not isinstance(ambiguity_reason, str) or not ambiguity_reason
    ):
        errors.append("turn-dispatch-ambiguity-reason-invalid")
    exact_turn = value.get("exact_response_turn_id")
    if exact_turn is not None and (not isinstance(exact_turn, str) or not exact_turn):
        errors.append("turn-dispatch-exact-response-turn-id-invalid")
    terminal = value.get("terminal_status_by_turn")
    if not isinstance(terminal, Mapping) or any(
        not isinstance(key, str)
        or not key
        or item not in {"completed", "failed", "interrupted"}
        for key, item in terminal.items()
    ):
        errors.append("turn-dispatch-terminal-statuses-invalid")
    if type(value.get("query_count")) is not int or value["query_count"] < 0:
        errors.append("turn-dispatch-query-count-invalid")
    for field in ("absence_verified", "archived"):
        if type(value.get(field)) is not bool:
            errors.append(f"turn-dispatch-{field.replace('_', '-')}-invalid")
    absence_proof_sha256 = value.get("absence_proof_sha256")
    if absence_proof_sha256 is not None and not _is_hash(absence_proof_sha256):
        errors.append("turn-dispatch-absence-proof-sha256-invalid")
    if value.get("ledger_resolution") not in TURN_DISPATCH_LEDGER_RESOLUTIONS:
        errors.append("turn-dispatch-ledger-resolution-invalid")
    empty_progress = bool(
        exact_turn is None
        and not value.get("notification_sequences")
        and not value.get("discovered_turn_ids")
        and not value.get("interrupt_attempted_turn_ids")
        and not value.get("interrupt_failed_turn_ids")
        and not value.get("terminal_status_by_turn")
        and not value.get("active_turn_ids_at_final_check")
        and value.get("query_count") == 0
        and value.get("absence_verified") is False
        and absence_proof_sha256 is None
        and value.get("archived") is False
    )
    if status == "prepared" and (
        value.get("wire_write_attempt_count") != 0
        or ambiguity_reason is not None
        or value.get("ledger_resolution") != "pending"
        or not empty_progress
    ):
        errors.append("turn-dispatch-prepared-state-invalid")
    if status == "dispatching" and (
        value.get("wire_write_attempt_count") != 1
        or ambiguity_reason is not None
        or value.get("ledger_resolution") != "pending"
        or not empty_progress
    ):
        errors.append("turn-dispatch-dispatching-state-invalid")
    if status == "acknowledged" and (
        value.get("wire_write_attempt_count") != 1
        or exact_turn is None
        or value.get("discovered_turn_ids") != [exact_turn]
        or value.get("ledger_resolution") != "turn-bound"
        or ambiguity_reason is not None
        or value.get("notification_sequences")
        or value.get("interrupt_attempted_turn_ids")
        or value.get("interrupt_failed_turn_ids")
        or value.get("terminal_status_by_turn")
        or value.get("active_turn_ids_at_final_check")
        or value.get("query_count") != 0
        or value.get("absence_verified") is not False
        or absence_proof_sha256 is not None
        or value.get("archived") is not False
    ):
        errors.append("turn-dispatch-acknowledged-state-invalid")
    if status in {"failed-contained", "failed-ambiguous"} and (
        value.get("wire_write_attempt_count") != 1 or ambiguity_reason is None
    ):
        errors.append("turn-dispatch-ambiguous-state-invalid")
    if status == "failed-contained" and (
        not value.get("absence_verified")
        or value.get("active_turn_ids_at_final_check")
        or value.get("interrupt_failed_turn_ids")
        or set(value.get("discovered_turn_ids", []))
        != set(value.get("terminal_status_by_turn", {}))
        or value.get("ledger_resolution") not in {"turn-bound", "verified-absent"}
        or bool(value.get("discovered_turn_ids"))
        != (value.get("ledger_resolution") == "turn-bound")
        or value.get("archived") is not True
    ):
        errors.append("turn-dispatch-contained-proof-invalid")
    if (
        status == "failed-ambiguous"
        and value.get("archived")
        and (
            not value.get("absence_verified")
            or value.get("active_turn_ids_at_final_check")
            or value.get("interrupt_failed_turn_ids")
            or set(value.get("discovered_turn_ids", []))
            != set(value.get("terminal_status_by_turn", {}))
            or value.get("ledger_resolution") == "pending"
        )
    ):
        errors.append("turn-dispatch-ambiguous-archive-invalid")
    if not set(value.get("interrupt_failed_turn_ids", [])).issubset(
        value.get("interrupt_attempted_turn_ids", [])
    ):
        errors.append("turn-dispatch-interrupt-failure-without-attempt")
    if not set(value.get("interrupt_attempted_turn_ids", [])).issubset(
        value.get("discovered_turn_ids", [])
    ):
        errors.append("turn-dispatch-interrupt-attempt-without-discovery")
    if not set(value.get("terminal_status_by_turn", {})).issubset(
        value.get("discovered_turn_ids", [])
    ):
        errors.append("turn-dispatch-terminal-status-without-discovery")
    if exact_turn is not None and exact_turn not in value.get(
        "discovered_turn_ids", []
    ):
        errors.append("turn-dispatch-exact-response-without-discovery")
    discovered = set(value.get("discovered_turn_ids", []))
    active = set(value.get("active_turn_ids_at_final_check", []))
    terminal_turns = set(value.get("terminal_status_by_turn", {}))
    if not active.issubset(discovered) or active.intersection(terminal_turns):
        errors.append("turn-dispatch-active-turn-phase-invalid")
    if set(value.get("preexisting_turn_ids", [])).intersection(discovered):
        errors.append("turn-dispatch-preexisting-turn-rediscovered")
    if any(
        sequence <= value.get("notification_cursor", -1)
        for sequence in value.get("notification_sequences", [])
    ):
        errors.append("turn-dispatch-notification-sequence-before-cursor")
    if value.get("absence_verified") and (value.get("query_count", 0) < 2 or active):
        errors.append("turn-dispatch-absence-phase-invalid")
    ledger_resolution = value.get("ledger_resolution")
    if ledger_resolution == "verified-absent" and (
        discovered
        or exact_turn is not None
        or not value.get("absence_verified")
        or not _is_hash(absence_proof_sha256)
    ):
        errors.append("turn-dispatch-verified-absent-resolution-invalid")
    if ledger_resolution == "turn-bound" and (
        not discovered or absence_proof_sha256 is not None
    ):
        errors.append("turn-dispatch-bound-resolution-invalid")
    if absence_proof_sha256 is not None and (
        discovered or not value.get("absence_verified")
    ):
        errors.append("turn-dispatch-absence-proof-phase-invalid")
    if value.get("archived") and status not in {
        "failed-contained",
        "failed-ambiguous",
    }:
        errors.append("turn-dispatch-archive-phase-invalid")
    if status not in {"failed-contained", "failed-ambiguous"} and (
        value.get("notification_sequences")
        or value.get("interrupt_attempted_turn_ids")
        or value.get("terminal_status_by_turn")
        or value.get("active_turn_ids_at_final_check")
        or value.get("query_count")
    ):
        errors.append("turn-dispatch-noncontainment-progress-invalid")
    if value.get("record_sha256") != _record_sha256(value):
        errors.append("turn-dispatch-record-sha256-invalid")
    return errors


def validate_turn_absence_proof(value: Any) -> list[str]:
    """Return strict findings for one immutable, quiet-window absence proof."""

    if not isinstance(value, Mapping):
        return ["turn-absence-proof-must-be-object"]
    errors: list[str] = []
    missing = sorted(TURN_ABSENCE_PROOF_FIELDS - set(value))
    unknown = sorted(set(value) - TURN_ABSENCE_PROOF_FIELDS)
    if missing:
        errors.append("turn-absence-proof-missing-fields:" + ",".join(missing))
    if unknown:
        errors.append("turn-absence-proof-unknown-fields:" + ",".join(unknown))
    if missing or unknown:
        return errors
    if value.get("artifact_type") != TURN_ABSENCE_PROOF_ARTIFACT_TYPE:
        errors.append("turn-absence-proof-artifact-type-invalid")
    if value.get("version") != 1:
        errors.append("turn-absence-proof-version-invalid")
    if not isinstance(value.get("thread_id"), str) or not value["thread_id"]:
        errors.append("turn-absence-proof-thread-id-invalid")
    if not _is_uuid(value.get("turn_intent_id")):
        errors.append("turn-absence-proof-intent-id-invalid")
    if not _is_uuid(value.get("ledger_id")):
        errors.append("turn-absence-proof-ledger-id-invalid")
    if not _is_hash(value.get("turn_intent_entry_sha256")):
        errors.append("turn-absence-proof-intent-entry-invalid")
    dispatch = value.get("dispatch_record")
    dispatch_errors = validate_turn_dispatch_record(dispatch)
    if dispatch_errors:
        errors.append(
            "turn-absence-proof-dispatch-invalid:" + ";".join(dispatch_errors)
        )
    elif (
        dispatch.get("thread_id") != value.get("thread_id")
        or dispatch.get("turn_intent_id") != value.get("turn_intent_id")
        or dispatch.get("ledger_id") != value.get("ledger_id")
        or dispatch.get("turn_intent_entry_sha256")
        != value.get("turn_intent_entry_sha256")
        or dispatch.get("status") != "failed-ambiguous"
        or dispatch.get("ledger_resolution") != "pending"
        or dispatch.get("absence_verified") is not True
        or dispatch.get("absence_proof_sha256") is not None
        or dispatch.get("archived") is not False
        or dispatch.get("discovered_turn_ids")
        or dispatch.get("active_turn_ids_at_final_check")
    ):
        errors.append("turn-absence-proof-dispatch-binding-invalid")
    first_query = value.get("first_empty_query_count")
    final_query = value.get("final_empty_query_count")
    if (
        type(first_query) is not int
        or type(final_query) is not int
        or first_query < 1
        or final_query <= first_query
        or (
            isinstance(dispatch, Mapping) and dispatch.get("query_count") != final_query
        )
    ):
        errors.append("turn-absence-proof-query-window-invalid")
    quiet_window_ms = value.get("quiet_window_ms")
    if (
        type(quiet_window_ms) is not int
        or quiet_window_ms < TURN_ABSENCE_PROOF_MIN_QUIET_WINDOW_MS
    ):
        errors.append("turn-absence-proof-quiet-window-invalid")
    cursor_before = value.get("notification_cursor_before_quiet")
    cursor_after = value.get("notification_cursor_after_final_query")
    if (
        type(cursor_before) is not int
        or type(cursor_after) is not int
        or cursor_before < 0
        or cursor_after < cursor_before
    ):
        errors.append("turn-absence-proof-notification-window-invalid")
    if not _is_sorted_unique_ints(value.get("post_query_notification_sequences")):
        errors.append("turn-absence-proof-notification-sequences-invalid")
    elif value.get("post_query_notification_sequences"):
        errors.append("turn-absence-proof-post-query-start-observed")
    if value.get("final_active_turn_ids") != []:
        errors.append("turn-absence-proof-active-turns-observed")
    if value.get("proof_sha256") != _absence_proof_sha256(value):
        errors.append("turn-absence-proof-sha256-invalid")
    return errors


def seal_turn_absence_proof(value: Mapping[str, Any]) -> dict[str, Any]:
    """Seal and validate one immutable quiet-window absence proof."""

    sealed = dict(value)
    sealed["proof_sha256"] = _absence_proof_sha256(sealed)
    errors = validate_turn_absence_proof(sealed)
    if errors:
        raise NativeTurnDispatchError(";".join(errors))
    return sealed


def seal_turn_dispatch_record(value: Mapping[str, Any]) -> dict[str, Any]:
    """Seal and validate one complete record."""

    sealed = dict(value)
    sealed["record_sha256"] = _record_sha256(sealed)
    errors = validate_turn_dispatch_record(sealed)
    if errors:
        raise NativeTurnDispatchError(";".join(errors))
    return sealed


@dataclass(frozen=True)
class TurnDispatchReservation:
    """All identities that must exist before the only ``turn/start`` write."""

    thread_id: str
    turn_intent_id: str
    request_id: int
    connection_epoch_sha256: str
    notification_cursor: int
    preexisting_turn_ids: tuple[str, ...]
    ledger_id: str | None
    ledger_head_entry_sha256: str | None
    turn_intent_entry_sha256: str | None
    wire_request_sha256: str

    def prepared_record(self) -> dict[str, Any]:
        return seal_turn_dispatch_record(
            {
                "artifact_type": TURN_DISPATCH_ARTIFACT_TYPE,
                "version": 1,
                "thread_id": self.thread_id,
                "turn_intent_id": self.turn_intent_id,
                "client_user_message_id": self.turn_intent_id,
                "request_id": self.request_id,
                "connection_epoch_sha256": self.connection_epoch_sha256,
                "notification_cursor": self.notification_cursor,
                "preexisting_turn_ids": sorted(set(self.preexisting_turn_ids)),
                "ledger_id": self.ledger_id,
                "ledger_head_entry_sha256": self.ledger_head_entry_sha256,
                "turn_intent_entry_sha256": self.turn_intent_entry_sha256,
                "wire_request_sha256": self.wire_request_sha256,
                "wire_write_attempt_count": 0,
                "status": "prepared",
                "ambiguity_reason": None,
                "exact_response_turn_id": None,
                "notification_sequences": [],
                "discovered_turn_ids": [],
                "interrupt_attempted_turn_ids": [],
                "interrupt_failed_turn_ids": [],
                "terminal_status_by_turn": {},
                "active_turn_ids_at_final_check": [],
                "query_count": 0,
                "absence_verified": False,
                "absence_proof_sha256": None,
                "archived": False,
                "ledger_resolution": "pending",
                "record_sha256": "",
            }
        )


def evolve_turn_dispatch_record(
    record: Mapping[str, Any], **updates: Any
) -> dict[str, Any]:
    """Return a strict resealed successor while preserving reserved identities."""

    errors = validate_turn_dispatch_record(record)
    if errors:
        raise NativeTurnDispatchError(";".join(errors))
    forbidden = {
        "artifact_type",
        "version",
        "thread_id",
        "turn_intent_id",
        "client_user_message_id",
        "request_id",
        "connection_epoch_sha256",
        "notification_cursor",
        "preexisting_turn_ids",
        "ledger_id",
        "ledger_head_entry_sha256",
        "turn_intent_entry_sha256",
        "wire_request_sha256",
        "record_sha256",
    }
    changed_forbidden = forbidden.intersection(updates)
    if changed_forbidden:
        raise NativeTurnDispatchError(
            "turn-dispatch-reservation-mutation:" + ",".join(sorted(changed_forbidden))
        )
    evolved = dict(record)
    evolved.update(updates)
    return seal_turn_dispatch_record(evolved)
