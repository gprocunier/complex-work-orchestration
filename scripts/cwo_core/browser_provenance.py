"""Complete private browser captures, checked against independently selected audit records.

Hashes identify bytes, not approval or provider authenticity. Processes with the
same user's access to both artifacts and the trusted audit store can replace
both; these checks do not authenticate against that same-user access.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import json
from pathlib import Path
import re
from typing import Any
from urllib.parse import urlparse
from weakref import WeakValueDictionary

from .chatgpt_urls import approved_chatgpt_origin
from .private_artifact import sha256_bytes

PRIVATE_RESPONSE_ARTIFACT_TYPE = "chatgpt-browser-private-response"
PRIVATE_RESPONSE_VERSION = 5
CAPTURE_CHECKS = ("request_turn", "response_turn", "completion_confirmed", "content_stable",
                  "conversation_stable", "assistant_extraction")
BROWSER_PREPARATION_TRACE_FIELDS = ("packet_source_sha256", "request_id", "outbound_prepared_sha256",
                                    "submitted_user_sha256")
USER_TEXT_NORMALIZATION = "crlf-strip-v1"
ACCESS_LIMIT = "Private files and audit bindings do not authenticate against same-user access to both stores."
_HEX = re.compile(r"^[0-9a-f]{64}$")
_REQUEST = re.compile(r"^[0-9a-f]{32}$")
_CONVERSATION = re.compile(r"/c/([A-Za-z0-9-]{8,})(?:/|$)")
_PACKET_FIELDS = ("dispatch_id", "bead_id", "executor", "provider_key", "share_boundary", "packet_sha256")
_PREPARED_FIELDS = ("outbound_source_sha256", "outbound_export_sha256", "outbound_prepared_sha256",
                    "outbound_screen_version")
_OBSERVATION_FIELDS = ("pinned_conversation_id", "observed_document_request_id", "observed_user_sha256",
                       "submitted_user_sha256", "user_text_normalization", "conversation_id", "conversation_url",
                       "user_message_id", "assistant_message_id", "response_extraction", "capture_checks")
_BINDING_FIELDS = (*_PACKET_FIELDS, "subject", "packet_source_sha256", "prompt_sha256", "request_id",
                   "submitted_sha256", *_PREPARED_FIELDS, "send_admission_sha256", *_OBSERVATION_FIELDS,
                   "response_sha256", "response_bytes", "response_chars", "response_file")
_EXPECTATIONS: WeakValueDictionary = WeakValueDictionary()


def _digest(value: Any) -> bool:
    return isinstance(value, str) and _HEX.fullmatch(value) is not None


def _json_digest(value: Any) -> str:
    try:
        raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)
    except (TypeError, ValueError, RecursionError):
        raise SystemExit("browser provenance identity is not canonical JSON") from None
    return sha256_bytes(raw.encode("ascii"))


def _projection(value: dict[str, Any], fields: tuple[str, ...]) -> dict[str, Any]:
    return {key: value.get(key) for key in fields}


def normalize_browser_request(value: str) -> str:
    """Compare requests ignoring only CRLF line endings and surrounding whitespace."""
    return value.replace("\r\n", "\n").strip()


def add_candidate_arguments(parser) -> None:
    parser.add_argument("--candidate", help="Private formal candidate identity record, when claiming candidate review.")
    parser.add_argument("--candidate-root", help="Current repository whose actual bytes are checked.")


def _read_context_json(path: str) -> Any:
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError):
        raise SystemExit("current candidate context is unreadable or malformed") from None


def candidate_context(args) -> dict[str, Any]:
    """Explicit private inputs only; no live Beads reads or full-record disclosure."""
    fields = (args.candidate, args.candidate_root)
    if not any(fields):
        return {}
    if not all(fields):
        raise SystemExit("candidate review requires --candidate and --candidate-root")
    return {"candidate_record": _read_context_json(args.candidate), "candidate_root": Path(args.candidate_root)}


def packet_subject(packet: dict[str, Any], *, candidate_record=None, candidate_root=None) -> dict[str, str]:
    """Identify the actual packet inputs; a candidate additionally needs the formal current check."""
    inputs = _projection(packet, ("bead_id", "bead_summary", "selected_snippets", "expert_profile"))
    subject = {"kind": "packet-input", "source_sha256": _json_digest(inputs)}
    if candidate_record is None:
        return subject
    if candidate_root is None:
        raise SystemExit("candidate subject requires the current repository")
    from .candidate_identity import candidate_binding, candidate_errors, verify_candidate

    if candidate_errors(candidate_record) or verify_candidate(candidate_record, candidate_root):
        raise SystemExit("candidate subject is malformed, stale or does not match current source")
    if candidate_record["bead_id"] != packet.get("bead_id"):
        raise SystemExit("candidate subject does not match the packet assignment")
    return {**subject, "kind": "candidate", "candidate_sha256": candidate_binding(candidate_record)}


def subject_errors(subject: Any) -> list[str]:
    if not isinstance(subject, dict):
        return ["subject must identify packet-input or a formal candidate"]
    kind = subject.get("kind")
    fields = {"kind", "source_sha256"}
    if kind == "candidate":
        fields.add("candidate_sha256")
        digest = subject.get("candidate_sha256")
        if not isinstance(digest, str) or not digest.startswith("sha256:") or not _digest(digest[7:]):
            return ["subject candidate_sha256 must be a formal candidate binding"]
    if kind not in ("candidate", "packet-input") or set(subject) != fields or not _digest(subject.get("source_sha256")):
        return ["subject has an invalid kind, digest or private fields"]
    return []


def _text_errors(record: dict[str, Any]) -> list[str]:
    fields = (*_PACKET_FIELDS[:-1], "captured_at", "response_file", "conversation_id", "conversation_url",
              "assistant_message_id", "user_message_id", "pinned_conversation_id")
    return [f"{key} must be a non-empty string" for key in fields
            if not isinstance(record.get(key), str) or not record[key].strip()]


def _hash_errors(record: dict[str, Any]) -> list[str]:
    fields = ("packet_sha256", "packet_source_sha256", "prompt_sha256", "submitted_sha256",
              *_PREPARED_FIELDS[:3], "send_admission_sha256", "observed_user_sha256", "submitted_user_sha256",
              "response_sha256")
    return [f"{key} must be a SHA-256 digest" for key in fields if not _digest(record.get(key))]


def _observation_errors(record: dict[str, Any]) -> list[str]:
    errors = []
    checks = record.get("capture_checks")
    if not isinstance(checks, dict) or any(checks.get(name) is not True for name in CAPTURE_CHECKS):
        errors.append("capture_checks must all be true")
    if record.get("response_extraction") != "assistant-message":
        errors.append("response_extraction must be assistant-message")
    if record.get("pinned_conversation_id") != record.get("conversation_id"):
        errors.append("observed conversation does not match the pinned conversation")
    if record.get("observed_document_request_id") != record.get("request_id"):
        errors.append("observed document does not match the submitted request")
    if (record.get("user_text_normalization") != USER_TEXT_NORMALIZATION
            or record.get("observed_user_sha256") != record.get("submitted_user_sha256")):
        errors.append("observed user turn does not match the normalized submitted text")
    return errors


def _conversation_errors(record: dict[str, Any]) -> list[str]:
    url = record.get("conversation_url")
    if not isinstance(url, str):
        return ["conversation_url must name the observed conversation"]
    try:
        match = _CONVERSATION.search(urlparse(url).path)
        origin = approved_chatgpt_origin(url)
    except ValueError:
        return ["conversation_url is malformed"]
    if origin is None or match is None or match.group(1) != record.get("conversation_id"):
        return ["conversation_url does not name conversation_id on a ChatGPT origin"]
    return []


def _prepared_errors(record: dict[str, Any]) -> list[str]:
    from .outbound_screen import SCREEN_VERSION

    errors = []
    version = record.get("outbound_screen_version")
    if type(version) is not int or version != SCREEN_VERSION:
        return ["outbound_screen_version is not supported"]
    prepared = [record.get("outbound_source_sha256"), record.get("outbound_export_sha256"),
                "ChatGPT browser Send", version]
    if record.get("outbound_prepared_sha256") != _json_digest(prepared):
        errors.append("outbound_prepared_sha256 does not bind the screened Send request")
    if record.get("outbound_export_sha256") != record.get("submitted_sha256"):
        errors.append("screened export does not match submitted_sha256")
    return errors


def provenance_errors(record: dict[str, Any]) -> list[str]:
    errors = _text_errors(record) + _hash_errors(record) + subject_errors(record.get("subject"))
    errors += _observation_errors(record) + _conversation_errors(record) + _prepared_errors(record)
    request = record.get("request_id")
    if not isinstance(request, str) or _REQUEST.fullmatch(request) is None:
        errors.append("request_id must be 32 lowercase hexadecimal characters")
    for key in ("response_bytes", "response_chars"):
        if type(record.get(key)) is not int or record[key] < 1:
            errors.append(f"{key} must be a positive integer")
    return errors


def capture_audit_fields(record: dict[str, Any], provenance_sha256: str) -> dict[str, Any]:
    """Flat identities for the existing dispatch event; never include private input or response bodies."""
    fields = ("packet_source_sha256", "prompt_sha256", "request_id", "submitted_sha256", *_PREPARED_FIELDS,
              "send_admission_sha256", "conversation_id", "user_message_id", "assistant_message_id",
              "response_sha256")
    return {**_projection(record, fields), "private_provenance_sha256": provenance_sha256,
            "private_capture_binding_sha256": _json_digest(_projection(record, _BINDING_FIELDS)),
            "subject_sha256": _json_digest(record.get("subject")),
            "observation_sha256": _json_digest(_projection(record, _OBSERVATION_FIELDS))}


@dataclass(frozen=True)
class PrivateCaptureExpectation:
    """Factory-selected current identities; repr never includes private records."""
    packet_json: str = field(repr=False)
    packet_source_sha256: str
    capture_event_hash: str
    event_json: str = field(repr=False)
    candidate_json: str = field(default="{}", repr=False)
    access_limit: str = ACCESS_LIMIT
    audit_file: Path | None = field(default=None, repr=False)


def _capture_event(capture_event_hash: str, audit_file: Path | None) -> dict[str, Any]:
    from .audit import iter_audit_events

    if not _digest(capture_event_hash):
        raise SystemExit("private intake requires an independently selected capture event hash")
    matches = [event for event in iter_audit_events(audit_file)
               if event.get("event_hash") == capture_event_hash and event.get("event_type") == "chatgpt_browser_dispatch"]
    if len(matches) != 1:
        raise SystemExit("private intake capture event is absent or ambiguous in the independent audit store")
    return matches[0]


def select_private_capture(packet: dict[str, Any], *, packet_source_sha256: str, capture_event_hash: str,
                           audit_file: Path | None = None, candidate_record=None,
                           candidate_root=None) -> PrivateCaptureExpectation:
    """Select expectations from current source and the real independently chosen persisted event."""
    from .packet_provenance import require_production_contractor_packet

    require_production_contractor_packet(packet, audit_file=audit_file)
    subject = packet_subject(packet, candidate_record=candidate_record, candidate_root=candidate_root)
    if subject_errors(packet.get("subject")) or packet["subject"] != subject:
        raise SystemExit("private intake subject does not match the current packet source/candidate")
    if not _digest(packet_source_sha256):
        raise SystemExit("private intake requires independently selected packet-source identity")
    event = _capture_event(capture_event_hash, audit_file)
    identities = {**_projection(packet, ("packet_sha256", "dispatch_id", "bead_id")),
                  "packet_source_sha256": packet_source_sha256, "subject_sha256": _json_digest(subject)}
    if any(event.get(key) != value for key, value in identities.items()):
        raise SystemExit("private intake current packet/source/candidate does not match the independent capture event")
    if not _digest(event.get("private_provenance_sha256")):
        raise SystemExit("private intake capture event lacks its independent provenance digest")
    current = {"candidate_record": candidate_record, "candidate_root": str(candidate_root)}
    selected = PrivateCaptureExpectation(json.dumps(packet, sort_keys=True), packet_source_sha256,
                                         capture_event_hash, json.dumps(event, sort_keys=True),
                                         candidate_json=json.dumps(current), audit_file=audit_file)
    _EXPECTATIONS[id(selected)] = selected
    return selected


def verify_provenance_pin(provenance_bytes: bytes, expected: PrivateCaptureExpectation | None) -> None:
    if not isinstance(expected, PrivateCaptureExpectation) or _EXPECTATIONS.get(id(expected)) is not expected:
        raise SystemExit("private intake requires independently selected current packet/source/candidate and capture event")
    event = _capture_event(expected.capture_event_hash, expected.audit_file)
    if event != json.loads(expected.event_json):
        raise SystemExit("private intake independent capture event changed after selection")
    if sha256_bytes(provenance_bytes) != event.get("private_provenance_sha256"):
        raise SystemExit("private response differs from the independent audit provenance digest")


def _record_errors(record: dict[str, Any]) -> list[str]:
    if record.get("artifact_type") != PRIVATE_RESPONSE_ARTIFACT_TYPE:
        return ["private response provenance has an unexpected artifact type"]
    if type(record.get("version")) is not int or record["version"] != PRIVATE_RESPONSE_VERSION:
        return ["private response provenance has an unsupported historical version"]
    if record.get("capture_complete") is not True:
        return ["private response capture is incomplete; it cannot be ingested as a complete return"]
    return provenance_errors(record)


def _expectation_errors(record: dict[str, Any], expected: PrivateCaptureExpectation) -> list[str]:
    packet = json.loads(expected.packet_json)
    current_subject = packet_subject(packet, **json.loads(expected.candidate_json))
    if current_subject != packet.get("subject"):
        return ["private response subject no longer matches current source/candidate"]
    identities = {**_projection(packet, (*_PACKET_FIELDS, "subject")),
                  "packet_source_sha256": expected.packet_source_sha256}
    if any(record.get(key) != value for key, value in identities.items()):
        return ["private response does not match the current packet/source/candidate"]
    event = json.loads(expected.event_json)
    fields = capture_audit_fields(record, event["private_provenance_sha256"])
    if any(event.get(key) != value for key, value in fields.items()):
        return ["private response request/prepared/admission/observation does not match independent capture event"]
    return []


def validate_private_capture(record: dict[str, Any], response_bytes: bytes, *,
                             expected: PrivateCaptureExpectation | None, provenance_bytes: bytes) -> str:
    """Validate a complete chain and return exact UTF-8 text, only for an intentional body consumer."""
    verify_provenance_pin(provenance_bytes, expected)
    if json.loads(provenance_bytes) != record:
        raise SystemExit("private response record differs from pinned provenance bytes")
    errors = _record_errors(record) + _expectation_errors(record, expected)
    if errors:
        raise SystemExit("private response provenance is incomplete or mismatched: " + "; ".join(errors))
    if sha256_bytes(response_bytes) != record["response_sha256"] or len(response_bytes) != record["response_bytes"]:
        raise SystemExit("private response digest or byte length does not match its provenance")
    try:
        text = response_bytes.decode("utf-8")
    except UnicodeDecodeError:
        raise SystemExit("private response is not valid UTF-8") from None
    if not text.strip() or len(text) != record["response_chars"]:
        raise SystemExit("private response is empty or its character length does not match provenance")
    return text
