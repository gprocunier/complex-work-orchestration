"""Bind a recorded peer review to the current return and pending evaluation."""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Callable

from .errors import CWOPolicyError
from .peer_review_identity import recorded_separation, review_identity


PEER_REVIEW_STATUSES = frozenset({"not-run", "pending", "passed", "failed", "disagreement", "blocked"})
PEER_REVIEW_HOLDS = frozenset({
    "peer-review-pending", "provider-conflict-peer-review-pending", "risk-review-pending",
})
_RECORD_FIELDS = frozenset({
    "record_type", "version", "reviewer_identity", "return_sha256", "evaluation_sha256", "decision",
})


def require_peer_review_status(status: object) -> None:
    if type(status) is not str or status not in PEER_REVIEW_STATUSES:
        raise CWOPolicyError("unsupported peer-review status")


def _review_record(record: object) -> dict[str, Any]:
    if type(record) is not dict or set(record) != _RECORD_FIELDS:
        raise CWOPolicyError("passed peer review requires a complete bound peer-review record")
    if (record["record_type"] != "cwo-peer-review" or type(record["version"]) is not int
            or record["version"] != 2 or record["decision"] != "passed"):
        raise CWOPolicyError("unsupported peer-review record type, version or decision")
    for name in ("return_sha256", "evaluation_sha256"):
        if type(record[name]) is not str or re.fullmatch(r"[0-9a-f]{64}", record[name]) is None:
            raise CWOPolicyError("peer-review record requires lowercase SHA-256 digests")
    return dict(record)


def validate_peer_review_request(status: object, reviewer: object, record: object) -> dict[str, Any] | None:
    """Validate the record shape and independent expected reviewer declaration."""
    require_peer_review_status(status)
    if status != "passed":
        if reviewer is not None or record is not None:
            raise CWOPolicyError("peer-review reviewer and record require passed status")
        return None
    reviewer = review_identity(reviewer)
    value = _review_record(record)
    if review_identity(value["reviewer_identity"]) != reviewer:
        raise CWOPolicyError("peer-review record reviewer identity mismatch")
    return value


def pending_evaluation_sha256(evaluation: dict[str, Any]) -> str:
    """Hash the complete pending result as canonical UTF-8 JSON, without a newline."""
    raw = json.dumps(evaluation, sort_keys=True, ensure_ascii=False,
                     separators=(",", ":"), allow_nan=False).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def bound_peer_review_record(evaluate: Callable[..., dict[str, Any]], inputs: dict[str, Any]) -> tuple:
    """Reevaluate identical inputs as pending; no result or review hashes itself."""
    record = validate_peer_review_request(inputs["peer_review_status"],
                                          inputs["peer_review_reviewer"], inputs["peer_review_record"])
    if record is None:
        return None, None
    pending_inputs = {**inputs, "peer_review_status": "pending",
                      "peer_review_reviewer": None, "peer_review_record": None}
    pending = evaluate(**pending_inputs)
    if record["return_sha256"] != hashlib.sha256(inputs["text"].encode("utf-8")).hexdigest():
        raise CWOPolicyError("peer-review record return digest mismatch")
    if record["evaluation_sha256"] != pending_evaluation_sha256(pending):
        raise CWOPolicyError("peer-review record evaluation digest mismatch")
    return record, recorded_separation(inputs, record["reviewer_identity"])


def reviewed_hold_metadata(hold: dict[str, Any], record: dict[str, Any] | None) -> dict[str, Any]:
    """Apply only the evaluator's already bound review to its procedural holds."""
    if record is None:
        return hold
    remaining = [reason for reason in hold["hold_reasons"] if reason not in PEER_REVIEW_HOLDS]
    return {**hold, "hold_reasons": remaining, "implementation_blocked": bool(remaining),
            "hold_classification": hold["hold_classification"] if remaining else "none"}


def peer_review_result_fields(reviewer: dict[str, str] | None, record: dict[str, Any] | None,
                             separation: dict[str, Any] | None) -> dict[str, Any]:
    if record is None:
        return {}
    return {"peer_review_reviewer": reviewer, "peer_review_record": record,
            "peer_review_separation": separation}
