from __future__ import annotations

from copy import deepcopy
from typing import Any, Mapping

from .native_release import RELEASE_STATES, validate_native_release_evidence
from .policy import load_policy


CONTAINMENT_REASON = "fsh.3-operative-release-gate"
CONTAINMENT_RELEASE = "complex-work-orchestration-fsh.3.5"
CONTAINMENT_AUTHORITY = "policy/native-worker-execution.yaml"
CONTAINMENT_ERROR = "native-precommit-containment-active"

_REQUIRED_FIELDS = {
    "version",
    "active",
    "status",
    "scope",
    "reason",
    "decision",
    "authority",
    "release_requires",
    "release_state_order",
    "maximum_release_state",
    "operative_dispatch_authorized",
    "canary_operations",
    "allowed_non_operative_operations",
    "blocked_operations",
}


def _string_list(value: Any, *, field: str) -> list[str]:
    if not isinstance(value, list) or not value:
        raise ValueError(f"malformed policy: precommit_containment.{field} must be a non-empty list")
    normalized: list[str] = []
    for item in value:
        if not isinstance(item, str) or not item.strip():
            raise ValueError(f"malformed policy: precommit_containment.{field} items must be non-empty strings")
        text = item.strip()
        if text in normalized:
            raise ValueError(f"malformed policy: precommit_containment.{field} contains duplicate {text!r}")
        normalized.append(text)
    return normalized


def native_operative_containment(
    policy: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Return the strict fsh.1 containment state or fail closed."""
    source = policy if policy is not None else load_policy("native-worker-execution")
    value = source.get("precommit_containment")
    if not isinstance(value, Mapping):
        raise ValueError("malformed policy: precommit_containment must be an object")
    fields = set(value)
    if fields != _REQUIRED_FIELDS:
        missing = sorted(_REQUIRED_FIELDS - fields)
        unknown = sorted(fields - _REQUIRED_FIELDS)
        details: list[str] = []
        if missing:
            details.append("missing " + ", ".join(missing))
        if unknown:
            details.append("unknown " + ", ".join(unknown))
        raise ValueError("malformed policy: precommit_containment fields: " + "; ".join(details))
    expected = {
        "version": 2,
        "active": True,
        "status": "operative-authorized",
        "scope": "native-operative-dispatch",
        "reason": CONTAINMENT_REASON,
        "decision": "evidence-gated",
        "authority": CONTAINMENT_AUTHORITY,
        "release_requires": CONTAINMENT_RELEASE,
        "maximum_release_state": "operative-authorized",
        "operative_dispatch_authorized": True,
    }
    for field, expected_value in expected.items():
        if value.get(field) != expected_value:
            raise ValueError(
                f"malformed policy: precommit_containment.{field} must equal {expected_value!r}"
            )
    normalized = deepcopy(dict(value))
    normalized["allowed_non_operative_operations"] = _string_list(
        value.get("allowed_non_operative_operations"),
        field="allowed_non_operative_operations",
    )
    normalized["blocked_operations"] = _string_list(
        value.get("blocked_operations"),
        field="blocked_operations",
    )
    normalized["release_state_order"] = _string_list(
        value.get("release_state_order"),
        field="release_state_order",
    )
    if normalized["release_state_order"] != list(RELEASE_STATES):
        raise ValueError("malformed policy: precommit_containment.release_state_order is invalid")
    if value.get("maximum_release_state") not in RELEASE_STATES:
        raise ValueError("malformed policy: precommit_containment.maximum_release_state is invalid")
    if not isinstance(value.get("operative_dispatch_authorized"), bool):
        raise ValueError("malformed policy: precommit_containment.operative_dispatch_authorized must be boolean")
    normalized["canary_operations"] = _string_list(
        value.get("canary_operations"),
        field="canary_operations",
    )
    if normalized["canary_operations"] != ["supervised-worker-fit-request"]:
        raise ValueError("malformed policy: precommit_containment.canary_operations is invalid")
    normalized["canary_authorized"] = value.get("maximum_release_state") in {
        "canary-authorized",
        "operative-authorized",
    }
    normalized["dispatch_authorized"] = (
        value.get("maximum_release_state") == "operative-authorized"
        and value.get("operative_dispatch_authorized") is True
    )
    normalized["evidence_required"] = True
    return normalized


def containment_error(
    operation: str,
    policy: Mapping[str, Any] | None = None,
    *,
    release_evidence: Mapping[str, Any] | None = None,
    expected_packet_id: str | None = None,
    expected_work_plan_sha256: str | None = None,
    expected_precommit_receipt_sha256: str | None = None,
) -> str:
    try:
        state = native_operative_containment(policy)
    except (SystemExit, ValueError) as exc:
        return f"{CONTAINMENT_ERROR}: containment policy unavailable or invalid: {exc}"
    if state.get("dispatch_authorized") is True and state.get("evidence_required") is not True:
        return ""
    if release_evidence is not None:
        evidence_errors = validate_native_release_evidence(
            release_evidence,
            policy=policy,
            operation=operation,
            expected_packet_id=expected_packet_id,
            expected_work_plan_sha256=expected_work_plan_sha256,
            expected_precommit_receipt_sha256=expected_precommit_receipt_sha256,
        )
        if evidence_errors:
            return f"{CONTAINMENT_ERROR}: release evidence rejected: {'; '.join(evidence_errors)}"
        evidence_state = release_evidence.get("release_state")
        if operation in state["canary_operations"] and evidence_state == "canary-authorized":
            if state.get("canary_authorized") is True:
                return ""
        if state.get("dispatch_authorized") is True and evidence_state == "operative-authorized":
            return ""
    return (
        f"{CONTAINMENT_ERROR}: {operation} is blocked by {state['reason']} "
        f"until {state['release_requires']}"
    )


def require_native_operative_dispatch(
    operation: str,
    policy: Mapping[str, Any] | None = None,
    *,
    release_evidence: Mapping[str, Any] | None = None,
    expected_packet_id: str | None = None,
    expected_work_plan_sha256: str | None = None,
    expected_precommit_receipt_sha256: str | None = None,
) -> None:
    error = containment_error(
        operation,
        policy,
        release_evidence=release_evidence,
        expected_packet_id=expected_packet_id,
        expected_work_plan_sha256=expected_work_plan_sha256,
        expected_precommit_receipt_sha256=expected_precommit_receipt_sha256,
    )
    if error:
        raise SystemExit(error)
