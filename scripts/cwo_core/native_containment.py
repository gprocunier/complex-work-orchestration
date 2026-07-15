from __future__ import annotations

from copy import deepcopy
from typing import Any, Mapping

from .policy import load_policy


CONTAINMENT_REASON = "fsh.1-precommit-control-gap"
CONTAINMENT_RELEASE = "complex-work-orchestration-fsh.2"
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
        "version": 1,
        "active": True,
        "status": "contained",
        "scope": "native-operative-dispatch",
        "reason": CONTAINMENT_REASON,
        "decision": "hard-stop",
        "authority": CONTAINMENT_AUTHORITY,
        "release_requires": CONTAINMENT_RELEASE,
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
    normalized["dispatch_authorized"] = False
    return normalized


def containment_error(operation: str, policy: Mapping[str, Any] | None = None) -> str:
    try:
        state = native_operative_containment(policy)
    except (SystemExit, ValueError) as exc:
        return f"{CONTAINMENT_ERROR}: containment policy unavailable or invalid: {exc}"
    if state.get("dispatch_authorized") is True:
        return ""
    return (
        f"{CONTAINMENT_ERROR}: {operation} is blocked by {state['reason']} "
        f"until {state['release_requires']}"
    )


def require_native_operative_dispatch(
    operation: str,
    policy: Mapping[str, Any] | None = None,
) -> None:
    error = containment_error(operation, policy)
    if error:
        raise SystemExit(error)
