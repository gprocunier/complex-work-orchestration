"""Native capability receipt primitives for model capability dispatch.

This module is intentionally stdlib-only and side-effect-free.
"""

from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Iterable, List, Mapping

from .native_authority import (
    VerifiedAuthority,
    validate_authority_provenance,
)


CAPABILITY_RECEIPT_TYPE = "cwo-native-model-capability-receipt"
CAPABILITY_RECEIPT_VERSION = 2
CAPABILITY_RECEIPT_VERSION_V1 = 1
CAPABILITY_EVIDENCE_FIELDS = (
    "requested_model",
    "configured_model",
    "advertised",
    "advertised_models",
    "spawn_accepted",
    "canary_session_id",
    "attestation_source",
    "attested_model",
    "tool_calls",
    "context_compactions",
    "runtime_seconds",
    "closure_receipt",
    "tool_surface_id",
)


def _to_rfc3339_datetime(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    normalized = value.replace("Z", "+00:00", 1)
    try:
        dt = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    return dt if dt.tzinfo is not None else None


def _nonempty_string(value: Any) -> bool:
    return isinstance(value, str) and len(value) > 0


def _is_bool(value: Any) -> bool:
    return isinstance(value, bool)


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _is_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _evaluate_base(evidence: dict[str, Any]) -> tuple[dict[str, bool], bool, bool, bool, bool]:
    requested_model = evidence.get("requested_model")
    configured_model = evidence.get("configured_model")
    tool_surface_id = evidence.get("tool_surface_id")
    canary_session_id = evidence.get("canary_session_id")
    attestation_source = evidence.get("attestation_source")
    attested_model = evidence.get("attested_model")
    advertised_models = evidence.get("advertised_models")

    configured = bool(requested_model and configured_model == requested_model)
    advertised = bool(evidence.get("advertised"))
    spawn_accepted = evidence.get("spawn_accepted")
    spawn_state = spawn_accepted is True
    attested = (
        attestation_source == "trusted-session-jsonl"
        and attested_model is not None
        and attested_model == requested_model
        and _nonempty_string(attested_model)
    )
    dispatchable = False
    return (
        {
            "configured": configured,
            "advertised": advertised,
            "spawn_accepted": spawn_state,
            "attested": attested,
            "dispatchable": dispatchable,
        },
        advertised,
        spawn_accepted,
        spawn_state,
        attested,
    )


def evaluate_native_capability(evidence: dict[str, Any], authorized_models: Iterable[str]) -> dict[str, Any]:
    """
    Evaluate evidence for native-capability dispatch readiness.
    Returns a structured assessment with outcome and reason chain.
    """
    if not isinstance(evidence, dict):
        evidence = {}
    if isinstance(authorized_models, (str, bytes, bytearray)) or not isinstance(authorized_models, Iterable):
        authorized_models = ()

    requested_model = evidence.get("requested_model")
    configured_model = evidence.get("configured_model")
    tool_calls = evidence.get("tool_calls")
    context_compactions = evidence.get("context_compactions")
    runtime_seconds = evidence.get("runtime_seconds")
    closure_receipt = evidence.get("closure_receipt")
    tool_surface_id = evidence.get("tool_surface_id")
    canary_session_id = evidence.get("canary_session_id")
    attestation_source = evidence.get("attestation_source")
    attested_model = evidence.get("attested_model")
    advertised_models = evidence.get("advertised_models")
    spawn_accepted_raw = evidence.get("spawn_accepted")
    spawn_accepted_state = spawn_accepted_raw is True
    advertising = evidence.get("advertised")
    advertised_bool = advertising is True

    states, _, _, _, attested_state = _evaluate_base(evidence)
    configured = states["configured"]

    reasons: List[str] = []
    outcome = "native-capability-confirmed"
    canary_required = False

    if not configured or requested_model not in authorized_models:
        outcome = "unauthorized-model"
        reasons = ["unauthorized-model"]
    elif advertised_bool is False and spawn_accepted_raw is None:
        outcome = "advertisement-mismatch"
        canary_required = True
        reasons = ["advertisement-mismatch"]
    elif spawn_accepted_raw is False:
        outcome = "native-spawn-rejected"
        reasons = ["native-spawn-rejected"]
    elif spawn_accepted_raw is not True:
        outcome = "native-capability-canary-required"
        canary_required = True
        reasons = ["native-capability-canary-required"]
    elif _is_int(tool_calls) and tool_calls != 0:
        outcome = "canary-tool-use"
        canary_required = False
        reasons = ["canary-tool-use"]
    elif _is_int(context_compactions) and context_compactions != 0:
        outcome = "canary-compaction"
        reasons = ["canary-compaction"]
    else:
        missing_or_bad = (
            not _nonempty_string(requested_model)
            or not _nonempty_string(configured_model)
            or not _nonempty_string(canary_session_id)
            or not _nonempty_string(attestation_source)
            or not _nonempty_string(attested_model)
            or not _nonempty_string(tool_surface_id)
            or not _is_bool(evidence.get("advertised"))
            or not isinstance(advertised_models, list)
            or any(not _nonempty_string(item) for item in advertised_models)
            or not _is_number(runtime_seconds)
            or runtime_seconds < 0
            or attestation_source != "trusted-session-jsonl"
            or _is_int(tool_calls) is False
            or _is_int(context_compactions) is False
        )
        if missing_or_bad:
            outcome = "unavailable-trusted-telemetry"
            reasons = ["unavailable-trusted-telemetry"]
        elif attested_model != requested_model:
            outcome = "native-attestation-mismatch"
            reasons = ["native-attestation-mismatch"]
            states["attested"] = False
            attested_state = False
        elif closure_receipt is not True:
            outcome = "missing-closure"
            reasons = ["missing-closure"]
        else:
            outcome = "native-capability-confirmed"
            states["dispatchable"] = True
            canary_required = False
            reasons = ["native-capability-confirmed"]

    return {
        "states": states,
        "outcome": outcome,
        "canary_required": canary_required,
        "reasons": reasons,
    }


def _compute_receipt_sha256(payload: dict[str, Any]) -> str:
    canonical = _canonical_json(payload)
    return hashlib.sha256(canonical.encode("ascii")).hexdigest()


def canonical_capability_evidence_sha256(evidence: Mapping[str, Any]) -> str:
    """Hash the exact trusted session evidence used by capability issuance."""

    if not isinstance(evidence, Mapping):
        raise ValueError("capability evidence must be an object")
    missing = [field for field in CAPABILITY_EVIDENCE_FIELDS if field not in evidence]
    if missing:
        raise ValueError(
            "capability evidence missing field(s): " + ", ".join(missing)
        )
    projection = {
        field: deepcopy(evidence[field]) for field in CAPABILITY_EVIDENCE_FIELDS
    }
    return _compute_receipt_sha256(projection)


@dataclass(frozen=True)
class ReceiptValidationResult:
    errors: List[str]


def _validate_v1_capability_receipt(receipt: dict[str, Any]) -> List[str]:
    """
    Validate a native capability receipt and return a deterministic list of failures.
    The list is empty only for fully valid receipts.
    """
    if not isinstance(receipt, dict):
        return ["invalid-receipt-type"]

    expected_keys = {
        "receipt_type",
        "version",
        "requested_model",
        "configured_model",
        "advertised",
        "advertised_models",
        "spawn_accepted",
        "canary_session_id",
        "attestation_source",
        "attested_model",
        "tool_calls",
        "context_compactions",
        "runtime_seconds",
        "closure_receipt",
        "tool_surface_id",
        "decision",
        "authority",
        "issued_at",
        "expires_at",
        "receipt_sha256",
    }
    errors: list[str] = []

    key_set = set(receipt.keys())
    missing = sorted(expected_keys - key_set)
    unexpected = sorted(key_set - expected_keys)
    for key in missing:
        errors.append(f"missing-{key}")
    for key in unexpected:
        errors.append(f"unexpected-{key}")
    if errors:
        return errors

    if receipt.get("receipt_type") != CAPABILITY_RECEIPT_TYPE:
        errors.append("receipt-type-mismatch")
    if receipt.get("version") != CAPABILITY_RECEIPT_VERSION_V1:
        errors.append("receipt-version-mismatch")

    requested_model = receipt.get("requested_model")
    configured_model = receipt.get("configured_model")
    if not _nonempty_string(requested_model):
        errors.append("invalid-requested-model")
    if not _nonempty_string(configured_model):
        errors.append("invalid-configured-model")
    if requested_model != configured_model:
        errors.append("configured-model-mismatch")

    advertised = receipt.get("advertised")
    if not _is_bool(advertised):
        errors.append("invalid-advertised")

    advertised_models = receipt.get("advertised_models")
    if not isinstance(advertised_models, list):
        errors.append("invalid-advertised-models")
    else:
        for index, item in enumerate(advertised_models):
            if not _nonempty_string(item):
                errors.append(f"invalid-advertised-models[{index}]")

    spawn_accepted = receipt.get("spawn_accepted")
    if not _is_bool(spawn_accepted):
        errors.append("invalid-spawn-accepted")
    elif spawn_accepted is not True:
        errors.append("spawn-accepted-not-true")

    canary_session_id = receipt.get("canary_session_id")
    if not _nonempty_string(canary_session_id):
        errors.append("invalid-canary-session-id")

    attestation_source = receipt.get("attestation_source")
    if not _nonempty_string(attestation_source):
        errors.append("invalid-attestation-source")
    elif attestation_source != "trusted-session-jsonl":
        errors.append("untrusted-attestation-source")

    attested_model = receipt.get("attested_model")
    if not _nonempty_string(attested_model):
        errors.append("invalid-attested-model")
    elif attested_model != requested_model:
        errors.append("attested-model-mismatch")

    tool_calls = receipt.get("tool_calls")
    if not _is_int(tool_calls):
        errors.append("invalid-tool-calls")
    elif tool_calls != 0:
        errors.append("tool-calls-nonzero")

    context_compactions = receipt.get("context_compactions")
    if not _is_int(context_compactions):
        errors.append("invalid-context-compactions")
    elif context_compactions != 0:
        errors.append("context-compactions-nonzero")

    runtime_seconds = receipt.get("runtime_seconds")
    if not _is_number(runtime_seconds):
        errors.append("invalid-runtime-seconds")
    elif runtime_seconds < 0:
        errors.append("negative-runtime-seconds")

    if not _is_bool(receipt.get("closure_receipt")):
        errors.append("invalid-closure-receipt")
    elif receipt.get("closure_receipt") is not True:
        errors.append("closure-receipt-false")

    tool_surface_id = receipt.get("tool_surface_id")
    if not _nonempty_string(tool_surface_id):
        errors.append("invalid-tool-surface-id")

    if receipt.get("decision") != "native-capability-confirmed":
        errors.append("invalid-decision")
    if receipt.get("authority") != "trusted-session-jsonl":
        errors.append("invalid-authority")

    issued_at = receipt.get("issued_at")
    expires_at = receipt.get("expires_at")
    issued_dt = _to_rfc3339_datetime(issued_at)
    expires_dt = _to_rfc3339_datetime(expires_at)
    if issued_dt is None:
        errors.append("invalid-issued-at")
    if expires_dt is None:
        errors.append("invalid-expires-at")
    elif issued_dt is not None and expires_dt <= issued_dt:
        errors.append("invalid-expiry-order")

    sha = receipt.get("receipt_sha256")
    if not _nonempty_string(sha):
        errors.append("invalid-receipt-sha256")
    else:
        if len(sha) != 64 or any(c not in "0123456789abcdef" for c in sha):
            errors.append("invalid-receipt-sha256-format")
        else:
            payload = {k: receipt[k] for k in receipt.keys() if k != "receipt_sha256"}
            if sha != _compute_receipt_sha256(payload):
                errors.append("invalid-receipt-sha256")

    return errors


def validate_native_capability_receipt(receipt: dict[str, Any]) -> List[str]:
    """Validate the operative provenance-bearing capability receipt."""

    if not isinstance(receipt, dict):
        return ["invalid-receipt-type"]
    if receipt.get("version") == CAPABILITY_RECEIPT_VERSION_V1:
        return ["receipt-version-1-historical-only"]
    expected_keys = {
        "receipt_type",
        "version",
        *CAPABILITY_EVIDENCE_FIELDS,
        "decision",
        "session_evidence_sha256",
        "authority_provenance",
        "issued_at",
        "expires_at",
        "receipt_sha256",
    }
    errors: list[str] = []
    key_set = set(receipt)
    for key in sorted(expected_keys - key_set):
        errors.append(f"missing-{key}")
    for key in sorted(key_set - expected_keys):
        errors.append(f"unexpected-{key}")
    if errors:
        return errors
    if receipt.get("receipt_type") != CAPABILITY_RECEIPT_TYPE:
        errors.append("receipt-type-mismatch")
    if receipt.get("version") != CAPABILITY_RECEIPT_VERSION:
        errors.append("receipt-version-mismatch")

    requested_model = receipt.get("requested_model")
    configured_model = receipt.get("configured_model")
    if not _nonempty_string(requested_model):
        errors.append("invalid-requested-model")
    if not _nonempty_string(configured_model):
        errors.append("invalid-configured-model")
    if requested_model != configured_model:
        errors.append("configured-model-mismatch")
    if not _is_bool(receipt.get("advertised")):
        errors.append("invalid-advertised")
    advertised_models = receipt.get("advertised_models")
    if not isinstance(advertised_models, list):
        errors.append("invalid-advertised-models")
    else:
        for index, item in enumerate(advertised_models):
            if not _nonempty_string(item):
                errors.append(f"invalid-advertised-models[{index}]")
    if not _is_bool(receipt.get("spawn_accepted")):
        errors.append("invalid-spawn-accepted")
    elif receipt.get("spawn_accepted") is not True:
        errors.append("spawn-accepted-not-true")
    if not _nonempty_string(receipt.get("canary_session_id")):
        errors.append("invalid-canary-session-id")
    if receipt.get("attestation_source") != "trusted-session-jsonl":
        errors.append("untrusted-attestation-source")
    if not _nonempty_string(receipt.get("attested_model")):
        errors.append("invalid-attested-model")
    elif receipt.get("attested_model") != requested_model:
        errors.append("attested-model-mismatch")
    if not _is_int(receipt.get("tool_calls")):
        errors.append("invalid-tool-calls")
    elif receipt.get("tool_calls") != 0:
        errors.append("tool-calls-nonzero")
    if not _is_int(receipt.get("context_compactions")):
        errors.append("invalid-context-compactions")
    elif receipt.get("context_compactions") != 0:
        errors.append("context-compactions-nonzero")
    if not _is_number(receipt.get("runtime_seconds")):
        errors.append("invalid-runtime-seconds")
    elif receipt.get("runtime_seconds") < 0:
        errors.append("negative-runtime-seconds")
    if receipt.get("closure_receipt") is not True:
        errors.append("closure-receipt-false")
    if not _nonempty_string(receipt.get("tool_surface_id")):
        errors.append("invalid-tool-surface-id")
    if receipt.get("decision") != "native-capability-confirmed":
        errors.append("invalid-decision")

    issued_dt = _to_rfc3339_datetime(receipt.get("issued_at"))
    expires_dt = _to_rfc3339_datetime(receipt.get("expires_at"))
    if issued_dt is None:
        errors.append("invalid-issued-at")
    if expires_dt is None:
        errors.append("invalid-expires-at")
    elif issued_dt is not None and expires_dt <= issued_dt:
        errors.append("invalid-expiry-order")
    try:
        expected_evidence_sha256 = canonical_capability_evidence_sha256(receipt)
    except (TypeError, ValueError):
        expected_evidence_sha256 = None
        errors.append("invalid-session-evidence")
    if receipt.get("session_evidence_sha256") != expected_evidence_sha256:
        errors.append("session-evidence-sha256-mismatch")

    authority = receipt.get("authority_provenance")
    authority_errors = validate_authority_provenance(authority)
    errors.extend("invalid-authority-provenance:" + error for error in authority_errors)
    if isinstance(authority, Mapping) and not authority_errors:
        if authority.get("source_type") != "worker-discovery":
            errors.append("capability-authority-source-type-mismatch")
        if authority.get("source_id") != receipt.get("canary_session_id"):
            errors.append("capability-authority-session-mismatch")
        if authority.get("source_sha256") != receipt.get("session_evidence_sha256"):
            errors.append("capability-authority-evidence-mismatch")
        if authority.get("actor_role") != "operative-worker":
            errors.append("capability-authority-role-mismatch")
        if authority.get("identity_source") != receipt.get("attestation_source"):
            errors.append("capability-authority-identity-source-mismatch")
        if authority.get("authorized_scope") != "child":
            errors.append("capability-authority-scope-mismatch")
        if authority.get("parent_receipt_sha256") is not None:
            errors.append("capability-authority-parent-receipt-forbidden")

    sha = receipt.get("receipt_sha256")
    if not _nonempty_string(sha) or len(sha) != 64 or any(
        char not in "0123456789abcdef" for char in str(sha)
    ):
        errors.append("invalid-receipt-sha256-format")
    else:
        payload = {key: receipt[key] for key in receipt if key != "receipt_sha256"}
        if sha != _compute_receipt_sha256(payload):
            errors.append("invalid-receipt-sha256")
    return errors


def read_native_capability_receipt(receipt: Any) -> dict[str, Any]:
    """Read v2 or a historical-only v1 receipt without making it operative."""

    if not isinstance(receipt, dict):
        raise ValueError("invalid-receipt-type")
    errors = (
        _validate_v1_capability_receipt(receipt)
        if receipt.get("version") == CAPABILITY_RECEIPT_VERSION_V1
        else validate_native_capability_receipt(receipt)
    )
    if errors:
        raise ValueError("invalid capability receipt: " + "; ".join(errors))
    return deepcopy(receipt)


def build_native_capability_receipt(
    evidence: dict[str, Any],
    authorized_models: Iterable[str],
    issued_at: str,
    expires_at: str,
    *,
    session_authority: VerifiedAuthority,
) -> dict[str, Any]:
    """
    Build a native capability receipt from evidence.
    """
    if isinstance(authorized_models, (str, bytes, bytearray)) or not isinstance(authorized_models, Iterable):
        raise ValueError("authorized_models must be a non-string iterable")
    evaluation = evaluate_native_capability(evidence, authorized_models)
    if evaluation["outcome"] != "native-capability-confirmed":
        raise ValueError("evidence does not confirm native capability")

    issued_dt = _to_rfc3339_datetime(issued_at)
    expires_dt = _to_rfc3339_datetime(expires_at)
    if issued_dt is None or expires_dt is None:
        raise ValueError("issued_at and expires_at must be aware RFC3339")
    if expires_dt <= issued_dt:
        raise ValueError("expires_at must be after issued_at")

    requested_model = evidence.get("requested_model")
    configured_model = evidence.get("configured_model")
    if not _nonempty_string(requested_model) or not _nonempty_string(configured_model):
        raise ValueError("invalid requested_model or configured_model")
    evidence_sha256 = canonical_capability_evidence_sha256(evidence)
    if not isinstance(session_authority, VerifiedAuthority):
        raise ValueError("capability verified session authority is required")
    if (
        session_authority.source_type != "worker-discovery"
        or session_authority.source_id != evidence.get("canary_session_id")
        or session_authority.source_sha256 != evidence_sha256
        or session_authority.actor_role != "operative-worker"
        or session_authority.identity_source != evidence.get("attestation_source")
        or session_authority.authorized_scope != "child"
        or session_authority.serialize().get("parent_receipt_sha256") is not None
    ):
        raise ValueError("capability session authority does not match trusted evidence")

    receipt_body = {
        "receipt_type": CAPABILITY_RECEIPT_TYPE,
        "version": CAPABILITY_RECEIPT_VERSION,
        "requested_model": requested_model,
        "configured_model": configured_model,
        "advertised": bool(evidence.get("advertised")),
        "advertised_models": list(evidence.get("advertised_models") or []),
        "spawn_accepted": True,
        "canary_session_id": evidence.get("canary_session_id"),
        "attestation_source": "trusted-session-jsonl",
        "attested_model": evidence.get("attested_model"),
        "tool_calls": int(evidence.get("tool_calls", 0)),
        "context_compactions": int(evidence.get("context_compactions", 0)),
        "runtime_seconds": float(evidence.get("runtime_seconds", 0)),
        "closure_receipt": True,
        "tool_surface_id": evidence.get("tool_surface_id"),
        "decision": "native-capability-confirmed",
        "session_evidence_sha256": evidence_sha256,
        "authority_provenance": session_authority.serialize(),
        "issued_at": issued_at,
        "expires_at": expires_at,
    }
    receipt_body["receipt_sha256"] = _compute_receipt_sha256(receipt_body)
    validation_errors = validate_native_capability_receipt(receipt_body)
    if validation_errors:
        raise ValueError(
            "capability receipt validation failed: " + "; ".join(validation_errors)
        )
    return receipt_body


def capability_receipt_applies(
    receipt: dict[str, Any], requested_model: str, tool_surface_id: str, at: str
) -> bool:
    if not _nonempty_string(requested_model) or not _nonempty_string(tool_surface_id):
        return False
    if validate_native_capability_receipt(receipt):
        return False

    if receipt.get("requested_model") != requested_model:
        return False
    if receipt.get("tool_surface_id") != tool_surface_id:
        return False

    at_dt = _to_rfc3339_datetime(at)
    if at_dt is None:
        return False
    issued_dt = _to_rfc3339_datetime(receipt.get("issued_at"))
    expires_dt = _to_rfc3339_datetime(receipt.get("expires_at"))
    if issued_dt is None or expires_dt is None:
        return False
    return issued_dt <= at_dt < expires_dt


def build_capability_receipt(
    evidence: dict[str, Any],
    authorized_models: Iterable[str],
    issued_at: str | None = None,
    expires_at: str | None = None,
    *,
    session_authority: VerifiedAuthority,
) -> dict[str, Any]:
    if isinstance(authorized_models, (str, bytes, bytearray)) or not isinstance(authorized_models, Iterable):
        raise ValueError("authorized_models must be a non-string iterable")
    if issued_at is None or expires_at is None:
        raise ValueError("issued_at and expires_at are required")
    return build_native_capability_receipt(
        evidence,
        authorized_models,
        issued_at,
        expires_at,
        session_authority=session_authority,
    )


def validate_capability_receipt(receipt: dict[str, Any]) -> List[str]:
    return validate_native_capability_receipt(receipt)
