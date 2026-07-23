"""Deterministic, non-dispatching recovery-policy foundations.

Recovery artifacts emitted here are audit evidence only.  In particular, a
serialized decision, digest, progress record, steering recommendation, or
retry receipt is never executable authority.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from copy import deepcopy
from types import MappingProxyType
from typing import Any


RECOVERY_DECISION_TYPE = "cwo-native-recovery-decision"
RECOVERY_DECISION_VERSION = 1
RECOVERY_DECISION_SCHEMA = "schemas/native-recovery-decision.schema.json"

RECOVERY_CLASSES = (
    "deterministic-construction-failure",
    "pre-dispatch-transport-failure",
    "contained-semantic-no-op",
    "individual-child-failure",
    "control-security-failure",
    "contradictory-authority-changing-validation",
)

RECOVERY_ACTIONS = (
    "reconstruct-same-admitted-bead",
    "replace-same-admitted-bead",
    "return-same-admitted-bead-to-main-thread",
    "stop-execution-path",
    "await-operator-input",
)

RECOVERY_DECISION_FIELDS = frozenset(
    {
        "decision_type",
        "version",
        "schema",
        "recovery_class",
        "action",
        "replacement_budget",
        "replacement_count",
        "replacements_remaining",
        "construction_attempt_budget",
        "construction_attempt_count",
        "construction_attempts_remaining",
        "stop_scope",
        "required_authority",
        "signals",
        "classification_evidence_sha256",
        "evidence_sha256",
        "fixed_cohort_sha256",
        "admitted_bead_id",
        "admitted_child_sha256",
        "admission_grade",
        "dispatch_authorized",
        "newly_ready_refill_allowed",
        "fixed_cohort_required",
        "decision_sha256",
    }
)

RECOVERY_SIGNAL_FIELDS = (
    "deterministic_construction_failure",
    "pre_dispatch_transport_failure",
    "contained_semantic_no_op",
    "individual_child_failure",
    "control_security_failure",
    "failed_ambiguous_dispatch",
    "contradictory_authority_changing_validation",
)

# Precedence is intentionally highest-first.  An unresolved ambiguous dispatch
# is folded into the protected control/security class and can never fall
# through to a replaceable transport, construction, or child-local outcome.
RECOVERY_PRECEDENCE = (
    (
        "contradictory_authority_changing_validation",
        "contradictory-authority-changing-validation",
    ),
    ("failed_ambiguous_dispatch", "control-security-failure"),
    ("control_security_failure", "control-security-failure"),
    ("individual_child_failure", "individual-child-failure"),
    ("contained_semantic_no_op", "contained-semantic-no-op"),
    ("pre_dispatch_transport_failure", "pre-dispatch-transport-failure"),
    (
        "deterministic_construction_failure",
        "deterministic-construction-failure",
    ),
)

PROVISIONAL_ADMISSION_GRADE = "provisional-fixed-cohort"
LEDGER_EVIDENCE_GRADE = "ledger-chain-only"


def _frozen_recovery_class_matrix() -> Mapping[str, Mapping[str, str | int]]:
    matrix: dict[str, dict[str, str | int]] = {
        "deterministic-construction-failure": {
            "initial_action": "reconstruct-same-admitted-bead",
            "exhausted_action": "return-same-admitted-bead-to-main-thread",
            "replacement_budget": 0,
            "stop_scope": "child",
            "required_authority": "verified-project-manager",
        },
        "pre-dispatch-transport-failure": {
            "initial_action": "replace-same-admitted-bead",
            "exhausted_action": "return-same-admitted-bead-to-main-thread",
            "replacement_budget": 1,
            "stop_scope": "child",
            "required_authority": "pm-controller-plus-supervisor-policy",
        },
        "contained-semantic-no-op": {
            "initial_action": "replace-same-admitted-bead",
            "exhausted_action": "return-same-admitted-bead-to-main-thread",
            "replacement_budget": 1,
            "stop_scope": "child",
            "required_authority": "pm-controller-plus-verified-containment",
        },
        "individual-child-failure": {
            "initial_action": "replace-same-admitted-bead",
            "exhausted_action": "return-same-admitted-bead-to-main-thread",
            "replacement_budget": 1,
            "stop_scope": "child",
            "required_authority": "pm-controller-plus-verified-containment",
        },
        "control-security-failure": {
            "initial_action": "stop-execution-path",
            "exhausted_action": "stop-execution-path",
            "replacement_budget": 0,
            "stop_scope": "execution-path",
            "required_authority": "supervisor-policy",
        },
        "contradictory-authority-changing-validation": {
            "initial_action": "await-operator-input",
            "exhausted_action": "await-operator-input",
            "replacement_budget": 0,
            "stop_scope": "complete-task",
            "required_authority": "verified-operator-directive",
        },
    }
    return MappingProxyType(
        {
            recovery_class: MappingProxyType(dict(contract))
            for recovery_class, contract in matrix.items()
        }
    )


RECOVERY_CLASS_MATRIX = _frozen_recovery_class_matrix()


class RecoveryPolicyError(ValueError):
    """Raised when recovery evidence or a recovery transition fails closed."""


def canonical_recovery_json(value: Any) -> str:
    """Return the unique JSON encoding used by recovery bindings."""

    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise RecoveryPolicyError("recovery-value-not-canonical-json") from exc


def canonical_recovery_sha256(value: Any, *, domain: str) -> str:
    """Hash a canonical value under an explicit recovery-policy domain."""

    if not isinstance(domain, str) or not domain.strip():
        raise RecoveryPolicyError("recovery-hash-domain-invalid")
    envelope = {"domain": domain, "value": value}
    return hashlib.sha256(canonical_recovery_json(envelope).encode("utf-8")).hexdigest()


def is_recovery_sha256(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _validated_signals(signals: Any) -> dict[str, bool]:
    if not isinstance(signals, Mapping):
        raise RecoveryPolicyError("recovery-signals-must-be-object")
    if set(signals) != set(RECOVERY_SIGNAL_FIELDS):
        missing = sorted(set(RECOVERY_SIGNAL_FIELDS) - set(signals))
        unknown = sorted(set(signals) - set(RECOVERY_SIGNAL_FIELDS))
        details: list[str] = []
        if missing:
            details.append("missing=" + ",".join(missing))
        if unknown:
            details.append("unknown=" + ",".join(unknown))
        raise RecoveryPolicyError(
            "recovery-signal-fields-invalid" + (":" + ";".join(details) if details else "")
        )
    normalized: dict[str, bool] = {}
    for field in RECOVERY_SIGNAL_FIELDS:
        value = signals[field]
        if type(value) is not bool:
            raise RecoveryPolicyError(f"recovery-signal-not-boolean:{field}")
        normalized[field] = value
    if not any(normalized.values()):
        raise RecoveryPolicyError("recovery-signal-required")
    return normalized


def classify_recovery_signals(signals: Any) -> str:
    """Return exactly one recovery class using the frozen precedence order."""

    normalized = _validated_signals(signals)
    for field, recovery_class in RECOVERY_PRECEDENCE:
        if normalized[field]:
            return recovery_class
    raise RecoveryPolicyError("recovery-classification-unreachable")


def build_recovery_audit_decision(
    signals: Any,
    *,
    replacement_count: int,
    construction_attempt_count: int,
    evidence_sha256: str,
    fixed_cohort_sha256: str,
    admitted_bead_id: str,
    admitted_child_sha256: str,
) -> dict[str, Any]:
    """Build a deterministic, sealed, explicitly non-executable decision."""

    normalized = _validated_signals(signals)
    recovery_class = classify_recovery_signals(normalized)
    matrix = RECOVERY_CLASS_MATRIX[recovery_class]
    replacement_budget = int(matrix["replacement_budget"])
    if type(replacement_count) is not int or replacement_count not in {0, 1}:
        raise RecoveryPolicyError("recovery-replacement-count-invalid")
    if (
        type(construction_attempt_count) is not int
        or construction_attempt_count not in {0, 1}
    ):
        raise RecoveryPolicyError("recovery-construction-attempt-count-invalid")
    if not is_recovery_sha256(evidence_sha256):
        raise RecoveryPolicyError("recovery-evidence-sha256-invalid")
    if not is_recovery_sha256(fixed_cohort_sha256):
        raise RecoveryPolicyError("recovery-fixed-cohort-sha256-invalid")
    if type(admitted_bead_id) is not str or not admitted_bead_id.strip():
        raise RecoveryPolicyError("recovery-admitted-bead-id-invalid")
    if not is_recovery_sha256(admitted_child_sha256):
        raise RecoveryPolicyError("recovery-admitted-child-sha256-invalid")

    construction_attempt_budget = int(
        recovery_class == "deterministic-construction-failure"
    )
    if recovery_class == "deterministic-construction-failure":
        exhausted = bool(replacement_count or construction_attempt_count)
    elif recovery_class in {
        "pre-dispatch-transport-failure",
        "contained-semantic-no-op",
        "individual-child-failure",
    }:
        exhausted = replacement_count == 1
    else:
        exhausted = False
    action_key = "exhausted_action" if exhausted else "initial_action"
    body: dict[str, Any] = {
        "decision_type": RECOVERY_DECISION_TYPE,
        "version": RECOVERY_DECISION_VERSION,
        "schema": RECOVERY_DECISION_SCHEMA,
        "recovery_class": recovery_class,
        "action": matrix[action_key],
        "replacement_budget": replacement_budget,
        "replacement_count": replacement_count,
        "replacements_remaining": max(0, replacement_budget - replacement_count),
        "construction_attempt_budget": construction_attempt_budget,
        "construction_attempt_count": construction_attempt_count,
        "construction_attempts_remaining": max(
            0,
            construction_attempt_budget - construction_attempt_count,
        ),
        "stop_scope": matrix["stop_scope"],
        "required_authority": matrix["required_authority"],
        "signals": deepcopy(normalized),
        "classification_evidence_sha256": canonical_recovery_sha256(
            normalized,
            domain="native-recovery-classification-evidence-v1",
        ),
        "evidence_sha256": evidence_sha256,
        "fixed_cohort_sha256": fixed_cohort_sha256,
        "admitted_bead_id": admitted_bead_id,
        "admitted_child_sha256": admitted_child_sha256,
        "admission_grade": PROVISIONAL_ADMISSION_GRADE,
        "dispatch_authorized": False,
        "newly_ready_refill_allowed": False,
        "fixed_cohort_required": True,
    }
    body["decision_sha256"] = canonical_recovery_sha256(
        body,
        domain="native-recovery-audit-decision-v1",
    )
    return body


def validate_recovery_audit_decision(value: Any) -> list[str]:
    """Validate an audit decision without promoting it to authority."""

    if type(value) is not dict:
        return ["recovery-decision-must-be-object"]
    if set(value) != RECOVERY_DECISION_FIELDS:
        return ["recovery-decision-fields-invalid"]
    try:
        expected = build_recovery_audit_decision(
            value["signals"],
            replacement_count=value["replacement_count"],
            construction_attempt_count=value["construction_attempt_count"],
            evidence_sha256=value["evidence_sha256"],
            fixed_cohort_sha256=value["fixed_cohort_sha256"],
            admitted_bead_id=value["admitted_bead_id"],
            admitted_child_sha256=value["admitted_child_sha256"],
        )
    except (KeyError, RecoveryPolicyError):
        return ["recovery-decision-invalid"]
    # Python's structural equality aliases bool and int (True == 1 and
    # False == 0).  Decisions cross a JSON boundary, so compare their exact
    # canonical JSON encodings instead of accepting that type confusion.
    if canonical_recovery_json(value) != canonical_recovery_json(expected):
        return ["recovery-decision-mismatch"]
    return []
