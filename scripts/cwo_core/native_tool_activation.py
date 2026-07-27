"""Exact operator activation for the temporary operative tool boundary.

The serialized tool-enforcement override is intent, not authority.  Authority
comes only from an opaque capability minted by ``OperatorApprovalVerifier`` for
one exact cohort context and consumed before admitted execution.
"""

from __future__ import annotations

from collections.abc import Callable
from copy import deepcopy
from datetime import datetime
from threading import Lock
from typing import Any, Mapping

from .native_authority import (
    AUTHORIZED_SCOPE_RANK,
    OPERATOR_REQUIRED_CHANGE_TYPES,
    AuthorityProvenanceError,
    OperatorApprovalVerifier,
    VerifiedOperatorApproval,
    assess_operator_required_changes,
    canonical_authority_sha256,
    canonical_json_object,
    is_sha256,
    protected_change_identity,
    require_exact_operator_approval_results,
)
from .native_pool_admission import (
    CHILD_BINDING_FIELDS,
    canonical_admission_sha256,
    validate_admission_child_binding,
)
from .native_recovery_authority import (
    RecoveryAuthorityError,
    fixed_cohort_sha256 as recovery_fixed_cohort_sha256,
)
from .native_tool_isolation import (
    TOOL_ENFORCEMENT_OVERRIDE_RISK,
    NativeToolIsolationError,
    normalize_tool_enforcement_override,
)


ACTIVATION_ACTION_TYPE = "cwo-native-tool-enforcement-activation"
ACTIVATION_ACTION_VERSION = 1
_ACTIVATION_TOKEN = object()
_ACTIVATION_CHILD_FIELDS = (
    "child_id",
    "packet_id",
    "packet_sha256",
    "attempt_nonce",
    "lease_id",
    "worktree",
    "isolation_class",
    "declared_write_paths",
    "integration_target_paths",
)
# Claim receipts do not exist when approval is consumed.  Bind the complete
# prospective admission child instead, then require any later reservation to
# reproduce its fixed-cohort and child-binding hashes exactly.
_ACTIVATION_ADMISSION_CHILD_FIELDS = (
    "bead_id",
    "work_unit_id",
    "candidate_sha256",
    "work_estimate_sha256",
    "worker_commitment_sha256",
    "lease_scope_sha256",
    "worktree_identity_sha256",
    "requested_model",
    "admitted_child_sha256",
)
_ACTIVATION_ADMISSION_MARKER_FIELDS = frozenset(
    _ACTIVATION_ADMISSION_CHILD_FIELDS
)


class NativeToolEnforcementActivationError(ValueError):
    """Raised when temporary tool-boundary authority is absent or mismatched."""


def _activation_context(request: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(request, Mapping):
        raise NativeToolEnforcementActivationError(
            "tool-enforcement-activation-request-must-be-object"
        )
    try:
        request_value = canonical_json_object(
            request,
            label="tool-enforcement-activation-request",
        )
    except AuthorityProvenanceError as error:
        raise NativeToolEnforcementActivationError(str(error)) from error
    children = request_value.get("children")
    requested_workers = request_value.get("requested_workers")
    if (
        not isinstance(children, list)
        or isinstance(requested_workers, bool)
        or not isinstance(requested_workers, int)
        or requested_workers not in {1, 2}
        or len(children) != requested_workers
    ):
        raise NativeToolEnforcementActivationError(
            "tool-enforcement-activation-cohort-invalid"
        )

    overrides: list[dict[str, Any]] = []
    admission_bindings: list[dict[str, Any]] = []
    admission_binding_presence: list[bool] = []
    child_bindings: list[dict[str, Any]] = []
    mutating_workers = 0
    for index, child in enumerate(children):
        if not isinstance(child, Mapping):
            raise NativeToolEnforcementActivationError(
                f"tool-enforcement-activation-child[{index}]-invalid"
            )
        policy = child.get("tool_policy")
        if (
            isinstance(policy, Mapping)
            and policy.get("workload_class") == "operative"
            and policy.get("enforcement_mode") == "trusted-detect-and-contain"
        ):
            try:
                overrides.append(
                    normalize_tool_enforcement_override(
                        policy.get("override_provenance")
                    )
                )
            except NativeToolIsolationError as error:
                raise NativeToolEnforcementActivationError(
                    f"tool-enforcement-activation-child[{index}]-override-invalid"
                ) from error
        binding = {
            field: deepcopy(child.get(field)) for field in _ACTIVATION_CHILD_FIELDS
        }
        for field in _ACTIVATION_ADMISSION_CHILD_FIELDS:
            if field in child:
                binding[field] = deepcopy(child.get(field))
        child_bindings.append(binding)
        has_admission_binding = any(
            field in child for field in _ACTIVATION_ADMISSION_MARKER_FIELDS
        )
        admission_binding_presence.append(has_admission_binding)
        if has_admission_binding:
            hard_budget = child.get("hard_budget")
            if (
                not all(field in child for field in CHILD_BINDING_FIELDS)
                or not isinstance(hard_budget, Mapping)
            ):
                raise NativeToolEnforcementActivationError(
                    "tool-enforcement-activation-admission-binding-incomplete"
                )
            admission_binding = {
                field: deepcopy(child[field])
                for field in CHILD_BINDING_FIELDS
                if field != "hard_budget"
            }
            admission_binding["hard_budget"] = {
                field: deepcopy(hard_budget.get(field))
                for field in (
                    "tool_calls",
                    "runtime_seconds",
                    "compactions",
                )
            }
            admission_errors = validate_admission_child_binding(
                admission_binding
            )
            if admission_errors:
                raise NativeToolEnforcementActivationError(
                    "tool-enforcement-activation-admission-binding-invalid:"
                    + ";".join(admission_errors)
                )
            admission_bindings.append(admission_binding)
        if child.get("isolation_class") == "mutable-isolated":
            mutating_workers += 1

    if len(overrides) != requested_workers:
        raise NativeToolEnforcementActivationError(
            "tool-enforcement-activation-complete-cohort-required"
        )
    override = overrides[0]
    if any(candidate != override for candidate in overrides[1:]):
        raise NativeToolEnforcementActivationError(
            "tool-enforcement-activation-override-cohort-mismatch"
        )
    if request_value.get("campaign_nonce") != override["campaign_nonce"]:
        raise NativeToolEnforcementActivationError(
            "tool-enforcement-activation-campaign-nonce-mismatch"
        )
    if mutating_workers > 1:
        raise NativeToolEnforcementActivationError(
            "tool-enforcement-activation-mutating-workers-exceeded"
        )
    if any(admission_binding_presence) and not all(
        admission_binding_presence
    ):
        raise NativeToolEnforcementActivationError(
            "tool-enforcement-activation-admission-cohort-incomplete"
        )

    child_bindings_sha256 = canonical_authority_sha256(
        {"children": child_bindings}
    )
    reservation = request_value.get("admission_reservation")
    fixed_cohort_sha256 = child_bindings_sha256
    admitted_child_bindings_sha256 = child_bindings_sha256
    if admission_bindings:
        try:
            fixed_cohort_sha256 = recovery_fixed_cohort_sha256(
                [
                    {
                        "bead_id": binding["bead_id"],
                        "work_unit_id": binding["work_unit_id"],
                        "admitted_child_sha256": binding[
                            "admitted_child_sha256"
                        ],
                    }
                    for binding in admission_bindings
                ]
            )
            admitted_child_bindings_sha256 = canonical_admission_sha256(
                admission_bindings
            )
        except (RecoveryAuthorityError, TypeError, ValueError) as error:
            raise NativeToolEnforcementActivationError(
                "tool-enforcement-activation-admission-cohort-invalid"
            ) from error
    if isinstance(reservation, Mapping):
        reservation_fixed_cohort_sha256 = reservation.get(
            "fixed_cohort_sha256"
        )
        reservation_child_bindings_sha256 = reservation.get(
            "child_bindings_sha256"
        )
        if (
            not admission_bindings
            or not is_sha256(reservation_fixed_cohort_sha256)
            or not is_sha256(reservation_child_bindings_sha256)
            or reservation_fixed_cohort_sha256 != fixed_cohort_sha256
            or reservation_child_bindings_sha256
            != admitted_child_bindings_sha256
        ):
            raise NativeToolEnforcementActivationError(
                "tool-enforcement-activation-reservation-binding-invalid"
            )

    return {
        "action_type": ACTIVATION_ACTION_TYPE,
        "version": ACTIVATION_ACTION_VERSION,
        "override": override,
        "override_sha256": override["canonical_override_sha256"],
        "launch_id": request_value.get("launch_id"),
        "pool_id": request_value.get("pool_id"),
        "pool_epoch": request_value.get("pool_epoch"),
        "campaign_nonce": override["campaign_nonce"],
        "candidate_commit": override["candidate_commit"],
        "candidate_tree": override["candidate_tree"],
        "requested_workers": requested_workers,
        "mutating_workers": mutating_workers,
        "fixed_cohort_sha256": fixed_cohort_sha256,
        "child_bindings_sha256": admitted_child_bindings_sha256,
        "derived_child_bindings_sha256": child_bindings_sha256,
        "risk_acknowledgement": TOOL_ENFORCEMENT_OVERRIDE_RISK,
    }


def tool_enforcement_activation_artifacts(
    request: Mapping[str, Any],
) -> dict[str, Any]:
    """Return the exact before/after subjects an operator must approve."""

    context = _activation_context(request)
    action_sha256 = canonical_authority_sha256(context)
    authority_context = {
        "action_type": ACTIVATION_ACTION_TYPE,
        "version": ACTIVATION_ACTION_VERSION,
        "action_sha256": action_sha256,
        "override_sha256": context["override_sha256"],
        "launch_id": context["launch_id"],
        "pool_id": context["pool_id"],
        "pool_epoch": context["pool_epoch"],
        "campaign_nonce": context["campaign_nonce"],
        "candidate_commit": context["candidate_commit"],
        "candidate_tree": context["candidate_tree"],
        "requested_workers": context["requested_workers"],
        "mutating_workers": context["mutating_workers"],
        "fixed_cohort_sha256": context["fixed_cohort_sha256"],
        "child_bindings_sha256": context["child_bindings_sha256"],
        "derived_child_bindings_sha256": context[
            "derived_child_bindings_sha256"
        ],
        "risk_acknowledgement": context["risk_acknowledgement"],
    }
    return {
        "action": context,
        "action_sha256": action_sha256,
        "before_artifact": {
            "security_context": {
                **authority_context,
                "decision": "server-allowlist-required",
            }
        },
        "after_artifact": {
            "security_context": {
                **authority_context,
                "decision": "operator-authorized-detect-and-contain",
            }
        },
    }


def tool_enforcement_activation_assessment(
    request: Mapping[str, Any],
    artifacts: Mapping[str, Any] | None = None,
):
    """Build the sealed protected-change assessment for one activation."""

    expected = tool_enforcement_activation_artifacts(request)
    if artifacts is None:
        exact = expected
    else:
        try:
            exact = canonical_json_object(
                artifacts,
                label="tool-enforcement-activation-artifacts",
            )
        except AuthorityProvenanceError as error:
            raise NativeToolEnforcementActivationError(str(error)) from error
        if exact != expected:
            raise NativeToolEnforcementActivationError(
                "tool-enforcement-activation-artifacts-mismatch"
            )
    action = exact.get("action")
    if not isinstance(action, Mapping):
        raise NativeToolEnforcementActivationError(
            "tool-enforcement-activation-artifacts-invalid"
        )
    return assess_operator_required_changes(
        exact.get("before_artifact"),
        exact.get("after_artifact"),
        operator_required_for=OPERATOR_REQUIRED_CHANGE_TYPES,
        profile="generic",
        identity=protected_change_identity(
            artifact_type=ACTIVATION_ACTION_TYPE,
            artifact_id=str(exact.get("action_sha256")),
            work_unit_id=str(action.get("override_sha256")),
            bead_id=None,
            packet_id=str(action.get("fixed_cohort_sha256")),
        ),
    )


class VerifiedToolEnforcementActivation:
    """Opaque, exact-context, single-use temporary boundary authority."""

    __slots__ = (
        "_action_sha256",
        "_approval",
        "_clock",
        "_context",
        "_expires_at",
        "_lock",
        "_state",
    )

    def __init__(
        self,
        *,
        context: Mapping[str, Any],
        action_sha256: str,
        approval: VerifiedOperatorApproval,
        expires_at: datetime,
        clock: Callable[[], datetime],
        token: object,
    ) -> None:
        if token is not _ACTIVATION_TOKEN:
            raise NativeToolEnforcementActivationError(
                "tool-enforcement-activation-construction-forbidden"
            )
        self._context = deepcopy(dict(context))
        self._action_sha256 = action_sha256
        self._approval = approval
        self._clock = clock
        self._expires_at = expires_at
        self._lock = Lock()
        self._state = "available"

    @property
    def action_sha256(self) -> str:
        return self._action_sha256

    @property
    def state(self) -> str:
        with self._lock:
            return self._state

    def authority_provenance(self) -> dict[str, Any]:
        return self._approval.authority.serialize()

    def __copy__(self):
        raise NativeToolEnforcementActivationError(
            "tool-enforcement-activation-copy-forbidden"
        )

    def __deepcopy__(self, _memo):
        raise NativeToolEnforcementActivationError(
            "tool-enforcement-activation-copy-forbidden"
        )

    def __reduce__(self):
        raise NativeToolEnforcementActivationError(
            "tool-enforcement-activation-serialization-forbidden"
        )

    def __reduce_ex__(self, _protocol):
        raise NativeToolEnforcementActivationError(
            "tool-enforcement-activation-serialization-forbidden"
        )

    def _require_binding(self, request: Mapping[str, Any]) -> None:
        context = _activation_context(request)
        if (
            context != self._context
            or canonical_authority_sha256(context) != self._action_sha256
        ):
            raise NativeToolEnforcementActivationError(
                "tool-enforcement-activation-binding-mismatch"
            )

    def _require_fresh_locked(self) -> None:
        if self._state != "available":
            raise NativeToolEnforcementActivationError(
                "tool-enforcement-activation-replayed"
            )
        try:
            now = self._clock()
        except (AuthorityProvenanceError, TypeError, ValueError) as error:
            self._state = "retired"
            raise NativeToolEnforcementActivationError(
                "tool-enforcement-activation-clock-invalid"
            ) from error
        if not isinstance(now, datetime):
            self._state = "retired"
            raise NativeToolEnforcementActivationError(
                "tool-enforcement-activation-clock-invalid"
            )
        if now >= self._expires_at:
            self._state = "retired"
            raise NativeToolEnforcementActivationError(
                "tool-enforcement-activation-expired"
            )

    def _validate(self, request: Mapping[str, Any]) -> dict[str, Any]:
        """Validate freshness and binding atomically without consuming."""

        with self._lock:
            self._require_fresh_locked()
            self._require_binding(request)
            return self.authority_provenance()

    def _consume(self, request: Mapping[str, Any]) -> None:
        """Burn this in-process capability before the first launch side effect."""

        with self._lock:
            self._require_fresh_locked()
            self._require_binding(request)
            self._state = "retired"


def verify_tool_enforcement_activation(
    request: Mapping[str, Any],
    *,
    approval_receipt: Mapping[str, Any],
    operator_approval_verifier: OperatorApprovalVerifier,
) -> VerifiedToolEnforcementActivation:
    """Consume one signed approval and mint opaque exact-context authority."""

    if type(operator_approval_verifier) is not OperatorApprovalVerifier:
        raise NativeToolEnforcementActivationError(
            "tool-enforcement-activation-operator-verifier-required"
        )
    artifacts = tool_enforcement_activation_artifacts(request)
    assessment = tool_enforcement_activation_assessment(request, artifacts)
    try:
        approvals = operator_approval_verifier.authorize_assessment(
            assessment,
            receipts={"security-or-authority-change": approval_receipt},
        )
        approvals = require_exact_operator_approval_results(approvals, assessment)
    except AuthorityProvenanceError as error:
        raise NativeToolEnforcementActivationError(str(error)) from error
    approval = approvals[0]
    if (
        AUTHORIZED_SCOPE_RANK.get(
            approval.authority.authorized_scope,
            -1,
        )
        < AUTHORIZED_SCOPE_RANK["complete-task"]
    ):
        raise NativeToolEnforcementActivationError(
            "tool-enforcement-activation-scope-insufficient"
        )
    return VerifiedToolEnforcementActivation(
        context=artifacts["action"],
        action_sha256=str(artifacts["action_sha256"]),
        approval=approval,
        expires_at=approval.expires_at,
        clock=operator_approval_verifier.activation_clock(),
        token=_ACTIVATION_TOKEN,
    )


def validate_tool_enforcement_activation_binding(
    authorization: object,
    request: Mapping[str, Any],
) -> tuple[list[str], dict[str, Any] | None]:
    """Validate opaque activation without consuming it."""

    if type(authorization) is not VerifiedToolEnforcementActivation:
        return ["tool-enforcement-activation-capability-required"], None
    try:
        authority_provenance = authorization._validate(request)
    except NativeToolEnforcementActivationError as error:
        return [str(error)], None
    except (AttributeError, AuthorityProvenanceError, KeyError, TypeError, ValueError):
        return ["tool-enforcement-activation-binding-invalid"], None
    return [], authority_provenance


def consume_tool_enforcement_activation(
    authorization: object,
    request: Mapping[str, Any],
) -> None:
    """Consume exact activation before admitted execution side effects."""

    if type(authorization) is not VerifiedToolEnforcementActivation:
        raise NativeToolEnforcementActivationError(
            "tool-enforcement-activation-capability-required"
        )
    authorization._consume(request)
