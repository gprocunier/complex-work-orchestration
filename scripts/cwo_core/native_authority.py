"""Reusable, provenance-bearing authority verification primitives.

Authority is derived from trusted runtime evidence, repository policy, or a
cryptographically verified operator directive.  Free text, model confidence,
and caller-selected role strings are never authority.
"""

from __future__ import annotations

from collections.abc import Callable, MutableSet
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import hmac
import json
import re
from typing import Any, Iterable, Mapping


AUTHORITY_PROVENANCE_VERSION = 1
OPERATOR_APPROVAL_VERSION = 1
OPERATOR_APPROVAL_TYPE = "cwo-operator-protected-change-approval"

AUTHORITY_SOURCE_TYPES = (
    "worker-discovery",
    "pm-observation",
    "architect-judgment",
    "operator-directive",
    "policy-enforcement",
)

AUTHORIZED_SCOPES = (
    "child",
    "cohort",
    "execution-path",
    "complete-task",
    "publication",
)
AUTHORIZED_SCOPE_RANK = {
    scope: index for index, scope in enumerate(AUTHORIZED_SCOPES)
}

ACTOR_SCOPE_CAPS = {
    "operative-worker": "child",
    "critic": "cohort",
    "project-manager": "execution-path",
    "architect": "complete-task",
    "supervisor-policy": "complete-task",
    "operator": "publication",
}

SOURCE_ROLE_BINDINGS = {
    "worker-discovery": frozenset({"operative-worker", "critic"}),
    "pm-observation": frozenset({"project-manager"}),
    "architect-judgment": frozenset({"architect"}),
    "operator-directive": frozenset({"operator"}),
    "policy-enforcement": frozenset({"supervisor-policy"}),
}

AUTHORITY_LEVEL_RANK = {
    "worker": 0,
    "pm": 1,
    "architect": 2,
    "operator": 3,
}
ACTOR_AUTHORITY_LEVEL = {
    "operative-worker": "worker",
    "project-manager": "pm",
    "architect": "architect",
    "operator": "operator",
}

AUTHORITY_PROVENANCE_FIELDS = frozenset(
    {
        "version",
        "source_type",
        "source_id",
        "source_sha256",
        "actor_id",
        "actor_role",
        "identity_source",
        "authorized_scope",
        "parent_receipt_sha256",
        "verification",
        "authority_sha256",
    }
)
VERIFICATION_FIELDS = frozenset({"method", "evidence_sha256"})
OPERATOR_DIRECTIVE_FIELDS = frozenset(
    {
        "version",
        "directive_id",
        "action_sha256",
        "actor_id",
        "identity_source",
        "authorized_scope",
        "parent_receipt_sha256",
        "issued_at",
        "nonce",
        "signature",
    }
)
OPERATOR_APPROVAL_FIELDS = frozenset(
    {
        "approval_type",
        "version",
        "approval_id",
        "change_type",
        "before_sha256",
        "after_sha256",
        "actor_id",
        "identity_source",
        "authorized_scope",
        "parent_receipt_sha256",
        "issued_at",
        "expires_at",
        "nonce",
        "signature",
    }
)
OPERATOR_REQUIRED_CHANGE_TYPES = (
    "aggregate-budget-increase",
    "model-substitution",
    "objective-change",
    "security-or-authority-change",
    "tainted-mutation-acceptance",
    "contradictory-validation",
)
OPERATOR_VERIFICATION_METHODS = frozenset(
    {
        "hmac-sha256-operator-directive-v1",
        "hmac-sha256-protected-change-v1",
    }
)
OPERATOR_APPROVAL_AUDIT_FIELDS = frozenset(
    {
        "approval_type",
        "version",
        "approval_id",
        "change_type",
        "before_sha256",
        "after_sha256",
        "issued_at",
        "expires_at",
        "nonce",
        "receipt_sha256",
        "signed_receipt",
        "authority_provenance",
    }
)
PROTECTED_CHANGE_SNAPSHOT_FIELDS = (
    "objective",
    "primary_outcome",
    "requested_model",
    "aggregate_allowance",
    "security_context",
    "authority_context",
    "operator_authority",
    "model_authority",
    "self_report_authority",
    "scope_authority",
    "mutation",
    "tainted_mutation_accepted",
    "contradictory_validation",
    "validation_contradiction",
    "validation_disposition",
)

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_AUTHORITY_TOKEN = object()
_OPERATOR_APPROVAL_TOKEN = object()


class AuthorityProvenanceError(ValueError):
    """Raised when authority provenance is malformed or unverified."""


def canonical_authority_sha256(value: Any) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def is_sha256(value: Any) -> bool:
    return isinstance(value, str) and _SHA256_RE.fullmatch(value) is not None


def _nonempty(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _require_scope(value: Any, label: str) -> str:
    if value not in AUTHORIZED_SCOPE_RANK:
        raise AuthorityProvenanceError(f"{label}-invalid")
    return str(value)


def _sealed_authority(payload: Mapping[str, Any]) -> dict[str, Any]:
    value = deepcopy(dict(payload))
    value.pop("authority_sha256", None)
    value["authority_sha256"] = canonical_authority_sha256(value)
    return value


class VerifiedAuthority:
    """Opaque authority produced only by this module's verification paths."""

    __slots__ = ("_payload",)

    def __init__(self, payload: Mapping[str, Any], token: object) -> None:
        if token is not _AUTHORITY_TOKEN:
            raise AuthorityProvenanceError("authority-construction-forbidden")
        self._payload = _sealed_authority(payload)
        errors = validate_authority_provenance(self._payload)
        if errors:
            raise AuthorityProvenanceError(
                "authority-provenance-invalid:" + ";".join(errors)
            )

    @property
    def authorized_scope(self) -> str:
        return str(self._payload["authorized_scope"])

    @property
    def source_type(self) -> str:
        return str(self._payload["source_type"])

    @property
    def actor_role(self) -> str:
        return str(self._payload["actor_role"])

    @property
    def authority_level(self) -> str | None:
        return ACTOR_AUTHORITY_LEVEL.get(self.actor_role)

    def serialize(self) -> dict[str, Any]:
        return deepcopy(self._payload)


class VerifiedOperatorApproval:
    """Opaque, exact-change approval emitted only by the trusted verifier."""

    __slots__ = ("_audit", "_authority")

    def __init__(
        self,
        receipt: Mapping[str, Any],
        authority: VerifiedAuthority,
        token: object,
    ) -> None:
        if token is not _OPERATOR_APPROVAL_TOKEN:
            raise AuthorityProvenanceError("operator-approval-construction-forbidden")
        self._authority = authority
        self._audit = {
            "approval_type": receipt["approval_type"],
            "version": receipt["version"],
            "approval_id": receipt["approval_id"],
            "change_type": receipt["change_type"],
            "before_sha256": receipt["before_sha256"],
            "after_sha256": receipt["after_sha256"],
            "issued_at": receipt["issued_at"],
            "expires_at": receipt["expires_at"],
            "nonce": receipt["nonce"],
            "receipt_sha256": canonical_authority_sha256(dict(receipt)),
            "signed_receipt": deepcopy(dict(receipt)),
            "authority_provenance": authority.serialize(),
        }
        errors = validate_operator_approval_audit(self._audit)
        if errors:
            raise AuthorityProvenanceError(
                "operator-approval-audit-invalid:" + ";".join(errors)
            )

    @property
    def authority(self) -> VerifiedAuthority:
        return self._authority

    @property
    def change_type(self) -> str:
        return str(self._audit["change_type"])

    @property
    def nonce(self) -> str:
        return str(self._audit["nonce"])

    def audit_record(self) -> dict[str, Any]:
        return deepcopy(self._audit)


def _parse_utc_timestamp(value: Any, *, label: str) -> datetime:
    if not _nonempty(value):
        raise AuthorityProvenanceError(f"{label}-invalid")
    normalized = str(value)
    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise AuthorityProvenanceError(f"{label}-invalid") from exc
    if parsed.tzinfo is None:
        raise AuthorityProvenanceError(f"{label}-timezone-required")
    return parsed.astimezone(timezone.utc)


def _current_time(
    value: datetime | str | Callable[[], datetime | str] | None,
) -> datetime:
    resolved = value() if callable(value) else value
    if resolved is None:
        return datetime.now(timezone.utc)
    if isinstance(resolved, datetime):
        if resolved.tzinfo is None:
            raise AuthorityProvenanceError("operator-approval-now-timezone-required")
        return resolved.astimezone(timezone.utc)
    return _parse_utc_timestamp(resolved, label="operator-approval-now")


def _operator_approval_signature(
    body: Mapping[str, Any], verification_key: bytes
) -> str:
    return hmac.new(
        verification_key,
        json.dumps(
            body,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def _nested_value(value: Mapping[str, Any], *path: str) -> Any:
    current: Any = value
    for part in path:
        if not isinstance(current, Mapping):
            return None
        current = current.get(part)
    return current


def protected_change_snapshot(value: Any) -> dict[str, Any]:
    """Project an artifact to the exact fields governed by operator policy."""

    if not isinstance(value, Mapping):
        raise AuthorityProvenanceError("protected-change-artifact-must-be-object")
    return {
        field: deepcopy(value[field])
        for field in PROTECTED_CHANGE_SNAPSHOT_FIELDS
        if field in value
    }


def _aggregate_budget_increased(
    before: Mapping[str, Any], after: Mapping[str, Any]
) -> bool:
    old = before.get("aggregate_allowance")
    new = after.get("aggregate_allowance")
    if old == new:
        return False
    if not isinstance(old, Mapping) or not isinstance(new, Mapping):
        return True
    for field in set(old) | set(new):
        old_value = old.get(field)
        new_value = new.get(field)
        if old_value == new_value:
            continue
        if (
            isinstance(old_value, (int, float))
            and not isinstance(old_value, bool)
            and isinstance(new_value, (int, float))
            and not isinstance(new_value, bool)
            and new_value <= old_value
        ):
            continue
        return True
    return False


def classify_operator_required_changes(
    before: Any,
    after: Any,
    operator_required_for: Iterable[str],
) -> list[str]:
    """Return configured protected categories changed by two JSON artifacts."""

    if not isinstance(before, Mapping) or not isinstance(after, Mapping):
        raise AuthorityProvenanceError("protected-change-artifacts-must-be-objects")
    if isinstance(operator_required_for, (str, bytes)):
        raise AuthorityProvenanceError("operator-required-for-invalid")
    try:
        configured = list(operator_required_for)
    except TypeError as exc:
        raise AuthorityProvenanceError("operator-required-for-invalid") from exc
    if len(configured) != len(set(configured)) or any(
        value not in OPERATOR_REQUIRED_CHANGE_TYPES for value in configured
    ):
        raise AuthorityProvenanceError("operator-required-for-invalid")

    changed: list[str] = []
    for change_type in configured:
        detected = False
        if change_type == "aggregate-budget-increase":
            detected = _aggregate_budget_increased(before, after)
        elif change_type == "model-substitution":
            detected = before.get("requested_model") != after.get("requested_model")
        elif change_type == "objective-change":
            detected = (
                before.get("objective") != after.get("objective")
                or before.get("primary_outcome") != after.get("primary_outcome")
            )
        elif change_type == "security-or-authority-change":
            detected = any(
                before.get(field) != after.get(field)
                for field in (
                    "security_context",
                    "authority_context",
                    "operator_authority",
                    "model_authority",
                    "self_report_authority",
                    "scope_authority",
                )
            )
        elif change_type == "tainted-mutation-acceptance":
            detected = (
                _nested_value(before, "mutation", "tainted")
                != _nested_value(after, "mutation", "tainted")
                or before.get("tainted_mutation_accepted")
                != after.get("tainted_mutation_accepted")
            )
        elif change_type == "contradictory-validation":
            detected = any(
                before.get(field) != after.get(field)
                for field in (
                    "contradictory_validation",
                    "validation_contradiction",
                    "validation_disposition",
                )
            )
        if detected:
            changed.append(change_type)
    return changed


def _verify_operator_approval(
    receipt: Any,
    *,
    verification_key: bytes,
    expected_actor_id: str,
    expected_identity_source: str,
    expected_change_type: str,
    before_artifact: Mapping[str, Any],
    after_artifact: Mapping[str, Any],
    seen_nonces: set[str],
    now: datetime,
) -> VerifiedOperatorApproval:
    if not isinstance(receipt, Mapping) or set(receipt) != OPERATOR_APPROVAL_FIELDS:
        raise AuthorityProvenanceError("operator-approval-fields-invalid")
    if not isinstance(verification_key, bytes) or not verification_key:
        raise AuthorityProvenanceError("operator-approval-verification-key-invalid")
    body = {
        key: deepcopy(value) for key, value in receipt.items() if key != "signature"
    }
    signature = receipt.get("signature")
    try:
        expected_signature = _operator_approval_signature(body, verification_key)
    except (TypeError, ValueError) as exc:
        raise AuthorityProvenanceError("operator-approval-body-invalid") from exc
    if not isinstance(signature, str) or not hmac.compare_digest(
        signature, expected_signature
    ):
        raise AuthorityProvenanceError("operator-approval-signature-invalid")
    if receipt.get("approval_type") != OPERATOR_APPROVAL_TYPE:
        raise AuthorityProvenanceError("operator-approval-type-invalid")
    if receipt.get("version") != OPERATOR_APPROVAL_VERSION:
        raise AuthorityProvenanceError("operator-approval-version-invalid")
    if expected_change_type not in OPERATOR_REQUIRED_CHANGE_TYPES:
        raise AuthorityProvenanceError("operator-approval-change-type-invalid")
    if receipt.get("change_type") != expected_change_type:
        raise AuthorityProvenanceError("operator-approval-change-type-mismatch")
    if receipt.get("actor_id") != expected_actor_id:
        raise AuthorityProvenanceError("operator-approval-actor-mismatch")
    if receipt.get("identity_source") != expected_identity_source:
        raise AuthorityProvenanceError("operator-approval-identity-source-mismatch")
    for field in ("approval_id", "actor_id", "identity_source", "nonce"):
        if not _nonempty(receipt.get(field)):
            raise AuthorityProvenanceError(
                f"operator-approval-{field.replace('_', '-')}-invalid"
            )
    nonce = str(receipt["nonce"])
    if nonce in seen_nonces:
        raise AuthorityProvenanceError("operator-approval-replayed")
    try:
        before_sha256 = canonical_authority_sha256(before_artifact)
        after_sha256 = canonical_authority_sha256(after_artifact)
    except (TypeError, ValueError) as exc:
        raise AuthorityProvenanceError("operator-approval-artifact-invalid") from exc
    if receipt.get("before_sha256") != before_sha256:
        raise AuthorityProvenanceError("operator-approval-before-sha256-mismatch")
    if receipt.get("after_sha256") != after_sha256:
        raise AuthorityProvenanceError("operator-approval-after-sha256-mismatch")
    issued_at = _parse_utc_timestamp(
        receipt.get("issued_at"), label="operator-approval-issued-at"
    )
    expires_at = _parse_utc_timestamp(
        receipt.get("expires_at"), label="operator-approval-expires-at"
    )
    if expires_at <= issued_at:
        raise AuthorityProvenanceError("operator-approval-expiry-window-invalid")
    if now < issued_at:
        raise AuthorityProvenanceError("operator-approval-not-yet-valid")
    if now >= expires_at:
        raise AuthorityProvenanceError("operator-approval-expired")
    scope = _require_scope(receipt.get("authorized_scope"), "operator-approval-scope")
    if AUTHORIZED_SCOPE_RANK[scope] < AUTHORIZED_SCOPE_RANK["complete-task"]:
        raise AuthorityProvenanceError("operator-approval-scope-insufficient")
    parent = receipt.get("parent_receipt_sha256")
    if parent is not None and not is_sha256(parent):
        raise AuthorityProvenanceError("operator-approval-parent-receipt-invalid")
    source_hash = canonical_authority_sha256(body)
    authority = _authority(
        source_type="operator-directive",
        source_id=str(receipt["approval_id"]),
        source_sha256=source_hash,
        actor_id=expected_actor_id,
        actor_role="operator",
        identity_source=expected_identity_source,
        authorized_scope=scope,
        parent_receipt_sha256=parent,
        verification_method="hmac-sha256-protected-change-v1",
        verification_evidence_sha256=canonical_authority_sha256(dict(receipt)),
    )
    return VerifiedOperatorApproval(receipt, authority, _OPERATOR_APPROVAL_TOKEN)


class OperatorApprovalVerifier:
    """Verify exact protected changes and retain replay state across calls."""

    __slots__ = (
        "_verification_key",
        "_expected_actor_id",
        "_expected_identity_source",
        "_consumed_nonces",
        "_now",
    )

    def __init__(
        self,
        *,
        verification_key: bytes,
        expected_actor_id: str,
        expected_identity_source: str,
        consumed_nonces: MutableSet[str] | None = None,
        now: datetime | str | Callable[[], datetime | str] | None = None,
    ) -> None:
        if not isinstance(verification_key, bytes) or not verification_key:
            raise AuthorityProvenanceError("operator-approval-verification-key-invalid")
        if not _nonempty(expected_actor_id) or not _nonempty(expected_identity_source):
            raise AuthorityProvenanceError("operator-approval-verifier-identity-invalid")
        if consumed_nonces is not None and not isinstance(consumed_nonces, MutableSet):
            raise AuthorityProvenanceError("operator-approval-replay-store-invalid")
        store = consumed_nonces if consumed_nonces is not None else set()
        if any(not _nonempty(value) for value in store):
            raise AuthorityProvenanceError("operator-approval-replay-store-invalid")
        self._verification_key = verification_key
        self._expected_actor_id = expected_actor_id
        self._expected_identity_source = expected_identity_source
        self._consumed_nonces = store
        self._now = now

    @property
    def consumed_nonces(self) -> frozenset[str]:
        return frozenset(self._consumed_nonces)

    def verify(
        self,
        receipt: Any,
        *,
        expected_change_type: str,
        before_artifact: Mapping[str, Any],
        after_artifact: Mapping[str, Any],
    ) -> VerifiedOperatorApproval:
        approval = _verify_operator_approval(
            receipt,
            verification_key=self._verification_key,
            expected_actor_id=self._expected_actor_id,
            expected_identity_source=self._expected_identity_source,
            expected_change_type=expected_change_type,
            before_artifact=before_artifact,
            after_artifact=after_artifact,
            seen_nonces=set(self._consumed_nonces),
            now=_current_time(self._now),
        )
        self._consumed_nonces.add(approval.nonce)
        return approval

    def verify_audit(
        self,
        audit: Any,
        *,
        before_artifact: Mapping[str, Any],
        after_artifact: Mapping[str, Any],
    ) -> VerifiedOperatorApproval:
        audit_errors = validate_operator_approval_audit(audit)
        if audit_errors:
            raise AuthorityProvenanceError(
                "operator-approval-audit-invalid:" + ";".join(audit_errors)
            )
        approval = _verify_operator_approval(
            audit["signed_receipt"],
            verification_key=self._verification_key,
            expected_actor_id=self._expected_actor_id,
            expected_identity_source=self._expected_identity_source,
            expected_change_type=str(audit["change_type"]),
            before_artifact=before_artifact,
            after_artifact=after_artifact,
            seen_nonces=set(self._consumed_nonces),
            now=_current_time(self._now),
        )
        if approval.audit_record() != dict(audit):
            raise AuthorityProvenanceError("operator-approval-audit-mismatch")
        self._consumed_nonces.add(approval.nonce)
        return approval

    def authorize_changes(
        self,
        before: Any,
        after: Any,
        *,
        operator_required_for: Iterable[str],
        receipts: Mapping[str, Any] | None,
        prior_nonces: Iterable[str] = (),
    ) -> list[VerifiedOperatorApproval]:
        changed = classify_operator_required_changes(
            before,
            after,
            operator_required_for,
        )
        if not changed:
            if receipts:
                raise AuthorityProvenanceError("operator-approval-unexpected")
            return []
        if not isinstance(receipts, Mapping) or set(receipts) != set(changed):
            raise AuthorityProvenanceError(
                "operator-approval-required-for:" + ",".join(changed)
            )
        if isinstance(prior_nonces, (str, bytes)):
            raise AuthorityProvenanceError("operator-approval-prior-nonces-invalid")
        try:
            persisted_nonces = set(prior_nonces)
        except TypeError as exc:
            raise AuthorityProvenanceError(
                "operator-approval-prior-nonces-invalid"
            ) from exc
        if any(not _nonempty(value) for value in persisted_nonces):
            raise AuthorityProvenanceError("operator-approval-prior-nonces-invalid")
        shadow_nonces = set(self._consumed_nonces) | persisted_nonces
        approvals: list[VerifiedOperatorApproval] = []
        now = _current_time(self._now)
        for change_type in changed:
            approval = _verify_operator_approval(
                receipts[change_type],
                verification_key=self._verification_key,
                expected_actor_id=self._expected_actor_id,
                expected_identity_source=self._expected_identity_source,
                expected_change_type=change_type,
                before_artifact=before,
                after_artifact=after,
                seen_nonces=shadow_nonces,
                now=now,
            )
            shadow_nonces.add(approval.nonce)
            approvals.append(approval)
        for approval in approvals:
            self._consumed_nonces.add(approval.nonce)
        return approvals


def require_minimum_authority(
    authority: Any,
    minimum_level: str,
    *,
    action: str,
) -> VerifiedAuthority:
    """Return verified authority only when its trusted role meets a minimum."""

    if not isinstance(authority, VerifiedAuthority):
        raise AuthorityProvenanceError(f"{action}-verified-authority-required")
    if minimum_level not in AUTHORITY_LEVEL_RANK:
        raise AuthorityProvenanceError("minimum-authority-level-invalid")
    observed = authority.authority_level
    if observed is None or AUTHORITY_LEVEL_RANK[observed] < AUTHORITY_LEVEL_RANK[
        minimum_level
    ]:
        raise AuthorityProvenanceError(
            f"{action}-insufficient-authority:{observed or authority.actor_role}"
        )
    return authority


def build_reason_records(
    reasons: Iterable[str],
    authority: VerifiedAuthority | Mapping[str, Any],
    *,
    detected_by: str,
) -> list[dict[str, Any]]:
    """Build audit-only reason records from already verified provenance."""

    if isinstance(reasons, (str, bytes)) or not _nonempty(detected_by):
        raise AuthorityProvenanceError("authority-reason-record-input-invalid")
    try:
        reason_values = list(reasons)
    except TypeError as exc:
        raise AuthorityProvenanceError("authority-reason-record-input-invalid") from exc
    if any(not _nonempty(reason) for reason in reason_values):
        raise AuthorityProvenanceError("authority-reason-record-reason-invalid")
    provenance = (
        authority.serialize()
        if isinstance(authority, VerifiedAuthority)
        else deepcopy(dict(authority))
        if isinstance(authority, Mapping)
        else None
    )
    errors = validate_authority_provenance(provenance)
    if errors:
        raise AuthorityProvenanceError(
            "authority-reason-record-provenance-invalid:" + ";".join(errors)
        )
    return [
        {
            "reason": reason,
            "authority_provenance": deepcopy(provenance),
            "detected_by": detected_by,
        }
        for reason in reason_values
    ]


def _authority(
    *,
    source_type: str,
    source_id: str,
    source_sha256: str,
    actor_id: str,
    actor_role: str,
    identity_source: str,
    authorized_scope: str,
    parent_receipt_sha256: str | None,
    verification_method: str,
    verification_evidence_sha256: str,
) -> VerifiedAuthority:
    return VerifiedAuthority(
        {
            "version": AUTHORITY_PROVENANCE_VERSION,
            "source_type": source_type,
            "source_id": source_id,
            "source_sha256": source_sha256,
            "actor_id": actor_id,
            "actor_role": actor_role,
            "identity_source": identity_source,
            "authorized_scope": authorized_scope,
            "parent_receipt_sha256": parent_receipt_sha256,
            "verification": {
                "method": verification_method,
                "evidence_sha256": verification_evidence_sha256,
            },
        },
        _AUTHORITY_TOKEN,
    )


def policy_authority(
    source_id: str,
    *,
    authorized_scope: str,
    source_sha256: str | None = None,
    identity_source: str = "repository-policy",
    compatibility_evidence_sha256: str | None = None,
) -> VerifiedAuthority:
    """Create authority for a deterministic internal policy rule."""

    scope = _require_scope(authorized_scope, "authorized-scope")
    if AUTHORIZED_SCOPE_RANK[scope] > AUTHORIZED_SCOPE_RANK["complete-task"]:
        raise AuthorityProvenanceError("policy-publication-authority-forbidden")
    if not _nonempty(source_id) or not _nonempty(identity_source):
        raise AuthorityProvenanceError("policy-authority-identity-invalid")
    source_hash = source_sha256 or canonical_authority_sha256(
        {
            "source_id": source_id,
            "identity_source": identity_source,
            "version": AUTHORITY_PROVENANCE_VERSION,
        }
    )
    if not is_sha256(source_hash):
        raise AuthorityProvenanceError("policy-authority-source-sha256-invalid")
    evidence_hash = compatibility_evidence_sha256 or source_hash
    if not is_sha256(evidence_hash):
        raise AuthorityProvenanceError("policy-authority-evidence-sha256-invalid")
    method = (
        "legacy-compatible-read-v1"
        if compatibility_evidence_sha256 is not None
        else "repository-policy-v1"
    )
    return _authority(
        source_type="policy-enforcement",
        source_id=source_id,
        source_sha256=source_hash,
        actor_id="native-supervisor-policy",
        actor_role="supervisor-policy",
        identity_source=identity_source,
        authorized_scope=scope,
        parent_receipt_sha256=None,
        verification_method=method,
        verification_evidence_sha256=evidence_hash,
    )


def trusted_actor_authority(
    *,
    source_type: str,
    source_id: str,
    source_sha256: str,
    actor_id: str,
    actor_role: str,
    identity_source: str,
    parent_receipt_sha256: str | None = None,
) -> VerifiedAuthority:
    """Bind a trusted runtime identity to its maximum permitted scope."""

    if actor_role == "operator" or source_type == "operator-directive":
        raise AuthorityProvenanceError(
            "operator-authority-requires-verified-directive"
        )
    if source_type == "policy-enforcement" or actor_role == "supervisor-policy":
        raise AuthorityProvenanceError("policy-authority-requires-policy-constructor")
    if (
        source_type not in SOURCE_ROLE_BINDINGS
        or actor_role not in SOURCE_ROLE_BINDINGS[source_type]
    ):
        raise AuthorityProvenanceError("authority-source-role-mismatch")
    if not all(_nonempty(value) for value in (source_id, actor_id, identity_source)):
        raise AuthorityProvenanceError("authority-identity-invalid")
    if not is_sha256(source_sha256):
        raise AuthorityProvenanceError("authority-source-sha256-invalid")
    if parent_receipt_sha256 is not None and not is_sha256(parent_receipt_sha256):
        raise AuthorityProvenanceError("authority-parent-receipt-invalid")
    return _authority(
        source_type=source_type,
        source_id=source_id,
        source_sha256=source_sha256,
        actor_id=actor_id,
        actor_role=actor_role,
        identity_source=identity_source,
        authorized_scope=ACTOR_SCOPE_CAPS[actor_role],
        parent_receipt_sha256=parent_receipt_sha256,
        verification_method="trusted-runtime-role-binding-v1",
        verification_evidence_sha256=source_sha256,
    )


def verify_operator_directive(
    receipt: Mapping[str, Any],
    *,
    verification_key: bytes,
    expected_actor_id: str,
    expected_identity_source: str,
    expected_action_sha256: str,
) -> VerifiedAuthority:
    """Verify a hash-bound operator directive and return opaque authority."""

    if not isinstance(receipt, Mapping) or set(receipt) != OPERATOR_DIRECTIVE_FIELDS:
        raise AuthorityProvenanceError("operator-directive-fields-invalid")
    if not isinstance(verification_key, bytes) or not verification_key:
        raise AuthorityProvenanceError("operator-directive-verification-key-invalid")
    body = {
        key: deepcopy(value) for key, value in receipt.items() if key != "signature"
    }
    signature = receipt.get("signature")
    expected_signature = hmac.new(
        verification_key,
        json.dumps(
            body,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    if not isinstance(signature, str) or not hmac.compare_digest(
        signature, expected_signature
    ):
        raise AuthorityProvenanceError("operator-directive-signature-invalid")
    if receipt.get("version") != AUTHORITY_PROVENANCE_VERSION:
        raise AuthorityProvenanceError("operator-directive-version-invalid")
    if receipt.get("actor_id") != expected_actor_id:
        raise AuthorityProvenanceError("operator-directive-actor-mismatch")
    if receipt.get("identity_source") != expected_identity_source:
        raise AuthorityProvenanceError(
            "operator-directive-identity-source-mismatch"
        )
    if receipt.get("action_sha256") != expected_action_sha256 or not is_sha256(
        expected_action_sha256
    ):
        raise AuthorityProvenanceError("operator-directive-action-mismatch")
    for field in ("directive_id", "actor_id", "identity_source", "issued_at", "nonce"):
        if not _nonempty(receipt.get(field)):
            raise AuthorityProvenanceError(
                f"operator-directive-{field.replace('_', '-')}-invalid"
            )
    scope = _require_scope(receipt.get("authorized_scope"), "operator-directive-scope")
    parent = receipt.get("parent_receipt_sha256")
    if parent is not None and not is_sha256(parent):
        raise AuthorityProvenanceError("operator-directive-parent-receipt-invalid")
    source_hash = canonical_authority_sha256(body)
    evidence_hash = canonical_authority_sha256(dict(receipt))
    return _authority(
        source_type="operator-directive",
        source_id=str(receipt["directive_id"]),
        source_sha256=source_hash,
        actor_id=expected_actor_id,
        actor_role="operator",
        identity_source=expected_identity_source,
        authorized_scope=scope,
        parent_receipt_sha256=parent,
        verification_method="hmac-sha256-operator-directive-v1",
        verification_evidence_sha256=evidence_hash,
    )


def validate_operator_approval_audit(value: Any) -> list[str]:
    """Validate the non-secret audit projection of a verified approval."""

    errors: list[str] = []
    if not isinstance(value, Mapping):
        return ["operator-approval-audit-must-be-object"]
    if set(value) != OPERATOR_APPROVAL_AUDIT_FIELDS:
        missing = sorted(OPERATOR_APPROVAL_AUDIT_FIELDS - set(value))
        unknown = sorted(set(value) - OPERATOR_APPROVAL_AUDIT_FIELDS)
        if missing:
            errors.append("operator-approval-audit-missing-fields:" + ",".join(missing))
        if unknown:
            errors.append("operator-approval-audit-unknown-fields:" + ",".join(unknown))
        return errors
    if value.get("approval_type") != OPERATOR_APPROVAL_TYPE:
        errors.append("operator-approval-audit-type-invalid")
    if value.get("version") != OPERATOR_APPROVAL_VERSION:
        errors.append("operator-approval-audit-version-invalid")
    if value.get("change_type") not in OPERATOR_REQUIRED_CHANGE_TYPES:
        errors.append("operator-approval-audit-change-type-invalid")
    for field in ("approval_id", "issued_at", "expires_at", "nonce"):
        if not _nonempty(value.get(field)):
            errors.append(
                f"operator-approval-audit-{field.replace('_', '-')}-invalid"
            )
    for field in ("before_sha256", "after_sha256", "receipt_sha256"):
        if not is_sha256(value.get(field)):
            errors.append(
                f"operator-approval-audit-{field.replace('_', '-')}-invalid"
            )
    signed_receipt = value.get("signed_receipt")
    if (
        not isinstance(signed_receipt, Mapping)
        or set(signed_receipt) != OPERATOR_APPROVAL_FIELDS
    ):
        errors.append("operator-approval-audit-signed-receipt-fields-invalid")
    else:
        try:
            signed_receipt_sha256 = canonical_authority_sha256(signed_receipt)
        except (TypeError, ValueError):
            signed_receipt_sha256 = None
            errors.append("operator-approval-audit-signed-receipt-invalid")
        if signed_receipt_sha256 != value.get("receipt_sha256"):
            errors.append("operator-approval-audit-signed-receipt-hash-mismatch")
        for field in (
            "approval_type",
            "version",
            "approval_id",
            "change_type",
            "before_sha256",
            "after_sha256",
            "issued_at",
            "expires_at",
            "nonce",
        ):
            if signed_receipt.get(field) != value.get(field):
                errors.append(
                    f"operator-approval-audit-signed-receipt-{field.replace('_', '-')}-mismatch"
                )
    try:
        issued_at = _parse_utc_timestamp(
            value.get("issued_at"), label="operator-approval-audit-issued-at"
        )
        expires_at = _parse_utc_timestamp(
            value.get("expires_at"), label="operator-approval-audit-expires-at"
        )
        if expires_at <= issued_at:
            errors.append("operator-approval-audit-expiry-window-invalid")
    except AuthorityProvenanceError as exc:
        errors.append(str(exc))
    authority_errors = validate_authority_provenance(
        value.get("authority_provenance")
    )
    errors.extend(
        "operator-approval-audit-" + error for error in authority_errors
    )
    return errors


def validate_authority_provenance(value: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(value, Mapping):
        return ["authority-provenance-must-be-object"]
    if set(value) != AUTHORITY_PROVENANCE_FIELDS:
        missing = sorted(AUTHORITY_PROVENANCE_FIELDS - set(value))
        unknown = sorted(set(value) - AUTHORITY_PROVENANCE_FIELDS)
        if missing:
            errors.append("authority-provenance-missing-fields:" + ",".join(missing))
        if unknown:
            errors.append("authority-provenance-unknown-fields:" + ",".join(unknown))
        return errors
    if value.get("version") != AUTHORITY_PROVENANCE_VERSION:
        errors.append("authority-provenance-version-invalid")
    source_type = value.get("source_type")
    actor_role = value.get("actor_role")
    if source_type not in AUTHORITY_SOURCE_TYPES:
        errors.append("authority-provenance-source-type-invalid")
    if actor_role not in ACTOR_SCOPE_CAPS:
        errors.append("authority-provenance-actor-role-invalid")
    elif (
        source_type in SOURCE_ROLE_BINDINGS
        and actor_role not in SOURCE_ROLE_BINDINGS[source_type]
    ):
        errors.append("authority-provenance-source-role-mismatch")
    for field in ("source_id", "actor_id", "identity_source"):
        if not _nonempty(value.get(field)):
            errors.append(
                f"authority-provenance-{field.replace('_', '-')}-invalid"
            )
    for field in ("source_sha256", "authority_sha256"):
        if not is_sha256(value.get(field)):
            errors.append(
                f"authority-provenance-{field.replace('_', '-')}-invalid"
            )
    parent = value.get("parent_receipt_sha256")
    if parent is not None and not is_sha256(parent):
        errors.append("authority-provenance-parent-receipt-sha256-invalid")
    scope = value.get("authorized_scope")
    if scope not in AUTHORIZED_SCOPE_RANK:
        errors.append("authority-provenance-authorized-scope-invalid")
    elif actor_role in ACTOR_SCOPE_CAPS and AUTHORIZED_SCOPE_RANK[scope] > (
        AUTHORIZED_SCOPE_RANK[ACTOR_SCOPE_CAPS[actor_role]]
    ):
        errors.append("authority-provenance-exceeds-role-cap")
    verification = value.get("verification")
    if not isinstance(verification, Mapping) or set(verification) != VERIFICATION_FIELDS:
        errors.append("authority-provenance-verification-fields-invalid")
    else:
        if not _nonempty(verification.get("method")):
            errors.append("authority-provenance-verification-method-invalid")
        if not is_sha256(verification.get("evidence_sha256")):
            errors.append("authority-provenance-verification-evidence-invalid")
    if is_sha256(value.get("authority_sha256")):
        body = dict(value)
        observed = body.pop("authority_sha256")
        if observed != canonical_authority_sha256(body):
            errors.append("authority-provenance-sha256-mismatch")
    if source_type == "operator-directive" and isinstance(verification, Mapping):
        if verification.get("method") not in OPERATOR_VERIFICATION_METHODS:
            errors.append("operator-authority-provenance-verification-invalid")
    if scope == "publication" and source_type != "operator-directive":
        errors.append("publication-scope-requires-operator-directive")
    return errors
