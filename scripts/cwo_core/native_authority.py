"""Reusable, provenance-bearing authority verification primitives.

Authority is derived from trusted runtime evidence, repository policy, or a
cryptographically verified operator directive.  Free text, model confidence,
and caller-selected role strings are never authority.
"""

from __future__ import annotations

from copy import deepcopy
import hashlib
import hmac
import json
import re
from typing import Any, Mapping


AUTHORITY_PROVENANCE_VERSION = 1

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

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_AUTHORITY_TOKEN = object()


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

    def serialize(self) -> dict[str, Any]:
        return deepcopy(self._payload)


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
        if verification.get("method") != "hmac-sha256-operator-directive-v1":
            errors.append("operator-authority-provenance-verification-invalid")
    if scope == "publication" and source_type != "operator-directive":
        errors.append("publication-scope-requires-operator-directive")
    return errors
