"""Provenance-bound stop scope and continuation contracts.

This module deliberately keeps scope authority separate from recommendations.
Free text and confidence values are never inputs to the authority constructors or
merge rule.  Publication authority is available only after verification of a
hash-bound operator directive.
"""

from __future__ import annotations

from copy import deepcopy
import hashlib
import hmac
import json
import re
from typing import Any, Iterable, Mapping


VERSION = 1

STOP_SCOPES = (
    "child",
    "cohort",
    "execution-path",
    "complete-task",
    "publication",
)
STOP_SCOPE_RANK = {scope: index for index, scope in enumerate(STOP_SCOPES)}

CONTINUATION_PATHS = (
    "retry-child",
    "replace-child",
    "continue-cohort",
    "retry-cohort",
    "alternate-execution-path",
    "resume-task",
    "task-remediation",
    "publication-review",
    "operator-adjudication",
)

AUTHORITY_SOURCE_TYPES = (
    "worker-discovery",
    "pm-observation",
    "architect-judgment",
    "operator-directive",
    "policy-enforcement",
)

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

STOP_METADATA_FIELDS = frozenset(
    {"stop_scope", "authorized_continuation_paths", "scope_authority"}
)
CONTINUATION_PATH_FIELDS = frozenset({"path", "target_id", "conditions"})
SCOPE_AUTHORITY_FIELDS = frozenset(
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


class StopScopeError(ValueError):
    """Raised when stop metadata or its provenance is invalid."""


def canonical_scope_sha256(value: Any) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _is_sha256(value: Any) -> bool:
    return isinstance(value, str) and _SHA256_RE.fullmatch(value) is not None


def _nonempty(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _require_scope(value: Any, label: str) -> str:
    if value not in STOP_SCOPE_RANK:
        raise StopScopeError(f"{label}-invalid")
    return str(value)


def _sealed_authority(payload: Mapping[str, Any]) -> dict[str, Any]:
    value = deepcopy(dict(payload))
    value.pop("authority_sha256", None)
    value["authority_sha256"] = canonical_scope_sha256(value)
    return value


class VerifiedScopeAuthority:
    """Opaque authority produced only by this module's verification paths."""

    __slots__ = ("_payload",)

    def __init__(self, payload: Mapping[str, Any], token: object) -> None:
        if token is not _AUTHORITY_TOKEN:
            raise StopScopeError("scope-authority-construction-forbidden")
        self._payload = _sealed_authority(payload)
        errors = validate_scope_authority(self._payload)
        if errors:
            raise StopScopeError("scope-authority-invalid:" + ";".join(errors))

    @property
    def authorized_scope(self) -> str:
        return str(self._payload["authorized_scope"])

    @property
    def source_type(self) -> str:
        return str(self._payload["source_type"])

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
) -> VerifiedScopeAuthority:
    return VerifiedScopeAuthority(
        {
            "version": VERSION,
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


def policy_scope_authority(
    source_id: str,
    *,
    authorized_scope: str,
    source_sha256: str | None = None,
    identity_source: str = "repository-policy",
    compatibility_evidence_sha256: str | None = None,
) -> VerifiedScopeAuthority:
    """Create authority for a deterministic internal policy rule.

    Policy may contain a task, but publication remains an operator-only scope.
    """

    scope = _require_scope(authorized_scope, "authorized-scope")
    if STOP_SCOPE_RANK[scope] > STOP_SCOPE_RANK["complete-task"]:
        raise StopScopeError("policy-publication-authority-forbidden")
    if not _nonempty(source_id) or not _nonempty(identity_source):
        raise StopScopeError("policy-authority-identity-invalid")
    source_hash = source_sha256 or canonical_scope_sha256(
        {"source_id": source_id, "identity_source": identity_source, "version": VERSION}
    )
    if not _is_sha256(source_hash):
        raise StopScopeError("policy-authority-source-sha256-invalid")
    evidence_hash = compatibility_evidence_sha256 or source_hash
    if not _is_sha256(evidence_hash):
        raise StopScopeError("policy-authority-evidence-sha256-invalid")
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


def trusted_actor_scope_authority(
    *,
    source_type: str,
    source_id: str,
    source_sha256: str,
    actor_id: str,
    actor_role: str,
    identity_source: str,
    parent_receipt_sha256: str | None = None,
) -> VerifiedScopeAuthority:
    """Bind a non-operator runtime identity to its maximum permitted scope."""

    if actor_role == "operator" or source_type == "operator-directive":
        raise StopScopeError("operator-authority-requires-verified-directive")
    if source_type == "policy-enforcement" or actor_role == "supervisor-policy":
        raise StopScopeError("policy-authority-requires-policy-constructor")
    if source_type not in SOURCE_ROLE_BINDINGS or actor_role not in SOURCE_ROLE_BINDINGS[source_type]:
        raise StopScopeError("scope-authority-source-role-mismatch")
    if not all(_nonempty(value) for value in (source_id, actor_id, identity_source)):
        raise StopScopeError("scope-authority-identity-invalid")
    if not _is_sha256(source_sha256):
        raise StopScopeError("scope-authority-source-sha256-invalid")
    if parent_receipt_sha256 is not None and not _is_sha256(parent_receipt_sha256):
        raise StopScopeError("scope-authority-parent-receipt-invalid")
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


def verify_operator_scope_directive(
    receipt: Mapping[str, Any],
    *,
    verification_key: bytes,
    expected_actor_id: str,
    expected_identity_source: str,
    expected_action_sha256: str,
) -> VerifiedScopeAuthority:
    """Verify an operator directive and return its opaque scope authority."""

    if not isinstance(receipt, Mapping) or set(receipt) != OPERATOR_DIRECTIVE_FIELDS:
        raise StopScopeError("operator-directive-fields-invalid")
    if not isinstance(verification_key, bytes) or not verification_key:
        raise StopScopeError("operator-directive-verification-key-invalid")
    body = {key: deepcopy(value) for key, value in receipt.items() if key != "signature"}
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
    if not isinstance(signature, str) or not hmac.compare_digest(signature, expected_signature):
        raise StopScopeError("operator-directive-signature-invalid")
    if receipt.get("version") != VERSION:
        raise StopScopeError("operator-directive-version-invalid")
    if receipt.get("actor_id") != expected_actor_id:
        raise StopScopeError("operator-directive-actor-mismatch")
    if receipt.get("identity_source") != expected_identity_source:
        raise StopScopeError("operator-directive-identity-source-mismatch")
    if receipt.get("action_sha256") != expected_action_sha256 or not _is_sha256(
        expected_action_sha256
    ):
        raise StopScopeError("operator-directive-action-mismatch")
    for field in ("directive_id", "actor_id", "identity_source", "issued_at", "nonce"):
        if not _nonempty(receipt.get(field)):
            raise StopScopeError(f"operator-directive-{field.replace('_', '-')}-invalid")
    scope = _require_scope(receipt.get("authorized_scope"), "operator-directive-scope")
    parent = receipt.get("parent_receipt_sha256")
    if parent is not None and not _is_sha256(parent):
        raise StopScopeError("operator-directive-parent-receipt-invalid")
    source_hash = canonical_scope_sha256(body)
    evidence_hash = canonical_scope_sha256(dict(receipt))
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


def continuation_path(
    path: str,
    *,
    target_id: str | None = None,
    conditions: Iterable[str] = (),
) -> dict[str, Any]:
    if path not in CONTINUATION_PATHS:
        raise StopScopeError("continuation-path-invalid")
    if target_id is not None and not _nonempty(target_id):
        raise StopScopeError("continuation-target-id-invalid")
    if isinstance(conditions, (str, bytes)):
        raise StopScopeError("continuation-conditions-invalid")
    try:
        condition_values = list(conditions)
    except TypeError as exc:
        raise StopScopeError("continuation-conditions-invalid") from exc
    if any(not _nonempty(value) for value in condition_values):
        raise StopScopeError("continuation-conditions-invalid")
    normalized_conditions = sorted(set(condition_values))
    return {
        "path": path,
        "target_id": target_id,
        "conditions": normalized_conditions,
    }


def validate_scope_authority(value: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(value, Mapping):
        return ["scope-authority-must-be-object"]
    if set(value) != SCOPE_AUTHORITY_FIELDS:
        missing = sorted(SCOPE_AUTHORITY_FIELDS - set(value))
        unknown = sorted(set(value) - SCOPE_AUTHORITY_FIELDS)
        if missing:
            errors.append("scope-authority-missing-fields:" + ",".join(missing))
        if unknown:
            errors.append("scope-authority-unknown-fields:" + ",".join(unknown))
        return errors
    if value.get("version") != VERSION:
        errors.append("scope-authority-version-invalid")
    source_type = value.get("source_type")
    actor_role = value.get("actor_role")
    if source_type not in AUTHORITY_SOURCE_TYPES:
        errors.append("scope-authority-source-type-invalid")
    if actor_role not in ACTOR_SCOPE_CAPS:
        errors.append("scope-authority-actor-role-invalid")
    elif source_type in SOURCE_ROLE_BINDINGS and actor_role not in SOURCE_ROLE_BINDINGS[source_type]:
        errors.append("scope-authority-source-role-mismatch")
    for field in ("source_id", "actor_id", "identity_source"):
        if not _nonempty(value.get(field)):
            errors.append(f"scope-authority-{field.replace('_', '-')}-invalid")
    for field in ("source_sha256", "authority_sha256"):
        if not _is_sha256(value.get(field)):
            errors.append(f"scope-authority-{field.replace('_', '-')}-invalid")
    parent = value.get("parent_receipt_sha256")
    if parent is not None and not _is_sha256(parent):
        errors.append("scope-authority-parent-receipt-sha256-invalid")
    scope = value.get("authorized_scope")
    if scope not in STOP_SCOPE_RANK:
        errors.append("scope-authority-authorized-scope-invalid")
    elif actor_role in ACTOR_SCOPE_CAPS and STOP_SCOPE_RANK[scope] > STOP_SCOPE_RANK[
        ACTOR_SCOPE_CAPS[actor_role]
    ]:
        errors.append("scope-authority-exceeds-role-cap")
    verification = value.get("verification")
    if not isinstance(verification, Mapping) or set(verification) != VERIFICATION_FIELDS:
        errors.append("scope-authority-verification-fields-invalid")
    else:
        if not _nonempty(verification.get("method")):
            errors.append("scope-authority-verification-method-invalid")
        if not _is_sha256(verification.get("evidence_sha256")):
            errors.append("scope-authority-verification-evidence-invalid")
    if _is_sha256(value.get("authority_sha256")):
        body = dict(value)
        observed = body.pop("authority_sha256")
        if observed != canonical_scope_sha256(body):
            errors.append("scope-authority-sha256-mismatch")
    if source_type == "operator-directive" and isinstance(verification, Mapping):
        if verification.get("method") != "hmac-sha256-operator-directive-v1":
            errors.append("operator-scope-authority-verification-invalid")
    if scope == "publication" and source_type != "operator-directive":
        errors.append("publication-scope-requires-operator-directive")
    return errors


def validate_continuation_paths(value: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(value, list):
        return ["authorized-continuation-paths-must-be-array"]
    normalized: list[dict[str, Any]] = []
    for index, item in enumerate(value):
        if not isinstance(item, Mapping) or set(item) != CONTINUATION_PATH_FIELDS:
            errors.append(f"continuation-path[{index}]-fields-invalid")
            continue
        try:
            normalized.append(
                continuation_path(
                    item.get("path"),
                    target_id=item.get("target_id"),
                    conditions=item.get("conditions", ()),
                )
            )
        except (StopScopeError, TypeError):
            errors.append(f"continuation-path[{index}]-invalid")
            continue
        if dict(item) != normalized[-1]:
            errors.append(f"continuation-path[{index}]-not-canonical")
    canonical = sorted(normalized, key=canonical_scope_sha256)
    if normalized != canonical:
        errors.append("authorized-continuation-paths-not-canonical")
    if len({canonical_scope_sha256(item) for item in normalized}) != len(normalized):
        errors.append("authorized-continuation-paths-duplicate")
    return errors


def validate_stop_metadata(value: Any) -> list[str]:
    if not isinstance(value, Mapping):
        return ["stop-metadata-must-be-object"]
    if set(value) != STOP_METADATA_FIELDS:
        errors: list[str] = []
        missing = sorted(STOP_METADATA_FIELDS - set(value))
        unknown = sorted(set(value) - STOP_METADATA_FIELDS)
        if missing:
            errors.append("stop-metadata-missing-fields:" + ",".join(missing))
        if unknown:
            errors.append("stop-metadata-unknown-fields:" + ",".join(unknown))
        return errors
    errors = []
    scope = value.get("stop_scope")
    if scope not in STOP_SCOPE_RANK:
        errors.append("stop-scope-invalid")
    authority = value.get("scope_authority")
    errors.extend(validate_scope_authority(authority))
    errors.extend(validate_continuation_paths(value.get("authorized_continuation_paths")))
    if (
        scope in STOP_SCOPE_RANK
        and isinstance(authority, Mapping)
        and authority.get("authorized_scope") in STOP_SCOPE_RANK
        and STOP_SCOPE_RANK[scope] > STOP_SCOPE_RANK[authority["authorized_scope"]]
    ):
        errors.append("stop-scope-exceeds-authority")
    return errors


def build_stop_metadata(
    requested_scope: str,
    *,
    authority: VerifiedScopeAuthority,
    authorized_continuation_paths: Iterable[Mapping[str, Any]] = (),
) -> dict[str, Any]:
    requested = _require_scope(requested_scope, "requested-stop-scope")
    if not isinstance(authority, VerifiedScopeAuthority):
        raise StopScopeError("verified-scope-authority-required")
    effective = STOP_SCOPES[
        min(STOP_SCOPE_RANK[requested], STOP_SCOPE_RANK[authority.authorized_scope])
    ]
    paths = []
    for item in authorized_continuation_paths:
        if not isinstance(item, Mapping):
            raise StopScopeError("authorized-continuation-path-must-be-object")
        paths.append(
            continuation_path(
                item.get("path"),
                target_id=item.get("target_id"),
                conditions=item.get("conditions", ()),
            )
        )
    paths.sort(key=canonical_scope_sha256)
    if len({canonical_scope_sha256(item) for item in paths}) != len(paths):
        raise StopScopeError("authorized-continuation-paths-duplicate")
    value = {
        "stop_scope": effective,
        "authorized_continuation_paths": paths,
        "scope_authority": authority.serialize(),
    }
    errors = validate_stop_metadata(value)
    if errors:
        raise StopScopeError("stop-metadata-invalid:" + ";".join(errors))
    return value


def _legacy_scope(value: Mapping[str, Any]) -> str:
    reasons = value.get("reasons")
    reason_values = [str(item) for item in reasons] if isinstance(reasons, list) else []
    if value.get("control_loss_scope") == "pool" or any(
        reason in {"aggregate-budget-exhausted", "cohort-exhausted"}
        for reason in reason_values
    ):
        return "cohort"
    return "child"


def read_stop_metadata(
    value: Mapping[str, Any],
    *,
    legacy_source_id: str,
) -> dict[str, Any]:
    """Read explicit metadata or conservatively migrate a legacy artifact."""

    if not isinstance(value, Mapping):
        raise StopScopeError("stop-artifact-must-be-object")
    present = STOP_METADATA_FIELDS & set(value)
    if present:
        if present != STOP_METADATA_FIELDS:
            raise StopScopeError("partial-stop-metadata-forbidden")
        metadata = {field: deepcopy(value[field]) for field in STOP_METADATA_FIELDS}
        errors = validate_stop_metadata(metadata)
        if errors:
            raise StopScopeError("stop-metadata-invalid:" + ";".join(errors))
        return metadata
    evidence_hash = canonical_scope_sha256(dict(value))
    scope = _legacy_scope(value)
    authority = policy_scope_authority(
        legacy_source_id,
        authorized_scope=scope,
        identity_source="legacy-compatible-read",
        compatibility_evidence_sha256=evidence_hash,
    )
    return build_stop_metadata(scope, authority=authority)


def merge_stop_metadata(*values: Mapping[str, Any]) -> dict[str, Any]:
    """Select the maximum *authorized* scope with deterministic tie handling."""

    if not values:
        raise StopScopeError("stop-metadata-merge-requires-input")
    normalized: list[dict[str, Any]] = []
    for value in values:
        errors = validate_stop_metadata(value)
        if errors:
            raise StopScopeError("stop-metadata-invalid:" + ";".join(errors))
        normalized.append(deepcopy(dict(value)))
    maximum = max(STOP_SCOPE_RANK[value["stop_scope"]] for value in normalized)
    winners = [value for value in normalized if STOP_SCOPE_RANK[value["stop_scope"]] == maximum]
    winners.sort(key=lambda item: canonical_scope_sha256(item["scope_authority"]))
    selected = winners[0]
    paths_by_hash = {
        canonical_scope_sha256(path): deepcopy(path)
        for winner in winners
        for path in winner["authorized_continuation_paths"]
    }
    return {
        "stop_scope": STOP_SCOPES[maximum],
        "authorized_continuation_paths": [paths_by_hash[key] for key in sorted(paths_by_hash)],
        "scope_authority": deepcopy(selected["scope_authority"]),
    }
