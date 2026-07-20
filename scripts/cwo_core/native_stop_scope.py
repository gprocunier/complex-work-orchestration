"""Provenance-bound stop scope and continuation contracts.

This module deliberately keeps scope authority separate from recommendations.
Free text and confidence values are never inputs to the authority constructors or
merge rule.  Publication authority is available only after verification of a
hash-bound operator directive.
"""

from __future__ import annotations

from copy import deepcopy
from typing import Any, Iterable, Mapping

from .native_authority import (
    ACTOR_SCOPE_CAPS,
    AUTHORITY_PROVENANCE_FIELDS,
    AUTHORITY_PROVENANCE_VERSION,
    AUTHORITY_SOURCE_TYPES,
    AUTHORIZED_SCOPES,
    SOURCE_ROLE_BINDINGS,
    AuthorityProvenanceError,
    VerifiedAuthority,
    canonical_authority_sha256,
    is_sha256,
    policy_authority,
    trusted_actor_authority,
    validate_authority_provenance,
    verify_operator_directive,
)

VERSION = AUTHORITY_PROVENANCE_VERSION

STOP_SCOPES = AUTHORIZED_SCOPES
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

STOP_METADATA_FIELDS = frozenset(
    {"stop_scope", "authorized_continuation_paths", "scope_authority"}
)
CONTINUATION_PATH_FIELDS = frozenset({"path", "target_id", "conditions"})
SCOPE_AUTHORITY_FIELDS = AUTHORITY_PROVENANCE_FIELDS
StopScopeError = AuthorityProvenanceError
VerifiedScopeAuthority = VerifiedAuthority
canonical_scope_sha256 = canonical_authority_sha256
_is_sha256 = is_sha256
policy_scope_authority = policy_authority
trusted_actor_scope_authority = trusted_actor_authority
verify_operator_scope_directive = verify_operator_directive


def _nonempty(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _require_scope(value: Any, label: str) -> str:
    if value not in STOP_SCOPE_RANK:
        raise StopScopeError(f"{label}-invalid")
    return str(value)


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
    return [
        error.replace("operator-authority-provenance", "operator-scope-authority")
        .replace("authority-provenance", "scope-authority")
        for error in validate_authority_provenance(value)
    ]


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
    authority: VerifiedAuthority,
    authorized_continuation_paths: Iterable[Mapping[str, Any]] = (),
) -> dict[str, Any]:
    requested = _require_scope(requested_scope, "requested-stop-scope")
    if not isinstance(authority, VerifiedAuthority):
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
