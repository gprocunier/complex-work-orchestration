"""Reusable, provenance-bearing authority verification primitives.

Authority is derived from trusted runtime evidence, repository policy, or a
cryptographically verified operator directive.  Free text, model confidence,
and caller-selected role strings are never authority.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import contextmanager
from copy import deepcopy
from datetime import datetime, timezone
import fcntl
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import stat
import tempfile
from threading import RLock
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
TERMINAL_PROTECTED_CHANGE_TYPES = frozenset(
    {
        "tainted-mutation-acceptance",
        "contradictory-validation",
    }
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

# These fields are emitted by the verifier after approval.  Including them in
# the signed after-subject would be circular.  No caller-selected exclusion is
# supported: every other caller-controlled field remains in the subject.
VERIFIER_OWNED_CIRCULAR_AUDIT_FIELDS = frozenset(
    {
        "operator_approval_receipts",
        "protected_change_authorizations",
    }
)

PROTECTED_CHANGE_IDENTITY_FIELDS = frozenset(
    {
        "artifact_type",
        "artifact_id",
        "work_unit_id",
        "bead_id",
        "packet_id",
    }
)

AGGREGATE_BUDGET_INTEGER_FIELDS = (
    "dispatch_soft_cap",
    "max_pm_replans",
    "max_architect_cycles",
    "max_compactions",
    "tool_calls_hard",
    "runtime_seconds_hard",
)
AGGREGATE_AUTHORITY_FIELDS = frozenset(
    {"dispatch_soft_cap_action", "continuation_authority"}
)

_WORK_ESTIMATE_UNPROTECTED_ROOTS = frozenset(
    {
        "parent_estimate_sha256",
        "refinement_authority",
        "expected_artifacts",
        "expert_profiles",
        "frozen_decisions",
        "unresolved_decisions",
        "subsystems",
        "write_paths",
        "context_manifest",
        "acceptance_checks",
        "task_profile",
        "estimates",
        "scores",
        "semantic_estimate",
        "pm_estimate",
        "domain_expert_estimate",
        "semantic_scores",
        "score_total",
        "route",
        "v1_route",
        "semantic_route",
        "operative_route",
        "variance_metrics",
        "task_class",
    }
)
_PROTECTED_CHANGE_PROFILES = {
    "generic": frozenset(),
    "native-replanning-refinement": frozenset(),
    "native-work-estimate-refinement": _WORK_ESTIMATE_UNPROTECTED_ROOTS,
    "native-ready-set-authority-change": frozenset(),
    "native-proportionality-override": frozenset(),
}

OPERATOR_APPROVAL_REPLAY_STORE_TYPE = "cwo-operator-approval-replay-store"
OPERATOR_APPROVAL_REPLAY_STORE_VERSION = 2
OPERATOR_APPROVAL_REPLAY_STORE_FIELDS = frozenset(
    {"store_type", "version", "entries", "store_hmac_sha256"}
)
OPERATOR_APPROVAL_REPLAY_ENTRY_FIELDS = frozenset(
    {
        "nonce",
        "approval_id",
        "receipt_sha256",
        "change_type",
        "before_sha256",
        "after_sha256",
    }
)
_MAX_REPLAY_STORE_BYTES = 8 * 1024 * 1024
_REPLAY_STORE_KEY_CONTEXT = b"cwo-operator-approval-replay-store-v2\x00"

# A keyed local ledger detects novel edits while the key remains outside the
# hostile process. Same-UID unrestricted filesystem access can still restore a
# previously valid ledger, and possession of both that access and the verifier
# key permits arbitrary rewrites. Rollback resistance therefore requires an
# external trusted monotonic anchor; this file cannot provide that boundary.
OPERATOR_APPROVAL_REPLAY_THREAT_BOUNDARY = (
    "same-UID unrestricted filesystem access can restore a prior valid ledger; "
    "with the verifier key it can also rewrite or reset the ledger, and rollback "
    "resistance requires an external trusted monotonic anchor"
)

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_AUTHORITY_TOKEN = object()
_OPERATOR_APPROVAL_TOKEN = object()
_PROTECTED_CHANGE_ASSESSMENT_TOKEN = object()
_MISSING = object()
_OPERATOR_APPROVAL_LOCK = RLock()


class AuthorityProvenanceError(ValueError):
    """Raised when authority provenance is malformed or unverified."""


def _ordinary_json(value: Any, *, label: str, active: set[int] | None = None) -> Any:
    """Materialize one ordinary, finite JSON value without equality coercions."""

    if active is None:
        active = set()
    if value is None or type(value) in {str, bool, int}:
        return value
    if type(value) is float:
        if value != value or value in {float("inf"), float("-inf")}:
            raise AuthorityProvenanceError(f"{label}-non-finite-number")
        return value
    if isinstance(value, Mapping):
        object_id = id(value)
        if object_id in active:
            raise AuthorityProvenanceError(f"{label}-circular")
        active.add(object_id)
        result: dict[str, Any] = {}
        try:
            try:
                items = value.items()
            except Exception as exc:
                raise AuthorityProvenanceError(f"{label}-mapping-invalid") from exc
            try:
                for raw_key, raw_value in items:
                    if type(raw_key) is not str or raw_key in result:
                        raise AuthorityProvenanceError(f"{label}-object-key-invalid")
                    result[raw_key] = _ordinary_json(
                        raw_value,
                        label=f"{label}.{raw_key}",
                        active=active,
                    )
            except AuthorityProvenanceError:
                raise
            except Exception as exc:
                raise AuthorityProvenanceError(f"{label}-mapping-invalid") from exc
        finally:
            active.remove(object_id)
        return result
    if type(value) is list:
        object_id = id(value)
        if object_id in active:
            raise AuthorityProvenanceError(f"{label}-circular")
        active.add(object_id)
        try:
            return [
                _ordinary_json(item, label=f"{label}[{index}]", active=active)
                for index, item in enumerate(value)
            ]
        finally:
            active.remove(object_id)
    raise AuthorityProvenanceError(f"{label}-json-type-invalid")


def canonical_json_object(value: Any, *, label: str = "json-object") -> dict[str, Any]:
    """Return one detached ordinary-JSON snapshot of an untrusted mapping."""

    result = _ordinary_json(value, label=label)
    if type(result) is not dict:
        raise AuthorityProvenanceError(f"{label}-must-be-object")
    return result


def canonical_authority_sha256(value: Any) -> str:
    canonical = _ordinary_json(value, label="canonical-json")
    encoded = json.dumps(
        canonical,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def is_sha256(value: Any) -> bool:
    return type(value) is str and _SHA256_RE.fullmatch(value) is not None


def _nonempty(value: Any) -> bool:
    return type(value) is str and bool(value.strip())


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
    def source_id(self) -> str:
        return str(self._payload["source_id"])

    @property
    def source_sha256(self) -> str:
        return str(self._payload["source_sha256"])

    @property
    def actor_id(self) -> str:
        return str(self._payload["actor_id"])

    @property
    def actor_role(self) -> str:
        return str(self._payload["actor_role"])

    @property
    def identity_source(self) -> str:
        return str(self._payload["identity_source"])

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

    @property
    def expires_at(self) -> datetime:
        """Return the verifier-validated approval expiry."""

        return _parse_utc_timestamp(
            self._audit["expires_at"],
            label="operator-approval-expires-at",
        )

    def audit_record(self) -> dict[str, Any]:
        return deepcopy(self._audit)


class ProtectedChangeAssessment:
    """Opaque, immutable assessment over complete canonical approval subjects."""

    __slots__ = (
        "_after_subject_json",
        "_before_subject_json",
        "_changed_json_pointers",
        "_identity_json",
        "_required_change_types",
        "_sealed",
        "_uncategorized_paths",
    )

    def __init__(
        self,
        *,
        before_subject: Mapping[str, Any],
        after_subject: Mapping[str, Any],
        identity: Mapping[str, Any] | None,
        changed_json_pointers: Iterable[str],
        required_change_types: Iterable[str],
        uncategorized_paths: Iterable[str],
        token: object,
    ) -> None:
        if token is not _PROTECTED_CHANGE_ASSESSMENT_TOKEN:
            raise AuthorityProvenanceError(
                "protected-change-assessment-construction-forbidden"
            )
        canonical_before = canonical_json_object(
            before_subject, label="protected-change-before-subject"
        )
        canonical_after = canonical_json_object(
            after_subject, label="protected-change-after-subject"
        )
        canonical_identity = (
            canonical_json_object(identity, label="protected-change-identity")
            if identity is not None
            else None
        )
        object.__setattr__(
            self,
            "_before_subject_json",
            json.dumps(
                canonical_before,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            ),
        )
        object.__setattr__(
            self,
            "_after_subject_json",
            json.dumps(
                canonical_after,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            ),
        )
        object.__setattr__(
            self,
            "_identity_json",
            json.dumps(
                canonical_identity,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            ),
        )
        object.__setattr__(
            self, "_changed_json_pointers", tuple(changed_json_pointers)
        )
        object.__setattr__(
            self, "_required_change_types", tuple(required_change_types)
        )
        object.__setattr__(
            self, "_uncategorized_paths", tuple(uncategorized_paths)
        )
        object.__setattr__(self, "_sealed", True)

    def __setattr__(self, name: str, value: Any) -> None:
        if getattr(self, "_sealed", False):
            raise AuthorityProvenanceError(
                "protected-change-assessment-sealed"
            )
        object.__setattr__(self, name, value)

    @property
    def before_subject(self) -> dict[str, Any]:
        return json.loads(self._before_subject_json)

    @property
    def after_subject(self) -> dict[str, Any]:
        return json.loads(self._after_subject_json)

    @property
    def identity(self) -> dict[str, Any] | None:
        return json.loads(self._identity_json)

    @property
    def changed_json_pointers(self) -> tuple[str, ...]:
        return self._changed_json_pointers

    @property
    def required_change_types(self) -> tuple[str, ...]:
        return self._required_change_types

    @property
    def uncategorized_paths(self) -> tuple[str, ...]:
        return self._uncategorized_paths


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

    source = canonical_json_object(value, label="protected-change-artifact")
    return {
        field: deepcopy(source[field])
        for field in PROTECTED_CHANGE_SNAPSHOT_FIELDS
        if field in source
    }


def _json_pointer_part(value: str) -> str:
    return value.replace("~", "~0").replace("/", "~1")


def _json_changed_pointers(before: Any, after: Any, path: str = "") -> list[str]:
    if before is _MISSING and after is _MISSING:
        return []
    if type(before) is not type(after):
        return [path or "/"]
    if type(before) is dict:
        changed: list[str] = []
        for key in sorted(set(before) | set(after)):
            child_path = f"{path}/{_json_pointer_part(key)}"
            if key not in before or key not in after:
                changed.append(child_path)
            else:
                changed.extend(
                    _json_changed_pointers(before[key], after[key], child_path)
                )
        return changed
    if type(before) is list:
        changed = []
        common = min(len(before), len(after))
        for index in range(common):
            changed.extend(
                _json_changed_pointers(
                    before[index], after[index], f"{path}/{index}"
                )
            )
        for index in range(common, max(len(before), len(after))):
            changed.append(f"{path}/{index}")
        return changed
    before_json = json.dumps(
        before, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    )
    after_json = json.dumps(
        after, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    )
    return [] if before_json == after_json else [path or "/"]


def _validate_operator_required_for(operator_required_for: Iterable[str]) -> None:
    if isinstance(operator_required_for, (str, bytes)):
        raise AuthorityProvenanceError("operator-required-for-invalid")
    try:
        configured = list(operator_required_for)
    except TypeError as exc:
        raise AuthorityProvenanceError("operator-required-for-invalid") from exc
    if (
        any(type(value) is not str for value in configured)
        or len(configured) != len(set(configured))
        or tuple(configured) != OPERATOR_REQUIRED_CHANGE_TYPES
    ):
        raise AuthorityProvenanceError("operator-required-for-invalid")


def protected_change_identity(
    *,
    artifact_type: str,
    artifact_id: str,
    work_unit_id: str | None,
    bead_id: str | None,
    packet_id: str | None,
) -> dict[str, Any]:
    """Build the exact identity envelope bound into both approval subjects."""

    result = {
        "artifact_type": artifact_type,
        "artifact_id": artifact_id,
        "work_unit_id": work_unit_id,
        "bead_id": bead_id,
        "packet_id": packet_id,
    }
    for field in ("artifact_type", "artifact_id"):
        if type(result[field]) is not str or not result[field].strip():
            raise AuthorityProvenanceError(f"protected-change-{field}-invalid")
    for field in ("work_unit_id", "bead_id", "packet_id"):
        value = result[field]
        if value is not None and (type(value) is not str or not value.strip()):
            raise AuthorityProvenanceError(f"protected-change-{field}-invalid")
    return result


def _canonical_identity(value: Any) -> dict[str, Any]:
    identity = canonical_json_object(value, label="protected-change-identity")
    if set(identity) != PROTECTED_CHANGE_IDENTITY_FIELDS:
        raise AuthorityProvenanceError("protected-change-identity-fields-invalid")
    return protected_change_identity(
        artifact_type=identity["artifact_type"],
        artifact_id=identity["artifact_id"],
        work_unit_id=identity["work_unit_id"],
        bead_id=identity["bead_id"],
        packet_id=identity["packet_id"],
    )


def _strip_circular_audit_fields(source: Mapping[str, Any]) -> dict[str, Any]:
    return {
        key: deepcopy(value)
        for key, value in source.items()
        if key not in VERIFIER_OWNED_CIRCULAR_AUDIT_FIELDS
    }


def _root_from_pointer(pointer: str) -> str | None:
    if not pointer.startswith("/") or pointer == "/":
        return None
    return pointer[1:].split("/", 1)[0].replace("~1", "/").replace("~0", "~")


def _contradictions(value: Mapping[str, Any]) -> Any:
    fit = value.get("fit_evidence")
    if type(fit) is not dict:
        return _MISSING
    return fit.get("contradictions", _MISSING)


def _protected_binding_paths(value: Mapping[str, Any]) -> frozenset[str]:
    fit_evidence = value.get("fit_evidence")
    bindings = (
        fit_evidence.get("protected_path_bindings")
        if type(fit_evidence) is dict
        else None
    )
    if type(bindings) is not dict:
        return frozenset()
    return frozenset(
        path
        for path, groups in bindings.items()
        if type(path) is str
        and path
        and type(groups) is list
        and bool(groups)
        and all(type(group) is str and bool(group) for group in groups)
    )


def _literal_patch_is_protected(value: Mapping[str, Any]) -> bool:
    profile = value.get("task_profile")
    if type(profile) is not dict:
        return False
    patch = profile.get("architect_literal_patch")
    return (
        type(patch) is dict
        and type(patch.get("path")) is str
        and patch["path"] in _protected_binding_paths(value)
    )


def _categorize_changed_path(
    pointer: str,
    *,
    before: Mapping[str, Any],
    after: Mapping[str, Any],
    profile: str,
) -> str | None:
    root = _root_from_pointer(pointer)
    if profile in {
        "native-ready-set-authority-change",
        "native-proportionality-override",
    }:
        return "security-or-authority-change"
    if root == "aggregate_allowance":
        old = before.get(root, _MISSING)
        new = after.get(root, _MISSING)
        if type(old) is not dict or type(new) is not dict:
            return "__uncategorized__"
        parts = pointer.split("/")
        if len(parts) != 3:
            return "__uncategorized__"
        field = parts[2].replace("~1", "/").replace("~0", "~")
        if field in AGGREGATE_BUDGET_INTEGER_FIELDS:
            old_value = old.get(field, _MISSING)
            new_value = new.get(field, _MISSING)
            if type(old_value) is not int or type(new_value) is not int:
                return "__uncategorized__"
            if new_value > old_value:
                return "aggregate-budget-increase"
            if new_value < old_value:
                return None
            return "__uncategorized__"
        if field in AGGREGATE_AUTHORITY_FIELDS:
            return "security-or-authority-change"
        return "__uncategorized__"
    if root == "requested_model":
        return "model-substitution"
    if root in {"objective", "primary_outcome"}:
        return "objective-change"
    if root in {
        "security_context",
        "authority_context",
        "operator_authority",
        "model_authority",
        "self_report_authority",
        "scope_authority",
        "authority_route",
        "protected_surface_matches",
        "route_conflict",
    }:
        return "security-or-authority-change"
    if root == "mutation" and (
        pointer == "/mutation/tainted" or pointer.startswith("/mutation/tainted/")
    ):
        return "tainted-mutation-acceptance"
    if root == "tainted_mutation_accepted":
        return "tainted-mutation-acceptance"
    if root in {
        "contradictory_validation",
        "validation_contradiction",
        "validation_disposition",
    }:
        return "contradictory-validation"
    if root == "fit_evidence":
        if pointer.startswith("/fit_evidence/protected_path_bindings"):
            return "security-or-authority-change"
        if _json_changed_pointers(_contradictions(before), _contradictions(after)):
            return "contradictory-validation"
        if profile == "native-work-estimate-refinement":
            return None
    if root == "hard_gate_reasons":
        before_reasons = before.get(root, [])
        after_reasons = after.get(root, [])
        if type(before_reasons) is list and type(after_reasons) is list:
            marker = "task-profile-contradiction"
            if (marker in before_reasons) != (marker in after_reasons):
                return "contradictory-validation"
        if profile == "native-work-estimate-refinement":
            return None
    if root == "fit_mode":
        return "security-or-authority-change"
    if (
        profile == "native-work-estimate-refinement"
        and pointer.startswith("/task_profile/architect_literal_patch/")
        and (
            _literal_patch_is_protected(before)
            or _literal_patch_is_protected(after)
        )
    ):
        return "security-or-authority-change"
    if root in _PROTECTED_CHANGE_PROFILES[profile]:
        return None
    return "__uncategorized__"


def _build_protected_change_assessment(
    before: Any,
    after: Any,
    *,
    operator_required_for: Iterable[str],
    profile: str,
    identity: Mapping[str, Any] | None,
) -> ProtectedChangeAssessment:
    _validate_operator_required_for(operator_required_for)
    if profile not in _PROTECTED_CHANGE_PROFILES:
        raise AuthorityProvenanceError("protected-change-profile-invalid")
    canonical_before = _strip_circular_audit_fields(
        canonical_json_object(before, label="protected-change-before")
    )
    canonical_after = _strip_circular_audit_fields(
        canonical_json_object(after, label="protected-change-after")
    )
    changed_paths = tuple(_json_changed_pointers(canonical_before, canonical_after))
    categories: set[str] = set()
    uncategorized: list[str] = []
    for pointer in changed_paths:
        category = _categorize_changed_path(
            pointer,
            before=canonical_before,
            after=canonical_after,
            profile=profile,
        )
        if category == "__uncategorized__":
            uncategorized.append(pointer)
        elif category is not None:
            categories.add(category)
    ordered_categories = tuple(
        category
        for category in OPERATOR_REQUIRED_CHANGE_TYPES
        if category in categories
    )
    canonical_identity = _canonical_identity(identity) if identity is not None else None
    if canonical_identity is None:
        before_subject = canonical_before
        after_subject = canonical_after
    else:
        before_subject = {
            "subject_type": "cwo-protected-change-subject",
            "version": 1,
            "identity": canonical_identity,
            "artifact": canonical_before,
        }
        after_subject = {
            "subject_type": "cwo-protected-change-subject",
            "version": 1,
            "identity": canonical_identity,
            "artifact": canonical_after,
        }
    assessment = ProtectedChangeAssessment(
        before_subject=before_subject,
        after_subject=after_subject,
        identity=canonical_identity,
        changed_json_pointers=changed_paths,
        required_change_types=ordered_categories,
        uncategorized_paths=uncategorized,
        token=_PROTECTED_CHANGE_ASSESSMENT_TOKEN,
    )
    if uncategorized:
        raise AuthorityProvenanceError(
            "protected-change-uncategorized:" + ",".join(uncategorized)
        )
    return assessment


def assess_operator_required_changes(
    before: Any,
    after: Any,
    *,
    operator_required_for: Iterable[str],
    profile: str,
    identity: Mapping[str, Any],
) -> ProtectedChangeAssessment:
    """Assess complete artifacts using one sealed, identity-bound profile."""

    return _build_protected_change_assessment(
        before,
        after,
        operator_required_for=operator_required_for,
        profile=profile,
        identity=identity,
    )


def classify_operator_required_changes(
    before: Any,
    after: Any,
    operator_required_for: Iterable[str],
) -> list[str]:
    """Strict compatibility classifier over complete generic artifacts."""

    return list(
        _build_protected_change_assessment(
            before,
            after,
            operator_required_for=operator_required_for,
            profile="generic",
            identity=None,
        ).required_change_types
    )


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
    receipt_payload = canonical_json_object(
        receipt, label="operator-approval-receipt"
    )
    if set(receipt_payload) != OPERATOR_APPROVAL_FIELDS:
        raise AuthorityProvenanceError("operator-approval-fields-invalid")
    if type(verification_key) is not bytes or not verification_key:
        raise AuthorityProvenanceError("operator-approval-verification-key-invalid")
    body = {
        key: deepcopy(value)
        for key, value in receipt_payload.items()
        if key != "signature"
    }
    signature = receipt_payload.get("signature")
    try:
        expected_signature = _operator_approval_signature(body, verification_key)
    except (TypeError, ValueError) as exc:
        raise AuthorityProvenanceError("operator-approval-body-invalid") from exc
    if type(signature) is not str or not hmac.compare_digest(
        signature, expected_signature
    ):
        raise AuthorityProvenanceError("operator-approval-signature-invalid")
    if receipt_payload.get("approval_type") != OPERATOR_APPROVAL_TYPE:
        raise AuthorityProvenanceError("operator-approval-type-invalid")
    if (
        type(receipt_payload.get("version")) is not int
        or receipt_payload["version"] != OPERATOR_APPROVAL_VERSION
    ):
        raise AuthorityProvenanceError("operator-approval-version-invalid")
    if expected_change_type not in OPERATOR_REQUIRED_CHANGE_TYPES:
        raise AuthorityProvenanceError("operator-approval-change-type-invalid")
    if receipt_payload.get("change_type") != expected_change_type:
        raise AuthorityProvenanceError("operator-approval-change-type-mismatch")
    if receipt_payload.get("actor_id") != expected_actor_id:
        raise AuthorityProvenanceError("operator-approval-actor-mismatch")
    if receipt_payload.get("identity_source") != expected_identity_source:
        raise AuthorityProvenanceError("operator-approval-identity-source-mismatch")
    for field in (
        "approval_type",
        "approval_id",
        "change_type",
        "before_sha256",
        "after_sha256",
        "actor_id",
        "identity_source",
        "authorized_scope",
        "issued_at",
        "expires_at",
        "nonce",
        "signature",
    ):
        if type(receipt_payload.get(field)) is not str or not receipt_payload[
            field
        ].strip():
            raise AuthorityProvenanceError(
                f"operator-approval-{field.replace('_', '-')}-invalid"
            )
    nonce = receipt_payload["nonce"]
    if nonce in seen_nonces:
        raise AuthorityProvenanceError("operator-approval-replayed")
    try:
        before_sha256 = canonical_authority_sha256(before_artifact)
        after_sha256 = canonical_authority_sha256(after_artifact)
    except (TypeError, ValueError) as exc:
        raise AuthorityProvenanceError("operator-approval-artifact-invalid") from exc
    if receipt_payload.get("before_sha256") != before_sha256:
        raise AuthorityProvenanceError("operator-approval-before-sha256-mismatch")
    if receipt_payload.get("after_sha256") != after_sha256:
        raise AuthorityProvenanceError("operator-approval-after-sha256-mismatch")
    issued_at = _parse_utc_timestamp(
        receipt_payload.get("issued_at"), label="operator-approval-issued-at"
    )
    expires_at = _parse_utc_timestamp(
        receipt_payload.get("expires_at"), label="operator-approval-expires-at"
    )
    if expires_at <= issued_at:
        raise AuthorityProvenanceError("operator-approval-expiry-window-invalid")
    if now < issued_at:
        raise AuthorityProvenanceError("operator-approval-not-yet-valid")
    if now >= expires_at:
        raise AuthorityProvenanceError("operator-approval-expired")
    scope = _require_scope(
        receipt_payload.get("authorized_scope"), "operator-approval-scope"
    )
    if AUTHORIZED_SCOPE_RANK[scope] < AUTHORIZED_SCOPE_RANK["complete-task"]:
        raise AuthorityProvenanceError("operator-approval-scope-insufficient")
    parent = receipt_payload.get("parent_receipt_sha256")
    if parent is not None and not is_sha256(parent):
        raise AuthorityProvenanceError("operator-approval-parent-receipt-invalid")
    source_hash = canonical_authority_sha256(body)
    authority = _authority(
        source_type="operator-directive",
        source_id=receipt_payload["approval_id"],
        source_sha256=source_hash,
        actor_id=expected_actor_id,
        actor_role="operator",
        identity_source=expected_identity_source,
        authorized_scope=scope,
        parent_receipt_sha256=parent,
        verification_method="hmac-sha256-protected-change-v1",
        verification_evidence_sha256=canonical_authority_sha256(receipt_payload),
    )
    return VerifiedOperatorApproval(
        receipt_payload, authority, _OPERATOR_APPROVAL_TOKEN
    )


def _replay_store_body(entries: list[dict[str, str]]) -> dict[str, Any]:
    return {
        "store_type": OPERATOR_APPROVAL_REPLAY_STORE_TYPE,
        "version": OPERATOR_APPROVAL_REPLAY_STORE_VERSION,
        "entries": sorted(entries, key=lambda item: item["receipt_sha256"]),
    }


def _derive_replay_store_key(verification_key: bytes) -> bytes:
    return hmac.new(
        verification_key,
        _REPLAY_STORE_KEY_CONTEXT,
        hashlib.sha256,
    ).digest()


def _replay_store_hmac(body: Mapping[str, Any], replay_key: bytes) -> str:
    encoded = json.dumps(
        _ordinary_json(body, label="operator-approval-replay-store-body"),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return hmac.new(replay_key, encoded, hashlib.sha256).hexdigest()


def _sealed_replay_store(
    entries: list[dict[str, str]], replay_key: bytes
) -> dict[str, Any]:
    result = _replay_store_body(entries)
    result["store_hmac_sha256"] = _replay_store_hmac(result, replay_key)
    return result


def _validate_replay_store(value: Any, replay_key: bytes) -> dict[str, Any]:
    payload = canonical_json_object(value, label="operator-approval-replay-store")
    if set(payload) != OPERATOR_APPROVAL_REPLAY_STORE_FIELDS:
        raise AuthorityProvenanceError("operator-approval-replay-store-fields-invalid")
    if payload.get("store_type") != OPERATOR_APPROVAL_REPLAY_STORE_TYPE:
        raise AuthorityProvenanceError("operator-approval-replay-store-type-invalid")
    if (
        type(payload.get("version")) is not int
        or payload["version"] != OPERATOR_APPROVAL_REPLAY_STORE_VERSION
    ):
        raise AuthorityProvenanceError("operator-approval-replay-store-version-invalid")
    entries = payload.get("entries")
    if type(entries) is not list:
        raise AuthorityProvenanceError("operator-approval-replay-store-entries-invalid")
    normalized: list[dict[str, str]] = []
    nonces: set[str] = set()
    approval_ids: set[str] = set()
    receipt_hashes: set[str] = set()
    for entry in entries:
        if type(entry) is not dict or set(entry) != OPERATOR_APPROVAL_REPLAY_ENTRY_FIELDS:
            raise AuthorityProvenanceError("operator-approval-replay-store-entry-invalid")
        if any(type(entry.get(field)) is not str or not entry[field].strip() for field in entry):
            raise AuthorityProvenanceError("operator-approval-replay-store-entry-invalid")
        if entry["change_type"] not in OPERATOR_REQUIRED_CHANGE_TYPES:
            raise AuthorityProvenanceError("operator-approval-replay-store-entry-invalid")
        if any(
            not is_sha256(entry[field])
            for field in ("receipt_sha256", "before_sha256", "after_sha256")
        ):
            raise AuthorityProvenanceError("operator-approval-replay-store-entry-invalid")
        if (
            entry["nonce"] in nonces
            or entry["approval_id"] in approval_ids
            or entry["receipt_sha256"] in receipt_hashes
        ):
            raise AuthorityProvenanceError("operator-approval-replay-store-duplicate-binding")
        nonces.add(entry["nonce"])
        approval_ids.add(entry["approval_id"])
        receipt_hashes.add(entry["receipt_sha256"])
        normalized.append(deepcopy(entry))
    expected = _sealed_replay_store(normalized, replay_key)
    supplied_hmac = payload.get("store_hmac_sha256")
    if not (
        type(supplied_hmac) is str
        and hmac.compare_digest(supplied_hmac, expected["store_hmac_sha256"])
    ):
        raise AuthorityProvenanceError(
            "operator-approval-replay-store-hmac-mismatch"
        )
    if payload != expected:
        raise AuthorityProvenanceError("operator-approval-replay-store-noncanonical")
    return expected


def _reject_replay_symlink_components(path: Path) -> None:
    if not path.is_absolute():
        raise AuthorityProvenanceError("operator-approval-replay-store-path-not-absolute")
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current = current / part
        try:
            identity = current.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(identity.st_mode):
            raise AuthorityProvenanceError("operator-approval-replay-store-symlink-forbidden")


def _validate_replay_parent(path: Path) -> tuple[int, int]:
    _reject_replay_symlink_components(path.parent)
    try:
        identity = path.parent.lstat()
    except OSError as exc:
        raise AuthorityProvenanceError("operator-approval-replay-store-parent-invalid") from exc
    if (
        not stat.S_ISDIR(identity.st_mode)
        or identity.st_uid != os.getuid()
        or stat.S_IMODE(identity.st_mode) & 0o077
    ):
        raise AuthorityProvenanceError("operator-approval-replay-store-parent-invalid")
    return identity.st_dev, identity.st_ino


def _validate_open_replay_file(
    descriptor: int,
    path: Path,
    *,
    label: str,
) -> os.stat_result:
    identity = os.fstat(descriptor)
    if (
        not stat.S_ISREG(identity.st_mode)
        or identity.st_uid != os.getuid()
        or identity.st_nlink != 1
        or stat.S_IMODE(identity.st_mode) & 0o077
    ):
        raise AuthorityProvenanceError(f"operator-approval-{label}-file-invalid")
    try:
        path_identity = path.lstat()
    except OSError as exc:
        raise AuthorityProvenanceError(f"operator-approval-{label}-path-invalid") from exc
    if (
        stat.S_ISLNK(path_identity.st_mode)
        or (path_identity.st_dev, path_identity.st_ino)
        != (identity.st_dev, identity.st_ino)
    ):
        raise AuthorityProvenanceError(f"operator-approval-{label}-inode-mismatch")
    return identity


def _replay_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _read_replay_store(
    path: Path,
    replay_key: bytes,
) -> tuple[dict[str, Any], tuple[int, int] | None]:
    _reject_replay_symlink_components(path)
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except FileNotFoundError:
        return _sealed_replay_store([], replay_key), None
    except OSError as exc:
        raise AuthorityProvenanceError("operator-approval-replay-store-open-failed") from exc
    try:
        identity = _validate_open_replay_file(
            descriptor, path, label="replay-store"
        )
        if identity.st_size > _MAX_REPLAY_STORE_BYTES:
            raise AuthorityProvenanceError("operator-approval-replay-store-too-large")
        chunks: list[bytes] = []
        remaining = _MAX_REPLAY_STORE_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        if len(raw) > _MAX_REPLAY_STORE_BYTES:
            raise AuthorityProvenanceError("operator-approval-replay-store-too-large")
        try:
            decoded = raw.decode("utf-8")
            payload = json.loads(
                decoded,
                object_pairs_hook=_replay_json_object,
            )
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            raise AuthorityProvenanceError("operator-approval-replay-store-corrupt") from exc
        return _validate_replay_store(payload, replay_key), (
            identity.st_dev,
            identity.st_ino,
        )
    finally:
        os.close(descriptor)


def _write_replay_store(
    path: Path,
    payload: Mapping[str, Any],
    *,
    replay_key: bytes,
    prior_identity: tuple[int, int] | None,
    prior_store_hmac_sha256: str,
    parent_identity: tuple[int, int],
) -> None:
    current_parent = _validate_replay_parent(path)
    if current_parent != parent_identity:
        raise AuthorityProvenanceError("operator-approval-replay-store-parent-inode-changed")
    current, current_identity = _read_replay_store(path, replay_key)
    if (
        current_identity != prior_identity
        or current.get("store_hmac_sha256") != prior_store_hmac_sha256
    ):
        raise AuthorityProvenanceError("operator-approval-replay-store-inode-changed")
    sealed = _validate_replay_store(payload, replay_key)
    encoded = (
        json.dumps(
            sealed,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")
    descriptor = -1
    temporary_name = ""
    try:
        descriptor, temporary_name = tempfile.mkstemp(
            dir=path.parent, prefix=f".{path.name}.tmp-"
        )
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            descriptor = -1
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        temporary = Path(temporary_name)
        temporary_identity = temporary.lstat()
        if (
            not stat.S_ISREG(temporary_identity.st_mode)
            or temporary_identity.st_uid != os.getuid()
            or temporary_identity.st_nlink != 1
        ):
            raise AuthorityProvenanceError("operator-approval-replay-store-temporary-invalid")
        final_current, final_identity = _read_replay_store(path, replay_key)
        if (
            final_identity != prior_identity
            or final_current.get("store_hmac_sha256")
            != prior_store_hmac_sha256
            or _validate_replay_parent(path) != parent_identity
        ):
            raise AuthorityProvenanceError("operator-approval-replay-store-inode-changed")
        os.replace(temporary, path)
        temporary_name = ""
        directory_descriptor = os.open(
            path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        )
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
    except AuthorityProvenanceError:
        raise
    except OSError as exc:
        raise AuthorityProvenanceError("operator-approval-replay-store-persist-failed") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if temporary_name:
            try:
                os.unlink(temporary_name)
            except FileNotFoundError:
                pass


@contextmanager
def _locked_replay_store(
    path: Path,
    *,
    replay_key: bytes,
    write: bool,
) -> Iterator[dict[str, Any]]:
    parent_identity = _validate_replay_parent(path)
    _reject_replay_symlink_components(path)
    lock_path = path.with_name(f"{path.name}.lock")
    _reject_replay_symlink_components(lock_path)
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(lock_path, flags, 0o600)
    except OSError as exc:
        raise AuthorityProvenanceError("operator-approval-replay-lock-open-failed") from exc
    try:
        _validate_open_replay_file(descriptor, lock_path, label="replay-lock")
        fcntl.flock(descriptor, fcntl.LOCK_EX if write else fcntl.LOCK_SH)
        _validate_open_replay_file(descriptor, lock_path, label="replay-lock")
        store, prior_identity = _read_replay_store(path, replay_key)
        prior_store_hmac_sha256 = store["store_hmac_sha256"]
        yield store
        if write:
            _validate_open_replay_file(descriptor, lock_path, label="replay-lock")
            _write_replay_store(
                path,
                store,
                replay_key=replay_key,
                prior_identity=prior_identity,
                prior_store_hmac_sha256=prior_store_hmac_sha256,
                parent_identity=parent_identity,
            )
    finally:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


def _approval_replay_entry(approval: VerifiedOperatorApproval) -> dict[str, str]:
    audit = approval.audit_record()
    return {
        field: str(audit[field])
        for field in OPERATOR_APPROVAL_REPLAY_ENTRY_FIELDS
    }


class OperatorApprovalVerifier:
    """Mint approvals only from sealed assessments and a durable replay store."""

    __slots__ = (
        "_verification_key",
        "_replay_store_key",
        "_expected_actor_id",
        "_expected_identity_source",
        "_replay_store_path",
        "_now",
    )

    def __init__(
        self,
        *,
        verification_key: bytes,
        expected_actor_id: str,
        expected_identity_source: str,
        replay_store_path: Path,
        now: datetime | str | Callable[[], datetime | str] | None = None,
    ) -> None:
        if type(verification_key) is not bytes or not verification_key:
            raise AuthorityProvenanceError("operator-approval-verification-key-invalid")
        if not _nonempty(expected_actor_id) or not _nonempty(expected_identity_source):
            raise AuthorityProvenanceError("operator-approval-verifier-identity-invalid")
        if not isinstance(replay_store_path, Path):
            raise AuthorityProvenanceError("operator-approval-replay-store-path-invalid")
        replay_path = Path(replay_store_path)
        _validate_replay_parent(replay_path)
        _reject_replay_symlink_components(replay_path)
        self._verification_key = verification_key
        self._replay_store_key = _derive_replay_store_key(verification_key)
        self._expected_actor_id = expected_actor_id
        self._expected_identity_source = expected_identity_source
        self._replay_store_path = replay_path
        self._now = now

    @property
    def consumed_nonces(self) -> frozenset[str]:
        with _OPERATOR_APPROVAL_LOCK, _locked_replay_store(
            self._replay_store_path,
            replay_key=self._replay_store_key,
            write=False,
        ) as store:
            return frozenset(entry["nonce"] for entry in store["entries"])

    def activation_clock(self) -> Callable[[], datetime]:
        """Return a trusted clock without retaining the verifier or its key."""

        source = self._now

        def current_time() -> datetime:
            return _current_time(source)

        return current_time

    @staticmethod
    def _validate_assessment(assessment: ProtectedChangeAssessment) -> list[str]:
        if type(assessment) is not ProtectedChangeAssessment:
            raise AuthorityProvenanceError("protected-change-assessment-required")
        if assessment.identity is None:
            raise AuthorityProvenanceError("protected-change-assessment-identity-required")
        if assessment.uncategorized_paths:
            raise AuthorityProvenanceError(
                "protected-change-uncategorized:"
                + ",".join(assessment.uncategorized_paths)
            )
        changed = list(assessment.required_change_types)
        terminal = [
            change_type
            for change_type in changed
            if change_type in TERMINAL_PROTECTED_CHANGE_TYPES
        ]
        if terminal:
            raise AuthorityProvenanceError(
                "operator-approval-terminal-change-not-authorizable:"
                + ",".join(terminal)
            )
        return changed

    def authorize_assessment(
        self,
        assessment: ProtectedChangeAssessment,
        *,
        receipts: Mapping[str, Any] | None,
        prior_nonces: Iterable[str] = (),
    ) -> list[VerifiedOperatorApproval]:
        """Verify and durably consume one complete assessment receipt set."""

        changed = self._validate_assessment(assessment)
        receipt_payload = (
            {}
            if receipts is None
            else canonical_json_object(receipts, label="operator-approval-receipts")
        )
        if not changed:
            if receipt_payload:
                raise AuthorityProvenanceError("operator-approval-unexpected")
            return []
        if tuple(receipt_payload) != tuple(changed):
            raise AuthorityProvenanceError(
                "operator-approval-required-for:" + ",".join(changed)
            )
        if isinstance(prior_nonces, (str, bytes)):
            raise AuthorityProvenanceError("operator-approval-prior-nonces-invalid")
        try:
            prior_values = list(prior_nonces)
        except TypeError as exc:
            raise AuthorityProvenanceError("operator-approval-prior-nonces-invalid") from exc
        if any(type(value) is not str or not value.strip() for value in prior_values):
            raise AuthorityProvenanceError("operator-approval-prior-nonces-invalid")
        before_subject = assessment.before_subject
        after_subject = assessment.after_subject
        with _OPERATOR_APPROVAL_LOCK, _locked_replay_store(
            self._replay_store_path,
            replay_key=self._replay_store_key,
            write=True,
        ) as store:
            existing = store["entries"]
            shadow_nonces = {entry["nonce"] for entry in existing} | set(prior_values)
            shadow_ids = {entry["approval_id"] for entry in existing}
            shadow_hashes = {entry["receipt_sha256"] for entry in existing}
            approvals: list[VerifiedOperatorApproval] = []
            now = _current_time(self._now)
            for change_type in changed:
                approval = _verify_operator_approval(
                    receipt_payload[change_type],
                    verification_key=self._verification_key,
                    expected_actor_id=self._expected_actor_id,
                    expected_identity_source=self._expected_identity_source,
                    expected_change_type=change_type,
                    before_artifact=before_subject,
                    after_artifact=after_subject,
                    seen_nonces=shadow_nonces,
                    now=now,
                )
                entry = _approval_replay_entry(approval)
                if (
                    entry["approval_id"] in shadow_ids
                    or entry["receipt_sha256"] in shadow_hashes
                ):
                    raise AuthorityProvenanceError("operator-approval-replayed")
                shadow_nonces.add(entry["nonce"])
                shadow_ids.add(entry["approval_id"])
                shadow_hashes.add(entry["receipt_sha256"])
                approvals.append(approval)
            store.clear()
            store.update(
                _sealed_replay_store(
                    existing + [_approval_replay_entry(item) for item in approvals],
                    self._replay_store_key,
                )
            )
        return approvals

    def validate_assessment_audits(
        self,
        assessment: ProtectedChangeAssessment,
        *,
        audits: Mapping[str, Any] | None,
        receipts: Mapping[str, Any] | None = None,
    ) -> None:
        """Non-consumingly prove stored audits match an assessment and durable bindings."""

        changed = self._validate_assessment(assessment)
        audit_payload = (
            {}
            if audits is None
            else canonical_json_object(audits, label="operator-approval-audits")
        )
        receipt_payload = (
            None
            if receipts is None
            else canonical_json_object(receipts, label="operator-approval-receipts")
        )
        if tuple(audit_payload) != tuple(changed):
            raise AuthorityProvenanceError(
                "operator-approval-audit-required-for:" + ",".join(changed)
            )
        if receipt_payload is not None and tuple(receipt_payload) != tuple(changed):
            raise AuthorityProvenanceError(
                "operator-approval-required-for:" + ",".join(changed)
            )
        before_subject = assessment.before_subject
        after_subject = assessment.after_subject
        with _OPERATOR_APPROVAL_LOCK, _locked_replay_store(
            self._replay_store_path,
            replay_key=self._replay_store_key,
            write=False,
        ) as store:
            by_hash = {entry["receipt_sha256"]: entry for entry in store["entries"]}
            for change_type in changed:
                audit = canonical_json_object(
                    audit_payload[change_type], label="operator-approval-audit"
                )
                audit_errors = validate_operator_approval_audit(audit)
                if audit_errors:
                    raise AuthorityProvenanceError(
                        "operator-approval-audit-invalid:" + ";".join(audit_errors)
                    )
                if audit.get("change_type") != change_type:
                    raise AuthorityProvenanceError("operator-approval-audit-change-type-mismatch")
                signed = audit["signed_receipt"]
                if receipt_payload is not None and canonical_authority_sha256(
                    receipt_payload[change_type]
                ) != canonical_authority_sha256(signed):
                    raise AuthorityProvenanceError("operator-approval-audit-receipt-mismatch")
                verification_time = _parse_utc_timestamp(
                    signed.get("issued_at"), label="operator-approval-issued-at"
                )
                approval = _verify_operator_approval(
                    signed,
                    verification_key=self._verification_key,
                    expected_actor_id=self._expected_actor_id,
                    expected_identity_source=self._expected_identity_source,
                    expected_change_type=change_type,
                    before_artifact=before_subject,
                    after_artifact=after_subject,
                    seen_nonces=set(),
                    now=verification_time,
                )
                if canonical_authority_sha256(
                    approval.audit_record()
                ) != canonical_authority_sha256(audit):
                    raise AuthorityProvenanceError("operator-approval-audit-mismatch")
                expected_entry = _approval_replay_entry(approval)
                if by_hash.get(expected_entry["receipt_sha256"]) != expected_entry:
                    raise AuthorityProvenanceError("operator-approval-audit-not-durably-consumed")


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
    if type(verification_key) is not bytes or not verification_key:
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
    try:
        payload = canonical_json_object(value, label="operator-approval-audit")
    except AuthorityProvenanceError as exc:
        return [str(exc)]
    if set(payload) != OPERATOR_APPROVAL_AUDIT_FIELDS:
        missing = sorted(OPERATOR_APPROVAL_AUDIT_FIELDS - set(payload))
        unknown = sorted(set(payload) - OPERATOR_APPROVAL_AUDIT_FIELDS)
        if missing:
            errors.append("operator-approval-audit-missing-fields:" + ",".join(missing))
        if unknown:
            errors.append("operator-approval-audit-unknown-fields:" + ",".join(unknown))
        return errors
    if payload.get("approval_type") != OPERATOR_APPROVAL_TYPE:
        errors.append("operator-approval-audit-type-invalid")
    if (
        type(payload.get("version")) is not int
        or payload["version"] != OPERATOR_APPROVAL_VERSION
    ):
        errors.append("operator-approval-audit-version-invalid")
    if payload.get("change_type") not in OPERATOR_REQUIRED_CHANGE_TYPES:
        errors.append("operator-approval-audit-change-type-invalid")
    for field in ("approval_id", "issued_at", "expires_at", "nonce"):
        if not _nonempty(payload.get(field)):
            errors.append(
                f"operator-approval-audit-{field.replace('_', '-')}-invalid"
            )
    for field in ("before_sha256", "after_sha256", "receipt_sha256"):
        if not is_sha256(payload.get(field)):
            errors.append(
                f"operator-approval-audit-{field.replace('_', '-')}-invalid"
            )
    signed_receipt = payload.get("signed_receipt")
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
        if signed_receipt_sha256 != payload.get("receipt_sha256"):
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
            if _json_changed_pointers(
                signed_receipt.get(field, _MISSING),
                payload.get(field, _MISSING),
            ):
                errors.append(
                    f"operator-approval-audit-signed-receipt-{field.replace('_', '-')}-mismatch"
                )
    try:
        issued_at = _parse_utc_timestamp(
            payload.get("issued_at"), label="operator-approval-audit-issued-at"
        )
        expires_at = _parse_utc_timestamp(
            payload.get("expires_at"), label="operator-approval-audit-expires-at"
        )
        if expires_at <= issued_at:
            errors.append("operator-approval-audit-expiry-window-invalid")
    except AuthorityProvenanceError as exc:
        errors.append(str(exc))
    authority_errors = validate_authority_provenance(
        payload.get("authority_provenance")
    )
    errors.extend(
        "operator-approval-audit-" + error for error in authority_errors
    )
    return errors


def require_exact_operator_approval_results(
    approvals: Any,
    assessment: ProtectedChangeAssessment,
) -> list[VerifiedOperatorApproval]:
    """Independently validate a consuming verifier's returned capabilities."""

    if type(assessment) is not ProtectedChangeAssessment:
        raise AuthorityProvenanceError("protected-change-assessment-required")
    expected_categories = assessment.required_change_types
    if type(approvals) is not list or len(approvals) != len(expected_categories):
        raise AuthorityProvenanceError("operator-approval-result-set-invalid")
    expected_before = canonical_authority_sha256(assessment.before_subject)
    expected_after = canonical_authority_sha256(assessment.after_subject)
    validated: list[VerifiedOperatorApproval] = []
    for index, expected_category in enumerate(expected_categories):
        approval = approvals[index]
        if type(approval) is not VerifiedOperatorApproval:
            raise AuthorityProvenanceError("operator-approval-result-type-invalid")
        try:
            audit = approval.audit_record()
            observed_category = approval.change_type
            authority = approval.authority
        except (AttributeError, KeyError, TypeError, ValueError) as exc:
            raise AuthorityProvenanceError(
                "operator-approval-result-audit-invalid"
            ) from exc
        if type(authority) is not VerifiedAuthority:
            raise AuthorityProvenanceError(
                "operator-approval-result-authority-invalid"
            )
        try:
            authority_payload = authority.serialize()
        except (AttributeError, KeyError, TypeError, ValueError) as exc:
            raise AuthorityProvenanceError(
                "operator-approval-result-authority-invalid"
            ) from exc
        errors = validate_operator_approval_audit(audit)
        if errors:
            raise AuthorityProvenanceError(
                "operator-approval-result-audit-invalid:" + ";".join(errors)
            )
        if (
            observed_category != expected_category
            or audit.get("change_type") != expected_category
            or audit.get("before_sha256") != expected_before
            or audit.get("after_sha256") != expected_after
            or audit.get("authority_provenance") != authority_payload
        ):
            raise AuthorityProvenanceError("operator-approval-result-binding-invalid")
        validated.append(approval)
    return validated


def validate_authority_provenance(value: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(value, Mapping):
        return ["authority-provenance-must-be-object"]
    try:
        payload = canonical_json_object(value, label="authority-provenance")
    except AuthorityProvenanceError as exc:
        return [str(exc)]
    if set(payload) != AUTHORITY_PROVENANCE_FIELDS:
        missing = sorted(AUTHORITY_PROVENANCE_FIELDS - set(payload))
        unknown = sorted(set(payload) - AUTHORITY_PROVENANCE_FIELDS)
        if missing:
            errors.append("authority-provenance-missing-fields:" + ",".join(missing))
        if unknown:
            errors.append("authority-provenance-unknown-fields:" + ",".join(unknown))
        return errors
    if (
        type(payload.get("version")) is not int
        or payload["version"] != AUTHORITY_PROVENANCE_VERSION
    ):
        errors.append("authority-provenance-version-invalid")
    source_type = payload.get("source_type")
    actor_role = payload.get("actor_role")
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
        if not _nonempty(payload.get(field)):
            errors.append(
                f"authority-provenance-{field.replace('_', '-')}-invalid"
            )
    for field in ("source_sha256", "authority_sha256"):
        if not is_sha256(payload.get(field)):
            errors.append(
                f"authority-provenance-{field.replace('_', '-')}-invalid"
            )
    parent = payload.get("parent_receipt_sha256")
    if parent is not None and not is_sha256(parent):
        errors.append("authority-provenance-parent-receipt-sha256-invalid")
    scope = payload.get("authorized_scope")
    if scope not in AUTHORIZED_SCOPE_RANK:
        errors.append("authority-provenance-authorized-scope-invalid")
    elif actor_role in ACTOR_SCOPE_CAPS and AUTHORIZED_SCOPE_RANK[scope] > (
        AUTHORIZED_SCOPE_RANK[ACTOR_SCOPE_CAPS[actor_role]]
    ):
        errors.append("authority-provenance-exceeds-role-cap")
    verification = payload.get("verification")
    if not isinstance(verification, Mapping) or set(verification) != VERIFICATION_FIELDS:
        errors.append("authority-provenance-verification-fields-invalid")
    else:
        if not _nonempty(verification.get("method")):
            errors.append("authority-provenance-verification-method-invalid")
        if not is_sha256(verification.get("evidence_sha256")):
            errors.append("authority-provenance-verification-evidence-invalid")
    if is_sha256(payload.get("authority_sha256")):
        body = dict(payload)
        observed = body.pop("authority_sha256")
        if observed != canonical_authority_sha256(body):
            errors.append("authority-provenance-sha256-mismatch")
    if source_type == "operator-directive" and isinstance(verification, Mapping):
        if verification.get("method") not in OPERATOR_VERIFICATION_METHODS:
            errors.append("operator-authority-provenance-verification-invalid")
    if scope == "publication" and source_type != "operator-directive":
        errors.append("publication-scope-requires-operator-directive")
    return errors
