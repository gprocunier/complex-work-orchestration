"""Deterministic, read-only Beads ready-set candidate planning.

This module deliberately stops before claims, worktree creation, lease
allocation, or native-pool rendering.  Its output is evidence for the later
admission stage; it is never dispatch authority.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from hashlib import sha256
from itertools import combinations
import json
from pathlib import PurePosixPath
from typing import Any, Mapping, Sequence

from .native_authority import (
    OPERATOR_REQUIRED_CHANGE_TYPES,
    AuthorityProvenanceError,
    OperatorApprovalVerifier,
    assess_operator_required_changes,
    canonical_authority_sha256,
    protected_change_identity,
    validate_authority_provenance,
    validate_operator_approval_audit,
)
from .native_capability import (
    capability_receipt_applies,
    validate_native_capability_receipt,
)
from .native_pool_capacity import PoolCapacityLimits, load_pool_capacity
from .native_pool_schedulability import scheduling_budget_proof
from .native_tool_isolation import (
    canonical_sha256 as canonical_tool_sha256,
    validate_tool_policy,
    validate_tool_surface_snapshot,
)
from .policy import load_policy
from .work_sizing import (
    canonical_work_estimate_sha256,
    validate_work_estimate,
    validate_worker_commitment,
)


SNAPSHOT_TYPE = "cwo-beads-ready-set-snapshot:v2"
SNAPSHOT_VERSION = 2
READY_SET_AUTHORITY = "candidate-evidence-only"
MAX_PHASE1_CANDIDATE_WORKERS = 3
ADMISSION_METADATA_VERSION = 2
LEASE_SCOPE_TYPE = "cwo-ready-set-lease-scope-intent"
LEASE_SCOPE_VERSION = 1
COHORT_TYPE = "cwo-compatible-ready-set"
COHORT_VERSION = 1
CONTROLLER_PROJECTION_FIELDS = frozenset(
    {
        "_cwo_canonical_ready",
        "_cwo_canonical_ready_rank",
        "_cwo_executable_leaf",
    }
)

RESTRICTED_LABELS = frozenset(
    {
        "contractor-only",
        "local-worker-only",
        "no-codex-exec",
        "no-sol-exec",
        "operator-only",
        "human-only",
    }
)
AUTHORITY_CHANGE_LABELS = frozenset(
    {"authority-change", "disclosure-change", "share-boundary-change"}
)
CONTAINER_LABELS = frozenset(
    {
        "grouping-container",
        "publication-parent",
        "publication-only",
        "release-parent",
        "release-gate",
    }
)
CONTAINER_TYPES = frozenset(
    {"epic", "molecule", "convoy", "merge-request", "gate"}
)
ISOLATION_CLASSES = frozenset({"read-only-shared", "mutable-isolated"})
POOL_BUDGET_FIELDS = (
    "tool_calls",
    "runtime_seconds",
    "compactions",
    "full_suite_runs",
    "mutations",
)
ADMISSION_METADATA_REQUIRED_FIELDS = frozenset(
    {
        "version",
        "work_plan",
        "worker_commitment",
        "declared_read_paths",
        "declared_write_paths",
        "integration_target_paths",
        "topology",
        "isolation_class",
        "architecture_authority",
        "execution_authority",
        "share_boundary",
        "required_tools",
        "tool_surface_id",
        "tool_policy",
        "tool_surface",
        "capability_receipt",
        "capability_assessed_at",
        "lease_scope",
        "hard_budget",
        "aggregate_hard_budget",
    }
)
ADMISSION_METADATA_OPTIONAL_FIELDS = frozenset(
    {
        "precommit_receipt",
        "authority_change_before",
        "authority_provenance",
        "operator_approval_audit",
    }
)
LEASE_SCOPE_FIELDS = frozenset(
    {
        "lease_scope_type",
        "version",
        "issue_id",
        "integration_root_identity_sha256",
        "workspace_scope_sha256",
        "target_paths",
        "lease_scope_sha256",
    }
)


class ReadySetError(ValueError):
    """Raised when a ready-set request cannot be evaluated safely."""


def canonical_json_sha256(value: Any) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return sha256(encoded).hexdigest()


def _json_mapping(value: Any) -> Mapping[str, Any] | None:
    if isinstance(value, Mapping):
        return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError:
            return None
        return parsed if isinstance(parsed, Mapping) else None
    return None


def _raw_issue(item: Mapping[str, Any]) -> Mapping[str, Any]:
    raw = item.get("raw")
    return raw if isinstance(raw, Mapping) else item


def _field(item: Mapping[str, Any], name: str, default: Any = None) -> Any:
    if name in item and item.get(name) is not None:
        return item[name]
    raw = _raw_issue(item)
    if name in raw and raw.get(name) is not None:
        return raw[name]
    metadata = _json_mapping(raw.get("metadata"))
    if metadata and name in metadata and metadata.get(name) is not None:
        return metadata[name]
    return default


def _issue_id(item: Mapping[str, Any]) -> str:
    return str(_field(item, "id", "") or "").strip()


def _issue_labels(item: Mapping[str, Any]) -> list[str]:
    value = _field(item, "labels", [])
    if isinstance(value, str):
        values = value.split(",")
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        values = value
    else:
        values = []
    return sorted({str(entry).strip() for entry in values if str(entry).strip()})


def _admission_metadata(item: Mapping[str, Any]) -> Mapping[str, Any] | None:
    raw = _raw_issue(item)
    metadata = _json_mapping(raw.get("metadata")) or {}
    for key in (
        "cwo_ready_set_admission",
        "ready_set_admission",
        "cwo_metadata_ready_set_admission",
    ):
        candidate = _json_mapping(metadata.get(key))
        if candidate is not None:
            return candidate
        candidate = _json_mapping(raw.get(key))
        if candidate is not None:
            return candidate
    return None


def _sha256_hex(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _nonempty_string(value: Any) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    return value.strip()


def _string_list(value: Any, *, field: str) -> tuple[list[str], list[str]]:
    if not isinstance(value, list):
        return [], [f"{field} must be an array"]
    result: list[str] = []
    errors: list[str] = []
    for index, entry in enumerate(value):
        text = _nonempty_string(entry)
        if text is None:
            errors.append(f"{field}[{index}] must be a non-empty string")
        elif text not in result:
            result.append(text)
    return sorted(result), errors


def _relative_paths(value: Any, *, field: str) -> tuple[list[str], list[str]]:
    values, errors = _string_list(value, field=field)
    normalized: list[str] = []
    for entry in values:
        path = PurePosixPath(entry)
        if path.is_absolute() or ".." in path.parts or entry in {".", ""}:
            errors.append(f"{field} contains unsafe relative path {entry!r}")
            continue
        text = path.as_posix()
        if text not in normalized:
            normalized.append(text)
    return sorted(normalized), errors


def _budget(value: Any, *, field: str) -> tuple[dict[str, int], list[str]]:
    if not isinstance(value, Mapping):
        return {}, [f"{field} must be an object"]
    errors: list[str] = []
    unknown = sorted(set(value) - set(POOL_BUDGET_FIELDS))
    missing = sorted(set(POOL_BUDGET_FIELDS) - set(value))
    if unknown:
        errors.append(f"{field} has unknown fields: {', '.join(unknown)}")
    if missing:
        errors.append(f"{field} is missing fields: {', '.join(missing)}")
    result: dict[str, int] = {}
    for name in POOL_BUDGET_FIELDS:
        candidate = value.get(name)
        if isinstance(candidate, bool) or not isinstance(candidate, int) or candidate < 0:
            errors.append(f"{field}.{name} must be a nonnegative integer")
            continue
        result[name] = candidate
    return result, errors


def _lease_scope(
    value: Any,
    *,
    issue_id: str,
    target_paths: Sequence[str],
) -> tuple[dict[str, Any] | None, list[str]]:
    """Validate a non-authoritative, hash-bound lease compatibility intent.

    P1-13A never creates or accepts an operative native supervision lease.
    This narrower object only lets the planner reject cohorts whose declared
    integration identity, workspace identity, or target scope cannot coexist.
    P1-13B must acquire and validate the real lease after claims.
    """

    if not isinstance(value, Mapping):
        return None, ["lease_scope must be an object"]
    errors: list[str] = []
    missing = sorted(LEASE_SCOPE_FIELDS - set(value))
    unknown = sorted(set(value) - LEASE_SCOPE_FIELDS)
    if missing:
        errors.append("lease_scope is missing fields: " + ", ".join(missing))
    if unknown:
        errors.append("lease_scope has unknown fields: " + ", ".join(unknown))
    if missing or unknown:
        return None, errors
    if value.get("lease_scope_type") != LEASE_SCOPE_TYPE:
        errors.append(f"lease_scope_type must equal {LEASE_SCOPE_TYPE}")
    if value.get("version") != LEASE_SCOPE_VERSION:
        errors.append(f"lease_scope.version must equal {LEASE_SCOPE_VERSION}")
    if value.get("issue_id") != issue_id:
        errors.append("lease_scope.issue_id must match the ready issue")
    for field in (
        "integration_root_identity_sha256",
        "workspace_scope_sha256",
        "lease_scope_sha256",
    ):
        if not _sha256_hex(value.get(field)):
            errors.append(f"lease_scope.{field} must be a canonical sha256")
    normalized_targets, target_errors = _relative_paths(
        value.get("target_paths"),
        field="lease_scope.target_paths",
    )
    errors.extend(target_errors)
    if normalized_targets != list(target_paths):
        errors.append(
            "lease_scope.target_paths must exactly match integration_target_paths"
        )
    body = {key: value[key] for key in value if key != "lease_scope_sha256"}
    try:
        expected_sha256 = canonical_json_sha256(body)
    except (TypeError, ValueError):
        expected_sha256 = None
        errors.append("lease_scope body must be canonical JSON")
    if value.get("lease_scope_sha256") != expected_sha256:
        errors.append("lease_scope_sha256 mismatch")
    return (dict(value) if not errors else None), errors


def _authorized_models(policy_document: Mapping[str, Any]) -> frozenset[str]:
    governance = policy_document.get("governance")
    native_worker = (
        governance.get("native_operative_worker")
        if isinstance(governance, Mapping)
        else None
    )
    models = (
        native_worker.get("authorized_models")
        if isinstance(native_worker, Mapping)
        else None
    )
    if not isinstance(models, list) or not all(
        isinstance(model, str) and model.strip() for model in models
    ):
        raise ReadySetError("native worker authorized model policy is missing")
    return frozenset(model.strip() for model in models)


def _required_topology(policy_document: Mapping[str, Any]) -> str:
    precommit = policy_document.get("precommit_supervision")
    topology = (
        precommit.get("control_topology")
        if isinstance(precommit, Mapping)
        else None
    )
    if topology != "single-host-process-v1":
        raise ReadySetError(
            "native precommit control topology must equal single-host-process-v1"
        )
    return topology


def _share_boundaries(
    share_policy_document: Mapping[str, Any],
) -> Mapping[str, Any]:
    boundaries = share_policy_document.get("boundaries")
    if not isinstance(boundaries, Mapping) or "no-outside-sharing" not in boundaries:
        raise ReadySetError("share-boundaries policy is missing required boundaries")
    return boundaries


def _parse_aware_datetime(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else None


def _capability_ttl_errors(
    receipt: Mapping[str, Any],
    policy_document: Mapping[str, Any],
) -> list[str]:
    pool = policy_document.get("native_supervision_pool")
    max_ttl = pool.get("max_capability_ttl_seconds") if isinstance(pool, Mapping) else None
    if isinstance(max_ttl, bool) or not isinstance(max_ttl, int) or max_ttl <= 0:
        raise ReadySetError("native pool capability TTL policy is missing")
    issued = _parse_aware_datetime(receipt.get("issued_at"))
    expires = _parse_aware_datetime(receipt.get("expires_at"))
    if issued is None or expires is None:
        return []
    ttl_seconds = (expires - issued).total_seconds()
    if ttl_seconds > max_ttl:
        return [
            f"capability receipt TTL {ttl_seconds:g}s exceeds policy maximum {max_ttl}s"
        ]
    return []


def authority_after_artifact(
    *,
    issue_id: str,
    change_labels: Sequence[str],
    architecture_authority: str,
    execution_authority: str,
    share_boundary: str,
    work_estimate_sha256: str,
    worker_commitment_sha256: str,
    read_paths: Sequence[str],
    write_paths: Sequence[str],
    integration_target_paths: Sequence[str],
    topology: str,
    isolation_class: str,
    lease_scope_sha256: str,
    requested_model: str,
    required_tools: Sequence[str],
    tool_surface_id: str,
    capability_receipt_sha256: str,
    hard_budget: Mapping[str, int],
    aggregate_hard_budget: Mapping[str, int],
) -> dict[str, Any]:
    """Return the exact issue/candidate scope protected by operator approval."""

    return {
        "artifact_type": "cwo-ready-set-authority-scope",
        "version": 1,
        "issue_id": issue_id,
        "change_labels": sorted(change_labels),
        "architecture_authority": architecture_authority,
        "execution_authority": execution_authority,
        "share_boundary": share_boundary,
        "work_estimate_sha256": work_estimate_sha256,
        "worker_commitment_sha256": worker_commitment_sha256,
        "declared_read_paths": list(read_paths),
        "declared_write_paths": list(write_paths),
        "integration_target_paths": list(integration_target_paths),
        "topology": topology,
        "isolation_class": isolation_class,
        "lease_scope_sha256": lease_scope_sha256,
        "requested_model": requested_model,
        "required_tools": list(required_tools),
        "tool_surface_id": tool_surface_id,
        "capability_receipt_sha256": capability_receipt_sha256,
        "hard_budget": dict(hard_budget),
        "aggregate_hard_budget": dict(aggregate_hard_budget),
    }


def _protected_domains(work_plan: Mapping[str, Any]) -> list[str]:
    value = work_plan.get("protected_surface_matches", [])
    if not isinstance(value, list):
        return []
    return sorted({str(entry).strip() for entry in value if str(entry).strip()})


def _commitment_sha256(commitment: Mapping[str, Any]) -> str:
    return canonical_json_sha256(commitment)


@dataclass(frozen=True, slots=True)
class ReadyCandidate:
    issue_id: str
    rank: int
    work_estimate_sha256: str
    worker_commitment_sha256: str
    admission_metadata_sha256: str
    read_paths: tuple[str, ...]
    write_paths: tuple[str, ...]
    integration_target_paths: tuple[str, ...]
    protected_domains: tuple[str, ...]
    topology: str
    isolation_class: str
    architecture_authority: str
    execution_authority: str
    share_boundary: str
    requested_model: str
    required_tools: tuple[str, ...]
    tool_surface_id: str
    tool_policy_sha256: str
    tool_surface_sha256: str
    capability_receipt_sha256: str
    capability_assessed_at: str
    lease_scope_sha256: str
    integration_root_identity_sha256: str
    workspace_scope_sha256: str
    authority_approval_audit_sha256: str | None
    hard_budget: tuple[tuple[str, int], ...]
    aggregate_hard_budget: tuple[tuple[str, int], ...]

    def hard_budget_dict(self) -> dict[str, int]:
        return dict(self.hard_budget)

    def aggregate_hard_budget_dict(self) -> dict[str, int]:
        return dict(self.aggregate_hard_budget)

    def evidence(self) -> dict[str, Any]:
        body = {
            "id": self.issue_id,
            "rank": self.rank,
            "work_estimate_sha256": self.work_estimate_sha256,
            "worker_commitment_sha256": self.worker_commitment_sha256,
            "admission_metadata_sha256": self.admission_metadata_sha256,
            "declared_read_paths": list(self.read_paths),
            "declared_write_paths": list(self.write_paths),
            "integration_target_paths": list(self.integration_target_paths),
            "protected_domains": list(self.protected_domains),
            "topology": self.topology,
            "isolation_class": self.isolation_class,
            "architecture_authority": self.architecture_authority,
            "execution_authority": self.execution_authority,
            "share_boundary": self.share_boundary,
            "requested_model": self.requested_model,
            "required_tools": list(self.required_tools),
            "tool_surface_id": self.tool_surface_id,
            "tool_policy_sha256": self.tool_policy_sha256,
            "tool_surface_sha256": self.tool_surface_sha256,
            "capability_receipt_sha256": self.capability_receipt_sha256,
            "capability_assessed_at": self.capability_assessed_at,
            "lease_scope_sha256": self.lease_scope_sha256,
            "integration_root_identity_sha256": (
                self.integration_root_identity_sha256
            ),
            "workspace_scope_sha256": self.workspace_scope_sha256,
            "authority_approval_audit_sha256": (
                self.authority_approval_audit_sha256
            ),
            "hard_budget": self.hard_budget_dict(),
            "aggregate_hard_budget": self.aggregate_hard_budget_dict(),
        }
        body["candidate_sha256"] = canonical_json_sha256(body)
        return body


def _exclusion(code: str, detail: str) -> dict[str, str]:
    return {"code": code, "detail": detail}


def evaluate_ready_candidate(
    item: Mapping[str, Any],
    *,
    rank: int,
    policy_document: Mapping[str, Any] | None = None,
    share_policy_document: Mapping[str, Any] | None = None,
    operator_approval_verifier: OperatorApprovalVerifier | None = None,
) -> tuple[ReadyCandidate | None, list[dict[str, str]]]:
    """Validate one exact-show-enriched ready issue for pool candidacy."""

    policy = policy_document or load_policy("native-worker-execution")
    share_policy = share_policy_document or load_policy("share-boundaries")
    authorized_models = _authorized_models(policy)
    required_topology = _required_topology(policy)
    share_boundaries = _share_boundaries(share_policy)
    issue_id = _issue_id(item)
    labels = set(_issue_labels(item))
    reasons: list[dict[str, str]] = []
    issue_type = str(_field(item, "type", _field(item, "issue_type", "issue"))).strip().lower()
    if issue_type in CONTAINER_TYPES or (
        labels & CONTAINER_LABELS and issue_type not in {"task", "bug", "chore"}
    ):
        reasons.append(_exclusion("grouping-container", "issue is not an executable leaf"))
    if _field(item, "_cwo_executable_leaf", True) is False:
        reasons.append(_exclusion("non-leaf", "issue has descendant work items"))
    for label in sorted(labels & RESTRICTED_LABELS):
        reasons.append(_exclusion("restricted-label", f"label {label} forbids normal pool pickup"))
    assignee = _field(item, "assignee")
    if isinstance(assignee, str) and assignee.strip():
        reasons.append(_exclusion("already-claimed", f"issue is assigned to {assignee.strip()}"))

    admission = _admission_metadata(item)
    if admission is None:
        reasons.append(
            _exclusion(
                "missing-admission-metadata",
                "cwo_ready_set_admission metadata is required for pool candidacy",
            )
        )
        return None, reasons
    if admission.get("version") != ADMISSION_METADATA_VERSION:
        reasons.append(
            _exclusion(
                "invalid-admission-metadata",
                f"admission metadata version must equal {ADMISSION_METADATA_VERSION}",
            )
        )
    missing_admission_fields = sorted(
        ADMISSION_METADATA_REQUIRED_FIELDS - set(admission)
    )
    unknown_admission_fields = sorted(
        set(admission)
        - ADMISSION_METADATA_REQUIRED_FIELDS
        - ADMISSION_METADATA_OPTIONAL_FIELDS
    )
    if missing_admission_fields:
        reasons.append(
            _exclusion(
                "invalid-admission-metadata",
                "admission metadata is missing fields: "
                + ", ".join(missing_admission_fields),
            )
        )
    if unknown_admission_fields:
        reasons.append(
            _exclusion(
                "invalid-admission-metadata",
                "admission metadata has unknown fields: "
                + ", ".join(unknown_admission_fields),
            )
        )

    work_plan = _json_mapping(admission.get("work_plan"))
    commitment = _json_mapping(admission.get("worker_commitment"))
    precommit_receipt = _json_mapping(admission.get("precommit_receipt"))
    if work_plan is None:
        reasons.append(_exclusion("missing-work-estimate", "validated work_plan is required"))
    if commitment is None:
        reasons.append(_exclusion("missing-worker-commitment", "validated worker_commitment is required"))
    if work_plan is not None:
        estimate_errors = validate_work_estimate(work_plan)
        if estimate_errors:
            reasons.append(
                _exclusion(
                    "invalid-work-estimate",
                    "; ".join(estimate_errors),
                )
            )
        if str(work_plan.get("bead_id") or "") != issue_id:
            reasons.append(_exclusion("work-estimate-bead-mismatch", "work_plan.bead_id must match the ready issue"))
    if work_plan is not None and commitment is not None:
        commitment_errors = validate_worker_commitment(
            commitment,
            work_plan,
            precommit_receipt=precommit_receipt,
        )
        if commitment_errors:
            reasons.append(
                _exclusion(
                    "invalid-worker-commitment",
                    "; ".join(commitment_errors),
                )
            )
        if commitment.get("decision") != "accept":
            reasons.append(_exclusion("worker-commitment-not-accepted", "worker commitment decision must be accept"))

    read_paths, read_errors = _relative_paths(
        admission.get("declared_read_paths"),
        field="declared_read_paths",
    )
    write_paths, write_errors = _relative_paths(
        admission.get("declared_write_paths"),
        field="declared_write_paths",
    )
    targets, target_errors = _relative_paths(
        admission.get("integration_target_paths"),
        field="integration_target_paths",
    )
    tools, tool_errors = _string_list(
        admission.get("required_tools"), field="required_tools"
    )
    reasons.extend(
        _exclusion("invalid-admission-metadata", error)
        for error in [
            *read_errors,
            *write_errors,
            *target_errors,
            *tool_errors,
        ]
    )

    hard_budget, hard_budget_errors = _budget(admission.get("hard_budget"), field="hard_budget")
    aggregate_budget, aggregate_budget_errors = _budget(
        admission.get("aggregate_hard_budget"),
        field="aggregate_hard_budget",
    )
    reasons.extend(
        _exclusion("invalid-budget-evidence", error)
        for error in [*hard_budget_errors, *aggregate_budget_errors]
    )

    scalar_fields = {
        "topology": _nonempty_string(admission.get("topology")),
        "isolation_class": _nonempty_string(admission.get("isolation_class")),
        "architecture_authority": _nonempty_string(admission.get("architecture_authority")),
        "execution_authority": _nonempty_string(admission.get("execution_authority")),
        "share_boundary": _nonempty_string(admission.get("share_boundary")),
        "tool_surface_id": _nonempty_string(admission.get("tool_surface_id")),
    }
    for name, value in scalar_fields.items():
        if value is None:
            reasons.append(_exclusion("missing-ownership-metadata", f"{name} must be a non-empty string"))
    if not labels & AUTHORITY_CHANGE_LABELS:
        if scalar_fields["architecture_authority"] not in {None, "architect"}:
            reasons.append(
                _exclusion(
                    "unapproved-architecture-authority",
                    "architecture_authority must remain architect unless an exact authority change is approved",
                )
            )
        if scalar_fields["execution_authority"] not in {None, "workerbee"}:
            reasons.append(
                _exclusion(
                    "unapproved-execution-authority",
                    "execution_authority must remain workerbee unless an exact authority change is approved",
                )
            )
    topology = scalar_fields["topology"]
    if topology is not None and topology != required_topology:
        reasons.append(
            _exclusion(
                "unsupported-topology",
                f"topology must equal repository policy value {required_topology}",
            )
        )
    isolation = scalar_fields["isolation_class"]
    if isolation is not None and isolation not in ISOLATION_CLASSES:
        reasons.append(
            _exclusion(
                "invalid-admission-metadata",
                "isolation_class must be read-only-shared or mutable-isolated",
            )
        )
    if isolation == "read-only-shared" and (write_paths or targets):
        reasons.append(
            _exclusion(
                "read-only-scope-mismatch",
                "read-only-shared work cannot declare write or integration target paths",
            )
        )
    if isolation == "mutable-isolated" and not write_paths:
        reasons.append(
            _exclusion(
                "mutable-scope-missing",
                "mutable-isolated work must declare at least one write path",
            )
        )
    work_estimate_sha256 = (
        canonical_work_estimate_sha256(work_plan)
        if work_plan is not None
        else ""
    )
    requested_model = (
        _nonempty_string(work_plan.get("requested_model"))
        if work_plan is not None
        else None
    )
    if requested_model is None:
        reasons.append(
            _exclusion(
                "missing-model-evidence",
                "work_plan.requested_model is required",
            )
        )
    elif requested_model not in authorized_models:
        reasons.append(
            _exclusion(
                "unauthorized-model",
                f"requested model {requested_model} is not authorized by native worker policy",
            )
        )

    share_boundary = scalar_fields["share_boundary"]
    boundary_record = (
        share_boundaries.get(share_boundary)
        if share_boundary is not None
        else None
    )
    if share_boundary is not None and not isinstance(boundary_record, Mapping):
        reasons.append(
            _exclusion(
                "unknown-share-boundary",
                f"share boundary {share_boundary} is not defined by repository policy",
            )
        )

    tool_policy = _json_mapping(admission.get("tool_policy"))
    tool_surface = _json_mapping(admission.get("tool_surface"))
    capability_receipt = _json_mapping(admission.get("capability_receipt"))
    capability_assessed_at = _nonempty_string(
        admission.get("capability_assessed_at")
    )
    if tool_policy is None:
        reasons.append(
            _exclusion("invalid-tool-policy", "tool_policy must be an object")
        )
    else:
        reasons.extend(
            _exclusion("invalid-tool-policy", error)
            for error in validate_tool_policy(tool_policy)
        )
        permitted = tool_policy.get("permitted_tools")
        if isinstance(permitted, list) and tools != permitted:
            reasons.append(
                _exclusion(
                    "tool-policy-scope-mismatch",
                    "required_tools must exactly match tool_policy.permitted_tools",
                )
            )
    if tool_surface is None:
        reasons.append(
            _exclusion("invalid-tool-surface", "tool_surface must be an object")
        )
    elif tool_policy is not None:
        reasons.extend(
            _exclusion("invalid-tool-surface", error)
            for error in validate_tool_surface_snapshot(tool_surface, tool_policy)
        )
    tool_surface_id = scalar_fields["tool_surface_id"]
    if (
        tool_surface is not None
        and tool_surface_id is not None
        and tool_surface.get("surface_sha256") != tool_surface_id
    ):
        reasons.append(
            _exclusion(
                "tool-surface-id-mismatch",
                "tool_surface_id must equal tool_surface.surface_sha256",
            )
        )
    if capability_receipt is None:
        reasons.append(
            _exclusion(
                "invalid-capability-receipt",
                "capability_receipt must be an operative provenance-bearing receipt",
            )
        )
    else:
        receipt_errors = validate_native_capability_receipt(dict(capability_receipt))
        reasons.extend(
            _exclusion("invalid-capability-receipt", error)
            for error in [
                *receipt_errors,
                *_capability_ttl_errors(capability_receipt, policy),
            ]
        )
        if (
            not receipt_errors
            and requested_model is not None
            and tool_surface_id is not None
            and capability_assessed_at is not None
            and not capability_receipt_applies(
                dict(capability_receipt),
                requested_model,
                tool_surface_id,
                capability_assessed_at,
            )
        ):
            reasons.append(
                _exclusion(
                    "capability-receipt-not-applicable",
                    "capability receipt must bind the requested model, tool surface, and assessed time",
                )
            )
    if capability_assessed_at is None or _parse_aware_datetime(
        capability_assessed_at
    ) is None:
        reasons.append(
            _exclusion(
                "invalid-capability-assessed-at",
                "capability_assessed_at must be an aware RFC3339 timestamp",
            )
        )

    lease_scope, lease_errors = _lease_scope(
        admission.get("lease_scope"),
        issue_id=issue_id,
        target_paths=targets,
    )
    reasons.extend(
        _exclusion("invalid-lease-scope-intent", error)
        for error in lease_errors
    )

    if work_plan is not None:
        planned_paths = work_plan.get("write_paths")
        if not isinstance(planned_paths, list) or sorted(planned_paths) != write_paths:
            reasons.append(
                _exclusion(
                    "work-estimate-scope-mismatch",
                    "declared_write_paths must exactly match work_plan.write_paths",
                )
            )
        allowance = work_plan.get("aggregate_allowance")
        if isinstance(allowance, Mapping) and hard_budget:
            if hard_budget.get("tool_calls", 0) > int(allowance.get("tool_calls_hard", -1)):
                reasons.append(_exclusion("hard-budget-exceeds-work-estimate", "tool-call budget exceeds work-plan allowance"))
            if hard_budget.get("runtime_seconds", 0) > int(allowance.get("runtime_seconds_hard", -1)):
                reasons.append(_exclusion("hard-budget-exceeds-work-estimate", "runtime budget exceeds work-plan allowance"))
            if hard_budget.get("compactions", 0) > int(
                allowance.get("max_compactions", -1)
            ):
                reasons.append(
                    _exclusion(
                        "hard-budget-exceeds-work-estimate",
                        "compaction budget exceeds work-plan allowance",
                    )
                )

    authority_approval_audit_sha256: str | None = None
    change_labels = sorted(labels & AUTHORITY_CHANGE_LABELS)
    disclosure_change = bool(
        labels & {"disclosure-change", "share-boundary-change"}
        or (
            isinstance(boundary_record, Mapping)
            and boundary_record.get("allows_external") is True
        )
    )
    authority_change_required = bool(change_labels or disclosure_change)
    if authority_change_required:
        authority_before = _json_mapping(admission.get("authority_change_before"))
        authority_provenance = _json_mapping(
            admission.get("authority_provenance")
        )
        approval_audit = _json_mapping(admission.get("operator_approval_audit"))
        if authority_before is None:
            reasons.append(
                _exclusion(
                    "unapproved-authority-change",
                    "authority_change_before must be a structured artifact",
                )
            )
        if authority_provenance is None:
            reasons.append(
                _exclusion(
                    "unapproved-authority-change",
                    "authority_provenance must be structured verified provenance",
                )
            )
        else:
            reasons.extend(
                _exclusion("invalid-authority-provenance", error)
                for error in validate_authority_provenance(authority_provenance)
            )
        if approval_audit is None:
            reasons.append(
                _exclusion(
                    "unapproved-authority-change",
                    "operator_approval_audit must be a structured verified audit",
                )
            )
        else:
            reasons.extend(
                _exclusion("invalid-operator-approval-audit", error)
                for error in validate_operator_approval_audit(approval_audit)
            )
        prerequisites = (
            authority_before is not None
            and authority_provenance is not None
            and approval_audit is not None
            and requested_model is not None
            and topology is not None
            and scalar_fields["architecture_authority"] is not None
            and scalar_fields["execution_authority"] is not None
            and share_boundary is not None
            and tool_surface_id is not None
            and lease_scope is not None
            and work_plan is not None
            and commitment is not None
            and capability_receipt is not None
            and not receipt_errors
            and _sha256_hex(capability_receipt.get("receipt_sha256"))
            and isolation is not None
            and bool(hard_budget)
            and bool(aggregate_budget)
        )
        if prerequisites:
            expected_after = authority_after_artifact(
                issue_id=issue_id,
                change_labels=change_labels,
                architecture_authority=str(
                    scalar_fields["architecture_authority"]
                ),
                execution_authority=str(scalar_fields["execution_authority"]),
                share_boundary=share_boundary,
                work_estimate_sha256=work_estimate_sha256,
                worker_commitment_sha256=_commitment_sha256(commitment),
                read_paths=read_paths,
                write_paths=write_paths,
                integration_target_paths=targets,
                topology=topology,
                isolation_class=str(isolation),
                lease_scope_sha256=str(lease_scope["lease_scope_sha256"]),
                requested_model=requested_model,
                required_tools=tools,
                tool_surface_id=tool_surface_id,
                capability_receipt_sha256=str(
                    capability_receipt["receipt_sha256"]
                ),
                hard_budget=hard_budget,
                aggregate_hard_budget=aggregate_budget,
            )
            try:
                authority_assessment = assess_operator_required_changes(
                    authority_before,
                    expected_after,
                    operator_required_for=OPERATOR_REQUIRED_CHANGE_TYPES,
                    profile="native-ready-set-authority-change",
                    identity=protected_change_identity(
                        artifact_type="cwo-ready-set-authority-change",
                        artifact_id=issue_id,
                        work_unit_id=str(work_plan["work_unit_id"]),
                        bead_id=issue_id,
                        packet_id=None,
                    ),
                )
            except AuthorityProvenanceError as exc:
                reasons.append(
                    _exclusion("operator-approval-assessment-failed", str(exc))
                )
                authority_assessment = None
            expected_scope = "publication" if disclosure_change else "complete-task"
            if approval_audit.get("change_type") != "security-or-authority-change":
                reasons.append(
                    _exclusion(
                        "operator-approval-change-type-mismatch",
                        "authority/disclosure changes require security-or-authority-change approval",
                    )
                )
            if approval_audit.get("before_sha256") != canonical_authority_sha256(
                authority_assessment.before_subject
                if authority_assessment is not None
                else authority_before
            ):
                reasons.append(
                    _exclusion(
                        "operator-approval-before-scope-mismatch",
                        "operator approval does not bind authority_change_before",
                    )
                )
            if approval_audit.get("after_sha256") != canonical_authority_sha256(
                authority_assessment.after_subject
                if authority_assessment is not None
                else expected_after
            ):
                reasons.append(
                    _exclusion(
                        "operator-approval-candidate-scope-mismatch",
                        "operator approval does not bind the exact issue candidate scope",
                    )
                )
            if approval_audit.get("authority_provenance") != authority_provenance:
                reasons.append(
                    _exclusion(
                        "operator-approval-authority-mismatch",
                        "audit and admission authority provenance must match exactly",
                    )
                )
            signed_receipt = approval_audit.get("signed_receipt")
            if not isinstance(signed_receipt, Mapping) or signed_receipt.get(
                "authorized_scope"
            ) != expected_scope:
                reasons.append(
                    _exclusion(
                        "operator-approval-scope-mismatch",
                        f"operator approval scope must equal {expected_scope}",
                    )
                )
            if authority_provenance.get("authorized_scope") != expected_scope:
                reasons.append(
                    _exclusion(
                        "authority-provenance-scope-mismatch",
                        f"authority provenance scope must equal {expected_scope}",
                    )
                )
            if operator_approval_verifier is None:
                reasons.append(
                    _exclusion(
                        "operator-approval-verifier-unavailable",
                        "serialized audit evidence is non-authoritative until a trusted verifier validates its signature, time, replay state, and exact scope",
                    )
                )
            elif not reasons and authority_assessment is not None:
                try:
                    operator_approval_verifier.validate_assessment_audits(
                        authority_assessment,
                        audits={"security-or-authority-change": approval_audit},
                        receipts={
                            "security-or-authority-change": approval_audit[
                                "signed_receipt"
                            ]
                        },
                    )
                except AuthorityProvenanceError as exc:
                    reasons.append(
                        _exclusion("operator-approval-verification-failed", str(exc))
                    )
                else:
                    authority_approval_audit_sha256 = canonical_json_sha256(
                        approval_audit
                    )
    elif any(
        field in admission
        for field in (
            "authority_change_before",
            "authority_provenance",
            "operator_approval_audit",
        )
    ):
        reasons.append(
            _exclusion(
                "unexpected-authority-evidence",
                "authority approval evidence is only valid for an explicit authority or disclosure change",
            )
        )

    if reasons:
        return None, reasons
    assert work_plan is not None
    assert commitment is not None
    assert all(value is not None for value in scalar_fields.values())
    assert requested_model is not None
    assert tool_policy is not None
    assert tool_surface is not None
    assert capability_receipt is not None
    assert capability_assessed_at is not None
    assert lease_scope is not None
    return (
        ReadyCandidate(
            issue_id=issue_id,
            rank=rank,
            work_estimate_sha256=work_estimate_sha256,
            worker_commitment_sha256=_commitment_sha256(commitment),
            admission_metadata_sha256=canonical_json_sha256(admission),
            read_paths=tuple(read_paths),
            write_paths=tuple(write_paths),
            integration_target_paths=tuple(targets),
            protected_domains=tuple(_protected_domains(work_plan)),
            topology=str(scalar_fields["topology"]),
            isolation_class=str(isolation),
            architecture_authority=str(scalar_fields["architecture_authority"]),
            execution_authority=str(scalar_fields["execution_authority"]),
            share_boundary=str(scalar_fields["share_boundary"]),
            requested_model=requested_model,
            required_tools=tuple(tools),
            tool_surface_id=str(scalar_fields["tool_surface_id"]),
            tool_policy_sha256=canonical_tool_sha256(tool_policy),
            tool_surface_sha256=str(tool_surface["surface_sha256"]),
            capability_receipt_sha256=str(
                capability_receipt["receipt_sha256"]
            ),
            capability_assessed_at=capability_assessed_at,
            lease_scope_sha256=str(lease_scope["lease_scope_sha256"]),
            integration_root_identity_sha256=str(
                lease_scope["integration_root_identity_sha256"]
            ),
            workspace_scope_sha256=str(lease_scope["workspace_scope_sha256"]),
            authority_approval_audit_sha256=authority_approval_audit_sha256,
            hard_budget=tuple(sorted(hard_budget.items())),
            aggregate_hard_budget=tuple(sorted(aggregate_budget.items())),
        ),
        [],
    )


def _path_overlap(left: str, right: str) -> bool:
    left_parts = PurePosixPath(left).parts
    right_parts = PurePosixPath(right).parts
    common = min(len(left_parts), len(right_parts))
    return left_parts[:common] == right_parts[:common]


def _scope_overlap(left: Sequence[str], right: Sequence[str]) -> list[str]:
    return sorted(
        {
            f"{left_path}<->{right_path}"
            for left_path in left
            for right_path in right
            if _path_overlap(left_path, right_path)
        }
    )


def candidate_conflicts(
    left: ReadyCandidate,
    right: ReadyCandidate,
) -> list[dict[str, Any]]:
    """Return deterministic concurrent-execution conflicts for two candidates."""

    issue_ids = sorted([left.issue_id, right.issue_id])
    reasons: list[dict[str, Any]] = []

    left_mutable = [*left.write_paths, *left.integration_target_paths]
    right_mutable = [*right.write_paths, *right.integration_target_paths]
    mutable_overlap = _scope_overlap(left_mutable, right_mutable)
    if mutable_overlap:
        reasons.append(
            {
                "code": "mutable-path-conflict",
                "issue_ids": issue_ids,
                "evidence": mutable_overlap,
            }
        )
    read_write_overlap = sorted(
        set(_scope_overlap(left.read_paths, right_mutable))
        | set(_scope_overlap(right.read_paths, left_mutable))
    )
    if read_write_overlap:
        reasons.append(
            {
                "code": "read-write-conflict",
                "issue_ids": issue_ids,
                "evidence": read_write_overlap,
            }
        )
    protected_overlap = sorted(set(left.protected_domains) & set(right.protected_domains))
    if protected_overlap and (left_mutable or right_mutable):
        reasons.append(
            {
                "code": "protected-domain-conflict",
                "issue_ids": issue_ids,
                "evidence": protected_overlap,
            }
        )
    if left.topology != right.topology:
        reasons.append(
            {
                "code": "topology-conflict",
                "issue_ids": issue_ids,
                "evidence": sorted([left.topology, right.topology]),
            }
        )
    if (
        left.isolation_class != right.isolation_class
        and (left.isolation_class != "read-only-shared" or right.isolation_class != "read-only-shared")
    ):
        reasons.append(
            {
                "code": "isolation-class-conflict",
                "issue_ids": issue_ids,
                "evidence": sorted([left.isolation_class, right.isolation_class]),
            }
        )
    for name in ("architecture_authority", "execution_authority", "share_boundary"):
        left_value = getattr(left, name)
        right_value = getattr(right, name)
        if left_value != right_value:
            reasons.append(
                {
                    "code": f"{name.replace('_', '-')}-conflict",
                    "issue_ids": issue_ids,
                    "evidence": sorted([left_value, right_value]),
                }
            )
    if left.requested_model != right.requested_model:
        reasons.append(
            {
                "code": "model-conflict",
                "issue_ids": issue_ids,
                "evidence": sorted([left.requested_model, right.requested_model]),
            }
        )
    if left.tool_surface_id != right.tool_surface_id or left.required_tools != right.required_tools:
        reasons.append(
            {
                "code": "tool-surface-conflict",
                "issue_ids": issue_ids,
                "evidence": sorted(
                    {
                        left.tool_surface_id,
                        right.tool_surface_id,
                        *left.required_tools,
                        *right.required_tools,
                    }
                ),
            }
        )
    if (
        left.integration_root_identity_sha256
        != right.integration_root_identity_sha256
    ):
        reasons.append(
            {
                "code": "lease-integration-root-conflict",
                "issue_ids": issue_ids,
                "evidence": sorted(
                    [
                        left.integration_root_identity_sha256,
                        right.integration_root_identity_sha256,
                    ]
                ),
            }
        )
    if left.workspace_scope_sha256 == right.workspace_scope_sha256:
        reasons.append(
            {
                "code": "lease-workspace-identity-conflict",
                "issue_ids": issue_ids,
                "evidence": [left.workspace_scope_sha256],
            }
        )
    if left.aggregate_hard_budget != right.aggregate_hard_budget:
        reasons.append(
            {
                "code": "aggregate-budget-contract-conflict",
                "issue_ids": issue_ids,
                "evidence": [
                    canonical_json_sha256(left.aggregate_hard_budget_dict()),
                    canonical_json_sha256(right.aggregate_hard_budget_dict()),
                ],
            }
        )
    return reasons


def _subset_budget_conflicts(candidates: Sequence[ReadyCandidate]) -> list[dict[str, Any]]:
    if not candidates:
        return []
    aggregate = candidates[0].aggregate_hard_budget_dict()
    totals = {
        field: sum(candidate.hard_budget_dict()[field] for candidate in candidates)
        for field in POOL_BUDGET_FIELDS
    }
    exceeded = [field for field in POOL_BUDGET_FIELDS if totals[field] > aggregate[field]]
    if not exceeded:
        return []
    return [
        {
            "code": "aggregate-budget-conflict",
            "issue_ids": sorted(candidate.issue_id for candidate in candidates),
            "evidence": [
                f"{field}:{totals[field]}>{aggregate[field]}" for field in exceeded
            ],
        }
    ]


def _safe_subset(
    candidates: Sequence[ReadyCandidate],
    pair_conflicts: Mapping[tuple[str, str], list[dict[str, Any]]],
) -> bool:
    for left, right in combinations(candidates, 2):
        key = tuple(sorted([left.issue_id, right.issue_id]))
        if pair_conflicts.get(key):
            return False
    return not _subset_budget_conflicts(candidates)


def _enumerate_safe_sets(
    candidates: Sequence[ReadyCandidate],
    *,
    capacity: int,
    pair_conflicts: Mapping[tuple[str, str], list[dict[str, Any]]],
) -> list[list[ReadyCandidate]]:
    """Return every compatible non-empty subset through the bounded capacity."""

    ordered = sorted(candidates, key=lambda candidate: (candidate.rank, candidate.issue_id))
    safe: list[list[ReadyCandidate]] = []
    for size in range(1, min(capacity, len(ordered)) + 1):
        for subset in combinations(ordered, size):
            if _safe_subset(subset, pair_conflicts):
                safe.append(list(subset))
    return sorted(
        safe,
        key=lambda subset: (
            -len(subset),
            tuple((candidate.rank, candidate.issue_id) for candidate in subset),
        ),
    )


def _cohort_evidence(
    candidates: Sequence[ReadyCandidate],
    *,
    snapshot_sha256: str,
    released_capacity: int,
) -> dict[str, Any]:
    membership = _cohort_membership(
        candidates,
        released_capacity=released_capacity,
    )
    body = {
        "cohort_type": COHORT_TYPE,
        "version": COHORT_VERSION,
        "snapshot_sha256": snapshot_sha256,
        **membership,
        "authority": READY_SET_AUTHORITY,
        "dispatch_authorized": False,
    }
    body["cohort_sha256"] = canonical_json_sha256(body)
    return body


def _cohort_membership(
    candidates: Sequence[ReadyCandidate],
    *,
    released_capacity: int,
) -> dict[str, Any]:
    """Return the non-circular cohort commitment sealed by the snapshot."""

    return {
        "issue_ids": [candidate.issue_id for candidate in candidates],
        "candidate_sha256s": [
            candidate.evidence()["candidate_sha256"] for candidate in candidates
        ],
        "worker_count": len(candidates),
        "within_released_capacity": len(candidates) <= released_capacity,
    }


def _dependency_projection(raw: Mapping[str, Any]) -> list[dict[str, Any]]:
    value = raw.get("dependencies", [])
    if not isinstance(value, list):
        return []
    result: list[dict[str, Any]] = []
    for entry in value:
        if isinstance(entry, str):
            result.append(
                {
                    "id": entry,
                    "type": "blocks",
                    "blocking": True,
                    "status": "unknown",
                    "updated_at": None,
                }
            )
            continue
        if not isinstance(entry, Mapping):
            continue
        dep_type = str(entry.get("dependency_type") or entry.get("type") or "blocks").strip().lower().replace("_", "-")
        dep_id = str(
            entry.get("depends_on_id")
            or entry.get("dependency_id")
            or entry.get("id")
            or ""
        ).strip()
        if dep_id:
            result.append(
                {
                    "id": dep_id,
                    "type": dep_type,
                    "blocking": dep_type in {"blocks", "until"},
                    "status": str(entry.get("status") or "unknown"),
                    "updated_at": entry.get("updated_at"),
                }
            )
    return sorted(result, key=lambda entry: (entry["id"], entry["type"]))


def _issue_projection(
    item: Mapping[str, Any],
    candidate: ReadyCandidate | None,
    *,
    canonical_ready_rank: int | None,
    candidate_rank: int | None,
) -> dict[str, Any]:
    raw = _raw_issue(item)
    exact_show_raw = {
        key: value
        for key, value in raw.items()
        if key not in CONTROLLER_PROJECTION_FIELDS
    }
    admission = _admission_metadata(item)
    ranking_dependencies = _field(item, "dependencies", [])
    if not isinstance(ranking_dependencies, list):
        ranking_dependencies = []
    projection: dict[str, Any] = {
        "id": _issue_id(item),
        "title": str(_field(item, "title", "") or ""),
        "description": str(_field(item, "description", "") or ""),
        "status": str(_field(item, "status", "open")),
        "updated_at": raw.get("updated_at"),
        "exact_show_raw_sha256": canonical_json_sha256(exact_show_raw),
        "type": str(_field(item, "type", _field(item, "issue_type", "issue"))),
        "priority": int(_field(item, "priority", 50)),
        "labels": _issue_labels(item),
        "assignee": _field(item, "assignee"),
        "owner": _field(item, "owner"),
        "parent": _field(item, "parent", _field(item, "parent_id")),
        "lane": _field(item, "lane"),
        "dependency_projection": _dependency_projection(raw),
        "ranking_dependencies": sorted(
            {str(value).strip() for value in ranking_dependencies if str(value).strip()}
        ),
        "canonical_ready": canonical_ready_rank is not None,
        "canonical_ready_rank": canonical_ready_rank,
        "candidate_rank": candidate_rank,
        "executable_leaf": bool(_field(item, "_cwo_executable_leaf", True)),
        "admission_metadata_sha256": (
            canonical_json_sha256(admission) if admission is not None else None
        ),
        "candidate_artifacts": None,
    }
    if candidate is not None:
        evidence = candidate.evidence()
        projection["candidate_artifacts"] = {
            "work_estimate_sha256": candidate.work_estimate_sha256,
            "worker_commitment_sha256": candidate.worker_commitment_sha256,
            "admission_metadata_sha256": candidate.admission_metadata_sha256,
            "capability_receipt_sha256": candidate.capability_receipt_sha256,
            "tool_policy_sha256": candidate.tool_policy_sha256,
            "tool_surface_sha256": candidate.tool_surface_sha256,
            "lease_scope_sha256": candidate.lease_scope_sha256,
            "candidate_sha256": evidence["candidate_sha256"],
        }
    projection["issue_projection_sha256"] = canonical_json_sha256(projection)
    return projection


def _capacity_evidence(
    *,
    requested_workers: int,
    limits: PoolCapacityLimits,
    policy_document: Mapping[str, Any],
) -> tuple[int, dict[str, Any]]:
    if isinstance(requested_workers, bool) or not isinstance(requested_workers, int) or requested_workers < 1:
        raise ReadySetError("requested_workers must be a positive integer")
    pool = policy_document.get("native_supervision_pool")
    if not isinstance(pool, Mapping):
        raise ReadySetError("native supervision pool policy is missing")
    certification = pool.get("callback_certification")
    scheduler = pool.get("scheduler")
    if not isinstance(certification, Mapping) or not isinstance(scheduler, Mapping):
        raise ReadySetError("native pool scheduling policy is missing")
    requested_bound = min(
        requested_workers,
        limits.hard_max_active_workers,
        MAX_PHASE1_CANDIDATE_WORKERS,
    )
    proofs: list[dict[str, Any]] = []
    schedulable = 0
    for candidate_size in range(1, requested_bound + 1):
        proof = scheduling_budget_proof(
            requested_workers=candidate_size,
            certified_callback_max_ms=certification.get("certified_callback_max_ms", {}),
            certified_scheduler_overhead_ms=certification.get("certified_scheduler_overhead_ms"),
            poll_interval_ms=scheduler.get("poll_interval_ms"),
        ).as_dict()
        proofs.append(proof)
        if proof["accepted"]:
            schedulable = candidate_size
    return schedulable, {
        "requested_workers": requested_workers,
        "released_max_active_workers": limits.released_max_active_workers,
        "hard_max_active_workers": limits.hard_max_active_workers,
        "phase1_candidate_ceiling": MAX_PHASE1_CANDIDATE_WORKERS,
        "bounded_candidate_capacity": schedulable,
        "released_capacity_is_dispatch_gate": True,
        "schedulability_proofs": proofs,
    }


def build_ready_set_evidence(
    ranked_ready: Sequence[Mapping[str, Any]],
    *,
    epic_id: str,
    requested_workers: int = MAX_PHASE1_CANDIDATE_WORKERS,
    policy_document: Mapping[str, Any] | None = None,
    scope_items: Sequence[Mapping[str, Any]] | None = None,
    share_policy_document: Mapping[str, Any] | None = None,
    operator_approval_verifier: OperatorApprovalVerifier | None = None,
) -> dict[str, Any]:
    """Build sealed candidate evidence without claims, leases, or dispatch."""

    policy = policy_document or load_policy("native-worker-execution")
    share_policy = share_policy_document or load_policy("share-boundaries")
    _authorized_models(policy)
    _required_topology(policy)
    _share_boundaries(share_policy)
    limits = load_pool_capacity(policy)
    capacity, capacity_evidence = _capacity_evidence(
        requested_workers=requested_workers,
        limits=limits,
        policy_document=policy,
    )

    ready_ids = [_issue_id(item) for item in ranked_ready]
    if any(not issue_id for issue_id in ready_ids):
        raise ReadySetError("ranked ready issues must have non-empty ids")
    if len(ready_ids) != len(set(ready_ids)):
        raise ReadySetError("ranked ready issue ids must be unique")
    scoped = list(scope_items) if scope_items is not None else list(ranked_ready)
    scoped_by_id: dict[str, Mapping[str, Any]] = {}
    for item in scoped:
        issue_id = _issue_id(item)
        if not issue_id:
            raise ReadySetError("scope issues must have non-empty ids")
        if issue_id in scoped_by_id:
            raise ReadySetError(f"duplicate scope issue id: {issue_id}")
        scoped_by_id[issue_id] = item
    missing_ready = sorted(set(ready_ids) - set(scoped_by_id))
    if missing_ready:
        raise ReadySetError(
            "ranked ready issue missing from scoped descendants: "
            + ", ".join(missing_ready)
        )
    ready_by_id = {_issue_id(item): item for item in ranked_ready}
    for issue_id in ready_ids:
        ranked_raw = canonical_json_sha256(_raw_issue(ready_by_id[issue_id]))
        scoped_raw = canonical_json_sha256(_raw_issue(scoped_by_id[issue_id]))
        if ranked_raw != scoped_raw:
            raise ReadySetError(
                f"ranked ready issue {issue_id} differs from scoped exact-show projection"
            )

    marked_ready_ranks: dict[str, int] = {}
    for issue_id in ready_ids:
        value = _field(scoped_by_id[issue_id], "_cwo_canonical_ready_rank")
        if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
            marked_ready_ranks[issue_id] = value
    if (
        len(marked_ready_ranks) == len(ready_ids)
        and len(set(marked_ready_ranks.values())) == len(ready_ids)
    ):
        canonical_ready_ids = sorted(
            ready_ids, key=lambda issue_id: (marked_ready_ranks[issue_id], issue_id)
        )
    else:
        canonical_ready_ids = list(ready_ids)
    canonical_rank_by_id = {
        issue_id: rank for rank, issue_id in enumerate(canonical_ready_ids)
    }
    candidate_rank_by_id = {
        issue_id: rank for rank, issue_id in enumerate(ready_ids)
    }

    candidates: list[ReadyCandidate] = []
    candidate_by_id: dict[str, ReadyCandidate] = {}
    exclusions: dict[str, list[dict[str, str]]] = {}
    for issue_id in ready_ids:
        candidate, reasons = evaluate_ready_candidate(
            scoped_by_id[issue_id],
            rank=candidate_rank_by_id[issue_id],
            policy_document=policy,
            share_policy_document=share_policy,
            operator_approval_verifier=operator_approval_verifier,
        )
        if candidate is None:
            exclusions[issue_id] = sorted(
                reasons, key=lambda reason: (reason["code"], reason["detail"])
            )
        else:
            candidates.append(candidate)
            candidate_by_id[issue_id] = candidate

    for issue_id in sorted(set(scoped_by_id) - set(ready_ids)):
        _, reasons = evaluate_ready_candidate(
            scoped_by_id[issue_id],
            rank=len(ready_ids),
            policy_document=policy,
            share_policy_document=share_policy,
            operator_approval_verifier=None,
        )
        reasons.append(
            _exclusion(
                "not-canonical-ready",
                "issue was not returned by canonical bd ready --unassigned",
            )
        )
        exclusions[issue_id] = sorted(
            reasons, key=lambda reason: (reason["code"], reason["detail"])
        )

    projections = [
        _issue_projection(
            scoped_by_id[issue_id],
            candidate_by_id.get(issue_id),
            canonical_ready_rank=canonical_rank_by_id.get(issue_id),
            candidate_rank=candidate_rank_by_id.get(issue_id),
        )
        for issue_id in sorted(scoped_by_id)
    ]
    pair_conflicts: dict[tuple[str, str], list[dict[str, Any]]] = {}
    all_conflicts: list[dict[str, Any]] = []
    for left, right in combinations(candidates, 2):
        conflicts = candidate_conflicts(left, right)
        key = tuple(sorted([left.issue_id, right.issue_id]))
        pair_conflicts[key] = conflicts
        all_conflicts.extend(conflicts)

    safe_sets = _enumerate_safe_sets(
        candidates,
        capacity=capacity,
        pair_conflicts=pair_conflicts,
    )
    selected = safe_sets[0] if safe_sets else []
    compatible_ready_set_commitments = [
        _cohort_membership(
            subset,
            released_capacity=limits.released_max_active_workers,
        )
        for subset in safe_sets
    ]
    snapshot_body = {
        "snapshot_type": SNAPSHOT_TYPE,
        "version": SNAPSHOT_VERSION,
        "epic_id": epic_id,
        "canonical_ready_issue_ids": canonical_ready_ids,
        "ranked_ready_issue_ids": ready_ids,
        "scope_issue_ids": sorted(scoped_by_id),
        "issue_projections": projections,
        "native_worker_policy_sha256": canonical_json_sha256(policy),
        "share_boundaries_policy_sha256": canonical_json_sha256(share_policy),
        "candidate_capacity_basis": dict(capacity_evidence),
        "compatible_ready_set_commitments": compatible_ready_set_commitments,
    }
    snapshot = {
        **snapshot_body,
        "snapshot_sha256": canonical_json_sha256(snapshot_body),
    }

    compatible_ready_sets = [
        _cohort_evidence(
            subset,
            snapshot_sha256=snapshot["snapshot_sha256"],
            released_capacity=limits.released_max_active_workers,
        )
        for subset in safe_sets
    ]
    selected_exceeds_released_capacity = (
        len(selected) > limits.released_max_active_workers
    )
    capacity_evidence["selected_workers"] = len(selected)
    capacity_evidence["selected_exceeds_released_capacity"] = (
        selected_exceeds_released_capacity
    )
    capacity_evidence["selected_within_released_capacity"] = (
        bool(selected) and not selected_exceeds_released_capacity
    )

    all_budget_conflicts: dict[str, dict[str, Any]] = {}
    for size in range(2, min(capacity, len(candidates)) + 1):
        for subset in combinations(candidates, size):
            for conflict in _subset_budget_conflicts(subset):
                all_budget_conflicts[canonical_json_sha256(conflict)] = conflict

    selected_issue_ids = [candidate.issue_id for candidate in selected]
    fanout_reasons: list[dict[str, Any]] = [
        {
            "code": "candidate-capacity-bound",
            "issue_ids": selected_issue_ids,
            "provenance": "policy/native-worker-execution.yaml",
            "detail": (
                f"requested={requested_workers}; released={limits.released_max_active_workers}; "
                f"schedulable_candidate_capacity={capacity}"
            ),
        }
    ]
    if selected_exceeds_released_capacity:
        fanout_reasons.append(
            {
                "code": "offline-unreleased-capacity-candidate",
                "issue_ids": selected_issue_ids,
                "provenance": "policy/native-worker-execution.yaml",
                "detail": (
                    f"selected={len(selected)} exceeds released dispatch capacity "
                    f"{limits.released_max_active_workers}; candidate remains offline evidence only"
                ),
            }
        )
    if requested_workers > MAX_PHASE1_CANDIDATE_WORKERS:
        fanout_reasons.append(
            {
                "code": "phase1-candidate-ceiling-applied",
                "issue_ids": selected_issue_ids,
                "provenance": SNAPSHOT_TYPE,
                "detail": (
                    f"requested={requested_workers} is capped at Phase 1 candidate ceiling "
                    f"{MAX_PHASE1_CANDIDATE_WORKERS}; N>=4 remains rejected"
                ),
            }
        )
    fanout_reasons.extend(
        {
            **conflict,
            "provenance": SNAPSHOT_TYPE,
            "detail": "conflict graph prevents concurrent candidate admission",
        }
        for conflict in sorted(
            all_conflicts,
            key=lambda value: (value["code"], value["issue_ids"]),
        )
    )
    fanout_reasons.extend(
        {
            **conflict,
            "provenance": SNAPSHOT_TYPE,
            "detail": "candidate subset exceeds the shared aggregate hard budget",
        }
        for conflict in sorted(
            all_budget_conflicts.values(),
            key=lambda value: (value["code"], value["issue_ids"]),
        )
    )
    if len(selected) >= 2:
        decision = "pool"
        fanout_reasons.append(
            {
                "code": "bounded-pool-candidate",
                "issue_ids": selected_issue_ids,
                "provenance": snapshot["snapshot_sha256"],
                "detail": "safe fixed-cohort candidate found; claims and preflight are still required",
            }
        )
    elif ranked_ready:
        decision = "single"
        fanout_reasons.append(
            {
                "code": "single-lane-fallback",
                "issue_ids": (
                    [selected[0].issue_id] if selected else [ready_ids[0]]
                ),
                "provenance": snapshot["snapshot_sha256"],
                "detail": "no multi-worker candidate is authorized by this evidence",
            }
        )
    else:
        decision = "blocked"
        fanout_reasons.append(
            {
                "code": "no-ready-executable-leaves",
                "issue_ids": [],
                "provenance": snapshot["snapshot_sha256"],
                "detail": "canonical Beads readiness returned no executable leaves",
            }
        )
    fanout_reasons.append(
        {
            "code": "p1-13b-final-revalidation-required",
            "issue_ids": selected_issue_ids,
            "provenance": snapshot["snapshot_sha256"],
            "detail": (
                "P1-13B must revalidate canonical readiness, issue drift, claims, "
                "capability freshness, tool surface, proportionality, and operative "
                "leases before any dispatch admission"
            ),
        }
    )

    return {
        "ranked_ready_issues": ready_ids,
        "recommended_ready_set": [candidate.evidence() for candidate in selected],
        "compatible_ready_sets": compatible_ready_sets,
        "excluded_ready_issues": [
            {"id": issue_id, "reasons": exclusions[issue_id]}
            for issue_id in sorted(exclusions)
        ],
        "beads_readiness_snapshot": snapshot,
        "beads_readiness_snapshot_sha256": snapshot["snapshot_sha256"],
        "fanout_decision": decision,
        "fanout_reasons": fanout_reasons,
        "candidate_capacity_evidence": capacity_evidence,
        "ready_set_authority": READY_SET_AUTHORITY,
        "dispatch_authorized": False,
    }


def markdown_fallback_evidence(
    ranked_ready: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    """Return explicitly non-pool evidence for reduced-durability input."""

    issue_ids = [_issue_id(item) for item in ranked_ready]
    decision = "single" if issue_ids else "blocked"
    return {
        "ranked_ready_issues": issue_ids,
        "recommended_ready_set": [],
        "compatible_ready_sets": [],
        "excluded_ready_issues": [
            {
                "id": issue_id,
                "reasons": [
                    _exclusion(
                        "markdown-fallback-non-authoritative",
                        "Markdown fallback cannot produce Beads-backed pool candidates",
                    )
                ],
            }
            for issue_id in issue_ids
        ],
        "beads_readiness_snapshot": None,
        "beads_readiness_snapshot_sha256": None,
        "fanout_decision": decision,
        "fanout_reasons": [
            {
                "code": "markdown-fallback-single-only",
                "issue_ids": issue_ids[:1],
                "provenance": "markdown-workgraph",
                "detail": "reduced-durability input cannot authorize or evidence a pool",
            }
        ],
        "candidate_capacity_evidence": None,
        "ready_set_authority": READY_SET_AUTHORITY,
        "dispatch_authorized": False,
    }
