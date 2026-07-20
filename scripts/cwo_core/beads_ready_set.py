"""Deterministic, read-only Beads ready-set candidate planning.

This module deliberately stops before claims, worktree creation, lease
allocation, or native-pool rendering.  Its output is evidence for the later
admission stage; it is never dispatch authority.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from itertools import combinations
import json
from pathlib import PurePosixPath
from typing import Any, Mapping, Sequence

from .native_pool_capacity import PoolCapacityLimits, load_pool_capacity
from .native_pool_schedulability import scheduling_budget_proof
from .policy import load_policy
from .work_sizing import (
    canonical_work_estimate_sha256,
    validate_work_estimate,
    validate_worker_commitment,
)


SNAPSHOT_TYPE = "cwo-beads-ready-set-snapshot:v1"
SNAPSHOT_VERSION = 1
READY_SET_AUTHORITY = "candidate-evidence-only"
MAX_PHASE1_CANDIDATE_WORKERS = 3

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
        "hard_budget",
        "aggregate_hard_budget",
    }
)
ADMISSION_METADATA_OPTIONAL_FIELDS = frozenset(
    {
        "precommit_receipt",
        "authority_change_approved",
        "authority_approval_sha256",
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
    hard_budget: tuple[tuple[str, int], ...]
    aggregate_hard_budget: tuple[tuple[str, int], ...]

    def hard_budget_dict(self) -> dict[str, int]:
        return dict(self.hard_budget)

    def aggregate_hard_budget_dict(self) -> dict[str, int]:
        return dict(self.aggregate_hard_budget)

    def evidence(self) -> dict[str, Any]:
        return {
            "id": self.issue_id,
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
            "hard_budget": self.hard_budget_dict(),
            "aggregate_hard_budget": self.aggregate_hard_budget_dict(),
        }


def _exclusion(code: str, detail: str) -> dict[str, str]:
    return {"code": code, "detail": detail}


def evaluate_ready_candidate(
    item: Mapping[str, Any],
    *,
    rank: int,
) -> tuple[ReadyCandidate | None, list[dict[str, str]]]:
    """Validate one exact-show-enriched ready issue for pool candidacy."""

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
    if admission.get("version") != 1:
        reasons.append(_exclusion("invalid-admission-metadata", "admission metadata version must equal 1"))
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

    if labels & AUTHORITY_CHANGE_LABELS:
        approval = admission.get("authority_approval_sha256")
        if admission.get("authority_change_approved") is not True or not _sha256_hex(approval):
            reasons.append(
                _exclusion(
                    "unapproved-authority-change",
                    "authority-changing work requires an exact approval receipt hash",
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
    tools, tool_errors = _string_list(admission.get("required_tools"), field="required_tools")
    reasons.extend(_exclusion("invalid-admission-metadata", error) for error in [*read_errors, *write_errors, *target_errors, *tool_errors])

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

    if reasons:
        return None, reasons
    assert work_plan is not None
    assert commitment is not None
    assert all(value is not None for value in scalar_fields.values())
    requested_model = _nonempty_string(work_plan.get("requested_model"))
    if requested_model is None:
        return None, [_exclusion("missing-model-evidence", "work_plan.requested_model is required")]
    return (
        ReadyCandidate(
            issue_id=issue_id,
            rank=rank,
            work_estimate_sha256=canonical_work_estimate_sha256(work_plan),
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


def _select_maximal_safe_set(
    candidates: Sequence[ReadyCandidate],
    *,
    capacity: int,
    pair_conflicts: Mapping[tuple[str, str], list[dict[str, Any]]],
) -> list[ReadyCandidate]:
    ordered = sorted(candidates, key=lambda candidate: (candidate.rank, candidate.issue_id))
    for size in range(min(capacity, len(ordered)), 0, -1):
        for subset in combinations(ordered, size):
            if _safe_subset(subset, pair_conflicts):
                return list(subset)
    return []


def _dependency_projection(raw: Mapping[str, Any]) -> list[dict[str, Any]]:
    value = raw.get("dependencies", [])
    if not isinstance(value, list):
        return []
    result: list[dict[str, Any]] = []
    for entry in value:
        if isinstance(entry, str):
            result.append({"id": entry, "type": "blocks", "status": "unknown", "updated_at": None})
            continue
        if not isinstance(entry, Mapping):
            continue
        dep_type = str(entry.get("dependency_type") or entry.get("type") or "blocks").strip().lower().replace("_", "-")
        if dep_type not in {"blocks", "until"}:
            continue
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
                    "status": str(entry.get("status") or "unknown"),
                    "updated_at": entry.get("updated_at"),
                }
            )
    return sorted(result, key=lambda entry: (entry["id"], entry["type"]))


def _issue_projection(
    item: Mapping[str, Any],
    candidate: ReadyCandidate | None,
) -> dict[str, Any]:
    raw = _raw_issue(item)
    projection: dict[str, Any] = {
        "id": _issue_id(item),
        "status": str(_field(item, "status", "open")),
        "updated_at": raw.get("updated_at"),
        "type": str(_field(item, "type", _field(item, "issue_type", "issue"))),
        "priority": int(_field(item, "priority", 50)),
        "labels": _issue_labels(item),
        "assignee": raw.get("assignee"),
        "parent": raw.get("parent"),
        "hard_dependencies": _dependency_projection(raw),
        "executable_leaf": bool(_field(item, "_cwo_executable_leaf", True)),
    }
    if candidate is not None:
        projection["candidate_artifacts"] = {
            "work_estimate_sha256": candidate.work_estimate_sha256,
            "worker_commitment_sha256": candidate.worker_commitment_sha256,
            "admission_metadata_sha256": candidate.admission_metadata_sha256,
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
) -> dict[str, Any]:
    """Build a sealed, deterministic candidate set without mutating Beads."""

    policy = policy_document or load_policy("native-worker-execution")
    limits = load_pool_capacity(policy)
    capacity, capacity_evidence = _capacity_evidence(
        requested_workers=requested_workers,
        limits=limits,
        policy_document=policy,
    )

    candidates: list[ReadyCandidate] = []
    candidate_by_id: dict[str, ReadyCandidate] = {}
    exclusions: dict[str, list[dict[str, str]]] = {}
    for rank, item in enumerate(ranked_ready):
        candidate, reasons = evaluate_ready_candidate(item, rank=rank)
        issue_id = _issue_id(item)
        if candidate is None:
            exclusions[issue_id] = reasons
        else:
            candidates.append(candidate)
            candidate_by_id[issue_id] = candidate

    projections = [
        _issue_projection(item, candidate_by_id.get(_issue_id(item)))
        for item in sorted(ranked_ready, key=_issue_id)
    ]
    snapshot_body = {
        "snapshot_type": SNAPSHOT_TYPE,
        "version": SNAPSHOT_VERSION,
        "epic_id": epic_id,
        "ready_issue_projections": projections,
    }
    snapshot = {
        **snapshot_body,
        "snapshot_sha256": canonical_json_sha256(snapshot_body),
    }

    pair_conflicts: dict[tuple[str, str], list[dict[str, Any]]] = {}
    all_conflicts: list[dict[str, Any]] = []
    for left, right in combinations(candidates, 2):
        conflicts = candidate_conflicts(left, right)
        key = tuple(sorted([left.issue_id, right.issue_id]))
        pair_conflicts[key] = conflicts
        all_conflicts.extend(conflicts)

    selected = _select_maximal_safe_set(
        candidates,
        capacity=capacity,
        pair_conflicts=pair_conflicts,
    )
    selected_ids = {candidate.issue_id for candidate in selected}
    selected_exceeds_released_capacity = (
        len(selected) > limits.released_max_active_workers
    )
    capacity_evidence["selected_workers"] = len(selected)
    capacity_evidence["selected_exceeds_released_capacity"] = (
        selected_exceeds_released_capacity
    )
    capacity_evidence["selected_released_for_dispatch"] = (
        bool(selected) and not selected_exceeds_released_capacity
    )
    selection_budget_conflicts: list[dict[str, Any]] = []
    for candidate in candidates:
        if candidate.issue_id in selected_ids:
            continue
        candidate_reasons: list[dict[str, str]] = []
        for selected_candidate in selected:
            key = tuple(sorted([candidate.issue_id, selected_candidate.issue_id]))
            for conflict in pair_conflicts.get(key, []):
                candidate_reasons.append(
                    _exclusion(
                        conflict["code"],
                        f"conflicts with selected issue {selected_candidate.issue_id}",
                    )
                )
        budget_conflicts = _subset_budget_conflicts([*selected, candidate])
        selection_budget_conflicts.extend(budget_conflicts)
        for conflict in budget_conflicts:
            candidate_reasons.append(
                _exclusion(
                    conflict["code"],
                    "candidate would exceed the shared aggregate hard budget",
                )
            )
        if not candidate_reasons:
            candidate_reasons.append(
                _exclusion(
                    "candidate-capacity-ceiling",
                    f"bounded candidate capacity is {capacity}",
                )
            )
        exclusions[candidate.issue_id] = candidate_reasons

    fanout_reasons: list[dict[str, Any]] = [
        {
            "code": "candidate-capacity-bound",
            "issue_ids": sorted(selected_ids),
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
                "issue_ids": sorted(selected_ids),
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
                "issue_ids": sorted(selected_ids),
                "provenance": "cwo-beads-ready-set-snapshot:v1",
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
            selection_budget_conflicts,
            key=lambda value: (value["code"], value["issue_ids"]),
        )
    )
    if len(selected) >= 2:
        decision = "pool"
        fanout_reasons.append(
            {
                "code": "bounded-pool-candidate",
                "issue_ids": sorted(selected_ids),
                "provenance": snapshot["snapshot_sha256"],
                "detail": "safe fixed-cohort candidate found; claims and preflight are still required",
            }
        )
    elif ranked_ready:
        decision = "single"
        fanout_reasons.append(
            {
                "code": "single-lane-fallback",
                "issue_ids": [selected[0].issue_id] if selected else [_issue_id(ranked_ready[0])],
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

    return {
        "ranked_ready_issues": [_issue_id(item) for item in ranked_ready],
        "recommended_ready_set": [candidate.evidence() for candidate in selected],
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
