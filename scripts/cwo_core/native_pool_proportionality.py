"""Pure, model-free proportionality admission for Beads-ready pool cohorts.

The evaluator consumes P1-13A candidate evidence and validated work estimates.
It produces candidate evidence for P1-13B; it never claims Beads, allocates a
worker, renders a pool, or grants dispatch authority.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
import hashlib
import json
from threading import Lock
from typing import Any, Mapping, Sequence

from .native_authority import (
    AUTHORIZED_SCOPE_RANK,
    AuthorityProvenanceError,
    OperatorApprovalVerifier,
    VerifiedOperatorApproval,
    validate_operator_approval_audit,
)
from .native_pool_capacity import (
    NativePoolCapacityPolicyError,
    PoolCapacityLimits,
    load_pool_capacity,
)
from .native_pool_schedulability import (
    PoolSchedulabilityError,
    scheduling_budget_proof,
)
from .policy import load_policy
from .work_sizing import (
    canonical_work_estimate_sha256,
    validate_work_estimate,
)


ASSESSMENT_TYPE = "cwo-native-pool-proportionality-assessment"
ASSESSMENT_VERSION = 1
ASSESSMENT_SCHEMA = "schemas/native-pool-proportionality-assessment.schema.json"
READINESS_SNAPSHOT_TYPE = "cwo-beads-ready-set-snapshot:v2"
READY_COHORT_TYPE = "cwo-compatible-ready-set"
READY_SET_AUTHORITY = "candidate-evidence-only"
OVERRIDE_ACTION_TYPE = "cwo-native-pool-proportionality-override"
OVERRIDE_ACTION_VERSION = 1

POLICY_FIELDS = frozenset(
    {
        "version",
        "status",
        "minimum_child_runtime_p90_ms",
        "minimum_gross_savings_overhead_multiple_milli",
        "conservative_fixed_overhead_ms",
        "per_worker_admission_overhead_ms",
        "per_worker_evidence_overhead_ms",
        "read_only_worker_topology_overhead_ms",
        "mutable_worker_topology_overhead_ms",
        "per_mutable_worker_mutation_overhead_ms",
        "per_mutable_worker_integration_overhead_ms",
        "forbidden_task_classes",
        "override_change_type",
        "override_required_scope",
    }
)
COHORT_FIELDS = frozenset(
    {
        "cohort_type",
        "version",
        "snapshot_sha256",
        "issue_ids",
        "candidate_sha256s",
        "worker_count",
        "within_released_capacity",
        "authority",
        "dispatch_authorized",
        "cohort_sha256",
    }
)
COHORT_COMMITMENT_FIELDS = frozenset(
    {
        "issue_ids",
        "candidate_sha256s",
        "worker_count",
        "within_released_capacity",
    }
)
ASSESSMENT_FIELDS = frozenset(
    {
        "assessment_type",
        "version",
        "schema",
        "authority",
        "dispatch_authorized",
        "readiness_snapshot_sha256",
        "readiness_evidence_sha256",
        "work_estimate_set_sha256",
        "native_worker_policy_sha256",
        "proportionality_policy_sha256",
        "requested_workers",
        "candidate_capacity_ceiling",
        "released_capacity",
        "measured_fixed_overhead_ms",
        "effective_fixed_overhead_ms",
        "fixed_overhead_source",
        "cohort_evaluations",
        "decision",
        "accepted",
        "selected_cohort",
        "fallback_issue_id",
        "candidate_mode",
        "override_authorization",
        "assessment_sha256",
    }
)
COHORT_EVALUATION_FIELDS = frozenset(
    {
        "cohort_sha256",
        "issue_ids",
        "worker_count",
        "within_released_capacity",
        "ready_order",
        "child_economics",
        "economics",
        "reasons",
        "eligible_without_override",
        "overridden",
        "overridden_rule_ids",
        "accepted",
        "evaluation_sha256",
    }
)
CHILD_ECONOMICS_FIELDS = frozenset(
    {
        "id",
        "rank",
        "task_class",
        "work_estimate_sha256",
        "runtime_p90_ms",
        "mutable",
    }
)
ECONOMICS_FIELDS = frozenset(
    {
        "serial_runtime_p90_ms",
        "parallel_critical_path_p90_ms",
        "overhead",
        "total_orchestration_overhead_ms",
        "modeled_parallel_elapsed_p90_ms",
        "gross_parallel_savings_ms",
        "net_parallel_savings_ms",
        "minimum_required_gross_savings_ms_exclusive",
        "savings_multiple_milli",
    }
)
OVERHEAD_FIELDS = frozenset(
    {
        "fixed_ms",
        "admission_ms",
        "evidence_ms",
        "topology_ms",
        "mutation_ms",
        "integration_ms",
        "schedulability_ms",
    }
)
REASON_FIELDS = frozenset({"code", "detail", "waivable"})
OVERRIDE_RECORD_FIELDS = frozenset(
    {
        "action_sha256",
        "baseline_assessment_sha256",
        "cohort_sha256",
        "reason",
        "reason_sha256",
        "operator_approval_audit",
    }
)

_OVERRIDE_TOKEN = object()


class PoolProportionalityError(ValueError):
    """Raised when proportionality inputs are incomplete, stale, or invalid."""


def canonical_proportionality_sha256(value: Any) -> str:
    """Return the canonical JSON hash used by proportionality artifacts."""

    try:
        encoded = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise PoolProportionalityError(
            "proportionality-input-must-be-canonical-json"
        ) from error
    return hashlib.sha256(encoded).hexdigest()


def _is_sha256(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _is_int(value: Any, *, minimum: int = 0) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= minimum


def _mapping(value: Any, *, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise PoolProportionalityError(f"{label}-must-be-object")
    return value


def _sequence(value: Any, *, label: str) -> Sequence[Any]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        raise PoolProportionalityError(f"{label}-must-be-array")
    return value


@dataclass(frozen=True, slots=True)
class PoolProportionalityPolicy:
    """Validated provisional economic policy for pool candidate selection."""

    minimum_child_runtime_p90_ms: int
    minimum_gross_savings_overhead_multiple_milli: int
    conservative_fixed_overhead_ms: int
    per_worker_admission_overhead_ms: int
    per_worker_evidence_overhead_ms: int
    read_only_worker_topology_overhead_ms: int
    mutable_worker_topology_overhead_ms: int
    per_mutable_worker_mutation_overhead_ms: int
    per_mutable_worker_integration_overhead_ms: int
    forbidden_task_classes: tuple[str, ...]
    override_change_type: str
    override_required_scope: str
    policy_sha256: str


def load_pool_proportionality_policy(
    policy_document: Mapping[str, Any] | None = None,
) -> PoolProportionalityPolicy:
    """Load the exact provisional economic defaults from repository policy."""

    document = (
        policy_document
        if policy_document is not None
        else load_policy("native-worker-execution")
    )
    pool = _mapping(
        document.get("native_supervision_pool"),
        label="native-supervision-pool-policy",
    )
    raw = _mapping(pool.get("proportionality"), label="proportionality-policy")
    if set(raw) != POLICY_FIELDS:
        missing = sorted(POLICY_FIELDS - set(raw))
        unknown = sorted(set(raw) - POLICY_FIELDS)
        detail = []
        if missing:
            detail.append("missing=" + ",".join(missing))
        if unknown:
            detail.append("unknown=" + ",".join(unknown))
        raise PoolProportionalityError(
            "proportionality-policy-fields-invalid:" + ";".join(detail)
        )
    if raw.get("version") != 1 or raw.get("status") != "provisional":
        raise PoolProportionalityError("proportionality-policy-header-invalid")
    positive_fields = (
        "minimum_child_runtime_p90_ms",
        "minimum_gross_savings_overhead_multiple_milli",
        "per_worker_admission_overhead_ms",
        "per_worker_evidence_overhead_ms",
    )
    nonnegative_fields = (
        "conservative_fixed_overhead_ms",
        "read_only_worker_topology_overhead_ms",
        "mutable_worker_topology_overhead_ms",
        "per_mutable_worker_mutation_overhead_ms",
        "per_mutable_worker_integration_overhead_ms",
    )
    for field in positive_fields:
        if not _is_int(raw.get(field), minimum=1):
            raise PoolProportionalityError(
                f"proportionality-policy-{field.replace('_', '-')}-invalid"
            )
    for field in nonnegative_fields:
        if not _is_int(raw.get(field)):
            raise PoolProportionalityError(
                f"proportionality-policy-{field.replace('_', '-')}-invalid"
            )
    if raw["minimum_gross_savings_overhead_multiple_milli"] < 1000:
        raise PoolProportionalityError(
            "proportionality-policy-savings-multiple-must-be-at-least-one"
        )
    forbidden = raw.get("forbidden_task_classes")
    if (
        not isinstance(forbidden, list)
        or not forbidden
        or any(not isinstance(item, str) or not item.strip() for item in forbidden)
        or len(forbidden) != len(set(forbidden))
        or "literal-command" not in forbidden
    ):
        raise PoolProportionalityError(
            "proportionality-policy-forbidden-task-classes-invalid"
        )
    if raw.get("override_change_type") != "security-or-authority-change":
        raise PoolProportionalityError(
            "proportionality-policy-override-change-type-invalid"
        )
    required_scope = raw.get("override_required_scope")
    if required_scope not in AUTHORIZED_SCOPE_RANK or (
        AUTHORIZED_SCOPE_RANK[required_scope] < AUTHORIZED_SCOPE_RANK["complete-task"]
    ):
        raise PoolProportionalityError("proportionality-policy-override-scope-invalid")
    return PoolProportionalityPolicy(
        minimum_child_runtime_p90_ms=int(raw["minimum_child_runtime_p90_ms"]),
        minimum_gross_savings_overhead_multiple_milli=int(
            raw["minimum_gross_savings_overhead_multiple_milli"]
        ),
        conservative_fixed_overhead_ms=int(raw["conservative_fixed_overhead_ms"]),
        per_worker_admission_overhead_ms=int(raw["per_worker_admission_overhead_ms"]),
        per_worker_evidence_overhead_ms=int(raw["per_worker_evidence_overhead_ms"]),
        read_only_worker_topology_overhead_ms=int(
            raw["read_only_worker_topology_overhead_ms"]
        ),
        mutable_worker_topology_overhead_ms=int(
            raw["mutable_worker_topology_overhead_ms"]
        ),
        per_mutable_worker_mutation_overhead_ms=int(
            raw["per_mutable_worker_mutation_overhead_ms"]
        ),
        per_mutable_worker_integration_overhead_ms=int(
            raw["per_mutable_worker_integration_overhead_ms"]
        ),
        forbidden_task_classes=tuple(forbidden),
        override_change_type=str(raw["override_change_type"]),
        override_required_scope=str(raw["override_required_scope"]),
        policy_sha256=canonical_proportionality_sha256(raw),
    )


def _snapshot_and_projections(
    readiness_evidence: Mapping[str, Any],
    *,
    policy_document: Mapping[str, Any],
) -> tuple[Mapping[str, Any], dict[str, Mapping[str, Any]]]:
    if readiness_evidence.get("ready_set_authority") != READY_SET_AUTHORITY:
        raise PoolProportionalityError("readiness-authority-invalid")
    if readiness_evidence.get("dispatch_authorized") is not False:
        raise PoolProportionalityError("readiness-must-not-authorize-dispatch")
    snapshot = _mapping(
        readiness_evidence.get("beads_readiness_snapshot"),
        label="readiness-snapshot",
    )
    if (
        snapshot.get("snapshot_type") != READINESS_SNAPSHOT_TYPE
        or snapshot.get("version") != 2
    ):
        raise PoolProportionalityError("readiness-snapshot-header-invalid")
    snapshot_sha256 = snapshot.get("snapshot_sha256")
    if not _is_sha256(snapshot_sha256):
        raise PoolProportionalityError("readiness-snapshot-sha256-invalid")
    unsigned = dict(snapshot)
    unsigned.pop("snapshot_sha256", None)
    if canonical_proportionality_sha256(unsigned) != snapshot_sha256:
        raise PoolProportionalityError("readiness-snapshot-sha256-mismatch")
    if readiness_evidence.get("beads_readiness_snapshot_sha256") != snapshot_sha256:
        raise PoolProportionalityError("readiness-top-level-snapshot-sha256-mismatch")
    if snapshot.get("native_worker_policy_sha256") != canonical_proportionality_sha256(
        policy_document
    ):
        raise PoolProportionalityError("readiness-native-worker-policy-drift")

    projections: dict[str, Mapping[str, Any]] = {}
    for index, raw in enumerate(
        _sequence(snapshot.get("issue_projections"), label="issue-projections")
    ):
        projection = _mapping(raw, label=f"issue-projection[{index}]")
        issue_id = projection.get("id")
        if not isinstance(issue_id, str) or not issue_id or issue_id in projections:
            raise PoolProportionalityError("issue-projection-id-invalid")
        projection_sha256 = projection.get("issue_projection_sha256")
        unsigned_projection = dict(projection)
        unsigned_projection.pop("issue_projection_sha256", None)
        if (
            not _is_sha256(projection_sha256)
            or canonical_proportionality_sha256(unsigned_projection)
            != projection_sha256
        ):
            raise PoolProportionalityError(
                f"issue-projection-sha256-mismatch:{issue_id}"
            )
        projections[issue_id] = projection
    ranked_ids = _sequence(
        snapshot.get("ranked_ready_issue_ids"), label="ranked-ready-issue-ids"
    )
    if any(not isinstance(item, str) or not item for item in ranked_ids) or len(
        ranked_ids
    ) != len(set(ranked_ids)):
        raise PoolProportionalityError("ranked-ready-issue-ids-invalid")
    return snapshot, projections


def _validated_capacity_basis(
    snapshot: Mapping[str, Any],
    *,
    policy_document: Mapping[str, Any],
    limits: PoolCapacityLimits,
) -> tuple[int, dict[int, Mapping[str, Any]]]:
    basis = _mapping(
        snapshot.get("candidate_capacity_basis"),
        label="candidate-capacity-basis",
    )
    expected_scalars = {
        "released_max_active_workers": limits.released_max_active_workers,
        "hard_max_active_workers": limits.hard_max_active_workers,
        "phase1_candidate_ceiling": 3,
        "released_capacity_is_dispatch_gate": True,
    }
    for field, expected in expected_scalars.items():
        if basis.get(field) != expected:
            raise PoolProportionalityError(
                f"candidate-capacity-basis-{field.replace('_', '-')}-mismatch"
            )
    bounded = basis.get("bounded_candidate_capacity")
    if not _is_int(bounded, minimum=1) or bounded > limits.hard_max_active_workers:
        raise PoolProportionalityError("bounded-candidate-capacity-invalid")
    pool = _mapping(
        policy_document.get("native_supervision_pool"),
        label="native-supervision-pool-policy",
    )
    certification = _mapping(
        pool.get("callback_certification"), label="callback-certification-policy"
    )
    scheduler = _mapping(pool.get("scheduler"), label="scheduler-policy")
    proofs_by_size: dict[int, Mapping[str, Any]] = {}
    for index, raw in enumerate(
        _sequence(basis.get("schedulability_proofs"), label="schedulability-proofs")
    ):
        proof = _mapping(raw, label=f"schedulability-proof[{index}]")
        inputs = _mapping(proof.get("inputs"), label="schedulability-proof-inputs")
        worker_count = inputs.get("requested_workers")
        if not _is_int(worker_count, minimum=1) or worker_count in proofs_by_size:
            raise PoolProportionalityError("schedulability-proof-worker-count-invalid")
        try:
            expected = scheduling_budget_proof(
                requested_workers=worker_count,
                certified_callback_max_ms=certification.get(
                    "certified_callback_max_ms"
                ),
                certified_scheduler_overhead_ms=certification.get(
                    "certified_scheduler_overhead_ms"
                ),
                poll_interval_ms=scheduler.get("poll_interval_ms"),
            ).as_dict()
        except PoolSchedulabilityError as error:
            raise PoolProportionalityError("schedulability-policy-invalid") from error
        if dict(proof) != expected:
            raise PoolProportionalityError(
                f"schedulability-proof-mismatch:{worker_count}"
            )
        proofs_by_size[worker_count] = proof
    accepted_sizes = [
        size for size, proof in proofs_by_size.items() if proof.get("accepted") is True
    ]
    if not accepted_sizes or max(accepted_sizes) != bounded:
        raise PoolProportionalityError("bounded-candidate-capacity-proof-mismatch")
    return bounded, proofs_by_size


def _validated_cohorts(
    readiness_evidence: Mapping[str, Any],
    *,
    snapshot: Mapping[str, Any],
    projections: Mapping[str, Mapping[str, Any]],
    limits: PoolCapacityLimits,
    bounded_capacity: int,
) -> list[dict[str, Any]]:
    snapshot_sha256 = str(snapshot["snapshot_sha256"])
    cohorts: list[dict[str, Any]] = []
    seen_hashes: set[str] = set()
    seen_issue_sets: set[tuple[str, ...]] = set()
    for index, raw in enumerate(
        _sequence(
            readiness_evidence.get("compatible_ready_sets"),
            label="compatible-ready-sets",
        )
    ):
        cohort = dict(_mapping(raw, label=f"compatible-ready-set[{index}]"))
        if set(cohort) != COHORT_FIELDS:
            raise PoolProportionalityError(
                f"compatible-ready-set-fields-invalid:{index}"
            )
        if cohort.get("cohort_type") != READY_COHORT_TYPE or cohort.get("version") != 1:
            raise PoolProportionalityError(
                f"compatible-ready-set-header-invalid:{index}"
            )
        if cohort.get("snapshot_sha256") != snapshot_sha256:
            raise PoolProportionalityError(
                f"compatible-ready-set-snapshot-mismatch:{index}"
            )
        if (
            cohort.get("authority") != READY_SET_AUTHORITY
            or cohort.get("dispatch_authorized") is not False
        ):
            raise PoolProportionalityError(
                f"compatible-ready-set-authority-invalid:{index}"
            )
        issue_ids = list(
            _sequence(cohort.get("issue_ids"), label=f"cohort[{index}]-issue-ids")
        )
        candidate_hashes = list(
            _sequence(
                cohort.get("candidate_sha256s"),
                label=f"cohort[{index}]-candidate-sha256s",
            )
        )
        worker_count = cohort.get("worker_count")
        if (
            not _is_int(worker_count, minimum=1)
            or worker_count != len(issue_ids)
            or worker_count != len(candidate_hashes)
            or worker_count > bounded_capacity
            or any(
                not isinstance(issue_id, str) or not issue_id for issue_id in issue_ids
            )
            or len(issue_ids) != len(set(issue_ids))
            or any(not _is_sha256(value) for value in candidate_hashes)
        ):
            raise PoolProportionalityError(
                f"compatible-ready-set-members-invalid:{index}"
            )
        expected_order: list[tuple[int, str]] = []
        expected_candidate_hashes: list[str] = []
        for issue_id in issue_ids:
            projection = projections.get(issue_id)
            if projection is None:
                raise PoolProportionalityError(
                    f"compatible-ready-set-issue-not-in-snapshot:{issue_id}"
                )
            rank = projection.get("candidate_rank")
            artifacts = projection.get("candidate_artifacts")
            if (
                not _is_int(rank)
                or not isinstance(artifacts, Mapping)
                or not _is_sha256(artifacts.get("candidate_sha256"))
            ):
                raise PoolProportionalityError(
                    f"compatible-ready-set-candidate-projection-invalid:{issue_id}"
                )
            expected_order.append((rank, issue_id))
            expected_candidate_hashes.append(str(artifacts["candidate_sha256"]))
        if expected_order != sorted(expected_order):
            raise PoolProportionalityError(
                f"compatible-ready-set-order-invalid:{index}"
            )
        if candidate_hashes != expected_candidate_hashes:
            raise PoolProportionalityError(
                f"compatible-ready-set-candidate-hash-mismatch:{index}"
            )
        expected_within_release = worker_count <= limits.released_max_active_workers
        if cohort.get("within_released_capacity") is not expected_within_release:
            raise PoolProportionalityError(
                f"compatible-ready-set-release-classification-mismatch:{index}"
            )
        cohort_sha256 = cohort.get("cohort_sha256")
        unsigned = dict(cohort)
        unsigned.pop("cohort_sha256", None)
        if (
            not _is_sha256(cohort_sha256)
            or canonical_proportionality_sha256(unsigned) != cohort_sha256
            or cohort_sha256 in seen_hashes
        ):
            raise PoolProportionalityError(
                f"compatible-ready-set-sha256-invalid:{index}"
            )
        issue_key = tuple(issue_ids)
        if issue_key in seen_issue_sets:
            raise PoolProportionalityError(
                f"compatible-ready-set-duplicate-members:{index}"
            )
        seen_hashes.add(str(cohort_sha256))
        seen_issue_sets.add(issue_key)
        cohorts.append(cohort)
    expected_commitments = [
        {
            field: cohort[field]
            for field in (
                "issue_ids",
                "candidate_sha256s",
                "worker_count",
                "within_released_capacity",
            )
        }
        for cohort in cohorts
    ]
    raw_commitments = _sequence(
        snapshot.get("compatible_ready_set_commitments"),
        label="compatible-ready-set-commitments",
    )
    commitments: list[dict[str, Any]] = []
    for index, raw in enumerate(raw_commitments):
        commitment = dict(
            _mapping(raw, label=f"compatible-ready-set-commitment[{index}]")
        )
        if set(commitment) != COHORT_COMMITMENT_FIELDS:
            raise PoolProportionalityError(
                f"compatible-ready-set-commitment-fields-invalid:{index}"
            )
        commitments.append(commitment)
    if commitments != expected_commitments:
        raise PoolProportionalityError("compatible-ready-set-commitment-mismatch")
    return cohorts


def _validated_estimates(
    work_estimates: Mapping[str, Mapping[str, Any]],
    *,
    cohorts: Sequence[Mapping[str, Any]],
    projections: Mapping[str, Mapping[str, Any]],
    policy_document: Mapping[str, Any],
) -> tuple[dict[str, dict[str, Any]], str]:
    if not isinstance(work_estimates, Mapping):
        raise PoolProportionalityError("work-estimates-must-be-object")
    required_ids = {
        str(issue_id) for cohort in cohorts for issue_id in cohort["issue_ids"]
    }
    if set(work_estimates) != required_ids:
        missing = sorted(required_ids - set(work_estimates))
        extra = sorted(set(work_estimates) - required_ids)
        detail = []
        if missing:
            detail.append("missing=" + ",".join(missing))
        if extra:
            detail.append("extra=" + ",".join(extra))
        raise PoolProportionalityError("work-estimate-set-mismatch:" + ";".join(detail))
    validated: dict[str, dict[str, Any]] = {}
    bindings: list[dict[str, str]] = []
    for issue_id in sorted(required_ids):
        estimate = dict(
            _mapping(work_estimates[issue_id], label=f"work-estimate:{issue_id}")
        )
        errors = validate_work_estimate(estimate, policy=policy_document)
        if errors:
            raise PoolProportionalityError(
                f"work-estimate-invalid:{issue_id}:" + ";".join(errors)
            )
        if estimate.get("bead_id") != issue_id:
            raise PoolProportionalityError(f"work-estimate-bead-mismatch:{issue_id}")
        estimate_sha256 = canonical_work_estimate_sha256(estimate)
        projection = projections[issue_id]
        artifacts = _mapping(
            projection.get("candidate_artifacts"),
            label=f"candidate-artifacts:{issue_id}",
        )
        if artifacts.get("work_estimate_sha256") != estimate_sha256:
            raise PoolProportionalityError(
                f"work-estimate-snapshot-binding-mismatch:{issue_id}"
            )
        validated[issue_id] = estimate
        bindings.append({"id": issue_id, "work_estimate_sha256": estimate_sha256})
    return validated, canonical_proportionality_sha256(bindings)


def _reason(code: str, detail: str, *, waivable: bool) -> dict[str, Any]:
    return {"code": code, "detail": detail, "waivable": waivable}


def _modeled_economics_and_reasons(
    children: Sequence[Mapping[str, Any]],
    *,
    worker_count: int,
    policy: PoolProportionalityPolicy,
    candidate_capacity_ceiling: int,
    effective_fixed_overhead_ms: int,
    schedulability_proof: Mapping[str, Any] | None,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Derive the exact policy economics and findings for one cohort."""

    reasons: list[dict[str, Any]] = []
    for child in children:
        issue_id = str(child["id"])
        task_class = str(child["task_class"])
        runtime_p90_ms = int(child["runtime_p90_ms"])
        if task_class in policy.forbidden_task_classes:
            reasons.append(
                _reason(
                    "forbidden-task-class",
                    f"{issue_id} task class {task_class} is never pool-eligible",
                    waivable=False,
                )
            )
        if runtime_p90_ms < policy.minimum_child_runtime_p90_ms:
            reasons.append(
                _reason(
                    "child-runtime-below-provisional-minimum",
                    f"{issue_id} runtime p90 {runtime_p90_ms}ms is below "
                    f"{policy.minimum_child_runtime_p90_ms}ms",
                    waivable=True,
                )
            )
    if worker_count < 2:
        reasons.append(
            _reason(
                "pool-requires-multiple-workers",
                "pool proportionality requires at least two compatible workers",
                waivable=False,
            )
        )
    if worker_count > candidate_capacity_ceiling:
        reasons.append(
            _reason(
                "candidate-capacity-ceiling-exceeded",
                f"cohort N={worker_count} exceeds requested/evidenced ceiling "
                f"N={candidate_capacity_ceiling}",
                waivable=False,
            )
        )
    if schedulability_proof is None or schedulability_proof.get("accepted") is not True:
        reasons.append(
            _reason(
                "schedulability-proof-not-accepted",
                f"no accepted exact schedulability proof exists for N={worker_count}",
                waivable=False,
            )
        )

    runtimes = [int(child["runtime_p90_ms"]) for child in children]
    serial_runtime_ms = sum(runtimes)
    critical_path_ms = max(runtimes, default=0)
    mutable_workers = sum(child["mutable"] is True for child in children)
    topology_ms = sum(
        policy.mutable_worker_topology_overhead_ms
        if child["mutable"] is True
        else policy.read_only_worker_topology_overhead_ms
        for child in children
    )
    overhead = {
        "fixed_ms": effective_fixed_overhead_ms,
        "admission_ms": worker_count * policy.per_worker_admission_overhead_ms,
        "evidence_ms": worker_count * policy.per_worker_evidence_overhead_ms,
        "topology_ms": topology_ms,
        "mutation_ms": mutable_workers * policy.per_mutable_worker_mutation_overhead_ms,
        "integration_ms": mutable_workers
        * policy.per_mutable_worker_integration_overhead_ms,
        "schedulability_ms": (
            int(schedulability_proof["total_demand_ms"])
            if schedulability_proof is not None
            else 0
        ),
    }
    total_overhead_ms = sum(overhead.values())
    gross_savings_ms = serial_runtime_ms - critical_path_ms
    modeled_parallel_elapsed_ms = critical_path_ms + total_overhead_ms
    net_savings_ms = serial_runtime_ms - modeled_parallel_elapsed_ms
    multiple_milli = policy.minimum_gross_savings_overhead_multiple_milli
    minimum_required_exclusive = (total_overhead_ms * multiple_milli) // 1000
    if gross_savings_ms * 1000 <= total_overhead_ms * multiple_milli:
        reasons.append(
            _reason(
                "insufficient-modeled-parallel-savings",
                f"gross savings {gross_savings_ms}ms must exceed "
                f"{multiple_milli}/1000 x overhead {total_overhead_ms}ms",
                waivable=True,
            )
        )
    reasons.sort(key=lambda item: (item["code"], item["detail"], item["waivable"]))
    economics = {
        "serial_runtime_p90_ms": serial_runtime_ms,
        "parallel_critical_path_p90_ms": critical_path_ms,
        "overhead": overhead,
        "total_orchestration_overhead_ms": total_overhead_ms,
        "modeled_parallel_elapsed_p90_ms": modeled_parallel_elapsed_ms,
        "gross_parallel_savings_ms": gross_savings_ms,
        "net_parallel_savings_ms": net_savings_ms,
        "minimum_required_gross_savings_ms_exclusive": minimum_required_exclusive,
        "savings_multiple_milli": multiple_milli,
    }
    return economics, reasons


def _cohort_evaluation(
    cohort: Mapping[str, Any],
    *,
    estimates: Mapping[str, Mapping[str, Any]],
    projections: Mapping[str, Mapping[str, Any]],
    policy: PoolProportionalityPolicy,
    candidate_capacity_ceiling: int,
    effective_fixed_overhead_ms: int,
    schedulability_proofs: Mapping[int, Mapping[str, Any]],
) -> dict[str, Any]:
    issue_ids = [str(value) for value in cohort["issue_ids"]]
    worker_count = int(cohort["worker_count"])
    children: list[dict[str, Any]] = []
    for issue_id in issue_ids:
        estimate = estimates[issue_id]
        projection = projections[issue_id]
        runtime_p90_ms = int(estimate["estimates"]["runtime_seconds_p90"]) * 1000
        task_class = str(estimate.get("task_class") or "")
        mutable = bool(estimate.get("write_paths"))
        children.append(
            {
                "id": issue_id,
                "rank": int(projection["candidate_rank"]),
                "task_class": task_class,
                "work_estimate_sha256": canonical_work_estimate_sha256(estimate),
                "runtime_p90_ms": runtime_p90_ms,
                "mutable": mutable,
            }
        )
    proof = schedulability_proofs.get(worker_count)
    economics, reasons = _modeled_economics_and_reasons(
        children,
        worker_count=worker_count,
        policy=policy,
        candidate_capacity_ceiling=candidate_capacity_ceiling,
        effective_fixed_overhead_ms=effective_fixed_overhead_ms,
        schedulability_proof=proof,
    )
    body = {
        "cohort_sha256": cohort["cohort_sha256"],
        "issue_ids": issue_ids,
        "worker_count": worker_count,
        "within_released_capacity": cohort["within_released_capacity"],
        "ready_order": [
            {"rank": child["rank"], "id": child["id"]} for child in children
        ],
        "child_economics": children,
        "economics": economics,
        "reasons": reasons,
        "eligible_without_override": not reasons,
        "overridden": False,
        "overridden_rule_ids": [],
        "accepted": not reasons,
    }
    body["evaluation_sha256"] = canonical_proportionality_sha256(body)
    return body


def _selection_key(evaluation: Mapping[str, Any]) -> tuple[Any, ...]:
    economics = _mapping(evaluation.get("economics"), label="cohort-economics")
    ready_order = _sequence(evaluation.get("ready_order"), label="ready-order")
    return (
        -int(evaluation["worker_count"]),
        -int(economics["net_parallel_savings_ms"]),
        tuple((int(item["rank"]), str(item["id"])) for item in ready_order),
    )


def _seal_assessment(body: Mapping[str, Any]) -> dict[str, Any]:
    result = deepcopy(dict(body))
    result.pop("assessment_sha256", None)
    result["assessment_sha256"] = canonical_proportionality_sha256(result)
    return result


def _base_assessment(
    readiness_evidence: Mapping[str, Any],
    work_estimates: Mapping[str, Mapping[str, Any]],
    *,
    requested_workers: int,
    measured_fixed_overhead_ms: int | None,
    policy_document: Mapping[str, Any],
) -> dict[str, Any]:
    if not _is_int(requested_workers, minimum=1):
        raise PoolProportionalityError("requested-workers-must-be-positive-integer")
    try:
        limits = load_pool_capacity(policy_document)
    except NativePoolCapacityPolicyError as error:
        raise PoolProportionalityError(str(error)) from error
    if requested_workers > limits.hard_max_active_workers:
        raise PoolProportionalityError(
            "requested-workers-exceed-hard-candidate-capacity"
        )
    if measured_fixed_overhead_ms is not None and not _is_int(
        measured_fixed_overhead_ms
    ):
        raise PoolProportionalityError(
            "measured-fixed-overhead-ms-must-be-nonnegative-integer"
        )
    proportionality_policy = load_pool_proportionality_policy(policy_document)
    readiness = _mapping(readiness_evidence, label="readiness-evidence")
    snapshot, projections = _snapshot_and_projections(
        readiness, policy_document=policy_document
    )
    bounded_capacity, proofs = _validated_capacity_basis(
        snapshot, policy_document=policy_document, limits=limits
    )
    candidate_capacity_ceiling = min(requested_workers, bounded_capacity)
    cohorts = _validated_cohorts(
        readiness,
        snapshot=snapshot,
        projections=projections,
        limits=limits,
        bounded_capacity=bounded_capacity,
    )
    estimates, estimate_set_sha256 = _validated_estimates(
        work_estimates,
        cohorts=cohorts,
        projections=projections,
        policy_document=policy_document,
    )
    effective_fixed_overhead_ms = max(
        proportionality_policy.conservative_fixed_overhead_ms,
        measured_fixed_overhead_ms or 0,
    )
    fixed_source = (
        "measured"
        if measured_fixed_overhead_ms is not None
        and measured_fixed_overhead_ms
        > proportionality_policy.conservative_fixed_overhead_ms
        else "conservative-policy"
    )
    evaluations = [
        _cohort_evaluation(
            cohort,
            estimates=estimates,
            projections=projections,
            policy=proportionality_policy,
            candidate_capacity_ceiling=candidate_capacity_ceiling,
            effective_fixed_overhead_ms=effective_fixed_overhead_ms,
            schedulability_proofs=proofs,
        )
        for cohort in cohorts
    ]
    evaluations.sort(key=_selection_key)
    accepted = [item for item in evaluations if item["accepted"] is True]
    selected = deepcopy(accepted[0]) if accepted else None
    ranked_ids = list(snapshot["ranked_ready_issue_ids"])
    decision = (
        "pool" if selected is not None else ("single" if ranked_ids else "blocked")
    )
    selected_count = int(selected["worker_count"]) if selected is not None else 0
    candidate_mode = (
        "offline-unreleased-candidate"
        if selected_count > limits.released_max_active_workers
        else ("released-capacity" if selected_count else "none")
    )
    return _seal_assessment(
        {
            "assessment_type": ASSESSMENT_TYPE,
            "version": ASSESSMENT_VERSION,
            "schema": ASSESSMENT_SCHEMA,
            "authority": READY_SET_AUTHORITY,
            "dispatch_authorized": False,
            "readiness_snapshot_sha256": snapshot["snapshot_sha256"],
            "readiness_evidence_sha256": canonical_proportionality_sha256(readiness),
            "work_estimate_set_sha256": estimate_set_sha256,
            "native_worker_policy_sha256": canonical_proportionality_sha256(
                policy_document
            ),
            "proportionality_policy_sha256": proportionality_policy.policy_sha256,
            "requested_workers": requested_workers,
            "candidate_capacity_ceiling": candidate_capacity_ceiling,
            "released_capacity": limits.released_max_active_workers,
            "measured_fixed_overhead_ms": measured_fixed_overhead_ms,
            "effective_fixed_overhead_ms": effective_fixed_overhead_ms,
            "fixed_overhead_source": fixed_source,
            "cohort_evaluations": evaluations,
            "decision": decision,
            "accepted": selected is not None,
            "selected_cohort": selected,
            "fallback_issue_id": ranked_ids[0] if ranked_ids else None,
            "candidate_mode": candidate_mode,
            "override_authorization": None,
        }
    )


class VerifiedProportionalityOverride:
    """Opaque authorization bound to one rejected cohort and one reason."""

    __slots__ = (
        "_action_sha256",
        "_baseline_assessment_sha256",
        "_cohort_sha256",
        "_reason",
        "_approval_audit",
        "_consumption_lock",
        "_consumed",
    )

    def __init__(
        self,
        *,
        action_sha256: str,
        baseline_assessment_sha256: str,
        cohort_sha256: str,
        reason: str,
        approval: VerifiedOperatorApproval,
        token: object,
    ) -> None:
        if token is not _OVERRIDE_TOKEN:
            raise PoolProportionalityError(
                "proportionality-override-construction-forbidden"
            )
        self._action_sha256 = action_sha256
        self._baseline_assessment_sha256 = baseline_assessment_sha256
        self._cohort_sha256 = cohort_sha256
        self._reason = reason
        self._approval_audit = approval.audit_record()
        self._consumption_lock = Lock()
        self._consumed = False

    @property
    def action_sha256(self) -> str:
        return self._action_sha256

    @property
    def baseline_assessment_sha256(self) -> str:
        return self._baseline_assessment_sha256

    @property
    def cohort_sha256(self) -> str:
        return self._cohort_sha256

    @property
    def reason(self) -> str:
        return self._reason

    def approval_audit(self) -> dict[str, Any]:
        return deepcopy(self._approval_audit)

    def _consume(self) -> None:
        """Atomically consume this capability exactly once."""

        with self._consumption_lock:
            if self._consumed:
                raise PoolProportionalityError(
                    "proportionality-override-authorization-replayed"
                )
            self._consumed = True


def proportionality_override_artifacts(
    baseline_assessment: Mapping[str, Any],
    *,
    cohort_sha256: str,
    reason: str,
    policy_document: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Build the exact before/after artifacts an operator must approve."""

    errors = validate_pool_proportionality_assessment(
        baseline_assessment,
        policy_document=policy_document,
    )
    if errors:
        raise PoolProportionalityError(
            "baseline-proportionality-assessment-invalid:" + ";".join(errors)
        )
    if baseline_assessment.get("override_authorization") is not None:
        raise PoolProportionalityError(
            "proportionality-override-baseline-must-be-unoverridden"
        )
    if not isinstance(reason, str) or not reason.strip():
        raise PoolProportionalityError("proportionality-override-reason-required")
    matching = [
        item
        for item in baseline_assessment["cohort_evaluations"]
        if item.get("cohort_sha256") == cohort_sha256
    ]
    if len(matching) != 1:
        raise PoolProportionalityError(
            "proportionality-override-cohort-not-in-assessment"
        )
    evaluation = matching[0]
    reasons = list(evaluation["reasons"])
    if not reasons:
        raise PoolProportionalityError(
            "proportionality-override-cohort-already-eligible"
        )
    if any(item.get("waivable") is not True for item in reasons):
        raise PoolProportionalityError(
            "proportionality-override-cohort-has-nonwaivable-findings"
        )
    normalized_reason = reason.strip()
    reason_sha256 = canonical_proportionality_sha256(normalized_reason)
    action = {
        "action_type": OVERRIDE_ACTION_TYPE,
        "version": OVERRIDE_ACTION_VERSION,
        "baseline_assessment_sha256": baseline_assessment["assessment_sha256"],
        "readiness_snapshot_sha256": baseline_assessment["readiness_snapshot_sha256"],
        "readiness_evidence_sha256": baseline_assessment["readiness_evidence_sha256"],
        "work_estimate_set_sha256": baseline_assessment["work_estimate_set_sha256"],
        "native_worker_policy_sha256": baseline_assessment[
            "native_worker_policy_sha256"
        ],
        "cohort_sha256": cohort_sha256,
        "issue_ids": list(evaluation["issue_ids"]),
        "rejected_rule_ids": sorted({item["code"] for item in reasons}),
        "reason_sha256": reason_sha256,
    }
    action_sha256 = canonical_proportionality_sha256(action)
    authority_context = {
        "action_type": OVERRIDE_ACTION_TYPE,
        "action_sha256": action_sha256,
        "cohort_sha256": cohort_sha256,
        "baseline_assessment_sha256": baseline_assessment["assessment_sha256"],
    }
    return {
        "action": action,
        "action_sha256": action_sha256,
        "before_artifact": {
            "authority_context": {
                **authority_context,
                "decision": "reject",
                "reason_sha256": None,
            }
        },
        "after_artifact": {
            "authority_context": {
                **authority_context,
                "decision": "operator-override-accept",
                "reason_sha256": reason_sha256,
            }
        },
    }


def verify_proportionality_override(
    baseline_assessment: Mapping[str, Any],
    *,
    cohort_sha256: str,
    reason: str,
    approval_receipt: Mapping[str, Any],
    operator_approval_verifier: OperatorApprovalVerifier,
    policy_document: Mapping[str, Any] | None = None,
) -> VerifiedProportionalityOverride:
    """Consume a fresh exact operator approval and return opaque authority."""

    if not isinstance(operator_approval_verifier, OperatorApprovalVerifier):
        raise PoolProportionalityError("operator-approval-verifier-required")
    document = (
        policy_document
        if policy_document is not None
        else load_policy("native-worker-execution")
    )
    policy = load_pool_proportionality_policy(document)
    artifacts = proportionality_override_artifacts(
        baseline_assessment,
        cohort_sha256=cohort_sha256,
        reason=reason,
        policy_document=document,
    )
    try:
        approval = operator_approval_verifier.verify(
            approval_receipt,
            expected_change_type=policy.override_change_type,
            before_artifact=artifacts["before_artifact"],
            after_artifact=artifacts["after_artifact"],
        )
    except AuthorityProvenanceError as error:
        raise PoolProportionalityError(str(error)) from error
    if (
        AUTHORIZED_SCOPE_RANK.get(approval.authority.authorized_scope, -1)
        < AUTHORIZED_SCOPE_RANK[policy.override_required_scope]
    ):
        raise PoolProportionalityError(
            "proportionality-override-operator-scope-insufficient"
        )
    return VerifiedProportionalityOverride(
        action_sha256=artifacts["action_sha256"],
        baseline_assessment_sha256=str(baseline_assessment["assessment_sha256"]),
        cohort_sha256=cohort_sha256,
        reason=reason.strip(),
        approval=approval,
        token=_OVERRIDE_TOKEN,
    )


def _apply_override(
    baseline: Mapping[str, Any],
    authorization: VerifiedProportionalityOverride,
    *,
    policy_document: Mapping[str, Any],
) -> dict[str, Any]:
    if not isinstance(authorization, VerifiedProportionalityOverride):
        raise PoolProportionalityError("verified-proportionality-override-required")
    if authorization.baseline_assessment_sha256 != baseline.get("assessment_sha256"):
        raise PoolProportionalityError("proportionality-override-baseline-mismatch")
    artifacts = proportionality_override_artifacts(
        baseline,
        cohort_sha256=authorization.cohort_sha256,
        reason=authorization.reason,
        policy_document=policy_document,
    )
    if artifacts["action_sha256"] != authorization.action_sha256:
        raise PoolProportionalityError("proportionality-override-action-mismatch")
    authorization._consume()
    result = deepcopy(dict(baseline))
    result.pop("assessment_sha256", None)
    overridden_rules: list[str] = []
    for evaluation in result["cohort_evaluations"]:
        if evaluation["cohort_sha256"] != authorization.cohort_sha256:
            continue
        overridden_rules = sorted({item["code"] for item in evaluation["reasons"]})
        evaluation["overridden"] = True
        evaluation["overridden_rule_ids"] = overridden_rules
        evaluation["accepted"] = True
        unsigned = dict(evaluation)
        unsigned.pop("evaluation_sha256", None)
        evaluation["evaluation_sha256"] = canonical_proportionality_sha256(unsigned)
    result["cohort_evaluations"].sort(key=_selection_key)
    accepted = [
        item for item in result["cohort_evaluations"] if item["accepted"] is True
    ]
    selected = deepcopy(accepted[0]) if accepted else None
    if selected is None:
        raise PoolProportionalityError(
            "proportionality-override-did-not-authorize-cohort"
        )
    result["selected_cohort"] = selected
    result["decision"] = "pool"
    result["accepted"] = True
    result["candidate_mode"] = (
        "offline-unreleased-candidate"
        if selected["worker_count"] > result["released_capacity"]
        else "released-capacity"
    )
    result["override_authorization"] = {
        "action_sha256": authorization.action_sha256,
        "baseline_assessment_sha256": authorization.baseline_assessment_sha256,
        "cohort_sha256": authorization.cohort_sha256,
        "reason": authorization.reason,
        "reason_sha256": canonical_proportionality_sha256(authorization.reason),
        "operator_approval_audit": authorization.approval_audit(),
    }
    return _seal_assessment(result)


def pool_proportionality_check(
    readiness_evidence: Mapping[str, Any],
    work_estimates: Mapping[str, Mapping[str, Any]],
    *,
    requested_workers: int,
    measured_fixed_overhead_ms: int | None = None,
    policy_document: Mapping[str, Any] | None = None,
    override_authorization: VerifiedProportionalityOverride | None = None,
) -> dict[str, Any]:
    """Select the largest economical compatible cohort under an N ceiling.

    Selection order is largest accepted cohort, highest modeled net savings,
    then exact P1-13A ready rank and Bead ID.  The returned artifact is always
    candidate evidence only, including when a verified operator override is
    present or when an offline N=3 candidate is selected.
    """

    document = (
        policy_document
        if policy_document is not None
        else load_policy("native-worker-execution")
    )
    baseline = _base_assessment(
        readiness_evidence,
        work_estimates,
        requested_workers=requested_workers,
        measured_fixed_overhead_ms=measured_fixed_overhead_ms,
        policy_document=document,
    )
    result = (
        _apply_override(
            baseline,
            override_authorization,
            policy_document=document,
        )
        if override_authorization is not None
        else baseline
    )
    errors = validate_pool_proportionality_assessment(
        result,
        policy_document=document,
    )
    if errors:
        raise PoolProportionalityError(
            "proportionality-assessment-invalid:" + ";".join(errors)
        )
    return result


def validate_pool_proportionality_assessment(
    value: Any,
    *,
    policy_document: Mapping[str, Any] | None = None,
) -> list[str]:
    """Validate the strict, self-consistent assessment artifact shape."""

    errors: list[str] = []
    if not isinstance(value, Mapping):
        return ["assessment-must-be-object"]
    assessment = dict(value)
    missing = sorted(ASSESSMENT_FIELDS - set(assessment))
    unknown = sorted(str(key) for key in set(assessment) - ASSESSMENT_FIELDS)
    if missing:
        errors.append("assessment-missing-fields:" + ",".join(missing))
    if unknown:
        errors.append("assessment-unknown-fields:" + ",".join(unknown))
    if missing or unknown:
        return errors
    document = (
        policy_document
        if policy_document is not None
        else load_policy("native-worker-execution")
    )
    try:
        policy_sha256 = canonical_proportionality_sha256(document)
        limits = load_pool_capacity(document)
        proportionality_policy = load_pool_proportionality_policy(document)
    except (NativePoolCapacityPolicyError, PoolProportionalityError):
        errors.append("assessment-bound-policy-invalid")
        policy_sha256 = None
        limits = None
        proportionality_policy = None
    if (
        assessment.get("assessment_type") != ASSESSMENT_TYPE
        or assessment.get("version") != ASSESSMENT_VERSION
        or assessment.get("schema") != ASSESSMENT_SCHEMA
    ):
        errors.append("assessment-header-invalid")
    if (
        assessment.get("authority") != READY_SET_AUTHORITY
        or assessment.get("dispatch_authorized") is not False
    ):
        errors.append("assessment-authority-invalid")
    for field in (
        "readiness_snapshot_sha256",
        "readiness_evidence_sha256",
        "work_estimate_set_sha256",
        "native_worker_policy_sha256",
        "proportionality_policy_sha256",
        "assessment_sha256",
    ):
        if not _is_sha256(assessment.get(field)):
            errors.append(f"assessment-{field.replace('_', '-')}-invalid")
    for field in (
        "requested_workers",
        "candidate_capacity_ceiling",
        "released_capacity",
        "effective_fixed_overhead_ms",
    ):
        if not _is_int(assessment.get(field), minimum=1):
            errors.append(f"assessment-{field.replace('_', '-')}-invalid")
    requested_workers = assessment.get("requested_workers")
    candidate_capacity_ceiling = assessment.get("candidate_capacity_ceiling")
    released_capacity = assessment.get("released_capacity")
    if _is_int(requested_workers, minimum=1) and requested_workers > 3:
        errors.append("assessment-requested-workers-exceeds-hard-cap")
    if _is_int(candidate_capacity_ceiling, minimum=1):
        if candidate_capacity_ceiling > 3:
            errors.append("assessment-candidate-capacity-ceiling-exceeds-hard-cap")
        if (
            _is_int(requested_workers, minimum=1)
            and candidate_capacity_ceiling > requested_workers
        ):
            errors.append("assessment-candidate-capacity-ceiling-exceeds-request")
    if _is_int(released_capacity, minimum=1) and released_capacity > 3:
        errors.append("assessment-released-capacity-exceeds-hard-cap")
    if policy_sha256 is not None and (
        assessment.get("native_worker_policy_sha256") != policy_sha256
    ):
        errors.append("assessment-native-worker-policy-sha256-mismatch")
    if limits is not None and released_capacity != limits.released_max_active_workers:
        errors.append("assessment-released-capacity-policy-mismatch")
    if proportionality_policy is not None and (
        assessment.get("proportionality_policy_sha256")
        != proportionality_policy.policy_sha256
    ):
        errors.append("assessment-proportionality-policy-sha256-mismatch")
    measured = assessment.get("measured_fixed_overhead_ms")
    if measured is not None and not _is_int(measured):
        errors.append("assessment-measured-fixed-overhead-ms-invalid")
    fixed_overhead_source = assessment.get("fixed_overhead_source")
    if not isinstance(fixed_overhead_source, str) or fixed_overhead_source not in (
        "measured",
        "conservative-policy",
    ):
        errors.append("assessment-fixed-overhead-source-invalid")
    if proportionality_policy is not None and (measured is None or _is_int(measured)):
        expected_effective_fixed_overhead_ms = max(
            proportionality_policy.conservative_fixed_overhead_ms,
            measured or 0,
        )
        expected_fixed_overhead_source = (
            "measured"
            if measured is not None
            and measured > proportionality_policy.conservative_fixed_overhead_ms
            else "conservative-policy"
        )
        if (
            assessment.get("effective_fixed_overhead_ms")
            != expected_effective_fixed_overhead_ms
        ):
            errors.append("assessment-effective-fixed-overhead-ms-policy-mismatch")
        if fixed_overhead_source != expected_fixed_overhead_source:
            errors.append("assessment-fixed-overhead-source-policy-mismatch")
    evaluations = assessment.get("cohort_evaluations")
    normalized: list[Mapping[str, Any]] = []
    if not isinstance(evaluations, list):
        errors.append("assessment-cohort-evaluations-invalid")
    else:
        seen: set[str] = set()
        for index, raw in enumerate(evaluations):
            if not isinstance(raw, Mapping) or set(raw) != COHORT_EVALUATION_FIELDS:
                errors.append(f"assessment-cohort[{index}]-fields-invalid")
                continue
            item = dict(raw)
            normalized.append(item)
            cohort_sha256 = item.get("cohort_sha256")
            if not _is_sha256(cohort_sha256) or cohort_sha256 in seen:
                errors.append(f"assessment-cohort[{index}]-sha256-invalid")
            else:
                seen.add(str(cohort_sha256))
            issue_ids = item.get("issue_ids")
            worker_count = item.get("worker_count")
            within_released_capacity = item.get("within_released_capacity")
            children = item.get("child_economics")
            ready_order = item.get("ready_order")
            issue_ids_valid = isinstance(issue_ids, list) and all(
                isinstance(issue_id, str) and bool(issue_id) for issue_id in issue_ids
            )
            ready_order_valid = isinstance(ready_order, list) and all(
                isinstance(entry, Mapping)
                and set(entry) == {"rank", "id"}
                and _is_int(entry.get("rank"))
                and isinstance(entry.get("id"), str)
                and bool(entry.get("id"))
                for entry in (ready_order if isinstance(ready_order, list) else [])
            )
            members_valid = not (
                not issue_ids_valid
                or not _is_int(worker_count, minimum=1)
                or worker_count > 3
                or worker_count != len(issue_ids)
                or len(issue_ids) != len(set(issue_ids))
                or not isinstance(children, list)
                or len(children) != worker_count
                or not ready_order_valid
                or len(ready_order) != worker_count
            )
            validated_children: list[Mapping[str, Any]] = []
            if not members_valid:
                errors.append(f"assessment-cohort[{index}]-members-invalid")
            else:
                for child_index, child in enumerate(children):
                    child_valid = not (
                        not isinstance(child, Mapping)
                        or set(child) != CHILD_ECONOMICS_FIELDS
                        or child.get("id") != issue_ids[child_index]
                        or not _is_int(child.get("rank"))
                        or not isinstance(child.get("task_class"), str)
                        or not child.get("task_class")
                        or not _is_sha256(child.get("work_estimate_sha256"))
                        or not _is_int(child.get("runtime_p90_ms"))
                        or not isinstance(child.get("mutable"), bool)
                    )
                    if not child_valid:
                        errors.append(
                            f"assessment-cohort[{index}]-child[{child_index}]-invalid"
                        )
                    else:
                        validated_children.append(child)
                expected_ready = [
                    {"rank": child["rank"], "id": child["id"]}
                    for child in children
                    if isinstance(child, Mapping) and "rank" in child and "id" in child
                ]
                if ready_order != expected_ready or ready_order != sorted(
                    ready_order, key=lambda entry: (entry["rank"], entry["id"])
                ):
                    errors.append(f"assessment-cohort[{index}]-ready-order-invalid")
            if not isinstance(within_released_capacity, bool):
                errors.append(
                    f"assessment-cohort[{index}]-release-classification-invalid"
                )
            elif _is_int(worker_count, minimum=1) and _is_int(
                released_capacity,
                minimum=1,
            ):
                expected_within_release = worker_count <= released_capacity
                if within_released_capacity is not expected_within_release:
                    errors.append(
                        f"assessment-cohort[{index}]-release-classification-mismatch"
                    )
            economics = item.get("economics")
            if not isinstance(economics, Mapping) or set(economics) != ECONOMICS_FIELDS:
                errors.append(f"assessment-cohort[{index}]-economics-fields-invalid")
            else:
                overhead = economics.get("overhead")
                if (
                    not isinstance(overhead, Mapping)
                    or set(overhead) != OVERHEAD_FIELDS
                ):
                    errors.append(f"assessment-cohort[{index}]-overhead-fields-invalid")
                elif any(not _is_int(number) for number in overhead.values()):
                    errors.append(f"assessment-cohort[{index}]-overhead-values-invalid")
                else:
                    total = sum(int(number) for number in overhead.values())
                    if economics.get("total_orchestration_overhead_ms") != total:
                        errors.append(
                            f"assessment-cohort[{index}]-overhead-total-mismatch"
                        )
                    serial = economics.get("serial_runtime_p90_ms")
                    critical = economics.get("parallel_critical_path_p90_ms")
                    gross = economics.get("gross_parallel_savings_ms")
                    net = economics.get("net_parallel_savings_ms")
                    elapsed = economics.get("modeled_parallel_elapsed_p90_ms")
                    if (
                        not all(
                            _is_int(number)
                            for number in (serial, critical, gross, elapsed)
                        )
                        or not isinstance(net, int)
                        or isinstance(net, bool)
                    ):
                        errors.append(
                            f"assessment-cohort[{index}]-economics-values-invalid"
                        )
                    elif (
                        gross != serial - critical
                        or elapsed != critical + total
                        or net != serial - elapsed
                    ):
                        errors.append(f"assessment-cohort[{index}]-economics-mismatch")
            reasons = item.get("reasons")
            reasons_valid = isinstance(reasons, list) and not any(
                not isinstance(reason, Mapping)
                or set(reason) != REASON_FIELDS
                or not isinstance(reason.get("code"), str)
                or not reason.get("code")
                or not isinstance(reason.get("detail"), str)
                or not reason.get("detail")
                or not isinstance(reason.get("waivable"), bool)
                for reason in (reasons if isinstance(reasons, list) else [])
            )
            if not reasons_valid:
                errors.append(f"assessment-cohort[{index}]-reasons-invalid")
            validated_reasons = reasons if reasons_valid else []
            if (
                members_valid
                and len(validated_children) == worker_count
                and proportionality_policy is not None
                and _is_int(candidate_capacity_ceiling, minimum=1)
                and _is_int(assessment.get("effective_fixed_overhead_ms"), minimum=1)
            ):
                try:
                    pool_policy = _mapping(
                        document.get("native_supervision_pool"),
                        label="assessment-native-supervision-pool-policy",
                    )
                    certification = _mapping(
                        pool_policy.get("callback_certification"),
                        label="assessment-callback-certification-policy",
                    )
                    scheduler = _mapping(
                        pool_policy.get("scheduler"),
                        label="assessment-scheduler-policy",
                    )
                    proof = scheduling_budget_proof(
                        requested_workers=worker_count,
                        certified_callback_max_ms=certification.get(
                            "certified_callback_max_ms"
                        ),
                        certified_scheduler_overhead_ms=certification.get(
                            "certified_scheduler_overhead_ms"
                        ),
                        poll_interval_ms=scheduler.get("poll_interval_ms"),
                    ).as_dict()
                    expected_economics, expected_reasons = (
                        _modeled_economics_and_reasons(
                            validated_children,
                            worker_count=worker_count,
                            policy=proportionality_policy,
                            candidate_capacity_ceiling=candidate_capacity_ceiling,
                            effective_fixed_overhead_ms=assessment[
                                "effective_fixed_overhead_ms"
                            ],
                            schedulability_proof=proof,
                        )
                    )
                except (PoolProportionalityError, PoolSchedulabilityError):
                    errors.append(f"assessment-cohort[{index}]-policy-model-invalid")
                else:
                    if (
                        not isinstance(economics, Mapping)
                        or dict(economics) != expected_economics
                    ):
                        errors.append(
                            f"assessment-cohort[{index}]-economics-policy-mismatch"
                        )
                    if reasons_valid and validated_reasons != expected_reasons:
                        errors.append(
                            f"assessment-cohort[{index}]-reasons-policy-mismatch"
                        )
            eligible = item.get("eligible_without_override")
            overridden = item.get("overridden")
            accepted = item.get("accepted")
            overridden_rules = item.get("overridden_rule_ids")
            if not all(
                isinstance(flag, bool) for flag in (eligible, overridden, accepted)
            ):
                errors.append(f"assessment-cohort[{index}]-decision-flags-invalid")
            elif eligible is not (not validated_reasons):
                errors.append(f"assessment-cohort[{index}]-eligibility-mismatch")
            if not isinstance(overridden_rules, list) or any(
                not isinstance(rule, str) or not rule for rule in overridden_rules
            ):
                errors.append(f"assessment-cohort[{index}]-overridden-rules-invalid")
            elif overridden:
                expected_rules = sorted(
                    {reason["code"] for reason in validated_reasons}
                )
                if (
                    not reasons_valid
                    or any(
                        reason["waivable"] is not True for reason in validated_reasons
                    )
                    or overridden_rules != expected_rules
                    or accepted is not True
                ):
                    errors.append(f"assessment-cohort[{index}]-override-invalid")
            elif overridden_rules or accepted is not eligible:
                errors.append(f"assessment-cohort[{index}]-decision-mismatch")
            if (
                accepted is True
                and _is_int(worker_count, minimum=1)
                and worker_count < 2
            ):
                errors.append(f"assessment-cohort[{index}]-accepted-single-worker-pool")
            if (
                accepted is True
                and _is_int(worker_count, minimum=1)
                and _is_int(candidate_capacity_ceiling, minimum=1)
                and worker_count > candidate_capacity_ceiling
            ):
                errors.append(
                    f"assessment-cohort[{index}]-accepted-above-capacity-ceiling"
                )
            if (
                accepted is True
                and _is_int(worker_count, minimum=1)
                and _is_int(requested_workers, minimum=1)
                and worker_count > requested_workers
            ):
                errors.append(
                    f"assessment-cohort[{index}]-accepted-above-requested-workers"
                )
            observed_evaluation_sha256 = item.get("evaluation_sha256")
            unsigned_item = dict(item)
            unsigned_item.pop("evaluation_sha256", None)
            try:
                expected_evaluation_sha256 = canonical_proportionality_sha256(
                    unsigned_item
                )
            except PoolProportionalityError:
                expected_evaluation_sha256 = None
            if (
                not _is_sha256(observed_evaluation_sha256)
                or observed_evaluation_sha256 != expected_evaluation_sha256
            ):
                errors.append(f"assessment-cohort[{index}]-evaluation-sha256-mismatch")
    selection_shape_valid = True
    try:
        expected_order = sorted(normalized, key=_selection_key)
    except (KeyError, TypeError, ValueError, PoolProportionalityError):
        selection_shape_valid = False
        expected_order = []
        errors.append("assessment-cohort-selection-input-invalid")
    if selection_shape_valid and normalized != expected_order:
        errors.append("assessment-cohort-selection-order-invalid")
    selected = assessment.get("selected_cohort")
    accepted_items = (
        [item for item in normalized if item.get("accepted") is True]
        if selection_shape_valid
        else []
    )
    expected_selected = accepted_items[0] if accepted_items else None
    if selected != expected_selected:
        errors.append("assessment-selected-cohort-mismatch")
    accepted = assessment.get("accepted")
    if not isinstance(accepted, bool) or accepted is not bool(expected_selected):
        errors.append("assessment-accepted-mismatch")
    if expected_selected is not None and assessment.get("decision") != "pool":
        errors.append("assessment-decision-mismatch")
    elif expected_selected is None and (
        not isinstance(assessment.get("decision"), str)
        or assessment.get("decision") not in ("single", "blocked")
    ):
        errors.append("assessment-decision-invalid")
    if (
        assessment.get("decision") == "blocked"
        and assessment.get("fallback_issue_id") is not None
    ):
        errors.append("assessment-blocked-fallback-invalid")
    if assessment.get("fallback_issue_id") is not None and not isinstance(
        assessment.get("fallback_issue_id"), str
    ):
        errors.append("assessment-fallback-issue-id-invalid")
    expected_mode = "none"
    if expected_selected is not None:
        worker_count = expected_selected.get("worker_count")
        released_capacity = assessment.get("released_capacity")
        if _is_int(worker_count, minimum=1) and _is_int(released_capacity, minimum=1):
            expected_mode = (
                "offline-unreleased-candidate"
                if worker_count > released_capacity
                else "released-capacity"
            )
        else:
            errors.append("assessment-candidate-mode-input-invalid")
    if assessment.get("candidate_mode") != expected_mode:
        errors.append("assessment-candidate-mode-mismatch")
    override = assessment.get("override_authorization")
    overridden_items = [item for item in normalized if item.get("overridden") is True]
    if override is None:
        if overridden_items:
            errors.append("assessment-override-record-missing")
    elif not isinstance(override, Mapping) or set(override) != OVERRIDE_RECORD_FIELDS:
        errors.append("assessment-override-record-fields-invalid")
    else:
        for field in (
            "action_sha256",
            "baseline_assessment_sha256",
            "cohort_sha256",
            "reason_sha256",
        ):
            if not _is_sha256(override.get(field)):
                errors.append(f"assessment-override-{field.replace('_', '-')}-invalid")
        reason = override.get("reason")
        if (
            not isinstance(reason, str)
            or not reason.strip()
            or (
                override.get("reason_sha256")
                != canonical_proportionality_sha256(reason)
            )
        ):
            errors.append("assessment-override-reason-invalid")
        try:
            audit_errors = validate_operator_approval_audit(
                override.get("operator_approval_audit")
            )
        except (AttributeError, KeyError, TypeError, ValueError):
            audit_errors = ["operator-approval-audit-malformed"]
        errors.extend("assessment-override-audit:" + error for error in audit_errors)
        if len(overridden_items) != 1 or overridden_items[0].get(
            "cohort_sha256"
        ) != override.get("cohort_sha256"):
            errors.append("assessment-override-cohort-mismatch")
    observed_sha256 = assessment.get("assessment_sha256")
    unsigned_assessment = dict(assessment)
    unsigned_assessment.pop("assessment_sha256", None)
    try:
        expected_sha256 = canonical_proportionality_sha256(unsigned_assessment)
    except PoolProportionalityError:
        expected_sha256 = None
    if not _is_sha256(observed_sha256) or observed_sha256 != expected_sha256:
        errors.append("assessment-sha256-mismatch")
    return sorted(set(errors))
