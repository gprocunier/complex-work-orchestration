"""Readiness-first transaction coordinator for admitted native-worker pools.

The coordinator deliberately owns only composition.  It does not replace the
admission, preflight, lease, or supervision implementations.  Productive work
still crosses :func:`run_admitted_native_pool`; this module makes every
deterministic check happen before a worker receives a productive turn.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
import datetime as dt
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from typing import Any, Callable, Mapping, Sequence

from .native_pool_admitted import run_admitted_native_pool
from .native_pool_contracts import canonical_sha256
from .util import atomic_write_text


PLAN_TYPE = "cwo-native-pool-transaction-plan"
PLAN_VERSION = 1
MAINTENANCE_PLAN_VERSION = 8
MAINTENANCE_PLAN_SCHEMA = "schemas/native-pool-transaction-plan-v8.schema.json"
PLAN_SCHEMA = "schemas/native-pool-transaction-plan.schema.json"
RECOVERY_PLAN_VERSION = 2
RECOVERY_PLAN_SCHEMA = "schemas/native-pool-transaction-plan-v2.schema.json"
CAMPAIGN_RECOVERY_PLAN_VERSION = 3
CAMPAIGN_RECOVERY_PLAN_SCHEMA = "schemas/native-pool-transaction-plan-v3.schema.json"
FINAL_CAMPAIGN_RECOVERY_PLAN_VERSION = 4
FINAL_CAMPAIGN_RECOVERY_PLAN_SCHEMA = "schemas/native-pool-transaction-plan-v4.schema.json"
SEVENTH_CAMPAIGN_RECOVERY_PLAN_VERSION = 5
SEVENTH_CAMPAIGN_RECOVERY_PLAN_SCHEMA = "schemas/native-pool-transaction-plan-v5.schema.json"
SEVENTH_CAMPAIGN_RECOVERY_BEAD = "complex-work-orchestration-bpm4.14"
EIGHTH_CAMPAIGN_RECOVERY_PLAN_VERSION = 6
EIGHTH_CAMPAIGN_RECOVERY_PLAN_SCHEMA = "schemas/native-pool-transaction-plan-v6.schema.json"
EIGHTH_CAMPAIGN_RECOVERY_BEAD = "complex-work-orchestration-bpm4.15"
NINTH_CAMPAIGN_RECOVERY_PLAN_VERSION = 7
NINTH_CAMPAIGN_RECOVERY_PLAN_SCHEMA = "schemas/native-pool-transaction-plan-v7.schema.json"
NINTH_CAMPAIGN_RECOVERY_BEAD = "complex-work-orchestration-bpm4.16"
CAMPAIGN_OPPORTUNITY_RECOVERY_TYPE = "cwo-native-pool-campaign-opportunity-recovery"
CAMPAIGN_RECOVERY_ID = "spark-retirement-task-selected-p1a"
CAMPAIGN_RECOVERY_PHASE = "task-selected-route-private-full-git-jit"
CAMPAIGN_RECOVERY_BEAD = "complex-work-orchestration-bpm4"
RECOVERY_TYPE = "cwo-native-pool-campaign-infrastructure-recovery"
READINESS_TYPE = "cwo-native-pool-transaction-readiness"
READINESS_VERSION = 1
READINESS_SCHEMA = "schemas/native-pool-transaction-readiness.schema.json"
JOURNAL_TYPE = "cwo-native-pool-transaction-journal-event"
JOURNAL_VERSION = 1
TERMINAL_STATES = frozenset({"ACCEPTED", "CONTAINED", "DEFERRED"})
TRANSACTION_CALL_GRAPH = (
    "validate_plan",
    "validate_execution_authoritative_beads",
    "reserve_complete_transaction_budget",
    "run_prelude_sessions",
    "build_readiness_record",
    "validate_remaining_release_horizon",
    "persist_allocation_intent",
    "start_and_attest_session",
    "bind_admission_and_supervision",
    "arm_effect_atomic_cohort",
    "run_admitted_native_pool",
    "contain_and_validate",
    "record_terminal_disposition",
)
TRANSACTION_CALL_GRAPH_SHA256 = canonical_sha256(
    {"call_graph": list(TRANSACTION_CALL_GRAPH)}
)

_HASH = re.compile(r"^[0-9a-f]{64}$")
_STATE_TRANSITIONS = {
    None: frozenset({"PREPARED"}),
    "PREPARED": frozenset({"RESERVED", "CONTAINED", "DEFERRED"}),
    "RESERVED": frozenset({"EVIDENCE_READY", "CONTAINED", "DEFERRED"}),
    "EVIDENCE_READY": frozenset({"ALLOCATING", "ARMED", "CONTAINED", "DEFERRED"}),
    "ALLOCATING": frozenset({"EVIDENCE_READY", "ARMED", "CONTAINED", "DEFERRED"}),
    "ARMED": frozenset({"RUNNING", "CONTAINED"}),
    "RUNNING": frozenset({"VALIDATING", "CONTAINED"}),
    "VALIDATING": frozenset(TERMINAL_STATES),
    "ACCEPTED": frozenset(),
    "CONTAINED": frozenset(),
    "DEFERRED": frozenset(),
}
_PLAN_FIELDS = frozenset(
    {
        "plan_type",
        "version",
        "schema",
        "transaction_id",
        "phase_id",
        "candidate_manifest_sha256",
        "controller_overlay_sha256",
        "authority_sha256",
        "call_graph_sha256",
        "runtime_adapter_path",
        "runtime_adapter_sha256",
        "created_at",
        "selected_model",
        "prelude_session_count",
        "required_session_count",
        "budget",
        "startup_bounds_ms",
        "children",
        "plan_sha256",
    }
)
_RECOVERY_FIELDS = frozenset(
    {
        "recovery_type",
        "version",
        "campaign_id",
        "phase_id",
        "bead_id",
        "selected_model",
        "authority_sha256",
        "prior_failure_evidence_sha256",
        "opportunity_ledger_path",
        "additional_opportunities",
        "grant_sha256",
    }
)
_BUDGET_FIELDS = frozenset(
    {
        "cumulative_before",
        "cumulative_ceiling",
        "reserved_sessions",
        "infrastructure_failures_before",
        "maximum_infrastructure_failures",
    }
)
_STARTUP_FIELDS = frozenset(
    {
        "pre_allocation_ms",
        "per_allocation_ms",
        "runtime_binding_ms",
        "admission_ms",
        "dispatch_and_first_observation_ms",
        "safety_margin_ms",
    }
)
_CHILD_FIELDS = frozenset(
    {
        "child_id",
        "bead_id",
        "segment_id",
        "work_unit_id",
        "requested_model",
        "bead_projection_sha256",
        "worktree_identity_sha256",
        "work_plan_sha256",
        "packet_blueprint_sha256",
        "write_paths",
    }
)
_CHILD_OPTIONAL_FIELDS = frozenset({"read_only"})
_DEPENDENCY_FIELDS = frozenset(
    {"child_id", "kind", "evidence_sha256", "issued_at", "expires_at"}
)
_PACKET_BINDING_FIELDS = frozenset(
    {
        "child_id",
        "packet_sha256",
        "precommit_receipt_sha256",
        "work_plan_sha256",
    }
)
_ALLOCATION_FIELDS = frozenset(
    {
        "allocation_id",
        "allocation_class",
        "child_id",
        "session_id",
        "requested_model",
        "actual_model",
        "attestation_source",
        "interrupt_supported",
        "close_supported",
        "wait_supported",
        "workspace_identity_sha256",
    }
)
_JOURNAL_FIELDS = frozenset(
    {
        "journal_type",
        "version",
        "transaction_id",
        "sequence",
        "at",
        "event_type",
        "state",
        "details",
        "previous_event_sha256",
        "event_sha256",
    }
)


class NativePoolTransactionError(ValueError):
    """Raised when transaction composition cannot safely continue."""


class NativePoolInfrastructureError(RuntimeError):
    """Raised for a session-consuming controller or transport failure."""


class NativePoolProtectedError(RuntimeError):
    """Raised when security, control, identity, or attribution requires a stop."""

    def __init__(self, message: str, *, evidence: Mapping[str, Any] | None = None) -> None:
        super().__init__(message)
        self.evidence = deepcopy(dict(evidence or {}))


class NativePoolItemError(RuntimeError):
    """Raised for an attributable item-local failure, not infrastructure."""

    def __init__(self, message: str, *, evidence: Mapping[str, Any] | None = None) -> None:
        super().__init__(message)
        self.evidence = deepcopy(dict(evidence or {}))


def _strict(value: Any, fields: frozenset[str], label: str) -> dict[str, Any]:
    if type(value) is not dict:
        raise NativePoolTransactionError(f"{label}-must-be-object")
    missing = sorted(fields - set(value))
    extra = sorted(set(value) - fields)
    if missing or extra:
        details: list[str] = []
        if missing:
            details.append("missing=" + ",".join(missing))
        if extra:
            details.append("unknown=" + ",".join(extra))
        raise NativePoolTransactionError(f"{label}-fields-invalid:" + ";".join(details))
    return dict(value)


def _strict_with_optional(
    value: Any,
    required_fields: frozenset[str],
    optional_fields: frozenset[str],
    label: str,
) -> dict[str, Any]:
    if type(value) is not dict:
        raise NativePoolTransactionError(f"{label}-must-be-object")
    missing = sorted(required_fields - set(value))
    extra = sorted(set(value) - required_fields - optional_fields)
    if missing or extra:
        details: list[str] = []
        if missing:
            details.append("missing=" + ",".join(missing))
        if extra:
            details.append("unknown=" + ",".join(extra))
        raise NativePoolTransactionError(f"{label}-fields-invalid:" + ";".join(details))
    return dict(value)


def _nonempty(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise NativePoolTransactionError(f"{label}-must-be-nonempty-string")
    return value.strip()


def _hash(value: Any, label: str) -> str:
    text = _nonempty(value, label)
    if _HASH.fullmatch(text) is None:
        raise NativePoolTransactionError(f"{label}-must-be-sha256")
    return text


def _integer(value: Any, label: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise NativePoolTransactionError(f"{label}-must-be-integer-gte-{minimum}")
    return value


def _parse_time(value: Any, label: str) -> dt.datetime:
    text = _nonempty(value, label)
    try:
        parsed = dt.datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise NativePoolTransactionError(f"{label}-invalid") from exc
    if parsed.tzinfo is None:
        raise NativePoolTransactionError(f"{label}-timezone-required")
    return parsed.astimezone(dt.timezone.utc)


def _iso(value: dt.datetime) -> str:
    return (
        value.astimezone(dt.timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


def _plan_hash(value: Mapping[str, Any]) -> str:
    return canonical_sha256(
        {key: item for key, item in value.items() if key != "plan_sha256"}
    )


def _readiness_hash(value: Mapping[str, Any]) -> str:
    return canonical_sha256(
        {key: item for key, item in value.items() if key != "readiness_sha256"}
    )


def _event_hash(value: Mapping[str, Any]) -> str:
    return canonical_sha256(
        {key: item for key, item in value.items() if key != "event_sha256"}
    )


def execution_authoritative_bead_projection(issue: Mapping[str, Any]) -> dict[str, Any]:
    """Project only Bead fields that can change execution or acceptance.

    Comments and display-only history remain provenance, not a live gate.
    Admission metadata may be stored either as an object or a JSON string by
    different Beads backends; both forms produce the same projection.
    """

    source = dict(issue)
    bead_id = _nonempty(source.get("id"), "bead.id")
    dependencies: list[dict[str, Any]] = []
    raw_dependencies = source.get("dependencies", [])
    if not isinstance(raw_dependencies, list):
        raise NativePoolTransactionError(f"bead-dependencies-invalid:{bead_id}")
    for item in raw_dependencies:
        if not isinstance(item, Mapping):
            raise NativePoolTransactionError(f"bead-dependency-invalid:{bead_id}")
        dependency = {
            "id": _nonempty(item.get("id"), "bead.dependency.id"),
            "status": item.get("status"),
            "dependency_type": item.get("dependency_type"),
        }
        dependencies.append(dependency)
    dependencies.sort(key=lambda item: (item["id"], str(item["dependency_type"])))

    metadata = source.get("metadata")
    admission: Any = metadata.get("cwo_ready_set_admission") if isinstance(metadata, Mapping) else None
    if isinstance(admission, str):
        try:
            admission = json.loads(admission)
        except json.JSONDecodeError as exc:
            raise NativePoolTransactionError(
                f"bead-admission-metadata-invalid:{bead_id}"
            ) from exc
    if admission is None:
        admission = {}
    if not isinstance(admission, Mapping):
        raise NativePoolTransactionError(f"bead-admission-metadata-invalid:{bead_id}")
    scope: dict[str, Any] = {}
    for field in (
        "declared_read_paths",
        "declared_write_paths",
        "integration_target_paths",
        "isolation_class",
        "topology",
        "share_boundary",
        "architecture_authority",
        "execution_authority",
        "required_tools",
        "tool_policy",
        "tool_surface_id",
        "hard_budget",
        "aggregate_hard_budget",
        "capability_receipt",
        "capability_assessed_at",
        "lease_scope",
    ):
        if field in admission:
            scope[field] = deepcopy(admission[field])
    work_plan = admission.get("work_plan")
    if isinstance(work_plan, Mapping):
        scope["work_plan_sha256"] = canonical_sha256(dict(work_plan))

    return {
        "id": bead_id,
        "title": source.get("title"),
        "status": source.get("status"),
        "assignee": source.get("assignee"),
        "parent": source.get("parent"),
        "priority": source.get("priority"),
        "issue_type": source.get("issue_type"),
        "acceptance_criteria": source.get("acceptance_criteria"),
        "labels": sorted(source.get("labels", [])),
        "dependencies": dependencies,
        "execution_scope": scope,
    }


def execution_authoritative_bead_sha256(issue: Mapping[str, Any]) -> str:
    return canonical_sha256(execution_authoritative_bead_projection(issue))


_CAMPAIGN_BUDGET_FIELDS = frozenset({
    "cumulative_before", "cumulative_ceiling", "reserved_sessions",
    "prior_campaign_opportunities", "prior_infrastructure_failures", "prior_item_failures",
    "maximum_campaign_opportunities",
})


def _recovery_record(plan: Mapping[str, Any]) -> Mapping[str, Any]:
    return plan["campaign_recovery" if plan.get("version") == NINTH_CAMPAIGN_RECOVERY_PLAN_VERSION else "infrastructure_recovery"]


def _prior_recovery_counts(plan: Mapping[str, Any]) -> dict[str, int]:
    budget = plan["budget"]
    if plan.get("version") == NINTH_CAMPAIGN_RECOVERY_PLAN_VERSION:
        return {key: budget[key] for key in ("prior_campaign_opportunities", "prior_infrastructure_failures", "prior_item_failures", "maximum_campaign_opportunities")}
    return {"prior_infrastructure_failures": budget["infrastructure_failures_before"]}


def validate_transaction_plan(value: Any) -> list[str]:
    try:
        if type(value) is not dict:
            raise NativePoolTransactionError("transaction-plan-must-be-object")
        if type(value.get("version")) is not int:
            raise NativePoolTransactionError("transaction-plan-version-must-be-integer")
        maintenance_version = value["version"] == MAINTENANCE_PLAN_VERSION
        recovery_version = value["version"] in (RECOVERY_PLAN_VERSION, CAMPAIGN_RECOVERY_PLAN_VERSION, FINAL_CAMPAIGN_RECOVERY_PLAN_VERSION, SEVENTH_CAMPAIGN_RECOVERY_PLAN_VERSION, EIGHTH_CAMPAIGN_RECOVERY_PLAN_VERSION, NINTH_CAMPAIGN_RECOVERY_PLAN_VERSION)
        campaign_recovery_version = value["version"] in (CAMPAIGN_RECOVERY_PLAN_VERSION, FINAL_CAMPAIGN_RECOVERY_PLAN_VERSION, SEVENTH_CAMPAIGN_RECOVERY_PLAN_VERSION, EIGHTH_CAMPAIGN_RECOVERY_PLAN_VERSION, NINTH_CAMPAIGN_RECOVERY_PLAN_VERSION)
        final_campaign_recovery_version = value["version"] == FINAL_CAMPAIGN_RECOVERY_PLAN_VERSION
        seventh_campaign_recovery_version = value["version"] == SEVENTH_CAMPAIGN_RECOVERY_PLAN_VERSION
        eighth_campaign_recovery_version = value["version"] == EIGHTH_CAMPAIGN_RECOVERY_PLAN_VERSION
        ninth_campaign_recovery_version = value["version"] == NINTH_CAMPAIGN_RECOVERY_PLAN_VERSION
        plan = _strict(
            value,
            _PLAN_FIELDS | ({"campaign_recovery"} if ninth_campaign_recovery_version else ({"infrastructure_recovery"} if recovery_version else set())),
            "transaction-plan",
        )
        if plan.get("plan_type") != PLAN_TYPE or (
            value["version"] == RECOVERY_PLAN_VERSION
            and plan.get("schema") != RECOVERY_PLAN_SCHEMA
        ) or (
            value["version"] == CAMPAIGN_RECOVERY_PLAN_VERSION
            and plan.get("schema") != CAMPAIGN_RECOVERY_PLAN_SCHEMA
        ) or (
            final_campaign_recovery_version
            and plan.get("schema") != FINAL_CAMPAIGN_RECOVERY_PLAN_SCHEMA
        ) or (
            seventh_campaign_recovery_version
            and plan.get("schema") != SEVENTH_CAMPAIGN_RECOVERY_PLAN_SCHEMA
        ) or (
            eighth_campaign_recovery_version
            and plan.get("schema") != EIGHTH_CAMPAIGN_RECOVERY_PLAN_SCHEMA
        ) or (
            ninth_campaign_recovery_version
            and plan.get("schema") != NINTH_CAMPAIGN_RECOVERY_PLAN_SCHEMA
        ) or (
            not recovery_version and not maintenance_version
            and (plan.get("version") != PLAN_VERSION or plan.get("schema") != PLAN_SCHEMA)
        ):
            raise NativePoolTransactionError("transaction-plan-header-invalid")
        if maintenance_version and plan.get("schema") != MAINTENANCE_PLAN_SCHEMA:
            raise NativePoolTransactionError("transaction-maintenance-schema-invalid")
        for field in ("transaction_id", "phase_id", "runtime_adapter_path", "selected_model"):
            _nonempty(plan.get(field), f"transaction-plan.{field}")
        _parse_time(plan.get("created_at"), "transaction-plan.created_at")
        for field in (
            "candidate_manifest_sha256",
            "controller_overlay_sha256",
            "authority_sha256",
            "call_graph_sha256",
            "runtime_adapter_sha256",
            "plan_sha256",
        ):
            _hash(plan.get(field), f"transaction-plan.{field}")
        if plan["call_graph_sha256"] != TRANSACTION_CALL_GRAPH_SHA256:
            raise NativePoolTransactionError("transaction-plan-call-graph-mismatch")
        prelude_count = _integer(
            plan.get("prelude_session_count"),
            "transaction-plan.prelude_session_count",
        )
        required_count = _integer(
            plan.get("required_session_count"),
            "transaction-plan.required_session_count",
            minimum=1,
        )
        budget_fields = ({"mode", "cumulative_before", "reserved_sessions"} if maintenance_version else (_CAMPAIGN_BUDGET_FIELDS if ninth_campaign_recovery_version else _BUDGET_FIELDS))
        budget = _strict(plan.get("budget"), budget_fields, "transaction-plan.budget")
        for field in budget_fields - {"mode"}:
            _integer(budget.get(field), f"transaction-plan.budget.{field}")
        if maintenance_version and budget["mode"] != "maintenance-unbounded":
            raise NativePoolTransactionError("transaction-maintenance-budget-mode-invalid")
        if not recovery_version and not maintenance_version and budget["maximum_infrastructure_failures"] != 3:
            raise NativePoolTransactionError(
                "transaction-plan-maximum-infrastructure-failures-must-equal-3"
            )
        if ninth_campaign_recovery_version:
            if (budget["prior_campaign_opportunities"] != 8 or budget["prior_infrastructure_failures"] != 7
                or budget["prior_item_failures"] != 1 or budget["maximum_campaign_opportunities"] != 9
                or budget["prior_campaign_opportunities"] != budget["prior_infrastructure_failures"] + budget["prior_item_failures"]
                or prelude_count != 1 or required_count != 2):
                raise NativePoolTransactionError("transaction-plan-campaign-split-budget-invalid")
        elif recovery_version:
            expected_prior, expected_maximum = (7, 8) if eighth_campaign_recovery_version else ((6, 7) if seventh_campaign_recovery_version else ((5, 6) if final_campaign_recovery_version else ((4, 5) if campaign_recovery_version else (3, 4))))
            if (
                budget["maximum_infrastructure_failures"] != expected_maximum
                or budget["infrastructure_failures_before"] != expected_prior
                or prelude_count != 1
                or required_count != 2
            ):
                raise NativePoolTransactionError("transaction-plan-recovery-budget-or-shape-invalid")
        if not maintenance_version and not ninth_campaign_recovery_version and budget["infrastructure_failures_before"] >= budget["maximum_infrastructure_failures"]:
            raise NativePoolTransactionError("transaction-plan-infrastructure-fuse-open")
        if budget["reserved_sessions"] < required_count:
            raise NativePoolTransactionError("transaction-plan-session-reservation-insufficient")
        if not maintenance_version and budget["cumulative_before"] + budget["reserved_sessions"] > budget["cumulative_ceiling"]:
            raise NativePoolTransactionError("transaction-plan-cumulative-budget-exceeded")
        bounds = _strict(
            plan.get("startup_bounds_ms"),
            _STARTUP_FIELDS,
            "transaction-plan.startup-bounds",
        )
        for field in _STARTUP_FIELDS:
            _integer(bounds.get(field), f"transaction-plan.startup-bounds.{field}")
        if bounds["safety_margin_ms"] < 1:
            raise NativePoolTransactionError("transaction-plan-safety-margin-required")
        children = plan.get("children")
        if not isinstance(children, list) or not 1 <= len(children) <= 3:
            raise NativePoolTransactionError("transaction-plan-children-must-have-one-to-three-items")
        if recovery_version:
            if len(children) != 1:
                raise NativePoolTransactionError("transaction-plan-recovery-requires-one-child")
            recovery = _strict(
                _recovery_record(plan), _RECOVERY_FIELDS,
                "transaction-plan.infrastructure-recovery",
            )
            expected_grant_version = 1 if ninth_campaign_recovery_version else 5 if eighth_campaign_recovery_version else (4 if seventh_campaign_recovery_version else (3 if final_campaign_recovery_version else (2 if campaign_recovery_version else 1)))
            if recovery.get("recovery_type") != (CAMPAIGN_OPPORTUNITY_RECOVERY_TYPE if ninth_campaign_recovery_version else RECOVERY_TYPE) or type(recovery.get("version")) is not int or recovery["version"] != expected_grant_version:
                raise NativePoolTransactionError("transaction-plan-recovery-header-invalid")
            if type(recovery.get("additional_opportunities")) is not int or recovery["additional_opportunities"] != 1:
                raise NativePoolTransactionError("transaction-plan-recovery-additional-opportunity-invalid")
            if type(children[0]) is not dict:
                raise NativePoolTransactionError("transaction-plan-recovery-child-must-be-object")
            for field in ("campaign_id", "phase_id", "bead_id", "selected_model", "opportunity_ledger_path"):
                _nonempty(recovery.get(field), "transaction-plan.infrastructure-recovery." + field)
            for field in ("authority_sha256", "prior_failure_evidence_sha256", "grant_sha256"):
                _hash(recovery.get(field), "transaction-plan.infrastructure-recovery." + field)
            if recovery["grant_sha256"] != canonical_sha256(
                {key: item for key, item in recovery.items() if key != "grant_sha256"}
            ):
                raise NativePoolTransactionError("transaction-plan-recovery-grant-hash-mismatch")
            ledger_path = Path(recovery["opportunity_ledger_path"])
            if not ledger_path.is_absolute() or ".." in ledger_path.parts:
                raise NativePoolTransactionError("transaction-plan-recovery-ledger-path-invalid")
            if (
                recovery["phase_id"] != plan["phase_id"]
                or recovery["bead_id"] != children[0].get("bead_id")
                or recovery["selected_model"] != plan["selected_model"]
                or recovery["authority_sha256"] != plan["authority_sha256"]
            ):
                raise NativePoolTransactionError("transaction-plan-recovery-binding-mismatch")
            if campaign_recovery_version and (
                recovery["campaign_id"] != CAMPAIGN_RECOVERY_ID
                or recovery["phase_id"] != CAMPAIGN_RECOVERY_PHASE
                or recovery["bead_id"] != (NINTH_CAMPAIGN_RECOVERY_BEAD if ninth_campaign_recovery_version else EIGHTH_CAMPAIGN_RECOVERY_BEAD if eighth_campaign_recovery_version else (SEVENTH_CAMPAIGN_RECOVERY_BEAD if seventh_campaign_recovery_version else CAMPAIGN_RECOVERY_BEAD))
            ):
                raise NativePoolTransactionError("transaction-plan-recovery-campaign-invalid")
        if required_count != prelude_count + len(children):
            raise NativePoolTransactionError("transaction-plan-required-session-count-mismatch")
        child_ids: set[str] = set()
        bead_ids: set[str] = set()
        segments: set[str] = set()
        work_units: set[str] = set()
        owned_paths: set[str] = set()
        for index, raw_child in enumerate(children):
            child = _strict_with_optional(
                raw_child,
                _CHILD_FIELDS,
                _CHILD_OPTIONAL_FIELDS,
                f"transaction-plan.child[{index}]",
            )
            for field in ("child_id", "bead_id", "segment_id", "work_unit_id", "requested_model"):
                _nonempty(child.get(field), f"transaction-plan.child[{index}].{field}")
            for field in (
                "bead_projection_sha256",
                "worktree_identity_sha256",
                "work_plan_sha256",
                "packet_blueprint_sha256",
            ):
                _hash(child.get(field), f"transaction-plan.child[{index}].{field}")
            if child["requested_model"] != plan["selected_model"]:
                raise NativePoolTransactionError("transaction-plan-child-model-mismatch")
            write_paths = child.get("write_paths")
            if (
                not isinstance(write_paths, list)
                or any(not isinstance(path, str) or not path.strip() for path in write_paths)
                or len(write_paths) != len(set(write_paths))
            ):
                raise NativePoolTransactionError("transaction-plan-child-write-paths-invalid")
            read_only = child.get("read_only", False)
            if type(read_only) is not bool or read_only != (write_paths == []):
                raise NativePoolTransactionError("transaction-plan-child-read-only-invalid")
            if owned_paths.intersection(write_paths):
                raise NativePoolTransactionError("transaction-plan-child-write-paths-overlap")
            owned_paths.update(write_paths)
            for value, seen, error in (
                (child["child_id"], child_ids, "child-id"),
                (child["bead_id"], bead_ids, "bead-id"),
                (child["segment_id"], segments, "segment-id"),
                (child["work_unit_id"], work_units, "work-unit-id"),
            ):
                if value in seen:
                    raise NativePoolTransactionError(f"transaction-plan-{error}-duplicate")
                seen.add(value)
        if plan["plan_sha256"] != _plan_hash(plan):
            raise NativePoolTransactionError("transaction-plan-canonical-hash-mismatch")
    except (NativePoolTransactionError, TypeError, ValueError) as exc:
        return [str(exc)]
    return []


def seal_transaction_plan(value: Mapping[str, Any]) -> dict[str, Any]:
    plan = deepcopy(dict(value))
    plan["plan_sha256"] = _plan_hash(plan)
    errors = validate_transaction_plan(plan)
    if errors:
        raise NativePoolTransactionError("invalid-transaction-plan:" + ";".join(errors))
    return plan


def _required_lifetime_ms(
    plan: Mapping[str, Any],
    *,
    remaining_allocations: int,
    include_pre_allocation: bool,
    include_binding_and_admission: bool = True,
) -> int:
    bounds = plan["startup_bounds_ms"]
    return (
        (bounds["pre_allocation_ms"] if include_pre_allocation else 0)
        + bounds["per_allocation_ms"] * remaining_allocations
        + (bounds["runtime_binding_ms"] if include_binding_and_admission else 0)
        + (bounds["admission_ms"] if include_binding_and_admission else 0)
        + bounds["dispatch_and_first_observation_ms"]
        + bounds["safety_margin_ms"]
    )


def _normalize_dependencies(
    plan: Mapping[str, Any],
    dependencies: Sequence[Mapping[str, Any]],
    *,
    now: dt.datetime,
) -> list[dict[str, Any]]:
    child_ids = {str(child["child_id"]) for child in plan["children"]}
    result: list[dict[str, Any]] = []
    identities: set[tuple[str, str]] = set()
    covered: set[str] = set()
    for index, raw in enumerate(dependencies):
        item = _strict(raw, _DEPENDENCY_FIELDS, f"release-dependency[{index}]")
        child_id = _nonempty(item.get("child_id"), "release-dependency.child_id")
        kind = _nonempty(item.get("kind"), "release-dependency.kind")
        if child_id not in child_ids:
            raise NativePoolTransactionError("release-dependency-child-not-in-plan")
        identity = (child_id, kind)
        if identity in identities:
            raise NativePoolTransactionError("release-dependency-duplicate")
        identities.add(identity)
        covered.add(child_id)
        _hash(item.get("evidence_sha256"), "release-dependency.evidence_sha256")
        issued = _parse_time(item.get("issued_at"), "release-dependency.issued_at")
        expires = _parse_time(item.get("expires_at"), "release-dependency.expires_at")
        if expires <= issued:
            raise NativePoolTransactionError("release-dependency-expiry-not-after-issuance")
        if not issued <= now <= expires:
            raise NativePoolTransactionError("release-dependency-not-live")
        # Persist dependency timestamps at the same precision as the readiness
        # record.  Keeping higher-precision input here while truncating the
        # summary timestamps would make canonical self-validation disagree.
        item["issued_at"] = _iso(issued)
        item["expires_at"] = _iso(expires)
        result.append(item)
    if covered != child_ids:
        raise NativePoolTransactionError("release-dependency-child-coverage-mismatch")
    operative_children = {
        item["child_id"] for item in result if item["kind"] == "operative-release"
    }
    if operative_children != child_ids:
        raise NativePoolTransactionError(
            "release-dependency-operative-release-coverage-mismatch"
        )
    result.sort(key=lambda item: (item["expires_at"], item["child_id"], item["kind"]))
    return result


def _normalize_packet_bindings(
    plan: Mapping[str, Any], bindings: Sequence[Mapping[str, Any]]
) -> list[dict[str, Any]]:
    children = {str(child["child_id"]): child for child in plan["children"]}
    normalized: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, raw in enumerate(bindings):
        binding = _strict(raw, _PACKET_BINDING_FIELDS, f"packet-binding[{index}]")
        child_id = _nonempty(binding.get("child_id"), "packet-binding.child_id")
        if child_id not in children or child_id in seen:
            raise NativePoolTransactionError("packet-binding-child-set-invalid")
        seen.add(child_id)
        for field in (
            "packet_sha256",
            "precommit_receipt_sha256",
            "work_plan_sha256",
        ):
            _hash(binding.get(field), f"packet-binding.{field}")
        if binding["work_plan_sha256"] != children[child_id]["work_plan_sha256"]:
            raise NativePoolTransactionError("packet-binding-work-plan-mismatch")
        normalized.append(binding)
    if seen != set(children):
        raise NativePoolTransactionError("packet-binding-child-coverage-mismatch")
    normalized.sort(key=lambda item: item["child_id"])
    return normalized


def build_readiness_record(
    plan: Mapping[str, Any],
    bead_records: Mapping[str, Mapping[str, Any]],
    packet_bindings: Sequence[Mapping[str, Any]],
    release_dependencies: Sequence[Mapping[str, Any]],
    *,
    now: dt.datetime,
    parent_readiness_sha256: str | None = None,
) -> dict[str, Any]:
    """Build one hash-bound, non-authorizing readiness snapshot."""

    plan_errors = validate_transaction_plan(plan)
    if plan_errors:
        raise NativePoolTransactionError("readiness-plan-invalid:" + ";".join(plan_errors))
    current = now.astimezone(dt.timezone.utc)
    projections: list[dict[str, Any]] = []
    for child in plan["children"]:
        bead_id = child["bead_id"]
        raw = bead_records.get(bead_id)
        if not isinstance(raw, Mapping):
            raise NativePoolTransactionError(f"readiness-bead-missing:{bead_id}")
        projection = execution_authoritative_bead_projection(raw)
        projection_sha256 = canonical_sha256(projection)
        if projection_sha256 != child["bead_projection_sha256"]:
            raise NativePoolTransactionError(f"readiness-bead-projection-drift:{bead_id}")
        projections.append(
            {
                "child_id": child["child_id"],
                "bead_id": bead_id,
                "projection": projection,
                "projection_sha256": projection_sha256,
            }
        )
    bindings = _normalize_packet_bindings(plan, packet_bindings)
    dependencies = _normalize_dependencies(plan, release_dependencies, now=current)
    earliest = min(
        _parse_time(item["expires_at"], "release-dependency.expires_at")
        for item in dependencies
    )
    required_ms = _required_lifetime_ms(
        plan,
        remaining_allocations=len(plan["children"]),
        include_pre_allocation=True,
    )
    # The evidence schema serializes timestamps at millisecond precision.  Base
    # derived durations on those exact persisted values as well; otherwise a
    # runtime clock carrying extra microseconds can make a just-built record
    # fail its own deterministic validation by one millisecond.
    persisted_created = _parse_time(_iso(current), "readiness-record.created_at")
    persisted_earliest = _parse_time(
        _iso(earliest), "readiness-record.earliest_expires_at"
    )
    available_ms = max(
        0, int((persisted_earliest - persisted_created).total_seconds() * 1000)
    )
    if parent_readiness_sha256 is not None:
        _hash(parent_readiness_sha256, "parent-readiness-sha256")
    record: dict[str, Any] = {
        "readiness_type": READINESS_TYPE,
        "version": READINESS_VERSION,
        "schema": READINESS_SCHEMA,
        "readiness_id": "native-pool-readiness-" + hashlib.sha256(
            f"{plan['transaction_id']}:{_iso(current)}:{parent_readiness_sha256}".encode("utf-8")
        ).hexdigest()[:24],
        "plan_sha256": plan["plan_sha256"],
        "parent_readiness_sha256": parent_readiness_sha256,
        "created_at": _iso(current),
        "bead_projections": projections,
        "packet_bindings": bindings,
        "release_dependencies": dependencies,
        "earliest_expires_at": _iso(earliest),
        "required_lifetime_ms": required_ms,
        "available_lifetime_ms": available_ms,
        "valid_through": _iso(current + dt.timedelta(milliseconds=required_ms)),
        "readiness_sha256": "",
    }
    record["readiness_sha256"] = _readiness_hash(record)
    errors = validate_readiness_record(record, plan=plan)
    if errors:
        raise NativePoolTransactionError("invalid-readiness-record:" + ";".join(errors))
    return record


def validate_readiness_record(
    value: Any,
    *,
    plan: Mapping[str, Any] | None = None,
) -> list[str]:
    fields = frozenset(
        {
            "readiness_type",
            "version",
            "schema",
            "readiness_id",
            "plan_sha256",
            "parent_readiness_sha256",
            "created_at",
            "bead_projections",
            "packet_bindings",
            "release_dependencies",
            "earliest_expires_at",
            "required_lifetime_ms",
            "available_lifetime_ms",
            "valid_through",
            "readiness_sha256",
        }
    )
    try:
        record = _strict(value, fields, "readiness-record")
        if (
            record.get("readiness_type") != READINESS_TYPE
            or record.get("version") != READINESS_VERSION
            or record.get("schema") != READINESS_SCHEMA
        ):
            raise NativePoolTransactionError("readiness-record-header-invalid")
        _nonempty(record.get("readiness_id"), "readiness-record.readiness_id")
        _hash(record.get("plan_sha256"), "readiness-record.plan_sha256")
        parent = record.get("parent_readiness_sha256")
        if parent is not None:
            _hash(parent, "readiness-record.parent_readiness_sha256")
        created = _parse_time(record.get("created_at"), "readiness-record.created_at")
        earliest = _parse_time(
            record.get("earliest_expires_at"), "readiness-record.earliest_expires_at"
        )
        valid_through = _parse_time(record.get("valid_through"), "readiness-record.valid_through")
        required_ms = _integer(
            record.get("required_lifetime_ms"), "readiness-record.required_lifetime_ms"
        )
        available_ms = _integer(
            record.get("available_lifetime_ms"), "readiness-record.available_lifetime_ms"
        )
        if valid_through != created + dt.timedelta(milliseconds=required_ms):
            raise NativePoolTransactionError("readiness-record-valid-through-mismatch")
        expected_available = max(0, int((earliest - created).total_seconds() * 1000))
        if available_ms != expected_available:
            raise NativePoolTransactionError("readiness-record-available-lifetime-mismatch")
        dependencies = record.get("release_dependencies")
        if not isinstance(dependencies, list) or not dependencies:
            raise NativePoolTransactionError("readiness-record-dependencies-invalid")
        normalized_earliest = min(
            _parse_time(item.get("expires_at"), "release-dependency.expires_at")
            for item in dependencies
            if isinstance(item, Mapping)
        )
        if normalized_earliest != earliest:
            raise NativePoolTransactionError("readiness-record-earliest-expiry-mismatch")
        projections = record.get("bead_projections")
        if not isinstance(projections, list) or not projections:
            raise NativePoolTransactionError("readiness-record-bead-projections-invalid")
        for item in projections:
            item = _strict(
                item,
                frozenset(
                    {"child_id", "bead_id", "projection", "projection_sha256"}
                ),
                "readiness-record.bead-projection",
            )
            _nonempty(item.get("child_id"), "readiness-record.child-id")
            _nonempty(item.get("bead_id"), "readiness-record.bead-id")
            _hash(
                item.get("projection_sha256"),
                "readiness-record.projection-sha256",
            )
            if canonical_sha256(item.get("projection")) != item.get("projection_sha256"):
                raise NativePoolTransactionError("readiness-record-bead-projection-hash-mismatch")
        packet_bindings = record.get("packet_bindings")
        if not isinstance(packet_bindings, list) or not packet_bindings:
            raise NativePoolTransactionError("readiness-record-packet-bindings-invalid")
        if plan is not None:
            plan_errors = validate_transaction_plan(plan)
            if plan_errors:
                raise NativePoolTransactionError("readiness-record-plan-invalid")
            if record["plan_sha256"] != plan["plan_sha256"]:
                raise NativePoolTransactionError("readiness-record-plan-binding-mismatch")
            child_ids = {child["child_id"] for child in plan["children"]}
            if {item.get("child_id") for item in projections} != child_ids:
                raise NativePoolTransactionError("readiness-record-projection-set-mismatch")
            if {item.get("child_id") for item in dependencies} != child_ids:
                raise NativePoolTransactionError("readiness-record-dependency-set-mismatch")
            if _normalize_dependencies(plan, dependencies, now=created) != dependencies:
                raise NativePoolTransactionError("readiness-record-dependencies-not-canonical")
            if _normalize_packet_bindings(plan, packet_bindings) != packet_bindings:
                raise NativePoolTransactionError("readiness-record-packet-bindings-not-canonical")
            expected_required = _required_lifetime_ms(
                plan,
                remaining_allocations=len(plan["children"]),
                include_pre_allocation=True,
            )
            if required_ms != expected_required:
                raise NativePoolTransactionError("readiness-record-required-lifetime-mismatch")
        if record.get("readiness_sha256") != _readiness_hash(record):
            raise NativePoolTransactionError("readiness-record-canonical-hash-mismatch")
    except (NativePoolTransactionError, TypeError, ValueError) as exc:
        return [str(exc)]
    return []


def readiness_horizon_errors(
    readiness: Mapping[str, Any],
    plan: Mapping[str, Any],
    *,
    now: dt.datetime,
    remaining_allocations: int,
    include_pre_allocation: bool = False,
    include_binding_and_admission: bool = True,
) -> list[str]:
    errors = validate_readiness_record(readiness, plan=plan)
    if errors:
        return errors
    try:
        remaining = _integer(
            remaining_allocations, "remaining-allocations"
        )
        if remaining > len(plan["children"]):
            raise NativePoolTransactionError("remaining-allocations-exceeds-cohort")
        current = now.astimezone(dt.timezone.utc)
        required_ms = _required_lifetime_ms(
            plan,
            remaining_allocations=remaining,
            include_pre_allocation=include_pre_allocation,
            include_binding_and_admission=include_binding_and_admission,
        )
        for dependency in readiness["release_dependencies"]:
            issued = _parse_time(dependency["issued_at"], "release-dependency.issued_at")
            expires = _parse_time(dependency["expires_at"], "release-dependency.expires_at")
            # Live validation is inclusive, matching native_release.py.
            if not issued <= current <= expires:
                raise NativePoolTransactionError(
                    "release-dependency-not-live:" + dependency["child_id"] + ":" + dependency["kind"]
                )
            available_ms = int((expires - current).total_seconds() * 1000)
            if available_ms < required_ms:
                raise NativePoolTransactionError(
                    "release-dependency-horizon-insufficient:"
                    + dependency["child_id"]
                    + ":"
                    + dependency["kind"]
                )
    except (NativePoolTransactionError, TypeError, ValueError) as exc:
        return [str(exc)]
    return []


class TransactionJournal:
    """Append-only, hash-chained transaction evidence and spending fuse."""

    def __init__(self, path: str | Path, transaction_id: str) -> None:
        self.path = Path(path).expanduser().resolve()
        self.transaction_id = _nonempty(transaction_id, "transaction-id")
        if self.path.is_symlink():
            raise NativePoolTransactionError("transaction-journal-symlink-forbidden")
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)

    def read(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        events: list[dict[str, Any]] = []
        previous: str | None = None
        previous_state: str | None = None
        previous_time: dt.datetime | None = None
        for index, line in enumerate(self.path.read_text(encoding="utf-8").splitlines()):
            try:
                event = json.loads(line)
            except json.JSONDecodeError as exc:
                raise NativePoolTransactionError("transaction-journal-json-invalid") from exc
            event = _strict(event, _JOURNAL_FIELDS, "transaction-journal-event")
            if (
                event.get("journal_type") != JOURNAL_TYPE
                or event.get("version") != JOURNAL_VERSION
                or event.get("transaction_id") != self.transaction_id
                or event.get("sequence") != index
                or event.get("previous_event_sha256") != previous
                or event.get("event_sha256") != _event_hash(event)
            ):
                raise NativePoolTransactionError("transaction-journal-chain-invalid")
            current_time = _parse_time(event.get("at"), "transaction-journal.at")
            if previous_time is not None and current_time < previous_time:
                raise NativePoolTransactionError("transaction-journal-time-regressed")
            _nonempty(event.get("event_type"), "transaction-journal.event-type")
            state = event.get("state")
            if state not in _STATE_TRANSITIONS:
                raise NativePoolTransactionError("transaction-journal-state-invalid")
            if previous_state is None:
                if state != "PREPARED":
                    raise NativePoolTransactionError("transaction-journal-first-state-invalid")
            elif previous_state in TERMINAL_STATES:
                raise NativePoolTransactionError("transaction-journal-event-after-terminal")
            elif state != previous_state and state not in _STATE_TRANSITIONS[previous_state]:
                raise NativePoolTransactionError("transaction-journal-state-transition-invalid")
            if not isinstance(event.get("details"), Mapping):
                raise NativePoolTransactionError("transaction-journal-details-invalid")
            previous = event["event_sha256"]
            previous_state = state
            previous_time = current_time
            events.append(event)
        return events

    def append(
        self,
        *,
        event_type: str,
        state: str,
        details: Mapping[str, Any],
        now: dt.datetime,
    ) -> dict[str, Any]:
        _nonempty(event_type, "journal-event-type")
        if state not in _STATE_TRANSITIONS:
            raise NativePoolTransactionError("journal-state-invalid")
        lock_path = self.path.with_suffix(self.path.suffix + ".lock")
        flags = os.O_RDWR | os.O_CREAT
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(lock_path, flags, 0o600)
        with os.fdopen(descriptor, "a+", encoding="utf-8") as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
            events = self.read()
            previous = events[-1]["event_sha256"] if events else None
            event: dict[str, Any] = {
                "journal_type": JOURNAL_TYPE,
                "version": JOURNAL_VERSION,
                "transaction_id": self.transaction_id,
                "sequence": len(events),
                "at": _iso(now),
                "event_type": event_type,
                "state": state,
                "details": deepcopy(dict(details)),
                "previous_event_sha256": previous,
                "event_sha256": "",
            }
            event["event_sha256"] = _event_hash(event)
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n")
                handle.flush()
                os.fsync(handle.fileno())
            self.path.chmod(0o600)
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
        return event

    @property
    def current_state(self) -> str | None:
        events = self.read()
        return events[-1]["state"] if events else None

    @property
    def infrastructure_failure_count(self) -> int:
        return sum(
            event["event_type"] == "infrastructure-failure" for event in self.read()
        )


@dataclass(frozen=True, slots=True)
class AdmittedPoolLaunch:
    reservation_receipt: Mapping[str, Any]
    admission_capability: object
    contract: Mapping[str, Any]
    preflight_request: Mapping[str, Any]
    preflight_result: Mapping[str, Any]
    child_contracts: Mapping[str, Mapping[str, Any]]
    task_inputs: Mapping[str, str]
    child_callbacks: Mapping[str, Mapping[str, Callable[..., Any]]]
    keyword_arguments: Mapping[str, Any]


@dataclass(frozen=True, slots=True)
class TransactionRuntime:
    trusted_session_count: Callable[[], int]
    read_bead: Callable[[str], Mapping[str, Any]]
    prepare: Callable[[Mapping[str, Any]], Mapping[str, Any]]
    start_prelude_session: Callable[[int, Mapping[str, Any]], Mapping[str, Any]]
    release_artifacts: Callable[
        [Mapping[str, Any], Mapping[str, Any], Mapping[str, Any] | None],
        Mapping[str, Any],
    ]
    refresh_release_artifacts: Callable[
        [Mapping[str, Any], Mapping[str, Any], Mapping[str, Any] | None],
        Mapping[str, Any],
    ]
    start_worker_session: Callable[
        [Mapping[str, Any], Mapping[str, Any]], Mapping[str, Any]
    ]
    bind_admitted_launch: Callable[
        [Mapping[str, Any], Sequence[Mapping[str, Any]], Mapping[str, Any]],
        AdmittedPoolLaunch,
    ]
    contain: Callable[
        [Sequence[Mapping[str, Any]], str, Mapping[str, Any]], Mapping[str, Any]
    ]
    validate: Callable[
        [Mapping[str, Any], Mapping[str, Any]], Mapping[str, Any]
    ]
    # Recovery versions only: controller-authoritative verification of the
    # exact prospective campaign grant. V1 runtimes need no such callback.
    authorize_recovery: Callable[[Mapping[str, Any]], bool] | None = None
    # Recovery versions only: fsync the controller's first allocation intent before the
    # irreversible campaign claim. The first starter must verify this intent
    # rather than append it again. V1 runtimes retain their original behavior.
    persist_first_allocation_intent: Callable[[Mapping[str, Any]], None] | None = None
    # V8 only: opaque authority minted by a trusted parent BEFORE adapter import.
    maintenance_operation: object | None = None
    maintenance_verifier: object | None = None


def require_recovery_authority(
    plan: Mapping[str, Any], runtime: TransactionRuntime
) -> None:
    """Reject recovery/maintenance unless its controller verifies current authority."""

    if plan.get("version") == MAINTENANCE_PLAN_VERSION:
        from .maintenance_authority import require_maintenance_operation
        require_maintenance_operation(runtime.maintenance_operation, plan=plan,
            verifier=runtime.maintenance_verifier, require_claimed=True)
        return
    if plan.get("version") not in (RECOVERY_PLAN_VERSION, CAMPAIGN_RECOVERY_PLAN_VERSION, FINAL_CAMPAIGN_RECOVERY_PLAN_VERSION, SEVENTH_CAMPAIGN_RECOVERY_PLAN_VERSION, EIGHTH_CAMPAIGN_RECOVERY_PLAN_VERSION, NINTH_CAMPAIGN_RECOVERY_PLAN_VERSION):
        return
    verifier = runtime.authorize_recovery
    if not callable(verifier):
        raise NativePoolProtectedError("transaction-recovery-authority-missing")
    if not callable(runtime.persist_first_allocation_intent):
        raise NativePoolProtectedError("transaction-recovery-intent-persistence-missing")
    try:
        accepted = verifier(plan)
    except BaseException as exc:
        raise NativePoolProtectedError(
            "transaction-recovery-authority-check-failed"
        ) from exc
    if accepted is not True:
        raise NativePoolProtectedError("transaction-recovery-authority-rejected")


def _open_recovery_parent(target: Path) -> int:
    """Pin a private ledger directory without following an ancestor symlink."""

    if not target.is_absolute() or ".." in target.parts or not target.name:
        raise NativePoolProtectedError("transaction-recovery-ledger-boundary-invalid")
    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open("/", directory_flags)
    try:
        components = target.parent.parts[1:]
        for component in components:
            next_descriptor = os.open(component, directory_flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
            details = os.fstat(descriptor)
            # A root-owned sticky /tmp is a trusted traversal anchor, but the
            # final campaign directory must be private to this user.
            sticky_root = (
                details.st_uid == 0
                and stat.S_ISDIR(details.st_mode)
                and bool(details.st_mode & stat.S_ISVTX)
                and bool(details.st_mode & stat.S_IWOTH)
            )
            if (
                not stat.S_ISDIR(details.st_mode)
                or details.st_uid not in (0, os.getuid())
                or (details.st_mode & 0o022 and not sticky_root)
            ):
                raise NativePoolProtectedError("transaction-recovery-ledger-ancestor-untrusted")
        parent_details = os.fstat(descriptor)
        if parent_details.st_uid != os.getuid() or stat.S_IMODE(parent_details.st_mode) & 0o077:
            raise NativePoolProtectedError("transaction-recovery-ledger-parent-not-private")
        current = os.stat(target.parent, follow_symlinks=False)
        if (current.st_dev, current.st_ino) != (parent_details.st_dev, parent_details.st_ino):
            raise NativePoolProtectedError("transaction-recovery-ledger-parent-replaced")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _consume_recovery_opportunity(plan: Mapping[str, Any]) -> str:
    """Spend the sole campaign opportunity across transaction IDs.

    The ledger is created atomically and fsynced before the first session
    allocation callback. A different transaction ID cannot erase this record.
    """

    recovery = _recovery_record(plan)
    target = Path(recovery["opportunity_ledger_path"])
    event = {
        "event_type": "cwo-campaign-recovery-opportunity-consumed",
        "version": 1,
        "campaign_id": recovery["campaign_id"],
        "grant_sha256": recovery["grant_sha256"],
        "prior_failure_evidence_sha256": recovery["prior_failure_evidence_sha256"],
        "transaction_id": plan["transaction_id"],
        "plan_sha256": plan["plan_sha256"],
        **_prior_recovery_counts(plan),
        "additional_opportunities": 1,
    }
    event_sha256 = canonical_sha256(event)
    event["event_sha256"] = event_sha256
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        parent_descriptor = _open_recovery_parent(target)
    except OSError as exc:
        raise NativePoolProtectedError("transaction-recovery-ledger-boundary-invalid") from exc
    try:
        try:
            descriptor = os.open(target.name, flags, 0o600, dir_fd=parent_descriptor)
        except FileExistsError as exc:
            raise NativePoolProtectedError(
                "transaction-recovery-opportunity-already-consumed"
            ) from exc
        except OSError as exc:
            raise NativePoolProtectedError(
                "transaction-recovery-opportunity-ledger-create-failed"
            ) from exc
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.fsync(parent_descriptor)
        pinned = os.fstat(parent_descriptor)
        current = os.stat(target.parent, follow_symlinks=False)
        if (current.st_dev, current.st_ino) != (pinned.st_dev, pinned.st_ino):
            raise NativePoolProtectedError("transaction-recovery-ledger-parent-replaced")
    finally:
        os.close(parent_descriptor)
    return event_sha256


def _validate_allocation(
    value: Any,
    *,
    plan: Mapping[str, Any],
    allocation_class: str,
    child: Mapping[str, Any] | None,
) -> dict[str, Any]:
    allocation = _strict(value, _ALLOCATION_FIELDS, "runtime-allocation")
    for field in (
        "allocation_id",
        "allocation_class",
        "session_id",
        "requested_model",
        "actual_model",
        "attestation_source",
    ):
        _nonempty(allocation.get(field), f"runtime-allocation.{field}")
    if allocation["allocation_class"] != allocation_class:
        raise NativePoolInfrastructureError("runtime-allocation-class-mismatch")
    if allocation["requested_model"] != plan["selected_model"]:
        raise NativePoolInfrastructureError("runtime-allocation-requested-model-mismatch")
    if allocation["actual_model"] != plan["selected_model"]:
        raise NativePoolInfrastructureError("runtime-allocation-actual-model-mismatch")
    if allocation["attestation_source"] not in (
        {"trusted-session-jsonl", "trusted-app-server-thread-start"}
        if plan.get("version") == MAINTENANCE_PLAN_VERSION else {"trusted-session-jsonl"}
    ):
        raise NativePoolInfrastructureError("runtime-allocation-attestation-untrusted")
    for field in ("interrupt_supported", "close_supported", "wait_supported"):
        if allocation.get(field) is not True:
            raise NativePoolInfrastructureError("runtime-allocation-control-incomplete")
    workspace_hash = allocation.get("workspace_identity_sha256")
    if allocation_class == "worker":
        if child is None or allocation.get("child_id") != child["child_id"]:
            raise NativePoolInfrastructureError("runtime-allocation-child-mismatch")
        if workspace_hash != child["worktree_identity_sha256"]:
            raise NativePoolInfrastructureError("runtime-allocation-workspace-mismatch")
    else:
        if allocation.get("child_id") is not None or workspace_hash is not None:
            raise NativePoolInfrastructureError("runtime-prelude-allocation-scope-invalid")
    return allocation


def _transition(
    journal: TransactionJournal,
    current: str | None,
    target: str,
    *,
    event_type: str,
    details: Mapping[str, Any],
    now: dt.datetime,
) -> str:
    if target not in _STATE_TRANSITIONS.get(current, frozenset()):
        raise NativePoolTransactionError(f"transaction-state-transition-invalid:{current}->{target}")
    journal.append(event_type=event_type, state=target, details=details, now=now)
    return target


def _launch_session(
    *,
    journal: TransactionJournal,
    plan: Mapping[str, Any],
    allocation_class: str,
    ordinal: int,
    child: Mapping[str, Any] | None,
    starter: Callable[..., Mapping[str, Any]],
    context: Mapping[str, Any],
    start_attempts: list[dict[str, Any]],
    now_utc: Callable[[], dt.datetime],
    before_first_start: Callable[[Mapping[str, Any]], str] | None = None,
) -> dict[str, Any]:
    allocation_id = canonical_sha256(
        {
            "transaction_id": plan["transaction_id"],
            "allocation_class": allocation_class,
            "ordinal": ordinal,
            "child_id": child.get("child_id") if child else None,
        }
    )
    journal.append(
        event_type="allocation-intent",
        state=journal.current_state or "RESERVED",
        details={
            "allocation_id": allocation_id,
            "allocation_class": allocation_class,
            "ordinal": ordinal,
            "child_id": child.get("child_id") if child else None,
            "requested_model": plan["selected_model"],
        },
        now=now_utc(),
    )
    # Runtime context may contain live server handles and locks.  Copy only the
    # mapping shell; never clone live control-plane identities.
    call_context = dict(context)
    call_context["transaction_allocation"] = {
        "allocation_id": allocation_id,
        "allocation_class": allocation_class,
        "ordinal": ordinal,
        "child_id": child.get("child_id") if child else None,
    }
    # The controller's durable allocation intent and every deterministic
    # journal write precede the irreversible campaign claim. A failure in
    # either pre-claim writer consumes no recovery opportunity.
    opportunity_sha256 = before_first_start(call_context) if before_first_start is not None else None
    attempt = {
        "allocation_id": allocation_id,
        "allocation_class": allocation_class,
        "child_id": child.get("child_id") if child else None,
        "session_id": None,
        "outcome": "acknowledgement-pending",
    }
    start_attempts.append(attempt)
    try:
        raw = (
            starter(ordinal, call_context)
            if child is None
            else starter(child, call_context)
        )
    except (NativePoolProtectedError, NativePoolInfrastructureError):
        raise
    except BaseException as exc:
        raise NativePoolInfrastructureError(
            f"allocation-acknowledgement-lost:{allocation_id}:{type(exc).__name__}"
        ) from exc
    allocation = _validate_allocation(
        raw,
        plan=plan,
        allocation_class=allocation_class,
        child=child,
    )
    if allocation["allocation_id"] != allocation_id:
        raise NativePoolInfrastructureError("runtime-allocation-id-mismatch")
    start_attempts[-1] = allocation
    if opportunity_sha256 is not None:
        journal.append(
            event_type="recovery-opportunity-consumed",
            state=journal.current_state or "RESERVED",
            details={
                "grant_sha256": _recovery_record(plan)["grant_sha256"],
                "opportunity_sha256": opportunity_sha256,
                **_prior_recovery_counts(plan),
            },
            now=now_utc(),
        )
    journal.append(
        event_type="allocation-bound",
        state=journal.current_state or "RESERVED",
        details={
            "allocation_id": allocation_id,
            "allocation_class": allocation_class,
            "ordinal": ordinal,
            "child_id": allocation["child_id"],
            "session_id": allocation["session_id"],
            "actual_model": allocation["actual_model"],
        },
        now=now_utc(),
    )
    return allocation


def _validate_launch_bindings(
    plan: Mapping[str, Any],
    allocations: Sequence[Mapping[str, Any]],
    launch: AdmittedPoolLaunch,
) -> None:
    if type(launch) is not AdmittedPoolLaunch:
        raise NativePoolInfrastructureError("admitted-launch-binding-type-invalid")
    expected = {item["child_id"]: item["session_id"] for item in allocations}
    children = launch.contract.get("children")
    if not isinstance(children, list):
        raise NativePoolInfrastructureError("admitted-launch-contract-children-invalid")
    observed = {
        child.get("child_id"): child.get("session_id")
        for child in children
        if isinstance(child, Mapping)
    }
    if observed != expected or set(observed) != {
        child["child_id"] for child in plan["children"]
    }:
        raise NativePoolInfrastructureError("admitted-launch-runtime-binding-mismatch")


def _assert_trusted_session_count(
    runtime: TransactionRuntime,
    *,
    baseline: int,
    attempts: list[dict[str, Any]],
    phase: str,
) -> None:
    observed = _integer(runtime.trusted_session_count(), "trusted-session-count")
    expected = baseline + len(attempts)
    if observed == expected:
        return
    for index in range(max(0, observed - expected)):
        attempts.append(
            {
                "allocation_id": canonical_sha256(
                    {
                        "phase": phase,
                        "unaccounted_index": index,
                        "observed": observed,
                        "expected": expected,
                    }
                ),
                "allocation_class": "unaccounted",
                "child_id": None,
                "session_id": None,
                "outcome": "trusted-count-without-allocation-acknowledgement",
            }
        )
    raise NativePoolInfrastructureError(
        f"transaction-{phase}-session-accounting-mismatch:{expected}:{observed}"
    )


def _split_release_artifacts(value: Any) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    bundle = _strict(
        value,
        frozenset({"packet_bindings", "release_dependencies"}),
        "release-artifacts",
    )
    bindings = bundle.get("packet_bindings")
    dependencies = bundle.get("release_dependencies")
    if not isinstance(bindings, list) or not isinstance(dependencies, list):
        raise NativePoolTransactionError("release-artifacts-lists-required")
    return [dict(item) for item in bindings], [dict(item) for item in dependencies]


def execute_native_pool_transaction(
    plan: Mapping[str, Any],
    runtime: TransactionRuntime,
    *,
    journal_path: str | Path,
    now_utc: Callable[[], dt.datetime] | None = None,
    run_pool: Callable[..., Mapping[str, Any]] = run_admitted_native_pool,
) -> dict[str, Any]:
    """Execute one bounded, effect-atomic admitted-pool transaction."""

    plan_errors = validate_transaction_plan(plan)
    if plan_errors:
        raise NativePoolTransactionError("transaction-plan-invalid:" + ";".join(plan_errors))
    if type(runtime) is not TransactionRuntime:
        raise NativePoolTransactionError("transaction-runtime-type-invalid")
    require_recovery_authority(plan, runtime)
    clock = now_utc or (lambda: dt.datetime.now(dt.timezone.utc))
    journal = TransactionJournal(journal_path, str(plan["transaction_id"]))
    if journal.read():
        raise NativePoolTransactionError("transaction-journal-must-be-new")
    state: str | None = None
    started: list[dict[str, Any]] = []
    context: Mapping[str, Any] = {}
    readiness: Mapping[str, Any] | None = None
    launched: Mapping[str, Any] | None = None
    try:
        baseline_session_count = _integer(
            runtime.trusted_session_count(), "trusted-session-count"
        )
        if baseline_session_count != plan["budget"]["cumulative_before"]:
            raise NativePoolTransactionError(
                "transaction-cumulative-session-count-mismatch"
            )
        bead_records = {child["bead_id"]: runtime.read_bead(child["bead_id"]) for child in plan["children"]}
        for child in plan["children"]:
            observed = execution_authoritative_bead_sha256(bead_records[child["bead_id"]])
            if observed != child["bead_projection_sha256"]:
                raise NativePoolTransactionError(
                    "transaction-prepared-bead-projection-drift:" + child["bead_id"]
                )
        adapter_path = Path(str(plan["runtime_adapter_path"])).expanduser().resolve()
        if (
            not adapter_path.is_file()
            or adapter_path.is_symlink()
            or hashlib.sha256(adapter_path.read_bytes()).hexdigest()
            != plan["runtime_adapter_sha256"]
        ):
            raise NativePoolTransactionError("transaction-runtime-adapter-drift")
        state = _transition(
            journal,
            state,
            "PREPARED",
            event_type="static-readiness-accepted",
            details={
                "plan_sha256": plan["plan_sha256"],
                "call_graph_sha256": plan["call_graph_sha256"],
                "bead_projection_set_sha256": canonical_sha256(
                    {
                        child["bead_id"]: child["bead_projection_sha256"]
                        for child in plan["children"]
                    }
                ),
            },
            now=clock(),
        )
        budget = plan["budget"]
        if plan["version"] == NINTH_CAMPAIGN_RECOVERY_PLAN_VERSION:
            if budget["prior_campaign_opportunities"] >= budget["maximum_campaign_opportunities"]:
                raise NativePoolTransactionError("transaction-campaign-opportunity-fuse-open")
        elif plan["version"] != MAINTENANCE_PLAN_VERSION and journal.infrastructure_failure_count + budget["infrastructure_failures_before"] >= budget["maximum_infrastructure_failures"]:
            raise NativePoolTransactionError("transaction-infrastructure-fuse-open")
        state = _transition(
            journal,
            state,
            "RESERVED",
            event_type="complete-transaction-budget-reserved",
            details={
                "required_session_count": plan["required_session_count"],
                "reserved_sessions": budget["reserved_sessions"],
                "cumulative_before": budget["cumulative_before"],
                "cumulative_ceiling": budget.get("cumulative_ceiling"),
                "accounting_mode": budget.get("mode", "finite-campaign"),
                "logical_cohort_sha256": canonical_sha256(
                    [
                        {
                            "child_id": child["child_id"],
                            "bead_id": child["bead_id"],
                            "segment_id": child["segment_id"],
                            "work_unit_id": child["work_unit_id"],
                        }
                        for child in plan["children"]
                    ]
                ),
                "disjoint_write_scope_sha256": canonical_sha256(
                    {
                        child["child_id"]: child["write_paths"]
                        for child in plan["children"]
                    }
                ),
            },
            now=clock(),
        )
        context = dict(runtime.prepare(plan))
        expected_static_context = {
            "candidate_manifest_sha256": plan["candidate_manifest_sha256"],
            "controller_overlay_sha256": plan["controller_overlay_sha256"],
            "authority_sha256": plan["authority_sha256"],
            "runtime_adapter_sha256": plan["runtime_adapter_sha256"],
        }
        if any(context.get(field) != expected for field, expected in expected_static_context.items()):
            raise NativePoolTransactionError("transaction-prepared-static-binding-mismatch")
        _assert_trusted_session_count(
            runtime,
            baseline=baseline_session_count,
            attempts=started,
            phase="prepare",
        )
        def first_recovery_claim(call_context: Mapping[str, Any]) -> str:
            persister = runtime.persist_first_allocation_intent
            if not callable(persister):
                raise NativePoolProtectedError("transaction-recovery-intent-persistence-missing")
            persister(call_context)
            return _consume_recovery_opportunity(plan)

        for ordinal in range(plan["prelude_session_count"]):
            require_recovery_authority(plan, runtime)
            allocation = _launch_session(
                journal=journal,
                plan=plan,
                allocation_class="prelude",
                ordinal=ordinal,
                child=None,
                starter=runtime.start_prelude_session,
                context=context,
                start_attempts=started,
                now_utc=clock,
                before_first_start=(
                    first_recovery_claim
                    if plan["version"] in (RECOVERY_PLAN_VERSION, CAMPAIGN_RECOVERY_PLAN_VERSION, FINAL_CAMPAIGN_RECOVERY_PLAN_VERSION, SEVENTH_CAMPAIGN_RECOVERY_PLAN_VERSION, EIGHTH_CAMPAIGN_RECOVERY_PLAN_VERSION, NINTH_CAMPAIGN_RECOVERY_PLAN_VERSION) and ordinal == 0
                    else None
                ),
            )
            _assert_trusted_session_count(
                runtime,
                baseline=baseline_session_count,
                attempts=started,
                phase="prelude",
            )

        packet_bindings, dependencies = _split_release_artifacts(
            runtime.release_artifacts(plan, context, None)
        )
        _assert_trusted_session_count(
            runtime,
            baseline=baseline_session_count,
            attempts=started,
            phase="release-issuer",
        )
        bead_records = {child["bead_id"]: runtime.read_bead(child["bead_id"]) for child in plan["children"]}
        try:
            readiness = build_readiness_record(
                plan,
                bead_records,
                packet_bindings,
                dependencies,
                now=clock(),
            )
        except NativePoolTransactionError as exc:
            if "release-dependency-" not in str(exc):
                raise
            packet_bindings, refreshed = _split_release_artifacts(
                runtime.refresh_release_artifacts(plan, context, None)
            )
            _assert_trusted_session_count(
                runtime,
                baseline=baseline_session_count,
                attempts=started,
                phase="release-refresh",
            )
            readiness = build_readiness_record(
                plan,
                bead_records,
                packet_bindings,
                refreshed,
                now=clock(),
            )
        initial_errors = readiness_horizon_errors(
            readiness,
            plan,
            now=clock(),
            remaining_allocations=len(plan["children"]),
            include_pre_allocation=True,
        )
        if initial_errors:
            packet_bindings, refreshed = _split_release_artifacts(
                runtime.refresh_release_artifacts(plan, context, readiness)
            )
            _assert_trusted_session_count(
                runtime,
                baseline=baseline_session_count,
                attempts=started,
                phase="release-refresh",
            )
            readiness = build_readiness_record(
                plan,
                bead_records,
                packet_bindings,
                refreshed,
                now=clock(),
                parent_readiness_sha256=readiness["readiness_sha256"],
            )
            initial_errors = readiness_horizon_errors(
                readiness,
                plan,
                now=clock(),
                remaining_allocations=len(plan["children"]),
                include_pre_allocation=True,
            )
        if initial_errors:
            raise NativePoolTransactionError(
                "transaction-initial-release-horizon-invalid:" + ";".join(initial_errors)
            )
        state = _transition(
            journal,
            state,
            "EVIDENCE_READY",
            event_type="release-horizon-accepted",
            details={"readiness_sha256": readiness["readiness_sha256"]},
            now=clock(),
        )

        worker_allocations: list[dict[str, Any]] = []
        for index, child in enumerate(plan["children"]):
            require_recovery_authority(plan, runtime)
            remaining = len(plan["children"]) - index
            horizon_errors = readiness_horizon_errors(
                readiness,
                plan,
                now=clock(),
                remaining_allocations=remaining,
            )
            if horizon_errors:
                packet_bindings, refreshed = _split_release_artifacts(
                    runtime.refresh_release_artifacts(plan, context, readiness)
                )
                _assert_trusted_session_count(
                    runtime,
                    baseline=baseline_session_count,
                    attempts=started,
                    phase="release-refresh",
                )
                bead_records = {item["bead_id"]: runtime.read_bead(item["bead_id"]) for item in plan["children"]}
                readiness = build_readiness_record(
                    plan,
                    bead_records,
                    packet_bindings,
                    refreshed,
                    now=clock(),
                    parent_readiness_sha256=readiness["readiness_sha256"],
                )
                horizon_errors = readiness_horizon_errors(
                    readiness,
                    plan,
                    now=clock(),
                    remaining_allocations=remaining,
                )
                if horizon_errors:
                    raise NativePoolTransactionError(
                        "transaction-release-horizon-invalid:" + ";".join(horizon_errors)
                    )
                if state == "ALLOCATING":
                    state = _transition(
                        journal,
                        state,
                        "EVIDENCE_READY",
                        event_type="release-evidence-refreshed",
                        details={"readiness_sha256": readiness["readiness_sha256"]},
                        now=clock(),
                    )
            if state == "EVIDENCE_READY":
                state = _transition(
                    journal,
                    state,
                    "ALLOCATING",
                    event_type="worker-allocation-started",
                    details={"remaining_allocations": remaining},
                    now=clock(),
                )
            allocation = _launch_session(
                journal=journal,
                plan=plan,
                allocation_class="worker",
                ordinal=plan["prelude_session_count"] + index,
                child=child,
                starter=runtime.start_worker_session,
                context=context,
                start_attempts=started,
                now_utc=clock,
            )
            worker_allocations.append(allocation)
            _assert_trusted_session_count(
                runtime,
                baseline=baseline_session_count,
                attempts=started,
                phase="worker",
            )

        binding_horizon_errors = readiness_horizon_errors(
            readiness,
            plan,
            now=clock(),
            remaining_allocations=0,
        )
        if binding_horizon_errors:
            packet_bindings, refreshed = _split_release_artifacts(
                runtime.refresh_release_artifacts(plan, context, readiness)
            )
            _assert_trusted_session_count(
                runtime,
                baseline=baseline_session_count,
                attempts=started,
                phase="release-refresh",
            )
            bead_records = {
                item["bead_id"]: runtime.read_bead(item["bead_id"])
                for item in plan["children"]
            }
            readiness = build_readiness_record(
                plan,
                bead_records,
                packet_bindings,
                refreshed,
                now=clock(),
                parent_readiness_sha256=readiness["readiness_sha256"],
            )
            binding_horizon_errors = readiness_horizon_errors(
                readiness,
                plan,
                now=clock(),
                remaining_allocations=0,
            )
        if binding_horizon_errors:
            raise NativePoolTransactionError(
                "transaction-binding-release-horizon-invalid:"
                + ";".join(binding_horizon_errors)
            )
        launch = runtime.bind_admitted_launch(plan, worker_allocations, context)
        _validate_launch_bindings(plan, worker_allocations, launch)
        _assert_trusted_session_count(
            runtime,
            baseline=baseline_session_count,
            attempts=started,
            phase="binding",
        )
        final_horizon_errors = readiness_horizon_errors(
            readiness,
            plan,
            now=clock(),
            remaining_allocations=0,
            include_binding_and_admission=False,
        )
        if final_horizon_errors:
            raise NativePoolTransactionError(
                "transaction-final-release-horizon-invalid:"
                + ";".join(final_horizon_errors)
            )
        state = _transition(
            journal,
            state,
            "ARMED",
            event_type="effect-atomic-cohort-armed",
            details={
                "worker_session_bindings_sha256": canonical_sha256(worker_allocations),
                "readiness_sha256": readiness["readiness_sha256"],
                "reservation_sha256": launch.reservation_receipt.get("reservation_sha256"),
                "contract_sha256": launch.contract.get("contract_sha256"),
            },
            now=clock(),
        )
        state = _transition(
            journal,
            state,
            "RUNNING",
            event_type="admitted-pool-commit",
            details={"entrypoint": "run_admitted_native_pool"},
            now=clock(),
        )
        require_recovery_authority(plan, runtime)
        launched = run_pool(
            launch.reservation_receipt,
            launch.admission_capability,
            launch.contract,
            launch.preflight_request,
            launch.preflight_result,
            launch.child_contracts,
            launch.task_inputs,
            launch.child_callbacks,
            **dict(launch.keyword_arguments),
        )
        _assert_trusted_session_count(
            runtime,
            baseline=baseline_session_count,
            attempts=started,
            phase="admitted-pool",
        )
        state = _transition(
            journal,
            state,
            "VALIDATING",
            event_type="admitted-pool-returned",
            details={"launch_result_sha256": canonical_sha256(launched)},
            now=clock(),
        )
        # Validation is an observer, not authority to change the admitted work.
        # Freeze the *current* post-persistence/pool projection, not the old
        # pre-precommit plan projection. All effectful readers run before the
        # final observation below; no observer follows that observation.
        validation_beads = {
            child["bead_id"]: execution_authoritative_bead_sha256(
                runtime.read_bead(child["bead_id"])
            )
            for child in plan["children"]
        }
        validation = dict(runtime.validate(launched, context))
        _assert_trusted_session_count(
            runtime,
            baseline=baseline_session_count,
            attempts=started,
            phase="validation",
        )
        terminal_time = clock()
        require_recovery_authority(plan, runtime)
        for bead_id, expected in validation_beads.items():
            observed = execution_authoritative_bead_sha256(runtime.read_bead(bead_id))
            if observed != expected:
                raise NativePoolTransactionError(
                    "transaction-final-bead-projection-drift:" + bead_id
                )
        accepted = validation.get("accepted") is True
        target = "ACCEPTED" if accepted else "CONTAINED"
        state = _transition(
            journal,
            state,
            target,
            event_type="transaction-terminal",
            details={
                "accepted": accepted,
                "validation_sha256": canonical_sha256(validation),
                "healthy_evidence_retained": validation.get(
                    "healthy_evidence_retained", False
                ),
                "atomic_promotion_authorized": validation.get(
                    "atomic_promotion_authorized", False
                ),
            },
            now=terminal_time,
        )
        return {
            "transaction_id": plan["transaction_id"],
            "state": state,
            "accepted": accepted,
            "plan_sha256": plan["plan_sha256"],
            "readiness_sha256": readiness["readiness_sha256"],
            "launch_result": deepcopy(dict(launched)),
            "validation": validation,
            "journal_last_event_sha256": journal.read()[-1]["event_sha256"],
        }
    except NativePoolProtectedError as exc:
        # A protected boundary is neither a product correction nor routine
        # infrastructure.  Contain every started session, preserve the exact
        # evidence, and keep the exception visible to the controlling Sol.
        containment = {"all_contained": True, "started_thread_count": 0}
        if started:
            try:
                containment = dict(runtime.contain(started, str(exc), context))
            except BaseException as containment_exc:
                containment = {
                    "all_contained": False,
                    "error": f"{type(containment_exc).__name__}:{containment_exc}",
                }
        journal.append(
            event_type="protected-stop",
            state=state or "PREPARED",
            details={
                "error_type": type(exc).__name__,
                "error": str(exc),
                "started_session_count": len(started),
                "protected_evidence_sha256": canonical_sha256(exc.evidence),
                "containment_sha256": canonical_sha256(containment),
                "all_contained": containment.get("all_contained") is True,
            },
            now=clock(),
        )
        if (
            state is not None
            and state not in TERMINAL_STATES
            and "CONTAINED" in _STATE_TRANSITIONS.get(state, frozenset())
        ):
            _transition(
                journal,
                state,
                "CONTAINED",
                event_type="transaction-terminal",
                details={
                    "accepted": False,
                    "failure_class": "protected",
                    "all_contained": containment.get("all_contained") is True,
                },
                now=clock(),
            )
        raise
    except NativePoolItemError as exc:
        # Product or focused-validation rejection is attributable to the item,
        # not to controller infrastructure.  Retain the healthy evidence,
        # contain all live sessions, and return a typed non-accepted result so
        # the caller can spend the item's bounded correction allowance.
        if not started:
            if (
                state is not None
                and state not in TERMINAL_STATES
                and "DEFERRED" in _STATE_TRANSITIONS.get(state, frozenset())
            ):
                _transition(
                    journal,
                    state,
                    "DEFERRED",
                    event_type="deterministic-zero-session-abort",
                    details={"error_type": type(exc).__name__, "error": str(exc)},
                    now=clock(),
                )
            raise
        try:
            containment = dict(runtime.contain(started, str(exc), context))
        except BaseException as containment_exc:
            containment = {
                "all_contained": False,
                "error": f"{type(containment_exc).__name__}:{containment_exc}",
            }
        journal.append(
            event_type="item-failure",
            state=state or "PREPARED",
            details={
                "error_type": type(exc).__name__,
                "error": str(exc),
                "started_session_count": len(started),
                "item_evidence_sha256": canonical_sha256(exc.evidence),
                "containment_sha256": canonical_sha256(containment),
                "all_contained": containment.get("all_contained") is True,
            },
            now=clock(),
        )
        if containment.get("all_contained") is not True:
            journal.append(
                event_type="infrastructure-failure",
                state=state or "PREPARED",
                details={
                    "error_type": "NativePoolInfrastructureError",
                    "error": "item-failure-containment-incomplete",
                    "started_session_count": len(started),
                    "containment_sha256": canonical_sha256(containment),
                    "all_contained": False,
                },
                now=clock(),
            )
            if (
                state not in TERMINAL_STATES
                and "CONTAINED" in _STATE_TRANSITIONS.get(state, frozenset())
            ):
                _transition(
                    journal,
                    state,
                    "CONTAINED",
                    event_type="transaction-terminal",
                    details={"accepted": False, "all_contained": False},
                    now=clock(),
                )
            raise NativePoolInfrastructureError(
                "item-failure-containment-incomplete"
            ) from exc
        if (
            state not in TERMINAL_STATES
            and "CONTAINED" in _STATE_TRANSITIONS.get(state, frozenset())
        ):
            state = _transition(
                journal,
                state,
                "CONTAINED",
                event_type="transaction-terminal",
                details={
                    "accepted": False,
                    "failure_class": "item",
                    "all_contained": True,
                    "healthy_evidence_retained": True,
                    "atomic_promotion_authorized": False,
                },
                now=clock(),
            )
        validation = {
            "accepted": False,
            "failure_class": "item",
            "error": str(exc),
            "item_evidence": deepcopy(exc.evidence),
            "healthy_evidence_retained": True,
            "atomic_promotion_authorized": False,
            "all_contained": True,
        }
        return {
            "transaction_id": plan["transaction_id"],
            "state": state,
            "accepted": False,
            "failure_class": "item",
            "plan_sha256": plan["plan_sha256"],
            "readiness_sha256": readiness["readiness_sha256"] if readiness else None,
            "launch_result": deepcopy(dict(launched or {})),
            "validation": validation,
            "journal_last_event_sha256": journal.read()[-1]["event_sha256"],
        }
    except BaseException as exc:
        # A deterministic rejection before any session is not an infrastructure
        # failure and consumes no item correction allowance.
        if started:
            try:
                containment = dict(runtime.contain(started, str(exc), context))
            except BaseException as containment_exc:
                containment = {
                    "all_contained": False,
                    "error": f"{type(containment_exc).__name__}:{containment_exc}",
                }
            journal.append(
                event_type="infrastructure-failure",
                state=state or "PREPARED",
                details={
                    "error_type": type(exc).__name__,
                    "error": str(exc),
                    "started_session_count": len(started),
                    "containment_sha256": canonical_sha256(containment),
                    "all_contained": containment.get("all_contained") is True,
                },
                now=clock(),
            )
            if state not in TERMINAL_STATES and "CONTAINED" in _STATE_TRANSITIONS.get(state, frozenset()):
                _transition(
                    journal,
                    state,
                    "CONTAINED",
                    event_type="transaction-terminal",
                    details={
                        "accepted": False,
                        "all_contained": containment.get("all_contained") is True,
                    },
                    now=clock(),
                )
        elif state is not None and state not in TERMINAL_STATES and "DEFERRED" in _STATE_TRANSITIONS.get(state, frozenset()):
            _transition(
                journal,
                state,
                "DEFERRED",
                event_type="deterministic-zero-session-abort",
                details={"error_type": type(exc).__name__, "error": str(exc)},
                now=clock(),
            )
        raise


def write_transaction_result(path: str | Path, value: Mapping[str, Any]) -> Path:
    target = Path(path).expanduser().resolve()
    if target.is_symlink():
        raise NativePoolTransactionError("transaction-result-symlink-forbidden")
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    atomic_write_text(target, json.dumps(dict(value), indent=2, sort_keys=True) + "\n")
    target.chmod(0o600)
    return target
