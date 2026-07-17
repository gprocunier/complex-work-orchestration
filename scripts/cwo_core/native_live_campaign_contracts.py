"""Strict successor authority and manifest contracts for native live campaigns."""

from __future__ import annotations

import datetime as dt
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile
from typing import Any, Mapping
import uuid

from .native_canary_contracts import validate_authorization_state
from .native_live_allocation_ledger import (
    NativeLiveAllocationLedgerError,
    summarize_live_allocation_ledger,
    validate_live_allocation_ledger,
)


AUTHORIZATION_TYPE = "cwo-full-auto-run-authorization"
AUTHORIZATION_VERSION = 5
AUTHORIZATION_SCHEMA = "schemas/full-auto-run-authorization.schema.json"
MANIFEST_TYPE = "cwo-native-live-campaign-manifest"
MANIFEST_VERSION = 2
MANIFEST_SCHEMA = "schemas/native-live-campaign-manifest.schema.json"
EXACT_STEERING_MODEL = "gpt-5.6-sol"
EXACT_STEERING_EFFORT = "max"
EXACT_OPERATIVE_MODEL = "gpt-5.3-codex-spark"
EXACT_OPERATIVE_EFFORT = "low"
EXACT_CRITIC_MODEL = "claude-opus-4-6"
EXACT_CRITIC_EFFORT = "max"
EXPECTED_ROLES = (
    "capability-calibration",
    "read-only-0",
    "read-only-1",
    "mutable-0",
    "mutable-1",
    "interrupt-0",
    "interrupt-1",
)
HASH_RE = re.compile(r"^[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")

AUTHORIZATION_FIELDS = {
    "authorization_type",
    "version",
    "schema",
    "authorization_id",
    "run_generation",
    "live_generation",
    "predecessor_live_generation",
    "issued_at",
    "issued_by",
    "operator_authority",
    "initial_state",
    "scope",
    "bindings",
    "supersession",
    "executors",
    "resource_limits",
    "progress_gate",
    "mandatory_gates",
    "persistence",
    "forbidden",
    "live_relaunch_rule",
    "release",
    "canonical_authorization_sha256",
}
SCOPE_FIELDS = {"epic_id", "parent_work_unit_id", "ordered_work_units"}
BINDING_FIELDS = {
    "checkpoint_commit",
    "checkpoint_tree",
    "origin_main_commit",
    "guarded_primary_diff_sha256",
    "pickup_path",
    "pickup_sha256",
    "recovery_plan_path",
    "recovery_plan_sha256",
    "campaign_nonce",
    "predecessor_authorization_id",
    "predecessor_authorization_file_sha256",
    "predecessor_authorization_canonical_sha256",
    "predecessor_manifest_file_sha256",
    "predecessor_manifest_canonical_sha256",
    "predecessor_authorization_state_file_sha256",
    "predecessor_authorization_state_canonical_sha256",
    "predecessor_failure_evidence_file_sha256",
    "predecessor_failure_evidence_canonical_sha256",
    "predecessor_containment_file_sha256",
    "predecessor_containment_canonical_sha256",
    "predecessor_original_containment_file_sha256",
    "predecessor_original_containment_canonical_sha256",
    "predecessor_allocation_ledger_file_sha256",
    "predecessor_allocation_ledger_state_sha256",
    "predecessor_allocation_audit_file_sha256",
    "backup_ref",
    "outer_authority_id",
    "outer_authority_canonical_sha256",
    "outer_authority_file_sha256",
}
SUPERSESSION_FIELDS = {
    "prior_authorization_id",
    "prior_terminal_state",
    "prior_live_generation",
    "prior_allocations",
    "prior_ambiguities",
    "prior_allowed_actions",
    "reuse_resume_retry_substitution_salvage_bridge",
}
EXECUTOR_FIELDS = {"final_architect", "steering", "operative", "outside_critic"}
STEERING_EXECUTOR_FIELDS = {"model", "effort", "surface", "authority"}
OPERATIVE_EXECUTOR_FIELDS = {"model", "effort", "surface", "session_policy"}
CRITIC_EXECUTOR_FIELDS = {"model", "effort", "surface", "authority"}
RESOURCE_LIMIT_FIELDS = {
    "sol_consultations_this_inner_hard",
    "opus_reviews_this_inner_hard",
    "spark_validation_sessions_this_inner_hard",
    "spark_live_turn_starts_exact",
    "spark_compactions_hard",
    "full_repository_suites_this_inner_hard",
    "focused_validation_bundles_this_inner_hard",
    "implementation_correction_sprints_this_inner_hard",
    "primary_checkout_mutations_hard",
}
PROGRESS_GATE_FIELDS = {
    "outer_authority_status",
    "qualification_basis",
    "predecessor_failure_class",
    "predecessor_failure_evidence_canonical_sha256",
    "predecessor_candidate_commit",
    "predecessor_candidate_tree",
    "predecessor_lineage_sha256",
    "new_falsifiable_cause",
    "cause_evidence_sha256",
    "repair_commit",
    "repair_tree",
    "independent_validation_receipt_canonical_sha256",
    "independent_validation_receipt_file_sha256",
    "independent_validation_session_id",
    "independent_validation_completed_at",
    "independent_validation_binding_sha256",
    "same_fault_without_new_evidence",
    "one_active_inner_campaign",
    "arbitrary_generation_cap",
    "fresh_exact_sol_pre_live_required",
    "qualification_sha256",
}
MANDATORY_GATE_FIELDS = {
    "strict_authorization_v5",
    "active_outer_authority_binding",
    "progress_qualification_validation",
    "contained_prior_generation_proof",
    "fresh_exact_spark_validation",
    "fresh_exact_sol_pre_mutation_receipt",
    "successor_contract_validation",
    "frozen_release_patch",
    "opus_second_line_review_adjudicated",
    "fresh_exact_sol_pre_live_receipt",
    "campaign_manifest_v2",
    "single_shot_per_generation_live_campaign",
    "main_thread_adjudication_each_gate",
    "guarded_primary_diff_stability",
    "staging_ci_before_main",
    "published_install_parity",
}
PERSISTENCE_FIELDS = {
    "run_level_full_auto_survives_recoverable_failure",
    "operator_recheck_required_for_routine_recovery",
    "evidence_bearing_live_failure_becomes_terminal",
    "fresh_successor_requires_new_authorization_id_nonce_receipts_sessions_and_paths",
    "combined_confidence_formula",
    "combined_confidence_minimum",
    "operator_stop_conditions",
}
FORBIDDEN_FIELDS = {
    "glm_5_2",
    "model_synthesis",
    "primary_checkout_mutation",
    "prior_authorization_reuse",
    "prior_nonce_session_receipt_registry_state_output_ledger_or_path_reuse",
    "worker_resume",
    "worker_salvage",
    "model_substitution",
    "evidence_bearing_live_retry",
    "sol_target_checkout_mutation",
    "release_before_live_acceptance",
    "force_push",
    "git_tag",
    "github_release",
}
RELAUNCH_FIELDS = {
    "pre_rpc_zero_artifact_relaunch_max",
    "requires_no_thread_start_request",
    "requires_no_allocation_intent",
    "requires_no_session_identity",
    "requires_no_audit_event",
    "requires_no_campaign_artifact",
}
AUTHORIZATION_RELEASE_FIELDS = {
    "authorized_only_after_accepting_live_evidence_and_main_go",
    "frozen_delta_required",
    "version_remains",
    "tag_or_github_release",
    "actions_after_gate",
}

MANIFEST_FIELDS = {
    "manifest_type",
    "version",
    "schema",
    "manifest_id",
    "created_at",
    "authorization_id",
    "authorization_raw_sha256",
    "authorization_canonical_sha256",
    "run_generation",
    "live_generation",
    "predecessor_live_generation",
    "campaign_nonce",
    "control_turn_id",
    "work_units",
    "candidate",
    "predecessor",
    "outer_authority",
    "progress_qualification_sha256",
    "executors",
    "expected_roles",
    "successful_turn_starts_exact",
    "prestart_zero_artifact_relaunch_max",
    "reviews",
    "release",
    "outputs",
    "no_resume_or_salvage",
    "glm_5_2_used",
    "model_synthesis_used",
    "manifest_sha256",
}
MANIFEST_WORK_UNIT_FIELDS = {"epic_id", "parent_work_unit_id", "live_work_unit_id"}
MANIFEST_CANDIDATE_FIELDS = {
    "commit",
    "tree",
    "origin_main_commit",
    "guarded_primary_diff_sha256",
}
MANIFEST_PREDECESSOR_FIELDS = {
    "authorization_id",
    "authorization_file_sha256",
    "authorization_canonical_sha256",
    "manifest_file_sha256",
    "manifest_canonical_sha256",
    "authorization_state_file_sha256",
    "authorization_state_canonical_sha256",
    "failure_evidence_file_sha256",
    "containment_file_sha256",
    "candidate_commit",
    "candidate_tree",
    "lineage_sha256",
    "failure_evidence_canonical_sha256",
    "containment_canonical_sha256",
    "original_containment_file_sha256",
    "original_containment_canonical_sha256",
    "allocation_ledger_file_sha256",
    "allocation_ledger_state_sha256",
    "allocation_audit_file_sha256",
}
MANIFEST_OUTER_AUTHORITY_FIELDS = {
    "authority_id",
    "canonical_sha256",
    "file_sha256",
}
MANIFEST_REVIEW_FIELDS = {
    "pre_mutation_receipt_canonical_sha256",
    "pre_mutation_receipt_file_sha256",
    "pre_mutation_adjudication_file_sha256",
    "opus_evidence_file_sha256",
    "opus_adjudication_file_sha256",
    "spark_validation_receipt_canonical_sha256",
    "spark_validation_receipt_file_sha256",
    "pre_live_receipt_canonical_sha256",
    "pre_live_receipt_file_sha256",
    "pre_live_adjudication_file_sha256",
}
MANIFEST_RELEASE_FIELDS = {
    "patch_file_sha256",
    "candidate_tree",
    "prospective_tree",
    "policy_before",
    "policy_after",
}
MANIFEST_POLICY_FIELDS = {"status", "cap_two_operative_release"}
MANIFEST_OUTPUT_FIELDS = {
    "evidence_basename",
    "authorization_state_basename",
    "steering_registry_basename",
    "allocation_ledger_basename",
}

HISTORICAL_AUTHORIZATION_FIELDS_V4 = (
    AUTHORIZATION_FIELDS - {"resource_limits", "progress_gate"}
) | {"budgets"}
HISTORICAL_BINDING_FIELDS_V4 = {
    "checkpoint_commit",
    "checkpoint_tree",
    "origin_main_commit",
    "guarded_primary_diff_sha256",
    "pickup_path",
    "pickup_sha256",
    "recovery_plan_path",
    "recovery_plan_sha256",
    "campaign_nonce",
    "predecessor_authorization_id",
    "predecessor_failure_evidence_file_sha256",
    "predecessor_failure_evidence_canonical_sha256",
    "predecessor_containment_file_sha256",
    "predecessor_containment_canonical_sha256",
    "backup_ref",
}
HISTORICAL_BUDGET_FIELDS_V4 = {
    "sol_consultations_observed_before_v10",
    "sol_consultations_added",
    "sol_consultations_global_hard",
    "opus_reviews_observed_before_v10",
    "opus_reviews_added",
    "opus_reviews_global_hard",
    "live_generations_consumed_before_current",
    "live_generations_global_hard",
    "live_generations_remaining_exact",
    "spark_live_turn_starts_per_generation_exact",
    "spark_read_only_validation_sessions_hard",
    "spark_compactions_hard",
    "full_repository_suites_observed_before_v10",
    "full_repository_suites_added",
    "full_repository_suites_global_hard",
    "focused_validation_bundles_hard",
    "implementation_correction_sprints_hard",
    "origin_reconciliation_cycles_hard",
    "primary_checkout_mutations_hard",
}
HISTORICAL_MANDATORY_GATE_FIELDS_V4 = {
    "strict_authorization_v4",
    "contained_prior_generation_proof",
    "fresh_exact_sol_pre_mutation_receipt",
    "successor_contract_validation",
    "frozen_release_patch",
    "fresh_opus_candidate_review",
    "fresh_exact_sol_pre_live_receipt",
    "campaign_manifest_v1",
    "single_shot_per_generation_live_campaign",
    "main_thread_adjudication_each_gate",
    "guarded_primary_diff_stability",
    "staging_ci_before_main",
    "published_install_parity",
}
HISTORICAL_FORBIDDEN_FIELDS_V4 = FORBIDDEN_FIELDS | {"generation_6"}
HISTORICAL_MANIFEST_FIELDS_V1 = MANIFEST_FIELDS - {
    "outer_authority",
    "progress_qualification_sha256",
}
HISTORICAL_MANIFEST_PREDECESSOR_FIELDS_V1 = {
    "authorization_id",
    "failure_evidence_canonical_sha256",
    "containment_canonical_sha256",
}
HISTORICAL_MANIFEST_REVIEW_FIELDS_V1 = MANIFEST_REVIEW_FIELDS - {
    "spark_validation_receipt_canonical_sha256",
    "spark_validation_receipt_file_sha256",
}
ORIGINAL_CONTAINMENT_FIELDS = {
    "schema",
    "bead_id",
    "recorded_at",
    "failed_authorization_id",
    "failed_campaign_nonce",
    "failed_manifest",
    "failed_evidence",
    "root_cause",
    "session_accounting",
    "allocation_ledger",
    "steering_consumption",
    "control_plane_recheck",
    "reclassification",
    "canonical_recovery_sha256",
}
CORRECTION_CONTAINMENT_FIELDS = {
    "schema",
    "recorded_at",
    "failed_authorization_id",
    "failed_campaign_nonce",
    "failed_evidence",
    "reclassification",
    "control_plane_recheck",
    "correction",
    "canonical_recovery_sha256",
}
CORRECTION_DETAIL_FIELDS = {
    "kind",
    "original_artifact_file_sha256",
    "original_artifact_canonical_sha256",
    "original_recorded_authorization_id",
    "corrected_authorization_id",
    "identity_authority",
    "evidence_or_disposition_changed",
    "main_architect_disposition",
}
CORRECTION_IDENTITY_AUTHORITY_FIELDS = {
    "authorization_file_sha256",
    "authorization_canonical_sha256",
    "manifest_file_sha256",
    "manifest_canonical_sha256",
    "authorization_state_file_sha256",
    "authorization_state_canonical_sha256",
    "failure_evidence_file_sha256",
    "failure_evidence_canonical_sha256",
}
CORRECTION_FAILED_EVIDENCE_FIELDS = {
    "file_sha256",
    "canonical_sha256",
    "authorization_state_file_sha256",
    "authorization_state_canonical_sha256",
}
CORRECTION_RECLASSIFICATION_FIELDS = {
    "global_live_generation_ordinal",
    "allocated_count",
    "calibration_turns_started",
    "pool_turns_started",
    "pool_tool_calls",
    "contained_count",
    "ambiguous_count",
    "all_contained",
    "release_gate_passed",
    "failed_authorization_terminal",
    "reuse_resume_retry_substitution_salvage_bridge",
}
CORRECTION_CONTROL_FIELDS = {
    "campaign_process_alive",
    "disposable_workspace_present",
    "protected_primary_diff_sha256",
    "isolated_checkout_head",
    "isolated_checkout_tree",
    "isolated_checkout_tracked_clean",
    "origin_main_commit",
    "release_policy_status",
    "operative_dispatch_authorized",
    "authorization_state_validation_errors",
    "evidence_canonical_hash_valid",
}
PREDECESSOR_LEDGER_EVENT_SEQUENCE = (
    "allocation-intent",
    "thread-bound",
    "turn-intent",
    "turn-bound",
    "interrupt-observed",
    "archive-observed",
    "containment-audited",
)
PREDECESSOR_LEDGER_OUTCOME_SEQUENCE = (
    "pending",
    "bound",
    "pending",
    "bound",
    "interrupt-request-accepted",
    "archive-request-accepted",
    "contained",
)


def canonical_sha256(value: Any) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _is_hash(value: Any) -> bool:
    return isinstance(value, str) and bool(HASH_RE.fullmatch(value))


def _is_commit(value: Any) -> bool:
    return isinstance(value, str) and bool(COMMIT_RE.fullmatch(value))


def _is_uuid(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    try:
        uuid.UUID(value)
    except ValueError:
        return False
    return True


def _is_int(value: Any, minimum: int = 0) -> bool:
    return not isinstance(value, bool) and isinstance(value, int) and value >= minimum


def _strict(value: Any, fields: set[str], label: str, errors: list[str]) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        errors.append(f"{label}-not-object")
        return {}
    result = dict(value)
    if set(result) != fields:
        errors.append(f"{label}-fields-invalid")
    return result


def _strings(value: Any) -> bool:
    return isinstance(value, list) and bool(value) and all(
        isinstance(item, str) and bool(item.strip()) for item in value
    )


def _run_git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _canonical_artifact_hash(value: Mapping[str, Any], hash_field: str) -> str:
    unsigned = dict(value)
    unsigned.pop(hash_field, None)
    return canonical_sha256(unsigned)


def _predecessor_lineage(
    bindings: Mapping[str, Any],
    progress: Mapping[str, Any],
    predecessor_live_generation: Any,
) -> dict[str, Any]:
    return {
        "authorization_id": bindings.get("predecessor_authorization_id"),
        "authorization_file_sha256": bindings.get(
            "predecessor_authorization_file_sha256"
        ),
        "authorization_canonical_sha256": bindings.get(
            "predecessor_authorization_canonical_sha256"
        ),
        "manifest_file_sha256": bindings.get("predecessor_manifest_file_sha256"),
        "manifest_canonical_sha256": bindings.get(
            "predecessor_manifest_canonical_sha256"
        ),
        "authorization_state_file_sha256": bindings.get(
            "predecessor_authorization_state_file_sha256"
        ),
        "authorization_state_canonical_sha256": bindings.get(
            "predecessor_authorization_state_canonical_sha256"
        ),
        "live_generation": predecessor_live_generation,
        "candidate_commit": progress.get("predecessor_candidate_commit"),
        "candidate_tree": progress.get("predecessor_candidate_tree"),
        "failure_evidence_canonical_sha256": bindings.get(
            "predecessor_failure_evidence_canonical_sha256"
        ),
        "failure_evidence_file_sha256": bindings.get(
            "predecessor_failure_evidence_file_sha256"
        ),
        "containment_canonical_sha256": bindings.get(
            "predecessor_containment_canonical_sha256"
        ),
        "containment_file_sha256": bindings.get(
            "predecessor_containment_file_sha256"
        ),
        "original_containment_file_sha256": bindings.get(
            "predecessor_original_containment_file_sha256"
        ),
        "original_containment_canonical_sha256": bindings.get(
            "predecessor_original_containment_canonical_sha256"
        ),
        "allocation_ledger_file_sha256": bindings.get(
            "predecessor_allocation_ledger_file_sha256"
        ),
        "allocation_ledger_state_sha256": bindings.get(
            "predecessor_allocation_ledger_state_sha256"
        ),
        "allocation_audit_file_sha256": bindings.get(
            "predecessor_allocation_audit_file_sha256"
        ),
    }


def _independent_validation_binding(
    authorization: Mapping[str, Any], progress: Mapping[str, Any]
) -> dict[str, Any]:
    bindings = (
        authorization.get("bindings")
        if isinstance(authorization.get("bindings"), Mapping)
        else {}
    )
    return {
        "authorization_id": authorization.get("authorization_id"),
        "campaign_nonce": bindings.get("campaign_nonce"),
        "candidate_commit": bindings.get("checkpoint_commit"),
        "candidate_tree": bindings.get("checkpoint_tree"),
        "outer_authority_id": bindings.get("outer_authority_id"),
        "receipt_canonical_sha256": progress.get(
            "independent_validation_receipt_canonical_sha256"
        ),
        "receipt_file_sha256": progress.get(
            "independent_validation_receipt_file_sha256"
        ),
        "session_id": progress.get("independent_validation_session_id"),
        "completed_at": progress.get("independent_validation_completed_at"),
    }


def _parse_utc(value: Any) -> dt.datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(dt.timezone.utc)


def _validate_historical_authorization_v4(
    value: Any,
    *,
    repo_root: Path | None = None,
) -> list[str]:
    """Validate an immutable version-4 authority under its original contract."""

    errors: list[str] = []
    authorization = _strict(
        value,
        HISTORICAL_AUTHORIZATION_FIELDS_V4,
        "historical-authorization",
        errors,
    )
    if not authorization:
        return sorted(set(errors))
    if (
        authorization.get("authorization_type") != AUTHORIZATION_TYPE
        or authorization.get("version") != 4
        or authorization.get("schema") != AUTHORIZATION_SCHEMA
    ):
        errors.append("historical-authorization-header-invalid")
    if not _is_uuid(authorization.get("authorization_id")):
        errors.append("historical-authorization-id-invalid")
    run_generation = authorization.get("run_generation")
    live_generation = authorization.get("live_generation")
    predecessor = authorization.get("predecessor_live_generation")
    if (
        not _is_int(run_generation, 1)
        or not _is_int(live_generation, 1)
        or not _is_int(predecessor, 0)
        or live_generation != predecessor + 1
    ):
        errors.append("historical-authorization-generation-invalid")
    if any(
        not isinstance(authorization.get(field), str)
        or not authorization[field].strip()
        for field in ("issued_at", "issued_by", "operator_authority")
    ) or authorization.get("initial_state") != "active":
        errors.append("historical-authorization-state-invalid")

    scope = _strict(
        authorization.get("scope"), SCOPE_FIELDS, "historical-authorization-scope", errors
    )
    if (
        any(
            not isinstance(scope.get(field), str) or not scope[field].strip()
            for field in ("epic_id", "parent_work_unit_id")
        )
        or not _strings(scope.get("ordered_work_units"))
        or len(scope.get("ordered_work_units", []))
        != len(set(scope.get("ordered_work_units", [])))
    ):
        errors.append("historical-authorization-scope-invalid")

    bindings = _strict(
        authorization.get("bindings"),
        HISTORICAL_BINDING_FIELDS_V4,
        "historical-authorization-bindings",
        errors,
    )
    for field in ("checkpoint_commit", "checkpoint_tree", "origin_main_commit"):
        if not _is_commit(bindings.get(field)):
            errors.append(f"historical-authorization-binding-{field}-invalid")
    for field in HISTORICAL_BINDING_FIELDS_V4 - {
        "checkpoint_commit",
        "checkpoint_tree",
        "origin_main_commit",
        "pickup_path",
        "recovery_plan_path",
        "campaign_nonce",
        "predecessor_authorization_id",
        "backup_ref",
    }:
        if not _is_hash(bindings.get(field)):
            errors.append(f"historical-authorization-binding-{field}-invalid")
    for field in ("campaign_nonce", "predecessor_authorization_id"):
        if not _is_uuid(bindings.get(field)):
            errors.append(f"historical-authorization-binding-{field}-invalid")
    if any(
        not isinstance(bindings.get(field), str) or not bindings[field].strip()
        for field in ("pickup_path", "recovery_plan_path", "backup_ref")
    ) or not str(bindings.get("backup_ref", "")).startswith("refs/heads/"):
        errors.append("historical-authorization-binding-path-invalid")

    supersession = _strict(
        authorization.get("supersession"),
        SUPERSESSION_FIELDS,
        "historical-authorization-supersession",
        errors,
    )
    if (
        supersession.get("prior_authorization_id")
        != bindings.get("predecessor_authorization_id")
        or supersession.get("prior_terminal_state") != "containment-only"
        or supersession.get("prior_live_generation") != predecessor
        or any(
            not _is_int(supersession.get(field), 0)
            for field in ("prior_allocations", "prior_ambiguities", "prior_allowed_actions")
        )
        or supersession.get("prior_ambiguities") != 0
        or supersession.get("prior_allowed_actions") != 0
        or supersession.get("reuse_resume_retry_substitution_salvage_bridge") is not False
    ):
        errors.append("historical-authorization-supersession-invalid")

    executors = _strict(
        authorization.get("executors"),
        EXECUTOR_FIELDS,
        "historical-authorization-executors",
        errors,
    )
    if (
        executors.get("final_architect") != "current-codex-main-thread"
        or _strict(
            executors.get("steering"),
            STEERING_EXECUTOR_FIELDS,
            "historical-authorization-steering",
            errors,
        )
        != {
            "model": EXACT_STEERING_MODEL,
            "effort": EXACT_STEERING_EFFORT,
            "surface": "codex-app-server-stdio",
            "authority": "read-only-evidence",
        }
        or _strict(
            executors.get("operative"),
            OPERATIVE_EXECUTOR_FIELDS,
            "historical-authorization-operative",
            errors,
        )
        != {
            "model": EXACT_OPERATIVE_MODEL,
            "effort": EXACT_OPERATIVE_EFFORT,
            "surface": "codex-app-server-stdio",
            "session_policy": "fresh-nonresumable-nonsalvageable",
        }
        or _strict(
            executors.get("outside_critic"),
            CRITIC_EXECUTOR_FIELDS,
            "historical-authorization-critic",
            errors,
        )
        != {
            "model": EXACT_CRITIC_MODEL,
            "effort": EXACT_CRITIC_EFFORT,
            "surface": "claude-cli-as-greg",
            "authority": "evidence-only",
        }
    ):
        errors.append("historical-authorization-executors-invalid")

    budgets = _strict(
        authorization.get("budgets"),
        HISTORICAL_BUDGET_FIELDS_V4,
        "historical-authorization-budgets",
        errors,
    )
    if any(not _is_int(budgets.get(field), 0) for field in HISTORICAL_BUDGET_FIELDS_V4):
        errors.append("historical-authorization-budgets-invalid")
    elif (
        budgets["sol_consultations_observed_before_v10"]
        + budgets["sol_consultations_added"]
        != budgets["sol_consultations_global_hard"]
        or budgets["opus_reviews_observed_before_v10"]
        + budgets["opus_reviews_added"]
        != budgets["opus_reviews_global_hard"]
        or budgets["live_generations_consumed_before_current"]
        + budgets["live_generations_remaining_exact"]
        != budgets["live_generations_global_hard"]
        or budgets["live_generations_consumed_before_current"] != predecessor
        or budgets["live_generations_remaining_exact"] != 1
        or budgets["spark_live_turn_starts_per_generation_exact"] != len(EXPECTED_ROLES)
        or budgets["spark_compactions_hard"] != 0
        or budgets["primary_checkout_mutations_hard"] != 0
        or budgets["full_repository_suites_observed_before_v10"]
        + budgets["full_repository_suites_added"]
        != budgets["full_repository_suites_global_hard"]
    ):
        errors.append("historical-authorization-budget-arithmetic-invalid")

    gates = _strict(
        authorization.get("mandatory_gates"),
        HISTORICAL_MANDATORY_GATE_FIELDS_V4,
        "historical-authorization-mandatory-gates",
        errors,
    )
    persistence = _strict(
        authorization.get("persistence"),
        PERSISTENCE_FIELDS,
        "historical-authorization-persistence",
        errors,
    )
    forbidden = _strict(
        authorization.get("forbidden"),
        HISTORICAL_FORBIDDEN_FIELDS_V4,
        "historical-authorization-forbidden",
        errors,
    )
    relaunch = _strict(
        authorization.get("live_relaunch_rule"),
        RELAUNCH_FIELDS,
        "historical-authorization-live-relaunch",
        errors,
    )
    release = _strict(
        authorization.get("release"),
        AUTHORIZATION_RELEASE_FIELDS,
        "historical-authorization-release",
        errors,
    )
    if any(gates.get(field) is not True for field in HISTORICAL_MANDATORY_GATE_FIELDS_V4):
        errors.append("historical-authorization-mandatory-gate-disabled")
    if (
        persistence.get("combined_confidence_formula")
        != "min(main,sol) when sol-used else main"
        or persistence.get("combined_confidence_minimum") != 0.5
        or persistence.get("run_level_full_auto_survives_recoverable_failure") is not True
        or persistence.get("operator_recheck_required_for_routine_recovery") is not False
        or persistence.get("evidence_bearing_live_failure_becomes_terminal") is not True
        or persistence.get(
            "fresh_successor_requires_new_authorization_id_nonce_receipts_sessions_and_paths"
        )
        is not True
        or not _strings(persistence.get("operator_stop_conditions"))
    ):
        errors.append("historical-authorization-persistence-invalid")
    if any(forbidden.get(field) is not True for field in HISTORICAL_FORBIDDEN_FIELDS_V4):
        errors.append("historical-authorization-forbidden-invalid")
    if relaunch.get("pre_rpc_zero_artifact_relaunch_max") != 1 or any(
        relaunch.get(field) is not True
        for field in RELAUNCH_FIELDS - {"pre_rpc_zero_artifact_relaunch_max"}
    ):
        errors.append("historical-authorization-live-relaunch-invalid")
    if (
        release.get("authorized_only_after_accepting_live_evidence_and_main_go") is not True
        or release.get("frozen_delta_required") is not True
        or release.get("version_remains") != "0.2.0-dev"
        or release.get("tag_or_github_release") is not False
        or not _strings(release.get("actions_after_gate"))
    ):
        errors.append("historical-authorization-release-invalid")
    if authorization.get("canonical_authorization_sha256") != _canonical_artifact_hash(
        authorization, "canonical_authorization_sha256"
    ):
        errors.append("historical-authorization-canonical-sha256-mismatch")

    if repo_root is not None and not errors:
        root = Path(repo_root).resolve()
        try:
            checkpoint = str(bindings["checkpoint_commit"])
            if _run_git(root, "rev-parse", f"{checkpoint}^{{tree}}") != bindings[
                "checkpoint_tree"
            ]:
                errors.append("historical-authorization-checkpoint-tree-mismatch")
            if _run_git(root, "rev-parse", "origin/main") != bindings["origin_main_commit"]:
                errors.append("historical-authorization-origin-main-mismatch")
        except subprocess.CalledProcessError:
            errors.append("historical-authorization-repository-binding-invalid")
    return sorted(set(errors))


def _validate_historical_manifest_v1(
    value: Any,
    *,
    authorization: Mapping[str, Any],
    authorization_raw_sha256: str,
    repo_root: Path | None = None,
) -> list[str]:
    """Validate a version-1 manifest and its complete version-4 authority binding."""

    errors = [
        f"manifest-authorization:{item}"
        for item in _validate_historical_authorization_v4(
            authorization, repo_root=repo_root
        )
    ]
    manifest = _strict(
        value,
        HISTORICAL_MANIFEST_FIELDS_V1,
        "historical-manifest",
        errors,
    )
    if not manifest:
        return sorted(set(errors))
    if (
        manifest.get("manifest_type") != MANIFEST_TYPE
        or manifest.get("version") != 1
        or manifest.get("schema") != MANIFEST_SCHEMA
    ):
        errors.append("historical-manifest-header-invalid")
    if any(
        not _is_uuid(manifest.get(field))
        for field in ("manifest_id", "authorization_id", "campaign_nonce")
    ) or any(
        not _is_hash(manifest.get(field))
        for field in ("authorization_raw_sha256", "authorization_canonical_sha256")
    ):
        errors.append("historical-manifest-identity-invalid")
    live_generation = manifest.get("live_generation")
    predecessor = manifest.get("predecessor_live_generation")
    if (
        not isinstance(manifest.get("created_at"), str)
        or not manifest["created_at"].strip()
        or not isinstance(manifest.get("control_turn_id"), str)
        or not manifest["control_turn_id"].strip()
        or not _is_int(manifest.get("run_generation"), 1)
        or not _is_int(live_generation, 1)
        or not _is_int(predecessor, 0)
        or live_generation != predecessor + 1
    ):
        errors.append("historical-manifest-state-invalid")
    work_units = _strict(
        manifest.get("work_units"),
        MANIFEST_WORK_UNIT_FIELDS,
        "historical-manifest-work-units",
        errors,
    )
    if any(
        not isinstance(work_units.get(field), str) or not work_units[field].strip()
        for field in MANIFEST_WORK_UNIT_FIELDS
    ):
        errors.append("historical-manifest-work-units-invalid")
    candidate = _strict(
        manifest.get("candidate"),
        MANIFEST_CANDIDATE_FIELDS,
        "historical-manifest-candidate",
        errors,
    )
    if any(
        not _is_commit(candidate.get(field))
        for field in ("commit", "tree", "origin_main_commit")
    ) or not _is_hash(candidate.get("guarded_primary_diff_sha256")):
        errors.append("historical-manifest-candidate-invalid")
    predecessor_value = _strict(
        manifest.get("predecessor"),
        HISTORICAL_MANIFEST_PREDECESSOR_FIELDS_V1,
        "historical-manifest-predecessor",
        errors,
    )
    if not _is_uuid(predecessor_value.get("authorization_id")) or any(
        not _is_hash(predecessor_value.get(field))
        for field in (
            "failure_evidence_canonical_sha256",
            "containment_canonical_sha256",
        )
    ):
        errors.append("historical-manifest-predecessor-invalid")
    executors = _strict(
        manifest.get("executors"),
        EXECUTOR_FIELDS,
        "historical-manifest-executors",
        errors,
    )
    if (
        executors.get("final_architect") != "current-codex-main-thread"
        or _strict(executors.get("steering"), STEERING_EXECUTOR_FIELDS, "historical-manifest-steering", errors)
        != {
            "model": EXACT_STEERING_MODEL,
            "effort": EXACT_STEERING_EFFORT,
            "surface": "codex-app-server-stdio",
            "authority": "read-only-evidence",
        }
        or _strict(executors.get("operative"), OPERATIVE_EXECUTOR_FIELDS, "historical-manifest-operative", errors)
        != {
            "model": EXACT_OPERATIVE_MODEL,
            "effort": EXACT_OPERATIVE_EFFORT,
            "surface": "codex-app-server-stdio",
            "session_policy": "fresh-nonresumable-nonsalvageable",
        }
        or _strict(executors.get("outside_critic"), CRITIC_EXECUTOR_FIELDS, "historical-manifest-critic", errors)
        != {
            "model": EXACT_CRITIC_MODEL,
            "effort": EXACT_CRITIC_EFFORT,
            "surface": "claude-cli-as-greg",
            "authority": "evidence-only",
        }
    ):
        errors.append("historical-manifest-executors-invalid")
    reviews = _strict(
        manifest.get("reviews"),
        HISTORICAL_MANIFEST_REVIEW_FIELDS_V1,
        "historical-manifest-reviews",
        errors,
    )
    release = _strict(
        manifest.get("release"),
        MANIFEST_RELEASE_FIELDS,
        "historical-manifest-release",
        errors,
    )
    before = _strict(
        release.get("policy_before"),
        MANIFEST_POLICY_FIELDS,
        "historical-manifest-policy-before",
        errors,
    )
    after = _strict(
        release.get("policy_after"),
        MANIFEST_POLICY_FIELDS,
        "historical-manifest-policy-after",
        errors,
    )
    outputs = _strict(
        manifest.get("outputs"),
        MANIFEST_OUTPUT_FIELDS,
        "historical-manifest-outputs",
        errors,
    )
    if (
        manifest.get("expected_roles") != list(EXPECTED_ROLES)
        or manifest.get("successful_turn_starts_exact") != len(EXPECTED_ROLES)
        or manifest.get("prestart_zero_artifact_relaunch_max") != 1
        or any(not _is_hash(reviews.get(field)) for field in HISTORICAL_MANIFEST_REVIEW_FIELDS_V1)
        or not _is_hash(release.get("patch_file_sha256"))
        or any(not _is_commit(release.get(field)) for field in ("candidate_tree", "prospective_tree"))
        or before != {"status": "canary-gated", "cap_two_operative_release": False}
        or after != {"status": "operative-authorized", "cap_two_operative_release": True}
        or release.get("candidate_tree") != candidate.get("tree")
        or manifest.get("no_resume_or_salvage") is not True
        or manifest.get("glm_5_2_used") is not False
        or manifest.get("model_synthesis_used") is not False
    ):
        errors.append("historical-manifest-policy-invalid")
    output_values = list(outputs.values())
    if any(
        not isinstance(item, str)
        or not item
        or Path(item).name != item
        or item in {".", ".."}
        for item in output_values
    ) or len(output_values) != len(set(output_values)):
        errors.append("historical-manifest-outputs-invalid")
    if manifest.get("manifest_sha256") != _canonical_artifact_hash(
        manifest, "manifest_sha256"
    ):
        errors.append("historical-manifest-canonical-sha256-mismatch")

    bindings = authorization.get("bindings") if isinstance(authorization.get("bindings"), Mapping) else {}
    scope = authorization.get("scope") if isinstance(authorization.get("scope"), Mapping) else {}
    if (
        manifest.get("authorization_id") != authorization.get("authorization_id")
        or manifest.get("authorization_raw_sha256") != authorization_raw_sha256
        or manifest.get("authorization_canonical_sha256")
        != authorization.get("canonical_authorization_sha256")
        or manifest.get("run_generation") != authorization.get("run_generation")
        or manifest.get("live_generation") != authorization.get("live_generation")
        or manifest.get("predecessor_live_generation")
        != authorization.get("predecessor_live_generation")
        or manifest.get("campaign_nonce") != bindings.get("campaign_nonce")
        or work_units.get("epic_id") != scope.get("epic_id")
        or work_units.get("parent_work_unit_id") != scope.get("parent_work_unit_id")
        or work_units.get("live_work_unit_id") not in scope.get("ordered_work_units", [])
        or candidate.get("origin_main_commit") != bindings.get("origin_main_commit")
        or candidate.get("guarded_primary_diff_sha256")
        != bindings.get("guarded_primary_diff_sha256")
        or predecessor_value
        != {
            "authorization_id": bindings.get("predecessor_authorization_id"),
            "failure_evidence_canonical_sha256": bindings.get(
                "predecessor_failure_evidence_canonical_sha256"
            ),
            "containment_canonical_sha256": bindings.get(
                "predecessor_containment_canonical_sha256"
            ),
        }
    ):
        errors.append("historical-manifest-authorization-binding-invalid")
    if repo_root is not None and not errors:
        root = Path(repo_root).resolve()
        try:
            if _run_git(root, "rev-parse", f"{candidate['commit']}^{{tree}}") != candidate[
                "tree"
            ]:
                errors.append("historical-manifest-candidate-tree-mismatch")
            if _run_git(root, "rev-parse", "origin/main") != candidate[
                "origin_main_commit"
            ]:
                errors.append("historical-manifest-origin-main-mismatch")
            if subprocess.run(
                [
                    "git",
                    "merge-base",
                    "--is-ancestor",
                    str(bindings["checkpoint_commit"]),
                    str(candidate["commit"]),
                ],
                cwd=root,
                capture_output=True,
            ).returncode != 0:
                errors.append("historical-manifest-authorization-candidate-lineage-invalid")
        except (KeyError, subprocess.CalledProcessError):
            errors.append("historical-manifest-repository-binding-invalid")
    return sorted(set(errors))


def _validate_predecessor_proof_graph(
    *,
    bindings: Mapping[str, Any],
    progress: Mapping[str, Any],
    supersession: Mapping[str, Any],
    predecessor_live_generation: int,
    predecessor_authorization: Mapping[str, Any],
    predecessor_authorization_raw_sha256: str,
    predecessor_manifest: Mapping[str, Any],
    predecessor_manifest_raw_sha256: str,
    predecessor_authorization_state: Mapping[str, Any],
    predecessor_authorization_state_raw_sha256: str,
    predecessor_failure_evidence: Mapping[str, Any],
    predecessor_failure_evidence_raw_sha256: str,
    predecessor_original_containment: Mapping[str, Any],
    predecessor_original_containment_raw_sha256: str,
    predecessor_containment: Mapping[str, Any],
    predecessor_containment_raw_sha256: str,
    predecessor_allocation_ledger: Mapping[str, Any],
    predecessor_allocation_ledger_raw_sha256: str,
    predecessor_allocation_audit_path: Path,
    predecessor_allocation_audit_raw_sha256: str,
    repo_root: Path | None,
) -> list[str]:
    """Validate the immutable predecessor evidence graph without self-assertions."""

    errors: list[str] = []
    prior_authorization = dict(predecessor_authorization)
    prior_manifest = dict(predecessor_manifest)
    prior_state = dict(predecessor_authorization_state)
    prior_failure = dict(predecessor_failure_evidence)
    original = _strict(
        predecessor_original_containment,
        ORIGINAL_CONTAINMENT_FIELDS,
        "authorization-predecessor-original-containment",
        errors,
    )
    correction = _strict(
        predecessor_containment,
        CORRECTION_CONTAINMENT_FIELDS,
        "authorization-predecessor-containment-correction",
        errors,
    )
    historical_manifest_errors = _validate_historical_manifest_v1(
        prior_manifest,
        authorization=prior_authorization,
        authorization_raw_sha256=predecessor_authorization_raw_sha256,
        repo_root=repo_root,
    )
    errors.extend(
        f"authorization-predecessor-historical-contract:{item}"
        for item in historical_manifest_errors
    )
    prior_authorization_id = prior_authorization.get("authorization_id")
    prior_authorization_canonical = prior_authorization.get(
        "canonical_authorization_sha256"
    )
    prior_manifest_canonical = prior_manifest.get("manifest_sha256")
    prior_authorization_bindings = prior_authorization.get("bindings")
    if not isinstance(prior_authorization_bindings, Mapping):
        prior_authorization_bindings = {}
    prior_nonce = prior_authorization_bindings.get("campaign_nonce")
    prior_candidate = prior_manifest.get("candidate")
    if not isinstance(prior_candidate, Mapping):
        prior_candidate = {}
    if (
        predecessor_authorization_raw_sha256
        != bindings.get("predecessor_authorization_file_sha256")
        or prior_authorization_canonical
        != bindings.get("predecessor_authorization_canonical_sha256")
        or prior_authorization_id != bindings.get("predecessor_authorization_id")
        or prior_authorization.get("live_generation") != predecessor_live_generation
        or predecessor_manifest_raw_sha256
        != bindings.get("predecessor_manifest_file_sha256")
        or prior_manifest_canonical
        != bindings.get("predecessor_manifest_canonical_sha256")
        or prior_candidate.get("commit") != progress.get("predecessor_candidate_commit")
        or prior_candidate.get("tree") != progress.get("predecessor_candidate_tree")
    ):
        errors.append("authorization-predecessor-historical-binding-invalid")

    required_revocations = {
        "install",
        "publish",
        "push",
        "relaunch",
        "release-enable",
        "replacement",
        "retry",
        "tracked-mutation",
    }
    if (
        predecessor_authorization_state_raw_sha256
        != bindings.get("predecessor_authorization_state_file_sha256")
        or prior_state.get("state_sha256")
        != bindings.get("predecessor_authorization_state_canonical_sha256")
        or validate_authorization_state(prior_state)
        or prior_state.get("authorization_id") != prior_authorization_id
        or prior_state.get("run_nonce") != prior_nonce
        or prior_state.get("state") != "containment-only"
        or not isinstance(prior_state.get("allowed_actions"), list)
        or required_revocations.intersection(prior_state.get("allowed_actions", []))
        or not required_revocations.issubset(set(prior_state.get("revoked_actions", [])))
    ):
        errors.append("authorization-predecessor-state-binding-invalid")

    try:
        ledger_errors = validate_live_allocation_ledger(
            predecessor_allocation_ledger,
            audit_file=predecessor_allocation_audit_path,
        )
    except (OSError, SystemExit, ValueError):
        ledger_errors = ["ledger-audit-unavailable"]
    if ledger_errors:
        errors.append(
            "authorization-predecessor-allocation-ledger-invalid:"
            + ",".join(ledger_errors)
        )
    if (
        predecessor_allocation_ledger_raw_sha256
        != bindings.get("predecessor_allocation_ledger_file_sha256")
        or predecessor_allocation_ledger.get("state_sha256")
        != bindings.get("predecessor_allocation_ledger_state_sha256")
        or predecessor_allocation_audit_raw_sha256
        != bindings.get("predecessor_allocation_audit_file_sha256")
    ):
        errors.append("authorization-predecessor-allocation-ledger-binding-invalid")
    entries = predecessor_allocation_ledger.get("entries")
    entries = entries if isinstance(entries, list) else []
    if (
        [entry.get("event") for entry in entries if isinstance(entry, Mapping)]
        != list(PREDECESSOR_LEDGER_EVENT_SEQUENCE)
        or [entry.get("outcome") for entry in entries if isinstance(entry, Mapping)]
        != list(PREDECESSOR_LEDGER_OUTCOME_SEQUENCE)
        or len(entries) != len(PREDECESSOR_LEDGER_EVENT_SEQUENCE)
        or any(
            not isinstance(entry, Mapping)
            or entry.get("role") != "capability-calibration"
            or entry.get("ordinal") != 0
            for entry in entries
        )
    ):
        errors.append("authorization-predecessor-allocation-ledger-sequence-invalid")
    else:
        identity_fields = (
            "allocation_intent_id",
            "thread_id",
            "turn_intent_id",
            "turn_id",
        )
        for field in identity_fields:
            non_null = {entry.get(field) for entry in entries if entry.get(field) is not None}
            if len(non_null) != 1:
                errors.append(
                    f"authorization-predecessor-allocation-ledger-{field}-invalid"
                )
    try:
        audit_records = [
            json.loads(line)
            for line in predecessor_allocation_audit_path.read_text(
                encoding="utf-8"
            ).splitlines()
            if line.strip()
        ]
    except (OSError, json.JSONDecodeError):
        audit_records = []
    if len(audit_records) != len(entries) or any(
        not isinstance(audit, Mapping)
        or not isinstance(entry, Mapping)
        or audit.get("event_type") != "native_live_allocation_ledger_entry"
        or audit.get("dispatch_id") != predecessor_allocation_ledger.get("ledger_id")
        or audit.get("packet_sha256") != entry.get("entry_sha256")
        or audit.get("phase") != entry.get("event")
        or audit.get("validation_lineage_attempt") != index
        for index, (audit, entry) in enumerate(zip(audit_records, entries), 1)
    ):
        errors.append("authorization-predecessor-allocation-audit-sequence-invalid")

    try:
        ledger_summary = summarize_live_allocation_ledger(
            predecessor_allocation_ledger,
            ledger_file_sha256=predecessor_allocation_ledger_raw_sha256,
        )
    except (KeyError, NativeLiveAllocationLedgerError, ValueError):
        ledger_summary = {}
    ledger_bindings = predecessor_allocation_ledger.get("bindings")
    if not isinstance(ledger_bindings, Mapping):
        ledger_bindings = {}
    expected_ledger_bindings = {
        "authorization_id": prior_authorization_id,
        "authorization_raw_sha256": predecessor_authorization_raw_sha256,
        "authorization_canonical_sha256": prior_authorization_canonical,
        "campaign_manifest_sha256": prior_manifest_canonical,
        "campaign_nonce": prior_nonce,
        "live_generation": predecessor_live_generation,
        "predecessor_generation": predecessor_live_generation - 1,
        "candidate_commit": prior_candidate.get("commit"),
        "candidate_tree": prior_candidate.get("tree"),
        "origin_main_commit": prior_candidate.get("origin_main_commit"),
        "guarded_primary_diff_sha256": prior_candidate.get(
            "guarded_primary_diff_sha256"
        ),
        "predecessor_containment_sha256": prior_authorization_bindings.get(
            "predecessor_containment_canonical_sha256"
        ),
        "frozen_release_patch_sha256": (
            prior_manifest.get("release", {}).get("patch_file_sha256")
            if isinstance(prior_manifest.get("release"), Mapping)
            else None
        ),
        "pre_mutation_steering_receipt_sha256": (
            prior_manifest.get("reviews", {}).get(
                "pre_mutation_receipt_canonical_sha256"
            )
            if isinstance(prior_manifest.get("reviews"), Mapping)
            else None
        ),
        "pre_live_steering_receipt_sha256": (
            prior_manifest.get("reviews", {}).get("pre_live_receipt_canonical_sha256")
            if isinstance(prior_manifest.get("reviews"), Mapping)
            else None
        ),
        "opus_review_sha256": (
            prior_manifest.get("reviews", {}).get("opus_evidence_file_sha256")
            if isinstance(prior_manifest.get("reviews"), Mapping)
            else None
        ),
    }
    if any(
        ledger_bindings.get(field) != expected
        for field, expected in expected_ledger_bindings.items()
    ):
        errors.append("authorization-predecessor-allocation-ledger-authority-mismatch")
    if supersession.get("prior_allocations") != ledger_summary.get(
        "allocation_intent_count"
    ):
        errors.append("authorization-predecessor-allocation-count-mismatch")

    failure_bindings = prior_failure.get("campaign_bindings")
    failure_containment = prior_failure.get("containment")
    if (
        predecessor_failure_evidence_raw_sha256
        != bindings.get("predecessor_failure_evidence_file_sha256")
        or prior_failure.get("evidence_sha256")
        != bindings.get("predecessor_failure_evidence_canonical_sha256")
        or prior_failure.get("evidence_sha256")
        != _canonical_artifact_hash(prior_failure, "evidence_sha256")
        or prior_failure.get("authorization_state_sha256")
        != bindings.get("predecessor_authorization_state_canonical_sha256")
        or prior_failure.get("release_gate_passed") is not False
        or prior_failure.get("validation_outcome") != "rejected"
        or prior_failure.get("allocation_ledger") != {"available": True, **ledger_summary}
        or not isinstance(failure_bindings, Mapping)
        or failure_bindings.get("authorization_raw_sha256")
        != predecessor_authorization_raw_sha256
        or failure_bindings.get("manifest_file_sha256")
        != predecessor_manifest_raw_sha256
        or failure_bindings.get("manifest_sha256") != prior_manifest_canonical
        or failure_bindings.get("candidate_commit") != prior_candidate.get("commit")
        or failure_bindings.get("candidate_tree") != prior_candidate.get("tree")
        or not isinstance(failure_containment, Mapping)
        or failure_containment.get("allocated_count")
        != ledger_summary.get("allocation_intent_count")
        or failure_containment.get("all_contained") is not True
        or failure_containment.get("ambiguous_count") != 0
        or failure_containment.get("ledger_consistent") is not True
        or failure_containment.get("unresolved_allocation_intent_count") != 0
        or failure_containment.get("unresolved_turn_intent_count") != 0
    ):
        errors.append("authorization-predecessor-failure-binding-invalid")

    original_failed_manifest = original.get("failed_manifest")
    original_failed_evidence = original.get("failed_evidence")
    original_reclassification = original.get("reclassification")
    original_control = original.get("control_plane_recheck")
    original_ledger = original.get("allocation_ledger")
    sessions = original.get("session_accounting")
    expected_original_ledger = {
        "ledger_type": ledger_summary.get("ledger_type"),
        "version": ledger_summary.get("version"),
        "ledger_id": ledger_summary.get("ledger_id"),
        "ledger_file_sha256": predecessor_allocation_ledger_raw_sha256,
        "audit_file_sha256": predecessor_allocation_audit_raw_sha256,
        "state_sha256": ledger_summary.get("state_sha256"),
        "head_entry_sha256": ledger_summary.get("head_entry_sha256"),
        "sequence": ledger_summary.get("sequence"),
        "allocation_intent_count": ledger_summary.get("allocation_intent_count"),
        "thread_bound_count": ledger_summary.get("thread_bound_count"),
        "turn_intent_count": ledger_summary.get("turn_intent_count"),
        "turn_bound_count": ledger_summary.get("turn_bound_count"),
        "unresolved_allocation_intent_count": ledger_summary.get(
            "unresolved_allocation_intent_count"
        ),
        "unresolved_turn_intent_count": ledger_summary.get(
            "unresolved_turn_intent_count"
        ),
        "validation_errors": [],
    }
    if (
        original.get("schema") != "cwo-live-canary-containment-recovery:v1"
        or predecessor_original_containment_raw_sha256
        != bindings.get("predecessor_original_containment_file_sha256")
        or original.get("canonical_recovery_sha256")
        != bindings.get("predecessor_original_containment_canonical_sha256")
        or original.get("canonical_recovery_sha256")
        != _canonical_artifact_hash(original, "canonical_recovery_sha256")
        or not isinstance(original.get("failed_authorization_id"), str)
        or _is_uuid(original.get("failed_authorization_id"))
        or original.get("failed_campaign_nonce") != prior_nonce
        or not isinstance(original_failed_manifest, Mapping)
        or original_failed_manifest.get("file_sha256")
        != predecessor_manifest_raw_sha256
        or original_failed_manifest.get("canonical_sha256") != prior_manifest_canonical
        or original_failed_manifest.get("live_generation") != predecessor_live_generation
        or not isinstance(original_failed_evidence, Mapping)
        or original_failed_evidence.get("file_sha256")
        != predecessor_failure_evidence_raw_sha256
        or original_failed_evidence.get("canonical_sha256")
        != prior_failure.get("evidence_sha256")
        or original_failed_evidence.get("authorization_state_file_sha256")
        != predecessor_authorization_state_raw_sha256
        or original_failed_evidence.get("authorization_state_canonical_sha256")
        != prior_state.get("state_sha256")
        or original_ledger != expected_original_ledger
        or not isinstance(sessions, list)
        or len(sessions) != 1
        or not isinstance(sessions[0], Mapping)
        or sessions[0].get("role") != "capability-calibration"
        or not isinstance(original_reclassification, Mapping)
        or original_reclassification.get("allocated_count") != 1
        or original_reclassification.get("calibration_turns_started") != 1
        or original_reclassification.get("pool_turns_started") != 0
        or original_reclassification.get("pool_tool_calls") != 0
        or original_reclassification.get("contained_count") != 1
        or original_reclassification.get("ambiguous_count") != 0
        or original_reclassification.get("all_contained") is not True
        or original_reclassification.get("release_gate_passed") is not False
        or original_reclassification.get("failed_authorization_terminal") is not True
        or original_reclassification.get(
            "reuse_resume_retry_substitution_salvage_bridge"
        )
        is not False
        or not isinstance(original_control, Mapping)
        or original_control.get("protected_primary_diff_sha256")
        != prior_candidate.get("guarded_primary_diff_sha256")
        or original_control.get("isolated_checkout_head")
        != prior_candidate.get("commit")
        or original_control.get("isolated_checkout_tree") != prior_candidate.get("tree")
        or original_control.get("origin_main_commit")
        != prior_candidate.get("origin_main_commit")
        or original_control.get("isolated_checkout_tracked_clean") is not True
        or original_control.get("release_policy_status") != "canary-gated"
        or original_control.get("operative_dispatch_authorized") is not False
    ):
        errors.append("authorization-predecessor-original-containment-binding-invalid")

    correction_detail = _strict(
        correction.get("correction"),
        CORRECTION_DETAIL_FIELDS,
        "authorization-predecessor-containment-correction-detail",
        errors,
    )
    identity_authority = _strict(
        correction_detail.get("identity_authority"),
        CORRECTION_IDENTITY_AUTHORITY_FIELDS,
        "authorization-predecessor-containment-correction-authority",
        errors,
    )
    correction_failed_evidence = _strict(
        correction.get("failed_evidence"),
        CORRECTION_FAILED_EVIDENCE_FIELDS,
        "authorization-predecessor-containment-correction-evidence",
        errors,
    )
    correction_reclassification = _strict(
        correction.get("reclassification"),
        CORRECTION_RECLASSIFICATION_FIELDS,
        "authorization-predecessor-containment-correction-reclassification",
        errors,
    )
    correction_control = _strict(
        correction.get("control_plane_recheck"),
        CORRECTION_CONTROL_FIELDS,
        "authorization-predecessor-containment-correction-control",
        errors,
    )
    if (
        correction.get("schema") != "cwo-live-containment-identity-correction:v1"
        or predecessor_containment_raw_sha256
        != bindings.get("predecessor_containment_file_sha256")
        or correction.get("canonical_recovery_sha256")
        != bindings.get("predecessor_containment_canonical_sha256")
        or correction.get("canonical_recovery_sha256")
        != _canonical_artifact_hash(correction, "canonical_recovery_sha256")
        or correction.get("failed_authorization_id") != prior_authorization_id
        or correction.get("failed_campaign_nonce") != prior_nonce
        or correction_detail.get("kind")
        != "legacy-containment-identifier-length-correction"
        or correction_detail.get("original_artifact_file_sha256")
        != predecessor_original_containment_raw_sha256
        or correction_detail.get("original_artifact_canonical_sha256")
        != original.get("canonical_recovery_sha256")
        or correction_detail.get("original_recorded_authorization_id")
        != original.get("failed_authorization_id")
        or correction_detail.get("corrected_authorization_id") != prior_authorization_id
        or identity_authority
        != {
            "authorization_file_sha256": predecessor_authorization_raw_sha256,
            "authorization_canonical_sha256": prior_authorization_canonical,
            "manifest_file_sha256": predecessor_manifest_raw_sha256,
            "manifest_canonical_sha256": prior_manifest_canonical,
            "authorization_state_file_sha256": predecessor_authorization_state_raw_sha256,
            "authorization_state_canonical_sha256": prior_state.get("state_sha256"),
            "failure_evidence_file_sha256": predecessor_failure_evidence_raw_sha256,
            "failure_evidence_canonical_sha256": prior_failure.get("evidence_sha256"),
        }
        or correction_detail.get("evidence_or_disposition_changed") is not False
        or correction_detail.get("main_architect_disposition")
        != "correct identifier transcription only; preserve terminal containment and all original evidence hashes"
        or not isinstance(correction_failed_evidence, Mapping)
        or dict(correction_failed_evidence)
        != {
            field: original_failed_evidence.get(field)
            for field in correction_failed_evidence
        }
        or not isinstance(correction_reclassification, Mapping)
        or dict(correction_reclassification)
        != {
            field: original_reclassification.get(field)
            for field in correction_reclassification
        }
        or not isinstance(correction_control, Mapping)
        or dict(correction_control)
        != {field: original_control.get(field) for field in correction_control}
    ):
        errors.append("authorization-predecessor-containment-correction-binding-invalid")
    return sorted(set(errors))


def validate_full_auto_authorization(
    value: Any,
    *,
    expected_campaign_nonce: str | None = None,
    predecessor_authorization: Mapping[str, Any] | None = None,
    predecessor_authorization_raw_sha256: str | None = None,
    predecessor_manifest: Mapping[str, Any] | None = None,
    predecessor_manifest_raw_sha256: str | None = None,
    predecessor_authorization_state: Mapping[str, Any] | None = None,
    predecessor_authorization_state_raw_sha256: str | None = None,
    predecessor_failure_evidence: Mapping[str, Any] | None = None,
    predecessor_failure_evidence_raw_sha256: str | None = None,
    predecessor_original_containment: Mapping[str, Any] | None = None,
    predecessor_original_containment_raw_sha256: str | None = None,
    predecessor_containment: Mapping[str, Any] | None = None,
    predecessor_containment_raw_sha256: str | None = None,
    predecessor_allocation_ledger: Mapping[str, Any] | None = None,
    predecessor_allocation_ledger_raw_sha256: str | None = None,
    predecessor_allocation_audit_path: Path | None = None,
    predecessor_allocation_audit_raw_sha256: str | None = None,
    cause_evidence: bytes | None = None,
    repo_root: Path | None = None,
) -> list[str]:
    errors: list[str] = []
    authorization = _strict(value, AUTHORIZATION_FIELDS, "authorization", errors)
    if not authorization:
        return sorted(set(errors))
    if (
        authorization.get("authorization_type") != AUTHORIZATION_TYPE
        or authorization.get("version") != AUTHORIZATION_VERSION
        or authorization.get("schema") != AUTHORIZATION_SCHEMA
    ):
        errors.append("authorization-header-invalid")
    if not _is_uuid(authorization.get("authorization_id")):
        errors.append("authorization-id-invalid")
    run_generation = authorization.get("run_generation")
    live_generation = authorization.get("live_generation")
    predecessor = authorization.get("predecessor_live_generation")
    if not _is_int(run_generation, 1):
        errors.append("authorization-run-generation-invalid")
    if not _is_int(live_generation, 1) or not _is_int(predecessor, 0):
        errors.append("authorization-live-generation-invalid")
    elif live_generation != predecessor + 1:
        errors.append("authorization-live-generation-not-successor")
    for field in ("issued_at", "issued_by", "operator_authority"):
        if not isinstance(authorization.get(field), str) or not authorization[field].strip():
            errors.append(f"authorization-{field.replace('_', '-')}-invalid")
    if authorization.get("initial_state") != "active":
        errors.append("authorization-initial-state-invalid")

    scope = _strict(authorization.get("scope"), SCOPE_FIELDS, "authorization-scope", errors)
    if not all(isinstance(scope.get(field), str) and scope[field].strip() for field in ("epic_id", "parent_work_unit_id")):
        errors.append("authorization-scope-identity-invalid")
    ordered = scope.get("ordered_work_units")
    if not _strings(ordered) or len(ordered) != len(set(ordered or [])):
        errors.append("authorization-scope-work-units-invalid")

    bindings = _strict(
        authorization.get("bindings"), BINDING_FIELDS, "authorization-bindings", errors
    )
    for field in ("checkpoint_commit", "checkpoint_tree", "origin_main_commit"):
        if not _is_commit(bindings.get(field)):
            errors.append(f"authorization-binding-{field.replace('_', '-')}-invalid")
    for field in (
        "guarded_primary_diff_sha256",
        "pickup_sha256",
        "recovery_plan_sha256",
        "outer_authority_canonical_sha256",
        "outer_authority_file_sha256",
        "predecessor_authorization_file_sha256",
        "predecessor_authorization_canonical_sha256",
        "predecessor_manifest_file_sha256",
        "predecessor_manifest_canonical_sha256",
        "predecessor_authorization_state_file_sha256",
        "predecessor_authorization_state_canonical_sha256",
        "predecessor_failure_evidence_file_sha256",
        "predecessor_failure_evidence_canonical_sha256",
        "predecessor_containment_file_sha256",
        "predecessor_containment_canonical_sha256",
        "predecessor_original_containment_file_sha256",
        "predecessor_original_containment_canonical_sha256",
        "predecessor_allocation_ledger_file_sha256",
        "predecessor_allocation_ledger_state_sha256",
        "predecessor_allocation_audit_file_sha256",
    ):
        if not _is_hash(bindings.get(field)):
            errors.append(f"authorization-binding-{field.replace('_', '-')}-invalid")
    for field in (
        "campaign_nonce",
        "predecessor_authorization_id",
        "outer_authority_id",
    ):
        if not _is_uuid(bindings.get(field)):
            errors.append(f"authorization-binding-{field.replace('_', '-')}-invalid")
    if expected_campaign_nonce is not None and bindings.get("campaign_nonce") != expected_campaign_nonce:
        errors.append("authorization-campaign-nonce-mismatch")
    if authorization.get("authorization_id") in {
        bindings.get("predecessor_authorization_id"),
        bindings.get("outer_authority_id"),
    }:
        errors.append("authorization-identity-reuse-invalid")
    for field in ("pickup_path", "recovery_plan_path", "backup_ref"):
        item = bindings.get(field)
        if not isinstance(item, str) or not item.strip():
            errors.append(f"authorization-binding-{field.replace('_', '-')}-invalid")
    backup_ref = bindings.get("backup_ref")
    if not isinstance(backup_ref, str) or not backup_ref.startswith("refs/heads/"):
        errors.append("authorization-binding-backup-ref-invalid")

    supersession = _strict(
        authorization.get("supersession"),
        SUPERSESSION_FIELDS,
        "authorization-supersession",
        errors,
    )
    if supersession.get("prior_authorization_id") != bindings.get("predecessor_authorization_id"):
        errors.append("authorization-supersession-id-mismatch")
    if supersession.get("prior_terminal_state") != "containment-only":
        errors.append("authorization-supersession-state-invalid")
    if supersession.get("prior_live_generation") != predecessor:
        errors.append("authorization-supersession-generation-mismatch")
    for field in ("prior_allocations", "prior_ambiguities", "prior_allowed_actions"):
        if not _is_int(supersession.get(field), 0):
            errors.append(f"authorization-supersession-{field.replace('_', '-')}-invalid")
    if supersession.get("prior_ambiguities") != 0 or supersession.get("prior_allowed_actions") != 0:
        errors.append("authorization-supersession-not-terminal")
    if supersession.get("reuse_resume_retry_substitution_salvage_bridge") is not False:
        errors.append("authorization-supersession-reuse-invalid")

    executors = _strict(
        authorization.get("executors"), EXECUTOR_FIELDS, "authorization-executors", errors
    )
    steering = _strict(
        executors.get("steering"),
        STEERING_EXECUTOR_FIELDS,
        "authorization-steering-executor",
        errors,
    )
    operative = _strict(
        executors.get("operative"),
        OPERATIVE_EXECUTOR_FIELDS,
        "authorization-operative-executor",
        errors,
    )
    critic = _strict(
        executors.get("outside_critic"),
        CRITIC_EXECUTOR_FIELDS,
        "authorization-critic-executor",
        errors,
    )
    if executors.get("final_architect") != "current-codex-main-thread":
        errors.append("authorization-final-architect-invalid")
    if steering != {
        "model": EXACT_STEERING_MODEL,
        "effort": EXACT_STEERING_EFFORT,
        "surface": "codex-app-server-stdio",
        "authority": "read-only-evidence",
    }:
        errors.append("authorization-steering-executor-invalid")
    if operative != {
        "model": EXACT_OPERATIVE_MODEL,
        "effort": EXACT_OPERATIVE_EFFORT,
        "surface": "codex-app-server-stdio",
        "session_policy": "fresh-nonresumable-nonsalvageable",
    }:
        errors.append("authorization-operative-executor-invalid")
    if critic != {
        "model": EXACT_CRITIC_MODEL,
        "effort": EXACT_CRITIC_EFFORT,
        "surface": "claude-cli-as-greg",
        "authority": "evidence-only",
    }:
        errors.append("authorization-critic-executor-invalid")

    resource_limits = _strict(
        authorization.get("resource_limits"),
        RESOURCE_LIMIT_FIELDS,
        "authorization-resource-limits",
        errors,
    )
    if any(
        not _is_int(resource_limits.get(field), 0)
        for field in RESOURCE_LIMIT_FIELDS
    ):
        errors.append("authorization-resource-limit-value-invalid")
    else:
        if resource_limits["sol_consultations_this_inner_hard"] < 2:
            errors.append("authorization-sol-resource-limit-invalid")
        if resource_limits["spark_validation_sessions_this_inner_hard"] < 1:
            errors.append("authorization-spark-validation-resource-limit-invalid")
        if resource_limits["spark_live_turn_starts_exact"] != len(EXPECTED_ROLES):
            errors.append("authorization-live-turn-resource-limit-invalid")
        if (
            resource_limits["spark_compactions_hard"] != 0
            or resource_limits["primary_checkout_mutations_hard"] != 0
        ):
            errors.append("authorization-protected-resource-limit-invalid")
        if (
            resource_limits["full_repository_suites_this_inner_hard"] < 1
            or resource_limits["focused_validation_bundles_this_inner_hard"] < 1
        ):
            errors.append("authorization-validation-resource-limit-invalid")

    progress = _strict(
        authorization.get("progress_gate"),
        PROGRESS_GATE_FIELDS,
        "authorization-progress-gate",
        errors,
    )
    if progress.get("outer_authority_status") != "active":
        errors.append("authorization-progress-outer-authority-not-active")
    if progress.get("qualification_basis") not in {
        "new-fault-class",
        "same-fault-with-new-evidence-and-validated-repair",
    }:
        errors.append("authorization-progress-qualification-basis-invalid")
    for field in ("predecessor_failure_class", "new_falsifiable_cause"):
        if not isinstance(progress.get(field), str) or not progress[field].strip():
            errors.append(f"authorization-progress-{field.replace('_', '-')}-invalid")
    for field in (
        "predecessor_failure_evidence_canonical_sha256",
        "cause_evidence_sha256",
        "predecessor_lineage_sha256",
        "independent_validation_receipt_canonical_sha256",
        "independent_validation_receipt_file_sha256",
        "independent_validation_binding_sha256",
    ):
        if not _is_hash(progress.get(field)):
            errors.append(f"authorization-progress-{field.replace('_', '-')}-invalid")
    for field in ("repair_commit", "repair_tree"):
        if not _is_commit(progress.get(field)):
            errors.append(f"authorization-progress-{field.replace('_', '-')}-invalid")
    for field in ("predecessor_candidate_commit", "predecessor_candidate_tree"):
        if not _is_commit(progress.get(field)):
            errors.append(f"authorization-progress-{field.replace('_', '-')}-invalid")
    if not _is_uuid(progress.get("independent_validation_session_id")):
        errors.append("authorization-progress-independent-validation-session-id-invalid")
    if _parse_utc(progress.get("independent_validation_completed_at")) is None:
        errors.append("authorization-progress-independent-validation-completed-at-invalid")
    if progress.get("predecessor_failure_evidence_canonical_sha256") != bindings.get(
        "predecessor_failure_evidence_canonical_sha256"
    ):
        errors.append("authorization-progress-predecessor-evidence-mismatch")
    if (
        progress.get("repair_commit") != bindings.get("checkpoint_commit")
        or progress.get("repair_tree") != bindings.get("checkpoint_tree")
    ):
        errors.append("authorization-progress-repair-checkpoint-mismatch")
    if (
        progress.get("repair_commit") == progress.get("predecessor_candidate_commit")
        or progress.get("repair_tree") == progress.get("predecessor_candidate_tree")
        or progress.get("cause_evidence_sha256")
        == progress.get("predecessor_failure_evidence_canonical_sha256")
    ):
        errors.append("authorization-progress-new-evidence-or-repair-missing")
    predecessor_lineage = _predecessor_lineage(bindings, progress, predecessor)
    if progress.get("predecessor_lineage_sha256") != canonical_sha256(
        predecessor_lineage
    ):
        errors.append("authorization-progress-predecessor-lineage-sha256-mismatch")
    if progress.get("independent_validation_binding_sha256") != canonical_sha256(
        _independent_validation_binding(authorization, progress)
    ):
        errors.append("authorization-progress-independent-validation-binding-sha256-mismatch")
    if any(
        progress.get(field) is not expected
        for field, expected in (
            ("same_fault_without_new_evidence", False),
            ("one_active_inner_campaign", True),
            ("arbitrary_generation_cap", False),
            ("fresh_exact_sol_pre_live_required", True),
        )
    ):
        errors.append("authorization-progress-containment-policy-invalid")
    qualification_hash = progress.get("qualification_sha256")
    unsigned_progress = dict(progress)
    unsigned_progress.pop("qualification_sha256", None)
    if not _is_hash(qualification_hash) or qualification_hash != canonical_sha256(
        unsigned_progress
    ):
        errors.append("authorization-progress-qualification-sha256-mismatch")

    gates = _strict(
        authorization.get("mandatory_gates"),
        MANDATORY_GATE_FIELDS,
        "authorization-mandatory-gates",
        errors,
    )
    if any(gates.get(field) is not True for field in MANDATORY_GATE_FIELDS):
        errors.append("authorization-mandatory-gate-disabled")
    persistence = _strict(
        authorization.get("persistence"),
        PERSISTENCE_FIELDS,
        "authorization-persistence",
        errors,
    )
    if persistence.get("combined_confidence_formula") != "min(main,sol) when sol-used else main" or persistence.get("combined_confidence_minimum") != 0.5:
        errors.append("authorization-confidence-policy-invalid")
    if any(
        persistence.get(field) is not expected
        for field, expected in (
            ("run_level_full_auto_survives_recoverable_failure", True),
            ("operator_recheck_required_for_routine_recovery", False),
            ("evidence_bearing_live_failure_becomes_terminal", True),
            ("fresh_successor_requires_new_authorization_id_nonce_receipts_sessions_and_paths", True),
        )
    ) or not _strings(persistence.get("operator_stop_conditions")):
        errors.append("authorization-persistence-policy-invalid")
    forbidden = _strict(
        authorization.get("forbidden"), FORBIDDEN_FIELDS, "authorization-forbidden", errors
    )
    if any(forbidden.get(field) is not True for field in FORBIDDEN_FIELDS):
        errors.append("authorization-forbidden-policy-invalid")
    relaunch = _strict(
        authorization.get("live_relaunch_rule"),
        RELAUNCH_FIELDS,
        "authorization-live-relaunch",
        errors,
    )
    if relaunch.get("pre_rpc_zero_artifact_relaunch_max") != 1 or any(
        relaunch.get(field) is not True for field in RELAUNCH_FIELDS - {"pre_rpc_zero_artifact_relaunch_max"}
    ):
        errors.append("authorization-live-relaunch-policy-invalid")
    release = _strict(
        authorization.get("release"),
        AUTHORIZATION_RELEASE_FIELDS,
        "authorization-release",
        errors,
    )
    if (
        release.get("authorized_only_after_accepting_live_evidence_and_main_go") is not True
        or release.get("frozen_delta_required") is not True
        or release.get("version_remains") != "0.2.0-dev"
        or release.get("tag_or_github_release") is not False
        or not _strings(release.get("actions_after_gate"))
    ):
        errors.append("authorization-release-policy-invalid")

    recorded_hash = authorization.get("canonical_authorization_sha256")
    unsigned = dict(authorization)
    unsigned.pop("canonical_authorization_sha256", None)
    if not _is_hash(recorded_hash) or recorded_hash != canonical_sha256(unsigned):
        errors.append("authorization-canonical-sha256-mismatch")

    predecessor_artifacts = (
        predecessor_authorization,
        predecessor_authorization_raw_sha256,
        predecessor_manifest,
        predecessor_manifest_raw_sha256,
        predecessor_authorization_state,
        predecessor_authorization_state_raw_sha256,
        predecessor_failure_evidence,
        predecessor_failure_evidence_raw_sha256,
        predecessor_original_containment,
        predecessor_original_containment_raw_sha256,
        predecessor_containment,
        predecessor_containment_raw_sha256,
        predecessor_allocation_ledger,
        predecessor_allocation_ledger_raw_sha256,
        predecessor_allocation_audit_path,
        predecessor_allocation_audit_raw_sha256,
        cause_evidence,
    )
    if any(item is not None for item in predecessor_artifacts):
        if any(item is None for item in predecessor_artifacts):
            errors.append("authorization-predecessor-artifacts-incomplete")
        else:
            errors.extend(
                _validate_predecessor_proof_graph(
                    bindings=bindings,
                    progress=progress,
                    supersession=supersession,
                    predecessor_live_generation=int(predecessor),
                    predecessor_authorization=predecessor_authorization or {},
                    predecessor_authorization_raw_sha256=str(
                        predecessor_authorization_raw_sha256
                    ),
                    predecessor_manifest=predecessor_manifest or {},
                    predecessor_manifest_raw_sha256=str(
                        predecessor_manifest_raw_sha256
                    ),
                    predecessor_authorization_state=predecessor_authorization_state
                    or {},
                    predecessor_authorization_state_raw_sha256=str(
                        predecessor_authorization_state_raw_sha256
                    ),
                    predecessor_failure_evidence=predecessor_failure_evidence or {},
                    predecessor_failure_evidence_raw_sha256=str(
                        predecessor_failure_evidence_raw_sha256
                    ),
                    predecessor_original_containment=predecessor_original_containment
                    or {},
                    predecessor_original_containment_raw_sha256=str(
                        predecessor_original_containment_raw_sha256
                    ),
                    predecessor_containment=predecessor_containment or {},
                    predecessor_containment_raw_sha256=str(
                        predecessor_containment_raw_sha256
                    ),
                    predecessor_allocation_ledger=predecessor_allocation_ledger or {},
                    predecessor_allocation_ledger_raw_sha256=str(
                        predecessor_allocation_ledger_raw_sha256
                    ),
                    predecessor_allocation_audit_path=Path(
                        predecessor_allocation_audit_path
                    ),
                    predecessor_allocation_audit_raw_sha256=str(
                        predecessor_allocation_audit_raw_sha256
                    ),
                    repo_root=repo_root,
                )
            )
            if (
                not isinstance(cause_evidence, bytes)
                or not cause_evidence
                or hashlib.sha256(cause_evidence).hexdigest()
                != progress.get("cause_evidence_sha256")
            ):
                errors.append("authorization-progress-cause-evidence-binding-invalid")
    if repo_root is not None and not errors:
        root = Path(repo_root).resolve()
        try:
            checkpoint = str(bindings["checkpoint_commit"])
            if _run_git(root, "rev-parse", f"{checkpoint}^{{tree}}") != bindings["checkpoint_tree"]:
                errors.append("authorization-checkpoint-tree-mismatch")
            head = _run_git(root, "rev-parse", "HEAD")
            if head != checkpoint:
                errors.append("authorization-checkpoint-not-head")
            predecessor_commit = str(progress["predecessor_candidate_commit"])
            if (
                _run_git(root, "rev-parse", f"{predecessor_commit}^{{tree}}")
                != progress["predecessor_candidate_tree"]
            ):
                errors.append("authorization-progress-predecessor-tree-mismatch")
            predecessor_ancestor = subprocess.run(
                ["git", "merge-base", "--is-ancestor", predecessor_commit, checkpoint],
                cwd=root,
                capture_output=True,
            )
            if predecessor_ancestor.returncode != 0:
                errors.append("authorization-progress-repair-lineage-invalid")
            if _run_git(root, "status", "--porcelain=v1", "--untracked-files=no"):
                errors.append("authorization-repository-not-clean")
            if _run_git(root, "rev-parse", "origin/main") != bindings["origin_main_commit"]:
                errors.append("authorization-origin-main-mismatch")
        except subprocess.CalledProcessError:
            errors.append("authorization-repository-binding-invalid")
    return sorted(set(errors))


def validate_campaign_manifest(
    value: Any,
    *,
    authorization: Mapping[str, Any] | None = None,
    authorization_raw_sha256: str | None = None,
    outer_authority: Mapping[str, Any] | None = None,
    outer_authority_raw_sha256: str | None = None,
    predecessor_authorization: Mapping[str, Any] | None = None,
    predecessor_authorization_raw_sha256: str | None = None,
    predecessor_manifest: Mapping[str, Any] | None = None,
    predecessor_manifest_raw_sha256: str | None = None,
    predecessor_authorization_state: Mapping[str, Any] | None = None,
    predecessor_authorization_state_raw_sha256: str | None = None,
    predecessor_failure_evidence: Mapping[str, Any] | None = None,
    predecessor_failure_evidence_raw_sha256: str | None = None,
    predecessor_original_containment: Mapping[str, Any] | None = None,
    predecessor_original_containment_raw_sha256: str | None = None,
    predecessor_containment: Mapping[str, Any] | None = None,
    predecessor_containment_raw_sha256: str | None = None,
    predecessor_allocation_ledger: Mapping[str, Any] | None = None,
    predecessor_allocation_ledger_raw_sha256: str | None = None,
    predecessor_allocation_audit_path: Path | None = None,
    predecessor_allocation_audit_raw_sha256: str | None = None,
    cause_evidence: bytes | None = None,
    independent_validation_receipt: Mapping[str, Any] | None = None,
    independent_validation_receipt_raw_sha256: str | None = None,
    repo_root: Path | None = None,
    expected_primary_diff_sha256: str | None = None,
) -> list[str]:
    errors: list[str] = []
    manifest = _strict(value, MANIFEST_FIELDS, "campaign-manifest", errors)
    if not manifest:
        return sorted(set(errors))
    if (
        manifest.get("manifest_type") != MANIFEST_TYPE
        or manifest.get("version") != MANIFEST_VERSION
        or manifest.get("schema") != MANIFEST_SCHEMA
    ):
        errors.append("campaign-manifest-header-invalid")
    if not _is_uuid(manifest.get("manifest_id")) or not _is_uuid(manifest.get("authorization_id")) or not _is_uuid(manifest.get("campaign_nonce")):
        errors.append("campaign-manifest-identity-invalid")
    if not isinstance(manifest.get("created_at"), str) or not manifest["created_at"].strip():
        errors.append("campaign-manifest-created-at-invalid")
    for field in ("authorization_raw_sha256", "authorization_canonical_sha256"):
        if not _is_hash(manifest.get(field)):
            errors.append(f"campaign-manifest-{field.replace('_', '-')}-invalid")
    live_generation = manifest.get("live_generation")
    predecessor = manifest.get("predecessor_live_generation")
    if not _is_int(manifest.get("run_generation"), 1) or not _is_int(live_generation, 1) or not _is_int(predecessor, 0) or live_generation != predecessor + 1:
        errors.append("campaign-manifest-generation-invalid")
    if not isinstance(manifest.get("control_turn_id"), str) or not manifest["control_turn_id"].strip():
        errors.append("campaign-manifest-control-turn-invalid")

    work_units = _strict(
        manifest.get("work_units"), MANIFEST_WORK_UNIT_FIELDS, "campaign-manifest-work-units", errors
    )
    if not all(isinstance(work_units.get(field), str) and work_units[field].strip() for field in MANIFEST_WORK_UNIT_FIELDS):
        errors.append("campaign-manifest-work-unit-invalid")
    candidate = _strict(
        manifest.get("candidate"), MANIFEST_CANDIDATE_FIELDS, "campaign-manifest-candidate", errors
    )
    for field in ("commit", "tree", "origin_main_commit"):
        if not _is_commit(candidate.get(field)):
            errors.append(f"campaign-manifest-candidate-{field}-invalid")
    if not _is_hash(candidate.get("guarded_primary_diff_sha256")):
        errors.append("campaign-manifest-primary-diff-invalid")
    predecessor_value = _strict(
        manifest.get("predecessor"),
        MANIFEST_PREDECESSOR_FIELDS,
        "campaign-manifest-predecessor",
        errors,
    )
    if not _is_uuid(predecessor_value.get("authorization_id")) or any(
        not _is_hash(predecessor_value.get(field))
        for field in (
            "authorization_file_sha256",
            "authorization_canonical_sha256",
            "manifest_file_sha256",
            "manifest_canonical_sha256",
            "authorization_state_file_sha256",
            "authorization_state_canonical_sha256",
            "failure_evidence_file_sha256",
            "lineage_sha256",
            "failure_evidence_canonical_sha256",
            "containment_file_sha256",
            "containment_canonical_sha256",
            "original_containment_file_sha256",
            "original_containment_canonical_sha256",
            "allocation_ledger_file_sha256",
            "allocation_ledger_state_sha256",
            "allocation_audit_file_sha256",
        )
    ):
        errors.append("campaign-manifest-predecessor-invalid")
    for field in ("candidate_commit", "candidate_tree"):
        if not _is_commit(predecessor_value.get(field)):
            errors.append("campaign-manifest-predecessor-invalid")
    manifest_outer_authority = _strict(
        manifest.get("outer_authority"),
        MANIFEST_OUTER_AUTHORITY_FIELDS,
        "campaign-manifest-outer-authority",
        errors,
    )
    if not _is_uuid(manifest_outer_authority.get("authority_id")) or any(
        not _is_hash(manifest_outer_authority.get(field))
        for field in ("canonical_sha256", "file_sha256")
    ):
        errors.append("campaign-manifest-outer-authority-invalid")
    if not _is_hash(manifest.get("progress_qualification_sha256")):
        errors.append("campaign-manifest-progress-qualification-invalid")
    executors = _strict(
        manifest.get("executors"), EXECUTOR_FIELDS, "campaign-manifest-executors", errors
    )
    if executors.get("final_architect") != "current-codex-main-thread":
        errors.append("campaign-manifest-final-architect-invalid")
    if _strict(executors.get("steering"), STEERING_EXECUTOR_FIELDS, "campaign-manifest-steering", errors) != {
        "model": EXACT_STEERING_MODEL,
        "effort": EXACT_STEERING_EFFORT,
        "surface": "codex-app-server-stdio",
        "authority": "read-only-evidence",
    }:
        errors.append("campaign-manifest-steering-invalid")
    if _strict(executors.get("operative"), OPERATIVE_EXECUTOR_FIELDS, "campaign-manifest-operative", errors) != {
        "model": EXACT_OPERATIVE_MODEL,
        "effort": EXACT_OPERATIVE_EFFORT,
        "surface": "codex-app-server-stdio",
        "session_policy": "fresh-nonresumable-nonsalvageable",
    }:
        errors.append("campaign-manifest-operative-invalid")
    if _strict(executors.get("outside_critic"), CRITIC_EXECUTOR_FIELDS, "campaign-manifest-critic", errors) != {
        "model": EXACT_CRITIC_MODEL,
        "effort": EXACT_CRITIC_EFFORT,
        "surface": "claude-cli-as-greg",
        "authority": "evidence-only",
    }:
        errors.append("campaign-manifest-critic-invalid")
    if manifest.get("expected_roles") != list(EXPECTED_ROLES) or manifest.get("successful_turn_starts_exact") != len(EXPECTED_ROLES):
        errors.append("campaign-manifest-role-contract-invalid")
    if manifest.get("prestart_zero_artifact_relaunch_max") != 1:
        errors.append("campaign-manifest-relaunch-invalid")
    reviews = _strict(
        manifest.get("reviews"), MANIFEST_REVIEW_FIELDS, "campaign-manifest-reviews", errors
    )
    if any(not _is_hash(reviews.get(field)) for field in MANIFEST_REVIEW_FIELDS):
        errors.append("campaign-manifest-review-hash-invalid")
    release = _strict(
        manifest.get("release"), MANIFEST_RELEASE_FIELDS, "campaign-manifest-release", errors
    )
    for field in ("patch_file_sha256", "candidate_tree", "prospective_tree"):
        validator = _is_hash if field == "patch_file_sha256" else _is_commit
        if not validator(release.get(field)):
            errors.append(f"campaign-manifest-release-{field.replace('_', '-')}-invalid")
    policy_before = _strict(release.get("policy_before"), MANIFEST_POLICY_FIELDS, "campaign-manifest-policy-before", errors)
    policy_after = _strict(release.get("policy_after"), MANIFEST_POLICY_FIELDS, "campaign-manifest-policy-after", errors)
    if policy_before != {"status": "canary-gated", "cap_two_operative_release": False}:
        errors.append("campaign-manifest-policy-before-invalid")
    if policy_after != {"status": "operative-authorized", "cap_two_operative_release": True}:
        errors.append("campaign-manifest-policy-after-invalid")
    if release.get("candidate_tree") != candidate.get("tree"):
        errors.append("campaign-manifest-release-candidate-tree-mismatch")
    outputs = _strict(
        manifest.get("outputs"), MANIFEST_OUTPUT_FIELDS, "campaign-manifest-outputs", errors
    )
    output_values = list(outputs.values())
    if any(
        not isinstance(item, str)
        or not item
        or Path(item).name != item
        or item in {".", ".."}
        for item in output_values
    ) or len(output_values) != len(set(output_values)):
        errors.append("campaign-manifest-output-identity-invalid")
    if manifest.get("no_resume_or_salvage") is not True or manifest.get("glm_5_2_used") is not False or manifest.get("model_synthesis_used") is not False:
        errors.append("campaign-manifest-containment-policy-invalid")
    unsigned = dict(manifest)
    unsigned.pop("manifest_sha256", None)
    if not _is_hash(manifest.get("manifest_sha256")) or manifest.get("manifest_sha256") != canonical_sha256(unsigned):
        errors.append("campaign-manifest-sha256-mismatch")

    if authorization is not None:
        auth_errors = validate_full_auto_authorization(
            authorization,
            predecessor_authorization=predecessor_authorization,
            predecessor_authorization_raw_sha256=predecessor_authorization_raw_sha256,
            predecessor_manifest=predecessor_manifest,
            predecessor_manifest_raw_sha256=predecessor_manifest_raw_sha256,
            predecessor_authorization_state=predecessor_authorization_state,
            predecessor_authorization_state_raw_sha256=predecessor_authorization_state_raw_sha256,
            predecessor_failure_evidence=predecessor_failure_evidence,
            predecessor_failure_evidence_raw_sha256=predecessor_failure_evidence_raw_sha256,
            predecessor_original_containment=predecessor_original_containment,
            predecessor_original_containment_raw_sha256=predecessor_original_containment_raw_sha256,
            predecessor_containment=predecessor_containment,
            predecessor_containment_raw_sha256=predecessor_containment_raw_sha256,
            predecessor_allocation_ledger=predecessor_allocation_ledger,
            predecessor_allocation_ledger_raw_sha256=predecessor_allocation_ledger_raw_sha256,
            predecessor_allocation_audit_path=predecessor_allocation_audit_path,
            predecessor_allocation_audit_raw_sha256=predecessor_allocation_audit_raw_sha256,
            cause_evidence=cause_evidence,
        )
        errors.extend(f"campaign-manifest-authorization:{item}" for item in auth_errors)
        bindings = authorization.get("bindings") if isinstance(authorization.get("bindings"), Mapping) else {}
        scope = authorization.get("scope") if isinstance(authorization.get("scope"), Mapping) else {}
        expected = {
            "authorization_id": authorization.get("authorization_id"),
            "authorization_canonical_sha256": authorization.get("canonical_authorization_sha256"),
            "run_generation": authorization.get("run_generation"),
            "live_generation": authorization.get("live_generation"),
            "predecessor_live_generation": authorization.get("predecessor_live_generation"),
            "campaign_nonce": bindings.get("campaign_nonce"),
        }
        for field, expected_value in expected.items():
            if manifest.get(field) != expected_value:
                errors.append(f"campaign-manifest-authorization-{field.replace('_', '-')}-mismatch")
        if authorization_raw_sha256 is not None and manifest.get("authorization_raw_sha256") != authorization_raw_sha256:
            errors.append("campaign-manifest-authorization-raw-sha256-mismatch")
        ordered_work_units = scope.get("ordered_work_units")
        if (
            work_units.get("epic_id") != scope.get("epic_id")
            or work_units.get("parent_work_unit_id")
            != scope.get("parent_work_unit_id")
            or not isinstance(ordered_work_units, list)
            or work_units.get("live_work_unit_id") not in ordered_work_units
        ):
            errors.append("campaign-manifest-work-unit-authorization-mismatch")
        if (
            candidate.get("commit") != bindings.get("checkpoint_commit")
            or candidate.get("tree") != bindings.get("checkpoint_tree")
            or candidate.get("origin_main_commit") != bindings.get("origin_main_commit")
            or candidate.get("guarded_primary_diff_sha256")
            != bindings.get("guarded_primary_diff_sha256")
        ):
            errors.append("campaign-manifest-candidate-authorization-mismatch")
        progress = (
            authorization.get("progress_gate")
            if isinstance(authorization.get("progress_gate"), Mapping)
            else {}
        )
        if predecessor_value != {
            "authorization_id": bindings.get("predecessor_authorization_id"),
            "authorization_file_sha256": bindings.get(
                "predecessor_authorization_file_sha256"
            ),
            "authorization_canonical_sha256": bindings.get(
                "predecessor_authorization_canonical_sha256"
            ),
            "manifest_file_sha256": bindings.get("predecessor_manifest_file_sha256"),
            "manifest_canonical_sha256": bindings.get(
                "predecessor_manifest_canonical_sha256"
            ),
            "authorization_state_file_sha256": bindings.get(
                "predecessor_authorization_state_file_sha256"
            ),
            "authorization_state_canonical_sha256": bindings.get(
                "predecessor_authorization_state_canonical_sha256"
            ),
            "candidate_commit": progress.get("predecessor_candidate_commit"),
            "candidate_tree": progress.get("predecessor_candidate_tree"),
            "lineage_sha256": progress.get("predecessor_lineage_sha256"),
            "failure_evidence_file_sha256": bindings.get(
                "predecessor_failure_evidence_file_sha256"
            ),
            "failure_evidence_canonical_sha256": bindings.get("predecessor_failure_evidence_canonical_sha256"),
            "containment_file_sha256": bindings.get(
                "predecessor_containment_file_sha256"
            ),
            "containment_canonical_sha256": bindings.get("predecessor_containment_canonical_sha256"),
            "original_containment_file_sha256": bindings.get(
                "predecessor_original_containment_file_sha256"
            ),
            "original_containment_canonical_sha256": bindings.get(
                "predecessor_original_containment_canonical_sha256"
            ),
            "allocation_ledger_file_sha256": bindings.get(
                "predecessor_allocation_ledger_file_sha256"
            ),
            "allocation_ledger_state_sha256": bindings.get(
                "predecessor_allocation_ledger_state_sha256"
            ),
            "allocation_audit_file_sha256": bindings.get(
                "predecessor_allocation_audit_file_sha256"
            ),
        }:
            errors.append("campaign-manifest-predecessor-authorization-mismatch")
        if manifest_outer_authority != {
            "authority_id": bindings.get("outer_authority_id"),
            "canonical_sha256": bindings.get("outer_authority_canonical_sha256"),
            "file_sha256": bindings.get("outer_authority_file_sha256"),
        }:
            errors.append("campaign-manifest-outer-authority-authorization-mismatch")
        if manifest.get("progress_qualification_sha256") != progress.get(
            "qualification_sha256"
        ):
            errors.append("campaign-manifest-progress-qualification-mismatch")

    if outer_authority is not None:
        if (
            outer_authority.get("authority_type")
            != "cwo-full-auto-outer-recovery-authority"
            or outer_authority.get("version") != 1
            or outer_authority.get("status") != "active"
        ):
            errors.append("campaign-manifest-outer-authority-state-invalid")
        if not _is_uuid(outer_authority.get("authority_id")) or not _is_hash(
            outer_authority.get("canonical_outer_authority_sha256")
        ):
            errors.append("campaign-manifest-outer-authority-id-invalid")
        if outer_authority.get(
            "canonical_outer_authority_sha256"
        ) != _canonical_artifact_hash(
            outer_authority, "canonical_outer_authority_sha256"
        ):
            errors.append("campaign-manifest-outer-authority-canonical-sha256-mismatch")
        outer_scope = outer_authority.get("scope")
        if (
            not isinstance(outer_scope, Mapping)
            or outer_scope.get("epic_id") != work_units.get("epic_id")
            or outer_scope.get("parent_work_unit_id")
            != work_units.get("parent_work_unit_id")
        ):
            errors.append("campaign-manifest-outer-authority-scope-mismatch")
        expected_outer = {
            "authority_id": outer_authority.get("authority_id"),
            "canonical_sha256": outer_authority.get(
                "canonical_outer_authority_sha256"
            ),
            "file_sha256": outer_authority_raw_sha256,
        }
        if manifest_outer_authority != expected_outer:
            errors.append("campaign-manifest-outer-authority-binding-mismatch")

    if independent_validation_receipt is not None:
        expected_activity = {
            "function_calls": 0,
            "custom_tool_calls": 0,
            "tool_item_types": [],
            "compactions": 0,
            "workspace_mutations": 0,
        }
        opinion = independent_validation_receipt.get("opinion")
        guard = independent_validation_receipt.get("guard")
        guard_before = guard.get("before") if isinstance(guard, Mapping) else None
        guard_after = guard.get("after") if isinstance(guard, Mapping) else None
        boundary = independent_validation_receipt.get("boundary")
        terminal_boundary = (
            boundary.get("terminal") if isinstance(boundary, Mapping) else None
        )
        recorded_receipt_hash = independent_validation_receipt.get(
            "canonical_receipt_sha256"
        )
        receipt_hash_valid = _is_hash(recorded_receipt_hash) and (
            recorded_receipt_hash
            == _canonical_artifact_hash(
                independent_validation_receipt, "canonical_receipt_sha256"
            )
        )
        if not receipt_hash_valid:
            errors.append(
                "campaign-manifest-independent-validation-canonical-sha256-mismatch"
            )
        if (
            independent_validation_receipt.get("schema")
            != "cwo-steering-receipt:v1"
            or independent_validation_receipt.get("gate") != "independent-validation"
            or independent_validation_receipt.get("authorization_id")
            != manifest_outer_authority.get("authority_id")
            or independent_validation_receipt.get("authorization_sha256")
            != manifest_outer_authority.get("file_sha256")
            or independent_validation_receipt.get("model")
            != EXACT_OPERATIVE_MODEL
            or independent_validation_receipt.get("effort")
            != EXACT_OPERATIVE_EFFORT
            or independent_validation_receipt.get("attestation_source")
            != "initialized-codex-home-session-jsonl-turn-context"
            or independent_validation_receipt.get("observed_activity")
            != expected_activity
            or independent_validation_receipt.get("closure_outcome")
            != "completed-and-archived"
            or independent_validation_receipt.get("disposition") != "accepting"
            or not receipt_hash_valid
            or not isinstance(opinion, Mapping)
            or opinion.get("recommendation") != "go"
            or opinion.get("conditions") != []
            or opinion.get("findings") != []
            or isinstance(opinion.get("confidence"), bool)
            or not isinstance(opinion.get("confidence"), (int, float))
            or opinion.get("confidence") < 0.8
            or not isinstance(guard_before, Mapping)
            or not isinstance(guard_after, Mapping)
            or guard_before != guard_after
            or guard_before.get("repo_head") != candidate.get("commit")
            or guard_before.get("primary_diff_sha256")
            != candidate.get("guarded_primary_diff_sha256")
            or guard_before.get("repo_status_sha256")
            != hashlib.sha256(b"").hexdigest()
            or not isinstance(terminal_boundary, Mapping)
            or terminal_boundary.get("invalid_record_count") != 0
            or terminal_boundary.get("trailing_partial") is not False
        ):
            errors.append("campaign-manifest-independent-validation-not-accepting")
        progress = (
            authorization.get("progress_gate")
            if isinstance(authorization, Mapping)
            and isinstance(authorization.get("progress_gate"), Mapping)
            else {}
        )
        authorization_value = authorization if isinstance(authorization, Mapping) else {}
        completed_at = _parse_utc(independent_validation_receipt.get("completed_at"))
        issued_at = _parse_utc(authorization_value.get("issued_at"))
        validation_age_seconds = (
            (issued_at - completed_at).total_seconds()
            if issued_at is not None and completed_at is not None
            else None
        )
        if (
            progress.get("independent_validation_session_id")
            != independent_validation_receipt.get("session_id")
            or progress.get("independent_validation_completed_at")
            != independent_validation_receipt.get("completed_at")
            or validation_age_seconds is None
            or validation_age_seconds < 0
            or validation_age_seconds > 3600
            or progress.get("independent_validation_binding_sha256")
            != canonical_sha256(
                _independent_validation_binding(authorization_value, progress)
            )
        ):
            errors.append("campaign-manifest-independent-validation-freshness-binding-mismatch")
        if (
            reviews.get("spark_validation_receipt_canonical_sha256")
            != independent_validation_receipt.get("canonical_receipt_sha256")
            or reviews.get("spark_validation_receipt_file_sha256")
            != independent_validation_receipt_raw_sha256
            or progress.get("independent_validation_receipt_canonical_sha256")
            != independent_validation_receipt.get("canonical_receipt_sha256")
            or progress.get("independent_validation_receipt_file_sha256")
            != independent_validation_receipt_raw_sha256
        ):
            errors.append("campaign-manifest-independent-validation-binding-mismatch")

    if expected_primary_diff_sha256 is not None and candidate.get("guarded_primary_diff_sha256") != expected_primary_diff_sha256:
        errors.append("campaign-manifest-primary-diff-mismatch")
    if repo_root is not None and not errors:
        root = Path(repo_root).resolve()
        try:
            if _run_git(root, "rev-parse", "HEAD") != candidate["commit"]:
                errors.append("campaign-manifest-head-mismatch")
            if _run_git(root, "rev-parse", "HEAD^{tree}") != candidate["tree"]:
                errors.append("campaign-manifest-tree-mismatch")
            if _run_git(root, "rev-parse", "origin/main") != candidate["origin_main_commit"]:
                errors.append("campaign-manifest-origin-main-mismatch")
            if _run_git(root, "status", "--porcelain=v1", "--untracked-files=no"):
                errors.append("campaign-manifest-repository-not-clean")
        except subprocess.CalledProcessError:
            errors.append("campaign-manifest-repository-binding-invalid")
    return sorted(set(errors))


def validate_release_patch_result(
    repo_root: Path,
    patch_path: Path,
    manifest: Mapping[str, Any],
) -> list[str]:
    errors: list[str] = []
    root = Path(repo_root).resolve()
    patch = Path(patch_path).resolve()
    release = manifest.get("release") if isinstance(manifest.get("release"), Mapping) else {}
    candidate = manifest.get("candidate") if isinstance(manifest.get("candidate"), Mapping) else {}
    try:
        if hashlib.sha256(patch.read_bytes()).hexdigest() != release.get("patch_file_sha256"):
            return ["release-patch-file-sha256-mismatch"]
    except OSError:
        return ["release-patch-unavailable"]
    with tempfile.TemporaryDirectory(prefix="cwo-release-patch-check-") as temporary:
        worktree = Path(temporary) / "worktree"
        added = False
        try:
            subprocess.run(
                ["git", "worktree", "add", "--detach", str(worktree), str(candidate.get("commit"))],
                cwd=root,
                check=True,
                capture_output=True,
                text=True,
            )
            added = True
            if _run_git(worktree, "rev-parse", "HEAD^{tree}") != candidate.get("tree"):
                errors.append("release-patch-candidate-tree-mismatch")
            subprocess.run(
                ["git", "apply", "--check", str(patch)],
                cwd=worktree,
                check=True,
                capture_output=True,
                text=True,
            )
            subprocess.run(
                ["git", "apply", "--index", str(patch)],
                cwd=worktree,
                check=True,
                capture_output=True,
                text=True,
            )
            if _run_git(worktree, "write-tree") != release.get("prospective_tree"):
                errors.append("release-patch-prospective-tree-mismatch")
        except subprocess.CalledProcessError:
            errors.append("release-patch-application-invalid")
        finally:
            if added:
                subprocess.run(
                    ["git", "worktree", "remove", "--force", str(worktree)],
                    cwd=root,
                    check=False,
                    capture_output=True,
                )
    return sorted(set(errors))
