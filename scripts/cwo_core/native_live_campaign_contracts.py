"""Strict successor authority and manifest contracts for native live campaigns."""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass
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
AUTHORIZATION_VERSION_V6 = 6
AUTHORIZATION_SCHEMA_V6 = "schemas/full-auto-run-authorization-v6.schema.json"
MANIFEST_TYPE = "cwo-native-live-campaign-manifest"
MANIFEST_VERSION = 2
MANIFEST_SCHEMA = "schemas/native-live-campaign-manifest.schema.json"
MANIFEST_VERSION_V3 = 3
MANIFEST_SCHEMA_V3 = "schemas/native-live-campaign-manifest-v3.schema.json"
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
CONTAINED_ROLE_TOOL_PREFIXES = {
    "capability-calibration": (("function", "exec_command"),),
    "read-only-0": (
        ("function", "exec_command"),
        ("function", "exec_command"),
    ),
    "read-only-1": (
        ("function", "exec_command"),
        ("function", "exec_command"),
    ),
    "mutable-0": (
        ("custom", "apply_patch"),
        ("function", "exec_command"),
    ),
    "mutable-1": (
        ("custom", "apply_patch"),
        ("function", "exec_command"),
    ),
    "interrupt-0": (("function", "exec_command"),),
    "interrupt-1": (("function", "exec_command"),),
}
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
BINDING_FIELDS_V6 = (
    BINDING_FIELDS
    - {
        "predecessor_original_containment_file_sha256",
        "predecessor_original_containment_canonical_sha256",
    }
) | {
    "recovery_cause_evidence_file_sha256",
    "recovery_cause_evidence_canonical_sha256",
    "predecessor_ancestor_lineage_sha256",
    "validator_contract_sha256",
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
MANDATORY_GATE_FIELDS_V6 = (
    MANDATORY_GATE_FIELDS
    - {"strict_authorization_v5", "campaign_manifest_v2"}
) | {
    "strict_authorization_v6",
    "campaign_manifest_v3",
    "finite_predecessor_proof_dag",
    "read_once_predecessor_snapshots",
    "atomic_launch_claim",
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
MANIFEST_PREDECESSOR_FIELDS_V3 = (
    MANIFEST_PREDECESSOR_FIELDS
    - {
        "original_containment_file_sha256",
        "original_containment_canonical_sha256",
    }
) | {
    "recovery_cause_evidence_file_sha256",
    "recovery_cause_evidence_canonical_sha256",
    "ancestor_lineage_sha256",
    "validator_contract_sha256",
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

RECOVERY_CAUSE_EVIDENCE_FIELDS = {
    "evidence_type",
    "version",
    "schema",
    "evidence_id",
    "recorded_at",
    "failed_authorization_id",
    "failed_manifest_id",
    "live_generation",
    "failure_evidence_file_sha256",
    "failure_evidence_canonical_sha256",
    "containment_file_sha256",
    "containment_canonical_sha256",
    "failure_class",
    "failure_message_sha256",
    "falsifiable_cause",
    "repair_commit",
    "repair_tree",
    "source_analysis_sha256",
    "focused_tests_passed",
    "repository_validation_passed",
    "compileall_passed",
    "diff_check_passed",
    "canonical_cause_evidence_sha256",
}
MODERN_CONTAINMENT_FIELDS = {
    "schema",
    "bead_id",
    "recorded_at",
    "failed_authorization",
    "failed_manifest",
    "failed_evidence",
    "root_cause",
    "session_accounting",
    "allocation_ledger",
    "containment",
    "control_plane_recheck",
    "disposition",
    "canonical_recovery_sha256",
}
MODERN_FAILURE_EVIDENCE_FIELDS = {
    "result_type",
    "version",
    "bead_id",
    "work_unit_id",
    "control_turn_id",
    "started_at",
    "failed_at",
    "exact_model",
    "campaign_bindings",
    "steering_consumptions",
    "allocation_ledger",
    "failure_class",
    "failure_code",
    "failure_message_sha256",
    "first_protected_fault",
    "containment",
    "authorization_state_sha256",
    "release_gate_passed",
    "validation_outcome",
    "no_resume_or_salvage",
    "glm_5_2_used",
    "model_synthesis_used",
    "evidence_sha256",
}


@dataclass(frozen=True)
class JsonArtifactSnapshot:
    """One immutable byte read and its parsed JSON object."""

    raw: bytes
    value: Mapping[str, Any]

    @property
    def raw_sha256(self) -> str:
        return hashlib.sha256(self.raw).hexdigest()


@dataclass(frozen=True)
class HistoricalV4V1ProofInputs:
    """Read-once inputs for the frozen generation-5 historical proof leaf."""

    authorization: JsonArtifactSnapshot
    manifest: JsonArtifactSnapshot
    authorization_state: JsonArtifactSnapshot
    failure_evidence: JsonArtifactSnapshot
    original_containment: JsonArtifactSnapshot
    containment: JsonArtifactSnapshot
    allocation_ledger: JsonArtifactSnapshot
    allocation_audit_bytes: bytes
    cause_evidence: bytes
    contained_session_bytes: tuple[bytes, ...] = ()


@dataclass(frozen=True)
class Version5PredecessorProofInputs:
    """Read-once inputs for one v5/v2 predecessor and its fixed v4/v1 leaf."""

    authorization: JsonArtifactSnapshot
    manifest: JsonArtifactSnapshot
    authorization_state: JsonArtifactSnapshot
    failure_evidence: JsonArtifactSnapshot
    containment: JsonArtifactSnapshot
    allocation_ledger: JsonArtifactSnapshot
    allocation_audit_bytes: bytes
    authorization_cause_evidence: bytes
    outer_authority: JsonArtifactSnapshot
    independent_validation_receipt: JsonArtifactSnapshot
    independent_validation_session_bytes: bytes
    ancestor: HistoricalV4V1ProofInputs
    contained_session_bytes: tuple[bytes, ...] = ()
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


def _validate_json_snapshot(
    snapshot: JsonArtifactSnapshot, label: str
) -> list[str]:
    errors: list[str] = []
    if not isinstance(snapshot, JsonArtifactSnapshot) or not isinstance(
        snapshot.raw, bytes
    ):
        return [f"{label}-snapshot-invalid"]
    try:
        parsed = json.loads(snapshot.raw)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return [f"{label}-snapshot-json-invalid"]
    if not isinstance(parsed, dict) or parsed != dict(snapshot.value):
        errors.append(f"{label}-snapshot-value-mismatch")
    if not snapshot.raw_sha256 or not _is_hash(snapshot.raw_sha256):
        errors.append(f"{label}-snapshot-sha256-invalid")
    return errors


VALIDATOR_CONTRACT_PATHS = (
    "scripts/cwo_core/audit.py",
    "scripts/cwo_core/native_canary_contracts.py",
    "scripts/cwo_core/native_live_allocation_ledger.py",
    "scripts/cwo_core/native_live_campaign_contracts.py",
    "scripts/run_native_pool_live_canaries.py",
    "schemas/full-auto-run-authorization.schema.json",
    "schemas/full-auto-run-authorization-v6.schema.json",
    "schemas/native-live-campaign-manifest.schema.json",
    "schemas/native-live-campaign-manifest-v3.schema.json",
    "schemas/native-live-campaign-cause-evidence.schema.json",
    "schemas/native-canary-authorization-state.schema.json",
    "schemas/native-canary-authorization-state-v2.schema.json",
    "schemas/native-live-allocation-ledger-v2.schema.json",
)


def validator_contract_sha256(
    repo_root: Path, checkpoint_tree: str | None = None
) -> str:
    """Bind validator blobs from one immutable checkpoint tree.

    Reading the working tree one pathname at a time leaves the digest vulnerable
    to a concurrent rewrite-and-restore race. Git tree objects provide one stable,
    candidate-bound snapshot for the complete validator contract.
    """

    root = Path(repo_root).resolve()
    if checkpoint_tree is None:
        completed = subprocess.run(
            ["git", "rev-parse", "HEAD^{tree}"],
            cwd=root,
            check=False,
            capture_output=True,
            text=True,
        )
        checkpoint_tree = completed.stdout.strip()
    if not _is_commit(checkpoint_tree):
        raise ValueError("validator-contract-tree-invalid")
    files: list[dict[str, str]] = []
    for relative in VALIDATOR_CONTRACT_PATHS:
        entry = subprocess.run(
            ["git", "ls-tree", checkpoint_tree, "--", relative],
            cwd=root,
            check=False,
            capture_output=True,
            text=True,
        )
        fields = entry.stdout.strip().split(None, 3)
        if (
            entry.returncode != 0
            or len(fields) != 4
            or fields[0] not in {"100644", "100755"}
            or fields[1] != "blob"
            or fields[3] != relative
        ):
            raise ValueError(f"validator-contract-path-invalid:{relative}")
        blob = subprocess.run(
            ["git", "show", f"{checkpoint_tree}:{relative}"],
            cwd=root,
            check=False,
            capture_output=True,
        )
        if blob.returncode != 0:
            raise ValueError(f"validator-contract-blob-invalid:{relative}")
        files.append(
            {
                "path": relative,
                "sha256": hashlib.sha256(blob.stdout).hexdigest(),
            }
        )
    return canonical_sha256(
        {
            "contract": "cwo-live-successor-validator:v1",
            "proof_dag": ["v6/v3", "v5/v2", "v4/v1"],
            "ancestor_depth_exact": 1,
            "checkpoint_tree": checkpoint_tree,
            "files": files,
        }
    )


def active_outer_authority_scope_key(epic_id: Any, parent_work_unit_id: Any) -> str:
    """Return the machine-local registry key for one outer-authority scope."""

    if (
        not isinstance(epic_id, str)
        or not epic_id
        or not isinstance(parent_work_unit_id, str)
        or not parent_work_unit_id
    ):
        raise ValueError("outer-authority-registry-scope-invalid")
    return canonical_sha256(
        {
            "contract": "cwo-active-outer-authority-registry:v1",
            "epic_id": epic_id,
            "parent_work_unit_id": parent_work_unit_id,
        }
    )


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


def _predecessor_lineage_v6(
    bindings: Mapping[str, Any],
    progress: Mapping[str, Any],
    predecessor_live_generation: Any,
) -> dict[str, Any]:
    """Ordered lineage identity for the finite v6 -> v5 -> v4 proof DAG."""

    return {
        "validator_contract_sha256": bindings.get("validator_contract_sha256"),
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
        "failure_evidence_file_sha256": bindings.get(
            "predecessor_failure_evidence_file_sha256"
        ),
        "failure_evidence_canonical_sha256": bindings.get(
            "predecessor_failure_evidence_canonical_sha256"
        ),
        "containment_file_sha256": bindings.get(
            "predecessor_containment_file_sha256"
        ),
        "containment_canonical_sha256": bindings.get(
            "predecessor_containment_canonical_sha256"
        ),
        "recovery_cause_evidence_file_sha256": bindings.get(
            "recovery_cause_evidence_file_sha256"
        ),
        "recovery_cause_evidence_canonical_sha256": bindings.get(
            "recovery_cause_evidence_canonical_sha256"
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
        "ancestor_lineage_sha256": bindings.get(
            "predecessor_ancestor_lineage_sha256"
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


def _validate_recovery_cause_evidence(
    value: Any,
    *,
    raw_sha256: str,
    bindings: Mapping[str, Any],
    progress: Mapping[str, Any],
    predecessor: Version5PredecessorProofInputs,
    source_analysis_bytes: bytes,
) -> list[str]:
    errors: list[str] = []
    evidence = _strict(
        value,
        RECOVERY_CAUSE_EVIDENCE_FIELDS,
        "authorization-recovery-cause-evidence",
        errors,
    )
    if not evidence:
        return sorted(set(errors))
    if (
        evidence.get("evidence_type")
        != "cwo-native-live-campaign-cause-evidence"
        or evidence.get("version") != 1
        or evidence.get("schema")
        != "schemas/native-live-campaign-cause-evidence.schema.json"
        or not _is_uuid(evidence.get("evidence_id"))
        or _parse_utc(evidence.get("recorded_at")) is None
    ):
        errors.append("authorization-recovery-cause-evidence-header-invalid")
    for field in (
        "failure_evidence_file_sha256",
        "failure_evidence_canonical_sha256",
        "containment_file_sha256",
        "containment_canonical_sha256",
        "failure_message_sha256",
        "source_analysis_sha256",
        "canonical_cause_evidence_sha256",
    ):
        if not _is_hash(evidence.get(field)):
            errors.append(
                f"authorization-recovery-cause-evidence-{field.replace('_', '-')}-invalid"
            )
    for field in ("repair_commit", "repair_tree"):
        if not _is_commit(evidence.get(field)):
            errors.append(
                f"authorization-recovery-cause-evidence-{field.replace('_', '-')}-invalid"
            )
    if (
        not _is_int(evidence.get("live_generation"), 1)
        or not _is_int(evidence.get("focused_tests_passed"), 1)
        or any(
            evidence.get(field) is not True
            for field in (
                "repository_validation_passed",
                "compileall_passed",
                "diff_check_passed",
            )
        )
        or not isinstance(evidence.get("failure_class"), str)
        or not evidence.get("failure_class", "").strip()
        or not isinstance(evidence.get("falsifiable_cause"), str)
        or not evidence.get("falsifiable_cause", "").strip()
    ):
        errors.append("authorization-recovery-cause-evidence-content-invalid")

    prior_authorization = predecessor.authorization.value
    prior_manifest = predecessor.manifest.value
    prior_failure = predecessor.failure_evidence.value
    prior_containment = predecessor.containment.value
    prior_root_cause = (
        prior_containment.get("root_cause")
        if isinstance(prior_containment.get("root_cause"), Mapping)
        else {}
    )
    if (
        raw_sha256 != bindings.get("recovery_cause_evidence_file_sha256")
        or evidence.get("canonical_cause_evidence_sha256")
        != bindings.get("recovery_cause_evidence_canonical_sha256")
        or evidence.get("canonical_cause_evidence_sha256")
        != _canonical_artifact_hash(
            evidence, "canonical_cause_evidence_sha256"
        )
        or progress.get("cause_evidence_sha256") != raw_sha256
        or evidence.get("failed_authorization_id")
        != prior_authorization.get("authorization_id")
        or evidence.get("failed_manifest_id") != prior_manifest.get("manifest_id")
        or evidence.get("live_generation")
        != prior_authorization.get("live_generation")
        or evidence.get("failure_evidence_file_sha256")
        != predecessor.failure_evidence.raw_sha256
        or evidence.get("failure_evidence_canonical_sha256")
        != prior_failure.get("evidence_sha256")
        or evidence.get("containment_file_sha256")
        != predecessor.containment.raw_sha256
        or evidence.get("containment_canonical_sha256")
        != prior_containment.get("canonical_recovery_sha256")
        or evidence.get("failure_class")
        != progress.get("predecessor_failure_class")
        or evidence.get("failure_class") != prior_root_cause.get("failure_class")
        or evidence.get("failure_message_sha256")
        != prior_failure.get("failure_message_sha256")
        or evidence.get("failure_message_sha256")
        != prior_root_cause.get("message_sha256")
        or evidence.get("falsifiable_cause")
        != progress.get("new_falsifiable_cause")
        or evidence.get("falsifiable_cause")
        != prior_root_cause.get("falsifiable_cause")
        or not isinstance(source_analysis_bytes, bytes)
        or not source_analysis_bytes
        or evidence.get("source_analysis_sha256")
        != hashlib.sha256(source_analysis_bytes).hexdigest()
        or evidence.get("repair_commit") != bindings.get("checkpoint_commit")
        or evidence.get("repair_tree") != bindings.get("checkpoint_tree")
    ):
        errors.append("authorization-recovery-cause-evidence-binding-invalid")
    return sorted(set(errors))


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
    predecessor_allocation_audit_path: Path | None,
    predecessor_allocation_audit_raw_sha256: str,
    predecessor_allocation_audit_bytes: bytes | None = None,
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
            audit_file=(
                predecessor_allocation_audit_path
                if predecessor_allocation_audit_bytes is None
                else None
            ),
            audit_bytes=predecessor_allocation_audit_bytes,
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
        audit_text = (
            predecessor_allocation_audit_bytes.decode("utf-8")
            if predecessor_allocation_audit_bytes is not None
            else Path(predecessor_allocation_audit_path).read_text(encoding="utf-8")
        )
        audit_records = [
            json.loads(line) for line in audit_text.splitlines() if line.strip()
        ]
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, TypeError):
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


def _validate_full_auto_authorization_v5(
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
    predecessor_allocation_audit_bytes: bytes | None = None,
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
        predecessor_allocation_audit_raw_sha256,
        cause_evidence,
    )
    audit_sources = sum(
        item is not None
        for item in (
            predecessor_allocation_audit_path,
            predecessor_allocation_audit_bytes,
        )
    )
    if any(item is not None for item in predecessor_artifacts) or audit_sources:
        if any(item is None for item in predecessor_artifacts) or audit_sources != 1:
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
                    predecessor_allocation_audit_path=(
                        Path(predecessor_allocation_audit_path)
                        if predecessor_allocation_audit_path is not None
                        else None
                    ),
                    predecessor_allocation_audit_raw_sha256=str(
                        predecessor_allocation_audit_raw_sha256
                    ),
                    predecessor_allocation_audit_bytes=(
                        bytes(predecessor_allocation_audit_bytes)
                        if predecessor_allocation_audit_bytes is not None
                        else None
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


def _historical_proof_kwargs(
    proof: HistoricalV4V1ProofInputs,
    *,
    cause_evidence: bytes | None = None,
) -> dict[str, Any]:
    return {
        "predecessor_authorization": proof.authorization.value,
        "predecessor_authorization_raw_sha256": proof.authorization.raw_sha256,
        "predecessor_manifest": proof.manifest.value,
        "predecessor_manifest_raw_sha256": proof.manifest.raw_sha256,
        "predecessor_authorization_state": proof.authorization_state.value,
        "predecessor_authorization_state_raw_sha256": proof.authorization_state.raw_sha256,
        "predecessor_failure_evidence": proof.failure_evidence.value,
        "predecessor_failure_evidence_raw_sha256": proof.failure_evidence.raw_sha256,
        "predecessor_original_containment": proof.original_containment.value,
        "predecessor_original_containment_raw_sha256": proof.original_containment.raw_sha256,
        "predecessor_containment": proof.containment.value,
        "predecessor_containment_raw_sha256": proof.containment.raw_sha256,
        "predecessor_allocation_ledger": proof.allocation_ledger.value,
        "predecessor_allocation_ledger_raw_sha256": proof.allocation_ledger.raw_sha256,
        "predecessor_allocation_audit_path": None,
        "predecessor_allocation_audit_raw_sha256": hashlib.sha256(
            proof.allocation_audit_bytes
        ).hexdigest(),
        "predecessor_allocation_audit_bytes": proof.allocation_audit_bytes,
        "cause_evidence": (
            proof.cause_evidence if cause_evidence is None else cause_evidence
        ),
    }


def _validate_independent_validation_session_snapshot(
    receipt: Mapping[str, Any], raw: bytes
) -> list[str]:
    errors: list[str] = []
    if not isinstance(raw, bytes) or not raw or not raw.endswith(b"\n"):
        return ["authorization-predecessor-validation-session-boundary-invalid"]
    try:
        records = [json.loads(line) for line in raw.splitlines()]
    except (UnicodeDecodeError, json.JSONDecodeError):
        return ["authorization-predecessor-validation-session-json-invalid"]
    if not all(isinstance(record, dict) for record in records):
        return ["authorization-predecessor-validation-session-record-invalid"]
    session_id = receipt.get("session_id")
    turn_id = receipt.get("submission_id")
    metas = [
        record.get("payload", {}).get("id")
        for record in records
        if record.get("type") == "session_meta"
        and isinstance(record.get("payload"), Mapping)
    ]
    contexts = [
        record.get("payload")
        for record in records
        if record.get("type") == "turn_context"
        and isinstance(record.get("payload"), Mapping)
        and (
            record["payload"].get("turn_id") == turn_id
            or record["payload"].get("turnId") == turn_id
        )
    ]
    terminal = (
        receipt.get("boundary", {}).get("terminal", {})
        if isinstance(receipt.get("boundary"), Mapping)
        else {}
    )
    if (
        metas != [session_id]
        or len(contexts) != 1
        or contexts[0].get("model") != EXACT_OPERATIVE_MODEL
        or (contexts[0].get("effort") or contexts[0].get("reasoning_effort"))
        != EXACT_OPERATIVE_EFFORT
        or terminal.get("boundary_sha256") != hashlib.sha256(raw).hexdigest()
        or terminal.get("record_count") != len(records)
        or terminal.get("byte_offset") != len(raw)
        or terminal.get("invalid_record_count") != 0
        or terminal.get("trailing_partial") is not False
    ):
        errors.append("authorization-predecessor-validation-session-binding-invalid")

    allowed_records = {
        "session_meta",
        "event_msg",
        "response_item",
        "world_state",
        "turn_context",
    }
    allowed_events = {
        "task_started",
        "user_message",
        "agent_message",
        "token_count",
        "task_complete",
    }
    allowed_responses = {"message", "reasoning"}
    starts = 0
    completes = 0
    event_finals: list[str] = []
    response_finals: list[str] = []
    for record in records:
        record_type = record.get("type")
        payload = record.get("payload")
        if record_type not in allowed_records or not isinstance(payload, Mapping):
            errors.append("authorization-predecessor-validation-session-activity-invalid")
            continue
        payload_type = payload.get("type")
        if record_type == "event_msg":
            if payload_type not in allowed_events:
                errors.append("authorization-predecessor-validation-session-activity-invalid")
            if payload_type in {"task_started", "task_complete"}:
                if payload.get("turn_id") != turn_id or "turnId" in payload:
                    errors.append("authorization-predecessor-validation-session-turn-invalid")
                if payload_type == "task_started":
                    starts += 1
                else:
                    completes += 1
            if payload_type == "agent_message":
                message = payload.get("message")
                if isinstance(message, str):
                    event_finals.append(message)
        elif record_type == "response_item":
            if payload_type not in allowed_responses:
                errors.append("authorization-predecessor-validation-session-tool-activity")
            if payload_type == "message" and payload.get("role") == "assistant":
                content = payload.get("content")
                if isinstance(content, list):
                    texts = [
                        item.get("text")
                        for item in content
                        if isinstance(item, Mapping)
                        and item.get("type") in {"output_text", "text"}
                        and isinstance(item.get("text"), str)
                    ]
                    if len(texts) == 1:
                        response_finals.append(str(texts[0]))
        marker = f"{record_type}:{payload_type}".lower()
        if "compact" in marker or "rerout" in marker:
            errors.append("authorization-predecessor-validation-session-containment-invalid")
    if starts != 1 or completes != 1 or len(event_finals) != 1 or len(response_finals) != 1:
        errors.append("authorization-predecessor-validation-session-lifecycle-invalid")
    elif (
        event_finals[0] != response_finals[0]
        or hashlib.sha256(response_finals[0].encode()).hexdigest()
        != receipt.get("final_response_sha256")
    ):
        errors.append("authorization-predecessor-validation-session-final-binding-invalid")
    return sorted(set(errors))


def _parse_contained_session_identity(
    raw: bytes, label: str
) -> tuple[
    str | None,
    set[str],
    int,
    tuple[tuple[str, str], ...],
    str | None,
    list[str],
]:
    errors: list[str] = []
    if not isinstance(raw, bytes) or not raw or not raw.endswith(b"\n"):
        return None, set(), 0, (), None, [f"{label}-boundary-invalid"]
    try:
        records = [json.loads(line) for line in raw.splitlines()]
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None, set(), 0, (), None, [f"{label}-json-invalid"]
    if not all(isinstance(record, dict) for record in records):
        return None, set(), len(records), (), None, [f"{label}-record-invalid"]
    allowed_payload_types: dict[str, set[str | None]] = {
        "session_meta": {None},
        "event_msg": {
            "task_started",
            "user_message",
            "agent_message",
            "token_count",
            "task_complete",
            "turn_aborted",
            "patch_apply_end",
        },
        "response_item": {
            "message",
            "reasoning",
            "function_call",
            "function_call_output",
            "custom_tool_call",
            "custom_tool_call_output",
        },
        "world_state": {None},
        "turn_context": {None},
    }
    session_meta_indices: list[int] = []
    started_events: list[tuple[int, str]] = []
    terminal_events: list[tuple[int, str, str]] = []
    turn_contexts: list[tuple[int, str]] = []
    calls: dict[str, tuple[int, str, str]] = {}
    outputs: dict[str, tuple[int, str]] = {}
    tool_sequence: list[tuple[str, str]] = []
    patch_events: dict[str, tuple[int, str]] = {}
    for index, record in enumerate(records):
        record_type = record.get("type")
        payload = record.get("payload")
        if record_type not in allowed_payload_types or not isinstance(
            payload, Mapping
        ):
            errors.append(f"{label}-activity-invalid")
            continue
        payload_type = payload.get("type")
        if payload_type not in allowed_payload_types[record_type]:
            errors.append(f"{label}-activity-invalid")
            continue
        marker = f"{record_type}:{payload_type}".lower()
        if "compact" in marker or "rerout" in marker:
            errors.append(f"{label}-activity-invalid")
        if record_type == "session_meta":
            session_meta_indices.append(index)
        if record_type == "event_msg" and payload_type in {
            "task_started",
            "task_complete",
            "turn_aborted",
        }:
            turn_id = payload.get("turn_id")
            if not _is_uuid(turn_id) or "turnId" in payload:
                errors.append(f"{label}-turn-identity-invalid")
            elif payload_type == "task_started":
                started_events.append((index, str(turn_id)))
            else:
                terminal_events.append((index, str(turn_id), str(payload_type)))
        elif record_type == "event_msg" and payload_type == "patch_apply_end":
            call_id = payload.get("call_id")
            turn_id = payload.get("turn_id")
            if (
                not isinstance(call_id, str)
                or not call_id
                or call_id in patch_events
                or not _is_uuid(turn_id)
            ):
                errors.append(f"{label}-patch-event-invalid")
            else:
                patch_events[call_id] = (index, str(turn_id))
        elif record_type == "turn_context":
            turn_id = payload.get("turn_id") or payload.get("turnId")
            if not _is_uuid(turn_id):
                errors.append(f"{label}-turn-context-invalid")
            else:
                turn_contexts.append((index, str(turn_id)))
        elif record_type == "response_item" and payload_type == "message":
            if payload.get("role") not in {"developer", "user", "assistant"}:
                errors.append(f"{label}-message-role-invalid")
        elif record_type == "response_item" and payload_type in {
            "function_call",
            "custom_tool_call",
        }:
            kind = "function" if payload_type == "function_call" else "custom"
            call_id = payload.get("call_id")
            name = payload.get("name")
            if (
                not isinstance(call_id, str)
                or not call_id
                or call_id in calls
                or not isinstance(name, str)
                or not name
                or (kind, name)
                not in {
                    ("function", "exec_command"),
                    ("custom", "apply_patch"),
                }
            ):
                errors.append(f"{label}-tool-call-invalid")
            else:
                calls[call_id] = (index, kind, name)
                tool_sequence.append((kind, name))
        elif (
            record_type == "response_item"
            and payload_type
            in {"function_call_output", "custom_tool_call_output"}
        ):
            kind = (
                "function"
                if payload_type == "function_call_output"
                else "custom"
            )
            call_id = payload.get("call_id")
            if (
                not isinstance(call_id, str)
                or not call_id
                or call_id in outputs
            ):
                errors.append(f"{label}-tool-output-invalid")
            else:
                outputs[call_id] = (index, kind)
    session_ids = [
        record.get("payload", {}).get("id")
        for record in records
        if record.get("type") == "session_meta"
        and isinstance(record.get("payload"), Mapping)
    ]
    session_id = session_ids[0] if len(session_ids) == 1 else None
    if not _is_uuid(session_id):
        errors.append(f"{label}-session-identity-invalid")
    started_turns = {turn_id for _index, turn_id in started_events}
    if len(started_turns) != 1:
        errors.append(f"{label}-turn-identity-invalid")
    expected_turn = next(iter(started_turns), None)
    if (
        session_meta_indices != [0]
        or len(started_events) != 1
        or (started_events and started_events[0][0] != 1)
        or len(terminal_events) != 1
        or terminal_events[0][0] != len(records) - 1
        or (
            started_events
            and terminal_events
            and started_events[0][1] != terminal_events[0][1]
        )
    ):
        errors.append(f"{label}-terminal-boundary-invalid")
    if any(turn_id != expected_turn for _index, turn_id in turn_contexts):
        errors.append(f"{label}-turn-context-mismatch")
    if set(calls) != set(outputs):
        errors.append(f"{label}-tool-pairing-invalid")
    for call_id in sorted(set(calls) & set(outputs)):
        call_index, call_kind, _name = calls[call_id]
        output_index, output_kind = outputs[call_id]
        if call_kind != output_kind or call_index >= output_index:
            errors.append(f"{label}-tool-order-invalid")
    for call_id, (event_index, event_turn) in patch_events.items():
        call = calls.get(call_id)
        output = outputs.get(call_id)
        if (
            call is None
            or output is None
            or call[1:] != ("custom", "apply_patch")
            or not (call[0] < event_index < output[0])
            or event_turn != expected_turn
        ):
            errors.append(f"{label}-patch-event-binding-invalid")
    terminal_type = terminal_events[0][2] if len(terminal_events) == 1 else None
    return (
        session_id,
        started_turns,
        len(records),
        tuple(tool_sequence),
        terminal_type,
        errors,
    )


def _validate_contained_session_snapshots(
    *,
    session_accounting: Any,
    ledger: Mapping[str, Any],
    raw_sessions: tuple[bytes, ...],
    label: str,
    historical: bool,
) -> list[str]:
    errors: list[str] = []
    if (
        not isinstance(session_accounting, list)
        or not session_accounting
        or not isinstance(raw_sessions, tuple)
        or len(raw_sessions) != len(session_accounting)
        or any(not isinstance(item, bytes) for item in raw_sessions)
    ):
        return [f"{label}-session-snapshot-set-invalid"]
    entries = ledger.get("entries")
    if not isinstance(entries, list):
        return [f"{label}-session-ledger-invalid"]
    thread_entries = {
        item.get("thread_id"): item
        for item in entries
        if isinstance(item, Mapping)
        and item.get("event") == "thread-bound"
        and _is_uuid(item.get("thread_id"))
    }
    turn_entries = {
        item.get("thread_id"): item
        for item in entries
        if isinstance(item, Mapping)
        and item.get("event") == "turn-bound"
        and _is_uuid(item.get("thread_id"))
        and _is_uuid(item.get("turn_id"))
    }
    accounting_by_id: dict[str, Mapping[str, Any]] = {}
    for item in session_accounting:
        if not isinstance(item, Mapping):
            errors.append(f"{label}-session-accounting-invalid")
            continue
        session_id = item.get("thread_id" if historical else "session_id")
        if not _is_uuid(session_id) or session_id in accounting_by_id:
            errors.append(f"{label}-session-accounting-identity-invalid")
            continue
        accounting_by_id[str(session_id)] = item
    parsed_by_id: dict[
        str,
        tuple[bytes, set[str], int, tuple[tuple[str, str], ...], str | None],
    ] = {}
    for index, raw in enumerate(raw_sessions):
        (
            session_id,
            started_turns,
            record_count,
            tool_sequence,
            terminal_type,
            parse_errors,
        ) = (
            _parse_contained_session_identity(raw, f"{label}-{index}")
        )
        errors.extend(parse_errors)
        if session_id is None or session_id in parsed_by_id:
            errors.append(f"{label}-session-snapshot-identity-invalid")
            continue
        parsed_by_id[session_id] = (
            raw,
            started_turns,
            record_count,
            tool_sequence,
            terminal_type,
        )
    if (
        set(accounting_by_id) != set(parsed_by_id)
        or set(accounting_by_id) != set(thread_entries)
        or set(accounting_by_id) != set(turn_entries)
    ):
        errors.append(f"{label}-session-ledger-identity-mismatch")
    for session_id in sorted(set(accounting_by_id) & set(parsed_by_id)):
        item = accounting_by_id[session_id]
        (
            raw,
            started_turns,
            record_count,
            tool_sequence,
            terminal_type,
        ) = parsed_by_id[session_id]
        thread_entry = thread_entries.get(session_id, {})
        turn_entry = turn_entries.get(session_id, {})
        expected_turn = turn_entry.get("turn_id")
        if expected_turn not in started_turns:
            errors.append(f"{label}-session-turn-mismatch")
        role = thread_entry.get("role")
        expected_tools = CONTAINED_ROLE_TOOL_PREFIXES.get(role)
        if expected_tools is None or (
            terminal_type == "task_complete"
            and tool_sequence != expected_tools
        ) or (
            terminal_type == "turn_aborted"
            and (
                len(tool_sequence) > len(expected_tools)
                or tool_sequence != expected_tools[: len(tool_sequence)]
            )
        ):
            errors.append(f"{label}-session-tool-activity-invalid")
        if historical:
            if (
                item.get("role") != thread_entry.get("role")
                or item.get("turn_id") != expected_turn
                or item.get("record_count") != record_count
                or item.get("byte_offset") != len(raw)
                or item.get("boundary_sha256")
                != hashlib.sha256(raw).hexdigest()
            ):
                errors.append(f"{label}-historical-session-binding-invalid")
        elif (
            item.get("archived_session_file_sha256")
            != hashlib.sha256(raw).hexdigest()
            or item.get("active_match_count") != 0
            or item.get("archive_match_count") != 1
        ):
            errors.append(f"{label}-modern-session-binding-invalid")
    return sorted(set(errors))


def _validate_modern_ledger_semantics(
    ledger: Mapping[str, Any], allocated: int
) -> list[str]:
    errors: list[str] = []
    entries = ledger.get("entries")
    if not isinstance(entries, list):
        return ["authorization-predecessor-modern-ledger-semantics-invalid"]
    allocations = [
        item
        for item in entries
        if isinstance(item, Mapping) and item.get("event") == "allocation-intent"
    ]
    roles = [item.get("role") for item in allocations]
    if len(allocations) != allocated or roles != list(EXPECTED_ROLES[:allocated]):
        errors.append("authorization-predecessor-modern-ledger-role-prefix-invalid")
    certifications = [
        item
        for item in entries
        if isinstance(item, Mapping) and item.get("event") == "certification-bound"
    ]
    later_allocations = [
        int(item.get("sequence", 0))
        for item in allocations
        if item.get("ordinal") not in {None, 0}
    ]
    capability_phase_sequences = [
        int(item.get("sequence", 0))
        for item in entries
        if isinstance(item, Mapping)
        and item.get("allocation_intent_id")
        == (allocations[0].get("allocation_intent_id") if allocations else None)
        and item.get("event") != "containment-audited"
    ]
    if (
        len(certifications) != 1
        or certifications[0].get("outcome") != "bound"
        or not capability_phase_sequences
        or int(certifications[0].get("sequence", 0))
        <= max(capability_phase_sequences)
        or (
            later_allocations
            and int(certifications[0].get("sequence", 0)) >= min(later_allocations)
        )
    ):
        errors.append("authorization-predecessor-modern-ledger-certification-invalid")
    for allocation in allocations:
        intent_id = allocation.get("allocation_intent_id")
        family = [
            item
            for item in entries
            if isinstance(item, Mapping)
            and item.get("allocation_intent_id") == intent_id
        ]
        family_events = [item.get("event") for item in family]
        if family_events != [
            "allocation-intent",
            "thread-bound",
            "turn-intent",
            "turn-bound",
            "interrupt-observed",
            "archive-observed",
            "containment-audited",
        ]:
            errors.append("authorization-predecessor-modern-ledger-lifecycle-order-invalid")
        audits = [item for item in family if item.get("event") == "containment-audited"]
        if len(audits) != 1 or audits[0].get("outcome") not in {
            "contained",
            "already-contained",
        }:
            errors.append("authorization-predecessor-modern-ledger-containment-invalid")
            continue
        interrupts = [
            item for item in family if item.get("event") == "interrupt-observed"
        ]
        archives = [
            item for item in family if item.get("event") == "archive-observed"
        ]
        if (
            len(interrupts) != 1
            or interrupts[0].get("outcome") != "interrupt-request-accepted"
        ):
            errors.append("authorization-predecessor-modern-ledger-interrupt-invalid")
        if (
            len(archives) != 1
            or archives[0].get("outcome") != "archive-request-accepted"
        ):
            errors.append("authorization-predecessor-modern-ledger-archive-invalid")
    return sorted(set(errors))


def _validate_v5_v2_predecessor_proof(
    *,
    bindings: Mapping[str, Any],
    progress: Mapping[str, Any],
    supersession: Mapping[str, Any],
    predecessor_live_generation: int,
    proof: Version5PredecessorProofInputs,
    repo_root: Path | None,
) -> list[str]:
    """Validate the fixed v6/v3 -> v5/v2 -> v4/v1 proof DAG."""

    errors: list[str] = []
    snapshots = {
        "authorization-predecessor-v5-authorization": proof.authorization,
        "authorization-predecessor-v2-manifest": proof.manifest,
        "authorization-predecessor-state": proof.authorization_state,
        "authorization-predecessor-failure": proof.failure_evidence,
        "authorization-predecessor-containment": proof.containment,
        "authorization-predecessor-ledger": proof.allocation_ledger,
        "authorization-predecessor-outer-authority": proof.outer_authority,
        "authorization-predecessor-independent-validation": proof.independent_validation_receipt,
        "authorization-ancestor-v4-authorization": proof.ancestor.authorization,
        "authorization-ancestor-v1-manifest": proof.ancestor.manifest,
        "authorization-ancestor-state": proof.ancestor.authorization_state,
        "authorization-ancestor-failure": proof.ancestor.failure_evidence,
        "authorization-ancestor-original-containment": proof.ancestor.original_containment,
        "authorization-ancestor-containment": proof.ancestor.containment,
        "authorization-ancestor-ledger": proof.ancestor.allocation_ledger,
    }
    for label, snapshot in snapshots.items():
        errors.extend(_validate_json_snapshot(snapshot, label))
    if not isinstance(proof.allocation_audit_bytes, bytes) or not isinstance(
        proof.ancestor.allocation_audit_bytes, bytes
    ) or not isinstance(proof.independent_validation_session_bytes, bytes):
        errors.append("authorization-predecessor-audit-snapshot-invalid")
        return sorted(set(errors))

    historical_kwargs = _historical_proof_kwargs(
        proof.ancestor,
        cause_evidence=proof.authorization_cause_evidence,
    )
    prior_authorization = dict(proof.authorization.value)
    prior_manifest = dict(proof.manifest.value)
    prior_state = dict(proof.authorization_state.value)
    prior_failure = dict(proof.failure_evidence.value)
    prior_containment = dict(proof.containment.value)
    prior_ledger = dict(proof.allocation_ledger.value)

    errors.extend(
        f"authorization-predecessor-v5-contract:{item}"
        for item in _validate_full_auto_authorization_v5(
            prior_authorization,
            **historical_kwargs,
            repo_root=None,
        )
    )
    errors.extend(
        f"authorization-predecessor-v2-contract:{item}"
        for item in _validate_campaign_manifest_v2(
            prior_manifest,
            authorization=prior_authorization,
            authorization_raw_sha256=proof.authorization.raw_sha256,
            outer_authority=proof.outer_authority.value,
            outer_authority_raw_sha256=proof.outer_authority.raw_sha256,
            independent_validation_receipt=proof.independent_validation_receipt.value,
            independent_validation_receipt_raw_sha256=(
                proof.independent_validation_receipt.raw_sha256
            ),
            **historical_kwargs,
            repo_root=None,
        )
    )
    errors.extend(
        _validate_independent_validation_session_snapshot(
            proof.independent_validation_receipt.value,
            proof.independent_validation_session_bytes,
        )
    )
    ancestor_original = proof.ancestor.original_containment.value
    errors.extend(
        _validate_contained_session_snapshots(
            session_accounting=ancestor_original.get("session_accounting"),
            ledger=proof.ancestor.allocation_ledger.value,
            raw_sessions=proof.ancestor.contained_session_bytes,
            label="authorization-ancestor",
            historical=True,
        )
    )

    prior_bindings = (
        prior_authorization.get("bindings")
        if isinstance(prior_authorization.get("bindings"), Mapping)
        else {}
    )
    prior_progress = (
        prior_authorization.get("progress_gate")
        if isinstance(prior_authorization.get("progress_gate"), Mapping)
        else {}
    )
    prior_candidate = (
        prior_manifest.get("candidate")
        if isinstance(prior_manifest.get("candidate"), Mapping)
        else {}
    )
    prior_reviews = (
        prior_manifest.get("reviews")
        if isinstance(prior_manifest.get("reviews"), Mapping)
        else {}
    )
    prior_release = (
        prior_manifest.get("release")
        if isinstance(prior_manifest.get("release"), Mapping)
        else {}
    )
    prior_authorization_id = prior_authorization.get("authorization_id")
    prior_nonce = prior_bindings.get("campaign_nonce")
    if (
        proof.authorization.raw_sha256
        != bindings.get("predecessor_authorization_file_sha256")
        or prior_authorization.get("canonical_authorization_sha256")
        != bindings.get("predecessor_authorization_canonical_sha256")
        or prior_authorization_id != bindings.get("predecessor_authorization_id")
        or prior_authorization.get("version") != AUTHORIZATION_VERSION
        or prior_authorization.get("live_generation")
        != predecessor_live_generation
        or proof.manifest.raw_sha256
        != bindings.get("predecessor_manifest_file_sha256")
        or prior_manifest.get("manifest_sha256")
        != bindings.get("predecessor_manifest_canonical_sha256")
        or prior_manifest.get("version") != MANIFEST_VERSION
        or prior_candidate.get("commit")
        != progress.get("predecessor_candidate_commit")
        or prior_candidate.get("tree")
        != progress.get("predecessor_candidate_tree")
    ):
        errors.append("authorization-predecessor-v5-v2-binding-invalid")

    ancestor_lineage = prior_progress.get("predecessor_lineage_sha256")
    prior_manifest_predecessor = (
        prior_manifest.get("predecessor")
        if isinstance(prior_manifest.get("predecessor"), Mapping)
        else {}
    )
    if (
        not _is_hash(ancestor_lineage)
        or ancestor_lineage
        != bindings.get("predecessor_ancestor_lineage_sha256")
        or prior_manifest_predecessor.get("lineage_sha256") != ancestor_lineage
    ):
        errors.append("authorization-predecessor-ancestor-lineage-binding-invalid")

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
        proof.authorization_state.raw_sha256
        != bindings.get("predecessor_authorization_state_file_sha256")
        or prior_state.get("state_sha256")
        != bindings.get("predecessor_authorization_state_canonical_sha256")
        or validate_authorization_state(prior_state)
        or prior_state.get("authorization_id") != prior_authorization_id
        or prior_state.get("run_nonce") != prior_nonce
        or prior_state.get("state") != "containment-only"
        or required_revocations.intersection(prior_state.get("allowed_actions", []))
        or not required_revocations.issubset(
            set(prior_state.get("revoked_actions", []))
        )
    ):
        errors.append("authorization-predecessor-modern-state-binding-invalid")

    audit_sha256 = hashlib.sha256(proof.allocation_audit_bytes).hexdigest()
    ledger_errors = validate_live_allocation_ledger(
        prior_ledger, audit_bytes=proof.allocation_audit_bytes
    )
    if ledger_errors:
        errors.append(
            "authorization-predecessor-modern-ledger-invalid:"
            + ",".join(ledger_errors)
        )
    try:
        ledger_summary = summarize_live_allocation_ledger(
            prior_ledger,
            ledger_file_sha256=proof.allocation_ledger.raw_sha256,
        )
    except (KeyError, NativeLiveAllocationLedgerError, ValueError):
        ledger_summary = {}
    errors.extend(
        _validate_modern_ledger_semantics(
            prior_ledger,
            int(ledger_summary.get("allocation_intent_count") or 0),
        )
    )
    if (
        proof.allocation_ledger.raw_sha256
        != bindings.get("predecessor_allocation_ledger_file_sha256")
        or prior_ledger.get("state_sha256")
        != bindings.get("predecessor_allocation_ledger_state_sha256")
        or audit_sha256 != bindings.get("predecessor_allocation_audit_file_sha256")
        or supersession.get("prior_allocations")
        != ledger_summary.get("allocation_intent_count")
        or ledger_summary.get("unresolved_allocation_intent_count") != 0
        or ledger_summary.get("unresolved_turn_intent_count") != 0
    ):
        errors.append("authorization-predecessor-modern-ledger-binding-invalid")
    ledger_bindings = (
        prior_ledger.get("bindings")
        if isinstance(prior_ledger.get("bindings"), Mapping)
        else {}
    )
    expected_ledger_bindings = {
        "authorization_id": prior_authorization_id,
        "authorization_raw_sha256": proof.authorization.raw_sha256,
        "authorization_canonical_sha256": prior_authorization.get(
            "canonical_authorization_sha256"
        ),
        "campaign_manifest_sha256": prior_manifest.get("manifest_sha256"),
        "campaign_nonce": prior_nonce,
        "live_generation": predecessor_live_generation,
        "predecessor_generation": predecessor_live_generation - 1,
        "candidate_commit": prior_candidate.get("commit"),
        "candidate_tree": prior_candidate.get("tree"),
        "origin_main_commit": prior_candidate.get("origin_main_commit"),
        "guarded_primary_diff_sha256": prior_candidate.get(
            "guarded_primary_diff_sha256"
        ),
        "predecessor_containment_sha256": prior_bindings.get(
            "predecessor_containment_canonical_sha256"
        ),
        "frozen_release_patch_sha256": prior_release.get("patch_file_sha256"),
        "pre_mutation_steering_receipt_sha256": prior_reviews.get(
            "pre_mutation_receipt_canonical_sha256"
        ),
        "pre_live_steering_receipt_sha256": prior_reviews.get(
            "pre_live_receipt_canonical_sha256"
        ),
        "opus_review_sha256": prior_reviews.get("opus_evidence_file_sha256"),
    }
    if any(
        ledger_bindings.get(field) != expected
        for field, expected in expected_ledger_bindings.items()
    ):
        errors.append("authorization-predecessor-modern-ledger-authority-mismatch")

    failure = _strict(
        prior_failure,
        MODERN_FAILURE_EVIDENCE_FIELDS,
        "authorization-predecessor-modern-failure",
        errors,
    )
    failure_bindings = (
        failure.get("campaign_bindings")
        if isinstance(failure.get("campaign_bindings"), Mapping)
        else {}
    )
    failure_containment = (
        failure.get("containment")
        if isinstance(failure.get("containment"), Mapping)
        else {}
    )
    if (
        proof.failure_evidence.raw_sha256
        != bindings.get("predecessor_failure_evidence_file_sha256")
        or failure.get("evidence_sha256")
        != bindings.get("predecessor_failure_evidence_canonical_sha256")
        or failure.get("evidence_sha256")
        != _canonical_artifact_hash(failure, "evidence_sha256")
        or failure.get("authorization_state_sha256")
        != prior_state.get("state_sha256")
        or failure.get("release_gate_passed") is not False
        or failure.get("validation_outcome") != "rejected"
        or failure.get("no_resume_or_salvage") is not True
        or failure.get("glm_5_2_used") is not False
        or failure.get("model_synthesis_used") is not False
        or failure.get("exact_model") != EXACT_OPERATIVE_MODEL
        or failure.get("allocation_ledger") != {"available": True, **ledger_summary}
        or failure_bindings.get("authorization_raw_sha256")
        != proof.authorization.raw_sha256
        or failure_bindings.get("manifest_file_sha256")
        != proof.manifest.raw_sha256
        or failure_bindings.get("manifest_sha256")
        != prior_manifest.get("manifest_sha256")
        or failure_bindings.get("candidate_commit") != prior_candidate.get("commit")
        or failure_bindings.get("candidate_tree") != prior_candidate.get("tree")
        or failure_bindings.get("spark_validation_session_file_sha256")
        != hashlib.sha256(proof.independent_validation_session_bytes).hexdigest()
        or failure_containment.get("allocated_count")
        != ledger_summary.get("allocation_intent_count")
        or failure_containment.get("all_contained") is not True
        or failure_containment.get("ambiguous_count") != 0
        or failure_containment.get("ledger_consistent") is not True
        or failure_containment.get("unresolved_allocation_intent_count") != 0
        or failure_containment.get("unresolved_turn_intent_count") != 0
    ):
        errors.append("authorization-predecessor-modern-failure-binding-invalid")

    containment = _strict(
        prior_containment,
        MODERN_CONTAINMENT_FIELDS,
        "authorization-predecessor-modern-containment",
        errors,
    )
    failed_authorization = (
        containment.get("failed_authorization")
        if isinstance(containment.get("failed_authorization"), Mapping)
        else {}
    )
    failed_manifest = (
        containment.get("failed_manifest")
        if isinstance(containment.get("failed_manifest"), Mapping)
        else {}
    )
    failed_evidence = (
        containment.get("failed_evidence")
        if isinstance(containment.get("failed_evidence"), Mapping)
        else {}
    )
    containment_summary = (
        containment.get("containment")
        if isinstance(containment.get("containment"), Mapping)
        else {}
    )
    containment_ledger = (
        containment.get("allocation_ledger")
        if isinstance(containment.get("allocation_ledger"), Mapping)
        else {}
    )
    control = (
        containment.get("control_plane_recheck")
        if isinstance(containment.get("control_plane_recheck"), Mapping)
        else {}
    )
    disposition = (
        containment.get("disposition")
        if isinstance(containment.get("disposition"), Mapping)
        else {}
    )
    root_cause = (
        containment.get("root_cause")
        if isinstance(containment.get("root_cause"), Mapping)
        else {}
    )
    sessions = containment.get("session_accounting")
    allocated = ledger_summary.get("allocation_intent_count")
    ledger_entries = prior_ledger.get("entries")
    containment_audits = [
        item
        for item in ledger_entries or []
        if isinstance(item, Mapping) and item.get("event") == "containment-audited"
    ]
    contained_count = len(
        [item for item in containment_audits if item.get("outcome") == "contained"]
    )
    already_contained_count = len(
        [
            item
            for item in containment_audits
            if item.get("outcome") == "already-contained"
        ]
    )
    derived_containment_summary = {
        "allocated_count": allocated,
        "identified_thread_count": ledger_summary.get("thread_bound_count"),
        "interrupted_count": contained_count,
        "archived_count": contained_count,
        "already_contained_count": already_contained_count,
        "unresolved_allocation_intent_count": ledger_summary.get(
            "unresolved_allocation_intent_count"
        ),
        "unresolved_turn_intent_count": ledger_summary.get(
            "unresolved_turn_intent_count"
        ),
        "ambiguous_count": 0,
        "all_contained": (
            len(containment_audits) == allocated
            and contained_count + already_contained_count == allocated
        ),
        "ledger_consistent": True,
        "ledger_error_sha256": [],
    }
    if (
        containment.get("schema")
        != "cwo-live-campaign-containment-recovery:v2"
        or proof.containment.raw_sha256
        != bindings.get("predecessor_containment_file_sha256")
        or containment.get("canonical_recovery_sha256")
        != bindings.get("predecessor_containment_canonical_sha256")
        or containment.get("canonical_recovery_sha256")
        != _canonical_artifact_hash(containment, "canonical_recovery_sha256")
        or failed_authorization
        != {
            "authorization_id": prior_authorization_id,
            "campaign_nonce": prior_nonce,
            "canonical_sha256": prior_authorization.get(
                "canonical_authorization_sha256"
            ),
            "file_sha256": proof.authorization.raw_sha256,
            "live_generation": predecessor_live_generation,
        }
        or failed_manifest.get("canonical_sha256")
        != prior_manifest.get("manifest_sha256")
        or failed_manifest.get("file_sha256") != proof.manifest.raw_sha256
        or failed_manifest.get("manifest_id") != prior_manifest.get("manifest_id")
        or failed_evidence.get("canonical_sha256") != failure.get("evidence_sha256")
        or failed_evidence.get("file_sha256") != proof.failure_evidence.raw_sha256
        or failed_evidence.get("authorization_state_canonical_sha256")
        != prior_state.get("state_sha256")
        or failed_evidence.get("authorization_state_file_sha256")
        != proof.authorization_state.raw_sha256
        or containment_summary.get("allocated_count") != allocated
        or containment_summary.get("identified_thread_count") != allocated
        or containment_summary.get("all_contained") is not True
        or containment_summary.get("ambiguous_count") != 0
        or containment_summary.get("ledger_consistent") is not True
        or containment_summary.get("unresolved_allocation_intent_count") != 0
        or containment_summary.get("unresolved_turn_intent_count") != 0
        or dict(containment_summary) != derived_containment_summary
        or not isinstance(failure_containment, Mapping)
        or dict(failure_containment) != derived_containment_summary
        or containment_ledger.get("ledger_file_sha256")
        != proof.allocation_ledger.raw_sha256
        or containment_ledger.get("audit_file_sha256") != audit_sha256
        or containment_ledger.get("state_sha256") != prior_ledger.get("state_sha256")
        or containment_ledger.get("allocation_intent_count") != allocated
        or containment_ledger.get("validation_errors") != []
        or control.get("isolated_checkout_head") != prior_candidate.get("commit")
        or control.get("isolated_checkout_tree") != prior_candidate.get("tree")
        or control.get("origin_main_commit") != prior_candidate.get("origin_main_commit")
        or control.get("protected_primary_diff_sha256")
        != prior_candidate.get("guarded_primary_diff_sha256")
        or control.get("isolated_checkout_tracked_clean") is not True
        or control.get("operative_dispatch_authorized") is not False
        or control.get("release_policy_status") != "canary-gated"
        or disposition.get("authorization_state") != "containment-only"
        or disposition.get("release_gate_passed") is not False
        or disposition.get("requires_fresh_live_generation")
        != predecessor_live_generation + 1
        or disposition.get("requires_validated_candidate_repair") is not True
        or disposition.get("reuse_resume_retry_substitution_salvage_bridge")
        is not False
        or root_cause.get("failure_class")
        != progress.get("predecessor_failure_class")
        or root_cause.get("message_sha256")
        != failure.get("failure_message_sha256")
        or root_cause.get("independent_reproduction") is not True
    ):
        errors.append("authorization-predecessor-modern-containment-binding-invalid")
    if (
        not isinstance(sessions, list)
        or len(sessions) != allocated
        or len(
            {
                item.get("session_id")
                for item in sessions
                if isinstance(item, Mapping)
            }
        )
        != allocated
        or any(
            not isinstance(item, Mapping)
            or not _is_uuid(item.get("session_id"))
            or item.get("active_match_count") != 0
            or item.get("archive_match_count") != 1
            or not _is_hash(item.get("archived_session_file_sha256"))
            for item in sessions or []
        )
    ):
        errors.append("authorization-predecessor-modern-session-accounting-invalid")
    errors.extend(
        _validate_contained_session_snapshots(
            session_accounting=sessions,
            ledger=prior_ledger,
            raw_sessions=proof.contained_session_bytes,
            label="authorization-predecessor-modern",
            historical=False,
        )
    )

    if (
        hashlib.sha256(proof.authorization_cause_evidence).hexdigest()
        != prior_progress.get("cause_evidence_sha256")
    ):
        errors.append("authorization-predecessor-v5-cause-evidence-binding-invalid")
    if (
        proof.outer_authority.raw_sha256
        != prior_bindings.get("outer_authority_file_sha256")
        or proof.outer_authority.value.get("canonical_outer_authority_sha256")
        != prior_bindings.get("outer_authority_canonical_sha256")
        or proof.outer_authority.value.get("authority_id")
        != prior_bindings.get("outer_authority_id")
    ):
        errors.append("authorization-predecessor-outer-authority-binding-invalid")

    if repo_root is not None:
        root = Path(repo_root).resolve()
        try:
            current_checkpoint = str(bindings["checkpoint_commit"])
            prior_checkpoint = str(prior_bindings["checkpoint_commit"])
            ancestor_authorization = proof.ancestor.authorization.value
            ancestor_manifest = proof.ancestor.manifest.value
            ancestor_bindings = (
                ancestor_authorization.get("bindings")
                if isinstance(ancestor_authorization.get("bindings"), Mapping)
                else {}
            )
            ancestor_checkpoint = str(ancestor_bindings["checkpoint_commit"])
            ancestor_candidate = (
                ancestor_manifest.get("candidate")
                if isinstance(ancestor_manifest.get("candidate"), Mapping)
                else {}
            )
            ancestor_candidate_commit = str(ancestor_candidate.get("commit"))
            anchors = (
                (ancestor_checkpoint, ancestor_bindings.get("checkpoint_tree")),
                (ancestor_candidate_commit, ancestor_candidate.get("tree")),
                (prior_checkpoint, prior_bindings.get("checkpoint_tree")),
                (current_checkpoint, bindings.get("checkpoint_tree")),
            )
            for commit, expected_tree in anchors:
                if _run_git(root, "rev-parse", f"{commit}^{{tree}}") != expected_tree:
                    errors.append("authorization-historical-anchor-tree-mismatch")
            for ancestor_commit, descendant_commit in (
                (ancestor_checkpoint, ancestor_candidate_commit),
                (ancestor_candidate_commit, prior_checkpoint),
                (prior_checkpoint, current_checkpoint),
            ):
                if subprocess.run(
                    ["git", "merge-base", "--is-ancestor", ancestor_commit, descendant_commit],
                    cwd=root,
                    capture_output=True,
                ).returncode != 0:
                    errors.append("authorization-historical-anchor-lineage-invalid")
            recorded_origin = bindings.get("origin_main_commit")
            if (
                prior_bindings.get("origin_main_commit") != recorded_origin
                or ancestor_bindings.get("origin_main_commit") != recorded_origin
                or _run_git(root, "rev-parse", "origin/main") != recorded_origin
            ):
                errors.append("authorization-historical-anchor-origin-mismatch")
        except (KeyError, subprocess.CalledProcessError):
            errors.append("authorization-historical-anchor-invalid")
    return sorted(set(errors))


def _v6_common_shadow(authorization: Mapping[str, Any]) -> dict[str, Any]:
    """Project v6 common fields into the frozen v5 structural validator."""

    shadow = json.loads(json.dumps(dict(authorization)))
    shadow["version"] = AUTHORIZATION_VERSION
    shadow["schema"] = AUTHORIZATION_SCHEMA
    bindings = shadow.get("bindings", {})
    bindings["predecessor_original_containment_file_sha256"] = bindings.pop(
        "recovery_cause_evidence_file_sha256", None
    )
    bindings["predecessor_original_containment_canonical_sha256"] = bindings.pop(
        "recovery_cause_evidence_canonical_sha256", None
    )
    bindings.pop("predecessor_ancestor_lineage_sha256", None)
    bindings.pop("validator_contract_sha256", None)
    gates = shadow.get("mandatory_gates", {})
    gates.pop("strict_authorization_v6", None)
    gates.pop("campaign_manifest_v3", None)
    gates.pop("finite_predecessor_proof_dag", None)
    gates.pop("read_once_predecessor_snapshots", None)
    gates.pop("atomic_launch_claim", None)
    gates["strict_authorization_v5"] = True
    gates["campaign_manifest_v2"] = True
    progress = shadow.get("progress_gate", {})
    progress["predecessor_lineage_sha256"] = canonical_sha256(
        _predecessor_lineage(
            bindings, progress, shadow.get("predecessor_live_generation")
        )
    )
    progress.pop("qualification_sha256", None)
    progress["qualification_sha256"] = canonical_sha256(progress)
    shadow.pop("canonical_authorization_sha256", None)
    shadow["canonical_authorization_sha256"] = canonical_sha256(shadow)
    return shadow


def _validate_full_auto_authorization_v6(
    value: Any,
    *,
    expected_campaign_nonce: str | None = None,
    predecessor_proof: Version5PredecessorProofInputs | None = None,
    recovery_cause_evidence: JsonArtifactSnapshot | None = None,
    recovery_cause_source_analysis: bytes | None = None,
    expected_validator_contract_sha256: str | None = None,
    repo_root: Path | None = None,
) -> list[str]:
    errors: list[str] = []
    authorization = _strict(value, AUTHORIZATION_FIELDS, "authorization-v6", errors)
    if not authorization:
        return sorted(set(errors))
    if (
        authorization.get("authorization_type") != AUTHORIZATION_TYPE
        or authorization.get("version") != AUTHORIZATION_VERSION_V6
        or authorization.get("schema") != AUTHORIZATION_SCHEMA_V6
    ):
        errors.append("authorization-v6-header-invalid")
    common_shadow = _v6_common_shadow(authorization)
    errors.extend(
        f"authorization-v6-common:{item}"
        for item in _validate_full_auto_authorization_v5(
            common_shadow,
            expected_campaign_nonce=expected_campaign_nonce,
            repo_root=repo_root,
        )
    )
    bindings = _strict(
        authorization.get("bindings"),
        BINDING_FIELDS_V6,
        "authorization-v6-bindings",
        errors,
    )
    progress = _strict(
        authorization.get("progress_gate"),
        PROGRESS_GATE_FIELDS,
        "authorization-v6-progress-gate",
        errors,
    )
    supersession = _strict(
        authorization.get("supersession"),
        SUPERSESSION_FIELDS,
        "authorization-v6-supersession",
        errors,
    )
    gates = _strict(
        authorization.get("mandatory_gates"),
        MANDATORY_GATE_FIELDS_V6,
        "authorization-v6-mandatory-gates",
        errors,
    )
    if any(gates.get(field) is not True for field in MANDATORY_GATE_FIELDS_V6):
        errors.append("authorization-v6-mandatory-gate-disabled")
    for field in BINDING_FIELDS_V6 - {
        "checkpoint_commit",
        "checkpoint_tree",
        "origin_main_commit",
        "pickup_path",
        "recovery_plan_path",
        "campaign_nonce",
        "predecessor_authorization_id",
        "backup_ref",
        "outer_authority_id",
    }:
        if not _is_hash(bindings.get(field)):
            errors.append(f"authorization-v6-binding-{field.replace('_', '-')}-invalid")
    expected_lineage = _predecessor_lineage_v6(
        bindings, progress, authorization.get("predecessor_live_generation")
    )
    if progress.get("predecessor_lineage_sha256") != canonical_sha256(
        expected_lineage
    ):
        errors.append("authorization-v6-predecessor-lineage-sha256-mismatch")
    unsigned_progress = dict(progress)
    unsigned_progress.pop("qualification_sha256", None)
    if progress.get("qualification_sha256") != canonical_sha256(unsigned_progress):
        errors.append("authorization-v6-progress-qualification-sha256-mismatch")
    unsigned = dict(authorization)
    unsigned.pop("canonical_authorization_sha256", None)
    if authorization.get("canonical_authorization_sha256") != canonical_sha256(
        unsigned
    ):
        errors.append("authorization-v6-canonical-sha256-mismatch")

    if repo_root is not None:
        try:
            observed_contract = validator_contract_sha256(
                Path(repo_root), bindings.get("checkpoint_tree")
            )
        except (OSError, ValueError):
            observed_contract = None
            errors.append("authorization-v6-validator-contract-unavailable")
        if bindings.get("validator_contract_sha256") != observed_contract:
            errors.append("authorization-v6-validator-contract-mismatch")
    if (
        expected_validator_contract_sha256 is not None
        and bindings.get("validator_contract_sha256")
        != expected_validator_contract_sha256
    ):
        errors.append("authorization-v6-expected-validator-contract-mismatch")

    if not isinstance(predecessor_proof, Version5PredecessorProofInputs):
        errors.append("authorization-v6-predecessor-proof-missing")
    else:
        errors.extend(
            _validate_v5_v2_predecessor_proof(
                bindings=bindings,
                progress=progress,
                supersession=supersession,
                predecessor_live_generation=int(
                    authorization.get("predecessor_live_generation", -1)
                ),
                proof=predecessor_proof,
                repo_root=repo_root,
            )
        )
    if not isinstance(recovery_cause_evidence, JsonArtifactSnapshot):
        errors.append("authorization-v6-recovery-cause-evidence-missing")
    elif not isinstance(recovery_cause_source_analysis, bytes):
        errors.append("authorization-v6-recovery-cause-source-analysis-missing")
    elif isinstance(predecessor_proof, Version5PredecessorProofInputs):
        errors.extend(
            _validate_json_snapshot(
                recovery_cause_evidence,
                "authorization-v6-recovery-cause-evidence",
            )
        )
        errors.extend(
            _validate_recovery_cause_evidence(
                recovery_cause_evidence.value,
                raw_sha256=recovery_cause_evidence.raw_sha256,
                bindings=bindings,
                progress=progress,
                predecessor=predecessor_proof,
                source_analysis_bytes=recovery_cause_source_analysis,
            )
        )
    return sorted(set(errors))


def validate_full_auto_authorization(
    value: Any,
    *,
    predecessor_proof: Version5PredecessorProofInputs | None = None,
    recovery_cause_evidence: JsonArtifactSnapshot | None = None,
    recovery_cause_source_analysis: bytes | None = None,
    expected_validator_contract_sha256: str | None = None,
    **legacy_kwargs: Any,
) -> list[str]:
    """Dispatch once to a frozen version validator; never recurse generically."""

    version = value.get("version") if isinstance(value, Mapping) else None
    if version == AUTHORIZATION_VERSION:
        if (
            predecessor_proof is not None
            or recovery_cause_evidence is not None
            or recovery_cause_source_analysis is not None
        ):
            return ["authorization-v5-modern-proof-input-forbidden"]
        return _validate_full_auto_authorization_v5(value, **legacy_kwargs)
    if version == AUTHORIZATION_VERSION_V6:
        legacy_predecessor_keys = {
            key
            for key, item in legacy_kwargs.items()
            if key.startswith("predecessor_") and item is not None
        }
        if legacy_predecessor_keys:
            return ["authorization-v6-legacy-proof-input-forbidden"]
        allowed = {
            "expected_campaign_nonce",
            "repo_root",
        }
        unknown = set(legacy_kwargs) - allowed
        if unknown:
            return ["authorization-v6-validator-arguments-invalid"]
        return _validate_full_auto_authorization_v6(
            value,
            expected_campaign_nonce=legacy_kwargs.get("expected_campaign_nonce"),
            predecessor_proof=predecessor_proof,
            recovery_cause_evidence=recovery_cause_evidence,
            recovery_cause_source_analysis=recovery_cause_source_analysis,
            expected_validator_contract_sha256=expected_validator_contract_sha256,
            repo_root=legacy_kwargs.get("repo_root"),
        )
    return ["authorization-header-invalid"]


def _validate_campaign_manifest_v2(
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
    predecessor_allocation_audit_bytes: bytes | None = None,
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
        auth_errors = _validate_full_auto_authorization_v5(
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
            predecessor_allocation_audit_bytes=predecessor_allocation_audit_bytes,
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


def _v3_common_shadow(
    manifest: Mapping[str, Any], authorization: Mapping[str, Any]
) -> tuple[dict[str, Any], dict[str, Any], str]:
    shadow_authorization = _v6_common_shadow(authorization)
    shadow_authorization_raw = json.dumps(
        shadow_authorization,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode()
    shadow_authorization_raw_sha256 = hashlib.sha256(
        shadow_authorization_raw
    ).hexdigest()
    shadow = json.loads(json.dumps(dict(manifest)))
    shadow["version"] = MANIFEST_VERSION
    shadow["schema"] = MANIFEST_SCHEMA
    shadow["authorization_raw_sha256"] = shadow_authorization_raw_sha256
    shadow["authorization_canonical_sha256"] = shadow_authorization[
        "canonical_authorization_sha256"
    ]
    shadow["progress_qualification_sha256"] = shadow_authorization[
        "progress_gate"
    ]["qualification_sha256"]
    predecessor = shadow.get("predecessor", {})
    predecessor["original_containment_file_sha256"] = predecessor.pop(
        "recovery_cause_evidence_file_sha256", None
    )
    predecessor["original_containment_canonical_sha256"] = predecessor.pop(
        "recovery_cause_evidence_canonical_sha256", None
    )
    predecessor.pop("ancestor_lineage_sha256", None)
    predecessor.pop("validator_contract_sha256", None)
    predecessor["lineage_sha256"] = shadow_authorization["progress_gate"][
        "predecessor_lineage_sha256"
    ]
    shadow.pop("manifest_sha256", None)
    shadow["manifest_sha256"] = canonical_sha256(shadow)
    return shadow, shadow_authorization, shadow_authorization_raw_sha256


def _validate_campaign_manifest_v3(
    value: Any,
    *,
    authorization: Mapping[str, Any] | None,
    authorization_raw_sha256: str | None,
    outer_authority: Mapping[str, Any] | None,
    outer_authority_raw_sha256: str | None,
    predecessor_proof: Version5PredecessorProofInputs | None,
    recovery_cause_evidence: JsonArtifactSnapshot | None,
    recovery_cause_source_analysis: bytes | None,
    independent_validation_receipt: Mapping[str, Any] | None,
    independent_validation_receipt_raw_sha256: str | None,
    expected_validator_contract_sha256: str | None,
    repo_root: Path | None,
    expected_primary_diff_sha256: str | None,
) -> list[str]:
    errors: list[str] = []
    manifest = _strict(value, MANIFEST_FIELDS, "campaign-manifest-v3", errors)
    if not manifest:
        return sorted(set(errors))
    if (
        manifest.get("manifest_type") != MANIFEST_TYPE
        or manifest.get("version") != MANIFEST_VERSION_V3
        or manifest.get("schema") != MANIFEST_SCHEMA_V3
    ):
        errors.append("campaign-manifest-v3-header-invalid")
    unsigned = dict(manifest)
    unsigned.pop("manifest_sha256", None)
    if manifest.get("manifest_sha256") != canonical_sha256(unsigned):
        errors.append("campaign-manifest-v3-sha256-mismatch")
    if not isinstance(authorization, Mapping):
        return sorted(set(errors + ["campaign-manifest-v3-authorization-missing"]))

    shadow, shadow_authorization, shadow_authorization_raw_sha256 = _v3_common_shadow(
        manifest, authorization
    )
    errors.extend(
        f"campaign-manifest-v3-common:{item}"
        for item in _validate_campaign_manifest_v2(
            shadow,
            authorization=shadow_authorization,
            authorization_raw_sha256=shadow_authorization_raw_sha256,
            outer_authority=outer_authority,
            outer_authority_raw_sha256=outer_authority_raw_sha256,
            independent_validation_receipt=independent_validation_receipt,
            independent_validation_receipt_raw_sha256=(
                independent_validation_receipt_raw_sha256
            ),
            repo_root=repo_root,
            expected_primary_diff_sha256=expected_primary_diff_sha256,
        )
    )
    errors.extend(
        f"campaign-manifest-v3-authorization:{item}"
        for item in _validate_full_auto_authorization_v6(
            authorization,
            predecessor_proof=predecessor_proof,
            recovery_cause_evidence=recovery_cause_evidence,
            recovery_cause_source_analysis=recovery_cause_source_analysis,
            expected_validator_contract_sha256=expected_validator_contract_sha256,
            repo_root=repo_root,
        )
    )
    work_units = (
        manifest.get("work_units")
        if isinstance(manifest.get("work_units"), Mapping)
        else {}
    )
    registry = (
        outer_authority.get("active_registry")
        if isinstance(outer_authority, Mapping)
        else None
    )
    expected_scope_key: str | None = None
    try:
        expected_scope_key = active_outer_authority_scope_key(
            work_units.get("epic_id"), work_units.get("parent_work_unit_id")
        )
    except ValueError:
        pass
    if (
        not isinstance(registry, Mapping)
        or set(registry) != {"contract", "scope_key"}
        or registry.get("contract")
        != "cwo-active-outer-authority-registry:v1"
        or registry.get("scope_key") != expected_scope_key
    ):
        errors.append("campaign-manifest-v3-outer-authority-registry-invalid")
    bindings = (
        authorization.get("bindings")
        if isinstance(authorization.get("bindings"), Mapping)
        else {}
    )
    progress = (
        authorization.get("progress_gate")
        if isinstance(authorization.get("progress_gate"), Mapping)
        else {}
    )
    predecessor = _strict(
        manifest.get("predecessor"),
        MANIFEST_PREDECESSOR_FIELDS_V3,
        "campaign-manifest-v3-predecessor",
        errors,
    )
    if not _is_uuid(predecessor.get("authorization_id")) or any(
        not _is_hash(predecessor.get(field))
        for field in MANIFEST_PREDECESSOR_FIELDS_V3
        - {"authorization_id", "candidate_commit", "candidate_tree"}
    ):
        errors.append("campaign-manifest-v3-predecessor-invalid")
    if any(
        not _is_commit(predecessor.get(field))
        for field in ("candidate_commit", "candidate_tree")
    ):
        errors.append("campaign-manifest-v3-predecessor-invalid")
    expected_predecessor = {
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
        "failure_evidence_canonical_sha256": bindings.get(
            "predecessor_failure_evidence_canonical_sha256"
        ),
        "containment_file_sha256": bindings.get(
            "predecessor_containment_file_sha256"
        ),
        "containment_canonical_sha256": bindings.get(
            "predecessor_containment_canonical_sha256"
        ),
        "recovery_cause_evidence_file_sha256": bindings.get(
            "recovery_cause_evidence_file_sha256"
        ),
        "recovery_cause_evidence_canonical_sha256": bindings.get(
            "recovery_cause_evidence_canonical_sha256"
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
        "ancestor_lineage_sha256": bindings.get(
            "predecessor_ancestor_lineage_sha256"
        ),
        "validator_contract_sha256": bindings.get("validator_contract_sha256"),
    }
    if predecessor != expected_predecessor:
        errors.append("campaign-manifest-v3-predecessor-authorization-mismatch")
    if (
        manifest.get("authorization_id") != authorization.get("authorization_id")
        or manifest.get("authorization_raw_sha256") != authorization_raw_sha256
        or manifest.get("authorization_canonical_sha256")
        != authorization.get("canonical_authorization_sha256")
        or manifest.get("progress_qualification_sha256")
        != progress.get("qualification_sha256")
    ):
        errors.append("campaign-manifest-v3-authorization-binding-mismatch")
    return sorted(set(errors))


def validate_campaign_manifest(
    value: Any,
    *,
    predecessor_proof: Version5PredecessorProofInputs | None = None,
    recovery_cause_evidence: JsonArtifactSnapshot | None = None,
    recovery_cause_source_analysis: bytes | None = None,
    expected_validator_contract_sha256: str | None = None,
    **legacy_kwargs: Any,
) -> list[str]:
    """Dispatch once to the immutable v2 or finite-DAG v3 manifest validator."""

    version = value.get("version") if isinstance(value, Mapping) else None
    if version == MANIFEST_VERSION:
        if (
            predecessor_proof is not None
            or recovery_cause_evidence is not None
            or recovery_cause_source_analysis is not None
        ):
            return ["campaign-manifest-v2-modern-proof-input-forbidden"]
        return _validate_campaign_manifest_v2(value, **legacy_kwargs)
    if version == MANIFEST_VERSION_V3:
        legacy_predecessor_keys = {
            key
            for key, item in legacy_kwargs.items()
            if key.startswith("predecessor_") and item is not None
        }
        if legacy_predecessor_keys:
            return ["campaign-manifest-v3-legacy-proof-input-forbidden"]
        allowed = {
            "authorization",
            "authorization_raw_sha256",
            "outer_authority",
            "outer_authority_raw_sha256",
            "independent_validation_receipt",
            "independent_validation_receipt_raw_sha256",
            "repo_root",
            "expected_primary_diff_sha256",
        }
        if set(legacy_kwargs) - allowed:
            return ["campaign-manifest-v3-validator-arguments-invalid"]
        return _validate_campaign_manifest_v3(
            value,
            authorization=legacy_kwargs.get("authorization"),
            authorization_raw_sha256=legacy_kwargs.get(
                "authorization_raw_sha256"
            ),
            outer_authority=legacy_kwargs.get("outer_authority"),
            outer_authority_raw_sha256=legacy_kwargs.get(
                "outer_authority_raw_sha256"
            ),
            predecessor_proof=predecessor_proof,
            recovery_cause_evidence=recovery_cause_evidence,
            recovery_cause_source_analysis=recovery_cause_source_analysis,
            independent_validation_receipt=legacy_kwargs.get(
                "independent_validation_receipt"
            ),
            independent_validation_receipt_raw_sha256=legacy_kwargs.get(
                "independent_validation_receipt_raw_sha256"
            ),
            expected_validator_contract_sha256=expected_validator_contract_sha256,
            repo_root=legacy_kwargs.get("repo_root"),
            expected_primary_diff_sha256=legacy_kwargs.get(
                "expected_primary_diff_sha256"
            ),
        )
    return ["campaign-manifest-header-invalid"]


def validate_release_patch_result(
    repo_root: Path,
    patch_path: Path | None,
    manifest: Mapping[str, Any],
    *,
    patch_bytes: bytes | None = None,
) -> list[str]:
    errors: list[str] = []
    root = Path(repo_root).resolve()
    release = manifest.get("release") if isinstance(manifest.get("release"), Mapping) else {}
    candidate = manifest.get("candidate") if isinstance(manifest.get("candidate"), Mapping) else {}
    if patch_bytes is None:
        if patch_path is None:
            return ["release-patch-unavailable"]
        try:
            patch_bytes = Path(patch_path).resolve().read_bytes()
        except OSError:
            return ["release-patch-unavailable"]
    if not isinstance(patch_bytes, bytes) or not patch_bytes:
        return ["release-patch-unavailable"]
    if hashlib.sha256(patch_bytes).hexdigest() != release.get("patch_file_sha256"):
        return ["release-patch-file-sha256-mismatch"]
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
                ["git", "apply", "--check", "-"],
                cwd=worktree,
                check=True,
                capture_output=True,
                input=patch_bytes,
            )
            subprocess.run(
                ["git", "apply", "--index", "-"],
                cwd=worktree,
                check=True,
                capture_output=True,
                input=patch_bytes,
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
