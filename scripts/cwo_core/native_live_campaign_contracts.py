"""Strict successor authority and manifest contracts for native live campaigns."""

# ruff: noqa: F841

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

from .native_canary_contracts import (
    canonical_sha256 as _domain_sha256,
    validate_authorization_state,
    validate_steering_receipt,
)
from .native_live_allocation_ledger import (
    NativeLiveAllocationLedgerError,
    _state_sha256 as _allocation_ledger_state_sha256,
    summarize_live_allocation_ledger,
    validate_live_allocation_ledger,
)


AUTHORIZATION_TYPE = "cwo-full-auto-run-authorization"
AUTHORIZATION_VERSION = 5
AUTHORIZATION_SCHEMA = "schemas/full-auto-run-authorization.schema.json"
AUTHORIZATION_VERSION_V6 = 6
AUTHORIZATION_SCHEMA_V6 = "schemas/full-auto-run-authorization-v6.schema.json"
AUTHORIZATION_VERSION_V7 = 7
AUTHORIZATION_SCHEMA_V7 = "schemas/full-auto-run-authorization-v7.schema.json"
AUTHORIZATION_VERSION_V8 = 8
AUTHORIZATION_SCHEMA_V8 = "schemas/full-auto-run-authorization-v8.schema.json"
AUTHORIZATION_VERSION_V9 = 9
AUTHORIZATION_SCHEMA_V9 = "schemas/full-auto-run-authorization-v9.schema.json"
AUTHORIZATION_VERSION_V10 = 10
AUTHORIZATION_SCHEMA_V10 = "schemas/full-auto-run-authorization-v10.schema.json"
AUTHORIZATION_VERSION_V11 = 11
AUTHORIZATION_SCHEMA_V11 = "schemas/full-auto-run-authorization-v11.schema.json"
MANIFEST_TYPE = "cwo-native-live-campaign-manifest"
MANIFEST_VERSION = 2
MANIFEST_SCHEMA = "schemas/native-live-campaign-manifest.schema.json"
MANIFEST_VERSION_V3 = 3
MANIFEST_SCHEMA_V3 = "schemas/native-live-campaign-manifest-v3.schema.json"
MANIFEST_VERSION_V4 = 4
MANIFEST_SCHEMA_V4 = "schemas/native-live-campaign-manifest-v4.schema.json"
MANIFEST_VERSION_V5 = 5
MANIFEST_SCHEMA_V5 = "schemas/native-live-campaign-manifest-v5.schema.json"
MANIFEST_VERSION_V6 = 6
MANIFEST_SCHEMA_V6 = "schemas/native-live-campaign-manifest-v6.schema.json"
MANIFEST_VERSION_V7 = 7
MANIFEST_SCHEMA_V7 = "schemas/native-live-campaign-manifest-v7.schema.json"
MANIFEST_VERSION_V8 = 8
MANIFEST_SCHEMA_V8 = "schemas/native-live-campaign-manifest-v8.schema.json"
LAUNCH_CLAIM_VERSION_V6 = 6
VALIDATOR_CONTRACT_VERSION_V6 = 6
OPERATIVE_VERSION_TUPLE = (
    AUTHORIZATION_VERSION_V11,
    MANIFEST_VERSION_V8,
    LAUNCH_CLAIM_VERSION_V6,
    VALIDATOR_CONTRACT_VERSION_V6,
)
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
BINDING_FIELDS_V7 = set(BINDING_FIELDS_V6)
BINDING_FIELDS_V8 = set(BINDING_FIELDS_V7) | {
    "predecessor_failure_ledger_prefix_file_sha256",
    "predecessor_failure_ledger_prefix_state_sha256",
    "predecessor_failure_ledger_prefix_head_entry_sha256",
    "predecessor_quarantined_session_file_sha256",
}
BINDING_FIELDS_V9 = set(BINDING_FIELDS_V7) | {
    "predecessor_contained_session_family_sha256",
    "predecessor_contained_session_count",
}
BINDING_FIELDS_V10 = (
    BINDING_FIELDS_V7
    - {
        "predecessor_allocation_ledger_file_sha256",
        "predecessor_allocation_ledger_state_sha256",
        "predecessor_allocation_audit_file_sha256",
    }
) | {
    "predecessor_global_claim_file_sha256",
    "predecessor_global_claim_canonical_sha256",
    "predecessor_authorization_marker_file_sha256",
    "predecessor_authorization_marker_canonical_sha256",
    "predecessor_nonce_marker_file_sha256",
    "predecessor_nonce_marker_canonical_sha256",
    "predecessor_scope_state_file_sha256",
    "predecessor_scope_state_canonical_sha256",
    "predecessor_launch_claim_sha256",
    "predecessor_preflight_file_sha256",
    "predecessor_preflight_canonical_sha256",
    "predecessor_pre_mutation_receipt_file_sha256",
    "predecessor_pre_mutation_receipt_canonical_sha256",
    "predecessor_pre_live_receipt_file_sha256",
    "predecessor_pre_live_receipt_canonical_sha256",
}
BINDING_FIELDS_V11 = set(BINDING_FIELDS_V10) | {
    "predecessor_allocation_ledger_file_sha256",
    "predecessor_allocation_ledger_state_sha256",
    "predecessor_allocation_ledger_head_entry_sha256",
    "predecessor_allocation_audit_file_sha256",
    "predecessor_steering_registry_file_sha256",
    "predecessor_terminal_session_file_sha256",
    "predecessor_terminal_session_id",
    "predecessor_terminal_turn_id",
    "predecessor_initial_empty_boundary_sha256",
    "predecessor_recovery_entry_sha256",
    "predecessor_interrupted_terminal_event_sha256",
    "predecessor_no_replacement_read_sha256",
    "predecessor_outer_authority_file_sha256",
    "predecessor_outer_authority_canonical_sha256",
    "predecessor_independent_validation_receipt_file_sha256",
    "predecessor_independent_validation_receipt_canonical_sha256",
    "predecessor_independent_validation_session_file_sha256",
    "predecessor_authorization_recovery_cause_evidence_file_sha256",
    "predecessor_authorization_recovery_cause_evidence_canonical_sha256",
    "predecessor_authorization_recovery_cause_source_analysis_sha256",
    "predecessor_terminal_facts_file_sha256",
    "predecessor_terminal_facts_canonical_sha256",
    "predecessor_generation11_runner_source_sha256",
    "predecessor_generation11_session_boundary_source_sha256",
    "predecessor_pre_mutation_adjudication_file_sha256",
    "predecessor_pre_mutation_adjudication_canonical_sha256",
    "predecessor_pre_live_adjudication_file_sha256",
    "predecessor_pre_live_adjudication_canonical_sha256",
    "predecessor_recovery_cause_analysis_sha256",
    "predecessor_recovery_steering_receipt_file_sha256",
    "predecessor_recovery_steering_receipt_canonical_sha256",
    "predecessor_recovery_steering_session_file_sha256",
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
MANDATORY_GATE_FIELDS_V7 = (
    MANDATORY_GATE_FIELDS_V6
    - {"strict_authorization_v6", "campaign_manifest_v3"}
) | {
    "strict_authorization_v7",
    "campaign_manifest_v4",
}
MANDATORY_GATE_FIELDS_V8 = (
    MANDATORY_GATE_FIELDS_V7
    - {"strict_authorization_v7", "campaign_manifest_v4"}
) | {
    "strict_authorization_v8",
    "campaign_manifest_v5",
    "nonattesting_quarantine_predecessor_proof",
}
MANDATORY_GATE_FIELDS_V9 = (
    MANDATORY_GATE_FIELDS_V7
    - {"strict_authorization_v7", "campaign_manifest_v4"}
) | {
    "strict_authorization_v9",
    "campaign_manifest_v6",
    "protected_fault_predecessor_proof",
}
MANDATORY_GATE_FIELDS_V10 = (
    MANDATORY_GATE_FIELDS_V7
    - {"strict_authorization_v7", "campaign_manifest_v4"}
) | {
    "strict_authorization_v10",
    "campaign_manifest_v7",
    "preallocation_fault_predecessor_proof",
    "shared_preclaim_steering_binding",
}
MANDATORY_GATE_FIELDS_V11 = (
    MANDATORY_GATE_FIELDS_V7
    - {"strict_authorization_v7", "campaign_manifest_v4"}
) | {
    "strict_authorization_v11",
    "campaign_manifest_v8",
    "interrupted_empty_boundary_predecessor_proof",
    "terminal_recovery_facts_binding",
    "consumed_steering_receipts_binding",
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
MANIFEST_PREDECESSOR_FIELDS_V4 = set(MANIFEST_PREDECESSOR_FIELDS_V3)
MANIFEST_PREDECESSOR_FIELDS_V5 = set(MANIFEST_PREDECESSOR_FIELDS_V4) | {
    "failure_ledger_prefix_file_sha256",
    "failure_ledger_prefix_state_sha256",
    "failure_ledger_prefix_head_entry_sha256",
    "quarantined_session_file_sha256",
}
MANIFEST_PREDECESSOR_FIELDS_V6 = set(MANIFEST_PREDECESSOR_FIELDS_V4) | {
    "contained_session_family_sha256",
    "contained_session_count",
}
MANIFEST_PREDECESSOR_FIELDS_V7 = (
    MANIFEST_PREDECESSOR_FIELDS_V4
    - {
        "allocation_ledger_file_sha256",
        "allocation_ledger_state_sha256",
        "allocation_audit_file_sha256",
    }
) | {
    "global_claim_file_sha256",
    "global_claim_canonical_sha256",
    "authorization_marker_file_sha256",
    "authorization_marker_canonical_sha256",
    "nonce_marker_file_sha256",
    "nonce_marker_canonical_sha256",
    "scope_state_file_sha256",
    "scope_state_canonical_sha256",
    "launch_claim_sha256",
    "preflight_file_sha256",
    "preflight_canonical_sha256",
    "pre_mutation_receipt_file_sha256",
    "pre_mutation_receipt_canonical_sha256",
    "pre_live_receipt_file_sha256",
    "pre_live_receipt_canonical_sha256",
}
MANIFEST_PREDECESSOR_FIELDS_V8 = set(MANIFEST_PREDECESSOR_FIELDS_V7) | {
    field.removeprefix("predecessor_")
    for field in BINDING_FIELDS_V11 - BINDING_FIELDS_V10
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
QUARANTINE_CONTAINMENT_FIELDS = MODERN_CONTAINMENT_FIELDS | {"scope_transition"}
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
GENERATION11_FAILURE_MESSAGE_SHA256 = (
    "585a72e5ebc2ab85317272de36f26b47e10cd0850a30d0c9681f8a6523f8451f"
)
GENERATION11_RUNNER_SOURCE_SHA256 = (
    "6bc88446cd12722244378ee9eff616f0056ff2d14375dd5391f7ba575c249e5c"
)
GENERATION11_SESSION_BOUNDARY_SOURCE_SHA256 = (
    "ea0f587f7ec6b38898393b16201afe8b05decd29ad343d406a22e7a6daebfc37"
)
GENERATION11_CONTAINMENT_FIELDS = {
    "allocation_ledger",
    "bead_id",
    "canonical_recovery_sha256",
    "claim_v5_and_scope",
    "contained_session",
    "containment",
    "control_plane_recheck",
    "control_turn_id",
    "disposition",
    "failed_authority",
    "generation12_recovery_contract",
    "recorded_at",
    "root_cause",
    "schema",
    "steering_consumptions",
    "terminal_failure",
    "version",
}
GENERATION11_INITIAL_EMPTY_BOUNDARY = {
    "availability": "materialized-empty",
    "boundary_sha256": hashlib.sha256(b"").hexdigest(),
    "byte_offset": 0,
    "invalid_record_count": 0,
    "record_count": 0,
    "trailing_partial": False,
}
GENERATION11_RECOVERY_ENTRY = {
    "entered": True,
    "operation": "thread/read",
    "trigger": "transient-rpc-fault",
    "before_trusted_attestation": True,
    "before_operative_activity": True,
}
GENERATION11_NO_REPLACEMENT_READ = {
    "replacement_attempted": False,
    "replacement_thread_count": 0,
    "replacement_turn_count": 0,
    "replacement_session_count": 0,
}
GENERATION11_TERMINAL_FACTS_FIELDS = {
    "artifact_type",
    "version",
    "schema",
    "recorded_at",
    "identity",
    "source_bindings",
    "facts",
    "source_root_sha256",
    "canonical_terminal_facts_sha256",
}
GENERATION11_TERMINAL_FACT_IDENTITY_FIELDS = {
    "authorization_id",
    "manifest_id",
    "campaign_nonce",
    "control_turn_id",
    "bead_id",
    "work_unit_id",
    "live_generation",
    "session_id",
    "turn_id",
    "candidate_commit",
    "candidate_tree",
}
GENERATION11_TERMINAL_FACT_SOURCE_FIELDS = {
    "authorization_file_sha256",
    "manifest_file_sha256",
    "authorization_state_file_sha256",
    "failure_evidence_file_sha256",
    "containment_file_sha256",
    "global_claim_file_sha256",
    "authorization_marker_file_sha256",
    "nonce_marker_file_sha256",
    "scope_state_file_sha256",
    "preflight_file_sha256",
    "pre_mutation_receipt_file_sha256",
    "pre_mutation_adjudication_file_sha256",
    "pre_live_receipt_file_sha256",
    "pre_live_adjudication_file_sha256",
    "allocation_ledger_file_sha256",
    "allocation_audit_file_sha256",
    "steering_registry_file_sha256",
    "terminal_session_file_sha256",
    "outer_authority_file_sha256",
    "recovery_cause_analysis_sha256",
    "recovery_steering_receipt_file_sha256",
    "recovery_steering_session_file_sha256",
    "generation11_runner_source_sha256",
    "generation11_session_boundary_source_sha256",
}
GENERATION11_TERMINAL_FACT_NAMES = {
    "initial_empty_boundary",
    "recovery_entry",
    "interrupted_terminal_event",
    "no_replacement_read",
}
GENERATION11_STEERING_ADJUDICATION_FIELDS = {
    "adjudication_type",
    "recorded_at",
    "bead_id",
    "control_turn_id",
    "gate",
    "authorization_id",
    "authorization_file_sha256",
    "candidate_commit",
    "candidate_tree",
    "sol_receipt_file_sha256",
    "sol_receipt_canonical_sha256",
    "sol_session_file_sha256",
    "sol_session_id",
    "sol_recommendation",
    "sol_confidence",
    "opus_evidence_file_sha256",
    "opus_adjudication_file_sha256",
    "spark_validation_receipt_file_sha256",
    "spark_validation_receipt_canonical_sha256",
    "main_architect_decision",
    "main_confidence",
    "combined_confidence",
    "combined_confidence_formula",
    "condition_adjudication",
    "unresolved_high_findings",
    "unresolved_medium_findings",
    "zero_allocation_preflight_required",
    "manifest_authorized",
    "live_campaign_authorized",
    "live_campaign_single_shot",
    "live_campaign_start_count_exact",
    "release_authorized",
    "publication_authorized",
    "glm52",
    "synthesis",
    "canonical_adjudication_sha256",
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


@dataclass(frozen=True)
class Version6PredecessorProofInputs:
    """Read-once inputs for one v6/v3 predecessor and its fixed v5/v2 DAG."""

    authorization: JsonArtifactSnapshot
    manifest: JsonArtifactSnapshot
    authorization_state: JsonArtifactSnapshot
    failure_evidence: JsonArtifactSnapshot
    containment: JsonArtifactSnapshot
    allocation_ledger: JsonArtifactSnapshot
    allocation_audit_bytes: bytes
    authorization_recovery_cause_evidence: JsonArtifactSnapshot
    authorization_recovery_cause_source_analysis: bytes
    outer_authority: JsonArtifactSnapshot
    independent_validation_receipt: JsonArtifactSnapshot
    independent_validation_session_bytes: bytes
    ancestor: Version5PredecessorProofInputs
    contained_session_bytes: tuple[bytes, ...] = ()


@dataclass(frozen=True)
class Version7QuarantinePredecessorProofInputs:
    """Read-once Generation-8 quarantine leaf for a v8/v5 successor.

    This is deliberately not an accepting predecessor proof.  Its archived
    session is nonattesting evidence used only to prove terminal containment of
    the failed v7/v4 campaign before a fresh generation may be authorized.
    """

    authorization: JsonArtifactSnapshot
    manifest: JsonArtifactSnapshot
    authorization_state: JsonArtifactSnapshot
    failure_evidence: JsonArtifactSnapshot
    containment: JsonArtifactSnapshot
    allocation_ledger: JsonArtifactSnapshot
    allocation_audit_bytes: bytes
    authorization_recovery_cause_evidence: JsonArtifactSnapshot
    authorization_recovery_cause_source_analysis: bytes
    outer_authority: JsonArtifactSnapshot
    independent_validation_receipt: JsonArtifactSnapshot
    independent_validation_session_bytes: bytes
    ancestor: Version6PredecessorProofInputs
    quarantined_session_bytes: bytes


@dataclass(frozen=True)
class Version8ProtectedFaultPredecessorProofInputs:
    """Read-once terminal Generation-9 leaf for a v9/v6 successor.

    The immediate predecessor is evidence only. Its five archived sessions and
    terminal ledger prove containment of a protected-fault campaign; its fixed
    v8/v5 ancestor preserves the complete finite historical proof DAG.
    """

    authorization: JsonArtifactSnapshot
    manifest: JsonArtifactSnapshot
    authorization_state: JsonArtifactSnapshot
    failure_evidence: JsonArtifactSnapshot
    containment: JsonArtifactSnapshot
    allocation_ledger: JsonArtifactSnapshot
    allocation_audit_bytes: bytes
    authorization_recovery_cause_evidence: JsonArtifactSnapshot
    authorization_recovery_cause_source_analysis: bytes
    outer_authority: JsonArtifactSnapshot
    independent_validation_receipt: JsonArtifactSnapshot
    independent_validation_session_bytes: bytes
    ancestor: Version7QuarantinePredecessorProofInputs
    contained_session_bytes: tuple[bytes, ...]


@dataclass(frozen=True)
class Version9PreallocationFaultPredecessorProofInputs:
    """Read-once terminal Generation-10 leaf for a v10/v7 successor."""

    authorization: JsonArtifactSnapshot
    manifest: JsonArtifactSnapshot
    authorization_state: JsonArtifactSnapshot
    failure_evidence: JsonArtifactSnapshot
    containment: JsonArtifactSnapshot
    global_claim: JsonArtifactSnapshot
    authorization_marker: JsonArtifactSnapshot
    nonce_marker: JsonArtifactSnapshot
    scope_state: JsonArtifactSnapshot
    preflight: JsonArtifactSnapshot
    pre_mutation_receipt: JsonArtifactSnapshot
    pre_live_receipt: JsonArtifactSnapshot
    authorization_recovery_cause_evidence: JsonArtifactSnapshot
    authorization_recovery_cause_source_analysis: bytes
    outer_authority: JsonArtifactSnapshot
    independent_validation_receipt: JsonArtifactSnapshot
    independent_validation_session_bytes: bytes
    ancestor: Version8ProtectedFaultPredecessorProofInputs


@dataclass(frozen=True)
class Version10InterruptedEmptyBoundaryPredecessorProofInputs:
    """Read-once terminal Generation-11 leaf for a v11/v8 successor.

    The immediate predecessor is evidence only.  Its one archived Spark/LOW
    session, terminal-facts seal, allocation ledger, and steering-consumption
    registry prove that the empty-boundary recovery fault was interrupted and
    contained without a replacement read or operative activity.  The fixed
    v10/v7 ancestor preserves the complete historical proof DAG.
    """

    authorization: JsonArtifactSnapshot
    manifest: JsonArtifactSnapshot
    authorization_state: JsonArtifactSnapshot
    failure_evidence: JsonArtifactSnapshot
    global_claim: JsonArtifactSnapshot
    authorization_marker: JsonArtifactSnapshot
    nonce_marker: JsonArtifactSnapshot
    scope_state: JsonArtifactSnapshot
    preflight: JsonArtifactSnapshot
    pre_mutation_receipt: JsonArtifactSnapshot
    pre_mutation_adjudication: JsonArtifactSnapshot
    pre_live_receipt: JsonArtifactSnapshot
    pre_live_adjudication: JsonArtifactSnapshot
    allocation_ledger: JsonArtifactSnapshot
    allocation_audit_bytes: bytes
    steering_registry: JsonArtifactSnapshot
    terminal_session_bytes: bytes
    containment: JsonArtifactSnapshot
    terminal_facts: JsonArtifactSnapshot
    generation11_runner_source_bytes: bytes
    generation11_session_boundary_source_bytes: bytes
    recovery_cause_analysis_bytes: bytes
    recovery_steering_receipt: JsonArtifactSnapshot
    recovery_steering_session_bytes: bytes
    authorization_recovery_cause_evidence: JsonArtifactSnapshot
    authorization_recovery_cause_source_analysis: bytes
    outer_authority: JsonArtifactSnapshot
    independent_validation_receipt: JsonArtifactSnapshot
    independent_validation_session_bytes: bytes
    ancestor: Version9PreallocationFaultPredecessorProofInputs


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
QUARANTINE_LEDGER_EVENT_SEQUENCE = (
    "allocation-intent",
    "thread-bound",
    "turn-intent",
    "turn-bound",
    "archive-observed",
    "containment-audited",
)
QUARANTINE_LEDGER_OUTCOME_SEQUENCE = (
    "pending",
    "bound",
    "pending",
    "bound",
    "archive-request-accepted",
    "contained",
)
GENERATION11_TERMINAL_LEDGER_GRAMMAR = (
    ("capability-calibration", "allocation-intent", "pending"),
    ("capability-calibration", "thread-bound", "bound"),
    ("capability-calibration", "turn-intent", "pending"),
    ("capability-calibration", "turn-bound", "bound"),
    ("capability-calibration", "archive-observed", "archive-request-accepted"),
    ("capability-calibration", "containment-audited", "contained"),
)


def canonical_sha256(value: Any) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _is_hash(value: Any) -> bool:
    return isinstance(value, str) and bool(HASH_RE.fullmatch(value))


def _is_commit(value: Any) -> bool:
    return isinstance(value, str) and bool(COMMIT_RE.fullmatch(value))


def _is_parseable_uuid(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    try:
        uuid.UUID(value)
    except ValueError:
        return False
    return True


def _is_uuid(value: Any) -> bool:
    return _is_parseable_uuid(value) and str(uuid.UUID(value)) == value


def _is_int(value: Any, minimum: int = 0) -> bool:
    return not isinstance(value, bool) and isinstance(value, int) and value >= minimum


def _generation_or_invalid(value: Any) -> int:
    """Return a validated generation without raising on hostile schema input."""
    return value if _is_int(value, 0) else -1


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


VALIDATOR_CONTRACT_PATHS_V1 = (
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
VALIDATOR_CONTRACT_PATHS_V2 = VALIDATOR_CONTRACT_PATHS_V1 + (
    "schemas/full-auto-run-authorization-v7.schema.json",
    "schemas/native-live-campaign-manifest-v4.schema.json",
)
VALIDATOR_CONTRACT_PATHS_V3 = VALIDATOR_CONTRACT_PATHS_V2 + (
    "schemas/full-auto-run-authorization-v8.schema.json",
    "schemas/native-live-campaign-manifest-v5.schema.json",
)
VALIDATOR_CONTRACT_PATHS_V4 = VALIDATOR_CONTRACT_PATHS_V3 + (
    "schemas/full-auto-run-authorization-v9.schema.json",
    "schemas/native-live-campaign-manifest-v6.schema.json",
)
VALIDATOR_CONTRACT_PATHS_V5 = VALIDATOR_CONTRACT_PATHS_V4 + (
    "schemas/full-auto-run-authorization-v10.schema.json",
    "schemas/native-live-campaign-manifest-v7.schema.json",
)
VALIDATOR_CONTRACT_PATHS_V6 = VALIDATOR_CONTRACT_PATHS_V5 + (
    "scripts/cwo_core/native_pool_config.py",
    "schemas/full-auto-run-authorization-v11.schema.json",
    "schemas/native-live-campaign-manifest-v8.schema.json",
    "schemas/generation11-terminal-facts.schema.json",
)
# Historical callers imported this name when v1 was the only contract. Keep the
# alias immutable; Generation 8 must opt in to the explicitly versioned v2 API.
VALIDATOR_CONTRACT_PATHS = VALIDATOR_CONTRACT_PATHS_V1


def _validator_contract_sha256(
    repo_root: Path,
    checkpoint_tree: str | None,
    *,
    paths: tuple[str, ...],
    contract: str,
    proof_dag: tuple[str, ...],
    ancestor_depth_exact: int,
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
    for relative in paths:
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
            "contract": contract,
            "proof_dag": list(proof_dag),
            "ancestor_depth_exact": ancestor_depth_exact,
            "checkpoint_tree": checkpoint_tree,
            "files": files,
        }
    )


def validator_contract_sha256(
    repo_root: Path, checkpoint_tree: str | None = None
) -> str:
    """Reproduce the frozen Generation-7 validator-contract v1 digest."""

    return _validator_contract_sha256(
        repo_root,
        checkpoint_tree,
        paths=VALIDATOR_CONTRACT_PATHS_V1,
        contract="cwo-live-successor-validator:v1",
        proof_dag=("v6/v3", "v5/v2", "v4/v1"),
        ancestor_depth_exact=1,
    )


def validator_contract_sha256_v2(
    repo_root: Path, checkpoint_tree: str | None = None
) -> str:
    """Bind the fixed Generation-8 v7/v4 finite predecessor proof DAG."""

    return _validator_contract_sha256(
        repo_root,
        checkpoint_tree,
        paths=VALIDATOR_CONTRACT_PATHS_V2,
        contract="cwo-live-successor-validator:v2",
        proof_dag=("v7/v4", "v6/v3", "v5/v2", "v4/v1"),
        ancestor_depth_exact=2,
    )


def validator_contract_sha256_v3(
    repo_root: Path, checkpoint_tree: str | None = None
) -> str:
    """Bind the v8/v5 DAG and its dedicated nonattesting quarantine leaf."""

    return _validator_contract_sha256(
        repo_root,
        checkpoint_tree,
        paths=VALIDATOR_CONTRACT_PATHS_V3,
        contract="cwo-live-successor-validator:v3",
        proof_dag=("v8/v5", "v7/v4", "v6/v3", "v5/v2", "v4/v1"),
        ancestor_depth_exact=3,
    )


def validator_contract_sha256_v4(
    repo_root: Path, checkpoint_tree: str | None = None
) -> str:
    """Bind the v9/v6 DAG and its terminal protected-fault predecessor leaf."""

    return _validator_contract_sha256(
        repo_root,
        checkpoint_tree,
        paths=VALIDATOR_CONTRACT_PATHS_V4,
        contract="cwo-live-successor-validator:v4",
        proof_dag=(
            "v9/v6",
            "v8/v5",
            "v7/v4",
            "v6/v3",
            "v5/v2",
            "v4/v1",
        ),
        ancestor_depth_exact=4,
    )


def validator_contract_sha256_v5(
    repo_root: Path, checkpoint_tree: str | None = None
) -> str:
    """Bind the v10/v7 DAG and its zero-allocation preflight-fault leaf."""

    return _validator_contract_sha256(
        repo_root,
        checkpoint_tree,
        paths=VALIDATOR_CONTRACT_PATHS_V5,
        contract="cwo-live-successor-validator:v5",
        proof_dag=(
            "v10/v7",
            "v9/v6",
            "v8/v5",
            "v7/v4",
            "v6/v3",
            "v5/v2",
            "v4/v1",
        ),
        ancestor_depth_exact=5,
    )


def validator_contract_sha256_v6(
    repo_root: Path, checkpoint_tree: str | None = None
) -> str:
    """Bind the v11/v8 DAG and terminal interrupted-empty-boundary leaf."""

    return _validator_contract_sha256(
        repo_root,
        checkpoint_tree,
        paths=VALIDATOR_CONTRACT_PATHS_V6,
        contract="cwo-live-successor-validator:v6",
        proof_dag=(
            "v11/v8",
            "v10/v7",
            "v9/v6",
            "v8/v5",
            "v7/v4",
            "v6/v3",
            "v5/v2",
            "v4/v1",
        ),
        ancestor_depth_exact=6,
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


def _predecessor_lineage_v7(
    bindings: Mapping[str, Any],
    progress: Mapping[str, Any],
    predecessor_live_generation: Any,
) -> dict[str, Any]:
    """Ordered identity for the fixed v7 -> v6 -> v5 -> v4 proof DAG."""

    return dict(
        _predecessor_lineage_v6(
            bindings, progress, predecessor_live_generation
        )
    )


def _predecessor_lineage_v8(
    bindings: Mapping[str, Any],
    progress: Mapping[str, Any],
    predecessor_live_generation: Any,
) -> dict[str, Any]:
    """Identity for v8's dedicated v7 quarantine predecessor leaf."""

    lineage = _predecessor_lineage_v7(
        bindings, progress, predecessor_live_generation
    )
    lineage.update(
        {
            "failure_ledger_prefix_file_sha256": bindings.get(
                "predecessor_failure_ledger_prefix_file_sha256"
            ),
            "failure_ledger_prefix_state_sha256": bindings.get(
                "predecessor_failure_ledger_prefix_state_sha256"
            ),
            "failure_ledger_prefix_head_entry_sha256": bindings.get(
                "predecessor_failure_ledger_prefix_head_entry_sha256"
            ),
            "quarantined_session_file_sha256": bindings.get(
                "predecessor_quarantined_session_file_sha256"
            ),
        }
    )
    return lineage


def _predecessor_lineage_v9(
    bindings: Mapping[str, Any],
    progress: Mapping[str, Any],
    predecessor_live_generation: Any,
) -> dict[str, Any]:
    """Identity for v9's terminal v8/v5 protected-fault predecessor leaf."""

    lineage = _predecessor_lineage_v7(
        bindings, progress, predecessor_live_generation
    )
    lineage.update(
        {
            "contained_session_family_sha256": bindings.get(
                "predecessor_contained_session_family_sha256"
            ),
            "contained_session_count": bindings.get(
                "predecessor_contained_session_count"
            ),
        }
    )
    return lineage


def _predecessor_lineage_v10(
    bindings: Mapping[str, Any],
    progress: Mapping[str, Any],
    predecessor_live_generation: Any,
) -> dict[str, Any]:
    """Identity for v10's terminal v9/v6 preallocation-fault leaf."""

    lineage = _predecessor_lineage_v7(
        bindings, progress, predecessor_live_generation
    )
    lineage.update(
        {
            field.removeprefix("predecessor_"): bindings.get(field)
            for field in (
                "predecessor_global_claim_file_sha256",
                "predecessor_global_claim_canonical_sha256",
                "predecessor_authorization_marker_file_sha256",
                "predecessor_authorization_marker_canonical_sha256",
                "predecessor_nonce_marker_file_sha256",
                "predecessor_nonce_marker_canonical_sha256",
                "predecessor_scope_state_file_sha256",
                "predecessor_scope_state_canonical_sha256",
                "predecessor_launch_claim_sha256",
                "predecessor_preflight_file_sha256",
                "predecessor_preflight_canonical_sha256",
                "predecessor_pre_mutation_receipt_file_sha256",
                "predecessor_pre_mutation_receipt_canonical_sha256",
                "predecessor_pre_live_receipt_file_sha256",
                "predecessor_pre_live_receipt_canonical_sha256",
            )
        }
    )
    return lineage


def _predecessor_lineage_v11(
    bindings: Mapping[str, Any],
    progress: Mapping[str, Any],
    predecessor_live_generation: Any,
) -> dict[str, Any]:
    """Identity for v11's terminal Generation-11 recovery-fault leaf."""

    lineage = _predecessor_lineage_v10(
        bindings, progress, predecessor_live_generation
    )
    lineage.update(
        {
            field.removeprefix("predecessor_"): bindings.get(field)
            for field in BINDING_FIELDS_V11 - BINDING_FIELDS_V10
        }
    )
    return lineage


def validate_operative_version_tuple(
    authorization_version: Any,
    manifest_version: Any,
    launch_claim_version: Any,
    validator_contract_version: Any,
) -> list[str]:
    """Accept only the current fail-closed operative compatibility tuple.

    Historical authorization and manifest validators remain available for
    predecessor inspection, but no historical or mixed tuple authorizes a
    live campaign.
    """

    observed = (
        authorization_version,
        manifest_version,
        launch_claim_version,
        validator_contract_version,
    )
    if any(not _is_int(item, 1) for item in observed):
        return ["operative-version-tuple-malformed"]
    if observed != OPERATIVE_VERSION_TUPLE:
        return ["operative-version-tuple-incompatible"]
    return []


def contained_session_family_sha256(
    session_accounting: list[Mapping[str, Any]],
    raw_sessions: tuple[bytes, ...],
) -> str:
    """Bind ordered roles, identities, and bytes for archived boundaries."""

    if (
        not isinstance(session_accounting, list)
        or not isinstance(raw_sessions, tuple)
        or not session_accounting
        or len(session_accounting) != len(raw_sessions)
        or any(not isinstance(item, Mapping) for item in session_accounting)
        or any(not isinstance(raw, bytes) or not raw for raw in raw_sessions)
    ):
        raise ValueError("contained-session-family-invalid")
    return canonical_sha256(
        {
            "contract": "cwo-contained-session-family:v1",
            "count": len(raw_sessions),
            "ordered_sessions": [
                {
                    "ordinal": index,
                    "role": item.get("role"),
                    "session_id": item.get("session_id"),
                    "turn_id": item.get("turn_id"),
                    "file_sha256": hashlib.sha256(raw).hexdigest(),
                }
                for index, (item, raw) in enumerate(
                    zip(session_accounting, raw_sessions, strict=True)
                )
            ],
        }
    )


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
    predecessor: (
        Version5PredecessorProofInputs
        | Version6PredecessorProofInputs
        | Version7QuarantinePredecessorProofInputs
        | Version8ProtectedFaultPredecessorProofInputs
        | Version9PreallocationFaultPredecessorProofInputs
    ),
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
    if isinstance(predecessor, Version9PreallocationFaultPredecessorProofInputs):
        pre_mutation = predecessor.pre_mutation_receipt.value
        pre_live = predecessor.pre_live_receipt.value
        root_cause_binding_valid = (
            evidence.get("failure_class")
            == progress.get("predecessor_failure_class")
            == prior_root_cause.get("failure_class")
            and evidence.get("failure_message_sha256")
            == prior_failure.get("failure_message_sha256")
            and evidence.get("falsifiable_cause")
            == progress.get("new_falsifiable_cause")
            and prior_root_cause.get("failure_code")
            == prior_failure.get("failure_code")
            and prior_root_cause.get("source_analysis_sha256")
            == evidence.get("source_analysis_sha256")
            and prior_root_cause.get("independent_reproduction") is True
            and prior_root_cause.get("pre_live_binding_correct") is True
            and prior_root_cause.get("required_inner_authorization_id")
            == prior_authorization.get("authorization_id")
            and prior_root_cause.get(
                "required_inner_authorization_file_sha256"
            )
            == predecessor.authorization.raw_sha256
            and prior_root_cause.get("pre_mutation_bound_authority_id")
            == pre_mutation.get("authorization_id")
            and prior_root_cause.get(
                "pre_mutation_bound_authority_file_sha256"
            )
            == pre_mutation.get("authorization_sha256")
            and pre_live.get("authorization_id")
            == prior_authorization.get("authorization_id")
            and pre_live.get("authorization_sha256")
            == predecessor.authorization.raw_sha256
        )
    else:
        root_cause_binding_valid = (
            evidence.get("failure_class")
            == progress.get("predecessor_failure_class")
            == prior_root_cause.get("failure_class")
            and evidence.get("failure_message_sha256")
            == prior_failure.get("failure_message_sha256")
            == prior_root_cause.get("message_sha256")
            and evidence.get("falsifiable_cause")
            == progress.get("new_falsifiable_cause")
            == prior_root_cause.get("falsifiable_cause")
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
        or not root_cause_binding_valid
        or not isinstance(source_analysis_bytes, bytes)
        or not source_analysis_bytes
        or evidence.get("source_analysis_sha256")
        != hashlib.sha256(source_analysis_bytes).hexdigest()
        or evidence.get("repair_commit") != bindings.get("checkpoint_commit")
        or evidence.get("repair_tree") != bindings.get("checkpoint_tree")
    ):
        errors.append("authorization-recovery-cause-evidence-binding-invalid")
    return sorted(set(errors))


def _validate_v11_recovery_cause_evidence(
    value: Any,
    *,
    raw_sha256: str,
    bindings: Mapping[str, Any],
    progress: Mapping[str, Any],
    predecessor: Version10InterruptedEmptyBoundaryPredecessorProofInputs,
    source_analysis_bytes: bytes,
) -> list[str]:
    """Validate Generation-12 cause evidence without changing frozen history."""

    errors: list[str] = []
    evidence = _strict(
        value,
        RECOVERY_CAUSE_EVIDENCE_FIELDS,
        "authorization-v11-recovery-cause-evidence",
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
        errors.append("authorization-v11-recovery-cause-evidence-header-invalid")
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
                "authorization-v11-recovery-cause-evidence-"
                f"{field.replace('_', '-')}-invalid"
            )
    for field in ("repair_commit", "repair_tree"):
        if not _is_commit(evidence.get(field)):
            errors.append(
                "authorization-v11-recovery-cause-evidence-"
                f"{field.replace('_', '-')}-invalid"
            )
    prior_authorization = predecessor.authorization.value
    prior_manifest = predecessor.manifest.value
    prior_failure = predecessor.failure_evidence.value
    prior_containment = predecessor.containment.value
    root_cause = (
        prior_containment.get("root_cause")
        if isinstance(prior_containment.get("root_cause"), Mapping)
        else {}
    )
    terminal_failure = (
        prior_containment.get("terminal_failure")
        if isinstance(prior_containment.get("terminal_failure"), Mapping)
        else {}
    )
    source_sha256 = (
        hashlib.sha256(source_analysis_bytes).hexdigest()
        if isinstance(source_analysis_bytes, bytes) and source_analysis_bytes
        else None
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
        errors.append("authorization-v11-recovery-cause-evidence-content-invalid")
    if (
        raw_sha256 != bindings.get("recovery_cause_evidence_file_sha256")
        or evidence.get("canonical_cause_evidence_sha256")
        != bindings.get("recovery_cause_evidence_canonical_sha256")
        or evidence.get("canonical_cause_evidence_sha256")
        != _canonical_artifact_hash(evidence, "canonical_cause_evidence_sha256")
        or progress.get("cause_evidence_sha256") != raw_sha256
        or evidence.get("failed_authorization_id")
        != prior_authorization.get("authorization_id")
        or evidence.get("failed_manifest_id") != prior_manifest.get("manifest_id")
        or evidence.get("live_generation") != prior_authorization.get("live_generation")
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
        or evidence.get("failure_class") != root_cause.get("cause_class")
        or evidence.get("failure_message_sha256")
        != prior_failure.get("failure_message_sha256")
        or evidence.get("failure_message_sha256")
        != terminal_failure.get("failure_message_sha256")
        or evidence.get("falsifiable_cause") != progress.get("new_falsifiable_cause")
        or terminal_failure.get("failure_class") != prior_failure.get("failure_class")
        or terminal_failure.get("failure_code") != prior_failure.get("failure_code")
        or root_cause.get("failed_edge") != "capability-read-recovery:at-fault"
        or root_cause.get("replacement_read_attempted") is not False
        or root_cause.get("source_analysis_file_sha256") != source_sha256
        or evidence.get("source_analysis_sha256") != source_sha256
        or evidence.get("repair_commit") != bindings.get("checkpoint_commit")
        or evidence.get("repair_tree") != bindings.get("checkpoint_tree")
    ):
        errors.append("authorization-v11-recovery-cause-evidence-binding-invalid")
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
    allowed_actions = (
        prior_state.get("allowed_actions")
        if isinstance(prior_state.get("allowed_actions"), list)
        else []
    )
    revoked_actions = (
        prior_state.get("revoked_actions")
        if isinstance(prior_state.get("revoked_actions"), list)
        else []
    )
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
        or required_revocations.intersection(allowed_actions)
        or not required_revocations.issubset(set(revoked_actions))
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
        or _is_parseable_uuid(original.get("failed_authorization_id"))
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
                    predecessor_live_generation=_generation_or_invalid(predecessor),
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
    if not _is_uuid(session_id) or not _is_uuid(turn_id):
        return ["authorization-predecessor-validation-session-identity-invalid"]
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
    turn_contexts: list[tuple[int, str, str | None, str | None]] = []
    top_level_session_identities: list[Any] = []
    calls: dict[str, tuple[int, str, str]] = {}
    outputs: dict[str, tuple[int, str]] = {}
    tool_sequence: list[tuple[str, str]] = []
    patch_events: dict[str, tuple[int, str]] = {}
    for index, record in enumerate(records):
        record_type = record.get("type")
        payload = record.get("payload")
        if "session_id" in record:
            top_level_session_identities.append(record.get("session_id"))
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
            snake_turn = payload.get("turn_id")
            camel_turn = payload.get("turnId")
            effort = payload.get("effort")
            reasoning_effort = payload.get("reasoning_effort")
            turn_id = snake_turn or camel_turn
            if (
                not _is_uuid(turn_id)
                or (
                    snake_turn is not None
                    and camel_turn is not None
                    and snake_turn != camel_turn
                )
                or (
                    effort is not None
                    and reasoning_effort is not None
                    and effort != reasoning_effort
                )
            ):
                errors.append(f"{label}-turn-context-invalid")
            else:
                turn_contexts.append(
                    (
                        index,
                        str(turn_id),
                        payload.get("model"),
                        effort or reasoning_effort,
                    )
                )
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
    session_metas = [
        record.get("payload")
        for record in records
        if record.get("type") == "session_meta"
        and isinstance(record.get("payload"), Mapping)
    ]
    session_id = session_metas[0].get("id") if len(session_metas) == 1 else None
    session_identities = list(top_level_session_identities)
    if len(session_metas) == 1:
        session_identities.append(session_metas[0].get("id"))
        if "session_id" in session_metas[0]:
            session_identities.append(session_metas[0].get("session_id"))
    if (
        not _is_uuid(session_id)
        or not session_identities
        or any(not _is_uuid(value) for value in session_identities)
        or set(session_identities) != {session_id}
    ):
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
    terminal_type = terminal_events[0][2] if len(terminal_events) == 1 else None
    if any(
        turn_id != expected_turn
        for _index, turn_id, _model, _effort in turn_contexts
    ):
        errors.append(f"{label}-turn-context-mismatch")
    if (
        (terminal_type == "task_complete" and len(turn_contexts) != 1)
        or (terminal_type == "turn_aborted" and len(turn_contexts) > 1)
        or any(
            model != EXACT_OPERATIVE_MODEL or effort != EXACT_OPERATIVE_EFFORT
            for _index, _turn_id, model, effort in turn_contexts
        )
    ):
        errors.append(f"{label}-turn-context-attestation-invalid")
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


def _generation8_failure_ledger_prefix(
    final_ledger: Mapping[str, Any],
) -> tuple[dict[str, Any], bytes]:
    """Reconstruct the exact sequence-4 ledger bytes sealed at first failure.

    The historical launcher atomically rewrote one canonical JSON ledger file,
    so the failure evidence retained its raw digest while recovery appended two
    entries to that same ledger.  Reconstructing from the final ledger preserves
    the ledger ID, authority bindings, and exact first four entry payloads.  A
    digest match therefore rejects a summary-only or cross-run prefix splice.
    """

    entries = final_ledger.get("entries")
    if not isinstance(entries, list) or len(entries) < 4:
        raise ValueError("generation8-quarantine-ledger-prefix-unavailable")
    prefix = json.loads(json.dumps(dict(final_ledger)))
    prefix["entries"] = prefix["entries"][:4]
    prefix["sequence"] = 4
    prefix["head_entry_sha256"] = prefix["entries"][-1].get("entry_sha256")
    prefix["state_sha256"] = _allocation_ledger_state_sha256(prefix)
    raw = (
        json.dumps(prefix, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")
    return prefix, raw


def _validate_generation8_quarantine_ledger(
    final_ledger: Mapping[str, Any],
    failure_ledger_summary: Any,
) -> list[str]:
    """Validate Generation 8's archive-only ledger without relaxing v6/v7."""

    errors: list[str] = []
    entries = final_ledger.get("entries")
    if not isinstance(entries, list):
        return ["authorization-predecessor-v7-quarantine-ledger-invalid"]
    if (
        final_ledger.get("version") != 2
        or final_ledger.get("ledger_type")
        != "cwo-native-live-allocation-ledger:v2"
        or final_ledger.get("sequence") != 6
        or [item.get("sequence") for item in entries if isinstance(item, Mapping)]
        != list(range(1, 7))
        or [item.get("event") for item in entries if isinstance(item, Mapping)]
        != list(QUARANTINE_LEDGER_EVENT_SEQUENCE)
        or [item.get("outcome") for item in entries if isinstance(item, Mapping)]
        != list(QUARANTINE_LEDGER_OUTCOME_SEQUENCE)
        or len(entries) != 6
    ):
        errors.append("authorization-predecessor-v7-quarantine-ledger-shape-invalid")
        return sorted(set(errors))
    first = entries[0]
    identity_fields = (
        "allocation_intent_id",
        "role",
        "ordinal",
    )
    if (
        first.get("role") != "capability-calibration"
        or first.get("ordinal") != 0
        or any(
            item.get(field) != first.get(field)
            for item in entries
            for field in identity_fields
        )
        or not _is_uuid(entries[1].get("thread_id"))
        or not _is_uuid(entries[2].get("turn_intent_id"))
        or not _is_uuid(entries[3].get("turn_id"))
        or any(
            item.get("thread_id") != entries[1].get("thread_id")
            for item in entries[2:]
        )
        or any(
            item.get("turn_intent_id") != entries[2].get("turn_intent_id")
            for item in entries[3:]
        )
        or any(
            item.get("turn_id") != entries[3].get("turn_id")
            for item in entries[4:]
        )
        or any(item.get("event") == "interrupt-observed" for item in entries)
        or any(item.get("event") == "certification-bound" for item in entries)
    ):
        errors.append("authorization-predecessor-v7-quarantine-ledger-identity-invalid")
    expected_containment_evidence_sha256 = _domain_sha256(
        {
            "thread_id_sha256": hashlib.sha256(
                str(entries[1].get("thread_id")).encode("utf-8")
            ).hexdigest(),
            "turn_status": "interrupted",
            "outcome": "contained",
        },
        domain="native-live-containment-audit",
    )
    if entries[5].get("evidence_sha256") != expected_containment_evidence_sha256:
        errors.append(
            "authorization-predecessor-v7-quarantine-ledger-containment-evidence-invalid"
        )

    summary = (
        dict(failure_ledger_summary)
        if isinstance(failure_ledger_summary, Mapping)
        else {}
    )
    ledger_bindings = (
        final_ledger.get("bindings")
        if isinstance(final_ledger.get("bindings"), Mapping)
        else {}
    )
    try:
        prefix, prefix_raw = _generation8_failure_ledger_prefix(final_ledger)
    except (TypeError, ValueError):
        errors.append("authorization-predecessor-v7-quarantine-ledger-prefix-invalid")
        return sorted(set(errors))
    expected_summary = {
        "allocated_roles": ["capability-calibration"],
        "allocation_intent_count": 1,
        "available": True,
        "campaign_manifest_sha256": ledger_bindings.get(
            "campaign_manifest_sha256"
        ),
        "head_entry_sha256": prefix.get("head_entry_sha256"),
        "ledger_file_sha256": hashlib.sha256(prefix_raw).hexdigest(),
        "ledger_id": final_ledger.get("ledger_id"),
        "ledger_type": final_ledger.get("ledger_type"),
        "live_generation": 8,
        "sequence": 4,
        "state_sha256": prefix.get("state_sha256"),
        "thread_bound_count": 1,
        "turn_bound_count": 1,
        "turn_intent_count": 1,
        "unresolved_allocation_intent_count": 0,
        "unresolved_turn_intent_count": 0,
        "version": 2,
    }
    if summary != expected_summary:
        errors.append("authorization-predecessor-v7-quarantine-ledger-prefix-binding-invalid")
    return sorted(set(errors))


def _validate_generation8_quarantine_session(
    raw: bytes,
    accounting: Any,
    *,
    expected_session_id: Any,
    expected_turn_id: Any,
    expected_file_sha256: Any,
) -> list[str]:
    """Accept only Generation 8's exact two-record nonattesting grammar."""

    errors: list[str] = []
    if not isinstance(raw, bytes) or not raw.endswith(b"\n"):
        return ["authorization-predecessor-v7-quarantine-session-boundary-invalid"]
    lines = raw.splitlines(keepends=True)
    if len(lines) != 2 or any(not line.endswith(b"\n") for line in lines):
        return ["authorization-predecessor-v7-quarantine-session-record-count-invalid"]
    try:
        records = [json.loads(line) for line in lines]
    except (UnicodeDecodeError, json.JSONDecodeError):
        return ["authorization-predecessor-v7-quarantine-session-json-invalid"]
    if any(
        not isinstance(record, Mapping)
        or set(record) != {"timestamp", "type", "payload"}
        or _parse_utc(record.get("timestamp")) is None
        or not isinstance(record.get("payload"), Mapping)
        for record in records
    ):
        errors.append("authorization-predecessor-v7-quarantine-session-envelope-invalid")
        return sorted(set(errors))
    meta, started = records
    meta_payload = meta["payload"]
    started_payload = started["payload"]
    if (
        meta.get("type") != "session_meta"
        or meta_payload.get("id") != expected_session_id
        or meta_payload.get("session_id") != expected_session_id
        or not _is_uuid(expected_session_id)
        or started.get("type") != "event_msg"
        or started_payload.get("type") != "task_started"
        or started_payload.get("turn_id") != expected_turn_id
        or not _is_uuid(expected_turn_id)
    ):
        errors.append("authorization-predecessor-v7-quarantine-session-identity-invalid")
    if any(
        record.get("type")
        in {"turn_context", "response_item", "compacted", "task_complete"}
        or record.get("payload", {}).get("type")
        in {
            "task_complete",
            "turn_aborted",
            "function_call",
            "custom_tool_call",
        }
        for record in records
    ):
        errors.append("authorization-predecessor-v7-quarantine-session-activity-invalid")
    item = dict(accounting) if isinstance(accounting, Mapping) else {}
    raw_sha256 = hashlib.sha256(raw).hexdigest()
    expected_accounting = {
        "active_match_count": 0,
        "archive_match_count": 1,
        "archive_request_outcome": "accepted",
        "archived_session_file_sha256": raw_sha256,
        "attestation_status": "unavailable-quarantined-nonaccepting",
        "byte_offset": len(raw),
        "control_plane_projection_before_archive": "interrupted",
        "record_count": 2,
        "session_id": expected_session_id,
        "terminal_event": None,
        "trusted_turn_context_count": 0,
        "turn_id": expected_turn_id,
    }
    if item != expected_accounting or raw_sha256 != expected_file_sha256:
        errors.append("authorization-predecessor-v7-quarantine-session-binding-invalid")
    return sorted(set(errors))


GENERATION9_PROTECTED_LEDGER_GRAMMAR = (
    ("capability-calibration", "allocation-intent", "pending"),
    ("capability-calibration", "thread-bound", "bound"),
    ("capability-calibration", "turn-intent", "pending"),
    ("capability-calibration", "turn-bound", "bound"),
    ("capability-calibration", "interrupt-observed", "interrupt-request-accepted"),
    ("capability-calibration", "archive-observed", "archive-request-accepted"),
    (None, "certification-bound", "bound"),
    ("read-only-0", "allocation-intent", "pending"),
    ("read-only-0", "thread-bound", "bound"),
    ("read-only-1", "allocation-intent", "pending"),
    ("read-only-1", "thread-bound", "bound"),
    ("read-only-0", "turn-intent", "pending"),
    ("read-only-0", "turn-bound", "bound"),
    ("read-only-1", "turn-intent", "pending"),
    ("read-only-1", "turn-bound", "bound"),
    ("read-only-0", "archive-observed", "archive-request-accepted"),
    ("read-only-1", "archive-observed", "archive-request-accepted"),
    ("mutable-0", "allocation-intent", "pending"),
    ("mutable-0", "thread-bound", "bound"),
    ("mutable-1", "allocation-intent", "pending"),
    ("mutable-1", "thread-bound", "bound"),
    ("mutable-0", "turn-intent", "pending"),
    ("mutable-0", "turn-bound", "bound"),
    ("mutable-1", "turn-intent", "pending"),
    ("mutable-1", "turn-bound", "bound"),
    ("mutable-0", "interrupt-observed", "interrupt-request-accepted"),
    ("mutable-0", "archive-observed", "archive-request-accepted"),
    ("mutable-1", "interrupt-observed", "interrupt-request-accepted"),
    ("mutable-1", "archive-observed", "archive-request-accepted"),
    ("capability-calibration", "containment-audited", "already-contained"),
    ("read-only-0", "containment-audited", "already-contained"),
    ("read-only-1", "containment-audited", "already-contained"),
    ("mutable-0", "containment-audited", "already-contained"),
    ("mutable-1", "containment-audited", "already-contained"),
)


def _validate_generation9_protected_fault_ledger(
    final_ledger: Mapping[str, Any], failure_ledger_summary: Any
) -> list[str]:
    """Validate the exact five-allocation terminal Generation-9 ledger."""

    errors: list[str] = []
    entries = final_ledger.get("entries")
    if not isinstance(entries, list) or any(
        not isinstance(item, Mapping) for item in entries
    ):
        return ["authorization-predecessor-v8-protected-ledger-invalid"]
    observed_grammar = tuple(
        (item.get("role"), item.get("event"), item.get("outcome"))
        for item in entries
    )
    if (
        final_ledger.get("version") != 2
        or final_ledger.get("ledger_type")
        != "cwo-native-live-allocation-ledger:v2"
        or final_ledger.get("sequence") != len(GENERATION9_PROTECTED_LEDGER_GRAMMAR)
        or len(entries) != len(GENERATION9_PROTECTED_LEDGER_GRAMMAR)
        or [item.get("sequence") for item in entries]
        != list(range(1, len(GENERATION9_PROTECTED_LEDGER_GRAMMAR) + 1))
        or observed_grammar != GENERATION9_PROTECTED_LEDGER_GRAMMAR
    ):
        errors.append("authorization-predecessor-v8-protected-ledger-shape-invalid")
        return sorted(set(errors))

    allocations = [
        item for item in entries if item.get("event") == "allocation-intent"
    ]
    expected_roles = list(EXPECTED_ROLES[:5])
    if (
        [item.get("role") for item in allocations] != expected_roles
        or [item.get("ordinal") for item in allocations] != list(range(5))
    ):
        errors.append("authorization-predecessor-v8-protected-ledger-role-invalid")
    for allocation in allocations:
        allocation_id = allocation.get("allocation_intent_id")
        family = [
            item
            for item in entries
            if item.get("allocation_intent_id") == allocation_id
        ]
        if (
            not _is_uuid(allocation_id)
            or any(item.get("role") != allocation.get("role") for item in family)
            or len(
                {
                    item.get("thread_id")
                    for item in family
                    if item.get("thread_id") is not None
                }
            )
            != 1
            or len(
                {
                    item.get("turn_id")
                    for item in family
                    if item.get("turn_id") is not None
                }
            )
            != 1
        ):
            errors.append(
                "authorization-predecessor-v8-protected-ledger-identity-invalid"
            )

    bindings = (
        final_ledger.get("bindings")
        if isinstance(final_ledger.get("bindings"), Mapping)
        else {}
    )
    summary = (
        dict(failure_ledger_summary)
        if isinstance(failure_ledger_summary, Mapping)
        else {}
    )
    expected_summary = {
        "allocated_roles": expected_roles,
        "allocation_intent_count": 5,
        "available": True,
        "campaign_manifest_sha256": bindings.get("campaign_manifest_sha256"),
        "head_entry_sha256": final_ledger.get("head_entry_sha256"),
        "ledger_file_sha256": hashlib.sha256(
            (json.dumps(final_ledger, sort_keys=True, separators=(",", ":")) + "\n").encode()
        ).hexdigest(),
        "ledger_id": final_ledger.get("ledger_id"),
        "ledger_type": final_ledger.get("ledger_type"),
        "live_generation": 9,
        "sequence": len(GENERATION9_PROTECTED_LEDGER_GRAMMAR),
        "state_sha256": final_ledger.get("state_sha256"),
        "thread_bound_count": 5,
        "turn_bound_count": 5,
        "turn_intent_count": 5,
        "unresolved_allocation_intent_count": 0,
        "unresolved_turn_intent_count": 0,
        "version": 2,
    }
    if summary != expected_summary:
        errors.append(
            "authorization-predecessor-v8-protected-ledger-summary-binding-invalid"
        )
    return sorted(set(errors))


GENERATION9_SESSION_ACCOUNTING_FIELDS = {
    "active_match_count",
    "archive_match_count",
    "archive_request_outcome",
    "archived_session_file_sha256",
    "attested_effort",
    "attested_model",
    "boundary_sha256",
    "byte_offset",
    "containment_outcome",
    "record_count",
    "role",
    "session_id",
    "terminal_event",
    "trusted_turn_context_count",
    "turn_id",
}


def _validate_generation9_protected_fault_sessions(
    raw_sessions: tuple[bytes, ...],
    session_accounting: Any,
    ledger: Mapping[str, Any],
    *,
    expected_family_sha256: Any,
) -> list[str]:
    """Validate every exact archived boundary in the terminal Gen-9 leaf."""

    errors: list[str] = []
    if (
        not isinstance(raw_sessions, tuple)
        or len(raw_sessions) != 5
        or any(not isinstance(raw, bytes) for raw in raw_sessions)
        or not isinstance(session_accounting, list)
        or len(session_accounting) != 5
    ):
        return ["authorization-predecessor-v8-protected-session-set-invalid"]
    accounting = [
        _strict(
            item,
            GENERATION9_SESSION_ACCOUNTING_FIELDS,
            f"authorization-predecessor-v8-protected-session-{index}",
            errors,
        )
        for index, item in enumerate(session_accounting)
    ]
    entries = ledger.get("entries")
    if not isinstance(entries, list):
        return sorted(
            set(errors + ["authorization-predecessor-v8-protected-session-ledger-invalid"])
        )
    thread_entries = {
        item.get("role"): item
        for item in entries
        if isinstance(item, Mapping) and item.get("event") == "thread-bound"
    }
    turn_entries = {
        item.get("role"): item
        for item in entries
        if isinstance(item, Mapping) and item.get("event") == "turn-bound"
    }
    expected_roles = list(EXPECTED_ROLES[:5])
    for index, (raw, item, role) in enumerate(
        zip(raw_sessions, accounting, expected_roles, strict=True)
    ):
        (
            session_id,
            started_turns,
            record_count,
            tool_sequence,
            terminal_type,
            parse_errors,
        ) = _parse_contained_session_identity(
            raw, f"authorization-predecessor-v8-protected-session-{index}"
        )
        errors.extend(parse_errors)
        thread = thread_entries.get(role, {})
        turn = turn_entries.get(role, {})
        expected_turn = turn.get("turn_id")
        try:
            raw_records = [json.loads(line) for line in raw.splitlines()]
        except (UnicodeDecodeError, json.JSONDecodeError):
            raw_records = []
        trusted_turn_contexts = [
            record.get("payload")
            for record in raw_records
            if isinstance(record, Mapping)
            and record.get("type") == "turn_context"
            and isinstance(record.get("payload"), Mapping)
            and (record["payload"].get("turn_id") or record["payload"].get("turnId"))
            == expected_turn
            and record["payload"].get("model") == EXACT_OPERATIVE_MODEL
            and (
                record["payload"].get("effort")
                or record["payload"].get("reasoning_effort")
            )
            == EXACT_OPERATIVE_EFFORT
        ]
        if len(trusted_turn_contexts) != 1:
            errors.append(
                "authorization-predecessor-v8-protected-session-turn-context-invalid"
            )
        expected_terminal_status = (
            "completed" if terminal_type == "task_complete" else "interrupted"
        )
        terminal_event = item.get("terminal_event")
        expected_tool_sequence = CONTAINED_ROLE_TOOL_PREFIXES[role]
        tool_sequence_valid = tool_sequence == expected_tool_sequence
        if role == "mutable-1":
            tool_sequence_valid = tool_sequence in {
                expected_tool_sequence,
                expected_tool_sequence + (("custom", "apply_patch"),),
            }
        if (
            item.get("role") != role
            or item.get("session_id") != session_id
            or session_id != thread.get("thread_id")
            or item.get("turn_id") != expected_turn
            or expected_turn not in started_turns
            or item.get("active_match_count") != 0
            or item.get("archive_match_count") != 1
            or item.get("archive_request_outcome") != "accepted"
            or item.get("containment_outcome") != "already-contained"
            or item.get("attested_model") != EXACT_OPERATIVE_MODEL
            or item.get("attested_effort") != EXACT_OPERATIVE_EFFORT
            or item.get("trusted_turn_context_count") != 1
            or len(trusted_turn_contexts) != 1
            or item.get("archived_session_file_sha256")
            != hashlib.sha256(raw).hexdigest()
            or item.get("boundary_sha256") != hashlib.sha256(raw).hexdigest()
            or item.get("byte_offset") != len(raw)
            or item.get("record_count") != record_count
            or not tool_sequence_valid
            or not isinstance(terminal_event, Mapping)
            or terminal_event.get("count") != 1
            or terminal_event.get("event_type") != terminal_type
            or terminal_event.get("record_index") != record_count - 1
            or terminal_event.get("status") != expected_terminal_status
        ):
            errors.append(
                "authorization-predecessor-v8-protected-session-binding-invalid"
            )
    try:
        observed_family_sha256 = contained_session_family_sha256(
            accounting, raw_sessions
        )
    except ValueError:
        observed_family_sha256 = None
    if observed_family_sha256 != expected_family_sha256:
        errors.append(
            "authorization-predecessor-v8-protected-session-family-invalid"
        )
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

    historical_kwargs = _historical_proof_kwargs(proof.ancestor)
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
    allowed_actions = (
        prior_state.get("allowed_actions")
        if isinstance(prior_state.get("allowed_actions"), list)
        else []
    )
    revoked_actions = (
        prior_state.get("revoked_actions")
        if isinstance(prior_state.get("revoked_actions"), list)
        else []
    )
    if (
        proof.authorization_state.raw_sha256
        != bindings.get("predecessor_authorization_state_file_sha256")
        or prior_state.get("state_sha256")
        != bindings.get("predecessor_authorization_state_canonical_sha256")
        or validate_authorization_state(prior_state)
        or prior_state.get("authorization_id") != prior_authorization_id
        or prior_state.get("run_nonce") != prior_nonce
        or prior_state.get("state") != "containment-only"
        or required_revocations.intersection(allowed_actions)
        or not required_revocations.issubset(set(revoked_actions))
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
    bindings = (
        dict(shadow.get("bindings"))
        if isinstance(shadow.get("bindings"), Mapping)
        else {}
    )
    shadow["bindings"] = bindings
    bindings["predecessor_original_containment_file_sha256"] = bindings.pop(
        "recovery_cause_evidence_file_sha256", None
    )
    bindings["predecessor_original_containment_canonical_sha256"] = bindings.pop(
        "recovery_cause_evidence_canonical_sha256", None
    )
    bindings.pop("predecessor_ancestor_lineage_sha256", None)
    bindings.pop("validator_contract_sha256", None)
    gates = (
        dict(shadow.get("mandatory_gates"))
        if isinstance(shadow.get("mandatory_gates"), Mapping)
        else {}
    )
    shadow["mandatory_gates"] = gates
    gates.pop("strict_authorization_v6", None)
    gates.pop("campaign_manifest_v3", None)
    gates.pop("finite_predecessor_proof_dag", None)
    gates.pop("read_once_predecessor_snapshots", None)
    gates.pop("atomic_launch_claim", None)
    gates["strict_authorization_v5"] = True
    gates["campaign_manifest_v2"] = True
    progress = (
        dict(shadow.get("progress_gate"))
        if isinstance(shadow.get("progress_gate"), Mapping)
        else {}
    )
    shadow["progress_gate"] = progress
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
                predecessor_live_generation=_generation_or_invalid(
                    authorization.get("predecessor_live_generation")
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


def _v7_common_shadow(authorization: Mapping[str, Any]) -> dict[str, Any]:
    """Project v7 common fields into the frozen v5 structural validator."""

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
    gates.pop("strict_authorization_v7", None)
    gates.pop("campaign_manifest_v4", None)
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


def _validate_full_auto_authorization_v7(
    value: Any,
    *,
    expected_campaign_nonce: str | None = None,
    predecessor_proof: Version6PredecessorProofInputs | None = None,
    recovery_cause_evidence: JsonArtifactSnapshot | None = None,
    recovery_cause_source_analysis: bytes | None = None,
    expected_validator_contract_sha256: str | None = None,
    repo_root: Path | None = None,
) -> list[str]:
    errors: list[str] = []
    authorization = _strict(value, AUTHORIZATION_FIELDS, "authorization-v7", errors)
    if not authorization:
        return sorted(set(errors))
    if (
        authorization.get("authorization_type") != AUTHORIZATION_TYPE
        or authorization.get("version") != AUTHORIZATION_VERSION_V7
        or authorization.get("schema") != AUTHORIZATION_SCHEMA_V7
    ):
        errors.append("authorization-v7-header-invalid")
    common_shadow = _v7_common_shadow(authorization)
    errors.extend(
        f"authorization-v7-common:{item}"
        for item in _validate_full_auto_authorization_v5(
            common_shadow,
            expected_campaign_nonce=expected_campaign_nonce,
            repo_root=repo_root,
        )
    )
    bindings = _strict(
        authorization.get("bindings"),
        BINDING_FIELDS_V7,
        "authorization-v7-bindings",
        errors,
    )
    progress = _strict(
        authorization.get("progress_gate"),
        PROGRESS_GATE_FIELDS,
        "authorization-v7-progress-gate",
        errors,
    )
    supersession = _strict(
        authorization.get("supersession"),
        SUPERSESSION_FIELDS,
        "authorization-v7-supersession",
        errors,
    )
    gates = _strict(
        authorization.get("mandatory_gates"),
        MANDATORY_GATE_FIELDS_V7,
        "authorization-v7-mandatory-gates",
        errors,
    )
    if any(gates.get(field) is not True for field in MANDATORY_GATE_FIELDS_V7):
        errors.append("authorization-v7-mandatory-gate-disabled")
    for field in BINDING_FIELDS_V7 - {
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
            errors.append(
                f"authorization-v7-binding-{field.replace('_', '-')}-invalid"
            )
    expected_lineage = _predecessor_lineage_v7(
        bindings, progress, authorization.get("predecessor_live_generation")
    )
    if progress.get("predecessor_lineage_sha256") != canonical_sha256(
        expected_lineage
    ):
        errors.append("authorization-v7-predecessor-lineage-sha256-mismatch")
    unsigned_progress = dict(progress)
    unsigned_progress.pop("qualification_sha256", None)
    if progress.get("qualification_sha256") != canonical_sha256(unsigned_progress):
        errors.append("authorization-v7-progress-qualification-sha256-mismatch")
    unsigned = dict(authorization)
    unsigned.pop("canonical_authorization_sha256", None)
    if authorization.get("canonical_authorization_sha256") != canonical_sha256(
        unsigned
    ):
        errors.append("authorization-v7-canonical-sha256-mismatch")

    if repo_root is not None:
        try:
            observed_contract = validator_contract_sha256_v2(
                Path(repo_root), bindings.get("checkpoint_tree")
            )
        except (OSError, ValueError):
            observed_contract = None
            errors.append("authorization-v7-validator-contract-unavailable")
        if bindings.get("validator_contract_sha256") != observed_contract:
            errors.append("authorization-v7-validator-contract-mismatch")
    if (
        expected_validator_contract_sha256 is not None
        and bindings.get("validator_contract_sha256")
        != expected_validator_contract_sha256
    ):
        errors.append("authorization-v7-expected-validator-contract-mismatch")

    if not isinstance(predecessor_proof, Version6PredecessorProofInputs):
        errors.append("authorization-v7-predecessor-proof-missing")
    else:
        errors.extend(
            _validate_v6_v3_predecessor_proof(
                bindings=bindings,
                progress=progress,
                supersession=supersession,
                predecessor_live_generation=_generation_or_invalid(
                    authorization.get("predecessor_live_generation")
                ),
                proof=predecessor_proof,
                repo_root=repo_root,
            )
        )
    if not isinstance(recovery_cause_evidence, JsonArtifactSnapshot):
        errors.append("authorization-v7-recovery-cause-evidence-missing")
    elif not isinstance(recovery_cause_source_analysis, bytes):
        errors.append("authorization-v7-recovery-cause-source-analysis-missing")
    elif isinstance(predecessor_proof, Version6PredecessorProofInputs):
        errors.extend(
            _validate_json_snapshot(
                recovery_cause_evidence,
                "authorization-v7-recovery-cause-evidence",
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


def _v8_common_shadow(authorization: Mapping[str, Any]) -> dict[str, Any]:
    """Project v8 common fields into the frozen v5 structural validator."""

    shadow = json.loads(json.dumps(dict(authorization)))
    shadow["version"] = AUTHORIZATION_VERSION_V7
    shadow["schema"] = AUTHORIZATION_SCHEMA_V7
    bindings = shadow.get("bindings", {})
    for field in BINDING_FIELDS_V8 - BINDING_FIELDS_V7:
        bindings.pop(field, None)
    gates = shadow.get("mandatory_gates", {})
    gates.pop("strict_authorization_v8", None)
    gates.pop("campaign_manifest_v5", None)
    gates.pop("nonattesting_quarantine_predecessor_proof", None)
    gates["strict_authorization_v7"] = True
    gates["campaign_manifest_v4"] = True
    progress = shadow.get("progress_gate", {})
    progress["predecessor_lineage_sha256"] = canonical_sha256(
        _predecessor_lineage_v7(
            bindings, progress, shadow.get("predecessor_live_generation")
        )
    )
    progress.pop("qualification_sha256", None)
    progress["qualification_sha256"] = canonical_sha256(progress)
    shadow.pop("canonical_authorization_sha256", None)
    shadow["canonical_authorization_sha256"] = canonical_sha256(shadow)
    return _v7_common_shadow(shadow)


def _validate_full_auto_authorization_v8(
    value: Any,
    *,
    expected_campaign_nonce: str | None = None,
    predecessor_proof: Version7QuarantinePredecessorProofInputs | None = None,
    recovery_cause_evidence: JsonArtifactSnapshot | None = None,
    recovery_cause_source_analysis: bytes | None = None,
    expected_validator_contract_sha256: str | None = None,
    repo_root: Path | None = None,
) -> list[str]:
    errors: list[str] = []
    authorization = _strict(value, AUTHORIZATION_FIELDS, "authorization-v8", errors)
    if not authorization:
        return sorted(set(errors))
    if (
        authorization.get("authorization_type") != AUTHORIZATION_TYPE
        or authorization.get("version") != AUTHORIZATION_VERSION_V8
        or authorization.get("schema") != AUTHORIZATION_SCHEMA_V8
    ):
        errors.append("authorization-v8-header-invalid")
    errors.extend(
        f"authorization-v8-common:{item}"
        for item in _validate_full_auto_authorization_v5(
            _v8_common_shadow(authorization),
            expected_campaign_nonce=expected_campaign_nonce,
            repo_root=repo_root,
        )
    )
    bindings = _strict(
        authorization.get("bindings"),
        BINDING_FIELDS_V8,
        "authorization-v8-bindings",
        errors,
    )
    progress = _strict(
        authorization.get("progress_gate"),
        PROGRESS_GATE_FIELDS,
        "authorization-v8-progress-gate",
        errors,
    )
    supersession = _strict(
        authorization.get("supersession"),
        SUPERSESSION_FIELDS,
        "authorization-v8-supersession",
        errors,
    )
    gates = _strict(
        authorization.get("mandatory_gates"),
        MANDATORY_GATE_FIELDS_V8,
        "authorization-v8-mandatory-gates",
        errors,
    )
    if any(gates.get(field) is not True for field in MANDATORY_GATE_FIELDS_V8):
        errors.append("authorization-v8-mandatory-gate-disabled")
    for field in BINDING_FIELDS_V8 - {
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
            errors.append(
                f"authorization-v8-binding-{field.replace('_', '-')}-invalid"
            )
    expected_lineage = _predecessor_lineage_v8(
        bindings, progress, authorization.get("predecessor_live_generation")
    )
    if progress.get("predecessor_lineage_sha256") != canonical_sha256(
        expected_lineage
    ):
        errors.append("authorization-v8-predecessor-lineage-sha256-mismatch")
    unsigned_progress = dict(progress)
    unsigned_progress.pop("qualification_sha256", None)
    if progress.get("qualification_sha256") != canonical_sha256(unsigned_progress):
        errors.append("authorization-v8-progress-qualification-sha256-mismatch")
    unsigned = dict(authorization)
    unsigned.pop("canonical_authorization_sha256", None)
    if authorization.get("canonical_authorization_sha256") != canonical_sha256(
        unsigned
    ):
        errors.append("authorization-v8-canonical-sha256-mismatch")

    if repo_root is not None:
        try:
            observed_contract = validator_contract_sha256_v3(
                Path(repo_root), bindings.get("checkpoint_tree")
            )
        except (OSError, ValueError):
            observed_contract = None
            errors.append("authorization-v8-validator-contract-unavailable")
        if bindings.get("validator_contract_sha256") != observed_contract:
            errors.append("authorization-v8-validator-contract-mismatch")
    if (
        expected_validator_contract_sha256 is not None
        and bindings.get("validator_contract_sha256")
        != expected_validator_contract_sha256
    ):
        errors.append("authorization-v8-expected-validator-contract-mismatch")

    if not isinstance(predecessor_proof, Version7QuarantinePredecessorProofInputs):
        errors.append("authorization-v8-predecessor-quarantine-proof-missing")
    else:
        errors.extend(
            _validate_v7_quarantine_predecessor_proof(
                bindings=bindings,
                progress=progress,
                supersession=supersession,
                predecessor_live_generation=_generation_or_invalid(
                    authorization.get("predecessor_live_generation")
                ),
                proof=predecessor_proof,
                repo_root=repo_root,
            )
        )
    if not isinstance(recovery_cause_evidence, JsonArtifactSnapshot):
        errors.append("authorization-v8-recovery-cause-evidence-missing")
    elif not isinstance(recovery_cause_source_analysis, bytes):
        errors.append("authorization-v8-recovery-cause-source-analysis-missing")
    elif isinstance(predecessor_proof, Version7QuarantinePredecessorProofInputs):
        errors.extend(
            _validate_json_snapshot(
                recovery_cause_evidence,
                "authorization-v8-recovery-cause-evidence",
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


def _v9_common_shadow(authorization: Mapping[str, Any]) -> dict[str, Any]:
    """Project v9 common fields into the frozen v5 structural validator."""

    shadow = json.loads(json.dumps(dict(authorization)))
    shadow["version"] = AUTHORIZATION_VERSION
    shadow["schema"] = AUTHORIZATION_SCHEMA
    bindings = (
        dict(shadow.get("bindings"))
        if isinstance(shadow.get("bindings"), Mapping)
        else {}
    )
    shadow["bindings"] = bindings
    bindings["predecessor_original_containment_file_sha256"] = bindings.pop(
        "recovery_cause_evidence_file_sha256", None
    )
    bindings["predecessor_original_containment_canonical_sha256"] = bindings.pop(
        "recovery_cause_evidence_canonical_sha256", None
    )
    bindings.pop("predecessor_ancestor_lineage_sha256", None)
    bindings.pop("validator_contract_sha256", None)
    bindings.pop("predecessor_contained_session_family_sha256", None)
    bindings.pop("predecessor_contained_session_count", None)
    gates = (
        dict(shadow.get("mandatory_gates"))
        if isinstance(shadow.get("mandatory_gates"), Mapping)
        else {}
    )
    shadow["mandatory_gates"] = gates
    gates.pop("strict_authorization_v9", None)
    gates.pop("campaign_manifest_v6", None)
    gates.pop("finite_predecessor_proof_dag", None)
    gates.pop("read_once_predecessor_snapshots", None)
    gates.pop("atomic_launch_claim", None)
    gates.pop("protected_fault_predecessor_proof", None)
    gates["strict_authorization_v5"] = True
    gates["campaign_manifest_v2"] = True
    progress = (
        dict(shadow.get("progress_gate"))
        if isinstance(shadow.get("progress_gate"), Mapping)
        else {}
    )
    shadow["progress_gate"] = progress
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


def _validate_full_auto_authorization_v9(
    value: Any,
    *,
    expected_campaign_nonce: str | None = None,
    predecessor_proof: Version8ProtectedFaultPredecessorProofInputs | None = None,
    recovery_cause_evidence: JsonArtifactSnapshot | None = None,
    recovery_cause_source_analysis: bytes | None = None,
    expected_validator_contract_sha256: str | None = None,
    repo_root: Path | None = None,
) -> list[str]:
    errors: list[str] = []
    authorization = _strict(value, AUTHORIZATION_FIELDS, "authorization-v9", errors)
    if not authorization:
        return sorted(set(errors))
    if (
        authorization.get("authorization_type") != AUTHORIZATION_TYPE
        or authorization.get("version") != AUTHORIZATION_VERSION_V9
        or authorization.get("schema") != AUTHORIZATION_SCHEMA_V9
    ):
        errors.append("authorization-v9-header-invalid")
    errors.extend(
        f"authorization-v9-common:{item}"
        for item in _validate_full_auto_authorization_v5(
            _v9_common_shadow(authorization),
            expected_campaign_nonce=expected_campaign_nonce,
            repo_root=repo_root,
        )
    )
    bindings = _strict(
        authorization.get("bindings"),
        BINDING_FIELDS_V9,
        "authorization-v9-bindings",
        errors,
    )
    progress = _strict(
        authorization.get("progress_gate"),
        PROGRESS_GATE_FIELDS,
        "authorization-v9-progress-gate",
        errors,
    )
    supersession = _strict(
        authorization.get("supersession"),
        SUPERSESSION_FIELDS,
        "authorization-v9-supersession",
        errors,
    )
    gates = _strict(
        authorization.get("mandatory_gates"),
        MANDATORY_GATE_FIELDS_V9,
        "authorization-v9-mandatory-gates",
        errors,
    )
    if any(gates.get(field) is not True for field in MANDATORY_GATE_FIELDS_V9):
        errors.append("authorization-v9-mandatory-gate-disabled")
    non_hash_fields = {
        "checkpoint_commit",
        "checkpoint_tree",
        "origin_main_commit",
        "pickup_path",
        "recovery_plan_path",
        "campaign_nonce",
        "predecessor_authorization_id",
        "predecessor_contained_session_count",
        "backup_ref",
        "outer_authority_id",
    }
    for field in BINDING_FIELDS_V9 - non_hash_fields:
        if not _is_hash(bindings.get(field)):
            errors.append(
                f"authorization-v9-binding-{field.replace('_', '-')}-invalid"
            )
    if bindings.get("predecessor_contained_session_count") != 5:
        errors.append("authorization-v9-predecessor-session-count-invalid")
    expected_lineage = _predecessor_lineage_v9(
        bindings, progress, authorization.get("predecessor_live_generation")
    )
    if progress.get("predecessor_lineage_sha256") != canonical_sha256(
        expected_lineage
    ):
        errors.append("authorization-v9-predecessor-lineage-sha256-mismatch")
    unsigned_progress = dict(progress)
    unsigned_progress.pop("qualification_sha256", None)
    if progress.get("qualification_sha256") != canonical_sha256(unsigned_progress):
        errors.append("authorization-v9-progress-qualification-sha256-mismatch")
    unsigned = dict(authorization)
    unsigned.pop("canonical_authorization_sha256", None)
    if authorization.get("canonical_authorization_sha256") != canonical_sha256(
        unsigned
    ):
        errors.append("authorization-v9-canonical-sha256-mismatch")

    if repo_root is not None:
        try:
            observed_contract = validator_contract_sha256_v4(
                Path(repo_root), bindings.get("checkpoint_tree")
            )
        except (OSError, ValueError):
            observed_contract = None
            errors.append("authorization-v9-validator-contract-unavailable")
        if bindings.get("validator_contract_sha256") != observed_contract:
            errors.append("authorization-v9-validator-contract-mismatch")
    if (
        expected_validator_contract_sha256 is not None
        and bindings.get("validator_contract_sha256")
        != expected_validator_contract_sha256
    ):
        errors.append("authorization-v9-expected-validator-contract-mismatch")

    if not isinstance(
        predecessor_proof, Version8ProtectedFaultPredecessorProofInputs
    ):
        errors.append("authorization-v9-predecessor-protected-proof-missing")
    else:
        errors.extend(
            _validate_v8_protected_fault_predecessor_proof(
                bindings=bindings,
                progress=progress,
                supersession=supersession,
                predecessor_live_generation=_generation_or_invalid(
                    authorization.get("predecessor_live_generation")
                ),
                proof=predecessor_proof,
                repo_root=repo_root,
            )
        )
    if not isinstance(recovery_cause_evidence, JsonArtifactSnapshot):
        errors.append("authorization-v9-recovery-cause-evidence-missing")
    elif not isinstance(recovery_cause_source_analysis, bytes):
        errors.append("authorization-v9-recovery-cause-source-analysis-missing")
    elif isinstance(
        predecessor_proof, Version8ProtectedFaultPredecessorProofInputs
    ):
        errors.extend(
            _validate_json_snapshot(
                recovery_cause_evidence,
                "authorization-v9-recovery-cause-evidence",
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


def _v10_common_shadow(authorization: Mapping[str, Any]) -> dict[str, Any]:
    """Project v10 common fields through the frozen v9-to-v5 validator."""

    shadow = json.loads(json.dumps(dict(authorization)))
    shadow["version"] = AUTHORIZATION_VERSION_V9
    shadow["schema"] = AUTHORIZATION_SCHEMA_V9
    bindings = (
        dict(shadow.get("bindings"))
        if isinstance(shadow.get("bindings"), Mapping)
        else {}
    )
    shadow["bindings"] = bindings
    # These aliases exist only in the frozen structural shadow. The v10
    # semantic validator below never treats them as allocation evidence.
    bindings["predecessor_allocation_ledger_file_sha256"] = bindings.get(
        "predecessor_global_claim_file_sha256"
    )
    bindings["predecessor_allocation_ledger_state_sha256"] = bindings.get(
        "predecessor_scope_state_canonical_sha256"
    )
    bindings["predecessor_allocation_audit_file_sha256"] = bindings.get(
        "predecessor_authorization_marker_file_sha256"
    )
    bindings["predecessor_contained_session_family_sha256"] = bindings.get(
        "predecessor_containment_canonical_sha256"
    )
    bindings["predecessor_contained_session_count"] = 5
    for field in BINDING_FIELDS_V10 - BINDING_FIELDS_V7:
        bindings.pop(field, None)
    gates = (
        dict(shadow.get("mandatory_gates"))
        if isinstance(shadow.get("mandatory_gates"), Mapping)
        else {}
    )
    shadow["mandatory_gates"] = gates
    gates.pop("strict_authorization_v10", None)
    gates.pop("campaign_manifest_v7", None)
    gates.pop("preallocation_fault_predecessor_proof", None)
    gates.pop("shared_preclaim_steering_binding", None)
    gates["strict_authorization_v9"] = True
    gates["campaign_manifest_v6"] = True
    gates["protected_fault_predecessor_proof"] = True
    progress = (
        dict(shadow.get("progress_gate"))
        if isinstance(shadow.get("progress_gate"), Mapping)
        else {}
    )
    shadow["progress_gate"] = progress
    progress["predecessor_lineage_sha256"] = canonical_sha256(
        _predecessor_lineage_v9(
            bindings, progress, shadow.get("predecessor_live_generation")
        )
    )
    progress.pop("qualification_sha256", None)
    progress["qualification_sha256"] = canonical_sha256(progress)
    shadow.pop("canonical_authorization_sha256", None)
    shadow["canonical_authorization_sha256"] = canonical_sha256(shadow)
    return _v9_common_shadow(shadow)


def _validate_full_auto_authorization_v10(
    value: Any,
    *,
    expected_campaign_nonce: str | None = None,
    predecessor_proof: Version9PreallocationFaultPredecessorProofInputs | None = None,
    recovery_cause_evidence: JsonArtifactSnapshot | None = None,
    recovery_cause_source_analysis: bytes | None = None,
    expected_validator_contract_sha256: str | None = None,
    repo_root: Path | None = None,
) -> list[str]:
    errors: list[str] = []
    authorization = _strict(value, AUTHORIZATION_FIELDS, "authorization-v10", errors)
    if not authorization:
        return sorted(set(errors))
    if (
        authorization.get("authorization_type") != AUTHORIZATION_TYPE
        or authorization.get("version") != AUTHORIZATION_VERSION_V10
        or authorization.get("schema") != AUTHORIZATION_SCHEMA_V10
    ):
        errors.append("authorization-v10-header-invalid")
    errors.extend(
        f"authorization-v10-common:{item}"
        for item in _validate_full_auto_authorization_v5(
            _v10_common_shadow(authorization),
            expected_campaign_nonce=expected_campaign_nonce,
            repo_root=repo_root,
        )
    )
    bindings = _strict(
        authorization.get("bindings"),
        BINDING_FIELDS_V10,
        "authorization-v10-bindings",
        errors,
    )
    progress = _strict(
        authorization.get("progress_gate"),
        PROGRESS_GATE_FIELDS,
        "authorization-v10-progress-gate",
        errors,
    )
    supersession = _strict(
        authorization.get("supersession"),
        SUPERSESSION_FIELDS,
        "authorization-v10-supersession",
        errors,
    )
    gates = _strict(
        authorization.get("mandatory_gates"),
        MANDATORY_GATE_FIELDS_V10,
        "authorization-v10-mandatory-gates",
        errors,
    )
    if any(gates.get(field) is not True for field in MANDATORY_GATE_FIELDS_V10):
        errors.append("authorization-v10-mandatory-gate-disabled")
    non_hash_fields = {
        "checkpoint_commit",
        "checkpoint_tree",
        "origin_main_commit",
        "pickup_path",
        "recovery_plan_path",
        "campaign_nonce",
        "predecessor_authorization_id",
        "backup_ref",
        "outer_authority_id",
    }
    for field in BINDING_FIELDS_V10 - non_hash_fields:
        if not _is_hash(bindings.get(field)):
            errors.append(
                f"authorization-v10-binding-{field.replace('_', '-')}-invalid"
            )
    expected_lineage = _predecessor_lineage_v10(
        bindings, progress, authorization.get("predecessor_live_generation")
    )
    if progress.get("predecessor_lineage_sha256") != canonical_sha256(
        expected_lineage
    ):
        errors.append("authorization-v10-predecessor-lineage-sha256-mismatch")
    unsigned_progress = dict(progress)
    unsigned_progress.pop("qualification_sha256", None)
    if progress.get("qualification_sha256") != canonical_sha256(unsigned_progress):
        errors.append("authorization-v10-progress-qualification-sha256-mismatch")
    unsigned = dict(authorization)
    unsigned.pop("canonical_authorization_sha256", None)
    if authorization.get("canonical_authorization_sha256") != canonical_sha256(
        unsigned
    ):
        errors.append("authorization-v10-canonical-sha256-mismatch")
    if repo_root is not None:
        try:
            observed_contract = validator_contract_sha256_v5(
                Path(repo_root), bindings.get("checkpoint_tree")
            )
        except (OSError, ValueError):
            observed_contract = None
            errors.append("authorization-v10-validator-contract-unavailable")
        if bindings.get("validator_contract_sha256") != observed_contract:
            errors.append("authorization-v10-validator-contract-mismatch")
    if (
        expected_validator_contract_sha256 is not None
        and bindings.get("validator_contract_sha256")
        != expected_validator_contract_sha256
    ):
        errors.append("authorization-v10-expected-validator-contract-mismatch")
    if not isinstance(
        predecessor_proof, Version9PreallocationFaultPredecessorProofInputs
    ):
        errors.append("authorization-v10-predecessor-preallocation-proof-missing")
    else:
        predecessor_live_generation = authorization.get(
            "predecessor_live_generation"
        )
        errors.extend(
            _validate_v9_preallocation_fault_predecessor_proof(
                bindings=bindings,
                progress=progress,
                supersession=supersession,
                predecessor_live_generation=(
                    predecessor_live_generation
                    if _is_int(predecessor_live_generation, 0)
                    else -1
                ),
                proof=predecessor_proof,
                repo_root=repo_root,
            )
        )
    if not isinstance(recovery_cause_evidence, JsonArtifactSnapshot):
        errors.append("authorization-v10-recovery-cause-evidence-missing")
    elif not isinstance(recovery_cause_source_analysis, bytes):
        errors.append("authorization-v10-recovery-cause-source-analysis-missing")
    elif isinstance(
        predecessor_proof, Version9PreallocationFaultPredecessorProofInputs
    ):
        errors.extend(
            _validate_json_snapshot(
                recovery_cause_evidence,
                "authorization-v10-recovery-cause-evidence",
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


def _v11_common_shadow(authorization: Mapping[str, Any]) -> dict[str, Any]:
    """Project v11 common fields through the frozen v10-to-v5 validator."""

    shadow = json.loads(json.dumps(dict(authorization)))
    shadow["version"] = AUTHORIZATION_VERSION_V10
    shadow["schema"] = AUTHORIZATION_SCHEMA_V10
    bindings = (
        dict(shadow.get("bindings"))
        if isinstance(shadow.get("bindings"), Mapping)
        else {}
    )
    shadow["bindings"] = bindings
    for field in BINDING_FIELDS_V11 - BINDING_FIELDS_V10:
        bindings.pop(field, None)
    gates = (
        dict(shadow.get("mandatory_gates"))
        if isinstance(shadow.get("mandatory_gates"), Mapping)
        else {}
    )
    shadow["mandatory_gates"] = gates
    gates.pop("strict_authorization_v11", None)
    gates.pop("campaign_manifest_v8", None)
    gates.pop("interrupted_empty_boundary_predecessor_proof", None)
    gates.pop("terminal_recovery_facts_binding", None)
    gates.pop("consumed_steering_receipts_binding", None)
    gates["strict_authorization_v10"] = True
    gates["campaign_manifest_v7"] = True
    gates["preallocation_fault_predecessor_proof"] = True
    gates["shared_preclaim_steering_binding"] = True
    progress = (
        dict(shadow.get("progress_gate"))
        if isinstance(shadow.get("progress_gate"), Mapping)
        else {}
    )
    shadow["progress_gate"] = progress
    progress["predecessor_lineage_sha256"] = canonical_sha256(
        _predecessor_lineage_v10(
            bindings, progress, shadow.get("predecessor_live_generation")
        )
    )
    progress.pop("qualification_sha256", None)
    progress["qualification_sha256"] = canonical_sha256(progress)
    supersession = (
        dict(shadow.get("supersession"))
        if isinstance(shadow.get("supersession"), Mapping)
        else {}
    )
    shadow["supersession"] = supersession
    # The frozen v5 structural validator requires a terminal predecessor to
    # expose zero remaining actions. Generation 11 legitimately retains a
    # bounded containment-only action set, which the v11 semantic proof below
    # validates against the actual containment artifact. Synthesize the legacy
    # value only in this compatibility shadow; never rewrite the v11 authority.
    supersession["prior_allowed_actions"] = 0
    shadow.pop("canonical_authorization_sha256", None)
    shadow["canonical_authorization_sha256"] = canonical_sha256(shadow)
    return _v10_common_shadow(shadow)


def _validate_full_auto_authorization_v11(
    value: Any,
    *,
    expected_campaign_nonce: str | None = None,
    predecessor_proof: (
        Version10InterruptedEmptyBoundaryPredecessorProofInputs | None
    ) = None,
    recovery_cause_evidence: JsonArtifactSnapshot | None = None,
    recovery_cause_source_analysis: bytes | None = None,
    expected_validator_contract_sha256: str | None = None,
    repo_root: Path | None = None,
) -> list[str]:
    errors: list[str] = []
    authorization = _strict(value, AUTHORIZATION_FIELDS, "authorization-v11", errors)
    if not authorization:
        return sorted(set(errors))
    if (
        authorization.get("authorization_type") != AUTHORIZATION_TYPE
        or authorization.get("version") != AUTHORIZATION_VERSION_V11
        or authorization.get("schema") != AUTHORIZATION_SCHEMA_V11
    ):
        errors.append("authorization-v11-header-invalid")
    try:
        common_errors = _validate_full_auto_authorization_v5(
            _v11_common_shadow(authorization),
            expected_campaign_nonce=expected_campaign_nonce,
            repo_root=repo_root,
        )
    except (AttributeError, KeyError, TypeError, ValueError):
        common_errors = ["authorization-v11-common-scalar-invalid"]
    errors.extend(f"authorization-v11-common:{item}" for item in common_errors)
    bindings = _strict(
        authorization.get("bindings"),
        BINDING_FIELDS_V11,
        "authorization-v11-bindings",
        errors,
    )
    progress = _strict(
        authorization.get("progress_gate"),
        PROGRESS_GATE_FIELDS,
        "authorization-v11-progress-gate",
        errors,
    )
    supersession = _strict(
        authorization.get("supersession"),
        SUPERSESSION_FIELDS,
        "authorization-v11-supersession",
        errors,
    )
    gates = _strict(
        authorization.get("mandatory_gates"),
        MANDATORY_GATE_FIELDS_V11,
        "authorization-v11-mandatory-gates",
        errors,
    )
    if any(gates.get(field) is not True for field in MANDATORY_GATE_FIELDS_V11):
        errors.append("authorization-v11-mandatory-gate-disabled")
    non_hash_fields = {
        "checkpoint_commit",
        "checkpoint_tree",
        "origin_main_commit",
        "pickup_path",
        "recovery_plan_path",
        "campaign_nonce",
        "predecessor_authorization_id",
        "predecessor_terminal_session_id",
        "predecessor_terminal_turn_id",
        "backup_ref",
        "outer_authority_id",
    }
    for field in BINDING_FIELDS_V11 - non_hash_fields:
        if not _is_hash(bindings.get(field)):
            errors.append(
                f"authorization-v11-binding-{field.replace('_', '-')}-invalid"
            )
    for field in (
        "campaign_nonce",
        "predecessor_authorization_id",
        "predecessor_terminal_session_id",
        "predecessor_terminal_turn_id",
        "outer_authority_id",
    ):
        if not _is_uuid(bindings.get(field)):
            errors.append(
                f"authorization-v11-binding-{field.replace('_', '-')}-invalid"
            )
    expected_lineage = _predecessor_lineage_v11(
        bindings, progress, authorization.get("predecessor_live_generation")
    )
    if progress.get("predecessor_lineage_sha256") != canonical_sha256(
        expected_lineage
    ):
        errors.append("authorization-v11-predecessor-lineage-sha256-mismatch")
    unsigned_progress = dict(progress)
    unsigned_progress.pop("qualification_sha256", None)
    if progress.get("qualification_sha256") != canonical_sha256(unsigned_progress):
        errors.append("authorization-v11-progress-qualification-sha256-mismatch")
    unsigned = dict(authorization)
    unsigned.pop("canonical_authorization_sha256", None)
    if authorization.get("canonical_authorization_sha256") != canonical_sha256(
        unsigned
    ):
        errors.append("authorization-v11-canonical-sha256-mismatch")
    if repo_root is not None:
        try:
            observed_contract = validator_contract_sha256_v6(
                Path(repo_root), bindings.get("checkpoint_tree")
            )
        except (OSError, ValueError):
            observed_contract = None
            errors.append("authorization-v11-validator-contract-unavailable")
        if bindings.get("validator_contract_sha256") != observed_contract:
            errors.append("authorization-v11-validator-contract-mismatch")
    if (
        expected_validator_contract_sha256 is not None
        and bindings.get("validator_contract_sha256")
        != expected_validator_contract_sha256
    ):
        errors.append("authorization-v11-expected-validator-contract-mismatch")
    if not isinstance(
        predecessor_proof, Version10InterruptedEmptyBoundaryPredecessorProofInputs
    ):
        errors.append("authorization-v11-predecessor-terminal-proof-missing")
    else:
        errors.extend(
            _validate_v10_interrupted_empty_boundary_predecessor_proof(
                bindings=bindings,
                progress=progress,
                supersession=supersession,
                predecessor_live_generation=_generation_or_invalid(
                    authorization.get("predecessor_live_generation")
                ),
                proof=predecessor_proof,
                repo_root=repo_root,
            )
        )
    if not isinstance(recovery_cause_evidence, JsonArtifactSnapshot):
        errors.append("authorization-v11-recovery-cause-evidence-missing")
    elif not isinstance(recovery_cause_source_analysis, bytes):
        errors.append("authorization-v11-recovery-cause-source-analysis-missing")
    elif isinstance(
        predecessor_proof, Version10InterruptedEmptyBoundaryPredecessorProofInputs
    ):
        errors.extend(
            _validate_json_snapshot(
                recovery_cause_evidence,
                "authorization-v11-recovery-cause-evidence",
            )
        )
        errors.extend(
            _validate_v11_recovery_cause_evidence(
                recovery_cause_evidence.value,
                raw_sha256=recovery_cause_evidence.raw_sha256,
                bindings=bindings,
                progress=progress,
                predecessor=predecessor_proof,
                source_analysis_bytes=recovery_cause_source_analysis,
            )
        )
    return sorted(set(errors))


def _dispatch_validate_full_auto_authorization(
    value: Any,
    *,
    predecessor_proof: (
        Version5PredecessorProofInputs
        | Version6PredecessorProofInputs
        | Version7QuarantinePredecessorProofInputs
        | Version8ProtectedFaultPredecessorProofInputs
        | Version9PreallocationFaultPredecessorProofInputs
        | Version10InterruptedEmptyBoundaryPredecessorProofInputs
        | None
    ) = None,
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
    if version == AUTHORIZATION_VERSION_V7:
        legacy_predecessor_keys = {
            key
            for key, item in legacy_kwargs.items()
            if key.startswith("predecessor_") and item is not None
        }
        if legacy_predecessor_keys:
            return ["authorization-v7-legacy-proof-input-forbidden"]
        allowed = {
            "expected_campaign_nonce",
            "repo_root",
        }
        unknown = set(legacy_kwargs) - allowed
        if unknown:
            return ["authorization-v7-validator-arguments-invalid"]
        return _validate_full_auto_authorization_v7(
            value,
            expected_campaign_nonce=legacy_kwargs.get("expected_campaign_nonce"),
            predecessor_proof=(
                predecessor_proof
                if isinstance(predecessor_proof, Version6PredecessorProofInputs)
                else None
            ),
            recovery_cause_evidence=recovery_cause_evidence,
            recovery_cause_source_analysis=recovery_cause_source_analysis,
            expected_validator_contract_sha256=expected_validator_contract_sha256,
            repo_root=legacy_kwargs.get("repo_root"),
        )
    if version == AUTHORIZATION_VERSION_V8:
        legacy_predecessor_keys = {
            key
            for key, item in legacy_kwargs.items()
            if key.startswith("predecessor_") and item is not None
        }
        if legacy_predecessor_keys:
            return ["authorization-v8-legacy-proof-input-forbidden"]
        allowed = {"expected_campaign_nonce", "repo_root"}
        if set(legacy_kwargs) - allowed:
            return ["authorization-v8-validator-arguments-invalid"]
        return _validate_full_auto_authorization_v8(
            value,
            expected_campaign_nonce=legacy_kwargs.get("expected_campaign_nonce"),
            predecessor_proof=(
                predecessor_proof
                if isinstance(
                    predecessor_proof,
                    Version7QuarantinePredecessorProofInputs,
                )
                else None
            ),
            recovery_cause_evidence=recovery_cause_evidence,
            recovery_cause_source_analysis=recovery_cause_source_analysis,
            expected_validator_contract_sha256=expected_validator_contract_sha256,
            repo_root=legacy_kwargs.get("repo_root"),
        )
    if version == AUTHORIZATION_VERSION_V9:
        legacy_predecessor_keys = {
            key
            for key, item in legacy_kwargs.items()
            if key.startswith("predecessor_") and item is not None
        }
        if legacy_predecessor_keys:
            return ["authorization-v9-legacy-proof-input-forbidden"]
        allowed = {"expected_campaign_nonce", "repo_root"}
        if set(legacy_kwargs) - allowed:
            return ["authorization-v9-validator-arguments-invalid"]
        return _validate_full_auto_authorization_v9(
            value,
            expected_campaign_nonce=legacy_kwargs.get("expected_campaign_nonce"),
            predecessor_proof=(
                predecessor_proof
                if isinstance(
                    predecessor_proof,
                    Version8ProtectedFaultPredecessorProofInputs,
                )
                else None
            ),
            recovery_cause_evidence=recovery_cause_evidence,
            recovery_cause_source_analysis=recovery_cause_source_analysis,
            expected_validator_contract_sha256=expected_validator_contract_sha256,
            repo_root=legacy_kwargs.get("repo_root"),
        )
    if version == AUTHORIZATION_VERSION_V10:
        legacy_predecessor_keys = {
            key
            for key, item in legacy_kwargs.items()
            if key.startswith("predecessor_") and item is not None
        }
        if legacy_predecessor_keys:
            return ["authorization-v10-legacy-proof-input-forbidden"]
        allowed = {"expected_campaign_nonce", "repo_root"}
        if set(legacy_kwargs) - allowed:
            return ["authorization-v10-validator-arguments-invalid"]
        return _validate_full_auto_authorization_v10(
            value,
            expected_campaign_nonce=legacy_kwargs.get("expected_campaign_nonce"),
            predecessor_proof=(
                predecessor_proof
                if isinstance(
                    predecessor_proof,
                    Version9PreallocationFaultPredecessorProofInputs,
                )
                else None
            ),
            recovery_cause_evidence=recovery_cause_evidence,
            recovery_cause_source_analysis=recovery_cause_source_analysis,
            expected_validator_contract_sha256=expected_validator_contract_sha256,
            repo_root=legacy_kwargs.get("repo_root"),
        )
    if version == AUTHORIZATION_VERSION_V11:
        legacy_predecessor_keys = {
            key
            for key, item in legacy_kwargs.items()
            if key.startswith("predecessor_") and item is not None
        }
        if legacy_predecessor_keys:
            return ["authorization-v11-legacy-proof-input-forbidden"]
        allowed = {"expected_campaign_nonce", "repo_root"}
        if set(legacy_kwargs) - allowed:
            return ["authorization-v11-validator-arguments-invalid"]
        return _validate_full_auto_authorization_v11(
            value,
            expected_campaign_nonce=legacy_kwargs.get("expected_campaign_nonce"),
            predecessor_proof=(
                predecessor_proof
                if isinstance(
                    predecessor_proof,
                    Version10InterruptedEmptyBoundaryPredecessorProofInputs,
                )
                else None
            ),
            recovery_cause_evidence=recovery_cause_evidence,
            recovery_cause_source_analysis=recovery_cause_source_analysis,
            expected_validator_contract_sha256=expected_validator_contract_sha256,
            repo_root=legacy_kwargs.get("repo_root"),
        )
    return ["authorization-header-invalid"]


def validate_full_auto_authorization(value: Any, **kwargs: Any) -> list[str]:
    """Fail closed instead of raising when an untrusted proof graph is malformed."""
    try:
        return _dispatch_validate_full_auto_authorization(value, **kwargs)
    except (AttributeError, IndexError, KeyError, TypeError, ValueError):
        return ["authorization-proof-structure-invalid"]


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
    predecessor = (
        dict(shadow.get("predecessor"))
        if isinstance(shadow.get("predecessor"), Mapping)
        else {}
    )
    shadow["predecessor"] = predecessor
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


def _validate_v6_v3_predecessor_proof(
    *,
    bindings: Mapping[str, Any],
    progress: Mapping[str, Any],
    supersession: Mapping[str, Any],
    predecessor_live_generation: int,
    proof: Version6PredecessorProofInputs,
    repo_root: Path | None,
) -> list[str]:
    """Validate the fixed v7/v4 -> v6/v3 -> v5/v2 -> v4/v1 DAG."""

    errors: list[str] = []
    if not isinstance(proof.ancestor, Version5PredecessorProofInputs):
        return ["authorization-predecessor-v6-ancestor-proof-type-invalid"]
    if not isinstance(proof.ancestor.ancestor, HistoricalV4V1ProofInputs):
        return ["authorization-predecessor-v5-historical-proof-type-invalid"]
    snapshots = {
        "authorization-predecessor-v6-authorization": proof.authorization,
        "authorization-predecessor-v3-manifest": proof.manifest,
        "authorization-predecessor-state": proof.authorization_state,
        "authorization-predecessor-failure": proof.failure_evidence,
        "authorization-predecessor-containment": proof.containment,
        "authorization-predecessor-ledger": proof.allocation_ledger,
        "authorization-predecessor-v6-cause": (
            proof.authorization_recovery_cause_evidence
        ),
        "authorization-predecessor-outer-authority": proof.outer_authority,
        "authorization-predecessor-independent-validation": (
            proof.independent_validation_receipt
        ),
    }
    for label, snapshot in snapshots.items():
        errors.extend(_validate_json_snapshot(snapshot, label))
    if (
        not isinstance(proof.allocation_audit_bytes, bytes)
        or not isinstance(
            proof.authorization_recovery_cause_source_analysis, bytes
        )
        or not isinstance(proof.independent_validation_session_bytes, bytes)
    ):
        errors.append("authorization-predecessor-v6-byte-snapshot-invalid")
        return sorted(set(errors))

    prior_authorization = dict(proof.authorization.value)
    prior_manifest = dict(proof.manifest.value)
    prior_state = dict(proof.authorization_state.value)
    prior_failure = dict(proof.failure_evidence.value)
    prior_containment = dict(proof.containment.value)
    prior_ledger = dict(proof.allocation_ledger.value)
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
    prior_supersession = (
        prior_authorization.get("supersession")
        if isinstance(prior_authorization.get("supersession"), Mapping)
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

    errors.extend(
        f"authorization-predecessor-v6-contract:{item}"
        for item in _validate_full_auto_authorization_v6(
            prior_authorization,
            predecessor_proof=proof.ancestor,
            recovery_cause_evidence=(
                proof.authorization_recovery_cause_evidence
            ),
            recovery_cause_source_analysis=(
                proof.authorization_recovery_cause_source_analysis
            ),
            expected_validator_contract_sha256=prior_bindings.get(
                "validator_contract_sha256"
            ),
            repo_root=None,
        )
    )
    errors.extend(
        f"authorization-predecessor-v3-contract:{item}"
        for item in _validate_campaign_manifest_v3(
            prior_manifest,
            authorization=prior_authorization,
            authorization_raw_sha256=proof.authorization.raw_sha256,
            outer_authority=proof.outer_authority.value,
            outer_authority_raw_sha256=proof.outer_authority.raw_sha256,
            predecessor_proof=proof.ancestor,
            recovery_cause_evidence=(
                proof.authorization_recovery_cause_evidence
            ),
            recovery_cause_source_analysis=(
                proof.authorization_recovery_cause_source_analysis
            ),
            independent_validation_receipt=(
                proof.independent_validation_receipt.value
            ),
            independent_validation_receipt_raw_sha256=(
                proof.independent_validation_receipt.raw_sha256
            ),
            expected_validator_contract_sha256=prior_bindings.get(
                "validator_contract_sha256"
            ),
            repo_root=None,
            expected_primary_diff_sha256=None,
        )
    )
    errors.extend(
        _validate_independent_validation_session_snapshot(
            proof.independent_validation_receipt.value,
            proof.independent_validation_session_bytes,
        )
    )

    prior_authorization_id = prior_authorization.get("authorization_id")
    prior_nonce = prior_bindings.get("campaign_nonce")
    if bindings.get("campaign_nonce") == prior_nonce:
        errors.append("authorization-v7-predecessor-campaign-nonce-reused")
    if (
        proof.authorization.raw_sha256
        != bindings.get("predecessor_authorization_file_sha256")
        or prior_authorization.get("canonical_authorization_sha256")
        != bindings.get("predecessor_authorization_canonical_sha256")
        or prior_authorization_id != bindings.get("predecessor_authorization_id")
        or prior_authorization.get("version") != AUTHORIZATION_VERSION_V6
        or prior_authorization.get("live_generation")
        != predecessor_live_generation
        or proof.manifest.raw_sha256
        != bindings.get("predecessor_manifest_file_sha256")
        or prior_manifest.get("manifest_sha256")
        != bindings.get("predecessor_manifest_canonical_sha256")
        or prior_manifest.get("version") != MANIFEST_VERSION_V3
        or prior_candidate.get("commit")
        != progress.get("predecessor_candidate_commit")
        or prior_candidate.get("tree")
        != progress.get("predecessor_candidate_tree")
    ):
        errors.append("authorization-predecessor-v6-v3-binding-invalid")

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
        errors.append("authorization-predecessor-v6-ancestor-lineage-invalid")

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
    protected_allowed_actions = (
        prior_state.get("allowed_actions")
        if isinstance(prior_state.get("allowed_actions"), list)
        else []
    )
    protected_revoked_actions = (
        prior_state.get("revoked_actions")
        if isinstance(prior_state.get("revoked_actions"), list)
        else []
    )
    if (
        proof.authorization_state.raw_sha256
        != bindings.get("predecessor_authorization_state_file_sha256")
        or prior_state.get("state_sha256")
        != bindings.get("predecessor_authorization_state_canonical_sha256")
        or validate_authorization_state(prior_state)
        or prior_state.get("authorization_id") != prior_authorization_id
        or prior_state.get("run_nonce") != prior_nonce
        or prior_state.get("state") != "containment-only"
        or required_revocations.intersection(protected_allowed_actions)
        or not required_revocations.issubset(set(protected_revoked_actions))
    ):
        errors.append("authorization-predecessor-v6-state-binding-invalid")

    audit_sha256 = hashlib.sha256(proof.allocation_audit_bytes).hexdigest()
    ledger_errors = validate_live_allocation_ledger(
        prior_ledger, audit_bytes=proof.allocation_audit_bytes
    )
    if ledger_errors:
        errors.append(
            "authorization-predecessor-v6-ledger-invalid:"
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
        errors.append("authorization-predecessor-v6-ledger-binding-invalid")
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
        errors.append("authorization-predecessor-v6-ledger-authority-mismatch")

    failure = _strict(
        prior_failure,
        MODERN_FAILURE_EVIDENCE_FIELDS,
        "authorization-predecessor-v6-failure",
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
        errors.append("authorization-predecessor-v6-failure-binding-invalid")

    containment = _strict(
        prior_containment,
        MODERN_CONTAINMENT_FIELDS,
        "authorization-predecessor-v6-containment",
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
        errors.append("authorization-predecessor-v6-containment-binding-invalid")
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
        errors.append("authorization-predecessor-v6-session-accounting-invalid")
    errors.extend(
        _validate_contained_session_snapshots(
            session_accounting=sessions,
            ledger=prior_ledger,
            raw_sessions=proof.contained_session_bytes,
            label="authorization-predecessor-v6",
            historical=False,
        )
    )

    if (
        proof.authorization_recovery_cause_evidence.raw_sha256
        != prior_progress.get("cause_evidence_sha256")
    ):
        errors.append("authorization-predecessor-v6-cause-evidence-binding-invalid")
    if (
        proof.outer_authority.raw_sha256
        != prior_bindings.get("outer_authority_file_sha256")
        or proof.outer_authority.value.get("canonical_outer_authority_sha256")
        != prior_bindings.get("outer_authority_canonical_sha256")
        or proof.outer_authority.value.get("authority_id")
        != prior_bindings.get("outer_authority_id")
    ):
        errors.append("authorization-predecessor-v6-outer-authority-binding-invalid")

    if repo_root is not None:
        root = Path(repo_root).resolve()
        ancestor_generation = prior_authorization.get(
            "predecessor_live_generation"
        )
        errors.extend(
            f"authorization-predecessor-v6-ancestor:{item}"
            for item in _validate_v5_v2_predecessor_proof(
                bindings=prior_bindings,
                progress=prior_progress,
                supersession=prior_supersession,
                predecessor_live_generation=(
                    ancestor_generation
                    if _is_int(ancestor_generation, 0)
                    else -1
                ),
                proof=proof.ancestor,
                repo_root=root,
            )
        )
        try:
            prior_checkpoint = str(prior_bindings["checkpoint_commit"])
            current_checkpoint = str(bindings["checkpoint_commit"])
            if (
                _run_git(root, "rev-parse", f"{prior_checkpoint}^{{tree}}")
                != prior_bindings.get("checkpoint_tree")
                or _run_git(
                    root,
                    "rev-parse",
                    f"{prior_candidate.get('commit')}^{{tree}}",
                )
                != prior_candidate.get("tree")
                or _run_git(root, "rev-parse", f"{current_checkpoint}^{{tree}}")
                != bindings.get("checkpoint_tree")
            ):
                errors.append("authorization-predecessor-v6-anchor-tree-mismatch")
            for ancestor_commit, descendant_commit in (
                (str(prior_candidate.get("commit")), prior_checkpoint),
                (prior_checkpoint, current_checkpoint),
            ):
                if subprocess.run(
                    [
                        "git",
                        "merge-base",
                        "--is-ancestor",
                        ancestor_commit,
                        descendant_commit,
                    ],
                    cwd=root,
                    capture_output=True,
                ).returncode != 0:
                    errors.append("authorization-predecessor-v6-anchor-lineage-invalid")
            recorded_origin = bindings.get("origin_main_commit")
            if (
                prior_bindings.get("origin_main_commit") != recorded_origin
                or _run_git(root, "rev-parse", "origin/main") != recorded_origin
            ):
                errors.append("authorization-predecessor-v6-anchor-origin-mismatch")
            observed_v1_contract = validator_contract_sha256(
                root, prior_bindings.get("checkpoint_tree")
            )
            if (
                prior_bindings.get("validator_contract_sha256")
                != observed_v1_contract
            ):
                errors.append("authorization-predecessor-v6-validator-contract-mismatch")
        except (KeyError, subprocess.CalledProcessError, ValueError):
            errors.append("authorization-predecessor-v6-anchor-invalid")
    return sorted(set(errors))


def _validate_v7_quarantine_predecessor_proof(
    *,
    bindings: Mapping[str, Any],
    progress: Mapping[str, Any],
    supersession: Mapping[str, Any],
    predecessor_live_generation: int,
    proof: Version7QuarantinePredecessorProofInputs,
    repo_root: Path | None,
) -> list[str]:
    """Validate the v7/v4 Generation-8 quarantine predecessor exactly.

    This path is intentionally separate from the accepting modern-session and
    seven-event lifecycle validators.  It proves only that one nonattesting
    capability allocation was archived and durably contained.
    """

    errors: list[str] = []
    if not isinstance(proof.ancestor, Version6PredecessorProofInputs):
        return ["authorization-predecessor-v7-ancestor-proof-type-invalid"]
    if not isinstance(proof.ancestor.ancestor, Version5PredecessorProofInputs):
        return ["authorization-predecessor-v6-ancestor-proof-type-invalid"]
    snapshots = {
        "authorization-predecessor-v7-authorization": proof.authorization,
        "authorization-predecessor-v4-manifest": proof.manifest,
        "authorization-predecessor-v7-state": proof.authorization_state,
        "authorization-predecessor-v7-failure": proof.failure_evidence,
        "authorization-predecessor-v7-containment": proof.containment,
        "authorization-predecessor-v7-ledger": proof.allocation_ledger,
        "authorization-predecessor-v7-cause": (
            proof.authorization_recovery_cause_evidence
        ),
        "authorization-predecessor-v7-outer-authority": proof.outer_authority,
        "authorization-predecessor-v7-independent-validation": (
            proof.independent_validation_receipt
        ),
    }
    for label, snapshot in snapshots.items():
        errors.extend(_validate_json_snapshot(snapshot, label))
    if (
        not isinstance(proof.allocation_audit_bytes, bytes)
        or not isinstance(
            proof.authorization_recovery_cause_source_analysis, bytes
        )
        or not isinstance(proof.independent_validation_session_bytes, bytes)
        or not isinstance(proof.quarantined_session_bytes, bytes)
    ):
        errors.append("authorization-predecessor-v7-quarantine-byte-snapshot-invalid")
        return sorted(set(errors))

    prior_authorization = dict(proof.authorization.value)
    prior_manifest = dict(proof.manifest.value)
    prior_state = dict(proof.authorization_state.value)
    prior_failure = dict(proof.failure_evidence.value)
    prior_containment = dict(proof.containment.value)
    prior_ledger = dict(proof.allocation_ledger.value)
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
    prior_supersession = (
        prior_authorization.get("supersession")
        if isinstance(prior_authorization.get("supersession"), Mapping)
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

    errors.extend(
        f"authorization-predecessor-v7-contract:{item}"
        for item in _validate_full_auto_authorization_v7(
            prior_authorization,
            predecessor_proof=proof.ancestor,
            recovery_cause_evidence=(
                proof.authorization_recovery_cause_evidence
            ),
            recovery_cause_source_analysis=(
                proof.authorization_recovery_cause_source_analysis
            ),
            expected_validator_contract_sha256=prior_bindings.get(
                "validator_contract_sha256"
            ),
            repo_root=None,
        )
    )
    errors.extend(
        f"authorization-predecessor-v4-contract:{item}"
        for item in _validate_campaign_manifest_v4(
            prior_manifest,
            authorization=prior_authorization,
            authorization_raw_sha256=proof.authorization.raw_sha256,
            outer_authority=proof.outer_authority.value,
            outer_authority_raw_sha256=proof.outer_authority.raw_sha256,
            predecessor_proof=proof.ancestor,
            recovery_cause_evidence=(
                proof.authorization_recovery_cause_evidence
            ),
            recovery_cause_source_analysis=(
                proof.authorization_recovery_cause_source_analysis
            ),
            independent_validation_receipt=(
                proof.independent_validation_receipt.value
            ),
            independent_validation_receipt_raw_sha256=(
                proof.independent_validation_receipt.raw_sha256
            ),
            expected_validator_contract_sha256=prior_bindings.get(
                "validator_contract_sha256"
            ),
            repo_root=None,
            expected_primary_diff_sha256=None,
        )
    )
    errors.extend(
        _validate_independent_validation_session_snapshot(
            proof.independent_validation_receipt.value,
            proof.independent_validation_session_bytes,
        )
    )

    prior_authorization_id = prior_authorization.get("authorization_id")
    prior_nonce = prior_bindings.get("campaign_nonce")
    if bindings.get("campaign_nonce") == prior_nonce:
        errors.append("authorization-v8-predecessor-campaign-nonce-reused")
    if (
        proof.authorization.raw_sha256
        != bindings.get("predecessor_authorization_file_sha256")
        or prior_authorization.get("canonical_authorization_sha256")
        != bindings.get("predecessor_authorization_canonical_sha256")
        or prior_authorization_id != bindings.get("predecessor_authorization_id")
        or prior_authorization.get("version") != AUTHORIZATION_VERSION_V7
        or prior_authorization.get("live_generation")
        != predecessor_live_generation
        or proof.manifest.raw_sha256
        != bindings.get("predecessor_manifest_file_sha256")
        or prior_manifest.get("manifest_sha256")
        != bindings.get("predecessor_manifest_canonical_sha256")
        or prior_manifest.get("version") != MANIFEST_VERSION_V4
        or prior_candidate.get("commit")
        != progress.get("predecessor_candidate_commit")
        or prior_candidate.get("tree")
        != progress.get("predecessor_candidate_tree")
    ):
        errors.append("authorization-predecessor-v7-v4-binding-invalid")

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
        errors.append("authorization-predecessor-v7-ancestor-lineage-invalid")

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
        errors.append("authorization-predecessor-v7-quarantine-state-binding-invalid")

    audit_sha256 = hashlib.sha256(proof.allocation_audit_bytes).hexdigest()
    ledger_errors = validate_live_allocation_ledger(
        prior_ledger, audit_bytes=proof.allocation_audit_bytes
    )
    if ledger_errors:
        errors.append(
            "authorization-predecessor-v7-quarantine-ledger-invalid:"
            + ",".join(ledger_errors)
        )
    try:
        ledger_summary = summarize_live_allocation_ledger(
            prior_ledger,
            ledger_file_sha256=proof.allocation_ledger.raw_sha256,
        )
    except (KeyError, NativeLiveAllocationLedgerError, ValueError):
        ledger_summary = {}
    failure_ledger_summary = prior_failure.get("allocation_ledger")
    errors.extend(
        _validate_generation8_quarantine_ledger(
            prior_ledger, failure_ledger_summary
        )
    )
    try:
        prefix, prefix_raw = _generation8_failure_ledger_prefix(prior_ledger)
    except (TypeError, ValueError):
        prefix, prefix_raw = {}, b""
    if (
        proof.allocation_ledger.raw_sha256
        != bindings.get("predecessor_allocation_ledger_file_sha256")
        or prior_ledger.get("state_sha256")
        != bindings.get("predecessor_allocation_ledger_state_sha256")
        or audit_sha256 != bindings.get("predecessor_allocation_audit_file_sha256")
        or hashlib.sha256(prefix_raw).hexdigest()
        != bindings.get("predecessor_failure_ledger_prefix_file_sha256")
        or prefix.get("state_sha256")
        != bindings.get("predecessor_failure_ledger_prefix_state_sha256")
        or prefix.get("head_entry_sha256")
        != bindings.get("predecessor_failure_ledger_prefix_head_entry_sha256")
        or supersession.get("prior_allocations") != 1
        or ledger_summary.get("allocation_intent_count") != 1
        or ledger_summary.get("sequence") != 6
        or ledger_summary.get("unresolved_allocation_intent_count") != 0
        or ledger_summary.get("unresolved_turn_intent_count") != 0
    ):
        errors.append("authorization-predecessor-v7-quarantine-ledger-binding-invalid")

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
        errors.append("authorization-predecessor-v7-quarantine-ledger-authority-mismatch")

    failure = _strict(
        prior_failure,
        MODERN_FAILURE_EVIDENCE_FIELDS,
        "authorization-predecessor-v7-quarantine-failure",
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
    expected_initial_containment = {
        "all_contained": False,
        "allocated_count": 1,
        "already_contained_count": 0,
        "ambiguous_count": 1,
        "archived_count": 0,
        "identified_thread_count": 1,
        "interrupted_count": 0,
        "ledger_consistent": True,
        "ledger_error_sha256": [],
        "unresolved_allocation_intent_count": 0,
        "unresolved_turn_intent_count": 0,
    }
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
        or failure.get("failure_class") != "AppServerError"
        or failure.get("failure_code") != "AppServerError"
        or failure_containment != expected_initial_containment
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
    ):
        errors.append("authorization-predecessor-v7-quarantine-failure-binding-invalid")

    containment = _strict(
        prior_containment,
        QUARANTINE_CONTAINMENT_FIELDS,
        "authorization-predecessor-v7-quarantine-containment",
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
    scope_transition = (
        containment.get("scope_transition")
        if isinstance(containment.get("scope_transition"), Mapping)
        else {}
    )
    sessions = containment.get("session_accounting")
    expected_final_containment = {
        "allocated_count": 1,
        "identified_thread_count": 1,
        "interrupted_count": 0,
        "archived_count": 1,
        "already_contained_count": 0,
        "unresolved_allocation_intent_count": 0,
        "unresolved_turn_intent_count": 0,
        "ambiguous_count": 0,
        "all_contained": True,
        "ledger_consistent": True,
        "ledger_error_sha256": [],
    }
    expected_containment_ledger = {
        "allocated_roles": ["capability-calibration"],
        "allocation_intent_count": 1,
        "audit_file_sha256": audit_sha256,
        "head_entry_sha256": prior_ledger.get("head_entry_sha256"),
        "ledger_file_sha256": proof.allocation_ledger.raw_sha256,
        "sequence": 6,
        "state_sha256": prior_ledger.get("state_sha256"),
        "thread_bound_count": 1,
        "turn_bound_count": 1,
        "turn_intent_count": 1,
        "unresolved_allocation_intent_count": 0,
        "unresolved_turn_intent_count": 0,
        "validation_errors": [],
    }
    controller_identity = (
        ledger_bindings.get("controller_identity")
        if isinstance(ledger_bindings.get("controller_identity"), Mapping)
        else {}
    )
    expected_control = {
        "authorization_state_validation_errors": [],
        "campaign_process_alive": False,
        "controller_pid": controller_identity.get("pid"),
        "disposable_workspace_present": False,
        "evidence_canonical_hash_valid": True,
        "isolated_checkout_head": prior_candidate.get("commit"),
        "isolated_checkout_tracked_clean": True,
        "isolated_checkout_tree": prior_candidate.get("tree"),
        "operative_dispatch_authorized": False,
        "origin_main_commit": prior_candidate.get("origin_main_commit"),
        "protected_primary_diff_sha256": prior_candidate.get(
            "guarded_primary_diff_sha256"
        ),
        "release_policy_status": "canary-gated",
    }
    expected_disposition = {
        "authorization_state": "containment-only",
        "outer_full_auto_recovery_permitted": True,
        "release_gate_passed": False,
        "requires_fresh_live_generation": predecessor_live_generation + 1,
        "requires_validated_candidate_repair": True,
        "reuse_resume_retry_substitution_salvage_bridge": False,
    }
    ledger_entries = prior_ledger.get("entries")
    thread_id = (
        ledger_entries[1].get("thread_id")
        if isinstance(ledger_entries, list)
        and len(ledger_entries) == 6
        and isinstance(ledger_entries[1], Mapping)
        else None
    )
    turn_id = (
        ledger_entries[3].get("turn_id")
        if isinstance(ledger_entries, list)
        and len(ledger_entries) == 6
        and isinstance(ledger_entries[3], Mapping)
        else None
    )
    accounting = sessions[0] if isinstance(sessions, list) and len(sessions) == 1 else None
    errors.extend(
        _validate_generation8_quarantine_session(
            proof.quarantined_session_bytes,
            accounting,
            expected_session_id=thread_id,
            expected_turn_id=turn_id,
            expected_file_sha256=bindings.get(
                "predecessor_quarantined_session_file_sha256"
            ),
        )
    )
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
        or dict(containment_summary) != expected_final_containment
        or dict(containment_ledger) != expected_containment_ledger
        or dict(control) != expected_control
        or dict(disposition) != expected_disposition
        or root_cause.get("failure_class")
        != progress.get("predecessor_failure_class")
        or root_cause.get("message_sha256")
        != failure.get("failure_message_sha256")
        or root_cause.get("independent_reproduction") is not True
        or scope_transition
        != {
            "from": "active",
            "terminal_evidence_field": "canonical_recovery_sha256",
            "to": "contained",
        }
        or not isinstance(sessions, list)
        or len(sessions) != 1
    ):
        errors.append("authorization-predecessor-v7-quarantine-containment-binding-invalid")

    if (
        proof.authorization_recovery_cause_evidence.raw_sha256
        != prior_progress.get("cause_evidence_sha256")
    ):
        errors.append("authorization-predecessor-v7-cause-evidence-binding-invalid")
    if (
        proof.outer_authority.raw_sha256
        != prior_bindings.get("outer_authority_file_sha256")
        or proof.outer_authority.value.get("canonical_outer_authority_sha256")
        != prior_bindings.get("outer_authority_canonical_sha256")
        or proof.outer_authority.value.get("authority_id")
        != prior_bindings.get("outer_authority_id")
    ):
        errors.append("authorization-predecessor-v7-outer-authority-binding-invalid")

    if repo_root is not None:
        root = Path(repo_root).resolve()
        errors.extend(
            f"authorization-predecessor-v7-ancestor:{item}"
            for item in _validate_v6_v3_predecessor_proof(
                bindings=prior_bindings,
                progress=prior_progress,
                supersession=prior_supersession,
                predecessor_live_generation=_generation_or_invalid(
                    prior_authorization.get("predecessor_live_generation")
                ),
                proof=proof.ancestor,
                repo_root=root,
            )
        )
        try:
            prior_checkpoint = str(prior_bindings["checkpoint_commit"])
            current_checkpoint = str(bindings["checkpoint_commit"])
            if (
                _run_git(root, "rev-parse", f"{prior_checkpoint}^{{tree}}")
                != prior_bindings.get("checkpoint_tree")
                or _run_git(
                    root,
                    "rev-parse",
                    f"{prior_candidate.get('commit')}^{{tree}}",
                )
                != prior_candidate.get("tree")
                or _run_git(root, "rev-parse", f"{current_checkpoint}^{{tree}}")
                != bindings.get("checkpoint_tree")
            ):
                errors.append("authorization-predecessor-v7-anchor-tree-mismatch")
            for ancestor_commit, descendant_commit in (
                (str(prior_candidate.get("commit")), prior_checkpoint),
                (prior_checkpoint, current_checkpoint),
            ):
                if subprocess.run(
                    [
                        "git",
                        "merge-base",
                        "--is-ancestor",
                        ancestor_commit,
                        descendant_commit,
                    ],
                    cwd=root,
                    capture_output=True,
                ).returncode != 0:
                    errors.append("authorization-predecessor-v7-anchor-lineage-invalid")
            recorded_origin = bindings.get("origin_main_commit")
            if (
                prior_bindings.get("origin_main_commit") != recorded_origin
                or _run_git(root, "rev-parse", "origin/main") != recorded_origin
            ):
                errors.append("authorization-predecessor-v7-anchor-origin-mismatch")
            observed_v2_contract = validator_contract_sha256_v2(
                root, prior_bindings.get("checkpoint_tree")
            )
            if prior_bindings.get("validator_contract_sha256") != observed_v2_contract:
                errors.append("authorization-predecessor-v7-validator-contract-mismatch")
        except (KeyError, subprocess.CalledProcessError, ValueError):
            errors.append("authorization-predecessor-v7-anchor-invalid")
    return sorted(set(errors))


def _validate_v8_protected_fault_predecessor_proof(
    *,
    bindings: Mapping[str, Any],
    progress: Mapping[str, Any],
    supersession: Mapping[str, Any],
    predecessor_live_generation: int,
    proof: Version8ProtectedFaultPredecessorProofInputs,
    repo_root: Path | None,
) -> list[str]:
    """Validate the exact terminal v8/v5 Generation-9 predecessor leaf."""

    errors: list[str] = []
    if not isinstance(proof.ancestor, Version7QuarantinePredecessorProofInputs):
        return ["authorization-predecessor-v8-ancestor-proof-type-invalid"]
    if not isinstance(proof.ancestor.ancestor, Version6PredecessorProofInputs):
        return ["authorization-predecessor-v7-ancestor-proof-type-invalid"]
    snapshots = {
        "authorization-predecessor-v8-authorization": proof.authorization,
        "authorization-predecessor-v5-manifest": proof.manifest,
        "authorization-predecessor-v8-state": proof.authorization_state,
        "authorization-predecessor-v8-failure": proof.failure_evidence,
        "authorization-predecessor-v8-containment": proof.containment,
        "authorization-predecessor-v8-ledger": proof.allocation_ledger,
        "authorization-predecessor-v8-cause": (
            proof.authorization_recovery_cause_evidence
        ),
        "authorization-predecessor-v8-outer-authority": proof.outer_authority,
        "authorization-predecessor-v8-independent-validation": (
            proof.independent_validation_receipt
        ),
    }
    for label, snapshot in snapshots.items():
        errors.extend(_validate_json_snapshot(snapshot, label))
    if (
        not isinstance(proof.allocation_audit_bytes, bytes)
        or not isinstance(proof.authorization_recovery_cause_source_analysis, bytes)
        or not isinstance(proof.independent_validation_session_bytes, bytes)
        or not isinstance(proof.contained_session_bytes, tuple)
        or len(proof.contained_session_bytes) != 5
        or any(not isinstance(raw, bytes) for raw in proof.contained_session_bytes)
    ):
        errors.append("authorization-predecessor-v8-protected-byte-snapshot-invalid")
        return sorted(set(errors))

    prior_authorization = dict(proof.authorization.value)
    prior_manifest = dict(proof.manifest.value)
    prior_state = dict(proof.authorization_state.value)
    prior_failure = dict(proof.failure_evidence.value)
    prior_containment = dict(proof.containment.value)
    prior_ledger = dict(proof.allocation_ledger.value)
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
    prior_supersession = (
        prior_authorization.get("supersession")
        if isinstance(prior_authorization.get("supersession"), Mapping)
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

    errors.extend(
        f"authorization-predecessor-v8-contract:{item}"
        for item in _validate_full_auto_authorization_v8(
            prior_authorization,
            predecessor_proof=proof.ancestor,
            recovery_cause_evidence=proof.authorization_recovery_cause_evidence,
            recovery_cause_source_analysis=(
                proof.authorization_recovery_cause_source_analysis
            ),
            expected_validator_contract_sha256=prior_bindings.get(
                "validator_contract_sha256"
            ),
            repo_root=None,
        )
    )
    errors.extend(
        f"authorization-predecessor-v5-contract:{item}"
        for item in _validate_campaign_manifest_v5(
            prior_manifest,
            authorization=prior_authorization,
            authorization_raw_sha256=proof.authorization.raw_sha256,
            outer_authority=proof.outer_authority.value,
            outer_authority_raw_sha256=proof.outer_authority.raw_sha256,
            predecessor_proof=proof.ancestor,
            recovery_cause_evidence=proof.authorization_recovery_cause_evidence,
            recovery_cause_source_analysis=(
                proof.authorization_recovery_cause_source_analysis
            ),
            independent_validation_receipt=(
                proof.independent_validation_receipt.value
            ),
            independent_validation_receipt_raw_sha256=(
                proof.independent_validation_receipt.raw_sha256
            ),
            expected_validator_contract_sha256=prior_bindings.get(
                "validator_contract_sha256"
            ),
            repo_root=None,
            expected_primary_diff_sha256=None,
        )
    )
    errors.extend(
        _validate_independent_validation_session_snapshot(
            proof.independent_validation_receipt.value,
            proof.independent_validation_session_bytes,
        )
    )

    prior_authorization_id = prior_authorization.get("authorization_id")
    prior_nonce = prior_bindings.get("campaign_nonce")
    if bindings.get("campaign_nonce") == prior_nonce:
        errors.append("authorization-v9-predecessor-campaign-nonce-reused")
    if (
        proof.authorization.raw_sha256
        != bindings.get("predecessor_authorization_file_sha256")
        or prior_authorization.get("canonical_authorization_sha256")
        != bindings.get("predecessor_authorization_canonical_sha256")
        or prior_authorization_id != bindings.get("predecessor_authorization_id")
        or prior_authorization.get("version") != AUTHORIZATION_VERSION_V8
        or prior_authorization.get("live_generation")
        != predecessor_live_generation
        or proof.manifest.raw_sha256
        != bindings.get("predecessor_manifest_file_sha256")
        or prior_manifest.get("manifest_sha256")
        != bindings.get("predecessor_manifest_canonical_sha256")
        or prior_manifest.get("version") != MANIFEST_VERSION_V5
        or prior_candidate.get("commit")
        != progress.get("predecessor_candidate_commit")
        or prior_candidate.get("tree")
        != progress.get("predecessor_candidate_tree")
    ):
        errors.append("authorization-predecessor-v8-v5-binding-invalid")

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
        errors.append("authorization-predecessor-v8-ancestor-lineage-invalid")

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
    protected_allowed_actions = (
        prior_state.get("allowed_actions")
        if isinstance(prior_state.get("allowed_actions"), list)
        else []
    )
    protected_revoked_actions = (
        prior_state.get("revoked_actions")
        if isinstance(prior_state.get("revoked_actions"), list)
        else []
    )
    if (
        proof.authorization_state.raw_sha256
        != bindings.get("predecessor_authorization_state_file_sha256")
        or prior_state.get("state_sha256")
        != bindings.get("predecessor_authorization_state_canonical_sha256")
        or validate_authorization_state(prior_state)
        or prior_state.get("authorization_id") != prior_authorization_id
        or prior_state.get("run_nonce") != prior_nonce
        or prior_state.get("state") != "containment-only"
        or required_revocations.intersection(protected_allowed_actions)
        or not required_revocations.issubset(set(protected_revoked_actions))
    ):
        errors.append("authorization-predecessor-v8-protected-state-binding-invalid")

    audit_sha256 = hashlib.sha256(proof.allocation_audit_bytes).hexdigest()
    ledger_errors = validate_live_allocation_ledger(
        prior_ledger, audit_bytes=proof.allocation_audit_bytes
    )
    if ledger_errors:
        errors.append(
            "authorization-predecessor-v8-protected-ledger-invalid:"
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
        _validate_generation9_protected_fault_ledger(
            prior_ledger, prior_failure.get("allocation_ledger")
        )
    )
    if (
        proof.allocation_ledger.raw_sha256
        != bindings.get("predecessor_allocation_ledger_file_sha256")
        or prior_ledger.get("state_sha256")
        != bindings.get("predecessor_allocation_ledger_state_sha256")
        or audit_sha256 != bindings.get("predecessor_allocation_audit_file_sha256")
        or supersession.get("prior_allocations") != 5
        or supersession.get("prior_live_generation") != predecessor_live_generation
        or supersession.get("prior_terminal_state") != "containment-only"
        or supersession.get("prior_ambiguities") != 0
        or supersession.get("reuse_resume_retry_substitution_salvage_bridge")
        is not False
        or ledger_summary.get("allocation_intent_count") != 5
        or ledger_summary.get("sequence") != 34
        or ledger_summary.get("unresolved_allocation_intent_count") != 0
        or ledger_summary.get("unresolved_turn_intent_count") != 0
    ):
        errors.append("authorization-predecessor-v8-protected-ledger-binding-invalid")

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
        errors.append(
            "authorization-predecessor-v8-protected-ledger-authority-mismatch"
        )

    failure = _strict(
        prior_failure,
        MODERN_FAILURE_EVIDENCE_FIELDS,
        "authorization-predecessor-v8-protected-failure",
        errors,
    )
    failure_bindings = (
        failure.get("campaign_bindings")
        if isinstance(failure.get("campaign_bindings"), Mapping)
        else {}
    )
    expected_containment = {
        "all_contained": True,
        "allocated_count": 5,
        "already_contained_count": 5,
        "ambiguous_count": 0,
        "archived_count": 0,
        "identified_thread_count": 5,
        "interrupted_count": 0,
        "ledger_consistent": True,
        "ledger_error_sha256": [],
        "unresolved_allocation_intent_count": 0,
        "unresolved_turn_intent_count": 0,
    }
    first_fault = (
        failure.get("first_protected_fault")
        if isinstance(failure.get("first_protected_fault"), Mapping)
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
        or failure.get("failure_class") != "LivePoolProtectedFault"
        or not str(failure.get("failure_code", "")).startswith(
            "live-pool-protected-fault:child-protected-fault"
        )
        or failure.get("containment") != expected_containment
        or first_fault.get("code") != "child-protected-fault"
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
    ):
        errors.append("authorization-predecessor-v8-protected-failure-binding-invalid")

    containment = _strict(
        prior_containment,
        QUARANTINE_CONTAINMENT_FIELDS,
        "authorization-predecessor-v8-protected-containment",
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
    reproduction = (
        root_cause.get("reproduction")
        if isinstance(root_cause.get("reproduction"), Mapping)
        else {}
    )
    scope_transition = (
        containment.get("scope_transition")
        if isinstance(containment.get("scope_transition"), Mapping)
        else {}
    )
    sessions = containment.get("session_accounting")
    expected_containment_ledger = {
        "allocated_roles": list(EXPECTED_ROLES[:5]),
        "allocation_intent_count": 5,
        "audit_file_sha256": audit_sha256,
        "head_entry_sha256": prior_ledger.get("head_entry_sha256"),
        "ledger_file_sha256": proof.allocation_ledger.raw_sha256,
        "sequence": 34,
        "state_sha256": prior_ledger.get("state_sha256"),
        "thread_bound_count": 5,
        "turn_bound_count": 5,
        "turn_intent_count": 5,
        "unresolved_allocation_intent_count": 0,
        "unresolved_turn_intent_count": 0,
        "validation_errors": [],
    }
    controller_identity = (
        ledger_bindings.get("controller_identity")
        if isinstance(ledger_bindings.get("controller_identity"), Mapping)
        else {}
    )
    expected_control = {
        "authorization_state_validation_errors": [],
        "campaign_process_alive": False,
        "controller_pid": controller_identity.get("pid"),
        "disposable_workspace_present": False,
        "evidence_canonical_hash_valid": True,
        "isolated_checkout_head": prior_candidate.get("commit"),
        "isolated_checkout_tracked_clean": True,
        "isolated_checkout_tree": prior_candidate.get("tree"),
        "operative_dispatch_authorized": False,
        "origin_main_commit": prior_candidate.get("origin_main_commit"),
        "protected_primary_diff_sha256": prior_candidate.get(
            "guarded_primary_diff_sha256"
        ),
        "release_policy_status": "canary-gated",
    }
    expected_disposition = {
        "authorization_state": "containment-only",
        "outer_full_auto_recovery_permitted": True,
        "release_gate_passed": False,
        "requires_fresh_live_generation": predecessor_live_generation + 1,
        "requires_validated_candidate_repair": True,
        "reuse_resume_retry_substitution_salvage_bridge": False,
    }
    errors.extend(
        _validate_generation9_protected_fault_sessions(
            proof.contained_session_bytes,
            sessions,
            prior_ledger,
            expected_family_sha256=bindings.get(
                "predecessor_contained_session_family_sha256"
            ),
        )
    )
    if (
        bindings.get("predecessor_contained_session_count") != 5
        or containment.get("schema")
        != "cwo-live-campaign-containment-recovery:v3"
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
        or containment.get("containment") != expected_containment
        or containment_ledger != expected_containment_ledger
        or control != expected_control
        or disposition != expected_disposition
        or root_cause.get("exception_class") != failure.get("failure_class")
        or root_cause.get("failure_class")
        != progress.get("predecessor_failure_class")
        or root_cause.get("message_sha256")
        != failure.get("failure_message_sha256")
        or root_cause.get("independent_reproduction") is not True
        or reproduction.get("canonical_parser_result")
        != "targets/child_1.txt"
        or reproduction.get("stripped_fixed_slice") != "argets/child_1.txt"
        or not _is_hash(reproduction.get("raw_record_sha256"))
        or scope_transition.get("from") != "active"
        or scope_transition.get("to") != "contained"
        or not _is_hash(scope_transition.get("scope_state_canonical_sha256"))
        or not _is_hash(scope_transition.get("scope_state_file_sha256"))
        or scope_transition.get("terminal_evidence_canonical_sha256")
        != failure.get("evidence_sha256")
    ):
        errors.append(
            "authorization-predecessor-v8-protected-containment-binding-invalid"
        )

    if (
        proof.authorization_recovery_cause_evidence.raw_sha256
        != prior_progress.get("cause_evidence_sha256")
    ):
        errors.append("authorization-predecessor-v8-cause-evidence-binding-invalid")
    if (
        proof.outer_authority.raw_sha256
        != prior_bindings.get("outer_authority_file_sha256")
        or proof.outer_authority.value.get("canonical_outer_authority_sha256")
        != prior_bindings.get("outer_authority_canonical_sha256")
        or proof.outer_authority.value.get("authority_id")
        != prior_bindings.get("outer_authority_id")
    ):
        errors.append("authorization-predecessor-v8-outer-authority-binding-invalid")

    if repo_root is not None:
        root = Path(repo_root).resolve()
        errors.extend(
            f"authorization-predecessor-v8-ancestor:{item}"
            for item in _validate_v7_quarantine_predecessor_proof(
                bindings=prior_bindings,
                progress=prior_progress,
                supersession=prior_supersession,
                predecessor_live_generation=_generation_or_invalid(
                    prior_authorization.get("predecessor_live_generation")
                ),
                proof=proof.ancestor,
                repo_root=root,
            )
        )
        try:
            prior_checkpoint = str(prior_bindings["checkpoint_commit"])
            current_checkpoint = str(bindings["checkpoint_commit"])
            if (
                _run_git(root, "rev-parse", f"{prior_checkpoint}^{{tree}}")
                != prior_bindings.get("checkpoint_tree")
                or _run_git(
                    root,
                    "rev-parse",
                    f"{prior_candidate.get('commit')}^{{tree}}",
                )
                != prior_candidate.get("tree")
                or _run_git(root, "rev-parse", f"{current_checkpoint}^{{tree}}")
                != bindings.get("checkpoint_tree")
            ):
                errors.append("authorization-predecessor-v8-anchor-tree-mismatch")
            for ancestor_commit, descendant_commit in (
                (str(prior_candidate.get("commit")), prior_checkpoint),
                (prior_checkpoint, current_checkpoint),
            ):
                if subprocess.run(
                    [
                        "git",
                        "merge-base",
                        "--is-ancestor",
                        ancestor_commit,
                        descendant_commit,
                    ],
                    cwd=root,
                    capture_output=True,
                ).returncode != 0:
                    errors.append(
                        "authorization-predecessor-v8-anchor-lineage-invalid"
                    )
            recorded_origin = bindings.get("origin_main_commit")
            if (
                prior_bindings.get("origin_main_commit") != recorded_origin
                or _run_git(root, "rev-parse", "origin/main") != recorded_origin
            ):
                errors.append("authorization-predecessor-v8-anchor-origin-mismatch")
            observed_v3_contract = validator_contract_sha256_v3(
                root, prior_bindings.get("checkpoint_tree")
            )
            if prior_bindings.get("validator_contract_sha256") != observed_v3_contract:
                errors.append(
                    "authorization-predecessor-v8-validator-contract-mismatch"
                )
        except (KeyError, subprocess.CalledProcessError, ValueError):
            errors.append("authorization-predecessor-v8-anchor-invalid")
    return sorted(set(errors))


def _validate_v9_preallocation_fault_predecessor_proof(
    *,
    bindings: Mapping[str, Any],
    progress: Mapping[str, Any],
    supersession: Mapping[str, Any],
    predecessor_live_generation: int,
    proof: Version9PreallocationFaultPredecessorProofInputs,
    repo_root: Path | None,
) -> list[str]:
    """Validate the exact terminal zero-allocation v9/v6 predecessor leaf."""

    errors: list[str] = []
    if not isinstance(proof.ancestor, Version8ProtectedFaultPredecessorProofInputs):
        return ["authorization-predecessor-v9-ancestor-proof-type-invalid"]
    snapshots = {
        "authorization-predecessor-v9-authorization": proof.authorization,
        "authorization-predecessor-v6-manifest": proof.manifest,
        "authorization-predecessor-v9-state": proof.authorization_state,
        "authorization-predecessor-v9-failure": proof.failure_evidence,
        "authorization-predecessor-v9-containment": proof.containment,
        "authorization-predecessor-v9-global-claim": proof.global_claim,
        "authorization-predecessor-v9-authorization-marker": (
            proof.authorization_marker
        ),
        "authorization-predecessor-v9-nonce-marker": proof.nonce_marker,
        "authorization-predecessor-v9-scope-state": proof.scope_state,
        "authorization-predecessor-v9-preflight": proof.preflight,
        "authorization-predecessor-v9-pre-mutation-receipt": (
            proof.pre_mutation_receipt
        ),
        "authorization-predecessor-v9-pre-live-receipt": proof.pre_live_receipt,
        "authorization-predecessor-v9-cause": (
            proof.authorization_recovery_cause_evidence
        ),
        "authorization-predecessor-v9-outer-authority": proof.outer_authority,
        "authorization-predecessor-v9-independent-validation": (
            proof.independent_validation_receipt
        ),
    }
    for label, snapshot in snapshots.items():
        errors.extend(_validate_json_snapshot(snapshot, label))
    if (
        not isinstance(proof.authorization_recovery_cause_source_analysis, bytes)
        or not isinstance(proof.independent_validation_session_bytes, bytes)
    ):
        errors.append("authorization-predecessor-v9-byte-snapshot-invalid")
        return sorted(set(errors))

    prior_authorization = dict(proof.authorization.value)
    prior_manifest = dict(proof.manifest.value)
    prior_state = dict(proof.authorization_state.value)
    failure = dict(proof.failure_evidence.value)
    containment = dict(proof.containment.value)
    claim = dict(proof.global_claim.value)
    scope = dict(proof.scope_state.value)
    preflight = dict(proof.preflight.value)
    pre_mutation = dict(proof.pre_mutation_receipt.value)
    pre_live = dict(proof.pre_live_receipt.value)
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
    prior_supersession = (
        prior_authorization.get("supersession")
        if isinstance(prior_authorization.get("supersession"), Mapping)
        else {}
    )
    prior_candidate = (
        prior_manifest.get("candidate")
        if isinstance(prior_manifest.get("candidate"), Mapping)
        else {}
    )
    prior_outputs = (
        prior_manifest.get("outputs")
        if isinstance(prior_manifest.get("outputs"), Mapping)
        else {}
    )
    prior_work_units = (
        prior_manifest.get("work_units")
        if isinstance(prior_manifest.get("work_units"), Mapping)
        else {}
    )
    prior_release = (
        prior_manifest.get("release")
        if isinstance(prior_manifest.get("release"), Mapping)
        else {}
    )
    predecessor_launch_claim_sha256 = bindings.get(
        "predecessor_launch_claim_sha256"
    )
    errors.extend(
        f"authorization-predecessor-v9-contract:{item}"
        for item in _validate_full_auto_authorization_v9(
            prior_authorization,
            predecessor_proof=proof.ancestor,
            recovery_cause_evidence=proof.authorization_recovery_cause_evidence,
            recovery_cause_source_analysis=(
                proof.authorization_recovery_cause_source_analysis
            ),
            expected_validator_contract_sha256=prior_bindings.get(
                "validator_contract_sha256"
            ),
            repo_root=None,
        )
    )
    errors.extend(
        f"authorization-predecessor-v6-contract:{item}"
        for item in _validate_campaign_manifest_v6(
            prior_manifest,
            authorization=prior_authorization,
            authorization_raw_sha256=proof.authorization.raw_sha256,
            outer_authority=proof.outer_authority.value,
            outer_authority_raw_sha256=proof.outer_authority.raw_sha256,
            predecessor_proof=proof.ancestor,
            recovery_cause_evidence=proof.authorization_recovery_cause_evidence,
            recovery_cause_source_analysis=(
                proof.authorization_recovery_cause_source_analysis
            ),
            independent_validation_receipt=(
                proof.independent_validation_receipt.value
            ),
            independent_validation_receipt_raw_sha256=(
                proof.independent_validation_receipt.raw_sha256
            ),
            expected_validator_contract_sha256=prior_bindings.get(
                "validator_contract_sha256"
            ),
            repo_root=None,
            expected_primary_diff_sha256=None,
        )
    )
    errors.extend(
        _validate_independent_validation_session_snapshot(
            proof.independent_validation_receipt.value,
            proof.independent_validation_session_bytes,
        )
    )

    prior_id = prior_authorization.get("authorization_id")
    prior_nonce = prior_bindings.get("campaign_nonce")
    prior_raw = proof.authorization.raw_sha256
    if (
        bindings.get("campaign_nonce") == prior_nonce
        or prior_authorization.get("version") != AUTHORIZATION_VERSION_V9
        or prior_manifest.get("version") != MANIFEST_VERSION_V6
        or prior_authorization.get("live_generation")
        != predecessor_live_generation
        or prior_id != bindings.get("predecessor_authorization_id")
        or prior_raw != bindings.get("predecessor_authorization_file_sha256")
        or prior_authorization.get("canonical_authorization_sha256")
        != bindings.get("predecessor_authorization_canonical_sha256")
        or proof.manifest.raw_sha256
        != bindings.get("predecessor_manifest_file_sha256")
        or prior_manifest.get("manifest_sha256")
        != bindings.get("predecessor_manifest_canonical_sha256")
        or prior_candidate.get("commit")
        != progress.get("predecessor_candidate_commit")
        or prior_candidate.get("tree") != progress.get("predecessor_candidate_tree")
    ):
        errors.append("authorization-predecessor-v9-v6-binding-invalid")

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
    allowed_actions = prior_state.get("allowed_actions", [])
    revoked_actions = prior_state.get("revoked_actions", [])
    allowed_action_set = (
        set(allowed_actions)
        if isinstance(allowed_actions, list)
        and all(isinstance(item, str) for item in allowed_actions)
        else set()
    )
    revoked_action_set = (
        set(revoked_actions)
        if isinstance(revoked_actions, list)
        and all(isinstance(item, str) for item in revoked_actions)
        else set()
    )
    if (
        proof.authorization_state.raw_sha256
        != bindings.get("predecessor_authorization_state_file_sha256")
        or prior_state.get("state_sha256")
        != bindings.get("predecessor_authorization_state_canonical_sha256")
        or validate_authorization_state(prior_state)
        or prior_state.get("authorization_id") != prior_id
        or prior_state.get("run_nonce") != prior_nonce
        or prior_state.get("launch_claim_sha256")
        != predecessor_launch_claim_sha256
        or prior_state.get("state") != "containment-only"
        or not isinstance(allowed_actions, list)
        or not all(isinstance(item, str) for item in allowed_actions)
        or not isinstance(revoked_actions, list)
        or not all(isinstance(item, str) for item in revoked_actions)
        or required_revocations.intersection(allowed_action_set)
        or not required_revocations.issubset(revoked_action_set)
    ):
        errors.append("authorization-predecessor-v9-state-binding-invalid")

    expected_containment = {
        "all_contained": True,
        "allocated_count": 0,
        "already_contained_count": 0,
        "ambiguous_count": 0,
        "archived_count": 0,
        "identified_thread_count": 0,
        "interrupted_count": 0,
        "ledger_consistent": True,
        "ledger_error_sha256": [],
        "unresolved_allocation_intent_count": 0,
        "unresolved_turn_intent_count": 0,
    }
    failure_fields = _strict(
        failure,
        MODERN_FAILURE_EVIDENCE_FIELDS,
        "authorization-predecessor-v9-failure",
        errors,
    )
    failure_bindings = (
        failure_fields.get("campaign_bindings")
        if isinstance(failure_fields.get("campaign_bindings"), Mapping)
        else {}
    )
    if (
        proof.failure_evidence.raw_sha256
        != bindings.get("predecessor_failure_evidence_file_sha256")
        or failure.get("evidence_sha256")
        != bindings.get("predecessor_failure_evidence_canonical_sha256")
        or failure.get("evidence_sha256")
        != _canonical_artifact_hash(failure, "evidence_sha256")
        or failure.get("failure_class") != "AppServerError"
        or failure.get("failure_code")
        != "pre-mutation-steering-binding-invalid"
        or not _is_hash(failure.get("failure_message_sha256"))
        or failure.get("authorization_state_sha256")
        != prior_state.get("state_sha256")
        or failure.get("bead_id") != prior_work_units.get("epic_id")
        or failure.get("work_unit_id")
        != prior_work_units.get("live_work_unit_id")
        or failure.get("control_turn_id")
        != prior_manifest.get("control_turn_id")
        or failure.get("exact_model") != "gpt-5.3-codex-spark"
        or failure.get("glm_5_2_used") is not False
        or failure.get("model_synthesis_used") is not False
        or failure.get("validation_outcome") != "rejected"
        or failure.get("release_gate_passed") is not False
        or failure.get("no_resume_or_salvage") is not True
        or failure.get("containment") != expected_containment
        or failure.get("steering_consumptions") != {}
        or failure.get("allocation_ledger") is not None
        or failure.get("first_protected_fault") is not None
        or failure_bindings.get("authorization_raw_sha256") != prior_raw
        or failure_bindings.get("manifest_file_sha256")
        != proof.manifest.raw_sha256
        or failure_bindings.get("candidate_commit") != prior_candidate.get("commit")
        or failure_bindings.get("candidate_tree") != prior_candidate.get("tree")
        or failure_bindings.get("manifest_sha256")
        != prior_manifest.get("manifest_sha256")
        or failure_bindings.get("origin_main_commit")
        != prior_bindings.get("origin_main_commit")
        or failure_bindings.get("guarded_primary_diff_sha256")
        != prior_bindings.get("guarded_primary_diff_sha256")
        or failure_bindings.get("outer_authority_file_sha256")
        != proof.outer_authority.raw_sha256
        or failure_bindings.get("release_patch_sha256")
        != prior_release.get("patch_file_sha256")
        or failure_bindings.get("validator_contract_sha256")
        != prior_bindings.get("validator_contract_sha256")
        or failure_bindings.get("launch_claim_sha256")
        != predecessor_launch_claim_sha256
    ):
        errors.append("authorization-predecessor-v9-failure-binding-invalid")

    containment_fields = {
        "schema",
        "recorded_at",
        "bead_id",
        "failed_authorization",
        "failed_manifest",
        "failed_evidence",
        "root_cause",
        "containment",
        "zero_activity",
        "global_claim",
        "scope_transition",
        "predecessor_proof",
        "control_plane_recheck",
        "disposition",
        "canonical_recovery_sha256",
    }
    containment_value = _strict(
        containment,
        containment_fields,
        "authorization-predecessor-v9-containment",
        errors,
    )
    containment_disposition = (
        containment_value.get("disposition")
        if isinstance(containment_value.get("disposition"), Mapping)
        else {}
    )
    zero_activity = (
        containment_value.get("zero_activity")
        if isinstance(containment_value.get("zero_activity"), Mapping)
        else {}
    )
    failed_authorization = _strict(
        containment_value.get("failed_authorization"),
        {
            "authorization_id",
            "campaign_nonce",
            "canonical_sha256",
            "file_sha256",
            "live_generation",
            "run_generation",
        },
        "authorization-predecessor-v9-containment-failed-authorization",
        errors,
    )
    failed_manifest = _strict(
        containment_value.get("failed_manifest"),
        {"canonical_sha256", "file_sha256", "manifest_id"},
        "authorization-predecessor-v9-containment-failed-manifest",
        errors,
    )
    failed_evidence = _strict(
        containment_value.get("failed_evidence"),
        {
            "authorization_state_canonical_sha256",
            "authorization_state_file_sha256",
            "canonical_sha256",
            "file_sha256",
        },
        "authorization-predecessor-v9-containment-failed-evidence",
        errors,
    )
    root_cause = _strict(
        containment_value.get("root_cause"),
        {
            "failure_class",
            "failure_code",
            "independent_reproduction",
            "pre_live_binding_correct",
            "pre_mutation_bound_authority_file_sha256",
            "pre_mutation_bound_authority_id",
            "required_inner_authorization_file_sha256",
            "required_inner_authorization_id",
            "source_analysis_sha256",
        },
        "authorization-predecessor-v9-containment-root-cause",
        errors,
    )
    containment_global_claim = _strict(
        containment_value.get("global_claim"),
        {
            "authorization_marker",
            "claim_canonical_sha256",
            "claim_file_sha256",
            "nonce_marker",
            "tombstones_permanent",
        },
        "authorization-predecessor-v9-containment-global-claim",
        errors,
    )
    containment_authorization_marker = _strict(
        containment_global_claim.get("authorization_marker"),
        {"canonical_sha256", "file_sha256"},
        "authorization-predecessor-v9-containment-authorization-marker",
        errors,
    )
    containment_nonce_marker = _strict(
        containment_global_claim.get("nonce_marker"),
        {"canonical_sha256", "file_sha256"},
        "authorization-predecessor-v9-containment-nonce-marker",
        errors,
    )
    scope_transition = _strict(
        containment_value.get("scope_transition"),
        {
            "scope_state_canonical_sha256",
            "scope_state_file_sha256",
            "terminal_evidence_canonical_sha256",
            "to",
        },
        "authorization-predecessor-v9-containment-scope-transition",
        errors,
    )
    containment_predecessor = _strict(
        containment_value.get("predecessor_proof"),
        {
            "generation9_contained_session_family_sha256",
            "generation9_containment_file_sha256",
            "generation9_failure_evidence_file_sha256",
            "generation9_lineage_sha256",
            "launch_claim_sha256",
        },
        "authorization-predecessor-v9-containment-predecessor-proof",
        errors,
    )
    control_plane_recheck = _strict(
        containment_value.get("control_plane_recheck"),
        {
            "isolated_checkout_head",
            "isolated_checkout_tracked_clean",
            "isolated_checkout_tree",
            "operative_dispatch_authorized",
            "protected_primary_diff_sha256",
            "release_gate_passed",
        },
        "authorization-predecessor-v9-containment-control-plane-recheck",
        errors,
    )
    if (
        proof.containment.raw_sha256
        != bindings.get("predecessor_containment_file_sha256")
        or containment.get("canonical_recovery_sha256")
        != bindings.get("predecessor_containment_canonical_sha256")
        or containment.get("canonical_recovery_sha256")
        != _canonical_artifact_hash(containment, "canonical_recovery_sha256")
        or containment.get("schema")
        != "cwo-live-campaign-containment-recovery:v4"
        or _parse_utc(containment.get("recorded_at")) is None
        or containment.get("bead_id") != failure.get("work_unit_id")
        or containment.get("containment") != expected_containment
        or zero_activity
        != {
            "allocation_intents": 0,
            "allocation_ledger_present": False,
            "sessions": 0,
            "steering_consumptions": 0,
            "steering_registry_present": False,
            "threads": 0,
            "turns": 0,
            "workspace_mutations": 0,
        }
        or containment_disposition.get("authorization_state")
        != "containment-only"
        or set(containment_disposition)
        != {
            "authorization_state",
            "release_gate_passed",
            "requires_fresh_live_generation",
            "requires_shared_preclaim_binding_repair",
            "reuse_resume_retry_substitution_salvage_bridge",
        }
        or containment_disposition.get("requires_fresh_live_generation")
        != predecessor_live_generation + 1
        or containment_disposition.get(
            "reuse_resume_retry_substitution_salvage_bridge"
        )
        is not False
        or containment_disposition.get("release_gate_passed") is not False
        or containment_disposition.get("requires_shared_preclaim_binding_repair")
        is not True
        or failed_authorization
        != {
            "authorization_id": prior_id,
            "campaign_nonce": prior_nonce,
            "canonical_sha256": prior_authorization.get(
                "canonical_authorization_sha256"
            ),
            "file_sha256": prior_raw,
            "live_generation": predecessor_live_generation,
            "run_generation": prior_authorization.get("run_generation"),
        }
        or failed_manifest
        != {
            "canonical_sha256": prior_manifest.get("manifest_sha256"),
            "file_sha256": proof.manifest.raw_sha256,
            "manifest_id": prior_manifest.get("manifest_id"),
        }
        or failed_evidence
        != {
            "authorization_state_canonical_sha256": prior_state.get(
                "state_sha256"
            ),
            "authorization_state_file_sha256": (
                proof.authorization_state.raw_sha256
            ),
            "canonical_sha256": failure.get("evidence_sha256"),
            "file_sha256": proof.failure_evidence.raw_sha256,
        }
        or root_cause.get("failure_class")
        != "preflight-live-steering-authority-binding-gap"
        or root_cause.get("failure_code") != failure.get("failure_code")
        or root_cause.get("independent_reproduction") is not True
        or root_cause.get("pre_live_binding_correct") is not True
        or root_cause.get("pre_mutation_bound_authority_id")
        != pre_mutation.get("authorization_id")
        or root_cause.get("pre_mutation_bound_authority_file_sha256")
        != pre_mutation.get("authorization_sha256")
        or root_cause.get("required_inner_authorization_id") != prior_id
        or root_cause.get("required_inner_authorization_file_sha256")
        != prior_raw
        or not _is_hash(root_cause.get("source_analysis_sha256"))
        or containment_global_claim.get("claim_canonical_sha256")
        != claim.get("canonical_claim_sha256")
        or containment_global_claim.get("claim_file_sha256")
        != proof.global_claim.raw_sha256
        or containment_global_claim.get("tombstones_permanent") is not True
        or containment_authorization_marker
        != {
            "canonical_sha256": proof.authorization_marker.value.get(
                "canonical_marker_sha256"
            ),
            "file_sha256": proof.authorization_marker.raw_sha256,
        }
        or containment_nonce_marker
        != {
            "canonical_sha256": proof.nonce_marker.value.get(
                "canonical_marker_sha256"
            ),
            "file_sha256": proof.nonce_marker.raw_sha256,
        }
        or scope_transition
        != {
            "scope_state_canonical_sha256": scope.get(
                "canonical_state_sha256"
            ),
            "scope_state_file_sha256": proof.scope_state.raw_sha256,
            "terminal_evidence_canonical_sha256": failure.get(
                "evidence_sha256"
            ),
            "to": "contained",
        }
        or containment_predecessor
        != {
            "generation9_contained_session_family_sha256": prior_bindings.get(
                "predecessor_contained_session_family_sha256"
            ),
            "generation9_containment_file_sha256": prior_bindings.get(
                "predecessor_containment_file_sha256"
            ),
            "generation9_failure_evidence_file_sha256": prior_bindings.get(
                "predecessor_failure_evidence_file_sha256"
            ),
            "generation9_lineage_sha256": prior_bindings.get(
                "predecessor_ancestor_lineage_sha256"
            ),
            "launch_claim_sha256": predecessor_launch_claim_sha256,
        }
        or control_plane_recheck
        != {
            "isolated_checkout_head": prior_candidate.get("commit"),
            "isolated_checkout_tracked_clean": True,
            "isolated_checkout_tree": prior_candidate.get("tree"),
            "operative_dispatch_authorized": False,
            "protected_primary_diff_sha256": prior_bindings.get(
                "guarded_primary_diff_sha256"
            ),
            "release_gate_passed": False,
        }
    ):
        errors.append("authorization-predecessor-v9-containment-binding-invalid")

    claim_fields = {
        "claim_type",
        "version",
        "identity",
        "identity_sha256",
        "launch_claim_sha256",
        "outer_authority_id",
        "candidate_commit",
        "candidate_tree",
        "output_paths",
        "claimed_at",
        "canonical_claim_sha256",
    }
    claim_value = _strict(
        claim, claim_fields, "authorization-predecessor-v9-global-claim", errors
    )
    claim_unsigned = dict(claim_value)
    claim_canonical = claim_unsigned.pop("canonical_claim_sha256", None)
    expected_identity = {
        "authorization_id": prior_id,
        "run_generation": prior_authorization.get("run_generation"),
        "live_generation": predecessor_live_generation,
        "campaign_nonce": prior_nonce,
    }
    claim_output_paths = _strict(
        claim_value.get("output_paths"),
        {"allocation_ledger", "authorization_state", "evidence", "steering_registry"},
        "authorization-predecessor-v9-global-claim-output-paths",
        errors,
    )
    expected_output_basenames = {
        "allocation_ledger": prior_outputs.get("allocation_ledger_basename"),
        "authorization_state": prior_outputs.get(
            "authorization_state_basename"
        ),
        "evidence": prior_outputs.get("evidence_basename"),
        "steering_registry": prior_outputs.get("steering_registry_basename"),
    }
    claim_output_paths_valid = all(
        isinstance(claim_output_paths.get(label), str)
        and Path(str(claim_output_paths.get(label))).is_absolute()
        and Path(str(claim_output_paths.get(label))).name == basename
        for label, basename in expected_output_basenames.items()
    )
    if (
        proof.global_claim.raw_sha256
        != bindings.get("predecessor_global_claim_file_sha256")
        or claim_canonical
        != bindings.get("predecessor_global_claim_canonical_sha256")
        or claim_canonical
        != _domain_sha256(
            claim_unsigned, domain="native-live-global-claim-artifact"
        )
        or claim.get("claim_type")
        != "cwo-native-live-campaign-global-claim"
        or claim.get("version") != 1
        or _parse_utc(claim.get("claimed_at")) is None
        or claim.get("identity") != expected_identity
        or claim.get("identity_sha256")
        != _domain_sha256(
            expected_identity, domain="native-live-global-claim"
        )
        or claim.get("launch_claim_sha256")
        != bindings.get("predecessor_launch_claim_sha256")
        or claim.get("outer_authority_id")
        != prior_bindings.get("outer_authority_id")
        or claim.get("candidate_commit") != prior_candidate.get("commit")
        or claim.get("candidate_tree") != prior_candidate.get("tree")
        or not claim_output_paths_valid
    ):
        errors.append("authorization-predecessor-v9-global-claim-binding-invalid")

    marker_fields = {
        "marker_type",
        "version",
        "kind",
        "identifier",
        "identifier_sha256",
        "claim_canonical_sha256",
        "created_at",
        "canonical_marker_sha256",
    }
    for label, marker_snapshot, kind, identifier in (
        (
            "authorization",
            proof.authorization_marker,
            "authorization",
            prior_id,
        ),
        ("nonce", proof.nonce_marker, "nonce", prior_nonce),
    ):
        marker = _strict(
            marker_snapshot.value,
            marker_fields,
            f"authorization-predecessor-v9-{label}-marker",
            errors,
        )
        marker_unsigned = dict(marker)
        marker_canonical = marker_unsigned.pop("canonical_marker_sha256", None)
        if (
            marker_snapshot.raw_sha256
            != bindings.get(f"predecessor_{label}_marker_file_sha256")
            or marker_canonical
            != bindings.get(f"predecessor_{label}_marker_canonical_sha256")
            or marker_canonical != canonical_sha256(marker_unsigned)
            or marker.get("marker_type")
            != "cwo-native-live-global-claim-identifier"
            or marker.get("version") != 1
            or _parse_utc(marker.get("created_at")) is None
            or marker.get("kind") != kind
            or marker.get("identifier") != identifier
            or marker.get("identifier_sha256")
            != _domain_sha256(
                {"kind": kind, "identifier": identifier},
                domain="native-live-global-claim-identifier",
            )
            or marker.get("claim_canonical_sha256") != claim_canonical
        ):
            errors.append(
                f"authorization-predecessor-v9-{label}-marker-binding-invalid"
            )

    scope_fields = {
        "state_type",
        "version",
        "scope_key",
        "phase",
        "outer_authority_id",
        "authorization_id",
        "campaign_nonce",
        "launch_claim_sha256",
        "candidate_commit",
        "candidate_tree",
        "previous_state_sha256",
        "reserved_at",
        "updated_at",
        "terminal_evidence_sha256",
        "canonical_state_sha256",
    }
    scope_value = _strict(
        scope, scope_fields, "authorization-predecessor-v9-scope-state", errors
    )
    try:
        expected_scope_key = active_outer_authority_scope_key(
            prior_work_units.get("epic_id"),
            prior_work_units.get("parent_work_unit_id"),
        )
    except ValueError:
        expected_scope_key = None
    if (
        proof.scope_state.raw_sha256
        != bindings.get("predecessor_scope_state_file_sha256")
        or scope.get("canonical_state_sha256")
        != bindings.get("predecessor_scope_state_canonical_sha256")
        or scope.get("canonical_state_sha256")
        != _canonical_artifact_hash(scope, "canonical_state_sha256")
        or scope.get("state_type")
        != "cwo-native-live-scope-campaign-state"
        or scope.get("version") != 1
        or scope.get("scope_key") != expected_scope_key
        or scope.get("phase") != "contained"
        or scope.get("outer_authority_id")
        != prior_bindings.get("outer_authority_id")
        or scope.get("authorization_id") != prior_id
        or scope.get("campaign_nonce") != prior_nonce
        or scope.get("launch_claim_sha256") != claim.get("launch_claim_sha256")
        or scope.get("terminal_evidence_sha256") != failure.get("evidence_sha256")
        or scope.get("candidate_commit") != prior_candidate.get("commit")
        or scope.get("candidate_tree") != prior_candidate.get("tree")
        or not _is_hash(scope.get("previous_state_sha256"))
        or _parse_utc(scope.get("reserved_at")) is None
        or _parse_utc(scope.get("updated_at")) is None
    ):
        errors.append("authorization-predecessor-v9-scope-state-binding-invalid")

    preflight_fields = {
        "active_outer_registry_sha256",
        "allocation_intents",
        "authorization_and_protected_fault_proof_valid",
        "authorization_id",
        "bound_manifest_validation_sha256",
        "campaign_artifacts_created",
        "campaign_claim_created",
        "campaign_nonce",
        "candidate_commit",
        "candidate_tree",
        "canonical_preflight_sha256",
        "current_authorization_marker_absent",
        "current_nonce_marker_absent",
        "current_pair_claim_absent",
        "declared_outputs_absent",
        "exact_spark_available",
        "glm_5_2_used",
        "guarded_primary_diff_sha256",
        "input_count",
        "input_inodes_unique",
        "input_paths_unique",
        "input_source_identities_captured",
        "launch_claim_sha256",
        "live_campaign_authorized",
        "manifest_and_launch_bindings_valid",
        "model_discovery",
        "model_synthesis_used",
        "predecessor_scope_phase",
        "recorded_at",
        "release_authorized",
        "schema",
        "sessions_created",
        "source_snapshots_rechecked",
        "steering_receipts_accepting",
        "thread_start_requests",
        "trusted_session_snapshots_rechecked",
    }
    preflight_value = _strict(
        preflight,
        preflight_fields,
        "authorization-predecessor-v9-preflight",
        errors,
    )
    preflight_unsigned = dict(preflight_value)
    preflight_canonical = preflight_unsigned.pop("canonical_preflight_sha256", None)
    model_discovery = _strict(
        preflight_value.get("model_discovery"),
        {"display_name", "id", "latency_ms", "model"},
        "authorization-predecessor-v9-preflight-model-discovery",
        errors,
    )
    if (
        proof.preflight.raw_sha256
        != bindings.get("predecessor_preflight_file_sha256")
        or preflight_canonical
        != bindings.get("predecessor_preflight_canonical_sha256")
        or preflight_canonical != canonical_sha256(preflight_unsigned)
        or preflight.get("schema")
        != "cwo-generation10-live-zero-allocation-preflight:v1"
        or preflight.get("authorization_id") != prior_id
        or preflight.get("campaign_nonce") != prior_nonce
        or preflight.get("candidate_commit") != prior_candidate.get("commit")
        or preflight.get("candidate_tree") != prior_candidate.get("tree")
        or _parse_utc(preflight.get("recorded_at")) is None
        or preflight.get("guarded_primary_diff_sha256")
        != prior_bindings.get("guarded_primary_diff_sha256")
        or preflight.get("launch_claim_sha256")
        != predecessor_launch_claim_sha256
        or not _is_hash(preflight.get("active_outer_registry_sha256"))
        or not _is_hash(preflight.get("bound_manifest_validation_sha256"))
        or preflight.get("input_count") != 81
        or preflight.get("input_source_identities_captured") != 81
        or preflight.get("predecessor_scope_phase") != "contained"
        or preflight.get("allocation_intents") != 0
        or preflight.get("thread_start_requests") != 0
        or preflight.get("sessions_created") != 0
        or preflight.get("campaign_claim_created") is not False
        or preflight.get("campaign_artifacts_created") is not False
        or preflight.get("release_authorized") is not False
        or preflight.get("glm_5_2_used") is not False
        or preflight.get("model_synthesis_used") is not False
        or any(
            preflight.get(field) is not True
            for field in (
                "authorization_and_protected_fault_proof_valid",
                "current_authorization_marker_absent",
                "current_nonce_marker_absent",
                "current_pair_claim_absent",
                "declared_outputs_absent",
                "exact_spark_available",
                "input_inodes_unique",
                "input_paths_unique",
                "live_campaign_authorized",
                "manifest_and_launch_bindings_valid",
                "source_snapshots_rechecked",
                "steering_receipts_accepting",
                "trusted_session_snapshots_rechecked",
            )
        )
        or model_discovery.get("id") != "gpt-5.3-codex-spark"
        or model_discovery.get("model") != "gpt-5.3-codex-spark"
        or isinstance(model_discovery.get("latency_ms"), bool)
        or not isinstance(model_discovery.get("latency_ms"), (int, float))
        or model_discovery.get("latency_ms", -1) < 0
    ):
        errors.append("authorization-predecessor-v9-preflight-binding-invalid")

    for label, receipt_snapshot, gate in (
        ("pre_mutation", proof.pre_mutation_receipt, "pre-mutation"),
        ("pre_live", proof.pre_live_receipt, "pre-live"),
    ):
        receipt = receipt_snapshot.value
        if (
            validate_steering_receipt(receipt, require_accepting=True)
            or receipt_snapshot.raw_sha256
            != bindings.get(f"predecessor_{label}_receipt_file_sha256")
            or receipt.get("canonical_receipt_sha256")
            != bindings.get(f"predecessor_{label}_receipt_canonical_sha256")
            or receipt.get("gate") != gate
        ):
            errors.append(
                f"authorization-predecessor-v9-{label.replace('_', '-')}-receipt-binding-invalid"
            )
    if (
        pre_mutation.get("authorization_id")
        != proof.outer_authority.value.get("authority_id")
        or pre_mutation.get("authorization_sha256")
        != proof.outer_authority.raw_sha256
        or pre_mutation.get("authorization_id") == prior_id
        or pre_mutation.get("authorization_sha256") == prior_raw
        or pre_live.get("authorization_id") != prior_id
        or pre_live.get("authorization_sha256") != prior_raw
    ):
        errors.append("authorization-predecessor-v9-steering-root-cause-invalid")

    if (
        supersession.get("prior_authorization_id") != prior_id
        or supersession.get("prior_terminal_state") != "containment-only"
        or supersession.get("prior_live_generation")
        != predecessor_live_generation
        or supersession.get("prior_allocations") != 0
        or supersession.get("prior_ambiguities") != 0
        or supersession.get("reuse_resume_retry_substitution_salvage_bridge")
        is not False
    ):
        errors.append("authorization-predecessor-v9-supersession-invalid")
    if (
        proof.authorization_recovery_cause_evidence.raw_sha256
        != prior_progress.get("cause_evidence_sha256")
        or proof.outer_authority.raw_sha256
        != prior_bindings.get("outer_authority_file_sha256")
        or proof.outer_authority.value.get("canonical_outer_authority_sha256")
        != prior_bindings.get("outer_authority_canonical_sha256")
        or proof.outer_authority.value.get("authority_id")
        != prior_bindings.get("outer_authority_id")
    ):
        errors.append("authorization-predecessor-v9-authority-cause-binding-invalid")

    prior_lineage = prior_progress.get("predecessor_lineage_sha256")
    if (
        not _is_hash(prior_lineage)
        or prior_lineage != bindings.get("predecessor_ancestor_lineage_sha256")
    ):
        errors.append("authorization-predecessor-v9-ancestor-lineage-invalid")

    if repo_root is not None:
        root = Path(repo_root).resolve()
        errors.extend(
            f"authorization-predecessor-v9-ancestor:{item}"
            for item in _validate_v8_protected_fault_predecessor_proof(
                bindings=prior_bindings,
                progress=prior_progress,
                supersession=prior_supersession,
                predecessor_live_generation=_generation_or_invalid(
                    prior_authorization.get("predecessor_live_generation")
                ),
                proof=proof.ancestor,
                repo_root=root,
            )
        )
        try:
            prior_checkpoint = str(prior_bindings["checkpoint_commit"])
            current_checkpoint = str(bindings["checkpoint_commit"])
            if (
                _run_git(root, "rev-parse", f"{prior_checkpoint}^{{tree}}")
                != prior_bindings.get("checkpoint_tree")
                or _run_git(root, "rev-parse", f"{prior_candidate.get('commit')}^{{tree}}")
                != prior_candidate.get("tree")
                or _run_git(root, "rev-parse", f"{current_checkpoint}^{{tree}}")
                != bindings.get("checkpoint_tree")
            ):
                errors.append("authorization-predecessor-v9-anchor-tree-mismatch")
            for ancestor_commit, descendant_commit in (
                (str(prior_candidate.get("commit")), prior_checkpoint),
                (prior_checkpoint, current_checkpoint),
            ):
                if subprocess.run(
                    ["git", "merge-base", "--is-ancestor", ancestor_commit, descendant_commit],
                    cwd=root,
                    capture_output=True,
                ).returncode != 0:
                    errors.append(
                        "authorization-predecessor-v9-anchor-lineage-invalid"
                    )
            if (
                prior_bindings.get("origin_main_commit")
                != bindings.get("origin_main_commit")
                or _run_git(root, "rev-parse", "origin/main")
                != bindings.get("origin_main_commit")
                or prior_bindings.get("validator_contract_sha256")
                != validator_contract_sha256_v4(
                    root, prior_bindings.get("checkpoint_tree")
                )
            ):
                errors.append("authorization-predecessor-v9-anchor-binding-invalid")
        except (KeyError, subprocess.CalledProcessError, ValueError):
            errors.append("authorization-predecessor-v9-anchor-invalid")
    return sorted(set(errors))


def _generation11_fact_sha256(value: Mapping[str, Any], *, leaf: str) -> str:
    return _domain_sha256(value, domain=f"native-live-generation11-{leaf}")


def _validate_generation11_steering_adjudication(
    snapshot: JsonArtifactSnapshot,
    *,
    gate: str,
    authorization: Mapping[str, Any],
    manifest: Mapping[str, Any],
    receipt: JsonArtifactSnapshot,
    source_hashes: Mapping[str, Any] | None = None,
) -> list[str]:
    """Bind a consumed Gen11 steering receipt to its main-thread decision."""

    errors = _validate_json_snapshot(
        snapshot, f"authorization-predecessor-v10-{gate}-adjudication"
    )
    value = _strict(
        snapshot.value,
        GENERATION11_STEERING_ADJUDICATION_FIELDS,
        f"authorization-predecessor-v10-{gate}-adjudication",
        errors,
    )
    candidate = (
        manifest.get("candidate")
        if isinstance(manifest.get("candidate"), Mapping)
        else {}
    )
    receipt_opinion = (
        receipt.value.get("opinion")
        if isinstance(receipt.value.get("opinion"), Mapping)
        else {}
    )
    authorization_scope = (
        authorization.get("scope")
        if isinstance(authorization.get("scope"), Mapping)
        else {}
    )
    receipt_boundary = (
        receipt.value.get("boundary")
        if isinstance(receipt.value.get("boundary"), Mapping)
        else {}
    )
    receipt_terminal = (
        receipt_boundary.get("terminal")
        if isinstance(receipt_boundary.get("terminal"), Mapping)
        else {}
    )
    receipt_conditions = (
        receipt_opinion.get("conditions")
        if isinstance(receipt_opinion.get("conditions"), list)
        else []
    )
    expected_condition_adjudication = [
        {
            "condition": condition,
            "status": "satisfied-by-frozen-generation11-launch-contract",
        }
        for condition in receipt_conditions
        if isinstance(condition, str)
    ]
    expected_source_hashes = source_hashes if isinstance(source_hashes, Mapping) else {}
    unsigned = dict(value)
    unsigned.pop("canonical_adjudication_sha256", None)
    expected_live_authorized = gate == "pre-live"
    if (
        value.get("adjudication_type")
        != "cwo-main-architect-inner-steering-adjudication:v1"
        or _parse_utc(value.get("recorded_at")) is None
        or value.get("bead_id") != receipt.value.get("bead_id")
        or value.get("control_turn_id") != receipt.value.get("control_turn_id")
        or value.get("bead_id") not in authorization_scope.get(
            "ordered_work_units", []
        )
        or value.get("gate") != gate
        or value.get("authorization_id") != authorization.get("authorization_id")
        or value.get("authorization_file_sha256")
        != receipt.value.get("authorization_sha256")
        or value.get("candidate_commit") != candidate.get("commit")
        or value.get("candidate_tree") != candidate.get("tree")
        or value.get("sol_receipt_file_sha256") != receipt.raw_sha256
        or value.get("sol_receipt_canonical_sha256")
        != receipt.value.get("canonical_receipt_sha256")
        or value.get("sol_session_file_sha256")
        != receipt_terminal.get("boundary_sha256")
        or value.get("sol_session_id") != receipt.value.get("session_id")
        or value.get("sol_recommendation")
        != receipt_opinion.get("recommendation")
        or value.get("sol_confidence")
        != receipt_opinion.get("confidence")
        or not isinstance(value.get("sol_confidence"), (int, float))
        or isinstance(value.get("sol_confidence"), bool)
        or value.get("main_architect_decision") != "go"
        or not isinstance(value.get("main_confidence"), (int, float))
        or isinstance(value.get("main_confidence"), bool)
        or value.get("main_confidence", 0) < 0.5
        or value.get("combined_confidence_formula") != "min(main,sol)"
        or value.get("combined_confidence")
        != min(value.get("main_confidence", 0), value.get("sol_confidence", 0))
        or value.get("condition_adjudication")
        != expected_condition_adjudication
        or value.get("opus_evidence_file_sha256")
        != expected_source_hashes.get("opus-review-evidence")
        or value.get("opus_adjudication_file_sha256")
        != expected_source_hashes.get("opus-adjudication")
        or value.get("unresolved_high_findings") != []
        or value.get("unresolved_medium_findings") != []
        or value.get("zero_allocation_preflight_required") is not True
        or value.get("manifest_authorized") is not True
        or value.get("live_campaign_authorized") is not expected_live_authorized
        or value.get("live_campaign_single_shot") is not True
        or value.get("live_campaign_start_count_exact") != 7
        or value.get("release_authorized") is not False
        or value.get("publication_authorized") is not False
        or value.get("glm52") != "forbidden"
        or value.get("synthesis") != "forbidden"
        or value.get("canonical_adjudication_sha256") != canonical_sha256(unsigned)
    ):
        errors.append(
            f"authorization-predecessor-v10-{gate}-adjudication-binding-invalid"
        )
    return sorted(set(errors))


def _validate_generation11_recovery_steering(
    receipt_snapshot: JsonArtifactSnapshot,
    session_bytes: bytes,
    *,
    bindings: Mapping[str, Any],
    authorization: Mapping[str, Any],
    manifest: Mapping[str, Any],
    expected_control_turn_id: Any,
) -> list[str]:
    """Validate the exact zero-tool Sol/MAX recovery turn and opinion."""

    errors = _validate_json_snapshot(
        receipt_snapshot, "authorization-predecessor-v10-recovery-steering"
    )
    receipt = receipt_snapshot.value
    errors.extend(
        f"authorization-predecessor-v10-recovery-steering:{item}"
        for item in validate_steering_receipt(receipt)
    )
    opinion = receipt.get("opinion") if isinstance(receipt.get("opinion"), Mapping) else {}
    findings = opinion.get("findings") if isinstance(opinion.get("findings"), list) else []
    finding_severities = [
        (item.get("code"), item.get("severity"))
        for item in findings
        if isinstance(item, Mapping)
    ]
    conditions = (
        opinion.get("conditions")
        if isinstance(opinion.get("conditions"), list)
        else []
    )
    work_units = (
        manifest.get("work_units")
        if isinstance(manifest.get("work_units"), Mapping)
        else {}
    )
    if (
        receipt_snapshot.raw_sha256
        != bindings.get("predecessor_recovery_steering_receipt_file_sha256")
        or receipt.get("canonical_receipt_sha256")
        != bindings.get("predecessor_recovery_steering_receipt_canonical_sha256")
        or receipt.get("gate") != "recovery-steering"
        or receipt.get("authorization_id") != authorization.get("authorization_id")
        or receipt.get("authorization_sha256")
        != bindings.get("predecessor_authorization_file_sha256")
        or receipt.get("bead_id")
        != work_units.get("live_work_unit_id")
        or receipt.get("control_turn_id")
        != expected_control_turn_id
        or receipt.get("model") != EXACT_STEERING_MODEL
        or receipt.get("effort") != EXACT_STEERING_EFFORT
        or receipt.get("disposition") != "conditional"
        or opinion.get("recommendation") != "conditional-go"
        or opinion.get("confidence") != 0.94
        or finding_severities
        != [
            ("EMPTY_FILE_RACE", "high"),
            ("TERMINAL_LEAVES", "medium"),
            ("VERSION_DISPATCH", "medium"),
            ("AUTONOMY_BOUNDARY", "low"),
        ]
        or len(conditions) != 4
        or any(not isinstance(item, str) or not item.strip() for item in conditions)
    ):
        errors.append(
            "authorization-predecessor-v10-recovery-steering-binding-invalid"
        )
    if not isinstance(session_bytes, bytes) or not session_bytes.endswith(b"\n"):
        return sorted(
            set(
                errors
                + ["authorization-predecessor-v10-recovery-steering-session-boundary-invalid"]
            )
        )
    try:
        records = [json.loads(line) for line in session_bytes.splitlines()]
    except (UnicodeDecodeError, json.JSONDecodeError):
        return sorted(
            set(
                errors
                + ["authorization-predecessor-v10-recovery-steering-session-json-invalid"]
            )
        )
    if any(not isinstance(record, Mapping) for record in records):
        return sorted(
            set(
                errors
                + ["authorization-predecessor-v10-recovery-steering-session-record-invalid"]
            )
        )
    expected_grammar = (
        ("session_meta", None, None),
        ("event_msg", "task_started", None),
        ("response_item", "message", "developer"),
        ("response_item", "message", "developer"),
        ("response_item", "message", "developer"),
        ("response_item", "message", "user"),
        ("world_state", None, None),
        ("turn_context", None, None),
        ("response_item", "message", "user"),
        ("event_msg", "user_message", None),
        ("response_item", "reasoning", None),
        ("response_item", "reasoning", None),
        ("event_msg", "agent_message", None),
        ("response_item", "message", "assistant"),
        ("event_msg", "token_count", None),
        ("event_msg", "task_complete", None),
    )
    observed: list[tuple[Any, Any, Any]] = []
    for record in records:
        payload = record.get("payload") if isinstance(record, Mapping) else None
        payload = payload if isinstance(payload, Mapping) else {}
        payload_type = payload.get("type")
        observed.append(
            (
                record.get("type") if isinstance(record, Mapping) else None,
                payload_type,
                payload.get("role") if payload_type == "message" else None,
            )
        )
    positional_payloads = [
        record.get("payload") if isinstance(record.get("payload"), Mapping) else {}
        for record in records
    ]
    meta = positional_payloads[0] if positional_payloads else {}
    start = positional_payloads[1] if len(positional_payloads) > 1 else {}
    context = positional_payloads[7] if len(positional_payloads) > 7 else {}
    event_final = positional_payloads[12] if len(positional_payloads) > 12 else {}
    response_final = positional_payloads[13] if len(positional_payloads) > 13 else {}
    terminal = positional_payloads[-1] if positional_payloads else {}
    response_content = response_final.get("content")
    response_texts = [
        item.get("text")
        for item in response_content
        if isinstance(item, Mapping)
        and item.get("type") == "output_text"
        and isinstance(item.get("text"), str)
    ] if isinstance(response_content, list) else []
    event_text = event_final.get("message")
    final_text = response_texts[0] if len(response_texts) == 1 else None
    try:
        final_opinion = json.loads(final_text) if isinstance(final_text, str) else None
    except json.JSONDecodeError:
        final_opinion = None
    session_sha256 = hashlib.sha256(session_bytes).hexdigest()
    terminal_boundary = (
        receipt.get("boundary", {}).get("terminal", {})
        if isinstance(receipt.get("boundary"), Mapping)
        else {}
    )
    if (
        tuple(observed) != expected_grammar
        or not isinstance(meta, Mapping)
        or meta.get("id") != receipt.get("session_id")
        or not isinstance(start, Mapping)
        or not _is_uuid(start.get("turn_id"))
        or start.get("turn_id") != receipt.get("submission_id")
        or not isinstance(context, Mapping)
        or context.get("turn_id") != start.get("turn_id")
        or "turnId" in context
        or context.get("model") != EXACT_STEERING_MODEL
        or (context.get("effort") or context.get("reasoning_effort"))
        != EXACT_STEERING_EFFORT
        or not isinstance(terminal, Mapping)
        or terminal.get("turn_id") != start.get("turn_id")
        or event_final.get("phase") != "final_answer"
        or response_final.get("phase") != "final_answer"
        or event_text != final_text
        or final_opinion != opinion
        or not isinstance(final_text, str)
        or hashlib.sha256(final_text.encode()).hexdigest()
        != receipt.get("final_response_sha256")
        or session_sha256
        != bindings.get("predecessor_recovery_steering_session_file_sha256")
        or terminal_boundary.get("boundary_sha256") != session_sha256
        or terminal_boundary.get("record_count") != len(records)
        or terminal_boundary.get("byte_offset") != len(session_bytes)
        or terminal_boundary.get("invalid_record_count") != 0
        or terminal_boundary.get("trailing_partial") is not False
    ):
        errors.append(
            "authorization-predecessor-v10-recovery-steering-session-binding-invalid"
        )
    return sorted(set(errors))


def _validate_generation11_terminal_facts(
    snapshot: JsonArtifactSnapshot,
    *,
    bindings: Mapping[str, Any],
    proof: Version10InterruptedEmptyBoundaryPredecessorProofInputs,
    authorization: Mapping[str, Any],
    manifest: Mapping[str, Any],
    failure: Mapping[str, Any],
    repo_root: Path | None,
) -> list[str]:
    """Derive the four terminal leaves from immutable Generation-11 sources."""

    errors = _validate_json_snapshot(
        snapshot, "authorization-predecessor-v10-terminal-facts"
    )
    artifact = _strict(
        snapshot.value,
        GENERATION11_TERMINAL_FACTS_FIELDS,
        "authorization-predecessor-v10-terminal-facts",
        errors,
    )
    identity = _strict(
        artifact.get("identity"),
        GENERATION11_TERMINAL_FACT_IDENTITY_FIELDS,
        "authorization-predecessor-v10-terminal-facts-identity",
        errors,
    )
    sources = _strict(
        artifact.get("source_bindings"),
        GENERATION11_TERMINAL_FACT_SOURCE_FIELDS,
        "authorization-predecessor-v10-terminal-facts-sources",
        errors,
    )
    facts = _strict(
        artifact.get("facts"),
        GENERATION11_TERMINAL_FACT_NAMES,
        "authorization-predecessor-v10-terminal-facts-facts",
        errors,
    )
    prior_bindings = (
        authorization.get("bindings")
        if isinstance(authorization.get("bindings"), Mapping)
        else {}
    )
    candidate = manifest.get("candidate") if isinstance(manifest.get("candidate"), Mapping) else {}
    work_units = manifest.get("work_units") if isinstance(manifest.get("work_units"), Mapping) else {}
    session_sha256 = hashlib.sha256(proof.terminal_session_bytes).hexdigest()
    try:
        terminal_records = [json.loads(line) for line in proof.terminal_session_bytes.splitlines()]
    except (UnicodeDecodeError, json.JSONDecodeError):
        terminal_records = []
    terminal_payload = (
        terminal_records[-1].get("payload")
        if terminal_records
        and isinstance(terminal_records[-1], Mapping)
        and isinstance(terminal_records[-1].get("payload"), Mapping)
        else {}
    )
    expected_identity = {
        "authorization_id": authorization.get("authorization_id"),
        "manifest_id": manifest.get("manifest_id"),
        "campaign_nonce": prior_bindings.get("campaign_nonce"),
        "control_turn_id": manifest.get("control_turn_id"),
        "bead_id": work_units.get("epic_id"),
        "work_unit_id": work_units.get("live_work_unit_id"),
        "live_generation": 11,
        "session_id": bindings.get("predecessor_terminal_session_id"),
        "turn_id": bindings.get("predecessor_terminal_turn_id"),
        "candidate_commit": candidate.get("commit"),
        "candidate_tree": candidate.get("tree"),
    }
    expected_sources = {
        "authorization_file_sha256": proof.authorization.raw_sha256,
        "manifest_file_sha256": proof.manifest.raw_sha256,
        "authorization_state_file_sha256": proof.authorization_state.raw_sha256,
        "failure_evidence_file_sha256": proof.failure_evidence.raw_sha256,
        "containment_file_sha256": proof.containment.raw_sha256,
        "global_claim_file_sha256": proof.global_claim.raw_sha256,
        "authorization_marker_file_sha256": proof.authorization_marker.raw_sha256,
        "nonce_marker_file_sha256": proof.nonce_marker.raw_sha256,
        "scope_state_file_sha256": proof.scope_state.raw_sha256,
        "preflight_file_sha256": proof.preflight.raw_sha256,
        "pre_mutation_receipt_file_sha256": proof.pre_mutation_receipt.raw_sha256,
        "pre_mutation_adjudication_file_sha256": proof.pre_mutation_adjudication.raw_sha256,
        "pre_live_receipt_file_sha256": proof.pre_live_receipt.raw_sha256,
        "pre_live_adjudication_file_sha256": proof.pre_live_adjudication.raw_sha256,
        "allocation_ledger_file_sha256": proof.allocation_ledger.raw_sha256,
        "allocation_audit_file_sha256": hashlib.sha256(proof.allocation_audit_bytes).hexdigest(),
        "steering_registry_file_sha256": proof.steering_registry.raw_sha256,
        "terminal_session_file_sha256": session_sha256,
        "outer_authority_file_sha256": proof.outer_authority.raw_sha256,
        "recovery_cause_analysis_sha256": hashlib.sha256(proof.recovery_cause_analysis_bytes).hexdigest(),
        "recovery_steering_receipt_file_sha256": proof.recovery_steering_receipt.raw_sha256,
        "recovery_steering_session_file_sha256": hashlib.sha256(proof.recovery_steering_session_bytes).hexdigest(),
        "generation11_runner_source_sha256": hashlib.sha256(proof.generation11_runner_source_bytes).hexdigest(),
        "generation11_session_boundary_source_sha256": hashlib.sha256(
            proof.generation11_session_boundary_source_bytes
        ).hexdigest(),
    }
    expected_fact_values: dict[str, tuple[Mapping[str, Any], str, list[str]]] = {
        "initial_empty_boundary": (
            GENERATION11_INITIAL_EMPTY_BOUNDARY,
            "source-code-derived-inference",
            [
                "generation11-runner-source",
                "generation11-session-boundary-source",
                "failure-evidence",
            ],
        ),
        "recovery_entry": (
            GENERATION11_RECOVERY_ENTRY,
            "source-code-derived-inference",
            ["generation11-runner-source", "failure-evidence"],
        ),
        "interrupted_terminal_event": (
            terminal_payload,
            "direct-session-telemetry",
            ["terminal-session", "allocation-ledger"],
        ),
        "no_replacement_read": (
            GENERATION11_NO_REPLACEMENT_READ,
            "source-code-derived-inference",
            ["generation11-runner-source", "allocation-ledger", "steering-registry"],
        ),
    }
    fact_binding_fields = {
        "initial_empty_boundary": "predecessor_initial_empty_boundary_sha256",
        "recovery_entry": "predecessor_recovery_entry_sha256",
        "interrupted_terminal_event": "predecessor_interrupted_terminal_event_sha256",
        "no_replacement_read": "predecessor_no_replacement_read_sha256",
    }
    for name, (expected_value, provenance, source_labels) in expected_fact_values.items():
        item = _strict(
            facts.get(name),
            {"provenance", "source_labels", "value", "fact_sha256"},
            f"authorization-predecessor-v10-terminal-fact-{name}",
            errors,
        )
        fact_hash = _generation11_fact_sha256(
            expected_value, leaf=name.replace("_", "-")
        )
        if (
            item.get("provenance") != provenance
            or item.get("source_labels") != source_labels
            or item.get("value") != expected_value
            or item.get("fact_sha256") != fact_hash
            or bindings.get(fact_binding_fields[name]) != fact_hash
        ):
            errors.append(
                f"authorization-predecessor-v10-terminal-fact-{name}-binding-invalid"
            )
    runner_markers = (
        b'"replacement_attempt_count": 0',
        b'read_recovery_pending = True',
        b'capture_recovery_boundary("at-fault")',
    )
    boundary_markers = (
        b"session file has no complete records",
        b"if not raw:",
    )
    if (
        not isinstance(proof.generation11_runner_source_bytes, bytes)
        or not proof.generation11_runner_source_bytes
        or not all(marker in proof.generation11_runner_source_bytes for marker in runner_markers)
        or not isinstance(proof.generation11_session_boundary_source_bytes, bytes)
        or not proof.generation11_session_boundary_source_bytes
        or not all(
            marker in proof.generation11_session_boundary_source_bytes
            for marker in boundary_markers
        )
    ):
        errors.append("authorization-predecessor-v10-terminal-facts-source-semantics-invalid")
    if repo_root is not None and _is_commit(candidate.get("commit")):
        root = Path(repo_root).resolve()
        for path, observed in (
            ("scripts/run_native_pool_live_canaries.py", proof.generation11_runner_source_bytes),
            ("scripts/cwo_core/native_session_boundary.py", proof.generation11_session_boundary_source_bytes),
        ):
            completed = subprocess.run(
                ["git", "show", f"{candidate.get('commit')}:{path}"],
                cwd=root,
                capture_output=True,
            )
            if completed.returncode != 0 or completed.stdout != observed:
                errors.append(
                    "authorization-predecessor-v10-terminal-facts-source-blob-mismatch"
                )
    unsigned = dict(artifact)
    unsigned.pop("canonical_terminal_facts_sha256", None)
    if (
        snapshot.raw_sha256 != bindings.get("predecessor_terminal_facts_file_sha256")
        or artifact.get("canonical_terminal_facts_sha256")
        != bindings.get("predecessor_terminal_facts_canonical_sha256")
        or artifact.get("canonical_terminal_facts_sha256") != canonical_sha256(unsigned)
        or artifact.get("artifact_type") != "cwo-generation11-terminal-facts"
        or artifact.get("version") != 1
        or artifact.get("schema") != "schemas/generation11-terminal-facts.schema.json"
        or _parse_utc(artifact.get("recorded_at")) is None
        or identity != expected_identity
        or sources != expected_sources
        or artifact.get("source_root_sha256") != canonical_sha256(expected_sources)
        or failure.get("failure_message_sha256") != GENERATION11_FAILURE_MESSAGE_SHA256
        or expected_sources["generation11_runner_source_sha256"]
        != bindings.get("predecessor_generation11_runner_source_sha256")
        or expected_sources["generation11_runner_source_sha256"]
        != GENERATION11_RUNNER_SOURCE_SHA256
        or expected_sources["generation11_session_boundary_source_sha256"]
        != bindings.get("predecessor_generation11_session_boundary_source_sha256")
        or expected_sources["generation11_session_boundary_source_sha256"]
        != GENERATION11_SESSION_BOUNDARY_SOURCE_SHA256
    ):
        errors.append("authorization-predecessor-v10-terminal-facts-binding-invalid")
    return sorted(set(errors))


def _validate_generation11_terminal_session(
    raw: bytes,
    *,
    ledger: Mapping[str, Any],
    facts: Mapping[str, Any],
    expected_file_sha256: Any,
    expected_event_sha256: Any,
) -> list[str]:
    """Validate the only archived Generation-11 session and interrupted event."""

    errors: list[str] = []
    if not isinstance(raw, bytes) or not raw or not raw.endswith(b"\n"):
        return ["authorization-predecessor-v10-terminal-session-boundary-invalid"]
    try:
        records = [json.loads(line) for line in raw.splitlines()]
    except (UnicodeDecodeError, json.JSONDecodeError):
        return ["authorization-predecessor-v10-terminal-session-json-invalid"]
    if not records or any(not isinstance(record, Mapping) for record in records):
        return ["authorization-predecessor-v10-terminal-session-record-invalid"]
    raw_sha256 = hashlib.sha256(raw).hexdigest()
    metas = [
        record.get("payload")
        for record in records
        if record.get("type") == "session_meta"
        and isinstance(record.get("payload"), Mapping)
    ]
    starts = [
        (index, record.get("payload"))
        for index, record in enumerate(records)
        if record.get("type") == "event_msg"
        and isinstance(record.get("payload"), Mapping)
        and record["payload"].get("type") == "task_started"
    ]
    contexts = [
        record.get("payload")
        for record in records
        if record.get("type") == "turn_context"
        and isinstance(record.get("payload"), Mapping)
    ]
    aborts = [
        (index, record.get("payload"))
        for index, record in enumerate(records)
        if record.get("type") == "event_msg"
        and isinstance(record.get("payload"), Mapping)
        and record["payload"].get("type") == "turn_aborted"
    ]
    expected_grammar = (
        ("session_meta", None, None),
        ("event_msg", "task_started", None),
        ("response_item", "message", "developer"),
        ("response_item", "message", "user"),
        ("world_state", None, None),
        ("turn_context", None, None),
        ("response_item", "message", "user"),
        ("event_msg", "user_message", None),
        ("response_item", "message", "user"),
        ("event_msg", "turn_aborted", None),
    )
    observed_grammar: list[tuple[Any, Any, Any]] = []
    assistant_messages = 0
    function_calls = 0
    custom_tool_calls = 0
    patch_events = 0
    compactions = 0
    reroutes = 0
    for record in records:
        record_type = record.get("type")
        payload = record.get("payload")
        if not isinstance(payload, Mapping):
            observed_grammar.append((record_type, None, None))
            errors.append(
                "authorization-predecessor-v10-terminal-session-activity-invalid"
            )
            continue
        payload_type = payload.get("type")
        role = payload.get("role") if payload_type == "message" else None
        observed_grammar.append((record_type, payload_type, role))
        marker = f"{record_type}:{payload_type}".lower()
        assistant_messages += int(payload_type == "message" and role == "assistant")
        function_calls += int(payload_type in {"function_call", "function_call_output"})
        custom_tool_calls += int(
            payload_type in {"custom_tool_call", "custom_tool_call_output"}
        )
        patch_events += int(payload_type == "patch_apply_end")
        compactions += int("compact" in marker)
        reroutes += int("rerout" in marker)
    if tuple(observed_grammar) != expected_grammar:
        errors.append(
            "authorization-predecessor-v10-terminal-session-activity-invalid"
        )
    session_id = metas[0].get("id") if len(metas) == 1 else None
    start_payload = starts[0][1] if len(starts) == 1 else {}
    turn_id = (
        start_payload.get("turn_id")
        if isinstance(start_payload, Mapping)
        else None
    )
    terminal_index, terminal_payload = aborts[0] if len(aborts) == 1 else (-1, {})
    terminal_payload = (
        terminal_payload if isinstance(terminal_payload, Mapping) else {}
    )
    event_sha256 = _generation11_fact_sha256(
        terminal_payload, leaf="interrupted-terminal-event"
    )
    entries = ledger.get("entries")
    entries = entries if isinstance(entries, list) else []
    thread_bound = [
        item
        for item in entries
        if isinstance(item, Mapping) and item.get("event") == "thread-bound"
    ]
    turn_bound = [
        item
        for item in entries
        if isinstance(item, Mapping) and item.get("event") == "turn-bound"
    ]
    terminal_fact = (
        facts.get("terminal_event")
        if isinstance(facts.get("terminal_event"), Mapping)
        else {}
    )
    if (
        len(metas) != 1
        or not _is_uuid(session_id)
        or len(starts) != 1
        or starts[0][0] != 1
        or not _is_uuid(turn_id)
        or len(contexts) != 1
        or contexts[0].get("turn_id") != turn_id
        or "turnId" in contexts[0]
        or contexts[0].get("model") != EXACT_OPERATIVE_MODEL
        or (contexts[0].get("effort") or contexts[0].get("reasoning_effort"))
        != EXACT_OPERATIVE_EFFORT
        or len(aborts) != 1
        or terminal_index != len(records) - 1
        or set(terminal_payload)
        != {"type", "turn_id", "reason", "completed_at", "duration_ms"}
        or terminal_payload.get("turn_id") != turn_id
        or terminal_payload.get("reason") != "interrupted"
        or isinstance(terminal_payload.get("completed_at"), bool)
        or not isinstance(terminal_payload.get("completed_at"), (int, float))
        or isinstance(terminal_payload.get("duration_ms"), bool)
        or not isinstance(terminal_payload.get("duration_ms"), (int, float))
        or terminal_payload.get("duration_ms", -1) < 0
        or len(thread_bound) != 1
        or thread_bound[0].get("thread_id") != session_id
        or len(turn_bound) != 1
        or turn_bound[0].get("thread_id") != session_id
        or turn_bound[0].get("turn_id") != turn_id
        or raw_sha256 != expected_file_sha256
        or facts.get("file_sha256") != raw_sha256
        or facts.get("session_id") != session_id
        or facts.get("turn_id") != turn_id
        or terminal_fact
        != {
            "count": 1,
            "event_type": "turn_aborted",
            "record_index": terminal_index,
            "status": "interrupted",
        }
        or event_sha256 != expected_event_sha256
        or facts.get("record_count") != len(records)
        or facts.get("byte_offset") != len(raw)
        or facts.get("assistant_messages") != assistant_messages
        or facts.get("function_calls") != function_calls
        or facts.get("custom_tool_calls") != custom_tool_calls
        or facts.get("patch_events") != patch_events
        or facts.get("compactions") != compactions
        or facts.get("reroutes") != reroutes
        or facts.get("trusted_turn_context_count") != len(contexts)
        or facts.get("turn_context_record_index") != 5
        or facts.get("attested_model") != EXACT_OPERATIVE_MODEL
        or facts.get("attested_effort") != EXACT_OPERATIVE_EFFORT
        or facts.get("active_match_count") != 0
        or facts.get("archive_match_count") != 1
        or facts.get("store") != "archived_sessions"
        or facts.get("workspace_mutation_evidence")
        != "zero-tool-plus-stable-checkout-guards"
    ):
        errors.append(
            "authorization-predecessor-v10-terminal-session-binding-invalid"
        )
    return sorted(set(errors))


def _validate_generation11_containment(
    snapshot: JsonArtifactSnapshot,
    *,
    bindings: Mapping[str, Any],
    prior_authorization: Mapping[str, Any],
    prior_manifest: Mapping[str, Any],
    failure: Mapping[str, Any],
    proof: Version10InterruptedEmptyBoundaryPredecessorProofInputs,
    ledger_summary: Mapping[str, Any] | None,
    expected_containment: Mapping[str, Any],
) -> list[str]:
    errors: list[str] = []
    ledger = proof.allocation_ledger.value
    terminal_session_bytes = proof.terminal_session_bytes
    errors.extend(
        _validate_json_snapshot(snapshot, "authorization-predecessor-v10-containment")
    )
    containment = _strict(
        snapshot.value,
        GENERATION11_CONTAINMENT_FIELDS,
        "authorization-predecessor-v10-containment",
        errors,
    )
    allocation_ledger = _strict(
        containment.get("allocation_ledger"),
        {
            "audit_anchor_count",
            "audit_chain_valid",
            "audit_file_sha256",
            "exact_lifecycle",
            "head_entry_sha256",
            "ledger_file_sha256",
            "ledger_id",
            "sequence",
            "state_sha256",
            "unresolved_allocation_intents",
            "unresolved_turn_intents",
        },
        "authorization-predecessor-v10-containment-allocation-ledger",
        errors,
    )
    claim_v5_and_scope = _strict(
        containment.get("claim_v5_and_scope"),
        {
            "authorization_marker_canonical_sha256",
            "authorization_marker_file_sha256",
            "authorization_state",
            "authorization_state_canonical_sha256",
            "authorization_state_file_sha256",
            "global_claim_canonical_sha256",
            "global_claim_file_sha256",
            "launch_claim_sha256",
            "launch_claim_version",
            "nonce_marker_canonical_sha256",
            "nonce_marker_file_sha256",
            "preflight_canonical_sha256",
            "preflight_file_sha256",
            "scope_key",
            "scope_phase",
            "scope_snapshot_basename",
            "scope_snapshot_canonical_sha256",
            "scope_snapshot_file_sha256",
            "scope_state_canonical_sha256",
            "scope_state_file_sha256",
            "terminal_evidence_canonical_sha256",
            "tombstones_permanent",
        },
        "authorization-predecessor-v10-containment-claim-scope",
        errors,
    )
    containment_summary = _strict(
        containment.get("containment"),
        set(expected_containment),
        "authorization-predecessor-v10-containment-summary",
        errors,
    )
    steering_consumptions = _strict(
        containment.get("steering_consumptions"),
        {"pre-mutation", "pre-live"},
        "authorization-predecessor-v10-containment-steering-consumptions",
        errors,
    )
    root_cause = _strict(
        containment.get("root_cause"),
        {
            "cause_class",
            "existing_zero_byte_session_boundary_accepted",
            "failed_edge",
            "independently_reproduced_failure_message_hash",
            "missing_session_boundary_accepted",
            "replacement_read_attempted",
            "source_analysis_file_sha256",
        },
        "authorization-predecessor-v10-containment-root-cause",
        errors,
    )
    failed_authority = _strict(
        containment.get("failed_authority"),
        {
            "authorization_canonical_sha256",
            "authorization_file_sha256",
            "authorization_id",
            "authorization_version",
            "campaign_nonce",
            "live_generation",
            "manifest_canonical_sha256",
            "manifest_file_sha256",
            "manifest_id",
            "manifest_version",
            "outer_authority_canonical_sha256",
            "outer_authority_file_sha256",
            "outer_authority_id",
            "run_generation",
        },
        "authorization-predecessor-v10-containment-failed-authority",
        errors,
    )
    terminal_failure = _strict(
        containment.get("terminal_failure"),
        {
            "failure_class",
            "failure_code",
            "failure_evidence_canonical_sha256",
            "failure_evidence_file_sha256",
            "failure_message",
            "failure_message_sha256",
            "first_protected_fault",
            "validation_outcome",
        },
        "authorization-predecessor-v10-containment-terminal-failure",
        errors,
    )
    contained_session = _strict(
        containment.get("contained_session"),
        {
            "active_match_count",
            "archive_match_count",
            "assistant_messages",
            "attested_effort",
            "attested_model",
            "byte_offset",
            "compactions",
            "custom_tool_calls",
            "file_sha256",
            "function_calls",
            "patch_events",
            "record_count",
            "reroutes",
            "session_id",
            "store",
            "terminal_event",
            "trusted_turn_context_count",
            "turn_context_record_index",
            "turn_id",
            "workspace_mutation_evidence",
        },
        "authorization-predecessor-v10-containment-session",
        errors,
    )
    generation12_contract = _strict(
        containment.get("generation12_recovery_contract"),
        {
            "accepted_finding_codes",
            "cause_analysis_file_sha256",
            "fresh_authority_required",
            "implementation_conditions_are_mandatory",
            "live_launch_authorized_by_this_artifact",
            "required_authorization_version",
            "required_launch_claim_version",
            "required_manifest_version",
            "required_validator_version",
            "sol_confidence",
            "sol_receipt_canonical_sha256",
            "sol_receipt_file_sha256",
            "sol_recommendation",
            "sol_session",
        },
        "authorization-predecessor-v10-containment-generation12-contract",
        errors,
    )
    recovery_sol_session = _strict(
        generation12_contract.get("sol_session"),
        {
            "archived",
            "attested_effort",
            "attested_model",
            "boundary_sha256",
            "byte_offset",
            "compactions",
            "custom_tool_calls",
            "file_sha256",
            "function_calls",
            "record_count",
            "reroutes",
            "session_id",
            "terminal_event",
            "turn_id",
        },
        "authorization-predecessor-v10-containment-recovery-sol-session",
        errors,
    )
    disposition = _strict(
        containment.get("disposition"),
        {
            "authorization_state",
            "generation11_retry_resume_substitute_bridge_salvage",
            "generation11_state",
            "glm_5_2_used",
            "model_synthesis_used",
            "operative_dispatch_authorized",
            "publish_push_install_authorized",
            "release_gate_passed",
            "requires_fresh_live_generation",
        },
        "authorization-predecessor-v10-containment-disposition",
        errors,
    )
    control_recheck = _strict(
        containment.get("control_plane_recheck"),
        {
            "cap_two_operative_release",
            "current_successor_implementation_in_progress",
            "failure_time_tracked_clean",
            "isolated_checkout_head",
            "isolated_checkout_tree",
            "native_supervision_pool_status",
            "operative_dispatch_authorized",
            "origin_main_commit",
            "protected_primary_diff_sha256",
            "release_gate_passed",
            "transient_successor_worktree_diff_bound",
            "workspace_mutations_observed",
        },
        "authorization-predecessor-v10-containment-control-recheck",
        errors,
    )
    initial_sha256 = _generation11_fact_sha256(
        GENERATION11_INITIAL_EMPTY_BOUNDARY, leaf="initial-empty-boundary"
    )
    recovery_sha256 = _generation11_fact_sha256(
        GENERATION11_RECOVERY_ENTRY, leaf="recovery-entry"
    )
    no_replacement_sha256 = _generation11_fact_sha256(
        GENERATION11_NO_REPLACEMENT_READ, leaf="no-replacement-read"
    )
    prior_state = proof.authorization_state.value
    claim = proof.global_claim.value
    scope = proof.scope_state.value
    preflight = proof.preflight.value
    registry = proof.steering_registry.value
    outer = proof.outer_authority.value
    ledger_entries = (
        ledger.get("entries") if isinstance(ledger.get("entries"), list) else []
    )
    audit_records: list[Any] = []
    try:
        audit_records = [json.loads(line) for line in proof.allocation_audit_bytes.splitlines()]
    except (UnicodeDecodeError, json.JSONDecodeError):
        pass
    expected_allocation_ledger = {
        "audit_anchor_count": len(audit_records),
        "audit_chain_valid": True,
        "audit_file_sha256": hashlib.sha256(proof.allocation_audit_bytes).hexdigest(),
        "exact_lifecycle": [
            item.get("event") for item in ledger_entries if isinstance(item, Mapping)
        ],
        "head_entry_sha256": ledger.get("head_entry_sha256"),
        "ledger_file_sha256": proof.allocation_ledger.raw_sha256,
        "ledger_id": ledger.get("ledger_id"),
        "sequence": ledger.get("sequence"),
        "state_sha256": ledger.get("state_sha256"),
        "unresolved_allocation_intents": (
            ledger_summary.get("unresolved_allocation_intent_count")
            if isinstance(ledger_summary, Mapping)
            else None
        ),
        "unresolved_turn_intents": (
            ledger_summary.get("unresolved_turn_intent_count")
            if isinstance(ledger_summary, Mapping)
            else None
        ),
    }
    expected_claim_scope = {
        "authorization_marker_canonical_sha256": proof.authorization_marker.value.get(
            "canonical_marker_sha256"
        ),
        "authorization_marker_file_sha256": proof.authorization_marker.raw_sha256,
        "authorization_state": prior_state.get("state"),
        "authorization_state_canonical_sha256": prior_state.get("state_sha256"),
        "authorization_state_file_sha256": proof.authorization_state.raw_sha256,
        "global_claim_canonical_sha256": claim.get("canonical_claim_sha256"),
        "global_claim_file_sha256": proof.global_claim.raw_sha256,
        "launch_claim_sha256": claim.get("launch_claim_sha256"),
        "launch_claim_version": 5,
        "nonce_marker_canonical_sha256": proof.nonce_marker.value.get(
            "canonical_marker_sha256"
        ),
        "nonce_marker_file_sha256": proof.nonce_marker.raw_sha256,
        "preflight_canonical_sha256": preflight.get("canonical_preflight_sha256"),
        "preflight_file_sha256": proof.preflight.raw_sha256,
        "scope_key": scope.get("scope_key"),
        "scope_phase": scope.get("phase"),
        "scope_snapshot_basename": "generation11-contained-scope-state-v32.json",
        "scope_snapshot_canonical_sha256": scope.get("canonical_state_sha256"),
        "scope_snapshot_file_sha256": proof.scope_state.raw_sha256,
        "scope_state_canonical_sha256": scope.get("canonical_state_sha256"),
        "scope_state_file_sha256": proof.scope_state.raw_sha256,
        "terminal_evidence_canonical_sha256": failure.get("evidence_sha256"),
        "tombstones_permanent": True,
    }
    consumed = registry.get("consumed") if isinstance(registry.get("consumed"), list) else []
    phase_inputs = {
        "pre-mutation": (
            proof.pre_mutation_receipt,
            proof.pre_mutation_adjudication,
            consumed[0] if len(consumed) > 0 and isinstance(consumed[0], Mapping) else {},
        ),
        "pre-live": (
            proof.pre_live_receipt,
            proof.pre_live_adjudication,
            consumed[1] if len(consumed) > 1 and isinstance(consumed[1], Mapping) else {},
        ),
    }
    expected_steering_consumptions: dict[str, dict[str, Any]] = {}
    for phase, (receipt, adjudication, consumption) in phase_inputs.items():
        phase_nonce = consumption.get("phase_nonce")
        expected_consumption_sha256 = _domain_sha256(
            {
                "receipt": receipt.value.get("canonical_receipt_sha256"),
                "run": receipt.value.get("authorization_id"),
                "attempt": receipt.value.get("submission_id"),
                "gate": receipt.value.get("gate"),
                "phase_nonce": phase_nonce,
                # The live runner consumes and records the SHA-256 of the exact
                # adjudication file bytes.  Successor validation must replay
                # that same binding, not the adjudication's inner canonical
                # content hash.
                "adjudication": adjudication.raw_sha256,
            },
            domain="steering-receipt-consumption",
        )
        expected_steering_consumptions[phase] = {
            "adjudication_file_sha256": adjudication.raw_sha256,
            "consumed_exactly_once": True,
            "consumption_sha256": expected_consumption_sha256,
            "phase_nonce": phase_nonce,
            "receipt_canonical_sha256": receipt.value.get(
                "canonical_receipt_sha256"
            ),
            "receipt_file_sha256": receipt.raw_sha256,
        }
    recovery_receipt = proof.recovery_steering_receipt.value
    recovery_opinion = (
        recovery_receipt.get("opinion")
        if isinstance(recovery_receipt.get("opinion"), Mapping)
        else {}
    )
    try:
        recovery_records = [
            json.loads(line) for line in proof.recovery_steering_session_bytes.splitlines()
        ]
    except (UnicodeDecodeError, json.JSONDecodeError):
        recovery_records = []
    recovery_start = (
        recovery_records[1].get("payload")
        if len(recovery_records) > 1
        and isinstance(recovery_records[1], Mapping)
        and isinstance(recovery_records[1].get("payload"), Mapping)
        else {}
    )
    recovery_session_sha256 = hashlib.sha256(
        proof.recovery_steering_session_bytes
    ).hexdigest()
    expected_recovery_sol_session = {
        "archived": True,
        "attested_effort": EXACT_STEERING_EFFORT,
        "attested_model": EXACT_STEERING_MODEL,
        "boundary_sha256": recovery_session_sha256,
        "byte_offset": len(proof.recovery_steering_session_bytes),
        "compactions": 0,
        "custom_tool_calls": 0,
        "file_sha256": recovery_session_sha256,
        "function_calls": 0,
        "record_count": len(recovery_records),
        "reroutes": 0,
        "session_id": recovery_receipt.get("session_id"),
        "terminal_event": {
            "count": 1,
            "event_type": "task_complete",
            "record_index": len(recovery_records) - 1,
            "status": "completed",
        },
        "turn_id": recovery_start.get("turn_id"),
    }
    expected_generation12_contract = {
        "accepted_finding_codes": [
            "EMPTY_FILE_RACE",
            "TERMINAL_LEAVES",
            "VERSION_DISPATCH",
            "AUTONOMY_BOUNDARY",
        ],
        "cause_analysis_file_sha256": hashlib.sha256(
            proof.recovery_cause_analysis_bytes
        ).hexdigest(),
        "fresh_authority_required": True,
        "implementation_conditions_are_mandatory": True,
        "live_launch_authorized_by_this_artifact": False,
        "required_authorization_version": AUTHORIZATION_VERSION_V11,
        "required_launch_claim_version": LAUNCH_CLAIM_VERSION_V6,
        "required_manifest_version": MANIFEST_VERSION_V8,
        "required_validator_version": VALIDATOR_CONTRACT_VERSION_V6,
        "sol_confidence": recovery_opinion.get("confidence"),
        "sol_receipt_canonical_sha256": recovery_receipt.get(
            "canonical_receipt_sha256"
        ),
        "sol_receipt_file_sha256": proof.recovery_steering_receipt.raw_sha256,
        "sol_recommendation": recovery_opinion.get("recommendation"),
        "sol_session": expected_recovery_sol_session,
    }
    prior_bindings = (
        prior_authorization.get("bindings")
        if isinstance(prior_authorization.get("bindings"), Mapping)
        else {}
    )
    prior_candidate = (
        prior_manifest.get("candidate")
        if isinstance(prior_manifest.get("candidate"), Mapping)
        else {}
    )
    expected_control_recheck = {
        "cap_two_operative_release": False,
        "current_successor_implementation_in_progress": True,
        "failure_time_tracked_clean": True,
        "isolated_checkout_head": prior_candidate.get("commit"),
        "isolated_checkout_tree": prior_candidate.get("tree"),
        "native_supervision_pool_status": "canary-gated",
        "operative_dispatch_authorized": False,
        "origin_main_commit": prior_bindings.get("origin_main_commit"),
        "protected_primary_diff_sha256": prior_bindings.get(
            "guarded_primary_diff_sha256"
        ),
        "release_gate_passed": False,
        "transient_successor_worktree_diff_bound": False,
        "workspace_mutations_observed": 0,
    }
    if (
        snapshot.raw_sha256 != bindings.get("predecessor_containment_file_sha256")
        or containment.get("canonical_recovery_sha256")
        != bindings.get("predecessor_containment_canonical_sha256")
        or containment.get("canonical_recovery_sha256")
        != _canonical_artifact_hash(containment, "canonical_recovery_sha256")
        or containment.get("schema")
        != "cwo-live-campaign-containment-recovery:v5"
        or containment.get("version") != 5
        or _parse_utc(containment.get("recorded_at")) is None
        or failed_authority.get("authorization_id")
        != prior_authorization.get("authorization_id")
        or failed_authority.get("authorization_file_sha256")
        != bindings.get("predecessor_authorization_file_sha256")
        or failed_authority.get("authorization_canonical_sha256")
        != bindings.get("predecessor_authorization_canonical_sha256")
        or failed_authority.get("authorization_version") != AUTHORIZATION_VERSION_V10
        or failed_authority.get("manifest_id") != prior_manifest.get("manifest_id")
        or failed_authority.get("manifest_file_sha256")
        != bindings.get("predecessor_manifest_file_sha256")
        or failed_authority.get("manifest_canonical_sha256")
        != bindings.get("predecessor_manifest_canonical_sha256")
        or failed_authority.get("manifest_version") != MANIFEST_VERSION_V7
        or failed_authority.get("live_generation") != 11
        or failed_authority.get("campaign_nonce")
        != prior_authorization.get("bindings", {}).get("campaign_nonce")
        or terminal_failure.get("failure_evidence_file_sha256")
        != bindings.get("predecessor_failure_evidence_file_sha256")
        or terminal_failure.get("failure_evidence_canonical_sha256")
        != bindings.get("predecessor_failure_evidence_canonical_sha256")
        or terminal_failure.get("failure_class") != "AppServerError"
        or terminal_failure.get("failure_code") != "AppServerError"
        or terminal_failure.get("failure_message")
        != "capability-read-recovery-fault-boundary-invalid:session file has no complete records"
        or terminal_failure.get("failure_message_sha256")
        != GENERATION11_FAILURE_MESSAGE_SHA256
        or terminal_failure.get("first_protected_fault") is not None
        or terminal_failure.get("validation_outcome") != "rejected"
        or failure.get("failure_message_sha256")
        != terminal_failure.get("failure_message_sha256")
        or root_cause
        != {
            "cause_class": "empty-materialized-session-boundary-rejected",
            "existing_zero_byte_session_boundary_accepted": False,
            "failed_edge": "capability-read-recovery:at-fault",
            "independently_reproduced_failure_message_hash": True,
            "missing_session_boundary_accepted": True,
            "replacement_read_attempted": False,
            "source_analysis_file_sha256": root_cause.get(
                "source_analysis_file_sha256"
            ),
        }
        or not _is_hash(root_cause.get("source_analysis_file_sha256"))
        or contained_session.get("file_sha256")
        != bindings.get("predecessor_terminal_session_file_sha256")
        or contained_session.get("session_id")
        != bindings.get("predecessor_terminal_session_id")
        or contained_session.get("turn_id")
        != bindings.get("predecessor_terminal_turn_id")
        or generation12_contract.get("fresh_authority_required") is not True
        or generation12_contract.get("implementation_conditions_are_mandatory")
        is not True
        or generation12_contract.get("live_launch_authorized_by_this_artifact")
        is not False
        or validate_operative_version_tuple(
            generation12_contract.get("required_authorization_version"),
            generation12_contract.get("required_manifest_version"),
            generation12_contract.get("required_launch_claim_version"),
            generation12_contract.get("required_validator_version"),
        )
        or disposition
        != {
            "authorization_state": "containment-only",
            "generation11_retry_resume_substitute_bridge_salvage": False,
            "generation11_state": "terminal-contained",
            "glm_5_2_used": False,
            "model_synthesis_used": False,
            "operative_dispatch_authorized": False,
            "publish_push_install_authorized": False,
            "release_gate_passed": False,
            "requires_fresh_live_generation": 12,
        }
        or control_recheck.get("operative_dispatch_authorized") is not False
        or control_recheck.get("release_gate_passed") is not False
        or control_recheck.get("cap_two_operative_release") is not False
        or control_recheck.get("workspace_mutations_observed") != 0
        or initial_sha256
        != bindings.get("predecessor_initial_empty_boundary_sha256")
        or recovery_sha256 != bindings.get("predecessor_recovery_entry_sha256")
        or no_replacement_sha256
        != bindings.get("predecessor_no_replacement_read_sha256")
    ):
        errors.append("authorization-predecessor-v10-containment-binding-invalid")
    work_units = (
        prior_manifest.get("work_units")
        if isinstance(prior_manifest.get("work_units"), Mapping)
        else {}
    )
    if (
        containment.get("bead_id") != work_units.get("live_work_unit_id")
        or containment.get("control_turn_id") != prior_manifest.get("control_turn_id")
        or allocation_ledger != expected_allocation_ledger
        or containment_summary != dict(expected_containment)
        or containment_summary != failure.get("containment")
    ):
        errors.append(
            "authorization-predecessor-v10-containment-derived-summary-invalid"
        )
    if claim_v5_and_scope != expected_claim_scope:
        errors.append(
            "authorization-predecessor-v10-containment-claim-scope-binding-invalid"
        )
    if steering_consumptions != expected_steering_consumptions:
        errors.append(
            "authorization-predecessor-v10-containment-steering-binding-invalid"
        )
    if (
        generation12_contract != expected_generation12_contract
        or recovery_sol_session != expected_recovery_sol_session
        or root_cause.get("source_analysis_file_sha256")
        != hashlib.sha256(proof.recovery_cause_analysis_bytes).hexdigest()
    ):
        errors.append(
            "authorization-predecessor-v10-containment-recovery-contract-binding-invalid"
        )
    if (
        failed_authority.get("outer_authority_id") != outer.get("authority_id")
        or failed_authority.get("outer_authority_file_sha256")
        != proof.outer_authority.raw_sha256
        or failed_authority.get("outer_authority_canonical_sha256")
        != outer.get("canonical_outer_authority_sha256")
        or failed_authority.get("run_generation")
        != prior_authorization.get("run_generation")
        or failed_authority.get("outer_authority_id")
        != prior_bindings.get("outer_authority_id")
        or failed_authority.get("outer_authority_file_sha256")
        != prior_bindings.get("outer_authority_file_sha256")
        or failed_authority.get("outer_authority_canonical_sha256")
        != prior_bindings.get("outer_authority_canonical_sha256")
    ):
        errors.append(
            "authorization-predecessor-v10-containment-outer-authority-binding-invalid"
        )
    if control_recheck != expected_control_recheck:
        errors.append(
            "authorization-predecessor-v10-containment-control-recheck-binding-invalid"
        )
    errors.extend(
        _validate_generation11_terminal_session(
            terminal_session_bytes,
            ledger=ledger,
            facts=contained_session,
            expected_file_sha256=bindings.get(
                "predecessor_terminal_session_file_sha256"
            ),
            expected_event_sha256=bindings.get(
                "predecessor_interrupted_terminal_event_sha256"
            ),
        )
    )
    return sorted(set(errors))


def _validate_v10_interrupted_empty_boundary_predecessor_proof(
    *,
    bindings: Mapping[str, Any],
    progress: Mapping[str, Any],
    supersession: Mapping[str, Any],
    predecessor_live_generation: int,
    proof: Version10InterruptedEmptyBoundaryPredecessorProofInputs,
    repo_root: Path | None,
) -> list[str]:
    """Validate the exact terminal Generation-11 v10/v7 predecessor leaf."""

    errors: list[str] = []
    if not isinstance(proof.ancestor, Version9PreallocationFaultPredecessorProofInputs):
        return ["authorization-predecessor-v10-ancestor-proof-type-invalid"]
    snapshots = {
        "authorization-predecessor-v10-authorization": proof.authorization,
        "authorization-predecessor-v10-manifest": proof.manifest,
        "authorization-predecessor-v10-state": proof.authorization_state,
        "authorization-predecessor-v10-failure": proof.failure_evidence,
        "authorization-predecessor-v10-containment": proof.containment,
        "authorization-predecessor-v10-global-claim": proof.global_claim,
        "authorization-predecessor-v10-authorization-marker": proof.authorization_marker,
        "authorization-predecessor-v10-nonce-marker": proof.nonce_marker,
        "authorization-predecessor-v10-scope-state": proof.scope_state,
        "authorization-predecessor-v10-preflight": proof.preflight,
        "authorization-predecessor-v10-pre-mutation-receipt": proof.pre_mutation_receipt,
        "authorization-predecessor-v10-pre-mutation-adjudication": proof.pre_mutation_adjudication,
        "authorization-predecessor-v10-pre-live-receipt": proof.pre_live_receipt,
        "authorization-predecessor-v10-pre-live-adjudication": proof.pre_live_adjudication,
        "authorization-predecessor-v10-allocation-ledger": proof.allocation_ledger,
        "authorization-predecessor-v10-steering-registry": proof.steering_registry,
        "authorization-predecessor-v10-terminal-facts": proof.terminal_facts,
        "authorization-predecessor-v10-recovery-steering": proof.recovery_steering_receipt,
        "authorization-predecessor-v10-cause": proof.authorization_recovery_cause_evidence,
        "authorization-predecessor-v10-outer-authority": proof.outer_authority,
        "authorization-predecessor-v10-independent-validation": proof.independent_validation_receipt,
    }
    for label, snapshot in snapshots.items():
        errors.extend(_validate_json_snapshot(snapshot, label))
    if any(
        not isinstance(raw, bytes) or not raw
        for raw in (
            proof.allocation_audit_bytes,
            proof.terminal_session_bytes,
            proof.generation11_runner_source_bytes,
            proof.generation11_session_boundary_source_bytes,
            proof.recovery_cause_analysis_bytes,
            proof.recovery_steering_session_bytes,
            proof.authorization_recovery_cause_source_analysis,
            proof.independent_validation_session_bytes,
        )
    ):
        errors.append("authorization-predecessor-v10-byte-snapshot-invalid")
        return sorted(set(errors))

    prior_authorization = dict(proof.authorization.value)
    prior_manifest = dict(proof.manifest.value)
    prior_state = dict(proof.authorization_state.value)
    failure = dict(proof.failure_evidence.value)
    claim = dict(proof.global_claim.value)
    scope = dict(proof.scope_state.value)
    preflight = dict(proof.preflight.value)
    ledger = dict(proof.allocation_ledger.value)
    registry = dict(proof.steering_registry.value)
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
    prior_supersession = (
        prior_authorization.get("supersession")
        if isinstance(prior_authorization.get("supersession"), Mapping)
        else {}
    )
    prior_candidate = (
        prior_manifest.get("candidate")
        if isinstance(prior_manifest.get("candidate"), Mapping)
        else {}
    )
    prior_outputs = (
        prior_manifest.get("outputs")
        if isinstance(prior_manifest.get("outputs"), Mapping)
        else {}
    )
    prior_work_units = (
        prior_manifest.get("work_units")
        if isinstance(prior_manifest.get("work_units"), Mapping)
        else {}
    )
    prior_id = prior_authorization.get("authorization_id")
    prior_nonce = prior_bindings.get("campaign_nonce")
    prior_raw = proof.authorization.raw_sha256
    predecessor_launch_claim_sha256 = bindings.get(
        "predecessor_launch_claim_sha256"
    )
    errors.extend(
        f"authorization-predecessor-v10-contract:{item}"
        for item in _validate_full_auto_authorization_v10(
            prior_authorization,
            predecessor_proof=proof.ancestor,
            recovery_cause_evidence=proof.authorization_recovery_cause_evidence,
            recovery_cause_source_analysis=(
                proof.authorization_recovery_cause_source_analysis
            ),
            expected_validator_contract_sha256=prior_bindings.get(
                "validator_contract_sha256"
            ),
            repo_root=None,
        )
    )
    errors.extend(
        f"authorization-predecessor-v10-manifest-contract:{item}"
        for item in _validate_campaign_manifest_v7(
            prior_manifest,
            authorization=prior_authorization,
            authorization_raw_sha256=prior_raw,
            outer_authority=proof.outer_authority.value,
            outer_authority_raw_sha256=proof.outer_authority.raw_sha256,
            predecessor_proof=proof.ancestor,
            recovery_cause_evidence=proof.authorization_recovery_cause_evidence,
            recovery_cause_source_analysis=(
                proof.authorization_recovery_cause_source_analysis
            ),
            independent_validation_receipt=proof.independent_validation_receipt.value,
            independent_validation_receipt_raw_sha256=(
                proof.independent_validation_receipt.raw_sha256
            ),
            expected_validator_contract_sha256=prior_bindings.get(
                "validator_contract_sha256"
            ),
            repo_root=None,
            expected_primary_diff_sha256=None,
        )
    )
    errors.extend(
        _validate_independent_validation_session_snapshot(
            proof.independent_validation_receipt.value,
            proof.independent_validation_session_bytes,
        )
    )
    if (
        bindings.get("campaign_nonce") == prior_nonce
        or predecessor_live_generation != 11
        or prior_authorization.get("version") != AUTHORIZATION_VERSION_V10
        or prior_manifest.get("version") != MANIFEST_VERSION_V7
        or prior_authorization.get("live_generation") != 11
        or prior_id != bindings.get("predecessor_authorization_id")
        or prior_raw != bindings.get("predecessor_authorization_file_sha256")
        or prior_authorization.get("canonical_authorization_sha256")
        != bindings.get("predecessor_authorization_canonical_sha256")
        or proof.manifest.raw_sha256
        != bindings.get("predecessor_manifest_file_sha256")
        or prior_manifest.get("manifest_sha256")
        != bindings.get("predecessor_manifest_canonical_sha256")
        or prior_candidate.get("commit")
        != progress.get("predecessor_candidate_commit")
        or prior_candidate.get("tree")
        != progress.get("predecessor_candidate_tree")
    ):
        errors.append("authorization-predecessor-v10-v7-binding-invalid")

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
    allowed_actions = prior_state.get("allowed_actions")
    revoked_actions = prior_state.get("revoked_actions")
    if (
        proof.authorization_state.raw_sha256
        != bindings.get("predecessor_authorization_state_file_sha256")
        or prior_state.get("state_sha256")
        != bindings.get("predecessor_authorization_state_canonical_sha256")
        or validate_authorization_state(prior_state)
        or prior_state.get("authorization_id") != prior_id
        or prior_state.get("run_nonce") != prior_nonce
        or prior_state.get("launch_claim_sha256")
        != predecessor_launch_claim_sha256
        or prior_state.get("state") != "containment-only"
        or not isinstance(allowed_actions, list)
        or not all(isinstance(item, str) for item in allowed_actions)
        or required_revocations.intersection(set(allowed_actions))
        or not isinstance(revoked_actions, list)
        or not all(isinstance(item, str) for item in revoked_actions)
        or not required_revocations.issubset(set(revoked_actions))
    ):
        errors.append("authorization-predecessor-v10-state-binding-invalid")

    claim_fields = {
        "claim_type",
        "version",
        "identity",
        "identity_sha256",
        "launch_claim_sha256",
        "outer_authority_id",
        "candidate_commit",
        "candidate_tree",
        "output_paths",
        "claimed_at",
        "canonical_claim_sha256",
    }
    claim_value = _strict(
        claim, claim_fields, "authorization-predecessor-v10-global-claim", errors
    )
    claim_unsigned = dict(claim_value)
    claim_canonical = claim_unsigned.pop("canonical_claim_sha256", None)
    expected_identity = {
        "authorization_id": prior_id,
        "run_generation": prior_authorization.get("run_generation"),
        "live_generation": 11,
        "campaign_nonce": prior_nonce,
    }
    claim_output_paths = _strict(
        claim_value.get("output_paths"),
        {"allocation_ledger", "authorization_state", "evidence", "steering_registry"},
        "authorization-predecessor-v10-global-claim-output-paths",
        errors,
    )
    expected_output_basenames = {
        "allocation_ledger": prior_outputs.get("allocation_ledger_basename"),
        "authorization_state": prior_outputs.get("authorization_state_basename"),
        "evidence": prior_outputs.get("evidence_basename"),
        "steering_registry": prior_outputs.get("steering_registry_basename"),
    }
    if (
        proof.global_claim.raw_sha256
        != bindings.get("predecessor_global_claim_file_sha256")
        or claim_canonical
        != bindings.get("predecessor_global_claim_canonical_sha256")
        or claim_canonical
        != _domain_sha256(claim_unsigned, domain="native-live-global-claim-artifact")
        or claim.get("claim_type") != "cwo-native-live-campaign-global-claim"
        or claim.get("version") != 1
        or claim.get("identity") != expected_identity
        or claim.get("identity_sha256")
        != _domain_sha256(expected_identity, domain="native-live-global-claim")
        or claim.get("launch_claim_sha256") != predecessor_launch_claim_sha256
        or claim.get("outer_authority_id") != prior_bindings.get("outer_authority_id")
        or claim.get("candidate_commit") != prior_candidate.get("commit")
        or claim.get("candidate_tree") != prior_candidate.get("tree")
        or _parse_utc(claim.get("claimed_at")) is None
        or any(
            not isinstance(claim_output_paths.get(label), str)
            or not Path(str(claim_output_paths.get(label))).is_absolute()
            or Path(str(claim_output_paths.get(label))).name != basename
            for label, basename in expected_output_basenames.items()
        )
    ):
        errors.append("authorization-predecessor-v10-global-claim-binding-invalid")

    marker_fields = {
        "marker_type",
        "version",
        "kind",
        "identifier",
        "identifier_sha256",
        "claim_canonical_sha256",
        "created_at",
        "canonical_marker_sha256",
    }
    for label, marker_snapshot, kind, identifier in (
        ("authorization", proof.authorization_marker, "authorization", prior_id),
        ("nonce", proof.nonce_marker, "nonce", prior_nonce),
    ):
        marker = _strict(
            marker_snapshot.value,
            marker_fields,
            f"authorization-predecessor-v10-{label}-marker",
            errors,
        )
        marker_unsigned = dict(marker)
        marker_canonical = marker_unsigned.pop("canonical_marker_sha256", None)
        if (
            marker_snapshot.raw_sha256
            != bindings.get(f"predecessor_{label}_marker_file_sha256")
            or marker_canonical
            != bindings.get(f"predecessor_{label}_marker_canonical_sha256")
            or marker_canonical != canonical_sha256(marker_unsigned)
            or marker.get("marker_type")
            != "cwo-native-live-global-claim-identifier"
            or marker.get("version") != 1
            or marker.get("kind") != kind
            or marker.get("identifier") != identifier
            or marker.get("identifier_sha256")
            != _domain_sha256(
                {"kind": kind, "identifier": identifier},
                domain="native-live-global-claim-identifier",
            )
            or marker.get("claim_canonical_sha256") != claim_canonical
            or _parse_utc(marker.get("created_at")) is None
        ):
            errors.append(
                f"authorization-predecessor-v10-{label}-marker-binding-invalid"
            )

    scope_fields = {
        "state_type",
        "version",
        "scope_key",
        "phase",
        "outer_authority_id",
        "authorization_id",
        "campaign_nonce",
        "launch_claim_sha256",
        "candidate_commit",
        "candidate_tree",
        "previous_state_sha256",
        "reserved_at",
        "updated_at",
        "terminal_evidence_sha256",
        "canonical_state_sha256",
    }
    scope_value = _strict(
        scope, scope_fields, "authorization-predecessor-v10-scope-state", errors
    )
    try:
        expected_scope_key = active_outer_authority_scope_key(
            prior_work_units.get("epic_id"),
            prior_work_units.get("parent_work_unit_id"),
        )
    except ValueError:
        expected_scope_key = None
    if (
        proof.scope_state.raw_sha256
        != bindings.get("predecessor_scope_state_file_sha256")
        or scope.get("canonical_state_sha256")
        != bindings.get("predecessor_scope_state_canonical_sha256")
        or scope.get("canonical_state_sha256")
        != _canonical_artifact_hash(scope_value, "canonical_state_sha256")
        or scope.get("state_type") != "cwo-native-live-scope-campaign-state"
        or scope.get("version") != 1
        or scope.get("scope_key") != expected_scope_key
        or scope.get("phase") != "contained"
        or scope.get("outer_authority_id") != prior_bindings.get("outer_authority_id")
        or scope.get("authorization_id") != prior_id
        or scope.get("campaign_nonce") != prior_nonce
        or scope.get("launch_claim_sha256") != predecessor_launch_claim_sha256
        or scope.get("candidate_commit") != prior_candidate.get("commit")
        or scope.get("candidate_tree") != prior_candidate.get("tree")
        or scope.get("terminal_evidence_sha256") != failure.get("evidence_sha256")
        or not _is_hash(scope.get("previous_state_sha256"))
        or _parse_utc(scope.get("reserved_at")) is None
        or _parse_utc(scope.get("updated_at")) is None
    ):
        errors.append("authorization-predecessor-v10-scope-state-binding-invalid")

    preflight_fields = {
        "active_outer_registry_sha256",
        "allocation_intents",
        "authorization_and_preallocation_fault_proof_valid",
        "authorization_id",
        "authorization_version",
        "bound_manifest_validation_sha256",
        "campaign_artifacts_created",
        "campaign_claim_created",
        "campaign_nonce",
        "candidate_commit",
        "candidate_tree",
        "canonical_preflight_sha256",
        "current_authorization_marker_absent",
        "current_nonce_marker_absent",
        "current_pair_claim_absent",
        "declared_outputs_absent",
        "exact_spark_available",
        "generation10_base_input_count",
        "generation10_contained_scope_snapshot_exact",
        "glm_5_2_used",
        "guarded_primary_diff_sha256",
        "immediate_predecessor_leaf_count",
        "input_count",
        "input_inodes_unique",
        "input_paths_unique",
        "input_source_identities_captured",
        "launch_claim_sha256",
        "launch_claim_version",
        "live_campaign_authorized",
        "manifest_and_launch_bindings_valid",
        "manifest_version",
        "model_discovery",
        "model_synthesis_used",
        "protected_workspace_rechecked",
        "recorded_at",
        "release_authorized",
        "release_prospective_tree",
        "schema",
        "sessions_created",
        "source_snapshots_rechecked",
        "steering_dry_run_consumptions_planned",
        "steering_launch_bindings_valid",
        "successful_turn_starts_exact",
        "thread_start_requests",
        "trusted_session_snapshots_rechecked",
        "validator_contract_sha256_v5",
    }
    preflight_value = _strict(
        preflight,
        preflight_fields,
        "authorization-predecessor-v10-preflight",
        errors,
    )
    preflight_unsigned = dict(preflight_value)
    preflight_canonical = preflight_unsigned.pop("canonical_preflight_sha256", None)
    model_discovery = (
        preflight.get("model_discovery")
        if isinstance(preflight.get("model_discovery"), Mapping)
        else {}
    )
    if (
        proof.preflight.raw_sha256
        != bindings.get("predecessor_preflight_file_sha256")
        or preflight_canonical
        != bindings.get("predecessor_preflight_canonical_sha256")
        or preflight_canonical != canonical_sha256(preflight_unsigned)
        or preflight.get("schema")
        != "cwo-generation11-live-zero-allocation-preflight:v1"
        or preflight.get("authorization_id") != prior_id
        or preflight.get("authorization_version") != AUTHORIZATION_VERSION_V10
        or preflight.get("manifest_version") != MANIFEST_VERSION_V7
        or preflight.get("launch_claim_version") != 5
        or preflight.get("campaign_nonce") != prior_nonce
        or preflight.get("candidate_commit") != prior_candidate.get("commit")
        or preflight.get("candidate_tree") != prior_candidate.get("tree")
        or preflight.get("guarded_primary_diff_sha256")
        != prior_bindings.get("guarded_primary_diff_sha256")
        or preflight.get("launch_claim_sha256")
        != predecessor_launch_claim_sha256
        or preflight.get("validator_contract_sha256_v5")
        != prior_bindings.get("validator_contract_sha256")
        or preflight.get("generation10_base_input_count") != 81
        or preflight.get("immediate_predecessor_leaf_count") != 17
        or preflight.get("input_count") != 98
        or preflight.get("input_source_identities_captured") != 98
        or preflight.get("allocation_intents") != 0
        or preflight.get("thread_start_requests") != 0
        or preflight.get("sessions_created") != 0
        or preflight.get("campaign_claim_created") is not False
        or preflight.get("campaign_artifacts_created") is not False
        or preflight.get("release_authorized") is not False
        or preflight.get("glm_5_2_used") is not False
        or preflight.get("model_synthesis_used") is not False
        or preflight.get("steering_dry_run_consumptions_planned")
        != ["pre-live", "pre-mutation"]
        or any(
            preflight.get(field) is not True
            for field in (
                "authorization_and_preallocation_fault_proof_valid",
                "current_authorization_marker_absent",
                "current_nonce_marker_absent",
                "current_pair_claim_absent",
                "declared_outputs_absent",
                "exact_spark_available",
                "generation10_contained_scope_snapshot_exact",
                "input_inodes_unique",
                "input_paths_unique",
                "live_campaign_authorized",
                "manifest_and_launch_bindings_valid",
                "protected_workspace_rechecked",
                "source_snapshots_rechecked",
                "steering_launch_bindings_valid",
                "trusted_session_snapshots_rechecked",
            )
        )
        or model_discovery.get("id") != EXACT_OPERATIVE_MODEL
        or model_discovery.get("model") != EXACT_OPERATIVE_MODEL
    ):
        errors.append("authorization-predecessor-v10-preflight-binding-invalid")

    for label, receipt_snapshot, gate in (
        ("pre_mutation", proof.pre_mutation_receipt, "pre-mutation"),
        ("pre_live", proof.pre_live_receipt, "pre-live"),
    ):
        receipt = receipt_snapshot.value
        if (
            validate_steering_receipt(receipt, require_accepting=True)
            or receipt_snapshot.raw_sha256
            != bindings.get(f"predecessor_{label}_receipt_file_sha256")
            or receipt.get("canonical_receipt_sha256")
            != bindings.get(f"predecessor_{label}_receipt_canonical_sha256")
            or receipt.get("gate") != gate
            or receipt.get("authorization_id") != prior_id
            or receipt.get("authorization_sha256") != prior_raw
        ):
            errors.append(
                f"authorization-predecessor-v10-{label.replace('_', '-')}-receipt-binding-invalid"
            )
    generation11_failure_bindings = (
        failure.get("campaign_bindings")
        if isinstance(failure.get("campaign_bindings"), Mapping)
        else {}
    )
    generation11_source_hashes = (
        generation11_failure_bindings.get("source_file_sha256s")
        if isinstance(
            generation11_failure_bindings.get("source_file_sha256s"), Mapping
        )
        else {}
    )
    for label, adjudication_snapshot, receipt_snapshot, gate in (
        (
            "pre_mutation",
            proof.pre_mutation_adjudication,
            proof.pre_mutation_receipt,
            "pre-mutation",
        ),
        (
            "pre_live",
            proof.pre_live_adjudication,
            proof.pre_live_receipt,
            "pre-live",
        ),
    ):
        errors.extend(
            _validate_generation11_steering_adjudication(
                adjudication_snapshot,
                gate=gate,
                authorization=prior_authorization,
                manifest=prior_manifest,
                receipt=receipt_snapshot,
                source_hashes=generation11_source_hashes,
            )
        )
        if (
            adjudication_snapshot.raw_sha256
            != bindings.get(f"predecessor_{label}_adjudication_file_sha256")
            or adjudication_snapshot.value.get("canonical_adjudication_sha256")
            != bindings.get(
                f"predecessor_{label}_adjudication_canonical_sha256"
            )
            or adjudication_snapshot.value.get(
                "spark_validation_receipt_file_sha256"
            )
            != proof.independent_validation_receipt.raw_sha256
            or adjudication_snapshot.value.get(
                "spark_validation_receipt_canonical_sha256"
            )
            != proof.independent_validation_receipt.value.get(
                "canonical_receipt_sha256"
            )
        ):
            errors.append(
                f"authorization-predecessor-v10-{label.replace('_', '-')}-adjudication-direct-binding-invalid"
            )
    consumed = registry.get("consumed")
    consumed = consumed if isinstance(consumed, list) else []
    expected_receipt_hashes = [
        proof.pre_mutation_receipt.value.get("canonical_receipt_sha256"),
        proof.pre_live_receipt.value.get("canonical_receipt_sha256"),
    ]
    consumption_hashes = [
        item.get("consumption_sha256")
        for item in consumed
        if isinstance(item, Mapping)
    ]
    if (
        set(registry) != {"consumed"}
        or proof.steering_registry.raw_sha256
        != bindings.get("predecessor_steering_registry_file_sha256")
        or len(consumed) != 2
        or any(
            not isinstance(item, Mapping)
            or set(item)
            != {"consumption_sha256", "phase_nonce", "receipt_sha256"}
            or not _is_hash(item.get("consumption_sha256"))
            or not _is_uuid(item.get("phase_nonce"))
            for item in consumed
        )
        or [item.get("receipt_sha256") for item in consumed]
        != expected_receipt_hashes
        or failure.get("steering_consumptions")
        != {
            "pre-mutation": consumption_hashes[0] if len(consumption_hashes) > 0 else None,
            "pre-live": consumption_hashes[1] if len(consumption_hashes) > 1 else None,
        }
    ):
        errors.append("authorization-predecessor-v10-steering-consumption-invalid")

    try:
        ledger_errors = validate_live_allocation_ledger(
            ledger, audit_bytes=proof.allocation_audit_bytes
        )
        ledger_summary = {
            "available": True,
            **summarize_live_allocation_ledger(
                ledger, ledger_file_sha256=proof.allocation_ledger.raw_sha256
            ),
        }
    except (NativeLiveAllocationLedgerError, OSError, SystemExit, ValueError):
        ledger_errors = ["ledger-audit-unavailable"]
        ledger_summary = None
    entries = ledger.get("entries")
    observed_grammar = (
        tuple(
            (item.get("role"), item.get("event"), item.get("outcome"))
            for item in entries
            if isinstance(item, Mapping)
        )
        if isinstance(entries, list)
        else ()
    )
    if (
        ledger_errors
        or proof.allocation_ledger.raw_sha256
        != bindings.get("predecessor_allocation_ledger_file_sha256")
        or ledger.get("state_sha256")
        != bindings.get("predecessor_allocation_ledger_state_sha256")
        or ledger.get("head_entry_sha256")
        != bindings.get("predecessor_allocation_ledger_head_entry_sha256")
        or hashlib.sha256(proof.allocation_audit_bytes).hexdigest()
        != bindings.get("predecessor_allocation_audit_file_sha256")
        or observed_grammar != GENERATION11_TERMINAL_LEDGER_GRAMMAR
        or ledger.get("sequence") != len(GENERATION11_TERMINAL_LEDGER_GRAMMAR)
        or ledger.get("bindings", {}).get("authorization_id") != prior_id
        or ledger.get("bindings", {}).get("authorization_raw_sha256") != prior_raw
        or ledger.get("bindings", {}).get("campaign_nonce") != prior_nonce
        or ledger.get("bindings", {}).get("live_generation") != 11
    ):
        errors.append("authorization-predecessor-v10-allocation-ledger-invalid")

    expected_containment = {
        "all_contained": True,
        "allocated_count": 1,
        "already_contained_count": 0,
        "ambiguous_count": 0,
        "archived_count": 1,
        "identified_thread_count": 1,
        "interrupted_count": 0,
        "ledger_consistent": True,
        "ledger_error_sha256": [],
        "unresolved_allocation_intent_count": 0,
        "unresolved_turn_intent_count": 0,
    }
    failure_value = _strict(
        failure,
        MODERN_FAILURE_EVIDENCE_FIELDS,
        "authorization-predecessor-v10-failure",
        errors,
    )
    failure_bindings = (
        failure_value.get("campaign_bindings")
        if isinstance(failure_value.get("campaign_bindings"), Mapping)
        else {}
    )
    source_hashes = (
        failure_bindings.get("source_file_sha256s")
        if isinstance(failure_bindings.get("source_file_sha256s"), Mapping)
        else {}
    )
    expected_source_hashes = {
        "authorization": prior_raw,
        "campaign-manifest": proof.manifest.raw_sha256,
        "cause-evidence": proof.authorization_recovery_cause_evidence.raw_sha256,
        "cause-source-analysis": hashlib.sha256(
            proof.authorization_recovery_cause_source_analysis
        ).hexdigest(),
        "outer-authority": proof.outer_authority.raw_sha256,
        "pre-live-steering-receipt": proof.pre_live_receipt.raw_sha256,
        "pre-mutation-steering-receipt": proof.pre_mutation_receipt.raw_sha256,
        "spark-validation-receipt": proof.independent_validation_receipt.raw_sha256,
        "spark-validation-session": hashlib.sha256(
            proof.independent_validation_session_bytes
        ).hexdigest(),
        "preallocation-failed-predecessor-authorization": proof.ancestor.authorization.raw_sha256,
        "preallocation-failed-predecessor-manifest": proof.ancestor.manifest.raw_sha256,
        "preallocation-failed-predecessor-authorization-state": proof.ancestor.authorization_state.raw_sha256,
        "preallocation-failed-predecessor-failure-evidence": proof.ancestor.failure_evidence.raw_sha256,
        "preallocation-failed-predecessor-containment": proof.ancestor.containment.raw_sha256,
        "preallocation-failed-predecessor-global-claim": proof.ancestor.global_claim.raw_sha256,
        "preallocation-failed-predecessor-authorization-marker": proof.ancestor.authorization_marker.raw_sha256,
        "preallocation-failed-predecessor-nonce-marker": proof.ancestor.nonce_marker.raw_sha256,
        "preallocation-failed-predecessor-scope-state": proof.ancestor.scope_state.raw_sha256,
        "preallocation-failed-predecessor-preflight": proof.ancestor.preflight.raw_sha256,
        "preallocation-failed-predecessor-pre-mutation-receipt": proof.ancestor.pre_mutation_receipt.raw_sha256,
        "preallocation-failed-predecessor-pre-live-receipt": proof.ancestor.pre_live_receipt.raw_sha256,
        "preallocation-failed-predecessor-recovery-cause-evidence": proof.ancestor.authorization_recovery_cause_evidence.raw_sha256,
        "preallocation-failed-predecessor-recovery-cause-source-analysis": hashlib.sha256(
            proof.ancestor.authorization_recovery_cause_source_analysis
        ).hexdigest(),
        "preallocation-failed-predecessor-outer-authority": proof.ancestor.outer_authority.raw_sha256,
        "preallocation-failed-predecessor-independent-validation-receipt": proof.ancestor.independent_validation_receipt.raw_sha256,
        "preallocation-failed-predecessor-independent-validation-session": hashlib.sha256(
            proof.ancestor.independent_validation_session_bytes
        ).hexdigest(),
    }
    if (
        proof.failure_evidence.raw_sha256
        != bindings.get("predecessor_failure_evidence_file_sha256")
        or failure.get("evidence_sha256")
        != bindings.get("predecessor_failure_evidence_canonical_sha256")
        or failure.get("evidence_sha256")
        != _canonical_artifact_hash(failure, "evidence_sha256")
        or failure.get("result_type")
        != "cwo-native-supervision-pool-live-canary-failure"
        or failure.get("version") != 1
        or failure.get("failure_class") != "AppServerError"
        or failure.get("failure_code") != "AppServerError"
        or failure.get("failure_message_sha256")
        != GENERATION11_FAILURE_MESSAGE_SHA256
        or failure.get("first_protected_fault") is not None
        or failure.get("exact_model") != EXACT_OPERATIVE_MODEL
        or failure.get("containment") != expected_containment
        or failure.get("allocation_ledger") != ledger_summary
        or failure.get("authorization_state_sha256") != prior_state.get("state_sha256")
        or failure.get("validation_outcome") != "rejected"
        or failure.get("release_gate_passed") is not False
        or failure.get("no_resume_or_salvage") is not True
        or failure.get("glm_5_2_used") is not False
        or failure.get("model_synthesis_used") is not False
        or failure.get("bead_id") != prior_work_units.get("epic_id")
        or failure.get("work_unit_id") != prior_work_units.get("live_work_unit_id")
        or failure.get("control_turn_id") != prior_manifest.get("control_turn_id")
        or failure_bindings.get("authorization_raw_sha256") != prior_raw
        or failure_bindings.get("manifest_file_sha256") != proof.manifest.raw_sha256
        or failure_bindings.get("manifest_sha256")
        != prior_manifest.get("manifest_sha256")
        or failure_bindings.get("candidate_commit") != prior_candidate.get("commit")
        or failure_bindings.get("candidate_tree") != prior_candidate.get("tree")
        or failure_bindings.get("launch_claim_sha256")
        != predecessor_launch_claim_sha256
        or failure_bindings.get("outer_authority_file_sha256")
        != proof.outer_authority.raw_sha256
        or failure_bindings.get("spark_validation_receipt_file_sha256")
        != proof.independent_validation_receipt.raw_sha256
        or failure_bindings.get("spark_validation_session_file_sha256")
        != hashlib.sha256(proof.independent_validation_session_bytes).hexdigest()
        or failure_bindings.get("recovery_cause_evidence_file_sha256")
        != proof.authorization_recovery_cause_evidence.raw_sha256
        or failure_bindings.get("recovery_cause_source_analysis_file_sha256")
        != hashlib.sha256(
            proof.authorization_recovery_cause_source_analysis
        ).hexdigest()
        or failure_bindings.get("validator_contract_sha256")
        != prior_bindings.get("validator_contract_sha256")
        or any(source_hashes.get(key) != value for key, value in expected_source_hashes.items())
    ):
        errors.append("authorization-predecessor-v10-failure-binding-invalid")

    errors.extend(
        _validate_generation11_recovery_steering(
            proof.recovery_steering_receipt,
            proof.recovery_steering_session_bytes,
            bindings=bindings,
            authorization=prior_authorization,
            manifest=prior_manifest,
            expected_control_turn_id=proof.pre_mutation_receipt.value.get(
                "control_turn_id"
            ),
        )
    )
    errors.extend(
        _validate_generation11_terminal_facts(
            proof.terminal_facts,
            bindings=bindings,
            proof=proof,
            authorization=prior_authorization,
            manifest=prior_manifest,
            failure=failure,
            repo_root=repo_root,
        )
    )
    errors.extend(
        _validate_generation11_containment(
            proof.containment,
            bindings=bindings,
            prior_authorization=prior_authorization,
            prior_manifest=prior_manifest,
            failure=failure,
            proof=proof,
            ledger_summary=ledger_summary,
            expected_containment=expected_containment,
        )
    )

    if (
        supersession.get("prior_authorization_id") != prior_id
        or supersession.get("prior_terminal_state") != "containment-only"
        or supersession.get("prior_live_generation") != 11
        or supersession.get("prior_allocations") != 1
        or supersession.get("prior_ambiguities") != 0
        or supersession.get("prior_allowed_actions")
        != (len(allowed_actions) if isinstance(allowed_actions, list) else -1)
        or supersession.get("reuse_resume_retry_substitution_salvage_bridge")
        is not False
    ):
        errors.append("authorization-predecessor-v10-supersession-invalid")
    if (
        proof.outer_authority.raw_sha256
        != bindings.get("predecessor_outer_authority_file_sha256")
        or proof.outer_authority.value.get("canonical_outer_authority_sha256")
        != bindings.get("predecessor_outer_authority_canonical_sha256")
        or proof.outer_authority.raw_sha256
        != prior_bindings.get("outer_authority_file_sha256")
        or proof.independent_validation_receipt.raw_sha256
        != bindings.get("predecessor_independent_validation_receipt_file_sha256")
        or proof.independent_validation_receipt.value.get("canonical_receipt_sha256")
        != bindings.get("predecessor_independent_validation_receipt_canonical_sha256")
        or hashlib.sha256(proof.independent_validation_session_bytes).hexdigest()
        != bindings.get("predecessor_independent_validation_session_file_sha256")
        or proof.authorization_recovery_cause_evidence.raw_sha256
        != bindings.get(
            "predecessor_authorization_recovery_cause_evidence_file_sha256"
        )
        or proof.authorization_recovery_cause_evidence.value.get(
            "canonical_cause_evidence_sha256"
        )
        != bindings.get(
            "predecessor_authorization_recovery_cause_evidence_canonical_sha256"
        )
        or hashlib.sha256(
            proof.authorization_recovery_cause_source_analysis
        ).hexdigest()
        != bindings.get(
            "predecessor_authorization_recovery_cause_source_analysis_sha256"
        )
        or proof.terminal_facts.raw_sha256
        != bindings.get("predecessor_terminal_facts_file_sha256")
        or proof.terminal_facts.value.get("canonical_terminal_facts_sha256")
        != bindings.get("predecessor_terminal_facts_canonical_sha256")
        or hashlib.sha256(proof.generation11_runner_source_bytes).hexdigest()
        != bindings.get("predecessor_generation11_runner_source_sha256")
        or hashlib.sha256(
            proof.generation11_session_boundary_source_bytes
        ).hexdigest()
        != bindings.get(
            "predecessor_generation11_session_boundary_source_sha256"
        )
        or proof.pre_mutation_adjudication.raw_sha256
        != bindings.get("predecessor_pre_mutation_adjudication_file_sha256")
        or proof.pre_mutation_adjudication.value.get(
            "canonical_adjudication_sha256"
        )
        != bindings.get("predecessor_pre_mutation_adjudication_canonical_sha256")
        or proof.pre_live_adjudication.raw_sha256
        != bindings.get("predecessor_pre_live_adjudication_file_sha256")
        or proof.pre_live_adjudication.value.get("canonical_adjudication_sha256")
        != bindings.get("predecessor_pre_live_adjudication_canonical_sha256")
        or hashlib.sha256(proof.recovery_cause_analysis_bytes).hexdigest()
        != bindings.get("predecessor_recovery_cause_analysis_sha256")
        or proof.recovery_steering_receipt.raw_sha256
        != bindings.get("predecessor_recovery_steering_receipt_file_sha256")
        or proof.recovery_steering_receipt.value.get("canonical_receipt_sha256")
        != bindings.get(
            "predecessor_recovery_steering_receipt_canonical_sha256"
        )
        or hashlib.sha256(proof.recovery_steering_session_bytes).hexdigest()
        != bindings.get("predecessor_recovery_steering_session_file_sha256")
    ):
        errors.append("authorization-predecessor-v10-direct-source-binding-invalid")
    if (
        prior_progress.get("predecessor_lineage_sha256")
        != bindings.get("predecessor_ancestor_lineage_sha256")
    ):
        errors.append("authorization-predecessor-v10-ancestor-lineage-invalid")

    if repo_root is not None:
        root = Path(repo_root).resolve()
        errors.extend(
            f"authorization-predecessor-v10-ancestor:{item}"
            for item in _validate_v9_preallocation_fault_predecessor_proof(
                bindings=prior_bindings,
                progress=prior_progress,
                supersession=prior_supersession,
                predecessor_live_generation=_generation_or_invalid(
                    prior_authorization.get("predecessor_live_generation")
                ),
                proof=proof.ancestor,
                repo_root=root,
            )
        )
        try:
            prior_checkpoint = str(prior_bindings["checkpoint_commit"])
            current_checkpoint = str(bindings["checkpoint_commit"])
            if (
                _run_git(root, "rev-parse", f"{prior_checkpoint}^{{tree}}")
                != prior_bindings.get("checkpoint_tree")
                or _run_git(
                    root, "rev-parse", f"{prior_candidate.get('commit')}^{{tree}}"
                )
                != prior_candidate.get("tree")
                or _run_git(root, "rev-parse", f"{current_checkpoint}^{{tree}}")
                != bindings.get("checkpoint_tree")
            ):
                errors.append("authorization-predecessor-v10-anchor-tree-mismatch")
            for ancestor_commit, descendant_commit in (
                (str(prior_candidate.get("commit")), prior_checkpoint),
                (prior_checkpoint, current_checkpoint),
            ):
                if subprocess.run(
                    ["git", "merge-base", "--is-ancestor", ancestor_commit, descendant_commit],
                    cwd=root,
                    capture_output=True,
                ).returncode != 0:
                    errors.append("authorization-predecessor-v10-anchor-lineage-invalid")
            if (
                prior_bindings.get("origin_main_commit")
                != bindings.get("origin_main_commit")
                or _run_git(root, "rev-parse", "origin/main")
                != bindings.get("origin_main_commit")
                or prior_bindings.get("validator_contract_sha256")
                != validator_contract_sha256_v5(
                    root, prior_bindings.get("checkpoint_tree")
                )
            ):
                errors.append("authorization-predecessor-v10-anchor-binding-invalid")
        except (KeyError, subprocess.CalledProcessError, ValueError):
            errors.append("authorization-predecessor-v10-anchor-invalid")
    return sorted(set(errors))


def _v4_common_shadow(
    manifest: Mapping[str, Any], authorization: Mapping[str, Any]
) -> tuple[dict[str, Any], dict[str, Any], str]:
    """Project v4/v7 common fields into the frozen v2/v5 validators."""

    shadow_authorization = _v7_common_shadow(authorization)
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


def _validate_campaign_manifest_v4(
    value: Any,
    *,
    authorization: Mapping[str, Any] | None,
    authorization_raw_sha256: str | None,
    outer_authority: Mapping[str, Any] | None,
    outer_authority_raw_sha256: str | None,
    predecessor_proof: Version6PredecessorProofInputs | None,
    recovery_cause_evidence: JsonArtifactSnapshot | None,
    recovery_cause_source_analysis: bytes | None,
    independent_validation_receipt: Mapping[str, Any] | None,
    independent_validation_receipt_raw_sha256: str | None,
    expected_validator_contract_sha256: str | None,
    repo_root: Path | None,
    expected_primary_diff_sha256: str | None,
) -> list[str]:
    errors: list[str] = []
    manifest = _strict(value, MANIFEST_FIELDS, "campaign-manifest-v4", errors)
    if not manifest:
        return sorted(set(errors))
    if (
        manifest.get("manifest_type") != MANIFEST_TYPE
        or manifest.get("version") != MANIFEST_VERSION_V4
        or manifest.get("schema") != MANIFEST_SCHEMA_V4
    ):
        errors.append("campaign-manifest-v4-header-invalid")
    unsigned = dict(manifest)
    unsigned.pop("manifest_sha256", None)
    if manifest.get("manifest_sha256") != canonical_sha256(unsigned):
        errors.append("campaign-manifest-v4-sha256-mismatch")
    if not isinstance(authorization, Mapping):
        return sorted(set(errors + ["campaign-manifest-v4-authorization-missing"]))

    shadow, shadow_authorization, shadow_authorization_raw_sha256 = _v4_common_shadow(
        manifest, authorization
    )
    errors.extend(
        f"campaign-manifest-v4-common:{item}"
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
        f"campaign-manifest-v4-authorization:{item}"
        for item in _validate_full_auto_authorization_v7(
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
        errors.append("campaign-manifest-v4-outer-authority-registry-invalid")
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
        MANIFEST_PREDECESSOR_FIELDS_V4,
        "campaign-manifest-v4-predecessor",
        errors,
    )
    if not _is_uuid(predecessor.get("authorization_id")) or any(
        not _is_hash(predecessor.get(field))
        for field in MANIFEST_PREDECESSOR_FIELDS_V4
        - {"authorization_id", "candidate_commit", "candidate_tree"}
    ):
        errors.append("campaign-manifest-v4-predecessor-invalid")
    if any(
        not _is_commit(predecessor.get(field))
        for field in ("candidate_commit", "candidate_tree")
    ):
        errors.append("campaign-manifest-v4-predecessor-invalid")
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
        errors.append("campaign-manifest-v4-predecessor-authorization-mismatch")
    if (
        manifest.get("authorization_id") != authorization.get("authorization_id")
        or manifest.get("authorization_raw_sha256") != authorization_raw_sha256
        or manifest.get("authorization_canonical_sha256")
        != authorization.get("canonical_authorization_sha256")
        or manifest.get("progress_qualification_sha256")
        != progress.get("qualification_sha256")
    ):
        errors.append("campaign-manifest-v4-authorization-binding-mismatch")
    return sorted(set(errors))


def _v5_common_shadow(
    manifest: Mapping[str, Any], authorization: Mapping[str, Any]
) -> tuple[dict[str, Any], dict[str, Any], str]:
    """Project v5/v8 common fields into the frozen v2/v5 validators."""

    shadow_authorization = _v8_common_shadow(authorization)
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
    for field in MANIFEST_PREDECESSOR_FIELDS_V5 - MANIFEST_PREDECESSOR_FIELDS_V4:
        predecessor.pop(field, None)
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


def _validate_campaign_manifest_v5(
    value: Any,
    *,
    authorization: Mapping[str, Any] | None,
    authorization_raw_sha256: str | None,
    outer_authority: Mapping[str, Any] | None,
    outer_authority_raw_sha256: str | None,
    predecessor_proof: Version7QuarantinePredecessorProofInputs | None,
    recovery_cause_evidence: JsonArtifactSnapshot | None,
    recovery_cause_source_analysis: bytes | None,
    independent_validation_receipt: Mapping[str, Any] | None,
    independent_validation_receipt_raw_sha256: str | None,
    expected_validator_contract_sha256: str | None,
    repo_root: Path | None,
    expected_primary_diff_sha256: str | None,
) -> list[str]:
    errors: list[str] = []
    manifest = _strict(value, MANIFEST_FIELDS, "campaign-manifest-v5", errors)
    if not manifest:
        return sorted(set(errors))
    if (
        manifest.get("manifest_type") != MANIFEST_TYPE
        or manifest.get("version") != MANIFEST_VERSION_V5
        or manifest.get("schema") != MANIFEST_SCHEMA_V5
    ):
        errors.append("campaign-manifest-v5-header-invalid")
    unsigned = dict(manifest)
    unsigned.pop("manifest_sha256", None)
    if manifest.get("manifest_sha256") != canonical_sha256(unsigned):
        errors.append("campaign-manifest-v5-sha256-mismatch")
    if not isinstance(authorization, Mapping):
        return sorted(set(errors + ["campaign-manifest-v5-authorization-missing"]))

    shadow, shadow_authorization, shadow_authorization_raw_sha256 = (
        _v5_common_shadow(manifest, authorization)
    )
    errors.extend(
        f"campaign-manifest-v5-common:{item}"
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
        f"campaign-manifest-v5-authorization:{item}"
        for item in _validate_full_auto_authorization_v8(
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
        errors.append("campaign-manifest-v5-outer-authority-registry-invalid")
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
        MANIFEST_PREDECESSOR_FIELDS_V5,
        "campaign-manifest-v5-predecessor",
        errors,
    )
    if not _is_uuid(predecessor.get("authorization_id")) or any(
        not _is_hash(predecessor.get(field))
        for field in MANIFEST_PREDECESSOR_FIELDS_V5
        - {"authorization_id", "candidate_commit", "candidate_tree"}
    ):
        errors.append("campaign-manifest-v5-predecessor-invalid")
    if any(
        not _is_commit(predecessor.get(field))
        for field in ("candidate_commit", "candidate_tree")
    ):
        errors.append("campaign-manifest-v5-predecessor-invalid")
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
        "failure_ledger_prefix_file_sha256": bindings.get(
            "predecessor_failure_ledger_prefix_file_sha256"
        ),
        "failure_ledger_prefix_state_sha256": bindings.get(
            "predecessor_failure_ledger_prefix_state_sha256"
        ),
        "failure_ledger_prefix_head_entry_sha256": bindings.get(
            "predecessor_failure_ledger_prefix_head_entry_sha256"
        ),
        "quarantined_session_file_sha256": bindings.get(
            "predecessor_quarantined_session_file_sha256"
        ),
    }
    if predecessor != expected_predecessor:
        errors.append("campaign-manifest-v5-predecessor-authorization-mismatch")
    if (
        manifest.get("authorization_id") != authorization.get("authorization_id")
        or manifest.get("authorization_raw_sha256") != authorization_raw_sha256
        or manifest.get("authorization_canonical_sha256")
        != authorization.get("canonical_authorization_sha256")
        or manifest.get("progress_qualification_sha256")
        != progress.get("qualification_sha256")
    ):
        errors.append("campaign-manifest-v5-authorization-binding-mismatch")
    return sorted(set(errors))


def _v6_manifest_common_shadow(
    manifest: Mapping[str, Any], authorization: Mapping[str, Any]
) -> tuple[dict[str, Any], dict[str, Any], str]:
    """Project v6/v9 common fields into the frozen v2/v5 validators."""

    shadow_authorization = _v9_common_shadow(authorization)
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
    predecessor = (
        dict(shadow.get("predecessor"))
        if isinstance(shadow.get("predecessor"), Mapping)
        else {}
    )
    shadow["predecessor"] = predecessor
    for field in MANIFEST_PREDECESSOR_FIELDS_V6 - MANIFEST_PREDECESSOR_FIELDS_V4:
        predecessor.pop(field, None)
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


def _validate_campaign_manifest_v6(
    value: Any,
    *,
    authorization: Mapping[str, Any] | None,
    authorization_raw_sha256: str | None,
    outer_authority: Mapping[str, Any] | None,
    outer_authority_raw_sha256: str | None,
    predecessor_proof: Version8ProtectedFaultPredecessorProofInputs | None,
    recovery_cause_evidence: JsonArtifactSnapshot | None,
    recovery_cause_source_analysis: bytes | None,
    independent_validation_receipt: Mapping[str, Any] | None,
    independent_validation_receipt_raw_sha256: str | None,
    expected_validator_contract_sha256: str | None,
    repo_root: Path | None,
    expected_primary_diff_sha256: str | None,
) -> list[str]:
    errors: list[str] = []
    manifest = _strict(value, MANIFEST_FIELDS, "campaign-manifest-v6", errors)
    if not manifest:
        return sorted(set(errors))
    if (
        manifest.get("manifest_type") != MANIFEST_TYPE
        or manifest.get("version") != MANIFEST_VERSION_V6
        or manifest.get("schema") != MANIFEST_SCHEMA_V6
    ):
        errors.append("campaign-manifest-v6-header-invalid")
    unsigned = dict(manifest)
    unsigned.pop("manifest_sha256", None)
    if manifest.get("manifest_sha256") != canonical_sha256(unsigned):
        errors.append("campaign-manifest-v6-sha256-mismatch")
    if not isinstance(authorization, Mapping):
        return sorted(set(errors + ["campaign-manifest-v6-authorization-missing"]))

    shadow, shadow_authorization, shadow_authorization_raw_sha256 = (
        _v6_manifest_common_shadow(manifest, authorization)
    )
    errors.extend(
        f"campaign-manifest-v6-common:{item}"
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
        f"campaign-manifest-v6-authorization:{item}"
        for item in _validate_full_auto_authorization_v9(
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
        or registry.get("contract") != "cwo-active-outer-authority-registry:v1"
        or registry.get("scope_key") != expected_scope_key
    ):
        errors.append("campaign-manifest-v6-outer-authority-registry-invalid")
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
        MANIFEST_PREDECESSOR_FIELDS_V6,
        "campaign-manifest-v6-predecessor",
        errors,
    )
    non_hash_fields = {
        "authorization_id",
        "candidate_commit",
        "candidate_tree",
        "contained_session_count",
    }
    if not _is_uuid(predecessor.get("authorization_id")) or any(
        not _is_hash(predecessor.get(field))
        for field in MANIFEST_PREDECESSOR_FIELDS_V6 - non_hash_fields
    ):
        errors.append("campaign-manifest-v6-predecessor-invalid")
    if any(
        not _is_commit(predecessor.get(field))
        for field in ("candidate_commit", "candidate_tree")
    ) or predecessor.get("contained_session_count") != 5:
        errors.append("campaign-manifest-v6-predecessor-invalid")
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
        "contained_session_family_sha256": bindings.get(
            "predecessor_contained_session_family_sha256"
        ),
        "contained_session_count": bindings.get(
            "predecessor_contained_session_count"
        ),
    }
    if predecessor != expected_predecessor:
        errors.append("campaign-manifest-v6-predecessor-authorization-mismatch")
    if (
        manifest.get("authorization_id") != authorization.get("authorization_id")
        or manifest.get("authorization_raw_sha256") != authorization_raw_sha256
        or manifest.get("authorization_canonical_sha256")
        != authorization.get("canonical_authorization_sha256")
        or manifest.get("progress_qualification_sha256")
        != progress.get("qualification_sha256")
    ):
        errors.append("campaign-manifest-v6-authorization-binding-mismatch")
    return sorted(set(errors))


def _v7_manifest_common_shadow(
    manifest: Mapping[str, Any], authorization: Mapping[str, Any]
) -> tuple[dict[str, Any], dict[str, Any], str]:
    """Project v7/v10 common fields into the frozen v2/v5 validators."""

    shadow_authorization = _v10_common_shadow(authorization)
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
    predecessor = (
        dict(shadow.get("predecessor"))
        if isinstance(shadow.get("predecessor"), Mapping)
        else {}
    )
    shadow["predecessor"] = predecessor
    predecessor["allocation_ledger_file_sha256"] = predecessor.get(
        "global_claim_file_sha256"
    )
    predecessor["allocation_ledger_state_sha256"] = predecessor.get(
        "scope_state_canonical_sha256"
    )
    predecessor["allocation_audit_file_sha256"] = predecessor.get(
        "authorization_marker_file_sha256"
    )
    for field in MANIFEST_PREDECESSOR_FIELDS_V7 - MANIFEST_PREDECESSOR_FIELDS_V4:
        predecessor.pop(field, None)
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


def _validate_campaign_manifest_v7(
    value: Any,
    *,
    authorization: Mapping[str, Any] | None,
    authorization_raw_sha256: str | None,
    outer_authority: Mapping[str, Any] | None,
    outer_authority_raw_sha256: str | None,
    predecessor_proof: Version9PreallocationFaultPredecessorProofInputs | None,
    recovery_cause_evidence: JsonArtifactSnapshot | None,
    recovery_cause_source_analysis: bytes | None,
    independent_validation_receipt: Mapping[str, Any] | None,
    independent_validation_receipt_raw_sha256: str | None,
    expected_validator_contract_sha256: str | None,
    repo_root: Path | None,
    expected_primary_diff_sha256: str | None,
) -> list[str]:
    errors: list[str] = []
    manifest = _strict(value, MANIFEST_FIELDS, "campaign-manifest-v7", errors)
    if not manifest:
        return sorted(set(errors))
    if (
        manifest.get("manifest_type") != MANIFEST_TYPE
        or manifest.get("version") != MANIFEST_VERSION_V7
        or manifest.get("schema") != MANIFEST_SCHEMA_V7
    ):
        errors.append("campaign-manifest-v7-header-invalid")
    unsigned = dict(manifest)
    unsigned.pop("manifest_sha256", None)
    if manifest.get("manifest_sha256") != canonical_sha256(unsigned):
        errors.append("campaign-manifest-v7-sha256-mismatch")
    if not isinstance(authorization, Mapping):
        return sorted(set(errors + ["campaign-manifest-v7-authorization-missing"]))
    shadow, shadow_authorization, shadow_authorization_raw_sha256 = (
        _v7_manifest_common_shadow(manifest, authorization)
    )
    errors.extend(
        f"campaign-manifest-v7-common:{item}"
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
        f"campaign-manifest-v7-authorization:{item}"
        for item in _validate_full_auto_authorization_v10(
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
    try:
        expected_scope_key = active_outer_authority_scope_key(
            work_units.get("epic_id"), work_units.get("parent_work_unit_id")
        )
    except ValueError:
        expected_scope_key = None
    if (
        not isinstance(registry, Mapping)
        or set(registry) != {"contract", "scope_key"}
        or registry.get("contract") != "cwo-active-outer-authority-registry:v1"
        or registry.get("scope_key") != expected_scope_key
    ):
        errors.append("campaign-manifest-v7-outer-authority-registry-invalid")
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
        MANIFEST_PREDECESSOR_FIELDS_V7,
        "campaign-manifest-v7-predecessor",
        errors,
    )
    non_hash_fields = {"authorization_id", "candidate_commit", "candidate_tree"}
    if not _is_uuid(predecessor.get("authorization_id")) or any(
        not _is_hash(predecessor.get(field))
        for field in MANIFEST_PREDECESSOR_FIELDS_V7 - non_hash_fields
    ):
        errors.append("campaign-manifest-v7-predecessor-invalid")
    if any(
        not _is_commit(predecessor.get(field))
        for field in ("candidate_commit", "candidate_tree")
    ):
        errors.append("campaign-manifest-v7-predecessor-invalid")
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
        "ancestor_lineage_sha256": bindings.get(
            "predecessor_ancestor_lineage_sha256"
        ),
        "validator_contract_sha256": bindings.get("validator_contract_sha256"),
        **{
            field.removeprefix("predecessor_"): bindings.get(field)
            for field in BINDING_FIELDS_V10 - BINDING_FIELDS_V7
        },
    }
    if predecessor != expected_predecessor:
        errors.append("campaign-manifest-v7-predecessor-authorization-mismatch")
    if (
        manifest.get("authorization_id") != authorization.get("authorization_id")
        or manifest.get("authorization_raw_sha256") != authorization_raw_sha256
        or manifest.get("authorization_canonical_sha256")
        != authorization.get("canonical_authorization_sha256")
        or manifest.get("progress_qualification_sha256")
        != progress.get("qualification_sha256")
    ):
        errors.append("campaign-manifest-v7-authorization-binding-mismatch")
    return sorted(set(errors))


def _v8_manifest_common_shadow(
    manifest: Mapping[str, Any], authorization: Mapping[str, Any]
) -> tuple[dict[str, Any], dict[str, Any], str]:
    """Project v8/v11 common fields into the frozen v2/v5 validators."""

    shadow_authorization = _v11_common_shadow(authorization)
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
    predecessor = (
        dict(shadow.get("predecessor"))
        if isinstance(shadow.get("predecessor"), Mapping)
        else {}
    )
    shadow["predecessor"] = predecessor
    for field in MANIFEST_PREDECESSOR_FIELDS_V8 - MANIFEST_PREDECESSOR_FIELDS_V4:
        predecessor.pop(field, None)
    shadow_bindings = shadow_authorization["bindings"]
    # The frozen v2 manifest validator compares these fields to the v5
    # authorization shadow. That authorization shadow deliberately aliases
    # the three legacy ledger slots to Generation-10 preallocation artifacts;
    # project the same aliases only into this deep-copied manifest shadow.
    # The caller-owned v8 manifest retains the actual Generation-11 ledger,
    # state, and audit hashes enforced by the semantic v8 validator below.
    for field in (
        "allocation_ledger_file_sha256",
        "allocation_ledger_state_sha256",
        "allocation_audit_file_sha256",
    ):
        predecessor[field] = shadow_bindings[f"predecessor_{field}"]
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


def _validate_campaign_manifest_v8(
    value: Any,
    *,
    authorization: Mapping[str, Any] | None,
    authorization_raw_sha256: str | None,
    outer_authority: Mapping[str, Any] | None,
    outer_authority_raw_sha256: str | None,
    predecessor_proof: (
        Version10InterruptedEmptyBoundaryPredecessorProofInputs | None
    ),
    recovery_cause_evidence: JsonArtifactSnapshot | None,
    recovery_cause_source_analysis: bytes | None,
    independent_validation_receipt: Mapping[str, Any] | None,
    independent_validation_receipt_raw_sha256: str | None,
    expected_validator_contract_sha256: str | None,
    repo_root: Path | None,
    expected_primary_diff_sha256: str | None,
) -> list[str]:
    errors: list[str] = []
    manifest = _strict(value, MANIFEST_FIELDS, "campaign-manifest-v8", errors)
    if not manifest:
        return sorted(set(errors))
    if (
        manifest.get("manifest_type") != MANIFEST_TYPE
        or manifest.get("version") != MANIFEST_VERSION_V8
        or manifest.get("schema") != MANIFEST_SCHEMA_V8
    ):
        errors.append("campaign-manifest-v8-header-invalid")
    unsigned = dict(manifest)
    unsigned.pop("manifest_sha256", None)
    if manifest.get("manifest_sha256") != canonical_sha256(unsigned):
        errors.append("campaign-manifest-v8-sha256-mismatch")
    if not isinstance(authorization, Mapping):
        return sorted(set(errors + ["campaign-manifest-v8-authorization-missing"]))
    try:
        shadow, shadow_authorization, shadow_authorization_raw_sha256 = (
            _v8_manifest_common_shadow(manifest, authorization)
        )
        common_errors = _validate_campaign_manifest_v2(
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
    except (AttributeError, KeyError, TypeError, ValueError):
        common_errors = ["campaign-manifest-v8-common-scalar-invalid"]
    errors.extend(f"campaign-manifest-v8-common:{item}" for item in common_errors)
    errors.extend(
        f"campaign-manifest-v8-authorization:{item}"
        for item in _validate_full_auto_authorization_v11(
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
    try:
        expected_scope_key = active_outer_authority_scope_key(
            work_units.get("epic_id"), work_units.get("parent_work_unit_id")
        )
    except ValueError:
        expected_scope_key = None
    if (
        not isinstance(registry, Mapping)
        or set(registry) != {"contract", "scope_key"}
        or registry.get("contract") != "cwo-active-outer-authority-registry:v1"
        or registry.get("scope_key") != expected_scope_key
    ):
        errors.append("campaign-manifest-v8-outer-authority-registry-invalid")
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
        MANIFEST_PREDECESSOR_FIELDS_V8,
        "campaign-manifest-v8-predecessor",
        errors,
    )
    non_hash_fields = {
        "authorization_id",
        "candidate_commit",
        "candidate_tree",
        "terminal_session_id",
        "terminal_turn_id",
    }
    if (
        not _is_uuid(predecessor.get("authorization_id"))
        or not _is_uuid(predecessor.get("terminal_session_id"))
        or not _is_uuid(predecessor.get("terminal_turn_id"))
        or any(
            not _is_hash(predecessor.get(field))
            for field in MANIFEST_PREDECESSOR_FIELDS_V8 - non_hash_fields
        )
        or any(
            not _is_commit(predecessor.get(field))
            for field in ("candidate_commit", "candidate_tree")
        )
    ):
        errors.append("campaign-manifest-v8-predecessor-invalid")
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
        "ancestor_lineage_sha256": bindings.get(
            "predecessor_ancestor_lineage_sha256"
        ),
        "validator_contract_sha256": bindings.get("validator_contract_sha256"),
        "allocation_ledger_file_sha256": bindings.get(
            "predecessor_allocation_ledger_file_sha256"
        ),
        "allocation_ledger_state_sha256": bindings.get(
            "predecessor_allocation_ledger_state_sha256"
        ),
        "allocation_audit_file_sha256": bindings.get(
            "predecessor_allocation_audit_file_sha256"
        ),
        **{
            field.removeprefix("predecessor_"): bindings.get(field)
            for field in BINDING_FIELDS_V11 - BINDING_FIELDS_V7
        },
    }
    if predecessor != expected_predecessor:
        errors.append("campaign-manifest-v8-predecessor-authorization-mismatch")
    if (
        manifest.get("authorization_id") != authorization.get("authorization_id")
        or manifest.get("authorization_raw_sha256") != authorization_raw_sha256
        or manifest.get("authorization_canonical_sha256")
        != authorization.get("canonical_authorization_sha256")
        or manifest.get("progress_qualification_sha256")
        != progress.get("qualification_sha256")
    ):
        errors.append("campaign-manifest-v8-authorization-binding-mismatch")
    return sorted(set(errors))


def _dispatch_validate_campaign_manifest(
    value: Any,
    *,
    predecessor_proof: (
        Version5PredecessorProofInputs
        | Version6PredecessorProofInputs
        | Version7QuarantinePredecessorProofInputs
        | Version8ProtectedFaultPredecessorProofInputs
        | Version9PreallocationFaultPredecessorProofInputs
        | Version10InterruptedEmptyBoundaryPredecessorProofInputs
        | None
    ) = None,
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
    if version == MANIFEST_VERSION_V4:
        legacy_predecessor_keys = {
            key
            for key, item in legacy_kwargs.items()
            if key.startswith("predecessor_") and item is not None
        }
        if legacy_predecessor_keys:
            return ["campaign-manifest-v4-legacy-proof-input-forbidden"]
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
            return ["campaign-manifest-v4-validator-arguments-invalid"]
        return _validate_campaign_manifest_v4(
            value,
            authorization=legacy_kwargs.get("authorization"),
            authorization_raw_sha256=legacy_kwargs.get(
                "authorization_raw_sha256"
            ),
            outer_authority=legacy_kwargs.get("outer_authority"),
            outer_authority_raw_sha256=legacy_kwargs.get(
                "outer_authority_raw_sha256"
            ),
            predecessor_proof=(
                predecessor_proof
                if isinstance(predecessor_proof, Version6PredecessorProofInputs)
                else None
            ),
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
    if version == MANIFEST_VERSION_V5:
        legacy_predecessor_keys = {
            key
            for key, item in legacy_kwargs.items()
            if key.startswith("predecessor_") and item is not None
        }
        if legacy_predecessor_keys:
            return ["campaign-manifest-v5-legacy-proof-input-forbidden"]
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
            return ["campaign-manifest-v5-validator-arguments-invalid"]
        return _validate_campaign_manifest_v5(
            value,
            authorization=legacy_kwargs.get("authorization"),
            authorization_raw_sha256=legacy_kwargs.get(
                "authorization_raw_sha256"
            ),
            outer_authority=legacy_kwargs.get("outer_authority"),
            outer_authority_raw_sha256=legacy_kwargs.get(
                "outer_authority_raw_sha256"
            ),
            predecessor_proof=(
                predecessor_proof
                if isinstance(
                    predecessor_proof,
                    Version7QuarantinePredecessorProofInputs,
                )
                else None
            ),
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
    if version == MANIFEST_VERSION_V6:
        legacy_predecessor_keys = {
            key
            for key, item in legacy_kwargs.items()
            if key.startswith("predecessor_") and item is not None
        }
        if legacy_predecessor_keys:
            return ["campaign-manifest-v6-legacy-proof-input-forbidden"]
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
            return ["campaign-manifest-v6-validator-arguments-invalid"]
        return _validate_campaign_manifest_v6(
            value,
            authorization=legacy_kwargs.get("authorization"),
            authorization_raw_sha256=legacy_kwargs.get(
                "authorization_raw_sha256"
            ),
            outer_authority=legacy_kwargs.get("outer_authority"),
            outer_authority_raw_sha256=legacy_kwargs.get(
                "outer_authority_raw_sha256"
            ),
            predecessor_proof=(
                predecessor_proof
                if isinstance(
                    predecessor_proof,
                    Version8ProtectedFaultPredecessorProofInputs,
                )
                else None
            ),
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
    if version == MANIFEST_VERSION_V7:
        legacy_predecessor_keys = {
            key
            for key, item in legacy_kwargs.items()
            if key.startswith("predecessor_") and item is not None
        }
        if legacy_predecessor_keys:
            return ["campaign-manifest-v7-legacy-proof-input-forbidden"]
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
            return ["campaign-manifest-v7-validator-arguments-invalid"]
        return _validate_campaign_manifest_v7(
            value,
            authorization=legacy_kwargs.get("authorization"),
            authorization_raw_sha256=legacy_kwargs.get(
                "authorization_raw_sha256"
            ),
            outer_authority=legacy_kwargs.get("outer_authority"),
            outer_authority_raw_sha256=legacy_kwargs.get(
                "outer_authority_raw_sha256"
            ),
            predecessor_proof=(
                predecessor_proof
                if isinstance(
                    predecessor_proof,
                    Version9PreallocationFaultPredecessorProofInputs,
                )
                else None
            ),
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
    if version == MANIFEST_VERSION_V8:
        legacy_predecessor_keys = {
            key
            for key, item in legacy_kwargs.items()
            if key.startswith("predecessor_") and item is not None
        }
        if legacy_predecessor_keys:
            return ["campaign-manifest-v8-legacy-proof-input-forbidden"]
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
            return ["campaign-manifest-v8-validator-arguments-invalid"]
        return _validate_campaign_manifest_v8(
            value,
            authorization=legacy_kwargs.get("authorization"),
            authorization_raw_sha256=legacy_kwargs.get(
                "authorization_raw_sha256"
            ),
            outer_authority=legacy_kwargs.get("outer_authority"),
            outer_authority_raw_sha256=legacy_kwargs.get(
                "outer_authority_raw_sha256"
            ),
            predecessor_proof=(
                predecessor_proof
                if isinstance(
                    predecessor_proof,
                    Version10InterruptedEmptyBoundaryPredecessorProofInputs,
                )
                else None
            ),
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


def validate_campaign_manifest(value: Any, **kwargs: Any) -> list[str]:
    """Fail closed instead of raising when an untrusted proof graph is malformed."""
    try:
        return _dispatch_validate_campaign_manifest(value, **kwargs)
    except (AttributeError, IndexError, KeyError, TypeError, ValueError):
        return ["campaign-manifest-proof-structure-invalid"]


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
