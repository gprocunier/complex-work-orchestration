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
        "containment_canonical_sha256": bindings.get(
            "predecessor_containment_canonical_sha256"
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
    predecessor_containment: Mapping[str, Any] | None = None,
    predecessor_containment_raw_sha256: str | None = None,
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
        predecessor_containment,
        predecessor_containment_raw_sha256,
        cause_evidence,
    )
    if any(item is not None for item in predecessor_artifacts):
        if any(item is None for item in predecessor_artifacts):
            errors.append("authorization-predecessor-artifacts-incomplete")
        else:
            prior_authorization = dict(predecessor_authorization or {})
            prior_manifest = dict(predecessor_manifest or {})
            prior_state = dict(predecessor_authorization_state or {})
            prior_failure = dict(predecessor_failure_evidence or {})
            prior_containment = dict(predecessor_containment or {})
            prior_authorization_canonical = prior_authorization.get(
                "canonical_authorization_sha256"
            )
            prior_manifest_canonical = prior_manifest.get("manifest_sha256")
            prior_candidate = prior_manifest.get("candidate")
            if (
                prior_authorization.get("authorization_type")
                != "cwo-full-auto-run-authorization"
                or prior_authorization.get("version") != 4
                or prior_authorization.get("schema")
                != "schemas/full-auto-run-authorization.schema.json"
                or prior_authorization.get("authorization_id")
                != bindings.get("predecessor_authorization_id")
                or prior_authorization.get("live_generation") != predecessor
                or prior_authorization.get("predecessor_live_generation")
                != predecessor - 1
                or predecessor_authorization_raw_sha256
                != bindings.get("predecessor_authorization_file_sha256")
                or prior_authorization_canonical
                != bindings.get("predecessor_authorization_canonical_sha256")
                or not _is_hash(prior_authorization_canonical)
                or prior_authorization_canonical
                != _canonical_artifact_hash(
                    prior_authorization, "canonical_authorization_sha256"
                )
            ):
                errors.append("authorization-predecessor-authorization-binding-invalid")
            if (
                prior_manifest.get("manifest_type")
                != "cwo-native-live-campaign-manifest"
                or prior_manifest.get("version") != 1
                or prior_manifest.get("schema")
                != "schemas/native-live-campaign-manifest.schema.json"
                or prior_manifest.get("authorization_id")
                != bindings.get("predecessor_authorization_id")
                or prior_manifest.get("authorization_canonical_sha256")
                != bindings.get("predecessor_authorization_canonical_sha256")
                or prior_manifest.get("authorization_raw_sha256")
                != bindings.get("predecessor_authorization_file_sha256")
                or prior_manifest.get("live_generation") != predecessor
                or predecessor_manifest_raw_sha256
                != bindings.get("predecessor_manifest_file_sha256")
                or prior_manifest_canonical
                != bindings.get("predecessor_manifest_canonical_sha256")
                or not _is_hash(prior_manifest_canonical)
                or prior_manifest_canonical
                != _canonical_artifact_hash(prior_manifest, "manifest_sha256")
                or not isinstance(prior_candidate, Mapping)
                or prior_candidate.get("commit")
                != progress.get("predecessor_candidate_commit")
                or prior_candidate.get("tree")
                != progress.get("predecessor_candidate_tree")
            ):
                errors.append("authorization-predecessor-manifest-binding-invalid")
            prior_authorization_bindings = prior_authorization.get("bindings")
            expected_prior_nonce = (
                prior_authorization_bindings.get("campaign_nonce")
                if isinstance(prior_authorization_bindings, Mapping)
                else None
            )
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
                prior_state.get("authorization_type")
                != "cwo-native-canary-authorization-state:v1"
                or prior_state.get("version") != 1
                or prior_state.get("schema")
                != "schemas/native-canary-authorization-state.schema.json"
                or predecessor_authorization_state_raw_sha256
                != bindings.get("predecessor_authorization_state_file_sha256")
                or prior_state.get("state_sha256")
                != bindings.get("predecessor_authorization_state_canonical_sha256")
                or validate_authorization_state(prior_state)
                or prior_state.get("authorization_id")
                != bindings.get("predecessor_authorization_id")
                or prior_state.get("run_nonce") != expected_prior_nonce
                or prior_state.get("state") != "containment-only"
                or not isinstance(prior_state.get("allowed_actions"), list)
                or any(
                    action in prior_state.get("allowed_actions", [])
                    for action in required_revocations
                )
                or not required_revocations.issubset(
                    set(prior_state.get("revoked_actions", []))
                )
            ):
                errors.append("authorization-predecessor-state-binding-invalid")
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
                or not isinstance(failure_bindings, Mapping)
                or failure_bindings.get("authorization_raw_sha256")
                != bindings.get("predecessor_authorization_file_sha256")
                or failure_bindings.get("manifest_file_sha256")
                != bindings.get("predecessor_manifest_file_sha256")
                or failure_bindings.get("manifest_sha256")
                != bindings.get("predecessor_manifest_canonical_sha256")
                or failure_bindings.get("candidate_commit")
                != progress.get("predecessor_candidate_commit")
                or failure_bindings.get("candidate_tree")
                != progress.get("predecessor_candidate_tree")
                or not isinstance(failure_containment, Mapping)
                or failure_containment.get("all_contained") is not True
                or failure_containment.get("ambiguous_count") != 0
                or failure_containment.get("ledger_consistent") is not True
                or failure_containment.get("unresolved_allocation_intent_count") != 0
                or failure_containment.get("unresolved_turn_intent_count") != 0
            ):
                errors.append("authorization-predecessor-failure-binding-invalid")
            containment_evidence = prior_containment.get("failed_evidence")
            containment_reclassification = prior_containment.get("reclassification")
            containment_control = prior_containment.get("control_plane_recheck")
            if (
                predecessor_containment_raw_sha256
                != bindings.get("predecessor_containment_file_sha256")
                or prior_containment.get("canonical_recovery_sha256")
                != bindings.get("predecessor_containment_canonical_sha256")
                or prior_containment.get("canonical_recovery_sha256")
                != _canonical_artifact_hash(
                    prior_containment, "canonical_recovery_sha256"
                )
                or prior_containment.get("failed_authorization_id")
                != bindings.get("predecessor_authorization_id")
                or prior_containment.get("failed_campaign_nonce")
                != expected_prior_nonce
                or not isinstance(containment_evidence, Mapping)
                or containment_evidence.get("file_sha256")
                != bindings.get("predecessor_failure_evidence_file_sha256")
                or containment_evidence.get("canonical_sha256")
                != bindings.get("predecessor_failure_evidence_canonical_sha256")
                or containment_evidence.get("authorization_state_file_sha256")
                != bindings.get("predecessor_authorization_state_file_sha256")
                or containment_evidence.get("authorization_state_canonical_sha256")
                != bindings.get("predecessor_authorization_state_canonical_sha256")
                or not isinstance(containment_reclassification, Mapping)
                or containment_reclassification.get("ambiguous_count") != 0
                or containment_reclassification.get("all_contained") is not True
                or containment_reclassification.get("release_gate_passed") is not False
                or containment_reclassification.get("failed_authorization_terminal")
                is not True
                or containment_reclassification.get(
                    "reuse_resume_retry_substitution_salvage_bridge"
                )
                is not False
                or not isinstance(containment_control, Mapping)
                or containment_control.get("isolated_checkout_tracked_clean")
                is not True
                or containment_control.get("release_policy_status")
                != "canary-gated"
                or containment_control.get("operative_dispatch_authorized") is not False
            ):
                errors.append("authorization-predecessor-containment-binding-invalid")
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
    predecessor_containment: Mapping[str, Any] | None = None,
    predecessor_containment_raw_sha256: str | None = None,
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
            predecessor_containment=predecessor_containment,
            predecessor_containment_raw_sha256=predecessor_containment_raw_sha256,
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
