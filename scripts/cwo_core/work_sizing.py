from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from copy import deepcopy
from fnmatch import fnmatch
from math import isfinite
from typing import Any

from cwo_core.policy import load_policy
from cwo_core.native_authority import (
    OPERATOR_APPROVAL_FIELDS,
    OPERATOR_REQUIRED_CHANGE_TYPES,
    AuthorityProvenanceError,
    OperatorApprovalVerifier,
    VerifiedAuthority,
    assess_operator_required_changes,
    canonical_authority_sha256,
    canonical_json_object,
    is_sha256,
    protected_change_identity,
    require_minimum_authority,
    validate_authority_provenance,
    validate_operator_approval_audit,
)
from cwo_core.native_containment import containment_error
from cwo_core.native_precommit import validate_precommit_receipt

DIMENSIONS = (
    "reasoning_uncertainty",
    "subsystem_coupling",
    "contract_risk",
    "diagnostic_uncertainty",
    "context_breadth",
    "validation_breadth",
)

SEMANTIC_SURFACE_KEYS = (
    "contract_surfaces",
    "cli_surfaces",
    "policy_surfaces",
    "telemetry_surfaces",
)

ROUTE_PRIORITY = {"spark": 0, "split": 1, "architect": 2}
ROUTE_BY_PRIORITY = ["spark", "split", "architect"]
TASK_CLASS_OPTIONS = (
    "literal-command",
    "read-only-validation",
    "narrow-mechanical",
    "bounded-implementation",
    "diagnosis",
    "architecture",
)
FIT_MODES = ("deterministic", "semantic", "architect")
SEMANTIC_ESTIMATE_KEYS = (
    "estimated_diff_p50",
    "estimated_diff_p90",
    "behavioral_changes",
    "state_machine_changes",
    "schema_changes",
    "self_hosting_risk",
    "live_control_risk",
    "contract_surfaces",
    "cli_surfaces",
    "policy_surfaces",
    "telemetry_surfaces",
    "expected_regressions",
    "test_construction_complexity",
    "command_complexity",
    "nested_quote_layers",
    "expected_context_reads",
    "expected_mutations",
    "read_to_mutation_ratio",
)
SEMANTIC_SCORE_KEYS = (
    "diff_p90",
    "behavioral_changes",
    "state_schema_changes",
    "surface_changes",
    "expected_regressions",
    "read_to_mutation_ratio",
    "self_hosting_live_control_risk",
    "test_construction_complexity",
    "command_complexity",
)
SEMANTIC_ROUTE_REASONS = (
    "semantic-authority-uncertainty",
    "semantic-route-conflict",
    "semantic-estimate-variance",
    "semantic-read-mutation-split-trigger",
    "task-profile-contradiction",
)

REQUIRED_SOURCE_FIELDS = (
    "estimate_type",
    "version",
    "work_unit_id",
    "bead_id",
    "requested_model",
    "primary_outcome",
    "expected_artifacts",
    "expert_profiles",
    "frozen_decisions",
    "unresolved_decisions",
    "subsystems",
    "write_paths",
    "context_manifest",
    "acceptance_checks",
    "estimates",
    "scores",
)

DERIVED_FIELDS = ("score_total", "route", "hard_gate_reasons", "aggregate_allowance")
DERIVED_TASK_PROFILE_FIELDS = (
    "task_class",
    "fit_mode",
    "protected_surface_matches",
    "fit_evidence",
)

HARD_GATE_REASONS = (
    "unresolved-decisions",
    "reasoning-uncertainty-architect",
    "contract-risk-architect",
    "too-many-subsystems",
    "too-many-write-paths",
    "too-many-context-entries",
    "too-many-acceptance-checks",
    "context-tokens-p90-exceeded",
    "tool-calls-p90-exceeded",
    "runtime-seconds-p90-exceeded",
    "semantic-authority-uncertainty",
    "semantic-route-conflict",
    "semantic-estimate-variance",
    "semantic-read-mutation-split-trigger",
    "task-profile-contradiction",
)

COMMITMENT_V1_REQUIRED_FIELDS = (
    "commitment_type",
    "version",
    "work_unit_id",
    "bead_id",
    "requested_model",
    "session_id",
    "attestation_source",
    "attested_model",
    "work_estimate_sha256",
    "decision",
    "confidence",
    "estimates",
    "tool_calls_before_commitment",
    "context_compactions_before_commitment",
    "reason",
)

COMMITMENT_V2_REQUIRED_FIELDS = (
    "commitment_type",
    "version",
    "packet_id",
    "attempt_nonce",
    "work_unit_id",
    "bead_id",
    "requested_model",
    "session_id",
    "agent_id",
    "attestation_source",
    "attested_model",
    "work_estimate_sha256",
    "decision",
    "estimates",
    "precommit_receipt_sha256",
)

COMMITMENT_DECISIONS = ("accept", "pm-realignment", "architect-realignment")
COMMITMENT_ESTIMATE_KEYS = ("tool_calls_p50", "tool_calls_p90", "runtime_seconds_p50", "runtime_seconds_p90")
REFINEMENT_LINEAGE_FIELDS = (
    "parent_estimate_sha256",
    "refinement_authority",
    "operator_approval_receipts",
    "protected_change_authorizations",
)

# Mirrors the top-level properties in native-work-estimate.schema.json.  The
# contract-version split is enforced here before any payload field is copied.
WORK_ESTIMATE_SCHEMA_FIELDS = frozenset(
    {
        "estimate_type",
        "version",
        "estimate_contract_version",
        "work_unit_id",
        "bead_id",
        "requested_model",
        "primary_outcome",
        "parent_estimate_sha256",
        "refinement_authority",
        "operator_approval_receipts",
        "protected_change_authorizations",
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
        "authority_route",
        "operative_route",
        "route_conflict",
        "variance_metrics",
        "task_class",
        "fit_mode",
        "protected_surface_matches",
        "fit_evidence",
        "hard_gate_reasons",
        "aggregate_allowance",
    }
)
WORK_ESTIMATE_V2_ONLY_FIELDS = frozenset(
    {
        "task_profile",
        "semantic_estimate",
        "pm_estimate",
        "domain_expert_estimate",
        "semantic_scores",
        "v1_route",
        "semantic_route",
        "authority_route",
        "operative_route",
        "route_conflict",
        "variance_metrics",
    }
)


def _route_priority(route: str) -> int:
    return ROUTE_PRIORITY.get(route, 0)


def _route_from_priority(priority: int) -> str:
    if priority <= 0:
        return ROUTE_BY_PRIORITY[0]
    if priority == 1:
        return ROUTE_BY_PRIORITY[1]
    return ROUTE_BY_PRIORITY[2]


def _bucket_diff_score(diff_p90: int) -> int:
    if diff_p90 <= 80:
        return 0
    if diff_p90 <= 250:
        return 1
    if diff_p90 <= 600:
        return 2
    return 3


def _bucket_behavior_score(behavioral_changes: int) -> int:
    if behavioral_changes <= 0:
        return 0
    if behavioral_changes <= 2:
        return 1
    if behavioral_changes <= 5:
        return 2
    return 3


def _bucket_state_schema_score(state_machine_changes: int, schema_changes: int) -> int:
    total = int(state_machine_changes) + int(schema_changes)
    if total <= 0:
        return 0
    if total == 1:
        return 1
    if total <= 3:
        return 2
    return 3


def _bucket_surface_score(surface_count: int) -> int:
    if surface_count <= 0:
        return 0
    if surface_count <= 2:
        return 1
    if surface_count <= 5:
        return 2
    return 3


def _bucket_regression_score(expected_regressions: int) -> int:
    if expected_regressions <= 3:
        return 0
    if expected_regressions <= 8:
        return 1
    if expected_regressions <= 16:
        return 2
    return 3


def _bucket_read_mutation_ratio_score(ratio: float) -> int:
    if ratio <= 2:
        return 0
    if ratio <= 5:
        return 1
    if ratio <= 10:
        return 2
    return 3


def _normalize_ratio(expected_reads: int, expected_mutations: int) -> float:
    if expected_mutations <= 0:
        return float(expected_reads)
    return float(expected_reads) / float(expected_mutations)


def _validate_ratio_input(expected_ratio: Any, expected_reads: int, expected_mutations: int, path: str) -> float:
    ratio = _ensure_float(expected_ratio, path=path, minimum=0.0, maximum=10_000_000.0)
    computed = _normalize_ratio(expected_reads, expected_mutations)
    if abs(ratio - computed) > 0.0001:
        raise ValueError(
            "malformed source payload: semantic_estimate.read_to_mutation_ratio must equal expected_context_reads/expected_mutations"
        )
    return ratio


def _surface_total(semantic_payload: Mapping[str, Any]) -> int:
    return (
        int(semantic_payload["contract_surfaces"])
        + int(semantic_payload["cli_surfaces"])
        + int(semantic_payload["policy_surfaces"])
        + int(semantic_payload["telemetry_surfaces"])
    )


def _ensure_mapping(value: Any, *, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"malformed source payload: {label} must be a mapping")
    return value


def _ensure_nonempty_str(value: Any, *, path: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"malformed source payload: {path} must be a non-empty string")
    return value


def _ensure_list(value: Any, *, path: str) -> list[Any]:
    if not isinstance(value, list):
        raise ValueError(f"malformed source payload: {path} must be a list")
    return list(value)


def _ensure_int(value: Any, *, path: str, minimum: int = 0, maximum: int | None = None) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ValueError(f"malformed source payload: {path} must be a non-negative integer")
    if maximum is not None and value > maximum:
        raise ValueError(f"malformed source payload: {path} must be at most {maximum}")
    return int(value)


def _ensure_float(value: Any, *, path: str, minimum: float = 0.0, maximum: float = 1.0) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"malformed source payload: {path} must be a number")
    if not isfinite(value):
        raise ValueError(f"malformed source payload: {path} must be a finite number")
    if value < minimum or value > maximum:
        raise ValueError(f"malformed source payload: {path} must be between {minimum} and {maximum}")
    return float(value)


def _ensure_mapping_exact(value: Any, *, path: str, required_fields: tuple[str, ...], allow_empty: bool = False) -> dict[str, Any]:
    mapping = _ensure_mapping(value, label=path)
    mapping_fields = set(mapping.keys())
    required = set(required_fields)
    if not allow_empty and (missing := sorted(required - mapping_fields)):
        raise ValueError(f"malformed source payload: {path} missing required field(s) {', '.join(missing)}")
    extras = sorted(mapping_fields - required)
    if extras:
        raise ValueError(f"malformed source payload: {path} has unknown field(s) {', '.join(extras)}")
    return dict(mapping)


def _ensure_estimate_mapping(value: Any, *, path: str) -> dict[str, Any]:
    estimate = _ensure_mapping_exact(
        value,
        path=path,
        required_fields=(
            "tool_calls_p50",
            "tool_calls_p90",
            "runtime_seconds_p50",
            "runtime_seconds_p90",
        ),
    )
    for key in estimate:
        _ensure_int(estimate[key], path=f"{path}.{key}", minimum=0)
    if estimate["tool_calls_p50"] > estimate["tool_calls_p90"]:
        raise ValueError(f"malformed source payload: {path}.tool_calls_p50 must be <= {path}.tool_calls_p90")
    if estimate["runtime_seconds_p50"] > estimate["runtime_seconds_p90"]:
        raise ValueError(f"malformed source payload: {path}.runtime_seconds_p50 must be <= {path}.runtime_seconds_p90")
    return estimate


def _sha256_hex(value: Any, *, path: str) -> str:
    hash_value = _ensure_nonempty_str(value, path=path)
    if len(hash_value) != 64 or any(char not in "0123456789abcdef" for char in hash_value):
        raise ValueError(f"malformed source payload: {path} must be a lowercase SHA-256 hex digest")
    return hash_value


def _valid_protection_patch(
    profile: Mapping[str, Any] | None,
    *,
    write_paths: list[str],
    source_mutation_paths: list[str],
    protected_surfaces: Mapping[str, list[str]],
) -> bool:
    if not isinstance(profile, Mapping):
        return False
    if set(profile) != {"path", "pre_patch_sha256", "post_patch_sha256"}:
        return False
    path = profile.get("path")
    pre_patch = profile.get("pre_patch_sha256")
    post_patch = profile.get("post_patch_sha256")
    try:
        patch_path = _ensure_nonempty_str(path, path="task_profile.architect_literal_patch.path")
        _sha256_hex(pre_patch, path="task_profile.architect_literal_patch.pre_patch_sha256")
        _sha256_hex(post_patch, path="task_profile.architect_literal_patch.post_patch_sha256")
        if write_paths != [patch_path] or source_mutation_paths != [patch_path]:
            return False
        return any(
            _path_matches_prefix(patch_path, pattern)
            for patterns in protected_surfaces.values()
            for pattern in patterns
        )
    except ValueError:
        return False


def _path_matches_prefix(path: str, pattern: str) -> bool:
    if not path or not pattern:
        return False
    if "*" in pattern:
        return fnmatch(path, pattern)
    normalized_path = path.rstrip("/")
    normalized_pattern = pattern.rstrip("/")
    return normalized_path == normalized_pattern or normalized_path.startswith(f"{normalized_pattern}/")


def _is_canonical_contract_path(path: str) -> bool:
    if not path or path.startswith("/") or "\\" in path:
        return False
    return all(part not in {"", ".", ".."} for part in path.split("/"))


def _task_class_policy(work_sizing: Mapping[str, Any]) -> Mapping[str, Any]:
    foundation = _get_work_sizing_section(work_sizing)
    if not isinstance(foundation, Mapping):
        raise ValueError("malformed policy: enforcement.foundation-canary missing")
    return _ensure_mapping(foundation.get("task_class_policy"), label="task_class_policy")


def _protected_surface_groups(work_sizing: Mapping[str, Any]) -> Mapping[str, list[str]]:
    foundation = _get_work_sizing_section(work_sizing)
    if not isinstance(foundation, Mapping):
        raise ValueError("malformed policy: enforcement.foundation-canary missing")
    protected = _ensure_mapping(foundation.get("protected_surfaces"), label="protected_surfaces")
    normalized: dict[str, list[str]] = {}
    for group_name, patterns in protected.items():
        normalized[group_name] = _ensure_list(patterns, path=f"protected_surfaces.{group_name}")
    return normalized


def _validate_command_entry(command: Any, idx: int) -> tuple[list[str], int]:
    command_payload = _ensure_mapping_exact(
        command,
        path=f"task_profile.commands[{idx}]",
        required_fields=("argv",),
    )
    argv = _ensure_list(command_payload["argv"], path=f"task_profile.commands[{idx}].argv")
    for arg_idx, arg in enumerate(argv):
        if not isinstance(arg, str):
            raise ValueError(
                f"malformed source payload: task_profile.commands[{idx}].argv[{arg_idx}] must be a string"
            )
    return argv, len(argv)


def _validate_execution_contract(
    value: Any,
    *,
    task_class: str,
    normalized_commands: list[list[str]],
) -> dict[str, Any]:
    contract = _ensure_mapping_exact(
        value,
        path="task_profile.execution_contract",
        required_fields=("mode", "checked_command_specs"),
    )
    mode = _ensure_nonempty_str(contract["mode"], path="task_profile.execution_contract.mode")
    if mode not in {"direct", "checked-sequence-v1"}:
        raise ValueError("malformed source payload: task_profile.execution_contract.mode must be direct or checked-sequence-v1")

    raw_specs = _ensure_list(
        contract["checked_command_specs"],
        path="task_profile.execution_contract.checked_command_specs",
    )
    if mode == "direct":
        if raw_specs:
            raise ValueError("malformed source payload: direct execution_contract requires empty checked_command_specs")
        return {"mode": mode, "checked_command_specs": []}

    if task_class != "bounded-implementation":
        raise ValueError("malformed source payload: checked-sequence-v1 requires bounded-implementation task_class")
    if not raw_specs:
        raise ValueError("malformed source payload: checked-sequence-v1 requires checked_command_specs")

    from cwo_core.checked_command import normalize_command_spec

    normalized_specs: list[dict[str, Any]] = []
    command_ids: set[str] = set()
    resolved_workdirs: set[str] = set()
    for idx, raw_spec in enumerate(raw_specs):
        path = f"task_profile.execution_contract.checked_command_specs[{idx}]"
        try:
            spec = normalize_command_spec(raw_spec)
        except ValueError as exc:
            raise ValueError(f"malformed source payload: {path} is invalid: {exc}") from exc
        if spec["mode"] != "argv":
            raise ValueError(f"malformed source payload: {path}.mode must be argv")
        if spec["command_id"] in command_ids:
            raise ValueError("malformed source payload: checked_command_specs command_id values must be unique")
        command_ids.add(spec["command_id"])
        resolved_workdirs.add(spec["cwd"])
        normalized_specs.append(spec)

    if len(resolved_workdirs) != 1:
        raise ValueError("malformed source payload: checked-sequence-v1 requires one resolved cwd")
    if [spec["argv"] for spec in normalized_specs] != normalized_commands:
        raise ValueError("malformed source payload: checked_command_specs argv must exactly match task_profile.commands in order")
    return {"mode": mode, "checked_command_specs": normalized_specs}


def _validate_task_profile(task_profile: Any) -> dict[str, Any] | None:
    if task_profile is None:
        return None

    payload = _ensure_mapping(task_profile, label="task_profile")
    required_keys = {
        "task_class",
        "declared_outcome_count",
        "command_count",
        "check_count",
        "focused_test_count",
        "full_suite_count",
        "read_context_count",
        "source_mutation_count",
        "commands",
    }
    optional_keys = {"source_mutation_paths", "architect_literal_patch", "execution_contract"}
    payload_keys = set(payload.keys())
    if missing := sorted(required_keys - payload_keys):
        raise ValueError(f"malformed source payload: task_profile missing required field(s) {', '.join(missing)}")
    if extras := sorted(payload_keys - (required_keys | optional_keys)):
        raise ValueError(f"malformed source payload: task_profile has unknown field(s) {', '.join(extras)}")
    payload = dict(payload)

    _ensure_nonempty_str(payload["task_class"], path="task_profile.task_class")
    _ensure_int(payload["declared_outcome_count"], path="task_profile.declared_outcome_count", minimum=0)
    _ensure_int(payload["command_count"], path="task_profile.command_count", minimum=0)
    _ensure_int(payload["check_count"], path="task_profile.check_count", minimum=0)
    _ensure_int(payload["focused_test_count"], path="task_profile.focused_test_count", minimum=0)
    _ensure_int(payload["full_suite_count"], path="task_profile.full_suite_count", minimum=0)
    _ensure_int(payload["read_context_count"], path="task_profile.read_context_count", minimum=0)
    _ensure_int(payload["source_mutation_count"], path="task_profile.source_mutation_count", minimum=0)

    commands = _ensure_list(payload["commands"], path="task_profile.commands")
    normalized_commands: list[list[str]] = []
    for idx, command in enumerate(commands):
        argv, _ = _validate_command_entry(command, idx)
        if not argv:
            raise ValueError(f"malformed source payload: task_profile.commands[{idx}].argv cannot be empty")
        normalized_commands.append(argv)
    if payload["command_count"] != len(normalized_commands):
        raise ValueError("malformed source payload: task_profile.command_count must equal len(task_profile.commands)")

    if "execution_contract" in payload:
        payload["execution_contract"] = _validate_execution_contract(
            payload["execution_contract"],
            task_class=payload["task_class"],
            normalized_commands=normalized_commands,
        )
    elif payload["task_class"] in {"literal-command", "read-only-validation"} and normalized_commands:
        payload["execution_contract"] = {"mode": "direct", "checked_command_specs": []}

    if "source_mutation_paths" in payload:
        mutation_paths = _ensure_list(payload["source_mutation_paths"], path="task_profile.source_mutation_paths")
        payload["source_mutation_paths"] = [
            _ensure_nonempty_str(item, path=f"task_profile.source_mutation_paths[{idx}]") for idx, item in enumerate(mutation_paths)
        ]
    if "architect_literal_patch" in payload:
        patch = _ensure_mapping_exact(
            payload["architect_literal_patch"],
            path="task_profile.architect_literal_patch",
            required_fields=("path", "pre_patch_sha256", "post_patch_sha256"),
        )
        _ensure_nonempty_str(patch["path"], path="task_profile.architect_literal_patch.path")
        _sha256_hex(patch["pre_patch_sha256"], path="task_profile.architect_literal_patch.pre_patch_sha256")
        _sha256_hex(patch["post_patch_sha256"], path="task_profile.architect_literal_patch.post_patch_sha256")
        payload["architect_literal_patch"] = patch

    return payload


def _derive_protected_surface_matches(
    write_paths: list[str],
    source_mutation_paths: list[str],
    protected_surfaces: Mapping[str, list[str]],
) -> list[str]:
    candidate_paths = list(dict.fromkeys(write_paths + source_mutation_paths))
    matches: list[str] = []
    for group_name, patterns in protected_surfaces.items():
        for pattern in patterns:
            _ensure_nonempty_str(pattern, path=f"protected_surfaces.{group_name}")
            for candidate in candidate_paths:
                if _path_matches_prefix(candidate, pattern):
                    matches.append(group_name)
                    break
            if group_name in matches:
                break
    return matches


def _evaluate_task_profile_fit(
    source: Mapping[str, Any],
    semantic_payload: dict[str, Any] | None,
    task_profile: Mapping[str, Any] | None,
    task_class_policy: Mapping[str, Any],
    protected_surface_matches: list[str],
    protected_surfaces: Mapping[str, list[str]],
) -> tuple[str, str, dict[str, Any], list[str]]:
    default_task_class = "bounded-implementation"
    fit_evidence: dict[str, Any] = {
        "task_profile_class": default_task_class,
        "source": "default",
        "checks": ["default-bounded-implementation-fit"],
        "policy_caps": {},
        "contradictions": [],
    }

    if task_profile is None:
        return default_task_class, "semantic", fit_evidence, protected_surface_matches

    task_class = _ensure_nonempty_str(task_profile["task_class"], path="task_profile.task_class")
    declared_outcomes = int(task_profile["declared_outcome_count"])
    command_count = int(task_profile["command_count"])
    check_count = int(task_profile["check_count"])
    focused_test_count = int(task_profile["focused_test_count"])
    full_suite_count = int(task_profile["full_suite_count"])
    read_context_count = int(task_profile["read_context_count"])
    source_mutation_count = int(task_profile["source_mutation_count"])
    commands = task_profile["commands"]
    source_mutation_paths = _ensure_list(task_profile.get("source_mutation_paths", []), path="task_profile.source_mutation_paths")

    fit_evidence["task_profile_class"] = task_class
    fit_evidence["source"] = "task-profile"
    fit_evidence["checks"] = ["task_profile_present"]

    if task_class not in TASK_CLASS_OPTIONS:
        fit_evidence["contradictions"].append("task_profile.task_class must be recognized")
        return "architecture", "architect", fit_evidence, []

    declared_class_profile = _ensure_mapping(
        task_class_policy.get(task_class),
        label=f"task_class_policy.{task_class}",
    )
    policy_fit_mode = _ensure_nonempty_str(
        declared_class_profile.get("fit_mode"),
        path=f"task_class_policy.{task_class}.fit_mode",
    )
    if policy_fit_mode not in FIT_MODES:
        raise ValueError(f"malformed policy: task_class_policy.{task_class}.fit_mode must be deterministic, semantic, or architect")

    contradictions: list[str] = []
    checks = fit_evidence["checks"]
    fit_evidence["policy_caps"] = dict(declared_class_profile)

    contract_paths = list(source["write_paths"]) + source_mutation_paths
    if any(not _is_canonical_contract_path(path) for path in contract_paths):
        contradictions.append("task profile paths must be canonical repository-relative paths")

    max_outcomes = int(declared_class_profile.get("max_task_outcomes", 2_147_483_647))
    max_paths = int(declared_class_profile.get("max_source_paths", 2_147_483_647))
    max_mutations = int(declared_class_profile.get("max_source_mutation_count", 2_147_483_647))
    max_context_reads = int(declared_class_profile.get("max_read_context_count", 2_147_483_647))
    max_focused_tests = int(declared_class_profile.get("max_focused_test_count", 2_147_483_647))
    max_command_count = int(declared_class_profile.get("max_command_count", 2_147_483_647))
    max_check_count = int(declared_class_profile.get("max_check_count", 2_147_483_647))
    max_full_suite_count = int(declared_class_profile.get("max_full_suite_count", 2_147_483_647))

    if len(source["write_paths"]) > max_paths:
        contradictions.append("write_path_count exceeds class cap")
    if declared_outcomes > max_outcomes:
        contradictions.append("declared_outcome_count exceeds class cap")
    if source_mutation_count > max_mutations:
        contradictions.append("source_mutation_count exceeds class cap")
    if source_mutation_paths and source_mutation_count != len(source_mutation_paths):
        contradictions.append("source_mutation_count must equal len(source_mutation_paths)")
    if source_mutation_count and not source_mutation_paths:
        contradictions.append("source_mutation_paths required when source_mutation_count is non-zero")
    if any(path not in source["write_paths"] for path in source_mutation_paths):
        contradictions.append("source_mutation_paths must be contained in write_paths")
    if read_context_count != len(source["context_manifest"]):
        contradictions.append("read_context_count must equal len(context_manifest)")
    if read_context_count > max_context_reads:
        contradictions.append("read_context_count exceeds class cap")
    if focused_test_count > max_focused_tests:
        contradictions.append("focused_test_count exceeds class cap")
    if command_count > max_command_count:
        contradictions.append("command_count exceeds class cap")
    if check_count > max_check_count:
        contradictions.append("check_count exceeds class cap")
    if full_suite_count > max_full_suite_count:
        contradictions.append("full_suite_count exceeds class cap")

    requires_argv = bool(declared_class_profile.get("requires_exact_argv", False))
    if requires_argv:
        checks.append(f"requires_exact_argv={requires_argv}")
        if not commands:
            contradictions.append("exact argv required but no commands were declared")
        for idx, command_argv in enumerate(commands):
            if not command_argv:
                contradictions.append(f"task_profile.commands[{idx}] must include non-empty argv")

    if task_class == "narrow-mechanical":
        max_diff_p90 = int(declared_class_profile.get("max_estimated_diff_p90", 2_147_483_647))
        checks.append("narrow-mechanical class")
        if declared_outcomes != 1:
            contradictions.append("narrow-mechanical requires exactly one outcome")
        if semantic_payload is None or int(semantic_payload["estimated_diff_p90"]) > max_diff_p90:
            contradictions.append("narrow-mechanical requires low semantic diff")

    if task_class == "read-only-validation":
        checks.append("read-only-validation class")
        if source_mutation_count != 0:
            contradictions.append("read-only-validation requires source_mutation_count == 0")
        if source["write_paths"]:
            contradictions.append("read-only-validation requires zero write_paths")

    if task_class == "literal-command":
        checks.append("literal-command class")
        if declared_outcomes != 1:
            contradictions.append("literal-command requires exactly one outcome")
        if source_mutation_count != 0 or source["write_paths"]:
            contradictions.append("literal-command requires zero source mutation and write_paths")

    if task_class == "diagnosis":
        checks.append("diagnosis class")
        if source_mutation_count != 0 or source["write_paths"]:
            contradictions.append("diagnosis requires zero source mutation and write_paths")

    if task_class == "architecture":
        checks.append("architecture class")

    if contradictions:
        fit_evidence["contradictions"] = contradictions
        fit_evidence["checks"].append("task-profile-contradiction")
        return "architecture", "architect", fit_evidence, protected_surface_matches

    if task_class == "architecture":
        return task_class, "architect", fit_evidence, protected_surface_matches

    fit_mode = policy_fit_mode
    if policy_fit_mode == "deterministic" and protected_surface_matches:
        if not _valid_protection_patch(
            task_profile.get("architect_literal_patch"),
            write_paths=list(source["write_paths"]),
            source_mutation_paths=source_mutation_paths,
            protected_surfaces=protected_surfaces,
        ):
            fit_mode = "semantic"
            fit_evidence["checks"].append("protected-surface-requires-path-bound-literal-patch")
        else:
            fit_evidence["checks"].append("protected-path-bound-literal-patch-verified")

    if fit_mode == "deterministic":
        checks.append("deterministic-fit-selected")
    return task_class, fit_mode, fit_evidence, protected_surface_matches


def _semantic_routing_policy(work_sizing: Mapping[str, Any]) -> Mapping[str, Any]:
    foundation = _get_work_sizing_section(work_sizing)
    if not isinstance(foundation, Mapping):
        raise ValueError("malformed policy: enforcement.foundation-canary missing")
    return _ensure_mapping(foundation.get("semantic_routing"), label="semantic_routing")


def _compute_semantic_scores(semantic_payload: dict[str, Any]) -> dict[str, int]:
    diff_score = _bucket_diff_score(int(semantic_payload["estimated_diff_p90"]))
    behavior_score = _bucket_behavior_score(int(semantic_payload["behavioral_changes"]))
    state_schema_score = _bucket_state_schema_score(
        int(semantic_payload["state_machine_changes"]),
        int(semantic_payload["schema_changes"]),
    )
    surface_score = _bucket_surface_score(_surface_total(semantic_payload))
    regression_score = _bucket_regression_score(int(semantic_payload["expected_regressions"]))
    ratio_score = _bucket_read_mutation_ratio_score(float(semantic_payload["read_to_mutation_ratio"]))
    return {
        "diff_p90": diff_score,
        "behavioral_changes": behavior_score,
        "state_schema_changes": state_schema_score,
        "surface_changes": surface_score,
        "expected_regressions": regression_score,
        "read_to_mutation_ratio": ratio_score,
        "self_hosting_live_control_risk": max(
            int(semantic_payload["self_hosting_risk"]),
            int(semantic_payload["live_control_risk"]),
        ),
        "test_construction_complexity": int(semantic_payload["test_construction_complexity"]),
        "command_complexity": max(
            int(semantic_payload["command_complexity"]),
            min(int(semantic_payload["nested_quote_layers"]), 3),
        ),
    }


def _estimate_deltas(left: Mapping[str, Any], right: Mapping[str, Any]) -> dict[str, int]:
    return {
        "tool_calls_p50": abs(int(left["tool_calls_p50"]) - int(right["tool_calls_p50"])),
        "tool_calls_p90": abs(int(left["tool_calls_p90"]) - int(right["tool_calls_p90"])),
        "runtime_seconds_p50": abs(int(left["runtime_seconds_p50"]) - int(right["runtime_seconds_p50"])),
        "runtime_seconds_p90": abs(int(left["runtime_seconds_p90"]) - int(right["runtime_seconds_p90"])),
    }


def _ensure_context_item(item: Any, *, index: int) -> None:
    mapping = _ensure_mapping(item, label=f"context_manifest[{index}]")
    allowed_keys = {"path", "selector", "purpose", "bytes", "sha256"}
    item_keys = set(mapping.keys())
    if item_keys != allowed_keys:
        raise ValueError(f"malformed source payload: context_manifest[{index}] must contain exact keys {sorted(allowed_keys)}")
    _ensure_nonempty_str(mapping["path"], path=f"context_manifest[{index}].path")
    _ensure_nonempty_str(mapping["selector"], path=f"context_manifest[{index}].selector")
    _ensure_nonempty_str(mapping["purpose"], path=f"context_manifest[{index}].purpose")
    _ensure_int(mapping["bytes"], path=f"context_manifest[{index}].bytes", minimum=0)
    sha256 = _ensure_nonempty_str(mapping["sha256"], path=f"context_manifest[{index}].sha256")
    if len(sha256) != 64 or any(ch not in "0123456789abcdef" for ch in sha256):
        raise ValueError(f"malformed source payload: context_manifest[{index}].sha256 must be lowercase 64 hex")


def _load_work_sizing_policy(policy: Mapping[str, Any] | None) -> Mapping[str, Any]:
    source = (
        policy
        if policy is not None
        else _ensure_mapping(load_policy("native-worker-execution"), label="native-worker-execution policy")
    )
    if not isinstance(source.get("work_sizing"), Mapping):
        raise ValueError("malformed policy: work_sizing section missing")
    return _ensure_mapping(source["work_sizing"], label="work_sizing policy")


def _get_work_sizing_section(policy: Mapping[str, Any]) -> Mapping[str, Any]:
    return _ensure_mapping(policy.get("enforcement"), label="work_sizing.enforcement").get(
        "foundation-canary",
        None,
    )


def _route_thresholds(policy: Mapping[str, Any]) -> Mapping[str, Any]:
    foundation = _get_work_sizing_section(policy)
    if not isinstance(foundation, Mapping):
        raise ValueError("malformed policy: enforcement.foundation-canary missing")
    return _ensure_mapping(foundation.get("route_thresholds"), label="route_thresholds")


def _hard_caps(policy: Mapping[str, Any]) -> Mapping[str, Any]:
    foundation = _get_work_sizing_section(policy)
    if not isinstance(foundation, Mapping):
        raise ValueError("malformed policy: enforcement.foundation-canary missing")
    return _ensure_mapping(foundation.get("hard_caps"), label="hard_caps")


def _architect_gates(policy: Mapping[str, Any]) -> Mapping[str, Any]:
    foundation = _get_work_sizing_section(policy)
    if not isinstance(foundation, Mapping):
        raise ValueError("malformed policy: enforcement.foundation-canary missing")
    return _ensure_mapping(foundation.get("architect_hard_gates"), label="architect_hard_gates")


def _autonomous_replanning(policy: Mapping[str, Any]) -> Mapping[str, Any]:
    foundation = _get_work_sizing_section(policy)
    if not isinstance(foundation, Mapping):
        raise ValueError("malformed policy: enforcement.foundation-canary missing")
    return _ensure_mapping(
        foundation.get("autonomous_replanning"),
        label="autonomous_replanning",
    )


def _commitment_policy(policy: Mapping[str, Any]) -> Mapping[str, Any]:
    foundation = _get_work_sizing_section(policy)
    if not isinstance(foundation, Mapping):
        raise ValueError("malformed policy: enforcement.foundation-canary missing")
    return _ensure_mapping(foundation.get("commitment"), label="work_sizing.enforcement.foundation-canary.commitment")


def _validate_refinement_lineage_shape(payload: Mapping[str, Any]) -> None:
    present = {field for field in REFINEMENT_LINEAGE_FIELDS if field in payload}
    if not present:
        return
    if present != set(REFINEMENT_LINEAGE_FIELDS):
        missing = sorted(set(REFINEMENT_LINEAGE_FIELDS) - present)
        raise ValueError(
            "malformed source payload: refinement lineage missing field(s) "
            + ", ".join(missing)
        )
    if not is_sha256(payload.get("parent_estimate_sha256")):
        raise ValueError(
            "malformed source payload: parent_estimate_sha256 must be a lowercase SHA-256 hex digest"
        )
    authority_errors = validate_authority_provenance(
        payload.get("refinement_authority")
    )
    if authority_errors:
        raise ValueError(
            "malformed source payload: refinement_authority invalid: "
            + "; ".join(authority_errors)
        )
    receipts = payload.get("operator_approval_receipts")
    if not isinstance(receipts, Mapping):
        raise ValueError(
            "malformed source payload: operator_approval_receipts must be an object"
        )
    for change_type, receipt in receipts.items():
        if not isinstance(change_type, str) or not change_type:
            raise ValueError(
                "malformed source payload: operator approval receipt key invalid"
            )
        if not isinstance(receipt, Mapping) or set(receipt) != OPERATOR_APPROVAL_FIELDS:
            raise ValueError(
                f"malformed source payload: operator approval receipt {change_type} fields invalid"
            )
        if receipt.get("change_type") != change_type:
            raise ValueError(
                f"malformed source payload: operator approval receipt {change_type} key mismatch"
            )
    authorizations = payload.get("protected_change_authorizations")
    if not isinstance(authorizations, list):
        raise ValueError(
            "malformed source payload: protected_change_authorizations must be an array"
        )
    audit_change_types: list[str] = []
    for index, audit in enumerate(authorizations):
        audit_errors = validate_operator_approval_audit(audit)
        if audit_errors:
            raise ValueError(
                f"malformed source payload: protected_change_authorizations[{index}] invalid: "
                + "; ".join(audit_errors)
            )
        audit_change_types.append(str(audit["change_type"]))
        receipt = receipts.get(audit["change_type"])
        if not isinstance(receipt, Mapping):
            raise ValueError(
                f"malformed source payload: protected_change_authorizations[{index}] receipt missing"
            )
        if audit.get("receipt_sha256") != canonical_authority_sha256(receipt):
            raise ValueError(
                f"malformed source payload: protected_change_authorizations[{index}] receipt hash mismatch"
            )
    if len(audit_change_types) != len(set(audit_change_types)):
        raise ValueError(
            "malformed source payload: protected_change_authorizations change types must be unique"
        )
    if set(audit_change_types) != set(receipts):
        raise ValueError(
            "malformed source payload: operator approval receipts and audit categories differ"
        )


def _validate_required_fields(payload: Mapping[str, Any]) -> dict[str, Any]:
    estimate_contract_version = _ensure_int(
        payload.get("estimate_contract_version", 1),
        path="estimate_contract_version",
        minimum=1,
        maximum=2,
    )
    allowed_fields = (
        WORK_ESTIMATE_SCHEMA_FIELDS
        if estimate_contract_version == 2
        else WORK_ESTIMATE_SCHEMA_FIELDS - WORK_ESTIMATE_V2_ONLY_FIELDS
    )
    if extras := sorted(set(payload) - allowed_fields):
        raise ValueError(
            "malformed source payload: work estimate contract version "
            f"{estimate_contract_version} has unknown field(s) {', '.join(extras)}"
        )
    if payload.get("estimate_type") != "cwo-native-work-estimate":
        raise ValueError("malformed source payload: estimate_type must be cwo-native-work-estimate")
    _ensure_int(payload.get("version"), path="version", minimum=1, maximum=1)
    _ensure_nonempty_str(payload.get("work_unit_id"), path="work_unit_id")
    _ensure_nonempty_str(payload.get("bead_id"), path="bead_id")
    _ensure_nonempty_str(payload.get("requested_model"), path="requested_model")
    _ensure_nonempty_str(payload.get("primary_outcome"), path="primary_outcome")
    _ensure_list(payload.get("expected_artifacts"), path="expected_artifacts")
    _ensure_list(payload.get("expert_profiles"), path="expert_profiles")
    _ensure_list(payload.get("frozen_decisions"), path="frozen_decisions")
    _ensure_list(payload.get("unresolved_decisions"), path="unresolved_decisions")
    _ensure_list(payload.get("subsystems"), path="subsystems")
    _ensure_list(payload.get("write_paths"), path="write_paths")
    _ensure_list(payload.get("context_manifest"), path="context_manifest")
    _ensure_list(payload.get("acceptance_checks"), path="acceptance_checks")
    estimates = _ensure_mapping(payload.get("estimates"), label="estimates")
    scores = _ensure_mapping(payload.get("scores"), label="scores")
    _validate_refinement_lineage_shape(payload)
    for dimension in DIMENSIONS:
        _ensure_int(scores.get(dimension), path=f"scores.{dimension}", minimum=0, maximum=3)

    expected_estimate_keys = {
        "tool_calls_p50",
        "tool_calls_p90",
        "runtime_seconds_p50",
        "runtime_seconds_p90",
        "context_tokens_p90",
    }
    if set(estimates.keys()) != expected_estimate_keys:
        raise ValueError("malformed source payload: estimates must contain exact keys tool_calls_p50, tool_calls_p90, runtime_seconds_p50, runtime_seconds_p90, context_tokens_p90")
    for key in expected_estimate_keys:
        _ensure_int(estimates[key], path=f"estimates.{key}", minimum=0)
    if estimates["tool_calls_p50"] > estimates["tool_calls_p90"]:
        raise ValueError("malformed source payload: estimates.tool_calls_p50 must be <= estimates.tool_calls_p90")
    if estimates["runtime_seconds_p50"] > estimates["runtime_seconds_p90"]:
        raise ValueError("malformed source payload: estimates.runtime_seconds_p50 must be <= estimates.runtime_seconds_p90")

    expected_context_keys = set(DIMENSIONS)
    if set(scores.keys()) != expected_context_keys:
        raise ValueError("malformed source payload: scores must contain exact DIMENSIONS keys")

    semantic_payload = payload.get("semantic_estimate")
    if semantic_payload is not None:
        semantic_payload = _ensure_mapping_exact(
            semantic_payload,
            path="semantic_estimate",
            required_fields=SEMANTIC_ESTIMATE_KEYS,
        )
    if estimate_contract_version == 2 and semantic_payload is None:
        raise ValueError("malformed source payload: semantic_estimate required for estimate_contract_version 2")
    task_profile = _validate_task_profile(payload.get("task_profile"))
    if task_profile is not None and estimate_contract_version != 2:
        raise ValueError("malformed source payload: task_profile requires estimate_contract_version 2")
    if estimate_payload := semantic_payload:
        bounded_complexity_keys = {
            "self_hosting_risk",
            "live_control_risk",
            "test_construction_complexity",
            "command_complexity",
        }
        for key in (
            "estimated_diff_p50",
            "estimated_diff_p90",
            "behavioral_changes",
            "state_machine_changes",
            "schema_changes",
            "self_hosting_risk",
            "live_control_risk",
            "contract_surfaces",
            "cli_surfaces",
            "policy_surfaces",
            "telemetry_surfaces",
            "expected_regressions",
            "test_construction_complexity",
            "command_complexity",
            "nested_quote_layers",
            "expected_context_reads",
            "expected_mutations",
        ):
            _ensure_int(
                estimate_payload[key],
                path=f"semantic_estimate.{key}",
                minimum=0,
                maximum=3 if key in bounded_complexity_keys else None,
            )
        if estimate_payload["estimated_diff_p50"] > estimate_payload["estimated_diff_p90"]:
            raise ValueError(
                "malformed source payload: semantic_estimate.estimated_diff_p50 must be <= estimated_diff_p90"
            )
        ratio = _validate_ratio_input(
            estimate_payload["read_to_mutation_ratio"],
            int(estimate_payload["expected_context_reads"]),
            int(estimate_payload["expected_mutations"]),
            path="semantic_estimate.read_to_mutation_ratio",
        )
        estimate_payload["read_to_mutation_ratio"] = ratio

    for pm_key in ("pm_estimate", "domain_expert_estimate"):
        if payload.get(pm_key) is not None:
            _ensure_estimate_mapping(payload.get(pm_key), path=pm_key)

    if estimate_contract_version == 2:
        if payload.get("pm_estimate") is None or payload.get("domain_expert_estimate") is None:
            raise ValueError("malformed source payload: estimate_contract_version 2 requires pm_estimate and domain_expert_estimate")

    for idx, item in enumerate(_ensure_list(payload.get("context_manifest"), path="context_manifest")):
        _ensure_context_item(item, index=idx)

    for idx, subsystem in enumerate(payload.get("subsystems", [])):
        if not isinstance(subsystem, str) or not subsystem:
            raise ValueError(f"malformed source payload: subsystems[{idx}] must be a non-empty string")
    for idx, path_value in enumerate(payload.get("write_paths", [])):
        if not isinstance(path_value, str) or not path_value:
            raise ValueError(f"malformed source payload: write_paths[{idx}] must be a non-empty string")
    for idx, decision in enumerate(payload.get("frozen_decisions", [])):
        if not isinstance(decision, str) or not decision:
            raise ValueError(f"malformed source payload: frozen_decisions[{idx}] must be a non-empty string")
    for idx, decision in enumerate(payload.get("unresolved_decisions", [])):
        if not isinstance(decision, str) or not decision:
            raise ValueError(f"malformed source payload: unresolved_decisions[{idx}] must be a non-empty string")
    for idx, check in enumerate(payload.get("acceptance_checks", [])):
        if not isinstance(check, str) or not check:
            raise ValueError(f"malformed source payload: acceptance_checks[{idx}] must be a non-empty string")
    for idx, item in enumerate(payload.get("expected_artifacts", [])):
        if not isinstance(item, str) or not item:
            raise ValueError(f"malformed source payload: expected_artifacts[{idx}] must be a non-empty string")
    for idx, profile in enumerate(payload.get("expert_profiles", [])):
        if not isinstance(profile, str) or not profile:
            raise ValueError(f"malformed source payload: expert_profiles[{idx}] must be a non-empty string")

    return {
        "estimates": estimates,
        "scores": scores,
        "estimate_contract_version": int(estimate_contract_version),
        "semantic_estimate": semantic_payload if semantic_payload is not None else None,
        "pm_estimate": _ensure_estimate_mapping(payload.get("pm_estimate"), path="pm_estimate") if payload.get("pm_estimate") else None,
        "domain_expert_estimate": (
            _ensure_estimate_mapping(payload.get("domain_expert_estimate"), path="domain_expert_estimate")
            if payload.get("domain_expert_estimate")
            else None
        ),
        "task_profile": task_profile,
    }


def _evaluate_v1_route(
    source: Mapping[str, Any],
    scores: Mapping[str, Any],
    estimates: Mapping[str, Any],
    route_thresholds: Mapping[str, Any],
    hard_caps: Mapping[str, Any],
    architect_gates: Mapping[str, Any],
) -> tuple[str, list[str]]:
    score_total = sum(int(scores[dimension]) for dimension in DIMENSIONS)
    reasons: list[str] = []
    spark_fit_max = _ensure_int(route_thresholds.get("spark_fit_max"), path="route_thresholds.spark_fit_max", minimum=0)
    split_min = _ensure_int(route_thresholds.get("split_min"), path="route_thresholds.split_min", minimum=0)
    split_max = _ensure_int(route_thresholds.get("split_max"), path="route_thresholds.split_max", minimum=0)
    architect_min = _ensure_int(route_thresholds.get("architect_min"), path="route_thresholds.architect_min", minimum=0)
    if source["unresolved_decisions"]:
        reasons.append("unresolved-decisions")

    if architect_gates.get("unresolved_decisions") is not True:
        raise ValueError("malformed policy: architect hard gate unresolved_decisions requires true")

    if scores["reasoning_uncertainty"] == int(architect_gates.get("reasoning_uncertainty", 3)):
        reasons.append("reasoning-uncertainty-architect")
    if scores["contract_risk"] == int(architect_gates.get("contract_risk", 3)):
        reasons.append("contract-risk-architect")

    if len(source["subsystems"]) > int(hard_caps.get("max_subsystems", 0)):
        reasons.append("too-many-subsystems")
    if len(source["write_paths"]) > int(hard_caps.get("max_write_paths", 0)):
        reasons.append("too-many-write-paths")
    if len(source["context_manifest"]) > int(hard_caps.get("max_context_entries", 0)):
        reasons.append("too-many-context-entries")
    if len(source["acceptance_checks"]) > int(hard_caps.get("max_acceptance_checks", 0)):
        reasons.append("too-many-acceptance-checks")
    if estimates["context_tokens_p90"] > int(hard_caps.get("max_context_tokens_p90", 0)):
        reasons.append("context-tokens-p90-exceeded")
    if estimates["tool_calls_p90"] > int(hard_caps.get("max_tool_calls_p90", 0)):
        reasons.append("tool-calls-p90-exceeded")
    if estimates["runtime_seconds_p90"] > int(hard_caps.get("max_runtime_seconds_p90", 0)):
        reasons.append("runtime-seconds-p90-exceeded")

    has_cap_reason = any(reason in reasons for reason in HARD_GATE_REASONS[3:])
    if reasons and any(r.startswith("too-many") or "exceeded" in r for r in reasons):
        has_cap_reason = True

    if reasons:
        if "unresolved-decisions" in reasons or "reasoning-uncertainty-architect" in reasons or "contract-risk-architect" in reasons:
            route = "architect"
        elif has_cap_reason and score_total < architect_min:
            route = "split"
        else:
            if score_total >= architect_min:
                route = "architect"
            elif score_total >= split_min:
                route = "split"
            else:
                route = "spark"
    else:
        if score_total >= architect_min:
            route = "architect"
        elif score_total >= split_min:
            route = "split"
        else:
            route = "spark"

    if route == "split":
        if score_total > split_max:
            route = "architect"

    if route == "spark" and score_total > spark_fit_max:
        route = "split"

    if score_total >= architect_min:
        route = "architect"
    return route, reasons


def _evaluate_v2_route(
    source: Mapping[str, Any],
    estimates: Mapping[str, Any],
    semantic_payload: dict[str, Any] | None,
    semantic_policy: Mapping[str, Any],
) -> tuple[str, list[str], dict[str, int], dict[str, Any], int, dict[str, str]]:
    reasons: list[str] = []
    if semantic_payload is None:
        reasons.append("semantic-authority-uncertainty")
        return (
            "architect",
            reasons,
            {},
            {"pm_estimate_delta": None, "domain_estimate_delta": None},
            _route_priority("architect"),
            {"authority_route": "architect", "operative_route": "split"},
        )

    semantic_scores = _compute_semantic_scores(semantic_payload)
    authority_uncertainty = (
        bool(source["unresolved_decisions"])
        or
        int(semantic_payload.get("self_hosting_risk", 0)) >= 3
        or int(semantic_payload.get("live_control_risk", 0)) >= 3
    )
    if authority_uncertainty:
        reasons.append("semantic-authority-uncertainty")

    expected_reads = int(semantic_payload["expected_context_reads"])
    expected_mutations = int(semantic_payload["expected_mutations"])
    zero_mutation_split = expected_mutations == 0 and expected_reads > 0
    spark_size_fit = (
        max(semantic_scores.values()) <= 2
        and not source["unresolved_decisions"]
        and int(semantic_payload["estimated_diff_p90"]) <= int(semantic_policy.get("max_diff_p90_for_spark", 350))
        and int(semantic_payload["behavioral_changes"]) <= int(semantic_policy.get("max_behavioral_changes_for_spark", 5))
        and int(semantic_payload["expected_regressions"]) <= int(semantic_policy.get("max_expected_regressions_for_spark", 12))
        and len(source["write_paths"]) <= int(semantic_policy.get("max_write_paths_for_spark", 6))
        and int(semantic_payload["expected_context_reads"]) <= int(semantic_policy.get("max_context_reads_for_spark", 12))
        and float(semantic_payload["read_to_mutation_ratio"]) <= float(semantic_policy.get("max_read_mutation_ratio_for_spark", 6))
        and int(estimates["tool_calls_p90"]) <= int(semantic_policy.get("max_tool_calls_p90", 25))
        and int(estimates["runtime_seconds_p90"]) <= int(semantic_policy.get("max_runtime_seconds_p90", 480))
        and not zero_mutation_split
    )
    operative_route = "spark" if spark_size_fit else "split"
    if zero_mutation_split:
        reasons.append("semantic-read-mutation-split-trigger")
    if int(semantic_payload["self_hosting_risk"]) >= 3 and int(semantic_payload["test_construction_complexity"]) >= 3:
        operative_route = "split"
        if "semantic-read-mutation-split-trigger" not in reasons:
            reasons.append("semantic-read-mutation-split-trigger")

    authority_route = "architect" if authority_uncertainty else "spark"
    route_priority = max(_route_priority(authority_route), _route_priority(operative_route))
    route = _route_from_priority(route_priority)
    return (
        route,
        reasons,
        semantic_scores,
        {"pm_estimate_delta": None, "domain_estimate_delta": None},
        route_priority,
        {"authority_route": authority_route, "operative_route": operative_route},
    )


def evaluate_work_estimate(payload: Any, policy: Mapping[str, Any] | None = None) -> dict[str, Any]:
    try:
        source = canonical_json_object(payload, label="work-estimate-payload")
    except AuthorityProvenanceError as exc:
        raise ValueError(str(exc)) from exc
    normalized = _validate_required_fields(source)
    work_sizing = _load_work_sizing_policy(policy)
    if int(work_sizing.get("version", 0)) != 1:
        raise ValueError("malformed policy: work_sizing.version must be 1")

    route_thresholds = _route_thresholds(work_sizing)
    hard_caps = _hard_caps(work_sizing)
    architect_gates = _architect_gates(work_sizing)
    replanning = _autonomous_replanning(work_sizing)
    task_class_policy = _task_class_policy(work_sizing)
    protected_surfaces = _protected_surface_groups(work_sizing)
    scores = normalized["scores"]
    estimates = normalized["estimates"]
    score_total = sum(int(scores[dimension]) for dimension in DIMENSIONS)
    v1_route, reasons = _evaluate_v1_route(
        source,
        scores,
        estimates,
        route_thresholds=route_thresholds,
        hard_caps=hard_caps,
        architect_gates=architect_gates,
    )
    hard_gate_reasons = sorted(set(reasons), key=lambda item: HARD_GATE_REASONS.index(item))

    estimate_contract_version = int(normalized["estimate_contract_version"])
    semantic_route = v1_route
    semantic_scores: dict[str, int] = {}
    route_conflict = False
    variance_metrics: dict[str, Any] = {}
    route_axes = {"authority_route": v1_route, "operative_route": v1_route}
    if estimate_contract_version >= 2:
        semantic_policy = _semantic_routing_policy(work_sizing)
        (
            semantic_route,
            semantic_reasons,
            semantic_scores,
            variance_metrics,
            semantic_priority,
            route_axes,
        ) = _evaluate_v2_route(
            source=source,
            estimates=estimates,
            semantic_payload=normalized["semantic_estimate"],
            semantic_policy=semantic_policy,
        )
        hard_gate_reasons.extend(semantic_reasons)

        # Authority-vs-size route conflict and deterministic variance.
        pm_estimate = normalized.get("pm_estimate")
        domain_estimate = normalized.get("domain_expert_estimate")
        thresholds = _ensure_mapping_exact(
            _ensure_mapping(semantic_policy.get("variance_thresholds"), label="semantic_routing.variance_thresholds")
            if semantic_policy.get("variance_thresholds")
            else {
                "pm_tool_calls_p90_delta": 8,
                "pm_runtime_seconds_p90_delta": 90,
                "domain_tool_calls_p90_delta": 8,
                "domain_runtime_seconds_p90_delta": 90,
            },
            path="semantic_routing.variance_thresholds",
            required_fields=(
                "pm_tool_calls_p90_delta",
                "pm_runtime_seconds_p90_delta",
                "domain_tool_calls_p90_delta",
                "domain_runtime_seconds_p90_delta",
            ),
        )

        if pm_estimate is not None and isinstance(pm_estimate, Mapping):
            pm_delta = _estimate_deltas(estimates, pm_estimate)
            variance_metrics["pm_estimate_delta"] = pm_delta
            if pm_delta["tool_calls_p90"] > int(thresholds["pm_tool_calls_p90_delta"]) or pm_delta["runtime_seconds_p90"] > int(
                thresholds["pm_runtime_seconds_p90_delta"]
            ):
                route_conflict = True
        if domain_estimate is not None and isinstance(domain_estimate, Mapping):
            domain_delta = _estimate_deltas(estimates, domain_estimate)
            variance_metrics["domain_estimate_delta"] = domain_delta
            if domain_delta["tool_calls_p90"] > int(
                thresholds["domain_tool_calls_p90_delta"]
            ) or domain_delta["runtime_seconds_p90"] > int(thresholds["domain_runtime_seconds_p90_delta"]):
                route_conflict = True

        if route_conflict and "semantic-estimate-variance" not in hard_gate_reasons:
            hard_gate_reasons.append("semantic-estimate-variance")

        if (v1_priority := _route_priority(v1_route)) != (semantic_priority := _route_priority(semantic_route)) or route_conflict:
            if "semantic-route-conflict" not in hard_gate_reasons:
                hard_gate_reasons.append("semantic-route-conflict")
            final_priority = max(v1_priority, semantic_priority, 1)
        else:
            final_priority = v1_priority

        # Preserve explicit authority separation: architect if semantic route asks architect and v1 did not escalate.
        if semantic_route == "architect" and final_priority < _route_priority("architect"):
            final_priority = _route_priority("architect")
        route = _route_from_priority(final_priority)
    else:
        route = v1_route

    task_profile = normalized["task_profile"]
    source_mutation_paths = (
        list(task_profile.get("source_mutation_paths", []))
        if isinstance(task_profile, Mapping)
        else []
    )
    protected_surface_matches = _derive_protected_surface_matches(
        list(source["write_paths"]),
        source_mutation_paths,
        protected_surfaces,
    )
    task_class, fit_mode, fit_evidence, protected_surface_matches = _evaluate_task_profile_fit(
        source,
        normalized["semantic_estimate"],
        task_profile,
        task_class_policy,
        protected_surface_matches,
        protected_surfaces,
    )

    profile_contradiction = bool(fit_evidence.get("contradictions"))
    authority_reasons = {
        "unresolved-decisions",
        "reasoning-uncertainty-architect",
        "contract-risk-architect",
        "semantic-authority-uncertainty",
    }
    if profile_contradiction:
        hard_gate_reasons.append("task-profile-contradiction")
        route = "architect"
        route_axes = {"authority_route": "architect", "operative_route": "architect"}
    elif fit_mode == "architect":
        route = "architect"
        route_axes = {"authority_route": "architect", "operative_route": "architect"}
    elif fit_mode == "deterministic":
        retained_authority_reasons = [reason for reason in hard_gate_reasons if reason in authority_reasons]
        hard_gate_reasons = retained_authority_reasons
        if retained_authority_reasons:
            route = "architect"
            route_axes = {"authority_route": "architect", "operative_route": "spark"}
        else:
            route = "spark"
            route_axes = {"authority_route": "spark", "operative_route": "spark"}

    # Ensure stable ordering and no duplicates for reporting.
    hard_gate_reasons = sorted(set(hard_gate_reasons), key=HARD_GATE_REASONS.index)

    aggregate_allowance = {
        "dispatch_soft_cap": int(replanning.get("dispatch_soft_cap", 0)),
        "dispatch_soft_cap_action": str(replanning.get("dispatch_soft_cap_action", "pm-architect-review")),
        "continuation_authority": "pm-architect-within-aggregate-budget",
        "max_pm_replans": int(replanning.get("max_pm_replans", 0)),
        "max_architect_cycles": int(replanning.get("max_architect_cycles", 0)),
        "max_compactions": int(replanning.get("max_compactions", 0)),
        "tool_calls_hard": int(estimates["tool_calls_p90"]) + int(replanning.get("tool_calls_extra", 0)),
        "runtime_seconds_hard": int(estimates["runtime_seconds_p90"]) + int(replanning.get("runtime_seconds_extra", 0)),
    }
    if fit_mode == "deterministic" and route == "spark":
        class_policy = _ensure_mapping(
            task_class_policy.get(task_class),
            label=f"task_class_policy.{task_class}",
        )
        aggregate_allowance["tool_calls_hard"] = _ensure_int(
            class_policy.get("tool_calls_hard"),
            path=f"task_class_policy.{task_class}.tool_calls_hard",
            minimum=1,
        )
        aggregate_allowance["runtime_seconds_hard"] = _ensure_int(
            class_policy.get("runtime_seconds_hard"),
            path=f"task_class_policy.{task_class}.runtime_seconds_hard",
            minimum=1,
        )

    estimate: dict[str, Any] = deepcopy(source)
    if task_profile is not None:
        estimate["task_profile"] = deepcopy(task_profile)
    if estimate_contract_version >= 2:
        estimate["estimate_contract_version"] = estimate_contract_version
        estimate["semantic_scores"] = semantic_scores
        estimate["v1_route"] = v1_route
        estimate["semantic_route"] = semantic_route
        estimate["authority_route"] = route_axes["authority_route"]
        estimate["operative_route"] = route_axes["operative_route"]
        estimate["route_conflict"] = route_conflict
        estimate["variance_metrics"] = variance_metrics
    estimate["score_total"] = score_total
    estimate["route"] = route
    estimate["hard_gate_reasons"] = hard_gate_reasons
    estimate["aggregate_allowance"] = aggregate_allowance
    estimate["task_class"] = task_class
    estimate["fit_mode"] = fit_mode
    estimate["protected_surface_matches"] = protected_surface_matches
    estimate["fit_evidence"] = fit_evidence
    return estimate


def validate_work_estimate(
    payload: Any,
    policy: Mapping[str, Any] | None = None,
    *,
    allow_refinement_inspection: bool = False,
) -> list[str]:
    try:
        source = canonical_json_object(payload, label="work-estimate")
    except AuthorityProvenanceError as exc:
        return [str(exc)]
    errors: list[str] = []
    if (
        any(field in source for field in REFINEMENT_LINEAGE_FIELDS)
        and not allow_refinement_inspection
    ):
        return [
            "refined work estimate requires validate_work_estimate_refinement before operative use"
        ]

    try:
        computed = evaluate_work_estimate(source, policy=policy)
    except ValueError as exc:
        errors.append(str(exc))
        return errors

    for field in DERIVED_FIELDS:
        if field not in source:
            errors.append(f"malformed source payload: missing enriched field {field}")

    if "task_profile" in source:
        for field in DERIVED_TASK_PROFILE_FIELDS:
            if field not in source:
                errors.append(f"malformed source payload: missing enriched field {field}")

    if errors:
        return errors

    def exact_match(left: Any, right: Any) -> bool:
        return canonical_authority_sha256(left) == canonical_authority_sha256(right)

    if not exact_match(source["score_total"], computed["score_total"]):
        errors.append("derived check failed: score_total must equal computed score_total")
    if not exact_match(source["route"], computed["route"]):
        errors.append("derived check failed: route must equal computed route")
    if not exact_match(source["hard_gate_reasons"], computed["hard_gate_reasons"]):
        errors.append("derived check failed: hard_gate_reasons must equal computed hard_gate_reasons")
    if not exact_match(source["aggregate_allowance"], computed["aggregate_allowance"]):
        errors.append("derived check failed: aggregate_allowance must equal computed aggregate_allowance")
    for field in DERIVED_TASK_PROFILE_FIELDS:
        if field in source and not exact_match(source.get(field), computed.get(field)):
            errors.append(f"derived check failed: {field} must equal computed {field}")
    if int(source.get("estimate_contract_version", 1)) >= 2:
        for field in (
            "semantic_scores",
            "v1_route",
            "semantic_route",
            "authority_route",
            "operative_route",
            "route_conflict",
            "variance_metrics",
        ):
            if not exact_match(source.get(field), computed.get(field)):
                errors.append(f"derived check failed: {field} must equal computed {field}")

    return errors


def canonical_work_estimate_sha256(work_estimate: Any) -> str:
    try:
        source = canonical_json_object(work_estimate, label="work-estimate")
    except AuthorityProvenanceError as exc:
        raise ValueError(str(exc)) from exc
    canonical = json.dumps(source, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _refinement_operator_policy(
    policy: Mapping[str, Any] | None,
) -> tuple[Mapping[str, Any], list[str]]:
    work_sizing = _load_work_sizing_policy(policy)
    replanning = _autonomous_replanning(work_sizing)
    configured = _ensure_list(
        replanning.get("operator_required_for"),
        path="work_sizing.autonomous_replanning.operator_required_for",
    )
    if (
        not configured
        or any(not isinstance(value, str) or not value for value in configured)
        or len(configured) != len(set(configured))
        or set(configured) != set(OPERATOR_REQUIRED_CHANGE_TYPES)
    ):
        raise ValueError(
            "malformed policy: operator_required_for must contain every supported "
            "protected change category exactly once"
        )
    return work_sizing, list(configured)


def build_work_estimate_refinement(
    parent_estimate: Any,
    refined_payload: Any,
    *,
    refinement_authority: VerifiedAuthority,
    operator_approval_verifier: OperatorApprovalVerifier | None = None,
    operator_approval_receipts: Mapping[str, Any] | None = None,
    policy: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a strict-write refinement bound to its parent and trusted actor."""

    try:
        parent = canonical_json_object(
            parent_estimate, label="parent-estimate"
        )
        source = canonical_json_object(
            refined_payload, label="refined-payload"
        )
    except AuthorityProvenanceError as exc:
        raise ValueError(str(exc)) from exc
    parent_errors = validate_work_estimate(
        parent,
        policy=policy,
        allow_refinement_inspection=True,
    )
    if parent_errors:
        raise ValueError("invalid parent_estimate: " + "; ".join(parent_errors))
    supplied_lineage = sorted(set(source) & set(REFINEMENT_LINEAGE_FIELDS))
    if supplied_lineage:
        raise ValueError(
            "refined_payload cannot supply verifier-owned lineage field(s): "
            + ", ".join(supplied_lineage)
        )
    try:
        require_minimum_authority(
            refinement_authority,
            "pm",
            action="work-estimate-refinement",
        )
    except AuthorityProvenanceError as exc:
        raise ValueError(str(exc)) from exc
    for identity_field in ("work_unit_id", "bead_id"):
        if source.get(identity_field) != parent.get(identity_field):
            raise ValueError(
                f"refined_payload.{identity_field} must match parent_estimate.{identity_field}"
            )

    candidate = evaluate_work_estimate(source, policy=policy)
    candidate["parent_estimate_sha256"] = canonical_work_estimate_sha256(parent)
    candidate["refinement_authority"] = refinement_authority.serialize()
    _, operator_required_for = _refinement_operator_policy(policy)
    try:
        assessment = assess_operator_required_changes(
            parent,
            candidate,
            operator_required_for=operator_required_for,
            profile="native-work-estimate-refinement",
            identity=protected_change_identity(
                artifact_type="cwo-native-work-estimate-refinement",
                artifact_id=candidate["parent_estimate_sha256"],
                work_unit_id=candidate["work_unit_id"],
                bead_id=candidate["bead_id"],
                packet_id=None,
            ),
        )
    except AuthorityProvenanceError as exc:
        raise ValueError(str(exc)) from exc
    protected_changes = list(assessment.required_change_types)

    try:
        receipts = canonical_json_object(
            {} if operator_approval_receipts is None else operator_approval_receipts,
            label="operator-approval-receipts",
        )
    except AuthorityProvenanceError as exc:
        raise ValueError(str(exc)) from exc
    approvals = []
    if protected_changes:
        if not isinstance(operator_approval_verifier, OperatorApprovalVerifier):
            raise ValueError(
                "work-estimate refinement requires a verified operator approval for: "
                + ",".join(protected_changes)
            )
        try:
            approvals = operator_approval_verifier.authorize_assessment(
                assessment,
                receipts=receipts,
                prior_nonces={
                    str(approval["nonce"])
                    for approval in parent.get(
                        "protected_change_authorizations", []
                    )
                },
            )
        except AuthorityProvenanceError as exc:
            raise ValueError(str(exc)) from exc
    elif receipts:
        raise ValueError("work-estimate refinement contains unexpected operator approvals")

    candidate["operator_approval_receipts"] = receipts
    candidate["protected_change_authorizations"] = [
        approval.audit_record() for approval in approvals
    ]
    lineage_errors = validate_work_estimate(
        candidate,
        policy=policy,
        allow_refinement_inspection=True,
    )
    if lineage_errors:
        raise ValueError("invalid work-estimate refinement: " + "; ".join(lineage_errors))
    return candidate


def validate_work_estimate_refinement(
    refinement: Any,
    parent_estimate: Any,
    *,
    refinement_authority: VerifiedAuthority,
    operator_approval_verifier: OperatorApprovalVerifier | None = None,
    policy: Mapping[str, Any] | None = None,
) -> list[str]:
    """Validate a refinement chain before it can drive a new operative write."""

    errors: list[str] = []
    try:
        parent = canonical_json_object(parent_estimate, label="parent-estimate")
        candidate = canonical_json_object(refinement, label="refinement")
    except AuthorityProvenanceError as exc:
        return [str(exc)]
    errors.extend(
        "invalid parent_estimate: " + error
        for error in validate_work_estimate(
            parent,
            policy=policy,
            allow_refinement_inspection=True,
        )
    )
    errors.extend(
        "invalid refinement: " + error
        for error in validate_work_estimate(
            candidate,
            policy=policy,
            allow_refinement_inspection=True,
        )
    )
    if errors:
        return errors
    if candidate.get("parent_estimate_sha256") != canonical_work_estimate_sha256(
        parent
    ):
        errors.append("refinement parent_estimate_sha256 does not match parent")
    try:
        require_minimum_authority(
            refinement_authority,
            "pm",
            action="work-estimate-refinement",
        )
    except AuthorityProvenanceError as exc:
        errors.append(str(exc))
    else:
        if candidate.get("refinement_authority") != refinement_authority.serialize():
            errors.append("refinement authority does not match verified caller authority")
    if candidate.get("work_unit_id") != parent.get("work_unit_id"):
        errors.append("refinement work_unit_id does not match parent")
    if candidate.get("bead_id") != parent.get("bead_id"):
        errors.append("refinement bead_id does not match parent")
    if errors:
        return errors

    try:
        _, operator_required_for = _refinement_operator_policy(policy)
        assessment = assess_operator_required_changes(
            parent,
            candidate,
            operator_required_for=operator_required_for,
            profile="native-work-estimate-refinement",
            identity=protected_change_identity(
                artifact_type="cwo-native-work-estimate-refinement",
                artifact_id=canonical_work_estimate_sha256(parent),
                work_unit_id=candidate["work_unit_id"],
                bead_id=candidate["bead_id"],
                packet_id=None,
            ),
        )
        protected_changes = list(assessment.required_change_types)
        if protected_changes:
            if not isinstance(operator_approval_verifier, OperatorApprovalVerifier):
                errors.append(
                    "refinement operator approval verifier required for: "
                    + ",".join(protected_changes)
                )
            else:
                approvals = operator_approval_verifier.authorize_assessment(
                    assessment,
                    receipts=candidate.get("operator_approval_receipts"),
                    prior_nonces={
                        str(approval["nonce"])
                        for approval in parent.get(
                            "protected_change_authorizations", []
                        )
                    },
                )
                expected_audit = [approval.audit_record() for approval in approvals]
                if candidate.get("protected_change_authorizations") != expected_audit:
                    errors.append("refinement operator approval audit mismatch")
        elif candidate.get("operator_approval_receipts") or candidate.get(
            "protected_change_authorizations"
        ):
            errors.append("refinement contains unexpected operator approvals")
    except (AuthorityProvenanceError, ValueError) as exc:
        errors.append(str(exc))
    return errors


def build_policy_fit_commitment(
    work_estimate: Any,
    *,
    precommit_receipt: Mapping[str, Any] | None = None,
    session_id: str | None = None,
    attested_model: str | None = None,
    policy: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Build commitment v2 only from an accepting deterministic trusted receipt."""
    if precommit_receipt is None:
        raise ValueError("deterministic policy fit requires a trusted precommit receipt")
    if session_id is not None or attested_model is not None:
        raise ValueError("session and model identity must be derived exclusively from the precommit receipt")
    estimate_errors = validate_work_estimate(work_estimate, policy=policy)
    if estimate_errors:
        raise ValueError("invalid work_estimate: " + "; ".join(estimate_errors))
    estimate = deepcopy(_ensure_mapping(work_estimate, label="work_estimate"))
    requested_model = _ensure_nonempty_str(estimate.get("requested_model"), path="work_estimate.requested_model")
    if requested_model != "gpt-5.3-codex-spark":
        raise ValueError("policy-derived commitment requires requested_model gpt-5.3-codex-spark")
    if estimate.get("fit_mode") != "deterministic":
        raise ValueError("policy-derived commitment requires work_estimate.fit_mode deterministic")
    if any(estimate.get(field) != "spark" for field in ("route", "authority_route", "operative_route")):
        raise ValueError("policy-derived commitment requires Spark route and authority axes")

    work_sizing = _load_work_sizing_policy(policy)
    task_class = _ensure_nonempty_str(estimate.get("task_class"), path="work_estimate.task_class")
    class_policy = _ensure_mapping(
        _task_class_policy(work_sizing).get(task_class),
        label=f"task_class_policy.{task_class}",
    )
    estimates = {
        "tool_calls_p50": _ensure_int(
            class_policy.get("tool_calls_p50"),
            path=f"task_class_policy.{task_class}.tool_calls_p50",
            minimum=1,
        ),
        "tool_calls_p90": _ensure_int(
            class_policy.get("tool_calls_p90"),
            path=f"task_class_policy.{task_class}.tool_calls_p90",
            minimum=1,
        ),
        "runtime_seconds_p50": _ensure_int(
            class_policy.get("runtime_seconds_p50"),
            path=f"task_class_policy.{task_class}.runtime_seconds_p50",
            minimum=1,
        ),
        "runtime_seconds_p90": _ensure_int(
            class_policy.get("runtime_seconds_p90"),
            path=f"task_class_policy.{task_class}.runtime_seconds_p90",
            minimum=1,
        ),
    }
    receipt_errors = validate_precommit_receipt(
        precommit_receipt,
        estimate,
        expected_packet_id=str(precommit_receipt.get("packet_id") or ""),
        require_accepting=True,
    )
    if receipt_errors:
        raise ValueError("invalid deterministic precommit receipt: " + "; ".join(receipt_errors))
    if precommit_receipt.get("submission_id") != "deterministic-policy":
        raise ValueError("policy-derived commitment requires a deterministic zero-length receipt")
    fit_result = precommit_receipt.get("fit_result")
    if not isinstance(fit_result, Mapping) or fit_result.get("decision") != "accept":
        raise ValueError("deterministic precommit receipt must contain an accepting fit result")
    if fit_result.get("estimates") != estimates:
        raise ValueError("deterministic precommit receipt estimates must exactly match task-class policy")
    commitment = {
        "commitment_type": "cwo-native-worker-fit-commitment",
        "version": 2,
        "packet_id": precommit_receipt["packet_id"],
        "attempt_nonce": precommit_receipt["attempt_nonce"],
        "work_unit_id": estimate["work_unit_id"],
        "bead_id": estimate["bead_id"],
        "requested_model": requested_model,
        "session_id": precommit_receipt["session_id"],
        "agent_id": precommit_receipt["agent_id"],
        "attestation_source": precommit_receipt["attestation_source"],
        "attested_model": precommit_receipt["attested_model"],
        "work_estimate_sha256": canonical_work_estimate_sha256(estimate),
        "decision": "accept",
        "estimates": estimates,
        "precommit_receipt_sha256": precommit_receipt["receipt_sha256"],
    }
    commitment_errors = validate_worker_commitment(
        commitment,
        estimate,
        policy=policy,
        dispatchable=True,
        precommit_receipt=precommit_receipt,
    )
    if commitment_errors:
        raise ValueError("invalid policy-derived commitment: " + "; ".join(commitment_errors))
    return commitment


def build_worker_commitment_from_receipt(
    work_estimate: Any,
    precommit_receipt: Mapping[str, Any],
    *,
    policy: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    estimate_errors = validate_work_estimate(work_estimate, policy=policy)
    if estimate_errors:
        raise ValueError("invalid work_estimate: " + "; ".join(estimate_errors))
    estimate = deepcopy(_ensure_mapping(work_estimate, label="work_estimate"))
    receipt_errors = validate_precommit_receipt(
        precommit_receipt,
        estimate,
        expected_packet_id=str(precommit_receipt.get("packet_id") or ""),
        require_accepting=True,
    )
    if receipt_errors:
        raise ValueError("invalid precommit receipt: " + "; ".join(receipt_errors))
    fit_result = precommit_receipt.get("fit_result")
    if not isinstance(fit_result, Mapping):
        raise ValueError("precommit receipt fit_result is missing")
    commitment = {
        "commitment_type": "cwo-native-worker-fit-commitment",
        "version": 2,
        "packet_id": precommit_receipt["packet_id"],
        "attempt_nonce": precommit_receipt["attempt_nonce"],
        "work_unit_id": precommit_receipt["work_unit_id"],
        "bead_id": precommit_receipt["bead_id"],
        "requested_model": precommit_receipt["requested_model"],
        "session_id": precommit_receipt["session_id"],
        "agent_id": precommit_receipt["agent_id"],
        "attestation_source": precommit_receipt["attestation_source"],
        "attested_model": precommit_receipt["attested_model"],
        "work_estimate_sha256": canonical_work_estimate_sha256(estimate),
        "decision": fit_result["decision"],
        "estimates": deepcopy(fit_result["estimates"]),
        "precommit_receipt_sha256": precommit_receipt["receipt_sha256"],
    }
    errors = validate_worker_commitment(
        commitment,
        estimate,
        policy=policy,
        dispatchable=commitment["decision"] == "accept",
        precommit_receipt=precommit_receipt,
    )
    if errors:
        raise ValueError("invalid receipt-derived commitment: " + "; ".join(errors))
    return commitment


def _validate_worker_commitment_v2(
    commitment: Mapping[str, Any],
    work_estimate: Mapping[str, Any],
    precommit_receipt: Mapping[str, Any] | None,
    *,
    policy: Mapping[str, Any] | None,
    dispatchable: bool,
) -> list[str]:
    errors: list[str] = []
    try:
        source_fields = set(commitment)
        required = set(COMMITMENT_V2_REQUIRED_FIELDS)
        if missing := sorted(required - source_fields):
            raise ValueError(f"malformed source payload: commitment missing required field(s) {', '.join(missing)}")
        if unknown := sorted(source_fields - required):
            raise ValueError(f"malformed source payload: commitment has unknown field(s) {', '.join(unknown)}")
        if commitment.get("commitment_type") != "cwo-native-worker-fit-commitment":
            raise ValueError("commitment.commitment_type is invalid")
        if commitment.get("version") != 2:
            raise ValueError("commitment.version must equal 2")
        if precommit_receipt is None:
            raise ValueError("commitment version 2 requires the bound precommit receipt")
        receipt_errors = validate_precommit_receipt(
            precommit_receipt,
            work_estimate,
            expected_packet_id=str(commitment.get("packet_id") or ""),
            require_accepting=dispatchable or commitment.get("decision") == "accept",
        )
        if receipt_errors:
            raise ValueError("commitment precommit receipt is invalid: " + "; ".join(receipt_errors))
        fit_result = precommit_receipt.get("fit_result")
        if not isinstance(fit_result, Mapping):
            raise ValueError("commitment precommit receipt fit_result is missing")
        expected = {
            "packet_id": precommit_receipt.get("packet_id"),
            "attempt_nonce": precommit_receipt.get("attempt_nonce"),
            "work_unit_id": work_estimate.get("work_unit_id"),
            "bead_id": work_estimate.get("bead_id"),
            "requested_model": work_estimate.get("requested_model"),
            "session_id": precommit_receipt.get("session_id"),
            "agent_id": precommit_receipt.get("agent_id"),
            "attestation_source": precommit_receipt.get("attestation_source"),
            "attested_model": precommit_receipt.get("attested_model"),
            "work_estimate_sha256": canonical_work_estimate_sha256(work_estimate),
            "decision": fit_result.get("decision"),
            "estimates": fit_result.get("estimates"),
            "precommit_receipt_sha256": precommit_receipt.get("receipt_sha256"),
        }
        for field, expected_value in expected.items():
            if commitment.get(field) != expected_value:
                raise ValueError(f"commitment.{field} must derive exclusively from the validated precommit receipt and work plan")
        estimates = _ensure_estimate_mapping(commitment.get("estimates"), path="commitment.estimates")
        allowance = _ensure_mapping(work_estimate.get("aggregate_allowance"), label="work_estimate.aggregate_allowance")
        if estimates["tool_calls_p90"] > int(allowance.get("tool_calls_hard", -1)):
            raise ValueError("commitment.estimates.tool_calls_p90 exceeds work plan aggregate hard allowance")
        if estimates["runtime_seconds_p90"] > int(allowance.get("runtime_seconds_hard", -1)):
            raise ValueError("commitment.estimates.runtime_seconds_p90 exceeds work plan aggregate hard allowance")
        if dispatchable and commitment.get("decision") != "accept":
            raise ValueError("dispatchable commitment decision must be accept")
    except (TypeError, ValueError) as exc:
        errors.append(str(exc))
    return errors


def validate_worker_commitment(
    commitment: Any,
    work_estimate: Any,
    policy: Mapping[str, Any] | None = None,
    *,
    dispatchable: bool = False,
    precommit_receipt: Mapping[str, Any] | None = None,
) -> list[str]:
    commitment_source = deepcopy(commitment)
    errors: list[str] = []
    if not isinstance(commitment_source, Mapping):
        return ["malformed source payload: source must be a mapping"]

    work_sizing = _load_work_sizing_policy(policy)
    if int(work_sizing.get("version", 0)) != 1:
        return ["malformed policy: work_sizing.version must be 1"]
    commitment_policy = _commitment_policy(work_sizing)

    estimate_errors = validate_work_estimate(work_estimate, policy=policy)
    if estimate_errors:
        return [f"invalid work_estimate: {error}" for error in estimate_errors]
    validated_estimate = _ensure_mapping(work_estimate, label="work_estimate")

    version = commitment_source.get("version")
    if version == 2:
        return _validate_worker_commitment_v2(
            commitment_source,
            validated_estimate,
            precommit_receipt,
            policy=policy,
            dispatchable=dispatchable,
        )
    if dispatchable:
        return ["commitment version 1 is historical-inspection-only and dispatch-forbidden"]

    expected_model = str(validated_estimate.get("requested_model", ""))
    expected_work_unit = str(validated_estimate.get("work_unit_id", ""))
    expected_bead = str(validated_estimate.get("bead_id", ""))

    try:
        commitment_fields = set(COMMITMENT_V1_REQUIRED_FIELDS)
        source_fields = set(commitment_source.keys())
        if missing_fields := sorted(commitment_fields - source_fields):
            raise ValueError(f"malformed source payload: commitment missing required field(s) {', '.join(missing_fields)}")
        if unknown_fields := sorted(source_fields - commitment_fields):
            raise ValueError(f"malformed source payload: commitment has unknown field(s) {', '.join(unknown_fields)}")

        _ensure_nonempty_str(commitment_source["commitment_type"], path="commitment.commitment_type")
        if commitment_source["commitment_type"] != str(commitment_policy.get("receipt_type", "")):
            raise ValueError("commitment.commitment_type must equal configured receipt_type")
        _ensure_int(commitment_source.get("version"), path="commitment.version", minimum=1, maximum=1)
        _ensure_nonempty_str(commitment_source["work_unit_id"], path="commitment.work_unit_id")
        _ensure_nonempty_str(commitment_source["bead_id"], path="commitment.bead_id")
        _ensure_nonempty_str(commitment_source["requested_model"], path="commitment.requested_model")
        _ensure_nonempty_str(commitment_source["session_id"], path="commitment.session_id")
        _ensure_nonempty_str(commitment_source["attestation_source"], path="commitment.attestation_source")
        if commitment_source["attestation_source"] != "trusted-session-jsonl":
            raise ValueError("historical commitment.attestation_source must equal trusted-session-jsonl")
        _ensure_nonempty_str(commitment_source["attested_model"], path="commitment.attested_model")
        if commitment_source["attested_model"] != commitment_source["requested_model"]:
            raise ValueError("commitment.attested_model must match commitment.requested_model")
        if commitment_source["requested_model"] != expected_model:
            raise ValueError("commitment.requested_model must match work_estimate.requested_model")

        work_estimate_sha256 = _ensure_nonempty_str(commitment_source["work_estimate_sha256"], path="commitment.work_estimate_sha256")
        if len(work_estimate_sha256) != 64 or any(char not in "0123456789abcdef" for char in work_estimate_sha256):
            raise ValueError("commitment.work_estimate_sha256 must be a lowercase SHA-256 hex digest")
        if work_estimate_sha256 != canonical_work_estimate_sha256(validated_estimate):
            raise ValueError("commitment.work_estimate_sha256 does not match evaluated work estimate payload")

        decision = _ensure_nonempty_str(commitment_source["decision"], path="commitment.decision")
        if decision not in COMMITMENT_DECISIONS:
            raise ValueError("commitment.decision must be accept, pm-realignment, or architect-realignment")
        configurable_decisions = _ensure_list(commitment_policy.get("decisions"), path="work_sizing.commitment.decisions")
        for idx, item in enumerate(configurable_decisions):
            if not isinstance(item, str) or not item:
                raise ValueError(f"malformed policy: commitment.decisions[{idx}] must be a non-empty string")
        if dispatchable:
            dispatchable_decision = _ensure_nonempty_str(commitment_policy.get("dispatchable_decision"), path="work_sizing.commitment.dispatchable_decision")
            if decision != dispatchable_decision:
                raise ValueError("commitment.decision must be the dispatchable decision for dispatchable commitments")
        elif decision not in configurable_decisions:
            raise ValueError("commitment.decision must match configured commitment decision set")

        confidence = _ensure_float(commitment_source.get("confidence"), path="commitment.confidence")
        min_confidence = float(commitment_policy.get("historical_v1_min_confidence", 0.75))
        if confidence < min_confidence:
            raise ValueError(f"commitment.confidence must be at least {min_confidence}")
        if commitment_source["work_unit_id"] != expected_work_unit:
            raise ValueError("commitment.work_unit_id must match work_estimate.work_unit_id")
        if commitment_source["bead_id"] != expected_bead:
            raise ValueError("commitment.bead_id must match work_estimate.bead_id")

        estimates = _ensure_mapping(commitment_source.get("estimates"), label="commitment.estimates")
        estimate_fields = set(COMMITMENT_ESTIMATE_KEYS)
        if missing := sorted(estimate_fields - set(estimates.keys())):
            raise ValueError(f"commitment.estimates missing required field(s) {', '.join(missing)}")
        extra = sorted(set(estimates.keys()) - estimate_fields)
        if extra:
            raise ValueError(f"commitment.estimates has unknown field(s) {', '.join(extra)}")

        positive_estimates_required = bool(commitment_policy.get("positive_estimates_required", False))
        estimate_minimum = 1 if positive_estimates_required else 0
        tool_calls_p50 = _ensure_int(estimates.get("tool_calls_p50"), path="commitment.estimates.tool_calls_p50", minimum=estimate_minimum)
        tool_calls_p90 = _ensure_int(estimates.get("tool_calls_p90"), path="commitment.estimates.tool_calls_p90", minimum=estimate_minimum)
        runtime_p50 = _ensure_int(estimates.get("runtime_seconds_p50"), path="commitment.estimates.runtime_seconds_p50", minimum=estimate_minimum)
        runtime_p90 = _ensure_int(estimates.get("runtime_seconds_p90"), path="commitment.estimates.runtime_seconds_p90", minimum=estimate_minimum)
        if tool_calls_p50 > tool_calls_p90:
            raise ValueError("commitment.estimates.tool_calls_p50 must be <= commitment.estimates.tool_calls_p90")
        if runtime_p50 > runtime_p90:
            raise ValueError("commitment.estimates.runtime_seconds_p50 must be <= commitment.estimates.runtime_seconds_p90")

        if commitment_policy.get("estimate_bound") == "within-work-plan-aggregate-hard-allowance":
            allowance = _ensure_mapping(validated_estimate.get("aggregate_allowance"), label="work_estimate.aggregate_allowance")
            tool_calls_hard = _ensure_int(allowance.get("tool_calls_hard"), path="work_estimate.aggregate_allowance.tool_calls_hard", minimum=0)
            runtime_hard = _ensure_int(allowance.get("runtime_seconds_hard"), path="work_estimate.aggregate_allowance.runtime_seconds_hard", minimum=0)
            if tool_calls_p90 > tool_calls_hard:
                raise ValueError("commitment.estimates.tool_calls_p90 exceeds work_estimate.aggregate_allowance.tool_calls_hard")
            if runtime_p90 > runtime_hard:
                raise ValueError("commitment.estimates.runtime_seconds_p90 exceeds work_estimate.aggregate_allowance.runtime_seconds_hard")
        elif str(commitment_policy.get("estimate_bound", "")):
            raise ValueError("unsupported commitment.estimate_bound")

        precommitment_tool_calls = _ensure_int(
            commitment_source.get("tool_calls_before_commitment"),
            path="commitment.tool_calls_before_commitment",
            maximum=0,
        )
        precommitment_compactions = _ensure_int(
            commitment_source.get("context_compactions_before_commitment"),
            path="commitment.context_compactions_before_commitment",
            maximum=0,
        )
        if precommitment_tool_calls != 0:
            raise ValueError("commitment.tool_calls_before_commitment must be 0")
        if precommitment_compactions != 0:
            raise ValueError("commitment.context_compactions_before_commitment must be 0")

        _ensure_nonempty_str(commitment_source["reason"], path="commitment.reason")
    except ValueError as exc:
        errors.append(str(exc))

    return errors


def _commitment_normalization_failure(errors: list[str]) -> dict[str, Any]:
    return {
        "normalization_type": "cwo-native-worker-commitment-normalization",
        "version": 2,
        "outcome": "pm-realignment",
        "decision": "pm-realignment",
        "normalized_commitment": None,
        "errors": list(errors),
        "model_retry_allowed": False,
    }


def _normalize_commitment_decision(value: Any) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    candidate = value.strip().lower()
    aliases = {
        "accept": "accept",
        "approve": "accept",
        "proceed": "accept",
        "pm-realignment": "pm-realignment",
        "refine": "pm-realignment",
        "refinement": "pm-realignment",
        "architect-realignment": "architect-realignment",
        "architect": "architect-realignment",
    }
    return aliases.get(candidate)


def _plain_text_commitment_source(raw: str) -> tuple[dict[str, Any] | None, list[str]]:
    decision_hits: set[str] = set()
    for alias in (
        "accept",
        "approve",
        "proceed",
        "pm-realignment",
        "refine",
        "refinement",
        "architect-realignment",
        "architect",
    ):
        if re.search(rf"(?<![A-Za-z0-9_-]){re.escape(alias)}(?![A-Za-z0-9_-])", raw, flags=re.IGNORECASE):
            normalized = _normalize_commitment_decision(alias)
            if normalized:
                decision_hits.add(normalized)
    if len(decision_hits) != 1:
        return None, ["plain-text commitment decision is missing or ambiguous"]

    field_aliases = {
        "tool_calls_p50": ("tool_calls_p50", "calls_p50"),
        "tool_calls_p90": ("tool_calls_p90", "calls_p90"),
        "runtime_seconds_p50": ("runtime_seconds_p50", "runtime_p50"),
        "runtime_seconds_p90": ("runtime_seconds_p90", "runtime_p90"),
    }
    estimates: dict[str, int] = {}
    errors: list[str] = []
    for canonical, aliases in field_aliases.items():
        pattern = "|".join(re.escape(alias) for alias in aliases)
        matches = re.findall(rf"(?:{pattern})\s*[:=]\s*([0-9]+)", raw, flags=re.IGNORECASE)
        if len(matches) != 1:
            errors.append(f"plain-text commitment requires exactly one {canonical}")
        else:
            estimates[canonical] = int(matches[0])
    confidence_matches = re.findall(r"confidence\s*[:=]\s*(0(?:\.[0-9]+)?|1(?:\.0+)?)", raw, flags=re.IGNORECASE)
    if len(confidence_matches) != 1:
        errors.append("plain-text commitment requires exactly one numeric confidence")
    if errors:
        return None, errors
    return {
        "decision": next(iter(decision_hits)),
        "confidence": float(confidence_matches[0]),
        "estimates": estimates,
        "reason": "normalized from one-pass plain-text commitment",
    }, []


def normalize_worker_commitment_response(
    raw_commitment: Any,
    work_estimate: Any,
    *,
    precommit_receipt: Mapping[str, Any] | None = None,
    session_id: str | None = None,
    attested_model: str | None = None,
) -> dict[str, Any]:
    _ = raw_commitment
    if precommit_receipt is None:
        containment = containment_error("worker-fit-commitment-normalization")
        errors = ["trusted precommit receipt is required"]
        if containment:
            errors.append(containment)
        return _commitment_normalization_failure(errors)
    if session_id is not None or attested_model is not None:
        return _commitment_normalization_failure(
            ["session and model identity must be derived exclusively from the precommit receipt"]
        )
    estimate_errors = validate_work_estimate(work_estimate)
    if estimate_errors:
        return _commitment_normalization_failure(
            [f"invalid work_estimate: {error}" for error in estimate_errors]
        )
    estimate = deepcopy(_ensure_mapping(work_estimate, label="work_estimate"))
    try:
        source = build_worker_commitment_from_receipt(estimate, precommit_receipt)
    except ValueError as exc:
        return _commitment_normalization_failure([str(exc)])
    decision = source["decision"]
    return {
        "normalization_type": "cwo-native-worker-commitment-normalization",
        "version": 2,
        "outcome": "normalized",
        "decision": decision,
        "normalized_commitment": source,
        "errors": [],
        "model_retry_allowed": False,
    }
