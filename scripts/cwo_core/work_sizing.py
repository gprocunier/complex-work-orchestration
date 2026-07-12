from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from copy import deepcopy
from math import isfinite
from typing import Any

from cwo_core.policy import load_policy

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
)

COMMITMENT_REQUIRED_FIELDS = (
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

COMMITMENT_DECISIONS = ("accept", "pm-realignment", "architect-realignment")
COMMITMENT_ESTIMATE_KEYS = ("tool_calls_p50", "tool_calls_p90", "runtime_seconds_p50", "runtime_seconds_p90")


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


def _validate_required_fields(payload: Mapping[str, Any]) -> dict[str, Any]:
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
    estimate_contract_version = _ensure_int(
        payload.get("estimate_contract_version", 1),
        path="estimate_contract_version",
        minimum=1,
        maximum=2,
    )
    if semantic_payload is not None:
        semantic_payload = _ensure_mapping_exact(
            semantic_payload,
            path="semantic_estimate",
            required_fields=SEMANTIC_ESTIMATE_KEYS,
        )
    if estimate_contract_version == 2 and semantic_payload is None:
        raise ValueError("malformed source payload: semantic_estimate required for estimate_contract_version 2")
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
    source = deepcopy(_ensure_mapping(payload, label="payload"))
    normalized = _validate_required_fields(source)
    work_sizing = _load_work_sizing_policy(policy)
    if int(work_sizing.get("version", 0)) != 1:
        raise ValueError("malformed policy: work_sizing.version must be 1")

    route_thresholds = _route_thresholds(work_sizing)
    hard_caps = _hard_caps(work_sizing)
    architect_gates = _architect_gates(work_sizing)
    replanning = _autonomous_replanning(work_sizing)
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

    estimate: dict[str, Any] = deepcopy(source)
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
    return estimate


def validate_work_estimate(payload: Any, policy: Mapping[str, Any] | None = None) -> list[str]:
    source = deepcopy(payload)
    errors: list[str] = []
    if not isinstance(source, Mapping):
        return ["malformed source payload: source must be a mapping"]

    try:
        computed = evaluate_work_estimate(source, policy=policy)
    except ValueError as exc:
        errors.append(str(exc))
        return errors

    for field in DERIVED_FIELDS:
        if field not in source:
            errors.append(f"malformed source payload: missing enriched field {field}")

    if errors:
        return errors

    if source["score_total"] != computed["score_total"]:
        errors.append("derived check failed: score_total must equal computed score_total")
    if source["route"] != computed["route"]:
        errors.append("derived check failed: route must equal computed route")
    if source["hard_gate_reasons"] != computed["hard_gate_reasons"]:
        errors.append("derived check failed: hard_gate_reasons must equal computed hard_gate_reasons")
    if source["aggregate_allowance"] != computed["aggregate_allowance"]:
        errors.append("derived check failed: aggregate_allowance must equal computed aggregate_allowance")
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
            if source.get(field) != computed.get(field):
                errors.append(f"derived check failed: {field} must equal computed {field}")

    return errors


def canonical_work_estimate_sha256(work_estimate: Any) -> str:
    canonical = json.dumps(_ensure_mapping(work_estimate, label="work_estimate"), sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def validate_worker_commitment(
    commitment: Any,
    work_estimate: Any,
    policy: Mapping[str, Any] | None = None,
    *,
    dispatchable: bool = False,
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

    expected_model = str(validated_estimate.get("requested_model", ""))
    expected_work_unit = str(validated_estimate.get("work_unit_id", ""))
    expected_bead = str(validated_estimate.get("bead_id", ""))

    try:
        commitment_fields = set(COMMITMENT_REQUIRED_FIELDS)
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
        if commitment_source["attestation_source"] != str(commitment_policy.get("attestation_source", "")):
            raise ValueError("commitment.attestation_source must equal configured attestation_source")
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
        min_confidence = float(commitment_policy.get("min_confidence", 0.75))
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

        precommit_tool_calls = _ensure_int(
            commitment_policy.get("precommitment_tool_calls"),
            path="work_sizing.commitment.precommitment_tool_calls",
            minimum=0,
            maximum=0,
        )
        precommit_compactions = _ensure_int(
            commitment_policy.get("precommitment_compactions"),
            path="work_sizing.commitment.precommitment_compactions",
            minimum=0,
            maximum=0,
        )
        precommitment_tool_calls = _ensure_int(
            commitment_source.get("tool_calls_before_commitment"),
            path="commitment.tool_calls_before_commitment",
            maximum=precommit_tool_calls,
        )
        precommitment_compactions = _ensure_int(
            commitment_source.get("context_compactions_before_commitment"),
            path="commitment.context_compactions_before_commitment",
            maximum=precommit_compactions,
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
        "version": 1,
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
    session_id: str,
    attested_model: str,
) -> dict[str, Any]:
    if not isinstance(session_id, str) or not session_id:
        return _commitment_normalization_failure(["trusted session_id is required"])
    if not isinstance(attested_model, str) or not attested_model:
        return _commitment_normalization_failure(["trusted attested_model is required"])
    estimate_errors = validate_work_estimate(work_estimate)
    if estimate_errors:
        return _commitment_normalization_failure(
            [f"invalid work_estimate: {error}" for error in estimate_errors]
        )
    estimate = deepcopy(_ensure_mapping(work_estimate, label="work_estimate"))

    source: dict[str, Any]
    if isinstance(raw_commitment, Mapping):
        source = deepcopy(dict(raw_commitment))
    elif isinstance(raw_commitment, str):
        text = raw_commitment.strip()
        if not text:
            return _commitment_normalization_failure(["commitment response is empty"])
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            parsed = None
        if isinstance(parsed, Mapping):
            source = deepcopy(dict(parsed))
        else:
            source, errors = _plain_text_commitment_source(text)
            if source is None:
                return _commitment_normalization_failure(errors)
    else:
        return _commitment_normalization_failure(
            ["commitment response must be a mapping, JSON object, or plain text"]
        )

    decision = _normalize_commitment_decision(source.get("decision"))
    if decision is None:
        return _commitment_normalization_failure(
            ["commitment decision is missing, ambiguous, or unsupported"]
        )
    source["decision"] = decision

    estimates = source.get("estimates")
    if not isinstance(estimates, Mapping):
        return _commitment_normalization_failure(
            ["commitment estimates must contain numeric p50 and p90 values"]
        )
    normalized_estimates = dict(estimates)
    estimate_aliases = {
        "calls_p50": "tool_calls_p50",
        "calls_p90": "tool_calls_p90",
        "runtime_p50": "runtime_seconds_p50",
        "runtime_p90": "runtime_seconds_p90",
    }
    for alias, canonical in estimate_aliases.items():
        if alias in normalized_estimates and canonical in normalized_estimates:
            return _commitment_normalization_failure(
                [f"commitment estimates contain both {canonical} and alias {alias}"]
            )
        if alias in normalized_estimates:
            normalized_estimates[canonical] = normalized_estimates.pop(alias)
    missing_quantiles = sorted(set(COMMITMENT_ESTIMATE_KEYS) - set(normalized_estimates))
    if missing_quantiles:
        return _commitment_normalization_failure(
            [f"commitment estimates missing numeric quantiles: {', '.join(missing_quantiles)}"]
        )
    source["estimates"] = normalized_estimates

    trusted_fields = {
        "commitment_type": "cwo-native-worker-fit-commitment",
        "version": 1,
        "work_unit_id": estimate["work_unit_id"],
        "bead_id": estimate["bead_id"],
        "requested_model": estimate["requested_model"],
        "session_id": session_id,
        "attestation_source": "trusted-session-jsonl",
        "attested_model": attested_model,
        "work_estimate_sha256": canonical_work_estimate_sha256(estimate),
        "tool_calls_before_commitment": 0,
        "context_compactions_before_commitment": 0,
    }
    for field, trusted_value in trusted_fields.items():
        if field in source and source[field] != trusted_value:
            return _commitment_normalization_failure(
                [f"commitment {field} contradicts trusted control-plane value"]
            )
        source[field] = trusted_value
    if attested_model != estimate["requested_model"]:
        return _commitment_normalization_failure(
            ["trusted attested_model does not match requested model"]
        )
    if not isinstance(source.get("reason"), str) or not source["reason"].strip():
        return _commitment_normalization_failure(["commitment reason is required"])

    errors = validate_worker_commitment(
        source,
        estimate,
        dispatchable=decision == "accept",
    )
    if errors:
        return _commitment_normalization_failure(errors)
    return {
        "normalization_type": "cwo-native-worker-commitment-normalization",
        "version": 1,
        "outcome": "normalized",
        "decision": decision,
        "normalized_commitment": source,
        "errors": [],
        "model_retry_allowed": False,
    }
