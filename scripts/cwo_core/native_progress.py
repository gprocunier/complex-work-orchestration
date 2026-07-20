from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
from math import ceil, isfinite
from typing import Any

from .native_authority import build_reason_records
from .policy import load_policy
from .native_stop_scope import (
    build_stop_metadata,
    canonical_scope_sha256,
    continuation_path,
    policy_scope_authority,
)

DECISION_TYPE = "cwo-native-progress-decision"
VERSION = 1


def _mapping(value: Any, path: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{path} must be a mapping")
    return value


def _integer(value: Any, path: str, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ValueError(f"{path} must be an integer >= {minimum}")
    return value


def _number(value: Any, path: str, minimum: float = 0.0) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not isfinite(value) or value < minimum:
        raise ValueError(f"{path} must be a finite number >= {minimum}")
    return float(value)


def _boolean(value: Any, path: str) -> bool:
    if not isinstance(value, bool):
        raise ValueError(f"{path} must be a boolean")
    return value


def _strings(value: Any, path: str) -> list[str]:
    if not isinstance(value, list):
        raise ValueError(f"{path} must be a list")
    result: list[str] = []
    for index, item in enumerate(value):
        if not isinstance(item, str) or not item:
            raise ValueError(f"{path}[{index}] must be a non-empty string")
        result.append(item)
    return result


def _policy_thresholds(policy: Mapping[str, Any] | None) -> dict[str, Any]:
    source = policy if policy is not None else load_policy("native-worker-execution")
    foundation = _mapping(
        _mapping(_mapping(source, "policy").get("work_sizing"), "policy.work_sizing")
        .get("enforcement"),
        "policy.work_sizing.enforcement",
    ).get("foundation-canary")
    autonomous = _mapping(
        _mapping(foundation, "policy.foundation-canary").get("autonomous_replanning"),
        "policy.autonomous_replanning",
    )
    thresholds = _mapping(autonomous.get("progress_thresholds"), "policy.progress_thresholds")
    result = {
        "early_warning_fraction_of_p50": _number(thresholds.get("early_warning_fraction_of_p50"), "progress_thresholds.early_warning_fraction_of_p50"),
        "minimum_reads_without_progress": _integer(thresholds.get("minimum_reads_without_progress"), "progress_thresholds.minimum_reads_without_progress", 1),
        "realignment_fraction_of_hard": _number(thresholds.get("realignment_fraction_of_hard"), "progress_thresholds.realignment_fraction_of_hard"),
        "read_ratio_multiplier": _number(thresholds.get("read_ratio_multiplier"), "progress_thresholds.read_ratio_multiplier"),
        "read_ratio_floor": _number(thresholds.get("read_ratio_floor"), "progress_thresholds.read_ratio_floor"),
        "max_consecutive_reads_without_progress": _integer(thresholds.get("max_consecutive_reads_without_progress"), "progress_thresholds.max_consecutive_reads_without_progress", 1),
    }
    if not 0 < result["early_warning_fraction_of_p50"] <= 1:
        raise ValueError("early_warning_fraction_of_p50 must be in (0, 1]")
    if not 0 < result["realignment_fraction_of_hard"] <= 1:
        raise ValueError("realignment_fraction_of_hard must be in (0, 1]")
    return result


def _normalize_plan(value: Any) -> dict[str, Any]:
    plan = _mapping(value, "plan")
    required = {
        "tool_calls_p50", "tool_calls_p90", "tool_calls_hard",
        "runtime_seconds_p50", "runtime_seconds_p90", "runtime_seconds_hard",
        "expected_context_reads", "expected_mutations", "expected_regressions",
        "read_to_mutation_ratio",
    }
    if set(plan) != required:
        raise ValueError(f"plan must contain exact fields {sorted(required)}")
    result = {key: _integer(plan[key], f"plan.{key}") for key in required if key != "read_to_mutation_ratio"}
    result["read_to_mutation_ratio"] = _number(plan["read_to_mutation_ratio"], "plan.read_to_mutation_ratio")
    if result["tool_calls_p50"] > result["tool_calls_p90"] or result["tool_calls_p90"] > result["tool_calls_hard"]:
        raise ValueError("plan tool-call quantiles must satisfy p50 <= p90 <= hard")
    if result["runtime_seconds_p50"] > result["runtime_seconds_p90"] or result["runtime_seconds_p90"] > result["runtime_seconds_hard"]:
        raise ValueError("plan runtime quantiles must satisfy p50 <= p90 <= hard")
    return result


def _normalize_actual(value: Any) -> dict[str, Any]:
    actual = _mapping(value, "actual")
    required = {
        "tool_calls", "runtime_seconds", "tokens", "context_reads",
        "consecutive_reads_without_progress", "mutations", "tests_run",
        "artifacts_completed", "validation_complete", "compactions",
        "projected_tool_calls", "projected_runtime_seconds",
    }
    if set(actual) != required:
        raise ValueError(f"actual must contain exact fields {sorted(required)}")
    result = {
        "tool_calls": _integer(actual["tool_calls"], "actual.tool_calls"),
        "runtime_seconds": _number(actual["runtime_seconds"], "actual.runtime_seconds"),
        "tokens": _integer(actual["tokens"], "actual.tokens"),
        "context_reads": _integer(actual["context_reads"], "actual.context_reads"),
        "consecutive_reads_without_progress": _integer(actual["consecutive_reads_without_progress"], "actual.consecutive_reads_without_progress"),
        "mutations": _integer(actual["mutations"], "actual.mutations"),
        "tests_run": _integer(actual["tests_run"], "actual.tests_run"),
        "artifacts_completed": _integer(actual["artifacts_completed"], "actual.artifacts_completed"),
        "validation_complete": _boolean(actual["validation_complete"], "actual.validation_complete"),
        "compactions": _integer(actual["compactions"], "actual.compactions"),
        "projected_tool_calls": _integer(actual["projected_tool_calls"], "actual.projected_tool_calls"),
        "projected_runtime_seconds": _number(actual["projected_runtime_seconds"], "actual.projected_runtime_seconds"),
    }
    return result


def _normalize_discoveries(value: Any) -> dict[str, Any]:
    source = {} if value is None else dict(_mapping(value, "discoveries"))
    bool_fields = (
        "new_work_class", "architecture_decision_attempted", "reasoning_required",
        "split_recommended", "model_mismatch", "control_loss", "security_violation",
        "authority_violation", "mutation_attribution_ambiguous", "contradictory_validation",
    )
    result = {field: _boolean(source.get(field, False), f"discoveries.{field}") for field in bool_fields}
    result.update({
        "completed_evidence": _strings(source.get("completed_evidence", []), "discoveries.completed_evidence"),
        "discovered_work": _strings(source.get("discovered_work", []), "discoveries.discovered_work"),
        "bounded_options": _strings(source.get("bounded_options", []), "discoveries.bounded_options"),
        "retained_artifacts": _strings(source.get("retained_artifacts", []), "discoveries.retained_artifacts"),
        "recommendation": source.get("recommendation", ""),
        "revised_scores": deepcopy(source.get("revised_scores", {})),
        "revised_estimate": deepcopy(source.get("revised_estimate", {})),
    })
    if not isinstance(result["recommendation"], str):
        raise ValueError("discoveries.recommendation must be a string")
    if not isinstance(result["revised_scores"], Mapping) or not isinstance(result["revised_estimate"], Mapping):
        raise ValueError("discoveries revised scores and estimate must be mappings")
    return result


def evaluate_worker_progress(
    plan: Any,
    actual: Any,
    *,
    discoveries: Any = None,
    policy: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    planned = _normalize_plan(plan)
    observed = _normalize_actual(actual)
    found = _normalize_discoveries(discoveries)
    thresholds = _policy_thresholds(policy)
    warnings: list[str] = []
    reasons: list[str] = []

    protected = {
        "model_mismatch": "model-mismatch",
        "control_loss": "control-loss",
        "security_violation": "security-violation",
        "authority_violation": "authority-violation",
        "mutation_attribution_ambiguous": "mutation-attribution-ambiguous",
        "contradictory_validation": "contradictory-validation",
    }
    for field, reason in protected.items():
        if found[field]:
            reasons.append(reason)
    if observed["compactions"] > 0:
        reasons.append("context-compaction")
    if observed["tool_calls"] >= planned["tool_calls_hard"] or observed["runtime_seconds"] >= planned["runtime_seconds_hard"]:
        reasons.append("aggregate-allowance-exhausted")

    half_p50 = max(1, ceil(planned["tool_calls_p50"] * thresholds["early_warning_fraction_of_p50"]))
    no_artifact = observed["artifacts_completed"] == 0 and observed["mutations"] == 0
    if observed["tool_calls"] >= half_p50 and no_artifact and observed["context_reads"] >= thresholds["minimum_reads_without_progress"]:
        warnings.append("calls-ahead-of-artifact-progress")
    if observed["consecutive_reads_without_progress"] >= thresholds["max_consecutive_reads_without_progress"]:
        warnings.append("consecutive-reads-without-progress")

    actual_ratio = float(observed["context_reads"]) if observed["mutations"] == 0 else observed["context_reads"] / observed["mutations"]
    ratio_limit = max(planned["read_to_mutation_ratio"] * thresholds["read_ratio_multiplier"], thresholds["read_ratio_floor"])
    realign_boundary = min(
        planned["tool_calls_p90"],
        ceil(planned["tool_calls_hard"] * thresholds["realignment_fraction_of_hard"]),
    )
    if observed["tool_calls"] >= realign_boundary and no_artifact:
        reasons.append("no-progress-at-realignment-boundary")
    if actual_ratio > ratio_limit and observed["context_reads"] > planned["expected_context_reads"]:
        reasons.append("read-to-mutation-ratio-exceeded")
    if observed["tool_calls"] >= planned["tool_calls_p90"] and not observed["validation_complete"]:
        reasons.append("p90-exceeded-before-validation")
    if observed["projected_tool_calls"] > planned["tool_calls_hard"] or observed["projected_runtime_seconds"] > planned["runtime_seconds_hard"]:
        reasons.append("projected-completion-exceeds-aggregate")
    if found["new_work_class"]:
        reasons.append("focused-validation-found-new-work-class")
    if found["architecture_decision_attempted"]:
        reasons.append("worker-entered-architecture-decision")

    protected_reasons = [reason for reason in reasons if reason in set(protected.values()) | {"context-compaction", "aggregate-allowance-exhausted"}]
    if protected_reasons:
        outcome = "protected-stop"
        pm_action = "protected-stop"
    elif reasons:
        outcome = "pm-realignment"
        if found["architecture_decision_attempted"] or found["reasoning_required"]:
            pm_action = "architect-question"
        elif found["split_recommended"] or "projected-completion-exceeds-aggregate" in reasons or found["new_work_class"]:
            pm_action = "material-split"
        else:
            pm_action = "packet-refinement"
    elif observed["validation_complete"] and observed["artifacts_completed"] > 0:
        outcome = "completed"
        pm_action = "none"
    elif warnings:
        outcome = "early-warning"
        pm_action = "none"
    else:
        outcome = "continue"
        pm_action = "none"

    retained = found["retained_artifacts"]
    calibration = {
        "tool_calls_vs_p90": observed["tool_calls"] - planned["tool_calls_p90"],
        "runtime_seconds_vs_p90": observed["runtime_seconds"] - planned["runtime_seconds_p90"],
        "planned_read_to_mutation_ratio": planned["read_to_mutation_ratio"],
        "actual_read_to_mutation_ratio": actual_ratio,
        "retained_productive_artifacts": len(retained),
        "pure_waste": observed["artifacts_completed"] == 0 and not retained,
    }
    realignment = None
    if outcome == "pm-realignment":
        realignment = {
            "completed_evidence": found["completed_evidence"],
            "mutation_state": "modified" if observed["mutations"] else "clean",
            "discovered_work": found["discovered_work"],
            "revised_scores": deepcopy(found["revised_scores"]),
            "revised_estimate": deepcopy(found["revised_estimate"]) or {
                "tool_calls_p90": observed["projected_tool_calls"],
                "runtime_seconds_p90": observed["projected_runtime_seconds"],
            },
            "decision_required": pm_action,
            "bounded_options": found["bounded_options"] or [pm_action],
            "recommendation": found["recommendation"] or pm_action,
            "retained_artifacts": retained,
        }
    continuation_paths: list[dict[str, Any]] = []
    if outcome == "protected-stop":
        continuation_paths = [
            continuation_path(
                "replace-child",
                conditions=["fault-contained", "fresh-attempt"],
            ),
            continuation_path(
                "continue-cohort",
                conditions=["healthy-peer-evidence-preserved"],
            ),
        ]
    elif outcome == "pm-realignment":
        continuation_paths = [
            continuation_path(
                "retry-child",
                conditions=["pm-decision-recorded", pm_action],
            )
        ]
    reason_values = sorted(set(reasons))
    warning_values = sorted(set(warnings))
    progress_authority = policy_scope_authority(
        "native-progress-outcome-policy-v1",
        authorized_scope="child",
        source_sha256=canonical_scope_sha256(
            {
                "outcome": outcome,
                "pm_action": pm_action,
                "reasons": reason_values,
                "warnings": warning_values,
            }
        ),
    )
    stop_metadata = build_stop_metadata(
        "child",
        authority=progress_authority,
        authorized_continuation_paths=continuation_paths,
    )
    return {
        "decision_type": DECISION_TYPE,
        "version": VERSION,
        "outcome": outcome,
        "pm_action": pm_action,
        "reasons": reason_values,
        "reason_records": build_reason_records(
            reason_values,
            progress_authority,
            detected_by="native-progress-policy",
        ),
        "warnings": warning_values,
        "planned": planned,
        "actual": observed,
        "calibration": calibration,
        "realignment": realignment,
        **stop_metadata,
    }
