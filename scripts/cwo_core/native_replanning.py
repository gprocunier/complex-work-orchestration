from __future__ import annotations

import copy
from collections.abc import Mapping
from typing import Any

from .native_authority import (
    OPERATOR_REQUIRED_CHANGE_TYPES,
    AuthorityProvenanceError,
    OperatorApprovalVerifier,
    VerifiedAuthority,
    assess_operator_required_changes,
    build_reason_records,
    canonical_json_object,
    protected_change_identity,
    require_minimum_authority,
    validate_authority_provenance,
    validate_operator_approval_audit,
)
from .policy import load_policy

REPLANNING_STATE_TYPE = "cwo-native-replanning-state"
REPLANNING_RECEIPT_TYPE = "cwo-native-replanning-receipt"
SCHEMA_PATH = "schemas/native-replanning-state.schema.json"
REPLANNING_VERSION = 2
MAIN_THREAD_SOURCE_TURN_CONTEXT = "trusted-turn-context"
MAIN_THREAD_SOURCE_USER = "user-declaration"
REQUIRED_MAIN_THREAD_RUNTIME_FIELDS = (
    "model",
    "effort",
    "source",
    "recommended_effort",
    "recommendation_reason",
    "advisory",
    "user_selected_effort_retained",
)

REQUIRED_STATES = (
    "planned",
    "commitment-required",
    "dispatchable",
    "executing",
    "pm-realignment",
    "architect-realignment",
    "reassignment-ready",
    "protected-stop",
    "completed",
)

EVENT_ACCEPTED = "accepted"
EVENT_DISPATCH_STARTED = "dispatch-started"
EVENT_NEEDS_REPLAN = "needs-replan"
EVENT_EXPLORATION_LIMIT = "exploration-limit"
EVENT_CLEAN_NO_ARTIFACT = "clean-no-artifact"
EVENT_PM_REFINED = "pm-refined"
EVENT_ARCHITECT_REFINED = "architect-refined"
EVENT_FRESH_WORKER_ASSIGNED = "fresh-worker-assigned"
EVENT_COMPLETED = "completed"
EVENT_WORKER_COMPACTION = "worker-compaction"

KNOWN_EVENTS = (
    EVENT_ACCEPTED,
    EVENT_DISPATCH_STARTED,
    EVENT_NEEDS_REPLAN,
    EVENT_EXPLORATION_LIMIT,
    EVENT_CLEAN_NO_ARTIFACT,
    EVENT_WORKER_COMPACTION,
    EVENT_PM_REFINED,
    EVENT_ARCHITECT_REFINED,
    EVENT_FRESH_WORKER_ASSIGNED,
    EVENT_COMPLETED,
    "model-mismatch",
    "control-loss",
    "security-or-authority-ambiguity",
    "out-of-scope-mutation",
    "tainted-mutation",
    "operator-trigger",
)

EVENT_MINIMUM_AUTHORITY = {
    EVENT_ACCEPTED: "worker",
    EVENT_DISPATCH_STARTED: "worker",
    EVENT_NEEDS_REPLAN: "worker",
    EVENT_EXPLORATION_LIMIT: "pm",
    EVENT_CLEAN_NO_ARTIFACT: "pm",
    EVENT_PM_REFINED: "pm",
    EVENT_ARCHITECT_REFINED: "architect",
    EVENT_FRESH_WORKER_ASSIGNED: "pm",
    EVENT_COMPLETED: "worker",
    EVENT_WORKER_COMPACTION: "architect",
    "model-mismatch": "operator",
    "control-loss": "operator",
    "security-or-authority-ambiguity": "operator",
    "out-of-scope-mutation": "operator",
    "tainted-mutation": "operator",
    "operator-trigger": "operator",
}

NEEDS_REPLAN_FIELDS = {
    "reason_code", "completed_evidence", "discovered_facts", "files_touched",
    "mutation_state", "mutation_stopped", "remaining_outcomes", "remaining_files",
    "remaining_tests", "uncertainty", "scope_delta", "bounded_options",
    "recommendation", "cumulative_usage",
}
NEEDS_REPLAN_REASONS = {
    "hidden-coupling", "scope-growth", "unexpected-reasoning",
    "decision-uncertainty", "environment",
}
NEEDS_REPLAN_DECISIONS = {"pm-refine", "architect-reasoning", "reassign-spark"}
NEEDS_REPLAN_ROUTES = NEEDS_REPLAN_DECISIONS | {"protected-stop"}
PROTECTED_REPLANNING_CHANGE_FIELDS = frozenset(
    {"objective", "requested_model", "security_context", "aggregate_allowance"}
)


def _valid_string_list(value: Any, *, nonempty: bool = False) -> bool:
    return (
        isinstance(value, list)
        and (bool(value) or not nonempty)
        and all(isinstance(item, str) and bool(item.strip()) for item in value)
    )


def _nonnegative_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def validate_needs_replan_payload(value: Any) -> list[str]:
    """Validate typed worker-to-PM evidence without authorizing a transition."""
    if not isinstance(value, Mapping):
        return ["replan must be an object"]
    payload = dict(value)
    if set(payload) != NEEDS_REPLAN_FIELDS:
        return ["replan must contain exactly the required typed fields"]
    errors: list[str] = []
    if payload["reason_code"] not in NEEDS_REPLAN_REASONS:
        errors.append("replan.reason_code is not recognized")
    if not isinstance(payload["completed_evidence"], str) or not payload["completed_evidence"].strip():
        errors.append("replan.completed_evidence must be a non-empty string")
    for field in ("discovered_facts", "files_touched", "remaining_outcomes", "remaining_files", "remaining_tests"):
        if not _valid_string_list(payload[field], nonempty=(field == "discovered_facts")):
            errors.append(f"replan.{field} must be a list of non-empty strings")
    if not any(payload[field] for field in ("remaining_outcomes", "remaining_files", "remaining_tests")):
        errors.append("replan must declare remaining work")
    if payload["mutation_state"] not in {"clean", "modified", "committed", "unknown"}:
        errors.append("replan.mutation_state is invalid")
    if payload["mutation_stopped"] is not True:
        errors.append("replan.mutation_stopped must be true")

    uncertainty = payload["uncertainty"]
    if not isinstance(uncertainty, Mapping) or set(uncertainty) != {"class", "decision", "detail"}:
        errors.append("replan.uncertainty has an invalid shape")
    else:
        if uncertainty["class"] not in {"bounded", "material", "architect"}:
            errors.append("replan.uncertainty.class is not recognized")
        if uncertainty["decision"] not in NEEDS_REPLAN_DECISIONS:
            errors.append("replan.uncertainty.decision is not recognized")
        if not isinstance(uncertainty["detail"], str) or not uncertainty["detail"].strip():
            errors.append("replan.uncertainty.detail must be non-empty")
        if uncertainty["class"] == "architect" and uncertainty["decision"] != "architect-reasoning":
            errors.append("architect uncertainty requires architect-reasoning")

    scope = payload["scope_delta"]
    scope_fields = {"outcomes_added", "files_added", "tests_added", "within_original_objective", "within_aggregate_allowance"}
    if not isinstance(scope, Mapping) or set(scope) != scope_fields:
        errors.append("replan.scope_delta has an invalid shape")
    else:
        if not all(_nonnegative_int(scope[field]) for field in ("outcomes_added", "files_added", "tests_added")):
            errors.append("replan.scope_delta counts must be non-negative integers")
        if not all(isinstance(scope[field], bool) for field in ("within_original_objective", "within_aggregate_allowance")):
            errors.append("replan.scope_delta boundary flags must be booleans")

    options = payload["bounded_options"]
    option_ids: list[str] = []
    option_fields = {"option_id", "route", "description", "tool_calls_p90", "runtime_seconds_p90"}
    if not isinstance(options, list) or not options:
        errors.append("replan.bounded_options must be a non-empty list")
    else:
        for index, option in enumerate(options):
            if not isinstance(option, Mapping) or set(option) != option_fields:
                errors.append(f"replan.bounded_options[{index}] has an invalid shape")
                continue
            option_id = option["option_id"]
            if not isinstance(option_id, str) or not option_id.strip() or option_id in option_ids:
                errors.append(f"replan.bounded_options[{index}].option_id is invalid")
            else:
                option_ids.append(option_id)
            if option["route"] not in NEEDS_REPLAN_ROUTES:
                errors.append(f"replan.bounded_options[{index}].route is invalid")
            if not isinstance(option["description"], str) or not option["description"].strip():
                errors.append(f"replan.bounded_options[{index}].description is invalid")
            if not all(_nonnegative_int(option[field]) for field in ("tool_calls_p90", "runtime_seconds_p90")):
                errors.append(f"replan.bounded_options[{index}] budget is invalid")
    if payload["recommendation"] not in option_ids:
        errors.append("replan.recommendation must identify one bounded option")

    usage = payload["cumulative_usage"]
    usage_fields = {"tool_calls", "runtime_seconds", "context_compactions", "full_suite_runs"}
    if not isinstance(usage, Mapping) or set(usage) != usage_fields or not all(_nonnegative_int(usage[field]) for field in usage_fields):
        errors.append("replan.cumulative_usage has an invalid shape")
    return errors


def _extract_main_thread_turn_context(value: Any, *, path: str) -> Mapping[str, Any] | None:
    if not isinstance(value, Mapping):
        return None
    if not value:
        return None
    model = value.get("attested_model") or value.get("model")
    effort = value.get("claude_effort") or value.get("effort")
    if model is None and effort is None:
        return None
    return {
        "model": model,
        "effort": effort,
    }


def _coalesce_main_thread_field(
    value: Mapping[str, Any] | None,
    key: str,
    *,
    path: str,
    default: str,
) -> str:
    if value is None or key not in value:
        return default
    return _ensure_nonempty_str(value.get(key), path=f"{path}.{key}")


def _coalesce_main_thread_bool(
    value: Mapping[str, Any] | None,
    key: str,
    *,
    path: str,
    default: bool,
) -> bool:
    if value is None or key not in value:
        return default
    return _ensure_bool(value.get(key), path=f"{path}.{key}")


def _ensure_str_list(value: Any, *, path: str, allow_empty: bool = True) -> list[str]:
    values = _ensure_list(value, path=path, allow_empty=allow_empty)
    normalized: list[str] = []
    for index, item in enumerate(values):
        if not isinstance(item, str) or not item:
            raise ValueError(f"malformed payload: {path}[{index}] must be a non-empty string")
        normalized.append(item)
    return normalized


def _ensure_mapping(value: Any, *, path: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"malformed payload: {path} must be a mapping")
    return value


def _ensure_nonempty_str(value: Any, *, path: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"malformed payload: {path} must be a non-empty string")
    return value


def _ensure_int(
    value: Any,
    *,
    path: str,
    minimum: int = 0,
    maximum: int | None = None,
) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"malformed payload: {path} must be an integer")
    number = int(value)
    if number < minimum or (maximum is not None and number > maximum):
        raise ValueError(f"malformed payload: {path} must be between {minimum} and {maximum}")
    return number


def _ensure_bool(value: Any, *, path: str) -> bool:
    if not isinstance(value, bool):
        raise ValueError(f"malformed payload: {path} must be a boolean")
    return bool(value)


def _ensure_list(value: Any, *, path: str, allow_empty: bool = True) -> list[Any]:
    if not isinstance(value, list):
        raise ValueError(f"malformed payload: {path} must be a list")
    if not allow_empty and not value:
        raise ValueError(f"malformed payload: {path} cannot be empty")
    return list(value)


def _coerce_event(event: Any) -> str:
    if not isinstance(event, str) or not event:
        raise ValueError("malformed event: must be a non-empty string")
    event_value = event.strip().lower()
    aliases = {
        "accept": EVENT_ACCEPTED,
        "acceptance": EVENT_ACCEPTED,
        "commitment-accepted": EVENT_ACCEPTED,
        "commitment accepted": EVENT_ACCEPTED,
    }
    return aliases.get(event_value, event_value)


def _load_policy_section(policy: Mapping[str, Any] | None) -> Mapping[str, Any]:
    policy_payload = policy if policy is not None else load_policy("native-worker-execution")
    policy_obj = _ensure_mapping(policy_payload, path="policy")
    work_sizing = _ensure_mapping(policy_obj.get("work_sizing"), path="policy.work_sizing")
    if str(work_sizing.get("version")) != "1":
        raise ValueError("malformed policy: work_sizing.version must be 1")
    enforcement = _ensure_mapping(work_sizing.get("enforcement"), path="policy.work_sizing.enforcement")
    foundation = _ensure_mapping(enforcement.get("foundation-canary"), path="policy.work_sizing.enforcement.foundation-canary")
    autonomous = _ensure_mapping(foundation.get("autonomous_replanning"), path="policy.work_sizing.enforcement.foundation-canary.autonomous_replanning")
    return autonomous


def _normalize_autonomous_policy(payload: Mapping[str, Any] | None) -> dict[str, Any]:
    autonomous = _load_policy_section(payload)

    states = _ensure_list(autonomous.get("states"), path="policy.autonomous_replanning.states", allow_empty=False)
    if set(REQUIRED_STATES) - set(states):
        raise ValueError("malformed policy: autonomous_replanning.states must include required replanning states")

    events = _ensure_list(autonomous.get("events"), path="policy.autonomous_replanning.events", allow_empty=False)
    if set(KNOWN_EVENTS) - set(events):
        raise ValueError("malformed policy: autonomous_replanning.events missing required names")

    telemetry_fields = _ensure_list(
        autonomous.get("telemetry_fields"),
        path="policy.autonomous_replanning.telemetry_fields",
        allow_empty=False,
    )
    if not set(telemetry_fields).issuperset({"tool_calls", "runtime_seconds", "dispatches", "compactions"}):
        raise ValueError("malformed policy: telemetry_fields must include tool_calls/runtime_seconds/dispatches/compactions")

    protected_stop_reasons = _ensure_list(
        autonomous.get("protected_stop_reasons"),
        path="policy.autonomous_replanning.protected_stop_reasons",
        allow_empty=False,
    )

    continuation_requires = _ensure_list(
        autonomous.get("continuation_requires"),
        path="policy.autonomous_replanning.continuation_requires",
        allow_empty=True,
    )

    exploration_limits = _ensure_mapping(
        autonomous.get("exploration_limits"),
        path="policy.autonomous_replanning.exploration_limits",
    )
    if EVENT_EXPLORATION_LIMIT not in exploration_limits or EVENT_CLEAN_NO_ARTIFACT not in exploration_limits:
        raise ValueError("malformed policy: exploration_limits must include exploration-limit and clean-no-artifact")
    limits: dict[str, int] = {}
    for event in (EVENT_EXPLORATION_LIMIT, EVENT_CLEAN_NO_ARTIFACT):
        event_limits = _ensure_mapping(exploration_limits[event], path=f"policy.autonomous_replanning.exploration_limits[{event}]")
        limits[event] = _ensure_int(
            event_limits.get("max_compactions"),
            path=f"policy.autonomous_replanning.exploration_limits[{event}].max_compactions",
            minimum=0,
        )

    refined_child_budgeting_payload = _ensure_mapping(
        autonomous.get("refined_child_budgeting"),
        path="policy.autonomous_replanning.refined_child_budgeting",
    )
    refined_child_budgeting = {
        "materially_refined_child": _ensure_nonempty_str(
            refined_child_budgeting_payload.get("materially_refined_child"),
            path="policy.autonomous_replanning.refined_child_budgeting.materially_refined_child",
        ),
        "immutable_retry": _ensure_nonempty_str(
            refined_child_budgeting_payload.get("immutable_retry"),
            path="policy.autonomous_replanning.refined_child_budgeting.immutable_retry",
        ),
        "cumulative_lineage_usage_required": _ensure_bool(
            refined_child_budgeting_payload.get("cumulative_lineage_usage_required"),
            path="policy.autonomous_replanning.refined_child_budgeting.cumulative_lineage_usage_required",
        ),
    }

    fresh_worker_reassignment = _ensure_mapping(
        autonomous.get("fresh-worker-reassignment"),
        path="policy.autonomous_replanning.fresh-worker-reassignment",
    )
    if not isinstance(fresh_worker_reassignment.get("required"), bool):
        raise ValueError(
            "malformed policy: autonomous_replanning.fresh-worker-reassignment.required must be a boolean"
        )
    fresh_worker_event = _ensure_nonempty_str(
        fresh_worker_reassignment.get("event"),
        path="policy.autonomous_replanning.fresh-worker-reassignment.event",
    )

    operator_required_for = _ensure_list(
        autonomous.get("operator_required_for"),
        path="policy.autonomous_replanning.operator_required_for",
        allow_empty=False,
    )
    if (
        len(operator_required_for) != len(set(operator_required_for))
        or set(operator_required_for) != set(OPERATOR_REQUIRED_CHANGE_TYPES)
    ):
        raise ValueError(
            "malformed policy: autonomous_replanning.operator_required_for must "
            "contain every supported protected change category exactly once"
        )

    main_thread_payload = _ensure_mapping(
        autonomous.get("main_thread_effort"),
        path="policy.autonomous_replanning.main_thread_effort",
    )
    main_thread_required_fields = _ensure_str_list(
        main_thread_payload.get("required_runtime_fields"),
        path="policy.autonomous_replanning.main_thread_effort.required_runtime_fields",
        allow_empty=False,
    )
    for required_field in REQUIRED_MAIN_THREAD_RUNTIME_FIELDS:
        if required_field not in set(main_thread_required_fields):
            raise ValueError(
                "malformed policy: main_thread_effort.required_runtime_fields must include"
                f" {required_field}"
            )
    required_recommendation_advisory = _ensure_bool(
        main_thread_payload.get("recommendation_advisory"),
        path="policy.autonomous_replanning.main_thread_effort.recommendation_advisory",
    )
    if not required_recommendation_advisory:
        raise ValueError(
            "malformed policy: main_thread_effort.recommendation_advisory must be true"
        )
    required_user_selection_authoritative = _ensure_bool(
        main_thread_payload.get("user_selection_authoritative"),
        path="policy.autonomous_replanning.main_thread_effort.user_selection_authoritative",
    )
    if not required_user_selection_authoritative:
        raise ValueError(
            "malformed policy: main_thread_effort.user_selection_authoritative must be true"
        )
    if _ensure_bool(
        main_thread_payload.get("automatic_effort_change"),
        path="policy.autonomous_replanning.main_thread_effort.automatic_effort_change",
    ):
        raise ValueError(
            "malformed policy: main_thread_effort.automatic_effort_change must be false"
        )
    if _ensure_bool(
        main_thread_payload.get("effort_is_execution_gate"),
        path="policy.autonomous_replanning.main_thread_effort.effort_is_execution_gate",
    ):
        raise ValueError(
            "malformed policy: main_thread_effort.effort_is_execution_gate must be false"
        )
    if _ensure_bool(
        main_thread_payload.get("effort_is_authority_boundary"),
        path="policy.autonomous_replanning.main_thread_effort.effort_is_authority_boundary",
    ):
        raise ValueError(
            "malformed policy: main_thread_effort.effort_is_authority_boundary must be false"
        )
    worker_compaction_payload = _ensure_mapping(
        autonomous.get("worker_compaction"),
        path="policy.autonomous_replanning.worker_compaction",
    )

    return {
        "dispatch_soft_cap": _ensure_int(
            autonomous.get("dispatch_soft_cap"),
            path="policy.autonomous_replanning.dispatch_soft_cap",
            minimum=0,
        ),
        "dispatch_soft_cap_action": _ensure_nonempty_str(
            autonomous.get("dispatch_soft_cap_action"),
            path="policy.autonomous_replanning.dispatch_soft_cap_action",
        ),
        "max_pm_replans": _ensure_int(
            autonomous.get("max_pm_replans"),
            path="policy.autonomous_replanning.max_pm_replans",
            minimum=0,
        ),
        "max_architect_cycles": _ensure_int(
            autonomous.get("max_architect_cycles"),
            path="policy.autonomous_replanning.max_architect_cycles",
            minimum=0,
        ),
        "max_compactions": _ensure_int(
            autonomous.get("max_compactions"),
            path="policy.autonomous_replanning.max_compactions",
            minimum=0,
        ),
        "tool_calls_extra": _ensure_int(
            autonomous.get("tool_calls_extra"),
            path="policy.autonomous_replanning.tool_calls_extra",
            minimum=0,
        ),
        "runtime_seconds_extra": _ensure_int(
            autonomous.get("runtime_seconds_extra"),
            path="policy.autonomous_replanning.runtime_seconds_extra",
            minimum=0,
        ),
        "states": states,
        "events": events,
        "telemetry_fields": telemetry_fields,
        "protected_stop_reasons": protected_stop_reasons,
        "continuation_requires": continuation_requires,
        "exploration_limits": limits,
        "fresh_worker_reassignment_required": _ensure_bool(
            fresh_worker_reassignment.get("required"),
            path="policy.autonomous_replanning.fresh-worker-reassignment.required",
        ),
        "fresh_worker_reassignment_event": fresh_worker_event,
        "operator_required_for": operator_required_for,
        "live_replay_enabled": _ensure_bool(
            autonomous.get("live_replay_enabled"),
            path="policy.autonomous_replanning.live_replay_enabled",
        ),
        "operator_required_for_set": set(operator_required_for),
        "main_thread_effort": {
            "capture_at": _ensure_str_list(
                main_thread_payload.get("capture_at"),
                path="policy.autonomous_replanning.main_thread_effort.capture_at",
                allow_empty=False,
            ),
            "sources": _ensure_str_list(
                main_thread_payload.get("sources"),
                path="policy.autonomous_replanning.main_thread_effort.sources",
                allow_empty=False,
            ),
            "required_runtime_fields": _ensure_str_list(
                main_thread_required_fields,
                path="policy.autonomous_replanning.main_thread_effort.required_runtime_fields",
                allow_empty=False,
            ),
            "recommendation_advisory": required_recommendation_advisory,
            "user_selection_authoritative": required_user_selection_authoritative,
            "automatic_effort_change": False,
            "effort_is_execution_gate": False,
            "effort_is_authority_boundary": False,
        },
        "worker_compaction": {
            "affected_worker_action": _ensure_nonempty_str(
                worker_compaction_payload.get("affected_worker_action"),
                path="policy.autonomous_replanning.worker_compaction.affected_worker_action",
            ),
            "clean_attributable_requires": _ensure_str_list(
                worker_compaction_payload.get("clean_attributable_requires"),
                path="policy.autonomous_replanning.worker_compaction.clean_attributable_requires",
                allow_empty=False,
            ),
            "clean_attributable_route": _ensure_nonempty_str(
                worker_compaction_payload.get("clean_attributable_route"),
                path="policy.autonomous_replanning.worker_compaction.clean_attributable_route",
            ),
            "retained_artifact_disposition": _ensure_nonempty_str(
                worker_compaction_payload.get("retained_artifact_disposition"),
                path="policy.autonomous_replanning.worker_compaction.retained_artifact_disposition",
            ),
            "ambiguous_route": _ensure_nonempty_str(
                worker_compaction_payload.get("ambiguous_route"),
                path="policy.autonomous_replanning.worker_compaction.ambiguous_route",
            ),
            "effort_escalation": _ensure_nonempty_str(
                worker_compaction_payload.get("effort_escalation"),
                path="policy.autonomous_replanning.worker_compaction.effort_escalation",
            ),
        },
        "refined_child_budgeting": refined_child_budgeting,
    }


def _normalize_mutation(value: Any, *, path: str) -> dict[str, bool]:
    source = _ensure_mapping(value, path=path)
    unknown = sorted(set(source) - {"out_of_scope", "tainted"})
    if unknown:
        raise ValueError(
            f"malformed payload: {path} has unknown field(s) {','.join(unknown)}"
        )
    return {
        "out_of_scope": _ensure_bool(
            source.get("out_of_scope", False), path=f"{path}.out_of_scope"
        ),
        "tainted": _ensure_bool(
            source.get("tainted", False), path=f"{path}.tainted"
        ),
    }


def _normalize_counters(value: Any, *, path: str) -> dict[str, int]:
    source = _ensure_mapping(value, path=path)
    return {
        "dispatches": _ensure_int(source.get("dispatches", 0), path=f"{path}.dispatches", minimum=0),
        "tool_calls_used": _ensure_int(source.get("tool_calls_used", 0), path=f"{path}.tool_calls_used", minimum=0),
        "runtime_seconds_used": _ensure_int(
            source.get("runtime_seconds_used", 0),
            path=f"{path}.runtime_seconds_used",
            minimum=0,
        ),
        "context_compactions": _ensure_int(
            source.get("context_compactions", 0),
            path=f"{path}.context_compactions",
            minimum=0,
        ),
        "pm_replans_used": _ensure_int(source.get("pm_replans_used", 0), path=f"{path}.pm_replans_used", minimum=0),
        "architect_cycles_used": _ensure_int(
            source.get("architect_cycles_used", 0),
            path=f"{path}.architect_cycles_used",
            minimum=0,
        ),
    }


def _normalize_allowance(value: Any, *, policy: Mapping[str, Any], path: str) -> dict[str, int]:
    source = _ensure_mapping(value, path=path)
    tool_calls_hard = _ensure_int(
        source.get("tool_calls_hard"),
        path=f"{path}.tool_calls_hard",
        minimum=0,
    )
    runtime_seconds_hard = _ensure_int(
        source.get("runtime_seconds_hard"),
        path=f"{path}.runtime_seconds_hard",
        minimum=0,
    )
    return {
        "tool_calls_hard": tool_calls_hard,
        "runtime_seconds_hard": runtime_seconds_hard,
        "dispatch_soft_cap": _ensure_int(
            policy["dispatch_soft_cap"],
            path="policy.dispatch_soft_cap",
            minimum=0,
        ),
        "dispatch_soft_cap_action": _ensure_nonempty_str(
            policy["dispatch_soft_cap_action"],
            path="policy.dispatch_soft_cap_action",
        ),
        "max_pm_replans": _ensure_int(policy["max_pm_replans"], path="policy.max_pm_replans", minimum=0),
        "max_architect_cycles": _ensure_int(policy["max_architect_cycles"], path="policy.max_architect_cycles", minimum=0),
        "max_compactions": _ensure_int(policy["max_compactions"], path="policy.max_compactions", minimum=0),
    }


def _normalize_main_thread(
    value: Any,
    policy: Mapping[str, Any],
    evidence: Mapping[str, Any],
    path: str,
    allow_runtime_overrides: bool = True,
) -> dict[str, Any]:
    source_payload = _ensure_mapping(value, path=path) if value is not None else {}
    model = _ensure_nonempty_str(
        source_payload.get("model"),
        path=f"{path}.model",
    )
    effort = _ensure_nonempty_str(
        source_payload.get("effort"),
        path=f"{path}.effort",
    )
    selection_source = _ensure_nonempty_str(
        source_payload.get("source"),
        path=f"{path}.source",
    )
    recommended_effort = _ensure_nonempty_str(
        source_payload.get("recommended_effort"),
        path=f"{path}.recommended_effort",
    )
    recommendation_reason = _ensure_nonempty_str(
        source_payload.get("recommendation_reason"),
        path=f"{path}.recommendation_reason",
    )
    advisory = _ensure_bool(
        source_payload.get("advisory"),
        path=f"{path}.advisory",
    )
    user_selected_effort_retained = _ensure_bool(
        source_payload.get("user_selected_effort_retained"),
        path=f"{path}.user_selected_effort_retained",
    )

    if allow_runtime_overrides:
        tc_payload = _extract_main_thread_turn_context(
            evidence.get("turn_context"),
            path="evidence.turn_context",
        )
        if tc_payload is not None:
            model = _ensure_nonempty_str(tc_payload.get("model"), path="evidence.turn_context.model")
            effort = _ensure_nonempty_str(tc_payload.get("effort"), path="evidence.turn_context.effort")
            selection_source = MAIN_THREAD_SOURCE_TURN_CONTEXT
            user_selected_effort_retained = policy["main_thread_effort"]["user_selection_authoritative"]
            advisory = policy["main_thread_effort"]["recommendation_advisory"]

        user_main_thread = evidence.get("main_thread")
        if isinstance(user_main_thread, Mapping):
            model = _coalesce_main_thread_field(
                user_main_thread,
                "model",
                path="evidence.main_thread",
                default=model,
            )
            effort = _coalesce_main_thread_field(
                user_main_thread,
                "effort",
                path="evidence.main_thread",
                default=effort,
            )
            recommended_effort = _coalesce_main_thread_field(
                user_main_thread,
                "recommended_effort",
                path="evidence.main_thread",
                default=recommended_effort,
            )
            recommendation_reason = _coalesce_main_thread_field(
                user_main_thread,
                "recommendation_reason",
                path="evidence.main_thread",
                default=recommendation_reason,
            )
            advisory = _coalesce_main_thread_bool(
                user_main_thread,
                "advisory",
                path="evidence.main_thread",
                default=advisory,
            )
            user_selected_effort_retained = _coalesce_main_thread_bool(
                user_main_thread,
                "user_selected_effort_retained",
                path="evidence.main_thread",
                default=user_selected_effort_retained,
            )
            selection_source = MAIN_THREAD_SOURCE_USER

    allowed_main_thread_sources = set(policy["main_thread_effort"]["sources"])
    if selection_source not in allowed_main_thread_sources:
        raise ValueError(f"malformed payload: {path}.source must be one of {sorted(allowed_main_thread_sources)!s}")

    if advisory is not policy["main_thread_effort"]["recommendation_advisory"]:
        raise ValueError(
            "malformed payload: state.main_thread.advisory must match policy requirement"
        )
    if user_selected_effort_retained is not policy["main_thread_effort"]["user_selection_authoritative"]:
        raise ValueError(
            "malformed payload: state.main_thread.user_selected_effort_retained must match policy requirement"
        )

    return {
        "model": model,
        "effort": effort,
        "source": selection_source,
        "recommended_effort": recommended_effort,
        "recommendation_reason": recommendation_reason,
        "advisory": advisory,
        "user_selected_effort_retained": user_selected_effort_retained,
    }


def _validate_usage_delta(value: Any, *, path: str) -> int:
    return _ensure_int(value, path=path, minimum=0)


def _usage_from_evidence(evidence: Mapping[str, Any]) -> tuple[int, int, int]:
    return (
        _validate_usage_delta(evidence.get("tool_calls_delta", 0), path="evidence.tool_calls_delta"),
        _validate_usage_delta(
            evidence.get("runtime_seconds_delta", 0),
            path="evidence.runtime_seconds_delta",
        ),
        _validate_usage_delta(
            evidence.get("context_compactions_delta", 0),
            path="evidence.context_compactions_delta",
        ),
    )


def _remaining_allowance(state: Mapping[str, Any]) -> tuple[int, int]:
    counters = state["counters"]
    allowance = state["aggregate_allowance"]
    return (
        allowance["tool_calls_hard"] - counters["tool_calls_used"],
        allowance["runtime_seconds_hard"] - counters["runtime_seconds_used"],
    )


def _remaining_dispatch_capacity(state: Mapping[str, Any]) -> int:
    allowance = state["aggregate_allowance"]
    return allowance["dispatch_soft_cap"] - state["counters"]["dispatches"]


def _emit_receipt(
    *,
    state_before: str,
    state_after: str,
    event: str,
    authority: VerifiedAuthority,
    decision: str,
    reason_codes: list[str],
    state: Mapping[str, Any],
) -> dict[str, Any]:
    tool_calls_remaining, runtime_seconds_remaining = _remaining_allowance(state)
    return {
        "result_type": REPLANNING_RECEIPT_TYPE,
        "version": REPLANNING_VERSION,
        "schema": SCHEMA_PATH,
        "state_before": state_before,
        "state_after": state_after,
        "event": event,
        "authority_provenance": authority.serialize(),
        "reason_records": build_reason_records(
            reason_codes,
            authority,
            detected_by=f"native-replanning:{event}",
        ),
        "protected_change_authorizations": copy.deepcopy(
            state["protected_change_authorizations"]
        ),
        "decision": decision,
        "reason_codes": reason_codes,
        "work_unit_id": state["work_unit_id"],
        "bead_id": state["bead_id"],
        "packet_id": state["packet_id"],
        "counters": {
            "dispatches": state["counters"]["dispatches"],
            "tool_calls_used": state["counters"]["tool_calls_used"],
            "runtime_seconds_used": state["counters"]["runtime_seconds_used"],
            "context_compactions": state["counters"]["context_compactions"],
            "pm_replans_used": state["counters"]["pm_replans_used"],
            "architect_cycles_used": state["counters"]["architect_cycles_used"],
            "tool_calls_remaining": max(0, tool_calls_remaining),
            "runtime_seconds_remaining": max(0, runtime_seconds_remaining),
            "dispatches_remaining": max(0, _remaining_dispatch_capacity(state)),
        },
        "aggregate": {
            "tool_calls_hard": state["aggregate_allowance"]["tool_calls_hard"],
            "runtime_seconds_hard": state["aggregate_allowance"]["runtime_seconds_hard"],
            "dispatch_soft_cap": state["aggregate_allowance"]["dispatch_soft_cap"],
            "dispatch_soft_cap_action": state["aggregate_allowance"]["dispatch_soft_cap_action"],
            "max_pm_replans": state["aggregate_allowance"]["max_pm_replans"],
            "max_architect_cycles": state["aggregate_allowance"]["max_architect_cycles"],
            "max_compactions": state["aggregate_allowance"]["max_compactions"],
        },
        "mutation": {
            "out_of_scope": state["mutation"]["out_of_scope"],
            "tainted": state["mutation"]["tainted"],
        },
        "model_health": {
            "exact_model": state["model_match"],
        },
        "control_health": {
            "healthy": state["control_healthy"],
        },
        "main_thread": {
            "model": state["main_thread"]["model"],
            "effort": state["main_thread"]["effort"],
            "source": state["main_thread"]["source"],
            "recommended_effort": state["main_thread"]["recommended_effort"],
            "recommendation_reason": state["main_thread"]["recommendation_reason"],
            "advisory": state["main_thread"]["advisory"],
            "user_selected_effort_retained": state["main_thread"]["user_selected_effort_retained"],
        },
        "next_action": state["next_action"],
    }


def _to_protected_stop(
    state: Mapping[str, Any],
    reason_codes: list[str],
    event: str,
    *,
    caller_authority: VerifiedAuthority,
    next_action: str = "operator-review",
) -> dict[str, Any]:
    result = copy.deepcopy(state)
    prior_state = str(result.get("state", "unknown"))
    result["state"] = "protected-stop"
    result["reason_codes"] = reason_codes
    result["next_action"] = next_action
    result["cwo_native_replanning_receipt"] = _emit_receipt(
        state_before=prior_state,
        state_after="protected-stop",
        event=event,
        authority=caller_authority,
        decision="protected-stop",
        reason_codes=reason_codes,
        state=result,
    )
    return result


def _apply_usage(state: dict[str, Any], evidence: Mapping[str, Any]) -> None:
    tool_calls_delta, runtime_seconds_delta, context_compactions_delta = _usage_from_evidence(evidence)
    state["counters"]["tool_calls_used"] += tool_calls_delta
    state["counters"]["runtime_seconds_used"] += runtime_seconds_delta
    state["counters"]["context_compactions"] += context_compactions_delta


def _check_aggregate_allowance(state: Mapping[str, Any]) -> list[str]:
    tool_calls_remaining, runtime_seconds_remaining = _remaining_allowance(state)
    reasons: list[str] = []
    if tool_calls_remaining < 0:
        reasons.append("aggregate-allowance-exhausted")
    if runtime_seconds_remaining < 0:
        reasons.append("aggregate-allowance-exhausted")
    return reasons


def _apply_operator_protected_refinement(
    state: dict[str, Any],
    proposed_changes: Any,
    *,
    policy: Mapping[str, Any],
    operator_approval_verifier: OperatorApprovalVerifier | None,
    operator_approval_receipts: Mapping[str, Any] | None,
) -> list[dict[str, Any]]:
    changes = _ensure_mapping(proposed_changes, path="evidence.proposed_changes")
    unknown = sorted(set(changes) - PROTECTED_REPLANNING_CHANGE_FIELDS)
    if unknown:
        raise ValueError(
            "malformed evidence: proposed_changes has unsupported field(s): "
            + ",".join(unknown)
        )
    if not changes:
        raise ValueError("malformed evidence: proposed_changes must not be empty")

    candidate = copy.deepcopy(state)
    if "objective" in changes:
        candidate["objective"] = _ensure_nonempty_str(
            changes["objective"], path="evidence.proposed_changes.objective"
        )
    if "requested_model" in changes:
        candidate["requested_model"] = _ensure_nonempty_str(
            changes["requested_model"],
            path="evidence.proposed_changes.requested_model",
        )
    if "security_context" in changes:
        candidate["security_context"] = _ensure_nonempty_str(
            changes["security_context"],
            path="evidence.proposed_changes.security_context",
        )
    if "aggregate_allowance" in changes:
        allowance = _ensure_mapping(
            changes["aggregate_allowance"],
            path="evidence.proposed_changes.aggregate_allowance",
        )
        expected_allowance_fields = {"tool_calls_hard", "runtime_seconds_hard"}
        if set(allowance) != expected_allowance_fields:
            raise ValueError(
                "malformed evidence: proposed aggregate_allowance must contain exactly "
                "tool_calls_hard and runtime_seconds_hard"
            )
        candidate["aggregate_allowance"] = _normalize_allowance(
            allowance,
            policy=policy,
            path="evidence.proposed_changes.aggregate_allowance",
        )
        if _check_aggregate_allowance(candidate):
            raise ValueError(
                "malformed evidence: proposed aggregate allowance is below cumulative usage"
            )
    if all(candidate.get(field) == state.get(field) for field in changes):
        raise ValueError("malformed evidence: proposed_changes is an idempotent no-op")

    try:
        assessment = assess_operator_required_changes(
            state,
            candidate,
            operator_required_for=policy["operator_required_for"],
            profile="native-replanning-refinement",
            identity=protected_change_identity(
                artifact_type=REPLANNING_STATE_TYPE,
                artifact_id=f"{state['result_type']}:{state['version']}",
                work_unit_id=state["work_unit_id"],
                bead_id=state["bead_id"],
                packet_id=state["packet_id"],
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
                "verified operator approval required for: "
                + ",".join(protected_changes)
            )
        try:
            approvals = operator_approval_verifier.authorize_assessment(
                assessment,
                receipts=receipts,
                prior_nonces={
                    str(approval["nonce"])
                    for approval in state["protected_change_authorizations"]
                },
            )
        except AuthorityProvenanceError as exc:
            raise ValueError(str(exc)) from exc
    elif receipts:
        raise ValueError("operator approval receipts are unexpected for this refinement")

    for field in changes:
        state[field] = copy.deepcopy(candidate[field])
    audit = [approval.audit_record() for approval in approvals]
    state["protected_change_authorizations"].extend(audit)
    return audit


def build_replanning_state(
    state: Any,
    *,
    caller_authority: VerifiedAuthority,
    policy: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    source = _ensure_mapping(state, path="state")
    try:
        require_minimum_authority(
            caller_authority,
            "worker",
            action="replanning-bootstrap",
        )
    except AuthorityProvenanceError as exc:
        raise ValueError(str(exc)) from exc
    policy_data = _normalize_autonomous_policy(policy)

    replanning_state = str(source.get("state", "planned"))
    if replanning_state not in REQUIRED_STATES:
        raise ValueError("malformed payload: state.state must be a valid replanning state")

    counters = _normalize_counters(
        source.get("counters", source),
        path="state",
    )
    allowance = _normalize_allowance(
        source.get("aggregate_allowance", source),
        policy=policy_data,
        path="state.aggregate_allowance",
    )
    mutation = _normalize_mutation(
        source.get("mutation", {}),
        path="state.mutation",
    )
    main_thread = _normalize_main_thread(
        source.get("main_thread", {}),
        policy=policy_data,
        evidence={},
        path="state.main_thread",
    )

    result = {
        "result_type": REPLANNING_STATE_TYPE,
        "version": REPLANNING_VERSION,
        "schema": SCHEMA_PATH,
        "state": replanning_state,
        "work_unit_id": _ensure_nonempty_str(source.get("work_unit_id"), path="state.work_unit_id"),
        "bead_id": _ensure_nonempty_str(source.get("bead_id"), path="state.bead_id"),
        "packet_id": _ensure_nonempty_str(source.get("packet_id"), path="state.packet_id"),
        "requested_model": _ensure_nonempty_str(source.get("requested_model"), path="state.requested_model"),
        "objective": _ensure_nonempty_str(source.get("objective"), path="state.objective"),
        "security_context": _ensure_nonempty_str(source.get("security_context"), path="state.security_context"),
        "authority_provenance": caller_authority.serialize(),
        "model_match": _ensure_bool(source.get("model_match", True), path="state.model_match"),
        "control_healthy": _ensure_bool(source.get("control_healthy", True), path="state.control_healthy"),
        "counters": counters,
        "aggregate_allowance": allowance,
        "mutation": mutation,
        "main_thread": main_thread,
        "reason_codes": _ensure_list(source.get("reason_codes", []), path="state.reason_codes"),
        "protected_change_authorizations": [],
        "next_action": str(source.get("next_action", "wait")),
        "policy_snapshot": {
            "dispatch_soft_cap": policy_data["dispatch_soft_cap"],
            "max_pm_replans": policy_data["max_pm_replans"],
            "max_architect_cycles": policy_data["max_architect_cycles"],
            "max_compactions": policy_data["max_compactions"],
            "live_replay_enabled": policy_data["live_replay_enabled"],
        },
    }
    result["cwo_native_replanning_receipt"] = _emit_receipt(
        state_before=replanning_state,
        state_after=replanning_state,
        event="bootstrap",
        authority=caller_authority,
        decision="initialized",
        reason_codes=[],
        state=result,
    )
    return result


def _validate_replanning_state(state: Mapping[str, Any]) -> None:
    if state.get("result_type") != REPLANNING_STATE_TYPE:
        raise ValueError("malformed state: result_type must be cwo-native-replanning-state")
    if int(state.get("version", 0)) != REPLANNING_VERSION:
        raise ValueError("malformed state: version must be 2; version 1 is historical-only")
    if state.get("schema") != SCHEMA_PATH:
        raise ValueError("malformed state: schema must be schemas/native-replanning-state.schema.json")
    if str(state.get("state")) not in REQUIRED_STATES:
        raise ValueError("malformed state: state is invalid")
    authority_errors = validate_authority_provenance(state.get("authority_provenance"))
    if authority_errors:
        raise ValueError(
            "malformed state: authority_provenance invalid: "
            + ";".join(authority_errors)
        )
    approval_audit = state.get("protected_change_authorizations")
    if not isinstance(approval_audit, list):
        raise ValueError(
            "malformed state: protected_change_authorizations must be an array"
        )
    seen_approval_nonces: set[str] = set()
    for index, approval in enumerate(approval_audit):
        approval_errors = validate_operator_approval_audit(approval)
        if approval_errors:
            raise ValueError(
                f"malformed state: protected_change_authorizations[{index}] invalid: "
                + ";".join(approval_errors)
            )
        nonce = str(approval["nonce"])
        if nonce in seen_approval_nonces:
            raise ValueError(
                "malformed state: protected change authorization nonce replayed"
            )
        seen_approval_nonces.add(nonce)
    receipt = state.get("cwo_native_replanning_receipt")
    if not isinstance(receipt, Mapping):
        raise ValueError("malformed state: replanning receipt must be an object")
    if receipt.get("protected_change_authorizations") != approval_audit:
        raise ValueError(
            "malformed state: replanning receipt protected approvals do not match state"
        )


def read_replanning_state(state: Any) -> dict[str, Any]:
    """Read current state or a non-operative historical version-1 artifact."""

    source = _ensure_mapping(state, path="state")
    version = source.get("version")
    if version == REPLANNING_VERSION:
        _validate_replanning_state(source)
        return copy.deepcopy(dict(source))
    if version != 1:
        raise ValueError("malformed state: unsupported replanning version")
    if source.get("result_type") != REPLANNING_STATE_TYPE:
        raise ValueError("malformed historical state: result_type invalid")
    if source.get("schema") != SCHEMA_PATH:
        raise ValueError("malformed historical state: schema invalid")
    if source.get("state") not in REQUIRED_STATES:
        raise ValueError("malformed historical state: state invalid")
    if not isinstance(source.get("authority"), str) or not source["authority"].strip():
        raise ValueError("malformed historical state: authority invalid")
    return copy.deepcopy(dict(source))


def transition_replanning_state(
    state: Any,
    event: Any,
    evidence: Any,
    *,
    caller_authority: VerifiedAuthority,
    operator_approval_verifier: OperatorApprovalVerifier | None = None,
    operator_approval_receipts: Mapping[str, Any] | None = None,
    policy: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    source = _ensure_mapping(state, path="state")
    source_is_raw = source.get("result_type") != REPLANNING_STATE_TYPE
    if source_is_raw:
        source = build_replanning_state(
            source,
            caller_authority=caller_authority,
            policy=policy,
        )
    else:
        _validate_replanning_state(source)
    normalized_event = _coerce_event(event)
    if normalized_event not in KNOWN_EVENTS:
        raise ValueError("malformed event: unknown event")
    try:
        require_minimum_authority(
            caller_authority,
            EVENT_MINIMUM_AUTHORITY[normalized_event],
            action=f"replanning-{normalized_event}",
        )
    except AuthorityProvenanceError as exc:
        raise ValueError(str(exc)) from exc

    policy_data = _normalize_autonomous_policy(policy)
    next_state = copy.deepcopy(source)
    evidence_payload = _ensure_mapping(evidence, path="evidence")
    proposed_changes = evidence_payload.get("proposed_changes")
    if proposed_changes is not None and normalized_event not in {
        EVENT_PM_REFINED,
        EVENT_ARCHITECT_REFINED,
    }:
        raise ValueError(
            "malformed evidence: proposed_changes is valid only for refinement events"
        )
    if proposed_changes is None and operator_approval_receipts is not None:
        try:
            unexpected_receipts = canonical_json_object(
                operator_approval_receipts,
                label="operator-approval-receipts",
            )
        except AuthorityProvenanceError as exc:
            raise ValueError(str(exc)) from exc
        if unexpected_receipts:
            raise ValueError("operator approval receipts require proposed_changes")
    if proposed_changes is not None:
        try:
            proposed_payload = canonical_json_object(
                proposed_changes, label="evidence.proposed_changes"
            )
        except AuthorityProvenanceError as exc:
            raise ValueError(str(exc)) from exc
        unknown_proposed = sorted(
            set(proposed_payload) - PROTECTED_REPLANNING_CHANGE_FIELDS
        )
        if unknown_proposed:
            raise ValueError(
                "malformed evidence: proposed_changes has unsupported field(s): "
                + ",".join(unknown_proposed)
            )
        if not proposed_payload:
            raise ValueError(
                "malformed evidence: proposed_changes must not be empty"
            )
        proposed_changes = proposed_payload

    next_state["authority_provenance"] = caller_authority.serialize()

    next_state["policy_snapshot"] = {
        "dispatch_soft_cap": policy_data["dispatch_soft_cap"],
        "max_pm_replans": policy_data["max_pm_replans"],
        "max_architect_cycles": policy_data["max_architect_cycles"],
        "max_compactions": policy_data["max_compactions"],
        "live_replay_enabled": policy_data["live_replay_enabled"],
    }
    main_thread_payload = next_state.get("main_thread", {})
    next_state["main_thread"] = _normalize_main_thread(
        main_thread_payload,
        policy=policy_data,
        evidence=evidence_payload,
        path="state.main_thread",
    )
    prior_mutation = _normalize_mutation(
        next_state.get("mutation", {}), path="state.mutation"
    )
    observed_mutation = _normalize_mutation(
        evidence_payload.get("mutation", next_state.get("mutation", {})),
        path="evidence.mutation",
    )
    next_state["mutation"] = {
        "out_of_scope": prior_mutation["out_of_scope"]
        or observed_mutation["out_of_scope"],
        "tainted": prior_mutation["tainted"] or observed_mutation["tainted"],
    }
    contradictory_observation = _ensure_bool(
        evidence_payload.get("contradictory_validation", False),
        path="evidence.contradictory_validation",
    )
    contradictory_sticky = contradictory_observation or (
        "contradictory-validation" in source.get("reason_codes", [])
    )
    _apply_usage(next_state, evidence_payload)

    def protected_stop(
        reason_codes: list[str],
        *,
        next_action: str = "operator-review",
    ) -> dict[str, Any]:
        return _to_protected_stop(
            next_state,
            reason_codes,
            normalized_event,
            caller_authority=caller_authority,
            next_action=next_action,
        )

    terminal_reasons: list[str] = []
    if next_state["mutation"]["tainted"]:
        terminal_reasons.append("tainted-mutation")
    if contradictory_sticky:
        terminal_reasons.append("contradictory-validation")
    if terminal_reasons:
        return protected_stop(terminal_reasons)

    if normalized_event in {"model-mismatch", "control-loss", "security-or-authority-ambiguity", "out-of-scope-mutation", "tainted-mutation", "operator-trigger"}:
        reason = normalized_event if normalized_event in {"model-mismatch", "control-loss"} else normalized_event
        return protected_stop([reason])

    aggregate_reasons = _check_aggregate_allowance(next_state)
    if aggregate_reasons:
        return protected_stop(aggregate_reasons)

    current_state = str(next_state["state"])
    if normalized_event == EVENT_ACCEPTED:
        if current_state not in {"planned", "commitment-required"}:
            raise ValueError("malformed event: accepted is valid only from planned or commitment-required")
        accepted = evidence_payload.get("commitment_accepted", True)
        if not isinstance(accepted, bool):
            raise ValueError("malformed evidence: commitment_accepted must be a boolean when provided")
        if not accepted:
            return protected_stop(["invalid-trusted-evidence"])
        next_state["state"] = "dispatchable"
        next_state["next_action"] = "dispatch"
        next_state["reason_codes"] = ["commitment-accepted"]
        next_state["cwo_native_replanning_receipt"] = _emit_receipt(
            state_before=current_state,
            state_after="dispatchable",
            event=normalized_event,
            authority=caller_authority,
            decision="advance",
            reason_codes=["commitment-accepted"],
            state=next_state,
        )
        return next_state

    if normalized_event == EVENT_DISPATCH_STARTED:
        if current_state != "dispatchable":
            if not (source_is_raw and current_state == "executing"):
                raise ValueError("malformed event: dispatch-started is valid only from dispatchable")
        if source_is_raw and current_state == "executing":
            current_state = "dispatchable"
        next_state["state"] = "executing"
        next_state["counters"]["dispatches"] += 1
        reasons = ["dispatch-started"]
        if _remaining_dispatch_capacity(next_state) < 0:
            reasons.append("dispatch-soft-cap-exceeded")
        next_state["reason_codes"] = reasons
        next_state["next_action"] = (
            "pm-architect-review"
            if _remaining_dispatch_capacity(next_state) < 0
            else next_state["aggregate_allowance"]["dispatch_soft_cap_action"]
        )
        next_state["cwo_native_replanning_receipt"] = _emit_receipt(
            state_before=current_state,
            state_after="executing",
            event=normalized_event,
            authority=caller_authority,
            decision="advance",
            reason_codes=reasons,
            state=next_state,
        )
        return next_state

    if normalized_event == EVENT_WORKER_COMPACTION:
        if current_state != "executing":
            raise ValueError("malformed event: worker-compaction is valid only from executing")

        next_state["main_thread"] = _normalize_main_thread(
            main_thread_payload,
            policy=policy_data,
            evidence={},
            path="state.main_thread",
            allow_runtime_overrides=False,
        )

        reasons: list[str] = []
        if not isinstance(evidence_payload.get("trusted_evidence", False), bool):
            raise ValueError("malformed evidence: trusted_evidence must be a boolean")
        if not evidence_payload.get("trusted_evidence", False):
            reasons.append("invalid-trusted-evidence")
        if not isinstance(evidence_payload.get("exact_model", True), bool):
            raise ValueError("malformed evidence: exact_model must be a boolean")
        exact_model = bool(evidence_payload.get("exact_model", next_state["model_match"]))
        next_state["model_match"] = exact_model
        if not exact_model:
            reasons.append("model-mismatch")
        if not isinstance(evidence_payload.get("control_healthy", True), bool):
            raise ValueError("malformed evidence: control_healthy must be a boolean")
        control_healthy = bool(evidence_payload.get("control_healthy", next_state["control_healthy"]))
        next_state["control_healthy"] = control_healthy
        if not control_healthy:
            reasons.append("control-loss")
        if not isinstance(evidence_payload.get("affected_worker_contained", False), bool):
            raise ValueError("malformed evidence: affected_worker_contained must be a boolean")
        if not evidence_payload.get("affected_worker_contained", False):
            reasons.append("affected-worker-containment")
        if next_state["mutation"]["out_of_scope"]:
            reasons.append("out-of-scope-mutation")
        if next_state["mutation"]["tainted"]:
            reasons.append("tainted-mutation")
        if bool(evidence_payload.get("security_changed", False)):
            reasons.append("security-or-authority-change")
        if bool(evidence_payload.get("authority_changed", False)):
            reasons.append("security-or-authority-change")

        if reasons:
            reasons.append("main-thread-adjudication")
            return protected_stop(
                reasons,
                next_action=policy_data["worker_compaction"]["ambiguous_route"],
            )

        next_state["state"] = "architect-realignment"
        next_state["next_action"] = policy_data["worker_compaction"]["clean_attributable_route"]
        next_state["reason_codes"] = [
            "clean-attributable-compaction",
            f"event:{normalized_event}",
        ]
        next_state["cwo_native_replanning_receipt"] = _emit_receipt(
            state_before=current_state,
            state_after="architect-realignment",
            event=normalized_event,
            authority=caller_authority,
            decision="replan",
            reason_codes=next_state["reason_codes"],
            state=next_state,
        )
        return next_state

    if normalized_event == EVENT_NEEDS_REPLAN:
        if current_state != "executing":
            raise ValueError("malformed event: needs-replan is valid only from executing")
        reasons: list[str] = []
        if not _ensure_bool(evidence_payload.get("trusted_evidence", False), path="evidence.trusted_evidence"):
            reasons.append("invalid-trusted-evidence")
        if not _ensure_bool(evidence_payload.get("exact_model", next_state["model_match"]), path="evidence.exact_model"):
            reasons.append("model-mismatch")
            next_state["model_match"] = False
        if not _ensure_bool(
            evidence_payload.get("control_healthy", next_state["control_healthy"]),
            path="evidence.control_healthy",
        ):
            reasons.append("control-loss")
            next_state["control_healthy"] = False
        if next_state["mutation"]["out_of_scope"]:
            reasons.append("out-of-scope-mutation")
        if next_state["mutation"]["tainted"]:
            reasons.append("tainted-mutation")
        if next_state["counters"]["context_compactions"] > next_state["aggregate_allowance"]["max_compactions"]:
            reasons.append("compaction")

        replan = evidence_payload.get("replan")
        replan_errors = validate_needs_replan_payload(replan)
        if replan_errors:
            reasons.append("invalid-needs-replan-evidence")
        if reasons:
            return protected_stop(list(dict.fromkeys(reasons)))

        assert isinstance(replan, Mapping)
        cumulative = replan["cumulative_usage"]
        if (
            cumulative["tool_calls"] != next_state["counters"]["tool_calls_used"]
            or cumulative["runtime_seconds"] != next_state["counters"]["runtime_seconds_used"]
            or cumulative["context_compactions"] != next_state["counters"]["context_compactions"]
        ):
            return protected_stop(["invalid-needs-replan-evidence"])

        scope_delta = replan["scope_delta"]
        if not scope_delta["within_original_objective"]:
            return protected_stop(["objective-change"])
        if not scope_delta["within_aggregate_allowance"]:
            return protected_stop(["aggregate-allowance-exhausted"])

        calls_remaining, runtime_remaining = _remaining_allowance(next_state)
        for option in replan["bounded_options"]:
            if option["route"] == "protected-stop":
                continue
            if option["tool_calls_p90"] > calls_remaining or option["runtime_seconds_p90"] > runtime_remaining:
                return protected_stop(["invalid-needs-replan-evidence"])

        uncertainty = replan["uncertainty"]
        reason_code = str(replan["reason_code"])
        if uncertainty["decision"] == "architect-reasoning":
            next_state["state"] = "architect-realignment"
            next_state["next_action"] = "request-architect-refinement"
            next_state["reason_codes"] = ["worker-needs-replan", reason_code, "architect-reasoning-required"]
        else:
            if next_state["counters"]["pm_replans_used"] >= policy_data["max_pm_replans"]:
                return protected_stop(["pm-replan-exhausted"])
            next_state["state"] = "pm-realignment"
            next_state["counters"]["pm_replans_used"] += 1
            next_state["next_action"] = "request-pm-refinement"
            next_state["reason_codes"] = ["worker-needs-replan", reason_code]
        next_state["cwo_native_replanning_receipt"] = _emit_receipt(
            state_before=current_state,
            state_after=next_state["state"],
            event=normalized_event,
            authority=caller_authority,
            decision="replan",
            reason_codes=next_state["reason_codes"],
            state=next_state,
        )
        return next_state

    if normalized_event in {EVENT_EXPLORATION_LIMIT, EVENT_CLEAN_NO_ARTIFACT}:
        if current_state != "executing":
            raise ValueError("malformed event: exploration-control events are valid only from executing")
        reasons: list[str] = []
        if not _ensure_bool(evidence_payload.get("trusted_evidence", True), path="evidence.trusted_evidence"):
            reasons.append("invalid-trusted-evidence")
        if not _ensure_bool(evidence_payload.get("exact_model", next_state["model_match"]), path="evidence.exact_model"):
            reasons.append("model-mismatch")
            next_state["model_match"] = False
        else:
            next_state["model_match"] = True
        if not _ensure_bool(
            evidence_payload.get("control_healthy", next_state["control_healthy"]),
            path="evidence.control_healthy",
        ):
            reasons.append("control-loss")
            next_state["control_healthy"] = False
        if next_state["mutation"]["out_of_scope"]:
            reasons.append("out-of-scope-mutation")
        if next_state["mutation"]["tainted"]:
            reasons.append("tainted-mutation")
        if bool(evidence_payload.get("objective_changed", False)):
            reasons.append("objective-change")
        if bool(evidence_payload.get("security_changed", False)):
            reasons.append("security-or-authority-change")
        if bool(evidence_payload.get("authority_changed", False)):
            reasons.append("security-or-authority-change")
        if next_state["counters"]["context_compactions"] > policy_data["exploration_limits"][normalized_event]:
            reasons.append("compaction")
        if next_state["counters"]["pm_replans_used"] >= policy_data["max_pm_replans"]:
            reasons.append("pm-replan-exhausted")

        next_state["reason_codes"] = reasons
        if reasons:
            return protected_stop(reasons)

        next_state["state"] = "pm-realignment"
        next_state["counters"]["pm_replans_used"] += 1
        next_state["next_action"] = "request-pm-refinement"
        next_state["reason_codes"] = ["exploration-limit-trigger", f"event:{normalized_event}"]
        next_state["cwo_native_replanning_receipt"] = _emit_receipt(
            state_before=current_state,
            state_after="pm-realignment",
            event=normalized_event,
            authority=caller_authority,
            decision="replan",
            reason_codes=next_state["reason_codes"],
            state=next_state,
        )
        return next_state

    if normalized_event == EVENT_PM_REFINED:
        if current_state != "pm-realignment":
            raise ValueError("malformed event: pm-refined is valid only from pm-realignment")
        requires_architect = evidence_payload.get("requires_architect_cycle", False)
        if not isinstance(requires_architect, bool):
            raise ValueError("malformed evidence: requires_architect_cycle must be a boolean")
        approval_audit = (
            _apply_operator_protected_refinement(
                next_state,
                proposed_changes,
                policy=policy_data,
                operator_approval_verifier=operator_approval_verifier,
                operator_approval_receipts=operator_approval_receipts,
            )
            if proposed_changes is not None
            else []
        )
        next_state["state"] = "architect-realignment" if requires_architect else "reassignment-ready"
        next_state["next_action"] = (
            "request-architect-refinement"
            if requires_architect
            else (
                "fresh-worker-assignment"
                if policy_data["fresh_worker_reassignment_required"]
                else "operator-resume"
            )
        )
        next_state["reason_codes"] = ["pm-refined"] + [
            f"operator-approved:{approval['change_type']}"
            for approval in approval_audit
        ]
        next_state["cwo_native_replanning_receipt"] = _emit_receipt(
            state_before=current_state,
            state_after=next_state["state"],
            event=normalized_event,
            authority=caller_authority,
            decision="advance" if not requires_architect else "replan",
            reason_codes=next_state["reason_codes"],
            state=next_state,
        )
        return next_state

    if normalized_event == EVENT_ARCHITECT_REFINED:
        if current_state != "architect-realignment":
            raise ValueError("malformed event: architect-refined is valid only from architect-realignment")
        if next_state["counters"]["architect_cycles_used"] >= policy_data["max_architect_cycles"]:
            return protected_stop(["architect-cycle-exhausted"])
        approval_audit = (
            _apply_operator_protected_refinement(
                next_state,
                proposed_changes,
                policy=policy_data,
                operator_approval_verifier=operator_approval_verifier,
                operator_approval_receipts=operator_approval_receipts,
            )
            if proposed_changes is not None
            else []
        )
        next_state["counters"]["architect_cycles_used"] += 1
        next_state["state"] = "reassignment-ready"
        next_state["next_action"] = (
            "fresh-worker-assignment" if policy_data["fresh_worker_reassignment_required"] else "operator-resume"
        )
        next_state["reason_codes"] = ["architect-refined"] + [
            f"operator-approved:{approval['change_type']}"
            for approval in approval_audit
        ]
        next_state["cwo_native_replanning_receipt"] = _emit_receipt(
            state_before=current_state,
            state_after="reassignment-ready",
            event=normalized_event,
            authority=caller_authority,
            decision="advance",
            reason_codes=next_state["reason_codes"],
            state=next_state,
        )
        return next_state

    if normalized_event == EVENT_FRESH_WORKER_ASSIGNED:
        if current_state != "reassignment-ready":
            raise ValueError("malformed event: fresh-worker-assigned is valid only from reassignment-ready")
        next_state["state"] = "dispatchable"
        next_state["next_action"] = "dispatch"
        next_state["reason_codes"] = [policy_data["fresh_worker_reassignment_event"]]
        next_state["cwo_native_replanning_receipt"] = _emit_receipt(
            state_before=current_state,
            state_after="dispatchable",
            event=normalized_event,
            authority=caller_authority,
            decision="advance",
            reason_codes=next_state["reason_codes"],
            state=next_state,
        )
        return next_state

    if normalized_event == EVENT_COMPLETED:
        if current_state != "executing":
            raise ValueError("malformed event: completed is valid only from executing")
        completed_ok = bool(evidence_payload.get("completed", False))
        if not completed_ok:
            return protected_stop(["invalid-completion-evidence"])
        next_state["state"] = "completed"
        next_state["next_action"] = "finished"
        next_state["reason_codes"] = ["completed"]
        next_state["cwo_native_replanning_receipt"] = _emit_receipt(
            state_before=current_state,
            state_after="completed",
            event=normalized_event,
            authority=caller_authority,
            decision="complete",
            reason_codes=next_state["reason_codes"],
            state=next_state,
        )
        return next_state

    raise ValueError("malformed event: unsupported transition")
