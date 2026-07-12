from __future__ import annotations

import copy
from collections.abc import Mapping
from typing import Any

from .policy import load_policy

REPLANNING_STATE_TYPE = "cwo-native-replanning-state"
REPLANNING_RECEIPT_TYPE = "cwo-native-replanning-receipt"
SCHEMA_PATH = "schemas/native-replanning-state.schema.json"
REPLANNING_VERSION = 1
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

KNOWN_EVENT_BY_AUTHORITY = {
    EVENT_ACCEPTED: "worker",
    EVENT_DISPATCH_STARTED: "worker",
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
    return {
        "out_of_scope": bool(source.get("out_of_scope", False)),
        "tainted": bool(source.get("tainted", False)),
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
    authority: str,
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
        "authority": authority,
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
        authority=KNOWN_EVENT_BY_AUTHORITY[event],
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


def build_replanning_state(
    state: Any,
    *,
    policy: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    source = _ensure_mapping(state, path="state")
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
        "authority": _ensure_nonempty_str(source.get("authority"), path="state.authority"),
        "model_match": _ensure_bool(source.get("model_match", True), path="state.model_match"),
        "control_healthy": _ensure_bool(source.get("control_healthy", True), path="state.control_healthy"),
        "counters": counters,
        "aggregate_allowance": allowance,
        "mutation": mutation,
        "main_thread": main_thread,
        "reason_codes": _ensure_list(source.get("reason_codes", []), path="state.reason_codes"),
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
        authority="worker",
        decision="initialized",
        reason_codes=[],
        state=result,
    )
    return result


def _validate_replanning_state(state: Mapping[str, Any]) -> None:
    if state.get("result_type") != REPLANNING_STATE_TYPE:
        raise ValueError("malformed state: result_type must be cwo-native-replanning-state")
    if int(state.get("version", 0)) != REPLANNING_VERSION:
        raise ValueError("malformed state: version must be 1")
    if state.get("schema") != SCHEMA_PATH:
        raise ValueError("malformed state: schema must be schemas/native-replanning-state.schema.json")
    if str(state.get("state")) not in REQUIRED_STATES:
        raise ValueError("malformed state: state is invalid")


def transition_replanning_state(
    state: Any,
    event: Any,
    evidence: Any,
    *,
    policy: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    source = _ensure_mapping(state, path="state")
    source_is_raw = source.get("result_type") != REPLANNING_STATE_TYPE
    if source_is_raw:
        source = build_replanning_state(source, policy=policy)
    else:
        _validate_replanning_state(source)
    normalized_event = _coerce_event(event)
    if normalized_event not in KNOWN_EVENTS:
        raise ValueError("malformed event: unknown event")

    policy_data = _normalize_autonomous_policy(policy)
    next_state = copy.deepcopy(source)
    evidence_payload = _ensure_mapping(evidence, path="evidence")

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
    next_state["mutation"] = _normalize_mutation(
        evidence_payload.get("mutation", next_state.get("mutation", {})),
        path="evidence.mutation",
    )
    _apply_usage(next_state, evidence_payload)

    if normalized_event in {"model-mismatch", "control-loss", "security-or-authority-ambiguity", "out-of-scope-mutation", "tainted-mutation", "operator-trigger"}:
        reason = normalized_event if normalized_event in {"model-mismatch", "control-loss"} else normalized_event
        return _to_protected_stop(next_state, [reason], normalized_event)

    aggregate_reasons = _check_aggregate_allowance(next_state)
    if aggregate_reasons:
        return _to_protected_stop(next_state, aggregate_reasons, normalized_event)

    current_state = str(next_state["state"])
    if normalized_event == EVENT_ACCEPTED:
        if current_state not in {"planned", "commitment-required"}:
            raise ValueError("malformed event: accepted is valid only from planned or commitment-required")
        accepted = evidence_payload.get("commitment_accepted", True)
        if not isinstance(accepted, bool):
            raise ValueError("malformed evidence: commitment_accepted must be a boolean when provided")
        if not accepted:
            return _to_protected_stop(next_state, ["invalid-trusted-evidence"], normalized_event)
        next_state["state"] = "dispatchable"
        next_state["next_action"] = "dispatch"
        next_state["reason_codes"] = ["commitment-accepted"]
        next_state["cwo_native_replanning_receipt"] = _emit_receipt(
            state_before=current_state,
            state_after="dispatchable",
            event=normalized_event,
            authority=KNOWN_EVENT_BY_AUTHORITY[normalized_event],
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
            authority=KNOWN_EVENT_BY_AUTHORITY[normalized_event],
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
            return _to_protected_stop(
                next_state,
                reasons,
                normalized_event,
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
            authority=KNOWN_EVENT_BY_AUTHORITY[normalized_event],
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
            return _to_protected_stop(next_state, reasons, normalized_event)

        next_state["state"] = "pm-realignment"
        next_state["counters"]["pm_replans_used"] += 1
        next_state["next_action"] = "request-pm-refinement"
        next_state["reason_codes"] = ["exploration-limit-trigger", f"event:{normalized_event}"]
        next_state["cwo_native_replanning_receipt"] = _emit_receipt(
            state_before=current_state,
            state_after="pm-realignment",
            event=normalized_event,
            authority=KNOWN_EVENT_BY_AUTHORITY[normalized_event],
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
        next_state["reason_codes"] = ["pm-refined"]
        next_state["cwo_native_replanning_receipt"] = _emit_receipt(
            state_before=current_state,
            state_after=next_state["state"],
            event=normalized_event,
            authority=KNOWN_EVENT_BY_AUTHORITY[normalized_event],
            decision="advance" if not requires_architect else "replan",
            reason_codes=next_state["reason_codes"],
            state=next_state,
        )
        return next_state

    if normalized_event == EVENT_ARCHITECT_REFINED:
        if current_state != "architect-realignment":
            raise ValueError("malformed event: architect-refined is valid only from architect-realignment")
        if next_state["counters"]["architect_cycles_used"] >= policy_data["max_architect_cycles"]:
            return _to_protected_stop(next_state, ["architect-cycle-exhausted"], normalized_event)
        next_state["counters"]["architect_cycles_used"] += 1
        next_state["state"] = "reassignment-ready"
        next_state["next_action"] = (
            "fresh-worker-assignment" if policy_data["fresh_worker_reassignment_required"] else "operator-resume"
        )
        next_state["reason_codes"] = ["architect-refined"]
        next_state["cwo_native_replanning_receipt"] = _emit_receipt(
            state_before=current_state,
            state_after="reassignment-ready",
            event=normalized_event,
            authority=KNOWN_EVENT_BY_AUTHORITY[normalized_event],
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
            authority=KNOWN_EVENT_BY_AUTHORITY[normalized_event],
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
            return _to_protected_stop(next_state, ["invalid-completion-evidence"], normalized_event)
        next_state["state"] = "completed"
        next_state["next_action"] = "finished"
        next_state["reason_codes"] = ["completed"]
        next_state["cwo_native_replanning_receipt"] = _emit_receipt(
            state_before=current_state,
            state_after="completed",
            event=normalized_event,
            authority=KNOWN_EVENT_BY_AUTHORITY[normalized_event],
            decision="complete",
            reason_codes=next_state["reason_codes"],
            state=next_state,
        )
        return next_state

    raise ValueError("malformed event: unsupported transition")
