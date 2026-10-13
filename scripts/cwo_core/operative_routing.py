from __future__ import annotations

import datetime as dt
import hashlib
import json
from copy import deepcopy
from typing import Any, Mapping

from .policy import RISK_ORDER, load_policy


SPARK_MODEL = "gpt-5.3-codex-spark"
GPT55_MODEL = "gpt-5.5"
TERRA_MODEL = "gpt-5.6-terra"
LUNA_MODEL = "gpt-5.6-luna"
FALLBACK_MODELS = (GPT55_MODEL, TERRA_MODEL, LUNA_MODEL)
AVAILABILITY_STATUSES = (
    "available",
    "verified-quota-exhausted",
    "verified-capacity-unavailable",
    "unknown",
    "model-mismatch",
    "control-fault",
    "security-fault",
)
FALLBACK_TRIGGERS = {"verified-quota-exhausted", "verified-capacity-unavailable"}
FALLBACK_SCOPES = {"current-bead", "current-wave", "until-spark-restored"}
PROTECTED_STATUSES = {"unknown", "model-mismatch", "control-fault", "security-fault"}
THREAD_ALLOCATION_ONLY_AVAILABILITY_BASIS = (
    "exact-model-thread-allocation-accepted"
)
DATA_SENSITIVITY_ORDER = ("public", "redacted", "internal", "restricted")
FIT_CONTEXT_FIELDS = {"bead_id", "wave_id", "fresh_segment", "work_lineage_id"}
CACHE_PROFILE_FIELDS = {
    "source",
    "observed_at",
    "total_context_tokens_p90",
    "stable_context_tokens_p90",
    "expected_reuse_opportunities",
    "repeatable_unit_count",
    "repeat_template_sha256",
    "observed_input_tokens",
    "observed_cached_input_tokens",
    "same_work_lineage",
    "context_plan_sha256",
    "telemetry_lineage_id",
    "evidence_sha256",
}
FIT_FIELDS = {
    "fit_type",
    "version",
    "evaluated_at",
    "work_estimate_sha256",
    "policy_version",
    "policy_sha256",
    "capability_evidence_sha256",
    "aggregate_budget_sha256",
    "context",
    "cache_profile",
    "classifications",
    "candidates",
    "fit_sha256",
}
TASK_SELECTED_FIT_FIELDS = {
    "fit_type",
    "version",
    "binding_rule_version",
    "evaluated_at",
    "work_estimate_sha256",
    "neutral_work_estimate_sha256",
    "policy_version",
    "policy_sha256",
    "capability_evidence_sha256",
    "aggregate_budget_sha256",
    "context",
    "cache_profile",
    "classifications",
    "candidates",
    "fit_sha256",
}
TASK_SELECTED_PORTFOLIO = (LUNA_MODEL, TERRA_MODEL)
TASK_SELECTED_ROLES = {
    LUNA_MODEL: "luna-first-operative-worker",
    TERRA_MODEL: "escalation-only-operative-worker",
}


def _canonical_sha256(value: Any) -> str:
    payload = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _mapping(value: Any) -> dict[str, Any]:
    return dict(value) if isinstance(value, Mapping) else {}


def _string(value: Any) -> str:
    return str(value).strip() if isinstance(value, str) else ""


def _string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item).strip() for item in value if isinstance(item, str) and item.strip()]


def _nonnegative_int(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{field} must be a non-negative integer")
    return int(value)


def _sha256(value: Any, field: str, *, nullable: bool = False) -> str | None:
    if value is None and nullable:
        return None
    text = _string(value)
    if len(text) != 64 or any(char not in "0123456789abcdef" for char in text):
        raise ValueError(f"{field} must be a lowercase SHA-256 hex digest")
    return text


def _parse_time(value: Any, field: str) -> dt.datetime:
    text = _string(value)
    if not text:
        raise ValueError(f"{field} must be a non-empty timestamp")
    try:
        parsed = dt.datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{field} must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"{field} must include a timezone")
    return parsed.astimezone(dt.timezone.utc)


def _now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def _fresh(observed_at: Any, evaluated_at: Any, policy: Mapping[str, Any]) -> bool:
    freshness = _mapping(policy.get("evidence_freshness"))
    maximum = freshness.get("max_age_seconds")
    future_skew = freshness.get("future_skew_seconds", 0)
    if isinstance(maximum, bool) or not isinstance(maximum, int) or maximum <= 0:
        return False
    if isinstance(future_skew, bool) or not isinstance(future_skew, int) or future_skew < 0:
        return False
    try:
        observed = _parse_time(observed_at, "observed_at")
        evaluated = _parse_time(evaluated_at, "evaluated_at")
    except ValueError:
        return False
    age = (evaluated - observed).total_seconds()
    return -future_skew <= age <= maximum


def _policy_bundle() -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]]:
    native = load_policy("native-worker-execution")
    routing = _mapping(native.get("operative_routing"))
    registry = _mapping(load_policy("executor-registry").get("executors"))
    environments = _mapping(load_policy("execution-environments").get("profiles"))
    return native, routing, registry, environments


def _environment_contract(
    environment: str,
    environments: Mapping[str, Any],
) -> tuple[str, str, list[str]]:
    profile = _mapping(environments.get(environment))
    worker = _mapping(_mapping(profile.get("role_bindings")).get("worker"))
    route = _mapping(profile.get("operative_routing"))
    primary_model = _string(route.get("primary_model")) or _string(worker.get("model")) or SPARK_MODEL
    primary_executor = _string(route.get("primary_executor")) or _string(worker.get("executor")) or "internal_worker"
    approved = _string_list(route.get("approved_fallback_executors"))
    return primary_model, primary_executor, approved


def operative_policy_sha256(execution_environment: str = "connected-codex") -> str:
    native, routing, registry, environments = _policy_bundle()
    _, _, approved = _environment_contract(execution_environment, environments)
    policy_projection = {
        "operative_routing": routing,
        "native_operative_worker": _mapping(_mapping(native.get("governance")).get("native_operative_worker")),
        "precommit_authorized_models": _mapping(native.get("precommit_supervision")).get("authorized_models"),
        "release_authorized_models": _mapping(native.get("native_release_evidence")).get("authorized_models"),
        "environment": _mapping(_mapping(environments.get(execution_environment)).get("operative_routing")),
        "executors": {key: _mapping(registry.get(key)) for key in approved},
    }
    return _canonical_sha256(policy_projection)


def _task_selected_policy(
    native: Mapping[str, Any],
) -> tuple[dict[str, Any], dict[str, str]]:
    routing = native.get("task_selected_routing")
    if not isinstance(routing, Mapping):
        raise ValueError("task selected routing policy must be an object")
    source = deepcopy(dict(routing))
    if set(source) != {
        "version",
        "status",
        "activation",
        "selection",
        "operative_roles",
        "historical_v2",
        "attempt_binding",
        "bounded_semantic_readonly",
    }:
        raise ValueError("task selected routing policy fields are invalid")
    if type(source.get("version")) is not int or source["version"] != 3:
        raise ValueError("task selected routing policy version 3 is required")
    if type(source.get("status")) is not str or source["status"] not in {
        "inactive-prospective",
        "active",
    }:
        raise ValueError("task selected routing policy status is invalid")
    activation = source.get("activation")
    if not isinstance(activation, Mapping) or set(activation) != {
        "active",
        "dispatch_authority",
        "requires_complete_candidate_acceptance",
    } or any(type(activation[key]) is not bool for key in activation):
        raise ValueError("task selected routing activation is invalid")
    selection = source.get("selection")
    if not isinstance(selection, Mapping) or set(selection) != {
        "sizing",
        "approved_portfolio",
        "primary_model",
        "terra_selection",
        "spark_dispatch",
        "gpt55_dispatch",
        "model_substitution",
    }:
        raise ValueError("task selected routing selection must be an object")
    portfolio = selection.get("approved_portfolio")
    if type(portfolio) is not list or portfolio != list(TASK_SELECTED_PORTFOLIO):
        raise ValueError("task selected routing approved portfolio must be Luna then Terra")
    expected_selection = {
        "sizing": "neutral-before-exact-model-selection",
        "primary_model": LUNA_MODEL,
        "terra_selection": "recorded-fit-qualification-risk-or-economics-escalation-only",
        "spark_dispatch": "prohibited",
        "gpt55_dispatch": "prohibited",
        "model_substitution": "forbidden",
    }
    if any(selection.get(key) != value for key, value in expected_selection.items()):
        raise ValueError("task selected routing selection values are invalid")
    roles = source.get("operative_roles")
    expected_roles = {
        **TASK_SELECTED_ROLES,
        SPARK_MODEL: "historical-nonoperative",
    }
    if not isinstance(roles, Mapping) or dict(roles) != expected_roles:
        raise ValueError("task selected routing operative roles must be an object")
    selected_roles: dict[str, str] = {}
    for model, expected_role in TASK_SELECTED_ROLES.items():
        if type(roles.get(model)) is not str or roles[model] != expected_role:
            raise ValueError(f"task selected routing role for {model} is invalid")
        selected_roles[model] = roles[model]
    historical = source.get("historical_v2")
    if historical != {
        "readable": True,
        "nonoperative_for_v3": True,
        "new_dispatch_authority": False,
    }:
        raise ValueError("task selected routing historical policy is invalid")
    attempt = source.get("attempt_binding")
    if attempt != {
        "exact_identity_required": True,
        "qualification_required": True,
        "provenance_required": True,
        "scope_required": True,
        "budget_required": True,
        "stopped_session_reuse": "forbidden",
        "session_substitution": "forbidden",
    }:
        raise ValueError("task selected routing attempt binding is invalid")
    readonly = source.get("bounded_semantic_readonly")
    readonly_limits = {
        "max_context_reads", "max_tool_calls_p90", "max_runtime_seconds_p90",
        "command_complexity_max", "test_construction_complexity_max",
        "self_hosting_risk_max", "live_control_risk_max",
    }
    if not isinstance(readonly, Mapping) or set(readonly) != readonly_limits | {
        "enabled", "task_class", "required_fit_mode",
    }:
        raise ValueError("task selected bounded semantic readonly policy fields are invalid")
    if (type(readonly.get("enabled")) is not bool
            or readonly.get("task_class") != "diagnosis"
            or readonly.get("required_fit_mode") != "semantic"):
        raise ValueError("task selected bounded semantic readonly policy is invalid")
    for field in readonly_limits:
        minimum = 1 if field.startswith("max_") else 0
        if type(readonly.get(field)) is not int or readonly[field] < minimum:
            raise ValueError("task selected bounded semantic readonly policy limit is invalid")
    return source, selected_roles


def task_selected_policy_sha256(execution_environment: str = "connected-codex") -> str:
    native, _, registry, environments = _policy_bundle()
    routing, _ = _task_selected_policy(native)
    _, _, approved = _environment_contract(execution_environment, environments)
    portfolio_executors = {
        key: _mapping(registry.get(key))
        for key in approved
        if _string(_mapping(registry.get(key)).get("model_label")) in TASK_SELECTED_PORTFOLIO
    }
    return _canonical_sha256(
        {
            "task_selected_routing": routing,
            "environment": _mapping(
                _mapping(environments.get(execution_environment)).get("operative_routing")
            ),
            "executors": portfolio_executors,
        }
    )


def _trusted_evidence_source(evidence: Mapping[str, Any], policy: Mapping[str, Any]) -> bool:
    source = _string(evidence.get("source"))
    trusted = set(_string_list(policy.get("trusted_evidence_sources")))
    return bool(source and source in trusted)


def _required_controls(policy: Mapping[str, Any]) -> set[str]:
    return set(_string_list(policy.get("required_lifecycle_controls")))


def _surface_controls_valid(surface: Mapping[str, Any], policy: Mapping[str, Any]) -> bool:
    return (
        surface.get("fresh_session_supported") is True
        and surface.get("exact_model_attestation_supported") is True
        and _required_controls(policy).issubset(set(_string_list(surface.get("lifecycle_controls"))))
        and surface.get("workspace_enforced") is True
        and surface.get("mutation_enforced") is True
    )


def classify_spark_availability(
    evidence: Mapping[str, Any] | None,
    *,
    primary_model: str = SPARK_MODEL,
    policy: Mapping[str, Any] | None = None,
    evaluated_at: str | None = None,
) -> tuple[str, str]:
    """Classify Spark only from attributed, fresh, trusted live evidence."""

    routing_policy = dict(policy) if isinstance(policy, Mapping) else _policy_bundle()[1]
    source = _mapping(evidence)
    surface = _mapping(source.get("spark"))
    if not source or not surface:
        return "unknown", "trusted-live-spark-evidence-missing"
    if not _trusted_evidence_source(source, routing_policy):
        return "unknown", "spark-evidence-source-untrusted"
    if (
        not _string(source.get("observed_at"))
        or source.get("fresh") is not True
        or not _fresh(source.get("observed_at"), evaluated_at or _now_iso(), routing_policy)
    ):
        return "unknown", "spark-evidence-not-fresh"
    if source.get("unattributed_mutation") is True or surface.get("unattributed_mutation") is True:
        return "security-fault", "unattributed-mutation"
    if source.get("security_fault") is True or surface.get("security_fault") is True:
        return "security-fault", "operative-surface-security-fault"
    if source.get("contradictory_validation") is True or surface.get("contradictory_validation") is True:
        return "control-fault", "contradictory-validation"
    actual_model = _string(surface.get("model"))
    if actual_model and actual_model != primary_model:
        return "model-mismatch", "spark-exact-model-mismatch"
    if surface.get("exact_model_available") is False:
        return "model-mismatch", "spark-exact-model-capability-missing"
    if surface.get("workspace_enforced") is False or surface.get("mutation_enforced") is False:
        return "security-fault", "workspace-or-mutation-enforcement-missing"
    if not _surface_controls_valid(surface, routing_policy):
        return "control-fault", "required-native-lifecycle-control-missing"

    quota = _string(surface.get("quota_status"))
    capacity = _string(surface.get("capacity_status"))
    if quota == "exhausted":
        return "verified-quota-exhausted", "trusted-live-quota-exhaustion"
    if capacity == "unavailable":
        return "verified-capacity-unavailable", "trusted-live-capacity-unavailability"
    if (
        quota == "usable"
        and _string(surface.get("availability_basis"))
        == THREAD_ALLOCATION_ONLY_AVAILABILITY_BASIS
    ):
        return "unknown", "spark-thread-allocation-is-not-quota-evidence"
    if surface.get("exact_model_available") is True and quota == "usable" and capacity == "available":
        return "available", "trusted-live-spark-available"
    return "unknown", "spark-quota-or-capacity-ambiguous"


def _risk_allowed(risk: str, maximum: str) -> bool:
    if risk not in RISK_ORDER or maximum not in RISK_ORDER:
        return False
    return RISK_ORDER.index(risk) <= RISK_ORDER.index(maximum)


def _sensitivity_allowed(sensitivity: str, maximum: str) -> bool:
    if sensitivity not in DATA_SENSITIVITY_ORDER or maximum not in DATA_SENSITIVITY_ORDER:
        return False
    return DATA_SENSITIVITY_ORDER.index(sensitivity) <= DATA_SENSITIVITY_ORDER.index(maximum)


def _live_model_records(evidence: Mapping[str, Any]) -> list[dict[str, Any]]:
    records = evidence.get("operative_models")
    if records is None:
        records = evidence.get("fallbacks")
    if not isinstance(records, list):
        return []
    return [dict(item) for item in records if isinstance(item, Mapping)]


def _validated_work_estimate(work_estimate: Any) -> tuple[dict[str, Any], str]:
    if not isinstance(work_estimate, Mapping):
        raise ValueError("fallback routing requires a validated native work estimate")
    # Local import avoids a module-initialization cycle through native_release.
    from .work_sizing import canonical_work_estimate_sha256, validate_work_estimate

    source = deepcopy(dict(work_estimate))
    errors = validate_work_estimate(source)
    if errors:
        raise ValueError("invalid native work estimate: " + "; ".join(errors))
    if source.get("estimate_contract_version") != 2:
        raise ValueError("fallback routing requires native work estimate contract version 2")
    return source, canonical_work_estimate_sha256(source)


def _validate_context(context: Any) -> dict[str, Any]:
    source = _mapping(context)
    if set(source) != FIT_CONTEXT_FIELDS:
        raise ValueError("fallback fit context must contain only bead_id, wave_id, fresh_segment, and work_lineage_id")
    if not _string(source.get("bead_id")) or not _string(source.get("work_lineage_id")):
        raise ValueError("fallback fit context requires bead_id and work_lineage_id")
    if source.get("wave_id") is not None and not _string(source.get("wave_id")):
        raise ValueError("fallback fit context wave_id must be null or a non-empty string")
    if source.get("fresh_segment") is not True:
        raise ValueError("fallback fit evidence requires a fresh segment")
    return deepcopy(source)


def _validate_cache_profile(cache_profile: Any, context: Mapping[str, Any]) -> dict[str, Any]:
    source = _mapping(cache_profile)
    if set(source) != CACHE_PROFILE_FIELDS:
        raise ValueError("fallback cache profile has missing or unknown fields")
    if type(source.get("source")) is not str or source["source"] not in {
        "deterministic-context-plan",
        "trusted-session-telemetry",
    }:
        raise ValueError("fallback cache profile source is invalid")
    _parse_time(source.get("observed_at"), "cache_profile.observed_at")
    for field in (
        "total_context_tokens_p90",
        "stable_context_tokens_p90",
        "expected_reuse_opportunities",
        "repeatable_unit_count",
        "observed_input_tokens",
        "observed_cached_input_tokens",
    ):
        source[field] = _nonnegative_int(source.get(field), f"cache_profile.{field}")
    if source["stable_context_tokens_p90"] > source["total_context_tokens_p90"]:
        raise ValueError("cache_profile stable context cannot exceed total context")
    if source["observed_cached_input_tokens"] > source["observed_input_tokens"]:
        raise ValueError("cache_profile cached input cannot exceed observed input")
    if not isinstance(source.get("same_work_lineage"), bool):
        raise ValueError("cache_profile.same_work_lineage must be boolean")
    for field in ("repeat_template_sha256", "context_plan_sha256"):
        source[field] = _sha256(source.get(field), f"cache_profile.{field}", nullable=True)
    source["evidence_sha256"] = _sha256(source.get("evidence_sha256"), "cache_profile.evidence_sha256")
    telemetry_lineage = source.get("telemetry_lineage_id")
    if telemetry_lineage is not None and not _string(telemetry_lineage):
        raise ValueError("cache_profile.telemetry_lineage_id must be null or a non-empty string")
    if source["source"] == "deterministic-context-plan":
        if source["context_plan_sha256"] is None:
            raise ValueError("predicted cache evidence requires context_plan_sha256")
        if telemetry_lineage is not None or source["same_work_lineage"] is not False:
            raise ValueError("predicted cache evidence must not claim session telemetry lineage")
    else:
        if not _string(telemetry_lineage):
            raise ValueError("observed cache evidence requires telemetry_lineage_id")
        matches = telemetry_lineage == context.get("work_lineage_id")
        if source["same_work_lineage"] is not matches:
            raise ValueError("cache_profile.same_work_lineage contradicts telemetry lineage")
        if source["context_plan_sha256"] is not None:
            raise ValueError("observed cache evidence must not claim context-plan provenance")
    return deepcopy(source)


def _classify_fit(
    work_estimate: Mapping[str, Any],
    cache_profile: Mapping[str, Any],
    policy: Mapping[str, Any],
    evaluated_at: str,
) -> dict[str, Any]:
    rules = _mapping(policy.get("fitness_rules"))
    substantial_rule = _mapping(rules.get("substantial"))
    cache_rule = _mapping(rules.get("cache_heavy"))
    luna_rule = _mapping(rules.get("luna_fit"))
    estimates = _mapping(work_estimate.get("estimates"))
    semantic = _mapping(work_estimate.get("semantic_estimate"))
    unresolved = work_estimate.get("unresolved_decisions")
    write_paths = work_estimate.get("write_paths")
    unresolved_empty = isinstance(unresolved, list) and not unresolved
    write_count = len(write_paths) if isinstance(write_paths, list) else 0

    substantial_signals = [
        int(estimates.get("context_tokens_p90", 0)) >= int(substantial_rule.get("context_tokens_p90_min", 32000)),
        int(estimates.get("tool_calls_p90", 0)) >= int(substantial_rule.get("tool_calls_p90_min", 12)),
        int(estimates.get("runtime_seconds_p90", 0)) >= int(substantial_rule.get("runtime_seconds_p90_min", 300)),
        int(semantic.get("estimated_diff_p90", 0)) >= int(substantial_rule.get("estimated_diff_p90_min", 81)),
        write_count >= int(substantial_rule.get("write_paths_min", 3)),
        int(semantic.get("behavioral_changes", 0)) >= int(substantial_rule.get("behavioral_changes_min", 3)),
    ]
    substantial = (
        work_estimate.get("task_class") == substantial_rule.get("required_task_class")
        and unresolved_empty
        and sum(substantial_signals) >= int(substantial_rule.get("minimum_signals", 2))
    )

    cache_fresh = _fresh(cache_profile.get("observed_at"), evaluated_at, policy)
    predicted = _mapping(cache_rule.get("predicted"))
    observed = _mapping(cache_rule.get("observed"))
    total_context = int(cache_profile.get("total_context_tokens_p90", 0))
    stable_context = int(cache_profile.get("stable_context_tokens_p90", 0))
    predicted_fraction = (stable_context / total_context) if total_context > 0 else 0.0
    predicted_cache_heavy = (
        cache_fresh
        and cache_profile.get("source") == predicted.get("required_source")
        and cache_profile.get("context_plan_sha256") is not None
        and stable_context >= int(predicted.get("stable_context_tokens_p90_min", 16000))
        and predicted_fraction >= float(predicted.get("stable_context_fraction_min", 0.5))
        and int(cache_profile.get("expected_reuse_opportunities", 0))
        >= int(predicted.get("expected_reuse_opportunities_min", 2))
    )
    input_tokens = int(cache_profile.get("observed_input_tokens", 0))
    cached_tokens = int(cache_profile.get("observed_cached_input_tokens", 0))
    observed_fraction = (cached_tokens / input_tokens) if input_tokens > 0 else 0.0
    observed_cache_heavy = (
        cache_fresh
        and cache_profile.get("source") == observed.get("required_source")
        and cache_profile.get("same_work_lineage") is True
        and input_tokens > 0
        and cached_tokens >= int(observed.get("observed_cached_input_tokens_min", 16000))
        and observed_fraction >= float(observed.get("cached_input_fraction_min", 0.5))
    )
    cache_heavy = predicted_cache_heavy or observed_cache_heavy

    narrow_rule = _mapping(luna_rule.get("narrow"))
    repeat_rule = _mapping(luna_rule.get("repeatable_high_volume"))
    narrow = (
        int(semantic.get("estimated_diff_p90", 0)) <= int(narrow_rule.get("estimated_diff_p90_max", 80))
        and write_count <= int(narrow_rule.get("write_paths_max", 2))
        and int(semantic.get("behavioral_changes", 0)) <= int(narrow_rule.get("behavioral_changes_max", 2))
        and int(estimates.get("tool_calls_p90", 0)) <= int(narrow_rule.get("tool_calls_p90_max", 12))
    )
    repeatable_high_volume = (
        int(cache_profile.get("repeatable_unit_count", 0)) >= int(repeat_rule.get("repeatable_unit_count_min", 10))
        and cache_profile.get("repeat_template_sha256") is not None
        and unresolved_empty
    )
    deterministic = (
        work_estimate.get("fit_mode") == luna_rule.get("required_fit_mode")
        and unresolved_empty
        and int(semantic.get("command_complexity", 99)) <= int(luna_rule.get("command_complexity_max", 1))
        and int(semantic.get("test_construction_complexity", 99)) <= int(luna_rule.get("test_construction_complexity_max", 1))
    )
    return {
        "substantial": substantial,
        "substantial_signal_count": sum(substantial_signals),
        "cache_heavy": cache_heavy,
        "cache_evidence_fresh": cache_fresh,
        "cache_path": "predicted" if predicted_cache_heavy else "observed" if observed_cache_heavy else "none",
        "deterministic": deterministic,
        "narrow": narrow,
        "repeatable_high_volume": repeatable_high_volume,
        "luna_fit": deterministic and (narrow or repeatable_high_volume),
        "work_route_eligible": (
            work_estimate.get("route") == "spark"
            and work_estimate.get("operative_route", "spark") == "spark"
            and work_estimate.get("authority_route", "spark") == "spark"
            and unresolved_empty
        ),
    }


def _model_record(evidence: Mapping[str, Any], executor: str, model: str) -> dict[str, Any]:
    for record in _live_model_records(evidence):
        if _string(record.get("executor")) == executor and _string(record.get("model")) == model:
            return record
    return {}


def _domain_independent(
    model_record: Mapping[str, Any],
    evidence: Mapping[str, Any],
    policy: Mapping[str, Any],
) -> bool:
    quota_domain = _string(model_record.get("quota_domain"))
    metering_domain = _string(model_record.get("cached_input_metering_domain"))
    if not quota_domain or not metering_domain or "unknown" in {quota_domain.lower(), metering_domain.lower()}:
        return False
    strategy = _mapping(policy.get("gpt55_strategy"))
    relevant_models = set(_string_list(strategy.get("distinct_from_models")))
    relevant: list[dict[str, Any]] = []
    spark = _mapping(evidence.get("spark"))
    if _string(spark.get("model")) in relevant_models:
        relevant.append(spark)
    relevant.extend(
        item
        for item in _live_model_records(evidence)
        if _string(item.get("model")) in relevant_models and _string(item.get("model")) != GPT55_MODEL
    )
    if not relevant:
        return False
    for other in relevant:
        other_quota = _string(other.get("quota_domain"))
        other_metering = _string(other.get("cached_input_metering_domain"))
        if not other_quota or not other_metering:
            return False
        if quota_domain == other_quota and metering_domain == other_metering:
            return False
    return True


def _aggregate_budget_covers(work_estimate: Mapping[str, Any], budget: Mapping[str, Any]) -> bool:
    estimates = _mapping(work_estimate.get("estimates"))
    tool_hard = budget.get("tool_calls_hard")
    runtime_hard = budget.get("runtime_seconds_hard")
    return (
        isinstance(tool_hard, int)
        and not isinstance(tool_hard, bool)
        and isinstance(runtime_hard, int)
        and not isinstance(runtime_hard, bool)
        and tool_hard >= int(estimates.get("tool_calls_p90", 0))
        and runtime_hard >= int(estimates.get("runtime_seconds_p90", 0))
        and budget.get("budget_reset_allowed", False) is False
    )


def _candidate_fit(
    *,
    executor_key: str,
    executor: Mapping[str, Any],
    model: str,
    base_rank: int,
    evidence: Mapping[str, Any],
    work_estimate: Mapping[str, Any],
    cache_profile: Mapping[str, Any],
    classifications: Mapping[str, Any],
    aggregate_budget: Mapping[str, Any],
    policy: Mapping[str, Any],
    evaluated_at: str,
    risk_level: str,
    data_sensitivity: str,
) -> dict[str, Any]:
    record = _model_record(evidence, executor_key, model)
    exclusions: list[str] = []
    inclusions: list[str] = []
    trusted_sources = set(_string_list(policy.get("trusted_evidence_sources")))
    record_source = _string(record.get("source")) or _string(evidence.get("source"))
    record_fresh = bool(record) and _fresh(record.get("observed_at"), evaluated_at, policy)
    exact_model = bool(record) and record.get("exact_model_available") is True and _string(record.get("model")) == model
    live_available = (
        bool(record)
        and record.get("available") is True
        and _string(record.get("quota_status")) == "usable"
        and _string(record.get("capacity_status")) == "available"
    )
    controls_valid = bool(record) and _surface_controls_valid(record, policy)
    risk_allowed = _risk_allowed(risk_level, _string(executor.get("max_risk")))
    sensitivity_allowed = _sensitivity_allowed(data_sensitivity, _string(executor.get("max_data_sensitivity")))

    if not record:
        exclusions.append("trusted-live-model-evidence-missing")
    if record and record_source not in trusted_sources:
        exclusions.append("model-evidence-source-untrusted")
    if record and not record_fresh:
        exclusions.append("model-evidence-stale")
    if record and not exact_model:
        exclusions.append("exact-model-evidence-mismatch")
    if record and record.get("available") is not True:
        exclusions.append("model-not-live-available")
    if record and _string(record.get("quota_status")) != "usable":
        exclusions.append("model-quota-not-usable")
    if record and _string(record.get("capacity_status")) != "available":
        exclusions.append("model-capacity-not-available")
    if record and not controls_valid:
        exclusions.append("required-operative-controls-missing")
    if executor.get("model_role") != "operative-worker" or executor.get("external") is not False:
        exclusions.append("executor-not-internal-operative-worker")
    if executor.get("supports_repo_read") is not True or executor.get("supports_repo_write") is not True or executor.get("supports_shell") is not True:
        exclusions.append("executor-operative-io-capability-missing")
    if executor.get("explicit_opt_in_required") is not True or executor.get("fallback_only") is not True:
        exclusions.append("executor-fallback-opt-in-policy-missing")
    if not risk_allowed:
        exclusions.append("executor-risk-limit-exceeded")
    if not sensitivity_allowed:
        exclusions.append("executor-data-sensitivity-limit-exceeded")
    if classifications.get("work_route_eligible") is not True:
        exclusions.append("work-estimate-not-operative-route")

    task_fit = "compatible"
    cache_strategy_valid = False
    domain_independent = False
    headroom_sufficient = True
    aggregate_budget_sufficient = True
    warning: str | None = None
    acknowledgement_required = False
    if model == GPT55_MODEL:
        task_fit = "strategic" if classifications.get("substantial") is True else "ineligible"
        cache_strategy_valid = classifications.get("cache_heavy") is True
        domain_independent = _domain_independent(record, evidence, policy) if record else False
        remaining = record.get("remaining_input_tokens") if record else None
        required = int(_mapping(work_estimate.get("estimates")).get("context_tokens_p90", 0))
        headroom_sufficient = isinstance(remaining, int) and not isinstance(remaining, bool) and remaining >= required
        aggregate_budget_sufficient = _aggregate_budget_covers(work_estimate, aggregate_budget)
        if classifications.get("substantial") is not True:
            exclusions.append("gpt55-requires-substantial-work")
        if classifications.get("cache_heavy") is not True:
            exclusions.append("gpt55-requires-cache-heavy-work")
            if classifications.get("cache_evidence_fresh") is not True:
                exclusions.append("cache-evidence-stale")
            if cache_profile.get("source") == "trusted-session-telemetry" and cache_profile.get("same_work_lineage") is not True:
                exclusions.append("cross-lineage-cache-telemetry-rejected")
        if not domain_independent:
            exclusions.append("gpt55-quota-or-metering-domain-independence-unproved")
        if not headroom_sufficient:
            exclusions.append("gpt55-model-headroom-insufficient")
        if not aggregate_budget_sufficient:
            exclusions.append("gpt55-aggregate-budget-insufficient")
    elif model == TERRA_MODEL:
        task_fit = "compatible" if classifications.get("luna_fit") is True else "preferred"
    elif model == LUNA_MODEL:
        if classifications.get("luna_fit") is True:
            task_fit = "preferred"
        else:
            task_fit = "degraded"
            degraded = _mapping(policy.get("degraded_luna"))
            warning = _string(degraded.get("warning")) or "Luna task fit is degraded for this work."
            acknowledgement_required = True

    eligible = not exclusions
    if eligible:
        inclusions.extend(["trusted-live-exact-model", "operative-controls-valid", "executor-risk-and-sensitivity-eligible"])
        if model == GPT55_MODEL:
            inclusions.extend(["substantial-cache-heavy-work", "quota-or-metering-domain-independent", "headroom-and-aggregate-budget-sufficient"])
        elif model == TERRA_MODEL:
            inclusions.append("terra-fit-for-non-luna-work" if task_fit == "preferred" else "terra-compatible-with-luna-fit-work")
        else:
            inclusions.append("luna-fit-work" if task_fit == "preferred" else "luna-retained-as-final-degraded-fallback")
    return {
        "executor": executor_key,
        "model": model,
        "display_name": _string(executor.get("display_name")) or executor_key,
        "policy_rank": base_rank,
        "rank": base_rank,
        "task_fit": task_fit,
        "cache_strategy_valid": cache_strategy_valid,
        "quota_domain": _string(record.get("quota_domain")) or None,
        "cached_input_metering_domain": _string(record.get("cached_input_metering_domain")) or None,
        "domain_independent": domain_independent,
        "live_available": live_available,
        "evidence_fresh": record_fresh,
        "exact_model": exact_model,
        "control_eligible": controls_valid,
        "risk_eligible": risk_allowed,
        "data_sensitivity_eligible": sensitivity_allowed,
        "headroom_sufficient": headroom_sufficient,
        "aggregate_budget_sufficient": aggregate_budget_sufficient,
        "eligible": eligible,
        "model_evidence_sha256": _canonical_sha256(record),
        "inclusion_reasons": inclusions,
        "exclusion_reasons": list(dict.fromkeys(exclusions)),
        "task_fit_warning": warning,
        "acknowledgement_required": acknowledgement_required,
    }


def build_operative_fallback_fit(
    *,
    work_estimate: Mapping[str, Any],
    cache_profile: Mapping[str, Any],
    capability_evidence: Mapping[str, Any],
    context: Mapping[str, Any],
    aggregate_budget: Mapping[str, Any],
    execution_environment: str = "connected-codex",
    risk_level: str = "medium",
    data_sensitivity: str = "internal",
    evaluated_at: str | None = None,
) -> dict[str, Any]:
    _, policy, registry, environments = _policy_bundle()
    if policy.get("version") != 2:
        raise ValueError("operative routing policy version 2 is required")
    estimate, estimate_sha = _validated_work_estimate(work_estimate)
    fit_context = _validate_context(context)
    cache = _validate_cache_profile(cache_profile, fit_context)
    evidence = _mapping(capability_evidence)
    budget = _mapping(aggregate_budget)
    evaluated = evaluated_at or _now_iso()
    _parse_time(evaluated, "evaluated_at")
    policy_sha = operative_policy_sha256(execution_environment)
    classifications = _classify_fit(estimate, cache, policy, evaluated)
    _, _, approved_executors = _environment_contract(execution_environment, environments)
    ordered_models = _string_list(policy.get("ordered_recommendation"))
    executor_by_model = {_string(_mapping(registry.get(key)).get("model_label")): key for key in approved_executors}
    candidates: list[dict[str, Any]] = []
    for base_rank, model in enumerate(ordered_models, start=1):
        executor_key = executor_by_model.get(model, "")
        candidate = _candidate_fit(
            executor_key=executor_key,
            executor=_mapping(registry.get(executor_key)),
            model=model,
            base_rank=base_rank,
            evidence=evidence,
            work_estimate=estimate,
            cache_profile=cache,
            classifications=classifications,
            aggregate_budget=budget,
            policy=policy,
            evaluated_at=evaluated,
            risk_level=risk_level,
            data_sensitivity=data_sensitivity,
        )
        candidates.append(candidate)

    gpt55 = next((item for item in candidates if item["model"] == GPT55_MODEL), None)
    if gpt55 and gpt55["eligible"]:
        recommendation_order = [GPT55_MODEL, TERRA_MODEL, LUNA_MODEL]
    elif classifications["luna_fit"]:
        recommendation_order = [LUNA_MODEL, TERRA_MODEL, GPT55_MODEL]
    else:
        recommendation_order = [TERRA_MODEL, LUNA_MODEL, GPT55_MODEL]
    order_index = {model: index for index, model in enumerate(recommendation_order, start=1)}
    candidates.sort(key=lambda item: (order_index.get(item["model"], 99), item["policy_rank"]))
    for rank, candidate in enumerate(candidates, start=1):
        candidate["rank"] = rank

    fit: dict[str, Any] = {
        "fit_type": "cwo-operative-fallback-fit",
        "version": 1,
        "evaluated_at": evaluated,
        "work_estimate_sha256": estimate_sha,
        "policy_version": int(policy["version"]),
        "policy_sha256": policy_sha,
        "capability_evidence_sha256": _canonical_sha256(evidence),
        "aggregate_budget_sha256": _canonical_sha256(budget),
        "context": fit_context,
        "cache_profile": cache,
        "classifications": classifications,
        "candidates": candidates,
    }
    fit["fit_sha256"] = _canonical_sha256(fit)
    return fit


def validate_operative_fallback_fit(
    fallback_fit: Any,
    *,
    work_estimate: Mapping[str, Any],
    capability_evidence: Mapping[str, Any],
    context: Mapping[str, Any],
    aggregate_budget: Mapping[str, Any],
    execution_environment: str = "connected-codex",
    risk_level: str = "medium",
    data_sensitivity: str = "internal",
) -> list[str]:
    if not isinstance(fallback_fit, Mapping):
        return ["fallback fitness evidence is missing"]
    source = deepcopy(dict(fallback_fit))
    if set(source) != FIT_FIELDS:
        missing = sorted(FIT_FIELDS - set(source))
        extras = sorted(set(source) - FIT_FIELDS)
        return [f"fallback fitness evidence fields are invalid; missing={missing}; unknown={extras}"]
    try:
        expected = build_operative_fallback_fit(
            work_estimate=work_estimate,
            cache_profile=_mapping(source.get("cache_profile")),
            capability_evidence=capability_evidence,
            context=context,
            aggregate_budget=aggregate_budget,
            execution_environment=execution_environment,
            risk_level=risk_level,
            data_sensitivity=data_sensitivity,
            evaluated_at=_string(source.get("evaluated_at")),
        )
    except (TypeError, ValueError) as exc:
        return [str(exc)]
    if _canonical_sha256(source) != _canonical_sha256(expected):
        return ["fallback fitness evidence does not match deterministic evaluation"]
    return []


def _classify_task_selected_fit(
    work_estimate: Mapping[str, Any],
    cache_profile: Mapping[str, Any],
    policy: Mapping[str, Any],
    task_policy: Mapping[str, Any],
    evaluated_at: str,
) -> dict[str, Any]:
    """Extend only v3 fit; a semantic diagnosis never becomes deterministic."""
    from .work_sizing import is_read_only_work_estimate

    result = _classify_fit(work_estimate, cache_profile, policy, evaluated_at)
    rule = task_policy["bounded_semantic_readonly"]
    semantic = _mapping(work_estimate.get("semantic_estimate"))
    estimates = _mapping(work_estimate.get("estimates"))
    limits = {
        "expected_context_reads": "max_context_reads",
        "command_complexity": "command_complexity_max",
        "test_construction_complexity": "test_construction_complexity_max",
        "self_hosting_risk": "self_hosting_risk_max",
        "live_control_risk": "live_control_risk_max",
    }
    readonly = (
        rule["enabled"] is True
        and work_estimate.get("task_class") == rule["task_class"]
        and work_estimate.get("fit_mode") == rule["required_fit_mode"]
        and result["work_route_eligible"] is True
        and is_read_only_work_estimate(work_estimate)
        and all(type(semantic.get(field)) is int and semantic[field] == 0 for field in (
            "expected_mutations", "estimated_diff_p50", "estimated_diff_p90",
            "behavioral_changes", "state_machine_changes", "schema_changes",
        ))
        and all(type(semantic.get(field)) is int and 0 <= semantic[field] <= rule[bound]
                for field, bound in limits.items())
        and all(type(estimates.get(field)) is int and 0 <= estimates[field] <= rule[bound]
                for field, bound in (
                    ("tool_calls_p90", "max_tool_calls_p90"),
                    ("runtime_seconds_p90", "max_runtime_seconds_p90"),
                ))
    )
    result["bounded_semantic_readonly"] = readonly
    result["luna_fit"] = result["luna_fit"] or readonly
    return result


def _maintenance_context_headroom_sufficient(
    record: Mapping[str, Any], *, model: str, required_input: int,
    record_source: str, policy: Mapping[str, Any], evaluated_at: str,
) -> bool:
    """Validate source-bound fresh-context capacity, never account token quota.

    These are inert observations. The trusted release producer must bind the
    observed source and actual selected-model qualification to owner authority.
    """
    if "remaining_input_tokens" in record:
        return False  # No competing legacy quota/context interpretation.
    headroom = record.get("context_headroom")
    source = record.get("context_window_source")
    if (not isinstance(headroom, Mapping) or set(headroom) != {
            "basis", "context_window_tokens", "reserved_output_tokens", "source_sha256",
        } or not isinstance(source, Mapping) or set(source) != {
            "source", "observed_at", "model", "context_window_tokens",
        }):
        return False
    if (headroom.get("basis") != "fresh-segment-context-window"
            or type(headroom.get("context_window_tokens")) is not int
            or headroom["context_window_tokens"] < 1
            or type(headroom.get("reserved_output_tokens")) is not int
            or headroom["reserved_output_tokens"] < 1
            or type(source.get("context_window_tokens")) is not int
            or source["context_window_tokens"] != headroom["context_window_tokens"]):
        return False
    if any(type(source.get(field)) is not str or not source[field]
           or source[field] != source[field].strip()
           for field in ("source", "model", "observed_at")):
        return False
    return (
        source["model"] == model
        and source["source"] == record_source
        and source["source"] in _string_list(policy.get("trusted_evidence_sources"))
        and _fresh(source["observed_at"], evaluated_at, policy)
        and type(headroom.get("source_sha256")) is str
        and headroom["source_sha256"] == _canonical_sha256(dict(source))
        and required_input + headroom["reserved_output_tokens"] <= headroom["context_window_tokens"]
    )


def _task_selected_budget_covers(
    work_estimate: Mapping[str, Any], budget: Mapping[str, Any],
) -> bool:
    # The caller normalizes the closed v3 union first. Historical v2 still
    # calls _aggregate_budget_covers directly with its original finite shape.
    if budget.get("mode") == "maintenance-unbounded":
        reservation = budget["reservation"]
        return _aggregate_budget_covers(work_estimate, {
            "tool_calls_hard": reservation["tool_calls"],
            "runtime_seconds_hard": reservation["runtime_seconds"],
            "budget_reset_allowed": False,
        })
    return _aggregate_budget_covers(work_estimate, budget)


def _task_selected_candidate_fit(
    *,
    executor_key: str,
    executor: Mapping[str, Any],
    model: str,
    base_rank: int,
    evidence: Mapping[str, Any],
    work_estimate: Mapping[str, Any],
    classifications: Mapping[str, Any],
    aggregate_budget: Mapping[str, Any],
    policy: Mapping[str, Any],
    evaluated_at: str,
    risk_level: str,
    data_sensitivity: str,
) -> dict[str, Any]:
    """Build inert candidate evidence for the v3 Luna/Terra portfolio only."""
    record = _model_record(evidence, executor_key, model)
    exclusions: list[str] = []
    trusted_sources = set(_string_list(policy.get("trusted_evidence_sources")))
    record_source = _string(record.get("source")) or _string(evidence.get("source"))
    record_fresh = bool(record) and _fresh(record.get("observed_at"), evaluated_at, policy)
    exact_model = bool(record) and record.get("exact_model_available") is True and _string(record.get("model")) == model
    controls_valid = bool(record) and _surface_controls_valid(record, policy)
    risk_allowed = _risk_allowed(risk_level, _string(executor.get("max_risk")))
    sensitivity_allowed = _sensitivity_allowed(data_sensitivity, _string(executor.get("max_data_sensitivity")))
    required_headroom = int(_mapping(work_estimate.get("estimates")).get("context_tokens_p90", 0))
    maintenance = aggregate_budget.get("mode") == "maintenance-unbounded"
    if maintenance:
        headroom_sufficient = _maintenance_context_headroom_sufficient(
            record, model=model, required_input=required_headroom,
            record_source=record_source, policy=policy, evaluated_at=evaluated_at,
        )
    else:
        remaining = record.get("remaining_input_tokens") if record else None
        headroom_sufficient = (
            isinstance(remaining, int)
            and not isinstance(remaining, bool)
            and remaining >= required_headroom
            and "context_headroom" not in record
            and "context_window_source" not in record
        )
    aggregate_budget_sufficient = _task_selected_budget_covers(work_estimate, aggregate_budget)
    live_available = (
        bool(record)
        and record.get("available") is True
        and _string(record.get("quota_status")) == "usable"
        and _string(record.get("capacity_status")) == "available"
    )

    if not record:
        exclusions.append("trusted-live-model-evidence-missing")
    if record and record_source not in trusted_sources:
        exclusions.append("model-evidence-source-untrusted")
    if record and not record_fresh:
        exclusions.append("model-evidence-stale")
    if record and not exact_model:
        exclusions.append("exact-model-evidence-mismatch")
    if record and record.get("available") is not True:
        exclusions.append("model-not-live-available")
    if record and _string(record.get("quota_status")) != "usable":
        exclusions.append("model-quota-not-usable")
    if record and _string(record.get("capacity_status")) != "available":
        exclusions.append("model-capacity-not-available")
    if record and not controls_valid:
        exclusions.append("required-operative-controls-missing")
    if executor.get("model_role") != "operative-worker" or executor.get("external") is not False:
        exclusions.append("executor-not-internal-operative-worker")
    if executor.get("supports_repo_read") is not True or executor.get("supports_repo_write") is not True or executor.get("supports_shell") is not True:
        exclusions.append("executor-operative-io-capability-missing")
    if executor.get("explicit_opt_in_required") is not True or executor.get("fallback_only") is not True:
        exclusions.append("executor-fallback-opt-in-policy-missing")
    if not risk_allowed:
        exclusions.append("executor-risk-limit-exceeded")
    if not sensitivity_allowed:
        exclusions.append("executor-data-sensitivity-limit-exceeded")
    if classifications.get("work_route_eligible") is not True:
        exclusions.append("work-estimate-not-operative-route")
    if not headroom_sufficient:
        exclusions.append("model-headroom-insufficient")
    if not aggregate_budget_sufficient:
        exclusions.append("aggregate-budget-insufficient")
    if model == LUNA_MODEL and classifications.get("luna_fit") is not True:
        exclusions.append("luna-fit-required")

    eligible = not exclusions
    task_fit = "preferred" if model == LUNA_MODEL and classifications.get("luna_fit") is True else "compatible"
    if model == LUNA_MODEL and classifications.get("luna_fit") is not True:
        task_fit = "ineligible"
    inclusions = []
    if eligible:
        inclusions = [
            "trusted-live-exact-model",
            "operative-controls-valid",
            "executor-risk-and-sensitivity-eligible",
            "headroom-and-aggregate-budget-sufficient",
            "luna-fit-work" if model == LUNA_MODEL else "terra-escalation-portfolio-member",
        ]
        if maintenance:
            inclusions.append("fresh-context-window-covers-estimate")
        if model == LUNA_MODEL and classifications.get("bounded_semantic_readonly") is True:
            inclusions.append("bounded-semantic-readonly-fit")
    return {
        "executor": executor_key,
        "model": model,
        "display_name": _string(executor.get("display_name")) or executor_key,
        "policy_rank": base_rank,
        "rank": base_rank,
        "task_fit": task_fit,
        "cache_strategy_valid": False,
        "quota_domain": _string(record.get("quota_domain")) or None,
        "cached_input_metering_domain": _string(record.get("cached_input_metering_domain")) or None,
        "domain_independent": False,
        "live_available": live_available,
        "evidence_fresh": record_fresh,
        "exact_model": exact_model,
        "control_eligible": controls_valid,
        "risk_eligible": risk_allowed,
        "data_sensitivity_eligible": sensitivity_allowed,
        "headroom_sufficient": headroom_sufficient,
        "aggregate_budget_sufficient": aggregate_budget_sufficient,
        "eligible": eligible,
        "model_evidence_sha256": _canonical_sha256(record),
        "inclusion_reasons": inclusions,
        "exclusion_reasons": list(dict.fromkeys(exclusions)),
        "task_fit_warning": None,
        "acknowledgement_required": False,
    }


def build_task_selected_fit(
    *,
    work_estimate: Mapping[str, Any],
    cache_profile: Mapping[str, Any],
    capability_evidence: Mapping[str, Any],
    context: Mapping[str, Any],
    aggregate_budget: Mapping[str, Any],
    execution_environment: str = "connected-codex",
    risk_level: str = "medium",
    data_sensitivity: str = "internal",
    evaluated_at: str | None = None,
) -> dict[str, Any]:
    """Construct sealed, non-authorizing v3 task-selected fit evidence."""
    native, policy, registry, environments = _policy_bundle()
    task_policy, _ = _task_selected_policy(native)
    if policy.get("version") != 2:
        raise ValueError("operative routing policy version 2 is required")
    estimate, estimate_sha = _validated_work_estimate(work_estimate)
    if not isinstance(aggregate_budget, Mapping):
        raise ValueError("aggregate budget must be an object")
    fit_context = _validate_context(context)
    cache = _validate_cache_profile(cache_profile, fit_context)
    evidence = _mapping(capability_evidence)
    budget = _normalize_current_budget(aggregate_budget)
    evaluated = evaluated_at or _now_iso()
    _parse_time(evaluated, "evaluated_at")

    # Neutralization is deliberately limited to model selection.  Re-evaluating
    # catches any derived-field change instead of trusting a copied estimate.
    neutral_source = deepcopy(estimate)
    neutral_source["requested_model"] = "unselected"
    from .work_sizing import canonical_work_estimate_sha256, evaluate_work_estimate

    try:
        neutral = evaluate_work_estimate(neutral_source)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"invalid neutral work estimate: {exc}") from exc
    neutral_sha = canonical_work_estimate_sha256(neutral)
    policy_sha = task_selected_policy_sha256(execution_environment)
    classifications = _classify_task_selected_fit(estimate, cache, policy, task_policy, evaluated)
    _, _, approved_executors = _environment_contract(execution_environment, environments)
    executor_by_model = {
        _string(_mapping(registry.get(key)).get("model_label")): key
        for key in approved_executors
    }
    candidates = [
        _task_selected_candidate_fit(
            executor_key=executor_by_model.get(model, ""),
            executor=_mapping(registry.get(executor_by_model.get(model, ""))),
            model=model,
            base_rank=rank,
            evidence=evidence,
            work_estimate=estimate,
            classifications=classifications,
            aggregate_budget=budget,
            policy=policy,
            evaluated_at=evaluated,
            risk_level=risk_level,
            data_sensitivity=data_sensitivity,
        )
        for rank, model in enumerate(TASK_SELECTED_PORTFOLIO, start=1)
    ]
    fit: dict[str, Any] = {
        "fit_type": "cwo-task-selected-fit",
        "version": 3,
        "binding_rule_version": 1,
        "evaluated_at": evaluated,
        "work_estimate_sha256": estimate_sha,
        "neutral_work_estimate_sha256": neutral_sha,
        "policy_version": task_policy["version"],
        "policy_sha256": policy_sha,
        "capability_evidence_sha256": _canonical_sha256(evidence),
        "aggregate_budget_sha256": _canonical_sha256(budget),
        "context": fit_context,
        "cache_profile": cache,
        "classifications": classifications,
        "candidates": candidates,
    }
    fit["fit_sha256"] = _canonical_sha256(fit)
    return fit


def validate_task_selected_fit(
    task_selected_fit: Any,
    *,
    work_estimate: Mapping[str, Any],
    capability_evidence: Mapping[str, Any],
    context: Mapping[str, Any],
    aggregate_budget: Mapping[str, Any],
    execution_environment: str = "connected-codex",
    risk_level: str = "medium",
    data_sensitivity: str = "internal",
) -> list[str]:
    """Validate supplied inert fit evidence without granting route authority."""
    if not isinstance(task_selected_fit, Mapping):
        return ["task selected fit evidence is missing"]
    try:
        source = deepcopy(dict(task_selected_fit))
        if set(source) != TASK_SELECTED_FIT_FIELDS:
            missing = sorted(TASK_SELECTED_FIT_FIELDS - set(source))
            extras = sorted(set(source) - TASK_SELECTED_FIT_FIELDS)
            return [f"task selected fit evidence fields are invalid; missing={missing}; unknown={extras}"]
        if source.get("fit_type") != "cwo-task-selected-fit":
            return ["task selected fit evidence type is invalid"]
        if type(source.get("version")) is not int or source["version"] != 3:
            return ["task selected fit evidence version is invalid"]
        if type(source.get("binding_rule_version")) is not int or source["binding_rule_version"] != 1:
            return ["task selected fit evidence binding rule version is invalid"]
        _parse_time(source.get("evaluated_at"), "evaluated_at")
        for field in (
            "work_estimate_sha256",
            "neutral_work_estimate_sha256",
            "policy_sha256",
            "capability_evidence_sha256",
            "aggregate_budget_sha256",
            "fit_sha256",
        ):
            _sha256(source.get(field), field)
        if type(source.get("policy_version")) is not int or source["policy_version"] != 3:
            return ["task selected fit policy version is invalid"]
        expected = build_task_selected_fit(
            work_estimate=work_estimate,
            cache_profile=source.get("cache_profile"),
            capability_evidence=capability_evidence,
            context=context,
            aggregate_budget=aggregate_budget,
            execution_environment=execution_environment,
            risk_level=risk_level,
            data_sensitivity=data_sensitivity,
            evaluated_at=_string(source.get("evaluated_at")),
        )
        if _canonical_sha256(source) != _canonical_sha256(expected):
            return ["task selected fit evidence does not match deterministic evaluation"]
    except (TypeError, ValueError, OverflowError) as exc:
        return [str(exc)]
    return []


_TASK_SELECTED_ROUTE_FIELDS = {
    "route_type",
    "version",
    "execution_environment",
    "risk_level",
    "data_sensitivity",
    "evaluated_at",
    "selected_model",
    "selected_executor",
    "dispatch_authorized",
    "protected_stop",
    "stop_reason",
    "policy_active",
    "policy_sha256",
    "portfolio_version",
    "selector_version",
    "binding_rule_version",
    "work_estimate_sha256",
    "neutral_work_estimate_sha256",
    "fit_evidence",
    "fit_sha256",
    "capability_evidence_sha256",
    "qualification",
    "provenance",
    "attempt",
    "aggregate_budget",
    "budget_reset",
    "role",
    "reasoning_effort",
    "selection_reason",
    "candidate_exclusions",
    "route_sha256",
}


def _route_shape_error(errors: list[str], condition: bool, message: str) -> None:
    if not condition:
        errors.append(message)


def _route_shape_sha256(value: Any, field: str, errors: list[str], *, nullable: bool = False) -> None:
    try:
        _sha256(value, field, nullable=nullable)
    except (TypeError, ValueError):
        errors.append(f"{field} is invalid")


def _route_shape_time(value: Any, field: str, errors: list[str]) -> dt.datetime | None:
    try:
        return _parse_time(value, field)
    except (TypeError, ValueError):
        errors.append(f"{field} is invalid")
        return None


def _validate_task_selected_route_fit_shape(value: Any, errors: list[str]) -> None:
    if not isinstance(value, Mapping):
        errors.append("fit_evidence must be an object")
        return
    fit = dict(value)
    if set(fit) != TASK_SELECTED_FIT_FIELDS:
        errors.append("fit_evidence fields are invalid")
        return
    _route_shape_error(errors, fit.get("fit_type") == "cwo-task-selected-fit", "fit_evidence type is invalid")
    _route_shape_error(errors, type(fit.get("version")) is int and fit["version"] == 3, "fit_evidence version is invalid")
    _route_shape_error(errors, type(fit.get("binding_rule_version")) is int and fit["binding_rule_version"] == 1, "fit_evidence binding rule version is invalid")
    _route_shape_error(errors, type(fit.get("policy_version")) is int and fit["policy_version"] == 3, "fit_evidence policy version is invalid")
    _route_shape_time(fit.get("evaluated_at"), "fit_evidence evaluated_at", errors)
    for field in (
        "work_estimate_sha256",
        "neutral_work_estimate_sha256",
        "policy_sha256",
        "capability_evidence_sha256",
        "aggregate_budget_sha256",
        "fit_sha256",
    ):
        _route_shape_sha256(fit.get(field), f"fit_evidence {field}", errors)
    for field in ("context", "cache_profile", "classifications"):
        _route_shape_error(errors, isinstance(fit.get(field), Mapping), f"fit_evidence {field} must be an object")
    candidates = fit.get("candidates")
    _route_shape_error(errors, type(candidates) is list and bool(candidates), "fit_evidence candidates must be a non-empty array")
    candidate_fields = {
        "executor", "model", "display_name", "policy_rank", "rank", "task_fit",
        "cache_strategy_valid", "quota_domain", "cached_input_metering_domain",
        "domain_independent", "live_available", "evidence_fresh", "exact_model",
        "control_eligible", "risk_eligible", "data_sensitivity_eligible",
        "headroom_sufficient", "aggregate_budget_sufficient", "eligible",
        "model_evidence_sha256", "inclusion_reasons", "exclusion_reasons",
        "task_fit_warning", "acknowledgement_required",
    }
    if type(candidates) is list:
        for candidate in candidates:
            _route_shape_error(errors, isinstance(candidate, Mapping) and set(candidate) == candidate_fields, "fit_evidence candidate is invalid")


def validate_task_selected_route_shape(value: Any) -> list[str]:
    """Validate the closed v3 route representation without authorizing dispatch.

    This deliberately checks only serialized shape and internal consistency.
    Current qualification, policy activation, and live dispatch authority belong
    to the later selector and must not be inferred from this result.
    """
    if not isinstance(value, Mapping):
        return ["task selected route must be an object"]
    try:
        route = deepcopy(dict(value))
    except (TypeError, ValueError, OverflowError):
        return ["task selected route cannot be copied"]

    errors: list[str] = []
    if set(route) != _TASK_SELECTED_ROUTE_FIELDS:
        missing = sorted(_TASK_SELECTED_ROUTE_FIELDS - set(route))
        extras = sorted(set(route) - _TASK_SELECTED_ROUTE_FIELDS)
        return [f"task selected route fields are invalid; missing={missing}; unknown={extras}"]
    _route_shape_error(errors, route.get("route_type") == "cwo-operative-route", "route_type is invalid")
    _route_shape_error(errors, type(route.get("version")) is int and route["version"] == 3, "version is invalid")
    _route_shape_error(errors, isinstance(route.get("execution_environment"), str) and bool(route["execution_environment"].strip()), "execution_environment is invalid")
    _route_shape_error(errors, type(route.get("risk_level")) is str and route["risk_level"] in RISK_ORDER, "risk_level is invalid")
    _route_shape_error(errors, type(route.get("data_sensitivity")) is str and route["data_sensitivity"] in DATA_SENSITIVITY_ORDER, "data_sensitivity is invalid")
    _route_shape_time(route.get("evaluated_at"), "evaluated_at", errors)
    for field, expected in (("portfolio_version", 3), ("selector_version", 1), ("binding_rule_version", 1)):
        _route_shape_error(errors, type(route.get(field)) is int and route[field] == expected, f"{field} is invalid")
    for field in ("dispatch_authorized", "protected_stop", "policy_active"):
        _route_shape_error(errors, type(route.get(field)) is bool, f"{field} must be a boolean")
    _route_shape_error(errors, route.get("budget_reset") is False, "budget_reset must be false")
    _route_shape_sha256(route.get("policy_sha256"), "policy_sha256", errors)
    _route_shape_sha256(route.get("route_sha256"), "route_sha256", errors)
    for field in ("work_estimate_sha256", "neutral_work_estimate_sha256", "fit_sha256", "capability_evidence_sha256"):
        _route_shape_sha256(route.get(field), field, errors, nullable=True)
    for field in ("selected_executor", "stop_reason", "role", "reasoning_effort"):
        item = route.get(field)
        _route_shape_error(errors, item is None or (type(item) is str and bool(item.strip())), f"{field} is invalid")
    _route_shape_error(errors, type(route.get("selection_reason")) is str and bool(route["selection_reason"].strip()), "selection_reason is invalid")
    selected_model = route.get("selected_model")
    _route_shape_error(errors, selected_model is None or (type(selected_model) is str and selected_model in TASK_SELECTED_PORTFOLIO), "selected_model is invalid")

    qualification = route.get("qualification")
    qualification_times: tuple[dt.datetime | None, dt.datetime | None] = (None, None)
    if qualification is not None:
        if not isinstance(qualification, Mapping) or set(qualification) != {
            "model", "receipt_sha256", "canary_sha256", "origin_issued_at", "origin_expires_at",
            "tool_profile_sha256", "control_image_sha256", "host_provenance_sha256",
            "command_sha256", "execution_sha256", "runner_sha256",
        }:
            errors.append("qualification fields are invalid")
        else:
            qualification_times = (
                _route_shape_time(qualification.get("origin_issued_at"), "qualification origin_issued_at", errors),
                _route_shape_time(qualification.get("origin_expires_at"), "qualification origin_expires_at", errors),
            )
            _route_shape_error(errors, qualification.get("model") in TASK_SELECTED_PORTFOLIO and type(qualification.get("model")) is str, "qualification model is invalid")
            for field in set(qualification) - {"model", "origin_issued_at", "origin_expires_at"}:
                _route_shape_sha256(qualification.get(field), f"qualification {field}", errors)
    for group, fields in (
        ("provenance", {"source_sha256", "context_sha256", "scope_sha256", "candidate_sha256"}),
        ("attempt", {"attempt_id", "bead_id", "work_lineage_id", "ownership_sha256", "fresh_segment"}),
    ):
        item = route.get(group)
        if item is not None:
            if not isinstance(item, Mapping) or set(item) != fields:
                errors.append(f"{group} fields are invalid")
            elif group == "provenance":
                for field in fields:
                    _route_shape_sha256(item.get(field), f"{group} {field}", errors)
            else:
                for field in ("attempt_id", "bead_id", "work_lineage_id"):
                    _route_shape_error(errors, type(item.get(field)) is str and bool(item[field].strip()), f"attempt {field} is invalid")
                _route_shape_sha256(item.get("ownership_sha256"), "attempt ownership_sha256", errors)
                _route_shape_error(errors, type(item.get("fresh_segment")) is bool, "attempt fresh_segment must be a boolean")

    budget = route.get("aggregate_budget")
    if budget is None and route.get("dispatch_authorized") is False:
        pass  # A denied route may honestly lack any supplied budget.
    else:
        try:
            budget = _normalize_current_budget(budget)
        except (TypeError, ValueError, OverflowError):
            errors.append("aggregate_budget fields or values are invalid")
        else:
            if (budget.get("mode") != "maintenance-unbounded"
                    and route.get("dispatch_authorized") is True
                    and budget["allocation_before"] + budget["terminal_reserve"] >= budget["allocation_ceiling"]):
                errors.append("aggregate_budget leaves no protected terminal allocation")

    exclusions = route.get("candidate_exclusions")
    if type(exclusions) is not list:
        errors.append("candidate_exclusions must be an array")
    else:
        seen_models: set[str] = set()
        for item in exclusions:
            if not isinstance(item, Mapping) or set(item) != {"model", "exclusion_reasons"}:
                errors.append("candidate_exclusions item is invalid")
                continue
            model = item.get("model")
            if type(model) is not str or model not in TASK_SELECTED_PORTFOLIO or model in seen_models:
                errors.append("candidate_exclusions model is invalid")
            if type(model) is str:
                seen_models.add(model)
            reasons = item.get("exclusion_reasons")
            if type(reasons) is not list or not reasons or any(type(reason) is not str or not reason.strip() for reason in reasons):
                errors.append("candidate_exclusions reasons are invalid")

    fit = route.get("fit_evidence")
    if fit is not None:
        _validate_task_selected_route_fit_shape(fit, errors)
    issued, expires = qualification_times
    if issued is not None and expires is not None and expires <= issued:
        errors.append("qualification expiry must follow issuance")

    authorized = route.get("dispatch_authorized") is True
    blocked = route.get("dispatch_authorized") is False
    if authorized:
        _route_shape_error(errors, route.get("protected_stop") is False, "authorized route must not be protected_stop")
        _route_shape_error(errors, route.get("stop_reason") is None, "authorized route stop_reason must be null")
        _route_shape_error(errors, route.get("policy_active") is True, "authorized route policy must be active")
        aliases = {LUNA_MODEL: "internal_worker_luna", TERRA_MODEL: "internal_worker_terra"}
        model = route.get("selected_model")
        expected_executor = aliases.get(model) if type(model) is str else None
        expected_role = TASK_SELECTED_ROLES.get(model) if type(model) is str else None
        _route_shape_error(errors, expected_executor is not None, "authorized route model is invalid")
        _route_shape_error(errors, route.get("selected_executor") == expected_executor, "authorized route executor does not match model")
        _route_shape_error(errors, route.get("role") == expected_role, "authorized route role does not match model")
        _route_shape_error(errors, route.get("reasoning_effort") == "high", "authorized route reasoning_effort is invalid")
        for field in ("work_estimate_sha256", "neutral_work_estimate_sha256", "fit_evidence", "fit_sha256", "capability_evidence_sha256", "qualification", "provenance", "attempt"):
            _route_shape_error(errors, route.get(field) is not None, f"authorized route requires {field}")
        if isinstance(qualification, Mapping):
            _route_shape_error(errors, qualification.get("model") == route.get("selected_model"), "qualification model does not match selected_model")
        if isinstance(route.get("attempt"), Mapping):
            _route_shape_error(errors, route["attempt"].get("fresh_segment") is True, "authorized route requires a fresh attempt")
    elif blocked:
        _route_shape_error(errors, route.get("protected_stop") is True, "blocked route must be protected_stop")
        _route_shape_error(errors, type(route.get("stop_reason")) is str and bool(route["stop_reason"].strip()), "blocked route requires stop_reason")
        for field in ("selected_model", "selected_executor", "role", "reasoning_effort"):
            _route_shape_error(errors, route.get(field) is None, f"blocked route {field} must be null")
    else:
        errors.append("dispatch_authorized must be a boolean")

    if isinstance(route.get("route_sha256"), str):
        sealed = {key: item for key, item in route.items() if key != "route_sha256"}
        if route["route_sha256"] != _canonical_sha256(sealed):
            errors.append("route_sha256 does not match route contents")
    return errors


def fallback_options(candidates: list[dict[str, Any]]) -> list[dict[str, str]]:
    options = []
    for item in candidates:
        if item.get("eligible") is not True:
            continue
        description = "; ".join(_string_list(item.get("inclusion_reasons")))
        if item.get("task_fit_warning"):
            description = f"{description}. Warning: {item['task_fit_warning']}"
        options.append({
            "label": str(item["display_name"]) + (" (Recommended)" if not options else ""),
            "value": f"fallback:{item['executor']}:{item['model']}",
            "description": description,
        })
    options.append({
        "label": "Wait for Spark",
        "value": "wait-for-spark",
        "description": "Start no fallback session and re-evaluate trusted Spark availability at the next fresh segment.",
    })
    return options


def read_explicit_fallback_selection(value: Mapping[str, Any] | None) -> dict[str, Any]:
    """Read current or legacy explicit selection metadata without authorizing legacy dispatch."""

    source = _mapping(value)
    if not source:
        return {"present": False, "format": None, "dispatch_eligible": False, "migration_required": False}
    current = source.get("version") == 2 and source.get("selection_source") == "user-explicit-fallback"
    return {
        "present": True,
        "format": "operative-fallback-selection-v2" if current else "legacy-explicit-fallback",
        "dispatch_eligible": current,
        "migration_required": not current,
        "selected_model": _string(source.get("selected_model")) or None,
        "selected_executor": _string(source.get("selected_executor")) or None,
        "source": deepcopy(source),
    }


def _selection_active(selection: Mapping[str, Any], context: Mapping[str, Any]) -> tuple[bool, str]:
    scope = _string(selection.get("scope"))
    if scope not in FALLBACK_SCOPES:
        return False, "fallback-selection-scope-invalid"
    if scope == "current-bead":
        active = bool(_string(context.get("bead_id"))) and selection.get("bead_id") == context.get("bead_id")
    elif scope == "current-wave":
        active = bool(_string(context.get("wave_id"))) and selection.get("wave_id") == context.get("wave_id")
    else:
        active = True
    return (active, "" if active else "fallback-selection-scope-expired")


def _validate_selection(
    selection: Mapping[str, Any],
    *,
    candidates: list[dict[str, Any]],
    context: Mapping[str, Any],
    capability_evidence_sha256: str,
    work_estimate_sha256: str,
    fallback_fit_sha256: str,
    policy_sha256: str,
) -> tuple[dict[str, Any] | None, str]:
    if selection.get("choice") == "wait-for-spark":
        if set(selection) != {"choice"}:
            return None, "wait-selection-fields-invalid"
        return {"choice": "wait-for-spark"}, ""
    if selection.get("version") != 2 or selection.get("selection_source") != "user-explicit-fallback":
        return None, "fallback-selection-migration-required"
    required_strings = (
        "selected_model", "selected_executor", "reason", "scope", "selected_at", "actor",
        "capability_evidence_sha256", "work_estimate_sha256", "fallback_fit_sha256",
        "policy_sha256", "candidate_evidence_sha256",
    )
    if any(not _string(selection.get(field)) for field in required_strings):
        return None, "fallback-selection-provenance-incomplete"
    scope = _string(selection.get("scope"))
    expected_fields = set(required_strings) | {"version", "selection_source"}
    if scope == "current-bead":
        expected_fields.add("bead_id")
    elif scope == "current-wave":
        expected_fields.add("wave_id")
    if selection.get("degraded_task_fit_acknowledged") is not None:
        if not isinstance(selection.get("degraded_task_fit_acknowledged"), bool):
            return None, "fallback-selection-acknowledgement-invalid"
        expected_fields.add("degraded_task_fit_acknowledged")
    if selection.get("expires_when") is not None:
        expected_fields.add("expires_when")
    if set(selection) != expected_fields:
        return None, "fallback-selection-fields-invalid"
    try:
        _parse_time(selection.get("selected_at"), "fallback_selection.selected_at")
        for field in (
            "capability_evidence_sha256",
            "work_estimate_sha256",
            "fallback_fit_sha256",
            "policy_sha256",
            "candidate_evidence_sha256",
        ):
            _sha256(selection.get(field), f"fallback_selection.{field}")
    except ValueError:
        return None, "fallback-selection-provenance-invalid"
    active, reason = _selection_active(selection, context)
    if not active:
        return None, reason
    expected_hashes = {
        "capability_evidence_sha256": capability_evidence_sha256,
        "work_estimate_sha256": work_estimate_sha256,
        "fallback_fit_sha256": fallback_fit_sha256,
        "policy_sha256": policy_sha256,
    }
    for field, expected in expected_hashes.items():
        if selection.get(field) != expected:
            return None, f"fallback-selection-{field.replace('_sha256', '').replace('_', '-')}-mismatch"
    candidate = next((
        item for item in candidates
        if item.get("eligible") is True
        and item["model"] == selection.get("selected_model")
        and item["executor"] == selection.get("selected_executor")
    ), None)
    if candidate is None:
        return None, "selected-fallback-not-live-fit-and-approved"
    if selection.get("candidate_evidence_sha256") != candidate.get("model_evidence_sha256"):
        return None, "fallback-selection-candidate-evidence-mismatch"
    if candidate.get("acknowledgement_required") and selection.get("degraded_task_fit_acknowledged") is not True:
        return None, "degraded-luna-task-fit-not-acknowledged"
    normalized = deepcopy(dict(selection))
    expected_expiry = {
        "current-bead": f"bead:{selection.get('bead_id')}:complete",
        "current-wave": f"wave:{selection.get('wave_id')}:complete",
        "until-spark-restored": "trusted-spark-status=available-at-fresh-segment",
    }[scope]
    if normalized.get("expires_when") not in {None, expected_expiry}:
        return None, "fallback-selection-expiry-mismatch"
    normalized["expires_when"] = expected_expiry
    return normalized, ""


def _recommendation(candidates: list[dict[str, Any]]) -> tuple[str | None, str | None, str]:
    first = next((item for item in candidates if item.get("eligible") is True), None)
    if first is None:
        return None, None, "No live policy-eligible fallback is proven; wait for Spark."
    reasons = ", ".join(_string_list(first.get("inclusion_reasons")))
    return str(first["model"]), str(first["executor"]), reasons


_CURRENT_AUTHORITY_FIELDS = {
    "version", "fit_inputs", "provenance", "attempt", "attempt_state",
    "bound_model", "identity", "qualifications", "escalation",
}
_CURRENT_AUTHORITY_FIT_INPUT_FIELDS = {
    "work_estimate", "cache_profile", "capability_evidence", "context",
    "aggregate_budget",
}
_CURRENT_AUTHORITY_QUALIFICATION_FIELDS = {
    "model", "receipt_sha256", "canary_sha256", "origin_issued_at",
    "origin_expires_at", "tool_profile_sha256", "control_image_sha256",
    "host_provenance_sha256", "command_sha256", "execution_sha256",
    "runner_sha256",
}
_CURRENT_AUTHORITY_PROVENANCE_FIELDS = {
    "source_sha256", "context_sha256", "scope_sha256", "candidate_sha256",
}
_CURRENT_AUTHORITY_ATTEMPT_FIELDS = {
    "attempt_id", "bead_id", "work_lineage_id", "ownership_sha256", "fresh_segment",
}
_CURRENT_AUTHORITY_IDENTITY_FIELDS = {
    "tool_profile_sha256", "control_image_sha256", "host_provenance_sha256",
}
_CURRENT_AUTHORITY_ESCALATION_FIELDS = {
    "kind", "reason", "evidence_sha256", "fit_sha256", "attempt_id",
}
_CURRENT_AUTHORITY_BUDGET_FIELDS = {
    "tool_calls_hard", "runtime_seconds_hard", "allocation_before",
    "allocation_ceiling", "terminal_reserve", "budget_reset_allowed",
}
_MAINTENANCE_BUDGET_FIELDS = {
    "mode", "mission_id", "mission_sha256", "operation_id", "cumulative_before",
    "reservation", "budget_reset_allowed",
}
_MAINTENANCE_RESERVATION_FIELDS = {
    "mode", "sessions", "tool_calls", "runtime_seconds", "cleanup_seconds", "max_concurrency",
}
_UNSET = object()


def _exact_mapping(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise ValueError(f"{label} fields are invalid")
    return deepcopy(dict(value))


def _normalize_current_budget(value: Any) -> dict[str, Any]:
    """Parse a closed, value-preserving budget union; neither branch is authority."""
    if isinstance(value, Mapping) and value.get("mode") == "maintenance-unbounded":
        budget = _exact_mapping(value, _MAINTENANCE_BUDGET_FIELDS, "maintenance aggregate budget")
        for field in ("mission_id", "operation_id"):
            if (type(budget.get(field)) is not str or not budget[field]
                    or budget[field] != budget[field].strip()):
                raise ValueError(f"maintenance aggregate budget {field} is invalid")
        digest = _sha256(budget.get("mission_sha256"), "maintenance aggregate budget mission_sha256")
        if budget["mission_sha256"] != digest:
            raise ValueError("maintenance aggregate budget mission_sha256 is invalid")
        if type(budget.get("cumulative_before")) is not int or budget["cumulative_before"] < 0:
            raise ValueError("maintenance aggregate budget cumulative_before is invalid")
        reservation = _exact_mapping(
            budget.get("reservation"), _MAINTENANCE_RESERVATION_FIELDS, "maintenance reservation"
        )
        if reservation.get("mode") != "finite-operation":
            raise ValueError("maintenance reservation mode is invalid")
        for field in _MAINTENANCE_RESERVATION_FIELDS - {"mode"}:
            if type(reservation.get(field)) is not int or reservation[field] < 1:
                raise ValueError(f"maintenance reservation {field} is invalid")
        if reservation["max_concurrency"] > 3 or reservation["max_concurrency"] > reservation["sessions"]:
            raise ValueError("maintenance reservation concurrency is invalid")
        if budget.get("budget_reset_allowed") is not False:
            raise ValueError("aggregate budget budget_reset_allowed must be false")
        return budget
    budget = _exact_mapping(value, _CURRENT_AUTHORITY_BUDGET_FIELDS, "aggregate budget")
    for field in _CURRENT_AUTHORITY_BUDGET_FIELDS - {"budget_reset_allowed"}:
        minimum = 1 if field in {
            "tool_calls_hard", "runtime_seconds_hard", "allocation_ceiling",
        } else 0
        try:
            number = _nonnegative_int(budget.get(field), f"aggregate_budget.{field}")
        except ValueError as exc:
            raise ValueError("aggregate budget is invalid") from exc
        if number < minimum:
            raise ValueError("aggregate budget is invalid")
    if budget.get("budget_reset_allowed") is not False:
        raise ValueError("aggregate budget budget_reset_allowed must be false")
    return budget


def _normalize_current_authority(value: Any) -> dict[str, Any]:
    """Return a closed, value-preserving v1 current-authority binding.

    This parser deliberately does not make a dispatch decision.  It validates
    every nested type before any membership, time, or hash operation so a
    malformed controller claim cannot become usable authority by coercion.
    """
    source = _exact_mapping(value, _CURRENT_AUTHORITY_FIELDS, "current authority")
    if type(source.get("version")) is not int or source["version"] != 1:
        raise ValueError("current authority version is invalid")
    fit_inputs = _exact_mapping(
        source.get("fit_inputs"), _CURRENT_AUTHORITY_FIT_INPUT_FIELDS, "current authority fit_inputs"
    )
    for field in ("work_estimate", "cache_profile", "capability_evidence", "context"):
        if not isinstance(fit_inputs.get(field), Mapping):
            raise ValueError(f"current authority fit_inputs {field} must be an object")
    _normalize_current_budget(fit_inputs.get("aggregate_budget"))
    provenance = _exact_mapping(
        source.get("provenance"), _CURRENT_AUTHORITY_PROVENANCE_FIELDS, "current authority provenance"
    )
    for field in _CURRENT_AUTHORITY_PROVENANCE_FIELDS:
        _sha256(provenance.get(field), f"current authority provenance {field}")
    attempt = _exact_mapping(source.get("attempt"), _CURRENT_AUTHORITY_ATTEMPT_FIELDS, "current authority attempt")
    for field in ("attempt_id", "bead_id", "work_lineage_id"):
        if not _string(attempt.get(field)):
            raise ValueError(f"current authority attempt {field} is invalid")
    _sha256(attempt.get("ownership_sha256"), "current authority attempt ownership_sha256")
    if type(attempt.get("fresh_segment")) is not bool:
        raise ValueError("current authority attempt fresh_segment is invalid")
    if type(source.get("attempt_state")) is not str or source["attempt_state"] not in {"ready", "stopped"}:
        raise ValueError("current authority attempt_state is invalid")
    bound_model = source.get("bound_model")
    if bound_model is not None and (type(bound_model) is not str or bound_model not in TASK_SELECTED_PORTFOLIO):
        raise ValueError("current authority bound_model is invalid")
    identity = _exact_mapping(source.get("identity"), _CURRENT_AUTHORITY_IDENTITY_FIELDS, "current authority identity")
    for field in _CURRENT_AUTHORITY_IDENTITY_FIELDS:
        _sha256(identity.get(field), f"current authority identity {field}")
    qualifications = source.get("qualifications")
    if not isinstance(qualifications, Mapping) or set(qualifications) != set(TASK_SELECTED_PORTFOLIO):
        raise ValueError("current authority qualifications are invalid")
    for model in TASK_SELECTED_PORTFOLIO:
        # An unqualified portfolio alternative is recorded honestly as absent.
        # Selection still requires an exact, current qualification below.
        if qualifications.get(model) is None:
            continue
        qualification = _exact_mapping(
            qualifications.get(model), _CURRENT_AUTHORITY_QUALIFICATION_FIELDS,
            f"current authority qualification {model}",
        )
        if qualification.get("model") != model:
            raise ValueError("current authority qualification model is invalid")
        _parse_time(qualification.get("origin_issued_at"), "current authority qualification origin_issued_at")
        _parse_time(qualification.get("origin_expires_at"), "current authority qualification origin_expires_at")
        for field in _CURRENT_AUTHORITY_QUALIFICATION_FIELDS - {"model", "origin_issued_at", "origin_expires_at"}:
            _sha256(qualification.get(field), f"current authority qualification {field}")
    escalation = source.get("escalation")
    if escalation is not None:
        escalation = _exact_mapping(escalation, _CURRENT_AUTHORITY_ESCALATION_FIELDS, "current authority escalation")
        if type(escalation.get("kind")) is not str or escalation["kind"] not in {"fit", "qualification", "risk", "economics"}:
            raise ValueError("current authority escalation kind is invalid")
        if not _string(escalation.get("reason")) or escalation.get("attempt_id") != attempt["attempt_id"]:
            raise ValueError("current authority escalation is invalid")
        _sha256(escalation.get("evidence_sha256"), "current authority escalation evidence_sha256")
        _sha256(escalation.get("fit_sha256"), "current authority escalation fit_sha256")
    return source


def _blocked_task_selected_route(
    *,
    aggregate_budget: Mapping[str, Any] | None,
    evaluated_at: str,
    execution_environment: str,
    risk_level: str,
    data_sensitivity: str,
    policy_active: bool,
    stop_reason: str,
) -> dict[str, Any]:
    route = {
        "route_type": "cwo-operative-route",
        "version": 3,
        "execution_environment": execution_environment,
        "risk_level": risk_level,
        "data_sensitivity": data_sensitivity,
        "evaluated_at": evaluated_at,
        "selected_model": None,
        "selected_executor": None,
        "dispatch_authorized": False,
        "protected_stop": True,
        "stop_reason": stop_reason,
        "policy_active": policy_active,
        "policy_sha256": task_selected_policy_sha256(execution_environment),
        "portfolio_version": 3,
        "selector_version": 1,
        "binding_rule_version": 1,
        "work_estimate_sha256": None,
        "neutral_work_estimate_sha256": None,
        "fit_evidence": None,
        "fit_sha256": None,
        "capability_evidence_sha256": None,
        "qualification": None,
        "provenance": None,
        "attempt": None,
        "aggregate_budget": deepcopy(dict(aggregate_budget)) if aggregate_budget is not None else None,
        "budget_reset": False,
        "role": None,
        "reasoning_effort": None,
        "selection_reason": "C1 preserves current authority for later selection; it does not authorize dispatch.",
        "candidate_exclusions": [],
    }
    route["route_sha256"] = _canonical_sha256(route)
    return route


def _current_authority_inputs(
    authority: Mapping[str, Any],
    *,
    capability_evidence: Mapping[str, Any] | None,
    work_estimate: Mapping[str, Any] | None,
    context: Mapping[str, Any] | None,
    aggregate_budget: Mapping[str, Any] | None,
) -> tuple[dict[str, Any] | None, str | None]:
    """Reject independently supplied inputs that disagree with the authority."""
    inputs = _mapping(authority.get("fit_inputs"))
    supplied = {
        "capability_evidence": capability_evidence,
        "work_estimate": work_estimate,
        "context": context,
        "aggregate_budget": aggregate_budget,
    }
    for field, value in supplied.items():
        if value is not None and _canonical_sha256(value) != _canonical_sha256(inputs[field]):
            return None, f"current-authority-{field.replace('_', '-')}-mismatch"
    return deepcopy(inputs), None


def _selected_task_route(
    *,
    authority: Mapping[str, Any],
    inputs: Mapping[str, Any],
    task_policy: Mapping[str, Any],
    execution_environment: str,
    risk_level: str,
    data_sensitivity: str,
    evaluated_at: str,
) -> tuple[dict[str, Any] | None, str]:
    """Build a sealed v3 route only from one exact current-authority claim."""
    active = (
        task_policy.get("status") == "active"
        and _mapping(task_policy.get("activation")).get("active") is True
        and _mapping(task_policy.get("activation")).get("dispatch_authority") is True
    )
    if not active:
        return None, "task-selected-policy-inactive"
    attempt = _mapping(authority.get("attempt"))
    if authority.get("attempt_state") != "ready" or attempt.get("fresh_segment") is not True:
        return None, "current-authority-attempt-not-ready"
    model = authority.get("bound_model")
    if model not in TASK_SELECTED_PORTFOLIO:
        return None, "current-authority-bound-model-missing-or-invalid"
    fit = build_task_selected_fit(
        work_estimate=_mapping(inputs.get("work_estimate")),
        cache_profile=_mapping(inputs.get("cache_profile")),
        capability_evidence=_mapping(inputs.get("capability_evidence")),
        context=_mapping(inputs.get("context")),
        aggregate_budget=_mapping(inputs.get("aggregate_budget")),
        execution_environment=execution_environment,
        risk_level=risk_level,
        data_sensitivity=data_sensitivity,
        evaluated_at=evaluated_at,
    )
    candidate = next((item for item in fit["candidates"] if item.get("model") == model), None)
    if not isinstance(candidate, Mapping) or candidate.get("eligible") is not True:
        return None, "current-authority-bound-model-not-qualified"
    escalation = authority.get("escalation")
    if model == TERRA_MODEL:
        if not isinstance(escalation, Mapping) or escalation.get("kind") not in {"fit", "qualification", "risk", "economics"}:
            return None, "terra-selection-requires-recorded-escalation"
        if escalation.get("fit_sha256") != fit["fit_sha256"]:
            return None, "terra-escalation-fit-mismatch"
    qualification = _mapping(_mapping(authority.get("qualifications")).get(model))
    try:
        issued = _parse_time(qualification.get("origin_issued_at"), "qualification origin_issued_at")
        expires = _parse_time(qualification.get("origin_expires_at"), "qualification origin_expires_at")
        current = _parse_time(evaluated_at, "evaluated_at")
    except ValueError:
        return None, "current-authority-qualification-invalid"
    if qualification.get("model") != model or not issued <= current < expires:
        return None, "current-authority-qualification-not-current"
    identity = _mapping(authority.get("identity"))
    if any(
        qualification.get(field) != identity.get(field)
        for field in _CURRENT_AUTHORITY_IDENTITY_FIELDS
    ):
        return None, "current-authority-identity-mismatch"
    fit_context = _mapping(inputs.get("context"))
    if (
        attempt.get("bead_id") != fit_context.get("bead_id")
        or attempt.get("work_lineage_id") != fit_context.get("work_lineage_id")
    ):
        return None, "current-authority-attempt-context-mismatch"
    route = {
        "route_type": "cwo-operative-route",
        "version": 3,
        "execution_environment": execution_environment,
        "risk_level": risk_level,
        "data_sensitivity": data_sensitivity,
        "evaluated_at": evaluated_at,
        "selected_model": model,
        "selected_executor": candidate["executor"],
        "dispatch_authorized": True,
        "protected_stop": False,
        "stop_reason": None,
        "policy_active": True,
        "policy_sha256": fit["policy_sha256"],
        "portfolio_version": 3,
        "selector_version": 1,
        "binding_rule_version": 1,
        "work_estimate_sha256": fit["work_estimate_sha256"],
        "neutral_work_estimate_sha256": fit["neutral_work_estimate_sha256"],
        "fit_evidence": fit,
        "fit_sha256": fit["fit_sha256"],
        "capability_evidence_sha256": fit["capability_evidence_sha256"],
        "qualification": deepcopy(qualification),
        "provenance": deepcopy(_mapping(authority.get("provenance"))),
        "attempt": deepcopy(attempt),
        "aggregate_budget": deepcopy(_mapping(inputs.get("aggregate_budget"))),
        "budget_reset": False,
        "role": TASK_SELECTED_ROLES[model],
        "reasoning_effort": "high",
        "selection_reason": (
            "Qualified Luna-first current selection."
            if model == LUNA_MODEL else "Qualified Terra selection with recorded escalation."
        ),
        "candidate_exclusions": [
            {"model": item["model"], "exclusion_reasons": deepcopy(item["exclusion_reasons"])}
            for item in fit["candidates"] if item.get("eligible") is not True
        ],
    }
    route["route_sha256"] = _canonical_sha256(route)
    return route, ""


def resolve_operative_route(
    *,
    execution_environment: str = "connected-codex",
    risk_level: str = "medium",
    data_sensitivity: str = "internal",
    capability_evidence: Mapping[str, Any] | None = None,
    work_estimate: Mapping[str, Any] | None = None,
    fallback_fit: Mapping[str, Any] | None = None,
    fallback_selection: Mapping[str, Any] | None = None,
    context: Mapping[str, Any] | None = None,
    aggregate_budget: Mapping[str, Any] | None = None,
    previous_route: Mapping[str, Any] | None = None,
    evaluated_at: str | None = None,
    current_authority: Any = _UNSET,
) -> dict[str, Any]:
    # An activated v3 policy never falls back to historical dispatch merely
    # because a wrapper omitted its authority argument. Omission still differs
    # from explicit invalid values while historical/inactive records are read.
    if current_authority is _UNSET:
        native, _, _, _ = _policy_bundle()
        selected_policy = native.get("task_selected_routing", {})
        if isinstance(selected_policy, Mapping) and selected_policy.get("status") == "active":
            current_authority = None
    if current_authority is not _UNSET:
        evaluated = evaluated_at or _now_iso()
        _parse_time(evaluated, "evaluated_at")
        authority: dict[str, Any] | None = None
        authority_error = "current-authority-missing"
        if current_authority is not None:
            try:
                authority = _normalize_current_authority(current_authority)
            except (TypeError, ValueError, OverflowError):
                authority_error = "current-authority-invalid"
        supplied_budget = aggregate_budget
        if supplied_budget is None and authority is not None:
            supplied_budget = authority["fit_inputs"]["aggregate_budget"]
        budget = None
        try:
            budget = _normalize_current_budget(supplied_budget)
        except (TypeError, ValueError):
            # A denied authority needs no fabricated budget. In contrast an
            # otherwise valid authority cannot dispatch without a valid one.
            if authority is not None:
                authority_error = "current-authority-budget-invalid"
                authority = None
        native, _, _, _ = _policy_bundle()
        task_policy, _ = _task_selected_policy(native)
        if authority is not None:
            inputs, input_error = _current_authority_inputs(
                authority,
                capability_evidence=capability_evidence,
                work_estimate=work_estimate,
                context=context,
                aggregate_budget=aggregate_budget,
            )
            if inputs is not None:
                route, selection_error = _selected_task_route(
                    authority=authority,
                    inputs=inputs,
                    task_policy=task_policy,
                    execution_environment=execution_environment,
                    risk_level=risk_level,
                    data_sensitivity=data_sensitivity,
                    evaluated_at=evaluated,
                )
                if route is not None:
                    return route
                authority_error = selection_error
            else:
                authority_error = input_error or "current-authority-input-mismatch"
        return _blocked_task_selected_route(
            aggregate_budget=budget,
            evaluated_at=evaluated,
            execution_environment=execution_environment,
            risk_level=risk_level,
            data_sensitivity=data_sensitivity,
            policy_active=(
                task_policy["status"] == "active"
                and task_policy["activation"]["active"] is True
                and task_policy["activation"]["dispatch_authority"] is True
            ),
            stop_reason=(
                authority_error
            ),
        )
    _, routing_policy, _, environments = _policy_bundle()
    primary_model, primary_executor, _ = _environment_contract(execution_environment, environments)
    evidence = _mapping(capability_evidence)
    runtime_context = _mapping(context)
    fresh_segment = runtime_context.get("fresh_segment", True) is True
    budget = _mapping(aggregate_budget)
    evaluated = evaluated_at or _string(_mapping(fallback_fit).get("evaluated_at")) or _now_iso()
    _parse_time(evaluated, "evaluated_at")
    evidence_sha256 = _canonical_sha256(evidence)
    policy_sha256 = operative_policy_sha256(execution_environment)
    status, status_reason = classify_spark_availability(
        evidence,
        primary_model=primary_model,
        policy=routing_policy,
        evaluated_at=evaluated,
    )

    fit_errors: list[str] = []
    estimate_value: dict[str, Any] | None = None
    estimate_sha256: str | None = None
    fit_value: dict[str, Any] | None = None
    fit_sha256: str | None = None
    candidates: list[dict[str, Any]] = []
    if status in FALLBACK_TRIGGERS and fresh_segment:
        try:
            estimate_value, estimate_sha256 = _validated_work_estimate(work_estimate)
        except ValueError as exc:
            fit_errors.append(str(exc))
        if estimate_value is not None:
            fit_errors.extend(validate_operative_fallback_fit(
                fallback_fit,
                work_estimate=estimate_value,
                capability_evidence=evidence,
                context=runtime_context,
                aggregate_budget=budget,
                execution_environment=execution_environment,
                risk_level=risk_level,
                data_sensitivity=data_sensitivity,
            ))
        if not fit_errors:
            fit_value = deepcopy(dict(fallback_fit or {}))
            fit_sha256 = _string(fit_value.get("fit_sha256"))
            candidates = [deepcopy(dict(item)) for item in fit_value.get("candidates", []) if isinstance(item, Mapping)]

    recommended_model, recommended_executor, recommendation_reason = _recommendation(candidates)
    previous = _mapping(previous_route)
    previous_fallback = _mapping(previous.get("fallback"))
    previous_selection = _mapping(previous_fallback.get("selection"))
    explicit_selection = _mapping(fallback_selection)
    supplied_selection = explicit_selection or previous_selection
    selection: dict[str, Any] | None = None
    selection_error = ""
    if supplied_selection and not fit_errors and estimate_sha256 and fit_sha256:
        selection, selection_error = _validate_selection(
            supplied_selection,
            candidates=candidates,
            context=runtime_context,
            capability_evidence_sha256=evidence_sha256,
            work_estimate_sha256=estimate_sha256,
            fallback_fit_sha256=fit_sha256,
            policy_sha256=policy_sha256,
        )
    elif supplied_selection and fit_errors:
        selection_error = "fallback-selection-cannot-authorize-invalid-fit-evidence"

    selected_model: str | None = None
    selected_executor: str | None = None
    selection_source: str | None = None
    dispatch_authorized = False
    protected_stop = False
    decision_required = False
    stop_reason: str | None = None
    expired_selection: dict[str, Any] | None = None

    if not fresh_segment:
        if previous.get("route_type") != "cwo-operative-route" or previous.get("version") != 2:
            protected_stop = True
            stop_reason = "in-progress-segment-current-route-metadata-missing"
        else:
            in_progress_model = _string(runtime_context.get("current_model")) or _string(previous.get("selected_model"))
            in_progress_executor = _string(runtime_context.get("current_executor")) or _string(previous.get("selected_executor"))
            if in_progress_model and in_progress_model == previous.get("selected_model"):
                selected_model = in_progress_model
                selected_executor = in_progress_executor or None
                selection_source = "in-progress-segment"
                dispatch_authorized = bool(previous.get("dispatch_authorized"))
                stop_reason = None if dispatch_authorized else "in-progress-segment-not-authorized"
            else:
                protected_stop = True
                stop_reason = "in-progress-segment-model-switch-forbidden"
    elif status == "available":
        previous_selection_status = read_explicit_fallback_selection(previous_selection)
        if previous_selection_status.get("dispatch_eligible") is True:
            expired_selection = {
                **deepcopy(previous_selection),
                "expired": True,
                "expiry_reason": "spark-restored-at-fresh-segment",
            }
        selected_model = primary_model
        selected_executor = primary_executor
        selection_source = "policy-primary"
        dispatch_authorized = True
        selection = None
    elif status in FALLBACK_TRIGGERS:
        if fit_errors:
            protected_stop = True
            stop_reason = "invalid-or-missing-fallback-fitness-evidence"
        elif selection_error:
            protected_stop = True
            stop_reason = selection_error
        elif selection and selection.get("choice") == "wait-for-spark":
            stop_reason = "waiting-for-spark"
        elif selection:
            selected_model = _string(selection.get("selected_model")) or None
            selected_executor = _string(selection.get("selected_executor")) or None
            selection_source = "user-explicit-fallback"
            dispatch_authorized = True
        else:
            decision_required = True
            stop_reason = "explicit-fallback-model-and-scope-selection-required"
    else:
        protected_stop = True
        stop_reason = status_reason

    options = fallback_options(candidates) if status in FALLBACK_TRIGGERS and not fit_errors else []
    fallback = {
        "decision_required": decision_required,
        "trigger": status if status in FALLBACK_TRIGGERS else None,
        "recommended_model": recommended_model if status in FALLBACK_TRIGGERS and not fit_errors else None,
        "recommended_executor": recommended_executor if status in FALLBACK_TRIGGERS and not fit_errors else None,
        "recommendation_reason": recommendation_reason,
        "work_estimate_sha256": estimate_sha256,
        "fallback_fit_sha256": fit_sha256,
        "policy_sha256": policy_sha256,
        "candidates": deepcopy(candidates) if status in FALLBACK_TRIGGERS else [],
        "options": options,
        "selection": deepcopy(selection),
        "selected_model": selected_model if selection_source == "user-explicit-fallback" else None,
        "selected_executor": selected_executor if selection_source == "user-explicit-fallback" else None,
        "selection_source": selection_source if selection_source == "user-explicit-fallback" else None,
        "scope": selection.get("scope") if isinstance(selection, Mapping) else None,
        "expires_when": selection.get("expires_when") if isinstance(selection, Mapping) else None,
        "expired_selection": expired_selection,
        "fitness_errors": fit_errors,
        "migration": read_explicit_fallback_selection(supplied_selection),
    }
    history = deepcopy(previous.get("history", [])) if isinstance(previous.get("history"), list) else []
    if fresh_segment:
        history_event: dict[str, Any] = {
            "availability_status": status,
            "availability_reason": status_reason,
            "capability_evidence_sha256": evidence_sha256,
            "work_estimate_sha256": estimate_sha256,
            "fallback_fit_sha256": fit_sha256,
            "policy_sha256": policy_sha256,
            "selected_model": selected_model,
            "selected_executor": selected_executor,
            "selection_source": selection_source,
            "dispatch_authorized": dispatch_authorized,
            "protected_stop": protected_stop,
            "stop_reason": stop_reason,
        }
        if selection is not None:
            history_event["fallback_selection"] = deepcopy(selection)
        if expired_selection is not None:
            history_event["expired_selection"] = deepcopy(expired_selection)
        history.append(history_event)
    return {
        "route_type": "cwo-operative-route",
        "version": 2,
        "execution_environment": execution_environment,
        "risk_level": risk_level,
        "data_sensitivity": data_sensitivity,
        "evaluated_at": evaluated,
        "primary_model": primary_model,
        "primary_executor": primary_executor,
        "primary_selection": "automatic-when-available",
        "availability_status": status,
        "availability_reason": status_reason,
        "availability_evidence": deepcopy(evidence),
        "availability_evidence_sha256": evidence_sha256,
        "capability_evidence_sha256": evidence_sha256,
        "policy_sha256": policy_sha256,
        "work_estimate": deepcopy(estimate_value),
        "work_estimate_sha256": estimate_sha256,
        "fallback_fit_evidence": deepcopy(fit_value),
        "fallback_fit_sha256": fit_sha256,
        "recommended_model": fallback["recommended_model"],
        "recommended_executor": fallback["recommended_executor"],
        "recommendation_reason": fallback["recommendation_reason"],
        "user_selection": deepcopy(selection),
        "user_selection_scope": selection.get("scope") if isinstance(selection, Mapping) else None,
        "selected_model": selected_model,
        "selected_executor": selected_executor,
        "selection_source": selection_source,
        "dispatch_authorized": dispatch_authorized,
        "protected_stop": protected_stop,
        "stop_reason": stop_reason,
        "fresh_segment": fresh_segment,
        "aggregate_budget": deepcopy(budget),
        "budget_reset": False,
        "fallback": fallback,
        "history": history,
    }


def validate_operative_route_for_model(
    route: Any,
    requested_model: str,
    *,
    work_estimate: Mapping[str, Any] | None = None,
    now: str | None = None,
    current_authority: Any = _UNSET,
    historical_parse: bool = False,
) -> list[str]:
    errors: list[str] = []
    if type(historical_parse) is not bool:
        return ["historical_parse must be boolean"]
    value = _mapping(route)
    if value.get("version") == 2 and not historical_parse:
        native, _, _, _ = _policy_bundle()
        policy = native.get("task_selected_routing", {})
        if isinstance(policy, Mapping) and policy.get("status") == "active":
            return ["historical v2 route is parseable but cannot authorize new dispatch"]
    if value.get("route_type") == "cwo-operative-route" and value.get("version") == 3:
        shape_errors = validate_task_selected_route_shape(value)
        if shape_errors:
            return [f"task selected route shape: {error}" for error in shape_errors]
        if current_authority is _UNSET or current_authority is None:
            return ["task selected route requires current authority"]
        try:
            authority = _normalize_current_authority(current_authority)
        except (TypeError, ValueError, OverflowError):
            return ["task selected route current authority is invalid"]
        try:
            current_time = _parse_time(now or _now_iso(), "now")
            route_time = _parse_time(value.get("evaluated_at"), "evaluated_at")
        except (TypeError, ValueError, OverflowError):
            return ["task selected route current time is invalid"]
        if route_time > current_time:
            return ["task selected route was evaluated after current validation time"]
        if work_estimate is not None and _canonical_sha256(work_estimate) != _canonical_sha256(
            _mapping(authority.get("fit_inputs")).get("work_estimate")
        ):
            return ["task selected route work estimate does not match current authority"]
        selected_qualification = _mapping(
            _mapping(authority.get("qualifications")).get(value.get("selected_model"))
        )
        try:
            issued = _parse_time(
                selected_qualification.get("origin_issued_at"),
                "current authority qualification origin_issued_at",
            )
            expires = _parse_time(
                selected_qualification.get("origin_expires_at"),
                "current authority qualification origin_expires_at",
            )
        except (TypeError, ValueError, OverflowError):
            return ["task selected route current qualification is invalid"]
        if not issued <= current_time < expires:
            return ["task selected route qualification is not current"]
        try:
            expected = resolve_operative_route(
                execution_environment=_string(value.get("execution_environment")) or "connected-codex",
                risk_level=_string(value.get("risk_level")) or "medium",
                data_sensitivity=_string(value.get("data_sensitivity")) or "internal",
                current_authority=authority,
                evaluated_at=_string(value.get("evaluated_at")),
            )
        except (TypeError, ValueError, OverflowError) as exc:
            return [f"task selected route current evaluation failed: {exc}"]
        if expected.get("dispatch_authorized") is not True:
            return [f"task selected route is not currently authorized: {expected.get('stop_reason')}"]
        if requested_model != value.get("selected_model"):
            return ["task selected route selected_model does not match requested model"]
        if _canonical_sha256(value) != _canonical_sha256(expected):
            return ["task selected route does not match current authority evaluation"]
        return []
    if value.get("route_type") != "cwo-operative-route" or value.get("version") != 2:
        return ["operative routing metadata must be cwo-operative-route version 2"]
    if value.get("dispatch_authorized") is not True or value.get("protected_stop") is not False:
        errors.append("operative routing metadata does not authorize dispatch")
    if value.get("selected_model") != requested_model:
        errors.append("operative routing selected_model does not match requested model")
    primary_model = _string(value.get("primary_model"))
    if requested_model == primary_model:
        if value.get("selection_source") != "policy-primary":
            errors.append("primary model dispatch must use policy-primary selection")
        if value.get("availability_status") != "available":
            errors.append("primary model dispatch requires trusted available status")
    else:
        fallback = _mapping(value.get("fallback"))
        selection = _mapping(fallback.get("selection"))
        embedded_estimate = _mapping(value.get("work_estimate"))
        current_estimate = _mapping(work_estimate) or embedded_estimate
        if not current_estimate:
            errors.append("fallback route is missing its validated work estimate")
        elif embedded_estimate and _canonical_sha256(current_estimate) != _canonical_sha256(embedded_estimate):
            errors.append("fallback route work estimate changed after selection")
        if value.get("selection_source") != "user-explicit-fallback":
            errors.append("fallback dispatch requires user-explicit-fallback selection")
        if selection.get("version") != 2:
            errors.append("fallback dispatch requires version 2 selection provenance")
        for field in (
            "selected_model", "selected_executor", "reason", "scope", "expires_when",
            "selected_at", "actor", "capability_evidence_sha256", "work_estimate_sha256",
            "fallback_fit_sha256", "policy_sha256", "candidate_evidence_sha256",
        ):
            if not _string(selection.get(field)):
                errors.append(f"fallback selection missing {field}")
        if selection.get("selected_model") != requested_model:
            errors.append("fallback selection model does not match requested model")
        if value.get("selected_executor") != selection.get("selected_executor"):
            errors.append("operative routing selected_executor does not match fallback selection")
        for field in ("capability_evidence_sha256", "work_estimate_sha256", "fallback_fit_sha256", "policy_sha256"):
            if selection.get(field) != value.get(field):
                errors.append(f"fallback selection {field} does not match route")
        candidate = next((
            item for item in fallback.get("candidates", [])
            if isinstance(item, Mapping)
            and item.get("model") == requested_model
            and item.get("executor") == value.get("selected_executor")
            and item.get("eligible") is True
        ), None)
        if candidate is None:
            errors.append("selected fallback is not an eligible displayed candidate")
        else:
            if selection.get("candidate_evidence_sha256") != candidate.get("model_evidence_sha256"):
                errors.append("fallback candidate evidence hash does not match selection")
            if candidate.get("acknowledgement_required") and selection.get("degraded_task_fit_acknowledged") is not True:
                errors.append("degraded Luna task fit requires explicit acknowledgement")
        current_time = now or _now_iso()
        selected_record = _model_record(
            _mapping(value.get("availability_evidence")),
            _string(value.get("selected_executor")),
            requested_model,
        )
        _, policy, _, _ = _policy_bundle()
        if not selected_record or not _fresh(selected_record.get("observed_at"), current_time, policy):
            errors.append("selected fallback model evidence is stale at dispatch")
        if value.get("availability_status") not in FALLBACK_TRIGGERS:
            errors.append("fallback dispatch requires a current verified quota or capacity trigger")
        fit = _mapping(value.get("fallback_fit_evidence"))
        fit_errors = validate_operative_fallback_fit(
            fit,
            work_estimate=current_estimate,
            capability_evidence=_mapping(value.get("availability_evidence")),
            context=_mapping(fit.get("context")),
            aggregate_budget=_mapping(value.get("aggregate_budget")),
            execution_environment=_string(value.get("execution_environment")) or "connected-codex",
            risk_level=_string(value.get("risk_level")) or "medium",
            data_sensitivity=_string(value.get("data_sensitivity")) or "internal",
        ) if current_estimate and fit else ["fallback fitness evidence is missing"]
        errors.extend(f"fallback fitness: {error}" for error in fit_errors)
        expected_policy_sha = operative_policy_sha256(_string(value.get("execution_environment")) or "connected-codex")
        if value.get("policy_sha256") != expected_policy_sha:
            errors.append("fallback route policy hash is stale")
        if not _fresh(value.get("evaluated_at"), current_time, policy):
            errors.append("fallback route evidence is stale at dispatch")
    if not isinstance(value.get("aggregate_budget"), Mapping):
        errors.append("operative routing aggregate_budget must be an object")
    if value.get("budget_reset") is not False:
        errors.append("operative routing must preserve aggregate budget without reset")
    return errors
