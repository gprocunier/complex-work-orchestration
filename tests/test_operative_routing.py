from __future__ import annotations

import copy
import json
import sys
import unittest
from unittest import mock
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from cwo_core.coach import coach_orchestration_prompt  # noqa: E402
from cwo_core.operative_routing import (  # noqa: E402
    GPT55_MODEL,
    LUNA_MODEL,
    SPARK_MODEL,
    TERRA_MODEL,
    _classify_fit,
    build_operative_fallback_fit,
    read_explicit_fallback_selection,
    resolve_operative_route,
    validate_operative_fallback_fit,
    validate_operative_route_for_model,
)
from cwo_core.native_disposition import derive_disposition  # noqa: E402
from cwo_core.policy import load_policy  # noqa: E402
from cwo_core.routing import classify_work  # noqa: E402
from cwo_core.work_sizing import DIMENSIONS, evaluate_work_estimate  # noqa: E402
from prepare_native_worker import (  # noqa: E402
    build_native_worker_packet,
    validate_native_worker_packet,
    validate_native_worker_return,
)
from scaffold_workgraph import planned_graph  # noqa: E402
from tests.historical_policy_fixtures import historical_v2_policy  # noqa: E402


NOW = "2026-09-03T19:15:00Z"
CONTEXT = {
    "bead_id": "cwo-test.1",
    "wave_id": None,
    "fresh_segment": True,
    "work_lineage_id": "lineage-1",
}
BUDGET = {
    "tool_calls_hard": 30,
    "runtime_seconds_hard": 600,
    "budget_reset_allowed": False,
}
EXECUTORS = {
    GPT55_MODEL: "internal_worker_gpt55",
    TERRA_MODEL: "internal_worker_terra",
    LUNA_MODEL: "internal_worker_luna",
}


def _surface(executor: str, model: str) -> dict:
    route56 = model in {SPARK_MODEL, TERRA_MODEL, LUNA_MODEL}
    return {
        "source": "trusted-control-plane-session-metadata",
        "observed_at": NOW,
        "executor": executor,
        "model": model,
        "exact_model_available": True,
        "available": True,
        "quota_status": "usable",
        "capacity_status": "available",
        "fresh_session_supported": True,
        "exact_model_attestation_supported": True,
        "lifecycle_controls": ["interrupt", "close", "wait"],
        "workspace_enforced": True,
        "mutation_enforced": True,
        "quota_domain": "route-56-quota" if route56 else "gpt55-quota",
        "cached_input_metering_domain": "route-56-cache" if route56 else "gpt55-cache",
        "remaining_input_tokens": 200_000,
    }


def capability_evidence(*, quota: str = "usable", capacity: str = "available") -> dict:
    spark = _surface("internal_worker", SPARK_MODEL)
    spark.update(quota_status=quota, capacity_status=capacity)
    return {
        "source": "trusted-control-plane-session-metadata",
        "observed_at": NOW,
        "fresh": True,
        "spark": spark,
        "operative_models": [
            _surface(EXECUTORS[GPT55_MODEL], GPT55_MODEL),
            _surface(EXECUTORS[TERRA_MODEL], TERRA_MODEL),
            _surface(EXECUTORS[LUNA_MODEL], LUNA_MODEL),
            _surface("local_secure_review_worker", "local-secure-review-model"),
            _surface("claude_architecture_critic", "claude-opus-4-6"),
        ],
    }


def cache_profile(
    *,
    source: str = "deterministic-context-plan",
    observed_at: str = NOW,
    total: int = 32_000,
    stable: int = 16_000,
    reuse: int = 2,
    repeatable_units: int = 0,
    repeat_template: str | None = None,
    observed_input: int = 0,
    observed_cached: int = 0,
    telemetry_lineage: str | None = None,
) -> dict:
    observed = source == "trusted-session-telemetry"
    return {
        "source": source,
        "observed_at": observed_at,
        "total_context_tokens_p90": total,
        "stable_context_tokens_p90": stable,
        "expected_reuse_opportunities": reuse,
        "repeatable_unit_count": repeatable_units,
        "repeat_template_sha256": repeat_template,
        "observed_input_tokens": observed_input,
        "observed_cached_input_tokens": observed_cached,
        "same_work_lineage": observed and telemetry_lineage == CONTEXT["work_lineage_id"],
        "context_plan_sha256": None if observed else "a" * 64,
        "telemetry_lineage_id": telemetry_lineage if observed else None,
        "evidence_sha256": "b" * 64,
    }


def work_plan(
    *,
    requested_model: str = GPT55_MODEL,
    narrow: bool = False,
    context_tokens: int | None = None,
    tool_calls: int | None = None,
    runtime: int | None = None,
    diff: int | None = None,
    write_count: int | None = None,
    behaviors: int | None = None,
) -> dict:
    defaults = (8_000, 6, 180, 40, 1, 1) if narrow else (32_000, 12, 300, 100, 3, 3)
    context_tokens, tool_calls, runtime, diff, write_count, behaviors = [
        supplied if supplied is not None else default
        for supplied, default in zip(
            (context_tokens, tool_calls, runtime, diff, write_count, behaviors),
            defaults,
        )
    ]
    paths = [f"file-{index}.py" for index in range(write_count)]
    context_manifest = [
        {
            "path": f"context-{index}.txt",
            "selector": "whole-file",
            "purpose": "bounded routing context",
            "bytes": 100,
            "sha256": f"{index + 1:x}" * 64,
        }
        for index in range(1 if narrow else min(write_count, 5))
    ]
    tool_p50 = min(tool_calls, 4 if narrow else 10)
    runtime_p50 = min(runtime, 90 if narrow else 200)
    diff_p50 = min(diff, 20 if narrow else 50)
    payload = {
        "estimate_type": "cwo-native-work-estimate",
        "version": 1,
        "estimate_contract_version": 2,
        "work_unit_id": "wu-model-policy",
        "bead_id": CONTEXT["bead_id"],
        "requested_model": requested_model,
        "primary_outcome": "exercise evidence-bound operative routing",
        "expected_artifacts": ["implementation.patch", "validation.report"],
        "expert_profiles": ["orchestrator", "qa"],
        "frozen_decisions": [
            "operative-readiness:v2",
            "behavior-cluster: fallback routing",
            "input-contract: hash-bound work and capability evidence",
            "output-contract: explicit fallback selection",
            "state-transitions: classify recommend select dispatch",
            "positive-tests: exact eligible fallback",
            "negative-tests: stale or mismatched provenance",
            "authority: user selection is required",
        ],
        "unresolved_decisions": [],
        "subsystems": ["operative-routing"],
        "write_paths": paths,
        "context_manifest": context_manifest,
        "acceptance_checks": ["focused routing tests pass"],
        "estimates": {
            "tool_calls_p50": tool_p50,
            "tool_calls_p90": tool_calls,
            "runtime_seconds_p50": runtime_p50,
            "runtime_seconds_p90": runtime,
            "context_tokens_p90": context_tokens,
        },
        "scores": {dimension: 0 for dimension in DIMENSIONS},
        "semantic_estimate": {
            "estimated_diff_p50": diff_p50,
            "estimated_diff_p90": diff,
            "behavioral_changes": behaviors,
            "state_machine_changes": 0,
            "schema_changes": 0,
            "self_hosting_risk": 1,
            "live_control_risk": 1,
            "contract_surfaces": 1,
            "cli_surfaces": 0,
            "policy_surfaces": 1,
            "telemetry_surfaces": 0,
            "expected_regressions": 3,
            "test_construction_complexity": 1,
            "command_complexity": 1,
            "nested_quote_layers": 0,
            "expected_context_reads": len(context_manifest),
            "expected_mutations": write_count,
            "read_to_mutation_ratio": (
                len(context_manifest) / write_count if write_count else float(len(context_manifest))
            ),
        },
        "pm_estimate": {
            "tool_calls_p50": tool_p50,
            "tool_calls_p90": tool_calls,
            "runtime_seconds_p50": runtime_p50,
            "runtime_seconds_p90": runtime,
        },
        "domain_expert_estimate": {
            "tool_calls_p50": tool_p50,
            "tool_calls_p90": tool_calls,
            "runtime_seconds_p50": runtime_p50,
            "runtime_seconds_p90": runtime,
        },
    }
    if narrow:
        payload["task_profile"] = {
            "task_class": "narrow-mechanical",
            "declared_outcome_count": 1,
            "command_count": 0,
            "check_count": 2,
            "focused_test_count": 2,
            "full_suite_count": 0,
            "read_context_count": len(context_manifest),
            "source_mutation_count": write_count,
            "commands": [],
            "source_mutation_paths": paths,
        }
    result = evaluate_work_estimate(payload)
    if result["route"] != "spark":
        raise AssertionError(f"test fixture unexpectedly routed {result['route']}: {result['hard_gate_reasons']}")
    return result


def fallback_bundle(
    *,
    plan: dict | None = None,
    evidence: dict | None = None,
    cache: dict | None = None,
    budget: dict | None = None,
    context: dict | None = None,
    evaluated_at: str = NOW,
) -> tuple[dict, dict, dict, dict, dict]:
    plan = plan or work_plan()
    evidence = evidence or capability_evidence(quota="exhausted")
    cache = cache or cache_profile()
    budget = budget or copy.deepcopy(BUDGET)
    context = context or copy.deepcopy(CONTEXT)
    fit = build_operative_fallback_fit(
        work_estimate=plan,
        cache_profile=cache,
        capability_evidence=evidence,
        context=context,
        aggregate_budget=budget,
        evaluated_at=evaluated_at,
    )
    route = resolve_operative_route(
        capability_evidence=evidence,
        work_estimate=plan,
        fallback_fit=fit,
        context=context,
        aggregate_budget=budget,
        evaluated_at=evaluated_at,
    )
    return plan, evidence, cache, fit, route


def select_model(decision: dict, model: str, *, scope: str = "current-bead", acknowledge: bool = False) -> dict:
    candidate = next(item for item in decision["fallback"]["candidates"] if item["model"] == model)
    selection = {
        "version": 2,
        "selection_source": "user-explicit-fallback",
        "selected_model": model,
        "selected_executor": candidate["executor"],
        "reason": "Operator explicitly selected a displayed live fallback.",
        "scope": scope,
        "selected_at": NOW,
        "actor": "operator@example.test",
        "capability_evidence_sha256": decision["capability_evidence_sha256"],
        "work_estimate_sha256": decision["work_estimate_sha256"],
        "fallback_fit_sha256": decision["fallback_fit_sha256"],
        "policy_sha256": decision["policy_sha256"],
        "candidate_evidence_sha256": candidate["model_evidence_sha256"],
    }
    if scope == "current-bead":
        selection["bead_id"] = CONTEXT["bead_id"]
    elif scope == "current-wave":
        selection["wave_id"] = "wave-1"
    if acknowledge:
        selection["degraded_task_fit_acknowledged"] = True
    return selection


def select_route(bundle: tuple[dict, dict, dict, dict, dict], model: str, **selection_kwargs) -> dict:
    plan, evidence, _, fit, decision = bundle
    return resolve_operative_route(
        capability_evidence=evidence,
        work_estimate=plan,
        fallback_fit=fit,
        fallback_selection=select_model(decision, model, **selection_kwargs),
        context=CONTEXT,
        aggregate_budget=BUDGET,
        evaluated_at=NOW,
    )


class CurrentPolicyHistoricalRouteTests(unittest.TestCase):
    def test_active_default_requires_current_authority_not_live_spark(self) -> None:
        route = resolve_operative_route(
            capability_evidence=capability_evidence(), evaluated_at=NOW,
        )
        self.assertEqual(route["version"], 3)
        self.assertFalse(route["dispatch_authorized"])
        self.assertIsNone(route["selected_model"])
        self.assertEqual(route["stop_reason"], "current-authority-missing")

    def test_actual_v2_record_is_readable_but_not_active_dispatch_authority(self) -> None:
        for model in (GPT55_MODEL, TERRA_MODEL, LUNA_MODEL):
            with self.subTest(model=model):
                with historical_v2_policy():
                    bundle = fallback_bundle(plan=work_plan(
                        requested_model=model, narrow=model == LUNA_MODEL,
                    ))
                    route = select_route(bundle, model)
                self.assertEqual(route["version"], 2)
                self.assertEqual(validate_operative_route_for_model(
                    route, model, work_estimate=bundle[0], now=NOW,
                    historical_parse=True,
                ), [])
                self.assertEqual(validate_operative_route_for_model(
                    route, model, work_estimate=bundle[0], now=NOW,
                ), ["historical v2 route is parseable but cannot authorize new dispatch"])


class OperativeRoutingTests(unittest.TestCase):
    """Frozen Spark/v2 compatibility, not current dispatch authority."""

    def setUp(self) -> None:
        self.enterContext(historical_v2_policy())

    def test_live_spark_wins_even_when_all_fallbacks_fit(self) -> None:
        plan, evidence, cache, _, _ = fallback_bundle()
        evidence["spark"].update(quota_status="usable", capacity_status="available")
        fit = build_operative_fallback_fit(
            work_estimate=plan, cache_profile=cache, capability_evidence=evidence,
            context=CONTEXT, aggregate_budget=BUDGET, evaluated_at=NOW,
        )
        route = resolve_operative_route(
            capability_evidence=evidence, work_estimate=plan, fallback_fit=fit,
            fallback_selection={"choice": "wait-for-spark"}, context=CONTEXT,
            aggregate_budget=BUDGET, evaluated_at=NOW,
        )
        self.assertEqual(route["selected_model"], SPARK_MODEL)
        self.assertEqual(route["selection_source"], "policy-primary")
        self.assertTrue(route["dispatch_authorized"])
        self.assertEqual(route["fallback"]["candidates"], [])

    def test_missing_ambiguous_and_fault_evidence_are_protected_stops(self) -> None:
        cases = [({}, "unknown"), (capability_evidence(quota="unknown"), "unknown")]
        stale = capability_evidence()
        stale["observed_at"] = "2026-09-03T17:00:00Z"
        cases.append((stale, "unknown"))
        for expected, mutate in (
            ("model-mismatch", lambda evidence: evidence["spark"].update(model="wrong")),
            ("control-fault", lambda evidence: evidence["spark"].update(contradictory_validation=True)),
            ("control-fault", lambda evidence: evidence["spark"].update(lifecycle_controls=["wait"])),
            ("security-fault", lambda evidence: evidence["spark"].update(unattributed_mutation=True)),
            ("security-fault", lambda evidence: evidence["spark"].update(security_fault=True)),
        ):
            evidence = capability_evidence()
            mutate(evidence)
            cases.append((evidence, expected))
        for evidence, status in cases:
            with self.subTest(status=status):
                route = resolve_operative_route(capability_evidence=evidence, evaluated_at=NOW)
                self.assertEqual(route["availability_status"], status)
                self.assertTrue(route["protected_stop"])
                self.assertFalse(route["fallback"]["decision_required"])

    def test_only_verified_exhaustion_or_capacity_opens_choice(self) -> None:
        for trigger, evidence in (
            ("verified-quota-exhausted", capability_evidence(quota="exhausted")),
            ("verified-capacity-unavailable", capability_evidence(capacity="unavailable")),
        ):
            plan = work_plan()
            fit = build_operative_fallback_fit(
                work_estimate=plan, cache_profile=cache_profile(), capability_evidence=evidence,
                context=CONTEXT, aggregate_budget=BUDGET, evaluated_at=NOW,
            )
            route = resolve_operative_route(
                capability_evidence=evidence, work_estimate=plan, fallback_fit=fit,
                context=CONTEXT, aggregate_budget=BUDGET, evaluated_at=NOW,
            )
            self.assertEqual(route["availability_status"], trigger)
            self.assertTrue(route["fallback"]["decision_required"])
            self.assertFalse(route["dispatch_authorized"])

    def test_thread_allocation_alone_cannot_claim_spark_quota_is_usable(self) -> None:
        evidence = capability_evidence()
        evidence["spark"]["availability_basis"] = (
            "exact-model-thread-allocation-accepted"
        )
        route = resolve_operative_route(
            capability_evidence=evidence,
            evaluated_at=NOW,
        )
        self.assertEqual(route["availability_status"], "unknown")
        self.assertEqual(
            route["availability_reason"],
            "spark-thread-allocation-is-not-quota-evidence",
        )
        self.assertTrue(route["protected_stop"])
        self.assertFalse(route["dispatch_authorized"])
        self.assertFalse(route["fallback"]["decision_required"])

        evidence["spark"]["quota_status"] = "exhausted"
        plan = work_plan()
        fit = build_operative_fallback_fit(
            work_estimate=plan,
            cache_profile=cache_profile(),
            capability_evidence=evidence,
            context=CONTEXT,
            aggregate_budget=BUDGET,
            evaluated_at=NOW,
        )
        exhausted = resolve_operative_route(
            capability_evidence=evidence,
            work_estimate=plan,
            fallback_fit=fit,
            context=CONTEXT,
            aggregate_budget=BUDGET,
            evaluated_at=NOW,
        )
        self.assertEqual(
            exhausted["availability_status"], "verified-quota-exhausted"
        )
        self.assertTrue(exhausted["fallback"]["decision_required"])

    def test_gpt55_is_recommended_only_for_proven_strategic_fit(self) -> None:
        _, _, _, fit, route = fallback_bundle()
        self.assertTrue(fit["classifications"]["substantial"])
        self.assertTrue(fit["classifications"]["cache_heavy"])
        gpt55 = next(item for item in fit["candidates"] if item["model"] == GPT55_MODEL)
        self.assertTrue(gpt55["domain_independent"])
        self.assertTrue(gpt55["eligible"])
        self.assertEqual(route["recommended_model"], GPT55_MODEL)

    def test_non_substantial_and_non_cache_heavy_exclude_gpt55_exactly(self) -> None:
        cases = (
            (work_plan(context_tokens=31_999, tool_calls=11, runtime=299, diff=80, write_count=2, behaviors=2), cache_profile(), "gpt55-requires-substantial-work"),
            (work_plan(), cache_profile(stable=15_999), "gpt55-requires-cache-heavy-work"),
        )
        for plan, cache, reason in cases:
            with self.subTest(reason=reason):
                _, _, _, fit, route = fallback_bundle(plan=plan, cache=cache)
                gpt55 = next(item for item in fit["candidates"] if item["model"] == GPT55_MODEL)
                self.assertIn(reason, gpt55["exclusion_reasons"])
                self.assertFalse(gpt55["eligible"])
                self.assertEqual(route["recommended_model"], TERRA_MODEL)

    def test_missing_stale_and_cross_lineage_cache_evidence_fail_closed(self) -> None:
        with self.assertRaisesRegex(ValueError, "missing or unknown"):
            build_operative_fallback_fit(
                work_estimate=work_plan(), cache_profile={"source": "deterministic-context-plan"},
                capability_evidence=capability_evidence(quota="exhausted"), context=CONTEXT,
                aggregate_budget=BUDGET, evaluated_at=NOW,
            )
        _, _, _, fit, _ = fallback_bundle(cache=cache_profile(observed_at="2026-09-03T17:00:00Z"))
        gpt55 = next(item for item in fit["candidates"] if item["model"] == GPT55_MODEL)
        self.assertIn("cache-evidence-stale", gpt55["exclusion_reasons"])
        cross = cache_profile(
            source="trusted-session-telemetry", observed_input=32_000,
            observed_cached=16_000, telemetry_lineage="different-lineage",
        )
        _, _, _, fit, _ = fallback_bundle(cache=cross)
        gpt55 = next(item for item in fit["candidates"] if item["model"] == GPT55_MODEL)
        self.assertIn("cross-lineage-cache-telemetry-rejected", gpt55["exclusion_reasons"])

    def test_unknown_or_shared_domains_exclude_gpt55(self) -> None:
        for value in ("", "route-56-quota"):
            evidence = capability_evidence(quota="exhausted")
            record = evidence["operative_models"][0]
            record["quota_domain"] = value
            if value:
                record["cached_input_metering_domain"] = "route-56-cache"
            _, _, _, fit, _ = fallback_bundle(evidence=evidence)
            gpt55 = next(item for item in fit["candidates"] if item["model"] == GPT55_MODEL)
            self.assertIn("gpt55-quota-or-metering-domain-independence-unproved", gpt55["exclusion_reasons"])

    def test_insufficient_headroom_or_aggregate_budget_excludes_gpt55(self) -> None:
        evidence = capability_evidence(quota="exhausted")
        evidence["operative_models"][0]["remaining_input_tokens"] = 31_999
        _, _, _, fit, _ = fallback_bundle(evidence=evidence)
        self.assertIn("gpt55-model-headroom-insufficient", next(item for item in fit["candidates"] if item["model"] == GPT55_MODEL)["exclusion_reasons"])
        budget = {**BUDGET, "tool_calls_hard": 11}
        _, _, _, fit, _ = fallback_bundle(budget=budget)
        self.assertIn("gpt55-aggregate-budget-insufficient", next(item for item in fit["candidates"] if item["model"] == GPT55_MODEL)["exclusion_reasons"])

    def test_terra_for_non_luna_shape_and_luna_for_narrow_or_repeatable(self) -> None:
        plan = work_plan(context_tokens=10_000, tool_calls=11, runtime=200, diff=80, write_count=2, behaviors=2)
        self.assertEqual(fallback_bundle(plan=plan)[4]["recommended_model"], TERRA_MODEL)
        narrow_bundle = fallback_bundle(plan=work_plan(requested_model=LUNA_MODEL, narrow=True))
        self.assertTrue(narrow_bundle[3]["classifications"]["luna_fit"])
        self.assertEqual(narrow_bundle[4]["recommended_model"], LUNA_MODEL)
        repeat = cache_profile(repeatable_units=10, repeat_template="c" * 64)
        repeat_bundle = fallback_bundle(plan=work_plan(requested_model=LUNA_MODEL, narrow=True), cache=repeat)
        self.assertTrue(repeat_bundle[3]["classifications"]["repeatable_high_volume"])
        self.assertEqual(repeat_bundle[4]["recommended_model"], LUNA_MODEL)

    def test_unavailable_candidates_fall_through_in_policy_order(self) -> None:
        evidence = capability_evidence(quota="exhausted")
        evidence["operative_models"][0]["available"] = False
        self.assertEqual(fallback_bundle(evidence=evidence)[4]["recommended_model"], TERRA_MODEL)
        evidence["operative_models"][1]["available"] = False
        route = fallback_bundle(evidence=evidence)[4]
        self.assertEqual(route["recommended_model"], LUNA_MODEL)
        self.assertTrue(route["fallback"]["options"][0]["value"].endswith(":" + LUNA_MODEL))

    def test_degraded_luna_requires_acknowledgement(self) -> None:
        plan = work_plan(context_tokens=10_000, tool_calls=11, runtime=200, diff=80, write_count=2, behaviors=2)
        bundle = fallback_bundle(plan=plan)
        luna = next(item for item in bundle[4]["fallback"]["candidates"] if item["model"] == LUNA_MODEL)
        self.assertEqual(luna["task_fit"], "degraded")
        self.assertTrue(luna["acknowledgement_required"])
        rejected = select_route(bundle, LUNA_MODEL)
        self.assertEqual(rejected["stop_reason"], "degraded-luna-task-fit-not-acknowledged")
        accepted = select_route(bundle, LUNA_MODEL, acknowledge=True)
        self.assertTrue(accepted["dispatch_authorized"])

    def test_no_eligible_model_leaves_only_wait(self) -> None:
        evidence = capability_evidence(quota="exhausted")
        for record in evidence["operative_models"][:3]:
            record["available"] = False
        route = fallback_bundle(evidence=evidence)[4]
        self.assertIsNone(route["recommended_model"])
        self.assertEqual(route["fallback"]["options"], [{
            "label": "Wait for Spark", "value": "wait-for-spark",
            "description": "Start no fallback session and re-evaluate trusted Spark availability at the next fresh segment.",
        }])

    def test_choice_is_required_but_any_eligible_displayed_model_may_be_selected(self) -> None:
        bundle = fallback_bundle()
        decision = bundle[4]
        self.assertEqual(decision["recommended_model"], GPT55_MODEL)
        self.assertFalse(decision["dispatch_authorized"])
        self.assertIsNone(decision["selected_model"])
        selected = select_route(bundle, TERRA_MODEL)
        self.assertTrue(selected["dispatch_authorized"])
        self.assertEqual(selected["selected_model"], TERRA_MODEL)
        self.assertEqual(selected["user_selection_scope"], "current-bead")

    def test_changed_bound_evidence_invalidates_prior_selection(self) -> None:
        bundle = fallback_bundle()
        plan, evidence, _, fit, decision = bundle
        selection = select_model(decision, GPT55_MODEL)
        cases = []
        changed_plan = copy.deepcopy(plan)
        changed_plan["primary_outcome"] += " changed"
        cases.append((changed_plan, evidence, fit, selection, "invalid-or-missing-fallback-fitness-evidence"))
        changed_fit = copy.deepcopy(fit)
        changed_fit["classifications"]["cache_heavy"] = False
        cases.append((plan, evidence, changed_fit, selection, "invalid-or-missing-fallback-fitness-evidence"))
        changed_evidence = copy.deepcopy(evidence)
        changed_evidence["operative_models"][0]["remaining_input_tokens"] -= 1
        cases.append((plan, changed_evidence, fit, selection, "invalid-or-missing-fallback-fitness-evidence"))
        changed_quota = copy.deepcopy(evidence)
        changed_quota["operative_models"][0]["quota_status"] = "exhausted"
        cases.append((plan, changed_quota, fit, selection, "invalid-or-missing-fallback-fitness-evidence"))
        bad_candidate = copy.deepcopy(selection)
        bad_candidate["candidate_evidence_sha256"] = "0" * 64
        cases.append((plan, evidence, fit, bad_candidate, "fallback-selection-candidate-evidence-mismatch"))
        bad_policy = copy.deepcopy(selection)
        bad_policy["policy_sha256"] = "0" * 64
        cases.append((plan, evidence, fit, bad_policy, "fallback-selection-policy-mismatch"))
        for candidate_plan, candidate_evidence, candidate_fit, candidate_selection, reason in cases:
            with self.subTest(reason=reason):
                route = resolve_operative_route(
                    capability_evidence=candidate_evidence, work_estimate=candidate_plan,
                    fallback_fit=candidate_fit, fallback_selection=candidate_selection,
                    context=CONTEXT, aggregate_budget=BUDGET, evaluated_at=NOW,
                )
                self.assertFalse(route["dispatch_authorized"])
                self.assertEqual(route["stop_reason"], reason)

    def test_critic_peer_opus_and_local_routes_are_orthogonal(self) -> None:
        route = classify_work(
            "Use Claude Opus 4.6 as an architecture critic and local review for this implementation.",
            external_ok=True, allow_disclosure_escalation=True, share_boundary="repo-readonly",
            requested_roles=["architecture"], operative_capabilities=capability_evidence(),
            operative_evaluated_at=NOW,
        )
        self.assertIn("claude_architecture_critic", route["critic_route"]["requested_executors"])
        self.assertEqual(route["operative_route"]["selected_model"], SPARK_MODEL)
        self.assertFalse(route["critic_route"]["may_change_operative_route"])
        candidate_text = json.dumps(fallback_bundle()[4]["fallback"]["candidates"])
        self.assertNotIn("claude-opus", candidate_text)
        self.assertNotIn("local-secure", candidate_text)

    def test_budget_preserved_scope_expiry_and_wait(self) -> None:
        bundle = fallback_bundle()
        selected = select_route(bundle, GPT55_MODEL, scope="current-wave")
        self.assertEqual(selected["aggregate_budget"], BUDGET)
        self.assertFalse(selected["budget_reset"])
        wrong_context = {**CONTEXT, "wave_id": "wrong"}
        selection = select_model(bundle[4], GPT55_MODEL, scope="current-wave")
        route = resolve_operative_route(
            capability_evidence=bundle[1], work_estimate=bundle[0], fallback_fit=bundle[3],
            fallback_selection=selection, context=wrong_context, aggregate_budget=BUDGET, evaluated_at=NOW,
        )
        self.assertEqual(route["stop_reason"], "invalid-or-missing-fallback-fitness-evidence")
        waiting = resolve_operative_route(
            capability_evidence=bundle[1], work_estimate=bundle[0], fallback_fit=bundle[3],
            fallback_selection={"choice": "wait-for-spark"}, context=CONTEXT,
            aggregate_budget=BUDGET, evaluated_at=NOW,
        )
        self.assertEqual(waiting["stop_reason"], "waiting-for-spark")
        self.assertFalse(waiting["dispatch_authorized"])

    def test_running_unit_cannot_switch_mid_segment(self) -> None:
        bundle = fallback_bundle()
        selected = select_route(bundle, GPT55_MODEL)
        running_context = {**CONTEXT, "fresh_segment": False, "current_model": TERRA_MODEL, "current_executor": EXECUTORS[TERRA_MODEL]}
        running = resolve_operative_route(
            capability_evidence=capability_evidence(), context=running_context,
            previous_route=selected, evaluated_at=NOW,
        )
        self.assertTrue(running["protected_stop"])
        self.assertEqual(running["stop_reason"], "in-progress-segment-model-switch-forbidden")

    def test_restored_spark_supersedes_until_restored_selection(self) -> None:
        bundle = fallback_bundle()
        selected = select_route(bundle, GPT55_MODEL, scope="until-spark-restored")
        restored = resolve_operative_route(
            capability_evidence=capability_evidence(), context=CONTEXT,
            previous_route=selected, evaluated_at=NOW,
        )
        self.assertEqual(restored["selected_model"], SPARK_MODEL)
        self.assertEqual(restored["selection_source"], "policy-primary")
        self.assertTrue(restored["fallback"]["expired_selection"]["expired"])
        self.assertEqual(restored["history"][-1]["expired_selection"]["expiry_reason"], "spark-restored-at-fresh-segment")

    def test_legacy_records_are_readable_but_cannot_authorize_v2(self) -> None:
        legacy = {"version": 1, "selected_model": LUNA_MODEL, "selected_by": "operator"}
        status = read_explicit_fallback_selection(legacy)
        self.assertTrue(status["present"])
        self.assertTrue(status["migration_required"])
        self.assertFalse(status["dispatch_eligible"])
        bundle = fallback_bundle()
        route = resolve_operative_route(
            capability_evidence=bundle[1], work_estimate=bundle[0], fallback_fit=bundle[3],
            fallback_selection=legacy, context=CONTEXT, aggregate_budget=BUDGET, evaluated_at=NOW,
        )
        self.assertEqual(route["stop_reason"], "fallback-selection-migration-required")

    def test_candidate_limit_wait_last_and_explanations(self) -> None:
        route = fallback_bundle()[4]
        self.assertLessEqual(len(route["fallback"]["candidates"]), 3)
        self.assertEqual(route["fallback"]["options"][-1]["value"], "wait-for-spark")
        self.assertLessEqual(len(route["fallback"]["options"]), 4)
        for candidate in route["fallback"]["candidates"]:
            self.assertTrue(candidate["inclusion_reasons"] or candidate["exclusion_reasons"])

    def test_numeric_threshold_boundaries_and_zero_ratios(self) -> None:
        policy = load_policy("native-worker-execution")["operative_routing"]
        base_estimate = {
            "task_class": "bounded-implementation", "fit_mode": "semantic", "unresolved_decisions": [],
            "write_paths": ["a", "b"], "route": "spark", "operative_route": "spark", "authority_route": "spark",
            "estimates": {"context_tokens_p90": 31_999, "tool_calls_p90": 11, "runtime_seconds_p90": 299},
            "semantic_estimate": {"estimated_diff_p90": 80, "behavioral_changes": 2, "command_complexity": 1, "test_construction_complexity": 1},
        }
        profile = cache_profile(stable=15_999, reuse=1)
        self.assertFalse(_classify_fit(base_estimate, profile, policy, NOW)["substantial"])
        signals = (
            ("estimates", "context_tokens_p90", 32_000), ("estimates", "tool_calls_p90", 12),
            ("estimates", "runtime_seconds_p90", 300), ("semantic_estimate", "estimated_diff_p90", 81),
            (None, "write_paths", ["a", "b", "c"]), ("semantic_estimate", "behavioral_changes", 3),
        )
        for first_index in range(len(signals)):
            estimate = copy.deepcopy(base_estimate)
            for index in (first_index, (first_index + 1) % len(signals)):
                section, key, value = signals[index]
                if section is None:
                    estimate[key] = value
                else:
                    estimate[section][key] = value
            self.assertTrue(_classify_fit(estimate, profile, policy, NOW)["substantial"])

        self.assertTrue(_classify_fit(base_estimate, cache_profile(total=32_000, stable=16_000, reuse=2), policy, NOW)["cache_heavy"])
        for changed in (cache_profile(total=32_000, stable=15_999, reuse=2), cache_profile(total=32_001, stable=16_000, reuse=2), cache_profile(total=32_000, stable=16_000, reuse=1)):
            self.assertFalse(_classify_fit(base_estimate, changed, policy, NOW)["cache_heavy"])
        self.assertTrue(_classify_fit(base_estimate, cache_profile(source="trusted-session-telemetry", observed_input=32_000, observed_cached=16_000, telemetry_lineage="lineage-1"), policy, NOW)["cache_heavy"])
        for changed in (
            cache_profile(source="trusted-session-telemetry", observed_input=32_000, observed_cached=15_999, telemetry_lineage="lineage-1"),
            cache_profile(source="trusted-session-telemetry", observed_input=32_001, observed_cached=16_000, telemetry_lineage="lineage-1"),
            cache_profile(source="trusted-session-telemetry", observed_input=0, observed_cached=0, telemetry_lineage="lineage-1"),
        ):
            self.assertFalse(_classify_fit(base_estimate, changed, policy, NOW)["cache_heavy"])
        for invalid in (cache_profile(stable=-1), cache_profile(
            source="trusted-session-telemetry", observed_input=1,
            observed_cached=2, telemetry_lineage="lineage-1",
        )):
            with self.assertRaises(ValueError):
                build_operative_fallback_fit(
                    work_estimate=work_plan(), cache_profile=invalid,
                    capability_evidence=capability_evidence(quota="exhausted"),
                    context=CONTEXT, aggregate_budget=BUDGET, evaluated_at=NOW,
                )

        deterministic = copy.deepcopy(base_estimate)
        deterministic.update(task_class="narrow-mechanical", fit_mode="deterministic")
        deterministic["estimates"]["tool_calls_p90"] = 12
        deterministic["semantic_estimate"].update(estimated_diff_p90=80, behavioral_changes=2)
        self.assertTrue(_classify_fit(deterministic, cache_profile(), policy, NOW)["luna_fit"])
        for section, key, value in (
            ("semantic_estimate", "estimated_diff_p90", 81), (None, "write_paths", ["a", "b", "c"]),
            ("semantic_estimate", "behavioral_changes", 3), ("estimates", "tool_calls_p90", 13),
            ("semantic_estimate", "command_complexity", 2), ("semantic_estimate", "test_construction_complexity", 2),
        ):
            changed = copy.deepcopy(deterministic)
            if section is None:
                changed[key] = value
            else:
                changed[section][key] = value
            self.assertFalse(_classify_fit(changed, cache_profile(), policy, NOW)["luna_fit"])
        repeatable = copy.deepcopy(deterministic)
        repeatable["semantic_estimate"]["estimated_diff_p90"] = 81
        self.assertTrue(_classify_fit(repeatable, cache_profile(repeatable_units=10, repeat_template="c" * 64), policy, NOW)["repeatable_high_volume"])
        self.assertFalse(_classify_fit(repeatable, cache_profile(repeatable_units=9, repeat_template="c" * 64), policy, NOW)["repeatable_high_volume"])

    def test_fit_and_route_schemas_are_strict(self) -> None:
        try:
            from jsonschema import Draft202012Validator
        except ImportError:  # pragma: no cover
            self.skipTest("jsonschema is not installed")
        bundle = fallback_bundle()
        selected = select_route(bundle, GPT55_MODEL, scope="until-spark-restored")
        restored = resolve_operative_route(
            capability_evidence=capability_evidence(), context=CONTEXT,
            previous_route=selected, evaluated_at=NOW,
        )
        fit_schema = json.loads((ROOT / "schemas/operative-fallback-fit.schema.json").read_text())
        route_schema = json.loads((ROOT / "schemas/operative-routing-state.schema.json").read_text())
        fit_validator = Draft202012Validator(fit_schema)
        route_validator = Draft202012Validator(route_schema)
        self.assertEqual(list(fit_validator.iter_errors(bundle[3])), [])
        for route in (bundle[4], selected, restored):
            self.assertEqual([error.message for error in route_validator.iter_errors(route)], [])
        malformed_fit = copy.deepcopy(bundle[3])
        malformed_fit["unknown"] = True
        self.assertTrue(list(fit_validator.iter_errors(malformed_fit)))
        self.assertTrue(validate_operative_fallback_fit(
            malformed_fit, work_estimate=bundle[0], capability_evidence=bundle[1],
            context=CONTEXT, aggregate_budget=BUDGET,
        ))
        malformed_route = copy.deepcopy(selected)
        malformed_route["unknown"] = True
        self.assertTrue(list(route_validator.iter_errors(malformed_route)))

    def test_changed_json_compatible_policy_files_load(self) -> None:
        for relative in ("policy/native-worker-execution.yaml", "policy/execution-environments.yaml", "policy/executor-registry.yaml"):
            self.assertIsInstance(json.loads((ROOT / relative).read_text(encoding="utf-8")), dict)

    def test_coach_requires_model_and_scope_and_shows_recommendation(self) -> None:
        bundle = fallback_bundle()
        result = coach_orchestration_prompt(
            "Use Sol as architect and Spark as the operative worker.",
            operative_capabilities=bundle[1], operative_work_estimate=bundle[0],
            operative_fallback_fit=bundle[3], operative_context=CONTEXT,
            aggregate_budget=BUDGET, operative_evaluated_at=NOW,
        )
        ids = [item["id"] for item in result["interactive_questions"]]
        self.assertIn("operative_fallback", ids)
        self.assertIn("operative_fallback_scope", ids)
        self.assertTrue(result["requires_user_selection_before_plan"])
        self.assertEqual(result["operative_route"]["recommended_model"], GPT55_MODEL)

    def test_scaffold_preserves_complete_routing_provenance(self) -> None:
        bundle = fallback_bundle()
        selected = select_route(bundle, TERRA_MODEL)
        result = classify_work(
            "Implement the bounded routing task.", operative_capabilities=bundle[1],
            operative_work_estimate=bundle[0], operative_fallback_fit=bundle[3],
            fallback_selection=selected["user_selection"], operative_context=CONTEXT,
            aggregate_budget=BUDGET, operative_evaluated_at=NOW,
        )
        graph = planned_graph("Fallback scaffold", result)
        implementation = next(item for item in graph if item.get("lane") == "implementation")
        metadata = implementation["metadata"]
        self.assertEqual(metadata["operative_recommended_model"], GPT55_MODEL)
        self.assertEqual(metadata["operative_selected_model"], TERRA_MODEL)
        self.assertEqual(metadata["operative_selection_source"], "user-explicit-fallback")
        self.assertEqual(metadata["operative_work_estimate_sha256"], bundle[4]["work_estimate_sha256"])
        self.assertEqual(metadata["operative_fallback_fit_sha256"], bundle[4]["fallback_fit_sha256"])
        self.assertEqual(metadata["operative_capability_evidence_sha256"], bundle[4]["capability_evidence_sha256"])
        self.assertEqual(metadata["operative_selection_scope"], "current-bead")
        self.assertEqual(metadata["operative_selection_expires_when"], f"bead:{CONTEXT['bead_id']}:complete")
        self.assertEqual(metadata["operative_aggregate_budget"], BUDGET)
        self.assertFalse(metadata["critic_route"]["may_change_operative_route"])

    @mock.patch(
        "cwo_core.operative_routing._now_iso",
        new=lambda: NOW,
    )
    def test_packet_and_return_validate_each_selected_fallback(self) -> None:
        for model in (GPT55_MODEL, TERRA_MODEL, LUNA_MODEL):
            with self.subTest(model=model):
                plan = work_plan(requested_model=model, narrow=model == LUNA_MODEL)
                bundle = fallback_bundle(plan=plan)
                route = select_route(bundle, model)
                packet = build_native_worker_packet(
                    bead_id=CONTEXT["bead_id"], lane="implementation", workdir=str(ROOT),
                    allowed_paths=plan["write_paths"], acceptance_checks=plan["acceptance_checks"],
                    requested_model=model, operative_routing=route,
                )
                self.assertEqual(validate_native_worker_packet(packet), [])
                result = {
                    "return_type": "cwo-native-worker-return", "version": 1,
                    "packet_id": packet["packet_id"], "bead_id": packet["bead_id"],
                    "session_id": "fresh-session", "segment_id": "segment-1", "status": "completed",
                    "requested_model": model, "actual_model": model,
                    "attestation_source": "trusted-control-plane-session-metadata", "attestation_status": "trusted",
                    "completed_evidence": "focused validation passed", "files_touched": [], "mutation_state": "clean",
                    "commands_run": ["python -m unittest tests.test_operative_routing"],
                    "validation": {"status": "pass"}, "decision_required": [],
                    "bounded_options": [], "recommendation": "accept", "remaining_scope": {},
                    "usage": {"tool_calls": 0, "elapsed_seconds": 1, "context_compactions": 0, "full_suite_runs": 0},
                    "residual_risks": [], "replan": None,
                }
                result.update(derive_disposition(
                    status=result["status"], requested_model=model, actual_model=model,
                    usage=result["usage"], budget=packet["budget"], validation=None,
                ))
                self.assertEqual(validate_native_worker_return(packet, result), [])
                wrong = copy.deepcopy(result)
                wrong["actual_model"] = SPARK_MODEL
                self.assertTrue(validate_native_worker_return(packet, wrong))

    def test_route_dispatch_validation_rejects_stale_and_wrong_attestation(self) -> None:
        bundle = fallback_bundle()
        selected = select_route(bundle, GPT55_MODEL)
        self.assertEqual(validate_operative_route_for_model(selected, GPT55_MODEL, work_estimate=bundle[0], now=NOW), [])
        self.assertTrue(validate_operative_route_for_model(selected, TERRA_MODEL, work_estimate=bundle[0], now=NOW))
        self.assertIn(
            "fallback route evidence is stale at dispatch",
            validate_operative_route_for_model(selected, GPT55_MODEL, work_estimate=bundle[0], now="2026-09-03T21:15:01Z"),
        )


if __name__ == "__main__":
    unittest.main()
