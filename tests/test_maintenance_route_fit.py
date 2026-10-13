"""Synthetic v3 fit evidence through actual sizing/routing; no live authority.

No provider is called. Genuine owner-capability, issuer and ledger joins belong
at maintenance_release, not this public deterministic evidence evaluator.
"""
from __future__ import annotations

import copy
import json
import unittest
from unittest.mock import patch

from tests.test_operative_routing import BUDGET, NOW, ROOT, cache_profile, capability_evidence
from tests.test_routing_current_authority import synthetic_authority
from tests.test_semantic_read_only_contract import semantic_review
from cwo_core import operative_routing as routing
from cwo_core.policy import load_policy
from cwo_core.routing import classify_work
from cwo_core.work_sizing import evaluate_work_estimate, is_read_only_work_estimate


def maintenance_budget():
    return {
        "mode": "maintenance-unbounded",
        "mission_id": "synthetic-maintenance-mission",
        "mission_sha256": "a" * 64,
        "operation_id": "synthetic-operation-1",
        "cumulative_before": 27,
        "reservation": {
            "mode": "finite-operation", "sessions": 2, "tool_calls": 18,
            "runtime_seconds": 480, "cleanup_seconds": 20, "max_concurrency": 1,
        },
        "budget_reset_allowed": False,
    }


def maintenance_authority():
    authority = synthetic_authority()
    inputs = authority["fit_inputs"]
    inputs["aggregate_budget"] = maintenance_budget()
    inputs["work_estimate"] = evaluate_work_estimate(semantic_review())
    for record in inputs["capability_evidence"]["operative_models"]:
        record.pop("remaining_input_tokens", None)
        source = {
            "source": record["source"], "observed_at": record["observed_at"],
            "model": record["model"], "context_window_tokens": 32_000,
        }
        record["context_window_source"] = source
        record["context_headroom"] = {
            "basis": "fresh-segment-context-window", "context_window_tokens": 32_000,
            "reserved_output_tokens": 4_000, "source_sha256": routing._canonical_sha256(source),
        }
    return authority


def luna_record(authority):
    return next(record for record in authority["fit_inputs"]["capability_evidence"]["operative_models"]
                if record["model"] == routing.LUNA_MODEL)


class MaintenanceRouteFitTests(unittest.TestCase):
    def setUp(self):
        self.native = copy.deepcopy(load_policy("native-worker-execution"))
        self.native["task_selected_routing"]["status"] = "active"
        self.native["task_selected_routing"]["activation"].update(active=True, dispatch_authority=True)
        original = routing.load_policy
        self.patch = patch.object(routing, "load_policy", side_effect=lambda name:
            copy.deepcopy(self.native) if name == "native-worker-execution" else original(name))
        self.patch.start()
        self.addCleanup(self.patch.stop)

    def route(self, authority):
        return classify_work("Synthetic bounded read-only diagnosis", current_authority=authority,
                             operative_evaluated_at=NOW)["operative_route"]

    def fit(self, authority):
        return routing.build_task_selected_fit(**authority["fit_inputs"], evaluated_at=NOW)

    def candidate(self, authority):
        return next(candidate for candidate in self.fit(authority)["candidates"]
                    if candidate["model"] == routing.LUNA_MODEL)

    def schema_check(self, route):
        self.assertEqual(routing.validate_task_selected_route_shape(route), [])
        try:
            import jsonschema
        except ImportError:
            return
        schema = json.loads((ROOT / "schemas/operative-routing-state.schema.json").read_text())
        jsonschema.Draft202012Validator(schema).validate(route)

    def assert_fit_denied(self, authority, reason):
        candidate = self.candidate(authority)
        self.assertFalse(candidate["eligible"])
        self.assertIn(reason, candidate["exclusion_reasons"])
        route = self.route(authority)
        self.assertFalse(route["dispatch_authorized"])
        self.schema_check(route)

    def test_genuine_evaluator_synthetic_positive_preserves_semantic_identity(self):
        authority = maintenance_authority()
        work = authority["fit_inputs"]["work_estimate"]
        self.assertTrue(is_read_only_work_estimate(work))
        self.assertEqual(work["fit_mode"], "semantic")
        route = self.route(authority)
        self.assertTrue(route["dispatch_authorized"], route["stop_reason"])
        self.assertEqual(route["selected_model"], routing.LUNA_MODEL)
        classifications = route["fit_evidence"]["classifications"]
        self.assertFalse(classifications["deterministic"])
        self.assertTrue(classifications["bounded_semantic_readonly"])
        self.assertTrue(classifications["luna_fit"])
        candidate = self.candidate(authority)
        self.assertIn("bounded-semantic-readonly-fit", candidate["inclusion_reasons"])
        self.assertIn("fresh-context-window-covers-estimate", candidate["inclusion_reasons"])
        self.assertNotIn("remaining_input_tokens", luna_record(authority))
        self.assertNotIn("allocation_ceiling", route["aggregate_budget"])
        self.assertNotIn("terminal_reserve", route["aggregate_budget"])
        self.schema_check(route)
        self.assertEqual(routing.validate_operative_route_for_model(route, routing.LUNA_MODEL,
            current_authority=authority, now=NOW), [])
        fit_inputs = dict(authority["fit_inputs"])
        fit_inputs.pop("cache_profile")
        self.assertEqual(routing.validate_task_selected_fit(route["fit_evidence"], **fit_inputs), [])

    def test_maintenance_budget_is_value_preserving_and_has_no_mission_ceiling(self):
        authority = maintenance_authority()
        budget = authority["fit_inputs"]["aggregate_budget"]
        budget["cumulative_before"] = 10 ** 50
        before = copy.deepcopy(budget)
        result = routing._normalize_current_budget(budget)
        self.assertEqual(result, before)
        self.assertIsNot(result, budget)
        self.assertIsNot(result["reservation"], budget["reservation"])
        self.assertTrue(self.route(authority)["dispatch_authorized"])
        self.assertEqual(budget, before)

    def test_budget_union_rejects_malformed_mixed_and_coerced_fields(self):
        changes = [(key, value) for key, values in {
            "mode": ("unbounded", True, None), "mission_id": ("", " x", [], None),
            "operation_id": ("", "x ", 7), "mission_sha256": ("g" * 64, "a" * 63, " " + "a" * 64),
            "cumulative_before": (True, -1, 0.0, "0"), "budget_reset_allowed": (True, 0, None),
            "reservation": (None, [], False), "allocation_ceiling": (999,),
            "terminal_reserve": (0,), "allocation_before": (27,), "operation_sha256": ("b" * 64,),
        }.items() for value in values]
        for key, value in changes:
            with self.subTest(key=key, value=value):
                authority = maintenance_authority()
                authority["fit_inputs"]["aggregate_budget"][key] = value
                with self.assertRaises(ValueError):
                    routing._normalize_current_budget(authority["fit_inputs"]["aggregate_budget"])
                route = self.route(authority)
                self.assertFalse(route["dispatch_authorized"])
                self.assertIsNone(route["aggregate_budget"])
                self.schema_check(route)
        for key in maintenance_budget():
            with self.subTest(missing=key):
                budget = maintenance_budget(); del budget[key]
                with self.assertRaises(ValueError):
                    routing._normalize_current_budget(budget)

    def test_reservations_are_finite_positive_strict_and_closed(self):
        for key in maintenance_budget()["reservation"]:
            for value in (None, True, 0, -1, 1.0, "1"):
                with self.subTest(key=key, value=value):
                    budget = maintenance_budget(); budget["reservation"][key] = value
                    with self.assertRaises(ValueError):
                        routing._normalize_current_budget(budget)
        for changes in ({"extra": 1}, {"mode": "unbounded"}, {"max_concurrency": 4},
                        {"sessions": 1, "max_concurrency": 2}):
            budget = maintenance_budget(); budget["reservation"].update(changes)
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                routing._normalize_current_budget(budget)

    def test_serialized_budget_union_remains_closed_in_both_validators(self):
        try:
            import jsonschema
        except ImportError:
            jsonschema = None
        schema = json.loads((ROOT / "schemas/operative-routing-state.schema.json").read_text())
        for budget in (
            dict(maintenance_budget(), allocation_ceiling=999),
            dict(maintenance_budget(), cumulative_before=True),
            dict(maintenance_budget(), budget_reset_allowed=0),
            dict(maintenance_budget(), reservation={"mode": "finite-operation"}),
            dict(synthetic_authority()["fit_inputs"]["aggregate_budget"], mission_id="mixed"),
        ):
            route = self.route(maintenance_authority())
            route["aggregate_budget"] = budget
            route["route_sha256"] = routing._canonical_sha256({k: v for k, v in route.items() if k != "route_sha256"})
            self.assertTrue(routing.validate_task_selected_route_shape(route))
            if jsonschema is not None:
                self.assertTrue(list(jsonschema.Draft202012Validator(schema).iter_errors(route)))

    def test_operation_runtime_and_tool_reservation_boundaries(self):
        for field, estimate in (("tool_calls", "tool_calls_p90"), ("runtime_seconds", "runtime_seconds_p90")):
            authority = maintenance_authority()
            required = authority["fit_inputs"]["work_estimate"]["estimates"][estimate]
            authority["fit_inputs"]["aggregate_budget"]["reservation"][field] = required
            self.assertTrue(self.candidate(authority)["eligible"])
            authority["fit_inputs"]["aggregate_budget"]["reservation"][field] = required - 1
            self.assert_fit_denied(authority, "aggregate-budget-insufficient")

    def test_context_window_boundary_accounts_for_output_not_unknown_account_quota(self):
        authority = maintenance_authority(); record = luna_record(authority)
        needed = authority["fit_inputs"]["work_estimate"]["estimates"]["context_tokens_p90"]
        record["context_headroom"]["reserved_output_tokens"] = 32_000 - needed
        # Account percentages and credits remain telemetry; never a token count.
        record["quota_observation"] = {"used_percent": 22, "credits": {"has_credits": True}}
        self.assertTrue(self.candidate(authority)["headroom_sufficient"])
        record["context_headroom"]["reserved_output_tokens"] += 1
        self.assert_fit_denied(authority, "model-headroom-insufficient")

    def test_headroom_requires_exact_complete_unambiguous_shapes(self):
        for field in ("context_headroom", "context_window_source"):
            for value in (None, [], True, {}, "unknown"):
                with self.subTest(field=field, value=value):
                    authority = maintenance_authority(); luna_record(authority)[field] = value
                    self.assert_fit_denied(authority, "model-headroom-insufficient")
            for key in luna_record(maintenance_authority())[field]:
                authority = maintenance_authority(); del luna_record(authority)[field][key]
                with self.subTest(field=field, missing=key):
                    self.assert_fit_denied(authority, "model-headroom-insufficient")
            authority = maintenance_authority(); luna_record(authority)[field]["extra"] = True
            self.assert_fit_denied(authority, "model-headroom-insufficient")
        for value in (None, 999_999):
            authority = maintenance_authority(); luna_record(authority)["remaining_input_tokens"] = value
            self.assert_fit_denied(authority, "model-headroom-insufficient")

    def test_headroom_integer_types_and_source_pin_are_not_coerced(self):
        for object_name, key in (("context_headroom", "context_window_tokens"),
                                 ("context_headroom", "reserved_output_tokens"),
                                 ("context_window_source", "context_window_tokens")):
            for value in (True, False, 0, -1, 32_000.0, "32000"):
                with self.subTest(object=object_name, key=key, value=value):
                    authority = maintenance_authority(); luna_record(authority)[object_name][key] = value
                    self.assert_fit_denied(authority, "model-headroom-insufficient")
        for key, value in (("basis", "remaining-account-tokens"), ("source_sha256", "b" * 64),
                           ("source_sha256", True), ("source_sha256", None)):
            authority = maintenance_authority(); luna_record(authority)["context_headroom"][key] = value
            self.assert_fit_denied(authority, "model-headroom-insufficient")

    def test_context_source_exact_model_trust_freshness_and_capacity_must_join(self):
        changes = (("model", routing.TERRA_MODEL), ("source", "worker-asserted"),
                   ("observed_at", "2026-09-03T18:14:59Z"),
                   ("observed_at", "2026-09-03T19:15:01Z"),
                   ("observed_at", "not-a-time"), ("model", " " + routing.LUNA_MODEL),
                   ("context_window_tokens", 99_999))
        for key, value in changes:
            with self.subTest(key=key, value=value):
                authority = maintenance_authority(); record = luna_record(authority)
                record["context_window_source"][key] = value
                # Even resealing cannot fix a semantic identity/freshness mismatch.
                record["context_headroom"]["source_sha256"] = routing._canonical_sha256(record["context_window_source"])
                self.assert_fit_denied(authority, "model-headroom-insufficient")

    def test_context_source_mutation_invalidates_previous_sealed_fit(self):
        authority = maintenance_authority(); fit = self.fit(authority)
        record = luna_record(authority)
        record["context_window_source"]["context_window_tokens"] += 1
        record["context_headroom"]["context_window_tokens"] += 1
        record["context_headroom"]["source_sha256"] = routing._canonical_sha256(record["context_window_source"])
        inputs = dict(authority["fit_inputs"]); inputs.pop("cache_profile")
        self.assertTrue(routing.validate_task_selected_fit(fit, **inputs))

    def test_unbounded_mission_does_not_bypass_quota_capacity_or_controls(self):
        for key, value, reason in (("quota_status", "exhausted", "model-quota-not-usable"),
                                   ("quota_status", "unknown", "model-quota-not-usable"),
                                   ("capacity_status", "unavailable", "model-capacity-not-available"),
                                   ("workspace_enforced", False, "required-operative-controls-missing")):
            authority = maintenance_authority(); luna_record(authority)[key] = value
            self.assert_fit_denied(authority, reason)

    def test_bounded_semantic_readonly_exact_limits_remain_semantic(self):
        raw = semantic_review()
        raw["context_manifest"] += [dict(raw["context_manifest"][0], path=f"context/{i}.py") for i in range(9, 12)]
        raw["task_profile"]["read_context_count"] = 12
        raw["semantic_estimate"].update(expected_context_reads=12, read_to_mutation_ratio=12)
        raw["estimates"].update(tool_calls_p90=12, runtime_seconds_p90=300)
        for observer in ("pm_estimate", "domain_expert_estimate"):
            raw[observer].update(tool_calls_p90=12, runtime_seconds_p90=300)
        authority = maintenance_authority(); authority["fit_inputs"]["work_estimate"] = evaluate_work_estimate(raw)
        fit = self.fit(authority)
        self.assertTrue(fit["classifications"]["bounded_semantic_readonly"])
        self.assertFalse(fit["classifications"]["deterministic"])
        self.assertTrue(self.route(authority)["dispatch_authorized"])

    def test_semantic_readonly_over_tool_or_time_limit_is_not_luna_fit(self):
        for key, value in (("tool_calls_p90", 13), ("runtime_seconds_p90", 301)):
            authority = maintenance_authority(); raw = semantic_review(); raw["estimates"][key] = value
            for observer in ("pm_estimate", "domain_expert_estimate"):
                raw[observer][key] = value
            authority["fit_inputs"]["work_estimate"] = evaluate_work_estimate(raw)
            self.assertEqual(authority["fit_inputs"]["work_estimate"]["fit_mode"], "semantic")
            self.assertTrue(self.fit(authority)["classifications"]["work_route_eligible"])
            self.assert_fit_denied(authority, "luna-fit-required")

    def test_thirteen_reads_and_unresolved_authority_are_not_relabelled(self):
        for kind in ("reads", "unresolved"):
            raw = semantic_review()
            if kind == "reads":
                raw["context_manifest"] += [dict(raw["context_manifest"][0], path=f"context/{i}.py") for i in range(9, 13)]
                raw["task_profile"]["read_context_count"] = 13
                raw["semantic_estimate"].update(expected_context_reads=13, read_to_mutation_ratio=13)
            else:
                raw["unresolved_decisions"] = ["Synthetic unresolved authority decision"]
            authority = maintenance_authority(); authority["fit_inputs"]["work_estimate"] = evaluate_work_estimate(raw)
            self.assert_fit_denied(authority, "work-estimate-not-operative-route")

    def test_mutation_contradiction_unsafe_argv_and_changed_behavior_are_denied(self):
        cases = []
        raw = semantic_review(); raw["semantic_estimate"]["expected_mutations"] = 1; cases.append(raw)
        raw = semantic_review(); raw["task_profile"].update(command_count=1,
            commands=[{"argv": ["git", "diff", "--output", "unsafe"]}]); cases.append(raw)
        for key in ("estimated_diff_p90", "behavioral_changes", "state_machine_changes", "schema_changes"):
            raw = semantic_review(); raw["semantic_estimate"][key] = 1; cases.append(raw)
        for raw in cases:
            authority = maintenance_authority(); authority["fit_inputs"]["work_estimate"] = evaluate_work_estimate(raw)
            self.assert_fit_denied(authority, "luna-fit-required")

    def test_complexity_and_live_control_risk_do_not_gain_luna_fit(self):
        for key, value in (("command_complexity", 2), ("test_construction_complexity", 2),
                           ("self_hosting_risk", 3), ("live_control_risk", 3)):
            authority = maintenance_authority(); raw = semantic_review(); raw["semantic_estimate"][key] = value
            authority["fit_inputs"]["work_estimate"] = evaluate_work_estimate(raw)
            self.assert_fit_denied(authority, "luna-fit-required")

    def test_malformed_or_tampered_work_estimate_is_not_accepted(self):
        for key, value in (("fit_mode", "deterministic"), ("route", "architect"),
                           ("write_paths", ["unexpected.py"])):
            authority = maintenance_authority(); authority["fit_inputs"]["work_estimate"][key] = value
            with self.assertRaises(ValueError):
                self.fit(authority)
        raw = semantic_review(); raw["estimates"]["tool_calls_p90"] = True
        with self.assertRaises(ValueError):
            evaluate_work_estimate(raw)

    def test_rule_disable_is_bound_by_policy_hash_and_preserves_semantic_value(self):
        authority = maintenance_authority(); previous = self.fit(authority)["policy_sha256"]
        self.native["task_selected_routing"]["bounded_semantic_readonly"]["enabled"] = False
        fit = self.fit(authority)
        self.assertNotEqual(previous, fit["policy_sha256"])
        self.assertFalse(fit["classifications"]["bounded_semantic_readonly"])
        self.assertFalse(fit["classifications"]["deterministic"])
        self.assert_fit_denied(authority, "luna-fit-required")

    def test_rule_shape_types_and_semantic_identity_are_closed(self):
        original = copy.deepcopy(self.native["task_selected_routing"]["bounded_semantic_readonly"])
        for key, value in (("enabled", 1), ("max_tool_calls_p90", True), ("max_runtime_seconds_p90", 0),
                           ("command_complexity_max", 1.0), ("required_fit_mode", "deterministic"),
                           ("task_class", "implementation"), ("extra", True)):
            with self.subTest(key=key, value=value):
                self.native["task_selected_routing"]["bounded_semantic_readonly"] = dict(original, **{key: value})
                with self.assertRaises(ValueError):
                    self.fit(maintenance_authority())

    def test_only_current_selected_model_qualification_can_authorize(self):
        for kind in ("missing", "expired", "wrong-model", "wrong-identity"):
            authority = maintenance_authority(); qualification = authority["qualifications"][routing.LUNA_MODEL]
            if kind == "missing": authority["qualifications"][routing.LUNA_MODEL] = None
            if kind == "expired": qualification["origin_expires_at"] = NOW
            if kind == "wrong-model": qualification["model"] = routing.TERRA_MODEL
            if kind == "wrong-identity": qualification["host_provenance_sha256"] = "9" * 64
            with self.subTest(kind=kind):
                self.assertFalse(self.route(authority)["dispatch_authorized"])
        authority = maintenance_authority(); authority["qualifications"][routing.TERRA_MODEL] = None
        self.assertTrue(self.route(authority)["dispatch_authorized"])
        route = self.route(authority)
        self.assertTrue(routing.validate_operative_route_for_model(route, routing.LUNA_MODEL,
            current_authority=authority, now=authority["qualifications"][routing.LUNA_MODEL]["origin_expires_at"]))

    def test_inactive_or_nonfresh_attempt_cannot_dispatch(self):
        for key, value in (("attempt_state", "stopped"), ("attempt.fresh_segment", False)):
            authority = maintenance_authority()
            if key.startswith("attempt."): authority["attempt"]["fresh_segment"] = value
            else: authority[key] = value
            self.assertFalse(self.route(authority)["dispatch_authorized"])
        self.native["task_selected_routing"]["activation"]["active"] = False
        self.assertFalse(self.route(maintenance_authority())["dispatch_authorized"])

    def test_changed_scope_budget_or_context_evidence_cannot_replay_a_route(self):
        for field in ("mission_sha256", "operation_id", "cumulative_before", "reservation"):
            authority = maintenance_authority(); route = self.route(authority)
            budget = authority["fit_inputs"]["aggregate_budget"]
            if field == "mission_sha256": budget[field] = "9" * 64
            if field == "operation_id": budget[field] = "synthetic-other-operation"
            if field == "cumulative_before": budget[field] += 1
            if field == "reservation": budget[field]["tool_calls"] += 1
            with self.subTest(field=field):
                self.assertTrue(routing.validate_operative_route_for_model(route, routing.LUNA_MODEL,
                    current_authority=authority, now=NOW))

    def test_finite_normalization_and_headroom_values_remain_unchanged(self):
        authority = synthetic_authority(); budget = authority["fit_inputs"]["aggregate_budget"]
        self.assertEqual(routing._normalize_current_budget(budget), budget)
        route = self.route(authority)
        self.assertTrue(route["dispatch_authorized"])
        self.schema_check(route)
        self.assertEqual(route["aggregate_budget"], budget)
        record = luna_record(authority)
        required = authority["fit_inputs"]["work_estimate"]["estimates"]["context_tokens_p90"]
        record["remaining_input_tokens"] = required
        self.assertTrue(self.candidate(authority)["headroom_sufficient"])
        record["remaining_input_tokens"] -= 1
        self.assert_fit_denied(authority, "model-headroom-insufficient")
        for key, value in (("mode", "maintenance-unbounded"), ("allocation_before", True),
                           ("allocation_ceiling", 0), ("terminal_reserve", -1), ("budget_reset_allowed", 0)):
            changed = dict(budget, **{key: value})
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                routing._normalize_current_budget(changed)

    def test_existing_finite_terminal_reserve_boundary_still_denies_final_gate(self):
        authority = synthetic_authority(); budget = authority["fit_inputs"]["aggregate_budget"]
        budget["allocation_before"] = budget["allocation_ceiling"] - budget["terminal_reserve"] - 1
        self.schema_check(self.route(authority))
        for delta in (1, 2):
            current = copy.deepcopy(authority); current["fit_inputs"]["aggregate_budget"]["allocation_before"] += delta
            route = self.route(current)
            self.assertIn("aggregate_budget leaves no protected terminal allocation",
                          routing.validate_task_selected_route_shape(route))
            self.assertTrue(routing.validate_operative_route_for_model(route, routing.LUNA_MODEL,
                current_authority=current, now=NOW))

    def test_historical_v2_classification_and_budget_are_not_reinterpreted(self):
        work = evaluate_work_estimate(semantic_review())
        profile = cache_profile(total=8000, stable=4000)
        old = routing._classify_fit(work, profile, self.native["operative_routing"], NOW)
        self.assertFalse(old["deterministic"])
        self.assertFalse(old["luna_fit"])
        self.assertNotIn("bounded_semantic_readonly", old)
        self.assertTrue(routing._aggregate_budget_covers(work, BUDGET))
        self.assertFalse(routing._aggregate_budget_covers(work, maintenance_budget()))
        self.native["task_selected_routing"]["status"] = "inactive-prospective"
        self.native["task_selected_routing"]["activation"].update(active=False, dispatch_authority=False)
        route = routing.resolve_operative_route(capability_evidence=capability_evidence(), evaluated_at=NOW)
        self.assertEqual(route["version"], 2)
        self.assertEqual(routing.validate_operative_route_for_model(route, routing.SPARK_MODEL,
            now=NOW, historical_parse=True), [])
        self.native["task_selected_routing"]["status"] = "active"
        self.assertTrue(routing.validate_operative_route_for_model(route, routing.SPARK_MODEL, now=NOW))
        self.assertEqual(routing.validate_operative_route_for_model(route, routing.SPARK_MODEL,
            now=NOW, historical_parse=True), [])


if __name__ == "__main__":
    unittest.main()
