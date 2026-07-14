import copy
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from prepare_native_worker import (
    _render_prompt,
    build_native_worker_packet,
    validate_native_worker_packet,
)
from cwo_core.work_sizing import (
    canonical_work_estimate_sha256,
    evaluate_work_estimate,
    normalize_worker_commitment_response,
)

PATHS = ["tests/test_native_worker_planning.py"]

CHECKS = [
    "python -m unittest tests.test_native_worker_planning -v",
    "python -m compileall tests/test_native_worker_planning.py scripts/prepare_native_worker.py",
    "git diff --check",
]

BUDGET = {
    "tool_calls_soft": 12,
    "tool_calls_hard": 16,
    "runtime_seconds_soft": 120,
    "runtime_seconds_hard": 249,
    "max_compactions": 0,
    "max_full_suite_runs": 0,
}


def draft() -> dict:
    return build_native_worker_packet(
        bead_id="bead-plan",
        lane="implementation",
        workdir=str(ROOT),
        allowed_paths=PATHS,
        acceptance_checks=CHECKS,
        budget_overrides=BUDGET,
        requested_model="gpt-5.3-codex-spark",
    )


def plan() -> dict:
    raw = {
        "estimate_type": "cwo-native-work-estimate",
        "version": 1,
        "work_unit_id": "wu-native-worker-planning",
        "bead_id": "bead-plan",
        "requested_model": "gpt-5.3-codex-spark",
        "primary_outcome": "build dispatch-ready native worker planning packet with aligned estimate metadata",
        "expected_artifacts": ["ticket", "packet", "estimate"],
        "expert_profiles": ["architect", "engineer", "planner"],
        "frozen_decisions": [],
        "unresolved_decisions": [],
        "subsystems": ["native_worker", "validation"],
        "write_paths": PATHS,
        "context_manifest": [],
        "acceptance_checks": CHECKS,
        "estimates": {
            "tool_calls_p50": 3,
            "tool_calls_p90": 4,
            "runtime_seconds_p50": 4,
            "runtime_seconds_p90": 9,
            "context_tokens_p90": 1000,
        },
        "scores": {
            "reasoning_uncertainty": 0,
            "subsystem_coupling": 1,
            "contract_risk": 1,
            "diagnostic_uncertainty": 0,
            "context_breadth": 1,
            "validation_breadth": 1,
        },
        "estimate_contract_version": 2,
        "semantic_estimate": {
            "estimated_diff_p50": 20, "estimated_diff_p90": 60, "behavioral_changes": 1,
            "state_machine_changes": 0, "schema_changes": 0, "self_hosting_risk": 1,
            "live_control_risk": 1, "contract_surfaces": 1, "cli_surfaces": 0,
            "policy_surfaces": 0, "telemetry_surfaces": 0, "expected_regressions": 3,
            "test_construction_complexity": 1, "command_complexity": 1, "nested_quote_layers": 1,
            "expected_context_reads": 1, "expected_mutations": 1, "read_to_mutation_ratio": 1,
        },
        "pm_estimate": {"tool_calls_p50": 3, "tool_calls_p90": 4, "runtime_seconds_p50": 4, "runtime_seconds_p90": 9},
        "domain_expert_estimate": {"tool_calls_p50": 3, "tool_calls_p90": 4, "runtime_seconds_p50": 4, "runtime_seconds_p90": 9},
    }
    return evaluate_work_estimate(raw)


def commitment(plan: dict, decision: str = "accept") -> dict:
    return {
        "commitment_type": "cwo-native-worker-fit-commitment",
        "version": 1,
        "work_unit_id": plan["work_unit_id"],
        "bead_id": plan["bead_id"],
        "requested_model": plan["requested_model"],
        "session_id": "session-native-worker-planning",
        "attestation_source": "trusted-session-jsonl",
        "attested_model": plan["requested_model"],
        "work_estimate_sha256": canonical_work_estimate_sha256(plan),
        "decision": decision,
        "confidence": 0.91,
        "estimates": {
            "tool_calls_p50": 3,
            "tool_calls_p90": 4,
            "runtime_seconds_p50": 4,
            "runtime_seconds_p90": 9,
        },
        "tool_calls_before_commitment": 0,
        "context_compactions_before_commitment": 0,
        "reason": "focused packet planning and estimate completion",
    }


def planned(decision: str = "accept", budget: dict = None) -> dict:
    budget = BUDGET if budget is None else budget
    p = plan()
    c = commitment(p, decision=decision)
    return build_native_worker_packet(
        bead_id="bead-plan",
        lane="implementation",
        workdir=str(ROOT),
        allowed_paths=PATHS,
        acceptance_checks=CHECKS,
        work_plan=p,
        worker_commitment=c,
        budget_overrides=budget,
        requested_model="gpt-5.3-codex-spark",
    )


def _contains(errors, text):
    lowered = text.lower()
    return any(lowered in err.lower() for err in errors)


class TestNativeWorkerPlanning(unittest.TestCase):
    def test_draft_validation_modes(self):
        non_dispatch_errors = validate_native_worker_packet(draft(), dispatchable=False)
        self.assertEqual(non_dispatch_errors, [])

        dispatchable_errors = validate_native_worker_packet(draft(), dispatchable=True)
        self.assertNotEqual(dispatchable_errors, [])
        self.assertTrue(
            _contains(dispatchable_errors, "dispatchable packet requires work_plan and worker_commitment")
        )

    def test_build_with_exactly_one_planning_arg_fails(self):
        with self.assertRaises(SystemExit):
            build_native_worker_packet(
                bead_id="bead-plan",
                lane="implementation",
                workdir=str(ROOT),
                allowed_paths=PATHS,
                acceptance_checks=CHECKS,
                budget_overrides=BUDGET,
                requested_model="gpt-5.3-codex-spark",
                work_plan=plan(),
            )

        with self.assertRaises(SystemExit):
            build_native_worker_packet(
                bead_id="bead-plan",
                lane="implementation",
                workdir=str(ROOT),
                allowed_paths=PATHS,
                acceptance_checks=CHECKS,
                budget_overrides=BUDGET,
                requested_model="gpt-5.3-codex-spark",
                worker_commitment=commitment(plan()),
            )

    def test_planned_dispatchable_accept(self):
        packet = planned()
        errors = validate_native_worker_packet(packet, dispatchable=True)
        self.assertEqual(errors, [])
        self.assertEqual(packet["work_plan"]["estimate_contract_version"], 2)
        self.assertEqual(packet["work_plan"]["authority_route"], "spark")
        self.assertEqual(packet["work_plan"]["operative_route"], "spark")
        self.assertEqual(packet["command_contract"]["wrapper"], "scripts/run_checked_command.py")

    def test_deterministic_plan_builds_policy_fit_commitment_from_trusted_attestation(self):
        deterministic = plan()
        deterministic["semantic_estimate"]["estimated_diff_p90"] = 40
        deterministic["task_profile"] = {
            "task_class": "narrow-mechanical",
            "declared_outcome_count": 1,
            "command_count": 0,
            "check_count": 3,
            "focused_test_count": 2,
            "full_suite_count": 0,
            "read_context_count": 0,
            "source_mutation_count": 1,
            "commands": [],
            "source_mutation_paths": PATHS,
        }
        deterministic = evaluate_work_estimate(deterministic)
        packet = build_native_worker_packet(
            bead_id="bead-plan",
            lane="implementation",
            workdir=str(ROOT),
            allowed_paths=PATHS,
            acceptance_checks=CHECKS,
            work_plan=deterministic,
            trusted_session_id="trusted-spark-session",
            attested_model="gpt-5.3-codex-spark",
            budget_overrides={
                "tool_calls_soft": 6,
                "tool_calls_hard": 10,
                "runtime_seconds_soft": 180,
                "runtime_seconds_hard": 300,
                "max_compactions": 0,
                "max_full_suite_runs": 0,
            },
            requested_model="gpt-5.3-codex-spark",
        )
        self.assertEqual(packet["worker_commitment"]["session_id"], "trusted-spark-session")
        self.assertEqual(packet["worker_commitment"]["estimates"]["tool_calls_p90"], 6)
        self.assertEqual(validate_native_worker_packet(packet, dispatchable=True), [])

    def test_semantic_plan_cannot_skip_worker_commitment(self):
        with self.assertRaisesRegex(SystemExit, "deterministic"):
            build_native_worker_packet(
                bead_id="bead-plan",
                lane="implementation",
                workdir=str(ROOT),
                allowed_paths=PATHS,
                acceptance_checks=CHECKS,
                work_plan=plan(),
                trusted_session_id="trusted-spark-session",
                attested_model="gpt-5.3-codex-spark",
                budget_overrides=BUDGET,
                requested_model="gpt-5.3-codex-spark",
            )

    def test_read_only_plan_separates_context_scope_from_write_scope(self):
        read_only = plan()
        read_only["write_paths"] = []
        read_only["context_manifest"] = [
            {"path": PATHS[0], "selector": "file", "purpose": "validation", "bytes": 1, "sha256": "0" * 64}
        ]
        read_only["semantic_estimate"].update(
            {
                "estimated_diff_p50": 0,
                "estimated_diff_p90": 0,
                "expected_context_reads": 1,
                "expected_mutations": 0,
                "read_to_mutation_ratio": 1,
            }
        )
        read_only["task_profile"] = {
            "task_class": "read-only-validation",
            "declared_outcome_count": 1,
            "command_count": 3,
            "check_count": 3,
            "focused_test_count": 1,
            "full_suite_count": 0,
            "read_context_count": 1,
            "source_mutation_count": 0,
            "commands": [
                {"argv": ["python3", "-m", "unittest", "tests.test_native_worker_planning", "-v"]},
                {"argv": ["python3", "-m", "compileall", "scripts/prepare_native_worker.py"]},
                {"argv": ["git", "diff", "--check"]},
            ],
            "source_mutation_paths": [],
        }
        read_only = evaluate_work_estimate(read_only)
        packet = build_native_worker_packet(
            bead_id="bead-plan",
            lane="validation",
            workdir=str(ROOT),
            allowed_paths=PATHS,
            acceptance_checks=CHECKS,
            work_plan=read_only,
            trusted_session_id="trusted-spark-session",
            attested_model="gpt-5.3-codex-spark",
            budget_overrides={
                "tool_calls_soft": 4,
                "tool_calls_hard": 8,
                "runtime_seconds_soft": 300,
                "runtime_seconds_hard": 600,
                "max_compactions": 0,
                "max_full_suite_runs": 0,
            },
        )
        self.assertEqual(packet["work_plan"]["write_paths"], [])
        self.assertEqual(packet["scope"]["allowed_paths"], PATHS)
        self.assertNotIn("edit-scoped-files", packet["scope"]["allowed_actions"])
        self.assertIn("source-mutation", packet["scope"]["prohibited_actions"])
        self.assertEqual(validate_native_worker_packet(packet, dispatchable=True), [])

        rendered = _render_prompt(packet)
        self.assertIn("Deterministic execution contract:", rendered)
        self.assertIn("The first tool call must execute command 1", rendered)
        self.assertIn("Do not acknowledge first, inspect helpers or source, run --help", rendered)
        self.assertIn("No exploratory tool calls are permitted", rendered)
        self.assertIn("1. python3 -m unittest tests.test_native_worker_planning -v", rendered)
        self.assertNotIn("- Wrapper: scripts/run_checked_command.py", rendered)
        self.assertNotIn("build wrapper specifications.\n- Wrapper:", rendered)
        self.assertIn('"files_touched": []', rendered)
        self.assertIn('"mutation_state": "clean"', rendered)

    def test_planned_non_dispatch_for_realignments_and_dispatchable_decision_message(self):
        for decision in ["pm-realignment", "architect-realignment"]:
            p = planned(decision=decision)
            non_dispatch_errors = validate_native_worker_packet(p, dispatchable=False)
            self.assertEqual(non_dispatch_errors, [])

            dispatchable_errors = validate_native_worker_packet(p, dispatchable=True)
            self.assertNotEqual(dispatchable_errors, [])
            self.assertTrue(_contains(dispatchable_errors, "dispatchable decision"))

    def test_tampered_commitment_hash_and_binding_errors(self):
        packet = planned()

        tampered = copy.deepcopy(packet)
        tampered["worker_commitment"]["work_estimate_sha256"] = "0" * 64
        self.assertTrue(
            any(
                "work_estimate_sha256" in err.lower() or "hash" in err.lower()
                for err in validate_native_worker_packet(tampered, dispatchable=True)
            )
        )

        binding = copy.deepcopy(packet)
        binding["bead_id"] = "different-bead"
        binding["worker_commitment"]["bead_id"] = "different-bead"
        binding["requested_model"] = "different-model"
        binding["worker_commitment"]["attested_model"] = "different-model"
        binding["scope"]["allowed_paths"] = ["other/path"]
        binding["acceptance_checks"] = [
            "python -m unittest tests.test_native_worker_planning -q"
        ]
        binding_errors = validate_native_worker_packet(binding, dispatchable=True)
        self.assertTrue(binding_errors)
        for token in ("bead", "model", "path", "acceptance"):
            self.assertTrue(any(token in err.lower() for err in binding_errors))

    def test_plan_allowance_violation_tool_calls_hard(self):
        budget = dict(BUDGET)
        budget["tool_calls_hard"] = 17
        errors = validate_native_worker_packet(
            planned(decision="accept", budget=budget), dispatchable=True
        )
        self.assertTrue(_contains(errors, "aggregate allowance"))

    def test_planned_route_is_spark_only(self):
        route_packet = copy.deepcopy(planned())
        route_work_plan = copy.deepcopy(route_packet["work_plan"])
        route_work_plan["scores"]["reasoning_uncertainty"] = 3
        for key in ("score_total", "route", "hard_gate_reasons", "aggregate_allowance"):
            route_work_plan.pop(key, None)
        route_packet["work_plan"] = evaluate_work_estimate(route_work_plan)
        route_packet["worker_commitment"]["work_estimate_sha256"] = canonical_work_estimate_sha256(
            route_packet["work_plan"]
        )
        route_errors = validate_native_worker_packet(route_packet, dispatchable=True)
        self.assertTrue(_contains(route_errors, "work_plan.route"))

    def test_commitment_normalizer_accepts_mapping_alias_once(self):
        p = plan()
        raw = commitment(p)
        raw["decision"] = "proceed"
        result = normalize_worker_commitment_response(
            raw,
            p,
            session_id=raw["session_id"],
            attested_model=raw["attested_model"],
        )
        self.assertEqual(result["outcome"], "normalized")
        self.assertEqual(result["decision"], "accept")
        self.assertFalse(result["model_retry_allowed"])

    def test_commitment_normalizer_accepts_json_and_estimate_aliases(self):
        import json

        p = plan()
        raw = commitment(p)
        raw["estimates"] = {
            "calls_p50": 3,
            "calls_p90": 4,
            "runtime_p50": 4,
            "runtime_p90": 9,
        }
        result = normalize_worker_commitment_response(
            json.dumps(raw),
            p,
            session_id=raw["session_id"],
            attested_model=raw["attested_model"],
        )
        self.assertEqual(result["outcome"], "normalized")
        self.assertEqual(
            set(result["normalized_commitment"]["estimates"]),
            {"tool_calls_p50", "tool_calls_p90", "runtime_seconds_p50", "runtime_seconds_p90"},
        )

    def test_commitment_normalizer_accepts_complete_plain_text(self):
        p = plan()
        result = normalize_worker_commitment_response(
            "proceed tool_calls_p50=3 tool_calls_p90=4 runtime_seconds_p50=4 "
            "runtime_seconds_p90=9 confidence=0.91",
            p,
            session_id="session-native-worker-planning",
            attested_model=p["requested_model"],
        )
        self.assertEqual(result["outcome"], "normalized")
        self.assertEqual(result["decision"], "accept")

    def test_commitment_normalizer_realigns_missing_quantiles_without_retry(self):
        p = plan()
        result = normalize_worker_commitment_response(
            "proceed tool_calls_p50=3 confidence=0.91",
            p,
            session_id="session-native-worker-planning",
            attested_model=p["requested_model"],
        )
        self.assertEqual(result["outcome"], "pm-realignment")
        self.assertIsNone(result["normalized_commitment"])
        self.assertFalse(result["model_retry_allowed"])

    def test_commitment_normalizer_realigns_mixed_decisions(self):
        p = plan()
        result = normalize_worker_commitment_response(
            "proceed refine tool_calls_p50=3 tool_calls_p90=4 runtime_seconds_p50=4 "
            "runtime_seconds_p90=9 confidence=0.91",
            p,
            session_id="session-native-worker-planning",
            attested_model=p["requested_model"],
        )
        self.assertEqual(result["outcome"], "pm-realignment")
        self.assertTrue(_contains(result["errors"], "ambiguous"))

    def test_commitment_normalizer_rejects_trusted_identity_contradiction(self):
        p = plan()
        raw = commitment(p)
        raw["requested_model"] = "wrong-model"
        result = normalize_worker_commitment_response(
            raw,
            p,
            session_id=raw["session_id"],
            attested_model=p["requested_model"],
        )
        self.assertEqual(result["outcome"], "pm-realignment")
        self.assertTrue(_contains(result["errors"], "contradicts trusted"))

    def test_commitment_normalizer_realigns_low_confidence(self):
        p = plan()
        raw = commitment(p)
        raw["confidence"] = 0.0
        result = normalize_worker_commitment_response(
            raw,
            p,
            session_id=raw["session_id"],
            attested_model=raw["attested_model"],
        )
        self.assertEqual(result["outcome"], "pm-realignment")
        self.assertTrue(_contains(result["errors"], "confidence"))
