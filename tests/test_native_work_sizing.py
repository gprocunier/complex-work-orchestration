from __future__ import annotations

import copy
import json
import sys
import tempfile
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import cwo_core.work_sizing as work_sizing  # noqa: E402

from cwo_core.work_sizing import DIMENSIONS, evaluate_work_estimate, validate_work_estimate  # noqa: E402
from cwo_core.work_sizing import (  # noqa: E402
    build_policy_fit_commitment,
    canonical_work_estimate_sha256,
    validate_worker_commitment,
)


def _valid_raw_payload():
    return {
        "estimate_type": "cwo-native-work-estimate",
        "version": 1,
        "work_unit_id": "wu-native-1",
        "bead_id": "bead-native-1",
        "requested_model": "gpt-5.3-codex-spark",
        "primary_outcome": "native-operator completion",
        "expected_artifacts": ["implementation.patch", "validation.report"],
        "expert_profiles": ["orchestrator", "architect", "qa"],
        "frozen_decisions": ["no-regression", "no-shortcuts"],
        "unresolved_decisions": [],
        "subsystems": ["routing", "policy"],
        "write_paths": ["scripts/cwo_core/a.py"],
        "context_manifest": [
            {
                "path": "schemas/native-work-estimate.schema.json",
                "selector": "schemas/native-work-estimate.schema.json",
                "purpose": "validation",
                "bytes": 512,
                "sha256": "0" * 64,
            }
        ],
        "acceptance_checks": ["unit", "lint", "jsonschema"],
        "estimates": {
            "tool_calls_p50": 4,
            "tool_calls_p90": 10,
            "runtime_seconds_p50": 40,
            "runtime_seconds_p90": 120,
            "context_tokens_p90": 2000,
        },
        "scores": {
            "reasoning_uncertainty": 1,
            "subsystem_coupling": 1,
            "contract_risk": 1,
            "diagnostic_uncertainty": 1,
            "context_breadth": 1,
            "validation_breadth": 1,
        },
    }


def _v2_policy():
    policy = json.loads((ROOT / "policy" / "native-worker-execution.yaml").read_text(encoding="utf-8"))
    foundation = policy["work_sizing"]["enforcement"]["foundation-canary"]
    foundation["semantic_routing"] = {
        "max_diff_p90_for_spark": 350,
        "max_behavioral_changes_for_spark": 5,
        "max_expected_regressions_for_spark": 12,
        "max_write_paths_for_spark": 6,
        "max_context_reads_for_spark": 12,
        "max_read_mutation_ratio_for_spark": 6,
        "max_tool_calls_p90": 25,
        "max_runtime_seconds_p90": 480,
        "variance_thresholds": {
            "pm_tool_calls_p90_delta": 8,
            "pm_runtime_seconds_p90_delta": 90,
            "domain_tool_calls_p90_delta": 8,
            "domain_runtime_seconds_p90_delta": 90,
        },
    }
    return policy


def _valid_v2_payload():
    payload = _valid_raw_payload()
    payload["scores"] = {dimension: 0 for dimension in DIMENSIONS}
    payload["estimate_contract_version"] = 2
    payload["semantic_estimate"] = {
        "estimated_diff_p50": 40,
        "estimated_diff_p90": 80,
        "behavioral_changes": 0,
        "state_machine_changes": 0,
        "schema_changes": 0,
        "self_hosting_risk": 1,
        "live_control_risk": 1,
        "contract_surfaces": 1,
        "cli_surfaces": 0,
        "policy_surfaces": 0,
        "telemetry_surfaces": 0,
        "expected_regressions": 3,
        "test_construction_complexity": 1,
        "command_complexity": 1,
        "nested_quote_layers": 1,
        "expected_context_reads": 4,
        "expected_mutations": 2,
        "read_to_mutation_ratio": 2,
    }
    estimate = {
        "tool_calls_p50": payload["estimates"]["tool_calls_p50"],
        "tool_calls_p90": payload["estimates"]["tool_calls_p90"],
        "runtime_seconds_p50": payload["estimates"]["runtime_seconds_p50"],
        "runtime_seconds_p90": payload["estimates"]["runtime_seconds_p90"],
    }
    payload["pm_estimate"] = copy.deepcopy(estimate)
    payload["domain_expert_estimate"] = copy.deepcopy(estimate)
    return payload


def _literal_command_payload():
    payload = _valid_v2_payload()
    payload["subsystems"] = ["validation"]
    payload["write_paths"] = []
    payload["context_manifest"] = []
    payload["semantic_estimate"]["estimated_diff_p50"] = 0
    payload["semantic_estimate"]["estimated_diff_p90"] = 0
    payload["semantic_estimate"]["expected_context_reads"] = 0
    payload["semantic_estimate"]["expected_mutations"] = 0
    payload["semantic_estimate"]["read_to_mutation_ratio"] = 0
    payload["task_profile"] = {
        "task_class": "literal-command",
        "declared_outcome_count": 1,
        "command_count": 1,
        "check_count": 2,
        "focused_test_count": 0,
        "full_suite_count": 0,
        "read_context_count": 0,
        "source_mutation_count": 0,
        "commands": [{"argv": ["git", "status", "--short"]}],
        "source_mutation_paths": [],
    }
    return payload


def _narrow_profile_payload(path: str = "tests/test_native_work_sizing.py"):
    payload = _valid_v2_payload()
    payload["subsystems"] = ["sizing"]
    payload["write_paths"] = [path]
    payload["semantic_estimate"]["estimated_diff_p50"] = 20
    payload["semantic_estimate"]["estimated_diff_p90"] = 40
    payload["semantic_estimate"]["expected_context_reads"] = 1
    payload["semantic_estimate"]["expected_mutations"] = 1
    payload["semantic_estimate"]["read_to_mutation_ratio"] = 1
    payload["task_profile"] = {
        "task_class": "narrow-mechanical",
        "declared_outcome_count": 1,
        "command_count": 0,
        "check_count": 2,
        "focused_test_count": 2,
        "full_suite_count": 0,
        "read_context_count": 1,
        "source_mutation_count": 1,
        "commands": [],
        "source_mutation_paths": [path],
    }
    return payload


def _checked_command_spec(cwd: str, command_id: str, argv: list[str]):
    return {
        "spec_type": "cwo-checked-command-spec",
        "version": 1,
        "command_id": command_id,
        "mode": "argv",
        "argv": argv,
        "cwd": cwd,
        "env": {},
        "inherit_environment": True,
        "stdin": None,
        "source": None,
        "preflights": [],
        "mutation_intent": "none",
        "allowed_paths": [],
        "timeout_seconds": 30,
    }


def _checked_sequence_payload(cwd: str):
    payload = _narrow_profile_payload()
    commands = [["python3", "-m", "unittest", "tests.test_native_work_sizing"], ["git", "diff", "--check"]]
    payload["task_profile"].update(
        {
            "task_class": "bounded-implementation",
            "command_count": len(commands),
            "commands": [{"argv": argv} for argv in commands],
            "execution_contract": {
                "mode": "checked-sequence-v1",
                "checked_command_specs": [
                    _checked_command_spec(cwd, f"check-{idx}", argv) for idx, argv in enumerate(commands)
                ],
            },
        }
    )
    return payload


def _valid_commitment_payload(work_estimate):
    return {
        "commitment_type": "cwo-native-worker-fit-commitment",
        "version": 1,
        "work_unit_id": work_estimate["work_unit_id"],
        "bead_id": work_estimate["bead_id"],
        "requested_model": work_estimate["requested_model"],
        "session_id": "native-session-1",
        "attestation_source": "trusted-session-jsonl",
        "attested_model": work_estimate["requested_model"],
        "work_estimate_sha256": canonical_work_estimate_sha256(work_estimate),
        "decision": "accept",
        "confidence": 0.9,
        "estimates": {
            "tool_calls_p50": 2,
            "tool_calls_p90": 3,
            "runtime_seconds_p50": 10,
            "runtime_seconds_p90": 20,
        },
        "tool_calls_before_commitment": 0,
        "context_compactions_before_commitment": 0,
        "reason": "fit confirmed against trust-bound metrics",
    }


class NativeWorkSizingTest(unittest.TestCase):
    def setUp(self):
        self.maxDiff = None

    def test_route_spark_for_low_score(self):
        payload = _valid_raw_payload()
        result = evaluate_work_estimate(payload)
        self.assertEqual(result["score_total"], 6)
        self.assertEqual(result["route"], "split")

    def test_route_split_threshold(self):
        payload = _valid_raw_payload()
        payload["scores"]["reasoning_uncertainty"] = 0
        payload["scores"]["subsystem_coupling"] = 0
        payload["scores"]["contract_risk"] = 0
        payload["scores"]["diagnostic_uncertainty"] = 3
        payload["scores"]["context_breadth"] = 3
        payload["scores"]["validation_breadth"] = 0  # total 6
        result = evaluate_work_estimate(payload)
        self.assertEqual(result["score_total"], 6)
        self.assertEqual(result["route"], "split")

    def test_route_architect_total_gate(self):
        payload = _valid_raw_payload()
        payload["scores"]["reasoning_uncertainty"] = 2
        payload["scores"]["subsystem_coupling"] = 2
        payload["scores"]["contract_risk"] = 2
        payload["scores"]["diagnostic_uncertainty"] = 2
        payload["scores"]["context_breadth"] = 1
        payload["scores"]["validation_breadth"] = 1  # total 10
        result = evaluate_work_estimate(payload)
        self.assertEqual(result["route"], "architect")

    def test_route_architect_unresolved_gate(self):
        payload = _valid_raw_payload()
        payload["unresolved_decisions"] = ["decision1"]
        result = evaluate_work_estimate(payload)
        self.assertEqual(result["route"], "architect")
        self.assertIn("unresolved-decisions", result["hard_gate_reasons"])

    def test_route_architect_reasoning_uncertainty_gate(self):
        payload = _valid_raw_payload()
        payload["scores"]["reasoning_uncertainty"] = 3
        result = evaluate_work_estimate(payload)
        self.assertEqual(result["route"], "architect")
        self.assertIn("reasoning-uncertainty-architect", result["hard_gate_reasons"])

    def test_route_architect_contract_risk_gate(self):
        payload = _valid_raw_payload()
        payload["scores"]["contract_risk"] = 3
        result = evaluate_work_estimate(payload)
        self.assertEqual(result["route"], "architect")
        self.assertIn("contract-risk-architect", result["hard_gate_reasons"])

    def test_all_caps_force_split_or_architect(self):
        payload = _valid_raw_payload()
        payload["scores"] = {
            "reasoning_uncertainty": 0,
            "subsystem_coupling": 0,
            "contract_risk": 0,
            "diagnostic_uncertainty": 0,
            "context_breadth": 0,
            "validation_breadth": 0,
        }
        payload["subsystems"] = ["a", "b", "c"]
        payload["write_paths"] = [
            "a",
            "b",
            "c",
            "d",
            "e",
            "f",
            "g",
            "h",
            "i",
            "j",
        ]
        payload["context_manifest"] = [
            {"path": "a", "selector": "a", "purpose": "check", "bytes": 0, "sha256": "0" * 64}
        ] * 13
        payload["acceptance_checks"] = ["x", "y", "z", "w"]
        payload["estimates"]["context_tokens_p90"] = 96001
        payload["estimates"]["tool_calls_p90"] = 31
        payload["estimates"]["runtime_seconds_p90"] = 481
        result = evaluate_work_estimate(payload)
        self.assertEqual(result["route"], "split")
        for reason in (
            "too-many-subsystems",
            "too-many-write-paths",
            "too-many-context-entries",
            "too-many-acceptance-checks",
            "context-tokens-p90-exceeded",
            "tool-calls-p90-exceeded",
            "runtime-seconds-p90-exceeded",
        ):
            self.assertIn(reason, result["hard_gate_reasons"])

    def test_malformed_source_and_bound_checks(self):
        payload = _valid_raw_payload()
        payload["estimates"]["tool_calls_p50"] = 100
        payload["estimates"]["tool_calls_p90"] = 10
        with self.assertRaises(ValueError) as err:
            evaluate_work_estimate(payload)
        self.assertIn("estimates.tool_calls_p50 must be <= estimates.tool_calls_p90", str(err.exception))
        payload = _valid_raw_payload()
        payload["expected_artifacts"] = "not-a-list"
        with self.assertRaises(ValueError) as err:
            evaluate_work_estimate(payload)
        self.assertIn("expected_artifacts must be a list", str(err.exception))
        payload = _valid_raw_payload()
        payload["estimates"]["runtime_seconds_p50"] = 90
        payload["estimates"]["runtime_seconds_p90"] = 20
        with self.assertRaises(ValueError) as err:
            evaluate_work_estimate(payload)
        self.assertIn("runtime_seconds_p50 must be <=", str(err.exception))

    def test_validate_work_estimate_derived_mismatch(self):
        payload = _valid_raw_payload()
        payload["route"] = "architect"
        payload["hard_gate_reasons"] = []
        payload["score_total"] = 1
        payload["aggregate_allowance"] = {
            "dispatch_soft_cap": 1,
            "dispatch_soft_cap_action": "pm-architect-review",
            "continuation_authority": "pm-architect-within-aggregate-budget",
            "max_pm_replans": 1,
            "max_architect_cycles": 1,
            "max_compactions": 0,
            "tool_calls_hard": 100,
            "runtime_seconds_hard": 200,
        }
        errors = validate_work_estimate(payload)
        self.assertIn("derived check failed: score_total", errors[0])
        self.assertIn("derived check failed: route", errors[1])

    def test_deep_copy_not_mutated(self):
        payload = _valid_raw_payload()
        original = copy.deepcopy(payload)
        result = evaluate_work_estimate(payload)
        self.assertEqual(payload, original)
        self.assertNotEqual(result["route"], "")

    def test_schema_is_json_loadable(self):
        path = Path(__file__).resolve().parents[1] / "schemas" / "native-work-estimate.schema.json"
        loaded = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(loaded["$schema"], "https://json-schema.org/draft/2020-12/schema")

    def test_monolith_with_many_write_paths_not_spark(self):
        payload = _valid_raw_payload()
        payload["write_paths"] = [f"p/{i}" for i in range(30)]
        payload["scores"] = {
            "reasoning_uncertainty": 0,
            "subsystem_coupling": 0,
            "contract_risk": 0,
            "diagnostic_uncertainty": 0,
            "context_breadth": 1,
            "validation_breadth": 0,
        }  # total 1
        result = evaluate_work_estimate(payload)
        self.assertNotEqual(result["route"], "spark")

    def test_dispatch_soft_cap_advisory_and_hard_limits(self):
        payload = _valid_raw_payload()
        result = evaluate_work_estimate(payload)
        allowance = result["aggregate_allowance"]
        self.assertEqual(allowance["dispatch_soft_cap"], 3)
        self.assertEqual(allowance["dispatch_soft_cap_action"], "pm-architect-review")
        self.assertEqual(
            allowance["tool_calls_hard"],
            result["estimates"]["tool_calls_p90"] + 12,
        )
        self.assertEqual(
            allowance["runtime_seconds_hard"],
            result["estimates"]["runtime_seconds_p90"] + 240,
        )
        self.assertNotIn("dispatch_hard_cap", allowance)
        self.assertEqual(allowance["continuation_authority"], "pm-architect-within-aggregate-budget")

    def test_native_commitment_validation_accept_dispatch_modes(self):
        work_estimate = evaluate_work_estimate(_valid_raw_payload())
        commitment = _valid_commitment_payload(work_estimate)
        self.assertEqual(validate_worker_commitment(commitment, work_estimate), [])
        self.assertIn(
            "historical-inspection-only",
            " ".join(validate_worker_commitment(commitment, work_estimate, dispatchable=True)),
        )

    def test_commitment_required_alias_is_removed(self) -> None:
        self.assertFalse(hasattr(work_sizing, "COMMITMENT_REQUIRED_FIELDS"))
        self.assertTrue(hasattr(work_sizing, "COMMITMENT_V1_REQUIRED_FIELDS"))
        self.assertTrue(hasattr(work_sizing, "COMMITMENT_V2_REQUIRED_FIELDS"))

    def test_native_commitment_validation_realignment_modes(self):
        work_estimate = evaluate_work_estimate(_valid_raw_payload())
        for decision in ("pm-realignment", "architect-realignment"):
            commitment = _valid_commitment_payload(work_estimate)
            commitment["decision"] = decision
            self.assertEqual(validate_worker_commitment(commitment, work_estimate), [])
            self.assertNotEqual(validate_worker_commitment(commitment, work_estimate, dispatchable=True), [])

    def test_native_commitment_validation_zero_estimate_fails(self):
        work_estimate = evaluate_work_estimate(_valid_raw_payload())
        for field in ("tool_calls_p50", "tool_calls_p90", "runtime_seconds_p50", "runtime_seconds_p90"):
            commitment = _valid_commitment_payload(work_estimate)
            commitment["estimates"][field] = 0
            errors = validate_worker_commitment(commitment, work_estimate)
            self.assertEqual(len(errors), 1, msg=field)
            self.assertEqual(errors[0], f"malformed source payload: commitment.estimates.{field} must be a non-negative integer")

    def test_native_commitment_validation_hash_and_identity_mismatches(self):
        work_estimate = evaluate_work_estimate(_valid_raw_payload())
        commitment = _valid_commitment_payload(work_estimate)
        commitment["work_estimate_sha256"] = "0" * 64
        self.assertEqual(validate_worker_commitment(commitment, work_estimate), ["commitment.work_estimate_sha256 does not match evaluated work estimate payload"])

        altered_work_unit = _valid_commitment_payload(work_estimate)
        altered_work_unit["work_unit_id"] = "different-work-unit"
        self.assertEqual(validate_worker_commitment(altered_work_unit, work_estimate), ["commitment.work_unit_id must match work_estimate.work_unit_id"])

        altered_bead = _valid_commitment_payload(work_estimate)
        altered_bead["bead_id"] = "different-bead"
        self.assertEqual(validate_worker_commitment(altered_bead, work_estimate), ["commitment.bead_id must match work_estimate.bead_id"])

        altered_model = _valid_commitment_payload(work_estimate)
        altered_model["requested_model"] = "different-model"
        altered_model["attested_model"] = "different-model"
        self.assertEqual(validate_worker_commitment(altered_model, work_estimate), ["commitment.requested_model must match work_estimate.requested_model"])

        altered_attested = _valid_commitment_payload(work_estimate)
        altered_attested["attested_model"] = "different-attested-model"
        self.assertEqual(validate_worker_commitment(altered_attested, work_estimate), ["commitment.attested_model must match commitment.requested_model"])

    def test_native_commitment_validation_low_confidence_fails(self):
        work_estimate = evaluate_work_estimate(_valid_raw_payload())
        commitment = _valid_commitment_payload(work_estimate)
        commitment["confidence"] = 0.74
        errors = validate_worker_commitment(commitment, work_estimate)
        self.assertEqual(errors, ["commitment.confidence must be at least 0.75"])

    def test_native_commitment_validation_over_aggregate_allowance_fails(self):
        work_estimate = evaluate_work_estimate(_valid_raw_payload())
        commitment = _valid_commitment_payload(work_estimate)
        commitment["estimates"]["tool_calls_p90"] = work_estimate["aggregate_allowance"]["tool_calls_hard"] + 1
        self.assertEqual(
            validate_worker_commitment(commitment, work_estimate),
            ["commitment.estimates.tool_calls_p90 exceeds work_estimate.aggregate_allowance.tool_calls_hard"],
        )

        commitment = _valid_commitment_payload(work_estimate)
        commitment["estimates"]["runtime_seconds_p90"] = work_estimate["aggregate_allowance"]["runtime_seconds_hard"] + 1
        self.assertEqual(
            validate_worker_commitment(commitment, work_estimate),
            ["commitment.estimates.runtime_seconds_p90 exceeds work_estimate.aggregate_allowance.runtime_seconds_hard"],
        )

    def test_native_commitment_validation_rejects_unknown_fields(self):
        work_estimate = evaluate_work_estimate(_valid_raw_payload())
        commitment = _valid_commitment_payload(work_estimate)
        commitment["extra_field"] = "extra"
        self.assertEqual(validate_worker_commitment(commitment, work_estimate), ["malformed source payload: commitment has unknown field(s) extra_field"])

        commitment = _valid_commitment_payload(work_estimate)
        commitment["estimates"]["tool_calls_p95"] = 1
        self.assertEqual(validate_worker_commitment(commitment, work_estimate), ["commitment.estimates has unknown field(s) tool_calls_p95"])

    def test_native_commitment_validation_precommitment_usage_must_be_zero(self):
        work_estimate = evaluate_work_estimate(_valid_raw_payload())
        commitment = _valid_commitment_payload(work_estimate)
        commitment["tool_calls_before_commitment"] = 1
        self.assertEqual(
            validate_worker_commitment(commitment, work_estimate),
            ["malformed source payload: commitment.tool_calls_before_commitment must be at most 0"],
        )

        commitment = _valid_commitment_payload(work_estimate)
        commitment["context_compactions_before_commitment"] = 1
        self.assertEqual(
            validate_worker_commitment(commitment, work_estimate),
            ["malformed source payload: commitment.context_compactions_before_commitment must be at most 0"],
        )

    def test_native_commitment_schema_json_loads(self):
        path = Path(__file__).resolve().parents[1] / "schemas" / "native-worker-commitment.schema.json"
        schema = json.loads(path.read_text(encoding="utf-8"))
        self.assertFalse(schema["additionalProperties"])

    def test_validate_work_estimate_for_score_examples(self):
        payload = _valid_raw_payload()
        payload["scores"]["reasoning_uncertainty"] = 0
        payload["scores"]["subsystem_coupling"] = 1
        payload["scores"]["contract_risk"] = 1
        payload["scores"]["diagnostic_uncertainty"] = 1
        payload["scores"]["context_breadth"] = 1
        payload["scores"]["validation_breadth"] = 2  # total 6
        result = evaluate_work_estimate(payload)
        payload.update(result)
        self.assertEqual(validate_work_estimate(payload), [])

        payload = _valid_raw_payload()
        payload["scores"]["reasoning_uncertainty"] = 0
        payload["scores"]["subsystem_coupling"] = 2
        payload["scores"]["contract_risk"] = 2
        payload["scores"]["diagnostic_uncertainty"] = 2
        payload["scores"]["context_breadth"] = 2
        payload["scores"]["validation_breadth"] = 2  # total 10
        payload.update(evaluate_work_estimate(payload))
        self.assertEqual(validate_work_estimate(payload), [])

        payload = _valid_raw_payload()
        payload["scores"]["reasoning_uncertainty"] = 3
        payload["scores"]["subsystem_coupling"] = 0
        payload["scores"]["contract_risk"] = 0
        payload["scores"]["diagnostic_uncertainty"] = 0
        payload["scores"]["context_breadth"] = 0
        payload["scores"]["validation_breadth"] = 0  # total 3
        payload.update(evaluate_work_estimate(payload))
        self.assertEqual(validate_work_estimate(payload), [])

    def test_v1_remains_readable_without_semantic_policy(self):
        result = evaluate_work_estimate(_valid_raw_payload())
        self.assertNotIn("estimate_contract_version", result)
        self.assertEqual(validate_work_estimate(result), [])

    def test_v2_spark_fit_exposes_authority_and_operative_axes(self):
        result = evaluate_work_estimate(_valid_v2_payload(), policy=_v2_policy())
        self.assertEqual(result["route"], "spark")
        self.assertEqual(result["authority_route"], "spark")
        self.assertEqual(result["operative_route"], "spark")
        self.assertFalse(result["route_conflict"])
        self.assertEqual(result["semantic_scores"]["diff_p90"], 0)
        self.assertEqual(result["semantic_scores"]["surface_changes"], 1)
        self.assertEqual(result["semantic_scores"]["read_to_mutation_ratio"], 0)

    def test_literal_command_fit_is_deterministic_and_counts_are_independent(self):
        payload = _literal_command_payload()
        original = copy.deepcopy(payload)
        result = evaluate_work_estimate(payload)
        self.assertEqual(payload, original)
        self.assertEqual(result["task_class"], "literal-command")
        self.assertEqual(result["fit_mode"], "deterministic")
        self.assertEqual(result["route"], "spark")
        self.assertEqual(result["authority_route"], "spark")
        self.assertEqual(result["operative_route"], "spark")
        self.assertEqual(result["aggregate_allowance"]["tool_calls_hard"], 4)
        self.assertEqual(result["aggregate_allowance"]["runtime_seconds_hard"], 120)
        self.assertNotIn("semantic-read-mutation-split-trigger", result["hard_gate_reasons"])
        self.assertEqual(validate_work_estimate(result), [])

    def test_read_only_validation_overrides_zero_mutation_semantic_split(self):
        payload = _literal_command_payload()
        payload["task_profile"].update(
            {
                "task_class": "read-only-validation",
                "command_count": 2,
                "focused_test_count": 1,
                "full_suite_count": 1,
                "read_context_count": 1,
                "commands": [
                    {"argv": ["python3", "-m", "unittest", "tests.test_native_work_sizing"]},
                    {"argv": ["git", "diff", "--check"]},
                ],
            }
        )
        payload["context_manifest"] = [
            {"path": "tests/test_native_work_sizing.py", "selector": "file", "purpose": "validation", "bytes": 1, "sha256": "0" * 64}
        ]
        payload["semantic_estimate"]["expected_context_reads"] = 1
        payload["semantic_estimate"]["read_to_mutation_ratio"] = 1
        result = evaluate_work_estimate(payload)
        self.assertEqual(result["fit_mode"], "deterministic")
        self.assertEqual(result["route"], "spark")
        self.assertEqual(result["aggregate_allowance"]["tool_calls_hard"], 10)

    def test_read_only_validation_command_count_boundary(self) -> None:
        payload = _literal_command_payload()
        commands = [
            {"argv": ["python3", "-m", "unittest", "tests.test_native_work_sizing"]},
            {"argv": ["python3", "-m", "unittest", "tests.test_native_worker_execution_policy"]},
            {"argv": ["python3", "-m", "unittest", "tests.test_native_worker_planning"]},
            {"argv": ["python3", "-m", "unittest", "tests.test_supervise_native_worker"]},
            {"argv": ["python3", "-m", "unittest", "tests.test_native_worker_planning", "--failfast"]},
            {"argv": ["python3", "-m", "unittest", "tests.test_native_replanning"]},
        ]
        payload["task_profile"].update(
            {
                "task_class": "read-only-validation",
                "command_count": 6,
                "check_count": 6,
                "focused_test_count": 1,
                "full_suite_count": 1,
                "read_context_count": 1,
                "source_mutation_count": 0,
                "source_mutation_paths": [],
                "commands": commands,
            }
        )
        payload["context_manifest"] = [
            {"path": "tests/test_native_work_sizing.py", "selector": "file", "purpose": "validation", "bytes": 1, "sha256": "0" * 64}
        ]
        payload["semantic_estimate"]["expected_context_reads"] = 1
        payload["semantic_estimate"]["expected_mutations"] = 1
        payload["semantic_estimate"]["read_to_mutation_ratio"] = 1
        six = evaluate_work_estimate(payload)
        self.assertEqual(six["fit_mode"], "deterministic")
        self.assertEqual(six["task_class"], "read-only-validation")
        self.assertEqual(six["route"], "spark")
        self.assertFalse(six["route_conflict"])

        seven_payload = copy.deepcopy(payload)
        seven_payload["task_profile"]["command_count"] = 7
        seven_payload["task_profile"]["commands"] = payload["task_profile"]["commands"] + [
            {"argv": ["python3", "-m", "unittest", "tests.test_native_precommit"]}
        ]
        seven_payload["task_profile"]["check_count"] = 6
        seven = evaluate_work_estimate(seven_payload)
        self.assertEqual(seven["route"], "architect")
        self.assertIn("task-profile-contradiction", seven["hard_gate_reasons"])
        self.assertEqual(
            seven["fit_evidence"]["contradictions"],
            ["command_count exceeds class cap"],
        )

    def test_protected_path_requires_path_bound_literal_patch(self):
        path = "policy/native-worker-execution.yaml"
        payload = _narrow_profile_payload(path)
        result = evaluate_work_estimate(payload)
        self.assertEqual(result["fit_mode"], "semantic")
        self.assertIn("policy-routing", result["protected_surface_matches"])
        self.assertIn(
            "protected-surface-requires-path-bound-literal-patch",
            result["fit_evidence"]["checks"],
        )

        payload["task_profile"]["architect_literal_patch"] = {
            "path": path,
            "pre_patch_sha256": "1" * 64,
            "post_patch_sha256": "2" * 64,
        }
        accepted = evaluate_work_estimate(payload)
        self.assertEqual(accepted["fit_mode"], "deterministic")
        self.assertEqual(accepted["route"], "spark")

        payload["task_profile"]["architect_literal_patch"]["path"] = "policy/other.yaml"
        rejected = evaluate_work_estimate(payload)
        self.assertEqual(rejected["fit_mode"], "semantic")

    def test_task_profile_contradiction_routes_every_axis_to_architect(self):
        payload = _narrow_profile_payload()
        payload["task_profile"]["declared_outcome_count"] = 2
        result = evaluate_work_estimate(payload)
        self.assertEqual(result["route"], "architect")
        self.assertEqual(result["authority_route"], "architect")
        self.assertEqual(result["operative_route"], "architect")
        self.assertIn("task-profile-contradiction", result["hard_gate_reasons"])
        self.assertTrue(result["fit_evidence"]["contradictions"])

    def test_policy_fit_commitment_rejects_static_identity_without_receipt(self):
        estimate = evaluate_work_estimate(_literal_command_payload())
        with self.assertRaisesRegex(ValueError, "trusted precommit receipt"):
            build_policy_fit_commitment(
                estimate,
                session_id="spark-session-1",
                attested_model="gpt-5.3-codex-spark",
            )

    def test_estimate_without_task_profile_remains_semantic_bounded_implementation(self):
        result = evaluate_work_estimate(_valid_v2_payload())
        self.assertEqual(result["task_class"], "bounded-implementation")
        self.assertEqual(result["fit_mode"], "semantic")

    def test_execution_contract_absent_remains_backward_compatible(self):
        result = evaluate_work_estimate(_narrow_profile_payload())
        self.assertNotIn("execution_contract", result["task_profile"])

    def test_direct_execution_contract_requires_empty_specs(self):
        payload = _literal_command_payload()
        payload["task_profile"]["execution_contract"] = {"mode": "direct", "checked_command_specs": []}
        result = evaluate_work_estimate(payload)
        self.assertEqual(result["task_profile"]["execution_contract"], {"mode": "direct", "checked_command_specs": []})

        payload["task_profile"]["execution_contract"]["checked_command_specs"] = [{}]
        with self.assertRaisesRegex(ValueError, "direct execution_contract requires empty"):
            evaluate_work_estimate(payload)

    def test_checked_sequence_execution_contract_is_normalized_and_preserved(self):
        with tempfile.TemporaryDirectory() as cwd:
            payload = _checked_sequence_payload(cwd)
            result = evaluate_work_estimate(payload)
            contract = result["task_profile"]["execution_contract"]
            self.assertEqual(contract["mode"], "checked-sequence-v1")
            self.assertEqual([spec["command_id"] for spec in contract["checked_command_specs"]], ["check-0", "check-1"])
            self.assertEqual({spec["cwd"] for spec in contract["checked_command_specs"]}, {str(Path(cwd).resolve())})
            self.assertEqual(validate_work_estimate(result), [])

    def test_nonempty_literal_command_task_synthesizes_direct_execution_contract(self):
        payload = _literal_command_payload()
        inferred = evaluate_work_estimate(payload)

        self.assertEqual(inferred["fit_mode"], "deterministic")
        self.assertEqual(inferred["task_class"], "literal-command")
        self.assertEqual(inferred["route"], "spark")
        self.assertEqual(inferred["authority_route"], "spark")
        inferred_contract = inferred["task_profile"].get("execution_contract")
        self.assertEqual(inferred_contract["mode"], "direct")

        explicit_payload = copy.deepcopy(payload)
        explicit_payload["task_profile"]["execution_contract"] = {"mode": "direct", "checked_command_specs": []}
        explicit = evaluate_work_estimate(explicit_payload)

        self.assertEqual(explicit["task_profile"]["execution_contract"].get("mode"), "direct")
        self.assertEqual(canonical_work_estimate_sha256(inferred), canonical_work_estimate_sha256(explicit))

    def test_nonempty_read_only_validation_task_synthesizes_direct_execution_contract(self):
        payload = _literal_command_payload()
        payload["task_profile"]["task_class"] = "read-only-validation"
        payload["task_profile"]["read_context_count"] = 0
        payload["semantic_estimate"]["expected_context_reads"] = 0
        inferred = evaluate_work_estimate(payload)

        self.assertEqual(inferred["fit_mode"], "deterministic")
        self.assertEqual(inferred["task_class"], "read-only-validation")
        self.assertEqual(inferred["route"], "spark")
        self.assertEqual(inferred["authority_route"], "spark")
        self.assertEqual(inferred["task_profile"]["execution_contract"]["mode"], "direct")

        explicit_payload = copy.deepcopy(payload)
        explicit_payload["task_profile"]["execution_contract"] = {"mode": "direct", "checked_command_specs": []}
        explicit = evaluate_work_estimate(explicit_payload)
        self.assertEqual(canonical_work_estimate_sha256(inferred), canonical_work_estimate_sha256(explicit))

    def test_empty_literal_command_does_not_synthesize_direct_execution_contract(self):
        payload = _literal_command_payload()
        payload["task_profile"]["command_count"] = 0
        payload["task_profile"]["commands"] = []

        result = evaluate_work_estimate(payload)
        self.assertNotEqual(result["task_profile"].get("execution_contract", {}).get("mode"), "direct")

    def test_unsupported_read_only_alias_does_not_synthesize_direct_execution_contract(self):
        payload = _literal_command_payload()
        payload["task_profile"]["task_class"] = "read-only"
        result = evaluate_work_estimate(payload)

        self.assertNotEqual(result["task_profile"].get("execution_contract", {}).get("mode"), "direct")

    def test_explicit_direct_validation_preserves_direct_execution_contract(self):
        payload = _literal_command_payload()
        payload["task_profile"]["execution_contract"] = {
            "mode": "direct",
            "checked_command_specs": [],
        }
        result = evaluate_work_estimate(payload)

        self.assertEqual(result["fit_mode"], "deterministic")
        self.assertEqual(result["task_profile"]["execution_contract"]["mode"], "direct")
        self.assertEqual(result["authority_route"], "spark")

        inferred_payload = _literal_command_payload()
        inferred_result = evaluate_work_estimate(inferred_payload)
        self.assertEqual(canonical_work_estimate_sha256(result), canonical_work_estimate_sha256(inferred_result))

    def test_checked_sequence_v1_does_not_receive_inferred_direct_execution_contract(self):
        with tempfile.TemporaryDirectory() as cwd:
            payload = _checked_sequence_payload(cwd)
            result = evaluate_work_estimate(payload)

            self.assertEqual(result["task_profile"]["execution_contract"]["mode"], "checked-sequence-v1")
            self.assertEqual(result["authority_route"], "spark")

    def test_checked_sequence_rejects_invalid_mode_empty_specs_and_wrong_task_class(self):
        with tempfile.TemporaryDirectory() as cwd:
            cases = []
            unknown = _checked_sequence_payload(cwd)
            unknown["task_profile"]["execution_contract"]["mode"] = "automatic"
            cases.append((unknown, "must be direct or checked-sequence-v1"))
            empty = _checked_sequence_payload(cwd)
            empty["task_profile"]["execution_contract"]["checked_command_specs"] = []
            cases.append((empty, "requires checked_command_specs"))
            wrong_class = _checked_sequence_payload(cwd)
            wrong_class["task_profile"]["task_class"] = "read-only-validation"
            cases.append((wrong_class, "requires bounded-implementation"))
            for payload, message in cases:
                with self.subTest(message=message), self.assertRaisesRegex(ValueError, message):
                    evaluate_work_estimate(payload)

    def test_checked_sequence_rejects_non_argv_duplicate_ids_and_mixed_cwd(self):
        with tempfile.TemporaryDirectory() as cwd, tempfile.TemporaryDirectory() as other_cwd:
            non_argv = _checked_sequence_payload(cwd)
            spec = non_argv["task_profile"]["execution_contract"]["checked_command_specs"][0]
            spec.update({"mode": "shell-source", "argv": [], "source": "true"})

            duplicate = _checked_sequence_payload(cwd)
            duplicate["task_profile"]["execution_contract"]["checked_command_specs"][1]["command_id"] = "check-0"

            mixed_cwd = _checked_sequence_payload(cwd)
            mixed_cwd["task_profile"]["execution_contract"]["checked_command_specs"][1]["cwd"] = other_cwd

            cases = (
                (non_argv, "mode must be argv"),
                (duplicate, "command_id values must be unique"),
                (mixed_cwd, "requires one resolved cwd"),
            )
            for payload, message in cases:
                with self.subTest(message=message), self.assertRaisesRegex(ValueError, message):
                    evaluate_work_estimate(payload)

    def test_checked_sequence_rejects_argv_order_mismatch(self):
        with tempfile.TemporaryDirectory() as cwd:
            payload = _checked_sequence_payload(cwd)
            payload["task_profile"]["execution_contract"]["checked_command_specs"].reverse()
            with self.assertRaisesRegex(ValueError, "argv must exactly match"):
                evaluate_work_estimate(payload)

    def test_execution_contract_schema_is_closed_and_strict(self):
        schema = json.loads((ROOT / "schemas" / "native-work-estimate.schema.json").read_text(encoding="utf-8"))
        contract = schema["$defs"]["taskProfile"]["properties"]["execution_contract"]
        self.assertFalse(contract["additionalProperties"])
        spec = contract["properties"]["checked_command_specs"]["items"]
        self.assertFalse(spec["additionalProperties"])
        self.assertEqual(spec["properties"]["mode"]["const"], "argv")

    def test_v2_semantic_score_floors_are_deterministic(self):
        cases = (
            ("estimated_diff_p90", 81, "diff_p90", 1),
            ("estimated_diff_p90", 251, "diff_p90", 2),
            ("estimated_diff_p90", 601, "diff_p90", 3),
            ("behavioral_changes", 1, "behavioral_changes", 1),
            ("behavioral_changes", 3, "behavioral_changes", 2),
            ("behavioral_changes", 6, "behavioral_changes", 3),
            ("expected_regressions", 4, "expected_regressions", 1),
            ("expected_regressions", 9, "expected_regressions", 2),
            ("expected_regressions", 17, "expected_regressions", 3),
        )
        for field, value, score_field, expected in cases:
            with self.subTest(field=field, value=value):
                payload = _valid_v2_payload()
                payload["semantic_estimate"][field] = value
                result = evaluate_work_estimate(payload, policy=_v2_policy())
                self.assertEqual(result["semantic_scores"][score_field], expected)

    def test_v2_authority_and_self_hosting_test_split_remain_distinct(self):
        payload = _valid_v2_payload()
        payload["semantic_estimate"]["self_hosting_risk"] = 3
        payload["semantic_estimate"]["test_construction_complexity"] = 3
        result = evaluate_work_estimate(payload, policy=_v2_policy())
        self.assertEqual(result["authority_route"], "architect")
        self.assertEqual(result["operative_route"], "split")
        self.assertEqual(result["route"], "architect")
        self.assertIn("semantic-authority-uncertainty", result["hard_gate_reasons"])
        self.assertIn("semantic-read-mutation-split-trigger", result["hard_gate_reasons"])

    def test_v2_estimate_variance_blocks_spark_without_changing_axes(self):
        payload = _valid_v2_payload()
        payload["pm_estimate"]["tool_calls_p90"] += 9
        result = evaluate_work_estimate(payload, policy=_v2_policy())
        self.assertTrue(result["route_conflict"])
        self.assertEqual(result["authority_route"], "spark")
        self.assertEqual(result["operative_route"], "spark")
        self.assertEqual(result["route"], "split")
        self.assertIn("semantic-estimate-variance", result["hard_gate_reasons"])
        self.assertIn("semantic-route-conflict", result["hard_gate_reasons"])

    def test_v2_reads_with_zero_expected_mutations_force_split(self):
        payload = _valid_v2_payload()
        payload["semantic_estimate"]["expected_mutations"] = 0
        payload["semantic_estimate"]["read_to_mutation_ratio"] = 4
        result = evaluate_work_estimate(payload, policy=_v2_policy())
        self.assertEqual(result["operative_route"], "split")
        self.assertIn("semantic-read-mutation-split-trigger", result["hard_gate_reasons"])

    def test_v2_rejects_bool_complexity_and_invalid_diff_order(self):
        payload = _valid_v2_payload()
        payload["estimate_contract_version"] = True
        with self.assertRaises(ValueError):
            evaluate_work_estimate(payload, policy=_v2_policy())

        payload = _valid_v2_payload()
        payload["semantic_estimate"]["self_hosting_risk"] = True
        with self.assertRaises(ValueError):
            evaluate_work_estimate(payload, policy=_v2_policy())

        payload = _valid_v2_payload()
        payload["semantic_estimate"]["estimated_diff_p50"] = 81
        with self.assertRaises(ValueError):
            evaluate_work_estimate(payload, policy=_v2_policy())

    def test_v2_derived_fields_are_validated(self):
        result = evaluate_work_estimate(_valid_v2_payload(), policy=_v2_policy())
        self.assertEqual(validate_work_estimate(result, policy=_v2_policy()), [])
        result["authority_route"] = "architect"
        self.assertIn(
            "derived check failed: authority_route must equal computed authority_route",
            validate_work_estimate(result, policy=_v2_policy()),
        )


if __name__ == "__main__":
    unittest.main()
