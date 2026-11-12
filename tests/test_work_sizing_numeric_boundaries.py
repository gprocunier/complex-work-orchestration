import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from cwo_core.model_identities import SPARK_MODEL  # noqa: E402
from cwo_core.work_sizing import (  # noqa: E402
    DIMENSIONS,
    build_policy_fit_commitment,
    canonical_work_estimate_sha256,
    evaluate_work_estimate,
    validate_work_estimate,
    validate_worker_commitment,
)

HUGE = 10**4000


def _raw_estimate(reads=1, mutations=1, ratio=1):
    estimates = {
        "tool_calls_p50": 3,
        "tool_calls_p90": 4,
        "runtime_seconds_p50": 4,
        "runtime_seconds_p90": 9,
    }
    return {
        "estimate_type": "cwo-native-work-estimate",
        "version": 1,
        "estimate_contract_version": 2,
        "work_unit_id": "wu-work-sizing-numeric-boundaries",
        "bead_id": "bead-work-sizing-numeric-boundaries",
        "requested_model": SPARK_MODEL,
        "primary_outcome": "exercise work-sizing numeric boundaries",
        "expected_artifacts": ["numeric-boundary-evidence"],
        "expert_profiles": [],
        "frozen_decisions": [],
        "unresolved_decisions": [],
        "subsystems": ["work-sizing"],
        "write_paths": ["example.py"],
        "context_manifest": [],
        "acceptance_checks": [],
        "estimates": {**estimates, "context_tokens_p90": 1000},
        "scores": {dimension: 0 for dimension in DIMENSIONS},
        "semantic_estimate": {
            "estimated_diff_p50": 1,
            "estimated_diff_p90": 1,
            "behavioral_changes": 1,
            "state_machine_changes": 0,
            "schema_changes": 0,
            "self_hosting_risk": 0,
            "live_control_risk": 0,
            "contract_surfaces": 0,
            "cli_surfaces": 0,
            "policy_surfaces": 0,
            "telemetry_surfaces": 0,
            "expected_regressions": 0,
            "test_construction_complexity": 0,
            "command_complexity": 0,
            "nested_quote_layers": 0,
            "expected_context_reads": reads,
            "expected_mutations": mutations,
            "read_to_mutation_ratio": ratio,
        },
        "pm_estimate": dict(estimates),
        "domain_expert_estimate": dict(estimates),
    }


def _historical_commitment(estimate, confidence):
    return {
        "commitment_type": "cwo-native-worker-fit-commitment",
        "version": 1,
        "work_unit_id": estimate["work_unit_id"],
        "bead_id": estimate["bead_id"],
        "requested_model": estimate["requested_model"],
        "session_id": "numeric-boundary-history",
        "attestation_source": "trusted-session-jsonl",
        "attested_model": estimate["requested_model"],
        "work_estimate_sha256": canonical_work_estimate_sha256(estimate),
        "decision": "accept",
        "confidence": confidence,
        "estimates": dict(estimate["pm_estimate"]),
        "tool_calls_before_commitment": 0,
        "context_compactions_before_commitment": 0,
        "reason": "historical inspection fixture only",
    }


class TestWorkSizingNumericBoundaries(unittest.TestCase):
    def test_ordinary_ratios_and_zero_convention(self):
        cases = (
            (0, 0, 0, "spark"),
            (3, 0, 3, "split"),
            (3, 2, 1.5, "spark"),
            (12, 2, 6, "spark"),
            (13, 2, 6.5, "split"),
            (10_000_000, 1, 10_000_000, "split"),
        )
        for reads, mutations, ratio, route in cases:
            with self.subTest(reads=reads, mutations=mutations):
                estimate = evaluate_work_estimate(_raw_estimate(reads, mutations, ratio))
                self.assertEqual(estimate["semantic_estimate"]["read_to_mutation_ratio"], ratio)
                self.assertEqual(estimate["route"], route)
                self.assertEqual(validate_work_estimate(estimate), [])

    def test_huge_counts_reach_public_normalization_and_routing(self):
        cases = (
            (HUGE, HUGE, 1, "split"),
            (3 * HUGE, 2 * HUGE, 1.5, "split"),
            (0, HUGE, 0, "spark"),
            (10_000_000 * HUGE, HUGE, 10_000_000, "split"),
        )
        for index, (reads, mutations, ratio, route) in enumerate(cases):
            with self.subTest(case=index):
                source = _raw_estimate(reads, mutations, ratio)
                estimate = evaluate_work_estimate(source)
                semantic = estimate["semantic_estimate"]
                self.assertEqual(semantic["expected_context_reads"], reads)
                self.assertEqual(semantic["expected_mutations"], mutations)
                self.assertEqual(semantic["read_to_mutation_ratio"], ratio)
                self.assertEqual(estimate["v1_route"], "spark")
                self.assertEqual(estimate["authority_route"], "spark")
                self.assertEqual(estimate["operative_route"], route)
                self.assertEqual(estimate["route"], route)
                self.assertEqual(validate_work_estimate(estimate), [])
                self.assertEqual(
                    canonical_work_estimate_sha256(estimate),
                    canonical_work_estimate_sha256(evaluate_work_estimate(estimate)),
                )

    def test_integral_ratio_keeps_canonical_integer_serialization(self):
        source = _raw_estimate(HUGE, HUGE, 1.0)
        estimate = evaluate_work_estimate(source)
        self.assertIs(type(estimate["semantic_estimate"]["read_to_mutation_ratio"]), int)
        self.assertIs(type(source["semantic_estimate"]["read_to_mutation_ratio"]), float)
        self.assertEqual(estimate["semantic_scores"]["read_to_mutation_ratio"], 0)

    def test_huge_unrepresentable_and_mismatched_ratios_are_controlled(self):
        cases = ((HUGE, 0, 1), (HUGE, 1, 1), (1, 1, HUGE), (HUGE, HUGE, 2))
        for index, (reads, mutations, ratio) in enumerate(cases):
            with self.subTest(case=index):
                source = _raw_estimate(reads, mutations, ratio)
                with self.assertRaisesRegex(ValueError, "semantic_estimate.read_to_mutation_ratio"):
                    evaluate_work_estimate(source)
                self.assertTrue(validate_work_estimate(source))

    def test_invalid_ratio_metadata_remains_refused(self):
        for index, ratio in enumerate((True, False, "1", None, [], -1, 10_000_001,
                                       float("nan"), float("inf"), float("-inf"))):
            with self.subTest(case=index):
                with self.assertRaises(ValueError):
                    evaluate_work_estimate(_raw_estimate(ratio=ratio))

    def test_invalid_counters_remain_refused(self):
        for key in ("expected_context_reads", "expected_mutations"):
            for value in (True, False, -1, 1.0):
                with self.subTest(key=key, value=value):
                    source = _raw_estimate()
                    source["semantic_estimate"][key] = value
                    with self.assertRaisesRegex(ValueError, key):
                        evaluate_work_estimate(source)

    def test_model_refusal_survives_huge_counter_normalization(self):
        for model, refusal in (
            ("unsupported-model", f"requires requested_model {SPARK_MODEL}"),
            (SPARK_MODEL, "requires work_estimate.fit_mode deterministic"),
        ):
            with self.subTest(model=model):
                source = _raw_estimate(HUGE, HUGE, 1)
                source["requested_model"] = model
                estimate = evaluate_work_estimate(source)
                self.assertEqual(estimate["requested_model"], model)
                self.assertEqual(estimate["route"], "split")
                self.assertEqual(validate_work_estimate(estimate), [])
                with self.assertRaisesRegex(ValueError, refusal):
                    build_policy_fit_commitment(estimate, precommit_receipt={})

    def test_historical_confidence_uses_controlled_numeric_refusals(self):
        estimate = evaluate_work_estimate(_raw_estimate(HUGE, HUGE, 1))
        for confidence in (0.91, 1):
            with self.subTest(confidence=confidence):
                record = _historical_commitment(estimate, confidence)
                self.assertEqual(validate_worker_commitment(record, estimate), [])
        for index, confidence in enumerate((HUGE, -HUGE, True, "0.91", 0.74, 1.1,
                                            float("nan"), float("inf"), float("-inf"))):
            with self.subTest(case=index):
                record = _historical_commitment(estimate, confidence)
                errors = validate_worker_commitment(record, estimate)
                self.assertTrue(errors)
                self.assertIn("commitment.confidence", errors[0])
        record = _historical_commitment(estimate, 0.91)
        self.assertEqual(
            validate_worker_commitment(record, estimate, dispatchable=True),
            ["commitment version 1 is historical-inspection-only and dispatch-forbidden"],
        )


if __name__ == "__main__":
    unittest.main()
