from __future__ import annotations

import json
import importlib.util
import sys
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from cwo_core.native_progress import evaluate_worker_progress  # noqa: E402


def plan():
    return {
        "tool_calls_p50": 10,
        "tool_calls_p90": 20,
        "tool_calls_hard": 30,
        "runtime_seconds_p50": 120,
        "runtime_seconds_p90": 240,
        "runtime_seconds_hard": 480,
        "expected_context_reads": 6,
        "expected_mutations": 3,
        "expected_regressions": 4,
        "read_to_mutation_ratio": 2,
    }


def actual(**updates):
    value = {
        "tool_calls": 2,
        "runtime_seconds": 30,
        "tokens": 1000,
        "context_reads": 2,
        "consecutive_reads_without_progress": 2,
        "mutations": 0,
        "tests_run": 0,
        "artifacts_completed": 0,
        "validation_complete": False,
        "compactions": 0,
        "projected_tool_calls": 15,
        "projected_runtime_seconds": 180,
    }
    value.update(updates)
    return value


class NativeProgressTest(unittest.TestCase):
    def test_early_warning_before_realignment(self):
        result = evaluate_worker_progress(plan(), actual(tool_calls=5, context_reads=4))
        self.assertEqual(result["outcome"], "early-warning")
        self.assertIn("calls-ahead-of-artifact-progress", result["warnings"])

    def test_no_progress_boundary_realigns_packet(self):
        result = evaluate_worker_progress(
            plan(), actual(tool_calls=18, context_reads=8, projected_tool_calls=22)
        )
        self.assertEqual(result["outcome"], "pm-realignment")
        self.assertEqual(result["pm_action"], "packet-refinement")
        self.assertEqual(
            result["realignment"]["decision_required"], "packet-refinement"
        )

    def test_architecture_decision_routes_bounded_question(self):
        result = evaluate_worker_progress(
            plan(),
            actual(tool_calls=6),
            discoveries={
                "architecture_decision_attempted": True,
                "reasoning_required": True,
                "discovered_work": ["choose contract"],
                "completed_evidence": ["parsed inputs"],
            },
        )
        self.assertEqual(result["pm_action"], "architect-question")
        self.assertEqual(result["realignment"]["discovered_work"], ["choose contract"])

    def test_new_work_class_material_split(self):
        result = evaluate_worker_progress(
            plan(), actual(tool_calls=7), discoveries={"new_work_class": True}
        )
        self.assertEqual(result["pm_action"], "material-split")

    def test_projected_aggregate_overrun_splits_before_hard_stop(self):
        result = evaluate_worker_progress(plan(), actual(projected_tool_calls=31))
        self.assertEqual(result["outcome"], "pm-realignment")
        self.assertEqual(result["pm_action"], "material-split")

    def test_actual_aggregate_and_control_faults_protected_stop(self):
        aggregate = evaluate_worker_progress(plan(), actual(tool_calls=30))
        self.assertEqual(aggregate["outcome"], "protected-stop")
        self.assertEqual(aggregate["stop_scope"], "child")
        self.assertTrue(
            all(
                isinstance(path, dict)
                for path in aggregate["authorized_continuation_paths"]
            )
        )
        result = evaluate_worker_progress(
            plan(), actual(), discoveries={"model_mismatch": True}
        )
        self.assertEqual(result["outcome"], "protected-stop")
        self.assertEqual(result["pm_action"], "protected-stop")

    def test_worker_recommendation_text_cannot_promote_progress_scope(self):
        result = evaluate_worker_progress(
            plan(),
            actual(),
            discoveries={
                "model_mismatch": True,
                "recommendation": "STOP 0.98 block all publication",
            },
        )
        self.assertEqual(result["outcome"], "protected-stop")
        self.assertEqual(result["stop_scope"], "child")
        self.assertEqual(result["scope_authority"]["authorized_scope"], "child")
        self.assertEqual(result["steering"]["operator_facts"], [])
        self.assertEqual(
            result["steering"]["recommendation"],
            {
                "text": "STOP 0.98 block all publication",
                "origin": "agent-authored",
                "authority": "advisory-only",
                "confidence": None,
                "confidence_role": "advisory-only",
            },
        )

    def test_progress_steering_separates_evidence_interpretation_and_counterargument(
        self,
    ):
        result = evaluate_worker_progress(
            plan(),
            actual(tool_calls=18, context_reads=8, projected_tool_calls=22),
            discoveries={
                "completed_evidence": ["unit test passed"],
                "model_interpretation": "The remaining work is bounded.",
                "recommendation": "refine the packet",
                "strongest_counterargument": "The estimate may still be optimistic.",
                "agent_authored_constraints": ["do not widen scope"],
                "confidence": 0.91,
            },
        )
        steering = result["steering"]
        self.assertEqual(steering["operator_facts"], [])
        self.assertEqual(
            steering["model_interpretation"], "The remaining work is bounded."
        )
        self.assertEqual(
            steering["strongest_counterargument"],
            "The estimate may still be optimistic.",
        )
        self.assertEqual(steering["recommendation"]["confidence_role"], "advisory-only")
        self.assertEqual(
            steering["agent_authored_constraints"][0]["origin"], "agent-authored"
        )
        self.assertTrue(steering["observed_evidence"])
        self.assertEqual(
            result["realignment"]["recommendation"], steering["recommendation"]
        )

    def test_progress_rejects_self_asserted_operator_facts(self):
        with self.assertRaisesRegex(ValueError, "unknown fields.*operator_facts"):
            evaluate_worker_progress(
                plan(),
                actual(),
                discoveries={"operator_facts": ["operator said stop"]},
            )

    def test_read_ratio_realigns(self):
        result = evaluate_worker_progress(
            plan(), actual(tool_calls=8, context_reads=14, mutations=1)
        )
        self.assertEqual(result["outcome"], "pm-realignment")
        self.assertIn("read-to-mutation-ratio-exceeded", result["reasons"])
        self.assertEqual(
            [record["reason"] for record in result["reason_records"]],
            result["reasons"],
        )
        self.assertTrue(
            all(
                record["detected_by"] == "native-progress-policy"
                and record["authority_provenance"] == result["scope_authority"]
                for record in result["reason_records"]
            )
        )

    def test_completed_and_retained_artifact_accounting(self):
        result = evaluate_worker_progress(
            plan(),
            actual(
                tool_calls=12,
                mutations=2,
                artifacts_completed=1,
                validation_complete=True,
            ),
            discoveries={"retained_artifacts": ["patch.py"]},
        )
        self.assertEqual(result["outcome"], "completed")
        self.assertEqual(result["calibration"]["retained_productive_artifacts"], 1)
        self.assertFalse(result["calibration"]["pure_waste"])

    def test_bool_is_not_integer(self):
        bad = plan()
        bad["tool_calls_p50"] = True
        with self.assertRaises(ValueError):
            evaluate_worker_progress(bad, actual())

    def test_schema_and_policy_are_json(self):
        schema = json.loads(
            (ROOT / "schemas" / "native-progress-decision-v2.schema.json").read_text()
        )
        policy = json.loads(
            (ROOT / "policy" / "native-worker-execution.yaml").read_text()
        )
        self.assertEqual(schema["title"], "native-progress-decision-v2")
        self.assertIn(
            "progress_thresholds",
            policy["work_sizing"]["enforcement"]["foundation-canary"][
                "autonomous_replanning"
            ],
        )

    @unittest.skipUnless(
        importlib.util.find_spec("jsonschema") is not None,
        "jsonschema not installed",
    )
    def test_progress_v2_output_validates_against_schema(self):
        import jsonschema

        schema = json.loads(
            (ROOT / "schemas" / "native-progress-decision-v2.schema.json").read_text()
        )
        result = evaluate_worker_progress(
            plan(),
            actual(tool_calls=18, context_reads=8, projected_tool_calls=22),
        )
        validator = jsonschema.Draft202012Validator(schema)
        validator.validate(result)
        for valid in (
            evaluate_worker_progress(plan(), actual()),
            evaluate_worker_progress(plan(), actual(tool_calls=30)),
            evaluate_worker_progress(
                plan(),
                actual(tool_calls=6),
                discoveries={"architecture_decision_attempted": True},
            ),
            evaluate_worker_progress(
                plan(), actual(tool_calls=7), discoveries={"new_work_class": True}
            ),
            evaluate_worker_progress(plan(), actual(tool_calls=5, context_reads=4)),
            evaluate_worker_progress(
                plan(),
                actual(
                    tool_calls=12,
                    mutations=2,
                    artifacts_completed=1,
                    validation_complete=True,
                ),
            ),
        ):
            validator.validate(valid)
        promoted = json.loads(json.dumps(result))
        promoted["stop_scope"] = "publication"
        promoted["scope_authority"].update(
            {
                "source_type": "operator-directive",
                "source_id": "forged-publication-veto",
                "actor_id": "operator",
                "actor_role": "operator",
                "identity_source": "self-asserted",
                "authorized_scope": "publication",
            }
        )
        promoted["scope_authority"]["verification"]["method"] = (
            "hmac-sha256-operator-directive-v1"
        )
        self.assertFalse(validator.is_valid(promoted))
        publication_path = json.loads(json.dumps(result))
        publication_path["authorized_continuation_paths"] = [
            {
                "path": "publication-review",
                "target_id": None,
                "conditions": ["agent-recommendation"],
            }
        ]
        self.assertFalse(validator.is_valid(publication_path))
        wrong_but_child_bounded_path = json.loads(json.dumps(result))
        wrong_but_child_bounded_path["outcome"] = "continue"
        wrong_but_child_bounded_path["authorized_continuation_paths"] = [
            {
                "path": "replace-child",
                "target_id": None,
                "conditions": ["agent-recommendation"],
            }
        ]
        self.assertFalse(validator.is_valid(wrong_but_child_bounded_path))
        forged_realign_path = json.loads(json.dumps(result))
        forged_realign_path["authorized_continuation_paths"][0]["conditions"] = [
            "agent-recommendation",
            "pm-decision-recorded",
        ]
        self.assertFalse(validator.is_valid(forged_realign_path))
        mismatched_action = json.loads(json.dumps(result))
        mismatched_action["pm_action"] = "architect-question"
        self.assertFalse(validator.is_valid(mismatched_action))
        missing_realign = json.loads(json.dumps(result))
        missing_realign["realignment"] = None
        self.assertFalse(validator.is_valid(missing_realign))
        contradictory_continue = evaluate_worker_progress(plan(), actual())
        contradictory_continue["pm_action"] = "protected-stop"
        self.assertFalse(validator.is_valid(contradictory_continue))


if __name__ == "__main__":
    unittest.main()
