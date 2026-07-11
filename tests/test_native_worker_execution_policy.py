from __future__ import annotations

import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class NativeWorkerExecutionPolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        payload_path = ROOT / "policy" / "native-worker-execution.yaml"
        with payload_path.open("r", encoding="utf-8") as handle:
            cls.policy = json.load(handle)

    def test_policy_is_json_loadable(self) -> None:
        self.assertIsInstance(self.__class__.policy, dict)

    def test_bootstrap_roles_and_attestation_invariants(self) -> None:
        policy = self.__class__.policy
        self.assertEqual(policy["governance"]["sol"]["role"], "architecture-and-adjudication-only")
        self.assertTrue(policy["governance"]["sol"]["may_authorize_worker_packets"])
        self.assertFalse(policy["governance"]["sol"]["may_execute_operative_work"])
        self.assertEqual(policy["governance"]["spark"]["exact_model"], "gpt-5.3-codex-spark")

        gate = policy["execution_bootstrap"]["spawn"]["attestation_gate"]
        self.assertTrue(gate["required"])
        self.assertEqual(gate["tool_mode"], "no-tools")
        self.assertEqual(gate["model_authority"], "trusted-control-plane-session-metadata")
        self.assertEqual(gate["self_report_authority"], "forbidden")
        self.assertEqual(gate["required_actual_model"], "gpt-5.3-codex-spark")

        segmenting = policy["execution_bootstrap"]["segmenting"]
        self.assertTrue(segmenting["new_task_segment"]["new_attestation_boundary"])
        self.assertEqual(segmenting["resume_agent"]["default"], "forbidden")
        self.assertEqual(
            segmenting["resume_agent"]["waiver_release_condition"],
            "post-resume model attestation exactly matches gpt-5.3-codex-spark",
        )

        mismatch = policy["execution_bootstrap"]["model_mismatch"]
        self.assertEqual(mismatch["action"], "quarantine_output")
        self.assertEqual(mismatch["required_follow_up"], "fresh-native-spark-redispatch")
        self.assertEqual(mismatch["return_status"], "model-mismatch")

        continuation = policy["execution_bootstrap"]["durable_continuation"]
        self.assertEqual(continuation["checkpoint"], "beads")
        self.assertEqual(continuation["worker_rotation"], "fresh-native-worker-per-segment")
        self.assertEqual(continuation["agent_resume_model"], "disallowed")

    def test_native_worker_lane_budgets_and_alignment_statuses(self) -> None:
        policy = self.__class__.policy
        lane_budgets = policy["lane_budgets"]

        self.assertEqual(
            lane_budgets["implementation"],
            {
                "tool_calls_soft": 60,
                "tool_calls_hard": 100,
                "runtime_seconds_soft": 720,
                "runtime_seconds_hard": 1080,
                "max_compactions": 0,
                "max_full_suite_runs": 0,
            },
        )
        self.assertEqual(
            lane_budgets["validation"],
            {
                "tool_calls_soft": 30,
                "tool_calls_hard": 50,
                "runtime_seconds_soft": 480,
                "runtime_seconds_hard": 720,
                "max_compactions": 0,
                "max_full_suite_runs": 1,
            },
        )
        self.assertEqual(
            lane_budgets["review"],
            {
                "tool_calls_soft": 40,
                "tool_calls_hard": 60,
                "runtime_seconds_soft": 480,
                "runtime_seconds_hard": 720,
                "max_compactions": 0,
                "max_full_suite_runs": 0,
            },
        )
        self.assertEqual(
            lane_budgets["publish-report-admin"],
            {
                "tool_calls_soft": 25,
                "tool_calls_hard": 40,
                "runtime_seconds_soft": 300,
                "runtime_seconds_hard": 480,
                "max_compactions": 0,
                "max_full_suite_runs": 0,
            },
        )

        self.assertEqual(
            policy["return_statuses"],
            [
                "completed",
                "blocked",
                "needs-architect-realignment",
                "budget-exhausted",
                "model-mismatch",
            ],
        )

        self.assertEqual(
            policy["realignment_return_contract"]["required_fields"],
            [
                "completed_evidence",
                "files_touched",
                "mutation_state",
                "decision_required",
                "bounded_options",
                "recommendation",
                "remaining_scope",
                "usage",
                "session_disposition",
                "artifact_disposition",
                "artifact_validation",
            ],
        )
        self.assertEqual(policy["realignment_return_contract"]["worker_mutation_policy"], "stop_mutating")

        self.assertEqual(
            policy["alignment_triggers"]["needs_architect_realignment"]["distinct_soft_limits_required"],
            2,
        )
        self.assertEqual(
            policy["alignment_triggers"]["needs_architect_realignment"]["any_hard_limit"],
            "realignment",
        )
        self.assertEqual(
            policy["alignment_triggers"]["needs_architect_realignment"]["any_compaction"],
            "hard-stop/realignment",
        )
        self.assertEqual(
            policy["alignment_triggers"]["needs_architect_realignment"]["status"],
            "needs-architect-realignment",
        )
        self.assertEqual(
            policy["realignment_return_contract"]["execution_sequence"],
            ["fix", "reload", "resume"],
        )
        self.assertEqual(policy["realignment_return_contract"]["resume_from"], "beads")

    def test_disposition_and_sol_breakfix_policy(self) -> None:
        policy = self.__class__.policy
        disposition = policy["disposition_policy"]
        self.assertFalse(disposition["automatic_sol_breakfix"])
        self.assertEqual(disposition["validation_attempt_limit"], 1)
        self.assertEqual(
            disposition["artifact_dispositions"],
            [
                "accepted",
                "independent-validation-required",
                "architect-adjudication-required",
                "rejected",
            ],
        )

        breakfix = policy["sol_breakfix"]
        self.assertEqual(breakfix["default"], "forbidden")
        self.assertTrue(breakfix["automatic_selection_forbidden"])
        self.assertEqual(
            breakfix["required_approval_source"],
            "explicit-operator-in-current-interaction",
        )
        self.assertTrue(breakfix["required_bead_record"])
        self.assertTrue(breakfix["independent_validation_required"])
        self.assertTrue(breakfix["expires_at_authorized_bead_closure"])
