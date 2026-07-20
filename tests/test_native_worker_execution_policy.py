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

    def test_live_supervision_policy_is_fail_closed(self) -> None:
        policy = self.__class__.policy
        self.assertEqual(policy["rollout_mode"], "canary-then-enforce")
        self.assertEqual(policy["enforcement_mode"], "fail-closed")
        self.assertEqual(policy["poll_interval_ms"], 1000)
        self.assertEqual(policy["poll_lag_tolerance_ms"], 1500)
        self.assertEqual(policy["arm_to_dispatch_max_ms"], 5000)
        self.assertTrue(policy["control_turn_required"])
        self.assertEqual(policy["segment_start_grace_seconds"], 10)
        self.assertEqual(policy["tool_reserve"], {"ratio": 0.10, "floor": 3})
        self.assertEqual(policy["runtime_reserve"], {"ratio": 0.10, "floor": 5})
        self.assertEqual(policy["required_control_adapter"], "native-multi-agent-v1")

    def test_precommit_supervision_policy_keeps_candidate_dispatch_contained(self) -> None:
        policy = self.__class__.policy
        precommit = policy["precommit_supervision"]
        self.assertEqual(precommit["version"], 2)
        self.assertEqual(precommit["required_model"], "gpt-5.3-codex-spark")
        self.assertEqual(precommit["attestation_source"], "trusted-control-plane-session-metadata")
        self.assertEqual(precommit["packet_stage"], "precommit-validated")
        self.assertFalse(precommit["operative_dispatch_authorized"])
        self.assertEqual(precommit["release_requires"], "complex-work-orchestration-fsh.3")
        containment = policy["precommit_containment"]
        self.assertTrue(containment["active"])
        self.assertEqual(containment["release_requires"], "complex-work-orchestration-fsh.3.5")
        self.assertEqual(containment["maximum_release_state"], "operative-authorized")
        self.assertTrue(containment["operative_dispatch_authorized"])
        self.assertEqual(policy["required_capabilities"], ["interrupt", "close", "wait"])
        self.assertEqual(policy["missing_telemetry_control"], "stop-before-dispatch")
        self.assertEqual(policy["validation_attempt_limit"], 1)
        self.assertTrue(policy["recursive_validation_forbidden"])
        self.assertEqual(
            policy["packet_versions"],
            {"emitted": 2, "historical": [1], "dispatchable": [2]},
        )

    def test_native_pool_is_opt_in_bounded_and_operative_authorized(self) -> None:
        pool = self.__class__.policy["native_supervision_pool"]
        self.assertTrue(pool["enabled"])
        self.assertEqual(pool["maturity"], "experimental")
        self.assertEqual(pool["status"], "operative-authorized")
        self.assertEqual(
            pool["capacity"],
            {
                "version": 1,
                "default_max_active_workers": 1,
                "released_max_active_workers": 2,
                "hard_max_active_workers": 3,
                "concurrency_enabled_by_default": False,
                "requires_explicit_opt_in": True,
                "requires_fresh_capability_receipt": True,
                "operator_activation_required_for_increase": True,
            },
        )
        self.assertEqual(pool["release_requires"], "complex-work-orchestration-18w.6")
        self.assertEqual(pool["scheduler"]["poll_interval_ms"], 1000)
        self.assertEqual(pool["scheduler"]["poll_lag_tolerance_ms"], 1500)
        self.assertFalse(pool["scheduler"]["hot_admission_allowed"])
        self.assertFalse(pool["scheduler"]["threads_allowed"])
        certification = pool["callback_certification"]
        self.assertEqual(
            certification["certified_callback_max_ms"],
            {
                "arm": 100,
                "send_input": 250,
                "mark_dispatched": 100,
                "check": 200,
                "interrupt": 250,
                "close": 250,
                "finalize": 100,
            },
        )
        self.assertEqual(certification["certified_scheduler_overhead_ms"], 100)
        self.assertEqual(certification["slack_warning_fraction"], 0.8)
        self.assertEqual(pool["scheduler"]["slack_warning_fraction"], 0.8)
        self.assertEqual(
            certification["response_time_equation"],
            "max_lifecycle+N*check+scheduler<=poll_interval",
        )
        self.assertEqual(pool["max_certified_check_ms"], 200)
        live = pool["trusted_live_canary"]
        self.assertEqual(live["runner"], "scripts/run_native_pool_live_canaries.py")
        self.assertEqual(live["exact_model"], "gpt-5.3-codex-spark")
        self.assertEqual(live["calibration_command"], "sleep 20")
        self.assertEqual(live["materialization_deadline_seconds"], 10)
        self.assertEqual(live["poll_interval_max_ms"], 250)
        self.assertEqual(live["liveness_observations"], 2)
        self.assertEqual(live["liveness_separation_min_ms"], 1000)
        self.assertEqual(live["interrupt_confirmation_deadline_seconds"], 5)
        self.assertEqual(live["successful_turn_starts_exact"], 7)
        self.assertEqual(live["prestart_zero_artifact_relaunch_max"], 1)
        self.assertIs(live["predecessor_lineage_artifacts_required"], True)
        self.assertIs(live["spark_receipt_canonical_recompute_required"], True)
        self.assertTrue(live["no_resume_or_salvage"])
        self.assertTrue(live["release_on_acceptance_only"])
        for surface in (
            "precommit-supervision",
            "candidate-packet-construction",
            "native-retry",
            "native-replay-dispatch",
            "outside-critic-review",
            "integration",
            "publication",
        ):
            self.assertIn(surface, pool["single_flight_surfaces"])

    def test_semantic_operative_packet_readiness_contract(self) -> None:
        readiness = self.__class__.policy["operative_packet_readiness"]
        self.assertEqual(readiness["version"], 2)
        self.assertEqual(readiness["required_marker"], "operative-readiness:v2")
        self.assertEqual(
            readiness["decisions"],
            ["operative-ready", "architect-resolution-required", "split-required"],
        )
        self.assertEqual(readiness["selector_grammar"], ["whole-file", "lines:<start>-<end>"])
        self.assertEqual(readiness["semantic_unit_identity"], "context-manifest-path-selector-sha256")
        self.assertEqual(readiness["max_chunks_per_unit"], 4)
        self.assertEqual(
            readiness["limits"],
            {
                "max_behavior_clusters": 1,
                "max_source_files": 4,
                "max_focused_test_modules": 2,
                "max_expected_diff_lines": 250,
                "max_tool_calls_p90": 18,
                "max_runtime_seconds_p90": 300,
                "max_compactions": 0,
                "max_implementation_full_suite_runs": 0,
            },
        )
        self.assertTrue(readiness["unresolved_decisions_required_empty"])
        self.assertEqual(len(readiness["required_frozen_decision_markers"]), 7)
        self.assertIn("context_unit_allowance", readiness["result_fields"])

    def test_semantic_activity_and_autonomous_replan_contract(self) -> None:
        controls = self.__class__.policy["operative_activity_controls"]
        self.assertEqual(controls["version"], 2)
        self.assertEqual(
            controls["categories"],
            ["targeted-read", "broad-scan", "memory-read", "mutation", "focused-validation", "unrelated"],
        )
        self.assertEqual(controls["semantic_unit_identity"], "context-manifest-path-selector-sha256")
        self.assertEqual(controls["mutation_authority"], "content-aware-workspace-baseline-v2")
        self.assertEqual(controls["max_chunks_per_unit"], 4)
        self.assertEqual(controls["warning"], {"semantic_units": 3, "pre_mutation_read_calls": 6})
        self.assertEqual(controls["needs_replan_before"], {"semantic_unit": 4, "pre_mutation_read_call": 11})
        self.assertEqual(controls["broad_scan"], "deny")
        self.assertEqual(controls["memory_read"], "exact-context-manifest-path-only")
        self.assertEqual(
            controls["recovery"],
            {
                "pm_refinements": 1,
                "automatic_sol_replans": 1,
                "final_attempts_after_sol_replan": 1,
                "operator_approval_for_healthy_packet_correction": False,
                "aggregate_budget_shared": True,
                "budget_reset": False,
                "recursive_salvage": False,
            },
        )
        self.assertIn("control-loss", controls["protected_stops"])
        self.assertIn("aggregate-budget-exhausted", controls["protected_stops"])
        self.assertIn("call-ordinal-first-mutation-gate", controls["prohibitions"])
        self.assertIn("recursive-salvage", controls["prohibitions"])
        self.assertIn("budget-reset", controls["prohibitions"])

    def test_bootstrap_roles_and_attestation_invariants(self) -> None:
        policy = self.__class__.policy
        self.assertEqual(policy["governance"]["sol"]["role"], "architecture-and-adjudication-only")
        self.assertTrue(policy["governance"]["sol"]["may_authorize_worker_packets"])
        self.assertFalse(policy["governance"]["sol"]["may_execute_operative_work"])
        self.assertEqual(policy["governance"]["spark"]["exact_model"], "gpt-5.3-codex-spark")
        worker = policy["governance"]["native_operative_worker"]
        self.assertEqual(worker["preferred_model"], "gpt-5.3-codex-spark")
        self.assertEqual(worker["authorized_models"], ["gpt-5.3-codex-spark", "gpt-5.6-luna"])
        self.assertEqual(worker["authorized_fallback_models"], ["gpt-5.6-luna"])
        self.assertEqual(worker["fallback_selection"], "explicit-only")

        gate = policy["execution_bootstrap"]["spawn"]["attestation_gate"]
        self.assertTrue(gate["required"])
        self.assertEqual(gate["tool_mode"], "no-tools")
        self.assertEqual(gate["model_authority"], "trusted-control-plane-session-metadata")
        self.assertEqual(gate["self_report_authority"], "forbidden")
        self.assertEqual(gate["required_actual_model_source"], "packet.requested_model")

        segmenting = policy["execution_bootstrap"]["segmenting"]
        self.assertTrue(segmenting["new_task_segment"]["new_attestation_boundary"])
        self.assertEqual(segmenting["resume_agent"]["default"], "forbidden")
        self.assertEqual(
            segmenting["resume_agent"]["waiver_release_condition"],
            "post-resume model attestation exactly matches packet.requested_model",
        )

        mismatch = policy["execution_bootstrap"]["model_mismatch"]
        self.assertEqual(mismatch["action"], "quarantine_output")
        self.assertEqual(mismatch["required_follow_up"], "fresh-native-operative-worker-redispatch")
        self.assertEqual(mismatch["return_status"], "model-mismatch")

        continuation = policy["execution_bootstrap"]["durable_continuation"]
        self.assertEqual(continuation["checkpoint"], "beads")
        self.assertEqual(continuation["worker_rotation"], "fresh-native-worker-per-segment")
        self.assertEqual(continuation["agent_resume_model"], "disallowed")

    def test_native_model_capability_policy_is_advisory_and_fail_closed(self) -> None:
        capability = self.__class__.policy["native_model_capability"]
        self.assertEqual(
            capability["states"],
            ["configured", "advertised", "spawn-accepted", "attested", "dispatchable"],
        )
        self.assertEqual(
            capability["dispatchable_requires"],
            ["configured", "spawn-accepted", "attested-exact-model"],
        )
        self.assertEqual(capability["advertisement"]["authority"], "advisory-telemetry")
        self.assertEqual(capability["advertisement"]["omission_outcome"], "advertisement-mismatch")
        self.assertEqual(capability["outcomes"]["native_spawn_rejected"], "hard-stop")
        self.assertEqual(capability["outcomes"]["native_attestation_mismatch"], "quarantine-hard-stop")
        self.assertEqual(capability["outcomes"]["native_capability_confirmed"], "dispatchable")
        self.assertEqual(capability["receipt"]["schema"], "schemas/native-model-capability-receipt.schema.json")
        self.assertEqual(capability["receipt"]["authority"], "trusted-session-jsonl")
        self.assertFalse(capability["receipt"]["cache_generated_registry"])
        self.assertIn("canary-tool-use", capability["hard_stops"])
        self.assertIn("generated-cache-edit", capability["prohibitions"])
        self.assertIn("model-self-report-authority", capability["prohibitions"])

    def test_bounded_native_retry_policy_contract(self) -> None:
        bounded_retry = self.__class__.policy["bounded_native_retry"]
        self.assertEqual(
            bounded_retry,
            {
                "version": 1,
                "enabled": True,
                "max_retries": 1,
                "eligible_semantic_statuses": ["delivery-failed", "no-artifact", "no-progress"],
                "eligible_interrupt_reasons": [
                    "delivery-failure",
                    "no-progress",
                    "tool-call-interrupt-threshold",
                    "runtime-interrupt-threshold",
                ],
                "authority": "cwo-native-supervisor-evidence",
                "actual_spawn_owner": "native-pm-controller",
                "operator_approval_required": False,
                "immutable_work_hash_required": True,
                "aggregate_budget_shared": True,
                "fresh_retry_session_required": True,
                "exact_model_attestation_required": True,
                "authorization_receipt": {
                    "type": "cwo-native-retry-authorization",
                    "version": 1,
                    "schema": "schemas/native-retry-authorization.schema.json",
                    "next_action": "spawn-fresh-native-retry",
                },
                "hard_stops": [
                    "model-mismatch",
                    "context-compaction",
                    "control-loss",
                    "security-violation",
                    "workspace-mutation",
                    "workspace-attribution-ambiguity",
                    "invalid-semantic-evidence",
                    "retry-exhausted",
                    "aggregate-allowance-exhausted",
                    "immutable-work-hash-mismatch",
                ],
                "prohibitions": [
                    "model-substitution",
                    "non-native-bridge",
                    "operative-agent-resume",
                    "sol-operative-substitution",
                    "automatic-salvage-chain",
                ],
            },
        )
        self.assertFalse(
            self.__class__.policy["work_sizing"]["enforcement"]["foundation-canary"]["autonomous_replanning"][
                "live_replay_enabled"
            ]
        )

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
                "needs-replan",
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

        needs_replan = policy["needs_replan_return_contract"]
        self.assertFalse(needs_replan["routine_operator_approval_required"])
        self.assertEqual(needs_replan["max_pm_refinements_per_work_unit"], 1)
        self.assertIn("unexpected-reasoning", needs_replan["reason_codes"])
        self.assertIn("architect-reasoning", needs_replan["decisions"])

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

    def test_static_task_classes_and_protected_surfaces(self) -> None:
        foundation = self.__class__.policy["work_sizing"]["enforcement"]["foundation-canary"]
        classes = foundation["task_class_policy"]
        self.assertEqual(
            set(classes),
            {
                "literal-command",
                "read-only-validation",
                "narrow-mechanical",
                "bounded-implementation",
                "diagnosis",
                "architecture",
            },
        )
        self.assertEqual(classes["literal-command"]["fit_mode"], "deterministic")
        self.assertEqual(classes["literal-command"]["tool_calls_p90"], 2)
        self.assertEqual(classes["literal-command"]["tool_calls_hard"], 4)
        self.assertEqual(classes["read-only-validation"]["runtime_seconds_hard"], 600)
        self.assertEqual(classes["read-only-validation"]["max_command_count"], 6)
        self.assertEqual(classes["read-only-validation"]["tool_calls_p50"], 2)
        self.assertEqual(classes["read-only-validation"]["tool_calls_p90"], 4)
        self.assertEqual(classes["read-only-validation"]["tool_calls_hard"], 10)
        self.assertEqual(classes["narrow-mechanical"]["max_estimated_diff_p90"], 50)
        self.assertEqual(classes["bounded-implementation"]["tool_calls_hard"], 37)
        self.assertEqual(classes["diagnosis"]["fit_mode"], "semantic")
        self.assertEqual(classes["architecture"]["fit_mode"], "architect")
        self.assertEqual(
            set(foundation["protected_surfaces"]),
            {
                "security-return-acceptance",
                "policy-routing",
                "schemas-public-contracts",
                "native-supervision-self-hosting",
                "provider-access-authority",
                "credentials",
                "release-publication",
                "workflow-automation",
            },
        )
        self.assertIn("needs-replan", foundation["autonomous_replanning"]["events"])

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
