from __future__ import annotations

import copy
import json
from pathlib import Path
import unittest
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from cwo_core.native_replanning import build_replanning_state, transition_replanning_state  # noqa: E402

POLICY = json.loads((ROOT / "policy" / "native-worker-execution.yaml").read_text(encoding="utf-8"))
WORK_SIZING = POLICY["work_sizing"]["enforcement"]["foundation-canary"]["autonomous_replanning"]


def _policy_with(overrides: dict[str, int] | None = None) -> dict:
    policy = copy.deepcopy(POLICY)
    replanning = policy["work_sizing"]["enforcement"]["foundation-canary"]["autonomous_replanning"]
    if overrides:
        replanning.update(overrides)
    return policy


def _base_state() -> dict:
    return {
        "state": "executing",
        "work_unit_id": "wu-native-replanning",
        "bead_id": "bead-native-replanning",
        "packet_id": "packet-native-replanning",
        "requested_model": "gpt-5.3-codex-spark",
        "objective": "native replanning validation",
        "security_context": "standard",
        "authority": "worker",
        "model_match": True,
        "control_healthy": True,
        "counters": {
            "dispatches": 0,
            "tool_calls_used": 0,
            "runtime_seconds_used": 0,
            "context_compactions": 0,
            "pm_replans_used": 0,
            "architect_cycles_used": 0,
        },
        "aggregate_allowance": {
            "tool_calls_hard": 100,
            "runtime_seconds_hard": 400,
            "dispatch_soft_cap": WORK_SIZING["dispatch_soft_cap"],
            "dispatch_soft_cap_action": WORK_SIZING["dispatch_soft_cap_action"],
            "max_pm_replans": WORK_SIZING["max_pm_replans"],
            "max_architect_cycles": WORK_SIZING["max_architect_cycles"],
            "max_compactions": WORK_SIZING["max_compactions"],
        },
        "mutation": {"out_of_scope": False, "tainted": False},
        "main_thread": {
            "model": "gpt-5.6-sol",
            "effort": "xhigh",
            "source": "user-declaration",
            "recommended_effort": "max",
            "recommendation_reason": "complex-repair",
            "advisory": True,
            "user_selected_effort_retained": True,
        },
    }


def _state_with_overrides(overrides: dict | None = None) -> dict:
    payload = _base_state()
    if overrides:
        payload.update(overrides)
    return build_replanning_state(payload)


class NativeReplanningTest(unittest.TestCase):
    def test_oversized_read_only_exploration_realigns_to_pm_before_compaction(self) -> None:
        evidence = {
            "trusted_evidence": True,
            "exact_model": True,
            "control_healthy": True,
            "tool_calls_delta": 2,
            "runtime_seconds_delta": 10,
            "context_compactions_delta": 0,
            "mutation": {"out_of_scope": False, "tainted": False},
            "objective_changed": False,
            "security_changed": False,
            "authority_changed": False,
        }
        result = transition_replanning_state(_state_with_overrides(), "clean-no-artifact", evidence)
        self.assertEqual(result["state"], "pm-realignment")
        self.assertEqual(result["counters"]["pm_replans_used"], 1)
        self.assertEqual(result["cwo_native_replanning_receipt"]["state_after"], "pm-realignment")

    def test_clean_no_artifact_pm_refined_to_fresh_worker(self) -> None:
        evidence = {
            "trusted_evidence": True,
            "exact_model": True,
            "control_healthy": True,
            "mutation": {"out_of_scope": False, "tainted": False},
        }
        pm = transition_replanning_state(_state_with_overrides(), "clean-no-artifact", evidence)
        reassigned = transition_replanning_state(pm, "pm-refined", {"requires_architect_cycle": False})
        ready = transition_replanning_state(reassigned, "fresh-worker-assigned", {})
        self.assertEqual(ready["state"], "dispatchable")
        self.assertEqual(ready["reason_codes"], [WORK_SIZING["fresh-worker-reassignment"]["event"]])

    def test_one_pm_plus_one_architect_cycle_then_second_cycle_stops(self) -> None:
        evidence = {
            "trusted_evidence": True,
            "exact_model": True,
            "control_healthy": True,
            "mutation": {"out_of_scope": False, "tainted": False},
        }
        pm = transition_replanning_state(_state_with_overrides(), "clean-no-artifact", evidence)
        architect_ready = transition_replanning_state(pm, "pm-refined", {"requires_architect_cycle": True})
        reassignment = transition_replanning_state(architect_ready, "architect-refined", {})
        dispatchable = transition_replanning_state(reassignment, "fresh-worker-assigned", {})
        retry_running = copy.deepcopy(dispatchable)
        retry_running["state"] = "executing"
        second_pm = transition_replanning_state(retry_running, "clean-no-artifact", evidence)
        self.assertEqual(second_pm["state"], "protected-stop")
        self.assertIn("pm-replan-exhausted", second_pm["reason_codes"])

        exhausted_architect = transition_replanning_state(
            {
                **_state_with_overrides(),
                "state": "architect-realignment",
                "counters": {
                    **_base_state()["counters"],
                    "architect_cycles_used": WORK_SIZING["max_architect_cycles"],
                },
            },
            "architect-refined",
            {},
        )
        self.assertEqual(exhausted_architect["state"], "protected-stop")
        self.assertIn("architect-cycle-exhausted", exhausted_architect["reason_codes"])

    def test_all_protected_boundaries_stop(self) -> None:
        base = _base_state()
        base_execution = _state_with_overrides()
        stopped = transition_replanning_state(base_execution, "model-mismatch", {})
        self.assertEqual(stopped["state"], "protected-stop")
        self.assertEqual(stopped["reason_codes"], ["model-mismatch"])

        base = _base_state()
        base["state"] = "executing"
        compaction = transition_replanning_state(
            build_replanning_state(base),
            "clean-no-artifact",
            {
                "trusted_evidence": True,
                "exact_model": True,
                "control_healthy": True,
                "mutation": {"out_of_scope": False, "tainted": False},
                "context_compactions_delta": 1,
            },
        )
        self.assertEqual(compaction["state"], "protected-stop")

        control = transition_replanning_state(
            _state_with_overrides(),
            "control-loss",
            {},
        )
        self.assertEqual(control["state"], "protected-stop")
        self.assertEqual(control["reason_codes"], ["control-loss"])

        security = transition_replanning_state(
            _state_with_overrides(),
            "clean-no-artifact",
            {
                "trusted_evidence": True,
                "exact_model": True,
                "control_healthy": True,
                "mutation": {"out_of_scope": False, "tainted": False},
                "security_changed": True,
            },
        )
        self.assertEqual(security["state"], "protected-stop")
        self.assertIn("security-or-authority-change", security["reason_codes"])

        invalid = transition_replanning_state(
            _state_with_overrides(),
            "clean-no-artifact",
            {
                "trusted_evidence": False,
                "exact_model": True,
                "control_healthy": True,
                "mutation": {"out_of_scope": False, "tainted": False},
            },
        )
        self.assertEqual(invalid["state"], "protected-stop")
        self.assertIn("invalid-trusted-evidence", invalid["reason_codes"])

    def test_aggregate_allowance_shared_across_reassignment(self) -> None:
        evidence = {
            "trusted_evidence": True,
            "exact_model": True,
            "control_healthy": True,
            "tool_calls_delta": 8,
            "runtime_seconds_delta": 16,
            "mutation": {"out_of_scope": False, "tainted": False},
        }
        with_dispatch = transition_replanning_state(_base_state(), "dispatch-started", {})
        with_dispatch["counters"]["tool_calls_used"] = 8
        with_dispatch["counters"]["runtime_seconds_used"] = 16
        with_dispatch = transition_replanning_state(with_dispatch, "clean-no-artifact", evidence)
        with_dispatch = transition_replanning_state(with_dispatch, "pm-refined", {"requires_architect_cycle": False})
        reassign = transition_replanning_state(with_dispatch, "fresh-worker-assigned", {})
        self.assertEqual(reassign["state"], "dispatchable")
        self.assertEqual(reassign["counters"]["tool_calls_used"], 16)
        self.assertEqual(reassign["counters"]["runtime_seconds_used"], 32)

    def test_dispatch_soft_cap_is_warning_only(self) -> None:
        policy = _policy_with({"dispatch_soft_cap": 1, "dispatch_soft_cap_action": "pm-architect-review"})
        state = build_replanning_state(
            {
                **_base_state(),
                "state": "dispatchable",
                "counters": {
                    **_base_state()["counters"],
                    "dispatches": 1,
                },
            },
            policy=policy,
        )
        dispatch = transition_replanning_state(state, "dispatch-started", {}, policy=policy)
        self.assertEqual(dispatch["state"], "executing")
        self.assertIn("dispatch-soft-cap-exceeded", dispatch["reason_codes"])
        self.assertNotEqual(dispatch["state"], "protected-stop")

    def test_invalid_state_event_evidence_fails_closed(self) -> None:
        with self.assertRaises(ValueError):
            build_replanning_state({"state": "executing", "work_unit_id": "wu", "bead_id": "bead", "packet_id": "pkt", "requested_model": "gpt-5.3-codex-spark", "objective": "x", "security_context": "x", "authority": "x", "aggregate_allowance": {"tool_calls_hard": 1, "runtime_seconds_hard": 1}})
        with self.assertRaises(ValueError):
            transition_replanning_state(_state_with_overrides(), "no-such-event", {})
        with self.assertRaises(ValueError):
            transition_replanning_state(_state_with_overrides(), "accepted", 42)

    def test_schema_and_policy_load_checks(self) -> None:
        policy = json.loads((ROOT / "policy" / "native-worker-execution.yaml").read_text(encoding="utf-8"))
        replanning = policy["work_sizing"]["enforcement"]["foundation-canary"]["autonomous_replanning"]
        self.assertIn("autonomous_replanning", str(policy))
        self.assertEqual(replanning["live_replay_enabled"], False)
        self.assertEqual(replanning["fresh-worker-reassignment"]["required"], True)

        schema = json.loads((ROOT / "schemas" / "native-replanning-state.schema.json").read_text(encoding="utf-8"))
        self.assertEqual(schema["title"], "Native Replanning State")
        required = set(schema["required"])
        self.assertIn("cwo_native_replanning_receipt", required)
        state = _state_with_overrides()
        self.assertEqual(state["schema"], "schemas/native-replanning-state.schema.json")
