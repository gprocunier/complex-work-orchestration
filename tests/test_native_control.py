from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from cwo_core.native_control import (  # noqa: E402
    ALLOWED_ACTIONS,
    NativeControlTurn,
    build_control_turn_contract,
    run_control_turn,
    validate_control_callbacks,
    validate_control_turn_contract,
)


TASK = "perform bounded work"


def contract() -> dict:
    return build_control_turn_contract(
        state_file="/tmp/cwo-supervision-state.json",
        agent_id="agent-1",
        control_turn_id="turn-1",
        task_sha256=hashlib.sha256(TASK.encode("utf-8")).hexdigest(),
        poll_interval_ms=1000,
    )


class FakeAdapter:
    def __init__(self, decisions: list[str], *, fail: str | None = None) -> None:
        self.decisions = list(decisions)
        self.fail = fail
        self.calls: list[tuple[str, dict]] = []

    def _call(self, name: str, kwargs: dict, result=None):
        self.calls.append((name, kwargs))
        if self.fail == name:
            raise RuntimeError(f"{name} failed")
        return result

    def callbacks(self) -> dict:
        return {
            "arm": lambda **kwargs: self._call("arm", kwargs),
            "send_input": lambda **kwargs: self._call("send_input", kwargs, {"submission_id": "submission-1"}),
            "mark_dispatched": lambda **kwargs: self._call("mark_dispatched", kwargs),
            "check": self.check,
            "interrupt": lambda **kwargs: self._call("interrupt", kwargs),
            "close": lambda **kwargs: self._call("close", kwargs),
            "finalize": lambda **kwargs: self._call("finalize", kwargs),
            "sleep": lambda **kwargs: self._call("sleep", kwargs),
        }

    def check(self, **kwargs):
        decision = self.decisions.pop(0)
        return self._call("check", kwargs, {"decision": decision})


class NativeControlTest(unittest.TestCase):
    def run_renderer(self, state: object, *, agent_id: str = "agent-1", task: str = TASK):
        with tempfile.TemporaryDirectory() as temporary:
            state_path = Path(temporary) / "state.json"
            if isinstance(state, str):
                state_path.write_text(state, encoding="utf-8")
            else:
                state_path.write_text(json.dumps(state), encoding="utf-8")
            return subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "scripts" / "render_native_control_turn.py"),
                    "--state-file",
                    str(state_path),
                    "--agent-id",
                    agent_id,
                    "--control-turn-id",
                    "turn-rendered",
                    "--task-sha256",
                    hashlib.sha256(task.encode("utf-8")).hexdigest(),
                ],
                cwd=ROOT,
                check=False,
                capture_output=True,
                text=True,
            )

    @staticmethod
    def renderer_state() -> dict:
        return {
            "status": "created",
            "submission_id": None,
            "control_turn_id": None,
            "control_turn_required": True,
            "decision": "continue",
            "agent_id": "agent-1",
            "poll_interval_ms": 1000,
        }

    def test_contract_is_hash_bound_json_and_has_no_wait_action(self) -> None:
        value = contract()
        self.assertEqual(validate_control_turn_contract(value), [])
        json.dumps(value)
        self.assertEqual(value["allowed_actions"], list(ALLOWED_ACTIONS))
        self.assertFalse(any("wait" in action for action in value["allowed_actions"]))
        changed = dict(value)
        changed["agent_id"] = "different"
        self.assertIn("contract-sha256-mismatch", validate_control_turn_contract(changed))

    def test_complete_path_has_immediate_check_and_policy_sleep(self) -> None:
        adapter = FakeAdapter(["continue", "warn", "complete"])
        result = run_control_turn(contract(), TASK, adapter.callbacks())
        self.assertEqual(result["terminal_state"], "completed")
        self.assertEqual(result["poll_count"], 3)
        self.assertEqual(
            result["actions"],
            [
                "arm",
                "send-input",
                "mark-dispatched",
                "check",
                "sleep",
                "check",
                "sleep",
                "check",
                "finalize:worker-completed",
                "close",
            ],
        )
        sleeps = [kwargs for name, kwargs in adapter.calls if name == "sleep"]
        self.assertEqual(sleeps, [{"seconds": 1.0}, {"seconds": 1.0}])

    def test_interrupt_path_records_interrupt_and_close_receipts(self) -> None:
        adapter = FakeAdapter(["interrupt"])
        result = run_control_turn(contract(), TASK, adapter.callbacks())
        self.assertEqual(result["terminal_state"], "closed")
        self.assertEqual(
            result["actions"][-4:],
            ["interrupt", "finalize:interrupt-confirmed", "close", "finalize:close-confirmed"],
        )
        final_actions = [kwargs["control_action"] for name, kwargs in adapter.calls if name == "finalize"]
        self.assertEqual(final_actions, ["interrupt-confirmed", "close-confirmed"])

    def test_control_lost_uses_same_fail_closed_native_actions(self) -> None:
        adapter = FakeAdapter(["control-lost"])
        result = run_control_turn(contract(), TASK, adapter.callbacks())
        self.assertEqual(result["decisions"], ["control-lost"])
        self.assertEqual(result["terminal_state"], "closed")
        self.assertIn("interrupt", result["actions"])

    def test_callback_failure_emits_control_failed_receipt(self) -> None:
        adapter = FakeAdapter(["complete"], fail="check")
        result = run_control_turn(contract(), TASK, adapter.callbacks())
        self.assertEqual(result["terminal_state"], "control-failed")
        self.assertTrue(any(error.startswith("callback-failed:RuntimeError") for error in result["errors"]))
        self.assertEqual(result["actions"][-1], "finalize:control-failed")

    def test_wait_callback_is_rejected_before_dispatch(self) -> None:
        adapter = FakeAdapter(["complete"])
        callbacks = adapter.callbacks()
        callbacks["wait_agent"] = lambda **kwargs: None
        errors = validate_control_callbacks(callbacks)
        self.assertIn("wait-callback-forbidden:wait_agent", errors)
        result = run_control_turn(contract(), TASK, callbacks)
        self.assertEqual(result["terminal_state"], "control-failed")
        self.assertEqual(adapter.calls, [])

    def test_malformed_contract_and_task_hash_fail_before_dispatch(self) -> None:
        adapter = FakeAdapter(["complete"])
        malformed = contract()
        malformed["poll_interval_ms"] = 0
        result = run_control_turn(malformed, TASK, adapter.callbacks())
        self.assertEqual(result["terminal_state"], "control-failed")
        self.assertEqual(adapter.calls, [])
        adapter = FakeAdapter(["complete"])
        result = run_control_turn(contract(), "different task", adapter.callbacks())
        self.assertIn("task-sha256-mismatch", result["errors"])
        self.assertEqual(adapter.calls, [])

    def test_turn_cannot_dispatch_twice(self) -> None:
        adapter = FakeAdapter(["complete"])
        runner = NativeControlTurn(contract(), adapter.callbacks())
        self.assertEqual(runner.run(TASK)["terminal_state"], "completed")
        second = runner.run(TASK)
        self.assertEqual(second["terminal_state"], "control-failed")
        self.assertEqual(second["errors"], ["control-turn-already-dispatched"])

    def test_unknown_decision_fails_closed(self) -> None:
        adapter = FakeAdapter(["maybe"])
        result = run_control_turn(contract(), TASK, adapter.callbacks())
        self.assertEqual(result["terminal_state"], "control-failed")
        self.assertTrue(any("invalid decision" in error for error in result["errors"]))

    def test_renderer_emits_hash_bound_contract_without_task_content(self) -> None:
        result = self.run_renderer(self.renderer_state(), task="private task content")
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(validate_control_turn_contract(payload), [])
        self.assertEqual(payload["agent_id"], "agent-1")
        self.assertEqual(payload["control_turn_id"], "turn-rendered")
        self.assertEqual(payload["poll_interval_ms"], 1000)
        self.assertEqual(payload["task_sha256"], hashlib.sha256(b"private task content").hexdigest())
        self.assertNotIn("private task content", result.stdout)

    def test_renderer_rejects_noncreated_or_dispatched_state(self) -> None:
        cases = [
            ({**self.renderer_state(), "status": "running"}, "state-status-invalid"),
            ({**self.renderer_state(), "submission_id": "submission-1"}, "state-submission-id-must-be-null"),
            ({**self.renderer_state(), "control_turn_id": "already-armed"}, "state-control-turn-id-must-be-null"),
        ]
        for state, expected in cases:
            with self.subTest(expected=expected):
                result = self.run_renderer(state)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(expected, result.stderr)

    def test_renderer_rejects_agent_mismatch_and_malformed_json(self) -> None:
        mismatch = self.run_renderer(self.renderer_state(), agent_id="different-agent")
        self.assertNotEqual(mismatch.returncode, 0)
        self.assertIn("state-agent-id-mismatch", mismatch.stderr)
        malformed = self.run_renderer("{")
        self.assertNotEqual(malformed.returncode, 0)
        self.assertIn("malformed-state-json", malformed.stderr)


if __name__ == "__main__":
    unittest.main()
