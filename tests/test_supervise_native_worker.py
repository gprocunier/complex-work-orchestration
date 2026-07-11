from __future__ import annotations

import json
import importlib.util
import datetime as dt
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "supervise_native_worker.py"
sys.path.insert(0, str(ROOT / "scripts"))

from prepare_native_worker import build_native_worker_packet  # noqa: E402


MODEL = "gpt-5.3-codex-spark"
CONTROL_TURN = "control-turn-test"
HAS_JSONSCHEMA = importlib.util.find_spec("jsonschema") is not None


def run_cli(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )


def write_records(path: Path, records: list[dict], *, trailing: str = "") -> None:
    text = "\n".join(json.dumps(record, separators=(",", ":")) for record in records) + "\n"
    path.write_text(text + trailing, encoding="utf-8")


def session_meta(session_id: str) -> dict:
    return {
        "timestamp": "2026-07-11T00:00:00Z",
        "type": "session_meta",
        "payload": {"id": session_id},
        "turn_context": {
            "model": MODEL,
            "attestation_source": "trusted-control-plane-session-metadata",
            "token_count": {"input": 0, "cached_input": 0, "output": 0, "reasoning": 0, "total": 0},
        },
    }


def event(
    timestamp: str,
    session_id: str,
    name: str,
    *,
    model: str = MODEL,
    tool: bool = False,
    command: str | None = None,
) -> dict:
    record: dict = {
        "timestamp": timestamp,
        "session_id": session_id,
        "event_msg": name,
        "turn_context": {
            "model": model,
            "attestation_source": "trusted-control-plane-session-metadata",
            "token_count": {"input": 1, "cached_input": 0, "output": 1, "reasoning": 0, "total": 2},
        },
    }
    if tool:
        record["response_item"] = {
            "type": "function_call",
            "arguments": json.dumps({"command": command or "true"}),
        }
    return record


class NativeWorkerSupervisorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="cwo-supervision-test-")
        self.root = Path(self.tmp.name)
        self.session_id = "spark-session"
        self.session_file = self.root / "session.jsonl"
        self.packet_file = self.root / "packet.json"
        self.state_file = self.root / "state.json"
        self.audit_file = self.root / "audit.jsonl"
        self.activated = False
        packet = build_native_worker_packet(
            bead_id="bead-supervision",
            lane="implementation",
            workdir=str(ROOT),
            allowed_paths=[str(ROOT / "scripts")],
            acceptance_checks=["focused tests pass"],
            packet_id="packet-supervision",
            budget_overrides={
                "tool_calls_soft": 5,
                "tool_calls_hard": 10,
                "runtime_seconds_soft": 30,
                "runtime_seconds_hard": 60,
            },
        )
        self.packet_file.write_text(json.dumps(packet), encoding="utf-8")
        write_records(self.session_file, [session_meta(self.session_id)])

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def start(self, *, now: str = "2026-07-11T00:00:00Z") -> subprocess.CompletedProcess[str]:
        return run_cli(
            "start",
            "--packet",
            str(self.packet_file),
            "--session-id",
            self.session_id,
            "--session-file",
            str(self.session_file),
            "--agent-id",
            "agent-spark",
            "--state-file",
            str(self.state_file),
            "--audit-file",
            str(self.audit_file),
            "--now",
            now,
            "--json",
        )

    def arm(self, now: str, *, control_turn: str = CONTROL_TURN) -> subprocess.CompletedProcess[str]:
        return run_cli(
            "arm",
            "--state-file",
            str(self.state_file),
            "--control-turn-id",
            control_turn,
            "--now",
            now,
            "--json",
        )

    def mark_dispatched(
        self,
        now: str,
        *,
        control_turn: str = CONTROL_TURN,
    ) -> subprocess.CompletedProcess[str]:
        result = run_cli(
            "mark-dispatched",
            "--state-file",
            str(self.state_file),
            "--control-turn-id",
            control_turn,
            "--submission-id",
            "submission-test",
            "--now",
            now,
            "--json",
        )
        if result.returncode == 0:
            self.activated = True
        return result

    def activate_before(self, now: str) -> None:
        parsed = dt.datetime.fromisoformat(now.replace("Z", "+00:00"))
        arm_at = (parsed - dt.timedelta(seconds=2)).strftime("%Y-%m-%dT%H:%M:%SZ")
        dispatch_at = (parsed - dt.timedelta(seconds=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
        state = json.loads(self.state_file.read_text(encoding="utf-8"))
        if state["status"] == "created":
            armed = self.arm(arm_at)
            self.assertEqual(armed.returncode, 0, armed.stderr)
        dispatched = self.mark_dispatched(dispatch_at)
        self.assertEqual(dispatched.returncode, 0, dispatched.stderr)

    def check(self, now: str, *, control_turn: str = CONTROL_TURN) -> subprocess.CompletedProcess[str]:
        if not self.activated:
            self.activate_before(now)
        return run_cli(
            "check",
            "--state-file",
            str(self.state_file),
            "--control-turn-id",
            control_turn,
            "--now",
            now,
            "--json",
        )

    def finalize(self, action: str) -> subprocess.CompletedProcess[str]:
        return run_cli(
            "finalize",
            "--state-file",
            str(self.state_file),
            "--control-turn-id",
            CONTROL_TURN,
            "--control-action",
            action,
            "--now",
            "2026-07-11T00:01:00Z",
            "--json",
        )

    def test_start_attests_and_refuses_duplicate_state(self) -> None:
        started = self.start()
        self.assertEqual(started.returncode, 0, started.stderr)
        payload = json.loads(started.stdout)
        self.assertEqual(payload["requested_model"], MODEL)
        self.assertEqual(payload["interrupt_thresholds"], {"tool_calls": 7, "runtime_seconds": 54})
        self.assertEqual(payload["segment_start_grace_seconds"], 10)
        self.assertEqual(payload["baseline_record_count"], 1)
        self.assertEqual(payload["status"], "created")
        events = [json.loads(line) for line in self.audit_file.read_text(encoding="utf-8").splitlines()]
        self.assertEqual([item["event_type"] for item in events], ["native_supervision_started"])
        self.assertEqual(events[0]["planned_tool_calls_hard"], 10)
        self.assertEqual(events[0]["interrupt_tool_calls_threshold"], 7)
        if HAS_JSONSCHEMA:
            import jsonschema

            state_schema = json.loads((ROOT / "schemas" / "native-supervision-state.schema.json").read_text(encoding="utf-8"))
            jsonschema.validate(json.loads(self.state_file.read_text(encoding="utf-8")), state_schema)
        armed = self.arm("2026-07-11T00:00:01Z")
        self.assertEqual(armed.returncode, 0, armed.stderr)
        invalid_receipt = self.finalize("interrupt-confirmed")
        self.assertNotEqual(invalid_receipt.returncode, 0)
        self.assertIn("requires an interrupt", invalid_receipt.stderr)
        invalid_completion = self.finalize("worker-completed")
        self.assertNotEqual(invalid_completion.returncode, 0)
        self.assertIn("requires a complete", invalid_completion.stderr)
        duplicate = self.start()
        self.assertNotEqual(duplicate.returncode, 0)
        self.assertIn("duplicate active", duplicate.stderr)

    def test_start_rejects_attestation_mismatch(self) -> None:
        records = [session_meta(self.session_id)]
        records[0]["turn_context"]["model"] = "gpt-5.6-sol"
        write_records(self.session_file, records)
        result = self.start()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("attestation mismatch", result.stderr)

    def test_unarmed_check_and_dispatch_are_rejected(self) -> None:
        self.assertEqual(self.start().returncode, 0)
        unchecked = run_cli(
            "check",
            "--state-file",
            str(self.state_file),
            "--control-turn-id",
            CONTROL_TURN,
            "--now",
            "2026-07-11T00:00:01Z",
            "--json",
        )
        self.assertNotEqual(unchecked.returncode, 0)
        self.assertIn("does not match", unchecked.stderr)
        dispatched = self.mark_dispatched("2026-07-11T00:00:01Z")
        self.assertNotEqual(dispatched.returncode, 0)
        self.assertIn("requires an armed", dispatched.stderr)

    def test_arm_window_and_control_turn_binding_fail_closed(self) -> None:
        self.assertEqual(self.start().returncode, 0)
        self.assertEqual(self.arm("2026-07-11T00:00:01Z").returncode, 0)
        wrong_turn = self.mark_dispatched(
            "2026-07-11T00:00:02Z",
            control_turn="different-turn",
        )
        self.assertEqual(wrong_turn.returncode, 2, wrong_turn.stderr)
        wrong_payload = json.loads(wrong_turn.stdout)
        self.assertEqual(wrong_payload["decision"], "control-lost")
        self.assertIn("control-turn-mismatch-after-dispatch", wrong_payload["reasons"])

        self.state_file.unlink()
        self.audit_file.unlink()
        write_records(self.session_file, [session_meta(self.session_id)])
        self.assertEqual(self.start().returncode, 0)
        self.assertEqual(self.arm("2026-07-11T00:00:01Z").returncode, 0)
        stale = self.mark_dispatched("2026-07-11T00:00:07Z")
        self.assertEqual(stale.returncode, 2, stale.stderr)
        payload = json.loads(stale.stdout)
        self.assertEqual(payload["decision"], "control-lost")
        self.assertIn("arm-to-dispatch-latency-exceeded", payload["reasons"])
        self.assertTrue(payload["control_action_required"])

    def test_wrong_control_turn_during_running_monitor_quarantines(self) -> None:
        self.assertEqual(self.start().returncode, 0)
        self.assertEqual(self.arm("2026-07-11T00:00:00Z").returncode, 0)
        self.assertEqual(self.mark_dispatched("2026-07-11T00:00:01Z").returncode, 0)
        checked = self.check(
            "2026-07-11T00:00:02Z",
            control_turn="different-turn",
        )
        self.assertEqual(checked.returncode, 2, checked.stderr)
        payload = json.loads(checked.stdout)
        self.assertEqual(payload["decision"], "control-lost")
        self.assertIn("control-turn-mismatch-during-monitoring", payload["reasons"])
        self.assertEqual(payload["session_disposition"], "quarantined")

    def test_late_first_and_intermediate_polls_fail_closed(self) -> None:
        self.assertEqual(self.start().returncode, 0)
        self.assertEqual(self.arm("2026-07-11T00:00:00Z").returncode, 0)
        self.assertEqual(self.mark_dispatched("2026-07-11T00:00:01Z").returncode, 0)
        late_first = self.check("2026-07-11T00:00:04Z")
        self.assertEqual(late_first.returncode, 2, late_first.stderr)
        payload = json.loads(late_first.stdout)
        self.assertEqual(payload["decision"], "control-lost")
        self.assertEqual(payload["control_timing"]["dispatch_to_first_poll_ms"], 3000)
        self.assertEqual(payload["control_timing"]["late_poll_count"], 1)

        self.state_file.unlink()
        self.audit_file.unlink()
        self.activated = False
        write_records(self.session_file, [session_meta(self.session_id)])
        self.assertEqual(self.start().returncode, 0)
        first = self.check("2026-07-11T00:00:03Z")
        self.assertEqual(first.returncode, 0, first.stderr)
        late_next = self.check("2026-07-11T00:00:06Z")
        self.assertEqual(late_next.returncode, 2, late_next.stderr)
        next_payload = json.loads(late_next.stdout)
        self.assertEqual(next_payload["decision"], "control-lost")
        self.assertEqual(next_payload["control_timing"]["max_poll_gap_ms"], 3000)

    def test_startup_grace_then_fail_closed_without_task_boundary(self) -> None:
        self.assertEqual(self.start().returncode, 0)
        waiting = self.check("2026-07-11T00:00:05Z")
        self.assertEqual(waiting.returncode, 0, waiting.stderr)
        self.assertEqual(json.loads(waiting.stdout)["reasons"], ["awaiting-task-boundary"])
        if HAS_JSONSCHEMA:
            import jsonschema

            decision_schema = json.loads((ROOT / "schemas" / "native-supervision-decision.schema.json").read_text(encoding="utf-8"))
            jsonschema.validate(json.loads(waiting.stdout), decision_schema)
        for second in range(6, 15):
            polled = self.check(f"2026-07-11T00:00:{second:02d}Z")
            self.assertEqual(polled.returncode, 0, polled.stderr)
        expired = self.check("2026-07-11T00:00:15Z")
        self.assertEqual(expired.returncode, 2, expired.stderr)
        payload = json.loads(expired.stdout)
        self.assertEqual(payload["decision"], "control-lost")
        self.assertTrue(payload["control_action_required"])

    def test_completed_attestation_segment_is_outside_live_task_watermark(self) -> None:
        attestation_records = [
            session_meta(self.session_id),
            event("2026-07-10T23:59:58Z", self.session_id, "task_started"),
            event("2026-07-10T23:59:59Z", self.session_id, "task_complete"),
        ]
        write_records(self.session_file, attestation_records)
        started = self.start()
        self.assertEqual(started.returncode, 0, started.stderr)
        self.assertEqual(json.loads(started.stdout)["baseline_record_count"], 3)

        waiting = self.check("2026-07-11T00:00:05Z")
        self.assertEqual(waiting.returncode, 0, waiting.stderr)
        self.assertEqual(json.loads(waiting.stdout)["reasons"], ["awaiting-task-boundary"])

        operative_records = [
            event("2026-07-11T00:00:05.100Z", self.session_id, "task_started"),
            event("2026-07-11T00:00:05.200Z", self.session_id, "assistant", tool=True),
            event("2026-07-11T00:00:05.300Z", self.session_id, "task_complete"),
        ]
        write_records(self.session_file, [*attestation_records, *operative_records])
        checked = self.check("2026-07-11T00:00:06Z")
        self.assertEqual(checked.returncode, 0, checked.stderr)
        payload = json.loads(checked.stdout)
        self.assertEqual(payload["decision"], "complete")
        self.assertEqual(payload["observed"]["tool_calls"], 1)

    def test_under_budget_completion_uses_selected_segment_not_raw_tail(self) -> None:
        self.assertEqual(self.start().returncode, 0)
        records = [
            session_meta(self.session_id),
            event("2026-07-11T00:00:01Z", self.session_id, "task_started"),
            event("2026-07-11T00:00:02Z", self.session_id, "assistant", tool=True),
            event("2026-07-11T00:00:03Z", self.session_id, "task_complete"),
        ]
        records.extend(
            event(f"2026-07-11T00:00:{second:02d}Z", self.session_id, "token_count")
            for second in range(4, 10)
        )
        write_records(self.session_file, records)
        checked = self.check("2026-07-11T00:00:10Z")
        self.assertEqual(checked.returncode, 0, checked.stderr)
        self.assertEqual(json.loads(checked.stdout)["decision"], "complete")
        finalized = self.finalize("worker-completed")
        self.assertEqual(finalized.returncode, 0, finalized.stderr)
        self.assertEqual(json.loads(finalized.stdout)["status"], "completed")
        events = [json.loads(line) for line in self.audit_file.read_text(encoding="utf-8").splitlines()]
        self.assertEqual(
            [item["event_type"] for item in events],
            ["native_supervision_started", "native_supervision_armed", "native_supervision_dispatched", "native_supervision_decision", "native_supervision_control_receipt"],
        )
        self.assertEqual(events[3]["observed_tool_calls"], 1)
        self.assertEqual(events[-1]["control_action"], "worker-completed")
        self.assertNotIn("agent_model_calls", events[0])
        self.assertEqual(events[3]["agent_model_calls"], 1)
        self.assertNotIn("agent_model_calls", events[-1])
        self.assertNotIn("workerbee_actual_model", events[-1])
        self.assertTrue(events[3]["monitor_armed_before_dispatch"])
        self.assertEqual(events[3]["arm_to_dispatch_ms"], 1000)
        self.assertEqual(events[3]["dispatch_to_first_poll_ms"], 1000)
        self.assertEqual(events[3]["max_poll_gap_ms"], 1000)
        self.assertEqual(events[3]["late_poll_count"], 0)

    def test_budget_observation_uses_selected_operative_segment(self) -> None:
        self.assertEqual(self.start().returncode, 0)
        records = [
            session_meta(self.session_id),
            event("2026-07-10T23:50:00Z", self.session_id, "task_started"),
            event("2026-07-11T00:00:00Z", self.session_id, "task_complete"),
            event("2026-07-11T00:00:01Z", self.session_id, "task_started"),
            event("2026-07-11T00:00:02Z", self.session_id, "assistant", tool=True),
            event("2026-07-11T00:00:03Z", self.session_id, "task_complete"),
        ]
        write_records(self.session_file, records)
        checked = self.check("2026-07-11T00:00:04Z")
        self.assertEqual(checked.returncode, 0, checked.stderr)
        payload = json.loads(checked.stdout)
        self.assertEqual(payload["decision"], "complete")
        self.assertEqual(payload["observed"]["tool_calls"], 1)
        self.assertEqual(payload["observed"]["elapsed_seconds"], 2)

    def test_tool_reserve_interrupts_at_threshold(self) -> None:
        self.assertEqual(self.start().returncode, 0)
        records = [session_meta(self.session_id), event("2026-07-11T00:00:01Z", self.session_id, "task_started")]
        records.extend(
            event(f"2026-07-11T00:00:{second:02d}Z", self.session_id, "assistant", tool=True)
            for second in range(2, 9)
        )
        write_records(self.session_file, records)
        checked = self.check("2026-07-11T00:00:09Z")
        self.assertEqual(checked.returncode, 2, checked.stderr)
        payload = json.loads(checked.stdout)
        self.assertEqual(payload["decision"], "interrupt")
        self.assertEqual(payload["observed"]["tool_calls"], 7)
        self.assertIn("tool-call-interrupt-threshold", payload["reasons"])

        premature = self.finalize("close-confirmed")
        self.assertNotEqual(premature.returncode, 0)
        self.assertIn("requires an interrupt-confirmed", premature.stderr)
        self.assertEqual(self.finalize("interrupt-confirmed").returncode, 0)
        closed = self.finalize("close-confirmed")
        self.assertEqual(closed.returncode, 0, closed.stderr)
        closed_payload = json.loads(closed.stdout)
        self.assertEqual(closed_payload["status"], "closed")
        self.assertFalse(closed_payload["control_action_required"])

    def test_compaction_full_suite_mismatch_and_trailing_partial_fail_closed(self) -> None:
        cases = [
            (event("2026-07-11T00:00:02Z", self.session_id, "context_compacted"), "context-compaction"),
            (
                event(
                    "2026-07-11T00:00:02Z",
                    self.session_id,
                    "assistant",
                    tool=True,
                    command="python -m unittest discover -s tests -v",
                ),
                "full-suite-limit",
            ),
            (event("2026-07-11T00:00:02Z", self.session_id, "assistant", model="gpt-5.6-sol"), "model-mismatch"),
        ]
        for index, (trigger, reason) in enumerate(cases):
            with self.subTest(reason=reason):
                if index:
                    self.state_file.unlink()
                    write_records(self.session_file, [session_meta(self.session_id)])
                    self.activated = False
                self.assertEqual(self.start().returncode, 0)
                records = [
                    session_meta(self.session_id),
                    event("2026-07-11T00:00:01Z", self.session_id, "task_started"),
                    trigger,
                ]
                write_records(self.session_file, records, trailing='{"timestamp":')
                checked = self.check("2026-07-11T00:00:03Z")
                self.assertEqual(checked.returncode, 2, checked.stderr)
                payload = json.loads(checked.stdout)
                self.assertIn(reason, payload["reasons"])
                self.assertTrue(payload["trailing_partial_record_ignored"])

    def test_missing_session_after_start_is_control_lost(self) -> None:
        self.assertEqual(self.start().returncode, 0)
        self.session_file.unlink()
        checked = self.check("2026-07-11T00:00:01Z")
        self.assertEqual(checked.returncode, 2, checked.stderr)
        self.assertEqual(json.loads(checked.stdout)["decision"], "control-lost")
        failed = self.finalize("control-failed")
        self.assertEqual(failed.returncode, 0, failed.stderr)
        self.assertFalse(json.loads(failed.stdout)["control_action_required"])
        final_check = self.check("2026-07-11T00:00:02Z")
        self.assertEqual(final_check.returncode, 2, final_check.stderr)


if __name__ == "__main__":
    unittest.main()
