from __future__ import annotations

import datetime as dt
from dataclasses import replace
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from typing import Mapping
import unittest
from unittest import mock
import uuid


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from cwo_core import native_live_campaign_contracts as CAMPAIGN_CONTRACTS  # noqa: E402

SPEC = importlib.util.spec_from_file_location(
    "run_native_pool_live_canaries", ROOT / "scripts" / "run_native_pool_live_canaries.py"
)
assert SPEC and SPEC.loader
LIVE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(LIVE)


class FakeCalibrationServer:
    def __init__(
        self,
        root: Path,
        *,
        early_status: str | None = None,
        command_status: str = "inProgress",
        command_source: str | None = "unifiedExecStartup",
        omit_command_source: bool = False,
        notification_item_type: str = "commandExecution",
        notification_command: str = "/bin/bash -lc 'sleep 20'",
        function_command: str = "sleep 20",
        notification_workspace_mismatch: bool = False,
        missing_start: bool = False,
        duplicate_start: bool = False,
        cross_turn_start: bool = False,
        cross_thread_start: bool = False,
        completed_before_interrupt: bool = False,
        output_before_interrupt: bool = False,
        duplicate_function_call: bool = False,
        competing_function_call: bool = False,
        replace_source_at_read: int | None = None,
        replace_notification_at_read: int | None = None,
        read_statuses: list[str] | None = None,
        durable_terminal_type: str | None = None,
        duplicate_durable_terminal: bool = False,
        interrupt_terminal_type: str = "turn_aborted",
    ) -> None:
        self.codex_home = root / "codex-home"
        self.active = self.codex_home / "sessions" / "2026" / "07"
        self.archive = self.codex_home / "archived_sessions"
        self.active.mkdir(parents=True)
        self.archive.mkdir(parents=True)
        self.thread_id = str(uuid.uuid4())
        self.turn_id = str(uuid.uuid4())
        self.path = self.active / f"rollout-{self.thread_id}.jsonl"
        self.read_count = 0
        self.interrupted = False
        self.early_status = early_status
        self.command_status = command_status
        self.command_source = command_source
        self.omit_command_source = omit_command_source
        self.notification_item_type = notification_item_type
        self.notification_command = notification_command
        self.function_command = function_command
        self.notification_workspace_mismatch = notification_workspace_mismatch
        self.missing_start = missing_start
        self.duplicate_start = duplicate_start
        self.cross_turn_start = cross_turn_start
        self.cross_thread_start = cross_thread_start
        self.completed_before_interrupt = completed_before_interrupt
        self.output_before_interrupt = output_before_interrupt
        self.duplicate_function_call = duplicate_function_call
        self.competing_function_call = competing_function_call
        self.replace_source_at_read = replace_source_at_read
        self.replace_notification_at_read = replace_notification_at_read
        self.read_statuses = list(read_statuses or [])
        self.durable_terminal_type = durable_terminal_type
        self.duplicate_durable_terminal = duplicate_durable_terminal
        self.interrupt_terminal_type = interrupt_terminal_type
        self.started_cwd: Path | None = None
        self.connection_epoch_sha256 = "b" * 64
        self._notifications: list[tuple[int, dict]] = []
        self.rpc_latencies = {}

    def _write(self, records: list[dict]) -> None:
        self.path.write_text("".join(json.dumps(item) + "\n" for item in records), encoding="utf-8")

    def start_thread(
        self, _cwd: Path, *, mutable: bool, role: str | None = None
    ) -> tuple[dict, float]:
        self.assert_false(mutable)
        self.started_cwd = _cwd.resolve()
        return {
            "model": LIVE.EXACT_MODEL,
            "modelProvider": "trusted",
            "thread": {"id": self.thread_id, "turns": [], "path": str(self.path)},
        }, 1.0

    @staticmethod
    def assert_false(value: bool) -> None:
        if value:
            raise AssertionError("expected false")

    def start_turn(self, thread_id: str, _prompt: str) -> tuple[dict, float]:
        if thread_id != self.thread_id:
            raise AssertionError("thread mismatch")
        self._write(
            [
                {"type": "session_meta", "payload": {"id": self.thread_id}},
                {"type": "event_msg", "payload": {"type": "task_started", "turn_id": self.turn_id}},
                {"type": "response_item", "payload": {"type": "message", "role": "user"}},
            ]
        )
        return {"id": self.turn_id}, 1.0

    def _thread(self) -> dict:
        status = "interrupted" if self.interrupted else self.early_status or "inProgress"
        return {
            "id": self.thread_id,
            "path": str(self.path),
            "turns": [{"id": self.turn_id, "status": status, "items": []}],
        }

    def _materialize(self) -> None:
        records = [
            {
                "type": "turn_context",
                "payload": {
                    "turn_id": self.turn_id,
                    "model": LIVE.EXACT_MODEL,
                    "effort": "low",
                },
            },
            {
                "type": "response_item",
                "payload": {
                    "type": "function_call",
                    "name": "exec_command",
                    "call_id": "call-one",
                    "id": "call-one",
                    "arguments": json.dumps({"cmd": self.function_command}),
                },
            },
        ]
        if self.duplicate_function_call:
            records.append(
                {
                    "type": "response_item",
                    "payload": {
                        "type": "function_call",
                        "name": "exec_command",
                        "call_id": "call-two",
                        "id": "call-two",
                        "arguments": json.dumps({"cmd": self.function_command}),
                    },
                }
            )
        if self.competing_function_call:
            records.append(
                {
                    "type": "response_item",
                    "payload": {
                        "type": "function_call",
                        "name": "custom_tool",
                        "call_id": "call-other",
                        "arguments": "{}",
                    },
                }
            )
        if self.output_before_interrupt:
            records.append(
                {
                    "type": "response_item",
                    "payload": {
                        "type": "function_call_output",
                        "call_id": "call-one",
                        "output": "sanitized",
                    },
                }
            )
        if self.durable_terminal_type is not None:
            records.append(
                {
                    "type": "event_msg",
                    "payload": {
                        "type": self.durable_terminal_type,
                        "turn_id": self.turn_id,
                    },
                }
            )
            if self.duplicate_durable_terminal:
                records.append(
                    {
                        "type": "event_msg",
                        "payload": {
                            "type": "turn_aborted",
                            "turn_id": self.turn_id,
                        },
                    }
                )
        with self.path.open("a", encoding="utf-8") as stream:
            stream.write("".join(json.dumps(item) + "\n" for item in records))
        if not self.missing_start:
            if self.started_cwd is None:
                raise AssertionError("thread cwd missing")
            notification_cwd = self.started_cwd
            if self.notification_workspace_mismatch:
                notification_cwd = self.codex_home.resolve()
            item = {
                "id": "command-one",
                "type": self.notification_item_type,
                "command": self.notification_command,
                "commandActions": [],
                "cwd": str(notification_cwd),
                "status": self.command_status,
            }
            if not self.omit_command_source:
                item["source"] = self.command_source
            params = {
                "threadId": "other-thread" if self.cross_thread_start else self.thread_id,
                "turnId": "other-turn" if self.cross_turn_start else self.turn_id,
                "startedAtMs": 1000,
                "item": item,
            }
            self._notifications.append(
                (1_000_000, {"method": "item/started", "params": params})
            )
            if self.duplicate_start:
                duplicate = {**item, "id": "command-two"}
                self._notifications.append(
                    (
                        1_000_001,
                        {
                            "method": "item/started",
                            "params": {**params, "item": duplicate},
                        },
                    )
                )
            if self.completed_before_interrupt:
                self._notifications.append(
                    (
                        1_000_002,
                        {
                            "method": "item/completed",
                            "params": {
                                "threadId": self.thread_id,
                                "turnId": self.turn_id,
                                "completedAtMs": 1001,
                                "item": {**item, "status": "completed"},
                            },
                        },
                    )
                )

    def read_thread(self, thread_id: str) -> tuple[dict, float]:
        if thread_id != self.thread_id:
            raise AssertionError("thread mismatch")
        self.read_count += 1
        if self.read_statuses:
            self.early_status = self.read_statuses.pop(0)
        if self.read_count == 3:
            self._materialize()
        if self.replace_source_at_read == self.read_count:
            replacement = self.path.with_suffix(".replacement")
            replacement.write_bytes(self.path.read_bytes())
            replacement.replace(self.path)
        if self.replace_notification_at_read == self.read_count and self._notifications:
            self._notifications[0][1]["params"]["item"]["command"] = "sleep 20"
        return self._thread(), 1.0

    def interrupt_turn(self, thread_id: str, turn_id: str) -> float:
        if (thread_id, turn_id) != (self.thread_id, self.turn_id):
            raise AssertionError("interrupt mismatch")
        self.interrupted = True
        with self.path.open("a", encoding="utf-8") as stream:
            stream.write(
                json.dumps(
                    {
                        "type": "event_msg",
                        "payload": {
                            "type": self.interrupt_terminal_type,
                            "turn_id": self.turn_id,
                        },
                    }
                )
                + "\n"
            )
        return 1.0

    def archive_thread(self, thread_id: str) -> float:
        if thread_id != self.thread_id:
            raise AssertionError("archive mismatch")
        target = self.archive / self.path.name
        shutil.move(self.path, target)
        self.path = target
        return 1.0

    def notifications(self, _thread_id: str, _method: str | None = None) -> list[dict]:
        return []

    def notification_cursor(self) -> int:
        return len(self._notifications)

    def notification_events(
        self,
        thread_id: str,
        turn_id: str,
        *,
        after_sequence: int,
    ) -> list[dict]:
        values = []
        for sequence, (received_ns, message) in enumerate(self._notifications, 1):
            params = message["params"]
            if sequence <= after_sequence:
                continue
            if params.get("threadId") != thread_id or params.get("turnId") != turn_id:
                continue
            values.append(
                {
                    "connection_epoch_sha256": self.connection_epoch_sha256,
                    "sequence": sequence,
                    "received_monotonic_ns": received_ns,
                    "method": message["method"],
                    "params": dict(params),
                }
            )
        return values


class FakeMonotonicClock:
    def __init__(self) -> None:
        self.now_ns = 0

    def __call__(self) -> int:
        return self.now_ns

    def advance_ms(self, milliseconds: int) -> None:
        self.now_ns += milliseconds * 1_000_000


class FakeLiveThreadServer:
    def __init__(
        self,
        root: Path,
        *,
        initial_boundary: str = "missing",
        read_statuses: list[str] | None = None,
    ) -> None:
        self.codex_home = root / "codex-home"
        self.active = self.codex_home / "sessions" / "2026" / "07"
        self.archive = self.codex_home / "archived_sessions"
        self.active.mkdir(parents=True)
        self.archive.mkdir(parents=True)
        self.thread_id = str(uuid.uuid4())
        self.turn_id = str(uuid.uuid4())
        self.path = self.active / f"rollout-{self.thread_id}.jsonl"
        self.started_threads: dict[str, str | None] = {self.thread_id: None}
        self.status = "inProgress"
        self.read_statuses = list(read_statuses or [])
        self.turn_result_id: str | None = self.turn_id
        self.bind_turn_result = True
        self.start_error: Exception | None = None
        self.archived = False
        self.set_boundary(initial_boundary)

    def set_boundary(self, kind: str) -> None:
        if self.path.exists():
            self.path.unlink()
        if kind == "missing":
            return
        if kind == "empty":
            self.path.touch()
            return
        if kind == "partial":
            self.path.write_bytes(b"{")
            return
        if kind == "newline-only":
            self.path.write_bytes(b"\n")
            return
        if kind != "valid":
            raise AssertionError(f"unknown boundary kind: {kind}")
        records = [
            {"type": "session_meta", "payload": {"id": self.thread_id}},
            {
                "type": "turn_context",
                "payload": {
                    "turn_id": self.turn_id,
                    "model": LIVE.EXACT_MODEL,
                    "effort": "low",
                },
            },
        ]
        self.path.write_text(
            "".join(json.dumps(record) + "\n" for record in records),
            encoding="utf-8",
        )

    def append_terminal(self, event_type: str) -> None:
        with self.path.open("a", encoding="utf-8") as stream:
            stream.write(
                json.dumps(
                    {
                        "type": "event_msg",
                        "payload": {
                            "type": event_type,
                            "turn_id": self.turn_id,
                        },
                    }
                )
                + "\n"
            )

    def thread_response(self) -> dict:
        return {
            "model": LIVE.EXACT_MODEL,
            "modelProvider": "trusted",
            "thread": {"id": self.thread_id, "turns": [], "path": str(self.path)},
        }

    def start_turn(self, thread_id: str, _message: str) -> tuple[dict, float]:
        if thread_id != self.thread_id:
            raise AssertionError("thread mismatch")
        if self.start_error is not None:
            raise self.start_error
        if self.bind_turn_result:
            self.started_threads[thread_id] = self.turn_result_id
        return {"id": self.turn_result_id}, 1.0

    def read_thread(self, thread_id: str) -> tuple[dict, float]:
        if thread_id != self.thread_id:
            raise AssertionError("thread mismatch")
        if self.read_statuses:
            self.status = self.read_statuses.pop(0)
        return {
            "id": self.thread_id,
            "path": str(self.path),
            "turns": [{"id": self.turn_id, "status": self.status, "items": []}],
        }, 1.0

    def interrupt_turn(self, thread_id: str, turn_id: str) -> float:
        if (thread_id, turn_id) != (self.thread_id, self.turn_id):
            raise AssertionError("turn mismatch")
        self.status = "interrupted"
        return 1.0

    def archive_thread(self, thread_id: str) -> float:
        if thread_id != self.thread_id:
            raise AssertionError("thread mismatch")
        target = self.archive / self.path.name
        if self.path.exists():
            shutil.move(self.path, target)
        self.path = target
        self.archived = True
        return 1.0

    @staticmethod
    def notifications(_thread_id: str, _method: str | None = None) -> list[dict]:
        return []


class LiveCanaryMaterializationTests(unittest.TestCase):
    def owner(self) -> dict:
        return {"pid": 1, "start_ticks": 1, "boot_id_sha256": "a" * 64}

    def test_pool_sleep_adapts_keyword_callback_to_positional_builtin(self) -> None:
        from tests.test_native_pool import PoolHarness

        with tempfile.TemporaryDirectory() as temporary:
            harness = PoolHarness(
                temporary,
                cap=2,
                decisions=[["continue", "complete"], ["continue", "complete"]],
            )
            harness.coordinator.pool_callbacks["sleep"] = LIVE.pool_sleep

            def advance(seconds: float) -> None:
                harness.clock.sleep(seconds=seconds)

            with mock.patch.object(LIVE.time, "sleep", side_effect=advance) as sleep:
                receipt = harness.coordinator.run()

            self.assertTrue(receipt["accepting"])
            self.assertTrue(sleep.called)
            self.assertTrue(all(call.args and not call.kwargs for call in sleep.call_args_list))

    def test_inprogress_before_turn_context_keeps_polling_then_interrupts(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            record_dir = root / "records"
            record_dir.mkdir()
            server = FakeCalibrationServer(root)
            receipt, evidence = LIVE.calibration(
                server,
                root,
                record_dir,
                self.owner(),
                run_nonce=str(uuid.uuid4()),
                phase_nonce=str(uuid.uuid4()),
            )
            self.assertEqual(receipt["validation_outcome"], "accepted")
            self.assertTrue(evidence["interrupt_confirmed"])
            self.assertGreaterEqual(server.read_count, 8)
            materialization = evidence["materialization_evidence"]
            self.assertEqual(materialization["disposition"], "accepted")
            self.assertEqual(materialization["version"], 4)
            self.assertEqual(materialization["thread_id"], server.thread_id)
            self.assertEqual(
                materialization["connection_epoch_sha256"], server.connection_epoch_sha256
            )
            first, second = materialization["liveness_observations"]
            self.assertEqual(first["command_item_id_sha256"], second["command_item_id_sha256"])
            self.assertEqual(first["function_call_id_sha256"], second["function_call_id_sha256"])
            self.assertEqual(
                first["execution_correlation_sha256"],
                second["execution_correlation_sha256"],
            )
            self.assertEqual(first["rendered_command_sha256"], second["rendered_command_sha256"])
            self.assertEqual(first["command_source"], "unifiedExecStartup")
            self.assertTrue(first["notification_command_semantic_match"])
            self.assertTrue(first["notification_workspace_match"])
            self.assertEqual(first["session_source_identity_sha256"], second["session_source_identity_sha256"])
            self.assertEqual(first["started_event_count"], 1)
            self.assertEqual(first["completed_event_count"], 0)
            self.assertEqual(first["paired_result_count"], 0)
            self.assertEqual(server._thread()["turns"][0]["items"], [])
            self.assertNotIn("path", json.dumps(materialization).lower())
            self.assertNotIn("arguments", json.dumps(materialization).lower())
            self.assertLessEqual(evidence["poll_interval_max_ms"], 250)
            control = materialization["control_observations"]
            self.assertEqual(
                [item["ordinal"] for item in control], list(range(len(control)))
            )
            self.assertEqual(control[-1]["decision"], "terminal-accepted")
            self.assertEqual(control[-1]["durable_status"], "interrupted")
            self.assertEqual(
                materialization["terminal_event"]["event_type"], "turn_aborted"
            )

    def test_transient_interrupted_projection_without_durable_terminal_keeps_polling(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            record_dir = root / "records"
            record_dir.mkdir()
            server = FakeCalibrationServer(
                root, read_statuses=["interrupted", "inProgress"]
            )
            _receipt, evidence = LIVE.calibration(
                server,
                root,
                record_dir,
                self.owner(),
                run_nonce=str(uuid.uuid4()),
                phase_nonce=str(uuid.uuid4()),
            )
            control = evidence["materialization_evidence"]["control_observations"]
            self.assertEqual(control[0]["projected_status"], "interrupted")
            self.assertEqual(control[0]["durable_status"], None)
            self.assertEqual(control[0]["decision"], "continue-provisional")
            self.assertIn("ready", [item["decision"] for item in control])

    def test_early_completion_and_failed_or_declined_command_are_nonaccepting(self) -> None:
        for early, command, expected in (
            ("completed", "inProgress", "terminal-event-before-deliberate-interrupt"),
            (None, "failed", "command-terminal-before-interrupt"),
            (None, "declined", "command-terminal-before-interrupt"),
        ):
            with self.subTest(early=early, command=command), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                record_dir = root / "records"
                record_dir.mkdir()
                server = FakeCalibrationServer(
                    root,
                    early_status=early,
                    command_status=command,
                    durable_terminal_type="task_complete" if early else None,
                )
                with self.assertRaisesRegex(LIVE.AppServerError, expected):
                    LIVE.calibration(
                        server,
                        root,
                        record_dir,
                        self.owner(),
                        run_nonce=str(uuid.uuid4()),
                        phase_nonce=str(uuid.uuid4()),
                    )

    def test_terminal_grammar_grace_and_interrupt_race_fail_closed(self) -> None:
        cases = (
            (
                {"durable_terminal_type": "turn_cancelled"},
                "terminal-grammar-invalid",
            ),
            (
                {
                    "durable_terminal_type": "task_complete",
                    "duplicate_durable_terminal": True,
                },
                "terminal-grammar-invalid",
            ),
            ({"durable_terminal_type": "task_failed"}, "terminal-event-before"),
            ({"interrupt_terminal_type": "task_complete"}, "interrupt-race-lost"),
        )
        for options, expected in cases:
            with self.subTest(options=options), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                record_dir = root / "records"
                record_dir.mkdir()
                server = FakeCalibrationServer(root, **options)
                with self.assertRaisesRegex(LIVE.AppServerError, expected):
                    LIVE.calibration(
                        server,
                        root,
                        record_dir,
                        self.owner(),
                        run_nonce=str(uuid.uuid4()),
                        phase_nonce=str(uuid.uuid4()),
                    )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            record_dir = root / "records"
            record_dir.mkdir()
            server = FakeCalibrationServer(root, early_status="interrupted")
            with mock.patch.object(LIVE, "PROVISIONAL_TERMINAL_GRACE_SECONDS", 0.1):
                with self.assertRaisesRegex(
                    LIVE.AppServerError, "uncorroborated-terminal-projection"
                ):
                    LIVE.calibration(
                        server,
                        root,
                        record_dir,
                        self.owner(),
                        run_nonce=str(uuid.uuid4()),
                        phase_nonce=str(uuid.uuid4()),
                        materialization_timeout_seconds=1.2,
                    )

    def test_production_shaped_notification_and_jsonl_confusion_fails_closed(self) -> None:
        cases = (
            ({"missing_start": True}, "materialization-deadline"),
            ({"cross_turn_start": True}, "materialization-deadline"),
            ({"cross_thread_start": True}, "materialization-deadline"),
            ({"notification_item_type": "agentMessage"}, "materialization-deadline"),
            ({"duplicate_start": True}, "command-start-not-singular"),
            ({"command_source": "agent"}, "command-source-invalid"),
            ({"command_source": "userShell"}, "command-source-invalid"),
            ({"command_source": "unifiedExecInteraction"}, "command-source-invalid"),
            ({"command_source": None}, "command-source-invalid"),
            ({"command_source": "unknown"}, "command-source-invalid"),
            ({"omit_command_source": True}, "command-source-missing"),
            ({"notification_command": "sleep 19"}, "rendered-command-not-exact-wrapper"),
            ({"notification_command": "sleep 20; true"}, "rendered-command-not-exact-wrapper"),
            ({"notification_command": "sleep 20 # ignored"}, "rendered-command-not-exact-wrapper"),
            ({"notification_command": "sleep 20 >/tmp/out"}, "rendered-command-not-exact-wrapper"),
            ({"notification_command": '/bin/bash -lc "sleep 20"'}, "rendered-command-not-exact-wrapper"),
            ({"notification_workspace_mismatch": True}, "notification-workspace-mismatch"),
            ({"function_command": "sleep 19"}, "function-call-command-digest-mismatch"),
            ({"completed_before_interrupt": True}, "command-completed-before-interrupt"),
            ({"output_before_interrupt": True}, "function-output-before-interrupt"),
            ({"duplicate_function_call": True}, "function-call-not-singular"),
            ({"competing_function_call": True}, "function-call-not-singular"),
            ({"replace_source_at_read": 6}, "session-source-identity-changed"),
            ({"replace_notification_at_read": 6}, "materialization-deadline"),
        )
        for options, expected in cases:
            with self.subTest(options=options), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                record_dir = root / "records"
                record_dir.mkdir()
                server = FakeCalibrationServer(root, **options)
                with self.assertRaisesRegex(LIVE.AppServerError, expected):
                    LIVE.calibration(
                        server,
                        root,
                        record_dir,
                        self.owner(),
                        run_nonce=str(uuid.uuid4()),
                        phase_nonce=str(uuid.uuid4()),
                        materialization_timeout_seconds=1.2,
                    )

    def test_containment_archives_allocated_threads(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            server = FakeCalibrationServer(root)
            server.start_thread(root, mutable=False)
            server.start_turn(server.thread_id, "prompt")
            server.started_threads = {server.thread_id: server.turn_id}
            result = LIVE.contain_started_threads(server)
            self.assertTrue(result["all_contained"])
            self.assertEqual(result["archived_count"], 1)

    def test_app_server_records_intents_before_thread_and_turn_rpc(self) -> None:
        from cwo_core.native_live_allocation_ledger import NativeLiveAllocationLedgerStore
        from tests.test_native_live_allocation_ledger import bindings

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            ledger = NativeLiveAllocationLedgerStore(root / "ledger")
            ledger.initialize(bindings())
            server = object.__new__(LIVE.AppServer)
            server.allocation_ledger = ledger
            server.started_threads = {}

            def request(method: str, _params: Mapping, *, timeout: float = 30):
                state = ledger.load()
                if method == "thread/start":
                    self.assertEqual(state["entries"][-1]["event"], "allocation-intent")
                    return {
                        "thread": {"id": "thread-1", "turns": []},
                        "model": LIVE.EXACT_MODEL,
                    }, 1.0
                if method == "turn/start":
                    self.assertEqual(state["entries"][-1]["event"], "turn-intent")
                    return {"turn": {"id": "turn-1"}}, 1.0
                raise AssertionError(method)

            server.request = request
            server.start_thread(root, mutable=False, role="capability-calibration")
            server.start_turn("thread-1", "bounded")
            events = [entry["event"] for entry in ledger.load()["entries"]]
            self.assertEqual(
                events,
                ["allocation-intent", "thread-bound", "turn-intent", "turn-bound"],
            )
            self.assertEqual(server.started_threads, {"thread-1": "turn-1"})

    def test_containment_is_idempotent_with_durable_archive_proof(self) -> None:
        from cwo_core.native_live_allocation_ledger import NativeLiveAllocationLedgerStore
        from tests.test_native_live_allocation_ledger import bindings

        class LedgerServer:
            def __init__(self, ledger: NativeLiveAllocationLedgerStore) -> None:
                self.allocation_ledger = ledger
                self.started_threads = {"thread-1": "turn-1"}
                self.status = "inProgress"
                self.archived = False

            def read_thread(self, _thread_id: str):
                if self.archived:
                    raise LIVE.AppServerError("app-server-request-failed:thread/read:-32600")
                return {
                    "id": "thread-1",
                    "turns": [{"id": "turn-1", "status": self.status, "items": []}],
                }, 1.0

            def interrupt_turn(self, _thread_id: str, _turn_id: str):
                self.status = "interrupted"
                self.allocation_ledger.record_lifecycle(
                    "thread-1", "interrupt-observed", "interrupt-request-accepted"
                )
                return 1.0

            def archive_thread(self, _thread_id: str):
                self.archived = True
                self.allocation_ledger.record_lifecycle(
                    "thread-1", "archive-observed", "archive-request-accepted"
                )
                return 1.0

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            ledger = NativeLiveAllocationLedgerStore(root / "ledger")
            ledger.initialize(bindings())
            allocation = ledger.allocation_intent("read-only-0")
            ledger.bind_thread(allocation, "thread-1")
            turn_intent = ledger.turn_intent("thread-1")
            ledger.bind_turn("thread-1", turn_intent, "turn-1")
            server = LedgerServer(ledger)
            first = LIVE.contain_started_threads(server)
            second = LIVE.contain_started_threads(server)
            self.assertTrue(first["all_contained"])
            self.assertEqual(first["archived_count"], 1)
            self.assertTrue(second["all_contained"])
            self.assertEqual(second["already_contained_count"], 1)
            self.assertTrue(second["ledger_consistent"])

    def test_unresolved_thread_start_intent_is_containment_ambiguity(self) -> None:
        from cwo_core.native_live_allocation_ledger import NativeLiveAllocationLedgerStore
        from tests.test_native_live_allocation_ledger import bindings

        with tempfile.TemporaryDirectory() as temporary:
            ledger = NativeLiveAllocationLedgerStore(Path(temporary) / "ledger")
            ledger.initialize(bindings())
            ledger.allocation_intent("read-only-0")
            server = type(
                "UnresolvedServer",
                (),
                {"allocation_ledger": ledger, "started_threads": {}},
            )()
            result = LIVE.contain_started_threads(server)
            self.assertFalse(result["all_contained"])
            self.assertEqual(result["ambiguous_count"], 1)
            self.assertEqual(result["unresolved_allocation_intent_count"], 1)


class LiveThreadBoundaryPhaseTests(unittest.TestCase):
    def adapter(
        self,
        root: Path,
        server: FakeLiveThreadServer,
        clock: FakeMonotonicClock,
    ) -> LIVE.LiveThreadAdapter:
        return LIVE.LiveThreadAdapter(
            server,
            server.thread_response(),
            prompt="bounded prompt",
            expected_token="DONE",
            worktree=root,
            mutable=False,
            expected_mutation=None,
            record_dir=root,
            monotonic_ns=clock,
        )

    def test_pre_dispatch_missing_and_empty_boundaries_are_unavailable(self) -> None:
        for materialization in ("missing", "empty"):
            with self.subTest(materialization=materialization), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                active = root / "sessions" / "2026" / "07"
                active.mkdir(parents=True)
                thread_id = str(uuid.uuid4())
                path = active / f"rollout-{thread_id}.jsonl"
                if materialization == "empty":
                    path.touch()
                summary = LIVE.session_boundary_summary(
                    root,
                    thread_id,
                    str(path),
                    allow_unmaterialized=True,
                )
                self.assertFalse(summary["available"])
                self.assertEqual(summary["record_count"], 0)
                self.assertEqual(summary["byte_offset"], 0)
                self.assertEqual(summary["attested_models"], [])

    def test_thread_reported_path_cannot_select_trusted_session_source(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            server = FakeLiveThreadServer(root, initial_boundary="valid")
            outside = root.parent / f"reported-{server.thread_id}.jsonl"
            outside.write_text(
                json.dumps(
                    {"type": "session_meta", "payload": {"id": server.thread_id}}
                )
                + "\n",
                encoding="utf-8",
            )
            self.addCleanup(outside.unlink)
            expected = LIVE.session_boundary_summary(
                server.codex_home,
                server.thread_id,
                None,
                turn_id=server.turn_id,
            )
            actual = LIVE.session_boundary_summary(
                server.codex_home,
                server.thread_id,
                str(outside),
                turn_id=server.turn_id,
            )
            self.assertEqual(actual, expected)

    def test_nonempty_incomplete_boundaries_remain_rejecting_before_dispatch(self) -> None:
        for raw, expected in ((b"{", "trailing partial"), (b"\n", "complete object")):
            with self.subTest(raw=raw), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                active = root / "sessions" / "2026" / "07"
                active.mkdir(parents=True)
                thread_id = str(uuid.uuid4())
                path = active / f"rollout-{thread_id}.jsonl"
                path.write_bytes(raw)
                with self.assertRaisesRegex(LIVE.AppServerError, expected):
                    LIVE.session_boundary_summary(
                        root,
                        thread_id,
                        str(path),
                        allow_unmaterialized=True,
                    )

    def test_dispatch_attempt_irreversibly_revokes_unmaterialized_allowance(self) -> None:
        class FailedSubmissionServer:
            def __init__(self, codex_home: Path) -> None:
                self.codex_home = codex_home

            @staticmethod
            def start_turn(_thread_id: str, _message: str) -> tuple[dict, float]:
                raise LIVE.AppServerError("synthetic-submission-failure")

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            thread_id = str(uuid.uuid4())
            server = FailedSubmissionServer(root)
            adapter = LIVE.LiveThreadAdapter(
                server,
                {
                    "model": LIVE.EXACT_MODEL,
                    "modelProvider": "trusted",
                    "thread": {"id": thread_id, "turns": [], "path": None},
                },
                prompt="bounded prompt",
                expected_token="DONE",
                worktree=root,
                mutable=False,
                expected_mutation=None,
                record_dir=root,
            )
            pre_dispatch = LIVE.session_boundary_summary(
                root,
                thread_id,
                None,
                allow_unmaterialized=adapter._boundary_phase == "pre-dispatch",
            )
            self.assertFalse(pre_dispatch["available"])
            with self.assertRaisesRegex(LIVE.AppServerError, "synthetic-submission-failure"):
                adapter.send_input(message="bounded prompt")
            self.assertEqual(adapter._boundary_phase, "dispatch-attempted")
            self.assertIsNone(adapter.turn_id)
            with self.assertRaisesRegex(LIVE.AppServerError, "trusted session file is missing"):
                adapter._trusted_summary()

    def test_bound_turn_missing_boundary_is_rejecting(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            thread_id = str(uuid.uuid4())
            with self.assertRaisesRegex(LIVE.AppServerError, "trusted session file is missing"):
                LIVE.session_boundary_summary(
                    root,
                    thread_id,
                    None,
                    allow_unmaterialized=False,
                )

    def test_acknowledged_missing_and_empty_boundaries_are_nonattesting(self) -> None:
        for boundary_kind in ("missing", "empty"):
            with self.subTest(boundary_kind=boundary_kind), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                clock = FakeMonotonicClock()
                server = FakeLiveThreadServer(root, initial_boundary=boundary_kind)
                adapter = self.adapter(root, server, clock)
                adapter.send_input(message="bounded prompt")
                with mock.patch.object(adapter, "_workspace_mutations", return_value=[]):
                    evidence = adapter.evidence()
                self.assertEqual(
                    adapter._boundary_phase,
                    "submission-acknowledged-awaiting-materialization",
                )
                self.assertEqual(evidence["session_disposition"], "accepted-with-warning")
                self.assertEqual(
                    evidence["artifact_disposition"], "independent-validation-required"
                )
                self.assertFalse(evidence["protected_fault"])
                self.assertFalse(evidence["control_loss"])

    def test_materialization_before_deadline_is_irreversible_and_exact(self) -> None:
        for initial_boundary in ("missing", "empty"):
            with self.subTest(initial_boundary=initial_boundary), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                clock = FakeMonotonicClock()
                server = FakeLiveThreadServer(root, initial_boundary=initial_boundary)
                adapter = self.adapter(root, server, clock)
                adapter.send_input(message="bounded prompt")
                adapter._capture_trusted_boundary(allow_pending=True)
                clock.advance_ms(1499)
                server.set_boundary("valid")
                with mock.patch.object(adapter, "_workspace_mutations", return_value=[]):
                    summary = adapter._trusted_summary()
                self.assertEqual(adapter._boundary_phase, "materialized")
                self.assertTrue(summary["session_boundary"]["available"])
                self.assertTrue(summary["model_exact"])
                self.assertIsNotNone(adapter._session_boundary_baseline)
                self.assertIsNotNone(adapter._session_source_identity_sha256)
                clock.advance_ms(5000)
                with mock.patch.object(adapter, "_workspace_mutations", return_value=[]):
                    self.assertTrue(adapter._trusted_summary()["model_exact"])

    def test_first_complete_boundary_at_deadline_and_late_missing_are_rejected(self) -> None:
        for materialize in (False, True):
            with self.subTest(materialize=materialize), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                clock = FakeMonotonicClock()
                server = FakeLiveThreadServer(root)
                adapter = self.adapter(root, server, clock)
                adapter.send_input(message="bounded prompt")
                clock.advance_ms(LIVE.POST_SUBMISSION_MATERIALIZATION_GRACE_MS)
                if materialize:
                    server.set_boundary("valid")
                with self.assertRaisesRegex(
                    LIVE.AppServerError, "materialization-deadline-exceeded"
                ):
                    adapter._trusted_summary()

    def test_submission_identity_and_mapping_must_be_exact(self) -> None:
        for failure in ("empty-id", "mapping-mismatch"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                clock = FakeMonotonicClock()
                server = FakeLiveThreadServer(root)
                if failure == "empty-id":
                    server.turn_result_id = ""
                else:
                    server.bind_turn_result = False
                adapter = self.adapter(root, server, clock)
                expected = "turn-start-response-invalid" if failure == "empty-id" else "binding-mismatch"
                with self.assertRaisesRegex(LIVE.AppServerError, expected):
                    adapter.send_input(message="bounded prompt")
                self.assertEqual(adapter._boundary_phase, "dispatch-attempted")
                self.assertIsNone(adapter.turn_id)

    def test_projected_terminal_without_durable_event_is_advisory(self) -> None:
        for statuses in (["completed"], ["inProgress", "completed"]):
            with self.subTest(statuses=statuses), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                clock = FakeMonotonicClock()
                server = FakeLiveThreadServer(root, read_statuses=statuses)
                adapter = self.adapter(root, server, clock)
                adapter.send_input(message="bounded prompt")
                with mock.patch.object(adapter, "_workspace_mutations", return_value=[]):
                    summary = adapter._trusted_summary()
                self.assertFalse(summary["session_boundary"]["available"])
                self.assertIsNone(summary["durable_terminal_event"])

    def test_pool_check_uses_durable_terminal_truth_and_tolerates_startup_flip(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            clock = FakeMonotonicClock()
            server = FakeLiveThreadServer(
                root, initial_boundary="valid", read_statuses=["interrupted"]
            )
            adapter = self.adapter(root, server, clock)
            adapter.send_input(message="bounded prompt")
            self.assertEqual(adapter.check(), {"decision": "continue"})
            server.status = "inProgress"
            self.assertEqual(adapter.check(), {"decision": "continue"})

        for event_type, expected in (
            ("task_complete", "control-lost"),
            ("turn_aborted", "interrupt"),
            ("task_failed", "control-lost"),
        ):
            with self.subTest(event_type=event_type), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                clock = FakeMonotonicClock()
                server = FakeLiveThreadServer(root, initial_boundary="valid")
                server.append_terminal(event_type)
                adapter = self.adapter(root, server, clock)
                adapter.send_input(message="bounded prompt")
                self.assertEqual(adapter.check(), {"decision": expected})

    def test_terminal_transition_interrupt_close_and_final_summary_are_strict(self) -> None:

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            clock = FakeMonotonicClock()
            server = FakeLiveThreadServer(root)
            adapter = self.adapter(root, server, clock)
            adapter.send_input(message="bounded prompt")
            adapter.interrupt()
            adapter._workspace_mutations = lambda: []
            summary = adapter._trusted_summary()
            self.assertEqual(
                summary["session_boundary"]["observation_type"],
                "containment-unmaterialized-nonattesting-rejected",
            )
            evidence = adapter.evidence()
            self.assertTrue(evidence["protected_fault"])
            self.assertEqual(evidence["session_disposition"], "quarantined")
            self.assertEqual(evidence["artifact_disposition"], "rejected")
            adapter.close()
            final = adapter.final_summary()
            self.assertEqual(
                final["session_boundary"]["observation_type"],
                "containment-unmaterialized-nonattesting-rejected",
            )

    def test_nonempty_invalid_boundary_never_uses_pending_allowance(self) -> None:
        for boundary_kind, expected in (("partial", "trailing partial"), ("newline-only", "complete object")):
            with self.subTest(boundary_kind=boundary_kind), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                clock = FakeMonotonicClock()
                server = FakeLiveThreadServer(root, initial_boundary=boundary_kind)
                adapter = self.adapter(root, server, clock)
                adapter.send_input(message="bounded prompt")
                with self.assertRaisesRegex(LIVE.AppServerError, expected):
                    adapter._trusted_summary()

    def test_post_materialization_disappearance_truncation_rewrite_and_replacement_fail(self) -> None:
        mutations = ("disappear", "zero", "truncate", "rewrite", "replace")
        for mutation in mutations:
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                clock = FakeMonotonicClock()
                server = FakeLiveThreadServer(root, initial_boundary="valid")
                adapter = self.adapter(root, server, clock)
                adapter.send_input(message="bounded prompt")
                adapter._capture_trusted_boundary(allow_pending=True)
                raw = server.path.read_bytes()
                if mutation == "disappear":
                    server.path.unlink()
                elif mutation == "zero":
                    server.path.write_bytes(b"")
                elif mutation == "truncate":
                    server.path.write_bytes(raw[:-1])
                elif mutation == "rewrite":
                    server.path.write_bytes(b"X" + raw[1:])
                else:
                    replacement = server.path.with_suffix(".replacement")
                    replacement.write_bytes(raw)
                    replacement.replace(server.path)
                with self.assertRaises(LIVE.AppServerError):
                    adapter._capture_trusted_boundary(allow_pending=True)

    def test_duplicate_active_and_archive_boundaries_remain_rejecting(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            clock = FakeMonotonicClock()
            server = FakeLiveThreadServer(root, initial_boundary="valid")
            duplicate = server.archive / server.path.name
            duplicate.write_bytes(server.path.read_bytes())
            adapter = self.adapter(root, server, clock)
            adapter.send_input(message="bounded prompt")
            with self.assertRaisesRegex(LIVE.AppServerError, "duplicate active/archive"):
                adapter._trusted_summary()


class FullAutoAuthorizationLauncherTests(unittest.TestCase):
    def test_launcher_root_is_repository_root(self) -> None:
        self.assertEqual(LIVE.ROOT, ROOT)

    def make_repo(self, root: Path) -> tuple[str, str]:
        subprocess.run(["git", "init", "-q"], cwd=root, check=True, stdout=subprocess.DEVNULL)
        subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=root, check=True)
        subprocess.run(["git", "config", "user.name", "CWO Test"], cwd=root, check=True)
        (root / "baseline.txt").write_text("initial", encoding="utf-8")
        subprocess.run(["git", "add", "baseline.txt"], cwd=root, check=True)
        subprocess.run(["git", "commit", "-qm", "baseline"], cwd=root, check=True)
        (root / "candidate.txt").write_text("candidate", encoding="utf-8")
        subprocess.run(["git", "add", "candidate.txt"], cwd=root, check=True)
        subprocess.run(["git", "commit", "-qm", "candidate"], cwd=root, check=True)
        (root / "checkpoint.txt").write_text("checkpoint", encoding="utf-8")
        subprocess.run(["git", "add", "checkpoint.txt"], cwd=root, check=True)
        subprocess.run(["git", "commit", "-qm", "checkpoint"], cwd=root, check=True)
        head = LIVE.run_git(root, "rev-parse", "HEAD")
        subprocess.run(["git", "checkout", "-q", "--orphan", "orphan"], cwd=root, check=True)
        (root / "orphan.txt").write_text("orphan", encoding="utf-8")
        subprocess.run(["git", "add", "orphan.txt"], cwd=root, check=True)
        subprocess.run(["git", "commit", "-qm", "orphan"], cwd=root, check=True)
        orphan = LIVE.run_git(root, "rev-parse", "HEAD")
        subprocess.run(["git", "checkout", "-q", "master"], cwd=root, check=True)
        subprocess.run(
            ["git", "update-ref", "refs/remotes/origin/main", head],
            cwd=root,
            check=True,
        )
        return head, orphan

    def predecessor_artifacts(
        self,
        root: Path,
        predecessor_authorization_id: str,
        candidate_commit: str,
        candidate_tree: str,
    ) -> dict[str, object]:
        cache_key = (
            str(root.resolve()),
            predecessor_authorization_id,
            candidate_commit,
            candidate_tree,
        )
        cache = getattr(self, "_predecessor_artifact_cache", {})
        if cache_key in cache:
            return cache[cache_key]

        def seal(value: dict, field: str) -> dict:
            value.pop(field, None)
            value[field] = LIVE.sha256_bytes(
                json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
            )
            return value

        def raw(value: dict) -> tuple[bytes, str]:
            payload = json.dumps(
                value, sort_keys=True, separators=(",", ":")
            ).encode()
            return payload, LIVE.sha256_bytes(payload)

        campaign_nonce = str(
            uuid.uuid5(uuid.UUID(predecessor_authorization_id), "campaign")
        )
        historical_predecessor_id = str(
            uuid.uuid5(uuid.UUID(predecessor_authorization_id), "generation-4")
        )
        try:
            historical_checkpoint = LIVE.run_git(
                root, "rev-parse", f"{candidate_commit}^"
            )
        except subprocess.CalledProcessError:
            historical_checkpoint = candidate_commit
        historical_checkpoint_tree = LIVE.run_git(
            root, "rev-parse", f"{historical_checkpoint}^{{tree}}"
        )
        origin_main = LIVE.run_git(root, "rev-parse", "origin/main")
        guarded_diff = LIVE.sha256_bytes(b"")

        predecessor_authorization = json.loads(
            (
                ROOT
                / "tests"
                / "fixtures"
                / "historical-full-auto-authorization-v4.json"
            ).read_text(encoding="utf-8")
        )
        predecessor_authorization.update(
            {
                "authorization_id": predecessor_authorization_id,
                "issued_at": "2026-07-17T10:00:00Z",
                "issued_by": "test-operator",
            }
        )
        predecessor_authorization["bindings"].update(
            {
                "checkpoint_commit": historical_checkpoint,
                "checkpoint_tree": historical_checkpoint_tree,
                "origin_main_commit": origin_main,
                "guarded_primary_diff_sha256": guarded_diff,
                "campaign_nonce": campaign_nonce,
                "predecessor_authorization_id": historical_predecessor_id,
            }
        )
        predecessor_authorization["supersession"][
            "prior_authorization_id"
        ] = historical_predecessor_id
        seal(predecessor_authorization, "canonical_authorization_sha256")
        (
            predecessor_authorization_bytes,
            predecessor_authorization_raw_sha256,
        ) = raw(predecessor_authorization)

        predecessor_manifest = json.loads(
            (
                ROOT
                / "tests"
                / "fixtures"
                / "historical-live-campaign-manifest-v1.json"
            ).read_text(encoding="utf-8")
        )
        predecessor_manifest.update(
            {
                "manifest_id": str(uuid.uuid4()),
                "created_at": "2026-07-17T10:01:00Z",
                "authorization_id": predecessor_authorization_id,
                "authorization_raw_sha256": predecessor_authorization_raw_sha256,
                "authorization_canonical_sha256": predecessor_authorization[
                    "canonical_authorization_sha256"
                ],
                "campaign_nonce": campaign_nonce,
            }
        )
        predecessor_manifest["candidate"] = {
            "commit": candidate_commit,
            "tree": candidate_tree,
            "origin_main_commit": origin_main,
            "guarded_primary_diff_sha256": guarded_diff,
        }
        predecessor_manifest["predecessor"] = {
            "authorization_id": historical_predecessor_id,
            "failure_evidence_canonical_sha256": predecessor_authorization[
                "bindings"
            ]["predecessor_failure_evidence_canonical_sha256"],
            "containment_canonical_sha256": predecessor_authorization["bindings"][
                "predecessor_containment_canonical_sha256"
            ],
        }
        predecessor_manifest["release"]["candidate_tree"] = candidate_tree
        predecessor_manifest["release"]["prospective_tree"] = candidate_tree
        seal(predecessor_manifest, "manifest_sha256")
        predecessor_manifest_bytes, predecessor_manifest_raw_sha256 = raw(
            predecessor_manifest
        )

        ledger_directory = root / (
            ".test-predecessor-ledger-" + uuid.uuid4().hex
        )
        ledger = LIVE.NativeLiveAllocationLedgerStore(ledger_directory)
        reviews = predecessor_manifest["reviews"]
        release = predecessor_manifest["release"]
        ledger.initialize(
            {
                "bead_id": "complex-work-orchestration-18w",
                "work_unit_id": "complex-work-orchestration-18w.6.19",
                "authorization_id": predecessor_authorization_id,
                "authorization_raw_sha256": predecessor_authorization_raw_sha256,
                "authorization_canonical_sha256": predecessor_authorization[
                    "canonical_authorization_sha256"
                ],
                "campaign_manifest_sha256": predecessor_manifest["manifest_sha256"],
                "campaign_nonce": campaign_nonce,
                "live_generation": 5,
                "predecessor_generation": 4,
                "candidate_commit": candidate_commit,
                "candidate_tree": candidate_tree,
                "origin_main_commit": origin_main,
                "guarded_primary_diff_sha256": guarded_diff,
                "predecessor_containment_sha256": predecessor_authorization[
                    "bindings"
                ]["predecessor_containment_canonical_sha256"],
                "frozen_release_patch_sha256": release["patch_file_sha256"],
                "pre_mutation_steering_receipt_sha256": reviews[
                    "pre_mutation_receipt_canonical_sha256"
                ],
                "pre_live_steering_receipt_sha256": reviews[
                    "pre_live_receipt_canonical_sha256"
                ],
                "opus_review_sha256": reviews["opus_evidence_file_sha256"],
                "certification_policy_sha256": "c" * 64,
                "controller_identity": {
                    "pid": 1,
                    "start_ticks": 1,
                    "boot_id_sha256": "d" * 64,
                },
                "connection_epoch_sha256": "e" * 64,
                "retention_class": "private-local-until-bead-closure",
                "expected_roles": list(LIVE.EXPECTED_ROLES),
            },
            version=2,
        )
        allocation_intent_id = ledger.allocation_intent(
            "capability-calibration"
        )
        thread_id = str(uuid.uuid4())
        turn_id = str(uuid.uuid4())
        ledger.bind_thread(allocation_intent_id, thread_id)
        turn_intent_id = ledger.turn_intent(thread_id)
        ledger.bind_turn(thread_id, turn_intent_id, turn_id)
        ledger.record_lifecycle(
            thread_id, "interrupt-observed", "interrupt-request-accepted"
        )
        ledger.record_lifecycle(
            thread_id, "archive-observed", "archive-request-accepted"
        )
        ledger.record_containment_audit(
            thread_id, outcome="contained", evidence={"contained": True}
        )
        contained_session_bytes = (
            json.dumps(
                {
                    "type": "session_meta",
                    "payload": {"id": thread_id, "session_id": thread_id},
                },
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
            + json.dumps(
                {
                    "type": "event_msg",
                    "payload": {"type": "task_started", "turn_id": turn_id},
                },
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        ).encode()
        predecessor_allocation_ledger = ledger.load()
        ledger_path = ledger.path
        audit_path = ledger.audit_file
        ledger_raw_sha256 = LIVE.sha256_bytes(ledger_path.read_bytes())
        audit_raw_sha256 = LIVE.sha256_bytes(audit_path.read_bytes())
        ledger_summary = ledger.summary()

        predecessor_state = {
            "authorization_type": "cwo-native-canary-authorization-state:v1",
            "version": 1,
            "schema": "schemas/native-canary-authorization-state.schema.json",
            "authorization_id": predecessor_authorization_id,
            "run_nonce": campaign_nonce,
            "state": "containment-only",
            "reason": "synthetic predecessor containment",
            "sequence": 1,
            "updated_at": "2026-07-17T11:00:00Z",
            "allowed_actions": [
                "beads-update",
                "close",
                "handoff",
                "interrupt",
                "local-checkpoint",
                "pickup",
                "reserved-steering",
                "sanitized-evidence",
            ],
            "revoked_actions": [
                "install",
                "publish",
                "push",
                "relaunch",
                "release-enable",
                "replacement",
                "retry",
                "tracked-mutation",
            ],
        }
        predecessor_state["state_sha256"] = LIVE.domain_sha256(
            predecessor_state, domain="native-canary-authorization"
        )
        predecessor_state_bytes, predecessor_state_raw_sha256 = raw(
            predecessor_state
        )
        predecessor_failure = seal(
            {
                "authorization_state_sha256": predecessor_state["state_sha256"],
                "release_gate_passed": False,
                "validation_outcome": "rejected",
                "allocation_ledger": {"available": True, **ledger_summary},
                "campaign_bindings": {
                    "authorization_raw_sha256": predecessor_authorization_raw_sha256,
                    "manifest_file_sha256": predecessor_manifest_raw_sha256,
                    "manifest_sha256": predecessor_manifest["manifest_sha256"],
                    "candidate_commit": candidate_commit,
                    "candidate_tree": candidate_tree,
                },
                "containment": {
                    "allocated_count": 1,
                    "all_contained": True,
                    "ambiguous_count": 0,
                    "ledger_consistent": True,
                    "unresolved_allocation_intent_count": 0,
                    "unresolved_turn_intent_count": 0,
                },
            },
            "evidence_sha256",
        )
        predecessor_failure_bytes, predecessor_failure_raw_sha256 = raw(
            predecessor_failure
        )

        malformed_authorization_id = (
            predecessor_authorization_id[:24]
            + predecessor_authorization_id[25:]
        )
        original_failed_evidence = {
            "file_sha256": predecessor_failure_raw_sha256,
            "canonical_sha256": predecessor_failure["evidence_sha256"],
            "authorization_state_file_sha256": predecessor_state_raw_sha256,
            "authorization_state_canonical_sha256": predecessor_state[
                "state_sha256"
            ],
        }
        original_reclassification = {
            "global_live_generation_ordinal": 5,
            "global_live_generation_hard_cap": 5,
            "remaining_generations_exact": 0,
            "allocated_count": 1,
            "calibration_turns_started": 1,
            "pool_turns_started": 0,
            "pool_tool_calls": 0,
            "external_interrupt_count_proven": 0,
            "harness_containment_interrupt_count": 1,
            "status_projection_flip_observed": True,
            "contained_count": 1,
            "ambiguous_count": 0,
            "all_contained": True,
            "release_gate_passed": False,
            "failed_authorization_terminal": True,
            "operator_stop_condition": "synthetic-terminal",
            "reuse_resume_retry_substitution_salvage_bridge": False,
        }
        original_control = {
            "campaign_process_alive": False,
            "controller_pid": 1,
            "controller_pid_alive": False,
            "disposable_workspace_present": False,
            "protected_primary_diff_sha256": guarded_diff,
            "isolated_checkout_head": candidate_commit,
            "isolated_checkout_tree": candidate_tree,
            "isolated_checkout_tracked_clean": True,
            "origin_main_commit": origin_main,
            "release_policy_status": "canary-gated",
            "operative_dispatch_authorized": False,
            "authorization_state_validation_errors": [],
            "ledger_validation_errors": [],
            "evidence_canonical_hash_valid": True,
        }
        predecessor_original_containment = seal(
            {
                "schema": "cwo-live-canary-containment-recovery:v1",
                "bead_id": "complex-work-orchestration-18w",
                "recorded_at": "2026-07-17T11:01:00Z",
                "failed_authorization_id": malformed_authorization_id,
                "failed_campaign_nonce": campaign_nonce,
                "failed_manifest": {
                    "file_sha256": predecessor_manifest_raw_sha256,
                    "canonical_sha256": predecessor_manifest["manifest_sha256"],
                    "live_generation": 5,
                    "predecessor_live_generation": 4,
                },
                "failed_evidence": original_failed_evidence,
                "root_cause": {},
                "session_accounting": [
                    {
                        "role": "capability-calibration",
                        "thread_id": thread_id,
                        "turn_id": turn_id,
                        "record_count": 2,
                        "byte_offset": len(contained_session_bytes),
                        "boundary_sha256": LIVE.sha256_bytes(
                            contained_session_bytes
                        ),
                    }
                ],
                "allocation_ledger": {
                    "ledger_type": ledger_summary["ledger_type"],
                    "version": ledger_summary["version"],
                    "ledger_id": ledger_summary["ledger_id"],
                    "ledger_file_sha256": ledger_raw_sha256,
                    "audit_file_sha256": audit_raw_sha256,
                    "state_sha256": ledger_summary["state_sha256"],
                    "head_entry_sha256": ledger_summary["head_entry_sha256"],
                    "sequence": ledger_summary["sequence"],
                    "allocation_intent_count": 1,
                    "thread_bound_count": 1,
                    "turn_intent_count": 1,
                    "turn_bound_count": 1,
                    "unresolved_allocation_intent_count": 0,
                    "unresolved_turn_intent_count": 0,
                    "validation_errors": [],
                },
                "steering_consumption": {},
                "control_plane_recheck": original_control,
                "reclassification": original_reclassification,
            },
            "canonical_recovery_sha256",
        )
        (
            predecessor_original_containment_bytes,
            predecessor_original_containment_raw_sha256,
        ) = raw(predecessor_original_containment)

        correction_reclassification_fields = (
            "global_live_generation_ordinal",
            "allocated_count",
            "calibration_turns_started",
            "pool_turns_started",
            "pool_tool_calls",
            "contained_count",
            "ambiguous_count",
            "all_contained",
            "release_gate_passed",
            "failed_authorization_terminal",
            "reuse_resume_retry_substitution_salvage_bridge",
        )
        correction_control_fields = (
            "campaign_process_alive",
            "disposable_workspace_present",
            "protected_primary_diff_sha256",
            "isolated_checkout_head",
            "isolated_checkout_tree",
            "isolated_checkout_tracked_clean",
            "origin_main_commit",
            "release_policy_status",
            "operative_dispatch_authorized",
            "authorization_state_validation_errors",
            "evidence_canonical_hash_valid",
        )
        predecessor_containment = seal(
            {
                "schema": "cwo-live-containment-identity-correction:v1",
                "recorded_at": "2026-07-17T11:02:00Z",
                "failed_authorization_id": predecessor_authorization_id,
                "failed_campaign_nonce": campaign_nonce,
                "failed_evidence": original_failed_evidence,
                "reclassification": {
                    field: original_reclassification[field]
                    for field in correction_reclassification_fields
                },
                "control_plane_recheck": {
                    field: original_control[field]
                    for field in correction_control_fields
                },
                "correction": {
                    "kind": "legacy-containment-identifier-length-correction",
                    "original_artifact_file_sha256": predecessor_original_containment_raw_sha256,
                    "original_artifact_canonical_sha256": predecessor_original_containment[
                        "canonical_recovery_sha256"
                    ],
                    "original_recorded_authorization_id": malformed_authorization_id,
                    "corrected_authorization_id": predecessor_authorization_id,
                    "identity_authority": {
                        "authorization_file_sha256": predecessor_authorization_raw_sha256,
                        "authorization_canonical_sha256": predecessor_authorization[
                            "canonical_authorization_sha256"
                        ],
                        "manifest_file_sha256": predecessor_manifest_raw_sha256,
                        "manifest_canonical_sha256": predecessor_manifest[
                            "manifest_sha256"
                        ],
                        "authorization_state_file_sha256": predecessor_state_raw_sha256,
                        "authorization_state_canonical_sha256": predecessor_state[
                            "state_sha256"
                        ],
                        "failure_evidence_file_sha256": predecessor_failure_raw_sha256,
                        "failure_evidence_canonical_sha256": predecessor_failure[
                            "evidence_sha256"
                        ],
                    },
                    "evidence_or_disposition_changed": False,
                    "main_architect_disposition": "correct identifier transcription only; preserve terminal containment and all original evidence hashes",
                },
            },
            "canonical_recovery_sha256",
        )
        predecessor_containment_bytes, predecessor_containment_raw_sha256 = raw(
            predecessor_containment
        )
        cause_evidence = (
            f"exact-turn-status-corroboration:{candidate_commit}:{candidate_tree}"
        ).encode()
        result = {
            "authorization": predecessor_authorization,
            "authorization_bytes": predecessor_authorization_bytes,
            "authorization_raw_sha256": predecessor_authorization_raw_sha256,
            "manifest": predecessor_manifest,
            "manifest_bytes": predecessor_manifest_bytes,
            "manifest_raw_sha256": predecessor_manifest_raw_sha256,
            "state": predecessor_state,
            "state_bytes": predecessor_state_bytes,
            "state_raw_sha256": predecessor_state_raw_sha256,
            "failure": predecessor_failure,
            "failure_bytes": predecessor_failure_bytes,
            "failure_raw_sha256": predecessor_failure_raw_sha256,
            "original_containment": predecessor_original_containment,
            "original_containment_bytes": predecessor_original_containment_bytes,
            "original_containment_raw_sha256": predecessor_original_containment_raw_sha256,
            "containment": predecessor_containment,
            "containment_bytes": predecessor_containment_bytes,
            "containment_raw_sha256": predecessor_containment_raw_sha256,
            "ledger": predecessor_allocation_ledger,
            "ledger_path": ledger_path,
            "ledger_raw_sha256": ledger_raw_sha256,
            "audit_path": audit_path,
            "audit_raw_sha256": audit_raw_sha256,
            "cause_evidence": cause_evidence,
            "contained_session_bytes": contained_session_bytes,
        }
        cache[cache_key] = result
        self._predecessor_artifact_cache = cache
        return result

    def predecessor_contract_kwargs(self, predecessor: dict) -> dict:
        return {
            "predecessor_authorization": predecessor["authorization"],
            "predecessor_authorization_raw_sha256": predecessor[
                "authorization_raw_sha256"
            ],
            "predecessor_manifest": predecessor["manifest"],
            "predecessor_manifest_raw_sha256": predecessor["manifest_raw_sha256"],
            "predecessor_authorization_state": predecessor["state"],
            "predecessor_authorization_state_raw_sha256": predecessor[
                "state_raw_sha256"
            ],
            "predecessor_failure_evidence": predecessor["failure"],
            "predecessor_failure_evidence_raw_sha256": predecessor[
                "failure_raw_sha256"
            ],
            "predecessor_original_containment": predecessor[
                "original_containment"
            ],
            "predecessor_original_containment_raw_sha256": predecessor[
                "original_containment_raw_sha256"
            ],
            "predecessor_containment": predecessor["containment"],
            "predecessor_containment_raw_sha256": predecessor[
                "containment_raw_sha256"
            ],
            "predecessor_allocation_ledger": predecessor["ledger"],
            "predecessor_allocation_ledger_raw_sha256": predecessor[
                "ledger_raw_sha256"
            ],
            "predecessor_allocation_audit_path": predecessor["audit_path"],
            "predecessor_allocation_audit_raw_sha256": predecessor[
                "audit_raw_sha256"
            ],
            "cause_evidence": predecessor["cause_evidence"],
        }

    def authorization(self, root: Path, checkpoint: str) -> dict:
        predecessor_authorization_id = str(uuid.uuid4())
        predecessor_candidate_commit = LIVE.run_git(root, "rev-parse", f"{checkpoint}^")
        predecessor_candidate_tree = LIVE.run_git(
            root, "rev-parse", f"{checkpoint}^^{{tree}}"
        )
        predecessor = self.predecessor_artifacts(
            root,
            predecessor_authorization_id,
            predecessor_candidate_commit,
            predecessor_candidate_tree,
        )
        predecessor_authorization = predecessor["authorization"]
        predecessor_manifest = predecessor["manifest"]
        predecessor_authorization_raw_sha256 = predecessor[
            "authorization_raw_sha256"
        ]
        predecessor_manifest_raw_sha256 = predecessor["manifest_raw_sha256"]
        value = {
            "authorization_type": "cwo-full-auto-run-authorization",
            "version": 5,
            "schema": "schemas/full-auto-run-authorization.schema.json",
            "authorization_id": str(uuid.uuid4()),
            "run_generation": 11,
            "live_generation": 6,
            "predecessor_live_generation": 5,
            "issued_at": "2026-07-17T12:00:00Z",
            "issued_by": "test-operator",
            "operator_authority": "comprehensive-full-auto",
            "initial_state": "active",
            "scope": {
                "epic_id": "complex-work-orchestration-18w",
                "parent_work_unit_id": "complex-work-orchestration-18w.6",
                "ordered_work_units": [
                    "complex-work-orchestration-18w.6.23",
                    "complex-work-orchestration-18w.6.24",
                    "complex-work-orchestration-18w.7",
                ],
            },
            "bindings": {
                "checkpoint_commit": checkpoint,
                "checkpoint_tree": LIVE.run_git(root, "rev-parse", f"{checkpoint}^{{tree}}"),
                "origin_main_commit": LIVE.run_git(root, "rev-parse", "origin/main"),
                "guarded_primary_diff_sha256": LIVE.sha256_bytes(b""),
                "pickup_path": "work-packets/18w/pickup-7.md",
                "pickup_sha256": "1" * 64,
                "recovery_plan_path": "work-packets/18w/recovery-plan-v11.md",
                "recovery_plan_sha256": "2" * 64,
                "campaign_nonce": str(uuid.uuid4()),
                "predecessor_authorization_id": predecessor_authorization_id,
                "predecessor_authorization_file_sha256": predecessor_authorization_raw_sha256,
                "predecessor_authorization_canonical_sha256": predecessor_authorization[
                    "canonical_authorization_sha256"
                ],
                "predecessor_manifest_file_sha256": predecessor_manifest_raw_sha256,
                "predecessor_manifest_canonical_sha256": predecessor_manifest[
                    "manifest_sha256"
                ],
                "predecessor_authorization_state_file_sha256": predecessor[
                    "state_raw_sha256"
                ],
                "predecessor_authorization_state_canonical_sha256": predecessor[
                    "state"
                ]["state_sha256"],
                "predecessor_failure_evidence_file_sha256": predecessor[
                    "failure_raw_sha256"
                ],
                "predecessor_failure_evidence_canonical_sha256": predecessor[
                    "failure"
                ]["evidence_sha256"],
                "predecessor_containment_file_sha256": predecessor[
                    "containment_raw_sha256"
                ],
                "predecessor_containment_canonical_sha256": predecessor[
                    "containment"
                ]["canonical_recovery_sha256"],
                "predecessor_original_containment_file_sha256": predecessor[
                    "original_containment_raw_sha256"
                ],
                "predecessor_original_containment_canonical_sha256": predecessor[
                    "original_containment"
                ]["canonical_recovery_sha256"],
                "predecessor_allocation_ledger_file_sha256": predecessor[
                    "ledger_raw_sha256"
                ],
                "predecessor_allocation_ledger_state_sha256": predecessor[
                    "ledger"
                ]["state_sha256"],
                "predecessor_allocation_audit_file_sha256": predecessor[
                    "audit_raw_sha256"
                ],
                "backup_ref": "refs/heads/backup/test-generation",
                "outer_authority_id": str(uuid.uuid4()),
                "outer_authority_canonical_sha256": "7" * 64,
                "outer_authority_file_sha256": "8" * 64,
            },
            "supersession": {
                "prior_authorization_id": predecessor_authorization_id,
                "prior_terminal_state": "containment-only",
                "prior_live_generation": 5,
                "prior_allocations": 1,
                "prior_ambiguities": 0,
                "prior_allowed_actions": 0,
                "reuse_resume_retry_substitution_salvage_bridge": False,
            },
            "executors": {
                "final_architect": "current-codex-main-thread",
                "steering": {
                    "model": "gpt-5.6-sol",
                    "effort": "max",
                    "surface": "codex-app-server-stdio",
                    "authority": "read-only-evidence",
                },
                "operative": {
                    "model": "gpt-5.3-codex-spark",
                    "effort": "low",
                    "surface": "codex-app-server-stdio",
                    "session_policy": "fresh-nonresumable-nonsalvageable",
                },
                "outside_critic": {
                    "model": "claude-opus-4-6",
                    "effort": "max",
                    "surface": "claude-cli-as-greg",
                    "authority": "evidence-only",
                },
            },
            "resource_limits": {
                "sol_consultations_this_inner_hard": 2,
                "opus_reviews_this_inner_hard": 0,
                "spark_validation_sessions_this_inner_hard": 1,
                "spark_live_turn_starts_exact": 7,
                "spark_compactions_hard": 0,
                "full_repository_suites_this_inner_hard": 2,
                "focused_validation_bundles_this_inner_hard": 3,
                "implementation_correction_sprints_this_inner_hard": 1,
                "primary_checkout_mutations_hard": 0,
            },
            "progress_gate": {
                "outer_authority_status": "active",
                "qualification_basis": "same-fault-with-new-evidence-and-validated-repair",
                "predecessor_failure_class": "startup-status-projection-race",
                "predecessor_failure_evidence_canonical_sha256": predecessor[
                    "failure"
                ]["evidence_sha256"],
                "predecessor_candidate_commit": predecessor_candidate_commit,
                "predecessor_candidate_tree": predecessor_candidate_tree,
                "new_falsifiable_cause": "projected terminal lacked exact-turn durable corroboration",
                "cause_evidence_sha256": LIVE.sha256_bytes(
                    predecessor["cause_evidence"]
                ),
                "repair_commit": checkpoint,
                "repair_tree": LIVE.run_git(root, "rev-parse", f"{checkpoint}^{{tree}}"),
                "independent_validation_receipt_canonical_sha256": "a" * 64,
                "independent_validation_receipt_file_sha256": "b" * 64,
                "independent_validation_session_id": str(uuid.uuid4()),
                "independent_validation_completed_at": "2026-07-17T11:59:00Z",
                "independent_validation_binding_sha256": "c" * 64,
                "same_fault_without_new_evidence": False,
                "one_active_inner_campaign": True,
                "arbitrary_generation_cap": False,
                "fresh_exact_sol_pre_live_required": True,
            },
            "mandatory_gates": {
                "strict_authorization_v5": True,
                "active_outer_authority_binding": True,
                "progress_qualification_validation": True,
                "contained_prior_generation_proof": True,
                "fresh_exact_spark_validation": True,
                "fresh_exact_sol_pre_mutation_receipt": True,
                "successor_contract_validation": True,
                "frozen_release_patch": True,
                "opus_second_line_review_adjudicated": True,
                "fresh_exact_sol_pre_live_receipt": True,
                "campaign_manifest_v2": True,
                "single_shot_per_generation_live_campaign": True,
                "main_thread_adjudication_each_gate": True,
                "guarded_primary_diff_stability": True,
                "staging_ci_before_main": True,
                "published_install_parity": True,
            },
            "persistence": {
                "run_level_full_auto_survives_recoverable_failure": True,
                "operator_recheck_required_for_routine_recovery": False,
                "evidence_bearing_live_failure_becomes_terminal": True,
                "fresh_successor_requires_new_authorization_id_nonce_receipts_sessions_and_paths": True,
                "combined_confidence_formula": "min(main,sol) when sol-used else main",
                "combined_confidence_minimum": 0.5,
                "operator_stop_conditions": ["unsafe-quarantine"],
            },
            "forbidden": {
                "glm_5_2": True,
                "model_synthesis": True,
                "primary_checkout_mutation": True,
                "prior_authorization_reuse": True,
                "prior_nonce_session_receipt_registry_state_output_ledger_or_path_reuse": True,
                "worker_resume": True,
                "worker_salvage": True,
                "model_substitution": True,
                "evidence_bearing_live_retry": True,
                "sol_target_checkout_mutation": True,
                "release_before_live_acceptance": True,
                "force_push": True,
                "git_tag": True,
                "github_release": True,
            },
            "live_relaunch_rule": {
                "pre_rpc_zero_artifact_relaunch_max": 1,
                "requires_no_thread_start_request": True,
                "requires_no_allocation_intent": True,
                "requires_no_session_identity": True,
                "requires_no_audit_event": True,
                "requires_no_campaign_artifact": True,
            },
            "release": {
                "authorized_only_after_accepting_live_evidence_and_main_go": True,
                "frozen_delta_required": True,
                "version_remains": "0.2.0-dev",
                "tag_or_github_release": False,
                "actions_after_gate": ["staging-ci", "main-fast-forward", "install-parity"],
            },
        }
        predecessor_lineage = {
            "authorization_id": predecessor_authorization_id,
            "authorization_file_sha256": predecessor_authorization_raw_sha256,
            "authorization_canonical_sha256": predecessor_authorization[
                "canonical_authorization_sha256"
            ],
            "manifest_file_sha256": predecessor_manifest_raw_sha256,
            "manifest_canonical_sha256": predecessor_manifest["manifest_sha256"],
            "authorization_state_file_sha256": predecessor["state_raw_sha256"],
            "authorization_state_canonical_sha256": predecessor["state"][
                "state_sha256"
            ],
            "live_generation": 5,
            "candidate_commit": predecessor_candidate_commit,
            "candidate_tree": predecessor_candidate_tree,
            "failure_evidence_canonical_sha256": predecessor["failure"][
                "evidence_sha256"
            ],
            "failure_evidence_file_sha256": predecessor["failure_raw_sha256"],
            "containment_canonical_sha256": predecessor["containment"][
                "canonical_recovery_sha256"
            ],
            "containment_file_sha256": predecessor["containment_raw_sha256"],
            "original_containment_file_sha256": predecessor[
                "original_containment_raw_sha256"
            ],
            "original_containment_canonical_sha256": predecessor[
                "original_containment"
            ]["canonical_recovery_sha256"],
            "allocation_ledger_file_sha256": predecessor["ledger_raw_sha256"],
            "allocation_ledger_state_sha256": predecessor["ledger"]["state_sha256"],
            "allocation_audit_file_sha256": predecessor["audit_raw_sha256"],
        }
        value["progress_gate"]["predecessor_lineage_sha256"] = LIVE.sha256_bytes(
            json.dumps(
                predecessor_lineage, sort_keys=True, separators=(",", ":")
            ).encode()
        )
        outer_authority = self.outer_authority(value)
        value["bindings"]["outer_authority_canonical_sha256"] = outer_authority[
            "canonical_outer_authority_sha256"
        ]
        value["bindings"]["outer_authority_file_sha256"] = LIVE.sha256_bytes(
            json.dumps(
                outer_authority, sort_keys=True, separators=(",", ":")
            ).encode()
        )
        self.reseal_authorization(value)
        return value

    def receipt(self, gate: str, authorization_id: str, recommendation: str = "go") -> dict:
        return {
            "gate": gate,
            "authorization_id": authorization_id,
            "authorization_sha256": "a" * 64,
            "canonical_receipt_sha256": ("b" if gate == "pre-mutation" else "c") * 64,
            "opinion": {"recommendation": recommendation},
        }

    def reseal_authorization(self, value: dict) -> None:
        progress = value.get("progress_gate")
        if isinstance(progress, dict):
            bindings = value.get("bindings", {})
            progress["predecessor_lineage_sha256"] = LIVE.sha256_bytes(
                json.dumps(
                    {
                        "authorization_id": bindings.get(
                            "predecessor_authorization_id"
                        ),
                        "authorization_file_sha256": bindings.get(
                            "predecessor_authorization_file_sha256"
                        ),
                        "authorization_canonical_sha256": bindings.get(
                            "predecessor_authorization_canonical_sha256"
                        ),
                        "manifest_file_sha256": bindings.get(
                            "predecessor_manifest_file_sha256"
                        ),
                        "manifest_canonical_sha256": bindings.get(
                            "predecessor_manifest_canonical_sha256"
                        ),
                        "authorization_state_file_sha256": bindings.get(
                            "predecessor_authorization_state_file_sha256"
                        ),
                        "authorization_state_canonical_sha256": bindings.get(
                            "predecessor_authorization_state_canonical_sha256"
                        ),
                        "live_generation": value.get("predecessor_live_generation"),
                        "candidate_commit": progress.get(
                            "predecessor_candidate_commit"
                        ),
                        "candidate_tree": progress.get(
                            "predecessor_candidate_tree"
                        ),
                        "failure_evidence_canonical_sha256": bindings.get(
                            "predecessor_failure_evidence_canonical_sha256"
                        ),
                        "failure_evidence_file_sha256": bindings.get(
                            "predecessor_failure_evidence_file_sha256"
                        ),
                        "containment_canonical_sha256": bindings.get(
                            "predecessor_containment_canonical_sha256"
                        ),
                        "containment_file_sha256": bindings.get(
                            "predecessor_containment_file_sha256"
                        ),
                        "original_containment_file_sha256": bindings.get(
                            "predecessor_original_containment_file_sha256"
                        ),
                        "original_containment_canonical_sha256": bindings.get(
                            "predecessor_original_containment_canonical_sha256"
                        ),
                        "allocation_ledger_file_sha256": bindings.get(
                            "predecessor_allocation_ledger_file_sha256"
                        ),
                        "allocation_ledger_state_sha256": bindings.get(
                            "predecessor_allocation_ledger_state_sha256"
                        ),
                        "allocation_audit_file_sha256": bindings.get(
                            "predecessor_allocation_audit_file_sha256"
                        ),
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode()
            )
            progress["independent_validation_binding_sha256"] = LIVE.sha256_bytes(
                json.dumps(
                    {
                        "authorization_id": value.get("authorization_id"),
                        "campaign_nonce": bindings.get("campaign_nonce"),
                        "candidate_commit": bindings.get("checkpoint_commit"),
                        "candidate_tree": bindings.get("checkpoint_tree"),
                        "outer_authority_id": bindings.get("outer_authority_id"),
                        "receipt_canonical_sha256": progress.get(
                            "independent_validation_receipt_canonical_sha256"
                        ),
                        "receipt_file_sha256": progress.get(
                            "independent_validation_receipt_file_sha256"
                        ),
                        "session_id": progress.get(
                            "independent_validation_session_id"
                        ),
                        "completed_at": progress.get(
                            "independent_validation_completed_at"
                        ),
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode()
            )
            progress.pop("qualification_sha256", None)
            progress["qualification_sha256"] = LIVE.sha256_bytes(
                json.dumps(progress, sort_keys=True, separators=(",", ":")).encode()
            )
        value.pop("canonical_authorization_sha256", None)
        value["canonical_authorization_sha256"] = LIVE.sha256_bytes(
            json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
        )

    def manifest(self, authorization: dict, candidate_commit: str, candidate_tree: str) -> dict:
        bindings = authorization["bindings"]
        value = {
            "manifest_type": "cwo-native-live-campaign-manifest",
            "version": 2,
            "schema": "schemas/native-live-campaign-manifest.schema.json",
            "manifest_id": str(uuid.uuid4()),
            "created_at": "2026-07-17T13:00:00Z",
            "authorization_id": authorization["authorization_id"],
            "authorization_raw_sha256": "7" * 64,
            "authorization_canonical_sha256": authorization[
                "canonical_authorization_sha256"
            ],
            "run_generation": authorization["run_generation"],
            "live_generation": authorization["live_generation"],
            "predecessor_live_generation": authorization["predecessor_live_generation"],
            "campaign_nonce": bindings["campaign_nonce"],
            "control_turn_id": LIVE.CONTROL_TURN_ID,
            "work_units": {
                "epic_id": authorization["scope"]["epic_id"],
                "parent_work_unit_id": authorization["scope"]["parent_work_unit_id"],
                "live_work_unit_id": "complex-work-orchestration-18w.6.24",
            },
            "candidate": {
                "commit": candidate_commit,
                "tree": candidate_tree,
                "origin_main_commit": bindings["origin_main_commit"],
                "guarded_primary_diff_sha256": bindings[
                    "guarded_primary_diff_sha256"
                ],
            },
            "predecessor": {
                "authorization_id": bindings["predecessor_authorization_id"],
                "authorization_file_sha256": bindings[
                    "predecessor_authorization_file_sha256"
                ],
                "authorization_canonical_sha256": bindings[
                    "predecessor_authorization_canonical_sha256"
                ],
                "manifest_file_sha256": bindings[
                    "predecessor_manifest_file_sha256"
                ],
                "manifest_canonical_sha256": bindings[
                    "predecessor_manifest_canonical_sha256"
                ],
                "authorization_state_file_sha256": bindings[
                    "predecessor_authorization_state_file_sha256"
                ],
                "authorization_state_canonical_sha256": bindings[
                    "predecessor_authorization_state_canonical_sha256"
                ],
                "candidate_commit": authorization["progress_gate"][
                    "predecessor_candidate_commit"
                ],
                "candidate_tree": authorization["progress_gate"][
                    "predecessor_candidate_tree"
                ],
                "lineage_sha256": authorization["progress_gate"][
                    "predecessor_lineage_sha256"
                ],
                "failure_evidence_file_sha256": bindings[
                    "predecessor_failure_evidence_file_sha256"
                ],
                "failure_evidence_canonical_sha256": bindings[
                    "predecessor_failure_evidence_canonical_sha256"
                ],
                "containment_file_sha256": bindings[
                    "predecessor_containment_file_sha256"
                ],
                "containment_canonical_sha256": bindings[
                    "predecessor_containment_canonical_sha256"
                ],
                "original_containment_file_sha256": bindings[
                    "predecessor_original_containment_file_sha256"
                ],
                "original_containment_canonical_sha256": bindings[
                    "predecessor_original_containment_canonical_sha256"
                ],
                "allocation_ledger_file_sha256": bindings[
                    "predecessor_allocation_ledger_file_sha256"
                ],
                "allocation_ledger_state_sha256": bindings[
                    "predecessor_allocation_ledger_state_sha256"
                ],
                "allocation_audit_file_sha256": bindings[
                    "predecessor_allocation_audit_file_sha256"
                ],
            },
            "outer_authority": {
                "authority_id": bindings["outer_authority_id"],
                "canonical_sha256": bindings[
                    "outer_authority_canonical_sha256"
                ],
                "file_sha256": bindings["outer_authority_file_sha256"],
            },
            "progress_qualification_sha256": authorization["progress_gate"][
                "qualification_sha256"
            ],
            "executors": json.loads(json.dumps(authorization["executors"])),
            "expected_roles": [
                "capability-calibration",
                "read-only-0",
                "read-only-1",
                "mutable-0",
                "mutable-1",
                "interrupt-0",
                "interrupt-1",
            ],
            "successful_turn_starts_exact": 7,
            "prestart_zero_artifact_relaunch_max": 1,
            "reviews": {
                "pre_mutation_receipt_canonical_sha256": "8" * 64,
                "pre_mutation_receipt_file_sha256": "9" * 64,
                "pre_mutation_adjudication_file_sha256": "a" * 64,
                "opus_evidence_file_sha256": "b" * 64,
                "opus_adjudication_file_sha256": "c" * 64,
                "spark_validation_receipt_canonical_sha256": authorization[
                    "progress_gate"
                ]["independent_validation_receipt_canonical_sha256"],
                "spark_validation_receipt_file_sha256": authorization[
                    "progress_gate"
                ]["independent_validation_receipt_file_sha256"],
                "pre_live_receipt_canonical_sha256": "d" * 64,
                "pre_live_receipt_file_sha256": "e" * 64,
                "pre_live_adjudication_file_sha256": "f" * 64,
            },
            "release": {
                "patch_file_sha256": "1" * 64,
                "candidate_tree": candidate_tree,
                "prospective_tree": "2" * 40,
                "policy_before": {
                    "status": "canary-gated",
                    "cap_two_operative_release": False,
                },
                "policy_after": {
                    "status": "operative-authorized",
                    "cap_two_operative_release": True,
                },
            },
            "outputs": {
                "evidence_basename": "generation6-evidence.json",
                "authorization_state_basename": "generation6-state.json",
                "steering_registry_basename": "generation6-steering.json",
                "allocation_ledger_basename": "generation6-ledger",
            },
            "no_resume_or_salvage": True,
            "glm_5_2_used": False,
            "model_synthesis_used": False,
        }
        value["manifest_sha256"] = LIVE.sha256_bytes(
            json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
        )
        return value

    def outer_authority(self, authorization: dict) -> dict:
        value = {
            "authority_type": "cwo-full-auto-outer-recovery-authority",
            "version": 1,
            "authority_id": authorization["bindings"]["outer_authority_id"],
            "status": "active",
            "scope": {
                "epic_id": authorization["scope"]["epic_id"],
                "parent_work_unit_id": authorization["scope"][
                    "parent_work_unit_id"
                ],
            },
        }
        value["canonical_outer_authority_sha256"] = LIVE.sha256_bytes(
            json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
        )
        return value

    def spark_validation_receipt(
        self, authorization: dict, candidate_commit: str
    ) -> dict:
        guard = {
            "repo_head": candidate_commit,
            "repo_status_sha256": LIVE.sha256_bytes(b""),
            "primary_diff_sha256": LIVE.sha256_bytes(b""),
        }
        value = {
            "schema": "cwo-steering-receipt:v1",
            "gate": "independent-validation",
            "authorization_id": authorization["bindings"]["outer_authority_id"],
            "authorization_sha256": authorization["bindings"][
                "outer_authority_file_sha256"
            ],
            "session_id": authorization["progress_gate"][
                "independent_validation_session_id"
            ],
            "submission_id": str(uuid.uuid4()),
            "completed_at": authorization["progress_gate"][
                "independent_validation_completed_at"
            ],
            "model": "gpt-5.3-codex-spark",
            "effort": "low",
            "attestation_source": "initialized-codex-home-session-jsonl-turn-context",
            "observed_activity": {
                "function_calls": 0,
                "custom_tool_calls": 0,
                "tool_item_types": [],
                "compactions": 0,
                "workspace_mutations": 0,
            },
            "guard": {"before": guard, "after": dict(guard)},
            "boundary": {
                "baseline": {
                    "invalid_record_count": 0,
                    "trailing_partial": False,
                },
                "terminal": {
                    "invalid_record_count": 0,
                    "trailing_partial": False,
                },
            },
            "opinion": {
                "recommendation": "go",
                "confidence": 0.9,
                "conditions": [],
                "findings": [],
            },
            "closure_outcome": "completed-and-archived",
            "disposition": "accepting",
        }
        value["canonical_receipt_sha256"] = LIVE.sha256_bytes(
            json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
        )
        return value

    def validation_session(
        self, root: Path, *, with_function_call: bool = False
    ) -> tuple[dict, Path]:
        session_id = str(uuid.uuid4())
        turn_id = str(uuid.uuid4())
        opinion = {
            "recommendation": "go",
            "confidence": 0.9,
            "conditions": [],
            "findings": [],
        }
        final_text = json.dumps(opinion, sort_keys=True, separators=(",", ":"))
        records = [
            {"type": "session_meta", "payload": {"id": session_id}},
            {
                "type": "event_msg",
                "payload": {"type": "task_started", "turn_id": turn_id},
            },
            {
                "type": "turn_context",
                "payload": {
                    "turn_id": turn_id,
                    "model": LIVE.EXACT_MODEL,
                    "effort": "low",
                },
            },
        ]
        if with_function_call:
            records.append(
                {
                    "type": "response_item",
                    "payload": {
                        "type": "function_call",
                        "name": "exec_command",
                    },
                }
            )
        records.extend(
            [
                {
                    "type": "event_msg",
                    "payload": {
                        "type": "agent_message",
                        "phase": "final_answer",
                        "message": final_text,
                    },
                },
                {
                    "type": "response_item",
                    "payload": {
                        "type": "message",
                        "role": "assistant",
                        "phase": "final_answer",
                        "content": [{"type": "output_text", "text": final_text}],
                    },
                },
                {
                    "type": "event_msg",
                    "payload": {"type": "task_complete", "turn_id": turn_id},
                },
            ]
        )
        archive = root / "archived_sessions"
        archive.mkdir(parents=True, exist_ok=True)
        path = archive / f"rollout-test-{session_id}.jsonl"
        path.write_text(
            "".join(json.dumps(item) + "\n" for item in records),
            encoding="utf-8",
        )
        path.chmod(0o600)
        boundary, _ = LIVE.capture_boundary(path, session_id)
        receipt = {
            "session_id": session_id,
            "submission_id": turn_id,
            "boundary": {
                "terminal": {
                    **boundary,
                    "path_sha256": LIVE.sha256_text(str(path.resolve())),
                    "invalid_record_count": 0,
                    "trailing_partial": False,
                }
            },
            "opinion": opinion,
            "final_response_sha256": LIVE.sha256_text(final_text),
        }
        return receipt, path

    def json_snapshot(self, value: dict) -> LIVE.JsonArtifactSnapshot:
        raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
        return LIVE.JsonArtifactSnapshot(raw=raw, value=value)

    def file_snapshot(self, path: Path) -> LIVE.JsonArtifactSnapshot:
        raw = path.read_bytes()
        return LIVE.JsonArtifactSnapshot(raw=raw, value=json.loads(raw))

    def seal_field(self, value: dict, field: str) -> dict:
        value.pop(field, None)
        value[field] = LIVE.sha256_bytes(
            json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
        )
        return value

    def historical_proof(self, predecessor: dict) -> LIVE.HistoricalV4V1ProofInputs:
        return LIVE.HistoricalV4V1ProofInputs(
            authorization=LIVE.JsonArtifactSnapshot(
                raw=predecessor["authorization_bytes"],
                value=predecessor["authorization"],
            ),
            manifest=LIVE.JsonArtifactSnapshot(
                raw=predecessor["manifest_bytes"],
                value=predecessor["manifest"],
            ),
            authorization_state=LIVE.JsonArtifactSnapshot(
                raw=predecessor["state_bytes"], value=predecessor["state"]
            ),
            failure_evidence=LIVE.JsonArtifactSnapshot(
                raw=predecessor["failure_bytes"], value=predecessor["failure"]
            ),
            original_containment=LIVE.JsonArtifactSnapshot(
                raw=predecessor["original_containment_bytes"],
                value=predecessor["original_containment"],
            ),
            containment=LIVE.JsonArtifactSnapshot(
                raw=predecessor["containment_bytes"],
                value=predecessor["containment"],
            ),
            allocation_ledger=self.file_snapshot(predecessor["ledger_path"]),
            allocation_audit_bytes=predecessor["audit_path"].read_bytes(),
            cause_evidence=predecessor["cause_evidence"],
            contained_session_bytes=(predecessor["contained_session_bytes"],),
        )

    def bound_validation_receipt(
        self,
        root: Path,
        authorization: dict,
        candidate_commit: str,
    ) -> tuple[dict, bytes, Path, bytes]:
        session_receipt, session_path = self.validation_session(root)
        receipt = self.spark_validation_receipt(authorization, candidate_commit)
        for field in (
            "session_id",
            "submission_id",
            "boundary",
            "opinion",
            "final_response_sha256",
        ):
            receipt[field] = json.loads(json.dumps(session_receipt[field]))
        self.seal_field(receipt, "canonical_receipt_sha256")
        receipt_raw = json.dumps(
            receipt, sort_keys=True, separators=(",", ":")
        ).encode()
        return receipt, receipt_raw, session_path, session_path.read_bytes()

    def install_validator_contract_files(self, root: Path) -> None:
        for relative in LIVE.VALIDATOR_CONTRACT_PATHS:
            target = root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / relative, target)

    def modern_predecessor_proof(
        self,
        root: Path,
        checkpoint: str,
    ) -> LIVE.Version5PredecessorProofInputs:
        authorization = self.authorization(root, checkpoint)
        ancestor_artifacts = self.predecessor_artifacts(
            root,
            authorization["bindings"]["predecessor_authorization_id"],
            authorization["progress_gate"]["predecessor_candidate_commit"],
            authorization["progress_gate"]["predecessor_candidate_tree"],
        )
        outer_authority = self.outer_authority(authorization)
        receipt, receipt_raw, _session_path, session_raw = (
            self.bound_validation_receipt(root, authorization, checkpoint)
        )
        progress = authorization["progress_gate"]
        progress.update(
            {
                "independent_validation_receipt_canonical_sha256": receipt[
                    "canonical_receipt_sha256"
                ],
                "independent_validation_receipt_file_sha256": LIVE.sha256_bytes(
                    receipt_raw
                ),
                "independent_validation_session_id": receipt["session_id"],
                "independent_validation_completed_at": receipt["completed_at"],
            }
        )
        self.reseal_authorization(authorization)
        authorization_snapshot = self.json_snapshot(authorization)
        candidate_tree = LIVE.run_git(root, "rev-parse", f"{checkpoint}^{{tree}}")
        manifest = self.manifest(authorization, checkpoint, candidate_tree)
        manifest["authorization_raw_sha256"] = authorization_snapshot.raw_sha256
        manifest["authorization_canonical_sha256"] = authorization[
            "canonical_authorization_sha256"
        ]
        manifest["reviews"]["spark_validation_receipt_canonical_sha256"] = receipt[
            "canonical_receipt_sha256"
        ]
        manifest["reviews"]["spark_validation_receipt_file_sha256"] = (
            LIVE.sha256_bytes(receipt_raw)
        )
        self.reseal_manifest(manifest)
        manifest_snapshot = self.json_snapshot(manifest)

        state_directory = root / (".modern-state-" + uuid.uuid4().hex)
        state_store = LIVE.CanaryAuthorizationStore(state_directory / "state.json")
        state_store.initialize(
            LIVE.new_authorization_state(
                authorization_id=authorization["authorization_id"],
                run_nonce=authorization["bindings"]["campaign_nonce"],
                now="2026-07-17T12:10:00Z",
            )
        )
        state_store.transition(
            "containment-only",
            reason="synthetic-modern-predecessor-failure",
            now="2026-07-17T12:11:00Z",
        )
        state_snapshot = self.file_snapshot(state_store.path)

        ledger_directory = root / (".modern-ledger-" + uuid.uuid4().hex)
        ledger = LIVE.NativeLiveAllocationLedgerStore(ledger_directory)
        reviews = manifest["reviews"]
        release = manifest["release"]
        ledger.initialize(
            {
                "bead_id": "complex-work-orchestration-18w",
                "work_unit_id": "complex-work-orchestration-18w.6.24",
                "authorization_id": authorization["authorization_id"],
                "authorization_raw_sha256": authorization_snapshot.raw_sha256,
                "authorization_canonical_sha256": authorization[
                    "canonical_authorization_sha256"
                ],
                "campaign_manifest_sha256": manifest["manifest_sha256"],
                "campaign_nonce": authorization["bindings"]["campaign_nonce"],
                "live_generation": 6,
                "predecessor_generation": 5,
                "candidate_commit": checkpoint,
                "candidate_tree": candidate_tree,
                "origin_main_commit": manifest["candidate"]["origin_main_commit"],
                "guarded_primary_diff_sha256": manifest["candidate"][
                    "guarded_primary_diff_sha256"
                ],
                "predecessor_containment_sha256": authorization["bindings"][
                    "predecessor_containment_canonical_sha256"
                ],
                "frozen_release_patch_sha256": release["patch_file_sha256"],
                "pre_mutation_steering_receipt_sha256": reviews[
                    "pre_mutation_receipt_canonical_sha256"
                ],
                "pre_live_steering_receipt_sha256": reviews[
                    "pre_live_receipt_canonical_sha256"
                ],
                "opus_review_sha256": reviews["opus_evidence_file_sha256"],
                "certification_policy_sha256": "c" * 64,
                "controller_identity": {
                    "pid": 1,
                    "start_ticks": 1,
                    "boot_id_sha256": "d" * 64,
                },
                "connection_epoch_sha256": "e" * 64,
                "retention_class": "private-local-until-bead-closure",
                "expected_roles": list(LIVE.EXPECTED_ROLES),
            },
            version=2,
        )
        allocation_intent_id = ledger.allocation_intent("capability-calibration")
        thread_id = str(uuid.uuid4())
        turn_id = str(uuid.uuid4())
        ledger.bind_thread(allocation_intent_id, thread_id)
        turn_intent_id = ledger.turn_intent(thread_id)
        ledger.bind_turn(thread_id, turn_intent_id, turn_id)
        ledger.record_lifecycle(
            thread_id, "interrupt-observed", "interrupt-request-accepted"
        )
        ledger.record_lifecycle(
            thread_id, "archive-observed", "archive-request-accepted"
        )
        ledger.bind_certification("b" * 64)
        ledger.record_containment_audit(
            thread_id, outcome="contained", evidence={"contained": True}
        )
        ledger_snapshot = self.file_snapshot(ledger.path)
        allocation_audit_bytes = ledger.audit_file.read_bytes()
        ledger_summary = ledger.summary()
        containment_summary = {
            "allocated_count": 1,
            "identified_thread_count": 1,
            "interrupted_count": 1,
            "archived_count": 1,
            "already_contained_count": 0,
            "unresolved_allocation_intent_count": 0,
            "unresolved_turn_intent_count": 0,
            "ambiguous_count": 0,
            "all_contained": True,
            "ledger_consistent": True,
            "ledger_error_sha256": [],
        }
        failure_message_sha256 = LIVE.sha256_text(
            "synthetic callback mismatch"
        )
        failure = self.seal_field(
            {
                "result_type": "cwo-native-supervision-pool-live-canary-failure",
                "version": 1,
                "bead_id": "complex-work-orchestration-18w",
                "work_unit_id": "complex-work-orchestration-18w.6.24",
                "control_turn_id": LIVE.CONTROL_TURN_ID,
                "started_at": "2026-07-17T12:09:00Z",
                "failed_at": "2026-07-17T12:12:00Z",
                "exact_model": LIVE.EXACT_MODEL,
                "campaign_bindings": {
                    "authorization_raw_sha256": authorization_snapshot.raw_sha256,
                    "manifest_file_sha256": manifest_snapshot.raw_sha256,
                    "manifest_sha256": manifest["manifest_sha256"],
                    "candidate_commit": checkpoint,
                    "candidate_tree": candidate_tree,
                    "spark_validation_session_file_sha256": LIVE.sha256_bytes(
                        session_raw
                    ),
                },
                "steering_consumptions": {},
                "allocation_ledger": {"available": True, **ledger_summary},
                "failure_class": "TypeError",
                "failure_code": "TypeError",
                "failure_message_sha256": failure_message_sha256,
                "first_protected_fault": None,
                "containment": containment_summary,
                "authorization_state_sha256": state_snapshot.value["state_sha256"],
                "release_gate_passed": False,
                "validation_outcome": "rejected",
                "no_resume_or_salvage": True,
                "glm_5_2_used": False,
                "model_synthesis_used": False,
            },
            "evidence_sha256",
        )
        failure_snapshot = self.json_snapshot(failure)
        session_id = thread_id
        contained_session_bytes = (
            json.dumps(
                {
                    "type": "session_meta",
                    "payload": {"id": session_id, "session_id": session_id},
                },
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
            + json.dumps(
                {
                    "type": "event_msg",
                    "payload": {"type": "task_started", "turn_id": turn_id},
                },
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        ).encode()
        containment = self.seal_field(
            {
                "schema": "cwo-live-campaign-containment-recovery:v2",
                "bead_id": "complex-work-orchestration-18w.6.24",
                "recorded_at": "2026-07-17T12:13:00Z",
                "failed_authorization": {
                    "authorization_id": authorization["authorization_id"],
                    "campaign_nonce": authorization["bindings"]["campaign_nonce"],
                    "canonical_sha256": authorization[
                        "canonical_authorization_sha256"
                    ],
                    "file_sha256": authorization_snapshot.raw_sha256,
                    "live_generation": 6,
                },
                "failed_manifest": {
                    "canonical_sha256": manifest["manifest_sha256"],
                    "file_sha256": manifest_snapshot.raw_sha256,
                    "manifest_id": manifest["manifest_id"],
                },
                "failed_evidence": {
                    "canonical_sha256": failure["evidence_sha256"],
                    "file_sha256": failure_snapshot.raw_sha256,
                    "authorization_state_canonical_sha256": state_snapshot.value[
                        "state_sha256"
                    ],
                    "authorization_state_file_sha256": state_snapshot.raw_sha256,
                },
                "root_cause": {
                    "exception_class": "TypeError",
                    "failure_class": "synthetic-live-callback-failure",
                    "falsifiable_cause": "a keyword adapter removes the mismatch",
                    "independent_reproduction": True,
                    "message": "synthetic callback mismatch",
                    "message_sha256": failure_message_sha256,
                },
                "session_accounting": [
                    {
                        "session_id": session_id,
                        "active_match_count": 0,
                        "archive_match_count": 1,
                        "archived_session_file_sha256": LIVE.sha256_bytes(
                            contained_session_bytes
                        ),
                    }
                ],
                "allocation_ledger": {
                    "allocated_roles": ["capability-calibration"],
                    "allocation_intent_count": 1,
                    "audit_file_sha256": LIVE.sha256_bytes(
                        allocation_audit_bytes
                    ),
                    "head_entry_sha256": ledger_summary["head_entry_sha256"],
                    "ledger_file_sha256": ledger_snapshot.raw_sha256,
                    "sequence": ledger_summary["sequence"],
                    "state_sha256": ledger_summary["state_sha256"],
                    "thread_bound_count": 1,
                    "turn_bound_count": 1,
                    "turn_intent_count": 1,
                    "unresolved_allocation_intent_count": 0,
                    "unresolved_turn_intent_count": 0,
                    "validation_errors": [],
                },
                "containment": containment_summary,
                "control_plane_recheck": {
                    "authorization_state_validation_errors": [],
                    "campaign_process_alive": False,
                    "controller_pid": 1,
                    "disposable_workspace_present": False,
                    "evidence_canonical_hash_valid": True,
                    "isolated_checkout_head": checkpoint,
                    "isolated_checkout_tracked_clean": True,
                    "isolated_checkout_tree": candidate_tree,
                    "operative_dispatch_authorized": False,
                    "origin_main_commit": manifest["candidate"][
                        "origin_main_commit"
                    ],
                    "protected_primary_diff_sha256": manifest["candidate"][
                        "guarded_primary_diff_sha256"
                    ],
                    "release_policy_status": "canary-gated",
                },
                "disposition": {
                    "authorization_state": "containment-only",
                    "outer_full_auto_recovery_permitted": True,
                    "release_gate_passed": False,
                    "requires_fresh_live_generation": 7,
                    "requires_validated_candidate_repair": True,
                    "reuse_resume_retry_substitution_salvage_bridge": False,
                },
            },
            "canonical_recovery_sha256",
        )
        return LIVE.Version5PredecessorProofInputs(
            authorization=authorization_snapshot,
            manifest=manifest_snapshot,
            authorization_state=state_snapshot,
            failure_evidence=failure_snapshot,
            containment=self.json_snapshot(containment),
            allocation_ledger=ledger_snapshot,
            allocation_audit_bytes=allocation_audit_bytes,
            authorization_cause_evidence=ancestor_artifacts["cause_evidence"],
            outer_authority=self.json_snapshot(outer_authority),
            independent_validation_receipt=LIVE.JsonArtifactSnapshot(
                raw=receipt_raw, value=receipt
            ),
            independent_validation_session_bytes=session_raw,
            ancestor=self.historical_proof(ancestor_artifacts),
            contained_session_bytes=(contained_session_bytes,),
        )

    def reseal_v6_authorization(self, value: dict) -> None:
        bindings = value["bindings"]
        progress = value["progress_gate"]
        lineage = {
            "validator_contract_sha256": bindings["validator_contract_sha256"],
            "authorization_id": bindings["predecessor_authorization_id"],
            "authorization_file_sha256": bindings[
                "predecessor_authorization_file_sha256"
            ],
            "authorization_canonical_sha256": bindings[
                "predecessor_authorization_canonical_sha256"
            ],
            "manifest_file_sha256": bindings["predecessor_manifest_file_sha256"],
            "manifest_canonical_sha256": bindings[
                "predecessor_manifest_canonical_sha256"
            ],
            "authorization_state_file_sha256": bindings[
                "predecessor_authorization_state_file_sha256"
            ],
            "authorization_state_canonical_sha256": bindings[
                "predecessor_authorization_state_canonical_sha256"
            ],
            "live_generation": value["predecessor_live_generation"],
            "candidate_commit": progress["predecessor_candidate_commit"],
            "candidate_tree": progress["predecessor_candidate_tree"],
            "failure_evidence_file_sha256": bindings[
                "predecessor_failure_evidence_file_sha256"
            ],
            "failure_evidence_canonical_sha256": bindings[
                "predecessor_failure_evidence_canonical_sha256"
            ],
            "containment_file_sha256": bindings[
                "predecessor_containment_file_sha256"
            ],
            "containment_canonical_sha256": bindings[
                "predecessor_containment_canonical_sha256"
            ],
            "recovery_cause_evidence_file_sha256": bindings[
                "recovery_cause_evidence_file_sha256"
            ],
            "recovery_cause_evidence_canonical_sha256": bindings[
                "recovery_cause_evidence_canonical_sha256"
            ],
            "allocation_ledger_file_sha256": bindings[
                "predecessor_allocation_ledger_file_sha256"
            ],
            "allocation_ledger_state_sha256": bindings[
                "predecessor_allocation_ledger_state_sha256"
            ],
            "allocation_audit_file_sha256": bindings[
                "predecessor_allocation_audit_file_sha256"
            ],
            "ancestor_lineage_sha256": bindings[
                "predecessor_ancestor_lineage_sha256"
            ],
        }
        progress["predecessor_lineage_sha256"] = LIVE.sha256_bytes(
            json.dumps(lineage, sort_keys=True, separators=(",", ":")).encode()
        )
        validation_binding = {
            "authorization_id": value["authorization_id"],
            "campaign_nonce": bindings["campaign_nonce"],
            "candidate_commit": bindings["checkpoint_commit"],
            "candidate_tree": bindings["checkpoint_tree"],
            "outer_authority_id": bindings["outer_authority_id"],
            "receipt_canonical_sha256": progress[
                "independent_validation_receipt_canonical_sha256"
            ],
            "receipt_file_sha256": progress[
                "independent_validation_receipt_file_sha256"
            ],
            "session_id": progress["independent_validation_session_id"],
            "completed_at": progress["independent_validation_completed_at"],
        }
        progress["independent_validation_binding_sha256"] = LIVE.sha256_bytes(
            json.dumps(
                validation_binding, sort_keys=True, separators=(",", ":")
            ).encode()
        )
        progress.pop("qualification_sha256", None)
        progress["qualification_sha256"] = LIVE.sha256_bytes(
            json.dumps(progress, sort_keys=True, separators=(",", ":")).encode()
        )
        value.pop("canonical_authorization_sha256", None)
        value["canonical_authorization_sha256"] = LIVE.sha256_bytes(
            json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
        )

    def generation7_successor(
        self,
        root: Path,
        predecessor: LIVE.Version5PredecessorProofInputs,
    ) -> dict[str, object]:
        (root / "generation7-repair.txt").write_text("repair", encoding="utf-8")
        subprocess.run(
            ["git", "add", "generation7-repair.txt"], cwd=root, check=True
        )
        subprocess.run(
            ["git", "commit", "-qm", "generation seven repair"],
            cwd=root,
            check=True,
        )
        checkpoint = LIVE.run_git(root, "rev-parse", "HEAD")
        checkpoint_tree = LIVE.run_git(root, "rev-parse", "HEAD^{tree}")
        self.install_validator_contract_files(root)
        validator_sha256 = LIVE.validator_contract_sha256(root)

        prior_authorization = predecessor.authorization.value
        prior_manifest = predecessor.manifest.value
        prior_state = predecessor.authorization_state.value
        prior_failure = predecessor.failure_evidence.value
        prior_containment = predecessor.containment.value
        prior_ledger = predecessor.allocation_ledger.value
        authorization = json.loads(json.dumps(prior_authorization))
        authorization.update(
            {
                "version": 6,
                "schema": "schemas/full-auto-run-authorization-v6.schema.json",
                "authorization_id": str(uuid.uuid4()),
                "run_generation": 12,
                "live_generation": 7,
                "predecessor_live_generation": 6,
                "issued_at": "2026-07-17T14:00:00Z",
            }
        )
        authorization["scope"]["ordered_work_units"] = [
            "complex-work-orchestration-18w.6.34",
            "complex-work-orchestration-18w.6.35",
            "complex-work-orchestration-18w.7",
        ]
        bindings = authorization["bindings"]
        bindings.update(
            {
                "checkpoint_commit": checkpoint,
                "checkpoint_tree": checkpoint_tree,
                "campaign_nonce": str(uuid.uuid4()),
                "predecessor_authorization_id": prior_authorization[
                    "authorization_id"
                ],
                "predecessor_authorization_file_sha256": predecessor.authorization.raw_sha256,
                "predecessor_authorization_canonical_sha256": prior_authorization[
                    "canonical_authorization_sha256"
                ],
                "predecessor_manifest_file_sha256": predecessor.manifest.raw_sha256,
                "predecessor_manifest_canonical_sha256": prior_manifest[
                    "manifest_sha256"
                ],
                "predecessor_authorization_state_file_sha256": predecessor.authorization_state.raw_sha256,
                "predecessor_authorization_state_canonical_sha256": prior_state[
                    "state_sha256"
                ],
                "predecessor_failure_evidence_file_sha256": predecessor.failure_evidence.raw_sha256,
                "predecessor_failure_evidence_canonical_sha256": prior_failure[
                    "evidence_sha256"
                ],
                "predecessor_containment_file_sha256": predecessor.containment.raw_sha256,
                "predecessor_containment_canonical_sha256": prior_containment[
                    "canonical_recovery_sha256"
                ],
                "predecessor_allocation_ledger_file_sha256": predecessor.allocation_ledger.raw_sha256,
                "predecessor_allocation_ledger_state_sha256": prior_ledger[
                    "state_sha256"
                ],
                "predecessor_allocation_audit_file_sha256": LIVE.sha256_bytes(
                    predecessor.allocation_audit_bytes
                ),
                "predecessor_ancestor_lineage_sha256": prior_authorization[
                    "progress_gate"
                ]["predecessor_lineage_sha256"],
                "validator_contract_sha256": validator_sha256,
                "outer_authority_id": str(uuid.uuid4()),
                "backup_ref": "refs/heads/backup/test-generation-seven",
            }
        )
        bindings.pop("predecessor_original_containment_file_sha256", None)
        bindings.pop("predecessor_original_containment_canonical_sha256", None)
        authorization["supersession"].update(
            {
                "prior_authorization_id": prior_authorization["authorization_id"],
                "prior_terminal_state": "containment-only",
                "prior_live_generation": 6,
                "prior_allocations": 1,
                "prior_ambiguities": 0,
                "prior_allowed_actions": 0,
            }
        )
        progress = authorization["progress_gate"]
        progress.update(
            {
                "predecessor_failure_class": "synthetic-live-callback-failure",
                "predecessor_failure_evidence_canonical_sha256": prior_failure[
                    "evidence_sha256"
                ],
                "predecessor_candidate_commit": prior_manifest["candidate"]["commit"],
                "predecessor_candidate_tree": prior_manifest["candidate"]["tree"],
                "new_falsifiable_cause": "a keyword adapter removes the mismatch",
                "repair_commit": checkpoint,
                "repair_tree": checkpoint_tree,
                "independent_validation_completed_at": "2026-07-17T13:59:00Z",
                "same_fault_without_new_evidence": False,
                "one_active_inner_campaign": True,
                "arbitrary_generation_cap": False,
                "fresh_exact_sol_pre_live_required": True,
            }
        )
        cause_source_analysis = b"synthetic callback source analysis\n"
        cause = self.seal_field(
            {
                "evidence_type": "cwo-native-live-campaign-cause-evidence",
                "version": 1,
                "schema": "schemas/native-live-campaign-cause-evidence.schema.json",
                "evidence_id": str(uuid.uuid4()),
                "recorded_at": "2026-07-17T13:58:00Z",
                "failed_authorization_id": prior_authorization["authorization_id"],
                "failed_manifest_id": prior_manifest["manifest_id"],
                "live_generation": 6,
                "failure_evidence_file_sha256": predecessor.failure_evidence.raw_sha256,
                "failure_evidence_canonical_sha256": prior_failure[
                    "evidence_sha256"
                ],
                "containment_file_sha256": predecessor.containment.raw_sha256,
                "containment_canonical_sha256": prior_containment[
                    "canonical_recovery_sha256"
                ],
                "failure_class": "synthetic-live-callback-failure",
                "failure_message_sha256": prior_failure[
                    "failure_message_sha256"
                ],
                "falsifiable_cause": "a keyword adapter removes the mismatch",
                "repair_commit": checkpoint,
                "repair_tree": checkpoint_tree,
                "source_analysis_sha256": LIVE.sha256_bytes(
                    cause_source_analysis
                ),
                "focused_tests_passed": 3,
                "repository_validation_passed": True,
                "compileall_passed": True,
                "diff_check_passed": True,
            },
            "canonical_cause_evidence_sha256",
        )
        cause_snapshot = self.json_snapshot(cause)
        bindings["recovery_cause_evidence_file_sha256"] = cause_snapshot.raw_sha256
        bindings["recovery_cause_evidence_canonical_sha256"] = cause[
            "canonical_cause_evidence_sha256"
        ]
        progress["cause_evidence_sha256"] = cause_snapshot.raw_sha256
        outer_authority = self.outer_authority(authorization)
        outer_snapshot = self.json_snapshot(outer_authority)
        bindings["outer_authority_canonical_sha256"] = outer_authority[
            "canonical_outer_authority_sha256"
        ]
        bindings["outer_authority_file_sha256"] = outer_snapshot.raw_sha256

        receipt, receipt_raw, session_path, session_raw = (
            self.bound_validation_receipt(root, authorization, checkpoint)
        )
        progress.update(
            {
                "independent_validation_receipt_canonical_sha256": receipt[
                    "canonical_receipt_sha256"
                ],
                "independent_validation_receipt_file_sha256": LIVE.sha256_bytes(
                    receipt_raw
                ),
                "independent_validation_session_id": receipt["session_id"],
                "independent_validation_completed_at": receipt["completed_at"],
            }
        )
        mandatory_gates = authorization["mandatory_gates"]
        mandatory_gates.pop("strict_authorization_v5", None)
        mandatory_gates.pop("campaign_manifest_v2", None)
        mandatory_gates.update(
            {
                "strict_authorization_v6": True,
                "campaign_manifest_v3": True,
                "finite_predecessor_proof_dag": True,
                "read_once_predecessor_snapshots": True,
                "atomic_launch_claim": True,
            }
        )
        self.reseal_v6_authorization(authorization)
        authorization_snapshot = self.json_snapshot(authorization)

        manifest = self.manifest(
            dict(prior_authorization), checkpoint, checkpoint_tree
        )
        manifest.update(
            {
                "version": 3,
                "schema": "schemas/native-live-campaign-manifest-v3.schema.json",
                "authorization_id": authorization["authorization_id"],
                "authorization_raw_sha256": authorization_snapshot.raw_sha256,
                "authorization_canonical_sha256": authorization[
                    "canonical_authorization_sha256"
                ],
                "run_generation": authorization["run_generation"],
                "live_generation": 7,
                "predecessor_live_generation": 6,
                "campaign_nonce": bindings["campaign_nonce"],
                "progress_qualification_sha256": progress[
                    "qualification_sha256"
                ],
                "executors": json.loads(json.dumps(authorization["executors"])),
            }
        )
        manifest["work_units"].update(
            {"live_work_unit_id": "complex-work-orchestration-18w.6.35"}
        )
        manifest["candidate"] = {
            "commit": checkpoint,
            "tree": checkpoint_tree,
            "origin_main_commit": bindings["origin_main_commit"],
            "guarded_primary_diff_sha256": bindings[
                "guarded_primary_diff_sha256"
            ],
        }
        manifest["predecessor"] = {
            "authorization_id": bindings["predecessor_authorization_id"],
            "authorization_file_sha256": bindings[
                "predecessor_authorization_file_sha256"
            ],
            "authorization_canonical_sha256": bindings[
                "predecessor_authorization_canonical_sha256"
            ],
            "manifest_file_sha256": bindings["predecessor_manifest_file_sha256"],
            "manifest_canonical_sha256": bindings[
                "predecessor_manifest_canonical_sha256"
            ],
            "authorization_state_file_sha256": bindings[
                "predecessor_authorization_state_file_sha256"
            ],
            "authorization_state_canonical_sha256": bindings[
                "predecessor_authorization_state_canonical_sha256"
            ],
            "candidate_commit": progress["predecessor_candidate_commit"],
            "candidate_tree": progress["predecessor_candidate_tree"],
            "lineage_sha256": progress["predecessor_lineage_sha256"],
            "failure_evidence_file_sha256": bindings[
                "predecessor_failure_evidence_file_sha256"
            ],
            "failure_evidence_canonical_sha256": bindings[
                "predecessor_failure_evidence_canonical_sha256"
            ],
            "containment_file_sha256": bindings[
                "predecessor_containment_file_sha256"
            ],
            "containment_canonical_sha256": bindings[
                "predecessor_containment_canonical_sha256"
            ],
            "recovery_cause_evidence_file_sha256": bindings[
                "recovery_cause_evidence_file_sha256"
            ],
            "recovery_cause_evidence_canonical_sha256": bindings[
                "recovery_cause_evidence_canonical_sha256"
            ],
            "allocation_ledger_file_sha256": bindings[
                "predecessor_allocation_ledger_file_sha256"
            ],
            "allocation_ledger_state_sha256": bindings[
                "predecessor_allocation_ledger_state_sha256"
            ],
            "allocation_audit_file_sha256": bindings[
                "predecessor_allocation_audit_file_sha256"
            ],
            "ancestor_lineage_sha256": bindings[
                "predecessor_ancestor_lineage_sha256"
            ],
            "validator_contract_sha256": validator_sha256,
        }
        manifest["outer_authority"] = {
            "authority_id": bindings["outer_authority_id"],
            "canonical_sha256": bindings["outer_authority_canonical_sha256"],
            "file_sha256": bindings["outer_authority_file_sha256"],
        }
        manifest["reviews"]["spark_validation_receipt_canonical_sha256"] = receipt[
            "canonical_receipt_sha256"
        ]
        manifest["reviews"]["spark_validation_receipt_file_sha256"] = (
            LIVE.sha256_bytes(receipt_raw)
        )
        manifest["release"]["candidate_tree"] = checkpoint_tree
        manifest["outputs"] = {
            "evidence_basename": "generation7-evidence.json",
            "authorization_state_basename": "generation7-state.json",
            "steering_registry_basename": "generation7-steering.json",
            "allocation_ledger_basename": "generation7-ledger",
        }
        self.reseal_manifest(manifest)
        return {
            "authorization": authorization,
            "authorization_snapshot": authorization_snapshot,
            "manifest": manifest,
            "manifest_snapshot": self.json_snapshot(manifest),
            "cause_snapshot": cause_snapshot,
            "cause_source_analysis": cause_source_analysis,
            "outer_snapshot": outer_snapshot,
            "receipt": receipt,
            "receipt_snapshot": LIVE.JsonArtifactSnapshot(
                raw=receipt_raw, value=receipt
            ),
            "session_path": session_path,
            "session_raw": session_raw,
            "validator_sha256": validator_sha256,
            "checkpoint": checkpoint,
            "checkpoint_tree": checkpoint_tree,
        }

    def test_independent_validation_session_binds_archived_jsonl(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            receipt, path = self.validation_session(root)
            with mock.patch.dict("os.environ", {"CODEX_HOME": str(root)}):
                self.assertEqual(
                    LIVE.validate_independent_validation_session(receipt, path),
                    receipt["boundary"]["terminal"]["boundary_sha256"],
                )
                path.chmod(0o644)
                self.assertEqual(
                    LIVE.validate_independent_validation_session(receipt, path),
                    receipt["boundary"]["terminal"]["boundary_sha256"],
                )
                path.chmod(0o664)
                with self.assertRaisesRegex(
                    LIVE.AppServerError, "permissions-invalid"
                ):
                    LIVE.validate_independent_validation_session(receipt, path)
                path.chmod(0o600)
                path.write_text(
                    path.read_text(encoding="utf-8") + "{}\n", encoding="utf-8"
                )
                with self.assertRaisesRegex(
                    LIVE.AppServerError, "boundary-mismatch"
                ):
                    LIVE.validate_independent_validation_session(receipt, path)

    def test_v6_v3_finite_predecessor_proof_accepts(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            predecessor_checkpoint, _orphan = self.make_repo(root)
            predecessor = self.modern_predecessor_proof(
                root, predecessor_checkpoint
            )
            successor = self.generation7_successor(root, predecessor)
            authorization = successor["authorization"]
            authorization_errors = LIVE.validate_full_auto_authorization_contract(
                authorization,
                expected_campaign_nonce=authorization["bindings"]["campaign_nonce"],
                predecessor_proof=predecessor,
                recovery_cause_evidence=successor["cause_snapshot"],
                recovery_cause_source_analysis=successor[
                    "cause_source_analysis"
                ],
                expected_validator_contract_sha256=successor["validator_sha256"],
                repo_root=root,
            )
            self.assertEqual(authorization_errors, [])
            manifest_errors = LIVE.validate_campaign_manifest(
                successor["manifest"],
                authorization=authorization,
                authorization_raw_sha256=successor[
                    "authorization_snapshot"
                ].raw_sha256,
                outer_authority=successor["outer_snapshot"].value,
                outer_authority_raw_sha256=successor["outer_snapshot"].raw_sha256,
                predecessor_proof=predecessor,
                recovery_cause_evidence=successor["cause_snapshot"],
                recovery_cause_source_analysis=successor[
                    "cause_source_analysis"
                ],
                independent_validation_receipt=successor["receipt"],
                independent_validation_receipt_raw_sha256=successor[
                    "receipt_snapshot"
                ].raw_sha256,
                expected_validator_contract_sha256=successor["validator_sha256"],
                repo_root=root,
                expected_primary_diff_sha256=LIVE.sha256_bytes(b""),
            )
            self.assertEqual(manifest_errors, [])

    def test_v6_proof_rejects_missing_legacy_alias_cause_and_session_tamper(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            predecessor_checkpoint, _orphan = self.make_repo(root)
            predecessor = self.modern_predecessor_proof(
                root, predecessor_checkpoint
            )
            successor = self.generation7_successor(root, predecessor)
            authorization = successor["authorization"]
            common = {
                "expected_campaign_nonce": authorization["bindings"][
                    "campaign_nonce"
                ],
                "recovery_cause_evidence": successor["cause_snapshot"],
                "recovery_cause_source_analysis": successor[
                    "cause_source_analysis"
                ],
                "expected_validator_contract_sha256": successor[
                    "validator_sha256"
                ],
                "repo_root": root,
            }
            missing = LIVE.validate_full_auto_authorization_contract(
                authorization, **common
            )
            self.assertIn("authorization-v6-predecessor-proof-missing", missing)
            legacy_alias = LIVE.validate_full_auto_authorization_contract(
                authorization,
                predecessor_proof=predecessor,
                predecessor_authorization=predecessor.authorization.value,
                **common,
            )
            self.assertEqual(
                legacy_alias,
                ["authorization-v6-legacy-proof-input-forbidden"],
            )

            changed_cause = dict(successor["cause_snapshot"].value)
            changed_cause["focused_tests_passed"] = 4
            cause_errors = LIVE.validate_full_auto_authorization_contract(
                authorization,
                predecessor_proof=predecessor,
                recovery_cause_evidence=LIVE.JsonArtifactSnapshot(
                    raw=successor["cause_snapshot"].raw,
                    value=changed_cause,
                ),
                recovery_cause_source_analysis=successor[
                    "cause_source_analysis"
                ],
                expected_validator_contract_sha256=successor[
                    "validator_sha256"
                ],
                repo_root=root,
            )
            self.assertTrue(
                any("recovery-cause-evidence" in item for item in cause_errors),
                cause_errors,
            )

            session_records = predecessor.independent_validation_session_bytes.splitlines(
                keepends=True
            )
            session_records.insert(
                -1,
                json.dumps(
                    {
                        "type": "response_item",
                        "payload": {
                            "type": "function_call",
                            "name": "exec_command",
                        },
                    }
                ).encode()
                + b"\n",
            )
            tool_session_proof = replace(
                predecessor,
                independent_validation_session_bytes=b"".join(session_records),
            )
            session_errors = LIVE.validate_full_auto_authorization_contract(
                authorization,
                predecessor_proof=tool_session_proof,
                **common,
            )
            self.assertTrue(
                any("validation-session-tool-activity" in item for item in session_errors),
                session_errors,
            )

    def test_v6_proof_rejects_ancestor_and_validator_anchor_changes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            predecessor_checkpoint, _orphan = self.make_repo(root)
            predecessor = self.modern_predecessor_proof(
                root, predecessor_checkpoint
            )
            successor = self.generation7_successor(root, predecessor)
            authorization = successor["authorization"]
            ancestor_authorization = json.loads(
                json.dumps(predecessor.ancestor.authorization.value)
            )
            ancestor_authorization["bindings"]["checkpoint_tree"] = "0" * 40
            changed_ancestor = replace(
                predecessor.ancestor,
                authorization=LIVE.JsonArtifactSnapshot(
                    raw=predecessor.ancestor.authorization.raw,
                    value=ancestor_authorization,
                ),
            )
            changed_proof = replace(predecessor, ancestor=changed_ancestor)
            ancestor_errors = LIVE.validate_full_auto_authorization_contract(
                authorization,
                expected_campaign_nonce=authorization["bindings"]["campaign_nonce"],
                predecessor_proof=changed_proof,
                recovery_cause_evidence=successor["cause_snapshot"],
                recovery_cause_source_analysis=successor[
                    "cause_source_analysis"
                ],
                expected_validator_contract_sha256=successor["validator_sha256"],
                repo_root=root,
            )
            self.assertTrue(
                any("historical-anchor-tree-mismatch" in item for item in ancestor_errors),
                ancestor_errors,
            )

            changed_authorization = json.loads(json.dumps(authorization))
            changed_authorization["bindings"]["validator_contract_sha256"] = "0" * 64
            self.reseal_v6_authorization(changed_authorization)
            validator_errors = LIVE.validate_full_auto_authorization_contract(
                changed_authorization,
                expected_campaign_nonce=changed_authorization["bindings"][
                    "campaign_nonce"
                ],
                predecessor_proof=predecessor,
                recovery_cause_evidence=successor["cause_snapshot"],
                recovery_cause_source_analysis=successor[
                    "cause_source_analysis"
                ],
                expected_validator_contract_sha256=successor["validator_sha256"],
                repo_root=root,
            )
            self.assertTrue(
                any("validator-contract" in item for item in validator_errors),
                validator_errors,
            )

    def test_v6_proof_rejects_session_ledger_cause_and_git_proof_gaps(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            predecessor_checkpoint, orphan = self.make_repo(root)
            predecessor = self.modern_predecessor_proof(
                root, predecessor_checkpoint
            )
            successor = self.generation7_successor(root, predecessor)
            authorization = successor["authorization"]

            def validate(
                proof: LIVE.Version5PredecessorProofInputs,
                *,
                source: bytes | None = successor["cause_source_analysis"],
            ) -> list[str]:
                return LIVE.validate_full_auto_authorization_contract(
                    authorization,
                    expected_campaign_nonce=authorization["bindings"][
                        "campaign_nonce"
                    ],
                    predecessor_proof=proof,
                    recovery_cause_evidence=successor["cause_snapshot"],
                    recovery_cause_source_analysis=source,
                    expected_validator_contract_sha256=successor[
                        "validator_sha256"
                    ],
                    repo_root=root,
                )

            self.assertIn(
                "authorization-v6-recovery-cause-source-analysis-missing",
                validate(predecessor, source=None),
            )
            self.assertIn(
                "authorization-recovery-cause-evidence-binding-invalid",
                validate(predecessor, source=b"different source analysis\n"),
            )

            contained_session_errors = validate(
                replace(predecessor, contained_session_bytes=(b"{}\n",))
            )
            self.assertTrue(
                any("modern-session" in item for item in contained_session_errors),
                contained_session_errors,
            )
            ancestor_session_errors = validate(
                replace(
                    predecessor,
                    ancestor=replace(
                        predecessor.ancestor,
                        contained_session_bytes=(b"{}\n",),
                    ),
                )
            )
            self.assertTrue(
                any("ancestor" in item for item in ancestor_session_errors),
                ancestor_session_errors,
            )

            changed_ledger = json.loads(
                json.dumps(predecessor.allocation_ledger.value)
            )
            next(
                item
                for item in changed_ledger["entries"]
                if item["event"] == "allocation-intent"
            )["role"] = "read-only-0"
            role_errors = validate(
                replace(
                    predecessor,
                    allocation_ledger=LIVE.JsonArtifactSnapshot(
                        raw=predecessor.allocation_ledger.raw,
                        value=changed_ledger,
                    ),
                )
            )
            self.assertIn(
                "authorization-predecessor-modern-ledger-role-prefix-invalid",
                role_errors,
            )

            missing_certification = json.loads(
                json.dumps(predecessor.allocation_ledger.value)
            )
            missing_certification["entries"] = [
                item
                for item in missing_certification["entries"]
                if item["event"] != "certification-bound"
            ]
            certification_errors = validate(
                replace(
                    predecessor,
                    allocation_ledger=LIVE.JsonArtifactSnapshot(
                        raw=predecessor.allocation_ledger.raw,
                        value=missing_certification,
                    ),
                )
            )
            self.assertIn(
                "authorization-predecessor-modern-ledger-certification-invalid",
                certification_errors,
            )

            ledger = predecessor.allocation_ledger.value
            allocated = sum(
                item.get("event") == "allocation-intent"
                for item in ledger["entries"]
            )
            self.assertEqual(
                CAMPAIGN_CONTRACTS._validate_modern_ledger_semantics(
                    ledger, allocated
                ),
                [],
            )
            missing_lifecycle = json.loads(json.dumps(ledger))
            capability_id = next(
                item["allocation_intent_id"]
                for item in missing_lifecycle["entries"]
                if item["event"] == "allocation-intent" and item["ordinal"] == 0
            )
            missing_lifecycle["entries"] = [
                item
                for item in missing_lifecycle["entries"]
                if not (
                    item.get("allocation_intent_id") == capability_id
                    and item.get("event")
                    in {"interrupt-observed", "archive-observed"}
                )
            ]
            lifecycle_errors = (
                CAMPAIGN_CONTRACTS._validate_modern_ledger_semantics(
                    missing_lifecycle, allocated
                )
            )
            self.assertIn(
                "authorization-predecessor-modern-ledger-interrupt-invalid",
                lifecycle_errors,
            )
            self.assertIn(
                "authorization-predecessor-modern-ledger-archive-invalid",
                lifecycle_errors,
            )

            wrong_outcomes = json.loads(json.dumps(ledger))
            for item in wrong_outcomes["entries"]:
                if item.get("event") == "interrupt-observed":
                    item["outcome"] = "arbitrary-nonempty"
                elif item.get("event") == "archive-observed":
                    item["outcome"] = "another-nonempty-value"
            outcome_errors = CAMPAIGN_CONTRACTS._validate_modern_ledger_semantics(
                wrong_outcomes, allocated
            )
            self.assertIn(
                "authorization-predecessor-modern-ledger-interrupt-invalid",
                outcome_errors,
            )
            self.assertIn(
                "authorization-predecessor-modern-ledger-archive-invalid",
                outcome_errors,
            )

            changed_manifest = json.loads(
                json.dumps(predecessor.ancestor.manifest.value)
            )
            changed_manifest["candidate"] = {
                **changed_manifest["candidate"],
                "commit": orphan,
                "tree": LIVE.run_git(root, "rev-parse", f"{orphan}^{{tree}}"),
            }
            anchor_errors = validate(
                replace(
                    predecessor,
                    ancestor=replace(
                        predecessor.ancestor,
                        manifest=LIVE.JsonArtifactSnapshot(
                            raw=predecessor.ancestor.manifest.raw,
                            value=changed_manifest,
                        ),
                    ),
                )
            )
            self.assertIn(
                "authorization-historical-anchor-lineage-invalid",
                anchor_errors,
            )

            changed_failure = json.loads(
                json.dumps(predecessor.failure_evidence.value)
            )
            changed_failure["failure_message_sha256"] = "0" * 64
            cause_errors = validate(
                replace(
                    predecessor,
                    failure_evidence=LIVE.JsonArtifactSnapshot(
                        raw=predecessor.failure_evidence.raw,
                        value=changed_failure,
                    ),
                )
            )
            self.assertIn(
                "authorization-recovery-cause-evidence-binding-invalid",
                cause_errors,
            )

    def test_v6_session_inputs_use_trusted_source_rules_and_recheck_bytes(
        self,
    ) -> None:
        self.assertFalse(
            LIVE.campaign_input_requires_private_parent(
                "predecessor-contained-session-0"
            )
        )
        self.assertFalse(
            LIVE.campaign_input_requires_private_parent(
                "ancestor-contained-session-0"
            )
        )
        self.assertFalse(
            LIVE.campaign_input_requires_private_parent("spark-validation-session")
        )
        self.assertTrue(LIVE.campaign_input_requires_private_parent("authorization"))

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            predecessor_checkpoint, _orphan = self.make_repo(root)
            predecessor = self.modern_predecessor_proof(
                root, predecessor_checkpoint
            )
            successor = self.generation7_successor(root, predecessor)
            session_path = successor["session_path"]
            session_path.parent.chmod(0o755)
            session_path.chmod(0o644)
            inputs = LIVE.CampaignLaunchInputs(
                authorization=successor["authorization_snapshot"],
                manifest=successor["manifest_snapshot"],
                outer_authority=successor["outer_snapshot"],
                release_patch_bytes=b"release patch",
                pre_mutation_receipt=self.json_snapshot(
                    {"canonical_receipt_sha256": LIVE.sha256_text("pre-mutation")}
                ),
                pre_mutation_adjudication=self.json_snapshot({"decision": "go"}),
                pre_live_receipt=self.json_snapshot(
                    {"canonical_receipt_sha256": LIVE.sha256_text("pre-live")}
                ),
                pre_live_adjudication=self.json_snapshot({"decision": "go"}),
                opus_review_evidence=self.json_snapshot({"verdict": "go"}),
                opus_adjudication=self.json_snapshot({"decision": "go"}),
                spark_validation_receipt=successor["receipt_snapshot"],
                spark_validation_session_path=session_path,
                spark_validation_session_bytes=successor["session_raw"],
                predecessor_proof=predecessor,
                recovery_cause_evidence=successor["cause_snapshot"],
                recovery_cause_source_analysis_bytes=successor[
                    "cause_source_analysis"
                ],
            )
            paths = {"spark-validation-session": session_path}
            for label, raw in (
                (
                    "predecessor-independent-validation-session",
                    predecessor.independent_validation_session_bytes,
                ),
                *(
                    (f"predecessor-contained-session-{index}", value)
                    for index, value in enumerate(predecessor.contained_session_bytes)
                ),
                *(
                    (f"ancestor-contained-session-{index}", value)
                    for index, value in enumerate(
                        predecessor.ancestor.contained_session_bytes
                    )
                ),
            ):
                path = root / f"{label}.jsonl"
                path.write_bytes(raw)
                paths[label] = path
            LIVE.require_trusted_session_snapshots_unchanged(paths, inputs)
            session_path.write_bytes(successor["session_raw"] + b"{}\n")
            with self.assertRaisesRegex(
                LIVE.AppServerError,
                "spark-validation-session-changed-before-allocation",
            ):
                LIVE.require_trusted_session_snapshots_unchanged(paths, inputs)

    def test_v3_cross_field_and_launch_claim_bind_every_immutable_input(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            predecessor_checkpoint, _orphan = self.make_repo(root)
            predecessor = self.modern_predecessor_proof(
                root, predecessor_checkpoint
            )
            successor = self.generation7_successor(root, predecessor)
            manifest = json.loads(json.dumps(successor["manifest"]))
            manifest["predecessor"]["ancestor_lineage_sha256"] = "0" * 64
            self.reseal_manifest(manifest)
            errors = LIVE.validate_campaign_manifest(
                manifest,
                authorization=successor["authorization"],
                authorization_raw_sha256=successor[
                    "authorization_snapshot"
                ].raw_sha256,
                outer_authority=successor["outer_snapshot"].value,
                outer_authority_raw_sha256=successor["outer_snapshot"].raw_sha256,
                predecessor_proof=predecessor,
                recovery_cause_evidence=successor["cause_snapshot"],
                recovery_cause_source_analysis=successor[
                    "cause_source_analysis"
                ],
                independent_validation_receipt=successor["receipt"],
                independent_validation_receipt_raw_sha256=successor[
                    "receipt_snapshot"
                ].raw_sha256,
                expected_validator_contract_sha256=successor["validator_sha256"],
                repo_root=root,
                expected_primary_diff_sha256=LIVE.sha256_bytes(b""),
            )
            self.assertIn(
                "campaign-manifest-v3-predecessor-authorization-mismatch", errors
            )

            def receipt_snapshot(label: str) -> LIVE.JsonArtifactSnapshot:
                value = {"canonical_receipt_sha256": LIVE.sha256_text(label)}
                return self.json_snapshot(value)

            inputs = LIVE.CampaignLaunchInputs(
                authorization=successor["authorization_snapshot"],
                manifest=successor["manifest_snapshot"],
                outer_authority=successor["outer_snapshot"],
                release_patch_bytes=b"release patch",
                pre_mutation_receipt=receipt_snapshot("pre-mutation"),
                pre_mutation_adjudication=receipt_snapshot("pre-mutation-adjudication"),
                pre_live_receipt=receipt_snapshot("pre-live"),
                pre_live_adjudication=receipt_snapshot("pre-live-adjudication"),
                opus_review_evidence=receipt_snapshot("opus"),
                opus_adjudication=receipt_snapshot("opus-adjudication"),
                spark_validation_receipt=successor["receipt_snapshot"],
                spark_validation_session_path=successor["session_path"],
                spark_validation_session_bytes=successor["session_raw"],
                predecessor_proof=predecessor,
                recovery_cause_evidence=successor["cause_snapshot"],
                recovery_cause_source_analysis_bytes=successor[
                    "cause_source_analysis"
                ],
            )
            parent = root / "outputs"
            parent.mkdir()
            output_paths = {
                "output": parent / "generation7-evidence.json",
                "authorization_state": parent / "generation7-state.json",
                "steering_registry": parent / "generation7-steering.json",
                "allocation_ledger": parent / "generation7-ledger",
            }
            claim = LIVE.campaign_launch_claim_sha256(inputs, **output_paths)
            changed_inputs = LIVE.CampaignLaunchInputs(
                authorization=inputs.authorization,
                manifest=inputs.manifest,
                outer_authority=inputs.outer_authority,
                release_patch_bytes=inputs.release_patch_bytes,
                pre_mutation_receipt=inputs.pre_mutation_receipt,
                pre_mutation_adjudication=inputs.pre_mutation_adjudication,
                pre_live_receipt=receipt_snapshot("changed-pre-live"),
                pre_live_adjudication=inputs.pre_live_adjudication,
                opus_review_evidence=inputs.opus_review_evidence,
                opus_adjudication=inputs.opus_adjudication,
                spark_validation_receipt=inputs.spark_validation_receipt,
                spark_validation_session_path=inputs.spark_validation_session_path,
                spark_validation_session_bytes=inputs.spark_validation_session_bytes,
                predecessor_proof=predecessor,
                recovery_cause_evidence=inputs.recovery_cause_evidence,
                recovery_cause_source_analysis_bytes=(
                    inputs.recovery_cause_source_analysis_bytes
                ),
            )
            self.assertNotEqual(
                claim,
                LIVE.campaign_launch_claim_sha256(
                    changed_inputs, **output_paths
                ),
            )
            alias = root / "same.json"
            alias.write_text("{}", encoding="utf-8")
            with self.assertRaisesRegex(LIVE.AppServerError, "path-alias"):
                LIVE.require_unique_input_paths({"one": alias, "two": alias})

    def test_independent_validation_session_rejects_tool_activity(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            receipt, path = self.validation_session(
                root, with_function_call=True
            )
            with mock.patch.dict("os.environ", {"CODEX_HOME": str(root)}):
                with self.assertRaisesRegex(
                    LIVE.AppServerError, "activity-invalid"
                ):
                    LIVE.validate_independent_validation_session(receipt, path)

    def test_independent_validation_session_rejects_cross_turn_assistant_output(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            receipt, path = self.validation_session(root)
            records = [json.loads(line) for line in path.read_text().splitlines()]
            records.insert(
                -1,
                {
                    "type": "response_item",
                    "payload": {
                        "type": "message",
                        "role": "assistant",
                        "phase": "final_answer",
                        "content": [{"type": "output_text", "text": "{}"}],
                    },
                },
            )
            path.write_text("".join(json.dumps(item) + "\n" for item in records))
            boundary, _ = LIVE.capture_boundary(path, receipt["session_id"])
            receipt["boundary"]["terminal"].update(boundary)
            with mock.patch.dict("os.environ", {"CODEX_HOME": str(root)}):
                with self.assertRaisesRegex(LIVE.AppServerError, "activity-invalid"):
                    LIVE.validate_independent_validation_session(receipt, path)

    def test_independent_validation_session_rejects_symlink_and_unknown_activity(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            receipt, path = self.validation_session(root)
            link = path.with_name("linked-" + path.name)
            link.symlink_to(path)
            with mock.patch.dict("os.environ", {"CODEX_HOME": str(root)}):
                with self.assertRaisesRegex(LIVE.AppServerError, "path-invalid"):
                    LIVE.validate_independent_validation_session(receipt, link)
            linked_archive = root / "linked-archive"
            linked_archive.symlink_to(path.parent, target_is_directory=True)
            with mock.patch.dict("os.environ", {"CODEX_HOME": str(root)}):
                with self.assertRaisesRegex(LIVE.AppServerError, "path-invalid"):
                    LIVE.validate_independent_validation_session(
                        receipt, linked_archive / path.name
                    )
            records = [json.loads(line) for line in path.read_text().splitlines()]
            records.insert(
                -1,
                {"type": "response_item", "payload": {"type": "fileChange"}},
            )
            path.write_text("".join(json.dumps(item) + "\n" for item in records))
            boundary, _ = LIVE.capture_boundary(path, receipt["session_id"])
            receipt["boundary"]["terminal"].update(boundary)
            with mock.patch.dict("os.environ", {"CODEX_HOME": str(root)}):
                with self.assertRaisesRegex(LIVE.AppServerError, "activity-invalid"):
                    LIVE.validate_independent_validation_session(receipt, path)

    def reseal_manifest(self, value: dict) -> None:
        value.pop("manifest_sha256", None)
        value["manifest_sha256"] = LIVE.sha256_bytes(
            json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
        )

    def test_full_auto_authorization_v5_acceptance_and_legacy_rejection(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            head, _orphan = self.make_repo(root)
            authorization = self.authorization(root, head)
            self.assertEqual(
                LIVE.validate_full_auto_authorization(
                    authorization,
                    authorization["bindings"]["campaign_nonce"],
                    repo_root=root,
                )[0],
                authorization["authorization_id"],
            )
            for version, schema in (
                (3, "cwo-full-auto-run-authorization:v3"),
                (4, "schemas/full-auto-run-authorization.schema.json"),
                (5, "unknown"),
            ):
                with self.subTest(version=version, schema=schema):
                    invalid = json.loads(json.dumps(authorization))
                    invalid["version"] = version
                    invalid["schema"] = schema
                    self.reseal_authorization(invalid)
                    with self.assertRaisesRegex(LIVE.AppServerError, "header"):
                        LIVE.validate_full_auto_authorization(
                            invalid,
                            invalid["bindings"]["campaign_nonce"],
                            repo_root=root,
                        )

    def test_manifest_strict_binding_replay_and_policy_contract(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            head, _orphan = self.make_repo(root)
            authorization = self.authorization(root, head)
            spark_receipt = self.spark_validation_receipt(authorization, head)
            authorization["progress_gate"][
                "independent_validation_receipt_canonical_sha256"
            ] = spark_receipt["canonical_receipt_sha256"]
            authorization["progress_gate"][
                "independent_validation_receipt_file_sha256"
            ] = "b" * 64
            self.reseal_authorization(authorization)
            tree = LIVE.run_git(root, "rev-parse", "HEAD^{tree}")
            manifest = self.manifest(authorization, head, tree)
            outer_authority = self.outer_authority(authorization)
            predecessor = self.predecessor_artifacts(
                root,
                authorization["bindings"]["predecessor_authorization_id"],
                authorization["progress_gate"]["predecessor_candidate_commit"],
                authorization["progress_gate"]["predecessor_candidate_tree"],
            )
            self.assertEqual(
                LIVE.validate_campaign_manifest(
                    manifest,
                    authorization=authorization,
                    authorization_raw_sha256="7" * 64,
                    outer_authority=outer_authority,
                    outer_authority_raw_sha256=authorization["bindings"][
                        "outer_authority_file_sha256"
                    ],
                    predecessor_authorization=predecessor["authorization"],
                    predecessor_authorization_raw_sha256=predecessor[
                        "authorization_raw_sha256"
                    ],
                    predecessor_manifest=predecessor["manifest"],
                    predecessor_manifest_raw_sha256=predecessor[
                        "manifest_raw_sha256"
                    ],
                    predecessor_authorization_state=predecessor["state"],
                    predecessor_authorization_state_raw_sha256=predecessor[
                        "state_raw_sha256"
                    ],
                    predecessor_failure_evidence=predecessor["failure"],
                    predecessor_failure_evidence_raw_sha256=predecessor[
                        "failure_raw_sha256"
                    ],
                    predecessor_original_containment=predecessor[
                        "original_containment"
                    ],
                    predecessor_original_containment_raw_sha256=predecessor[
                        "original_containment_raw_sha256"
                    ],
                    predecessor_containment=predecessor["containment"],
                    predecessor_containment_raw_sha256=predecessor[
                        "containment_raw_sha256"
                    ],
                    predecessor_allocation_ledger=predecessor["ledger"],
                    predecessor_allocation_ledger_raw_sha256=predecessor[
                        "ledger_raw_sha256"
                    ],
                    predecessor_allocation_audit_path=predecessor["audit_path"],
                    predecessor_allocation_audit_raw_sha256=predecessor[
                        "audit_raw_sha256"
                    ],
                    cause_evidence=predecessor["cause_evidence"],
                    independent_validation_receipt=spark_receipt,
                    independent_validation_receipt_raw_sha256="b" * 64,
                    expected_primary_diff_sha256=LIVE.sha256_bytes(b""),
                ),
                [],
            )
            legacy = json.loads(json.dumps(manifest))
            legacy["version"] = 1
            self.reseal_manifest(legacy)
            self.assertIn(
                "campaign-manifest-header-invalid",
                LIVE.validate_campaign_manifest(legacy, authorization=authorization),
            )
            unknown = json.loads(json.dumps(manifest))
            unknown["unknown"] = True
            self.reseal_manifest(unknown)
            self.assertIn(
                "campaign-manifest-fields-invalid",
                LIVE.validate_campaign_manifest(unknown, authorization=authorization),
            )
            replay = json.loads(json.dumps(manifest))
            replay["campaign_nonce"] = str(uuid.uuid4())
            self.reseal_manifest(replay)
            self.assertIn(
                "campaign-manifest-authorization-campaign-nonce-mismatch",
                LIVE.validate_campaign_manifest(replay, authorization=authorization),
            )
            changed_candidate = json.loads(json.dumps(manifest))
            changed_candidate["candidate"]["commit"] = "0" * 40
            self.reseal_manifest(changed_candidate)
            self.assertIn(
                "campaign-manifest-candidate-authorization-mismatch",
                LIVE.validate_campaign_manifest(
                    changed_candidate, authorization=authorization
                ),
            )
            duplicate_output = json.loads(json.dumps(manifest))
            duplicate_output["outputs"]["steering_registry_basename"] = duplicate_output[
                "outputs"
            ]["evidence_basename"]
            self.reseal_manifest(duplicate_output)
            self.assertIn(
                "campaign-manifest-output-identity-invalid",
                LIVE.validate_campaign_manifest(duplicate_output, authorization=authorization),
            )
            policy = json.loads(json.dumps(manifest))
            policy["release"]["policy_before"]["cap_two_operative_release"] = True
            self.reseal_manifest(policy)
            self.assertIn(
                "campaign-manifest-policy-before-invalid",
                LIVE.validate_campaign_manifest(policy, authorization=authorization),
            )
            inactive_outer = dict(outer_authority)
            inactive_outer["status"] = "parked"
            self.assertIn(
                "campaign-manifest-outer-authority-state-invalid",
                LIVE.validate_campaign_manifest(
                    manifest,
                    authorization=authorization,
                    outer_authority=inactive_outer,
                    outer_authority_raw_sha256=authorization["bindings"][
                        "outer_authority_file_sha256"
                    ],
                ),
            )
            self.assertIn(
                "campaign-manifest-outer-authority-canonical-sha256-mismatch",
                LIVE.validate_campaign_manifest(
                    manifest,
                    authorization=authorization,
                    outer_authority=inactive_outer,
                    outer_authority_raw_sha256=authorization["bindings"][
                        "outer_authority_file_sha256"
                    ],
                ),
            )
            self.assertIn(
                "campaign-manifest-outer-authority-binding-mismatch",
                LIVE.validate_campaign_manifest(
                    manifest,
                    authorization=authorization,
                    outer_authority=outer_authority,
                    outer_authority_raw_sha256="0" * 64,
                ),
            )
            wrong_spark = json.loads(json.dumps(spark_receipt))
            wrong_spark["model"] = "gpt-5.6-sol"
            self.assertIn(
                "campaign-manifest-independent-validation-not-accepting",
                LIVE.validate_campaign_manifest(
                    manifest,
                    authorization=authorization,
                    independent_validation_receipt=wrong_spark,
                    independent_validation_receipt_raw_sha256="b" * 64,
                ),
            )
            self.assertIn(
                "campaign-manifest-independent-validation-canonical-sha256-mismatch",
                LIVE.validate_campaign_manifest(
                    manifest,
                    authorization=authorization,
                    independent_validation_receipt=wrong_spark,
                    independent_validation_receipt_raw_sha256="b" * 64,
                ),
            )

    def test_predecessor_lineage_and_receipt_integrity_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            head, _orphan = self.make_repo(root)
            authorization = self.authorization(root, head)
            spark_receipt = self.spark_validation_receipt(authorization, head)
            authorization["progress_gate"][
                "independent_validation_receipt_canonical_sha256"
            ] = spark_receipt["canonical_receipt_sha256"]
            authorization["progress_gate"][
                "independent_validation_receipt_file_sha256"
            ] = "b" * 64
            self.reseal_authorization(authorization)
            manifest = self.manifest(
                authorization,
                head,
                LIVE.run_git(root, "rev-parse", "HEAD^{tree}"),
            )
            predecessor = self.predecessor_artifacts(
                root,
                authorization["bindings"]["predecessor_authorization_id"],
                authorization["progress_gate"]["predecessor_candidate_commit"],
                authorization["progress_gate"]["predecessor_candidate_tree"],
            )

            tampered_receipt = json.loads(json.dumps(spark_receipt))
            tampered_receipt["opinion"]["findings"] = [
                {"code": "forged", "severity": "none"}
            ]
            self.assertIn(
                "campaign-manifest-independent-validation-canonical-sha256-mismatch",
                LIVE.validate_campaign_manifest(
                    manifest,
                    authorization=authorization,
                    independent_validation_receipt=tampered_receipt,
                    independent_validation_receipt_raw_sha256="b" * 64,
                ),
            )

            arbitrary_ancestor = json.loads(json.dumps(authorization))
            arbitrary_ancestor["progress_gate"]["predecessor_candidate_commit"] = (
                LIVE.run_git(root, "rev-parse", f"{head}^^")
            )
            arbitrary_ancestor["progress_gate"]["predecessor_candidate_tree"] = (
                LIVE.run_git(root, "rev-parse", f"{head}^^^{{tree}}")
            )
            self.reseal_authorization(arbitrary_ancestor)
            arbitrary_manifest = self.manifest(
                arbitrary_ancestor,
                head,
                LIVE.run_git(root, "rev-parse", "HEAD^{tree}"),
            )
            self.assertIn(
                "campaign-manifest-authorization:authorization-predecessor-historical-binding-invalid",
                LIVE.validate_campaign_manifest(
                    arbitrary_manifest,
                    authorization=arbitrary_ancestor,
                    predecessor_authorization=predecessor["authorization"],
                    predecessor_authorization_raw_sha256=predecessor[
                        "authorization_raw_sha256"
                    ],
                    predecessor_manifest=predecessor["manifest"],
                    predecessor_manifest_raw_sha256=predecessor[
                        "manifest_raw_sha256"
                    ],
                    predecessor_authorization_state=predecessor["state"],
                    predecessor_authorization_state_raw_sha256=predecessor[
                        "state_raw_sha256"
                    ],
                    predecessor_failure_evidence=predecessor["failure"],
                    predecessor_failure_evidence_raw_sha256=predecessor[
                        "failure_raw_sha256"
                    ],
                    predecessor_original_containment=predecessor["original_containment"],
                    predecessor_original_containment_raw_sha256=predecessor["original_containment_raw_sha256"],
                    predecessor_allocation_ledger=predecessor["ledger"],
                    predecessor_allocation_ledger_raw_sha256=predecessor["ledger_raw_sha256"],
                    predecessor_allocation_audit_path=predecessor["audit_path"],
                    predecessor_allocation_audit_raw_sha256=predecessor["audit_raw_sha256"],
                    predecessor_containment=predecessor["containment"],
                    predecessor_containment_raw_sha256=predecessor[
                        "containment_raw_sha256"
                    ],
                    cause_evidence=predecessor["cause_evidence"],
                ),
            )

            wrong_identity = json.loads(json.dumps(predecessor["authorization"]))
            wrong_identity["authorization_id"] = str(uuid.uuid4())
            self.assertIn(
                "authorization-predecessor-historical-binding-invalid",
                LIVE.validate_full_auto_authorization_contract(
                    authorization,
                    predecessor_authorization=wrong_identity,
                    predecessor_authorization_raw_sha256=predecessor[
                        "authorization_raw_sha256"
                    ],
                    predecessor_manifest=predecessor["manifest"],
                    predecessor_manifest_raw_sha256=predecessor[
                        "manifest_raw_sha256"
                    ],
                    predecessor_authorization_state=predecessor["state"],
                    predecessor_authorization_state_raw_sha256=predecessor[
                        "state_raw_sha256"
                    ],
                    predecessor_failure_evidence=predecessor["failure"],
                    predecessor_failure_evidence_raw_sha256=predecessor[
                        "failure_raw_sha256"
                    ],
                    predecessor_original_containment=predecessor["original_containment"],
                    predecessor_original_containment_raw_sha256=predecessor["original_containment_raw_sha256"],
                    predecessor_allocation_ledger=predecessor["ledger"],
                    predecessor_allocation_ledger_raw_sha256=predecessor["ledger_raw_sha256"],
                    predecessor_allocation_audit_path=predecessor["audit_path"],
                    predecessor_allocation_audit_raw_sha256=predecessor["audit_raw_sha256"],
                    predecessor_containment=predecessor["containment"],
                    predecessor_containment_raw_sha256=predecessor[
                        "containment_raw_sha256"
                    ],
                    cause_evidence=predecessor["cause_evidence"],
                ),
            )
            self.assertIn(
                "authorization-predecessor-artifacts-incomplete",
                LIVE.validate_full_auto_authorization_contract(
                    authorization,
                    predecessor_authorization=predecessor["authorization"],
                ),
            )
            tamper_cases = (
                ("state", "state", "active", "state-binding"),
                (
                    "failure",
                    "validation_outcome",
                    "accepted",
                    "failure-binding",
                ),
                (
                    "containment",
                    "failed_campaign_nonce",
                    str(uuid.uuid4()),
                    "containment-correction-binding",
                ),
            )
            for artifact_name, field, changed, expected in tamper_cases:
                with self.subTest(artifact=artifact_name):
                    artifacts = dict(predecessor)
                    artifacts[artifact_name] = json.loads(
                        json.dumps(predecessor[artifact_name])
                    )
                    artifacts[artifact_name][field] = changed
                    errors = LIVE.validate_full_auto_authorization_contract(
                        authorization,
                        predecessor_authorization=artifacts["authorization"],
                        predecessor_authorization_raw_sha256=artifacts[
                            "authorization_raw_sha256"
                        ],
                        predecessor_manifest=artifacts["manifest"],
                        predecessor_manifest_raw_sha256=artifacts[
                            "manifest_raw_sha256"
                        ],
                        predecessor_authorization_state=artifacts["state"],
                        predecessor_authorization_state_raw_sha256=artifacts[
                            "state_raw_sha256"
                        ],
                        predecessor_failure_evidence=artifacts["failure"],
                        predecessor_failure_evidence_raw_sha256=artifacts[
                            "failure_raw_sha256"
                        ],
                        predecessor_original_containment=artifacts["original_containment"],
                        predecessor_original_containment_raw_sha256=artifacts["original_containment_raw_sha256"],
                        predecessor_allocation_ledger=artifacts["ledger"],
                        predecessor_allocation_ledger_raw_sha256=artifacts["ledger_raw_sha256"],
                        predecessor_allocation_audit_path=artifacts["audit_path"],
                        predecessor_allocation_audit_raw_sha256=artifacts["audit_raw_sha256"],
                        predecessor_containment=artifacts["containment"],
                        predecessor_containment_raw_sha256=artifacts[
                            "containment_raw_sha256"
                        ],
                        cause_evidence=artifacts["cause_evidence"],
                    )
                    self.assertTrue(any(expected in item for item in errors), errors)
            self.assertIn(
                "authorization-progress-cause-evidence-binding-invalid",
                LIVE.validate_full_auto_authorization_contract(
                    authorization,
                    predecessor_authorization=predecessor["authorization"],
                    predecessor_authorization_raw_sha256=predecessor[
                        "authorization_raw_sha256"
                    ],
                    predecessor_manifest=predecessor["manifest"],
                    predecessor_manifest_raw_sha256=predecessor[
                        "manifest_raw_sha256"
                    ],
                    predecessor_authorization_state=predecessor["state"],
                    predecessor_authorization_state_raw_sha256=predecessor[
                        "state_raw_sha256"
                    ],
                    predecessor_failure_evidence=predecessor["failure"],
                    predecessor_failure_evidence_raw_sha256=predecessor[
                        "failure_raw_sha256"
                    ],
                    predecessor_original_containment=predecessor["original_containment"],
                    predecessor_original_containment_raw_sha256=predecessor["original_containment_raw_sha256"],
                    predecessor_allocation_ledger=predecessor["ledger"],
                    predecessor_allocation_ledger_raw_sha256=predecessor["ledger_raw_sha256"],
                    predecessor_allocation_audit_path=predecessor["audit_path"],
                    predecessor_allocation_audit_raw_sha256=predecessor["audit_raw_sha256"],
                    predecessor_containment=predecessor["containment"],
                    predecessor_containment_raw_sha256=predecessor[
                        "containment_raw_sha256"
                    ],
                    cause_evidence=b"unbound-cause",
                ),
            )
            self.assertIn(
                "authorization-predecessor-historical-binding-invalid",
                LIVE.validate_full_auto_authorization_contract(
                    authorization,
                    predecessor_authorization=predecessor["authorization"],
                    predecessor_authorization_raw_sha256="0" * 64,
                    predecessor_manifest=predecessor["manifest"],
                    predecessor_manifest_raw_sha256=predecessor[
                        "manifest_raw_sha256"
                    ],
                    predecessor_authorization_state=predecessor["state"],
                    predecessor_authorization_state_raw_sha256=predecessor[
                        "state_raw_sha256"
                    ],
                    predecessor_failure_evidence=predecessor["failure"],
                    predecessor_failure_evidence_raw_sha256=predecessor[
                        "failure_raw_sha256"
                    ],
                    predecessor_original_containment=predecessor["original_containment"],
                    predecessor_original_containment_raw_sha256=predecessor["original_containment_raw_sha256"],
                    predecessor_allocation_ledger=predecessor["ledger"],
                    predecessor_allocation_ledger_raw_sha256=predecessor["ledger_raw_sha256"],
                    predecessor_allocation_audit_path=predecessor["audit_path"],
                    predecessor_allocation_audit_raw_sha256=predecessor["audit_raw_sha256"],
                    predecessor_containment=predecessor["containment"],
                    predecessor_containment_raw_sha256=predecessor[
                        "containment_raw_sha256"
                    ],
                    cause_evidence=predecessor["cause_evidence"],
                ),
            )

    def test_predecessor_proof_graph_rejects_structural_ledger_and_correction_tamper(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            head, _orphan = self.make_repo(root)
            authorization = self.authorization(root, head)
            predecessor = self.predecessor_artifacts(
                root,
                authorization["bindings"]["predecessor_authorization_id"],
                authorization["progress_gate"]["predecessor_candidate_commit"],
                authorization["progress_gate"]["predecessor_candidate_tree"],
            )
            base_kwargs = self.predecessor_contract_kwargs(predecessor)
            self.assertEqual(
                LIVE.validate_full_auto_authorization_contract(
                    authorization, repo_root=root, **base_kwargs
                ),
                [],
            )

            cases = []
            historical_authorization = json.loads(
                json.dumps(predecessor["authorization"])
            )
            historical_authorization["unexpected"] = True
            cases.append(
                (
                    {"predecessor_authorization": historical_authorization},
                    "historical-authorization-fields-invalid",
                )
            )
            historical_manifest = json.loads(json.dumps(predecessor["manifest"]))
            historical_manifest["unexpected"] = True
            cases.append(
                (
                    {"predecessor_manifest": historical_manifest},
                    "historical-manifest-fields-invalid",
                )
            )
            ledger = json.loads(json.dumps(predecessor["ledger"]))
            ledger["entries"][0]["outcome"] = "bound"
            cases.append(
                (
                    {"predecessor_allocation_ledger": ledger},
                    "allocation-ledger",
                )
            )
            failure = json.loads(json.dumps(predecessor["failure"]))
            failure["allocation_ledger"]["allocation_intent_count"] = 2
            cases.append(
                (
                    {"predecessor_failure_evidence": failure},
                    "failure-binding",
                )
            )
            original = json.loads(json.dumps(predecessor["original_containment"]))
            original["failed_authorization_id"] = "different-malformed-id"
            cases.append(
                (
                    {"predecessor_original_containment": original},
                    "original-containment-binding",
                )
            )
            correction = json.loads(json.dumps(predecessor["containment"]))
            correction["correction"]["evidence_or_disposition_changed"] = True
            cases.append(
                (
                    {"predecessor_containment": correction},
                    "containment-correction-binding",
                )
            )
            for overrides, expected in cases:
                with self.subTest(expected=expected):
                    kwargs = {**base_kwargs, **overrides}
                    errors = LIVE.validate_full_auto_authorization_contract(
                        authorization, **kwargs
                    )
                    self.assertTrue(any(expected in item for item in errors), errors)

            tampered_audit = predecessor["audit_path"].with_name(
                "tampered-audit.jsonl"
            )
            tampered_audit.write_bytes(
                predecessor["audit_path"].read_bytes() + b"{}\n"
            )
            tampered_audit.chmod(0o600)
            audit_kwargs = {
                **base_kwargs,
                "predecessor_allocation_audit_path": tampered_audit,
                "predecessor_allocation_audit_raw_sha256": LIVE.sha256_bytes(
                    tampered_audit.read_bytes()
                ),
            }
            audit_errors = LIVE.validate_full_auto_authorization_contract(
                authorization, **audit_kwargs
            )
            self.assertTrue(
                any("allocation-audit" in item or "allocation-ledger" in item for item in audit_errors),
                audit_errors,
            )

    def test_release_patch_is_bound_to_candidate_and_prospective_tree(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            head, _orphan = self.make_repo(root)
            authorization = self.authorization(root, head)
            candidate_tree = LIVE.run_git(root, "rev-parse", "HEAD^{tree}")
            manifest = self.manifest(authorization, head, candidate_tree)
            (root / "baseline.txt").write_text("released\n", encoding="utf-8")
            patch_bytes = subprocess.run(
                ["git", "diff", "--binary"],
                cwd=root,
                check=True,
                capture_output=True,
            ).stdout
            patch_path = root / "release.patch"
            patch_path.write_bytes(patch_bytes)
            subprocess.run(["git", "add", "baseline.txt"], cwd=root, check=True)
            prospective_tree = LIVE.run_git(root, "write-tree")
            subprocess.run(
                ["git", "restore", "--staged", "--worktree", "baseline.txt"],
                cwd=root,
                check=True,
            )
            manifest["release"]["patch_file_sha256"] = LIVE.sha256_bytes(patch_bytes)
            manifest["release"]["prospective_tree"] = prospective_tree
            self.reseal_manifest(manifest)
            self.assertEqual(
                LIVE.validate_release_patch_result(root, patch_path, manifest),
                [],
            )
            patch_path.write_bytes(patch_bytes + b"\n")
            self.assertEqual(
                LIVE.validate_release_patch_result(root, patch_path, manifest),
                ["release-patch-file-sha256-mismatch"],
            )

    def test_full_auto_authorization_rejects_descendant_after_inner_mint(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            checkpoint, _orphan = self.make_repo(root)
            (root / "correction.txt").write_text("correction", encoding="utf-8")
            subprocess.run(["git", "add", "correction.txt"], cwd=root, check=True)
            subprocess.run(["git", "commit", "-qm", "correction"], cwd=root, check=True)
            authorization = self.authorization(root, checkpoint)
            with self.assertRaisesRegex(
                LIVE.AppServerError, "checkpoint-not-head"
            ):
                LIVE.validate_full_auto_authorization(
                    authorization,
                    authorization["bindings"]["campaign_nonce"],
                    repo_root=root,
                )

    def test_full_auto_authorization_rejects_hash_tamper_and_dirty_repository(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            head, _orphan = self.make_repo(root)
            authorization = self.authorization(root, head)
            authorization["initial_state"] = "parked"
            with self.assertRaisesRegex(LIVE.AppServerError, "canonical-sha256"):
                LIVE.validate_full_auto_authorization(
                    authorization,
                    authorization["bindings"]["campaign_nonce"],
                    repo_root=root,
                )
            authorization = self.authorization(root, head)
            (root / "baseline.txt").write_text("dirty", encoding="utf-8")
            with self.assertRaisesRegex(LIVE.AppServerError, "repository-not-clean"):
                LIVE.validate_full_auto_authorization(
                    authorization,
                    authorization["bindings"]["campaign_nonce"],
                    repo_root=root,
                )

    def test_full_auto_authorization_checkpoint_must_be_head(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            head, _orphan = self.make_repo(root)
            authorization = self.authorization(
                root, LIVE.run_git(root, "rev-parse", f"{head}^")
            )
            with self.assertRaisesRegex(
                LIVE.AppServerError, "checkpoint-not-head"
            ):
                LIVE.validate_full_auto_authorization(
                    authorization,
                    authorization["bindings"]["campaign_nonce"],
                    repo_root=root,
                )

    def test_full_auto_authorization_rejects_weakened_live_bindings(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            head, _orphan = self.make_repo(root)
            base = self.authorization(root, head)
            cases = (
                (("resource_limits", "spark_live_turn_starts_exact"), 6, "resource-limit"),
                (("executors", "operative", "model"), "other", "executor"),
                (("mandatory_gates", "fresh_exact_sol_pre_live_receipt"), False, "gate"),
                (("forbidden", "model_synthesis"), False, "forbidden"),
                (("progress_gate", "one_active_inner_campaign"), False, "progress"),
                (("progress_gate", "arbitrary_generation_cap"), True, "progress"),
                (
                    ("progress_gate", "cause_evidence_sha256"),
                    base["progress_gate"][
                        "predecessor_failure_evidence_canonical_sha256"
                    ],
                    "new-evidence",
                ),
            )
            for path, value, expected in cases:
                with self.subTest(path=path):
                    authorization = json.loads(json.dumps(base))
                    target = authorization
                    for field in path[:-1]:
                        target = target[field]
                    target[path[-1]] = value
                    self.reseal_authorization(authorization)
                    with self.assertRaisesRegex(LIVE.AppServerError, expected):
                        LIVE.validate_full_auto_authorization(
                            authorization,
                            authorization["bindings"]["campaign_nonce"],
                            repo_root=root,
                        )
            reused = json.loads(json.dumps(base))
            reused["bindings"]["predecessor_authorization_id"] = reused[
                "authorization_id"
            ]
            reused["supersession"]["prior_authorization_id"] = reused[
                "authorization_id"
            ]
            self.reseal_authorization(reused)
            with self.assertRaisesRegex(LIVE.AppServerError, "identity-reuse"):
                LIVE.validate_full_auto_authorization(
                    reused,
                    reused["bindings"]["campaign_nonce"],
                    repo_root=root,
                )

    def test_steering_plan_checks_both_bindings_before_validation(self) -> None:
        campaign_nonce = str(uuid.uuid4())
        auth_id = str(uuid.uuid4())
        pre_mutation = self.receipt("pre-mutation", auth_id)
        pre_live = self.receipt("pre-live", "wrong-authorization")
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(
            LIVE, "consume_steering_receipt"
        ) as consume:
            with self.assertRaisesRegex(LIVE.AppServerError, "pre-live-steering-binding"):
                LIVE.plan_steering_receipt_consumptions(
                    campaign_nonce,
                    auth_id,
                    "a" * 64,
                    registry_file=Path(temporary) / "registry.json",
                    repo_head="d" * 40,
                    pre_mutation_receipt=pre_mutation,
                    pre_mutation_adjudication={"main_architect_decision": "go"},
                    pre_mutation_adjudication_sha256="d" * 64,
                    pre_live_receipt=pre_live,
                    pre_live_adjudication={"main_architect_decision": "go"},
                    pre_live_adjudication_sha256="e" * 64,
                )
            consume.assert_not_called()

    def test_steering_plan_dry_validates_both_before_consumption(self) -> None:
        auth_id = str(uuid.uuid4())
        receipts = (
            self.receipt("pre-mutation", auth_id),
            self.receipt("pre-live", auth_id),
        )
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(
            LIVE,
            "consume_steering_receipt",
            side_effect=("pre-ok", LIVE.NativeCanaryContractError("pre-live-invalid")),
        ) as consume:
            registry = Path(temporary) / "registry.json"
            with self.assertRaisesRegex(LIVE.AppServerError, "pre-live-steering-not-accepting"):
                LIVE.plan_steering_receipt_consumptions(
                    str(uuid.uuid4()),
                    auth_id,
                    "a" * 64,
                    registry_file=registry,
                    repo_head="d" * 40,
                    pre_mutation_receipt=receipts[0],
                    pre_mutation_adjudication={"main_architect_decision": "go"},
                    pre_mutation_adjudication_sha256="d" * 64,
                    pre_live_receipt=receipts[1],
                    pre_live_adjudication={"main_architect_decision": "go"},
                    pre_live_adjudication_sha256="e" * 64,
                )
            self.assertEqual(consume.call_count, 2)
            self.assertTrue(all(call.kwargs["dry_run"] for call in consume.call_args_list))
            self.assertFalse(registry.exists())

    def test_steering_plan_scopes_resolved_stop_to_pre_mutation(self) -> None:
        auth_id = str(uuid.uuid4())
        pre_mutation = self.receipt("pre-mutation", auth_id, "stop")
        pre_live = self.receipt("pre-live", auth_id)
        resolution = {"schema": "cwo-resolved-stop-adjudication:v1"}
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(
            LIVE, "consume_steering_receipt", return_value="validated"
        ) as consume:
            prepared = LIVE.plan_steering_receipt_consumptions(
                str(uuid.uuid4()),
                auth_id,
                "a" * 64,
                registry_file=Path(temporary) / "registry.json",
                repo_head="d" * 40,
                pre_mutation_receipt=pre_mutation,
                pre_mutation_adjudication={
                    "main_architect_decision": "go",
                    "resolved_stop": resolution,
                },
                pre_mutation_adjudication_sha256="d" * 64,
                pre_live_receipt=pre_live,
                pre_live_adjudication={"main_architect_decision": "go"},
                pre_live_adjudication_sha256="e" * 64,
            )
            self.assertTrue(prepared["pre-mutation"][1]["allow_resolved_stop"])
            self.assertIs(prepared["pre-mutation"][1]["resolved_stop_adjudication"], resolution)
            self.assertNotIn("allow_resolved_stop", prepared["pre-live"][1])
            self.assertTrue(all(call.kwargs["dry_run"] for call in consume.call_args_list))


if __name__ == "__main__":
    unittest.main()
