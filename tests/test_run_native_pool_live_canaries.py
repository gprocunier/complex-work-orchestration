from __future__ import annotations

import datetime as dt
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
        predecessor_authorization_id: str,
        candidate_commit: str,
        candidate_tree: str,
    ) -> dict[str, object]:
        def seal(value: dict, field: str) -> dict:
            value[field] = LIVE.sha256_bytes(
                json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
            )
            return value

        campaign_nonce = str(
            uuid.uuid5(uuid.UUID(predecessor_authorization_id), "campaign")
        )
        predecessor_authorization = {
            "authorization_type": "cwo-full-auto-run-authorization",
            "version": 4,
            "schema": "schemas/full-auto-run-authorization.schema.json",
            "authorization_id": predecessor_authorization_id,
            "live_generation": 5,
            "predecessor_live_generation": 4,
            "bindings": {"campaign_nonce": campaign_nonce},
        }
        seal(predecessor_authorization, "canonical_authorization_sha256")
        predecessor_authorization_bytes = json.dumps(
            predecessor_authorization, sort_keys=True, separators=(",", ":")
        ).encode()
        predecessor_authorization_raw_sha256 = LIVE.sha256_bytes(
            predecessor_authorization_bytes
        )
        predecessor_manifest = {
            "manifest_type": "cwo-native-live-campaign-manifest",
            "version": 1,
            "schema": "schemas/native-live-campaign-manifest.schema.json",
            "authorization_id": predecessor_authorization_id,
            "authorization_raw_sha256": predecessor_authorization_raw_sha256,
            "authorization_canonical_sha256": predecessor_authorization[
                "canonical_authorization_sha256"
            ],
            "live_generation": 5,
            "predecessor_live_generation": 4,
            "candidate": {
                "commit": candidate_commit,
                "tree": candidate_tree,
            },
        }
        seal(predecessor_manifest, "manifest_sha256")
        predecessor_manifest_raw_sha256 = LIVE.sha256_bytes(
            json.dumps(
                predecessor_manifest,
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
        )
        predecessor_state = seal(
            {
                "authorization_type": "cwo-native-canary-authorization-state:v1",
                "version": 1,
                "schema": "schemas/native-canary-authorization-state.schema.json",
                "authorization_id": predecessor_authorization_id,
                "run_nonce": campaign_nonce,
                "state": "containment-only",
                "allowed_actions": [],
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
            },
            "state_sha256",
        )
        predecessor_state_raw_sha256 = LIVE.sha256_bytes(
            json.dumps(
                predecessor_state, sort_keys=True, separators=(",", ":")
            ).encode()
        )
        predecessor_failure = seal(
            {
                "authorization_state_sha256": predecessor_state["state_sha256"],
                "release_gate_passed": False,
                "validation_outcome": "rejected",
                "campaign_bindings": {
                    "authorization_raw_sha256": predecessor_authorization_raw_sha256,
                    "manifest_file_sha256": predecessor_manifest_raw_sha256,
                    "manifest_sha256": predecessor_manifest["manifest_sha256"],
                    "candidate_commit": candidate_commit,
                    "candidate_tree": candidate_tree,
                },
                "containment": {
                    "all_contained": True,
                    "ambiguous_count": 0,
                    "ledger_consistent": True,
                    "unresolved_allocation_intent_count": 0,
                    "unresolved_turn_intent_count": 0,
                },
            },
            "evidence_sha256",
        )
        predecessor_failure_raw_sha256 = LIVE.sha256_bytes(
            json.dumps(
                predecessor_failure, sort_keys=True, separators=(",", ":")
            ).encode()
        )
        predecessor_containment = seal(
            {
                "failed_authorization_id": predecessor_authorization_id,
                "failed_campaign_nonce": campaign_nonce,
                "failed_evidence": {
                    "file_sha256": predecessor_failure_raw_sha256,
                    "canonical_sha256": predecessor_failure["evidence_sha256"],
                    "authorization_state_file_sha256": predecessor_state_raw_sha256,
                    "authorization_state_canonical_sha256": predecessor_state[
                        "state_sha256"
                    ],
                },
                "reclassification": {
                    "ambiguous_count": 0,
                    "all_contained": True,
                    "release_gate_passed": False,
                    "failed_authorization_terminal": True,
                    "reuse_resume_retry_substitution_salvage_bridge": False,
                },
                "control_plane_recheck": {
                    "isolated_checkout_tracked_clean": True,
                    "release_policy_status": "canary-gated",
                    "operative_dispatch_authorized": False,
                },
            },
            "canonical_recovery_sha256",
        )
        predecessor_containment_raw_sha256 = LIVE.sha256_bytes(
            json.dumps(
                predecessor_containment, sort_keys=True, separators=(",", ":")
            ).encode()
        )
        cause_evidence = (
            f"exact-turn-status-corroboration:{candidate_commit}:{candidate_tree}"
        ).encode()
        return {
            "authorization": predecessor_authorization,
            "authorization_raw_sha256": predecessor_authorization_raw_sha256,
            "manifest": predecessor_manifest,
            "manifest_raw_sha256": predecessor_manifest_raw_sha256,
            "state": predecessor_state,
            "state_raw_sha256": predecessor_state_raw_sha256,
            "failure": predecessor_failure,
            "failure_raw_sha256": predecessor_failure_raw_sha256,
            "containment": predecessor_containment,
            "containment_raw_sha256": predecessor_containment_raw_sha256,
            "cause_evidence": cause_evidence,
        }

    def authorization(self, root: Path, checkpoint: str) -> dict:
        predecessor_authorization_id = str(uuid.uuid4())
        predecessor_candidate_commit = LIVE.run_git(root, "rev-parse", f"{checkpoint}^")
        predecessor_candidate_tree = LIVE.run_git(
            root, "rev-parse", f"{checkpoint}^^{{tree}}"
        )
        predecessor = self.predecessor_artifacts(
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
            "containment_canonical_sha256": predecessor["containment"][
                "canonical_recovery_sha256"
            ],
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
                        "containment_canonical_sha256": bindings.get(
                            "predecessor_containment_canonical_sha256"
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
                    "type": "response_item",
                    "payload": {
                        "type": "message",
                        "role": "assistant",
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
        archive.mkdir(parents=True)
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

    def test_independent_validation_session_binds_archived_jsonl(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            receipt, path = self.validation_session(root)
            with mock.patch.dict("os.environ", {"CODEX_HOME": str(root)}):
                self.assertEqual(
                    LIVE.validate_independent_validation_session(receipt, path),
                    receipt["boundary"]["terminal"]["boundary_sha256"],
                )
                path.write_text(
                    path.read_text(encoding="utf-8") + "{}\n", encoding="utf-8"
                )
                with self.assertRaisesRegex(
                    LIVE.AppServerError, "boundary-mismatch"
                ):
                    LIVE.validate_independent_validation_session(receipt, path)

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
                    predecessor_containment=predecessor["containment"],
                    predecessor_containment_raw_sha256=predecessor[
                        "containment_raw_sha256"
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
                "campaign-manifest-authorization:authorization-predecessor-manifest-binding-invalid",
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
                "authorization-predecessor-authorization-binding-invalid",
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
                    "containment-binding",
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
                    predecessor_containment=predecessor["containment"],
                    predecessor_containment_raw_sha256=predecessor[
                        "containment_raw_sha256"
                    ],
                    cause_evidence=b"unbound-cause",
                ),
            )
            self.assertIn(
                "authorization-predecessor-authorization-binding-invalid",
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
                    predecessor_containment=predecessor["containment"],
                    predecessor_containment_raw_sha256=predecessor[
                        "containment_raw_sha256"
                    ],
                    cause_evidence=predecessor["cause_evidence"],
                ),
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
