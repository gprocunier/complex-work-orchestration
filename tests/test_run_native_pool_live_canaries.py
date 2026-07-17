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
                        "payload": {"type": "turn_aborted", "turn_id": self.turn_id},
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
            self.assertEqual(materialization["version"], 3)
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

    def test_early_completion_and_failed_or_declined_command_are_nonaccepting(self) -> None:
        for early, command, expected in (
            ("completed", "inProgress", "completed-before-deliberate-interrupt"),
            (None, "failed", "command-terminal-before-interrupt"),
            (None, "declined", "command-terminal-before-interrupt"),
        ):
            with self.subTest(early=early, command=command), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                record_dir = root / "records"
                record_dir.mkdir()
                server = FakeCalibrationServer(root, early_status=early, command_status=command)
                with self.assertRaisesRegex(LIVE.AppServerError, expected):
                    LIVE.calibration(
                        server,
                        root,
                        record_dir,
                        self.owner(),
                        run_nonce=str(uuid.uuid4()),
                        phase_nonce=str(uuid.uuid4()),
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

    def test_terminal_transition_interrupt_close_and_final_summary_are_strict(self) -> None:
        for statuses in (["completed"], ["inProgress", "completed"]):
            with self.subTest(statuses=statuses), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                clock = FakeMonotonicClock()
                server = FakeLiveThreadServer(root, read_statuses=statuses)
                adapter = self.adapter(root, server, clock)
                adapter.send_input(message="bounded prompt")
                with self.assertRaisesRegex(LIVE.AppServerError, "status-invalid:completed"):
                    adapter._trusted_summary()

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
        head = LIVE.run_git(root, "rev-parse", "HEAD")
        subprocess.run(["git", "checkout", "-q", "--orphan", "orphan"], cwd=root, check=True)
        (root / "orphan.txt").write_text("orphan", encoding="utf-8")
        subprocess.run(["git", "add", "orphan.txt"], cwd=root, check=True)
        subprocess.run(["git", "commit", "-qm", "orphan"], cwd=root, check=True)
        orphan = LIVE.run_git(root, "rev-parse", "HEAD")
        subprocess.run(["git", "checkout", "-q", "master"], cwd=root, check=True)
        return head, orphan

    def authorization(self, checkpoint: str) -> dict:
        value = {
            "schema": "cwo-full-auto-run-authorization:v3",
            "run_generation": 5,
            "initial_state": "active",
            "authorization_id": str(uuid.uuid4()),
            "forbidden": {
                "glm_5_2": True,
                "model_synthesis": True,
                "release_before_live_acceptance": True,
            },
            "bindings": {
                "campaign_nonce": str(uuid.uuid4()),
                "checkpoint_commit": checkpoint,
            },
            "budgets": {
                "spark_live_turn_starts_per_generation_exact": 7,
                "spark_live_campaign_generations_hard": 3,
            },
            "executors": {
                "steering": {"model": "gpt-5.6-sol", "effort": "max"},
                "operative": {"model": "gpt-5.3-codex-spark"},
            },
            "mandatory_gates": {
                "fresh_exact_sol_pre_mutation_receipt": True,
                "fresh_exact_sol_pre_live_receipt": True,
                "single_shot_per_generation_live_campaign": True,
            },
        }
        value["canonical_authorization_sha256"] = LIVE.sha256_bytes(
            json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
        )
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
        value.pop("canonical_authorization_sha256", None)
        value["canonical_authorization_sha256"] = LIVE.sha256_bytes(
            json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
        )

    def test_full_auto_authorization_v3_acceptance_and_v2_rejection(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            head, _orphan = self.make_repo(root)
            authorization = self.authorization(head)
            self.assertEqual(
                LIVE.validate_full_auto_authorization(
                    authorization,
                    authorization["bindings"]["campaign_nonce"],
                    repo_root=root,
                )[0],
                authorization["authorization_id"],
            )
            for schema in ("cwo-full-auto-run-authorization:v2", "unknown"):
                with self.subTest(schema=schema):
                    invalid = json.loads(json.dumps(authorization))
                    invalid["schema"] = schema
                    with self.assertRaisesRegex(LIVE.AppServerError, "schema"):
                        LIVE.validate_full_auto_authorization(
                            invalid,
                            invalid["bindings"]["campaign_nonce"],
                            repo_root=root,
                        )

    def test_full_auto_authorization_allows_descendant_correction_commit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            checkpoint, _orphan = self.make_repo(root)
            (root / "correction.txt").write_text("correction", encoding="utf-8")
            subprocess.run(["git", "add", "correction.txt"], cwd=root, check=True)
            subprocess.run(["git", "commit", "-qm", "correction"], cwd=root, check=True)
            authorization = self.authorization(checkpoint)
            _authorization_id, current_head = LIVE.validate_full_auto_authorization(
                authorization,
                authorization["bindings"]["campaign_nonce"],
                repo_root=root,
            )
            self.assertNotEqual(checkpoint, current_head)

    def test_full_auto_authorization_rejects_hash_tamper_and_dirty_repository(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            head, _orphan = self.make_repo(root)
            authorization = self.authorization(head)
            authorization["initial_state"] = "parked"
            with self.assertRaisesRegex(LIVE.AppServerError, "canonical-hash"):
                LIVE.validate_full_auto_authorization(
                    authorization,
                    authorization["bindings"]["campaign_nonce"],
                    repo_root=root,
                )
            authorization = self.authorization(head)
            (root / "baseline.txt").write_text("dirty", encoding="utf-8")
            with self.assertRaisesRegex(LIVE.AppServerError, "repository-not-clean"):
                LIVE.validate_full_auto_authorization(
                    authorization,
                    authorization["bindings"]["campaign_nonce"],
                    repo_root=root,
                )

    def test_full_auto_authorization_checkpoint_must_be_ancestor(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _head, orphan = self.make_repo(root)
            authorization = self.authorization(orphan)
            with self.assertRaisesRegex(
                LIVE.AppServerError, "full-auto-checkpoint-not-ancestor"
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
            base = self.authorization(head)
            cases = (
                (("budgets", "spark_live_turn_starts_per_generation_exact"), 6, "budget"),
                (("executors", "operative", "model"), "other", "executor"),
                (("mandatory_gates", "fresh_exact_sol_pre_live_receipt"), False, "gates"),
                (("forbidden", "model_synthesis"), False, "forbidden"),
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
