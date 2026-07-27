from __future__ import annotations

from dataclasses import replace
import importlib.util
import io
import inspect
import json
from pathlib import Path
import queue
import shutil
import subprocess
import sys
import tempfile
import threading
from typing import Any, Callable, Mapping
import unittest
from unittest import mock
import uuid


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from cwo_core import native_live_campaign_contracts as CAMPAIGN_CONTRACTS  # noqa: E402
from cwo_core.native_tool_isolation import (  # noqa: E402
    seal_tool_enforcement_override,
)

SPEC = importlib.util.spec_from_file_location(
    "run_native_pool_live_canaries", ROOT / "scripts" / "run_native_pool_live_canaries.py"
)
assert SPEC and SPEC.loader
LIVE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(LIVE)


CANONICAL_UUID_TEXT = "123e4567-e89b-12d3-a456-426614174000"
UUID_TEXT_ALIASES = (
    CANONICAL_UUID_TEXT.upper(),
    "{" + CANONICAL_UUID_TEXT + "}",
    uuid.UUID(CANONICAL_UUID_TEXT).hex,
    "urn:uuid:" + CANONICAL_UUID_TEXT,
    " " + CANONICAL_UUID_TEXT,
    CANONICAL_UUID_TEXT + " ",
    CANONICAL_UUID_TEXT + "\n",
)
PARSEABLE_UUID_ALIASES = UUID_TEXT_ALIASES[:4]


def temporary_tool_override_fixture() -> tuple[dict[str, object], dict[str, object]]:
    manifest: dict[str, object] = {
        "authorization_id": str(uuid.uuid4()),
        "authorization_canonical_sha256": "a" * 64,
        "outer_authority": {
            "authority_id": str(uuid.uuid4()),
            "file_sha256": "b" * 64,
            "canonical_sha256": "c" * 64,
        },
        "campaign_nonce": str(uuid.uuid4()),
        "candidate": {
            "commit": "d" * 40,
            "tree": "e" * 40,
        },
        "control_turn_id": LIVE.CONTROL_TURN_ID,
    }
    outer = manifest["outer_authority"]
    candidate = manifest["candidate"]
    assert isinstance(outer, dict)
    assert isinstance(candidate, dict)
    override = seal_tool_enforcement_override(
        {
            "override_type": "cwo-native-tool-enforcement-override",
            "version": 1,
            "schema": "schemas/native-tool-enforcement-override.schema.json",
            "authorization_id": manifest["authorization_id"],
            "authorization_canonical_sha256": manifest[
                "authorization_canonical_sha256"
            ],
            "outer_authority_id": outer["authority_id"],
            "outer_authority_file_sha256": outer["file_sha256"],
            "outer_authority_canonical_sha256": outer["canonical_sha256"],
            "campaign_nonce": manifest["campaign_nonce"],
            "candidate_commit": candidate["commit"],
            "candidate_tree": candidate["tree"],
            "max_workers": 2,
            "max_mutating_workers": 1,
            "single_use": True,
            "risk_acknowledgement": (
                "unlisted-built-ins-may-act-before-detection"
            ),
        }
    )
    return manifest, override


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
        read_faults: Mapping[int, tuple[str, int, float]] | None = None,
        read_delays: Mapping[int, float] | None = None,
        materialize_before_fault_read: int | None = None,
        materialize_before_read: int | None = None,
        empty_initial_session: bool = False,
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
        self.thread_start_count = 0
        self.turn_start_count = 0
        self.read_faults = dict(read_faults or {})
        self.read_delays = dict(read_delays or {})
        self.materialize_before_fault_read = materialize_before_fault_read
        self.materialize_before_read = materialize_before_read
        self.empty_initial_session = empty_initial_session
        self.read_started: list[float] = []
        self.read_timeouts: list[float] = []
        self.guarded_read_count = 0
        self.guarded_read_snapshots: list[dict] = []
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
        self.terminal_containment_calls: list[dict[str, str]] = []

    def _write(self, records: list[dict]) -> None:
        self.path.write_text("".join(json.dumps(item) + "\n" for item in records), encoding="utf-8")
        self.path.chmod(0o600)

    def start_thread(
        self, _cwd: Path, *, mutable: bool, role: str | None = None
    ) -> tuple[dict, float]:
        self.assert_false(mutable)
        self.thread_start_count += 1
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
        self.turn_start_count += 1
        if self.empty_initial_session:
            self.path.touch(mode=0o600)
            self.path.chmod(0o600)
        else:
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
        if self.path.exists() and self.path.stat().st_size == 0:
            self._write(
                [
                    {"type": "session_meta", "payload": {"id": self.thread_id}},
                    {"type": "event_msg", "payload": {"type": "task_started", "turn_id": self.turn_id}},
                    {"type": "response_item", "payload": {"type": "message", "role": "user"}},
                ]
            )
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

    def read_thread(
        self,
        thread_id: str,
        *,
        timeout: float = LIVE.THREAD_READ_TIMEOUT_SECONDS,
    ) -> tuple[dict, float]:
        if thread_id != self.thread_id:
            raise AssertionError("thread mismatch")
        self.read_count += 1
        self.read_started.append(LIVE.time.monotonic())
        self.read_timeouts.append(timeout)
        delay = self.read_delays.get(self.read_count, 0.0)
        if delay:
            LIVE.time.sleep(delay)
        if self.materialize_before_read == self.read_count:
            self._materialize()
        fault = self.read_faults.get(self.read_count)
        if fault is not None:
            if self.materialize_before_fault_read == self.read_count:
                self._materialize()
            method, code, latency_ms = fault
            raise LIVE.AppServerRpcError(
                method=method,
                code=code,
                request_id=self.read_count,
                latency_ms=latency_ms,
            )
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

    def read_thread_once_with_guard(
        self,
        thread_id: str,
        *,
        timeout: float,
        pre_dispatch_guard,
    ) -> tuple[dict, float, dict, int, str]:
        """Model the production client's single guarded application request."""

        guarded = dict(pre_dispatch_guard())
        self.guarded_read_count += 1
        self.guarded_read_snapshots.append(guarded)
        thread, latency = self.read_thread(thread_id, timeout=timeout)
        request_id = self.read_count
        request_sha256 = LIVE.domain_sha256(
            {
                "id": request_id,
                "method": "thread/read",
                "params": {"threadId": thread_id, "includeTurns": True},
            },
            domain="app-server-single-wire-request",
        )
        return thread, latency, guarded, request_id, request_sha256

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

    def record_terminal_archive_containment(
        self,
        thread_id: str,
        turn_id: str,
        *,
        terminal_evidence_sha256: str,
    ) -> dict[str, str]:
        if (
            (thread_id, turn_id) != (self.thread_id, self.turn_id)
            or not self.interrupted
            or self.path.parent != self.archive
        ):
            raise AssertionError("terminal containment recorded too early")
        call = {
            "thread_id": thread_id,
            "turn_id": turn_id,
            "terminal_evidence_sha256": terminal_evidence_sha256,
        }
        self.terminal_containment_calls.append(call)
        return call

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


def deterministic_calibration_measurement(
    action: Callable[[], Any],
    *,
    guard_seconds: float = 0.0,
) -> tuple[Any, float]:
    if guard_seconds != 0.0:
        raise AssertionError("functional calibration fixture requires disabled guard")
    return action(), 50.0


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
        self.items: list[dict] = []
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
            "turns": [
                {
                    "id": self.turn_id,
                    "status": self.status,
                    "items": list(self.items),
                }
            ],
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


class AppServerRpcErrorTests(unittest.TestCase):
    def request_server(self, response: dict) -> LIVE.AppServer:
        server = object.__new__(LIVE.AppServer)
        server.process = mock.Mock()
        server.process.stdin = io.StringIO()
        server.process.poll.return_value = None
        server.process.returncode = None
        server._condition = threading.Condition()
        server._responses = {1: response}
        server._request_id = 0
        server._reader_error = None
        server.connection_epoch_sha256 = "a" * 64
        server.rpc_latencies = {}
        server.started_threads = {}
        server._known_thread_turn_ids = {}
        server._turn_dispatch_records = {}
        server._fresh_never_turned_thread_proofs = {}
        server._archive_acceptance_proofs = {}
        server._same_process_containment_proofs = {}
        server.allocation_ledger = None
        return server

    def test_correlated_error_preserves_local_method_and_concrete_code(self) -> None:
        server = self.request_server(
            {
                "id": 1,
                "error": {
                    "code": -32603,
                    "message": "internal error",
                    "method": "attacker/supplied",
                },
            }
        )
        with self.assertRaises(LIVE.AppServerRpcError) as raised:
            server.request("thread/read", {"threadId": "thread-1"})
        self.assertEqual(raised.exception.method, "thread/read")
        self.assertEqual(raised.exception.code, -32603)
        self.assertEqual(raised.exception.request_id, 1)
        self.assertGreaterEqual(raised.exception.latency_ms, 0)
        self.assertEqual(len(server.rpc_latencies["thread/read"]), 1)

    def test_noninteger_code_and_unmatched_response_id_are_not_structured(self) -> None:
        for code in (True, "-32603"):
            with self.subTest(code=code):
                server = self.request_server(
                    {"id": 1, "error": {"code": code, "message": "invalid"}}
                )
                with self.assertRaises(LIVE.AppServerError) as raised:
                    server.request("thread/read", {"threadId": "thread-1"})
                self.assertNotIsInstance(raised.exception, LIVE.AppServerRpcError)
                self.assertIn("error-response-invalid", str(raised.exception))
        server = self.request_server(
            {"id": 2, "error": {"code": -32603, "message": "wrong id"}}
        )
        with self.assertRaisesRegex(LIVE.AppServerError, "response-id-invalid") as raised:
            server.request("thread/read", {"threadId": "thread-1"})
        self.assertNotIsInstance(raised.exception, LIVE.AppServerRpcError)

    def test_current_thread_start_rejects_unenforced_tool_allowlist_before_allocation(
        self,
    ) -> None:
        class RecordingLedger:
            def __init__(self) -> None:
                self.roles: list[str] = []

            def allocation_intent(self, role: str) -> str:
                self.roles.append(role)
                return "allocation-intent"

        thread_id = str(uuid.uuid4())
        server = self.request_server(
            {
                "id": 1,
                "result": {
                    "model": LIVE.EXACT_MODEL,
                    "thread": {"id": thread_id, "turns": []},
                },
            }
        )
        ledger = RecordingLedger()
        server.allocation_ledger = ledger
        server.started_threads = {}
        with self.assertRaisesRegex(
            LIVE.AppServerError, "tool-restriction-unsupported"
        ):
            server.start_thread(
                ROOT,
                mutable=False,
                role="capability-calibration",
                permitted_tools=["exec_command"],
                allowlist_parameter="tools",
            )
        self.assertEqual(ledger.roles, [])
        self.assertEqual(server.process.stdin.getvalue(), "")

    def test_synthetic_capability_backed_thread_start_forwards_exact_tool_allowlist(
        self,
    ) -> None:
        thread_id = str(uuid.uuid4())
        server = self.request_server(
            {
                "id": 1,
                "result": {
                    "model": LIVE.EXACT_MODEL,
                    "thread": {"id": thread_id, "turns": []},
                },
            }
        )
        server.allocation_ledger = None
        server.started_threads = {}
        server.tool_surface_capability = lambda *, permitted_tools: {
            "source": "supported-test-server",
            "server_allowlist_supported": True,
            "allowlist_parameter": "tools",
            "effective_allowlist": list(permitted_tools),
        }
        server.start_thread(
            ROOT,
            mutable=False,
            permitted_tools=["exec_command"],
            allowlist_parameter="tools",
        )
        wire = json.loads(server.process.stdin.getvalue().splitlines()[-1])
        self.assertEqual(wire["params"]["tools"], ["exec_command"])
        self.assertNotIn("dynamicTools", wire["params"])

    def test_fresh_thread_proof_requires_exact_empty_turns(self) -> None:
        cases = (
            ("empty", [], True),
            ("missing", None, False),
            ("nonempty", [{"id": "old-turn"}], False),
        )
        for name, turns, expected in cases:
            with self.subTest(name=name):
                thread_id = str(uuid.uuid4())
                thread = {"id": thread_id}
                if turns is not None:
                    thread["turns"] = turns
                server = self.request_server(
                    {
                        "id": 1,
                        "result": {
                            "model": LIVE.EXACT_MODEL,
                            "thread": thread,
                        },
                    }
                )
                server.start_thread(ROOT, mutable=False)
                proof = server.fresh_never_turned_thread_proof(
                    thread_id
                )
                self.assertEqual(proof is not None, expected)

    def test_start_turn_entry_revokes_fresh_thread_proof_before_local_failure(
        self,
    ) -> None:
        thread_id = str(uuid.uuid4())
        server = self.request_server(
            {
                "id": 1,
                "result": {
                    "model": LIVE.EXACT_MODEL,
                    "thread": {"id": thread_id, "turns": []},
                },
            }
        )
        server.start_thread(ROOT, mutable=False)
        self.assertIsNotNone(
            server.fresh_never_turned_thread_proof(thread_id)
        )
        server.process.poll.return_value = 17
        server.process.returncode = 17
        with self.assertRaisesRegex(
            LIVE.AppServerError,
            "app-server-exited-before-turn-intent",
        ):
            server.start_turn(thread_id, "bounded")
        self.assertIsNone(
            server.fresh_never_turned_thread_proof(thread_id)
        )

    def test_preview_containment_archives_proven_never_turned_without_read(
        self,
    ) -> None:
        thread_id = str(uuid.uuid4())
        server = self.request_server(
            {
                "id": 1,
                "result": {
                    "model": LIVE.EXACT_MODEL,
                    "thread": {"id": thread_id, "turns": []},
                },
            }
        )
        server.start_thread(ROOT, mutable=False)
        server._responses[2] = {"id": 2, "result": {}}
        server.read_thread = mock.Mock(
            side_effect=AssertionError("thread/read must not run")
        )
        result = LIVE.contain_started_threads(
            server,
            allow_same_process_proofs=True,
        )
        self.assertTrue(result["all_contained"])
        self.assertEqual(result["archived_count"], 1)
        server.read_thread.assert_not_called()
        proofs = server.same_process_containment_proofs()
        self.assertEqual(len(proofs), 1)
        self.assertEqual(proofs[0]["kind"], "never-turned-archived")
        self.assertNotIn(thread_id, json.dumps(proofs))
        tampered = dict(proofs[0])
        tampered["kind"] = "terminal-turn-archived"
        server._same_process_containment_proofs[thread_id] = tampered
        self.assertIsNone(
            server.same_process_containment_proof(thread_id)
        )

    def test_preview_containment_rejects_absence_and_archive_failure(
        self,
    ) -> None:
        unproven = self.request_server({})
        unproven.started_threads = {"thread-unproven": None}
        unproven.read_thread = mock.Mock(
            side_effect=LIVE.AppServerError(
                "app-server-request-failed:thread/read:-32600"
            )
        )
        result = LIVE.contain_started_threads(
            unproven,
            allow_same_process_proofs=True,
        )
        self.assertFalse(result["all_contained"])
        self.assertEqual(result["ambiguous_count"], 1)

        thread_id = str(uuid.uuid4())
        archive_failure = self.request_server(
            {
                "id": 1,
                "result": {
                    "model": LIVE.EXACT_MODEL,
                    "thread": {"id": thread_id, "turns": []},
                },
            }
        )
        archive_failure.start_thread(ROOT, mutable=False)
        archive_failure.read_thread = mock.Mock(
            side_effect=AssertionError("thread/read must not run")
        )
        archive_failure.archive_thread = mock.Mock(
            side_effect=LIVE.AppServerError("fixed-archive-failure")
        )
        result = LIVE.contain_started_threads(
            archive_failure,
            allow_same_process_proofs=True,
        )
        self.assertFalse(result["all_contained"])
        self.assertEqual(result["ambiguous_count"], 1)
        archive_failure.read_thread.assert_not_called()

    def test_preview_containment_proves_calibration_plus_n1_and_n2_workers(
        self,
    ) -> None:
        for worker_count in (1, 2):
            with self.subTest(worker_count=worker_count):
                calibration_thread = str(uuid.uuid4())
                calibration_turn = str(uuid.uuid4())
                server = self.request_server(
                    {
                        "id": 1,
                        "result": {
                            "model": LIVE.EXACT_MODEL,
                            "thread": {
                                "id": calibration_thread,
                                "turns": [],
                            },
                        },
                    }
                )
                server.start_thread(ROOT, mutable=False)
                server._fresh_never_turned_thread_proofs.pop(
                    calibration_thread
                )
                server.started_threads[
                    calibration_thread
                ] = calibration_turn
                server._responses[2] = {"id": 2, "result": {}}
                server.archive_thread(calibration_thread)
                terminal_proof = (
                    server.record_terminal_archive_containment(
                        calibration_thread,
                        calibration_turn,
                        terminal_evidence_sha256="b" * 64,
                    )
                )
                self.assertEqual(
                    terminal_proof["kind"],
                    "terminal-turn-archived",
                )
                connection_epoch = server.connection_epoch_sha256
                server.connection_epoch_sha256 = "c" * 64
                self.assertIsNone(
                    server.same_process_containment_proof(
                        calibration_thread
                    )
                )
                server.connection_epoch_sha256 = connection_epoch

                worker_threads: list[str] = []
                for _index in range(worker_count):
                    thread_id = str(uuid.uuid4())
                    worker_threads.append(thread_id)
                    request_id = server._request_id + 1
                    server._responses[request_id] = {
                        "id": request_id,
                        "result": {
                            "model": LIVE.EXACT_MODEL,
                            "thread": {
                                "id": thread_id,
                                "turns": [],
                            },
                        },
                    }
                    server.start_thread(ROOT, mutable=False)
                first_archive_request = server._request_id + 1
                for index, _thread_id in enumerate(worker_threads):
                    request_id = first_archive_request + index
                    server._responses[request_id] = {
                        "id": request_id,
                        "result": {},
                    }

                server.read_thread = mock.Mock(
                    side_effect=AssertionError("thread/read must not run")
                )
                result = LIVE.contain_started_threads(
                    server,
                    allow_same_process_proofs=True,
                )
                self.assertTrue(result["all_contained"])
                self.assertEqual(result["already_contained_count"], 1)
                self.assertEqual(
                    result["archived_count"],
                    worker_count,
                )
                self.assertEqual(result["ambiguous_count"], 0)
                server.read_thread.assert_not_called()
                self.assertEqual(
                    len(server.same_process_containment_proofs()),
                    worker_count + 1,
                )

    def test_thread_start_rejects_untrusted_capability_claims_before_allocation(
        self,
    ) -> None:
        cases = (
            (
                "missing-field",
                {
                    "source": "test-server",
                    "server_allowlist_supported": True,
                    "allowlist_parameter": "tools",
                },
                "capability-invalid",
                "tools",
            ),
            (
                "empty-source",
                {
                    "source": "",
                    "server_allowlist_supported": True,
                    "allowlist_parameter": "tools",
                    "effective_allowlist": ["exec_command"],
                },
                "capability-invalid",
                "tools",
            ),
            (
                "parameter-mismatch",
                {
                    "source": "test-server",
                    "server_allowlist_supported": True,
                    "allowlist_parameter": "allowedTools",
                    "effective_allowlist": ["exec_command"],
                },
                "parameter-mismatch",
                "tools",
            ),
            (
                "malformed-effective-set",
                {
                    "source": "test-server",
                    "server_allowlist_supported": True,
                    "allowlist_parameter": "tools",
                    "effective_allowlist": [1],
                },
                "capability-invalid",
                "tools",
            ),
            (
                "expanded-effective-set",
                {
                    "source": "test-server",
                    "server_allowlist_supported": True,
                    "allowlist_parameter": "tools",
                    "effective_allowlist": ["exec_command", "spawn_agent"],
                },
                "effective-mismatch",
                "tools",
            ),
            (
                "parameter-collision",
                {
                    "source": "test-server",
                    "server_allowlist_supported": True,
                    "allowlist_parameter": "sandbox",
                    "effective_allowlist": ["exec_command"],
                },
                "parameter-collision",
                "sandbox",
            ),
        )
        for name, capability, error, allowlist_parameter in cases:
            with self.subTest(name=name):
                server = self.request_server({})
                ledger = mock.Mock()
                server.allocation_ledger = ledger
                server.started_threads = {}
                server.tool_surface_capability = (
                    lambda *, permitted_tools, result=capability: dict(result)
                )
                with self.assertRaisesRegex(LIVE.AppServerError, error):
                    server.start_thread(
                        ROOT,
                        mutable=False,
                        role="capability-calibration",
                        permitted_tools=["exec_command"],
                        allowlist_parameter=allowlist_parameter,
                    )
                ledger.allocation_intent.assert_not_called()
                self.assertEqual(server.process.stdin.getvalue(), "")


class AmbiguousTurnDispatchTests(unittest.TestCase):
    class _EqualityAlias:
        """Distinct object crafted to compare equal to one opaque capability."""

        def __init__(self, target: object) -> None:
            self.target = target

        def __hash__(self) -> int:
            return hash(self.target)

        def __eq__(self, other: object) -> bool:
            return other is self.target

    class _StdoutQueue:
        _CLOSED = object()

        def __init__(self) -> None:
            self._items: queue.Queue[object] = queue.Queue()

        def push(self, message: Mapping[str, object]) -> None:
            self._items.put(json.dumps(dict(message), separators=(",", ":")) + "\n")

        def close(self) -> None:
            self._items.put(self._CLOSED)

        def __iter__(self):
            return self

        def __next__(self) -> str:
            item = self._items.get()
            if item is self._CLOSED:
                raise StopIteration
            assert isinstance(item, str)
            return item

    class _Writer:
        def __init__(self, callback) -> None:
            self.callback = callback
            self.payloads: list[dict] = []
            self.flush_count = 0

        def write(self, raw: str) -> int:
            payload = json.loads(raw)
            self.payloads.append(payload)
            self.callback(payload)
            return len(raw)

        def flush(self) -> None:
            self.flush_count += 1

    def server(self, root: Path, mode: str):
        from cwo_core.native_live_allocation_ledger import (
            NativeLiveAllocationLedgerStore,
        )
        from tests.test_native_live_allocation_ledger import bindings_v2

        thread_id = str(uuid.uuid4())
        turn_ids = [str(uuid.uuid4())]
        if mode == "multiple":
            turn_ids.append(str(uuid.uuid4()))
        ledger = NativeLiveAllocationLedgerStore(root / "ledger")
        ledger_bindings = bindings_v2()
        ledger_bindings["connection_epoch_sha256"] = "b" * 64
        ledger.initialize(ledger_bindings, version=2)
        allocation = ledger.allocation_intent("capability-calibration")
        ledger.bind_thread(allocation, thread_id)

        server = object.__new__(LIVE.AppServer)
        server._condition = threading.Condition()
        server._responses = {}
        server._notifications = []
        server._request_id = 0
        server._reader_error = None
        server.connection_epoch_sha256 = "b" * 64
        server.rpc_latencies = {}
        server.started_threads = {thread_id: None}
        server._known_thread_turn_ids = {thread_id: {"old-terminal"}}
        server._turn_dispatch_records = {}
        server._pending_turn_start_response_observers = {}
        server._observed_negative_turn_response_capabilities_by_request = {}
        server._negative_turn_response_capabilities = (
            LIVE._IdentityCapabilityRegistry()
        )
        server.allocation_ledger = ledger
        stdout = self._StdoutQueue()
        state = {
            "mode": mode,
            "turns": {"old-terminal": "completed"},
            "last_payload": None,
            "read_count": 0,
            "interrupts": [],
            "archive_count": 0,
        }

        def on_write(payload: dict) -> None:
            self.assertEqual(payload["method"], "turn/start")
            pending_observer = server._pending_turn_start_response_observers.get(
                payload["id"]
            )
            self.assertIsInstance(pending_observer, Mapping)
            assert isinstance(pending_observer, Mapping)
            self.assertEqual(pending_observer["request_id"], payload["id"])
            self.assertEqual(
                pending_observer["wire_request_sha256"],
                LIVE.domain_sha256(
                    payload,
                    domain="app-server-single-wire-request",
                ),
            )
            self.assertIn(
                pending_observer["capability"],
                ledger._pending_turn_negative_response_observer_capabilities,
            )
            self.assertNotIn(
                pending_observer["capability"],
                ledger._turn_negative_response_observer_capabilities,
            )
            state["pending_capability"] = pending_observer["capability"]
            state["last_payload"] = payload
            if mode == "normal":
                stdout.push(
                    {
                        "id": payload["id"],
                        "result": {"turn": {"id": turn_ids[0]}},
                    }
                )
                return
            if mode == "rpc-error":
                stdout.push(
                    {
                        "id": payload["id"],
                        "error": {"code": -32600, "message": "rejected"},
                    }
                )
                return
            if mode in {
                "crash",
                "write-error",
                "late-response",
                "notification",
                "query",
                "multiple",
                "interrupt-failure",
                "interrupt-transient",
                "no-terminal",
                "query-failure",
            }:
                state["turns"].update({turn_id: "inProgress" for turn_id in turn_ids})
            if mode in {"notification", "query-failure"}:
                server._notifications.append(
                    (
                        1,
                        {
                            "method": "turn/started",
                            "params": {
                                "threadId": thread_id,
                                "turn": {"id": turn_ids[0]},
                            },
                        },
                    )
                )
            if mode == "write-error":
                raise OSError("injected write error after server start")
            if mode == "crash":
                raise KeyboardInterrupt("injected crash after server start")

        writer = self._Writer(on_write)
        process = mock.Mock()
        process.stdin = writer
        process.stdout = stdout
        process.poll.return_value = None
        process.returncode = None
        server.process = process
        reader = threading.Thread(target=server._read_stdout, daemon=True)
        reader.start()
        self.addCleanup(reader.join, 1.0)
        self.addCleanup(stdout.close)

        def read_thread(requested_thread_id: str, *, timeout: float = 15.0):
            self.assertEqual(requested_thread_id, thread_id)
            self.assertGreater(timeout, 0)
            state["read_count"] += 1
            if mode == "query-failure":
                raise LIVE.AppServerError("injected thread/read failure")
            if mode == "late-response" and state["read_count"] == 1:
                payload = state["last_payload"]
                stdout.push(
                    {
                        "id": payload["id"],
                        "result": {"turn": {"id": turn_ids[0]}},
                    }
                )
            if mode == "late-rpc-error" and state["read_count"] == 1:
                payload = state["last_payload"]
                stdout.push(
                    {
                        "id": payload["id"],
                        "error": {"code": -32600, "message": "late rejected"},
                    }
                )
            return {
                "id": thread_id,
                "turns": [
                    {"id": turn_id, "status": status, "items": []}
                    for turn_id, status in state["turns"].items()
                ],
            }, 0.1

        def interrupt_turn(
            requested_thread_id: str, turn_id: str, *, timeout: float = 15.0
        ):
            self.assertEqual(requested_thread_id, thread_id)
            self.assertGreater(timeout, 0)
            state["interrupts"].append(turn_id)
            if mode == "interrupt-failure":
                raise LIVE.AppServerError("injected interrupt failure")
            if mode == "interrupt-transient" and len(state["interrupts"]) == 1:
                raise LIVE.AppServerError("injected transient interrupt failure")
            if mode != "no-terminal":
                state["turns"][turn_id] = "interrupted"
            return 0.1

        def archive_thread(requested_thread_id: str):
            self.assertEqual(requested_thread_id, thread_id)
            state["archive_count"] += 1
            ledger.record_lifecycle(
                thread_id, "archive-observed", "archive-request-accepted"
            )
            return 0.1

        server.read_thread = read_thread
        server.interrupt_turn = interrupt_turn
        server.archive_thread = archive_thread
        return server, ledger, state, writer, thread_id, turn_ids

    def test_normal_success_reserves_stable_intent_and_preserves_api(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            server, ledger, _state, writer, thread_id, turn_ids = self.server(
                Path(temporary), "normal"
            )
            turn, latency = server.start_turn(thread_id, "bounded")
            record = server.turn_dispatch_record(thread_id)
            self.assertEqual(turn, {"id": turn_ids[0]})
            self.assertGreaterEqual(latency, 0)
            self.assertIsNotNone(record)
            assert record is not None
            self.assertEqual(record["status"], "acknowledged")
            self.assertEqual(record["wire_write_attempt_count"], 1)
            self.assertEqual(len(writer.payloads), 1)
            self.assertEqual(writer.flush_count, 1)
            self.assertEqual(
                writer.payloads[0]["params"]["clientUserMessageId"],
                record["turn_intent_id"],
            )
            self.assertEqual(record["preexisting_turn_ids"], ["old-terminal"])
            self.assertEqual(ledger.summary()["unresolved_turn_intent_count"], 0)
            path = (
                ledger.directory
                / "turn-dispatch"
                / f"{record['turn_intent_id']}.json"
            )
            self.assertEqual(json.loads(path.read_text(encoding="utf-8")), record)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(path.parent.stat().st_mode & 0o777, 0o700)
            tampered = {**record, "request_id": record["request_id"] + 1}
            self.assertIn(
                "turn-dispatch-record-sha256-invalid",
                LIVE.validate_turn_dispatch_record(tampered),
            )
            with self.assertRaisesRegex(
                ValueError, "turn-dispatch-reservation-mutation"
            ):
                LIVE.evolve_turn_dispatch_record(
                    record, notification_cursor=record["notification_cursor"] + 1
                )

    def test_exact_rpc_error_preserves_error_type_after_verified_absence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            server, ledger, state, writer, thread_id, _turn_ids = self.server(
                Path(temporary), "rpc-error"
            )
            with self.assertRaises(LIVE.AppServerRpcError) as raised:
                server.start_turn(thread_id, "bounded", ambiguity_timeout=0.1)
            self.assertEqual(raised.exception.code, -32600)
            record = server.turn_dispatch_record(thread_id)
            assert record is not None
            self.assertEqual(record["status"], "failed-contained")
            self.assertEqual(record["ledger_resolution"], "verified-absent")
            self.assertEqual(state["archive_count"], 1)
            self.assertEqual(len(writer.payloads), 1)
            self.assertEqual(ledger.summary()["unresolved_turn_intent_count"], 0)
            proof_path = (
                ledger.directory
                / "turn-absence"
                / f"{record['turn_intent_id']}.json"
            )
            proof = json.loads(proof_path.read_text(encoding="utf-8"))
            negative = proof["negative_response"]
            self.assertEqual(negative["request_id"], record["request_id"])
            self.assertEqual(
                negative["connection_epoch_sha256"],
                record["connection_epoch_sha256"],
            )
            self.assertEqual(
                negative["wire_request_sha256"], record["wire_request_sha256"]
            )
            self.assertEqual(
                negative["response_sha256"],
                LIVE.domain_sha256(
                    {
                        "id": record["request_id"],
                        "error": {"code": -32600, "message": "rejected"},
                    },
                    domain="app-server-turn-start-negative-response",
                ),
            )

    def test_late_raw_rpc_error_uses_only_stdout_observed_capability(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            server, ledger, state, writer, thread_id, _turn_ids = self.server(
                Path(temporary), "late-rpc-error"
            )
            with self.assertRaises(LIVE.AmbiguousTurnStartError) as raised:
                server.start_turn(
                    thread_id,
                    "bounded",
                    timeout=0,
                    ambiguity_timeout=0.2,
                )
            record = raised.exception.record
            self.assertEqual(record["status"], "failed-contained")
            self.assertEqual(record["ambiguity_reason"], "rpc-error-response")
            self.assertEqual(record["ledger_resolution"], "verified-absent")
            self.assertTrue(record["absence_verified"])
            self.assertTrue(record["archived"])
            self.assertEqual(state["archive_count"], 1)
            self.assertEqual(len(writer.payloads), 1)
            self.assertEqual(ledger.summary()["unresolved_turn_intent_count"], 0)

    def test_relabel_and_fabricated_response_cannot_mint_absence_authority(
        self,
    ) -> None:
        from cwo_core.native_live_allocation_ledger import (
            NativeLiveAllocationLedgerError,
            NativeLiveAllocationLedgerStore,
        )

        with tempfile.TemporaryDirectory() as temporary:
            server, ledger, state, writer, thread_id, _turn_ids = self.server(
                Path(temporary), "absent"
            )
            with self.assertRaises(LIVE.AmbiguousTurnStartError) as raised:
                server.start_turn(
                    thread_id,
                    "bounded",
                    timeout=0,
                    ambiguity_timeout=0,
                )
            pending = raised.exception.record
            self.assertEqual(pending["status"], "failed-ambiguous")
            self.assertEqual(pending["ledger_resolution"], "pending")
            relabeled = LIVE.evolve_turn_dispatch_record(
                pending,
                ambiguity_reason="rpc-error-response",
            )
            server._persist_turn_dispatch_record(relabeled)

            pending_capability = state["pending_capability"]
            self.assertIn(
                pending_capability,
                ledger._pending_turn_negative_response_observer_capabilities,
            )
            self.assertNotIn(
                pending_capability,
                ledger._turn_negative_response_observer_capabilities,
            )
            pending_alias = self._EqualityAlias(pending_capability)
            self.assertNotIn(
                pending_alias,
                ledger._pending_turn_negative_response_observer_capabilities,
            )
            fabricated_response = {
                "id": relabeled["request_id"],
                "error": {
                    "code": -32600,
                    "message": "caller fabricated; never observed",
                },
            }
            fabricated_proof = LIVE.seal_turn_absence_proof(
                {
                    "artifact_type": LIVE.TURN_ABSENCE_PROOF_ARTIFACT_TYPE,
                    "version": 1,
                    "thread_id": thread_id,
                    "turn_intent_id": relabeled["turn_intent_id"],
                    "ledger_id": relabeled["ledger_id"],
                    "turn_intent_entry_sha256": relabeled[
                        "turn_intent_entry_sha256"
                    ],
                    "dispatch_record": relabeled,
                    "negative_response": {
                        "request_id": relabeled["request_id"],
                        "connection_epoch_sha256": relabeled[
                            "connection_epoch_sha256"
                        ],
                        "wire_request_sha256": relabeled[
                            "wire_request_sha256"
                        ],
                        "code": -32600,
                        "response_sha256": LIVE.domain_sha256(
                            fabricated_response,
                            domain=(
                                "app-server-turn-start-negative-response"
                            ),
                        ),
                    },
                    "proof_sha256": "",
                }
            )
            with self.assertRaisesRegex(
                NativeLiveAllocationLedgerError,
                "turn-negative-response-observer-capability-invalid",
            ):
                ledger._mint_turn_absence_verifier_capability(
                    fabricated_proof,
                    negative_response_capability=pending_capability,
                )
            self.assertEqual(ledger.summary()["unresolved_turn_intent_count"], 1)
            fresh_ledger = NativeLiveAllocationLedgerStore(ledger.directory)
            fresh_ledger.open()
            self.assertEqual(
                len(
                    fresh_ledger._pending_turn_negative_response_observer_capabilities
                ),
                0,
            )
            self.assertEqual(
                len(fresh_ledger._turn_negative_response_observer_capabilities),
                0,
            )
            with self.assertRaisesRegex(
                NativeLiveAllocationLedgerError,
                "turn-negative-response-observer-capability-invalid",
            ):
                fresh_ledger._mint_turn_absence_verifier_capability(
                    fabricated_proof,
                    negative_response_capability=pending_capability,
                )

            self.assertFalse(
                hasattr(server, "_mint_negative_turn_response_capability")
            )
            with self.assertRaises(AttributeError):
                getattr(server, "_mint_negative_turn_response_capability")

            with server._condition:
                server._responses[int(relabeled["request_id"])] = (
                    fabricated_response
                )
            after_mapping = server.contain_ambiguous_turn_dispatch(
                thread_id,
                timeout=0,
            )
            self.assertEqual(after_mapping["status"], "failed-ambiguous")
            self.assertEqual(after_mapping["ledger_resolution"], "pending")
            self.assertFalse(after_mapping["absence_verified"])
            self.assertFalse(after_mapping["archived"])

            after_lookalike = server.contain_ambiguous_turn_dispatch(
                thread_id,
                timeout=0,
                negative_response_capability=object(),
            )
            self.assertEqual(after_lookalike["status"], "failed-ambiguous")
            self.assertEqual(after_lookalike["ledger_resolution"], "pending")
            self.assertFalse(after_lookalike["absence_verified"])
            self.assertFalse(after_lookalike["archived"])
            self.assertEqual(state["archive_count"], 0)
            self.assertEqual(len(writer.payloads), 1)
            self.assertEqual(ledger.summary()["unresolved_turn_intent_count"], 1)

    def test_ambiguous_sources_are_discovered_contained_and_never_replayed(
        self,
    ) -> None:
        for mode in ("write-error", "late-response", "notification", "query"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temporary:
                server, ledger, state, writer, thread_id, turn_ids = self.server(
                    Path(temporary), mode
                )
                with self.assertRaises(LIVE.AmbiguousTurnStartError) as raised:
                    server.start_turn(
                        thread_id,
                        "bounded",
                        timeout=0,
                        ambiguity_timeout=0.2,
                    )
                record = raised.exception.record
                self.assertEqual(record["status"], "failed-contained")
                self.assertEqual(record["discovered_turn_ids"], turn_ids)
                self.assertTrue(record["absence_verified"])
                self.assertEqual(
                    record["terminal_status_by_turn"][turn_ids[0]], "interrupted"
                )
                self.assertEqual(state["interrupts"], turn_ids)
                self.assertEqual(state["archive_count"], 1)
                self.assertEqual(len(writer.payloads), 1)
                self.assertEqual(record["wire_write_attempt_count"], 1)
                self.assertEqual(ledger.summary()["unresolved_turn_intent_count"], 0)
                if mode == "late-response":
                    self.assertEqual(record["exact_response_turn_id"], turn_ids[0])
                if mode == "notification":
                    self.assertEqual(record["notification_sequences"], [1])

    def test_multiple_discovered_turns_are_all_interrupted_and_verified(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            server, ledger, state, writer, thread_id, turn_ids = self.server(
                Path(temporary), "multiple"
            )
            with self.assertRaises(LIVE.AmbiguousTurnStartError) as raised:
                server.start_turn(
                    thread_id,
                    "bounded",
                    timeout=0,
                    ambiguity_timeout=0.2,
                )
            record = raised.exception.record
            self.assertEqual(record["status"], "failed-contained")
            self.assertEqual(record["discovered_turn_ids"], sorted(turn_ids))
            self.assertEqual(record["interrupt_attempted_turn_ids"], sorted(turn_ids))
            self.assertEqual(sorted(state["interrupts"]), sorted(turn_ids))
            self.assertEqual(len(writer.payloads), 1)
            self.assertEqual(ledger.summary()["unresolved_turn_intent_count"], 0)

    def test_exact_negative_resolves_intent_without_inventing_a_turn(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            server, ledger, state, writer, thread_id, _turn_ids = self.server(
                Path(temporary), "rpc-error"
            )
            with self.assertRaises(LIVE.AppServerRpcError):
                server.start_turn(
                    thread_id,
                    "bounded",
                    ambiguity_timeout=0.1,
                )
            record = server.turn_dispatch_record(thread_id)
            assert record is not None
            self.assertEqual(record["status"], "failed-contained")
            self.assertEqual(record["discovered_turn_ids"], [])
            self.assertEqual(record["ledger_resolution"], "verified-absent")
            self.assertEqual(state["interrupts"], [])
            self.assertEqual(state["archive_count"], 1)
            self.assertEqual(len(writer.payloads), 1)
            summary = ledger.summary()
            self.assertEqual(summary["turn_bound_count"], 0)
            self.assertEqual(summary["unresolved_turn_intent_count"], 0)
            with self.assertRaisesRegex(
                ValueError, "containment-outcome-reserved"
            ):
                ledger.record_containment_audit(
                    thread_id,
                    outcome="turn-intent-verified-absent",
                    evidence={"forged": True},
                )
            with self.assertRaisesRegex(
                (TypeError, ValueError),
                "proof|verifier|unexpected keyword",
            ):
                ledger.resolve_turn_intent_absent(
                    thread_id,
                    record["turn_intent_id"],
                    proof_sha256="not-a-proof-hash",
                )

    def test_incomplete_proof_stays_failed_ambiguous_and_pending(self) -> None:
        for mode in ("query-failure", "interrupt-failure", "no-terminal"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temporary:
                server, ledger, state, writer, thread_id, _turn_ids = self.server(
                    Path(temporary), mode
                )
                started = LIVE.time.monotonic()
                with self.assertRaises(LIVE.AmbiguousTurnStartError) as raised:
                    server.start_turn(
                        thread_id,
                        "bounded",
                        timeout=0,
                        ambiguity_timeout=0.03,
                    )
                elapsed = LIVE.time.monotonic() - started
                record = raised.exception.record
                self.assertLess(elapsed, 0.30)
                self.assertEqual(record["status"], "failed-ambiguous")
                self.assertFalse(record["absence_verified"])
                self.assertFalse(record["archived"])
                self.assertEqual(state["archive_count"], 0)
                self.assertEqual(len(writer.payloads), 1)
                self.assertEqual(ledger.summary()["unresolved_turn_intent_count"], 1)
                if mode == "query-failure":
                    self.assertTrue(state["interrupts"])
                if mode == "interrupt-failure":
                    self.assertTrue(record["interrupt_failed_turn_ids"])
                if mode == "no-terminal":
                    self.assertTrue(record["active_turn_ids_at_final_check"])

    def test_containment_retry_is_idempotent_after_proof(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            server, _ledger, state, writer, thread_id, _turn_ids = self.server(
                Path(temporary), "query"
            )
            with self.assertRaises(LIVE.AmbiguousTurnStartError) as raised:
                server.start_turn(
                    thread_id,
                    "bounded",
                    timeout=0,
                    ambiguity_timeout=0.2,
                )
            first = raised.exception.record
            interrupts = list(state["interrupts"])
            archive_count = state["archive_count"]
            second = server.contain_ambiguous_turn_dispatch(thread_id, timeout=0)
            self.assertEqual(second, first)
            self.assertEqual(state["interrupts"], interrupts)
            self.assertEqual(state["archive_count"], archive_count)
            self.assertEqual(len(writer.payloads), 1)

    def test_dispatching_crash_record_is_recovered_by_global_containment(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            server, ledger, state, writer, thread_id, turn_ids = self.server(
                Path(temporary), "crash"
            )
            with self.assertRaises(KeyboardInterrupt):
                server.start_turn(thread_id, "bounded", timeout=0)
            record = server.turn_dispatch_record(thread_id)
            assert record is not None
            self.assertEqual(record["status"], "dispatching")
            self.assertEqual(record["wire_write_attempt_count"], 1)

            result = LIVE.contain_started_threads(server)
            recovered = server.turn_dispatch_record(thread_id)
            assert recovered is not None
            self.assertTrue(result["all_contained"])
            self.assertEqual(recovered["status"], "failed-contained")
            self.assertEqual(recovered["discovered_turn_ids"], turn_ids)
            self.assertEqual(state["interrupts"], turn_ids)
            self.assertEqual(state["archive_count"], 1)
            self.assertEqual(len(writer.payloads), 1)
            self.assertEqual(ledger.summary()["unresolved_turn_intent_count"], 0)

    def test_second_query_rechecks_notifications_after_first_empty_query(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            server, _ledger, state, _writer, thread_id, turn_ids = self.server(
                Path(temporary), "absent"
            )
            original_read = server.read_thread
            wrapper_reads = 0

            def read_with_late_start(
                requested_thread_id: str, *, timeout: float = 15.0
            ):
                nonlocal wrapper_reads
                wrapper_reads += 1
                if wrapper_reads == 2:
                    state["turns"][turn_ids[0]] = "inProgress"
                    server._notifications.append(
                        (
                            2,
                            {
                                "method": "turn/started",
                                "params": {
                                    "threadId": thread_id,
                                    "turn": {"id": turn_ids[0]},
                                },
                            },
                        )
                    )
                return original_read(requested_thread_id, timeout=timeout)

            server.read_thread = read_with_late_start
            with self.assertRaises(LIVE.AmbiguousTurnStartError) as raised:
                server.start_turn(
                    thread_id, "bounded", timeout=0, ambiguity_timeout=0.25
                )
            record = raised.exception.record
            self.assertGreaterEqual(wrapper_reads, 3)
            self.assertEqual(record["status"], "failed-contained")
            self.assertEqual(record["discovered_turn_ids"], turn_ids)
            self.assertEqual(record["notification_sequences"], [1])
            self.assertIn(turn_ids[0], state["interrupts"])
            self.assertNotEqual(record["ledger_resolution"], "verified-absent")

    def test_final_notification_boundary_silence_never_certifies_absence(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            server, ledger, state, writer, thread_id, turn_ids = self.server(
                Path(temporary), "absent"
            )
            original_snapshot = server._post_cursor_turn_starts
            snapshot_count = 0

            def snapshot_then_start(**kwargs):
                nonlocal snapshot_count
                snapshot_count += 1
                observed = original_snapshot(**kwargs)
                if snapshot_count == 2:
                    state["turns"][turn_ids[0]] = "inProgress"
                    server._notifications.append(
                        (
                            2,
                            {
                                "method": "turn/started",
                                "params": {
                                    "threadId": thread_id,
                                    "turn": {"id": turn_ids[0]},
                                },
                            },
                        )
                    )
                return observed

            server._post_cursor_turn_starts = snapshot_then_start
            with self.assertRaises(LIVE.AmbiguousTurnStartError) as raised:
                server.start_turn(
                    thread_id,
                    "bounded",
                    timeout=0,
                    ambiguity_timeout=0,
                )
            record = raised.exception.record
            self.assertEqual(snapshot_count, 2)
            self.assertEqual(record["status"], "failed-ambiguous")
            self.assertFalse(record["absence_verified"])
            self.assertIsNone(record["absence_proof_sha256"])
            self.assertEqual(record["ledger_resolution"], "pending")
            self.assertFalse(record["archived"])
            self.assertEqual(state["turns"][turn_ids[0]], "inProgress")
            self.assertEqual(state["archive_count"], 0)
            self.assertEqual(len(writer.payloads), 1)
            self.assertEqual(ledger.summary()["unresolved_turn_intent_count"], 1)

    def test_fresh_client_loads_private_dispatch_and_contains_server_turn(self) -> None:
        from cwo_core.native_live_allocation_ledger import (
            NativeLiveAllocationLedgerStore,
        )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original, ledger, state, writer, thread_id, turn_ids = self.server(
                root, "crash"
            )
            original._notifications.extend(
                [
                    (1, {"method": "unrelated/one", "params": {}}),
                    (2, {"method": "unrelated/two", "params": {}}),
                ]
            )
            with self.assertRaises(KeyboardInterrupt):
                original.start_turn(thread_id, "bounded", timeout=0)
            original_record = original.turn_dispatch_record(thread_id)
            assert original_record is not None
            self.assertEqual(original_record["notification_cursor"], 2)

            recovered = object.__new__(LIVE.AppServer)
            recovered._condition = threading.Condition()
            recovered._responses = {}
            recovered._notifications = [
                (
                    1,
                    {
                        "method": "turn/started",
                        "params": {
                            "threadId": thread_id,
                            "turn": {"id": turn_ids[0]},
                        },
                    },
                )
            ]
            recovered._request_id = 0
            recovered._reader_error = None
            recovered.connection_epoch_sha256 = "c" * 64
            recovered.rpc_latencies = {}
            recovered.started_threads = {}
            recovered._known_thread_turn_ids = {}
            recovered._turn_dispatch_records = {}
            recovered.allocation_ledger = None
            process = mock.Mock()
            process.poll.return_value = None
            process.returncode = None
            recovered.process = process
            fresh_ledger = NativeLiveAllocationLedgerStore(ledger.directory)
            recovered.attach_allocation_ledger(fresh_ledger)

            self.assertIn(thread_id, recovered._turn_dispatch_records)
            self.assertEqual(
                recovered._turn_dispatch_records[thread_id]["status"], "dispatching"
            )
            self.assertIn(thread_id, recovered.started_threads)

            def read_thread(requested_thread_id: str, *, timeout: float = 15.0):
                self.assertEqual(requested_thread_id, thread_id)
                self.assertGreater(timeout, 0)
                return {
                    "id": thread_id,
                    "turns": [
                        {"id": turn_id, "status": status, "items": []}
                        for turn_id, status in state["turns"].items()
                    ],
                }, 0.1

            def interrupt_turn(
                requested_thread_id: str, turn_id: str, *, timeout: float = 15.0
            ):
                self.assertEqual(requested_thread_id, thread_id)
                state["interrupts"].append(turn_id)
                state["turns"][turn_id] = "interrupted"
                fresh_ledger.record_lifecycle(
                    thread_id, "interrupt-observed", "interrupt-request-accepted"
                )
                return 0.1

            def archive_thread(requested_thread_id: str):
                self.assertEqual(requested_thread_id, thread_id)
                state["archive_count"] += 1
                fresh_ledger.record_lifecycle(
                    thread_id, "archive-observed", "archive-request-accepted"
                )
                return 0.1

            recovered.read_thread = read_thread
            recovered.interrupt_turn = interrupt_turn
            recovered.archive_thread = archive_thread
            result = LIVE.contain_started_threads(recovered)
            record = recovered.turn_dispatch_record(thread_id)
            assert record is not None
            self.assertTrue(result["all_contained"])
            self.assertEqual(record["status"], "failed-contained")
            self.assertEqual(record["discovered_turn_ids"], turn_ids)
            self.assertEqual(record["connection_epoch_sha256"], "b" * 64)
            self.assertEqual(record["notification_cursor"], 2)
            self.assertEqual(
                record["notification_connection_epoch_sha256"], "c" * 64
            )
            self.assertEqual(record["notification_sequences"], [1])
            self.assertEqual(LIVE.validate_turn_dispatch_record(record), [])
            self.assertEqual(state["interrupts"], turn_ids)
            self.assertEqual(len(writer.payloads), 1)

    def test_absence_resolution_crash_window_retains_bound_persisted_proof(
        self,
    ) -> None:
        from cwo_core.native_live_allocation_ledger import (
            NativeLiveAllocationLedgerStore,
        )

        with tempfile.TemporaryDirectory() as temporary:
            server, ledger, _state, _writer, thread_id, _turn_ids = self.server(
                Path(temporary), "rpc-error"
            )
            persist_locked = server._persist_turn_dispatch_record_locked

            def crash_before_final_record(record: Mapping[str, object]):
                if record.get("status") == "failed-contained":
                    raise KeyboardInterrupt("crash after ledger resolution")
                return persist_locked(record)

            server._persist_turn_dispatch_record_locked = crash_before_final_record
            with self.assertRaises(KeyboardInterrupt):
                server.start_turn(
                    thread_id, "bounded", timeout=0, ambiguity_timeout=0.15
                )
            durable_record = json.loads(
                next((ledger.directory / "turn-dispatch").glob("*.json")).read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(durable_record["status"], "failed-ambiguous")
            self.assertEqual(
                durable_record["ledger_resolution"], "verified-absent"
            )
            self.assertRegex(
                durable_record["absence_proof_sha256"], r"^[0-9a-f]{64}$"
            )
            self.assertTrue(durable_record["absence_verified"])
            self.assertTrue(durable_record["archived"])
            fresh = NativeLiveAllocationLedgerStore(ledger.directory)
            fresh.open()
            resolution = fresh.turn_intent_resolution(
                str(durable_record["turn_intent_id"])
            )
            self.assertEqual(resolution["resolution"], "verified-absent")
            self.assertRegex(resolution["evidence_sha256"], r"^[0-9a-f]{64}$")
            proof_path = (
                ledger.directory
                / "turn-absence"
                / f"{durable_record['turn_intent_id']}.json"
            )
            proof = json.loads(proof_path.read_text(encoding="utf-8"))
            self.assertEqual(proof["proof_sha256"], resolution["evidence_sha256"])
            self.assertEqual(
                proof["dispatch_record"]["request_id"],
                durable_record["request_id"],
            )
            self.assertEqual(
                proof["dispatch_record"]["wire_request_sha256"],
                durable_record["wire_request_sha256"],
            )

    def test_crash_after_success_audit_reuses_exact_single_final_audit(self) -> None:
        for mode in ("query", "rpc-error"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temporary:
                server, ledger, _state, _writer, thread_id, _turn_ids = self.server(
                    Path(temporary), mode
                )
                persist_locked = server._persist_turn_dispatch_record_locked

                def crash_before_final_record(record: Mapping[str, object]):
                    if record.get("status") == "failed-contained":
                        raise KeyboardInterrupt("crash after successful audit")
                    return persist_locked(record)

                server._persist_turn_dispatch_record_locked = (
                    crash_before_final_record
                )
                with self.assertRaises(KeyboardInterrupt):
                    server.start_turn(
                        thread_id,
                        "bounded",
                        timeout=0,
                        ambiguity_timeout=0.2,
                    )
                before = ledger.load()
                success_before = [
                    entry
                    for entry in before["entries"]
                    if entry.get("event") == "containment-audited"
                    and entry.get("thread_id") == thread_id
                    and entry.get("outcome")
                    in {"contained", "already-contained"}
                ]
                self.assertEqual(len(success_before), 1)
                audit_before = ledger.audit_file.read_bytes()
                archive_count_before = _state["archive_count"]

                server._persist_turn_dispatch_record_locked = persist_locked
                recovered = server.contain_ambiguous_turn_dispatch(
                    thread_id, timeout=0.2
                )
                self.assertEqual(recovered["status"], "failed-contained")
                after = ledger.load()
                success_after = [
                    entry
                    for entry in after["entries"]
                    if entry.get("event") == "containment-audited"
                    and entry.get("thread_id") == thread_id
                    and entry.get("outcome")
                    in {"contained", "already-contained"}
                ]
                self.assertEqual(success_after, success_before)
                self.assertEqual(ledger.audit_file.read_bytes(), audit_before)
                self.assertEqual(_state["archive_count"], archive_count_before)

    def test_audit_pending_resume_never_creates_missing_success_audit(self) -> None:
        for mode in ("query", "rpc-error"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temporary:
                server, ledger, state, _writer, thread_id, _turn_ids = self.server(
                    Path(temporary), mode
                )
                with mock.patch.object(
                    ledger,
                    "record_containment_audit",
                    side_effect=OSError("injected success-audit failure"),
                ):
                    with self.assertRaises(LIVE.AmbiguousTurnStartError) as raised:
                        server.start_turn(
                            thread_id,
                            "bounded",
                            timeout=0,
                            ambiguity_timeout=0.2,
                        )
                precursor = raised.exception.record
                self.assertEqual(precursor["status"], "failed-ambiguous")
                self.assertTrue(precursor["archived"])
                self.assertTrue(precursor["absence_verified"])
                self.assertFalse(precursor["active_turn_ids_at_final_check"])
                self.assertFalse(precursor["interrupt_failed_turn_ids"])
                self.assertEqual(
                    set(precursor["discovered_turn_ids"]),
                    set(precursor["terminal_status_by_turn"]),
                )
                archive_count = state["archive_count"]
                success_before = [
                    entry
                    for entry in ledger.load()["entries"]
                    if entry.get("event") == "containment-audited"
                    and entry.get("thread_id") == thread_id
                    and entry.get("outcome") in {"contained", "already-contained"}
                ]
                self.assertEqual(success_before, [])

                resumed = server.contain_ambiguous_turn_dispatch(
                    thread_id, timeout=0.2
                )
                self.assertEqual(resumed, precursor)
                self.assertEqual(state["archive_count"], archive_count)
                self.assertEqual(
                    [
                        entry
                        for entry in ledger.load()["entries"]
                        if entry.get("event") == "containment-audited"
                        and entry.get("thread_id") == thread_id
                        and entry.get("outcome")
                        in {"contained", "already-contained"}
                    ],
                    [],
                )

                fabricated_final = LIVE.evolve_turn_dispatch_record(
                    precursor,
                    status="failed-contained",
                )
                server._persist_turn_dispatch_record(fabricated_final)
                rejected = server.contain_ambiguous_turn_dispatch(
                    thread_id, timeout=0.2
                )
                self.assertEqual(rejected["status"], "failed-ambiguous")
                self.assertEqual(state["archive_count"], archive_count)
                self.assertFalse(
                    ledger.has_exact_containment_audit_for_dispatch(
                        fabricated_final
                    )
                )

    def test_contained_record_without_ledger_is_downgraded(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            server, _ledger, state, _writer, thread_id, _turn_ids = self.server(
                Path(temporary), "query"
            )
            with self.assertRaises(LIVE.AmbiguousTurnStartError) as raised:
                server.start_turn(
                    thread_id,
                    "bounded",
                    timeout=0,
                    ambiguity_timeout=0.2,
                )
            self.assertEqual(raised.exception.record["status"], "failed-contained")
            archive_count = state["archive_count"]
            server.allocation_ledger = None
            downgraded = server.contain_ambiguous_turn_dispatch(
                thread_id, timeout=0.2
            )
            self.assertEqual(downgraded["status"], "failed-ambiguous")
            self.assertEqual(state["archive_count"], archive_count)

    def test_cross_app_server_dispatch_lock_preserves_newer_precursor(self) -> None:
        from cwo_core.native_live_allocation_ledger import (
            NativeLiveAllocationLedgerStore,
        )

        with tempfile.TemporaryDirectory() as temporary:
            server, ledger, state, _writer, thread_id, _turn_ids = self.server(
                Path(temporary), "query"
            )
            persist_locked = server._persist_turn_dispatch_record_locked

            def crash_before_final_record(record: Mapping[str, object]):
                if record.get("status") == "failed-contained":
                    raise KeyboardInterrupt("crash after exact success audit")
                return persist_locked(record)

            server._persist_turn_dispatch_record_locked = crash_before_final_record
            with self.assertRaises(KeyboardInterrupt):
                server.start_turn(
                    thread_id,
                    "bounded",
                    timeout=0,
                    ambiguity_timeout=0.2,
                )
            server._persist_turn_dispatch_record_locked = persist_locked
            precursor = server.turn_dispatch_record(thread_id)
            assert precursor is not None
            newer = LIVE.evolve_turn_dispatch_record(
                precursor,
                query_count=precursor["query_count"] + 1,
            )

            second = object.__new__(LIVE.AppServer)
            second._condition = threading.Condition()
            second._turn_dispatch_records = {thread_id: dict(precursor)}
            second_ledger = NativeLiveAllocationLedgerStore(ledger.directory)
            second_ledger.open()
            second.allocation_ledger = second_ledger
            original_second_locked = second._persist_turn_dispatch_record_locked
            newer_written = threading.Event()
            release_newer_writer = threading.Event()
            writer_failures: list[BaseException] = []
            containment_failures: list[BaseException] = []
            containment_results: list[dict[str, object]] = []
            containment_started = threading.Event()

            def hold_newer_dispatch(record: Mapping[str, object]):
                result = original_second_locked(record)
                newer_written.set()
                if not release_newer_writer.wait(2):
                    raise AssertionError("test failed to release newer writer")
                return result

            second._persist_turn_dispatch_record_locked = hold_newer_dispatch

            def write_newer() -> None:
                try:
                    second._persist_turn_dispatch_record(newer)
                except BaseException as exc:  # pragma: no cover - asserted below
                    writer_failures.append(exc)

            def resume_stale_precursor() -> None:
                try:
                    containment_started.set()
                    containment_results.append(
                        server.contain_ambiguous_turn_dispatch(
                            thread_id, timeout=0.2
                        )
                    )
                except BaseException as exc:  # pragma: no cover - asserted below
                    containment_failures.append(exc)

            writer_thread = threading.Thread(target=write_newer)
            writer_thread.start()
            self.assertTrue(newer_written.wait(2))
            containment_thread = threading.Thread(target=resume_stale_precursor)
            containment_thread.start()
            self.assertTrue(containment_started.wait(2))
            self.assertTrue(containment_thread.is_alive())
            release_newer_writer.set()
            writer_thread.join(2)
            containment_thread.join(2)

            self.assertFalse(writer_thread.is_alive())
            self.assertFalse(containment_thread.is_alive())
            self.assertEqual(writer_failures, [])
            self.assertEqual(containment_failures, [])
            self.assertEqual(containment_results, [newer])
            self.assertEqual(server.turn_dispatch_record(thread_id), newer)
            path = (
                ledger.directory
                / "turn-dispatch"
                / f"{precursor['turn_intent_id']}.json"
            )
            self.assertEqual(json.loads(path.read_text(encoding="utf-8")), newer)
            self.assertEqual(state["archive_count"], 1)

    def test_cross_app_server_stale_resume_rejects_unaudited_newer_final(
        self,
    ) -> None:
        from cwo_core.native_live_allocation_ledger import (
            NativeLiveAllocationLedgerStore,
        )

        with tempfile.TemporaryDirectory() as temporary:
            server, ledger, state, _writer, thread_id, _turn_ids = self.server(
                Path(temporary), "query"
            )
            persist_locked = server._persist_turn_dispatch_record_locked

            def crash_before_final_record(record: Mapping[str, object]):
                if record.get("status") == "failed-contained":
                    raise KeyboardInterrupt("crash after exact success audit")
                return persist_locked(record)

            server._persist_turn_dispatch_record_locked = crash_before_final_record
            with self.assertRaises(KeyboardInterrupt):
                server.start_turn(
                    thread_id,
                    "bounded",
                    timeout=0,
                    ambiguity_timeout=0.2,
                )
            server._persist_turn_dispatch_record_locked = persist_locked
            precursor = server.turn_dispatch_record(thread_id)
            assert precursor is not None
            forged_final = LIVE.evolve_turn_dispatch_record(
                precursor,
                status="failed-contained",
                query_count=precursor["query_count"] + 1,
            )
            self.assertFalse(
                ledger.has_exact_containment_audit_for_dispatch(forged_final)
            )

            second = object.__new__(LIVE.AppServer)
            second._condition = threading.Condition()
            second._turn_dispatch_records = {thread_id: dict(precursor)}
            second_ledger = NativeLiveAllocationLedgerStore(ledger.directory)
            second_ledger.open()
            second.allocation_ledger = second_ledger
            second._persist_turn_dispatch_record(forged_final)

            archive_count = state["archive_count"]
            recovered = server.contain_ambiguous_turn_dispatch(
                thread_id,
                timeout=0.2,
            )
            self.assertEqual(recovered["status"], "failed-ambiguous")
            self.assertEqual(
                recovered["query_count"],
                forged_final["query_count"],
            )
            self.assertNotEqual(
                recovered["record_sha256"],
                forged_final["record_sha256"],
            )
            self.assertEqual(server.turn_dispatch_record(thread_id), recovered)
            path = (
                ledger.directory
                / "turn-dispatch"
                / f"{precursor['turn_intent_id']}.json"
            )
            self.assertEqual(json.loads(path.read_text(encoding="utf-8")), recovered)
            self.assertFalse(
                ledger.has_exact_containment_audit_for_dispatch(forged_final)
            )
            self.assertEqual(state["archive_count"], archive_count)

    def test_failure_before_absence_ledger_append_keeps_intent_pending(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            server, ledger, state, _writer, thread_id, _turn_ids = self.server(
                Path(temporary), "rpc-error"
            )
            with mock.patch.object(
                ledger,
                "resolve_turn_intent_absent",
                side_effect=OSError("injected pre-append failure"),
            ):
                with self.assertRaises(LIVE.AmbiguousTurnStartError) as raised:
                    server.start_turn(
                        thread_id, "bounded", timeout=0, ambiguity_timeout=0.15
                    )
            record = raised.exception.record
            self.assertEqual(record["status"], "failed-ambiguous")
            self.assertEqual(record["ledger_resolution"], "pending")
            self.assertIsNone(record["absence_proof_sha256"])
            self.assertEqual(ledger.summary()["unresolved_turn_intent_count"], 1)
            self.assertEqual(state["archive_count"], 0)

    def test_absence_proof_requires_exact_dispatch_and_opaque_one_shot_capability(
        self,
    ) -> None:
        from cwo_core.native_live_allocation_ledger import (
            NativeLiveAllocationLedgerError,
            NativeLiveAllocationLedgerStore,
        )

        def capture_case(root: Path):
            server, ledger, _state, _writer, thread_id, _turn_ids = self.server(
                root, "rpc-error"
            )
            captured: dict[str, object] = {}

            def stop_before_resolution(*_args, **kwargs):
                captured.update(kwargs)
                raise KeyboardInterrupt(
                    "capture exact proof before guarded resolution"
                )

            with mock.patch.object(
                ledger,
                "resolve_turn_intent_absent",
                side_effect=stop_before_resolution,
            ):
                with self.assertRaises(KeyboardInterrupt):
                    server.start_turn(thread_id, "bounded", ambiguity_timeout=0.1)
            proof = captured["proof"]
            capability = captured["verifier_capability"]
            assert isinstance(proof, Mapping)
            return ledger, thread_id, dict(proof), capability

        with tempfile.TemporaryDirectory() as temporary:
            ledger, thread_id, proof, capability = capture_case(Path(temporary))
            with self.assertRaisesRegex(
                NativeLiveAllocationLedgerError,
                "standalone-persistence-forbidden",
            ):
                ledger.persist_turn_absence_proof(dict(proof))
            dispatch_path = (
                ledger.directory
                / "turn-dispatch"
                / f"{proof['turn_intent_id']}.json"
            )
            dispatch_path.unlink()
            with self.assertRaisesRegex(
                NativeLiveAllocationLedgerError,
                "absence-dispatch-missing",
            ):
                ledger.resolve_turn_intent_absent(
                    thread_id,
                    str(proof["turn_intent_id"]),
                    proof=proof,
                    verifier_capability=capability,
                )
            ledger.open()
            self.assertEqual(ledger.summary()["unresolved_turn_intent_count"], 1)

        with tempfile.TemporaryDirectory() as temporary:
            ledger, thread_id, proof, _capability = capture_case(Path(temporary))
            with self.assertRaisesRegex(
                NativeLiveAllocationLedgerError,
                "verifier-capability-invalid",
            ):
                ledger.resolve_turn_intent_absent(
                    thread_id,
                    str(proof["turn_intent_id"]),
                    proof=dict(proof),
                    verifier_capability=object(),
                )
            ledger.open()
            self.assertEqual(ledger.summary()["unresolved_turn_intent_count"], 1)

        with tempfile.TemporaryDirectory() as temporary:
            ledger, thread_id, proof, capability = capture_case(Path(temporary))
            forged = json.loads(json.dumps(proof))
            forged["negative_response"]["response_sha256"] = "f" * 64
            forged = LIVE.seal_turn_absence_proof(forged)
            with self.assertRaisesRegex(
                NativeLiveAllocationLedgerError,
                "verifier-capability-mismatch",
            ):
                ledger.resolve_turn_intent_absent(
                    thread_id,
                    str(proof["turn_intent_id"]),
                    proof=forged,
                    verifier_capability=capability,
                )
            ledger.open()
            self.assertEqual(ledger.summary()["unresolved_turn_intent_count"], 1)

        with tempfile.TemporaryDirectory() as temporary:
            ledger, thread_id, proof, capability = capture_case(Path(temporary))
            ledger.resolve_turn_intent_absent(
                thread_id,
                str(proof["turn_intent_id"]),
                proof=proof,
                verifier_capability=capability,
            )
            with self.assertRaisesRegex(
                NativeLiveAllocationLedgerError,
                "verifier-capability-invalid",
            ):
                ledger.resolve_turn_intent_absent(
                    thread_id,
                    str(proof["turn_intent_id"]),
                    proof=proof,
                    verifier_capability=capability,
                )
            ledger.open()
            self.assertEqual(ledger.summary()["unresolved_turn_intent_count"], 0)
            proof_path = (
                ledger.directory
                / "turn-absence"
                / f"{proof['turn_intent_id']}.json"
            )
            tampered = json.loads(proof_path.read_text(encoding="utf-8"))
            tampered["negative_response"]["response_sha256"] = "e" * 64
            proof_path.write_text(json.dumps(tampered) + "\n", encoding="utf-8")
            proof_path.chmod(0o600)
            with self.assertRaisesRegex(
                NativeLiveAllocationLedgerError,
                "ledger-store-stale|turn-intent-absence-proof-link-invalid",
            ):
                ledger.summary()
            with self.assertRaisesRegex(
                NativeLiveAllocationLedgerError,
                "turn-intent-absence-proof-link-invalid",
            ):
                NativeLiveAllocationLedgerStore(ledger.directory).open()

    def test_negative_response_observer_capability_is_opaque_and_one_shot(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            server, ledger, state, _writer, thread_id, _turn_ids = self.server(
                Path(temporary), "rpc-error"
            )
            captured: dict[str, object] = {}

            def stop_before_observer_consumption(*_args, **kwargs):
                captured.update(kwargs)
                raise KeyboardInterrupt("capture opaque observer capability")

            with mock.patch.object(
                server,
                "contain_ambiguous_turn_dispatch",
                side_effect=stop_before_observer_consumption,
            ):
                with self.assertRaises(KeyboardInterrupt):
                    server.start_turn(thread_id, "bounded", ambiguity_timeout=0.1)
            record = server.turn_dispatch_record(thread_id)
            assert record is not None
            capability = captured["negative_response_capability"]
            pending_capability = state["pending_capability"]
            self.assertIsNot(capability, pending_capability)
            self.assertNotIn(
                pending_capability,
                ledger._pending_turn_negative_response_observer_capabilities,
            )
            self.assertNotIn(
                pending_capability,
                ledger._turn_negative_response_observer_capabilities,
            )
            self.assertIn(
                capability,
                ledger._turn_negative_response_observer_capabilities,
            )
            with self.assertRaisesRegex(
                LIVE.AppServerError,
                "turn-negative-response-capability-invalid",
            ):
                server._consume_negative_turn_response_capability(object(), record)
            equality_alias = self._EqualityAlias(capability)
            self.assertIsNot(equality_alias, capability)
            with self.assertRaisesRegex(
                LIVE.AppServerError,
                "turn-negative-response-capability-invalid",
            ):
                server._consume_negative_turn_response_capability(
                    equality_alias,
                    record,
                )
            witness = server._consume_negative_turn_response_capability(
                capability, record
            )
            self.assertEqual(witness["request_id"], record["request_id"])
            self.assertEqual(
                witness["connection_epoch_sha256"],
                record["connection_epoch_sha256"],
            )
            self.assertEqual(
                witness["wire_request_sha256"], record["wire_request_sha256"]
            )
            self.assertRegex(witness["response_sha256"], r"^[0-9a-f]{64}$")
            with self.assertRaisesRegex(
                LIVE.AppServerError,
                "turn-negative-response-capability-invalid",
            ):
                server._consume_negative_turn_response_capability(
                    capability, record
                )

    def test_ledger_observed_response_capability_is_exact_and_one_shot(
        self,
    ) -> None:
        from cwo_core.native_live_allocation_ledger import (
            NativeLiveAllocationLedgerError,
        )

        def capture_case(root: Path):
            server, ledger, state, _writer, thread_id, _turn_ids = self.server(
                root, "rpc-error"
            )
            captured: dict[str, object] = {}
            mint = ledger._mint_turn_absence_verifier_capability

            def stop_before_mint(
                proof: Mapping[str, object],
                *,
                negative_response_capability: object,
            ) -> object:
                captured["proof"] = dict(proof)
                captured["observed_capability"] = negative_response_capability
                raise KeyboardInterrupt("capture stdout-observed capability")

            with mock.patch.object(
                ledger,
                "_mint_turn_absence_verifier_capability",
                side_effect=stop_before_mint,
            ):
                with self.assertRaises(KeyboardInterrupt):
                    server.start_turn(
                        thread_id,
                        "bounded",
                        ambiguity_timeout=0.1,
                    )
            proof = captured["proof"]
            observed = captured["observed_capability"]
            assert isinstance(proof, Mapping)
            return (
                ledger,
                thread_id,
                dict(proof),
                observed,
                state["pending_capability"],
                mint,
            )

        with tempfile.TemporaryDirectory() as temporary:
            ledger, _thread_id, proof, observed, pending, mint = capture_case(
                Path(temporary)
            )
            self.assertIsNot(observed, pending)
            equality_alias = self._EqualityAlias(observed)
            self.assertIsNot(equality_alias, observed)
            self.assertNotIn(
                equality_alias,
                ledger._turn_negative_response_observer_capabilities,
            )
            with self.assertRaisesRegex(
                NativeLiveAllocationLedgerError,
                "turn-negative-response-observer-capability-invalid",
            ):
                mint(proof, negative_response_capability=equality_alias)
            forged = json.loads(json.dumps(proof))
            forged["negative_response"]["response_sha256"] = "f" * 64
            forged = LIVE.seal_turn_absence_proof(forged)
            with self.assertRaisesRegex(
                NativeLiveAllocationLedgerError,
                "turn-intent-absence-proof-link-invalid",
            ):
                mint(forged, negative_response_capability=observed)
            with self.assertRaisesRegex(
                NativeLiveAllocationLedgerError,
                "turn-negative-response-observer-capability-invalid",
            ):
                mint(proof, negative_response_capability=observed)
            self.assertEqual(ledger.summary()["unresolved_turn_intent_count"], 1)

        with tempfile.TemporaryDirectory() as temporary:
            ledger, thread_id, proof, observed, _pending, mint = capture_case(
                Path(temporary)
            )
            verifier = mint(
                proof,
                negative_response_capability=observed,
            )
            with self.assertRaisesRegex(
                NativeLiveAllocationLedgerError,
                "turn-negative-response-observer-capability-invalid",
            ):
                mint(proof, negative_response_capability=observed)
            verifier_alias = self._EqualityAlias(verifier)
            self.assertIsNot(verifier_alias, verifier)
            with self.assertRaisesRegex(
                NativeLiveAllocationLedgerError,
                "turn-intent-absence-verifier-capability-invalid",
            ):
                ledger.resolve_turn_intent_absent(
                    thread_id,
                    str(proof["turn_intent_id"]),
                    proof=proof,
                    verifier_capability=verifier_alias,
                )
            ledger.open()
            self.assertEqual(ledger.summary()["unresolved_turn_intent_count"], 1)

        with tempfile.TemporaryDirectory() as temporary:
            ledger, thread_id, proof, observed, _pending, mint = capture_case(
                Path(temporary)
            )
            verifier = mint(
                proof,
                negative_response_capability=observed,
            )
            ledger.resolve_turn_intent_absent(
                thread_id,
                str(proof["turn_intent_id"]),
                proof=proof,
                verifier_capability=verifier,
            )
            self.assertEqual(ledger.summary()["unresolved_turn_intent_count"], 0)

    def test_transient_interrupt_failure_is_retried_and_cleared(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            server, _ledger, state, _writer, thread_id, turn_ids = self.server(
                Path(temporary), "interrupt-transient"
            )
            with self.assertRaises(LIVE.AmbiguousTurnStartError) as raised:
                server.start_turn(
                    thread_id, "bounded", timeout=0, ambiguity_timeout=0.25
                )
            record = raised.exception.record
            self.assertEqual(record["status"], "failed-contained")
            self.assertGreaterEqual(state["interrupts"].count(turn_ids[0]), 2)
            self.assertEqual(record["interrupt_failed_turn_ids"], [])

    def test_typed_dispatch_validator_rejects_impossible_phases(self) -> None:
        from cwo_core.native_turn_dispatch import TurnDispatchReservation

        prepared = TurnDispatchReservation(
            thread_id="thread-1",
            turn_intent_id=str(uuid.uuid4()),
            request_id=1,
            connection_epoch_sha256="a" * 64,
            notification_cursor=4,
            preexisting_turn_ids=(),
            ledger_id=None,
            ledger_head_entry_sha256=None,
            turn_intent_entry_sha256=None,
            wire_request_sha256="b" * 64,
        ).prepared_record()
        cases = (
            ({"query_count": 2, "absence_verified": True}, "prepared-state"),
            ({"archived": True}, "archive-phase"),
            (
                {
                    "notification_connection_epoch_sha256": "a" * 64,
                    "notification_sequences": [4],
                },
                "notification-sequence-before-cursor",
            ),
            (
                {
                    "status": "failed-contained",
                    "wire_write_attempt_count": 1,
                    "ambiguity_reason": "timeout",
                    "query_count": 2,
                    "absence_verified": True,
                    "ledger_resolution": "verified-absent",
                    "absence_proof_sha256": "c" * 64,
                    "archived": False,
                },
                "contained-proof",
            ),
            (
                {
                    "status": "failed-ambiguous",
                    "wire_write_attempt_count": 1,
                    "ambiguity_reason": "timeout",
                    "discovered_turn_ids": ["turn-1"],
                    "ledger_resolution": "verified-absent",
                    "query_count": 2,
                    "absence_verified": True,
                    "absence_proof_sha256": "c" * 64,
                },
                "verified-absent-resolution",
            ),
            (
                {
                    "status": "failed-ambiguous",
                    "wire_write_attempt_count": 1,
                    "ambiguity_reason": "timeout",
                    "ledger_resolution": "turn-bound",
                },
                "bound-resolution",
            ),
        )
        for updates, expected in cases:
            with self.subTest(expected=expected):
                impossible = {**prepared, **updates}
                findings = LIVE.validate_turn_dispatch_record(impossible)
                self.assertTrue(any(expected in item for item in findings), findings)

    def test_failed_ambiguous_cannot_be_laundered_as_containment_audit(self) -> None:
        from cwo_core.native_live_allocation_ledger import (
            NativeLiveAllocationLedgerStore,
        )
        from tests.test_native_live_allocation_ledger import bindings

        with tempfile.TemporaryDirectory() as temporary:
            ledger = NativeLiveAllocationLedgerStore(Path(temporary) / "ledger")
            ledger.initialize(bindings())
            allocation = ledger.allocation_intent("read-only-0")
            ledger.bind_thread(allocation, "thread-1")
            intent = ledger.turn_intent("thread-1")
            ledger.bind_turn("thread-1", intent, "turn-1")
            ledger.record_lifecycle(
                "thread-1", "archive-observed", "archive-request-accepted"
            )
            with self.assertRaisesRegex(ValueError, "containment-outcome-not-success"):
                ledger.record_containment_audit(
                    "thread-1",
                    outcome="failed-ambiguous",
                    evidence={"archived": True},
                )
            self.assertFalse(ledger.has_successful_containment("thread-1"))

class CalibrationTimingTests(unittest.TestCase):
    def test_guarded_measure_does_not_yield_when_guard_is_disabled(self) -> None:
        clock_ns = [0]
        samples: dict[str, list[float]] = {}

        def action() -> str:
            clock_ns[0] += 1_000_000
            return "done"

        def scheduler_yield(_seconds: float) -> None:
            clock_ns[0] += 250_000_000

        with (
            mock.patch.object(
                LIVE.time, "monotonic_ns", side_effect=lambda: clock_ns[0]
            ),
            mock.patch.object(
                LIVE.time, "sleep", side_effect=scheduler_yield
            ) as sleep,
        ):
            result = LIVE.guarded_measure(
                samples,
                "finalize",
                action,
                guard_seconds=0.0,
            )

        self.assertEqual(result, "done")
        self.assertEqual(samples, {"finalize": [1.0]})
        sleep.assert_not_called()

    def test_measurement_primitive_preserves_enabled_guard(self) -> None:
        clock_ns = [0]

        def action() -> str:
            clock_ns[0] += 1_000_000
            return "done"

        def guarded_sleep(seconds: float) -> None:
            self.assertEqual(seconds, 0.02)
            clock_ns[0] += 20_000_000

        with (
            mock.patch.object(
                LIVE.time, "monotonic_ns", side_effect=lambda: clock_ns[0]
            ),
            mock.patch.object(
                LIVE.time, "sleep", side_effect=guarded_sleep
            ) as sleep,
        ):
            result, elapsed_ms = LIVE._measure_action_ms(
                action,
                guard_seconds=0.02,
            )

        self.assertEqual(result, "done")
        self.assertEqual(elapsed_ms, 21.0)
        sleep.assert_called_once_with(0.02)


class LiveCanaryMaterializationTests(unittest.TestCase):
    def setUp(self) -> None:
        patcher = mock.patch.object(
            LIVE,
            "_measure_action_ms",
            side_effect=deterministic_calibration_measurement,
        )
        patcher.start()
        self.addCleanup(patcher.stop)

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

    def test_final_watermark_failure_prevents_calibration_allocation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            record_dir = root / "records"
            record_dir.mkdir()
            server = FakeCalibrationServer(root)

            def reject_changed_source() -> None:
                raise LIVE.AppServerError("campaign-source-changed-at-final-watermark")

            with self.assertRaisesRegex(
                LIVE.AppServerError,
                "source-changed-at-final-watermark",
            ):
                LIVE.calibration(
                    server,
                    root,
                    record_dir,
                    self.owner(),
                    run_nonce=str(uuid.uuid4()),
                    phase_nonce=str(uuid.uuid4()),
                    pre_allocation_check=reject_changed_source,
                )
            self.assertEqual(server.thread_start_count, 0)
            self.assertEqual(server.turn_start_count, 0)

    def test_functional_calibration_isolated_from_host_artifact_latency(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            record_dir = root / "records"
            record_dir.mkdir()
            server = FakeCalibrationServer(root)
            write_private_artifact = LIVE.write_private_artifact

            def delayed_artifact_write(path: Path, value: Mapping) -> None:
                write_private_artifact(path, value)
                if path.name in {
                    "calibration-mark.json",
                    "calibration-finalize.json",
                }:
                    LIVE.time.sleep(0.11)

            with mock.patch.object(
                LIVE,
                "write_private_artifact",
                side_effect=delayed_artifact_write,
            ):
                receipt, _evidence = LIVE.calibration(
                    server,
                    root,
                    record_dir,
                    self.owner(),
                    run_nonce=str(uuid.uuid4()),
                    phase_nonce=str(uuid.uuid4()),
                )

            self.assertEqual(receipt["validation_outcome"], "accepted")
            self.assertEqual(receipt["callbacks"]["mark_dispatched"]["max_ms"], 50.0)
            self.assertEqual(receipt["callbacks"]["finalize"]["max_ms"], 50.0)
            self.assertEqual(len(server.terminal_containment_calls), 1)
            self.assertRegex(
                server.terminal_containment_calls[0][
                    "terminal_evidence_sha256"
                ],
                r"^[0-9a-f]{64}$",
            )

    def test_one_pre_attestation_internal_read_fault_recovers_in_same_calibration(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            record_dir = root / "records"
            record_dir.mkdir()
            server = FakeCalibrationServer(
                root,
                read_faults={1: ("thread/read", -32603, 137.0)},
                empty_initial_session=True,
            )
            connection_epoch = server.connection_epoch_sha256
            receipt, evidence = LIVE.calibration(
                server,
                root,
                record_dir,
                self.owner(),
                run_nonce=str(uuid.uuid4()),
                phase_nonce=str(uuid.uuid4()),
                materialization_timeout_seconds=3.0,
            )
            telemetry = evidence["thread_read_recovery"]
            self.assertEqual(
                LIVE.validate_calibration_read_recovery_telemetry(telemetry),
                [],
            )
            self.assertEqual(telemetry["outcome"], "recovered")
            self.assertTrue(telemetry["token_consumed"])
            self.assertEqual(telemetry["replacement_attempt_count"], 1)
            self.assertEqual(telemetry["method"], "thread/read")
            self.assertEqual(telemetry["code"], -32603)
            self.assertEqual(telemetry["phase"], "materialization")
            self.assertFalse(telemetry["attestation_observed_at_fault"])
            self.assertEqual(
                telemetry["prior_boundary_sha256"],
                LIVE.sha256_bytes(b""),
            )
            self.assertEqual(telemetry["fault_boundary_record_count"], 0)
            self.assertEqual(telemetry["fault_boundary_byte_offset"], 0)
            self.assertRegex(
                telemetry["prior_source_identity_sha256"], r"^[0-9a-f]{64}$"
            )
            self.assertEqual(
                telemetry["pre_attempt_source_identity_sha256"],
                telemetry["prior_source_identity_sha256"],
            )
            self.assertEqual(
                telemetry["pre_attempt_boundary_sha256"],
                telemetry["prior_boundary_sha256"],
            )
            self.assertEqual(telemetry["pre_attempt_boundary_record_count"], 0)
            self.assertEqual(
                telemetry["pre_attempt_boundary_byte_offset"],
                telemetry["fault_boundary_byte_offset"],
            )
            self.assertEqual(
                evidence["thread_read_recovery_sha256"],
                telemetry["telemetry_sha256"],
            )
            self.assertGreaterEqual(receipt["callbacks"]["check"]["max_ms"], 137.0)
            self.assertEqual(server.thread_start_count, 1)
            self.assertEqual(server.turn_start_count, 1)
            self.assertEqual(server.connection_epoch_sha256, connection_epoch)
            self.assertGreaterEqual(len(server.read_timeouts), 2)
            self.assertTrue(all(0 < timeout <= 3.0 for timeout in server.read_timeouts[:2]))
            retry_gap = server.read_started[1] - server.read_started[0]
            self.assertGreaterEqual(retry_gap, 0.0)
            self.assertLessEqual(retry_gap, LIVE.CALIBRATION_POLL_GAP_MAX_SECONDS)
            self.assertEqual(server.guarded_read_count, 1)
            self.assertEqual(telemetry["wire_dispatch_count"], 1)
            self.assertEqual(telemetry["transport_outcome"], "response-correlated")
            self.assertEqual(
                evidence["materialization_evidence"]["control_observations"][0][
                    "ordinal"
                ],
                0,
            )

            tampered = dict(telemetry)
            tampered["replacement_attempt_count"] = 0
            self.assertTrue(
                LIVE.validate_calibration_read_recovery_telemetry(tampered)
            )
            unknown = dict(telemetry)
            unknown["unexpected"] = True
            self.assertIn(
                "read-recovery-telemetry-fields-invalid",
                LIVE.validate_calibration_read_recovery_telemetry(unknown),
            )

            regressed_count = dict(telemetry)
            regressed_count["pre_attempt_boundary_record_count"] = 2
            regressed_count["telemetry_sha256"] = LIVE.canonical_sha256(
                {
                    key: value
                    for key, value in regressed_count.items()
                    if key != "telemetry_sha256"
                }
            )
            self.assertIn(
                "read-recovery-pre-attempt-boundary-changed",
                LIVE.validate_calibration_read_recovery_telemetry(regressed_count),
            )

            regressed_offset = dict(telemetry)
            regressed_offset["pre_attempt_boundary_byte_offset"] = (
                telemetry["fault_boundary_byte_offset"] - 1
            )
            regressed_offset["telemetry_sha256"] = LIVE.canonical_sha256(
                {
                    key: value
                    for key, value in regressed_offset.items()
                    if key != "telemetry_sha256"
                }
            )
            self.assertIn(
                "read-recovery-pre-attempt-boundary-changed",
                LIVE.validate_calibration_read_recovery_telemetry(regressed_offset),
            )

            changed_source = dict(telemetry)
            changed_source["pre_attempt_source_identity_sha256"] = "f" * 64
            changed_source["telemetry_sha256"] = LIVE.canonical_sha256(
                {
                    key: value
                    for key, value in changed_source.items()
                    if key != "telemetry_sha256"
                }
            )
            self.assertIn(
                "read-recovery-pre-attempt-source-changed",
                LIVE.validate_calibration_read_recovery_telemetry(changed_source),
            )

    def test_read_recovery_rechecks_durable_attestation_at_fault_time(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            record_dir = root / "records"
            record_dir.mkdir()
            server = FakeCalibrationServer(
                root,
                read_faults={1: ("thread/read", -32603, 1.0)},
                materialize_before_fault_read=1,
                empty_initial_session=True,
            )
            with self.assertRaisesRegex(
                LIVE.AppServerError,
                "read-recovery-attestation-observed-at-fault",
            ):
                LIVE.calibration(
                    server,
                    root,
                    record_dir,
                    self.owner(),
                    run_nonce=str(uuid.uuid4()),
                    phase_nonce=str(uuid.uuid4()),
                    materialization_timeout_seconds=3.0,
                )
            self.assertEqual(server.read_count, 1)
            self.assertEqual(server.thread_start_count, 1)
            self.assertEqual(server.turn_start_count, 1)

    def test_read_recovery_rejects_attestation_before_dispatch_and_then_uses_normal_validation(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            record_dir = root / "records"
            record_dir.mkdir()
            server = FakeCalibrationServer(
                root,
                read_faults={1: ("thread/read", -32603, 1.0)},
                empty_initial_session=True,
            )
            materialized = False
            original_guarded_read = server.read_thread_once_with_guard

            def materialize_before_dispatch(*args, **kwargs):
                nonlocal materialized
                if not materialized:
                    server._materialize()
                    materialized = True
                return original_guarded_read(*args, **kwargs)

            with mock.patch.object(
                server,
                "read_thread_once_with_guard",
                side_effect=materialize_before_dispatch,
            ), self.assertRaisesRegex(
                LIVE.AppServerError,
                "attestation-observed-before-dispatch",
            ):
                LIVE.calibration(
                    server,
                    root,
                    record_dir,
                    self.owner(),
                    run_nonce=str(uuid.uuid4()),
                    phase_nonce=str(uuid.uuid4()),
                    materialization_timeout_seconds=3.0,
                )
            self.assertEqual(server.read_count, 1)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            record_dir = root / "records"
            record_dir.mkdir()
            server = FakeCalibrationServer(
                root,
                read_faults={1: ("thread/read", -32603, 1.0)},
                materialize_before_read=2,
                empty_initial_session=True,
            )
            original_materialize = server._materialize
            materialized_once = False

            def materialize_once() -> None:
                nonlocal materialized_once
                if materialized_once:
                    return
                materialized_once = True
                original_materialize()

            server._materialize = materialize_once  # type: ignore[method-assign]
            receipt, evidence = LIVE.calibration(
                server,
                root,
                record_dir,
                self.owner(),
                run_nonce=str(uuid.uuid4()),
                phase_nonce=str(uuid.uuid4()),
                materialization_timeout_seconds=3.0,
            )
            self.assertEqual(receipt["validation_outcome"], "accepted")
            self.assertEqual(
                evidence["thread_read_recovery"]["outcome"], "recovered"
            )
            self.assertEqual(server.guarded_read_count, 1)

    def test_read_recovery_is_single_use_pre_attestation_and_exact_error_only(self) -> None:
        cases = (
            (
                {
                    "read_faults": {
                        1: ("thread/read", -32603, 1.0),
                        2: ("thread/read", -32603, 1.0),
                    },
                    "empty_initial_session": True,
                },
                2,
                "app-server-request-failed:thread/read:-32603",
            ),
            (
                {"read_faults": {1: ("thread/read", -32600, 1.0)}},
                1,
                "app-server-request-failed:thread/read:-32600",
            ),
            (
                {"read_faults": {1: ("thread/list", -32603, 1.0)}},
                1,
                "app-server-request-failed:thread/list:-32603",
            ),
            (
                {"read_faults": {4: ("thread/read", -32603, 1.0)}},
                4,
                "app-server-request-failed:thread/read:-32603",
            ),
        )
        for options, expected_reads, expected in cases:
            with self.subTest(options=options), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                record_dir = root / "records"
                record_dir.mkdir()
                server = FakeCalibrationServer(root, **options)
                with self.assertRaisesRegex(
                    LIVE.AppServerRpcError, expected
                ) as caught:
                    LIVE.calibration(
                        server,
                        root,
                        record_dir,
                        self.owner(),
                        run_nonce=str(uuid.uuid4()),
                        phase_nonce=str(uuid.uuid4()),
                        materialization_timeout_seconds=3.0,
                    )
                self.assertEqual(server.read_count, expected_reads)
                self.assertEqual(server.thread_start_count, 1)
                self.assertEqual(server.turn_start_count, 1)
                if expected_reads == 2:
                    fault = getattr(
                        caught.exception, "first_protected_fault", None
                    )
                    self.assertIsInstance(fault, dict)
                    self.assertEqual(
                        fault["fault_type"],
                        "calibration-thread-read-recovery",
                    )
                    self.assertEqual(
                        fault["recovery_telemetry"]["wire_dispatch_count"], 1
                    )

    def test_read_recovery_rejects_epoch_drift_and_workspace_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            record_dir = root / "records"
            record_dir.mkdir()
            server = FakeCalibrationServer(
                root,
                read_faults={1: ("thread/read", -32603, 1.0)},
                empty_initial_session=True,
            )
            original_guarded_read = server.read_thread_once_with_guard

            def drift_epoch(*args, **kwargs):
                server.connection_epoch_sha256 = "c" * 64
                return original_guarded_read(*args, **kwargs)

            with mock.patch.object(
                server,
                "read_thread_once_with_guard",
                side_effect=drift_epoch,
            ), self.assertRaisesRegex(
                LIVE.AppServerError,
                "read-recovery-predispatch-state-invalid",
            ) as caught:
                LIVE.calibration(
                    server,
                    root,
                    record_dir,
                    self.owner(),
                    run_nonce=str(uuid.uuid4()),
                    phase_nonce=str(uuid.uuid4()),
                    materialization_timeout_seconds=3.0,
                )
            self.assertEqual(server.read_count, 1)
            self.assertIsInstance(
                getattr(caught.exception, "first_protected_fault", None), dict
            )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workspace = root / "workspace"
            workspace.mkdir()
            subprocess.run(["git", "init", "-q"], cwd=workspace, check=True)
            subprocess.run(
                ["git", "config", "user.name", "CWO Test"],
                cwd=workspace,
                check=True,
            )
            subprocess.run(
                ["git", "config", "user.email", "cwo@example.invalid"],
                cwd=workspace,
                check=True,
            )
            (workspace / "tracked.txt").write_text("baseline\n", encoding="utf-8")
            subprocess.run(["git", "add", "."], cwd=workspace, check=True)
            subprocess.run(
                ["git", "commit", "-qm", "baseline"],
                cwd=workspace,
                check=True,
            )
            record_dir = root / "records"
            record_dir.mkdir()
            server = FakeCalibrationServer(
                root,
                read_faults={1: ("thread/read", -32603, 1.0)},
                empty_initial_session=True,
            )
            original_guarded_read = server.read_thread_once_with_guard

            def mutate_workspace(*args, **kwargs):
                (workspace / "mutation.txt").write_text(
                    "unexpected\n", encoding="utf-8"
                )
                return original_guarded_read(*args, **kwargs)

            with mock.patch.object(
                server,
                "read_thread_once_with_guard",
                side_effect=mutate_workspace,
            ), self.assertRaisesRegex(
                LIVE.AppServerError,
                "read-recovery-workspace-mutated-before-dispatch",
            ) as caught:
                LIVE.calibration(
                    server,
                    workspace,
                    record_dir,
                    self.owner(),
                    run_nonce=str(uuid.uuid4()),
                    phase_nonce=str(uuid.uuid4()),
                    materialization_timeout_seconds=3.0,
                )
            fault = caught.exception.first_protected_fault
            self.assertTrue(
                fault["recovery_telemetry"]["workspace_mutation_observed"]
            )
            self.assertEqual(server.read_count, 1)

    def test_read_recovery_rejects_late_precheck_and_post_attempt(self) -> None:
        cases = (
            (
                {
                    "read_faults": {1: ("thread/read", -32603, 1.0)},
                    "read_delays": {1: 0.26},
                    "empty_initial_session": True,
                },
                1,
            ),
            (
                {
                    "read_faults": {1: ("thread/read", -32603, 1.0)},
                    "read_delays": {2: 0.26},
                    "empty_initial_session": True,
                },
                2,
            ),
        )
        for options, expected_reads in cases:
            with self.subTest(options=options), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                record_dir = root / "records"
                record_dir.mkdir()
                server = FakeCalibrationServer(root, **options)
                with self.assertRaisesRegex(
                    LIVE.AppServerError,
                    "capability-poll-interval-exceeded",
                ):
                    LIVE.calibration(
                        server,
                        root,
                        record_dir,
                        self.owner(),
                        run_nonce=str(uuid.uuid4()),
                        phase_nonce=str(uuid.uuid4()),
                        materialization_timeout_seconds=2.0,
                    )
                self.assertEqual(server.read_count, expected_reads)

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
            recovery = evidence["thread_read_recovery"]
            self.assertEqual(recovery["outcome"], "not-needed")
            self.assertFalse(recovery["token_consumed"])
            self.assertEqual(recovery["replacement_attempt_count"], 0)
            self.assertEqual(
                LIVE.validate_calibration_read_recovery_telemetry(recovery),
                [],
            )
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
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            server, ledger, _state, writer, thread_id, _turn_ids = (
                AmbiguousTurnDispatchTests().server(root, "normal")
            )
            server.start_turn(thread_id, "bounded")
            events = [entry["event"] for entry in ledger.load()["entries"]]
            self.assertEqual(
                events,
                ["allocation-intent", "thread-bound", "turn-intent", "turn-bound"],
            )
            self.assertEqual(len(writer.payloads), 1)
            self.assertEqual(
                writer.payloads[0]["params"]["clientUserMessageId"],
                ledger.load()["entries"][2]["turn_intent_id"],
            )

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

    def test_archive_observation_alone_never_proves_containment(self) -> None:
        from cwo_core.native_live_allocation_ledger import (
            NativeLiveAllocationLedgerStore,
        )
        from tests.test_native_live_allocation_ledger import bindings

        class ArchiveOnlyServer:
            def __init__(self, ledger: NativeLiveAllocationLedgerStore) -> None:
                self.allocation_ledger = ledger
                self.started_threads = {"thread-1": "turn-1"}

            @staticmethod
            def read_thread(_thread_id: str):
                raise LIVE.AppServerError("thread already archived")

        with tempfile.TemporaryDirectory() as temporary:
            ledger = NativeLiveAllocationLedgerStore(Path(temporary) / "ledger")
            ledger.initialize(bindings())
            allocation = ledger.allocation_intent("read-only-0")
            ledger.bind_thread(allocation, "thread-1")
            intent = ledger.turn_intent("thread-1")
            ledger.bind_turn("thread-1", intent, "turn-1")
            ledger.record_lifecycle(
                "thread-1", "archive-observed", "archive-request-accepted"
            )
            result = LIVE.contain_started_threads(ArchiveOnlyServer(ledger))
            self.assertFalse(result["all_contained"])
            self.assertEqual(result["ambiguous_count"], 1)
            self.assertEqual(result["already_contained_count"], 0)

    def test_unresolved_turn_intent_is_counted_as_containment_ambiguity(self) -> None:
        from cwo_core.native_live_allocation_ledger import (
            NativeLiveAllocationLedgerStore,
        )
        from tests.test_native_live_allocation_ledger import bindings

        class PendingTurnServer:
            def __init__(self, ledger: NativeLiveAllocationLedgerStore) -> None:
                self.allocation_ledger = ledger
                self.started_threads = {"thread-1": None}

            @staticmethod
            def read_thread(_thread_id: str):
                return {"id": "thread-1", "turns": []}, 0.1

            def archive_thread(self, thread_id: str):
                self.allocation_ledger.record_lifecycle(
                    thread_id, "archive-observed", "archive-request-accepted"
                )
                return 0.1

        with tempfile.TemporaryDirectory() as temporary:
            ledger = NativeLiveAllocationLedgerStore(Path(temporary) / "ledger")
            ledger.initialize(bindings())
            allocation = ledger.allocation_intent("read-only-0")
            ledger.bind_thread(allocation, "thread-1")
            ledger.turn_intent("thread-1")
            result = LIVE.contain_started_threads(PendingTurnServer(ledger))
            self.assertFalse(result["all_contained"])
            self.assertEqual(result["unresolved_turn_intent_count"], 1)
            self.assertEqual(result["ambiguous_count"], 1)

    def test_unresolved_thread_start_intent_is_containment_ambiguity(self) -> None:
        from cwo_core.native_live_allocation_ledger import (
            NativeLiveAllocationLedgerStore,
        )
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
    @staticmethod
    def complete_turn(
        server: FakeLiveThreadServer,
        *,
        token: str = "DONE",
        trusted_tool_calls: int = 0,
        projected_tool_calls: int = 0,
    ) -> None:
        records: list[dict] = []
        for index in range(trusted_tool_calls):
            call_id = f"trusted-call-{index}"
            records.extend(
                [
                    {
                        "type": "response_item",
                        "payload": {
                            "type": "function_call",
                            "name": "exec_command",
                            "call_id": call_id,
                            "arguments": json.dumps({"cmd": f"rg evidence-{index}"}),
                        },
                    },
                    {
                        "type": "response_item",
                        "payload": {
                            "type": "function_call_output",
                            "call_id": call_id,
                            "exit_code": 0,
                            "output": "bounded",
                        },
                    },
                ]
            )
        records.append(
            {
                "type": "event_msg",
                "payload": {
                    "type": "task_complete",
                    "turn_id": server.turn_id,
                },
            }
        )
        with server.path.open("a", encoding="utf-8") as stream:
            stream.write("".join(json.dumps(record) + "\n" for record in records))
        server.items = [
            {
                "type": "commandExecution",
                "status": "completed",
            }
            for _ in range(projected_tool_calls)
        ] + [
            {
                "type": "agentMessage",
                "phase": "finalAnswer",
                "text": token,
            }
        ]
        server.status = "completed"

    def test_porcelain_mutation_paths_preserve_status_columns(self) -> None:
        self.assertEqual(
            LIVE.porcelain_mutation_paths(
                " M targets/child_1.txt\n"
                "M  targets/staged.txt\n"
                "R  targets/old.txt -> targets/new.txt\n"
                '?? "targets/quoted name.txt"\n'
            ),
            [
                "targets/child_1.txt",
                "targets/new.txt",
                "targets/quoted name.txt",
                "targets/staged.txt",
            ],
        )

    def test_porcelain_mutation_paths_reject_partial_or_malformed_records(self) -> None:
        with self.assertRaisesRegex(
            LIVE.AppServerError, "workspace-status-trailing-partial"
        ):
            LIVE.porcelain_mutation_paths(" M targets/child_1.txt")
        with self.assertRaisesRegex(
            LIVE.AppServerError, "workspace-status-record-invalid"
        ):
            LIVE.porcelain_mutation_paths("M targets/child_1.txt\n")

    def test_workspace_mutations_use_unstripped_porcelain_output(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            clock = FakeMonotonicClock()
            server = FakeLiveThreadServer(root)
            adapter = self.adapter(root, server, clock)
            completed = subprocess.CompletedProcess(
                args=["git", "status"],
                returncode=0,
                stdout=" M targets/child_1.txt\n",
                stderr="",
            )
            with mock.patch.object(LIVE.subprocess, "run", return_value=completed) as run:
                self.assertEqual(
                    adapter._workspace_mutations(), ["targets/child_1.txt"]
                )
            self.assertEqual(run.call_args.kwargs["cwd"], root)

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

    def test_trusted_tool_evidence_is_scoped_to_the_exact_turn(self) -> None:
        prior_turn = "prior-turn"
        current_turn = "current-turn"
        records = [
            {"type": "turn_context", "payload": {"turn_id": prior_turn}},
            {
                "type": "response_item",
                "payload": {
                    "type": "function_call",
                    "name": "exec_command",
                    "call_id": "prior-call",
                    "arguments": json.dumps({"cmd": "rg stale"}),
                },
            },
            {
                "type": "response_item",
                "payload": {
                    "type": "function_call_output",
                    "call_id": "prior-call",
                    "exit_code": 0,
                    "output": "stale",
                },
            },
            {"type": "turn_context", "payload": {"turn_id": current_turn}},
            {
                "type": "event_msg",
                "payload": {"type": "task_complete", "turn_id": current_turn},
            },
        ]
        summary = LIVE.trusted_tool_evidence_summary(
            records,
            turn_id=current_turn,
            terminal_event={"record_index": 4},
        )
        self.assertEqual(summary["trusted_tool_calls"], 0)
        self.assertEqual(summary["trusted_completed_tool_calls"], 0)
        self.assertEqual(summary["trusted_tool_evidence_sha256"], [])

    def test_trusted_tool_evidence_quarantines_receipt_grammar_anomalies(
        self,
    ) -> None:
        cases = (
            (
                "paired",
                [
                    {
                        "type": "response_item",
                        "payload": {
                            "type": "function_call",
                            "name": "exec_command",
                            "call_id": "call-1",
                            "arguments": json.dumps({"cmd": "rg bounded"}),
                        },
                    },
                    {
                        "type": "response_item",
                        "payload": {
                            "type": "function_call_output",
                            "call_id": "call-1",
                            "exit_code": 0,
                            "output": "bounded",
                        },
                    },
                ],
                "exec_command",
                1,
            ),
            (
                "unpaired-call",
                [
                    {
                        "type": "response_item",
                        "payload": {
                            "type": "function_call",
                            "name": "exec_command",
                            "call_id": "call-1",
                            "arguments": json.dumps({"cmd": "rg bounded"}),
                        },
                    }
                ],
                "exec_command",
                0,
            ),
            (
                "unpaired-output",
                [
                    {
                        "type": "response_item",
                        "payload": {
                            "type": "function_call_output",
                            "call_id": "call-1",
                            "exit_code": 0,
                            "output": "bounded",
                        },
                    }
                ],
                "telemetry_anomaly.unknown",
                0,
            ),
            (
                "duplicate-call-id",
                [
                    {
                        "type": "response_item",
                        "payload": {
                            "type": "function_call",
                            "name": "exec_command",
                            "call_id": "call-1",
                            "arguments": json.dumps({"cmd": "rg bounded"}),
                        },
                    },
                    {
                        "type": "response_item",
                        "payload": {
                            "type": "function_call",
                            "name": "exec_command",
                            "call_id": "call-1",
                            "arguments": json.dumps({"cmd": "rg spoofed"}),
                        },
                    },
                    {
                        "type": "response_item",
                        "payload": {
                            "type": "function_call_output",
                            "call_id": "call-1",
                            "exit_code": 0,
                            "output": "bounded",
                        },
                    },
                ],
                "telemetry_anomaly.exec_command",
                0,
            ),
            (
                "duplicate-output",
                [
                    {
                        "type": "response_item",
                        "payload": {
                            "type": "function_call",
                            "name": "exec_command",
                            "call_id": "call-1",
                            "arguments": json.dumps({"cmd": "rg bounded"}),
                        },
                    },
                    {
                        "type": "response_item",
                        "payload": {
                            "type": "function_call_output",
                            "call_id": "call-1",
                            "exit_code": 0,
                            "output": "bounded",
                        },
                    },
                    {
                        "type": "response_item",
                        "payload": {
                            "type": "function_call_output",
                            "call_id": "call-1",
                            "exit_code": 0,
                            "output": "spoofed",
                        },
                    },
                ],
                "telemetry_anomaly.exec_command",
                0,
            ),
        )
        for label, events, expected_tool, completed in cases:
            with self.subTest(label=label):
                records = [
                    {
                        "type": "turn_context",
                        "payload": {"turn_id": "current-turn"},
                    },
                    *events,
                    {
                        "type": "event_msg",
                        "payload": {
                            "type": "task_complete",
                            "turn_id": "current-turn",
                        },
                    },
                ]
                summary = LIVE.trusted_tool_evidence_summary(
                    records,
                    turn_id="current-turn",
                    terminal_event={"record_index": len(records) - 1},
                )
                self.assertEqual(summary["trusted_tool_calls"], 1)
                self.assertEqual(
                    summary["trusted_completed_tool_calls"], completed
                )
                self.assertEqual(summary["trusted_tool_names"], [expected_tool])

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

    def test_effective_tool_surface_expansion_blocks_turn_dispatch(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            server = FakeLiveThreadServer(root)
            reads = 0

            def surface(*, permitted_tools: list[str]) -> dict:
                nonlocal reads
                reads += 1
                effective = list(permitted_tools)
                if reads > 1:
                    effective.append("spawn_agent")
                    effective.sort()
                return {
                    "source": "supported-test-server",
                    "server_allowlist_supported": True,
                    "allowlist_parameter": "tools",
                    "effective_allowlist": effective,
                }

            server.tool_surface_capability = surface
            adapter = self.adapter(root, server, FakeMonotonicClock())
            with self.assertRaisesRegex(LIVE.AppServerError, "tool-surface-expanded"):
                adapter.send_input(message="bounded prompt")
            self.assertIsNone(server.started_threads[server.thread_id])
            self.assertEqual(adapter._boundary_phase, "pre-dispatch")

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

    def test_acknowledged_turn_is_not_read_before_exact_started_notification(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            clock = FakeMonotonicClock()
            server = FakeLiveThreadServer(root, initial_boundary="missing")
            adapter = self.adapter(root, server, clock)
            adapter.send_input(message="bounded prompt")
            with mock.patch.object(
                server,
                "read_thread",
                side_effect=AssertionError("thread/read raced turn/started"),
            ) as read_thread, mock.patch.object(
                adapter, "_workspace_mutations", return_value=[]
            ):
                evidence = adapter.evidence()
            read_thread.assert_not_called()
            self.assertEqual(
                evidence["session_disposition"], "accepted-with-warning"
            )
            self.assertEqual(
                adapter._capture_trusted_boundary(allow_pending=True)[
                    "observation_type"
                ],
                "post-submission-turn-start-pending-nonattesting",
            )

    def test_only_exact_turn_started_notification_unlocks_thread_read(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            clock = FakeMonotonicClock()
            server = FakeLiveThreadServer(root, initial_boundary="missing")
            adapter = self.adapter(root, server, clock)
            adapter.send_input(message="bounded prompt")
            notifications = [
                {
                    "method": "turn/started",
                    "params": {
                        "threadId": server.thread_id,
                        "turn": {"id": str(uuid.uuid4())},
                    },
                }
            ]
            server.notifications = lambda _thread_id, _method=None: notifications
            with mock.patch.object(server, "read_thread", wraps=server.read_thread) as read_thread:
                boundary = adapter._capture_trusted_boundary(allow_pending=True)
                read_thread.assert_not_called()
                notifications[0]["params"]["turn"]["id"] = server.turn_id
                boundary = adapter._capture_trusted_boundary(allow_pending=True)
            self.assertEqual(read_thread.call_count, 2)
            self.assertEqual(
                boundary["observation_type"],
                "post-submission-unmaterialized-nonattesting-nonaccepting",
            )

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

    def test_exact_token_with_zero_trusted_tools_is_interrupted_and_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            server = FakeLiveThreadServer(root, initial_boundary="valid")
            adapter = self.adapter(root, server, FakeMonotonicClock())
            adapter.send_input(message="bounded prompt")
            self.complete_turn(server)
            self.assertEqual(adapter.check(), {"decision": "interrupt"})
            with mock.patch.object(adapter, "_workspace_mutations", return_value=[]):
                evidence = adapter.evidence()
                summary = adapter._trusted_summary()
            self.assertEqual(evidence["usage"]["tool_calls"], 0)
            self.assertEqual(summary["projected_tool_calls"], 0)
            self.assertEqual(
                evidence["reasons"],
                [
                    "zero-tool-completion",
                    "premature-completion",
                    "required-evidence-missing",
                ],
            )
            self.assertTrue(evidence["protected_fault"])
            self.assertEqual(evidence["artifact_disposition"], "rejected")

    def test_exact_token_after_trusted_tool_evidence_is_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            server = FakeLiveThreadServer(root, initial_boundary="valid")
            adapter = self.adapter(root, server, FakeMonotonicClock())
            adapter.send_input(message="bounded prompt")
            self.complete_turn(server, trusted_tool_calls=1)
            self.assertEqual(adapter.check(), {"decision": "complete"})
            with mock.patch.object(adapter, "_workspace_mutations", return_value=[]):
                evidence = adapter.evidence()
            self.assertEqual(evidence["usage"]["tool_calls"], 1)
            self.assertEqual(evidence["reasons"], [])
            self.assertFalse(evidence["protected_fault"])
            self.assertEqual(evidence["artifact_disposition"], "accepted")

    def test_projected_tool_without_trusted_receipt_interrupts_temporary_operative(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            server = FakeLiveThreadServer(root, initial_boundary="valid")
            _manifest, override = temporary_tool_override_fixture()
            policy = LIVE.default_tool_policy(
                mutable=False,
                enforcement_override=override,
            )
            adapter = LIVE.LiveThreadAdapter(
                server,
                server.thread_response(),
                prompt="bounded prompt",
                expected_token="DONE",
                worktree=root,
                mutable=False,
                expected_mutation=None,
                tool_policy=policy,
                record_dir=root,
                monotonic_ns=FakeMonotonicClock(),
            )
            adapter.send_input(message="bounded prompt")
            self.complete_turn(
                server,
                trusted_tool_calls=1,
                projected_tool_calls=2,
            )
            self.assertEqual(adapter.check(), {"decision": "interrupt"})
            adapter.interrupt()
            with mock.patch.object(
                adapter, "_workspace_mutations", return_value=[]
            ):
                evidence = adapter.evidence()
                summary = adapter.final_summary()
            self.assertIn("forbidden-tool-activity", evidence["reasons"])
            self.assertEqual(
                summary["forbidden_tool_activity"][0]["tool"],
                "telemetry_anomaly.missing_call_receipt",
            )

    def test_terminal_unpaired_call_interrupts_temporary_operative(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            server = FakeLiveThreadServer(root, initial_boundary="valid")
            _manifest, override = temporary_tool_override_fixture()
            policy = LIVE.default_tool_policy(
                mutable=False,
                enforcement_override=override,
            )
            adapter = LIVE.LiveThreadAdapter(
                server,
                server.thread_response(),
                prompt="bounded prompt",
                expected_token="DONE",
                worktree=root,
                mutable=False,
                expected_mutation=None,
                tool_policy=policy,
                record_dir=root,
                monotonic_ns=FakeMonotonicClock(),
            )
            adapter.send_input(message="bounded prompt")
            with server.path.open("a", encoding="utf-8") as stream:
                stream.write(
                    json.dumps(
                        {
                            "type": "response_item",
                            "payload": {
                                "type": "function_call",
                                "name": "exec_command",
                                "call_id": "incomplete-call",
                                "arguments": json.dumps({"cmd": "rg bounded"}),
                            },
                        }
                    )
                    + "\n"
                )
                stream.write(
                    json.dumps(
                        {
                            "type": "event_msg",
                            "payload": {
                                "type": "task_complete",
                                "turn_id": server.turn_id,
                            },
                        }
                    )
                    + "\n"
                )
            server.items = [
                {"type": "commandExecution", "status": "completed"},
                {
                    "type": "agentMessage",
                    "phase": "finalAnswer",
                    "text": "DONE",
                },
            ]
            server.status = "completed"
            self.assertEqual(adapter.check(), {"decision": "interrupt"})
            with mock.patch.object(
                adapter, "_workspace_mutations", return_value=[]
            ):
                evidence = adapter.evidence()
                summary = adapter.final_summary()
            self.assertIn("forbidden-tool-activity", evidence["reasons"])
            self.assertEqual(
                summary["forbidden_tool_activity"][0]["tool"],
                "telemetry_anomaly.exec_command",
            )

    def test_unpermitted_trusted_tool_activity_interrupts_and_is_classified(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            server = FakeLiveThreadServer(root, initial_boundary="valid")
            adapter = self.adapter(root, server, FakeMonotonicClock())
            adapter.send_input(message="bounded prompt")
            with server.path.open("a", encoding="utf-8") as stream:
                stream.write(
                    json.dumps(
                        {
                            "type": "response_item",
                            "payload": {
                                "type": "function_call",
                                "name": "spawn_agent",
                                "call_id": "forbidden-call",
                                "arguments": json.dumps({"task": "escape"}),
                            },
                        }
                    )
                    + "\n"
                )
            self.assertEqual(adapter.check(), {"decision": "interrupt"})
            adapter.interrupt()
            with mock.patch.object(adapter, "_workspace_mutations", return_value=[]):
                evidence = adapter.evidence()
                summary = adapter.final_summary()
            self.assertIn("forbidden-tool-activity", evidence["reasons"])
            self.assertTrue(evidence["protected_fault"])
            self.assertEqual(
                summary["forbidden_tool_activity"][0]["tool"], "spawn_agent"
            )
            self.assertEqual(
                summary["tool_policy"]["permitted_tools"],
                ["exec_command", "write_stdin"],
            )
            self.assertIsNone(summary["override_provenance"])

    def test_call_shaped_unknown_tool_activity_is_detected_from_trusted_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            server = FakeLiveThreadServer(root, initial_boundary="valid")
            adapter = self.adapter(root, server, FakeMonotonicClock())
            adapter.send_input(message="bounded prompt")
            with server.path.open("a", encoding="utf-8") as stream:
                stream.write(
                    json.dumps(
                        {
                            "type": "response_item",
                            "payload": {
                                "type": "web_search_call",
                                "name": "exec_command",
                                "id": "search-1",
                                "query": "out of contract",
                            },
                        }
                    )
                    + "\n"
                )
            self.assertEqual(adapter.check(), {"decision": "interrupt"})
            adapter.interrupt()
            with mock.patch.object(adapter, "_workspace_mutations", return_value=[]):
                summary = adapter.final_summary()
            self.assertEqual(
                summary["forbidden_tool_activity"][0]["tool"],
                "web_search_call",
            )
            self.assertNotIn("out of contract", json.dumps(summary))

    def test_required_tool_evidence_hash_must_match_trusted_receipt(self) -> None:
        for matching in (True, False):
            with self.subTest(matching=matching), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                server = FakeLiveThreadServer(root, initial_boundary="valid")
                records = [
                    {
                        "type": "turn_context",
                        "payload": {"turn_id": server.turn_id},
                    },
                    {
                        "type": "response_item",
                        "payload": {
                            "type": "function_call",
                            "name": "exec_command",
                            "call_id": "trusted-call-0",
                            "arguments": json.dumps({"cmd": "rg evidence-0"}),
                        },
                    },
                    {
                        "type": "response_item",
                        "payload": {
                            "type": "function_call_output",
                            "call_id": "trusted-call-0",
                            "exit_code": 0,
                            "output": "bounded",
                        },
                    },
                    {
                        "type": "event_msg",
                        "payload": {
                            "type": "task_complete",
                            "turn_id": server.turn_id,
                        },
                    },
                ]
                receipt_hash = LIVE.trusted_tool_evidence_summary(
                    records,
                    turn_id=server.turn_id,
                    terminal_event={"record_index": 3},
                )["trusted_tool_evidence_sha256"][0]
                policy = LIVE.default_completion_evidence_policy(
                    "read-only-shared"
                )
                policy["required_evidence"]["sha256"] = [
                    receipt_hash if matching else "0" * 64
                ]
                adapter = LIVE.LiveThreadAdapter(
                    server,
                    server.thread_response(),
                    prompt="bounded prompt",
                    expected_token="DONE",
                    worktree=root,
                    mutable=False,
                    expected_mutation=None,
                    completion_evidence_policy=policy,
                    record_dir=root,
                    monotonic_ns=FakeMonotonicClock(),
                )
                adapter.send_input(message="bounded prompt")
                self.complete_turn(server, trusted_tool_calls=1)
                self.assertEqual(
                    adapter.check(),
                    {"decision": "complete" if matching else "interrupt"},
                )
                with mock.patch.object(
                    adapter, "_workspace_mutations", return_value=[]
                ):
                    evidence = adapter.evidence()
                self.assertEqual(
                    evidence["artifact_disposition"],
                    "accepted" if matching else "rejected",
                )
                self.assertEqual(
                    "required-evidence-missing" in evidence["reasons"],
                    not matching,
                )

    def test_explicit_empty_completion_policy_is_not_defaulted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            server = FakeLiveThreadServer(root, initial_boundary="valid")
            with self.assertRaisesRegex(
                LIVE.AppServerError,
                "completion-evidence-policy-invalid",
            ):
                LIVE.LiveThreadAdapter(
                    server,
                    server.thread_response(),
                    prompt="bounded prompt",
                    expected_token="DONE",
                    worktree=root,
                    mutable=False,
                    expected_mutation=None,
                    completion_evidence_policy={},
                    record_dir=root,
                    monotonic_ns=FakeMonotonicClock(),
                )

    def test_projected_or_self_reported_tool_count_cannot_replace_session_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            server = FakeLiveThreadServer(root, initial_boundary="valid")
            adapter = self.adapter(root, server, FakeMonotonicClock())
            adapter.send_input(message="bounded prompt")
            self.complete_turn(server, projected_tool_calls=7)
            self.assertEqual(adapter.check(), {"decision": "interrupt"})
            with mock.patch.object(adapter, "_workspace_mutations", return_value=[]):
                evidence = adapter.evidence()
                summary = adapter._trusted_summary()
            self.assertEqual(summary["projected_tool_calls"], 7)
            self.assertEqual(evidence["usage"]["tool_calls"], 0)
            self.assertIn("zero-tool-completion", evidence["reasons"])

    def test_explicit_read_only_tool_free_policy_is_narrowly_accepted(self) -> None:
        policy = {
            "minimum_tool_calls": 0,
            "required_evidence": {
                "predicates": [
                    "read-only-workspace-clean",
                    "trusted-terminal-boundary",
                ],
                "sha256": [],
            },
            "allow_zero_tool_completion": True,
            "expected_mutation_mode": "read-only",
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            server = FakeLiveThreadServer(root, initial_boundary="valid")
            adapter = LIVE.LiveThreadAdapter(
                server,
                server.thread_response(),
                prompt="bounded prompt",
                expected_token="DONE",
                worktree=root,
                mutable=False,
                expected_mutation=None,
                completion_evidence_policy=policy,
                record_dir=root,
                monotonic_ns=FakeMonotonicClock(),
            )
            adapter.send_input(message="bounded prompt")
            self.complete_turn(server)
            self.assertEqual(adapter.check(), {"decision": "complete"})
            with mock.patch.object(adapter, "_workspace_mutations", return_value=[]):
                evidence = adapter.evidence()
            self.assertEqual(evidence["reasons"], [])
            self.assertEqual(evidence["artifact_disposition"], "accepted")

    def test_mutable_completion_without_expected_mutation_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            server = FakeLiveThreadServer(root, initial_boundary="valid")
            adapter = LIVE.LiveThreadAdapter(
                server,
                server.thread_response(),
                prompt="bounded prompt",
                expected_token="DONE",
                worktree=root,
                mutable=True,
                expected_mutation="targets/child_0.txt",
                record_dir=root,
                monotonic_ns=FakeMonotonicClock(),
            )
            adapter.send_input(message="bounded prompt")
            self.complete_turn(server, trusted_tool_calls=1)
            self.assertEqual(adapter.check(), {"decision": "complete"})
            with mock.patch.object(adapter, "_workspace_mutations", return_value=[]):
                evidence = adapter.evidence()
            self.assertIn("required-evidence-missing", evidence["reasons"])
            self.assertIn(
                "mutable-workspace-attribution-mismatch",
                evidence["reasons"],
            )
            self.assertEqual(evidence["artifact_disposition"], "rejected")

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
    def test_uuid_aliases_reject_before_control_key_derivation(self) -> None:
        self.assertTrue(LIVE._valid_uuid_text(CANONICAL_UUID_TEXT))
        self.assertTrue(CAMPAIGN_CONTRACTS._is_uuid(CANONICAL_UUID_TEXT))
        for alias in UUID_TEXT_ALIASES:
            with self.subTest(alias=repr(alias)):
                self.assertFalse(LIVE._valid_uuid_text(alias))
                self.assertFalse(CAMPAIGN_CONTRACTS._is_uuid(alias))
                self.assertEqual(
                    CAMPAIGN_CONTRACTS._is_parseable_uuid(alias),
                    alias in PARSEABLE_UUID_ALIASES,
                )
                with tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    with self.assertRaisesRegex(
                        LIVE.AppServerError,
                        "campaign-global-claim-marker-identity-invalid",
                    ):
                        LIVE._claim_identifier_marker_path(
                            root, "authorization", alias
                        )
                    with self.assertRaisesRegex(
                        LIVE.AppServerError, "active-outer-authority-id-invalid"
                    ):
                        LIVE._authority_history_path(root, "scope", alias)
                    self.assertEqual(list(root.iterdir()), [])

    def test_legacy_claim_migration_quarantines_uuid_aliases(self) -> None:
        for alias in UUID_TEXT_ALIASES:
            with self.subTest(alias=repr(alias)), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                root.chmod(0o700)
                identity = {
                    "authorization_id": alias,
                    "run_generation": 20,
                    "live_generation": 8,
                    "campaign_nonce": str(uuid.uuid4()),
                }
                claim = {
                    "claim_type": "cwo-native-live-campaign-global-claim",
                    "version": 1,
                    "identity": identity,
                    "identity_sha256": LIVE.domain_sha256(
                        identity, domain="native-live-global-claim"
                    ),
                    "launch_claim_sha256": "a" * 64,
                    "outer_authority_id": str(uuid.uuid4()),
                    "candidate_commit": "b" * 40,
                    "candidate_tree": "c" * 40,
                    "output_paths": {
                        "evidence": "/tmp/evidence",
                        "authorization_state": "/tmp/state",
                        "steering_registry": "/tmp/steering",
                        "allocation_ledger": "/tmp/ledger",
                    },
                    "claimed_at": "2026-07-17T00:00:00Z",
                }
                claim["canonical_claim_sha256"] = LIVE.domain_sha256(
                    claim, domain="native-live-global-claim-artifact"
                )
                path = root / "legacy.json"
                path.write_text(json.dumps(claim), encoding="utf-8")
                path.chmod(0o600)
                with self.assertRaisesRegex(
                    LIVE.AppServerError,
                    "campaign-global-claim-registry-entry-invalid",
                ):
                    LIVE._migrate_global_claim_markers(root)
                self.assertEqual([item.name for item in root.iterdir()], ["legacy.json"])

    def test_launcher_root_is_repository_root(self) -> None:
        self.assertEqual(LIVE.ROOT, ROOT)

    def test_pool_prompt_and_unsupported_operative_policy_fail_before_allocation(self) -> None:
        class NoThreadStartServer:
            def __init__(self) -> None:
                self.starts = 0

            def start_thread(self, *_args, **_kwargs):
                self.starts += 1
                raise AssertionError("tool preflight must precede allocation")

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            server = NoThreadStartServer()
            checks: list[str] = []
            with self.assertRaisesRegex(LIVE.AppServerError, "prompt-trigger-conflict"):
                LIVE.build_pool_inputs(
                    server,
                    {},
                    {},
                    root=root,
                    integration=root,
                    pool_name="prompt-conflict",
                    worktrees=[root],
                    mutable=False,
                    prompts=["Invoke $complex-work-orchestration now"],
                    expected_tokens=["DONE"],
                    pre_thread_start_check=lambda: checks.append("manifest"),
                )
            self.assertEqual(server.starts, 0)
            self.assertEqual(checks, [])

            operative = LIVE.default_tool_policy(mutable=False)
            with self.assertRaisesRegex(
                LIVE.AppServerError, "operative-tool-restriction-unsupported"
            ):
                LIVE.build_pool_inputs(
                    server,
                    {},
                    {},
                    root=root,
                    integration=root,
                    pool_name="operative-unsupported",
                    worktrees=[root],
                    mutable=False,
                    prompts=["Inspect the assigned file."],
                    expected_tokens=["DONE"],
                    tool_policies=[operative],
                    pre_thread_start_check=lambda: checks.append("manifest"),
                )
            self.assertEqual(server.starts, 0)
            self.assertEqual(checks, [])

    def test_temporary_operative_override_binds_before_thread_allocation(
        self,
    ) -> None:
        class NoThreadStartServer:
            def __init__(self) -> None:
                self.starts = 0

            def start_thread(self, *_args, **_kwargs):
                self.starts += 1
                raise AssertionError("override gate must precede allocation")

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            integration = root / "integration"
            first = root / "worker-0"
            second = root / "worker-1"
            integration.mkdir()
            first.mkdir()
            second.mkdir()
            manifest, override = temporary_tool_override_fixture()
            policy = LIVE.default_tool_policy(
                mutable=False,
                enforcement_override=override,
            )

            mismatched = dict(manifest)
            mismatched["campaign_nonce"] = str(uuid.uuid4())
            server = NoThreadStartServer()
            with self.assertRaisesRegex(
                LIVE.AppServerError,
                "campaign-nonce-mismatch",
            ):
                LIVE.build_pool_inputs(
                    server,
                    {},
                    mismatched,
                    root=root,
                    integration=integration,
                    pool_name="mismatched-override",
                    worktrees=[first],
                    mutable=False,
                    prompts=["Inspect the assigned file."],
                    expected_tokens=["DONE"],
                    tool_policies=[policy],
                    pre_thread_start_check=lambda: {},
                )
            self.assertEqual(server.starts, 0)

            server = NoThreadStartServer()
            with self.assertRaisesRegex(
                LIVE.AppServerError,
                "mutating-workers-exceed-override",
            ):
                LIVE.build_pool_inputs(
                    server,
                    {},
                    manifest,
                    root=root,
                    integration=integration,
                    pool_name="excess-mutation-override",
                    worktrees=[first, second],
                    mutable=True,
                    prompts=["Inspect one.", "Inspect two."],
                    expected_tokens=["ONE", "TWO"],
                    tool_policies=[policy, policy],
                    pre_thread_start_check=lambda: {},
                )
            self.assertEqual(server.starts, 0)

    def test_temporary_operative_override_rejects_exact_server_surface(
        self,
    ) -> None:
        class ExactSurfaceServer:
            def __init__(self) -> None:
                self.starts = 0

            @staticmethod
            def tool_surface_capability(
                *, permitted_tools: list[str]
            ) -> dict[str, object]:
                return {
                    "source": "supported-test-server",
                    "server_allowlist_supported": True,
                    "allowlist_parameter": "tools",
                    "effective_allowlist": list(permitted_tools),
                }

            def start_thread(self, *_args, **_kwargs):
                self.starts += 1
                raise AssertionError("weaker override must not allocate")

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            integration = root / "integration"
            worktree = root / "worker"
            integration.mkdir()
            worktree.mkdir()
            manifest, override = temporary_tool_override_fixture()
            policy = LIVE.default_tool_policy(
                mutable=False,
                enforcement_override=override,
            )
            server = ExactSurfaceServer()
            with self.assertRaisesRegex(
                LIVE.AppServerError,
                "override-unnecessary-exact-capability-available",
            ):
                LIVE.build_pool_inputs(
                    server,
                    {},
                    manifest,
                    root=root,
                    integration=integration,
                    pool_name="exact-surface",
                    worktrees=[worktree],
                    mutable=False,
                    prompts=["Inspect the assigned file."],
                    expected_tokens=["DONE"],
                    tool_policies=[policy],
                    pre_thread_start_check=lambda: {},
                )
            self.assertEqual(server.starts, 0)

    def test_raw_temporary_operative_override_fails_before_thread_start(
        self,
    ) -> None:
        class RecordingThreadStartServer:
            def __init__(self) -> None:
                self.calls: list[dict[str, object]] = []

            def start_thread(
                self,
                _worktree: Path,
                **kwargs: object,
            ) -> tuple[dict[str, object], float]:
                self.calls.append(dict(kwargs))
                return {
                    "model": LIVE.EXACT_MODEL,
                    "thread": {
                        "id": str(uuid.uuid4()),
                        "turns": [],
                    },
                }, 0.0

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            integration = root / "integration"
            worktree = root / "worker"
            integration.mkdir()
            worktree.mkdir()
            manifest, override = temporary_tool_override_fixture()
            policy = LIVE.default_tool_policy(
                mutable=False,
                enforcement_override=override,
            )
            server = RecordingThreadStartServer()
            with self.assertRaisesRegex(
                LIVE.AppServerError,
                "tools.policy-enforcement-activation",
            ):
                LIVE.build_pool_inputs(
                    server,
                    {},
                    manifest,
                    root=root,
                    integration=integration,
                    pool_name="temporary-operative",
                    worktrees=[worktree],
                    mutable=False,
                    prompts=["Inspect the assigned file."],
                    expected_tokens=["DONE"],
                    tool_policies=[policy],
                    pre_thread_start_check=lambda: {},
                )
            self.assertEqual(server.calls, [])

    def test_tool_surface_expansion_after_pool_preflight_blocks_thread_start(self) -> None:
        class ExpandingSurfaceServer:
            def __init__(self) -> None:
                self.surface_reads = 0
                self.starts = 0

            def tool_surface_capability(self, *, permitted_tools: list[str]) -> dict:
                self.surface_reads += 1
                effective = list(permitted_tools)
                if self.surface_reads > 1:
                    effective.append("spawn_agent")
                    effective.sort()
                return {
                    "source": "supported-test-server",
                    "server_allowlist_supported": True,
                    "allowlist_parameter": "tools",
                    "effective_allowlist": effective,
                }

            def start_thread(self, *_args, **_kwargs):
                self.starts += 1
                raise AssertionError("expanded surface must block allocation")

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            integration = root / "integration"
            worktree = root / "worktree"
            integration.mkdir()
            worktree.mkdir()
            server = ExpandingSurfaceServer()
            campaign = {
                "campaign_nonce": str(uuid.uuid4()),
                "control_turn_id": LIVE.CONTROL_TURN_ID,
            }
            with mock.patch.object(
                LIVE, "validate_live_canary_manifest_gate", return_value=[]
            ), self.assertRaisesRegex(LIVE.AppServerError, "tool-surface-expanded"):
                LIVE.build_pool_inputs(
                    server,
                    {},
                    campaign,
                    root=root,
                    integration=integration,
                    pool_name="expanded-surface",
                    worktrees=[worktree],
                    mutable=False,
                    prompts=["Inspect the assigned file."],
                    expected_tokens=["DONE"],
                    pre_thread_start_check=lambda: {},
                )
            self.assertEqual(server.starts, 0)

    def test_deterministic_pool_preflight_rejection_blocks_thread_creation(self) -> None:
        class NoThreadStartServer:
            def __init__(self) -> None:
                self.starts = 0

            def start_thread(self, *_args, **_kwargs):
                self.starts += 1
                raise AssertionError("preflight rejection must block allocation")

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            integration = root / "integration"
            worktree = root / "worktree"
            integration.mkdir()
            worktree.mkdir()
            server = NoThreadStartServer()
            manifest_checks: list[str] = []
            with mock.patch.object(
                LIVE,
                "require_pool_preflight",
                side_effect=LIVE.NativePoolPreflightError(
                    "pool-preflight-rejected:fallback.declared"
                ),
            ) as preflight, self.assertRaisesRegex(
                LIVE.AppServerError, "fallback.declared"
            ):
                LIVE.build_pool_inputs(
                    server,
                    {},
                    {
                        "campaign_nonce": str(uuid.uuid4()),
                        "control_turn_id": LIVE.CONTROL_TURN_ID,
                    },
                    root=root,
                    integration=integration,
                    pool_name="rejected",
                    worktrees=[worktree],
                    mutable=False,
                    prompts=["Inspect the assigned file."],
                    expected_tokens=["DONE"],
                    pre_thread_start_check=lambda: manifest_checks.append("manifest"),
                )
            preflight.assert_called_once()
            self.assertEqual(server.starts, 0)
            self.assertEqual(manifest_checks, [])
            self.assertEqual(list(root.glob("rejected-*-records")), [])

    def test_pool_threads_require_bound_manifest_revalidation_first(self) -> None:
        class NoThreadStartServer:
            started = False

            def start_thread(
                self, _worktree: Path, *, mutable: bool, role: str | None = None
            ) -> tuple[dict, float]:
                self.started = True
                raise AssertionError("thread-started-before-bound-validation")

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            integration = root / "integration"
            shared_worktree = root / "shared-worktree"
            integration.mkdir()
            shared_worktree.mkdir()
            server = NoThreadStartServer()
            checks: list[str] = []

            def reject_unbound_manifest() -> dict[str, object]:
                checks.append("full-bound-v3-validation")
                raise LIVE.AppServerError("campaign-bound-inputs-changed")

            with self.assertRaisesRegex(
                LIVE.AppServerError, "campaign-bound-inputs-changed"
            ):
                LIVE.build_pool_inputs(
                    server,
                    {},
                    {"campaign_nonce": str(uuid.uuid4())},
                    root=root,
                    integration=integration,
                    pool_name="read-only",
                    worktrees=[shared_worktree, shared_worktree],
                    mutable=False,
                    prompts=["one", "two"],
                    expected_tokens=["ONE", "TWO"],
                    pre_thread_start_check=reject_unbound_manifest,
                    expected_bound_manifest_validation={},
                )
            self.assertEqual(checks, ["full-bound-v3-validation"])
            self.assertFalse(server.started)
            self.assertFalse((root / "read-only-records").exists())

            manifest = {
                "version": 8,
                "manifest_id": str(uuid.uuid4()),
                "manifest_sha256": LIVE.sha256_text("manifest"),
                "authorization_id": str(uuid.uuid4()),
                "campaign_nonce": str(uuid.uuid4()),
                "control_turn_id": LIVE.CONTROL_TURN_ID,
                "candidate": {"commit": "a" * 40, "tree": "b" * 40},
            }
            expected = LIVE.seal_bound_manifest_validation(
                manifest,
                {"launch_claim_sha256": LIVE.sha256_text("expected-claim")},
            )
            stale = LIVE.seal_bound_manifest_validation(
                manifest,
                {"launch_claim_sha256": LIVE.sha256_text("stale-claim")},
            )
            for label, observed in (("missing", None), ("stale", stale)):
                server.started = False
                with self.subTest(label=label), self.assertRaisesRegex(
                    LIVE.AppServerError,
                    "campaign-manifest-invalid-before-thread-start",
                ):
                    LIVE.build_pool_inputs(
                        server,
                        {},
                        manifest,
                        root=root,
                        integration=integration,
                        pool_name="read-only",
                        worktrees=[shared_worktree, shared_worktree],
                        mutable=False,
                        prompts=["one", "two"],
                        expected_tokens=["ONE", "TWO"],
                        pre_thread_start_check=lambda observed=observed: observed,
                        expected_bound_manifest_validation=expected,
                    )
                self.assertFalse(server.started)
                self.assertFalse((root / "read-only-records").exists())

    def test_pool_setup_forwards_bound_receipt_without_context_free_validation(self) -> None:
        class ThreadStartSentinelServer:
            starts = 0

            def start_thread(
                self, _worktree: Path, *, mutable: bool, role: str | None = None
            ) -> tuple[dict, float]:
                self.starts += 1
                return {
                    "model": LIVE.EXACT_MODEL,
                    "thread": {"id": str(uuid.uuid4()), "turns": []},
                }, 0.0

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            integration = root / "integration"
            shared_worktree = root / "shared-worktree"
            integration.mkdir()
            shared_worktree.mkdir()
            manifest = {
                "version": 8,
                "manifest_id": str(uuid.uuid4()),
                "manifest_sha256": LIVE.sha256_text("manifest"),
                "authorization_id": str(uuid.uuid4()),
                "campaign_nonce": str(uuid.uuid4()),
                "control_turn_id": LIVE.CONTROL_TURN_ID,
                "candidate": {"commit": "a" * 40, "tree": "b" * 40},
            }
            bound = LIVE.seal_bound_manifest_validation(
                manifest,
                {"launch_claim_sha256": LIVE.sha256_text("launch-claim")},
            )
            rendered = {"children": []}
            with mock.patch.object(
                LIVE,
                "build_live_canary_pool_contract",
                return_value=rendered,
            ) as builder, mock.patch.object(
                LIVE,
                "PoolWorkspaceMonitor",
                return_value=mock.sentinel.monitor,
            ), mock.patch.object(
                LIVE,
                "require_pool_preflight",
                return_value={"accepted": True, "result_sha256": "a" * 64},
            ):
                (
                    contract,
                    _controls,
                    _adapters,
                    monitor,
                    _preflights,
                ) = LIVE.build_pool_inputs(
                    ThreadStartSentinelServer(),
                    {},
                    manifest,
                    root=root,
                    integration=integration,
                    pool_name="read-only",
                    worktrees=[shared_worktree, shared_worktree],
                    mutable=False,
                    prompts=["one", "two"],
                    expected_tokens=["ONE", "TWO"],
                    pre_thread_start_check=lambda: bound,
                    expected_bound_manifest_validation=bound,
                )
            self.assertIs(contract, rendered)
            self.assertIs(monitor, mock.sentinel.monitor)
            self.assertIs(
                builder.call_args.kwargs["bound_manifest_validation"], bound
            )

    def test_full_bound_gate_is_immediately_before_capability_allocation(self) -> None:
        source = inspect.getsource(LIVE.main)
        gate = "require_bound_campaign_inputs_before_thread_start()"
        calibration_call = "capability, calibration_evidence = calibration("
        self.assertIn(gate + "\n            " + calibration_call, source)
        self.assertNotIn(
            "validate_campaign_manifest(", inspect.getsource(LIVE.build_pool_inputs)
        )

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
            + json.dumps(
                {
                    "type": "event_msg",
                    "payload": {"type": "turn_aborted", "turn_id": turn_id},
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
                        "record_count": 3,
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

    def valid_steering_receipt(
        self, gate: str, authorization_id: str, authorization_sha256: str
    ) -> dict:
        from cwo_core.native_canary_contracts import seal_neutral_steering_receipt
        from tests.test_native_canary_contracts import steering

        receipt = steering()
        receipt["gate"] = gate
        receipt["authorization_id"] = authorization_id
        receipt["authorization_sha256"] = authorization_sha256
        return seal_neutral_steering_receipt(receipt)

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
        scope = {
            "epic_id": authorization["scope"]["epic_id"],
            "parent_work_unit_id": authorization["scope"][
                "parent_work_unit_id"
            ],
        }
        value = {
            "authority_type": "cwo-full-auto-outer-recovery-authority",
            "version": 1,
            "authority_id": authorization["bindings"]["outer_authority_id"],
            "status": "active",
            "scope": scope,
            "active_registry": {
                "contract": "cwo-active-outer-authority-registry:v1",
                "scope_key": LIVE.active_outer_authority_scope_key(
                    scope["epic_id"], scope["parent_work_unit_id"]
                ),
            },
            "bindings": {
                "candidate_commit": authorization["bindings"]["checkpoint_commit"],
                "candidate_tree": authorization["bindings"]["checkpoint_tree"],
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

    def install_validator_contract_files(
        self,
        root: Path,
        paths: tuple[str, ...] = LIVE.VALIDATOR_CONTRACT_PATHS,
    ) -> None:
        for relative in paths:
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
            + json.dumps(
                {
                    "type": "event_msg",
                    "payload": {"type": "turn_aborted", "turn_id": turn_id},
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
        self.install_validator_contract_files(root)
        subprocess.run(
            ["git", "add", *LIVE.VALIDATOR_CONTRACT_PATHS],
            cwd=root,
            check=True,
        )
        subprocess.run(
            ["git", "commit", "-qm", "install validator contract"],
            cwd=root,
            check=True,
        )
        checkpoint = LIVE.run_git(root, "rev-parse", "HEAD")
        checkpoint_tree = LIVE.run_git(root, "rev-parse", "HEAD^{tree}")
        validator_sha256 = LIVE.validator_contract_sha256(root, checkpoint_tree)

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
            session_raw = path.read_bytes()
            with mock.patch.dict("os.environ", {"CODEX_HOME": str(root)}):
                self.assertEqual(
                    LIVE.validate_independent_validation_session(receipt, path),
                    receipt["boundary"]["terminal"]["boundary_sha256"],
                )
                for field in ("session_id", "submission_id"):
                    for alias in UUID_TEXT_ALIASES:
                        with self.subTest(field=field, alias=repr(alias)):
                            aliased_receipt = json.loads(json.dumps(receipt))
                            aliased_receipt[field] = alias
                            with self.assertRaisesRegex(
                                LIVE.AppServerError,
                                "spark-validation-session-identity-invalid",
                            ):
                                LIVE.validate_independent_validation_session_snapshot(
                                    aliased_receipt,
                                    path,
                                    session_raw,
                                )
                            self.assertEqual(
                                CAMPAIGN_CONTRACTS._validate_independent_validation_session_snapshot(
                                    aliased_receipt, session_raw
                                ),
                                [
                                    "authorization-predecessor-validation-session-identity-invalid"
                                ],
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

    def test_validator_contract_hash_is_immutable_tree_bound(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.make_repo(root)
            self.install_validator_contract_files(root)
            subprocess.run(
                ["git", "add", *LIVE.VALIDATOR_CONTRACT_PATHS],
                cwd=root,
                check=True,
            )
            subprocess.run(
                ["git", "commit", "-qm", "install validator contract"],
                cwd=root,
                check=True,
            )
            first_tree = LIVE.run_git(root, "rev-parse", "HEAD^{tree}")
            first_hash = LIVE.validator_contract_sha256(root, first_tree)
            contract_path = root / LIVE.VALIDATOR_CONTRACT_PATHS[0]
            contract_path.write_bytes(contract_path.read_bytes() + b"working-tree-change\n")
            self.assertEqual(
                LIVE.validator_contract_sha256(root, first_tree), first_hash
            )
            subprocess.run(
                ["git", "add", LIVE.VALIDATOR_CONTRACT_PATHS[0]],
                cwd=root,
                check=True,
            )
            subprocess.run(
                ["git", "commit", "-qm", "change validator contract"],
                cwd=root,
                check=True,
            )
            second_tree = LIVE.run_git(root, "rev-parse", "HEAD^{tree}")
            self.assertNotEqual(
                LIVE.validator_contract_sha256(root, second_tree), first_hash
            )

    def test_v6_validator_contract_explicitly_binds_pool_config(self) -> None:
        pool_config = "scripts/cwo_core/native_pool_config.py"
        self.assertIn(
            pool_config,
            CAMPAIGN_CONTRACTS.VALIDATOR_CONTRACT_PATHS_V6,
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.make_repo(root)
            self.install_validator_contract_files(
                root,
                CAMPAIGN_CONTRACTS.VALIDATOR_CONTRACT_PATHS_V6,
            )
            subprocess.run(
                [
                    "git",
                    "add",
                    *CAMPAIGN_CONTRACTS.VALIDATOR_CONTRACT_PATHS_V6,
                ],
                cwd=root,
                check=True,
            )
            subprocess.run(
                ["git", "commit", "-qm", "install v6 validator contract"],
                cwd=root,
                check=True,
            )
            first_tree = LIVE.run_git(root, "rev-parse", "HEAD^{tree}")
            first_hash = LIVE.validator_contract_sha256_v6(root, first_tree)
            contract_path = root / pool_config
            contract_path.write_bytes(
                contract_path.read_bytes() + b"working-tree-change\n"
            )
            self.assertEqual(
                LIVE.validator_contract_sha256_v6(root, first_tree),
                first_hash,
            )
            subprocess.run(
                ["git", "add", pool_config],
                cwd=root,
                check=True,
            )
            subprocess.run(
                ["git", "commit", "-qm", "change pool config contract"],
                cwd=root,
                check=True,
            )
            second_tree = LIVE.run_git(root, "rev-parse", "HEAD^{tree}")
            self.assertNotEqual(
                LIVE.validator_contract_sha256_v6(root, second_tree),
                first_hash,
            )

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
            contained_records = predecessor.contained_session_bytes[0].splitlines(
                keepends=True
            )
            completed_without_required_tools = [
                json.loads(line) for line in contained_records
            ]
            completed_without_required_tools[-1]["payload"]["type"] = (
                "task_complete"
            )
            completed_without_required_tools_raw = b"".join(
                json.dumps(record, sort_keys=True).encode() + b"\n"
                for record in completed_without_required_tools
            )
            completed_without_required_tools_errors = validate(
                replace(
                    predecessor,
                    contained_session_bytes=(
                        completed_without_required_tools_raw,
                    ),
                )
            )
            self.assertIn(
                "authorization-predecessor-modern-session-tool-activity-invalid",
                completed_without_required_tools_errors,
            )
            post_terminal = b"".join(
                [
                    *contained_records,
                    json.dumps(
                        {
                            "type": "event_msg",
                            "payload": {"type": "token_count"},
                        }
                    ).encode()
                    + b"\n",
                ]
            )
            *_, post_terminal_errors = (
                CAMPAIGN_CONTRACTS._parse_contained_session_identity(
                    post_terminal, "post-terminal"
                )
            )
            self.assertIn(
                "post-terminal-terminal-boundary-invalid", post_terminal_errors
            )
            unknown_activity = b"".join(
                [
                    *contained_records[:-1],
                    json.dumps(
                        {
                            "type": "response_item",
                            "payload": {"type": "unknown_tool_call"},
                        }
                    ).encode()
                    + b"\n",
                    contained_records[-1],
                ]
            )
            *_, unknown_activity_errors = (
                CAMPAIGN_CONTRACTS._parse_contained_session_identity(
                    unknown_activity, "unknown-activity"
                )
            )
            self.assertIn(
                "unknown-activity-activity-invalid", unknown_activity_errors
            )

            tool_session_index = 0
            parsed_records = [
                json.loads(line)
                for line in predecessor.contained_session_bytes[
                    tool_session_index
                ].splitlines()
            ]
            malicious_tool_records = json.loads(json.dumps(parsed_records))
            malicious_tool_records[-1:-1] = [
                {
                    "type": "response_item",
                    "payload": {
                        "type": "function_call",
                        "name": "apply_patch",
                        "call_id": "malicious-call",
                    },
                },
                {
                    "type": "response_item",
                    "payload": {
                        "type": "function_call_output",
                        "call_id": "malicious-call",
                    },
                },
            ]
            malicious_tool = b"".join(
                json.dumps(record, sort_keys=True).encode() + b"\n"
                for record in malicious_tool_records
            )
            *_, malicious_parse_errors = (
                CAMPAIGN_CONTRACTS._parse_contained_session_identity(
                    malicious_tool, "malicious-tool"
                )
            )
            self.assertIn(
                "malicious-tool-tool-call-invalid", malicious_parse_errors
            )
            malicious_tool_errors = validate(
                replace(
                    predecessor,
                    contained_session_bytes=tuple(
                        malicious_tool if index == tool_session_index else raw
                        for index, raw in enumerate(
                            predecessor.contained_session_bytes
                        )
                    ),
                )
            )
            self.assertTrue(
                any(
                    "tool-call-invalid" in item
                    for item in malicious_tool_errors
                ),
                malicious_tool_errors,
            )

            wrong_role_records = json.loads(json.dumps(parsed_records))
            wrong_role_records[-1:-1] = [
                {
                    "type": "response_item",
                    "payload": {
                        "type": "custom_tool_call",
                        "name": "apply_patch",
                        "call_id": "wrong-role-call",
                    },
                },
                {
                    "type": "response_item",
                    "payload": {
                        "type": "custom_tool_call_output",
                        "call_id": "wrong-role-call",
                    },
                },
            ]
            wrong_role = b"".join(
                json.dumps(record, sort_keys=True).encode() + b"\n"
                for record in wrong_role_records
            )
            wrong_role_errors = validate(
                replace(
                    predecessor,
                    contained_session_bytes=tuple(
                        wrong_role if index == tool_session_index else raw
                        for index, raw in enumerate(
                            predecessor.contained_session_bytes
                        )
                    ),
                )
            )
            self.assertTrue(
                any(
                    "session-tool-activity-invalid" in item
                    for item in wrong_role_errors
                ),
                wrong_role_errors,
            )

            out_of_order_records = json.loads(json.dumps(parsed_records))
            out_of_order_records[-1:-1] = [
                {
                    "type": "response_item",
                    "payload": {
                        "type": "function_call_output",
                        "call_id": "out-of-order-call",
                    },
                },
                {
                    "type": "response_item",
                    "payload": {
                        "type": "function_call",
                        "name": "exec_command",
                        "call_id": "out-of-order-call",
                    },
                },
            ]
            out_of_order = b"".join(
                json.dumps(record, sort_keys=True).encode() + b"\n"
                for record in out_of_order_records
            )
            *_, out_of_order_errors = (
                CAMPAIGN_CONTRACTS._parse_contained_session_identity(
                    out_of_order, "out-of-order"
                )
            )
            self.assertIn("out-of-order-tool-order-invalid", out_of_order_errors)

            prestart_records = json.loads(json.dumps(parsed_records))
            prestart_records[1], prestart_records[2] = (
                prestart_records[2],
                prestart_records[1],
            )
            prestart = b"".join(
                json.dumps(record, sort_keys=True).encode() + b"\n"
                for record in prestart_records
            )
            *_, prestart_errors = (
                CAMPAIGN_CONTRACTS._parse_contained_session_identity(
                    prestart, "prestart"
                )
            )
            self.assertIn("prestart-terminal-boundary-invalid", prestart_errors)

            mutable_session_id = str(uuid.uuid4())
            mutable_turn_id = str(uuid.uuid4())
            mutable_records = [
                {
                    "type": "session_meta",
                    "payload": {"id": mutable_session_id},
                },
                {
                    "type": "event_msg",
                    "payload": {
                        "type": "task_started",
                        "turn_id": mutable_turn_id,
                    },
                },
                {
                    "type": "turn_context",
                    "payload": {
                        "turn_id": mutable_turn_id,
                        "model": LIVE.EXACT_MODEL,
                        "effort": "low",
                    },
                },
                {
                    "type": "response_item",
                    "payload": {
                        "type": "custom_tool_call",
                        "name": "apply_patch",
                        "call_id": "patch-call",
                    },
                },
                {
                    "type": "event_msg",
                    "payload": {
                        "type": "patch_apply_end",
                        "call_id": "patch-call",
                        "turn_id": mutable_turn_id,
                    },
                },
                {
                    "type": "response_item",
                    "payload": {
                        "type": "custom_tool_call_output",
                        "call_id": "patch-call",
                    },
                },
                {
                    "type": "response_item",
                    "payload": {
                        "type": "function_call",
                        "name": "exec_command",
                        "call_id": "exec-call",
                    },
                },
                {
                    "type": "response_item",
                    "payload": {
                        "type": "function_call_output",
                        "call_id": "exec-call",
                    },
                },
                {
                    "type": "event_msg",
                    "payload": {
                        "type": "task_complete",
                        "turn_id": mutable_turn_id,
                    },
                },
            ]
            mutable_raw = b"".join(
                json.dumps(record, sort_keys=True).encode() + b"\n"
                for record in mutable_records
            )
            (
                parsed_session_id,
                parsed_turns,
                _record_count,
                parsed_tools,
                terminal_type,
                mutable_errors,
            ) = CAMPAIGN_CONTRACTS._parse_contained_session_identity(
                mutable_raw, "mutable"
            )
            self.assertEqual(mutable_errors, [])
            self.assertEqual(parsed_session_id, mutable_session_id)
            self.assertEqual(parsed_turns, {mutable_turn_id})
            self.assertEqual(
                parsed_tools,
                CAMPAIGN_CONTRACTS.CONTAINED_ROLE_TOOL_PREFIXES["mutable-0"],
            )
            self.assertEqual(terminal_type, "task_complete")

            conflicting_identity_records = json.loads(
                json.dumps(mutable_records)
            )
            conflicting_identity_records[0]["payload"]["session_id"] = str(
                uuid.uuid4()
            )
            conflicting_identity_records[1]["session_id"] = str(uuid.uuid4())
            conflicting_identity = b"".join(
                json.dumps(record, sort_keys=True).encode() + b"\n"
                for record in conflicting_identity_records
            )
            *_, conflicting_identity_errors = (
                CAMPAIGN_CONTRACTS._parse_contained_session_identity(
                    conflicting_identity, "conflicting-identity"
                )
            )
            self.assertIn(
                "conflicting-identity-session-identity-invalid",
                conflicting_identity_errors,
            )

            wrong_context_records = json.loads(json.dumps(mutable_records))
            wrong_context_records[2]["payload"]["model"] = "gpt-5.6-sol"
            wrong_context_records[2]["payload"]["effort"] = "max"
            wrong_context = b"".join(
                json.dumps(record, sort_keys=True).encode() + b"\n"
                for record in wrong_context_records
            )
            *_, wrong_context_errors = (
                CAMPAIGN_CONTRACTS._parse_contained_session_identity(
                    wrong_context, "wrong-context"
                )
            )
            self.assertIn(
                "wrong-context-turn-context-attestation-invalid",
                wrong_context_errors,
            )

            missing_context = b"".join(
                json.dumps(record, sort_keys=True).encode() + b"\n"
                for index, record in enumerate(mutable_records)
                if index != 2
            )
            *_, missing_context_errors = (
                CAMPAIGN_CONTRACTS._parse_contained_session_identity(
                    missing_context, "missing-context"
                )
            )
            self.assertIn(
                "missing-context-turn-context-attestation-invalid",
                missing_context_errors,
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
            inputs.source_identities = LIVE.capture_input_source_identities(paths)
            LIVE.require_trusted_session_snapshots_unchanged(paths, inputs)
            private_snapshots = {
                "authorization": inputs.authorization.raw,
                "campaign-manifest": inputs.manifest.raw,
                "outer-authority": inputs.outer_authority.raw,
                "release-patch": inputs.release_patch_bytes,
                "pre-mutation-steering-receipt": inputs.pre_mutation_receipt.raw,
                "pre-mutation-adjudication": inputs.pre_mutation_adjudication.raw,
                "pre-live-steering-receipt": inputs.pre_live_receipt.raw,
                "pre-live-adjudication": inputs.pre_live_adjudication.raw,
                "opus-review-evidence": inputs.opus_review_evidence.raw,
                "opus-adjudication": inputs.opus_adjudication.raw,
                "spark-validation-receipt": inputs.spark_validation_receipt.raw,
                "predecessor-authorization": predecessor.authorization.raw,
                "predecessor-manifest": predecessor.manifest.raw,
                "predecessor-authorization-state": predecessor.authorization_state.raw,
                "predecessor-failure-evidence": predecessor.failure_evidence.raw,
                "predecessor-containment": predecessor.containment.raw,
                "predecessor-allocation-ledger": predecessor.allocation_ledger.raw,
                "predecessor-allocation-audit": predecessor.allocation_audit_bytes,
                "predecessor-outer-authority": predecessor.outer_authority.raw,
                "predecessor-independent-validation-receipt": (
                    predecessor.independent_validation_receipt.raw
                ),
                "predecessor-authorization-cause-evidence": (
                    predecessor.authorization_cause_evidence
                ),
                "ancestor-authorization": predecessor.ancestor.authorization.raw,
                "ancestor-manifest": predecessor.ancestor.manifest.raw,
                "ancestor-authorization-state": (
                    predecessor.ancestor.authorization_state.raw
                ),
                "ancestor-failure-evidence": predecessor.ancestor.failure_evidence.raw,
                "ancestor-original-containment": (
                    predecessor.ancestor.original_containment.raw
                ),
                "ancestor-containment": predecessor.ancestor.containment.raw,
                "ancestor-allocation-ledger": predecessor.ancestor.allocation_ledger.raw,
                "ancestor-allocation-audit": (
                    predecessor.ancestor.allocation_audit_bytes
                ),
                "cause-evidence": inputs.recovery_cause_evidence.raw,
                "cause-source-analysis": inputs.recovery_cause_source_analysis_bytes,
            }
            for label, raw in private_snapshots.items():
                path = root / f"private-{label}"
                path.write_bytes(raw)
                path.chmod(0o600)
                paths[label] = path
            inputs.source_identities = LIVE.capture_input_source_identities(paths)
            LIVE.require_launch_source_snapshots_unchanged(paths, inputs)
            outer_path = paths["outer-authority"]
            replacement = outer_path.with_suffix(".replacement")
            replacement.write_bytes(outer_path.read_bytes())
            replacement.chmod(0o600)
            replacement.replace(outer_path)
            with self.assertRaisesRegex(
                LIVE.AppServerError, "outer-authority-source-identity-changed"
            ):
                LIVE.require_launch_source_snapshots_unchanged(paths, inputs)
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
            relocated_paths = {
                label: root / "relocated" / path.name
                for label, path in output_paths.items()
            }
            self.assertNotEqual(
                claim,
                LIVE.campaign_launch_claim_sha256(inputs, **relocated_paths),
            )
            alias = root / "same.json"
            alias.write_text("{}", encoding="utf-8")
            with self.assertRaisesRegex(LIVE.AppServerError, "path-alias"):
                LIVE.require_unique_input_paths({"one": alias, "two": alias})
            hardlink = root / "hardlink.json"
            hardlink.hardlink_to(alias)
            with self.assertRaisesRegex(LIVE.AppServerError, "path-alias"):
                LIVE.require_unique_input_paths({"one": alias, "two": hardlink})

            authority_registry = root / "authority-registry"
            claim_registry = root / "claim-registry"
            for alias in UUID_TEXT_ALIASES:
                aliased_outer = json.loads(
                    json.dumps(successor["outer_snapshot"].value)
                )
                aliased_outer["authority_id"] = alias
                self.seal_field(
                    aliased_outer, "canonical_outer_authority_sha256"
                )
                with self.subTest(surface="outer-authority", alias=repr(alias)), self.assertRaisesRegex(
                    LIVE.AppServerError, "active-outer-authority-artifact-invalid"
                ):
                    LIVE.register_active_outer_authority(
                        self.json_snapshot(aliased_outer),
                        candidate_commit=successor["checkpoint"],
                        candidate_tree=successor["checkpoint_tree"],
                        registry_root=authority_registry,
                    )
            self.assertFalse(authority_registry.exists())
            LIVE.register_active_outer_authority(
                successor["outer_snapshot"],
                candidate_commit=successor["checkpoint"],
                candidate_tree=successor["checkpoint_tree"],
                registry_root=authority_registry,
            )
            LIVE.validate_active_outer_authority(
                successor["outer_snapshot"],
                candidate_commit=successor["checkpoint"],
                candidate_tree=successor["checkpoint_tree"],
                registry_root=authority_registry,
            )
            LIVE.register_active_outer_authority(
                successor["outer_snapshot"],
                candidate_commit=successor["checkpoint"],
                candidate_tree=successor["checkpoint_tree"],
                registry_root=authority_registry,
            )
            changed_same_id = json.loads(
                json.dumps(successor["outer_snapshot"].value)
            )
            changed_same_id["created_at"] = "2026-07-17T13:00:00Z"
            self.seal_field(
                changed_same_id, "canonical_outer_authority_sha256"
            )
            with self.assertRaisesRegex(
                LIVE.AppServerError, "authority-id-reused"
            ):
                LIVE.register_active_outer_authority(
                    self.json_snapshot(changed_same_id),
                    candidate_commit=successor["checkpoint"],
                    candidate_tree=successor["checkpoint_tree"],
                    registry_root=authority_registry,
                )
            with mock.patch.object(
                LIVE,
                "_fsync_owned_control_directory",
                wraps=LIVE._fsync_owned_control_directory,
            ) as durable_directory:
                reservation = LIVE.acquire_global_campaign_claim(
                    inputs,
                    launch_claim_sha256=claim,
                    claim_root=claim_registry,
                    registry_root=authority_registry,
                    **output_paths,
                )
            self.assertTrue(
                any(
                    call.args[:2]
                    == (claim_registry.parent.resolve(), "campaign-global-claim-parent")
                    and call.kwargs == {"require_private": False}
                    for call in durable_directory.mock_calls
                ),
                durable_directory.mock_calls,
            )
            LIVE.transition_global_campaign_state(
                reservation,
                "contained",
                terminal_evidence_sha256="f" * 64,
            )
            with self.assertRaisesRegex(
                LIVE.AppServerError, "global-authorization-reused"
            ):
                LIVE.acquire_global_campaign_claim(
                    inputs,
                    launch_claim_sha256=claim,
                    claim_root=claim_registry,
                    registry_root=authority_registry,
                    **output_paths,
                )

            def claim_inputs(
                authorization_id: str, campaign_nonce: str
            ) -> LIVE.CampaignLaunchInputs:
                authorization_value = json.loads(
                    json.dumps(inputs.authorization.value)
                )
                authorization_value["authorization_id"] = authorization_id
                authorization_value["bindings"]["campaign_nonce"] = (
                    campaign_nonce
                )
                return LIVE.CampaignLaunchInputs(
                    authorization=self.json_snapshot(authorization_value),
                    manifest=inputs.manifest,
                    outer_authority=inputs.outer_authority,
                    release_patch_bytes=inputs.release_patch_bytes,
                    pre_mutation_receipt=inputs.pre_mutation_receipt,
                    pre_mutation_adjudication=inputs.pre_mutation_adjudication,
                    pre_live_receipt=inputs.pre_live_receipt,
                    pre_live_adjudication=inputs.pre_live_adjudication,
                    opus_review_evidence=inputs.opus_review_evidence,
                    opus_adjudication=inputs.opus_adjudication,
                    spark_validation_receipt=inputs.spark_validation_receipt,
                    spark_validation_session_path=(
                        inputs.spark_validation_session_path
                    ),
                    spark_validation_session_bytes=(
                        inputs.spark_validation_session_bytes
                    ),
                    predecessor_proof=inputs.predecessor_proof,
                    recovery_cause_evidence=inputs.recovery_cause_evidence,
                    recovery_cause_source_analysis_bytes=(
                        inputs.recovery_cause_source_analysis_bytes
                    ),
                )

            initial_claim_registry_snapshot = {
                path.name: path.read_bytes()
                for path in claim_registry.iterdir()
                if path.is_file()
            }
            for identity_field in ("authorization_id", "campaign_nonce"):
                for alias in UUID_TEXT_ALIASES:
                    aliased_inputs = claim_inputs(
                        alias
                        if identity_field == "authorization_id"
                        else str(uuid.uuid4()),
                        alias
                        if identity_field == "campaign_nonce"
                        else str(uuid.uuid4()),
                    )
                    with self.subTest(surface="global-claim", field=identity_field, alias=repr(alias)), self.assertRaisesRegex(
                        LIVE.AppServerError,
                        "campaign-global-claim-identity-invalid",
                    ):
                        LIVE.acquire_global_campaign_claim(
                            aliased_inputs,
                            launch_claim_sha256="0" * 64,
                            claim_root=claim_registry,
                            registry_root=authority_registry,
                            **output_paths,
                        )
            self.assertEqual(
                {
                    path.name: path.read_bytes()
                    for path in claim_registry.iterdir()
                    if path.is_file()
                },
                initial_claim_registry_snapshot,
            )

            original_authorization_id = str(
                inputs.authorization.value["authorization_id"]
            )
            original_nonce = str(
                inputs.authorization.value["bindings"]["campaign_nonce"]
            )
            with self.assertRaisesRegex(
                LIVE.AppServerError, "global-authorization-reused"
            ):
                LIVE.acquire_global_campaign_claim(
                    claim_inputs(original_authorization_id, str(uuid.uuid4())),
                    launch_claim_sha256="1" * 64,
                    claim_root=claim_registry,
                    registry_root=authority_registry,
                    **output_paths,
                )
            with self.assertRaisesRegex(
                LIVE.AppServerError, "global-nonce-reused"
            ):
                LIVE.acquire_global_campaign_claim(
                    claim_inputs(str(uuid.uuid4()), original_nonce),
                    launch_claim_sha256="2" * 64,
                    claim_root=claim_registry,
                    registry_root=authority_registry,
                    **output_paths,
                )
            fresh_claim_inputs = claim_inputs(
                str(uuid.uuid4()), str(uuid.uuid4())
            )
            fresh_reservation = LIVE.acquire_global_campaign_claim(
                fresh_claim_inputs,
                launch_claim_sha256="3" * 64,
                claim_root=claim_registry,
                registry_root=authority_registry,
                **output_paths,
            )
            LIVE.transition_global_campaign_state(
                fresh_reservation,
                "contained",
                terminal_evidence_sha256="d" * 64,
            )

            original_claim_write = LIVE._write_exclusive_private_bytes

            def exercise_claim_crash(stage: str) -> None:
                crash_claim_registry = root / f"crash-claim-{stage}"
                crash_authorization_id = str(uuid.uuid4())
                crash_nonce = str(uuid.uuid4())
                crash_inputs = claim_inputs(
                    crash_authorization_id, crash_nonce
                )

                def fail_at_marker(
                    path: Path, raw: bytes, label: str
                ) -> None:
                    marker_kind = (
                        "authorization"
                        if path.name.startswith("authorization-")
                        else "nonce"
                        if path.name.startswith("nonce-")
                        else None
                    )
                    if (
                        label == "campaign-global-claim-marker"
                        and marker_kind == stage
                    ):
                        raise LIVE.AppServerError("injected-claim-crash")
                    original_claim_write(path, raw, label)

                if stage == "reservation":
                    with mock.patch.object(
                        LIVE,
                        "_write_scope_campaign_state",
                        side_effect=LIVE.AppServerError(
                            "injected-claim-crash"
                        ),
                    ):
                        with self.assertRaisesRegex(
                            LIVE.AppServerError, "injected-claim-crash"
                        ):
                            LIVE.acquire_global_campaign_claim(
                                crash_inputs,
                                launch_claim_sha256="4" * 64,
                                claim_root=crash_claim_registry,
                                registry_root=authority_registry,
                                **output_paths,
                            )
                else:
                    with mock.patch.object(
                        LIVE,
                        "_write_exclusive_private_bytes",
                        side_effect=fail_at_marker,
                    ):
                        with self.assertRaisesRegex(
                            LIVE.AppServerError, "injected-claim-crash"
                        ):
                            LIVE.acquire_global_campaign_claim(
                                crash_inputs,
                                launch_claim_sha256="4" * 64,
                                claim_root=crash_claim_registry,
                                registry_root=authority_registry,
                                **output_paths,
                            )
                crash_values = [
                    LIVE.load_private_json(path, "crash-claim")
                    for path in crash_claim_registry.glob("*.json")
                ]
                self.assertTrue(
                    any(
                        item.get("claim_type")
                        == "cwo-native-live-campaign-global-claim"
                        for item in crash_values
                    )
                )
                with self.assertRaisesRegex(
                    LIVE.AppServerError, "global-authorization-reused"
                ):
                    LIVE.acquire_global_campaign_claim(
                        claim_inputs(
                            crash_authorization_id, str(uuid.uuid4())
                        ),
                        launch_claim_sha256="5" * 64,
                        claim_root=crash_claim_registry,
                        registry_root=authority_registry,
                        **output_paths,
                    )
                with self.assertRaisesRegex(
                    LIVE.AppServerError, "global-nonce-reused"
                ):
                    LIVE.acquire_global_campaign_claim(
                        claim_inputs(str(uuid.uuid4()), crash_nonce),
                        launch_claim_sha256="6" * 64,
                        claim_root=crash_claim_registry,
                        registry_root=authority_registry,
                        **output_paths,
                    )

            for crash_stage in ("authorization", "nonce", "reservation"):
                exercise_claim_crash(crash_stage)

            replacement_outer = json.loads(
                json.dumps(successor["outer_snapshot"].value)
            )
            replacement_outer["supersession"] = {
                "prior_outer_authority_id": replacement_outer["authority_id"],
                "prior_outer_authority_file_sha256": successor[
                    "outer_snapshot"
                ].raw_sha256,
                "prior_outer_authority_canonical_sha256": replacement_outer[
                    "canonical_outer_authority_sha256"
                ],
            }
            replacement_outer["authority_id"] = str(uuid.uuid4())
            self.seal_field(
                replacement_outer, "canonical_outer_authority_sha256"
            )
            replacement_snapshot = self.json_snapshot(replacement_outer)
            atomic_claim_registry = root / "atomic-claim-registry"
            claim_write_entered = threading.Event()
            permit_claim_write = threading.Event()
            replacement_finished = threading.Event()
            thread_errors: list[BaseException] = []
            replacement_errors: list[BaseException] = []
            atomic_reservations: list[LIVE.GlobalCampaignReservation] = []
            original_write = LIVE._write_exclusive_private_bytes

            def gated_write(path: Path, raw: bytes, label: str) -> None:
                if label == "campaign-global-claim":
                    claim_write_entered.set()
                    if not permit_claim_write.wait(timeout=5):
                        raise AssertionError("timed out waiting to release claim write")
                original_write(path, raw, label)

            def claim_worker() -> None:
                try:
                    atomic_reservations.append(
                        LIVE.acquire_global_campaign_claim(
                            inputs,
                            launch_claim_sha256=claim,
                            claim_root=atomic_claim_registry,
                            registry_root=authority_registry,
                            **output_paths,
                        )
                    )
                except BaseException as exc:  # pragma: no cover - asserted below
                    thread_errors.append(exc)

            def replacement_worker() -> None:
                try:
                    LIVE.register_active_outer_authority(
                        replacement_snapshot,
                        candidate_commit=successor["checkpoint"],
                        candidate_tree=successor["checkpoint_tree"],
                        registry_root=authority_registry,
                    )
                except BaseException as exc:  # pragma: no cover - asserted below
                    replacement_errors.append(exc)
                finally:
                    replacement_finished.set()

            with mock.patch.object(
                LIVE, "_write_exclusive_private_bytes", side_effect=gated_write
            ):
                claim_thread = threading.Thread(target=claim_worker)
                claim_thread.start()
                self.assertTrue(claim_write_entered.wait(timeout=5))
                replacement_thread = threading.Thread(target=replacement_worker)
                replacement_thread.start()
                self.assertFalse(replacement_finished.wait(timeout=0.1))
                permit_claim_write.set()
                claim_thread.join(timeout=5)
                replacement_thread.join(timeout=5)
            self.assertFalse(claim_thread.is_alive())
            self.assertFalse(replacement_thread.is_alive())
            self.assertEqual(thread_errors, [])
            self.assertEqual(len(atomic_reservations), 1)
            self.assertEqual(len(replacement_errors), 1)
            self.assertIn(
                "active-scope-campaign-nonterminal",
                str(replacement_errors[0]),
            )
            LIVE.validate_active_outer_authority(
                successor["outer_snapshot"],
                candidate_commit=successor["checkpoint"],
                candidate_tree=successor["checkpoint_tree"],
                registry_root=authority_registry,
            )
            LIVE.transition_global_campaign_state(
                atomic_reservations[0],
                "active",
                outer_authority=successor["outer_snapshot"],
                candidate_commit=successor["checkpoint"],
                candidate_tree=successor["checkpoint_tree"],
                registry_root=authority_registry,
            )
            with self.assertRaisesRegex(
                LIVE.AppServerError, "active-scope-campaign-nonterminal"
            ):
                LIVE.register_active_outer_authority(
                    replacement_snapshot,
                    candidate_commit=successor["checkpoint"],
                    candidate_tree=successor["checkpoint_tree"],
                    registry_root=authority_registry,
                )
            LIVE.transition_global_campaign_state(
                atomic_reservations[0],
                "terminal",
                terminal_evidence_sha256="e" * 64,
            )
            LIVE.register_active_outer_authority(
                replacement_snapshot,
                candidate_commit=successor["checkpoint"],
                candidate_tree=successor["checkpoint_tree"],
                registry_root=authority_registry,
            )
            with self.assertRaisesRegex(
                LIVE.AppServerError, "registry-mismatch"
            ):
                LIVE.validate_active_outer_authority(
                    successor["outer_snapshot"],
                    candidate_commit=successor["checkpoint"],
                    candidate_tree=successor["checkpoint_tree"],
                    registry_root=authority_registry,
                )
            recycled_outer = json.loads(
                json.dumps(successor["outer_snapshot"].value)
            )
            recycled_outer["supersession"] = {
                "prior_outer_authority_id": replacement_outer["authority_id"],
                "prior_outer_authority_file_sha256": replacement_snapshot.raw_sha256,
                "prior_outer_authority_canonical_sha256": replacement_outer[
                    "canonical_outer_authority_sha256"
                ],
            }
            self.seal_field(
                recycled_outer, "canonical_outer_authority_sha256"
            )
            with self.assertRaisesRegex(
                LIVE.AppServerError, "authority-id-reused"
            ):
                LIVE.register_active_outer_authority(
                    self.json_snapshot(recycled_outer),
                    candidate_commit=successor["checkpoint"],
                    candidate_tree=successor["checkpoint_tree"],
                    registry_root=authority_registry,
                )

            real_registry = root / "real-authority-registry"
            real_registry.mkdir(mode=0o700)
            alias_registry = root / "alias-authority-registry"
            alias_registry.symlink_to(real_registry, target_is_directory=True)
            with self.assertRaisesRegex(
                LIVE.AppServerError, "directory-permissions-invalid"
            ):
                LIVE.register_active_outer_authority(
                    replacement_snapshot,
                    candidate_commit=successor["checkpoint"],
                    candidate_tree=successor["checkpoint_tree"],
                    registry_root=alias_registry,
                )
            with tempfile.TemporaryDirectory() as alternate_home, mock.patch.dict(
                "os.environ", {"HOME": alternate_home}
            ), mock.patch.object(
                LIVE.pwd,
                "getpwuid",
                return_value=mock.Mock(pw_dir=str(root / "account-home")),
            ):
                account_home = root / "account-home"
                account_home.mkdir(mode=0o700)
                (account_home / ".codex").mkdir(mode=0o700)
                stable_root = LIVE._stable_codex_control_root()
            self.assertEqual(
                stable_root,
                (account_home / ".codex").resolve(),
            )
            self.assertNotEqual(stable_root, Path(alternate_home) / ".codex")

    def test_existing_control_root_and_parent_are_fsynced(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            control_root = parent / "existing-control-root"
            control_root.mkdir(mode=0o700)
            with mock.patch.object(
                LIVE,
                "_fsync_owned_control_directory",
                wraps=LIVE._fsync_owned_control_directory,
            ) as durable_directory:
                self.assertEqual(
                    LIVE._private_control_directory(control_root, "existing"),
                    control_root,
                )
            self.assertTrue(
                any(
                    call.args[:2] == (control_root, "existing")
                    and call.kwargs == {"require_private": True}
                    for call in durable_directory.mock_calls
                ),
                durable_directory.mock_calls,
            )
            self.assertTrue(
                any(
                    call.args[:2] == (parent, "existing-parent")
                    and call.kwargs == {"require_private": False}
                    for call in durable_directory.mock_calls
                ),
                durable_directory.mock_calls,
            )

            original_fsync = LIVE._fsync_owned_control_directory

            def fail_parent_fsync(
                path: Path, label: str, *, require_private: bool
            ) -> None:
                if path == parent:
                    raise LIVE.AppServerError("injected-parent-fsync-failure")
                original_fsync(
                    path, label, require_private=require_private
                )

            with mock.patch.object(
                LIVE,
                "_fsync_owned_control_directory",
                side_effect=fail_parent_fsync,
            ):
                with self.assertRaisesRegex(
                    LIVE.AppServerError, "injected-parent-fsync-failure"
                ):
                    LIVE._private_control_directory(control_root, "existing")

    def test_conflicting_legacy_claims_quarantine_registry(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            authorization_id = str(uuid.uuid4())

            def legacy_claim(nonce: str) -> dict:
                identity = {
                    "authorization_id": authorization_id,
                    "run_generation": 11,
                    "live_generation": 6,
                    "campaign_nonce": nonce,
                }
                value = {
                    "claim_type": "cwo-native-live-campaign-global-claim",
                    "version": 1,
                    "identity": identity,
                    "identity_sha256": LIVE.domain_sha256(
                        identity, domain="native-live-global-claim"
                    ),
                }
                value["canonical_claim_sha256"] = LIVE.domain_sha256(
                    value, domain="native-live-global-claim-artifact"
                )
                return value

            for index in range(2):
                value = legacy_claim(str(uuid.uuid4()))
                path = root / f"legacy-{index}.json"
                path.write_text(
                    json.dumps(value, sort_keys=True), encoding="utf-8"
                )
                path.chmod(0o600)
            with self.assertRaisesRegex(
                LIVE.AppServerError, "global-claim-marker-conflict"
            ):
                LIVE._migrate_global_claim_markers(root)

    def test_historical_campaign_contract_is_not_operative(self) -> None:
        for authorization_version, manifest_version in (
            (5, 2),
            (6, 3),
            (7, 4),
            (8, 5),
            (9, 6),
            (10, 7),
        ):
            with self.subTest(
                authorization_version=authorization_version,
                manifest_version=manifest_version,
            ), self.assertRaisesRegex(
                LIVE.AppServerError,
                "campaign-authorization-version-historical-only",
            ):
                LIVE.require_operative_campaign_contract(
                    authorization_version, manifest_version
                )
        with self.assertRaisesRegex(
            LIVE.AppServerError, "campaign-contract-version-mismatch"
        ):
            LIVE.require_operative_campaign_contract(12, 7, 6, 6)
        LIVE.require_operative_campaign_contract(12, 8, 6, 6)

    def test_legacy_authority_history_requires_complete_seed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            registry_root = root / "authority-registry"
            candidate_commit = "1" * 40
            candidate_tree = "2" * 40
            scope = {
                "epic_id": "complex-work-orchestration-18w",
                "parent_work_unit_id": "complex-work-orchestration-18w.6",
            }
            scope_key = LIVE.active_outer_authority_scope_key(
                scope["epic_id"], scope["parent_work_unit_id"]
            )

            def outer(
                authority_id: str,
                *,
                predecessor: LIVE.JsonArtifactSnapshot | None = None,
            ) -> dict:
                value = {
                    "authority_type": "cwo-full-auto-outer-recovery-authority",
                    "version": 1,
                    "authority_id": authority_id,
                    "status": "active",
                    "scope": scope,
                    "active_registry": {
                        "contract": "cwo-active-outer-authority-registry:v1",
                        "scope_key": scope_key,
                    },
                    "bindings": {
                        "candidate_commit": candidate_commit,
                        "candidate_tree": candidate_tree,
                    },
                }
                if predecessor is not None:
                    value["supersession"] = {
                        "prior_outer_authority_id": predecessor.value[
                            "authority_id"
                        ],
                        "prior_outer_authority_file_sha256": (
                            predecessor.raw_sha256
                        ),
                        "prior_outer_authority_canonical_sha256": (
                            predecessor.value[
                                "canonical_outer_authority_sha256"
                            ]
                        ),
                    }
                self.seal_field(value, "canonical_outer_authority_sha256")
                return value

            first = self.json_snapshot(outer(str(uuid.uuid4())))
            LIVE.register_active_outer_authority(
                first,
                candidate_commit=candidate_commit,
                candidate_tree=candidate_tree,
                registry_root=registry_root,
            )
            active_path, _lock_path, _scope_key = (
                LIVE._active_authority_registry_path(
                    first.value, registry_root
                )
            )
            current = LIVE.load_private_json(
                active_path, "active-outer-authority-registry"
            )
            history_path = LIVE._authority_history_path(
                active_path.parent,
                scope_key,
                str(first.value["authority_id"]),
            )
            history_path.unlink()

            replacement_value = outer(str(uuid.uuid4()), predecessor=first)
            with self.assertRaisesRegex(
                LIVE.AppServerError, "authority-history-seed-missing"
            ):
                LIVE.register_active_outer_authority(
                    self.json_snapshot(replacement_value),
                    candidate_commit=candidate_commit,
                    candidate_tree=candidate_tree,
                    registry_root=registry_root,
                )

            seed_entry = {
                "authority_id": current["authority_id"],
                "authority_file_sha256": current[
                    "authority_file_sha256"
                ],
                "authority_canonical_sha256": current[
                    "authority_canonical_sha256"
                ],
                "candidate_commit": current["candidate_commit"],
                "candidate_tree": current["candidate_tree"],
                "predecessor_authority_id": None,
            }

            mismatched = json.loads(json.dumps(replacement_value))
            mismatched_seed = {
                "contract": "cwo-native-live-authority-history-seed:v1",
                "complete": True,
                "entries": [
                    {**seed_entry, "candidate_tree": "3" * 40}
                ],
            }
            self.seal_field(mismatched_seed, "canonical_seed_sha256")
            mismatched["authority_history_seed"] = mismatched_seed
            self.seal_field(mismatched, "canonical_outer_authority_sha256")
            with self.assertRaisesRegex(
                LIVE.AppServerError,
                "authority-history-seed-current-mismatch",
            ):
                LIVE.register_active_outer_authority(
                    self.json_snapshot(mismatched),
                    candidate_commit=candidate_commit,
                    candidate_tree=candidate_tree,
                    registry_root=registry_root,
                )

            seed = {
                "contract": "cwo-native-live-authority-history-seed:v1",
                "complete": True,
                "entries": [seed_entry],
            }
            self.seal_field(seed, "canonical_seed_sha256")
            replacement_value["authority_history_seed"] = seed
            self.seal_field(
                replacement_value, "canonical_outer_authority_sha256"
            )
            replacement = self.json_snapshot(replacement_value)
            LIVE.register_active_outer_authority(
                replacement,
                candidate_commit=candidate_commit,
                candidate_tree=candidate_tree,
                registry_root=registry_root,
            )
            self.assertTrue(history_path.is_file())
            self.assertTrue(
                LIVE._authority_history_path(
                    active_path.parent,
                    scope_key,
                    str(replacement.value["authority_id"]),
                ).is_file()
            )

    def test_descriptor_identity_blocks_replacement_read_restore(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source.json"
            attacker = root / "attacker.json"
            saved = root / "saved.json"
            source.write_text('{"source":true}\n', encoding="utf-8")
            attacker.write_text('{"attacker":true}\n', encoding="utf-8")
            source.chmod(0o600)
            attacker.chmod(0o600)
            identity = LIVE.capture_input_source_identities(
                {"source": source}
            )["source"]
            original_open = LIVE.os.open

            def replacement_open(path: object, flags: int, *args: object) -> int:
                if Path(path) == source.resolve():
                    LIVE.os.replace(source, saved)
                    LIVE.os.replace(attacker, source)
                    descriptor = original_open(path, flags, *args)
                    LIVE.os.replace(source, attacker)
                    LIVE.os.replace(saved, source)
                    return descriptor
                return original_open(path, flags, *args)

            with mock.patch.object(LIVE.os, "open", side_effect=replacement_open):
                with self.assertRaisesRegex(
                    LIVE.AppServerError, "source-identity-changed"
                ):
                    LIVE.load_private_bytes(
                        source,
                        "source",
                        expected_identity=identity,
                    )
            with mock.patch.object(LIVE.os, "open", side_effect=replacement_open):
                with self.assertRaisesRegex(
                    LIVE.AppServerError, "source-identity-changed"
                ):
                    LIVE.load_trusted_session_bytes(
                        source,
                        "source-session",
                        expected_identity=identity,
                    )

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

            graph_kwargs = {
                key: value
                for key, value in base_kwargs.items()
                if key != "cause_evidence"
            }
            for alias in PARSEABLE_UUID_ALIASES:
                original = json.loads(
                    json.dumps(predecessor["original_containment"])
                )
                original["failed_authorization_id"] = alias
                self.seal_field(original, "canonical_recovery_sha256")
                original_raw = json.dumps(
                    original, sort_keys=True, separators=(",", ":")
                ).encode()
                correction = json.loads(json.dumps(predecessor["containment"]))
                correction["correction"][
                    "original_recorded_authorization_id"
                ] = alias
                correction["correction"][
                    "original_artifact_file_sha256"
                ] = LIVE.sha256_bytes(original_raw)
                correction["correction"][
                    "original_artifact_canonical_sha256"
                ] = original["canonical_recovery_sha256"]
                self.seal_field(correction, "canonical_recovery_sha256")
                correction_raw = json.dumps(
                    correction, sort_keys=True, separators=(",", ":")
                ).encode()
                bindings = json.loads(json.dumps(authorization["bindings"]))
                bindings.update(
                    {
                        "predecessor_original_containment_file_sha256": LIVE.sha256_bytes(
                            original_raw
                        ),
                        "predecessor_original_containment_canonical_sha256": original[
                            "canonical_recovery_sha256"
                        ],
                        "predecessor_containment_file_sha256": LIVE.sha256_bytes(
                            correction_raw
                        ),
                        "predecessor_containment_canonical_sha256": correction[
                            "canonical_recovery_sha256"
                        ],
                    }
                )
                errors = CAMPAIGN_CONTRACTS._validate_predecessor_proof_graph(
                    bindings=bindings,
                    progress=authorization["progress_gate"],
                    supersession=authorization["supersession"],
                    predecessor_live_generation=authorization[
                        "predecessor_live_generation"
                    ],
                    repo_root=root,
                    **{
                        **graph_kwargs,
                        "predecessor_original_containment": original,
                        "predecessor_original_containment_raw_sha256": LIVE.sha256_bytes(
                            original_raw
                        ),
                        "predecessor_containment": correction,
                        "predecessor_containment_raw_sha256": LIVE.sha256_bytes(
                            correction_raw
                        ),
                    },
                )
                with self.subTest(alias=repr(alias)):
                    self.assertIn(
                        "authorization-predecessor-original-containment-binding-invalid",
                        errors,
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

    def test_pure_steering_launch_binding_rejects_each_mismatch(self) -> None:
        auth_id = str(uuid.uuid4())
        auth_sha = "a" * 64
        base_mutation = self.receipt("pre-mutation", auth_id)
        base_live = self.receipt("pre-live", auth_id)
        cases = (
            ("pre-mutation", "gate", "pre-live", "pre-mutation-steering-binding"),
            ("pre-mutation", "authorization_id", str(uuid.uuid4()), "pre-mutation-steering-binding"),
            ("pre-mutation", "authorization_sha256", "b" * 64, "pre-mutation-steering-binding"),
            ("pre-live", "gate", "pre-mutation", "pre-live-steering-binding"),
            ("pre-live", "authorization_id", str(uuid.uuid4()), "pre-live-steering-binding"),
            ("pre-live", "authorization_sha256", "b" * 64, "pre-live-steering-binding"),
        )
        for target, field, value, expected in cases:
            with self.subTest(target=target, field=field):
                pre_mutation = dict(base_mutation)
                pre_live = dict(base_live)
                (pre_mutation if target == "pre-mutation" else pre_live)[field] = value
                with self.assertRaisesRegex(LIVE.AppServerError, expected):
                    LIVE.validate_steering_launch_bindings(
                        auth_id,
                        auth_sha,
                        pre_mutation_receipt=pre_mutation,
                        pre_mutation_adjudication={"main_architect_decision": "go"},
                        pre_mutation_adjudication_sha256="c" * 64,
                        pre_live_receipt=pre_live,
                        pre_live_adjudication={"main_architect_decision": "go"},
                        pre_live_adjudication_sha256="d" * 64,
                    )

    def test_pure_steering_launch_binding_accepts_exact_current_inner(self) -> None:
        auth_id = str(uuid.uuid4())
        LIVE.validate_steering_launch_bindings(
            auth_id,
            "a" * 64,
            pre_mutation_receipt=self.receipt("pre-mutation", auth_id),
            pre_mutation_adjudication={"main_architect_decision": "go"},
            pre_mutation_adjudication_sha256="c" * 64,
            pre_live_receipt=self.receipt("pre-live", auth_id),
            pre_live_adjudication={"main_architect_decision": "go"},
            pre_live_adjudication_sha256="d" * 64,
        )

    def test_preclaim_rejection_creates_no_durable_campaign_authority(self) -> None:
        paths = {
            "output": Path("/private/evidence.json"),
            "authorization_state": Path("/private/state.json"),
            "steering_registry": Path("/private/steering.json"),
            "allocation_ledger": Path("/private/ledger"),
        }
        with mock.patch.object(
            LIVE,
            "validate_campaign_launch_bindings",
            side_effect=LIVE.AppServerError("pre-mutation-steering-binding-invalid"),
        ), mock.patch.object(LIVE, "campaign_launch_claim_sha256") as claim, mock.patch.object(
            LIVE, "seal_bound_manifest_validation"
        ) as seal, mock.patch.object(LIVE, "acquire_global_campaign_claim") as acquire:
            with self.assertRaisesRegex(
                LIVE.AppServerError, "pre-mutation-steering-binding-invalid"
            ):
                LIVE.validate_and_acquire_global_campaign_claim(
                    mock.sentinel.inputs,
                    campaign_nonce=str(uuid.uuid4()),
                    authorization_id=str(uuid.uuid4()),
                    authorization_sha256="a" * 64,
                    repo_head="b" * 40,
                    guarded_primary=Path("/guarded"),
                    **paths,
                )
        claim.assert_not_called()
        seal.assert_not_called()
        acquire.assert_not_called()

    def test_nonaccepting_steering_never_acquires_global_claim(self) -> None:
        inputs = mock.MagicMock()
        inputs.pre_mutation_receipt.value = {}
        inputs.pre_mutation_adjudication.value = {}
        inputs.pre_live_receipt.value = {}
        inputs.pre_live_adjudication.value = {}
        paths = {
            "output": Path("/private/evidence.json"),
            "authorization_state": Path("/private/state.json"),
            "steering_registry": Path("/private/steering.json"),
            "allocation_ledger": Path("/private/ledger"),
        }
        with mock.patch.object(
            LIVE, "validate_campaign_launch_bindings", return_value={}
        ), mock.patch.object(
            LIVE,
            "plan_steering_receipt_consumptions",
            side_effect=LIVE.AppServerError(
                "pre-mutation-steering-not-accepting"
            ),
        ), mock.patch.object(LIVE, "campaign_launch_claim_sha256") as claim, mock.patch.object(
            LIVE, "acquire_global_campaign_claim"
        ) as acquire:
            with self.assertRaisesRegex(
                LIVE.AppServerError, "pre-mutation-steering-not-accepting"
            ):
                LIVE.validate_and_acquire_global_campaign_claim(
                    inputs,
                    campaign_nonce=str(uuid.uuid4()),
                    authorization_id=str(uuid.uuid4()),
                    authorization_sha256="a" * 64,
                    repo_head="b" * 40,
                    guarded_primary=Path("/guarded"),
                    **paths,
                )
        claim.assert_not_called()
        acquire.assert_not_called()

    def test_global_claim_path_forwards_gate_scoped_operator_authorities(
        self,
    ) -> None:
        inputs = mock.MagicMock()
        inputs.pre_mutation_receipt.value = {"gate": "pre-mutation"}
        inputs.pre_mutation_adjudication.value = {"main_architect_decision": "go"}
        inputs.pre_mutation_adjudication.raw_sha256 = "d" * 64
        inputs.pre_live_receipt.value = {"gate": "pre-live"}
        inputs.pre_live_adjudication.value = {"main_architect_decision": "go"}
        inputs.pre_live_adjudication.raw_sha256 = "e" * 64
        pre_mutation_authorities = (mock.sentinel.pre_mutation_authority,)
        pre_live_authorities = (mock.sentinel.pre_live_authority,)
        prepared = {
            "pre-mutation": ("a" * 64, {}),
            "pre-live": ("b" * 64, {}),
        }
        with mock.patch.object(
            LIVE, "validate_campaign_launch_bindings", return_value={}
        ), mock.patch.object(
            LIVE, "plan_steering_receipt_consumptions", return_value=prepared
        ) as plan_receipts, mock.patch.object(
            LIVE, "campaign_launch_claim_sha256", return_value="c" * 64
        ), mock.patch.object(
            LIVE, "seal_bound_manifest_validation", return_value={"sealed": True}
        ), mock.patch.object(
            LIVE, "acquire_global_campaign_claim", return_value=mock.sentinel.reservation
        ):
            result = LIVE.validate_and_acquire_global_campaign_claim(
                inputs,
                campaign_nonce=str(uuid.uuid4()),
                authorization_id=str(uuid.uuid4()),
                authorization_sha256="a" * 64,
                repo_head="b" * 40,
                guarded_primary=Path("/guarded"),
                output=Path("/private/evidence.json"),
                authorization_state=Path("/private/state.json"),
                steering_registry=Path("/private/steering.json"),
                allocation_ledger=Path("/private/ledger"),
                pre_mutation_verified_operator_authorities=(
                    pre_mutation_authorities
                ),
                pre_live_verified_operator_authorities=pre_live_authorities,
            )
        self.assertIs(result[3], prepared)
        self.assertIs(result[4], mock.sentinel.reservation)
        self.assertIs(
            plan_receipts.call_args.kwargs[
                "pre_mutation_verified_operator_authorities"
            ],
            pre_mutation_authorities,
        )
        self.assertIs(
            plan_receipts.call_args.kwargs["pre_live_verified_operator_authorities"],
            pre_live_authorities,
        )

    def test_real_malformed_or_replayed_steering_never_acquires_claim(self) -> None:
        for scenario in ("malformed-canonical", "replay"):
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                campaign_nonce = str(uuid.uuid4())
                authorization_id = str(uuid.uuid4())
                authorization_sha256 = "a" * 64
                pre_mutation = self.valid_steering_receipt(
                    "pre-mutation", authorization_id, authorization_sha256
                )
                pre_live = self.valid_steering_receipt(
                    "pre-live", authorization_id, authorization_sha256
                )
                registry = root / "steering.json"
                if scenario == "malformed-canonical":
                    pre_mutation["canonical_receipt_sha256"] = "f" * 64
                else:
                    phase_nonce = str(
                        uuid.uuid5(
                            uuid.NAMESPACE_URL,
                            (
                                f"{campaign_nonce}:pre-mutation:"
                                f"{pre_mutation['canonical_receipt_sha256']}"
                            ),
                        )
                    )
                    LIVE.consume_steering_receipt(
                        pre_mutation,
                        registry,
                        phase_nonce=phase_nonce,
                        architect_adjudication_sha256="d" * 64,
                        architect_decision="go",
                    )
                inputs = mock.MagicMock()
                inputs.pre_mutation_receipt.value = pre_mutation
                inputs.pre_mutation_adjudication.value = {
                    "main_architect_decision": "go"
                }
                inputs.pre_mutation_adjudication.raw_sha256 = "d" * 64
                inputs.pre_live_receipt.value = pre_live
                inputs.pre_live_adjudication.value = {
                    "main_architect_decision": "go"
                }
                inputs.pre_live_adjudication.raw_sha256 = "e" * 64
                paths = {
                    "output": root / "evidence.json",
                    "authorization_state": root / "state.json",
                    "steering_registry": registry,
                    "allocation_ledger": root / "ledger",
                }
                with mock.patch.object(
                    LIVE, "validate_campaign_launch_bindings", return_value={}
                ), mock.patch.object(
                    LIVE, "campaign_launch_claim_sha256"
                ) as claim, mock.patch.object(
                    LIVE, "acquire_global_campaign_claim"
                ) as acquire:
                    with self.assertRaisesRegex(
                        LIVE.AppServerError, "pre-mutation-steering-not-accepting"
                    ):
                        LIVE.validate_and_acquire_global_campaign_claim(
                            inputs,
                            campaign_nonce=campaign_nonce,
                            authorization_id=authorization_id,
                            authorization_sha256=authorization_sha256,
                            repo_head="b" * 40,
                            guarded_primary=root / "guarded",
                            **paths,
                        )
                claim.assert_not_called()
                acquire.assert_not_called()
                self.assertFalse(paths["output"].exists())
                self.assertFalse(paths["authorization_state"].exists())
                self.assertFalse(paths["allocation_ledger"].exists())

    def test_steering_plan_rejects_uuid_aliases_before_receipt_validation(self) -> None:
        auth_id = str(uuid.uuid4())
        pre_mutation = self.receipt("pre-mutation", auth_id)
        pre_live = self.receipt("pre-live", auth_id)
        for identity_field in ("campaign_nonce", "authorization_id"):
            for alias in UUID_TEXT_ALIASES:
                with self.subTest(field=identity_field, alias=repr(alias)), tempfile.TemporaryDirectory() as temporary, mock.patch.object(
                    LIVE, "consume_steering_receipt"
                ) as consume:
                    with self.assertRaisesRegex(
                        LIVE.AppServerError,
                        (
                            "steering-control-identity-invalid"
                            if identity_field == "campaign_nonce"
                            else "steering-authorization-identity-invalid"
                        ),
                    ):
                        LIVE.plan_steering_receipt_consumptions(
                            alias
                            if identity_field == "campaign_nonce"
                            else str(uuid.uuid4()),
                            alias if identity_field == "authorization_id" else auth_id,
                            "a" * 64,
                            registry_file=Path(temporary) / "registry.json",
                            repo_head="d" * 40,
                            pre_mutation_receipt=pre_mutation,
                            pre_mutation_adjudication={
                                "main_architect_decision": "go"
                            },
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

    def test_steering_plan_preserves_gate_scoped_operator_authorities(self) -> None:
        auth_id = str(uuid.uuid4())
        pre_mutation_authority = mock.sentinel.pre_mutation_authority
        pre_live_authority = mock.sentinel.pre_live_authority
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(
            LIVE, "consume_steering_receipt", return_value="validated"
        ) as consume:
            prepared = LIVE.plan_steering_receipt_consumptions(
                str(uuid.uuid4()),
                auth_id,
                "a" * 64,
                registry_file=Path(temporary) / "registry.json",
                repo_head="d" * 40,
                pre_mutation_receipt=self.receipt("pre-mutation", auth_id),
                pre_mutation_adjudication={"main_architect_decision": "go"},
                pre_mutation_adjudication_sha256="d" * 64,
                pre_live_receipt=self.receipt("pre-live", auth_id),
                pre_live_adjudication={"main_architect_decision": "go"},
                pre_live_adjudication_sha256="e" * 64,
                pre_mutation_verified_operator_authorities=iter(
                    [pre_mutation_authority]
                ),
                pre_live_verified_operator_authorities=iter([pre_live_authority]),
            )
        expected = {
            "pre-mutation": (pre_mutation_authority,),
            "pre-live": (pre_live_authority,),
        }
        for label, call in zip(expected, consume.call_args_list, strict=True):
            self.assertEqual(
                call.kwargs["verified_operator_authorities"], expected[label]
            )
            self.assertIs(
                prepared[label][1]["verified_operator_authorities"][0],
                expected[label][0],
            )


if __name__ == "__main__":
    unittest.main()
