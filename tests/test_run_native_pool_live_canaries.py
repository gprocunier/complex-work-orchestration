from __future__ import annotations

import copy
import datetime as dt
import importlib.util
import io
import json
import os
from pathlib import Path
import queue
import shutil
import subprocess
import sys
import tempfile
import threading
from typing import Any, Mapping
import unittest
from unittest import mock
import uuid


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from cwo_core.native_live_allocation_ledger import EXPECTED_ROLES  # noqa: E402
from cwo_core import workspace_capture  # noqa: E402
# AppServer and its helpers live here; patch module globals they read at their
# defining module, not on the runner that re-exports them.
from cwo_core.supervision.transport import app_server as TRANSPORT  # noqa: E402
from cwo_core.supervision import live_thread as LIVE_THREAD  # noqa: E402
from cwo_core.native_tool_isolation import (  # noqa: E402
    seal_tool_enforcement_override,
)
from cwo_core.native_activation_preview import (  # noqa: E402
    MUTABLE_PATCH_INPUT,
    fixed_activation_tool_trace,
)
from cwo_core.native_worker_contracts import (  # noqa: E402
    canonical_argument_hash,
)
from tests.real_beads_fixture import configure_git_fixture

SPEC = importlib.util.spec_from_file_location(
    "run_native_pool_live_canaries", ROOT / "scripts" / "run_native_pool_live_canaries.py"
)
assert SPEC and SPEC.loader
LIVE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(LIVE)


def setUpModule() -> None:
    # held-route mechanics use fake processes/RPC and fake durable writers.
    global _F5_HELD_ROUTE_PATCH
    _F5_HELD_ROUTE_PATCH = mock.patch.multiple(LIVE.live_availability,
        N1_LIVE_AVAILABLE=True, POOL_LIVE_AVAILABLE=True, CAMPAIGN_LIVE_AVAILABLE=True)
    _F5_HELD_ROUTE_PATCH.start()


def tearDownModule() -> None:
    _F5_HELD_ROUTE_PATCH.stop()


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


class FakeMonotonicClock:
    def __init__(self) -> None:
        self.now_ns = 0

    def __call__(self) -> int:
        return self.now_ns

    def advance_ms(self, milliseconds: int) -> None:
        self.now_ns += milliseconds * 1_000_000


class FakeElapsedClock:
    def __init__(self) -> None:
        self.seconds = 0.0
        self.started_at = dt.datetime(
            2026, 1, 1, tzinfo=dt.timezone.utc
        )

    def monotonic(self) -> float:
        return self.seconds

    def monotonic_ns(self) -> int:
        return round(self.seconds * 1_000_000_000)

    def sleep(self, seconds: float) -> None:
        self.seconds += seconds

    def utc_now(self) -> dt.datetime:
        return self.started_at + dt.timedelta(seconds=self.seconds)


class FakeLiveThreadServer:
    def __init__(
        self,
        root: Path,
        *,
        initial_boundary: str = "missing",
        read_statuses: list[str] | None = None,
    ) -> None:
        self.root = root.resolve()
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
        self.requested_model = LIVE.EXACT_MODEL
        self._effective_thread_start_evidence: dict[str, dict] = {}
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
            {
                "type": "session_meta",
                "payload": {
                    "id": self.thread_id,
                    "session_id": self.thread_id,
                    "cwd": str(self.root),
                },
            },
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

    def thread_response(self, *, mutable: bool = False) -> dict:
        request = {
            "model": LIVE.EXACT_MODEL,
            "allowProviderModelFallback": False,
            "sandbox": "workspace-write" if mutable else "read-only",
            "approvalPolicy": "never",
            "cwd": str(self.root),
            "runtimeWorkspaceRoots": [str(self.root)],
        }
        response = {
            "model": LIVE.EXACT_MODEL,
            "modelProvider": "trusted",
            "sandbox": {
                "type": "workspaceWrite" if mutable else "readOnly",
                **({"writableRoots": []} if mutable else {}),
            },
            "approvalPolicy": "never",
            "cwd": str(self.root),
            "runtimeWorkspaceRoots": [str(self.root)],
            "thread": {"id": self.thread_id, "turns": [], "path": str(self.path)},
        }
        self._effective_thread_start_evidence[self.thread_id] = {
            "request": copy.deepcopy(request),
            "response": copy.deepcopy(response),
        }
        return response

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
        server._delete_acceptance_proofs = {}
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

    def test_only_original_qualification_read_classifies_cold_history(self) -> None:
        from cwo_core.supervision.transport.app_server import _QUALIFICATION_RPC

        diagnostic = ("thread thread-1 is not materialized yet; "
                      "includeTurns is unavailable before first user message")
        for label, selected, thread_id, include_turns, code, peer_message in (
            ("exact", True, "thread-1", True, -32600, diagnostic),
            ("generic", True, "thread-1", True, -32600, "bad request"),
            ("extra text", True, "thread-1", True, -32600, diagnostic + " EXAMPLE marker"),
            ("wrong diagnostic thread", True, "thread-1", True, -32600, diagnostic.replace("thread-1", "thread-2")),
            ("wrong request thread", True, "thread-2", True, -32600, diagnostic.replace("thread-1", "thread-2")),
            ("metadata only", True, "thread-1", False, -32600, diagnostic),
            ("non-boolean includeTurns", True, "thread-1", 1, -32600, diagnostic),
            ("unsupported", True, "thread-1", True, -32601, diagnostic),
            ("before thread start", True, "thread-1", True, -32600, diagnostic),
            ("other route", False, "thread-1", True, -32600, diagnostic),
        ):
            with self.subTest(label=label):
                server = self.request_server({"id": 1, "error": {"code": code, "message": peer_message}})
                if selected:
                    server.thread_id = None if label == "before thread start" else "thread-1"
                    _QUALIFICATION_RPC.register(server, (lambda: None, lambda *_args: None, "default"))
                    self.addCleanup(_QUALIFICATION_RPC.pop, server, None)
                with self.assertRaises(LIVE.AppServerRpcError) as raised:
                    server.request("thread/read", {"threadId": thread_id, "includeTurns": include_turns})
                self.assertIs(raised.exception.qualification_thread_unmaterialized, label == "exact")
                self.assertEqual(str(raised.exception), f"app-server-request-failed:thread/read:{code}")
                self.assertNotIn(peer_message, repr(vars(raised.exception)))

    def test_cold_history_classification_requires_a_boolean(self) -> None:
        with self.assertRaisesRegex(ValueError, "qualification-unmaterialized-invalid"):
            LIVE.AppServerRpcError(method="thread/read", code=-32600, request_id=1,
                latency_ms=1.0, qualification_thread_unmaterialized=1)

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

    def test_precommit_fit_thread_start_is_estimate_only_and_exact_schema(self) -> None:
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
        exact_tools = ["apply_patch", "exec_command", "write_stdin"]
        server.tool_surface_capability = lambda *, permitted_tools: {
            "source": "supported-test-server",
            "server_allowlist_supported": True,
            "allowlist_parameter": "tools",
            "effective_allowlist": list(permitted_tools),
        }
        server.operative_tool_transport = lambda: LIVE.NAMESPACED_EXEC_TOOL_TRANSPORT
        server.start_thread(
            ROOT,
            mutable=False,
            thread_phase=LIVE.THREAD_PHASE_PRECOMMIT_FIT,
            permitted_tools=exact_tools,
            allowlist_parameter="tools",
        )
        wire = json.loads(server.process.stdin.getvalue().splitlines()[-1])
        instructions = wire["params"]["developerInstructions"]
        self.assertIn("no-tools precommit fit estimate", instructions)
        self.assertIn("not the later implementation task", instructions)
        self.assertIn("containing only these five fields", instructions)
        for field in (
            "decision",
            "tool_calls_p50",
            "tool_calls_p90",
            "runtime_seconds_p50",
            "runtime_seconds_p90",
        ):
            self.assertIn(field, instructions)
        self.assertIn("Do not add status, reason, primary_outcome", instructions)
        self.assertNotIn("Follow the user task exactly", instructions)
        self.assertNotIn("functions.exec transport", instructions)
        self.assertEqual(wire["params"]["sandbox"], "read-only")

    def test_live_canary_thread_start_preserves_namespaced_exec_instructions(self) -> None:
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
        server.operative_tool_transport = lambda: LIVE.NAMESPACED_EXEC_TOOL_TRANSPORT
        server.start_thread(ROOT, mutable=True)
        wire = json.loads(server.process.stdin.getvalue().splitlines()[-1])
        instructions = wire["params"]["developerInstructions"]
        self.assertIn("bounded CWO live canary", instructions)
        self.assertIn("Follow the user task exactly", instructions)
        self.assertIn("functions.exec transport", instructions)
        self.assertNotIn("precommit fit estimate", instructions)
        self.assertEqual(wire["params"]["sandbox"], "workspace-write")

    def test_direct_thread_start_makes_controller_cwd_authoritative(self) -> None:
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
        server.operative_tool_transport = lambda: LIVE.DIRECT_TOOL_TRANSPORT
        server.start_thread(ROOT, mutable=True)
        wire = json.loads(server.process.stdin.getvalue().splitlines()[-1])
        instructions = wire["params"]["developerInstructions"]
        self.assertIn("controller-supplied thread cwd is authoritative", instructions)
        self.assertIn("Omit the workdir argument", instructions)
        self.assertEqual(wire["params"]["cwd"], str(ROOT))
        self.assertEqual(wire["params"]["runtimeWorkspaceRoots"], [str(ROOT)])

    def test_thread_start_rejects_noncanonical_workdir_before_transport(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "target"
            target.mkdir()
            alias = root / "alias"
            alias.symlink_to(target, target_is_directory=True)
            for invalid in (Path("relative"), alias, root / "missing"):
                with self.subTest(invalid=invalid):
                    server = self.request_server({"id": 1, "result": {}})
                    server.operative_tool_transport = mock.Mock(
                        side_effect=AssertionError(
                            "workdir gate must precede transport"
                        )
                    )
                    with self.assertRaisesRegex(
                        LIVE.AppServerError, "controller-workdir-invalid"
                    ):
                        server.start_thread(invalid, mutable=False)
                    server.operative_tool_transport.assert_not_called()
                    self.assertEqual(server.process.stdin.getvalue(), "")

    def test_unknown_thread_phase_fails_before_transport_or_allocation(self) -> None:
        server = self.request_server({"id": 1, "result": {}})
        server.operative_tool_transport = mock.Mock(
            side_effect=AssertionError("phase gate must precede transport")
        )
        with self.assertRaisesRegex(LIVE.AppServerError, "thread-start-phase-invalid"):
            server.start_thread(ROOT, mutable=False, thread_phase="unknown-phase")
        server.operative_tool_transport.assert_not_called()
        self.assertEqual(server.process.stdin.getvalue(), "")

    def test_config_proof_thread_start_forwards_locked_config_and_no_dynamic_tools(
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
        server._tool_surface_proof = {"proof_sha256": "a" * 64, "tool_profile": "mutating-v1"}
        exact_tools = ["apply_patch", "exec_command", "write_stdin"]
        verified = {
            "proof_sha256": "a" * 64,
            "observed_tools": exact_tools,
            "codex_version": "0.153.2",
            "tool_transport": LIVE.DIRECT_TOOL_TRANSPORT,
        }
        locked = {"features": {"multi_agent": False}}
        with (
            mock.patch.object(TRANSPORT, "require_surface_proof", return_value=verified),
            mock.patch.object(
                TRANSPORT,
                "thread_start_enforcement_params",
                return_value={"config": locked, "dynamicTools": []},
            ),
        ):
            surface = LIVE.capture_server_tool_surface(
                server,
                LIVE.default_tool_policy(mutable=True),
            )
            server.start_thread(
                ROOT,
                mutable=True,
                permitted_tools=exact_tools,
                allowlist_parameter="config",
            )
            self.assertEqual(
                server.capability_adapter_version(),
                "codex-app-server-0.153.2",
            )
        self.assertTrue(surface["server_allowlist_supported"])
        self.assertEqual(surface["effective_allowlist"], exact_tools)
        wire = json.loads(server.process.stdin.getvalue().splitlines()[-1])
        self.assertEqual(wire["params"]["config"], locked)
        self.assertEqual(wire["params"]["dynamicTools"], [])

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

    def test_activation_containment_deletes_proven_never_turned_without_read(
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
        server.archive_thread = mock.Mock(
            side_effect=AssertionError("thread/archive must not run")
        )
        actions: list[dict] = []
        result = LIVE.contain_started_threads(
            server,
            allow_same_process_proofs=True,
            delete_proven_never_turned=True,
            containment_actions=actions,
        )
        self.assertTrue(result["all_contained"])
        self.assertEqual(result["archived_count"], 0)
        self.assertEqual(
            set(result),
            {
                "allocated_count",
                "identified_thread_count",
                "interrupted_count",
                "archived_count",
                "already_contained_count",
                "unresolved_allocation_intent_count",
                "unresolved_turn_intent_count",
                "ambiguous_count",
                "all_contained",
                "ledger_consistent",
                "ledger_error_sha256",
            },
        )
        self.assertEqual(
            actions,
            [
                {
                    "action": "never-turned-delete",
                    "thread_id_sha256": LIVE.sha256_text(thread_id),
                    "proof_sha256": server.same_process_containment_proofs()[
                        0
                    ]["proof_sha256"],
                }
            ],
        )
        server.read_thread.assert_not_called()
        server.archive_thread.assert_not_called()
        wire = json.loads(server.process.stdin.getvalue().splitlines()[-1])
        self.assertEqual(wire["method"], "thread/delete")
        proofs = server.same_process_containment_proofs()
        self.assertEqual(len(proofs), 1)
        self.assertEqual(proofs[0]["kind"], "never-turned-deleted")
        self.assertEqual(proofs[0]["version"], 2)
        self.assertNotIn(thread_id, json.dumps(proofs))
        server._delete_acceptance_proofs[thread_id][
            "delete_response_sha256"
        ] = "0" * 64
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
        unproven.delete_thread = mock.Mock()
        result = LIVE.contain_started_threads(
            unproven,
            allow_same_process_proofs=True,
            delete_proven_never_turned=True,
        )
        self.assertFalse(result["all_contained"])
        self.assertEqual(result["ambiguous_count"], 1)
        unproven.delete_thread.assert_not_called()

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
        diagnostics: list[dict] = []
        result = LIVE.contain_started_threads(
            archive_failure,
            allow_same_process_proofs=True,
            failure_diagnostics=diagnostics,
        )
        self.assertFalse(result["all_contained"])
        self.assertEqual(result["ambiguous_count"], 1)
        self.assertEqual(
            diagnostics,
            [
                {
                    "thread_id_sha256": LIVE.sha256_text(thread_id),
                    "substep": "never-turned-archive",
                    "failure_class": "AppServerError",
                    "failure_message_sha256": LIVE.sha256_text(
                        "fixed-archive-failure"
                    ),
                }
            ],
        )
        archive_failure.read_thread.assert_not_called()

    def test_activation_delete_failure_is_ambiguous_and_diagnostic(
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
        server.delete_thread = mock.Mock(
            side_effect=LIVE.AppServerRpcError(
                method="thread/delete",
                code=-32603,
                request_id=2,
                latency_ms=1.0,
            )
        )
        server.archive_thread = mock.Mock(
            side_effect=AssertionError("thread/archive must not run")
        )
        server.read_thread = mock.Mock(
            side_effect=AssertionError("thread/read must not run")
        )
        diagnostics: list[dict] = []
        actions: list[dict] = []
        result = LIVE.contain_started_threads(
            server,
            allow_same_process_proofs=True,
            delete_proven_never_turned=True,
            failure_diagnostics=diagnostics,
            containment_actions=actions,
        )
        self.assertFalse(result["all_contained"])
        self.assertEqual(result["ambiguous_count"], 1)
        self.assertEqual(actions, [])
        self.assertEqual(
            diagnostics,
            [
                {
                    "thread_id_sha256": LIVE.sha256_text(thread_id),
                    "substep": "never-turned-delete",
                    "failure_class": "AppServerRpcError",
                    "failure_message_sha256": LIVE.sha256_text(
                        "app-server-request-failed:thread/delete:-32603"
                    ),
                    "rpc_method": "thread/delete",
                    "rpc_code": -32603,
                }
            ],
        )
        server.delete_thread.assert_called_once_with(thread_id)
        server.archive_thread.assert_not_called()
        server.read_thread.assert_not_called()

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
                clock = FakeElapsedClock()
                clock_sleep = mock.Mock(side_effect=clock.sleep)
                clock_time = mock.Mock(
                    spec_set=["monotonic", "monotonic_ns", "sleep"],
                    monotonic=clock.monotonic,
                    monotonic_ns=clock.monotonic_ns,
                    sleep=clock_sleep,
                )
                started = clock.monotonic()
                with mock.patch.object(TRANSPORT, "time", clock_time):
                    with self.assertRaises(LIVE.AmbiguousTurnStartError) as raised:
                        server.start_turn(
                            thread_id,
                            "bounded",
                            timeout=0,
                            ambiguity_timeout=0.03,
                        )
                elapsed = clock.monotonic() - started
                waits = [call.args[0] for call in clock_sleep.call_args_list]
                self.assertTrue(waits)
                self.assertTrue(all(0 < seconds <= 0.03 for seconds in waits))
                self.assertAlmostEqual(elapsed, sum(waits))
                self.assertGreater(elapsed, 0)
                self.assertLessEqual(elapsed, 0.03)
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

    def test_containment_archives_allocated_threads(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            server = FakeLiveThreadServer(root, initial_boundary="valid")
            server.start_turn(server.thread_id, "prompt")
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

class PendingExecTelemetryTests(unittest.TestCase):
    TURN_ID = "pending-exec-turn"

    @classmethod
    def call(cls, tool: str, call_id: str, arguments: dict[str, object]) -> dict:
        return {
            "type": "response_item",
            "payload": {
                "type": "custom_tool_call",
                "call_id": call_id,
                "name": "exec",
                "input": (
                    f"const result = await tools.{tool}("
                    + json.dumps(arguments, separators=(",", ":"))
                    + "); text(JSON.stringify(result));"
                ),
            },
        }

    @staticmethod
    def output(call_id: str, result: dict[str, object]) -> dict:
        return {
            "type": "response_item",
            "payload": {
                "type": "custom_tool_call_output",
                "call_id": call_id,
                "output": [
                    {
                        "type": "input_text",
                        "text": "Script completed\nWall time 1.2 seconds\nOutput:\n",
                    },
                    {
                        "type": "input_text",
                        "text": json.dumps(result, separators=(",", ":")),
                    },
                ],
            },
        }

    @classmethod
    def pending_records(cls) -> list[dict]:
        return [
            {
                "type": "turn_context",
                "payload": {"turn_id": cls.TURN_ID},
            },
            cls.call(
                "exec_command",
                "exec",
                {"cmd": "sleep 2", "workdir": "/tmp"},
            ),
            cls.output(
                "exec",
                {
                    "chunk_id": "abc",
                    "wall_time_seconds": 1.0,
                    "session_id": 28838,
                    "original_token_count": 1,
                    "output": "partial",
                },
            ),
        ]

    @classmethod
    def terminal(cls, records: list[dict]) -> tuple[list[dict], dict]:
        completed = list(records) + [
            {
                "type": "event_msg",
                "payload": {
                    "type": "task_complete",
                    "turn_id": cls.TURN_ID,
                },
            }
        ]
        return completed, {"record_index": len(completed) - 1}

    def test_pending_exec_is_nonfaulting_while_active_but_not_completed(self) -> None:
        summary = LIVE.trusted_tool_evidence_summary(
            self.pending_records(),
            turn_id=self.TURN_ID,
            tool_transport=LIVE.NAMESPACED_EXEC_TOOL_TRANSPORT,
        )
        self.assertEqual(summary["trusted_tool_calls"], 1)
        self.assertEqual(summary["trusted_completed_tool_calls"], 0)
        self.assertEqual(
            summary["trusted_tool_receipts"][0]["result_kind"],
            "paired-pending",
        )
        self.assertEqual(summary["trusted_tool_names"], ["exec_command"])
        self.assertEqual(
            LIVE.forbidden_tool_activity(
                summary["trusted_tool_activity"],
                LIVE.default_tool_policy(mutable=True, workload_class="operative"),
            ),
            [],
        )

    def test_terminal_unresolved_pending_exec_fails_closed(self) -> None:
        records, terminal = self.terminal(self.pending_records())
        summary = LIVE.trusted_tool_evidence_summary(
            records,
            turn_id=self.TURN_ID,
            terminal_event=terminal,
            tool_transport=LIVE.NAMESPACED_EXEC_TOOL_TRANSPORT,
        )
        self.assertEqual(
            summary["trusted_tool_names"],
            ["telemetry_anomaly.exec_command"],
        )
        self.assertTrue(
            LIVE.forbidden_tool_activity(
                summary["trusted_tool_activity"],
                LIVE.default_tool_policy(mutable=True, workload_class="operative"),
            )
        )

    def test_same_session_write_stdin_resolves_pending_exec(self) -> None:
        records = self.pending_records() + [
            self.call(
                "write_stdin",
                "wait",
                {"session_id": 28838, "chars": ""},
            ),
            self.output(
                "wait",
                {
                    "chunk_id": "def",
                    "wall_time_seconds": 2.0,
                    "exit_code": 0,
                    "original_token_count": 2,
                    "output": "done",
                },
            ),
        ]
        records, terminal = self.terminal(records)
        summary = LIVE.trusted_tool_evidence_summary(
            records,
            turn_id=self.TURN_ID,
            terminal_event=terminal,
            tool_transport=LIVE.NAMESPACED_EXEC_TOOL_TRANSPORT,
        )
        self.assertEqual(summary["trusted_completed_tool_calls"], 2)
        self.assertEqual(
            [item["result_kind"] for item in summary["trusted_tool_receipts"]],
            ["paired-deferred", "paired-success"],
        )
        self.assertEqual(
            LIVE.forbidden_tool_activity(
                summary["trusted_tool_activity"],
                LIVE.default_tool_policy(mutable=True, workload_class="operative"),
            ),
            [],
        )

    def test_different_session_wait_does_not_resolve_pending_exec(self) -> None:
        records = self.pending_records() + [
            self.call(
                "write_stdin",
                "wait",
                {"session_id": 28839, "chars": ""},
            ),
            self.output(
                "wait",
                {
                    "chunk_id": "def",
                    "wall_time_seconds": 2.0,
                    "exit_code": 0,
                    "original_token_count": 2,
                    "output": "done",
                },
            ),
        ]
        records, terminal = self.terminal(records)
        summary = LIVE.trusted_tool_evidence_summary(
            records,
            turn_id=self.TURN_ID,
            terminal_event=terminal,
            tool_transport=LIVE.NAMESPACED_EXEC_TOOL_TRANSPORT,
        )
        self.assertEqual(
            summary["trusted_tool_receipts"][0]["result_kind"],
            "paired-pending",
        )
        self.assertIn(
            "telemetry_anomaly.exec_command",
            summary["trusted_tool_names"],
        )


class ControllerWorkdirTelemetryTests(unittest.TestCase):
    TURN_ID = "controller-workdir-turn"
    NO_PROCESS = (
        'exec_command failed: CreateProcess { message: "Rejected(\\"Failed to '
        'create unified exec process: No such file or directory (os error 2)\\")" }'
    )

    def summary(
        self,
        expected: Path,
        *,
        workdir: object = None,
        include_workdir: bool = True,
        output: str = "ok",
        exit_code: int | None = 0,
    ) -> dict[str, Any]:
        arguments: dict[str, object] = {"cmd": "pwd"}
        if include_workdir:
            arguments["workdir"] = workdir
        output_payload: dict[str, object] = {
            "type": "function_call_output",
            "call_id": "workdir-call",
            "output": output,
        }
        if exit_code is not None:
            output_payload["exit_code"] = exit_code
        return LIVE.trusted_tool_evidence_summary(
            [
                {
                    "type": "turn_context",
                    "payload": {"turn_id": self.TURN_ID},
                },
                {
                    "type": "response_item",
                    "payload": {
                        "type": "function_call",
                        "name": "exec_command",
                        "call_id": "workdir-call",
                        "arguments": json.dumps(arguments),
                    },
                },
                {"type": "response_item", "payload": output_payload},
            ],
            turn_id=self.TURN_ID,
            expected_workdir=expected,
        )

    def assert_forbidden(self, summary: Mapping[str, Any], tool: str) -> None:
        self.assertEqual(summary["trusted_tool_names"], [tool])
        self.assertEqual(
            LIVE.forbidden_tool_activity(
                summary["trusted_tool_activity"],
                LIVE.default_tool_policy(
                    mutable=True, workload_class="operative"
                ),
            )[0]["tool"],
            tool,
        )

    def test_exact_or_omitted_workdir_uses_controller_binding(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            expected = Path(temporary).resolve()
            exact = self.summary(expected, workdir=str(expected))
            omitted = self.summary(expected, include_workdir=False)
        for summary in (exact, omitted):
            self.assertEqual(summary["trusted_tool_names"], ["exec_command"])
            self.assertEqual(
                summary["trusted_tool_receipts"][0]["result_kind"],
                "paired-success",
            )
            self.assertEqual(
                LIVE.forbidden_tool_activity(
                    summary["trusted_tool_activity"],
                    LIVE.default_tool_policy(
                        mutable=True, workload_class="operative"
                    ),
                ),
                [],
            )

    def test_exact_no_process_response_for_nonexistent_typo_is_recoverable(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            expected = Path(temporary).resolve()
            missing = expected / "mistyped-workdir"
            summary = self.summary(
                expected,
                workdir=str(missing),
                output=self.NO_PROCESS,
                exit_code=None,
            )
        self.assertEqual(summary["trusted_tool_names"], ["exec_command"])
        self.assertEqual(summary["trusted_completed_tool_calls"], 1)
        self.assertEqual(
            summary["trusted_tool_receipts"][0]["result_kind"],
            "paired-recoverable-workdir-input-error",
        )
        self.assertEqual(
            LIVE.forbidden_tool_activity(
                summary["trusted_tool_activity"],
                LIVE.default_tool_policy(
                    mutable=True, workload_class="operative"
                ),
            ),
            [],
        )
        self.assertNotIn(str(missing), json.dumps(summary))

    def test_unsafe_or_unproven_workdir_mismatches_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            expected = Path(temporary).resolve()
            existing = expected / "existing"
            existing.mkdir()
            link = expected / "broken-link"
            link.symlink_to(expected / "missing-target", target_is_directory=True)
            cases = (
                ("existing-success", str(existing), "ok", 0),
                ("broken-symlink", str(link), self.NO_PROCESS, None),
                ("relative", "mistyped-workdir", self.NO_PROCESS, None),
                ("malformed", 7, self.NO_PROCESS, None),
                (
                    "ambiguous-nonexistent",
                    str(expected / "missing"),
                    "not the exact transport failure",
                    None,
                ),
            )
            for name, workdir, output, exit_code in cases:
                with self.subTest(name=name):
                    summary = self.summary(
                        expected,
                        workdir=workdir,
                        output=output,
                        exit_code=exit_code,
                    )
                    self.assert_forbidden(
                        summary,
                        "security_violation.exec_command_workdir",
                    )

            exact_root_error = self.summary(
                expected,
                workdir=str(expected),
                output=self.NO_PROCESS,
                exit_code=None,
            )
            self.assert_forbidden(
                exact_root_error, "telemetry_anomaly.exec_command"
            )


class LiveThreadBoundaryPhaseTests(unittest.TestCase):
    def controller_bind_and_arm(
        self,
        adapter: LIVE.LiveThreadAdapter,
        *,
        arm: bool = True,
    ) -> dict[str, Any]:
        packet_id = "test-packet"
        child_id = "test-child"
        control_turn_id = "test-control-turn"
        state_file = str(adapter.worktree / "test-worker-state.json")
        packet_sha256 = LIVE.sha256_text("test-packet")
        lease_id = "test-lease"
        paths = [adapter.expected_mutation] if adapter.expected_mutation else []
        isolation = "mutable-isolated" if adapter.mutable else "read-only-shared"
        planned = {
            "child_id": child_id,
            "packet_id": packet_id,
            "attempt_nonce": "test-attempt",
            "session_id": adapter.thread_id,
            "agent_id": adapter.thread_id,
            "packet_sha256": packet_sha256,
            "lease_id": lease_id,
            "worktree": str(adapter.worktree),
            "isolation_class": isolation,
            "completion_evidence_policy": copy.deepcopy(
                adapter.completion_evidence_policy
            ),
            "tool_policy": copy.deepcopy(adapter.tool_policy),
            "hard_budget": {
                "tool_calls": 10,
                "runtime_seconds": 300,
                "compactions": 0,
                "full_suite_runs": 0,
                "mutations": 1 if adapter.mutable else 0,
            },
            "prompt": adapter.prompt,
            "prompt_preflight": copy.deepcopy(adapter.prompt_preflight),
            "tool_surface": copy.deepcopy(adapter.preflight_tool_surface),
            "declared_write_paths": paths,
            "integration_target_paths": paths,
        }
        child = {
            key: copy.deepcopy(value)
            for key, value in planned.items()
            if key
            not in {"prompt", "prompt_preflight", "tool_surface", "hard_budget"}
        }
        child.update(
            {
                "control_turn_id": control_turn_id,
                "control_contract_file": str(
                    adapter.worktree / "test-control-contract.json"
                ),
                "state_file": state_file,
            }
        )
        control = {
            "contract_type": "cwo-native-control-turn-contract",
            "version": 1,
            "state_file": state_file,
            "agent_id": adapter.thread_id,
            "control_turn_id": control_turn_id,
            "task_sha256": LIVE.sha256_text(adapter.prompt),
            "poll_interval_ms": LIVE.POOL_POLL_INTERVAL_MS,
            "allowed_actions": [
                "arm",
                "send-input",
                "mark-dispatched",
                "check",
                "interrupt",
                "close",
                "finalize",
            ],
        }
        control["contract_sha256"] = LIVE.canonical_sha256(control)
        pool_child = {
            key: copy.deepcopy(value)
            for key, value in child.items()
            if key != "control_contract_file"
        }
        pool_child["control_contract_sha256"] = control["contract_sha256"]
        pool_child["worktree_identity"] = {
            "canonical_path_sha256": LIVE.sha256_text(str(adapter.worktree))
        }
        pool = {
            "contract_type": "cwo-native-supervision-pool-contract",
            "version": 1,
            "pool_id": "test-pool",
            "pool_epoch": "test-epoch",
            "control_turn_id": LIVE.CONTROL_TURN_ID,
            "children": [pool_child],
        }
        pool["contract_sha256"] = LIVE.canonical_sha256(pool)
        proof = {
            "accepted": True,
            "decision": "accept",
            "stage": "pre-dispatch",
            "contract_sha256": pool["contract_sha256"],
        }
        proof["result_sha256"] = LIVE.canonical_sha256(proof)
        adapter.bind_effective_boundary(
            planned_child=planned,
            runtime_child=child,
            pool_contract=pool,
            control_contract=control,
            predispatch_proof=proof,
            writable_roots=[adapter.worktree] if adapter.mutable else [],
        )
        if arm:
            adapter.arm()
        return {
            "planned_child": planned,
            "runtime_child": child,
            "pool_contract": pool,
            "control_contract": control,
            "predispatch_proof": proof,
        }

    def test_unbound_send_fails_closed(self) -> None:
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
                record_dir=root,
            )
            with self.assertRaisesRegex(
                LIVE.AppServerError, "effective-boundary-not-armed"
            ):
                adapter.send_input(message="bounded prompt")

    def test_nested_effective_boundary_mutations_fail_at_arm(self) -> None:
        cases = (
            ("planned-packet", "planned_child", "packet_id", "changed-packet"),
            ("runtime-lease", "runtime_child", "lease_id", "changed-lease"),
            ("control-task", "control_contract", "task_sha256", "0" * 64),
            ("proof-decision", "predispatch_proof", "decision", "reject"),
        )
        for name, source, field, value in cases:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
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
                    record_dir=root,
                )
                bound = self.controller_bind_and_arm(adapter, arm=False)
                bound[source][field] = value
                if source == "control_contract":
                    bound[source]["contract_sha256"] = LIVE.canonical_sha256(
                        {
                            key: item
                            for key, item in bound[source].items()
                            if key != "contract_sha256"
                        }
                    )
                if source == "predispatch_proof":
                    bound[source]["result_sha256"] = LIVE.canonical_sha256(
                        {
                            key: item
                            for key, item in bound[source].items()
                            if key != "result_sha256"
                        }
                    )
                with self.assertRaisesRegex(
                    LIVE.AppServerError, "effective-boundary"
                ):
                    adapter.arm()
                self.assertFalse(adapter._effective_boundary_armed)

    def test_provider_scope_pool_and_return_pairings_fail_at_arm(self) -> None:
        mutations = (
            "provider",
            "writable-root",
            "pool-packet",
            "return-token",
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
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
                    record_dir=root,
                )
                bound = self.controller_bind_and_arm(adapter, arm=False)
                if mutation == "provider":
                    server._effective_thread_start_evidence[adapter.thread_id][
                        "response"
                    ]["modelProvider"] = "other-provider"
                elif mutation == "writable-root":
                    server._effective_thread_start_evidence[adapter.thread_id][
                        "response"
                    ]["sandbox"]["writableRoots"] = [str(root)]
                elif mutation == "pool-packet":
                    pool = bound["pool_contract"]
                    pool["children"][0]["packet_id"] = "other-packet"
                    pool["contract_sha256"] = LIVE.canonical_sha256(
                        {
                            key: item
                            for key, item in pool.items()
                            if key != "contract_sha256"
                        }
                    )
                else:
                    adapter.expected_token = "OTHER"
                with self.assertRaisesRegex(
                    LIVE.AppServerError, "effective-boundary"
                ):
                    adapter.arm()
                self.assertFalse(adapter._effective_boundary_armed)

    def test_bind_arm_and_send_are_individually_one_shot(self) -> None:
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
                record_dir=root,
            )
            bound = self.controller_bind_and_arm(adapter)
            with self.assertRaisesRegex(
                LIVE.AppServerError, "effective-boundary-already-bound"
            ):
                adapter.bind_effective_boundary(
                    **bound,
                    writable_roots=[],
                )
            with self.assertRaisesRegex(
                LIVE.AppServerError, "effective-boundary-already-armed"
            ):
                adapter.arm()
            with mock.patch.object(
                server, "start_turn", wraps=server.start_turn
            ) as start_turn:
                adapter.send_input(message="bounded prompt")
                with self.assertRaisesRegex(
                    LIVE.AppServerError, "effective-boundary-send-not-one-shot"
                ):
                    adapter.send_input(message="bounded prompt")
            self.assertEqual(start_turn.call_count, 1)

    def test_reentrant_surface_observer_cannot_duplicate_submission(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            server = FakeLiveThreadServer(root, initial_boundary="valid")
            policy = LIVE.default_tool_policy(
                mutable=False, workload_class="safety-canary"
            )
            baseline_surface = LIVE.capture_server_tool_surface(server, policy)
            adapter: LIVE.LiveThreadAdapter | None = None
            reenter = False
            reentrant_errors: list[str] = []

            def surface_reader() -> Mapping[str, Any]:
                if reenter and adapter is not None:
                    try:
                        adapter.send_input(message="bounded prompt")
                    except LIVE.AppServerError as exc:
                        reentrant_errors.append(str(exc))
                return copy.deepcopy(baseline_surface)

            adapter = LIVE.LiveThreadAdapter(
                server,
                server.thread_response(),
                prompt="bounded prompt",
                expected_token="DONE",
                worktree=root,
                mutable=False,
                expected_mutation=None,
                tool_policy=policy,
                tool_surface_reader=surface_reader,
                record_dir=root,
            )
            self.controller_bind_and_arm(adapter)
            reenter = True
            with mock.patch.object(
                server, "start_turn", wraps=server.start_turn
            ) as start_turn:
                adapter.send_input(message="bounded prompt")
            self.assertEqual(
                reentrant_errors,
                ["effective-boundary-send-not-one-shot"],
            )
            self.assertEqual(start_turn.call_count, 1)

    def test_reentrant_surface_observer_cannot_duplicate_arm(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            server = FakeLiveThreadServer(root, initial_boundary="valid")
            policy = LIVE.default_tool_policy(
                mutable=False, workload_class="safety-canary"
            )
            baseline_surface = LIVE.capture_server_tool_surface(server, policy)
            adapter: LIVE.LiveThreadAdapter | None = None
            reenter = False
            reentrant_errors: list[str] = []

            def surface_reader() -> Mapping[str, Any]:
                if reenter and adapter is not None:
                    try:
                        adapter.arm()
                    except LIVE.AppServerError as exc:
                        reentrant_errors.append(str(exc))
                return copy.deepcopy(baseline_surface)

            adapter = LIVE.LiveThreadAdapter(
                server,
                server.thread_response(),
                prompt="bounded prompt",
                expected_token="DONE",
                worktree=root,
                mutable=False,
                expected_mutation=None,
                tool_policy=policy,
                tool_surface_reader=surface_reader,
                record_dir=root,
            )
            self.controller_bind_and_arm(adapter, arm=False)
            reenter = True
            self.assertEqual(adapter.arm(), {"ack": "armed"})
            self.assertEqual(
                reentrant_errors,
                ["effective-boundary-already-armed"],
            )
            with self.assertRaisesRegex(
                LIVE.AppServerError, "effective-boundary-already-armed"
            ):
                adapter.arm()

    def test_reentrant_surface_observer_cannot_send_during_arm(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            server = FakeLiveThreadServer(root, initial_boundary="valid")
            policy = LIVE.default_tool_policy(
                mutable=False, workload_class="safety-canary"
            )
            baseline_surface = LIVE.capture_server_tool_surface(server, policy)
            adapter: LIVE.LiveThreadAdapter | None = None
            reenter = False
            return_invalid_surface = False
            callback_depth = 0
            reentrant_errors: list[str] = []

            def surface_reader() -> Mapping[str, Any]:
                nonlocal callback_depth
                callback_depth += 1
                try:
                    if reenter and callback_depth == 1 and adapter is not None:
                        try:
                            adapter.send_input(message="bounded prompt")
                        except LIVE.AppServerError as exc:
                            reentrant_errors.append(str(exc))
                    surface = copy.deepcopy(baseline_surface)
                    if return_invalid_surface and callback_depth == 1:
                        surface["source"] = "substituted-during-arm"
                    return surface
                finally:
                    callback_depth -= 1

            adapter = LIVE.LiveThreadAdapter(
                server,
                server.thread_response(),
                prompt="bounded prompt",
                expected_token="DONE",
                worktree=root,
                mutable=False,
                expected_mutation=None,
                tool_policy=policy,
                tool_surface_reader=surface_reader,
                record_dir=root,
            )
            self.controller_bind_and_arm(adapter, arm=False)
            reenter = True
            return_invalid_surface = True
            with mock.patch.object(
                server, "start_turn", wraps=server.start_turn
            ) as start_turn, self.assertRaisesRegex(
                LIVE.AppServerError, "tool-surface-snapshot-mismatch"
            ):
                adapter.arm()
            self.assertEqual(
                reentrant_errors,
                ["effective-boundary-arm-in-progress"],
            )
            start_turn.assert_not_called()
            self.assertFalse(adapter._effective_boundary_arm_in_progress)
            self.assertFalse(adapter._effective_boundary_armed)
            self.assertFalse(adapter._effective_boundary_send_reserved)
            self.assertIsNone(adapter.turn_id)

    def test_surface_callback_boundary_mutation_rejects_before_submission(self) -> None:
        for mutation in ("runtime-lease", "requested-model", "thread-freshness"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                server = FakeLiveThreadServer(root, initial_boundary="valid")
                policy = LIVE.default_tool_policy(
                    mutable=False, workload_class="safety-canary"
                )
                baseline_surface = LIVE.capture_server_tool_surface(server, policy)
                adapter: LIVE.LiveThreadAdapter | None = None
                bound: dict[str, Any] | None = None
                mutate = False

                def surface_reader() -> Mapping[str, Any]:
                    if mutate and bound is not None and adapter is not None:
                        if mutation == "runtime-lease":
                            bound["runtime_child"]["lease_id"] = (
                                "mutated-during-callback"
                            )
                        elif mutation == "requested-model":
                            server.requested_model = "substituted-model"
                        else:
                            adapter.thread["turns"] = [{"id": "stale-turn"}]
                    return copy.deepcopy(baseline_surface)

                adapter = LIVE.LiveThreadAdapter(
                    server,
                    server.thread_response(),
                    prompt="bounded prompt",
                    expected_token="DONE",
                    worktree=root,
                    mutable=False,
                    expected_mutation=None,
                    tool_policy=policy,
                    tool_surface_reader=surface_reader,
                    record_dir=root,
                )
                bound = self.controller_bind_and_arm(adapter)
                mutate = True
                with mock.patch.object(
                    server, "start_turn", wraps=server.start_turn
                ) as start_turn, self.assertRaisesRegex(
                    LIVE.AppServerError, "effective-boundary"
                ):
                    adapter.send_input(message="bounded prompt")
                start_turn.assert_not_called()
                self.assertTrue(adapter._effective_boundary_send_reserved)

    def test_synchronous_start_turn_observes_reserved_attempt(self) -> None:
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
                record_dir=root,
            )
            self.controller_bind_and_arm(adapter)
            original = server.start_turn

            def observing_start_turn(
                thread_id: str, message: str
            ) -> tuple[dict[str, Any], float]:
                self.assertTrue(adapter._effective_boundary_send_reserved)
                self.assertEqual(adapter._boundary_phase, "dispatch-attempted")
                return original(thread_id, message)

            server.start_turn = observing_start_turn
            adapter.send_input(message="bounded prompt")
            self.assertIsNotNone(adapter.turn_id)

    @staticmethod
    def settle_and_close(adapter: LIVE.LiveThreadAdapter) -> dict[str, Any]:
        assert adapter._staged_archive is not None
        adapter._staged_archive.require_complete(timeout_seconds=1.0)
        return adapter.close()

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

    def test_unbound_workspace_mutations_use_inert_capture(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            subprocess.run(["git", "init", "-q"], cwd=root, check=True)
            configure_git_fixture(root)
            subprocess.run(["git", "config", "user.email", "cwo@example.invalid"], cwd=root, check=True)
            subprocess.run(["git", "config", "user.name", "CWO Test"], cwd=root, check=True)
            (root / "targets").mkdir()
            child = root / "targets" / "child_1.txt"
            child.write_text("committed\n", encoding="utf-8")
            subprocess.run(["git", "add", "-A"], cwd=root, check=True)
            subprocess.run(["git", "commit", "-qm", "baseline"], cwd=root, check=True)
            marker = root.parent / f"{root.name}-fsmonitor-ran"
            hook = root.parent / f"{root.name}-fsmonitor-hook"
            hook.write_text(f"#!/bin/sh\ntouch '{marker}'\nexit 1\n", encoding="utf-8")
            hook.chmod(0o755)
            child.write_text("changed\n", encoding="utf-8")
            (root / "quoted name.txt").write_text("new\n", encoding="utf-8")
            clock = FakeMonotonicClock()
            server = FakeLiveThreadServer(root)
            adapter = self.adapter(root, server, clock)
            try:
                # A hook command whose dependencies cannot be established (a shell
                # script string run by a program found on PATH) leaves the status
                # incomplete, and still never runs.
                subprocess.run(["git", "config", "core.fsmonitor", f"sh -c 'touch {marker}; exit 1' --"], cwd=root, check=True)
                with self.assertRaisesRegex(LIVE.AppServerError, "workspace-status-incomplete"):
                    adapter._workspace_mutations()
                self.assertFalse(marker.exists(), "the worktree's fsmonitor must not run")
                # A hook named by its path is a program too: its dependencies cannot be established,
                # so the status is incomplete, and it never runs either.
                subprocess.run(["git", "config", "core.fsmonitor", str(hook)], cwd=root, check=True)
                with self.assertRaisesRegex(LIVE.AppServerError, "workspace-status-incomplete"):
                    adapter._workspace_mutations()
                self.assertFalse(marker.exists(), "the worktree's fsmonitor must not run")
                # A boolean value is supported: the mutations are listed. A trusted Git 2.35 resolves
                # any non-empty value as a program, so there the status is incomplete; the empty value
                # disables the monitor on every release.
                trusted = workspace_capture.trusted_git()
                self.assertIsNotNone(trusted)
                for value in ("false", "true", ""):
                    subprocess.run(["git", "config", "core.fsmonitor", value], cwd=root, check=True)
                    if value and trusted.version[:2] < (2, 36):
                        with self.assertRaisesRegex(LIVE.AppServerError, "workspace-status-incomplete"):
                            adapter._workspace_mutations()
                    else:
                        self.assertEqual(adapter._workspace_mutations(), ["quoted name.txt", "targets/child_1.txt"])
                self.assertFalse(marker.exists(), "the worktree's fsmonitor must not run")
            finally:
                marker.unlink(missing_ok=True)
                hook.unlink(missing_ok=True)

    def test_real_bound_capture_reaches_readonly_evidence_refusal(self) -> None:
        from tests.test_native_pool_workspace import WorkspaceFixture
        with tempfile.TemporaryDirectory() as temporary:
            fixture = WorkspaceFixture(Path(temporary))
            root = fixture.first
            server = FakeLiveThreadServer(root, initial_boundary="valid")
            adapter = LIVE.LiveThreadAdapter(server, server.thread_response(), prompt="bounded prompt",
                expected_token="DONE", worktree=root, mutable=False, expected_mutation=None,
                record_dir=root, monotonic_ns=FakeMonotonicClock(), campaign_live_route=False)
            adapter.bind_workspace_baseline(LIVE.capture_workspace_baseline(root, allowed_paths=[], include_untracked=True))
            self.controller_bind_and_arm(adapter)
            self.assertFalse(adapter.evidence()["protected_fault"])
            (root / "README.md").write_text("unapproved\n", encoding="utf-8")
            evidence = adapter.evidence()
            self.assertIn("read-only-workspace-mutation", evidence["reasons"])
            self.assertTrue(evidence["protected_fault"])

    def test_real_bound_capture_cap_and_config_change_cannot_accept(self) -> None:
        from tests.test_native_pool_workspace import WorkspaceFixture
        with tempfile.TemporaryDirectory() as temporary:
            fixture = WorkspaceFixture(Path(temporary))
            root = fixture.first
            server = FakeLiveThreadServer(root, initial_boundary="valid")
            adapter = LIVE.LiveThreadAdapter(server, server.thread_response(), prompt="bounded prompt",
                expected_token="DONE", worktree=root, mutable=False, expected_mutation=None,
                record_dir=root, monotonic_ns=FakeMonotonicClock(), campaign_live_route=False)
            adapter.bind_workspace_baseline(LIVE.capture_workspace_baseline(root, allowed_paths=[], include_untracked=True))
            self.controller_bind_and_arm(adapter)
            original = LIVE.capture_workspace_baseline
            capped = lambda *args, **kwargs: original(*args, **{**kwargs, "max_files": 0})
            with mock.patch.object(LIVE_THREAD, "capture_workspace_baseline", side_effect=capped):
                with self.assertRaisesRegex(LIVE.AppServerError, "workspace-baseline-comparison-incomplete"):
                    adapter.evidence()
            subprocess.run(["git", "config", "core.sshCommand", "EXAMPLE-unapproved"], cwd=root, check=True)
            evidence = adapter.evidence()
            self.assertIn("read-only-workspace-mutation", evidence["reasons"])
            self.assertTrue(evidence["protected_fault"])

    def test_real_bound_mutable_scoped_write_and_unplanned_control(self) -> None:
        from tests.test_native_pool_workspace import WorkspaceFixture
        with tempfile.TemporaryDirectory() as temporary:
            fixture = WorkspaceFixture(Path(temporary))
            root = fixture.first
            records = Path(temporary) / "records"
            records.mkdir(mode=0o700)
            server = FakeLiveThreadServer(root, initial_boundary="valid")
            target = "scripts/child_0.py"
            adapter = LIVE.LiveThreadAdapter(server, server.thread_response(mutable=True), prompt="bounded prompt",
                expected_token="DONE", worktree=root, mutable=True, expected_mutation=target,
                record_dir=records, monotonic_ns=FakeMonotonicClock(), campaign_live_route=False)
            adapter.bind_workspace_baseline(LIVE.capture_workspace_baseline(root, allowed_paths=[target], include_untracked=True))
            self.controller_bind_and_arm(adapter)
            self.assertFalse(adapter.evidence()["protected_fault"])
            adapter.send_input(message="bounded prompt")
            (root / target).write_bytes(b"ZERO = 2\n")
            self.assertFalse(adapter.evidence()["protected_fault"])
            (root / "README.md").write_bytes(b"unplanned\n")
            evidence = adapter.evidence()
            self.assertIn("mutable-workspace-attribution-mismatch", evidence["reasons"])
            self.assertTrue(evidence["protected_fault"])

    def test_unbound_workspace_mutations_refuse_unknown_cleanliness(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            subprocess.run(["git", "init", "-q"], cwd=root, check=True)
            configure_git_fixture(root)
            subprocess.run(["git", "config", "user.email", "cwo@example.invalid"], cwd=root, check=True)
            subprocess.run(["git", "config", "user.name", "CWO Test"], cwd=root, check=True)
            (root / ".gitattributes").write_text("*.txt filter=lfs\n", encoding="utf-8")
            (root / "notes.txt").write_text("committed\n", encoding="utf-8")
            subprocess.run(["git", "add", "-A"], cwd=root, check=True)
            subprocess.run(["git", "commit", "-qm", "baseline"], cwd=root, check=True)
            adapter = self.adapter(root, FakeLiveThreadServer(root), FakeMonotonicClock())
            # Raw status is empty, but a filter could make Git see the files differently.
            with self.assertRaisesRegex(LIVE.AppServerError, "workspace-cleanliness-unknown"):
                adapter._workspace_mutations()

    def test_unbound_workspace_mutations_refuse_a_special_attributes_file(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            subprocess.run(["git", "init", "-q"], cwd=root, check=True)
            configure_git_fixture(root)
            subprocess.run(["git", "config", "user.email", "cwo@example.invalid"], cwd=root, check=True)
            subprocess.run(["git", "config", "user.name", "CWO Test"], cwd=root, check=True)
            (root / "notes.txt").write_text("committed\n", encoding="utf-8")
            subprocess.run(["git", "add", "-A"], cwd=root, check=True)
            subprocess.run(["git", "commit", "-qm", "baseline"], cwd=root, check=True)
            # An untracked FIFO is not status, but what Git would read from it is unknown.
            os.mkfifo(root / ".gitattributes")
            adapter = self.adapter(root, FakeLiveThreadServer(root), FakeMonotonicClock())
            with self.assertRaisesRegex(LIVE.AppServerError, "workspace-cleanliness-unknown"):
                adapter._workspace_mutations()

    def test_workspace_mutations_are_relative_to_bound_complete_dirty_baseline(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            subprocess.run(["git", "init", "-q"], cwd=root, check=True)
            configure_git_fixture(root)
            subprocess.run(
                ["git", "config", "user.email", "cwo@example.invalid"],
                cwd=root,
                check=True,
            )
            subprocess.run(
                ["git", "config", "user.name", "CWO Test"],
                cwd=root,
                check=True,
            )
            tracked = root / "tracked.txt"
            tracked.write_text("committed\n", encoding="utf-8")
            subprocess.run(["git", "add", "tracked.txt"], cwd=root, check=True)
            subprocess.run(
                ["git", "commit", "-qm", "baseline"], cwd=root, check=True
            )
            tracked.write_text("dirty-before-dispatch\n", encoding="utf-8")
            untracked = root / "existing-untracked.txt"
            untracked.write_text("existing\n", encoding="utf-8")
            link = root / "existing-link"
            link.symlink_to("tracked.txt")
            # The fake server keeps its home inside this worktree; create it
            # before the baseline so its directories are not new mutations.
            server = FakeLiveThreadServer(root)
            baseline = LIVE.capture_workspace_baseline(
                root,
                allowed_paths=["."],
                include_untracked=True,
            )
            clock = FakeMonotonicClock()
            adapter = LIVE.LiveThreadAdapter(
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
            adapter.bind_workspace_baseline(baseline)
            self.controller_bind_and_arm(adapter)

            self.assertEqual(adapter._workspace_mutations(), [])

            tracked.write_text("changed-after-dispatch\n", encoding="utf-8")
            self.assertEqual(adapter._workspace_mutations(), ["tracked.txt"])
            tracked.write_text("dirty-before-dispatch\n", encoding="utf-8")

            link.unlink()
            link.symlink_to("existing-untracked.txt")
            self.assertEqual(adapter._workspace_mutations(), ["existing-link"])
            link.unlink()
            link.symlink_to("tracked.txt")

            link.unlink()
            link.symlink_to("../outside-worktree")
            self.assertEqual(adapter._workspace_mutations(), ["existing-link"])
            link.unlink()
            link.symlink_to("tracked.txt")

            untracked.unlink()
            self.assertEqual(
                adapter._workspace_mutations(),
                ["existing-untracked.txt"],
            )
            untracked.write_text("existing\n", encoding="utf-8")

            (root / "added.txt").write_text("added\n", encoding="utf-8")
            self.assertEqual(adapter._workspace_mutations(), ["added.txt"])
            (root / "added.txt").unlink()

            subprocess.run(["git", "add", "tracked.txt"], cwd=root, check=True)
            self.assertEqual(adapter._workspace_mutations(), ["tracked.txt"])

    def test_workspace_baseline_binding_rejects_incomplete_wrong_root_and_late_use(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            subprocess.run(["git", "init", "-q"], cwd=root, check=True)
            configure_git_fixture(root)
            baseline = LIVE.capture_workspace_baseline(
                root,
                allowed_paths=["."],
                include_untracked=True,
            )
            clock = FakeMonotonicClock()
            server = FakeLiveThreadServer(root)

            def new_adapter() -> LIVE.LiveThreadAdapter:
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

            incomplete = copy.deepcopy(baseline)
            incomplete["incomplete"] = True
            incomplete["baseline_complete"] = False
            with self.assertRaisesRegex(
                LIVE.AppServerError,
                "workspace-baseline-invalid",
            ):
                new_adapter().bind_workspace_baseline(incomplete)

            wrong_root = copy.deepcopy(baseline)
            wrong_root["cwd"] = str(root / "other")
            with self.assertRaisesRegex(
                LIVE.AppServerError,
                "workspace-baseline-root-mismatch",
            ):
                new_adapter().bind_workspace_baseline(wrong_root)

            already_bound = new_adapter()
            already_bound.bind_workspace_baseline(baseline)
            self.controller_bind_and_arm(already_bound)
            with self.assertRaisesRegex(
                LIVE.AppServerError,
                "workspace-baseline-already-bound",
            ):
                already_bound.bind_workspace_baseline(baseline)

            late_first_bind = new_adapter()
            self.controller_bind_and_arm(late_first_bind)
            self.assertIsNone(late_first_bind._workspace_baseline)
            with self.assertRaisesRegex(
                LIVE.AppServerError,
                "workspace-baseline-binding-too-late",
            ):
                late_first_bind.bind_workspace_baseline(baseline)
            self.assertIsNone(late_first_bind._workspace_baseline)

    def adapter(
        self,
        root: Path,
        server: FakeLiveThreadServer,
        clock: FakeMonotonicClock,
    ) -> LIVE.LiveThreadAdapter:
        adapter = LIVE.LiveThreadAdapter(
            server,
            server.thread_response(),
            prompt="bounded prompt",
            expected_token="DONE",
            worktree=root,
            mutable=False,
            expected_mutation=None,
            record_dir=root,
            monotonic_ns=clock,
            campaign_live_route=False,
        )
        self.controller_bind_and_arm(adapter)
        return adapter

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
                1,
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
                1,
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
                2,
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
                1,
                0,
            ),
        )
        for label, events, expected_tool, expected_calls, completed in cases:
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
                self.assertEqual(
                    summary["trusted_tool_calls"],
                    expected_calls,
                )
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
                self.requested_model = LIVE.EXACT_MODEL
                self.started_threads: dict[str, str | None] = {}
                self._effective_thread_start_evidence: dict[str, dict] = {}

            @staticmethod
            def start_turn(_thread_id: str, _message: str) -> tuple[dict, float]:
                raise LIVE.AppServerError("synthetic-submission-failure")

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            thread_id = str(uuid.uuid4())
            server = FailedSubmissionServer(root)
            response = {
                "model": LIVE.EXACT_MODEL,
                "modelProvider": "trusted",
                "sandbox": {"type": "readOnly"},
                "approvalPolicy": "never",
                "cwd": str(root),
                "runtimeWorkspaceRoots": [str(root)],
                "thread": {"id": thread_id, "turns": [], "path": None},
            }
            server.started_threads[thread_id] = None
            server._effective_thread_start_evidence[thread_id] = {
                "request": {
                    "model": LIVE.EXACT_MODEL,
                    "allowProviderModelFallback": False,
                    "sandbox": "read-only",
                    "approvalPolicy": "never",
                    "cwd": str(root),
                    "runtimeWorkspaceRoots": [str(root)],
                },
                "response": copy.deepcopy(response),
            }
            adapter = LIVE.LiveThreadAdapter(
                server,
                response,
                prompt="bounded prompt",
                expected_token="DONE",
                worktree=root,
                mutable=False,
                expected_mutation=None,
                record_dir=root,
            )
            self.controller_bind_and_arm(adapter)
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
                if reads > 2:
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

    def test_effective_tool_surface_expansion_blocks_arm(self) -> None:
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
            adapter = LIVE.LiveThreadAdapter(
                server,
                server.thread_response(),
                prompt="bounded prompt",
                expected_token="DONE",
                worktree=root,
                mutable=False,
                expected_mutation=None,
                record_dir=root,
                monotonic_ns=FakeMonotonicClock(),
            )
            self.controller_bind_and_arm(adapter, arm=False)
            with self.assertRaisesRegex(
                LIVE.AppServerError, "tool-surface-expanded"
            ):
                adapter.arm()
            self.assertFalse(adapter._effective_boundary_armed)
            self.assertIsNone(server.started_threads[server.thread_id])

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

    def test_check_does_not_read_before_exact_started_notification(self) -> None:
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
            ) as read_thread:
                self.assertEqual(adapter.check(), {"decision": "continue"})
            read_thread.assert_not_called()

    def test_check_treats_initial_projection_rpc_race_as_pending(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            clock = FakeMonotonicClock()
            server = FakeLiveThreadServer(root, initial_boundary="empty")
            adapter = self.adapter(root, server, clock)
            adapter.send_input(message="bounded prompt")
            server.notifications = lambda _thread_id, _method=None: [
                {
                    "method": "turn/started",
                    "params": {
                        "threadId": server.thread_id,
                        "turn": {"id": server.turn_id},
                    },
                }
            ]
            error = LIVE.AppServerRpcError(
                method="thread/read",
                code=-32603,
                request_id=1,
                latency_ms=1.0,
            )
            with mock.patch.object(
                server, "read_thread", side_effect=error
            ) as read_thread:
                self.assertEqual(adapter.check(), {"decision": "continue"})
            read_thread.assert_called_once_with(server.thread_id)
            self.assertEqual(
                adapter._boundary_phase,
                "submission-acknowledged-awaiting-materialization",
            )
            self.assertIsNone(adapter._session_boundary_baseline)

    def test_check_refuses_qualification_cold_read_outside_its_pending_route(self) -> None:
        for materialized in (False, True):
            with self.subTest(materialized=materialized), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                server = FakeLiveThreadServer(root, initial_boundary="empty")
                adapter = self.adapter(root, server, FakeMonotonicClock())
                adapter.send_input(message="bounded prompt")
                if materialized:
                    server.set_boundary("valid")
                server.notifications = lambda _thread_id, _method=None: [{
                    "method": "turn/started", "params": {
                        "threadId": server.thread_id, "turn": {"id": server.turn_id},
                    },
                }]
                error = LIVE.AppServerRpcError(method="thread/read", code=-32600, request_id=1,
                    latency_ms=1.0, qualification_thread_unmaterialized=True)
                # After materialization, check bypasses the pending read path.
                pending_read = ({"return_value": False} if materialized else
                                {"wraps": adapter._fresh_nonterminal_thread_locked})
                with (mock.patch.object(adapter, "_fresh_nonterminal_thread_locked", **pending_read) as pending,
                      mock.patch.object(server, "read_thread", side_effect=error),
                      self.assertRaises(LIVE.AppServerRpcError) as raised):
                    adapter.check()
                self.assertIs(raised.exception, error)
                self.assertEqual(pending.call_count, 0 if materialized else 1)

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
        for statuses in (
            ["completed"],
            ["failed"],
            ["interrupted"],
        ):
            with self.subTest(statuses=statuses), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                clock = FakeMonotonicClock()
                server = FakeLiveThreadServer(
                    root,
                    initial_boundary="valid",
                    read_statuses=statuses,
                )
                adapter = self.adapter(root, server, clock)
                adapter.send_input(message="bounded prompt")
                self.assertEqual(
                    adapter.check(),
                    {"decision": "continue"},
                )
                with mock.patch.object(adapter, "_workspace_mutations", return_value=[]):
                    summary = adapter._trusted_summary()
                    evidence = adapter.evidence()
                self.assertTrue(summary["session_boundary"]["available"])
                self.assertIsNone(summary["durable_terminal_event"])
                self.assertIsNone(summary["turn_status"])
                self.assertEqual(
                    summary["projected_turn_status"],
                    statuses[0],
                )
                self.assertEqual(evidence["reasons"], [])
                self.assertFalse(evidence["protected_fault"])
                self.assertFalse(evidence["control_loss"])
                self.assertIsNone(evidence["failure_class"])

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

    def test_task_complete_error_is_control_loss_not_completion_mismatch(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            server = FakeLiveThreadServer(root, initial_boundary="valid")
            adapter = LIVE.LiveThreadAdapter(
                server,
                server.thread_response(mutable=True),
                prompt="Use apply_patch exactly once, then run git diff --check",
                expected_token="DONE",
                worktree=root,
                mutable=True,
                expected_mutation="targets/activation.txt",
                expected_tool_trace=fixed_activation_tool_trace(
                    "n1-mutable",
                    0,
                    worktree=root,
                ),
                record_dir=root,
                monotonic_ns=FakeMonotonicClock(),
            )
            self.controller_bind_and_arm(adapter)
            adapter.send_input(message=adapter.prompt)
            with server.path.open("a", encoding="utf-8") as stream:
                stream.write(
                    json.dumps(
                        {
                            "type": "event_msg",
                            "payload": {
                                "type": "task_complete",
                                "turn_id": server.turn_id,
                                "last_agent_message": None,
                                "error": {
                                    "message": (
                                        "Selected model is at capacity. "
                                        "Please try a different model."
                                    ),
                                    "codex_error_info": "server_overloaded",
                                },
                            },
                        }
                    )
                    + "\n"
                )

            self.assertEqual(
                adapter.check(),
                {"decision": "control-lost"},
            )
            with mock.patch.object(
                adapter,
                "_workspace_mutations",
                return_value=[],
            ):
                evidence = adapter.evidence()
                summary = adapter.final_summary()
            self.assertEqual(evidence["reasons"], ["trusted-turn-failed"])
            self.assertTrue(evidence["protected_fault"])
            self.assertTrue(evidence["control_loss"])
            self.assertEqual(
                evidence["failure_class"],
                "control-security-failure",
            )
            self.assertEqual(
                evidence["session_disposition"],
                "quarantined",
            )
            self.assertEqual(
                evidence["artifact_disposition"],
                "rejected",
            )
            self.assertEqual(summary["turn_status"], "failed")
            self.assertEqual(
                summary["exact_tool_trace_observation"]["status"],
                "pending",
            )
            for false_reason in (
                "exact-tool-trace-mismatch",
                "invalid-final-response",
                "mutable-workspace-attribution-mismatch",
                "zero-tool-completion",
                "premature-completion",
                "required-evidence-missing",
            ):
                self.assertNotIn(false_reason, evidence["reasons"])

            with mock.patch.object(
                server,
                "interrupt_turn",
                side_effect=AssertionError(
                    "a durably terminal turn must not be interrupted"
                ),
            ) as interrupt_turn:
                self.assertEqual(
                    adapter.interrupt(),
                    {"ack": "already-terminal"},
                )
                interrupt_turn.assert_not_called()
                self.assertFalse(adapter.interrupted)
                self.assertEqual(
                    adapter.finalize(control_action="interrupt-confirmed"),
                    {
                        "ack": "interrupt-confirmed",
                        "close_wait_required": True,
                    },
                )
                self.assertEqual(
                    self.settle_and_close(adapter),
                    {"ack": "closed"},
                )
                self.assertTrue(server.archived)

    def test_interrupt_skips_rpc_for_other_durable_terminal_statuses(
        self,
    ) -> None:
        for event_type in ("task_complete", "turn_aborted"):
            with (
                self.subTest(event_type=event_type),
                tempfile.TemporaryDirectory() as temporary,
            ):
                root = Path(temporary)
                server = FakeLiveThreadServer(root, initial_boundary="valid")
                adapter = LIVE.LiveThreadAdapter(
                    server,
                    server.thread_response(mutable=True),
                    prompt="Use apply_patch exactly once, then run git diff --check",
                    expected_token="DONE",
                    worktree=root,
                    mutable=True,
                    expected_mutation="targets/activation.txt",
                    expected_tool_trace=fixed_activation_tool_trace(
                        "n1-mutable",
                        0,
                        worktree=root,
                    ),
                    record_dir=root,
                    monotonic_ns=FakeMonotonicClock(),
                )
                self.controller_bind_and_arm(adapter)
                adapter.send_input(message=adapter.prompt)
                server.append_terminal(event_type)
                self.assertEqual(
                    adapter.check(),
                    {"decision": "interrupt"},
                )

                with mock.patch.object(
                    server,
                    "interrupt_turn",
                    side_effect=AssertionError(
                        "a durably terminal turn must not be interrupted"
                    ),
                ) as interrupt_turn:
                    self.assertEqual(
                        adapter.interrupt(),
                        {"ack": "already-terminal"},
                    )
                    interrupt_turn.assert_not_called()
                self.assertFalse(adapter.interrupted)
                self.assertEqual(
                    adapter.finalize(control_action="interrupt-confirmed"),
                    {
                        "ack": "interrupt-confirmed",
                        "close_wait_required": True,
                    },
                )
                self.assertEqual(
                    self.settle_and_close(adapter),
                    {"ack": "closed"},
                )
                self.assertTrue(server.archived)

    def test_interrupt_adjudicates_terminal_transition_after_rpc_error_once(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            server = FakeLiveThreadServer(root, initial_boundary="valid")
            adapter = self.adapter(root, server, FakeMonotonicClock())
            adapter.send_input(message="bounded prompt")

            def terminal_race(_thread_id: str, _turn_id: str) -> float:
                server.append_terminal("task_complete")
                raise LIVE.AppServerRpcError(
                    method="turn/interrupt",
                    code=-32600,
                    request_id=1,
                    latency_ms=1.0,
                )

            with mock.patch.object(
                server,
                "interrupt_turn",
                side_effect=terminal_race,
            ) as interrupt_turn:
                self.assertEqual(
                    adapter.interrupt(),
                    {"ack": "already-terminal"},
                )
                interrupt_turn.assert_called_once_with(
                    server.thread_id,
                    server.turn_id,
                )
            self.assertEqual(
                adapter._durable_terminal_status,
                "completed",
            )
            self.assertFalse(adapter.interrupted)
            self.assertEqual(
                adapter.finalize(control_action="interrupt-confirmed"),
                {
                    "ack": "interrupt-confirmed",
                    "close_wait_required": True,
                },
            )
            self.assertEqual(
                self.settle_and_close(adapter),
                {"ack": "closed"},
            )
            self.assertTrue(server.archived)

    def test_interrupt_rpc_error_without_terminal_evidence_propagates_once(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            server = FakeLiveThreadServer(root, initial_boundary="valid")
            adapter = self.adapter(root, server, FakeMonotonicClock())
            adapter.send_input(message="bounded prompt")
            error = LIVE.AppServerRpcError(
                method="turn/interrupt",
                code=-32600,
                request_id=1,
                latency_ms=1.0,
            )

            with mock.patch.object(
                server,
                "interrupt_turn",
                side_effect=error,
            ) as interrupt_turn:
                with self.assertRaises(LIVE.AppServerRpcError) as raised:
                    adapter.interrupt()
                self.assertIs(raised.exception, error)
                interrupt_turn.assert_called_once_with(
                    server.thread_id,
                    server.turn_id,
                )
            self.assertIsNone(adapter._durable_terminal_status)
            self.assertFalse(adapter.interrupted)

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

    def test_exact_tool_trace_accepts_only_complete_ordered_sequence(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            server = FakeLiveThreadServer(root, initial_boundary="valid")
            expected = fixed_activation_tool_trace(
                "n1-read-only",
                0,
                worktree=root,
            )
            adapter = LIVE.LiveThreadAdapter(
                server,
                server.thread_response(),
                prompt=(
                    "Use exec_command for git rev-parse HEAD and "
                    "sha256sum data/shared.txt"
                ),
                expected_token="DONE",
                worktree=root,
                mutable=False,
                expected_mutation=None,
                expected_tool_trace=expected,
                record_dir=root,
                monotonic_ns=FakeMonotonicClock(),
            )
            self.controller_bind_and_arm(adapter)
            adapter.send_input(message=adapter.prompt)
            records = []
            for index, command in enumerate(
                ("git rev-parse HEAD", "sha256sum data/shared.txt")
            ):
                call_id = f"exact-{index}"
                records.extend(
                    [
                        {
                            "type": "response_item",
                            "payload": {
                                "type": "function_call",
                                "name": "exec_command",
                                "call_id": call_id,
                                "arguments": json.dumps(
                                    {"cmd": command}
                                ),
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
                stream.write(
                    "".join(
                        json.dumps(record) + "\n"
                        for record in records
                    )
                )
            server.items = [
                {"type": "commandExecution", "status": "completed"},
                {"type": "commandExecution", "status": "completed"},
                {
                    "type": "agentMessage",
                    "phase": "finalAnswer",
                    "text": "DONE",
                },
            ]
            server.status = "completed"
            self.assertEqual(adapter.check(), {"decision": "complete"})
            with mock.patch.object(
                adapter,
                "_workspace_mutations",
                return_value=[],
            ):
                evidence = adapter.evidence()
                summary = adapter.final_summary()
            self.assertEqual(evidence["reasons"], [])
            self.assertTrue(summary["exact_tool_trace_satisfied"])
            self.assertEqual(
                len(summary["trusted_tool_receipts"]),
                2,
            )

    def test_exact_tool_trace_accepts_only_bounded_exec_argument_variants(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            server = FakeLiveThreadServer(root, initial_boundary="valid")
            expected = fixed_activation_tool_trace(
                "n1-read-only",
                0,
                worktree=root,
            )
            adapter = LIVE.LiveThreadAdapter(
                server,
                server.thread_response(),
                prompt="bounded",
                expected_token="DONE",
                worktree=root,
                mutable=False,
                expected_mutation=None,
                expected_tool_trace=expected,
                record_dir=root,
                monotonic_ns=FakeMonotonicClock(),
            )
            commands = (
                "git rev-parse HEAD",
                "sha256sum data/shared.txt",
            )
            variants = (
                lambda command: {"cmd": command},
                lambda command: {
                    "cmd": command,
                    "workdir": str(root),
                },
                lambda command: {
                    "cmd": command,
                    "workdir": str(root),
                    "login": False,
                },
            )
            for variant in variants:
                receipts = [
                    {
                        "sequence": step["sequence"],
                        "tool": step["tool"],
                        "canonical_argument_hash": canonical_argument_hash(
                            variant(command)
                        ),
                        "action_class": step["action_class"],
                        "determinable_target_paths": step[
                            "determinable_target_paths"
                        ],
                        "pairing_status": "paired",
                        "result_kind": "paired-success",
                        "exit_code": 0,
                    }
                    for step, command in zip(expected, commands, strict=True)
                ]
                with self.subTest(receipts=receipts):
                    pending = adapter._exact_tool_trace_observation(
                        receipts,
                        terminal=False,
                    )
                    self.assertEqual(pending["status"], "pending")
                    self.assertFalse(pending["satisfied"])
                    observation = adapter._exact_tool_trace_observation(
                        receipts,
                        terminal=True,
                    )
                    self.assertTrue(observation["satisfied"])
                    self.assertFalse(observation["mismatch"])

            unexpected = [
                {
                    "sequence": step["sequence"],
                    "tool": step["tool"],
                    "canonical_argument_hash": canonical_argument_hash(
                        {
                            "cmd": command,
                            "workdir": str(root),
                            "login": False,
                            "yield_time_ms": 1_000,
                        }
                    ),
                    "action_class": step["action_class"],
                    "determinable_target_paths": step[
                        "determinable_target_paths"
                    ],
                    "pairing_status": "paired",
                    "result_kind": "paired-success",
                    "exit_code": 0,
                }
                for step, command in zip(expected, commands, strict=True)
            ]
            observation = adapter._exact_tool_trace_observation(
                unexpected,
                terminal=True,
            )
            self.assertTrue(observation["mismatch"])
            self.assertEqual(
                observation["reason"],
                "step-0-canonical-argument-mismatch",
            )

    def test_failed_patch_retry_is_exact_tool_trace_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            server = FakeLiveThreadServer(root, initial_boundary="valid")
            adapter = LIVE.LiveThreadAdapter(
                server,
                server.thread_response(mutable=True),
                prompt="Use apply_patch once then exec_command once",
                expected_token="DONE",
                worktree=root,
                mutable=True,
                expected_mutation="targets/activation.txt",
                expected_tool_trace=fixed_activation_tool_trace(
                    "n1-mutable",
                    0,
                    worktree=root,
                ),
                record_dir=root,
                monotonic_ns=FakeMonotonicClock(),
            )
            self.controller_bind_and_arm(adapter)
            adapter.send_input(message=adapter.prompt)
            failed_patch = MUTABLE_PATCH_INPUT.replace(
                "+activation-preview-mutated",
                "activation-preview-mutated",
            )
            records = [
                {
                    "type": "response_item",
                    "payload": {
                        "type": "custom_tool_call",
                        "name": "apply_patch",
                        "call_id": "failed",
                        "input": failed_patch,
                    },
                },
                {
                    "type": "response_item",
                    "payload": {
                        "type": "custom_tool_call_output",
                        "call_id": "failed",
                        "output": (
                            "apply_patch verification failed: missing line"
                        ),
                    },
                },
                {
                    "type": "response_item",
                    "payload": {
                        "type": "custom_tool_call",
                        "name": "apply_patch",
                        "call_id": "succeeded",
                        "input": MUTABLE_PATCH_INPUT,
                    },
                },
                {
                    "type": "event_msg",
                    "payload": {
                        "type": "patch_apply_end",
                        "call_id": "succeeded",
                        "turn_id": server.turn_id,
                        "success": True,
                        "status": "completed",
                    },
                },
                {
                    "type": "response_item",
                    "payload": {
                        "type": "custom_tool_call_output",
                        "call_id": "succeeded",
                        "output": "Exit code: 0\nOutput:\nSuccess.\n",
                    },
                },
                {
                    "type": "response_item",
                    "payload": {
                        "type": "function_call",
                        "name": "exec_command",
                        "call_id": "check",
                        "arguments": json.dumps(
                            {"cmd": "git diff --check"}
                        ),
                    },
                },
                {
                    "type": "response_item",
                    "payload": {
                        "type": "function_call_output",
                        "call_id": "check",
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
            with server.path.open("a", encoding="utf-8") as stream:
                stream.write(
                    "".join(
                        json.dumps(record) + "\n"
                        for record in records
                    )
                )
            server.items = [
                {"type": "commandExecution", "status": "completed"}
                for _ in range(3)
            ] + [
                {
                    "type": "agentMessage",
                    "phase": "finalAnswer",
                    "text": "DONE",
                }
            ]
            server.status = "completed"
            self.assertEqual(adapter.check(), {"decision": "interrupt"})
            with mock.patch.object(
                adapter,
                "_workspace_mutations",
                return_value=["targets/activation.txt"],
            ):
                evidence = adapter.evidence()
                summary = adapter.final_summary()
            self.assertIn(
                "exact-tool-trace-mismatch",
                evidence["reasons"],
            )
            self.assertFalse(summary["exact_tool_trace_satisfied"])
            self.assertEqual(
                [
                    receipt["result_kind"]
                    for receipt in summary["trusted_tool_receipts"]
                ],
                ["paired-failure", "paired-success", "paired-success"],
            )
            exact_without_failed_attempt = (
                adapter._exact_tool_trace_observation(
                    [
                        {**receipt, "sequence": sequence}
                        for sequence, receipt in enumerate(
                            summary["trusted_tool_receipts"][1:]
                        )
                    ],
                    terminal=True,
                )
            )
            self.assertTrue(exact_without_failed_attempt["satisfied"])

    def test_contradictory_patch_success_event_and_failure_output_interrupts(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            server = FakeLiveThreadServer(root, initial_boundary="valid")
            adapter = LIVE.LiveThreadAdapter(
                server,
                server.thread_response(mutable=True),
                prompt="Use apply_patch once then exec_command once",
                expected_token="DONE",
                worktree=root,
                mutable=True,
                expected_mutation="targets/activation.txt",
                expected_tool_trace=fixed_activation_tool_trace(
                    "n1-mutable",
                    0,
                    worktree=root,
                ),
                record_dir=root,
                monotonic_ns=FakeMonotonicClock(),
            )
            self.controller_bind_and_arm(adapter)
            adapter.send_input(message=adapter.prompt)
            records = [
                {
                    "type": "response_item",
                    "payload": {
                        "type": "custom_tool_call",
                        "name": "apply_patch",
                        "call_id": "patch",
                        "input": MUTABLE_PATCH_INPUT,
                    },
                },
                {
                    "type": "event_msg",
                    "payload": {
                        "type": "patch_apply_end",
                        "call_id": "patch",
                        "turn_id": server.turn_id,
                        "success": True,
                        "status": "completed",
                    },
                },
                {
                    "type": "response_item",
                    "payload": {
                        "type": "custom_tool_call_output",
                        "call_id": "patch",
                        "output": (
                            "apply_patch verification failed: "
                            "target mismatch"
                        ),
                    },
                },
                {
                    "type": "response_item",
                    "payload": {
                        "type": "function_call",
                        "name": "exec_command",
                        "call_id": "check",
                        "arguments": json.dumps(
                            {"cmd": "git diff --check"}
                        ),
                    },
                },
                {
                    "type": "response_item",
                    "payload": {
                        "type": "function_call_output",
                        "call_id": "check",
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
            with server.path.open("a", encoding="utf-8") as stream:
                stream.write(
                    "".join(
                        json.dumps(record) + "\n"
                        for record in records
                    )
                )
            server.items = [
                {"type": "commandExecution", "status": "completed"},
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
                adapter,
                "_workspace_mutations",
                return_value=["targets/activation.txt"],
            ):
                evidence = adapter.evidence()
                summary = adapter.final_summary()
            self.assertIn(
                "exact-tool-trace-mismatch",
                evidence["reasons"],
            )
            self.assertFalse(summary["exact_tool_trace_satisfied"])
            self.assertEqual(
                [
                    receipt["result_kind"]
                    for receipt in summary["trusted_tool_receipts"]
                ],
                [
                    "ambiguous-call-or-output-cardinality",
                    "paired-success",
                ],
            )

    def test_projected_terminal_does_not_finalize_exact_tool_trace(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            server = FakeLiveThreadServer(root, initial_boundary="valid")
            adapter = LIVE.LiveThreadAdapter(
                server,
                server.thread_response(),
                prompt=(
                    "Use exec_command for git rev-parse HEAD and "
                    "sha256sum data/shared.txt"
                ),
                expected_token="DONE",
                worktree=root,
                mutable=False,
                expected_mutation=None,
                expected_tool_trace=fixed_activation_tool_trace(
                    "n1-read-only",
                    0,
                    worktree=root,
                ),
                record_dir=root,
                monotonic_ns=FakeMonotonicClock(),
            )
            self.controller_bind_and_arm(adapter)
            adapter.send_input(message=adapter.prompt)
            server.status = "completed"
            server.items = [
                {
                    "type": "agentMessage",
                    "phase": "finalAnswer",
                    "text": "DONE",
                }
            ]
            self.assertEqual(adapter.check(), {"decision": "continue"})

    def test_projected_terminal_does_not_finalize_operative_tool_anomaly(
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
            self.controller_bind_and_arm(adapter)
            adapter.send_input(message="bounded prompt")
            with server.path.open("a", encoding="utf-8") as stream:
                stream.write(
                    json.dumps(
                        {
                            "type": "response_item",
                            "payload": {
                                "type": "function_call",
                                "name": "exec_command",
                                "call_id": "pending-call",
                                "arguments": json.dumps(
                                    {"cmd": "rg bounded"}
                                ),
                            },
                        }
                    )
                    + "\n"
                )
            server.status = "completed"
            server.items = [
                {"type": "commandExecution", "status": "completed"},
            ]

            self.assertEqual(adapter.check(), {"decision": "continue"})
            with mock.patch.object(
                adapter,
                "_workspace_mutations",
                return_value=[],
            ):
                evidence = adapter.evidence()
                summary = adapter.final_summary()
            self.assertIsNone(summary["durable_terminal_event"])
            self.assertEqual(
                summary["projected_turn_status"],
                "completed",
            )
            self.assertEqual(summary["forbidden_tool_activity"], [])
            self.assertNotIn(
                "forbidden-tool-activity",
                evidence["reasons"],
            )

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
            self.controller_bind_and_arm(adapter)
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
            self.controller_bind_and_arm(adapter)
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

    def test_pending_namespaced_patch_does_not_latch_before_outer_output(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            server = FakeLiveThreadServer(root, initial_boundary="valid")
            server.operative_tool_transport = (
                lambda: LIVE.NAMESPACED_EXEC_TOOL_TRANSPORT
            )
            _manifest, override = temporary_tool_override_fixture()
            policy = LIVE.default_tool_policy(
                mutable=True,
                enforcement_override=override,
            )
            adapter = LIVE.LiveThreadAdapter(
                server,
                server.thread_response(mutable=True),
                prompt="bounded prompt",
                expected_token="DONE",
                worktree=root,
                mutable=True,
                expected_mutation="scripts/child_2.py",
                tool_policy=policy,
                record_dir=root,
                monotonic_ns=FakeMonotonicClock(),
            )
            self.controller_bind_and_arm(adapter)
            adapter.send_input(message="bounded prompt")
            patch = (
                "*** Begin Patch\n"
                "*** Update File: scripts/child_2.py\n"
                "@@\n"
                "+VALUE = 12\n"
                "*** End Patch"
            )
            source = (
                "const result = await tools.apply_patch("
                + json.dumps(patch)
                + "); text(JSON.stringify(result));"
            )
            records = [
                {"type": "turn_context", "payload": {"turn_id": server.turn_id}},
                {
                    "type": "response_item",
                    "payload": {
                        "type": "custom_tool_call",
                        "call_id": "outer-call",
                        "name": "exec",
                        "input": source,
                    },
                },
                {
                    "type": "event_msg",
                    "payload": {
                        "type": "patch_apply_end",
                        "call_id": "nested-call",
                        "turn_id": server.turn_id,
                        "success": True,
                        "status": "completed",
                        "changes": {
                            str(root / "scripts/child_2.py"): {
                                "type": "update"
                            }
                        },
                    },
                },
            ]
            pending = LIVE.trusted_tool_evidence_summary(
                records,
                turn_id=server.turn_id,
                tool_transport=LIVE.NAMESPACED_EXEC_TOOL_TRANSPORT,
            )
            self.assertEqual(pending["trusted_tool_calls"], 1)
            self.assertEqual(pending["trusted_completed_tool_calls"], 0)
            self.assertEqual(
                pending["trusted_tool_receipts"][0]["result_kind"],
                "unpaired-call",
            )
            self.assertEqual(adapter._observe_forbidden_tool_activity(pending), [])

            records.append(
                {
                    "type": "response_item",
                    "payload": {
                        "type": "custom_tool_call_output",
                        "call_id": "outer-call",
                        "output": [
                            {
                                "type": "input_text",
                                "text": (
                                    "Script completed\n"
                                    "Wall time 0.1 seconds\n"
                                    "Output:\n"
                                ),
                            },
                            {"type": "input_text", "text": "{}"},
                        ],
                    },
                }
            )
            completed = LIVE.trusted_tool_evidence_summary(
                records,
                turn_id=server.turn_id,
                tool_transport=LIVE.NAMESPACED_EXEC_TOOL_TRANSPORT,
            )
            self.assertEqual(completed["trusted_completed_tool_calls"], 1)
            self.assertEqual(
                completed["trusted_tool_receipts"][0]["result_kind"],
                "paired-success",
            )
            self.assertEqual(
                adapter._observe_forbidden_tool_activity(completed),
                [],
            )

    def test_pending_direct_patch_waits_for_output_and_fails_closed_terminally(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            server = FakeLiveThreadServer(root, initial_boundary="valid")
            _manifest, override = temporary_tool_override_fixture()
            policy = LIVE.default_tool_policy(
                mutable=True,
                enforcement_override=override,
            )
            adapter = LIVE.LiveThreadAdapter(
                server,
                server.thread_response(mutable=True),
                prompt="bounded prompt",
                expected_token="DONE",
                worktree=root,
                mutable=True,
                expected_mutation="scripts/child_2.py",
                tool_policy=policy,
                record_dir=root,
                monotonic_ns=FakeMonotonicClock(),
            )
            self.controller_bind_and_arm(adapter)
            adapter.send_input(message="bounded prompt")
            records = [
                {"type": "turn_context", "payload": {"turn_id": server.turn_id}},
                {
                    "type": "response_item",
                    "payload": {
                        "type": "custom_tool_call",
                        "call_id": "direct-call",
                        "name": "apply_patch",
                        "input": (
                            "*** Begin Patch\n"
                            "*** Update File: scripts/child_2.py\n"
                            "@@\n"
                            "+VALUE = 12\n"
                            "*** End Patch"
                        ),
                    },
                },
                {
                    "type": "event_msg",
                    "payload": {
                        "type": "patch_apply_end",
                        "call_id": "direct-call",
                        "turn_id": server.turn_id,
                        "success": True,
                        "status": "completed",
                        "changes": {
                            str(root / "scripts/child_2.py"): {"type": "update"}
                        },
                    },
                },
            ]
            pending = LIVE.trusted_tool_evidence_summary(
                records,
                turn_id=server.turn_id,
                tool_transport=LIVE.DIRECT_TOOL_TRANSPORT,
            )
            self.assertEqual(
                pending["trusted_tool_receipts"][0]["result_kind"],
                "paired-pending",
            )
            self.assertEqual(pending["trusted_tool_names"], ["apply_patch"])
            self.assertEqual(adapter._observe_forbidden_tool_activity(pending), [])

            terminal = LIVE.trusted_tool_evidence_summary(
                records,
                turn_id=server.turn_id,
                terminal_event={"status": "interrupted", "record_index": 3},
                tool_transport=LIVE.DIRECT_TOOL_TRANSPORT,
            )
            self.assertEqual(
                terminal["trusted_tool_names"],
                ["telemetry_anomaly.apply_patch"],
            )
            self.assertEqual(
                [item["tool"] for item in adapter._observe_forbidden_tool_activity(terminal)],
                ["telemetry_anomaly.apply_patch"],
            )

    def test_pending_namespaced_patch_fails_closed_at_every_terminal_state(
        self,
    ) -> None:
        for terminal_status in ("completed", "failed", "interrupted"):
            with self.subTest(terminal_status=terminal_status), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                server = FakeLiveThreadServer(root, initial_boundary="valid")
                _manifest, override = temporary_tool_override_fixture()
                policy = LIVE.default_tool_policy(
                    mutable=True,
                    enforcement_override=override,
                )
                adapter = LIVE.LiveThreadAdapter(
                    server,
                    server.thread_response(),
                    prompt="bounded prompt",
                    expected_token="DONE",
                    worktree=root,
                    mutable=True,
                    expected_mutation="scripts/child_2.py",
                    tool_policy=policy,
                    record_dir=root,
                    monotonic_ns=FakeMonotonicClock(),
                )
                adapter.turn_id = server.turn_id
                boundary = {
                    "trusted_tool_calls": 1,
                    "trusted_tool_activity": [
                        {
                            "tool": "apply_patch",
                            "evidence_sha256": "a" * 64,
                            "pairing_status": "unpaired",
                            "result_kind": "unpaired-call",
                        }
                    ],
                    "terminal_event": {"status": terminal_status},
                }

                observed = adapter._observe_forbidden_tool_activity(boundary)

                self.assertEqual(len(observed), 1)
                self.assertEqual(
                    observed[0]["tool"],
                    "telemetry_anomaly.apply_patch",
                )

    def test_namespaced_patch_output_after_terminal_cannot_complete_call(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            server = FakeLiveThreadServer(root, initial_boundary="valid")
            _manifest, override = temporary_tool_override_fixture()
            policy = LIVE.default_tool_policy(
                mutable=True,
                enforcement_override=override,
            )
            adapter = LIVE.LiveThreadAdapter(
                server,
                server.thread_response(),
                prompt="bounded prompt",
                expected_token="DONE",
                worktree=root,
                mutable=True,
                expected_mutation="scripts/child_2.py",
                tool_policy=policy,
                record_dir=root,
                monotonic_ns=FakeMonotonicClock(),
            )
            adapter.turn_id = server.turn_id
            patch = (
                "*** Begin Patch\n"
                "*** Update File: scripts/child_2.py\n"
                "@@\n"
                "+VALUE = 12\n"
                "*** End Patch"
            )
            source = (
                "const result = await tools.apply_patch("
                + json.dumps(patch)
                + "); text(JSON.stringify(result));"
            )
            records = [
                {"type": "turn_context", "payload": {"turn_id": server.turn_id}},
                {
                    "type": "response_item",
                    "payload": {
                        "type": "custom_tool_call",
                        "call_id": "outer-call",
                        "name": "exec",
                        "input": source,
                    },
                },
                {
                    "type": "event_msg",
                    "payload": {
                        "type": "patch_apply_end",
                        "call_id": "nested-call",
                        "turn_id": server.turn_id,
                        "success": True,
                        "status": "completed",
                        "changes": {
                            str(root / "scripts/child_2.py"): {
                                "type": "update"
                            }
                        },
                    },
                },
                {
                    "type": "event_msg",
                    "payload": {
                        "type": "task_complete",
                        "turn_id": server.turn_id,
                    },
                },
                {
                    "type": "response_item",
                    "payload": {
                        "type": "custom_tool_call_output",
                        "call_id": "outer-call",
                        "output": (
                            "Script completed\n"
                            "Wall time 0.1 seconds\n"
                            "Output:\n{}"
                        ),
                    },
                },
            ]
            boundary = LIVE.trusted_tool_evidence_summary(
                records,
                turn_id=server.turn_id,
                terminal_event={"record_index": 3, "status": "completed"},
                tool_transport=LIVE.NAMESPACED_EXEC_TOOL_TRANSPORT,
            )
            boundary["terminal_event"] = {"status": "completed"}

            self.assertEqual(boundary["trusted_completed_tool_calls"], 0)
            self.assertEqual(
                boundary["trusted_tool_receipts"][0]["result_kind"],
                "unpaired-call",
            )
            self.assertEqual(
                adapter._observe_forbidden_tool_activity(boundary)[0]["tool"],
                "telemetry_anomaly.apply_patch",
            )

    def test_interrupted_exec_result_rejects_normal_worker_completion(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            server = FakeLiveThreadServer(root, initial_boundary="valid")
            adapter = self.adapter(root, server, FakeMonotonicClock())
            adapter.send_input(message="bounded prompt")
            with server.path.open("a", encoding="utf-8") as stream:
                for record in (
                    {
                        "type": "response_item",
                        "payload": {
                            "type": "function_call",
                            "name": "exec_command",
                            "call_id": "interrupted-call",
                            "arguments": json.dumps({"cmd": "sleep 20"}),
                        },
                    },
                    {
                        "type": "response_item",
                        "payload": {
                            "type": "function_call_output",
                            "call_id": "interrupted-call",
                            "output": "aborted by user after 1.3s",
                        },
                    },
                    {
                        "type": "event_msg",
                        "payload": {
                            "type": "task_complete",
                            "turn_id": server.turn_id,
                        },
                    },
                ):
                    stream.write(json.dumps(record) + "\n")
            server.items = [
                {
                    "type": "agentMessage",
                    "phase": "finalAnswer",
                    "text": "DONE",
                }
            ]
            server.status = "completed"

            self.assertEqual(adapter.check(), {"decision": "interrupt"})
            with mock.patch.object(
                adapter,
                "_workspace_mutations",
                return_value=[],
            ):
                evidence = adapter.evidence()
                summary = adapter.final_summary()
            self.assertIn("forbidden-tool-activity", evidence["reasons"])
            self.assertTrue(evidence["protected_fault"])
            self.assertFalse(summary["completion_evidence_satisfied"])
            self.assertEqual(
                summary["forbidden_tool_activity"][0]["tool"],
                "telemetry_anomaly.exec_command",
            )

    def test_recoverable_nonexistent_workdir_does_not_interrupt_worker(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            server = FakeLiveThreadServer(root, initial_boundary="valid")
            adapter = self.adapter(root, server, FakeMonotonicClock())
            adapter.send_input(message="bounded prompt")
            missing = root / "mistyped-workdir"
            with server.path.open("a", encoding="utf-8") as stream:
                for record in (
                    {
                        "type": "response_item",
                        "payload": {
                            "type": "function_call",
                            "name": "exec_command",
                            "call_id": "recoverable-call",
                            "arguments": json.dumps(
                                {"cmd": "pwd", "workdir": str(missing)}
                            ),
                        },
                    },
                    {
                        "type": "response_item",
                        "payload": {
                            "type": "function_call_output",
                            "call_id": "recoverable-call",
                            "output": ControllerWorkdirTelemetryTests.NO_PROCESS,
                        },
                    },
                ):
                    stream.write(json.dumps(record) + "\n")

            self.assertEqual(adapter.check(), {"decision": "continue"})
            self.assertEqual(adapter._forbidden_tool_activity, [])
            boundary = adapter._capture_trusted_boundary(allow_pending=True)
            self.assertEqual(
                boundary["trusted_tool_receipts"][0]["result_kind"],
                "paired-recoverable-workdir-input-error",
            )

    def test_existing_workdir_escape_attempt_interrupts_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            outside = root.parent
            server = FakeLiveThreadServer(root, initial_boundary="valid")
            adapter = self.adapter(root, server, FakeMonotonicClock())
            adapter.send_input(message="bounded prompt")
            with server.path.open("a", encoding="utf-8") as stream:
                for record in (
                    {
                        "type": "response_item",
                        "payload": {
                            "type": "function_call",
                            "name": "exec_command",
                            "call_id": "escape-call",
                            "arguments": json.dumps(
                                {"cmd": "pwd", "workdir": str(outside)}
                            ),
                        },
                    },
                    {
                        "type": "response_item",
                        "payload": {
                            "type": "function_call_output",
                            "call_id": "escape-call",
                            "output": str(outside),
                            "exit_code": 0,
                        },
                    },
                ):
                    stream.write(json.dumps(record) + "\n")

            self.assertEqual(adapter.check(), {"decision": "interrupt"})
            self.assertEqual(
                adapter._forbidden_tool_activity[0]["tool"],
                "security_violation.exec_command_workdir",
            )

    def test_trusted_session_cwd_mismatch_is_a_control_error(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            server = FakeLiveThreadServer(root, initial_boundary="valid")
            records = [json.loads(line) for line in server.path.read_text().splitlines()]
            records[0]["payload"]["cwd"] = str(root / "other")
            server.path.write_text(
                "".join(json.dumps(record) + "\n" for record in records),
                encoding="utf-8",
            )
            adapter = self.adapter(root, server, FakeMonotonicClock())
            adapter.send_input(message="bounded prompt")
            with self.assertRaisesRegex(
                LIVE.AppServerError, "session-controller-workdir-mismatch"
            ):
                adapter.check()

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
                self.controller_bind_and_arm(adapter)
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
            self.controller_bind_and_arm(adapter)
            adapter.send_input(message="bounded prompt")
            self.complete_turn(server)
            self.assertEqual(adapter.check(), {"decision": "complete"})
            with mock.patch.object(adapter, "_workspace_mutations", return_value=[]):
                evidence = adapter.evidence()
            self.assertEqual(evidence["reasons"], [])
            self.assertEqual(evidence["artifact_disposition"], "accepted")

    def test_mutable_empty_workspace_is_not_faulted_before_or_after_dispatch(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            server = FakeLiveThreadServer(root, initial_boundary="missing")
            adapter = LIVE.LiveThreadAdapter(
                server,
                server.thread_response(mutable=True),
                prompt="bounded prompt",
                expected_token="DONE",
                worktree=root,
                mutable=True,
                expected_mutation="targets/child_0.txt",
                record_dir=root,
                monotonic_ns=FakeMonotonicClock(),
            )
            self.controller_bind_and_arm(adapter)
            with mock.patch.object(
                adapter,
                "_workspace_mutations",
                return_value=[],
            ):
                armed_evidence = adapter.evidence()
                self.assertFalse(armed_evidence["protected_fault"])
                self.assertNotIn(
                    "mutable-workspace-attribution-mismatch",
                    armed_evidence["reasons"],
                )
                adapter.send_input(message="bounded prompt")
                dispatched_evidence = adapter.evidence()
            self.assertFalse(dispatched_evidence["protected_fault"])
            self.assertNotIn(
                "mutable-workspace-attribution-mismatch",
                dispatched_evidence["reasons"],
            )

    def test_mutable_predispatch_mutation_is_rejected_even_at_expected_path(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            server = FakeLiveThreadServer(root, initial_boundary="missing")
            adapter = LIVE.LiveThreadAdapter(
                server,
                server.thread_response(mutable=True),
                prompt="bounded prompt",
                expected_token="DONE",
                worktree=root,
                mutable=True,
                expected_mutation="targets/child_0.txt",
                record_dir=root,
                monotonic_ns=FakeMonotonicClock(),
            )
            with mock.patch.object(
                adapter,
                "_workspace_mutations",
                return_value=["targets/child_0.txt"],
            ):
                evidence = adapter.evidence()
            self.assertIn(
                "mutable-workspace-attribution-mismatch",
                evidence["reasons"],
            )
            self.assertTrue(evidence["protected_fault"])

    def test_mutable_wrong_postdispatch_mutation_is_rejected_immediately(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            server = FakeLiveThreadServer(root, initial_boundary="missing")
            adapter = LIVE.LiveThreadAdapter(
                server,
                server.thread_response(mutable=True),
                prompt="bounded prompt",
                expected_token="DONE",
                worktree=root,
                mutable=True,
                expected_mutation="targets/child_0.txt",
                record_dir=root,
                monotonic_ns=FakeMonotonicClock(),
            )
            self.controller_bind_and_arm(adapter)
            adapter.send_input(message="bounded prompt")
            with mock.patch.object(
                adapter,
                "_workspace_mutations",
                return_value=["targets/unexpected.txt"],
            ):
                evidence = adapter.evidence()
            self.assertIn(
                "mutable-workspace-attribution-mismatch",
                evidence["reasons"],
            )
            self.assertTrue(evidence["protected_fault"])

    def test_mutable_completion_without_expected_mutation_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            server = FakeLiveThreadServer(root, initial_boundary="valid")
            adapter = LIVE.LiveThreadAdapter(
                server,
                server.thread_response(mutable=True),
                prompt="bounded prompt",
                expected_token="DONE",
                worktree=root,
                mutable=True,
                expected_mutation="targets/child_0.txt",
                record_dir=root,
                monotonic_ns=FakeMonotonicClock(),
            )
            self.controller_bind_and_arm(adapter)
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
            self.assertEqual(
                adapter.finalize(control_action="interrupt-confirmed"),
                {
                    "ack": "interrupt-confirmed",
                    "close_wait_required": True,
                },
            )
            self.assertEqual(
                self.settle_and_close(adapter),
                {"ack": "closed"},
            )
            final = adapter.final_summary()
            self.assertEqual(
                set(final["callback_subphase_stats"]),
                {
                    "send_input.acknowledgement_binding",
                    "send_input.boundary_lock_wait",
                    "send_input.prompt_preflight",
                    "send_input.tool_surface_capture",
                    "send_input.tool_surface_validation",
                    "send_input.turn_start_rpc",
                },
            )
            self.assertEqual(
                final["session_boundary"]["observation_type"],
                "containment-unmaterialized-nonattesting-rejected",
            )

    def test_close_defers_until_staged_archive_is_ready(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            server = FakeLiveThreadServer(root, initial_boundary="valid")
            adapter = self.adapter(root, server, FakeMonotonicClock())
            adapter._capture_trusted_boundary(allow_pending=True)
            staged_archive = mock.Mock()
            staged_archive.completion_ready.side_effect = [False, True]
            staged_archive.require_complete.return_value = 1.0
            adapter._staged_archive = staged_archive

            self.assertEqual(
                adapter.close(),
                {
                    "ack": "close-pending",
                    "close_wait_required": True,
                },
            )
            self.assertFalse(adapter.archived)
            staged_archive.require_complete.assert_not_called()

            target = server.archive / server.path.name
            server.path.replace(target)
            server.path = target
            self.assertEqual(adapter.close(), {"ack": "closed"})
            self.assertTrue(adapter.archived)
            self.assertEqual(adapter.reported_session_path, str(target))
            staged_archive.require_complete.assert_called_once_with(
                timeout_seconds=0.0,
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

    @staticmethod
    def read_only_authority(
        root: Path,
        *,
        pending: bool = False,
        tool_transport: str = LIVE.DIRECT_TOOL_TRANSPORT,
    ) -> list[dict[str, Any]]:
        command = "python -B -m unittest tests.test_local_dispatch" if pending else "git diff --check"
        exec_arguments = {
            "cmd": command,
            "workdir": str(root),
        }
        if tool_transport == LIVE.DIRECT_TOOL_TRANSPORT:
            exec_arguments["login"] = False
        authority: list[dict[str, Any]] = [
            {
                "sequence": 0,
                "tool": "exec_command",
                "argument_alternatives": [exec_arguments],
                "continuation_of": None,
            }
        ]
        if pending:
            authority.append(
                {
                    "sequence": 1,
                    "tool": "write_stdin",
                    "argument_alternatives": [
                        {
                            "session_id": LIVE.PENDING_EXEC_SESSION,
                            "chars": "",
                        }
                    ],
                    "continuation_of": 0,
                }
            )
        return authority

    def authorized_read_only_adapter(
        self,
        root: Path,
        server: FakeLiveThreadServer,
        *,
        pending: bool = False,
    ) -> LIVE.LiveThreadAdapter:
        transport_reader = getattr(server, "operative_tool_transport", None)
        tool_transport = (
            transport_reader()
            if callable(transport_reader)
            else LIVE.DIRECT_TOOL_TRANSPORT
        )
        adapter = LIVE.LiveThreadAdapter(
            server,
            server.thread_response(),
            prompt="Run only the exact controller-authorized validation commands",
            expected_token="DONE",
            worktree=root,
            mutable=False,
            expected_mutation=None,
            read_only_command_authority=self.read_only_authority(
                root,
                pending=pending,
                tool_transport=tool_transport,
            ),
            record_dir=root,
            monotonic_ns=FakeMonotonicClock(),
        )
        self.controller_bind_and_arm(adapter)
        return adapter

    @staticmethod
    def append_terminal_records(
        server: FakeLiveThreadServer,
        records: list[dict[str, Any]],
    ) -> None:
        terminal = {
            "type": "event_msg",
            "payload": {
                "type": "task_complete",
                "turn_id": server.turn_id,
            },
        }
        with server.path.open("a", encoding="utf-8") as stream:
            stream.write(
                "".join(
                    json.dumps(record) + "\n"
                    for record in [*records, terminal]
                )
            )
        server.items = [
            {"type": "commandExecution", "status": "completed"}
            for _item in records
            if _item.get("type") == "response_item"
            and _item.get("payload", {}).get("type")
            in {"function_call", "custom_tool_call"}
        ] + [
            {
                "type": "agentMessage",
                "phase": "finalAnswer",
                "text": "DONE",
            }
        ]
        server.status = "completed"

    def test_read_only_command_authority_reaches_final_acceptance_on_both_transports(
        self,
    ) -> None:
        for transport in (
            LIVE.DIRECT_TOOL_TRANSPORT,
            LIVE.NAMESPACED_EXEC_TOOL_TRANSPORT,
        ):
            with self.subTest(transport=transport), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                server = FakeLiveThreadServer(root, initial_boundary="valid")
                server.operative_tool_transport = lambda: transport
                adapter = self.authorized_read_only_adapter(root, server)
                adapter.send_input(message=adapter.prompt)
                arguments = self.read_only_authority(
                    root,
                    tool_transport=transport,
                )[0][
                    "argument_alternatives"
                ][0]
                if transport == LIVE.DIRECT_TOOL_TRANSPORT:
                    records = [
                        {
                            "type": "response_item",
                            "payload": {
                                "type": "function_call",
                                "name": "exec_command",
                                "call_id": "read-only-command",
                                "arguments": json.dumps(arguments),
                            },
                        },
                        {
                            "type": "response_item",
                            "payload": {
                                "type": "function_call_output",
                                "call_id": "read-only-command",
                                "exit_code": 0,
                                "output": "bounded",
                            },
                        },
                    ]
                else:
                    source = (
                        "const result = await tools.exec_command("
                        + json.dumps(arguments, separators=(",", ":"))
                        + "); text(JSON.stringify(result));"
                    )
                    records = [
                        {
                            "type": "response_item",
                            "payload": {
                                "type": "custom_tool_call",
                                "name": "exec",
                                "call_id": "read-only-command",
                                "input": source,
                            },
                        },
                        {
                            "type": "response_item",
                            "payload": {
                                "type": "custom_tool_call_output",
                                "call_id": "read-only-command",
                                "output": [
                                    {
                                        "type": "input_text",
                                        "text": "Script completed\nWall time 0.1 seconds\nOutput:\n",
                                    },
                                    {
                                        "type": "input_text",
                                        "text": json.dumps(
                                            {
                                                "wall_time_seconds": 0.1,
                                                "exit_code": 0,
                                                "output": "bounded",
                                            },
                                            separators=(",", ":"),
                                        ),
                                    },
                                ],
                            },
                        },
                    ]
                self.append_terminal_records(server, records)
                self.assertEqual(adapter.check(), {"decision": "complete"})
                with mock.patch.object(
                    adapter,
                    "_workspace_mutations",
                    return_value=[],
                ):
                    evidence = adapter.evidence()
                    summary = adapter.final_summary()
                self.assertEqual(evidence["reasons"], [])
                self.assertTrue(
                    summary["read_only_command_authority_satisfied"]
                )
                self.assertTrue(summary["completion_evidence_satisfied"])

    def test_read_only_command_authority_binds_pending_poll_to_exact_parent(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            server = FakeLiveThreadServer(root, initial_boundary="valid")
            adapter = self.authorized_read_only_adapter(
                root,
                server,
                pending=True,
            )
            arguments = self.read_only_authority(root, pending=True)[0][
                "argument_alternatives"
            ][0]
            records = [
                {"type": "turn_context", "payload": {"turn_id": "authority-turn"}},
                {
                    "type": "response_item",
                    "payload": {
                        "type": "function_call",
                        "name": "exec_command",
                        "call_id": "exec",
                        "arguments": json.dumps(arguments),
                    },
                },
                {
                    "type": "response_item",
                    "payload": {
                        "type": "function_call_output",
                        "call_id": "exec",
                        "output": (
                            "Chunk ID: abc123\n"
                            "Wall time: 30.0 seconds\n"
                            "Process running with session ID 28838\n"
                            "Original token count: 0\n"
                            "Output:\n"
                        ),
                    },
                },
                {
                    "type": "response_item",
                    "payload": {
                        "type": "function_call",
                        "name": "write_stdin",
                        "call_id": "poll",
                        "arguments": json.dumps(
                            {"session_id": 28838, "chars": ""}
                        ),
                    },
                },
                {
                    "type": "response_item",
                    "payload": {
                        "type": "function_call_output",
                        "call_id": "poll",
                        "output": (
                            "Chunk ID: def456\n"
                            "Wall time: 1.0 seconds\n"
                            "Process exited with code 0\n"
                            "Final output:\n"
                        ),
                    },
                },
                {
                    "type": "event_msg",
                    "payload": {
                        "type": "task_complete",
                        "turn_id": "authority-turn",
                    },
                },
            ]
            summary = LIVE.trusted_tool_evidence_summary(
                records,
                turn_id="authority-turn",
                terminal_event={"record_index": len(records) - 1},
                tool_transport=LIVE.DIRECT_TOOL_TRANSPORT,
            )
            self.assertEqual(
                [
                    item["result_kind"]
                    for item in summary["trusted_tool_authority_receipts"]
                ],
                ["paired-deferred", "paired-success"],
            )
            accepted = adapter._read_only_command_authority_observation(
                summary["trusted_tool_authority_receipts"],
                terminal=True,
            )
            self.assertTrue(accepted["satisfied"])
            wrong = copy.deepcopy(summary["trusted_tool_authority_receipts"])
            wrong[1]["operation_session_id_sha256"] = LIVE.sha256_text("28839")
            rejected = adapter._read_only_command_authority_observation(
                wrong,
                terminal=True,
            )
            self.assertTrue(rejected["mismatch"])
            self.assertEqual(rejected["reason"], "step-1-pending-parent-mismatch")

    def test_read_only_command_authority_rejects_poll_before_parent_result(
        self,
    ) -> None:
        for transport in (
            LIVE.DIRECT_TOOL_TRANSPORT,
            LIVE.NAMESPACED_EXEC_TOOL_TRANSPORT,
        ):
            with self.subTest(transport=transport), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                server = FakeLiveThreadServer(root, initial_boundary="valid")
                server.operative_tool_transport = lambda: transport
                adapter = self.authorized_read_only_adapter(
                    root,
                    server,
                    pending=True,
                )
                authority = self.read_only_authority(
                    root,
                    pending=True,
                    tool_transport=transport,
                )
                exec_arguments = authority[0]["argument_alternatives"][0]
                poll_arguments = {"session_id": 28838, "chars": ""}
                if transport == LIVE.DIRECT_TOOL_TRANSPORT:
                    records = [
                        {"type": "turn_context", "payload": {"turn_id": "authority-turn"}},
                        {
                            "type": "response_item",
                            "payload": {
                                "type": "function_call",
                                "name": "exec_command",
                                "call_id": "exec",
                                "arguments": json.dumps(exec_arguments),
                            },
                        },
                        {
                            "type": "response_item",
                            "payload": {
                                "type": "function_call",
                                "name": "write_stdin",
                                "call_id": "poll",
                                "arguments": json.dumps(poll_arguments),
                            },
                        },
                        {
                            "type": "response_item",
                            "payload": {
                                "type": "function_call_output",
                                "call_id": "poll",
                                "output": (
                                    "Chunk ID: def456\n"
                                    "Wall time: 1.0 seconds\n"
                                    "Process exited with code 0\n"
                                    "Final output:\n"
                                ),
                            },
                        },
                        {
                            "type": "response_item",
                            "payload": {
                                "type": "function_call_output",
                                "call_id": "exec",
                                "output": (
                                    "Chunk ID: abc123\n"
                                    "Wall time: 30.0 seconds\n"
                                    "Process running with session ID 28838\n"
                                    "Original token count: 0\n"
                                    "Output:\n"
                                ),
                            },
                        },
                    ]
                else:
                    records = [
                        {"type": "turn_context", "payload": {"turn_id": "authority-turn"}},
                        PendingExecTelemetryTests.call(
                            "exec_command", "exec", exec_arguments
                        ),
                        PendingExecTelemetryTests.call(
                            "write_stdin", "poll", poll_arguments
                        ),
                        PendingExecTelemetryTests.output(
                            "poll",
                            {
                                "chunk_id": "def456",
                                "wall_time_seconds": 1.0,
                                "exit_code": 0,
                                "original_token_count": 0,
                                "output": "",
                            },
                        ),
                        PendingExecTelemetryTests.output(
                            "exec",
                            {
                                "chunk_id": "abc123",
                                "wall_time_seconds": 30.0,
                                "session_id": 28838,
                                "original_token_count": 0,
                                "output": "",
                            },
                        ),
                    ]
                records.append(
                    {
                        "type": "event_msg",
                        "payload": {
                            "type": "task_complete",
                            "turn_id": "authority-turn",
                        },
                    }
                )
                summary = LIVE.trusted_tool_evidence_summary(
                    records,
                    turn_id="authority-turn",
                    terminal_event={"record_index": len(records) - 1},
                    tool_transport=transport,
                )
                rejected = adapter._read_only_command_authority_observation(
                    summary["trusted_tool_authority_receipts"],
                    terminal=True,
                )
                self.assertTrue(rejected["mismatch"])
                self.assertEqual(
                    rejected["reason"],
                    "step-1-raw-receipt-binding-invalid",
                )

    def test_read_only_command_authority_rejects_shell_and_interpreter_escape_grammars(
        self,
    ) -> None:
        bad_commands = (
            "git diff --check; touch escaped",
            "git diff --check && rm -f target",
            "git diff --check > /tmp/result",
            "python -B -c 'open(\"target\", \"w\").write(\"x\")'",
            "sed -n '1,10p' target",
            "sed -i s/a/b/ target",
            "sed -n '1e id' target",
            "sed -n 'w /tmp/escaped' target",
            "find . -delete",
            "find . -fls /tmp/not-executed",
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for command in bad_commands:
                with self.subTest(command=command), self.assertRaises(
                    LIVE.AppServerError
                ):
                    LIVE._normalize_read_only_command_authority(
                        [
                            {
                                "sequence": 0,
                                "tool": "exec_command",
                                "argument_alternatives": [
                                    {
                                        "cmd": command,
                                        "workdir": str(root),
                                        "login": False,
                                    }
                                ],
                                "continuation_of": None,
                            }
                        ],
                        worktree=root,
                        tool_transport=LIVE.DIRECT_TOOL_TRANSPORT,
                    )

    def test_read_only_command_authority_rejects_find_fls_on_both_transports(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for transport in (
                LIVE.DIRECT_TOOL_TRANSPORT,
                LIVE.NAMESPACED_EXEC_TOOL_TRANSPORT,
            ):
                arguments = {
                    "cmd": "find . -fls /tmp/not-executed",
                    "workdir": str(root),
                }
                if transport == LIVE.DIRECT_TOOL_TRANSPORT:
                    arguments["login"] = False
                with self.subTest(transport=transport), self.assertRaisesRegex(
                    LIVE.AppServerError,
                    "read-only-command-authority-option-forbidden",
                ):
                    LIVE._normalize_read_only_command_authority(
                        [
                            {
                                "sequence": 0,
                                "tool": "exec_command",
                                "argument_alternatives": [arguments],
                                "continuation_of": None,
                            }
                        ],
                        worktree=root,
                        tool_transport=transport,
                    )

    def test_read_only_command_authority_rejects_git_external_helpers_on_both_transports(
        self,
    ) -> None:
        commands = (
            "git diff --ext",
            "git diff --ext-",
            "git diff --ext-d",
            "git diff --ext-di",
            "git diff --ext-diff",
            "git diff --textc",
            "git diff --textco",
            "git diff --textcon",
            "git diff --textconv",
            "git show --ext-diff HEAD",
            "git show --textconv HEAD",
            "git diff --ext-diff=true",
            "git show --textconv=true HEAD",
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for transport in (
                LIVE.DIRECT_TOOL_TRANSPORT,
                LIVE.NAMESPACED_EXEC_TOOL_TRANSPORT,
            ):
                for command in commands:
                    arguments = {
                        "cmd": command,
                        "workdir": str(root),
                    }
                    if transport == LIVE.DIRECT_TOOL_TRANSPORT:
                        arguments["login"] = False
                    with (
                        self.subTest(transport=transport, command=command),
                        self.assertRaisesRegex(
                            LIVE.AppServerError,
                            "read-only-command-authority-git-option-forbidden",
                        ),
                    ):
                        LIVE._normalize_read_only_command_authority(
                            [
                                {
                                    "sequence": 0,
                                    "tool": "exec_command",
                                    "argument_alternatives": [arguments],
                                    "continuation_of": None,
                                }
                            ],
                            worktree=root,
                            tool_transport=transport,
                        )

    def test_read_only_command_authority_preserves_reviewed_git_grammar_on_both_transports(
        self,
    ) -> None:
        commands = (
            "git diff --check",
            "git diff --exit-code",
            "git diff --text",
            "git diff --no-ext-diff",
            "git show --no-textconv HEAD",
            "git status --short",
            "git rev-parse --show-toplevel",
            "git show --stat HEAD",
            "git ls-files",
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for transport in (
                LIVE.DIRECT_TOOL_TRANSPORT,
                LIVE.NAMESPACED_EXEC_TOOL_TRANSPORT,
            ):
                for command in commands:
                    arguments = {
                        "cmd": command,
                        "workdir": str(root),
                    }
                    if transport == LIVE.DIRECT_TOOL_TRANSPORT:
                        arguments["login"] = False
                    with self.subTest(transport=transport, command=command):
                        normalized = LIVE._normalize_read_only_command_authority(
                            [
                                {
                                    "sequence": 0,
                                    "tool": "exec_command",
                                    "argument_alternatives": [arguments],
                                    "continuation_of": None,
                                }
                            ],
                            worktree=root,
                            tool_transport=transport,
                        )
                        self.assertEqual(normalized[0]["tool"], "exec_command")
                        self.assertEqual(
                            normalized[0]["argument_alternatives"][0]["cmd"],
                            command,
                        )

    def test_read_only_command_authority_rejects_substitution_and_stays_sticky(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            server = FakeLiveThreadServer(root, initial_boundary="valid")
            adapter = self.authorized_read_only_adapter(root, server)
            expected_arguments = self.read_only_authority(root)[0][
                "argument_alternatives"
            ][0]
            bad_receipt = {
                "sequence": 0,
                "tool": "exec_command",
                "canonical_argument_hash": LIVE.canonical_argument_hash(
                    {**expected_arguments, "cmd": "git status --short"}
                ),
                "continuation_argument_hash": None,
                "call_id_sha256": LIVE.sha256_text("substituted"),
                "operation_session_id_sha256": None,
                "raw_pairing_status": "exact",
                "raw_receipt_alignment": "exact",
                "pairing_status": "paired",
                "result_kind": "paired-success",
                "exit_code": 0,
            }
            boundary = {
                "trusted_tool_activity": [],
                "trusted_tool_authority_receipts": [bad_receipt],
                "terminal_event": None,
            }
            first = adapter._observe_forbidden_tool_activity(boundary)
            self.assertTrue(first)
            self.assertEqual(
                first[0]["tool"],
                "security_violation.read_only_command_authority",
            )
            second = adapter._observe_forbidden_tool_activity(
                {
                    "trusted_tool_activity": [],
                    "trusted_tool_authority_receipts": [],
                    "terminal_event": None,
                }
            )
            self.assertEqual(second, first)

    def test_read_only_command_authority_distinguishes_authorized_failure_from_success(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            server = FakeLiveThreadServer(root, initial_boundary="valid")
            adapter = self.authorized_read_only_adapter(root, server)
            arguments = self.read_only_authority(root)[0][
                "argument_alternatives"
            ][0]
            observed = [
                {
                    "sequence": 0,
                    "tool": "exec_command",
                    "canonical_argument_hash": LIVE.canonical_argument_hash(
                        arguments
                    ),
                    "continuation_argument_hash": None,
                    "call_id_sha256": LIVE.sha256_text("failed"),
                    "operation_session_id_sha256": None,
                    "raw_pairing_status": "exact",
                    "raw_receipt_alignment": "exact",
                    "pairing_status": "paired",
                    "result_kind": "paired-failure",
                    "exit_code": 1,
                }
            ]
            result = adapter._read_only_command_authority_observation(
                observed,
                terminal=True,
            )
            self.assertFalse(result["mismatch"])
            self.assertFalse(result["satisfied"])
            self.assertEqual(result["status"], "authorized-failure")

    def test_read_only_command_authority_is_unavailable_to_mutable_workers(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            server = FakeLiveThreadServer(root, initial_boundary="valid")
            with self.assertRaisesRegex(
                LIVE.AppServerError,
                "read-only-command-authority-mutable-forbidden",
            ):
                LIVE.LiveThreadAdapter(
                    server,
                    server.thread_response(mutable=True),
                    prompt="bounded",
                    expected_token="DONE",
                    worktree=root,
                    mutable=True,
                    expected_mutation="target.txt",
                    read_only_command_authority=self.read_only_authority(root),
                    record_dir=root,
                )


# Synthetic wire fixtures: the real host probes are recorded separately.
class ProfileThreadBoundaryTests(unittest.TestCase):
    request_server = AppServerRpcErrorTests.request_server

    def test_readonly_developer_instructions_and_enforcement_agree(self):
        for transport in [LIVE.DIRECT_TOOL_TRANSPORT,LIVE.NAMESPACED_EXEC_TOOL_TRANSPORT]:
            server=self.request_server({'id':1,'result':{'model':LIVE.EXACT_MODEL,'thread':{'id':str(uuid.uuid4()),'turns':[]}}})
            tools=['exec_command','write_stdin']
            server.operative_tool_transport=lambda:transport
            server.tool_surface_capability=lambda **kw:{'source':'synthetic-fixed-two-tool-profile','server_allowlist_supported':True,'allowlist_parameter':'tools','effective_allowlist':tools}
            server.start_thread(ROOT,mutable=False,permitted_tools=tools,allowlist_parameter='tools')
            params=json.loads(server.process.stdin.getvalue().splitlines()[-1])['params']
            self.assertEqual(params['tools'],tools);self.assertEqual(params['sandbox'],'read-only')
            self.assertNotIn('apply_patch',params['developerInstructions'])
            for tool in tools:self.assertIn(tool,params['developerInstructions'])

    def test_failed_capability_is_before_allocation_or_transport(self):
        for permitted in [None,{},['exec_command',{}],['exec_command','write_stdin']]:
            server=self.request_server({'id':1,'result':{}})
            ledger=mock.Mock();server.allocation_ledger=ledger
            server.tool_surface_capability=lambda **kw:{'source':'synthetic-broader','server_allowlist_supported':True,'allowlist_parameter':'tools','effective_allowlist':['apply_patch','exec_command','write_stdin']}
            with self.subTest(permitted=permitted),self.assertRaises(LIVE.AppServerError):
                server.start_thread(ROOT,mutable=False,role=next(iter(EXPECTED_ROLES)),permitted_tools=permitted,allowlist_parameter='tools')
            ledger.allocation_intent.assert_not_called();self.assertEqual(server.process.stdin.getvalue(),'')

    def test_profile_consumers_do_not_reinsert_three_tools(self):
        tools=['exec_command','write_stdin'];server=self.request_server({'id':1,'result':{}})
        server._tool_surface_proof={'requested_tools':tools}
        proof={'codex_version':'test-version','tool_transport':LIVE.NAMESPACED_EXEC_TOOL_TRANSPORT}
        with mock.patch.object(TRANSPORT,'require_surface_proof',return_value=proof) as require:
            self.assertEqual(server.capability_adapter_version(),'codex-app-server-test-version')
            self.assertEqual(server.operative_tool_transport(),LIVE.NAMESPACED_EXEC_TOOL_TRANSPORT)
            for call in require.call_args_list:self.assertEqual(call.kwargs['permitted_tools'],tools)

    def test_invalid_proof_rejected_before_process_start(self):
        for bad in [[],{},None]:
            if bad is None:continue
            with mock.patch.object(TRANSPORT.subprocess,'Popen') as popen,self.assertRaises(LIVE.AppServerError):
                LIVE.AppServer(requested_model='gpt-5.6-luna',tool_surface_proof=bad)
            popen.assert_not_called()

    def test_readonly_profile_cannot_open_mutable_thread(self):
        server=self.request_server({'id':1,'result':{}})
        server._tool_surface_proof={'tool_profile':'read-only-v1'}
        server.operative_tool_transport=lambda:LIVE.DIRECT_TOOL_TRANSPORT
        server._thread_tool_allowlist_params=lambda **kw:{}
        with self.assertRaisesRegex(LIVE.AppServerError,'read-only-tool-profile-mutable-thread-forbidden'):
            server.start_thread(ROOT,mutable=True)
        self.assertEqual(server.process.stdin.getvalue(),'')

    def test_proof_startup_is_forwarded_and_home_drift_closes(self):
        proof={'requested_tools':['exec_command','write_stdin']}
        verified={'startup_config':{'model_catalog_json':'/fixture/catalog.json'},'codex_home':'/fixture/home','codex_binary':'/fixture/codex','capture_binding':{'fixture':True}}
        with mock.patch.object(TRANSPORT, 'check_codex_capabilities') as capabilities, \
                mock.patch.object(TRANSPORT,'require_surface_proof',return_value=verified),mock.patch.object(TRANSPORT,'require_capture_binding',return_value=verified),mock.patch.object(TRANSPORT.subprocess,'Popen') as process,mock.patch.object(LIVE.threading,'Thread'),mock.patch.object(LIVE.AppServer,'request',return_value=({'codexHome':'/different/home'},0)),mock.patch.object(LIVE.AppServer,'close',return_value={'all_contained':True,'resources_closed':True,'errors':[]}) as close:
            with self.assertRaisesRegex(LIVE.AppServerError,'codex-tool-surface-home-drift'):
                LIVE.AppServer(requested_model='gpt-5.6-luna',tool_surface_proof=proof)
            capabilities.assert_called_once_with('/fixture/codex')
            self.assertEqual(process.call_args.args[0],['/fixture/codex','-c','model_catalog_json="/fixture/catalog.json"','app-server','--stdio'])
            close.assert_called_once()


class StartupLifecycleTests(unittest.TestCase):
    """No provider: fake RPCs plus a bounded, real owned Python child."""
    def setUp(self):
        capabilities = mock.patch.object(TRANSPORT, 'check_codex_capabilities')
        self.addCleanup(capabilities.stop)
        capabilities.start()

    def construct(self, *, failure=None, process=None, callback=None):
        """Startup failure checks use an explicit disposable home/executable."""
        import io,os
        home=Path(tempfile.gettempdir()).resolve()
        process=process or mock.Mock()
        process.pid=123;process.returncode=None
        process.stdin=io.StringIO();process.stdout=io.StringIO();process.stderr=io.StringIO()
        process.poll.side_effect=lambda:process.returncode
        def wait(**kw):process.returncode=-15;return -15
        process.wait.side_effect=wait
        reader=mock.Mock();reader.ident=None;reader.is_alive.return_value=False
        if failure=='pipes':process.stdout=None
        if failure=='reader':reader.start.side_effect=RuntimeError('reader-failed')
        original=LIVE.AppServerError('initialize-original')
        instance=[]
        def request(server,*args,**kw):
            instance.append(server)
            if callback:callback(server,process)
            if failure=='rpc':raise original
            if failure=='invalid':return {},0
            if failure=='invalid-home':return {'codexHome':{}},0
            return {'codexHome':str(home if failure!='home' else home/'wrong')},0
        def notify(server,*args):
            if failure=='notify':raise RuntimeError('notification-original')
        with mock.patch.dict(os.environ,{'CODEX_HOME':str(home)}),mock.patch.object(TRANSPORT,'_codex_binary',return_value=Path('/verified/codex')),mock.patch.object(TRANSPORT.subprocess,'Popen',return_value=process) as popen,mock.patch.object(LIVE.threading,'Thread',return_value=reader),mock.patch.object(LIVE.AppServer,'request',request),mock.patch.object(LIVE.AppServer,'notify',notify):
            try:
                server=LIVE.AppServer(requested_model='gpt-5.6-luna', executable='/verified/codex', codex_home=home)
                self.assertEqual(popen.call_args.args[0][0],'/verified/codex')
                return server,process
            except BaseException as exc:
                self.assertTrue(exc.app_server_cleanup['all_contained'])
                self.assertTrue(exc.app_server_cleanup['resources_closed'])
                self.assertEqual(exc.app_server_cleanup['errors'],[])
                self.assertIsNotNone(process.returncode)
                if failure=='rpc':self.assertIs(exc,original)
                raise

    def test_all_post_spawn_failures_reap_owned_child(self):
        for failure in ['pipes','rpc','invalid','invalid-home','home','reader','notify']:
            with self.subTest(failure=failure),self.assertRaises((LIVE.AppServerError,RuntimeError)):
                self.construct(failure=failure)

    def test_synchronous_close_during_initialize_and_repeated_close(self):
        def callback(server,process):
            first=server.close();self.assertTrue(first['all_contained']);self.assertEqual(first,server.close())
        with self.assertRaisesRegex(LIVE.AppServerError,'closed-during-startup'):
            self.construct(callback=callback)
        server,process=self.construct();first=server.close();self.assertEqual(first,server.close());process.terminate.assert_called_once()

    def test_reentrant_close_does_not_claim_completion(self):
        server,process=self.construct()
        seen=[]
        def terminate():
            try:server.close()
            except LIVE.AppServerError as exc:seen.append(exc.app_server_cleanup)
        process.terminate.side_effect=terminate
        self.assertTrue(server.close()['all_contained']);self.assertEqual(seen[0]['all_contained'],False)

    def test_terminate_wait_kill_and_pipe_failures_remain_truthful(self):
        for failure in ['terminate','wait','kill','pipe']:
            server,process=self.construct()
            if failure=='terminate':process.terminate.side_effect=OSError('terminate-failed')
            if failure in ['wait','kill']:
                process.wait.side_effect=TRANSPORT.subprocess.TimeoutExpired('fixture',0)
                if failure=='wait':
                    def kill():process.returncode=-9;process.wait.side_effect=None;process.wait.return_value=-9
                    process.kill.side_effect=kill
                else:process.kill.side_effect=OSError('kill-failed')
            if failure=='pipe':process.stdin=mock.Mock();process.stdin.close.side_effect=OSError('close-failed')
            with self.subTest(failure=failure),self.assertRaisesRegex(LIVE.AppServerError,'cleanup-failed') as caught:server.close()
            result=caught.exception.app_server_cleanup
            self.assertEqual(result['all_contained'],failure!='kill')
            self.assertTrue(result['errors'])
            with self.assertRaises(LIVE.AppServerError) as again:server.close()
            self.assertEqual(again.exception.app_server_cleanup,result)

    def test_r5_original_error_and_cleanup_failure_are_separate(self):
        original=LIVE.AppServerError('primary-initialize')
        with mock.patch.object(TRANSPORT,'_codex_binary',return_value=Path('/fixture/codex')),mock.patch.object(TRANSPORT.subprocess,'Popen') as popen,mock.patch.object(LIVE.threading,'Thread'),mock.patch.object(LIVE.AppServer,'request',side_effect=original),mock.patch.object(LIVE.AppServer,'close',side_effect=OSError('cleanup-failure')):
            with self.assertRaises(LIVE.AppServerError) as caught:LIVE.AppServer(requested_model='gpt-5.6-luna', executable='/fixture/codex', codex_home=Path(tempfile.gettempdir()).resolve())
            popen.assert_called_once()
        self.assertIs(caught.exception,original);self.assertFalse(original.app_server_cleanup['all_contained']);self.assertIn('cleanup-failure',str(original.app_server_cleanup))

    def test_r5_real_disposable_child_is_reaped_when_constructor_fails(self):
        import os,subprocess,sys
        spawn=subprocess.Popen;children=[]
        def factory(*args,**kw):
            child=spawn([sys.executable,'-c','import time; time.sleep(30)'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
            children.append(child);return child
        original=LIVE.AppServerError('real-child-initialize-failure')
        try:
            with mock.patch.object(TRANSPORT,'_codex_binary',return_value=Path(sys.executable)),mock.patch.object(TRANSPORT.subprocess,'Popen',side_effect=factory),mock.patch.object(LIVE.AppServer,'request',side_effect=original):
                with self.assertRaises(LIVE.AppServerError) as caught:LIVE.AppServer(requested_model='gpt-5.6-luna', executable=sys.executable, codex_home=Path(tempfile.gettempdir()).resolve())
            self.assertIs(caught.exception,original);self.assertEqual(len(children),1)
            child=children[0];self.assertIsNotNone(child.poll());self.assertTrue(original.app_server_cleanup['all_contained'])
            self.assertTrue(all(stream.closed for stream in [child.stdin,child.stdout,child.stderr]))
            with self.assertRaises(ChildProcessError):os.waitpid(child.pid,os.WNOHANG)
        finally:
            for child in children:
                if child.poll() is None:child.kill();child.wait(timeout=5)


if __name__ == "__main__":
    unittest.main()
