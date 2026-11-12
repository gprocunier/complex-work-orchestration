"""Launch refusal and negative-response attribution, with no process effects.

The parser receives raw stdout. Fixtures seed the already-admitted observer seam;
the transport and ledger use their real identity registries and revocation code.
"""
from __future__ import annotations

import io
import json
import os
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import registered_app_server_transport as transport
from cwo_core import native_live_allocation_ledger as ledger_api

from tests import test_codex_tool_surface as surface_fixtures


class _FixtureRegisteredServer(transport.RegisteredAppServer):
    """An explicit test launch boundary returning inert in-memory pipes."""

    def _default_executable(self):
        return "/EXAMPLE/registered-codex"

    def _launch_process(self, command, environment):
        self.launches.append((command, environment))
        return self.fixture_process


class RegisteredTransportF2Tests(unittest.TestCase):
    def bare_server(self):
        server = object.__new__(transport.RegisteredAppServer)
        server._prepare_rpc_state()
        return server

    def proof_fixture(self):
        fixture = surface_fixtures.CodexToolSurfaceTests("runTest")
        fixture.setUp()
        self.addCleanup(fixture.tearDown)
        self.enterContext(mock.patch("codex_tool_surface._codex_binary", return_value=fixture.binary))
        self.enterContext(mock.patch("codex_tool_surface._codex_version", return_value="test-version"))
        self.enterContext(mock.patch.dict(os.environ, {"CODEX_HOME": str(fixture.home)}))
        server = self.bare_server()
        server.requested_model = transport.EXACT_MODEL
        return server, fixture._proof(), fixture.home

    def pending_response(self, *, with_ledger=True, epoch=None):
        server = self.bare_server()
        capability = object()
        pending = {
            "capability": capability,
            "thread_id": "EXAMPLE-original-thread",
            "turn_intent_id": "EXAMPLE-original-intent",
            "request_id": 41,
            "connection_epoch_sha256": epoch or server.connection_epoch_sha256,
            "wire_request_sha256": "b" * 64,
            "dispatch_record_sha256": "c" * 64,
        }
        server._pending_turn_start_response_observers[41] = pending
        ledger = None
        if with_ledger:
            directory = self.enterContext(tempfile.TemporaryDirectory())
            ledger = ledger_api.NativeLiveAllocationLedgerStore(directory)
            binding = ledger_api._PendingTurnNegativeResponseObserverBinding(
                **{key: value for key, value in pending.items() if key != "capability"}
            )
            ledger._pending_turn_negative_response_observer_capabilities.register(capability, binding)
            server.allocation_ledger = ledger
        message = {"id": 41, "error": {"code": -32600, "message": "EXAMPLE rejected"}}
        return server, pending, ledger, capability, message

    def assert_no_observed_witness(self, server, ledger):
        self.assertEqual(server._observed_negative_turn_response_capabilities_by_request, {})
        self.assertEqual(len(server._negative_turn_response_capabilities), 0)
        if ledger is not None:
            self.assertEqual(len(ledger._turn_negative_response_observer_capabilities), 0)

    def test_f2_base_transport_refuses_before_any_launch(self):
        """Both base hooks refuse, even with an explicit command."""
        with (
            mock.patch("cwo_core.supervision.transport.app_server.subprocess.Popen") as launch,
            mock.patch("cwo_core.supervision.transport.app_server._codex_binary") as find_binary,
        ):
            with self.assertRaisesRegex(transport.AppServerError, "registered-app-server-launcher-required") as raised:
                transport.RegisteredAppServer()
            self.assertEqual(raised.exception.app_server_cleanup,
                             {"all_contained": True, "resources_closed": True, "errors": []})
            server = self.bare_server()
            with self.assertRaisesRegex(transport.AppServerError, "registered-app-server-launcher-required"):
                server._launch_process(["/EXAMPLE/codex", "app-server", "--stdio"], {})
            launch.assert_not_called()
            find_binary.assert_not_called()

    def test_f2_tool_proof_probe_conflicts_M146(self):
        """Valid proof alone works; either conflicting probe refuses."""
        server, proof, home = self.proof_fixture()
        prepared_home, binding, _startup = server._prepare_tool_binding(proof, None, None)
        self.assertEqual(prepared_home, home)
        self.assertEqual(binding, proof["capture_binding"])
        for catalog, probe in ((home / "catalog.json", None), (None, binding)):
            with (
                self.subTest(catalog=catalog, probe=probe is not None),
                self.assertRaisesRegex(transport.AppServerError, "tool-proof-and-probe-catalog-conflict"),
            ):
                server._prepare_tool_binding(proof, catalog, probe)

    def test_f2_probe_catalog_mismatch_M147(self):
        """A verified binding cannot be paired with another catalog."""
        server, proof, home = self.proof_fixture()
        binding = proof["capture_binding"]
        self.assertEqual(server._prepare_tool_binding(None, None, binding)[1], binding)
        with self.assertRaisesRegex(transport.AppServerError, "tool-probe-binding-mismatch"):
            server._prepare_tool_binding(None, home / "different-catalog.json", binding)

    def test_f2_each_missing_pipe_refuses_M148(self):
        """All three pipes are required on the explicit fixture launcher."""
        for missing in (None, "stdin", "stdout", "stderr"):
            with self.subTest(missing=missing):
                server = object.__new__(_FixtureRegisteredServer)
                server.launches = []
                streams = {name: io.StringIO() for name in ("stdin", "stdout", "stderr")}
                if missing is not None:
                    streams[missing] = None
                server.fixture_process = SimpleNamespace(**streams)
                home = Path("/EXAMPLE/registered-home")
                if missing is None:
                    server._launch_registered_transport(home, None, {})
                    self.assertIs(server.process, server.fixture_process)
                else:
                    with self.assertRaisesRegex(transport.AppServerError, "app-server-pipes-unavailable"):
                        server._launch_registered_transport(home, None, {})
                self.assertEqual(len(server.launches), 1)
                command, environment = server.launches[0]
                self.assertEqual(command, ["/EXAMPLE/registered-codex", "app-server", "--stdio"])
                self.assertEqual(environment["CODEX_HOME"], str(home))

    def test_f2_exact_negative_mints_single_use_bound_witness_M152(self):
        """A present capability permits the exact response, with or without a ledger."""
        for with_ledger in (False, True):
            with self.subTest(with_ledger=with_ledger):
                server, pending, ledger, original, message = self.pending_response(with_ledger=with_ledger)
                server._consume_raw_stdout_line(json.dumps(message))
                observed = server._observed_negative_turn_response_capabilities_by_request[41]
                self.assertIsNot(observed, original)
                self.assertEqual(server._pending_turn_start_response_observers, {})
                self.assertEqual(server._responses, {41: message})
                self.assertIsNone(server._reader_error)
                if ledger is not None:
                    self.assertNotIn(original, ledger._pending_turn_negative_response_observer_capabilities)
                    ledger_binding = ledger._turn_negative_response_observer_capabilities.get(observed)
                    self.assertEqual(ledger_binding.thread_id, pending["thread_id"])
                    self.assertEqual(ledger_binding.connection_epoch_sha256, server.connection_epoch_sha256)
                    self.assertEqual(ledger_binding.response_code, -32600)
                witness = server._consume_negative_turn_response_capability(observed, pending)
                self.assertEqual(witness, {
                    "request_id": 41,
                    "connection_epoch_sha256": server.connection_epoch_sha256,
                    "wire_request_sha256": pending["wire_request_sha256"],
                    "code": -32600,
                    "response_sha256": transport.domain_sha256(
                        message, domain="app-server-turn-start-negative-response"),
                })
                with self.assertRaisesRegex(transport.AppServerError, "turn-negative-response-capability-invalid"):
                    server._consume_negative_turn_response_capability(observed, pending)
                server._discard_negative_turn_response_capability(observed)
                self.assert_no_observed_witness(server, ledger)

    def test_f2_negative_attribution_matrix_M150_M152_M153_M154_M155_M157(self):
        """Malformed or misbound negatives give no retry witness."""
        cases = (
            ("missing-error-message", True), ("non-string-error-message", True),
            ("missing-capability", False), ("none-capability", False),
            ("missing-thread", False), ("non-string-thread", False),
            ("old-connection-epoch", True), ("wrong-thread", True),
            ("unregistered-capability", True),
        )
        for case, with_ledger in cases:
            with self.subTest(case=case):
                epoch = "a" * 64 if case == "old-connection-epoch" else None
                server, pending, ledger, original, message = self.pending_response(
                    with_ledger=with_ledger, epoch=epoch)
                if case == "missing-error-message":
                    message["error"].pop("message")
                elif case == "non-string-error-message":
                    message["error"]["message"] = 7
                elif case == "missing-capability":
                    pending.pop("capability")
                elif case == "none-capability":
                    pending["capability"] = None
                elif case == "missing-thread":
                    pending.pop("thread_id")
                elif case == "non-string-thread":
                    pending["thread_id"] = 7
                elif case == "wrong-thread":
                    binding = ledger._pending_turn_negative_response_observer_capabilities.pop(original)
                    ledger._pending_turn_negative_response_observer_capabilities.register(
                        original, replace(binding, thread_id="EXAMPLE-another-thread"))
                elif case == "unregistered-capability":
                    ledger._pending_turn_negative_response_observer_capabilities.pop(original)
                server._consume_raw_stdout_line(json.dumps(message))
                self.assert_no_observed_witness(server, ledger)
                self.assertEqual(server._pending_turn_start_response_observers, {})
                self.assertEqual(server._responses, {41: message})
                self.assertIsNone(server._reader_error)
                if ledger is not None:
                    self.assertNotIn(original, ledger._pending_turn_negative_response_observer_capabilities)

    def test_f2_duplicate_response_revokes_new_negative_witness_M151(self):
        """A duplicate response records a fault and revokes its new witness."""
        server, _pending, ledger, original, message = self.pending_response()
        first = {"id": 41, "result": {"turn": {"id": "EXAMPLE-prior-response"}}}
        server._responses[41] = first
        server._consume_raw_stdout_line(json.dumps(message))
        self.assertEqual(server._reader_error, "app-server-duplicate-response-id")
        self.assertEqual(server._responses, {41: first})
        self.assert_no_observed_witness(server, ledger)
        self.assertNotIn(original, ledger._pending_turn_negative_response_observer_capabilities)

    def test_f2_non_json_stdout_records_fault_and_stops_M149(self):
        """Invalid JSON returns after its fault without attributing a response."""
        server, pending, ledger, original, _message = self.pending_response()
        server._consume_raw_stdout_line("EXAMPLE non-JSON stdout\n")
        self.assertEqual(server._reader_error, "app-server-non-json-output")
        self.assertEqual(server._responses, {})
        self.assertEqual(server._pending_turn_start_response_observers, {41: pending})
        self.assert_no_observed_witness(server, ledger)
        self.assertIn(original, ledger._pending_turn_negative_response_observer_capabilities)


if __name__ == "__main__":
    unittest.main()
