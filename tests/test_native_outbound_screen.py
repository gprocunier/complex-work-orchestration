"""Original native writer: final model bytes, retained charges and no retry."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from cwo_core.outbound_screen import OutboundRefused  # noqa: E402
from cwo_core import prepared_outbound  # noqa: E402
from cwo_core.supervision.transport import app_server as transport  # noqa: E402
from tests import test_run_native_pool_live_canaries as native_fixture  # noqa: E402
from tests import test_registered_n1_factory as registered_fixture  # noqa: E402


class NativeOutboundScreenTests(unittest.TestCase):
    def setUp(self):
        hold = mock.patch.object(transport.live_availability, "N1_LIVE_AVAILABLE", True)
        hold.start()
        self.addCleanup(hold.stop)

    def turn_fixture(self, root, mode="absent"):
        fixture = native_fixture.AmbiguousTurnDispatchTests()
        self.addCleanup(fixture.doCleanups)
        return fixture.server(root, mode)

    def registered_fixture(self, **changes):
        fixture = registered_fixture.FactoryTests("runTest")
        fixture._outcome = self._outcome
        self.addCleanup(registered_fixture.cleanup_helper, self, fixture)
        fixture.setUp()
        case = fixture.case(archive_schedule="settled", **changes)
        return fixture, case, fixture.factory(case)

    def pipe_writer(self, payload, *, method=None, before_fileno=None):
        read_fd, write_fd = os.pipe()
        self.addCleanup(os.close, read_fd)
        stream = os.fdopen(write_fd, "w")
        self.addCleanup(stream.close)
        server = object.__new__(transport.AppServer)
        server._condition = threading.Condition()
        server._reader_error = None
        server.process = SimpleNamespace(stdin=stream, terminate=mock.Mock())
        if before_fileno is not None:
            original = stream.fileno
            stream.fileno = lambda: (before_fileno(), original())[1]
        os.set_blocking(read_fd, False)
        return server, read_fd, method or payload["method"]

    def write(self, server, payload, method, timeout=1):
        with server._condition:
            return server._write_payload(payload, method=method, timeout=timeout)

    def assert_empty(self, read_fd):
        with self.assertRaises(BlockingIOError):
            os.read(read_fd, 65536)

    def test_sensitive_prompt_and_metadata_keep_original_intent_without_wire(self):
        for metadata in (False, True):
            with self.subTest(metadata=metadata), tempfile.TemporaryDirectory() as temporary:
                server, ledger, _state, writer, thread_id, _turns = self.turn_fixture(Path(temporary))
                prompt = "Explain the local function."
                if metadata:
                    server.operation_metadata = {"password": "hunter2"}
                else:
                    prompt = "password=hunter2"
                with self.assertRaises(transport.AmbiguousTurnStartError) as caught:
                    server.start_turn(thread_id, prompt, timeout=0.02, ambiguity_timeout=0)
                self.assertEqual(writer.payloads, [])
                self.assertIsInstance(caught.exception.__cause__, OutboundRefused)
                record = caught.exception.record
                self.assertEqual((record["status"], record["ledger_resolution"],
                                  record["wire_write_attempt_count"]),
                                 ("failed-ambiguous", "pending", 1))
                self.assertEqual(ledger.summary()["unresolved_turn_intent_count"], 1)
                self.assertEqual(len(server._pending_turn_start_response_observers), 1)
                self.assertNotIn("hunter2", str(caught.exception) + str(caught.exception.__cause__) + json.dumps(record))

    def test_clean_original_turn_remains_useful_and_single_dispatch(self):
        with tempfile.TemporaryDirectory() as temporary:
            server, _ledger, _state, writer, thread_id, turns = self.turn_fixture(Path(temporary), "normal")
            result, _latency = server.start_turn(thread_id, "Explain the local function.", timeout=1)
            self.assertEqual(result["id"], turns[0])
            self.assertEqual(len(writer.payloads), 1)
            self.assertEqual(writer.payloads[0]["params"]["input"][0]["text"], "Explain the local function.")

    def test_final_serialized_injection_is_refused_before_original_pipe_write(self):
        payload = {"id": 1, "method": "turn/start", "params": {"input": "Explain the function."}}
        server, read_fd, method = self.pipe_writer(payload)
        dumps = json.dumps
        def inject(value, **kwargs):
            if value is not None and isinstance(value, dict) and value.get("method") == "turn/start" and not kwargs.get("sort_keys"):
                value = {**value, "params": {**value["params"], "password": "hunter2"}}
            return dumps(value, **kwargs)
        with mock.patch.object(transport.json, "dumps", side_effect=inject), self.assertRaises(OutboundRefused):
            self.write(server, payload, method)
        self.assert_empty(read_fd)

    def test_declared_method_cannot_hide_model_payload(self):
        payload = {"id": 1, "method": "turn/start", "params": {"input": "password=hunter2"}}
        server, read_fd, _method = self.pipe_writer(payload)
        with self.assertRaises(OutboundRefused):
            self.write(server, payload, "command/exec")
        self.assert_empty(read_fd)

    def test_other_host_model_context_methods_are_screened(self):
        methods = ("turn/steer", "review/start", "thread/start", "thread/resume", "thread/fork",
                   "thread/goal/set", "thread/inject_items", "thread/attachment/add", "thread/metadata/update")
        for method in methods:
            with self.subTest(method=method):
                payload = {"id": 1, "method": method, "params": {"developerInstructions": "password=hunter2"}}
                server, read_fd, _method = self.pipe_writer(payload)
                with self.assertRaises(OutboundRefused):
                    self.write(server, payload, method)
                self.assert_empty(read_fd)

    def test_source_drift_at_descriptor_callout_refuses_original_pipe(self):
        payload = {"id": 1, "method": "turn/start", "params": {"input": "Explain the function."}}
        def mutate():
            payload["params"]["input"] = "password=hunter2"
        server, read_fd, method = self.pipe_writer(payload, before_fileno=mutate)
        with self.assertRaises(OutboundRefused):
            self.write(server, payload, method)
        self.assert_empty(read_fd)

    def test_fixed_command_diagnostic_keeps_original_wire_bytes(self):
        payload = {"id": 1, "method": "command/exec", "params": {"command": ["printf", "password=hunter2"]}}
        server, read_fd, method = self.pipe_writer(payload)
        self.write(server, payload, method)
        self.assertEqual(os.read(read_fd, 65536), (json.dumps(payload, separators=(",", ":")) + "\n").encode())

    def test_json_frame_binding_rejects_typed_drift_duplicates_and_incomplete_frames(self):
        source = {"flag": True}
        frames = (b'{"flag":1}', b'{"flag":1.0}', b'{"flag":true,"flag":true}',
                  b'{"flag":NaN}', b'{"flag":true', b'{"flag":true}\n{}')
        for frame in frames:
            with self.subTest(frame=frame), self.assertRaises(OutboundRefused):
                prepared_outbound.prepare_json_frame(source, frame, surface="native model request")
        frame = b'{"flag":true}\n'
        prepared = prepared_outbound.prepare_json_frame(source, frame, surface="native model request")
        self.assertEqual(prepared.require_unchanged(source, frame), frame)
        with self.assertRaises(OutboundRefused):
            prepared.require_unchanged(source, frame + b" ")

    def test_screening_consumes_original_total_writer_deadline(self):
        payload = {"id": 1, "method": "turn/start", "params": {"input": "Explain the function."}}
        server, read_fd, method = self.pipe_writer(payload)
        clean = prepared_outbound.require_clean
        def delayed(*args, **kwargs):
            time.sleep(0.03)
            return clean(*args, **kwargs)
        with mock.patch.object(prepared_outbound, "require_clean", side_effect=delayed):
            with self.assertRaisesRegex(transport.AppServerError, "^app-server-request-write-timeout:turn/start$"):
                self.write(server, payload, method, timeout=0.01)
        self.assert_empty(read_fd)
        server.process.terminate.assert_called_once()

    def test_inner_writer_deadline_preserves_original_timeout_latch(self):
        payload = {"id": 1, "method": "fake/echo", "params": {"text": "Explain the function."}}
        server, read_fd, method = self.pipe_writer(payload)
        frame, binding = transport._prepare_native_frame(payload, method)
        expected = "app-server-request-write-timeout:fake/echo"
        # The outer remaining-time check succeeds; exact-source revalidation
        # reaches the same original deadline before any physical write.
        with server._condition, mock.patch.object(transport.time, "monotonic", side_effect=(0, 2)):
            with self.assertRaisesRegex(transport.AppServerError, "^" + expected + "$"):
                server._write_wire_bytes(server.process.stdin.fileno(), frame, 1, method, binding)
        self.assertEqual(server._reader_error, expected)
        server.process.terminate.assert_called_once()
        self.assert_empty(read_fd)
        with self.assertRaisesRegex(transport.AppServerError, "^" + expected + "$"):
            self.write(server, {"id": 2, "method": "thread/read", "params": {}}, "thread/read")
        self.assert_empty(read_fd)

    def test_partial_write_source_drift_stops_connection_without_second_frame(self):
        payload = {"id": 1, "method": "turn/start", "params": {"input": "Explain the function."}}
        server, read_fd, method = self.pipe_writer(payload)
        raw_write, prefixes = os.write, []
        def mutate(fd, data):
            count = raw_write(fd, data[:7])
            prefixes.append(data[:count])
            payload["params"]["input"] = "password=hunter2"
            return count
        with mock.patch.object(transport.os, "write", side_effect=mutate), self.assertRaises(OutboundRefused):
            self.write(server, payload, method)
        self.assertEqual(os.read(read_fd, 65536), b'{"id":1')
        self.assertEqual(len(prefixes), 1)
        self.assertEqual(server._reader_error, "app-server-outbound-frame-refused")
        server.process.terminate.assert_called_once()
        with self.assertRaisesRegex(transport.AppServerError, "^app-server-outbound-frame-refused$"):
            self.write(server, {"id": 2, "method": "thread/read", "params": {}}, "thread/read")
        self.assert_empty(read_fd)

    def test_outbound_primary_survives_containment_failure_without_sensitive_notes(self):
        with tempfile.TemporaryDirectory() as temporary:
            server, ledger, _state, writer, thread_id, _turns = self.turn_fixture(Path(temporary))
            with mock.patch.object(server, "contain_ambiguous_turn_dispatch", side_effect=RuntimeError("hunter2")):
                with self.assertRaises(OutboundRefused) as caught:
                    server.start_turn(thread_id, "password=hunter2", timeout=0.02, ambiguity_timeout=0)
            self.assertEqual(writer.payloads, [])
            self.assertEqual(ledger.summary()["unresolved_turn_intent_count"], 1)
            self.assertNotIn("hunter2", str(caught.exception) + str(caught.exception.__notes__))
            self.assertTrue(caught.exception.__suppress_context__)

    def test_secondary_termination_descriptor_and_note_failures_preserve_primary(self):
        class NoteFailure(OutboundRefused):
            def add_note(self, _note):
                raise RuntimeError("hunter2")
        payload = {"id": 1, "method": "turn/start", "params": {"input": "Explain the function."}}
        for failure in ("termination", "descriptor"):
            with self.subTest(failure=failure):
                server, read_fd, method = self.pipe_writer(payload)
                primary = NoteFailure("safe original refusal")
                blocking = os.set_blocking
                def restore(fd, value):
                    if value and failure == "descriptor":
                        raise OSError("hunter2")
                    blocking(fd, value)
                if failure == "termination":
                    server.process.terminate.side_effect = RuntimeError("hunter2")
                with mock.patch.object(transport, "_checked_native_frame", side_effect=primary):
                    with mock.patch.object(transport.os, "set_blocking", side_effect=restore):
                        with self.assertRaises(OutboundRefused) as caught:
                            self.write(server, payload, method)
                self.assertIs(caught.exception, primary)
                self.assert_empty(read_fd)
                self.assertFalse(server._wire_writing)
        with tempfile.TemporaryDirectory() as temporary:
            server, ledger, _state, writer, thread_id, _turns = self.turn_fixture(Path(temporary))
            primary = NoteFailure("safe original refusal")
            with mock.patch.object(prepared_outbound, "require_clean", side_effect=primary):
                with mock.patch.object(server, "contain_ambiguous_turn_dispatch", side_effect=RuntimeError("hunter2")):
                    with self.assertRaises(OutboundRefused) as caught:
                        server.start_turn(thread_id, "Explain the function.", timeout=0.02, ambiguity_timeout=0)
            self.assertIs(caught.exception, primary)
            self.assertEqual(writer.payloads, [])
            self.assertEqual(ledger.summary()["unresolved_turn_intent_count"], 1)

    def test_registered_model_refusal_preserves_first_failure_without_session(self):
        fixture, case, factory = self.registered_fixture(task_prompt="password=hunter2")
        prepare = transport.prepare_json_frame
        refusals = []
        def observe(*args, **kwargs):
            try:
                return prepare(*args, **kwargs)
            except OutboundRefused as refusal:
                refusals.append(refusal)
                raise
        with mock.patch.object(transport, "prepare_json_frame", side_effect=observe):
            with self.assertRaises(registered_fixture.runtime.native.OfflineHostError) as caught:
                factory.run()
        report = caught.exception.native_report
        self.assertIn("AmbiguousTurnStartError", report["error"])
        self.assertNotIn("session-boundary-invalid", report["error"])
        self.assertNotIn("hunter2", str(caught.exception) + report["error"] + json.dumps(report["receipt"]))
        self.assertTrue(report["receipt"]["errors"])
        self.assertIsNone(report["artifact"])
        attempt = fixture.attempt(case)
        self.assertEqual((attempt["outcome"], attempt["charge"]), ("unknown", attempt["amount"]))
        self.assertNotIn("turn/start", fixture.spawned[0].methods)
        self.assertIsNone(factory.token)
        cleanup_failure = factory.server.transport_failure
        self.assertIsInstance(cleanup_failure, BaseException)
        with self.assertRaises(transport.AmbiguousTurnStartError) as observed:
            factory.adapter.final_summary()
        self.assertIs(observed.exception.__cause__, refusals[0])
        self.assertIs(factory.server.transport_failure, cleanup_failure)

    def test_registered_model_task_preserves_complete_original_context_and_acceptance(self):
        fixture, case, factory = self.registered_fixture()
        original = case.receipt.request_bytes
        selected = json.loads(case.receipt.selected_node_bytes)
        task_bytes = factory.model_task_bytes()
        task = json.loads(task_bytes)
        self.assertEqual(task['task'], {key: selected[key] for key in
                                      ('prompt', 'wrappers', 'attachments', 'sources')})
        self.assertEqual(task['acceptance'], {
            'allowed_command': case.spec['command'], 'completion_marker': case.spec['expected_token'],
            'outputs': case.policy.report['outputs'],
            'expected_artifacts': selected['unit_estimate']['expected_artifacts'],
            'acceptance_checks': selected['unit_estimate']['acceptance_checks']})
        self.assertNotIn('execution', task)
        self.assertEqual(case.receipt.request_bytes, original)
        self.assertLessEqual(len(task_bytes), len(original))
        self.assertEqual(factory.model_task_binding(), {
            'projection_version': 1, 'original_request_sha256': hashlib.sha256(original).hexdigest(),
            'model_task_sha256': hashlib.sha256(task_bytes).hexdigest()})
        registered_fixture.assert_no_native_births(self, fixture)
        self.assertFalse(case.ledger.root.exists())

    def test_model_task_drift_and_serialized_binding_never_grant_authority(self):
        fixture, case, factory = self.registered_fixture()
        binding = factory.model_task_binding()
        factory._model_task += b' '
        with self.assertRaisesRegex(registered_fixture.runtime.native.OfflineHostError, 'model task changed'):
            factory.guard()
        fake = SimpleNamespace(model_task_bytes=b'Explain the function.', registered_task=binding)
        with self.assertRaises(registered_fixture.runtime.native.OfflineHostError):
            registered_fixture.runtime.require_factory(fake, case.host)
        registered_fixture.assert_no_native_births(self, fixture)
        self.assertFalse(case.ledger.root.exists())

    def test_original_useful_host_keeps_strict_path_screening_under_long_temporary_parent(self):
        with tempfile.TemporaryDirectory(dir='/tmp') as temporary:
            parent = Path(temporary) / 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
            parent.mkdir(mode=0o700)
            old_path = str(parent / 'worker')
            payload = {'id': 1, 'method': 'thread/start',
                       'params': {'cwd': old_path, 'runtimeWorkspaceRoots': [old_path]}}
            server, read_fd, method = self.pipe_writer(payload)
            with self.assertRaises(OutboundRefused):
                self.write(server, payload, method)
            self.assert_empty(read_fd)
            fixture = registered_fixture.FactoryTests('test_original_rpc_useful_capture_validation_and_no_redispatch')
            fixture._outcome = self._outcome
            self.addCleanup(registered_fixture.cleanup_helper, self, fixture)
            with mock.patch.object(tempfile, 'tempdir', str(parent)):
                fixture.setUp()
                self.assertEqual(fixture.repositories.root.parent, Path('/tmp').resolve())
                fixture.test_original_rpc_useful_capture_validation_and_no_redispatch()


if __name__ == "__main__":
    unittest.main()
