"""Frozen outbound content at the actual offline consumers."""
from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from dataclasses import replace
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import dispatch_work
import generate_manual_dispatch_prompt as manual
import chatgpt_browser_review as browser
from cwo_core import local_invocation
from cwo_core.outbound_screen import OutboundRefused, require_clean, screen_outbound, screen_request
from cwo_core.prepared_outbound import PreparedSource
from tests import test_outbound_screen as helpers


def setUpModule():
    from tests.local_invocation_fixtures import isolate_local_invocation_ledgers
    isolate_local_invocation_ledgers()
    enabled = patch.object(dispatch_work, "LOCAL_INVOCATION_AVAILABLE", True)
    enabled.start()
    unittest.addModuleCleanup(enabled.stop)


class PreparedTokenTests(unittest.TestCase):
    def test_source_capture_freezes_file_pairs_and_original_contents(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "task.txt"
            original = b"Review the plan."
            path.write_bytes(original)
            raw = bytearray(original)
            pair = [str(path), raw]
            files = [pair]
            source = {"task": "Review the plan."}
            capture = PreparedSource.capture(source, files)
            digest = capture.sha256
            raw[:] = b"VelvetSunset42!"
            pair[:] = [str(path.with_name("other.txt")), raw]
            files.clear()
            self.assertEqual(capture.sha256, digest)
            self.assertEqual(capture.files, ((str(path), original),))
            self.assertIs(type(capture.files[0]), tuple)
            self.assertIs(type(capture.files[0][0]), str)
            self.assertIs(type(capture.files[0][1]), bytes)
            capture.require_unchanged(source)
            path.write_bytes(raw)
            with self.assertRaises(OutboundRefused) as caught:
                capture.require_unchanged(source)
            self.assertNotIn("VelvetSunset42!", str(caught.exception))

    def test_invalid_utf8_candidate_refuses_without_repeating_content(self):
        token = require_clean("Review the plan.", surface="manual export")
        with self.assertRaises(OutboundRefused) as caught:
            token.require_unchanged("VelvetSunset42!\ud800")
        self.assertNotIn("VelvetSunset42!", str(caught.exception))

    def test_mutable_and_unsupported_candidates_refuse(self):
        token = require_clean("Review the plan.", surface="manual export")
        for candidate in (bytearray(token.data), memoryview(token.data), [token.data]):
            with self.subTest(kind=type(candidate).__name__), self.assertRaises(OutboundRefused):
                token.require_unchanged(candidate)

    def test_supported_candidates_return_the_captured_immutable_bytes(self):
        token = require_clean("Review the café plan.", surface="manual export")
        for candidate in (token.text(), bytes(bytearray(token.data))):
            with self.subTest(kind=type(candidate).__name__):
                returned = token.require_unchanged(candidate)
                self.assertIs(returned, token.data)
                self.assertIs(type(returned), bytes)

    def test_file_changed_by_stdout_flush_refuses_before_any_bytes_are_written(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "task.txt"
            path.write_bytes(b"Review the plan.")
            source = {"task": "Review the plan.", "json": False}
            token = manual.screen_export("Review the plan.", as_json=False)
            prepared = PreparedSource.capture(source, ((str(path), path.read_bytes()),)).bind(source, token)
            stream = Mock()
            stream.flush.side_effect = lambda: path.write_bytes(b"VelvetSunset42!")
            with patch.object(sys, "stdout", stream), self.assertRaises(OutboundRefused) as caught:
                manual.write_export(token, prepared=prepared, source=source)
            stream.buffer.write.assert_not_called()
            self.assertNotIn("VelvetSunset42!", str(caught.exception))

    def test_request_validates_its_descriptor_token_before_transport(self):
        token = screen_request("POST", "http://127.0.0.1:8000/v1/chat", {"Content-Type": "application/json"}, b"{}", surface="test")
        altered = replace(token, descriptor=replace(token.descriptor, sha256="0" * 64))
        with self.assertRaises(OutboundRefused):
            altered.require_unchanged("POST", "http://127.0.0.1:8000/v1/chat", {"Content-Type": "application/json"}, b"{}")

    def test_rerender_after_screening_refuses_and_private_capture_has_no_content_repr(self):
        source = {"task": "Review the plan.", "json": False}
        token = manual.screen_export("Review the plan.", as_json=False)
        capture = PreparedSource.capture(source, (("private-input", b"VelvetSunset42!"),))
        self.assertNotIn("VelvetSunset42!", repr(capture))
        self.assertNotIn("private-input", repr(capture))
        capture = PreparedSource.capture(source)
        prepared = capture.bind(source, token)
        stream = Mock()
        rerendered = manual.screen_export("Review a different plan.", as_json=False)
        with patch.object(sys, "stdout", stream), self.assertRaises(OutboundRefused):
            manual.write_export(rerendered, prepared=prepared, source=source)
        self.assertEqual(stream.mock_calls, [])

    def test_findings_cannot_be_used_as_an_export_token(self):
        token = screen_outbound("password=VelvetSunset42!", surface="manual export")
        self.assertTrue(token.findings)
        with self.assertRaises(OutboundRefused) as caught:
            token.require_unchanged(token.data)
        self.assertNotIn("VelvetSunset42!", str(caught.exception))

    def test_token_checks_its_own_data_as_well_as_the_candidate(self):
        token = require_clean("Review the plan.", surface="manual export")
        changed = replace(token, data=b"different text")
        with self.assertRaises(OutboundRefused):
            changed.require_unchanged(token.data)

    def test_writer_refuses_findings_and_tampered_tokens_before_output(self):
        clean = require_clean("Review the plan.", surface="manual export")
        for token in (replace(clean, sha256="0" * 64), replace(clean, data=b"other text"),
                      screen_outbound("password=VelvetSunset42!", surface="manual export")):
            stream = Mock()
            with patch.object(sys, "stdout", stream), self.assertRaises(OutboundRefused) as caught:
                manual.write_export(token)
            self.assertEqual(stream.mock_calls, [])
            self.assertNotIn("VelvetSunset42!", str(caught.exception))


class PreparedManualTests(unittest.TestCase):
    def test_raw_manual_routes_keep_frozen_bytes_and_refuse_source_drift(self):
        for module in (manual, dispatch_work):
            for as_json in (False, True):
                for drift in (False, True):
                    with self.subTest(route=module.__name__, as_json=as_json, drift=drift), tempfile.TemporaryDirectory() as tmp:
                        path = Path(tmp) / "task.txt"
                        path.write_text("Architecture critic review for a public retry plan.", encoding="utf-8")
                        argv = [module.__name__, "--file", str(path), "--external-ok", "--share-boundary", "redacted-packet",
                                "--requested-role", "architecture-critic", "--allow-raw-manual-prompt", "--rehearsal",
                                "--waiver-reason", "offline export test", *(["--json"] if as_json else [])]
                        target = "screen_export" if module is dispatch_work else "require_clean"
                        original = getattr(module, target)
                        scanned = []

                        def screen(*args, **kwargs):
                            token = original(*args, **kwargs)
                            scanned.append(token.data)
                            if drift:
                                path.write_text("VelvetSunset42!", encoding="utf-8")
                            return token

                        output = io.StringIO()
                        with patch.object(sys, "argv", argv), contextlib.redirect_stdout(output), \
                                patch.object(module, target, side_effect=screen), contextlib.ExitStack() as stack:
                            if module is dispatch_work:
                                stack.enter_context(patch.object(module, "enforce_contracting_quota", return_value=helpers.QUOTA_INFO))
                            if drift:
                                with self.assertRaises(OutboundRefused) as caught:
                                    module.main()
                                self.assertEqual(output.getvalue(), "")
                                self.assertNotIn("VelvetSunset42!", str(caught.exception))
                            else:
                                module.main()
                                self.assertEqual(output.getvalue().encode("utf-8"), scanned[-1])

    def test_packet_file_changed_after_screen_refuses_at_both_consumers(self):
        for module in (manual, dispatch_work):
            with self.subTest(route=module.__name__), tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp) / "packet.json"
                path.write_text(json.dumps(helpers.packet_with("Review the plan.")), encoding="utf-8")
                target = "screen_export" if module is dispatch_work else "require_clean"
                original = getattr(module, target)

                def change(*args, **kwargs):
                    token = original(*args, **kwargs)
                    path.write_text("VelvetSunset42!", encoding="utf-8")
                    return token

                output = io.StringIO()
                with patch.object(sys, "argv", [module.__name__, "--packet", str(path)]), \
                        contextlib.redirect_stdout(output), patch.object(module, target, side_effect=change), \
                        patch.object(module, "require_production_contractor_packet"), contextlib.ExitStack() as stack:
                    if module is dispatch_work:
                        stack.enter_context(patch.object(module, "enforce_contracting_quota", return_value=helpers.QUOTA_INFO))
                        host = stack.enter_context(patch.object(module, "record_prepared_dispatch"))
                        audit = stack.enter_context(patch.object(module, "record_audit_event"))
                    with self.assertRaises(OutboundRefused) as caught:
                        module.main()
                self.assertEqual(output.getvalue(), "")
                self.assertNotIn("VelvetSunset42!", str(caught.exception))
                if module is dispatch_work:
                    host.assert_not_called()
                    audit.assert_not_called()

    def test_renderer_cannot_add_fields_to_the_captured_packet(self):
        for module in (manual, dispatch_work):
            with self.subTest(route=module.__name__):
                original = module.render_packet_prompt

                def changed(packet):
                    packet["late"] = "VelvetSunset42!"
                    return original(packet)

                with patch.object(module, "render_packet_prompt", side_effect=changed):
                    out, failure, host, audit = self._packet_run(module)
                self.assertIsInstance(failure, OutboundRefused)
                self.assertEqual(out, "")
                self.assertNotIn("VelvetSunset42!", str(failure))
                if host is not None:
                    host.assert_not_called()
                    audit.assert_not_called()

    def _packet_run(self, module, mutation=None, *, as_json=False, callback="screen", packet=None):
        packet = packet or helpers.packet_with("Review the retry plan.")
        output = io.StringIO()
        real_screen = module.screen_export if module is dispatch_work else module.require_clean

        def screen(*args, **kwargs):
            result = real_screen(*args, **kwargs)
            if callback == "screen" and mutation:
                mutation(packet)
            return result

        def host(*args, **kwargs):
            if callback == "host" and mutation:
                mutation(packet)

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "packet.json"
            path.write_text(json.dumps(packet), encoding="utf-8")
            argv = [module.__name__, "--packet", str(path), *(["--json"] if as_json else [])]
            with contextlib.ExitStack() as stack:
                stack.enter_context(patch.object(sys, "argv", argv))
                stack.enter_context(contextlib.redirect_stdout(output))
                stack.enter_context(patch.object(module, "load_packet_file", return_value=packet))
                stack.enter_context(patch.object(module, "require_production_contractor_packet"))
                stack.enter_context(patch.object(module, "screen_export" if module is dispatch_work else "require_clean", side_effect=screen))
                host_spy = audit_spy = None
                if module is dispatch_work:
                    stack.enter_context(patch.object(module, "enforce_contracting_quota", return_value=helpers.QUOTA_INFO))
                    host_spy = stack.enter_context(patch.object(module, "record_prepared_dispatch", side_effect=host))
                    audit_spy = stack.enter_context(patch.object(module, "record_audit_event"))
                try:
                    module.main()
                    failure = None
                except OutboundRefused as exc:
                    failure = exc
        return output.getvalue(), failure, host_spy, audit_spy

    def test_added_source_field_refuses_at_both_manual_consumers(self):
        for module in (manual, dispatch_work):
            with self.subTest(route=module.__name__):
                out, failure, host, audit = self._packet_run(module, lambda p: p.update(late="VelvetSunset42!"))
                self.assertIsInstance(failure, OutboundRefused)
                self.assertEqual(out, "")
                self.assertNotIn("VelvetSunset42!", str(failure))
                if host is not None:
                    host.assert_not_called()
                    audit.assert_not_called()

    def test_source_mutation_by_host_callback_refuses_before_export(self):
        out, failure, _, _ = self._packet_run(dispatch_work, lambda p: p.update(late="VelvetSunset42!"), callback="host")
        self.assertIsInstance(failure, OutboundRefused)
        self.assertEqual(out, "")
        self.assertNotIn("VelvetSunset42!", str(failure))

    def test_task_file_drift_after_screen_refuses(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "task.txt"
            path.write_text("Review the retry plan.", encoding="utf-8")
            original = manual.require_clean

            def change(*args, **kwargs):
                result = original(*args, **kwargs)
                path.write_text("password=VelvetSunset42!", encoding="utf-8")
                return result

            output = io.StringIO()
            with patch.object(sys, "argv", ["manual", "--file", str(path)]), contextlib.redirect_stdout(output), \
                    patch.object(manual, "require_clean", side_effect=change):
                with self.assertRaises(OutboundRefused) as caught:
                    manual.main()
            self.assertEqual(output.getvalue(), "")
            self.assertNotIn("VelvetSunset42!", str(caught.exception))

    def test_exact_plain_and_json_export_digests_join_host_and_audit(self):
        for as_json in (False, True):
            with self.subTest(as_json=as_json):
                out, failure, host, audit = self._packet_run(dispatch_work, as_json=as_json)
                self.assertIsNone(failure)
                digest = hashlib.sha256(out.encode("utf-8")).hexdigest()
                metadata = host.call_args.kwargs["evaluation_metadata"]
                self.assertEqual(metadata["outbound_export_sha256"], digest)
                event = audit.call_args.args[0]
                for key in ("outbound_export_sha256", "outbound_source_sha256", "outbound_prepared_sha256", "outbound_screen_version"):
                    self.assertEqual(event[key], metadata[key])
                prompt = json.loads(out)["manual_prompt"] if as_json else out[:-1]
                self.assertEqual(host.call_args.kwargs["request_sha256"], hashlib.sha256(prompt.encode()).hexdigest())


class PreparedBrowserTests(unittest.TestCase):
    def test_source_changed_by_browser_callbacks_refuses_before_fill_or_send(self):
        for stage in ("origin", "button"):
            with self.subTest(stage=stage):
                runner = browser.PlaywrightChatGPTRunner({"selectors": {}})
                box, button, page = Mock(), Mock(), Mock()
                page.query_selector_all.return_value = [box]
                box.evaluate.return_value = True
                box.evaluate_handle.return_value.as_element.return_value = button

                def origin(handle):
                    if (stage == "origin" and handle is box) or (stage == "button" and handle is button):
                        runner.config["late"] = "VelvetSunset42!"
                    return "https://chatgpt.com"

                with patch.object(runner, "_frame_origin", side_effect=origin), self.assertRaises(OutboundRefused) as caught:
                    runner._submit_prompt(page, "Review the plan.", 1000, "0" * 32)
                button.evaluate.assert_not_called()
                if stage == "origin":
                    box.evaluate.assert_not_called()
                self.assertNotIn("VelvetSunset42!", str(caught.exception))

    def test_prompt_file_capture_is_private_and_checked_at_send(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "prompt.txt"
            path.write_text("Review the plan.", encoding="utf-8")
            args = helpers.Namespace(packet=None, prompt_file=str(path), allow_degraded_packet=True,
                allow_unlinked_packet=True, rehearsal=True, dispatch_id="dispatch-1", bead="cwo-1", epic=None,
                packet_sha256="0" * 64, share_boundary="redacted-packet")
            sources = []
            with patch.object(browser, "assert_repo_safe_path", side_effect=lambda p: p):
                prompt, metadata = browser.load_prompt_from_args(args, prepared_sources=sources)
            self.assertNotIn("PreparedSource", repr(metadata))
            runner = browser.PlaywrightChatGPTRunner({"selectors": {}})
            runner.prepared_sources = tuple(sources)
            page, box = Mock(), Mock()
            page.query_selector_all.return_value = [box]
            # Change during the frame-origin callback, after the initial screen.
            def change(handle):
                path.write_text("password=VelvetSunset42!", encoding="utf-8")
                return "https://chatgpt.com"
            with patch.object(runner, "_frame_origin", side_effect=change), self.assertRaises(OutboundRefused) as caught:
                runner._submit_prompt(page, prompt, 1000, "0" * 32)
            box.evaluate.assert_not_called()
            self.assertNotIn("VelvetSunset42!", str(caught.exception))

    @unittest.skipUnless(shutil.which("node"), "Optional Node harness")
    def test_send_executes_text_check_and_click_in_one_script(self):
        harness = r"""
const vm = require('node:vm'), fs = require('node:fs');
const scripts = JSON.parse(fs.readFileSync(0, 'utf8'));
const result = [];
for (const kind of ['textarea', 'input', 'editable']) for (const drift of ['same', 'text', 'detached', 'document', 'stamp', 'composer']) {
  let clicks = 0;
  class TextArea {} class Input {}
  const document = {}, window = {};
  const box = kind === 'textarea' ? new TextArea() : kind === 'input' ? new Input() : {};
  Object.assign(box, {ownerDocument: document, isConnected: true, value: 'Review café.', innerText: 'Review café.'});
  const button = {ownerDocument: document, isConnected: true, disabled: false, getAttribute: () => null, click: () => clicks++};
  const context = {window, document, HTMLTextAreaElement: TextArea, HTMLInputElement: Input, location: {href: 'https://chatgpt.com/'}};
  document.querySelectorAll = selector => selector === 'button' ? [button] : [];
  vm.runInNewContext('(' + scripts.stamp + ')', context)(box, scripts.id);
  vm.runInNewContext('(' + scripts.button + ')', context)(box, 'button');
  if (drift === 'text') box.value = box.innerText = 'password=VelvetSunset42!';
  if (drift === 'detached') box.isConnected = false;
  if (drift === 'document') button.ownerDocument = {};
  if (drift === 'stamp') window.__cwoSubmission = 'changed';
  if (drift === 'composer') window.__cwoComposer = {...box};
  const state = vm.runInNewContext('(' + scripts.send + ')', context)(button, scripts.id + '\nReview café.');
  const snapshot = vm.runInNewContext('(' + scripts.snapshot + ')', context)(['marker']);
  const second = vm.runInNewContext('(' + scripts.send + ')', context)(button, scripts.id + '\nReview café.');
  result.push({kind, drift, state, clicks, stamp: snapshot.stamp, second});
}
console.log(JSON.stringify(result));
"""
        result = subprocess.run(["node", "-e", harness], input=json.dumps({"stamp": browser._STAMP_SCRIPT,
            "button": browser._SEND_BUTTON_SCRIPT, "send": browser._SEND_SCRIPT,
            "snapshot": browser._SNAPSHOT_SCRIPT, "id": "0" * 32}),
            capture_output=True, text=True, check=True)
        for row in json.loads(result.stdout):
            with self.subTest(kind=row["kind"], drift=row["drift"]):
                self.assertEqual(row["clicks"], int(row["drift"] == "same"))
                self.assertEqual(row["state"], "pressed" if row["drift"] == "same" else "refused")
                self.assertEqual(row["second"], "refused")
                if row["drift"] == "same":
                    self.assertEqual(row["stamp"], "0" * 32, "capture must still see the submission stamp after Send")


class PreparedRouteTraceTests(unittest.TestCase):
    def test_helper_changes_identify_the_actual_consumers_for_review(self):
        from cwo_core import release_effect_routes as routes
        inventory = json.loads((ROOT / routes.INVENTORY).read_bytes())
        helper = "scripts/cwo_core/prepared_outbound.py"
        # Local HTTP and registered review dispatch call the helper through the
        # same consumer. Browser submission uses it; model-only confirmation,
        # raw network helpers and dormant sharing methods do not call it.
        expected = {"H1.1", "H1.2", "H2.1", "H4.1", "H4.2", "H4.3"}
        observed = {route["id"] for route in routes._routes(inventory) if helper in route["trace_files"]}
        self.assertEqual(observed, expected)


class PreparedLocalTests(helpers._OutboundHelpers, unittest.TestCase):
    def test_late_request_body_field_refuses_at_transport(self):
        original = dispatch_work.request.Request
        requests = []
        opener = self.Opener()

        def build(*args, **kwargs):
            req = original(*args, **kwargs)
            requests.append(req)
            return req

        def change(event):
            if event["event"] == "request":
                body = json.loads(requests[0].data)
                body["late"] = "VelvetSunset42!"
                requests[0].data = json.dumps(body).encode()

        with patch.object(local_invocation, "OBSERVERS", [change]), \
                self.assertRaisesRegex(SystemExit, "changed during observer") as caught:
            self._execute("Documentation review for internal example notes.", opener, build)
        self.assertEqual(opener.bodies, [])
        self.assertNotIn("VelvetSunset42!", str(caught.exception))

    def test_mutable_message_source_changed_during_screen_refuses_before_resolution(self):
        original = dispatch_work.screen_request
        opener = self.Opener()
        env = {"CWO_OPENSHIFT_AI_VLLM_BASE_URL": "http://127.0.0.1:8000", "CWO_OPENSHIFT_AI_VLLM_MODEL": "test-model"}
        with patch.dict(os.environ, env):
            envelope, route, args = self._envelope("Documentation review for internal example notes.")
            def change(*args, **kwargs):
                token = original(*args, **kwargs)
                envelope["messages"].append({"role": "user", "content": "VelvetSunset42!"})
                return token
            with patch.object(dispatch_work, "screen_request", side_effect=change), \
                    patch.object(dispatch_work, "pinned_local_endpoint_address") as resolve, \
                    patch.object(dispatch_work.request, "build_opener", return_value=opener), self.assertRaises(OutboundRefused):
                dispatch_work.execute_local_envelope(envelope, route["selected_executor"], args)
        resolve.assert_not_called()
        self.assertEqual(opener.bodies, [])

    def _observed(self, drift, *, files=()):
        env = {"CWO_OPENSHIFT_AI_VLLM_BASE_URL": "http://127.0.0.1:8000", "CWO_OPENSHIFT_AI_VLLM_MODEL": "test-model"}
        opener = self.Opener()
        with patch.dict(os.environ, env):
            envelope, route, args = self._envelope("Documentation review for internal example notes.")

            def observe(event):
                if event["event"] == "request":
                    drift(envelope)

            with patch.object(local_invocation, "OBSERVERS", [observe]), \
                    patch.object(dispatch_work.request, "build_opener", return_value=opener):
                try:
                    result = dispatch_work.execute_local_envelope(envelope, route["selected_executor"], args, source_files=files)
                    failure = None
                except OutboundRefused as exc:
                    result, failure = None, exc
        return result, failure, opener.bodies

    def test_late_envelope_field_refuses_after_request_observers(self):
        _, failure, bodies = self._observed(lambda e: e.update(late="VelvetSunset42!"))
        self.assertIsInstance(failure, OutboundRefused)
        self.assertEqual(bodies, [])
        self.assertNotIn("VelvetSunset42!", str(failure))

    def test_original_input_file_changed_by_request_observer_refuses(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "task.txt"
            raw = b"Documentation review for internal example notes."
            path.write_bytes(raw)
            _, failure, bodies = self._observed(lambda e: path.write_text("VelvetSunset42!", encoding="utf-8"),
                                               files=((str(path), raw),))
        self.assertIsInstance(failure, OutboundRefused)
        self.assertEqual(bodies, [])
        self.assertNotIn("VelvetSunset42!", str(failure))

    def test_unchanged_local_source_sends_exact_screened_body(self):
        bodies = []
        original = dispatch_work.screen_request

        def record(*args, **kwargs):
            screened = original(*args, **kwargs)
            if args[0] == "POST":
                bodies.append(screened.body.data)
            return screened

        with patch.object(dispatch_work, "screen_request", side_effect=record):
            result, failure, sent = self._observed(lambda e: None)
        self.assertIsNone(failure)
        self.assertTrue(result)
        self.assertEqual(sent, bodies)
        self.assertEqual(len(sent), 1)
