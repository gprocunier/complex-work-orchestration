from __future__ import annotations

import contextlib
import json
import os
import sys
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import browser_request  # noqa: E402
import dispatch_work  # noqa: E402
import generate_manual_dispatch_prompt as manual  # noqa: E402
from cwo_core import outbound_screen as screening  # noqa: E402
from cwo_core.prepared_outbound import PreparedSource  # noqa: E402
from tests.local_invocation_fixtures import isolate_local_invocation_ledgers  # noqa: E402
from tests.test_outbound_screen import _OutboundHelpers, packet_with  # noqa: E402


def setUpModule() -> None:
    enabled = patch.object(dispatch_work, "LOCAL_INVOCATION_AVAILABLE", True)
    enabled.start()
    unittest.addModuleCleanup(enabled.stop)
    isolate_local_invocation_ledgers()


class OutboundFormatTests(_OutboundHelpers, unittest.TestCase):
    def test_unencodable_text_has_a_fixed_refusal_on_each_surface(self) -> None:
        for surface, media in (("manual export", "text/plain"), ("ChatGPT browser Send", "text/plain"),
                               ("local HTTP request", "application/json")):
            with self.subTest(surface=surface):
                with self.assertRaises(screening.OutboundRefused) as raised:
                    screening.require_clean("unencodable \ud800 text", surface=surface, content_type=media)
                self.assertNotIn("unencodable", str(raised.exception))

    def test_unsupported_media_types_and_charsets_refuse_on_each_surface(self) -> None:
        for surface in ("manual export", "ChatGPT browser Send", "local HTTP request"):
            for media in ("application/pdf", "multipart/form-data; boundary=private-boundary", "text/html",
                          "text/plain; charset=utf-16", "application/json; charset=iso-8859-1",
                          "application/json; charset=utf-8; charset=utf-16"):
                effect = Mock()
                with self.subTest(surface=surface):
                    with self.assertRaises(screening.OutboundRefused) as raised:
                        screened = screening.require_clean("{}", surface=surface, content_type=media)
                        effect(screened.data)
                    effect.assert_not_called()
                    self.assertNotIn(media, str(raised.exception))

    def test_surface_contracts_and_utf8_positive_controls(self) -> None:
        supported = (("manual export", "text/plain"), ("manual export", "application/json"),
                     ("ChatGPT browser Send", "text/plain"), ("local HTTP request", "application/json"))
        for surface, media in supported:
            with self.subTest(surface=surface, media=media):
                screened = screening.require_clean('{}', surface=surface, content_type=media + '; charset="UTF-8"')
                self.assertEqual(screened.data, b"{}")
        for surface, media in (("ChatGPT browser Send", "application/json"), ("local HTTP request", "text/plain")):
            with self.subTest(surface=surface), self.assertRaises(screening.OutboundRefused):
                screening.require_clean("{}", surface=surface, content_type=media)

    def test_http_descriptors_refuse_even_with_an_empty_body(self) -> None:
        bad_headers = ([('Content-Type', 'text/plain')], [('Content-Type', 'application/json; charset=utf-16')],
                       [('Content-Type', 'application/json'), ('content-type', 'application/json')],
                       [('Content-Encoding', 'gzip')], [('Transfer-Encoding', 'chunked')])
        for headers in bad_headers:
            effect = Mock()
            with self.subTest(header_names=[name for name, _ in headers]):
                with self.assertRaises(screening.OutboundRefused):
                    screened = screening.screen_request("GET", "http://127.0.0.1:8000/v1/models", headers, b"",
                                                       surface="local HTTP model preflight")
                    effect(screened)
                effect.assert_not_called()
        screened = screening.screen_request("POST", "http://127.0.0.1:8000/v1/chat", {
            "Content-Type": "application/json; charset=utf-8", "Content-Encoding": "identity",
            "Authorization": "Bearer configured-credential",
        }, b"{}", surface="local HTTP request")
        self.assertEqual(screened.body.data, b"{}")

    def test_nontext_manual_input_refuses_before_output(self) -> None:
        with patch.object(manual, "write_export") as write:
            with self.assertRaises(screening.OutboundRefused):
                manual.export_screened(b"plain bytes", as_json=False)
        write.assert_not_called()

    def test_attachment_declarations_refuse_before_render_or_http_effects(self) -> None:
        for name in ("attachments", "files", "uploads"):
            with self.subTest(field=name), self.assertRaises(screening.OutboundRefused):
                manual.render_packet_prompt({**packet_with("Review ordinary notes."), name: []})
        env = {"CWO_OPENSHIFT_AI_VLLM_BASE_URL": "http://127.0.0.1:8000", "CWO_OPENSHIFT_AI_VLLM_MODEL": "test-model"}
        with patch.dict(os.environ, env):
            envelope, route, args = self._envelope("Documentation review for internal example notes.")
            envelope["attachments"] = [{"path": "notes.txt"}]
            with patch.object(dispatch_work, "pinned_local_endpoint_address", return_value="127.0.0.1") as resolve, \
                    patch.object(dispatch_work.request, "build_opener", return_value=self.Opener()) as opener:
                with self.assertRaises(screening.OutboundRefused):
                    dispatch_work.execute_local_envelope(envelope, route["selected_executor"], args)
            resolve.assert_not_called()
            opener.assert_not_called()


@contextlib.contextmanager
def detector_views():
    """Observe the actual detector inputs, independently of require_clean's return token."""
    seen = []
    original = screening._Detector.scan

    def observe(detector, view):
        seen.append((view.name, view.text))
        yield from original(detector, view)

    with patch.object(screening._Detector, "scan", observe):
        yield seen


class RendererScanCoverageTests(_OutboundHelpers, unittest.TestCase):
    FIELDS = {"title": "Title café", "profile": "Profile étude", "metadata": "Metadata façade",
              "snippet": "Snippet crème", "final_body": "Body résumé"}

    def assert_both_views(self, seen, final, fields) -> None:
        self.assertIn(("raw", final), seen, "the complete final serialized bytes reach the detector")
        decoded = [text for name, text in seen if name != "raw"]
        for value in fields:
            self.assertTrue(any(value in text for text in decoded), "a disclosed field missed decoded scanning")

    def test_manual_plain_and_json_disclosed_fields_reach_both_views(self) -> None:
        for as_json in (False, True):
            text = json.dumps(self.FIELDS) if as_json else "\n".join(self.FIELDS.values())
            # Plain text needs no decoding; the normalized view is its semantic reading.
            with self.subTest(as_json=as_json), detector_views() as seen, patch.object(manual, "write_export") as write:
                manual.export_screened(text, as_json=as_json)
            final = text + "\n"
            self.assertIn(("raw", final), seen)
            if as_json:
                self.assert_both_views(seen, final, self.FIELDS.values())
            else:
                self.assert_both_views(seen, final, ("Title cafe", "Profile etude", "Metadata facade", "Snippet creme", "Body resume"))
            write.assert_called_once()

    def test_desktop_preparation_screens_disclosed_fields_in_final_request(self) -> None:
        prompt = json.dumps(self.FIELDS)
        source = {"prompt": prompt}
        capture = PreparedSource.capture(source)
        submitted = browser_request.bound_request(prompt, "0" * 32)
        with detector_views() as seen:
            prepared = browser_request.prepare_browser_submission(submitted, capture=capture, source=source)
        self.assertEqual(prepared.payload.text(), submitted)
        self.assert_both_views(seen, submitted, self.FIELDS.values())

    def test_every_http_body_field_and_descriptor_reaches_the_detector(self) -> None:
        opener = self.Opener()
        with detector_views() as seen:
            self._execute(json.dumps(self.FIELDS), opener)
        self.assertEqual(len(opener.bodies), 1)
        final = opener.bodies[0].decode("utf-8")
        self.assert_both_views(seen, final, self.FIELDS.values())
        body = json.loads(final)
        for value in ("model", body["model"], "messages", "system", "user", "temperature"):
            self.assertTrue(any(name != "raw" and value in text for name, text in seen))
        self.assertTrue(any(name == "raw" and "POST http://127.0.0.1:8000" in text
                            and "content-type: application/json" in text and "x-cwo-dispatch-id:" in text
                            for name, text in seen))

    def test_incomplete_scans_refuse_at_each_consumer(self) -> None:
        normal_rules = screening._rules()
        rules = {**normal_rules, "limits": {"max_input_bytes": 16, "max_json_depth": 3}}
        with patch.object(screening, "_rules", return_value=rules), patch.object(manual, "write_export") as write:
            with self.assertRaises(screening.OutboundRefused):
                manual.export_screened("Long review document.", as_json=False)
            opener = self.Opener()
            with self.assertRaises(screening.OutboundRefused):
                self._execute("Documentation review for internal example notes.", opener)
            self.assertEqual(len(opener.bodies), 0)
        self.assertEqual(write.call_count, 0)

        source = {"prompt": "Review this plan."}
        capture = PreparedSource.capture(source)
        request = browser_request.bound_request(source["prompt"], "0" * 32)
        with patch.object(screening, "_rules", return_value=rules), self.assertRaises(screening.OutboundRefused):
            browser_request.prepare_browser_submission(request, capture=capture, source=source)
        prepared = browser_request.prepare_browser_submission(request, capture=capture, source=source)
        self.assertEqual(prepared.payload.text(), request)
