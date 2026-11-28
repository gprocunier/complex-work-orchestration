"""Compact synthetic disclosure fixtures at the supported offline consumers."""
from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tests import test_outbound_screen as helpers
from tests import test_prepared_outbound as preparation_tests
from tests.local_invocation_fixtures import isolate_local_invocation_ledgers

import browser_request
import dispatch_work
import generate_manual_dispatch_prompt as manual
from cwo_core import outbound_screen as screening
from cwo_core.packets import packet_payload_hash, validate_contractor_packet

FIXTURE = Path(__file__).parent / "fixtures/outbound_screening/disclosure-surfaces.json"


def fixture():
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def digest(value):
    return hashlib.sha256(value.encode() if isinstance(value, str) else value).hexdigest()


def packet_for(row, *, control=False):
    """Update the disclosed source and every affected production packet binding."""
    packet = helpers.packet_with("Review the public retry plan.")
    text = row["control"] if control else row["text"]
    slot = row["slot"]
    if slot == "title":
        packet["bead_summary"]["title"] = text
    elif slot == "profile":
        packet["expert_profile"]["content"] = text
    elif slot == "boundary_description":
        packet["boundary_description"] = text
    elif slot == "included_artifact_path":
        packet["included_artifacts"][0]["path"] = text
    elif slot == "snippet":
        packet["selected_snippets"][0]["content"] = text
    elif slot == "attachment":
        if control:
            packet["selected_snippets"][0]["content"] = text
        else:
            packet["attachments"] = [{"path": "notes.txt", "content": text}]
    profile = packet["expert_profile"]
    profile["sha256"] = digest(profile["content"])
    for snippet in packet["selected_snippets"]:
        snippet["sha256"] = digest(snippet["content"])
        snippet["line_count"] = len(snippet["content"].splitlines())
    for artifact in packet["included_artifacts"]:
        if artifact["type"] == "assignment_summary":
            artifact["sha256"] = digest(json.dumps(packet["bead_summary"], sort_keys=True))
        elif artifact["type"] == "expert_profile":
            artifact.update(path=profile["path"], sha256=profile["sha256"])
        else:
            snippet = next(s for s in packet["selected_snippets"] if s["path"] == artifact["path"])
            artifact.update({key: snippet[key] for key in ("sha256", "line_count", "truncated")})
    packet["packet_sha256"] = packet_payload_hash(packet)
    return packet


def rendered(packet, row, *, control=False):
    text = manual.render_packet_prompt(packet)
    if row["slot"] == "final_body":
        text += "\n" + (row["control"] if control else row["text"])
    return text


def packet_errors(row, control):
    if control:
        return []
    if "packet_residual_path" in row:
        return ["packet contains residual private or secret-like context at: " + row["packet_residual_path"]]
    if row["slot"] == "attachment":
        return ["packet contains forbidden boundary fields: attachments"]
    return []


@contextlib.contextmanager
def input_limit(row, control):
    rules = screening._rules()
    limit = rules["limits"]["max_input_bytes"] if control else row.get("max_input_bytes", rules["limits"]["max_input_bytes"])
    with patch.object(screening, "_rules", return_value={**rules, "limits": {**rules["limits"], "max_input_bytes": limit}}):
        yield


def setUpModule():
    isolate_local_invocation_ledgers()
    enabled = patch.object(dispatch_work, "LOCAL_INVOCATION_AVAILABLE", True)
    enabled.start()
    unittest.addModuleCleanup(enabled.stop)


class DisclosureSurfaceTests(helpers._OutboundHelpers, unittest.TestCase):
    def assert_private_diagnostics(self, row, *messages):
        private = row["sensitive"] + [fixture()["preparation"]["value"]]
        if row["sensitive"]:
            private.append(row["text"])
        spans = private + [s[:12] for s in private if len(s) >= 12]
        self.assertFalse(any(s in message for s in spans for message in messages), "private fixture content in diagnostics")

    def assert_packet_refusal(self, row, failure, errors):
        self.assert_private_diagnostics(row, str(failure))
        self.assertTrue(str(failure) == "invalid contractor packet:\n- " + "\n- ".join(errors),
                        "consumer did not refuse at packet validation")

    def test_manual_plain_and_json(self):
        for row in fixture()["cases"]:
            for as_json in (False, True):
                for control in (False, True):
                    with self.subTest(row=row["id"], surface="manual-json" if as_json else "manual-plain", slot=row["slot"]):
                        self._manual_case(row, as_json, control)

    def _manual_case(self, row, as_json, control):
        packet = packet_for(row, control=control)
        # Exercise the export seam independently, including the JSON packet and rendered prompt.
        self.assertTrue(validate_contractor_packet(packet) == packet_errors(row, control),
                        "unexpected validation result for bound fixture")
        output, stderr = io.StringIO(), io.StringIO()
        failure, writes = None, []
        real_write = manual.write_export

        def write(token, **kwargs):
            writes.append(token.data)
            real_write(token, **kwargs)

        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(stderr), input_limit(row, control), \
                patch.object(manual, "write_export", side_effect=write):
            try:
                prompt = rendered(packet, row, control=control)
                text = json.dumps({"packet": packet, "prompt": prompt}, indent=2, sort_keys=True) if as_json else prompt
                token = manual.screen_export(text, as_json=as_json)
                manual.write_export(token)
            except screening.OutboundRefused as exc:
                failure = exc
        self.assert_private_diagnostics(row, stderr.getvalue(), str(failure))
        if control:
            self.assertTrue(failure is None, "clean manual control refused")
            self.assertEqual(len(writes), 1, "clean control must reach the real writer")
            self.assertEqual(digest(output.getvalue()), digest(text + "\n"), "manual output bytes changed")
            self.assertEqual(digest(writes[0]), digest(output.getvalue()), "writer received different bytes")
        else:
            self.assertTrue(isinstance(failure, screening.OutboundRefused), "sensitive or unsupported manual disclosure passed")
            self.assertEqual(len(writes), 0, "refusal reached the writer")
            self.assertEqual(len(output.getvalue()), 0, "refusal emitted output")
            self.assert_private_diagnostics(row, output.getvalue())

    def test_manual_refuses_residual_profile_before_rendering(self):
        for row in fixture()["cases"]:
            if "packet_residual_path" in row:
                for as_json in (False, True):
                    with self.subTest(row=row["id"], surface="manual-json" if as_json else "manual-plain"):
                        self._assert_manual_validation_refusal(row, as_json)

    def _assert_manual_validation_refusal(self, row, as_json):
        packet = packet_for(row)
        output, stderr = io.StringIO(), io.StringIO()
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "packet.json"
            path.write_text(json.dumps(packet), encoding="utf-8")
            argv = ["generate_manual_dispatch_prompt.py", "--packet", str(path)]
            if as_json:
                argv.append("--json")
            with patch.object(sys, "argv", argv), helpers.with_provenance(packet), \
                    contextlib.redirect_stdout(output), contextlib.redirect_stderr(stderr), \
                    patch.object(manual, "render_packet_prompt", wraps=manual.render_packet_prompt) as render, \
                    patch.object(manual, "write_export", wraps=manual.write_export) as write:
                with self.assertRaises(SystemExit) as caught:
                    manual.main()
            self.assert_packet_refusal(row, caught.exception, packet_errors(row, False))
            self.assertEqual((render.call_count, write.call_count, len(output.getvalue())), (0, 0, 0))
            self.assert_private_diagnostics(row, stderr.getvalue())

    def test_desktop_browser_packet_is_screened_before_export(self):
        request_id = "0" * 32
        for row in fixture()["cases"]:
            for control in (False, True):
                with self.subTest(row=row["id"], control=control):
                    packet = packet_for(row, control=control)
                    self._browser_case(row, packet, request_id, control=control, errors=packet_errors(row, control))

    def test_desktop_browser_screens_rendered_profile_witnesses(self):
        for row in fixture()["cases"]:
            if "packet_residual_path" in row:
                with self.subTest(row=row["id"], surface="browser-outbound"):
                    # Inject the original rendered witness after a clean packet passes validation.
                    clean_packet = packet_for(row, control=True)
                    self._browser_case(row, clean_packet, "0" * 32, control=False, errors=[], rendered_packet=packet_for(row))

    def _browser_case(self, row, packet, request_id, *, control, errors, rendered_packet=None):
        from tests.dispatch_workload_fixture import write_workload

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "packet.json"
            path.write_text(json.dumps(packet), encoding="utf-8")
            with input_limit(row, control), helpers.with_provenance(packet), patch.object(
                browser_request, "render_packet_prompt", side_effect=lambda p: rendered(rendered_packet or p, row, control=control)
            ) as render:
                if control:
                    prompt = rendered(packet, row, control=True)
                    workload = write_workload(path.with_name("workload.json"), packet, browser=True, prompt=prompt)
                    request = browser_request.prepare_browser_packet_request(path, request_id=request_id,
                                                                             workload_path=workload)
                    expected = browser_request.bound_request(prompt, request_id)
                    self.assertEqual(digest(request.require_unchanged()), digest(expected))
                else:
                    with self.assertRaises(SystemExit) as caught:
                        browser_request.prepare_browser_packet_request(path, request_id=request_id)
                    if errors:
                        self.assert_packet_refusal(row, caught.exception, errors)
                    else:
                        self.assert_private_diagnostics(row, str(caught.exception))
                        self.assertTrue(isinstance(caught.exception, screening.OutboundRefused), "browser outbound screen did not refuse")
                self.assertEqual(render.call_count, 0 if errors else 1)

    def test_local_user_message_from_rendered_source_fields(self):
        # HTTP has no contractor-packet consumer: render disclosed fields into its supported task text.
        for row in fixture()["cases"]:
            for control in (False, True):
                with self.subTest(row=row["id"], surface="local-http", slot=row["slot"]):
                    self._local_case(row, control)

    def _local_case(self, row, control, *, metadata=None):
        packet = packet_for(row, control=control or metadata is not None)
        packet.pop("attachments", None)  # The HTTP declaration belongs on the envelope, not inside task text.
        packet["packet_sha256"] = packet_payload_hash(packet)
        task = manual.render_packet_prompt(packet)
        output, stderr, opener = io.StringIO(), io.StringIO(), self.Opener()
        requests = []
        real_open = opener.open

        def open_request(req, **kwargs):
            requests.append(req)
            return real_open(req, **kwargs)
        env = {"CWO_OPENSHIFT_AI_VLLM_BASE_URL": "http://127.0.0.1:8000", "CWO_OPENSHIFT_AI_VLLM_MODEL": "test-model"}
        if metadata == "model":
            env["CWO_OPENSHIFT_AI_VLLM_MODEL"] = row["control"] if control else row["text"]
        failure, scanned = None, []
        real_screen = dispatch_work.screen_request

        def screen(*args, **kwargs):
            token = real_screen(*args, **kwargs)
            scanned.append(token.body.data)
            return token

        real_transport = dispatch_work.local_transport

        def transport(*args, **kwargs):
            value = real_transport(*args, **kwargs)
            if metadata == "request_options":
                text = row["control"] if control else row["text"]
                value = {**value, "request_options": {**value.get("request_options", {}), "stop": [text]}}
            return value

        with patch.dict(os.environ, env), contextlib.redirect_stdout(output), contextlib.redirect_stderr(stderr), \
                input_limit(row, control), patch.object(dispatch_work, "screen_request", side_effect=screen), \
                patch.object(dispatch_work, "local_transport", side_effect=transport), \
                patch.object(opener, "open", new=open_request), \
                patch.object(dispatch_work, "pinned_local_endpoint_address", return_value="127.0.0.1") as resolve, \
                patch.object(dispatch_work.request, "build_opener", return_value=opener) as build:
            try:
                envelope, route, args = self._envelope(task)
                if row["slot"] == "final_body":
                    # Exercise the already rendered HTTP message, then bind it as normal input to execution.
                    envelope["messages"][1]["content"] += "\n" + (row["control"] if control else row["text"])
                    envelope["messages_sha256"] = dispatch_work._canonical_json_hash(envelope["messages"])
                if row["slot"] == "attachment" and not control:
                    envelope["attachments"] = [{"path": "notes.txt", "content": row["text"]}]
                if metadata == "header":
                    envelope["dispatch_id"] = row["control"] if control else row["text"]
                dispatch_work.execute_local_envelope(envelope, route["selected_executor"], args)
            except SystemExit as exc:
                failure = exc
        self.assert_private_diagnostics(row, output.getvalue(), stderr.getvalue(), str(failure))
        if control:
            self.assertTrue(failure is None, "clean HTTP control refused")
            self.assertEqual((len(opener.bodies), resolve.call_count, build.call_count), (1, 1, 1), "clean control must send once")
            self.assertEqual(digest(opener.bodies[0]), digest(scanned[-1]), "HTTP sent different screened bytes")
            if metadata:
                body = json.loads(opener.bodies[0])
                value = {"model": body["model"], "request_options": body.get("stop", [""])[0],
                         "header": dict(requests[0].header_items()).get("X-cwo-dispatch-id", "")}[metadata]
                self.assertEqual(digest(value), digest(row["control"]), "HTTP metadata did not reach transport")
        else:
            self.assertTrue(isinstance(failure, screening.OutboundRefused), "HTTP disclosure missed the final screen")
            self.assertEqual((len(opener.bodies), resolve.call_count, build.call_count), (0, 0, 0), "refusal reached HTTP effects")

    def test_http_model_options_and_dispatch_header(self):
        row = next(r for r in fixture()["cases"] if r["id"] == "ds04")
        for slot in ("model", "request_options", "header"):
            for control in (False, True):
                with self.subTest(row=row["id"], surface="local-http", slot=slot):
                    self._local_case(row, control, metadata=slot)

    def test_fixture_scanner_offsets_idempotence_and_limits(self):
        for row in fixture()["cases"]:
            with self.subTest(row=row["id"], surface="scanner", slot=row["slot"]):
                if "max_input_bytes" in row:
                    with input_limit(row, False), self.assertRaises(screening.OutboundRefused):
                        screening.require_clean(row["text"] * 2, surface="test")
                    continue
                first = screening.screen_outbound(row["text"], surface="test")
                second = screening.screen_outbound(row["text"], surface="test")
                self.assertTrue(bool(first.findings), "fixture has no scanner witness")
                self.assert_scanner_spans(row, first.findings)
                self.assertEqual(first.findings, second.findings, "scanner results changed on identical input")
                self.assertFalse(bool(screening.screen_outbound(row["control"], surface="test").findings), "clean fixture control refused")
                if "offset_span" in row:
                    start = row["text"].index(row["offset_span"])
                    end = start + len(row["offset_span"])
                    self.assertTrue(any(f.start == start and f.end == end for f in first.findings), "Unicode raw offsets changed")

    def assert_scanner_spans(self, row, findings):
        for span in row["sensitive"]:
            occurrences = helpers.raw_occurrences(row["text"], span)
            covered = any(f.fingerprint == digest(span) for f in findings)
            if occurrences:
                covered = all(any(f.start < end and f.end > start for f in findings) for start, end in occurrences)
            self.assertTrue(covered, "expected fixture span lacks a mapped finding or decoded fingerprint")


class DisclosureDiagnosticsTests(unittest.TestCase):
    def test_deliberate_preparation_failure_withholds_private_values(self):
        private = fixture()["preparation"]["value"]
        report = io.StringIO()
        case = preparation_tests.PreparedTokenTests("test_invalid_utf8_candidate_refuses_without_repeating_content")
        with patch.object(screening.ScreenedPayload, "require_unchanged", side_effect=screening.OutboundRefused(private)):
            result = unittest.TextTestRunner(stream=report).run(case)
        self.assertEqual(len(result.failures), 1, "the deliberate diagnostic failure must execute")
        self.assertEqual(len(result.errors), 0, "the diagnostic witness must fail an assertion")
        self.assertFalse(private in report.getvalue(), "preparation diagnostics exposed fixture content")

    def test_deliberate_effect_failure_reports_only_a_counter(self):
        private, report = fixture()["preparation"]["value"], io.StringIO()

        def effect(*args, **kwargs):
            sys.stdout.buffer.write(private.encode())
            raise screening.OutboundRefused("forced refusal")

        case = preparation_tests.PreparedTokenTests("test_file_changed_by_stdout_flush_refuses_before_any_bytes_are_written")
        with patch.object(manual, "write_export", side_effect=effect):
            result = unittest.TextTestRunner(stream=report).run(case)
        self.assertEqual(len(result.failures), 1, "the deliberate effect failure must execute")
        self.assertEqual(len(result.errors), 0, "the effect witness must fail an assertion")
        self.assertTrue("1 != 0" in report.getvalue(), "effect diagnostics must report the numeric counter")
        self.assertFalse(private in report.getvalue(), "effect diagnostics exposed fixture content")
