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
from argparse import Namespace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from tests import test_chatgpt_browser_review as browser_tests
from tests import test_outbound_screen as helpers
from tests import test_prepared_outbound as preparation_tests
from tests.local_invocation_fixtures import isolate_local_invocation_ledgers

import chatgpt_browser_review as browser
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


@contextlib.contextmanager
def input_limit(row, control):
    rules = screening._rules()
    limit = rules["limits"]["max_input_bytes"] if control else row.get("max_input_bytes", rules["limits"]["max_input_bytes"])
    with patch.object(screening, "_rules", return_value={**rules, "limits": {**rules["limits"], "max_input_bytes": limit}}):
        yield


def setUpModule():
    isolate_local_invocation_ledgers()
    for module, flag in ((dispatch_work, "LOCAL_INVOCATION_AVAILABLE"), (browser, "BROWSER_DISPATCH_AVAILABLE")):
        enabled = patch.object(module, flag, True)
        enabled.start()
        unittest.addModuleCleanup(enabled.stop)


class DisclosureSurfaceTests(helpers._OutboundHelpers, unittest.TestCase):
    def assert_private_diagnostics(self, row, *messages):
        private = row["sensitive"] + [fixture()["preparation"]["value"]]
        if row["sensitive"]:
            private.append(row["text"])
        spans = private + [s[:12] for s in private if len(s) >= 12]
        self.assertFalse(any(s in message for s in spans for message in messages), "private fixture content in diagnostics")

    def test_manual_plain_and_json(self):
        for row in fixture()["cases"]:
            for as_json in (False, True):
                for control in (False, True):
                    with self.subTest(row=row["id"], surface="manual-json" if as_json else "manual-plain", slot=row["slot"]):
                        self._manual_case(row, as_json, control)

    def _manual_case(self, row, as_json, control):
        packet = packet_for(row, control=control)
        errors = validate_contractor_packet(packet)
        expected = ["packet contains forbidden boundary fields: attachments"] if row["slot"] == "attachment" and not control else []
        self.assertTrue(errors == expected, "fixture must pass production bindings or refuse the unsupported declaration")
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

    def test_browser_packet_loader_through_fake_send(self):
        for row in fixture()["cases"]:
            for control in (False, True):
                with self.subTest(row=row["id"], surface="browser", slot=row["slot"]):
                    self._browser_case(row, control)

    def _browser_case(self, row, control):
        packet = packet_for(row, control=control)
        output, stderr, sent, filled = io.StringIO(), io.StringIO(), [], []
        failure, outcome = None, None
        with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stdout(output), contextlib.redirect_stderr(stderr), input_limit(row, control):
            path = Path(tmp) / "packet.json"
            path.write_text(json.dumps(packet), encoding="utf-8")
            args = Namespace(packet=str(path), prompt_file=None, allow_degraded_packet=False, allow_unlinked_packet=False)
            sources = []
            try:
                with helpers.with_provenance(packet), patch.object(browser, "render_packet_prompt", side_effect=lambda p: rendered(p, row, control=control)):
                    prompt, _ = browser.load_prompt_from_args(args, prepared_sources=sources)
                runner = browser.PlaywrightChatGPTRunner({"selectors": {}, "chrome_user_data_dir": tmp})
                runner.prepared_sources = tuple(sources)
                outcome = self._fake_send(runner, prompt, sent, filled)
            except (SystemExit, browser.ChatGPTBrowserReviewError) as exc:
                failure = exc
        self.assert_private_diagnostics(row, output.getvalue(), stderr.getvalue(), str(failure))
        if control:
            self.assertTrue(failure is None, "clean browser control refused")
            self.assertEqual((len(sent), len(filled)), (1, 1), "clean control must fill and press fake Send")
            expected = browser.bound_request(prompt, "0" * 32)
            self.assertEqual(digest(sent[0]), digest(expected), "fake Send bytes changed")
            self.assertEqual(digest(filled[0]), digest(expected), "composer bytes changed")
            self.assertEqual(outcome["submitted_sha256"], digest(expected), "submission digest changed")
        else:
            refused = isinstance(failure, (screening.OutboundRefused, browser.ChatGPTBrowserReviewError))
            if row["slot"] == "attachment":
                refused = isinstance(failure, SystemExit) and "forbidden boundary fields: attachments" in str(failure)
            self.assertTrue(refused, "browser disclosure passed")
            self.assertEqual((len(sent), len(filled)), (0, 0), "refusal reached composer or Send")

    def _fake_send(self, runner, prompt, sent, filled):
        helper = browser_tests.ChatGPTBrowserReviewTests()
        url = "https://chatgpt.com/c/0123abcd-4567"

        def press(script, arg):
            sent.append(arg.split("\n", 1)[1])
            return "pressed"

        button = helper._Handle(press, url)

        def box_answer(script, arg):
            if script == browser._FILL_SCRIPT:
                filled.append(arg)
            return button if script == browser._SEND_BUTTON_SCRIPT else True

        box = helper._Handle(box_answer, url)
        page = SimpleNamespace(url=url, goto=lambda *a, **k: None, query_selector_all=lambda selector: [box])
        captured = {"text": "Public review complete.", "extraction": "assistant-message", "message_id": "msg-1",
                    "conversation_url": url, "conversation_id": "0123abcd-4567", "capture_complete": True}
        replacements = {"_select_page": page, "_wait_for_prompt": None, "_select_configured_labels": None,
                        "_confirm_configured_labels": {"status": "confirmed"}, "_conversation_text": "before",
                        "_message_snapshot": {"available": True, "messages": [], "url": url},
                        "_pin_conversation": "0123abcd-4567", "_wait_for_stable_response": "reply",
                        "_capture_assistant_response": captured}
        with patch.dict(sys.modules, helper._fake_playwright_modules()), patch.object(browser.secrets, "token_hex", return_value="0" * 32), contextlib.ExitStack() as stack:
            for name, value in replacements.items():
                stack.enter_context(patch.object(runner, name, return_value=value))
            return runner.run(prompt)

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


class BrowserDestinationTests(unittest.TestCase):
    def _config(self):
        return {"selectors": {}, "chrome_user_data_dir": "/tmp/offline-profile", "chatgpt_url": "https://chatgpt.com/"}

    def _attempt(self, config, mode, *, stage=None, slot=None, changed=None, replace_config=False):
        effects = dict(factory=0, start=0, connect=0, launch=0, navigate=0, send=0)
        disclosed = {"chatgpt_url": [], "connect_over_cdp_url": []}
        runner = browser.PlaywrightChatGPTRunner(config)

        def checkpoint(name):
            effects[name] += 1
            if stage == name:
                if replace_config:
                    runner.config = {**config, slot: changed}
                else:
                    config[slot] = changed

        page = SimpleNamespace(url="https://chatgpt.com/c/public-review")

        def navigate(url, **kwargs):
            disclosed["chatgpt_url"].append(url)
            checkpoint("navigate")

        page.goto = navigate
        context = SimpleNamespace(close=lambda: None)

        def connect(url):
            disclosed["connect_over_cdp_url"].append(url)
            checkpoint("connect")
            return SimpleNamespace(contexts=[context])

        def launch(*args, **kwargs):
            checkpoint("launch")
            return context

        chromium = SimpleNamespace(connect_over_cdp=connect, launch_persistent_context=launch)

        def start():
            checkpoint("start")
            return SimpleNamespace(chromium=chromium, stop=lambda: None)

        def factory():
            checkpoint("factory")
            return SimpleNamespace(start=start)

        def select(context):
            if stage == "page":
                config[slot] = changed
            return page

        real_screen = browser.require_clean

        def screen(*args, **kwargs):
            token = real_screen(*args, **kwargs)
            if stage == "screen" and kwargs.get("surface") == "ChatGPT browser destination":
                config[slot] = changed
            return token

        captured = {"text": "Public reply.", "extraction": "assistant-message", "message_id": "msg-1",
                    "conversation_url": page.url, "conversation_id": "public-review"}
        replacements = {"_wait_for_prompt": None, "_select_configured_labels": None,
                        "_confirm_configured_labels": {"status": "confirmed"}, "_conversation_text": "before",
                        "_message_snapshot": {"available": True, "messages": [], "url": page.url},
                        "_pin_conversation": "public-review", "_wait_for_stable_response": "reply",
                        "_capture_assistant_response": captured}
        modules = browser_tests.ChatGPTBrowserReviewTests()._fake_playwright_modules()
        modules["playwright.sync_api"].sync_playwright = factory
        output, stderr, failure = io.StringIO(), io.StringIO(), None
        with patch.dict(sys.modules, modules), patch.object(runner, "_select_page", side_effect=select), \
                patch.object(runner, "_submit_prompt", side_effect=lambda *a, **k: checkpoint("send")), \
                patch.object(browser, "require_clean", side_effect=screen), \
                contextlib.redirect_stdout(output), contextlib.redirect_stderr(stderr), contextlib.ExitStack() as stack:
            for name, value in replacements.items():
                stack.enter_context(patch.object(runner, name, return_value=value))
            try:
                runner._run("Review the public notes.") if mode == "run" else runner.confirm_model_only()
            except (SystemExit, browser.ChatGPTBrowserReviewError) as exc:
                failure = exc
        return failure, effects, disclosed, output.getvalue() + stderr.getvalue()

    def _assert_private(self, row, failure, output):
        spans = row.get("sensitive", []) + [row["text"]]
        self.assertFalse(any(s in output + str(failure) for s in spans), "destination diagnostics exposed fixture content")

    def test_sensitive_destinations_refuse_before_startup(self):
        for row in fixture()["browser_destinations"]:
            for mode in ("run", "confirm"):
                with self.subTest(row=row["id"], surface=mode, slot=row["slot"]), tempfile.TemporaryDirectory() as tmp:
                    config = self._config()
                    config[row["slot"]] = row["text"]
                    path = Path(tmp) / "browser.json"
                    path.write_text(json.dumps(config), encoding="utf-8")
                    path.chmod(0o600)
                    loaded = browser.load_browser_config(path)
                    failure, effects, _, output = self._attempt(loaded, mode)
                    self._assert_private(row, failure, output)
                    self.assertTrue(isinstance(failure, screening.OutboundRefused), "destination metadata bypassed screening")
                    self.assertEqual(sum(effects.values()), 0, "refusal reached browser startup or disclosure")

    def test_unchanged_destinations_reach_effects_byte_for_byte(self):
        for row in fixture()["browser_destinations"]:
            for mode in ("run", "confirm"):
                with self.subTest(row=row["id"], surface=mode, slot=row["slot"]):
                    config = self._config()
                    config[row["slot"]] = row["control"]
                    failure, effects, disclosed, output = self._attempt(config, mode)
                    self._assert_private(row, failure, output)
                    self.assertTrue(failure is None, "benign destination control refused")
                    self.assertEqual((effects["factory"], effects["start"], effects["navigate"]), (1, 1, 1), "clean startup/navigation must function")
                    self.assertEqual(len(disclosed[row["slot"]]), 1, "selected destination did not reach its effect")
                    self.assertEqual(digest(disclosed[row["slot"]][0]), digest(row["control"]), "destination bytes changed")
                    self.assertEqual((effects["connect"], effects["launch"]), (int(row["slot"] == "connect_over_cdp_url"), int(row["slot"] != "connect_over_cdp_url")))

    def test_postscan_destination_drift_refuses_before_next_effect(self):
        for row in (fixture()["browser_destinations"][0], fixture()["browser_destinations"][2]):
            for mode in ("run", "confirm"):
                for stage in ("screen", "factory", "start", "connect", "page"):
                    with self.subTest(row=row["id"], surface=mode, slot=row["slot"]):
                        config = self._config()
                        config["connect_over_cdp_url"] = fixture()["browser_destinations"][2]["control"]
                        failure, effects, disclosed, output = self._attempt(config, mode, stage=stage, slot=row["slot"], changed=row["text"])
                        self._assert_private(row, failure, output)
                        self.assertTrue(isinstance(failure, (screening.OutboundRefused, browser.ChatGPTBrowserReviewError)), "postscan destination drift passed")
                        self.assertTrue("source changed" in str(failure), "destination drift missed the source binding")
                        expected = (int(stage != "screen"), int(stage in {"start", "connect", "page"}), int(stage in {"connect", "page"}), 0, 0, 0)
                        self.assertEqual(tuple(effects.values()), expected, "destination drift reached a later effect")
                        if disclosed["connect_over_cdp_url"]:
                            self.assertEqual(digest(disclosed["connect_over_cdp_url"][0]), digest(fixture()["browser_destinations"][2]["control"]), "earlier connection bytes changed")

    def test_profile_launch_drift_refuses_before_navigation(self):
        row = fixture()["browser_destinations"][0]
        for mode in ("run", "confirm"):
            with self.subTest(row=row["id"], surface=mode, slot=row["slot"]):
                failure, effects, _, output = self._attempt(self._config(), mode, stage="launch", slot=row["slot"], changed=row["control"])
                self._assert_private(row, failure, output)
                self.assertTrue(isinstance(failure, (screening.OutboundRefused, browser.ChatGPTBrowserReviewError)), "benign URL drift passed")
                self.assertEqual(tuple(effects.values()), (1, 1, 0, 1, 0, 0), "profile callback drift reached navigation")

    def test_replaced_config_refuses_before_connection(self):
        row = fixture()["browser_destinations"][2]
        for mode in ("run", "confirm"):
            with self.subTest(row=row["id"], surface=mode, slot=row["slot"]):
                config = self._config()
                config[row["slot"]] = row["control"]
                failure, effects, _, output = self._attempt(config, mode, stage="start", slot=row["slot"], changed=row["text"], replace_config=True)
                self._assert_private(row, failure, output)
                self.assertTrue(isinstance(failure, screening.OutboundRefused), "replacement config escaped source binding")
                self.assertEqual(tuple(effects.values()), (1, 1, 0, 0, 0, 0), "replacement config reached a connection")

    def test_embedding_defaults_and_undisclosed_local_paths(self):
        paths = fixture()["browser_local_paths"]
        for mode in ("run", "confirm"):
            with self.subTest(row="ds15", surface=mode, slot="defaults"):
                config = {"selectors": {}, "chrome_user_data_dir": paths["profile"], "chrome_executable_path": paths["executable"]}
                failure, effects, disclosed, output = self._attempt(config, mode)
                self.assertFalse(any(v in output + str(failure) for v in paths.values()), "local paths leaked in diagnostics")
                self.assertTrue(failure is None, "embedding defaults or local paths were rejected")
                self.assertEqual(tuple(effects.values()), (1, 1, 0, 1, 1, int(mode == "run")))
                self.assertEqual(digest(disclosed["chatgpt_url"][0]), digest("https://chatgpt.com/"), "embedding navigation default changed")

    def test_embedding_destination_origin_and_locality_validation(self):
        for row in fixture()["browser_invalid_destinations"]:
            for mode in ("run", "confirm"):
                with self.subTest(row=row["id"], surface=mode, slot=row["slot"]):
                    config = self._config()
                    config[row["slot"]] = row["text"]
                    failure, effects, _, output = self._attempt(config, mode)
                    self._assert_private(row, failure, output)
                    self.assertTrue(isinstance(failure, SystemExit), "invalid destination passed origin/locality validation")
                    self.assertEqual(sum(effects.values()), 0, "invalid destination reached browser startup")


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

    @unittest.skipUnless(preparation_tests.shutil.which("node"), "Optional Node harness")
    def test_deliberate_node_failure_reports_only_a_digest(self):
        private, report = fixture()["preparation"]["value"], io.StringIO()
        case = preparation_tests.PreparedBrowserTests("test_send_executes_text_check_and_click_in_one_script")
        failed = SimpleNamespace(returncode=1, stdout="", stderr=private)
        with patch.object(preparation_tests.subprocess, "run", return_value=failed):
            result = unittest.TextTestRunner(stream=report).run(case)
        self.assertEqual(len(result.failures), 1, "the deliberate Node failure must execute")
        self.assertEqual(len(result.errors), 0, "the Node witness must fail an assertion")
        self.assertTrue(digest(private) in report.getvalue(), "Node failure must carry a stderr digest")
        self.assertFalse(private in report.getvalue(), "Node diagnostics exposed fixture content")
