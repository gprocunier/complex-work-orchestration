from __future__ import annotations

import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import chatgpt_browser_review as browser
from tests.browser_connected_fixture import Page, REPLY, admitted_runner, packet_input, runtime_modules
from cwo_core import audit


class ConnectedBrowserTests(unittest.TestCase):
    def test_audit_failure_retains_publication_without_an_intake_event(self):
        from tests.browser_connected_fixture import connected_capture
        from cwo_core.browser_provenance import select_private_capture
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with patch.object(browser, "record_audit_event", side_effect=OSError("offline audit unavailable")), \
                    self.assertRaises(OSError) as caught:
                connected_capture(root)
            self.assertNotIn(REPLY, str(caught.exception))
            self.assertEqual(len(list((root / "returns").iterdir())), 2)
            packet = json.loads((root / "packet.json").read_bytes())
            self.assertEqual(len(audit.iter_audit_events(root / "audit.jsonl")), 1)
            with self.assertRaises(SystemExit):
                select_private_capture(packet, packet_source_sha256="a" * 64, capture_event_hash="b" * 64,
                                       audit_file=root / "audit.jsonl")

    def test_share_failure_records_one_entered_effect_and_never_retries(self):
        from browser_action_dispatch import BrowserActionRefused
        from cwo_core.invocation_ledger import InvocationLedgerError
        calls = []
        selection = {"origin": "https://chatgpt.com", "conversation_id": "0123abcd-4567", "purpose": "peer review",
                     "messages": [{"message_id": "user-1", "role": "user", "content": "Review café."}]}

        def fail(*args, **kwargs):
            calls.append(1)
            raise RuntimeError(REPLY)

        runner = browser.PlaywrightChatGPTRunner({"selectors": {}})
        with admitted_runner(runner, "Review café.", share=selection, create_share=fail) as admission:
            ticket = admission.parent.authorize_create_share(purpose="peer review", expires_at=admission.clock() + 100)
            with self.assertRaises(BrowserActionRefused) as caught:
                runner.create_share(ticket)
            self.assertNotIn(REPLY, str(caught.exception))
            with self.assertRaises((BrowserActionRefused, InvocationLedgerError)):
                runner.create_share(ticket)
            attempts = list(json.loads((admission.ledger.root / "ledger.json").read_bytes())["attempts"].values())
            self.assertIsNone(attempts[0]["observed_usage"])
            self.assertEqual(attempts[0]["charge"]["effect_calls"], 1)
        self.assertEqual(len(calls), 1)

    def test_real_lifecycle_observes_exact_response_and_accounts_post_send_failure(self):
        for outcome in ("matched", "output-overrun", "deadline"):
            with self.subTest(outcome=outcome):
                runner = browser.PlaywrightChatGPTRunner({"selectors": {}, "require_model_confirmation": False,
                    "chrome_user_data_dir": "offline-profile", "stable_wait_seconds": 0})
                page = Page()
                size = 1 if outcome == "output-overrun" else len(REPLY.encode("utf-8"))
                limits = {"timeout_seconds": 1, "max_output_bytes": size, "max_send_probes": 1}
                with admitted_runner(runner, "Review café.", lifecycle=True, timeout_ms=30000, action_limits=limits) as admission, \
                        patch.object(browser.secrets, "token_hex", return_value="0" * 32), \
                        patch.object(browser, "BROWSER_DISPATCH_AVAILABLE", True), patch.dict(sys.modules, runtime_modules(page)):
                    if outcome == "deadline":
                        page.callback = lambda stage: setattr(admission.clock, "now", admission.clock.now + 2) if stage == "snapshot" and len(page.snapshots) >= 4 else None
                    if outcome == "matched":
                        runner.run("Review café.")
                    else:
                        with self.assertRaises(browser.ChatGPTBrowserReviewError) as caught:
                            runner.run("Review café.")
                        self.assertEqual(caught.exception.stage, "response-wait")
                        self.assertNotIn(REPLY, str(caught.exception))
                    attempts = list(json.loads((admission.ledger.root / "ledger.json").read_bytes())["attempts"].values())
                    usage = attempts[0]["observed_usage"]
                    self.assertEqual(usage["effect_calls"], 1)
                    self.assertEqual(usage["output_bytes"], len(REPLY.encode("utf-8")))
                    self.assertEqual(attempts[0]["outcome"], "completed" if outcome == "matched" else "failed")
                self.assertEqual(len(page.sent), 1)
                self.assertEqual(runner.send_state, "submitted")

    def test_loaded_packet_file_and_original_options_are_checked_after_callbacks(self):
        for mutation in ("file", "options"):
            with self.subTest(source=mutation), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                _, args, log = packet_input(root)
                sources = []
                with patch.object(audit, "AUDIT_LOG", log):
                    prompt, metadata = browser.load_prompt_from_args(args, prepared_sources=sources)
                runner = browser.PlaywrightChatGPTRunner({"selectors": {}})
                runner.prepared_sources, runner.packet_metadata = tuple(sources), metadata

                def change(stage):
                    if stage != "button-origin":
                        return
                    if mutation == "file":
                        Path(args.packet).write_bytes(b"{}")
                    else:
                        args.allow_unlinked_packet = True

                page = Page(change)
                with admitted_runner(runner, prompt), self.assertRaises(SystemExit):
                    runner._submit_prompt(page, prompt, 1000, "0" * 32)
                self.assertEqual(len(page.sent), 0)

    def test_candidate_connected_capture_binds_real_current_repository_bytes(self):
        from cwo_core.candidate_identity import candidate_binding
        from cwo_core.browser_provenance import select_private_capture
        from tests.browser_connected_fixture import connected_capture
        from tests.test_browser_subject import candidate_fixture
        with tempfile.TemporaryDirectory() as tmp:
            current = candidate_fixture(Path(tmp))
            candidate, root = current["candidate_record"], current["candidate_root"]
            capture = connected_capture(Path(tmp), **current)
            self.assertEqual(capture.provenance["subject"]["candidate_sha256"], candidate_binding(candidate))
            self.assertTrue(capture.text == REPLY, "candidate response bytes changed")
            changed = {**candidate, "baseline": {"version": 1, "digest": "sha256:" + "b" * 64}}
            with self.assertRaises(SystemExit):
                select_private_capture(capture.packet, packet_source_sha256=capture.metadata["packet_source_sha256"],
                                       capture_event_hash=capture.event["event_hash"], audit_file=capture.log,
                                       candidate_record=changed, candidate_root=root)
            (root / "source.txt").write_bytes(b"changed actual source bytes\n")
            from ingest_chatgpt_share_return import load_private_response
            with self.assertRaises(SystemExit):
                load_private_response(Path(capture.artifact["provenance_path"]), expected=capture.expected)

    def test_share_cannot_replace_registered_creation_callback(self):
        from browser_action_dispatch import BrowserActionRefused
        calls = []
        selection = {"origin": "https://chatgpt.com", "conversation_id": "0123abcd-4567", "purpose": "peer review",
                     "messages": [{"message_id": "user-1", "role": "user", "content": "Review café."}]}
        runner = browser.PlaywrightChatGPTRunner({"selectors": {}})
        with admitted_runner(runner, "Review café.", share=selection, create_share=lambda *a, **k: b"created") as admission:
            ticket = admission.parent.authorize_create_share(purpose="peer review", expires_at=admission.clock() + 100)
            admission.adapter._create_effect = lambda *a, **k: calls.append(a) or b"changed"
            with self.assertRaises(BrowserActionRefused):
                runner.create_share(ticket)
        self.assertEqual(len(calls), 0)

    def test_exhausted_send_aggregate_prevents_the_separate_share_effect(self):
        from cwo_core.invocation_ledger import InvocationLedgerError
        calls, page = [], Page()
        selection = {"origin": "https://chatgpt.com", "conversation_id": "0123abcd-4567", "purpose": "peer review",
                     "messages": [{"message_id": "user-1", "role": "user", "content": "Review café."}]}
        runner = browser.PlaywrightChatGPTRunner({"selectors": {}})
        capacity = {"effect_calls": 4, "payload_bytes": 100_000_000, "output_bytes": 100_000_000, "runtime_milliseconds": 100_000_000}
        with admitted_runner(runner, "Review café.", share=selection, create_share=lambda *a, **k: calls.append(a) or b"created",
                             capacity=capacity) as admission:
            runner._submit_prompt(page, "Review café.", 1000, "0" * 32)
            ticket = admission.parent.authorize_create_share(purpose="peer review", expires_at=admission.clock() + 100)
            with self.assertRaises(InvocationLedgerError):
                runner.create_share(ticket)
            attempts = list(json.loads((admission.ledger.root / "ledger.json").read_bytes())["attempts"].values())
            self.assertEqual(runner.send_admission_sha256, attempts[0]["admission_sha256"])
            self.assertNotEqual(attempts[0]["request_id"], "browser-action:" + runner.send_admission_sha256)
            self.assertEqual(attempts[0]["observed_usage"]["effect_calls"], 1)
            self.assertNotIn("output_bytes", attempts[0]["observed_usage"])
        self.assertEqual((len(page.sent), len(calls)), (1, 0))

    def test_separate_share_action_reaches_one_registered_creation(self):
        from browser_action_dispatch import BrowserActionRefused
        from cwo_core.invocation_ledger import InvocationLedgerError
        calls = []
        prompt = "Review café."
        selection = {"origin": "https://chatgpt.com", "conversation_id": "0123abcd-4567", "purpose": "peer review",
                     "messages": [{"message_id": "user-1", "role": "user", "content": prompt},
                                  {"message_id": "assistant-1", "role": "assistant", "content": REPLY}]}
        runner, page = browser.PlaywrightChatGPTRunner({"selectors": {}, "share_link_required": True}), Page()

        def create(raw, **limits):
            calls.append(raw)
            return b"offline-creation-observed"

        with admitted_runner(runner, prompt, share=selection, create_share=create) as admission:
            runner._submit_prompt(page, prompt, 1000, "0" * 32)
            observed = page.evaluate(browser._SNAPSHOT_SCRIPT)
            runner._share_selection["messages"] = [{"message_id": m["id"], "role": m["role"], "content": m["text"]}
                                                  for m in observed["messages"]]
            with patch.object(runner, "_create_share_link", side_effect=AssertionError("dormant helper reached")), \
                    patch.object(runner, "_try_social_share_url", side_effect=AssertionError("social helper reached")):
                with self.assertRaises(BrowserActionRefused):
                    runner.create_share(None)
                ticket = admission.parent.authorize_create_share(purpose="peer review", expires_at=admission.clock() + 100)
                result = runner.create_share(ticket)
                with self.assertRaises((BrowserActionRefused, InvocationLedgerError)):
                    runner.create_share(ticket)
        self.assertEqual((len(page.sent), len(calls)), (1, 1))
        self.assertTrue(json.loads(calls[0]) == selection, "share selection bytes changed")
        self.assertFalse(result.remote_usage_known)
        self.assertNotIn(REPLY, repr(result))

    def test_share_wrong_content_conversation_purpose_and_expiry_refuse_before_effect(self):
        from browser_action_dispatch import BrowserActionRefused
        for drift in ("content", "conversation", "purpose", "expiry", "copied", "missing"):
            with self.subTest(binding=drift):
                import copy
                calls = []
                selection = {"origin": "https://chatgpt.com", "conversation_id": "0123abcd-4567", "purpose": "peer review",
                             "messages": [{"message_id": "user-1", "role": "user", "content": "Review café."}]}
                runner = browser.PlaywrightChatGPTRunner({"selectors": {}})
                with admitted_runner(runner, "Review café.", share=selection,
                                     create_share=lambda *a, **k: calls.append(a) or b"created") as admission:
                    ticket = admission.parent.authorize_create_share(purpose="peer review", expires_at=admission.clock() + 100)
                    if drift == "content":
                        selection["messages"][0]["content"] += " changed"
                    elif drift == "conversation":
                        selection["conversation_id"] = "other-conversation"
                    elif drift == "purpose":
                        selection["purpose"] = "other purpose"
                    elif drift == "expiry":
                        admission.clock.now += 200
                    elif drift == "copied":
                        ticket = copy.copy(ticket)
                    else:
                        ticket = None
                    with self.assertRaises(BrowserActionRefused):
                        runner.create_share(ticket)
                self.assertEqual(len(calls), 0)

    def test_connected_capture_persists_the_complete_chain(self):
        from tests.browser_connected_fixture import connected_capture
        with tempfile.TemporaryDirectory() as tmp:
            output, errors = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
                capture = connected_capture(Path(tmp))
            record = capture.provenance
            self.assertEqual(len(capture.page.sent), 1)
            self.assertTrue(capture.page.sent[0] == browser.bound_request(capture.prompt, capture.captured["request_id"]).encode("utf-8"), "submitted bytes changed")
            self.assertTrue(capture.text == REPLY, "response bytes changed")
            self.assertEqual(record["version"], 5)
            self.assertTrue(record["capture_complete"])
            for key in ("outbound_source_sha256", "outbound_export_sha256", "outbound_prepared_sha256",
                        "outbound_screen_version", "send_admission_sha256", "observed_user_sha256", "submitted_user_sha256"):
                self.assertEqual(record[key], capture.captured[key], key)
            self.assertEqual(record["packet_sha256"], capture.packet["packet_sha256"])
            self.assertEqual(record["subject"], capture.packet["subject"])
            self.assertEqual(record["packet_source_sha256"], capture.metadata["packet_source_sha256"])
            self.assertEqual(record["observed_document_request_id"], record["request_id"])
            self.assertEqual((record["user_message_id"], record["assistant_message_id"]), ("user-1", "assistant-1"))
            self.assertEqual(record["response_bytes"], len(REPLY.encode("utf-8")))
            self.assertEqual(capture.result["response_artifact"]["capture_event_hash"], capture.event["event_hash"])
            persisted = audit.iter_audit_events(capture.log)[-1]
            attempt, = capture.accounting["attempts"].values()
            for boundary, value in (("private-v5", record), ("independent-audit", persisted)):
                with self.subTest(boundary=boundary):
                    self.assertEqual(value["send_admission_sha256"], attempt["admission_sha256"])
            self.assertNotEqual(attempt["request_id"], "browser-action:" + record["send_admission_sha256"])
            self.assertEqual(persisted["private_provenance_sha256"], capture.artifact["provenance_sha256"])
            self.assertFalse(capture.result["share"]["available"])
            self.assertFalse(REPLY in json.dumps(capture.result) + capture.log.read_text() + output.getvalue() + errors.getvalue())

    def test_connected_intake_refuses_coherently_rewritten_bindings(self):
        from tests.browser_connected_fixture import connected_capture
        from ingest_chatgpt_share_return import load_private_response
        with tempfile.TemporaryDirectory() as tmp:
            capture = connected_capture(Path(tmp))
            path = Path(capture.artifact["provenance_path"])
            original = path.read_bytes()
            changes = {
                "subject": {"kind": "packet-input", "source_sha256": "b" * 64},
                "packet_source_sha256": "b" * 64, "packet_sha256": "b" * 64, "request_id": "1" * 32,
                "submitted_sha256": "b" * 64, "outbound_prepared_sha256": "b" * 64,
                "send_admission_sha256": "b" * 64, "conversation_id": "other-conversation",
                "user_message_id": "other-user", "assistant_message_id": "other-assistant", "response_sha256": "b" * 64,
            }
            for key, value in changes.items():
                with self.subTest(field=key):
                    altered = json.loads(original)
                    altered[key] = value
                    if key == "conversation_id":
                        altered["conversation_url"] = "https://chatgpt.com/c/other-conversation"
                        altered["pinned_conversation_id"] = value
                    path.write_text(json.dumps(altered), encoding="utf-8")
                    with self.assertRaises(SystemExit) as caught:
                        load_private_response(path, expected=capture.expected)
                    self.assertNotIn(REPLY, str(caught.exception))
            path.write_bytes(original)
            response = Path(capture.artifact["response_path"])
            response.write_bytes(b"substituted response")
            with self.assertRaises(SystemExit):
                load_private_response(path, expected=capture.expected)

    def test_final_callbacks_revalidate_original_execution_and_inputs(self):
        mutations = {
            "selectors": lambda runner: setattr(runner, "selectors", {"submit_button": "other"}),
            "config": lambda runner: setattr(runner, "config", {**runner.config, "late": "changed"}),
            "limits": lambda runner: setattr(runner, "_action_limits", {**runner._action_limits, "max_output_bytes": 1}),
            "request": lambda runner: runner.packet_metadata.update(dispatch_id="changed"),
            "model": lambda runner: setattr(runner, "_model_observation", {"status": "changed"}),
            "timeout": lambda runner: setattr(runner, "_action_submission", (*runner._action_submission[:-1], 999)),
        }
        for stage in ("origin", "stamp", "fill", "button", "button-origin"):
            for name, mutate in mutations.items():
                with self.subTest(stage=stage, binding=name):
                    runner = browser.PlaywrightChatGPTRunner({"selectors": {}})
                    page = Page(lambda observed: mutate(runner) if observed == stage else None)
                    with admitted_runner(runner, "Review café."), self.assertRaises(SystemExit) as caught:
                        runner._submit_prompt(page, "Review café.", 1000, "0" * 32)
                    self.assertEqual(len(page.sent), 0)
                    self.assertNotIn(REPLY, str(caught.exception))

    def test_actual_send_is_one_use_and_expired_authority_has_zero_effects(self):
        for state in ("replay", "expired", "copied", "forged", "foreign", "missing"):
            with self.subTest(authority=state):
                import copy
                runner, page = browser.PlaywrightChatGPTRunner({"selectors": {}}), Page()
                with admitted_runner(runner, "Review café.") as binding:
                    if state == "replay":
                        self.assertEqual(runner._submit_prompt(page, "Review café.", 1000, "0" * 32), "pressed")
                    elif state == "expired":
                        binding.clock.now += 20000
                    elif state == "copied":
                        runner._send_ticket = copy.copy(runner._send_ticket)
                    elif state == "forged":
                        runner._send_ticket = {"authorized": True}
                    elif state == "foreign":
                        other = browser.PlaywrightChatGPTRunner({"selectors": {}})
                        with admitted_runner(other, "Review café."):
                            runner._send_ticket = other._send_ticket
                    else:
                        runner._send_ticket = None
                    count = len(page.sent)
                    with self.assertRaises(SystemExit):
                        runner._submit_prompt(page, "Review café.", 1000, "0" * 32)
                    self.assertEqual(len(page.sent), count)
                    self.assertEqual(len(page.filled), count)

    def test_missing_admission_refuses_before_fill(self):
        page = Page()
        runner = browser.PlaywrightChatGPTRunner({"selectors": {}})
        with self.assertRaises(SystemExit) as caught:
            runner._submit_prompt(page, "Review café.\n", 1000, "0" * 32)
        self.assertIn("admission", str(caught.exception))
        self.assertEqual((len(page.filled), len(page.sent)), (0, 0))

    def test_registered_offline_parent_cannot_enable_the_shipped_route(self):
        runner, page = browser.PlaywrightChatGPTRunner({"selectors": {}}), Page()
        with admitted_runner(runner, "Review café."), patch.object(browser, "BROWSER_DISPATCH_AVAILABLE", False), \
                patch.dict(sys.modules, runtime_modules(page)), self.assertRaises(SystemExit):
            runner.run("Review café.")
        self.assertEqual((len(page.filled), len(page.sent)), (0, 0))

    def test_real_run_without_parent_refuses_before_fill(self):
        page, output = Page(), io.StringIO()
        config = {"selectors": {}, "require_model_confirmation": False, "chrome_user_data_dir": "offline-profile",
                  "stable_wait_seconds": 0}
        runner = browser.PlaywrightChatGPTRunner(config)
        with patch.object(browser, "BROWSER_DISPATCH_AVAILABLE", True), patch.dict(sys.modules, runtime_modules(page)), \
                contextlib.redirect_stdout(output), self.assertRaises((SystemExit, browser.ChatGPTBrowserReviewError)) as caught:
            runner.run("Review café.\n")
        self.assertIn("admission", str(caught.exception))
        self.assertEqual((len(page.filled), len(page.sent)), (0, 0))
        self.assertNotIn(REPLY, output.getvalue() + str(caught.exception))
