"""Exact disclosure consent at the separate, registered browser consumer."""
from __future__ import annotations

import copy
import io
import json
import sys
import tempfile
import unittest
from contextlib import contextmanager, redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import browser_action_dispatch as actions
import chatgpt_browser_review as browser
from cwo_core.invocation_ledger import InvocationLedger, InvocationLedgerError
from cwo_core.outbound_screen import OutboundRefused, require_clean
from cwo_core.prepared_outbound import PreparedSource


PROMPT = "Review the synthetic example."
RESPONSE = "Synthetic café response with trailing space.  \n"
URL = "https://chatgpt.com/c/offline-conversation"
SHARE_URL = "https://chatgpt.com/share/offline-result"


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


class Clock:
    now = 1000000.0

    def __call__(self):
        return self.now


class Boundary:
    """Registered complete offline observation, with an atomic expectation check."""

    def __init__(self, selection):
        self.observation = {
            "document_id": "offline-document", "conversation_url": URL,
            "selection": copy.deepcopy(selection), "coverage": "complete",
            "representation": canonical(selection), "existing_share": None,
        }
        self.calls = []
        self.on_observe = self.on_create = self.on_result = None
        self.returned = SHARE_URL
        self.result_url = SHARE_URL
        self.failure = None

    def observe(self):
        observed = copy.deepcopy(self.observation)
        if self.on_observe:
            self.on_observe()
        return observed

    def create(self, expectation, **limits):
        if self.on_create:
            self.on_create()
        if canonical(self.observation) != canonical(expectation["observation"]):
            raise actions.BrowserActionRefused("Offline atomic disclosure check refused.")
        self.calls.append(1)
        if self.failure:
            raise self.failure
        self.observation["existing_share"] = {
            "url": self.result_url, "document_id": self.observation["document_id"],
            "conversation_url": self.observation["conversation_url"],
            "action_sha256": expectation["action_sha256"],
        }
        return self.returned.encode("utf-8")

    def result(self):
        if self.on_result:
            self.on_result()
        return copy.deepcopy(self.observation)


@contextmanager
def admitted(*, observers=(), legacy=False, share_required=False, content=None, selection_change=None,
             tracked_input=False):
    """Real source preparation, original parent/adapter, ledger and runner."""
    with tempfile.TemporaryDirectory() as directory:
        clock = Clock()
        runner = browser.PlaywrightChatGPTRunner({"selectors": {}, "share_link_required": share_required})
        selection = {"origin": "https://chatgpt.com", "conversation_id": "offline-conversation",
                     "messages": [{"message_id": "earlier", "role": "user", "content": "Earlier synthetic turn."},
                                  {"message_id": "user", "role": "user", "content": PROMPT},
                                  {"message_id": "assistant", "role": "assistant", "content": RESPONSE}],
                     "purpose": "independent review"}
        if content is not None:
            index, text = content
            selection["messages"][index]["content"] = text
        if selection_change is not None:
            selection_change(selection)
        runner.packet_metadata = {"packet_sha256": "a" * 64, "dispatch_id": "offline-consent",
                                  "subject": {"kind": "packet-input", "source_sha256": "b" * 64}}
        source, capture = runner._capture_submission_source(PROMPT)
        input_path = Path(directory) / "original-input.json"
        if tracked_input:
            input_path.write_text('{"input":"Synthetic original source."}', encoding="utf-8")
            capture = PreparedSource.capture(source, ((str(input_path), input_path.read_bytes()),))
        prepared = capture.bind(source, require_clean(PROMPT, surface="ChatGPT browser Send"))
        runner._action_submission = prepared, source, PROMPT, "0" * 32, 1000
        runner._action_limits = {"timeout_seconds": 10, "max_output_bytes": 1024, "max_send_probes": 1}
        runner._share_selection = selection
        boundary = Boundary(selection)
        options = {"create_share": lambda *a, **k: boundary.calls.append(1) or SHARE_URL.encode()}
        if not legacy:
            options = {"share_boundary": boundary}
        adapter = browser.BrowserRunnerAdapter(runner, **options)
        ledger = InvocationLedger(Path(directory) / "ledger", clock=clock)
        parent = actions.RegisteredBrowserParent(prepared, ledger=ledger, adapter=adapter, observers=observers,
            aggregate_scope={"aggregate_id": "offline-consent", "purpose": "review"},
            aggregate_limits={"effect_calls": 8, "payload_bytes": 100000,
                              "output_bytes": 100000, "runtime_milliseconds": 100000})
        runner._action_parent = adapter.parent = parent
        runner._send_ticket = adapter.ticket = parent.issue_send(expires_at=clock() + 100)
        yield type("Admission", (), {"runner": runner, "parent": parent, "boundary": boundary,
                                     "clock": clock, "ledger": ledger, "adapter": adapter,
                                     "input_path": input_path})()


def consent(admission):
    return admission.parent.consent_to_share(purpose="independent review", expires_at=admission.clock() + 60)


def ticket(admission, grant=None):
    return admission.parent.authorize_create_share(purpose="independent review", expires_at=admission.clock() + 50,
                                                    consent=consent(admission) if grant is None else grant)


def attempts(admission):
    return list(json.loads((admission.ledger.root / "ledger.json").read_bytes())["attempts"].values())


class ShareConsentTests(unittest.TestCase):
    def test_legacy_unbound_callback_cannot_share_without_fresh_consent(self):
        with admitted(legacy=True) as a:
            with self.assertRaises(actions.BrowserActionRefused):
                old = a.parent.authorize_create_share(purpose="independent review", expires_at=a.clock() + 50)
                a.runner.create_share(old)
            self.assertEqual(len(a.boundary.calls), 0)

    def test_exact_final_disclosure_reaches_one_effect_without_fallback(self):
        with admitted(share_required=True) as a, \
                patch.object(a.runner, "_create_share_link", side_effect=AssertionError("legacy boundary reached")), \
                patch.object(a.runner, "_try_social_share_url", side_effect=AssertionError("social boundary reached")):
            grant = consent(a)
            selected = ticket(a, grant)
            result = a.runner.create_share(selected)
            self.assertEqual((result.status, len(a.boundary.calls)), ("created", 1))
            self.assertEqual(attempts(a)[0]["observed_usage"]["effect_calls"], 1)
            self.assertFalse(browser.BROWSER_DISPATCH_AVAILABLE)
            self.assertFalse(browser.share_status(a.runner.config)["available"])

    def test_default_missing_consent_and_config_flags_never_create(self):
        for flag in (False, True):
            with self.subTest(flag=flag), admitted(share_required=flag) as a:
                with self.assertRaises(actions.BrowserActionRefused):
                    a.parent.authorize_create_share(purpose="independent review", expires_at=a.clock() + 50)
                with self.assertRaises(actions.BrowserActionRefused):
                    a.runner.create_share(None)
                self.assertEqual(len(a.boundary.calls), 0)

    def test_unknown_and_incomplete_coverage_refuse_consent(self):
        for coverage in (None, False, "unknown", "partial"):
            with self.subTest(coverage=coverage), admitted() as a:
                a.boundary.observation["coverage"] = coverage
                with self.assertRaises(actions.BrowserActionRefused):
                    consent(a)
                self.assertEqual(len(a.boundary.calls), 0)

    def test_missing_response_and_unrelated_request_cannot_claim_complete_coverage(self):
        for missing in (True, False):
            def change(selection):
                if missing:
                    selection["messages"].pop()
                else:
                    selection["messages"][-2]["content"] = "Another prepared request."
            with self.subTest(missing_response=missing), admitted(selection_change=change) as a:
                with self.assertRaises(actions.BrowserActionRefused):
                    consent(a)
                self.assertEqual(len(a.boundary.calls), 0)

    def test_result_url_control_characters_cannot_be_hidden_by_url_parser(self):
        with admitted() as a:
            selected = ticket(a)
            a.boundary.returned = a.boundary.result_url = SHARE_URL + "\n"
            with self.assertRaises(actions.BrowserActionRefused):
                a.runner.create_share(selected)
            self.assertEqual(len(a.boundary.calls), 1)
            self.assertEqual(attempts(a)[0]["outcome"], "unknown")

    def test_ordered_content_document_and_representation_drift_refuse(self):
        for drift in ("earlier", "insert", "response", "reorder", "document", "url", "representation", "coverage"):
            with self.subTest(drift=drift), admitted() as a:
                selected = ticket(a)
                observed = a.boundary.observation
                if drift == "earlier":
                    observed["selection"]["messages"][0]["content"] += " changed"
                elif drift == "insert":
                    observed["selection"]["messages"].insert(0, {"message_id": "new", "role": "user", "content": "Inserted turn."})
                elif drift == "response":
                    observed["selection"]["messages"][-1]["content"] += " changed"
                elif drift == "reorder":
                    observed["selection"]["messages"].reverse()
                else:
                    key = {"document": "document_id", "url": "conversation_url"}.get(drift, drift)
                    observed[key] = "changed"
                with self.assertRaises((actions.BrowserActionRefused, SystemExit)):
                    a.runner.create_share(selected)
                self.assertEqual(len(a.boundary.calls), 0)

    def test_expired_copied_foreign_and_reused_consent_refuse(self):
        with admitted() as a, admitted() as foreign:
            grant = consent(a)
            for invalid in (copy.copy(grant), copy.deepcopy(grant), consent(foreign), {"consent": True}):
                with self.assertRaises(actions.BrowserActionRefused):
                    ticket(a, invalid)
            selected = ticket(a, grant)
            with self.assertRaises(actions.BrowserActionRefused):
                ticket(a, grant)
            a.clock.now += 61
            with self.assertRaises(actions.BrowserActionRefused):
                a.runner.create_share(selected)
            self.assertEqual(len(a.boundary.calls), 0)
        with admitted() as a:
            grant = consent(a)
            a.clock.now += 61
            with self.assertRaises(actions.BrowserActionRefused):
                ticket(a, grant)
            self.assertEqual(len(a.boundary.calls), 0)

    def test_far_future_expiry_cannot_extend_freshness_beyond_original_timeout(self):
        with admitted() as a:
            grant = a.parent.consent_to_share(purpose="independent review", expires_at=a.clock() + 100000)
            selected = ticket(a, grant)
            a.clock.now += a.runner._action_limits["timeout_seconds"] + 1
            with self.assertRaises(actions.BrowserActionRefused):
                a.runner.create_share(selected)
            self.assertEqual(len(a.boundary.calls), 0)

    def test_final_consumer_rescreens_before_create(self):
        with admitted() as a:
            selected = ticket(a)
            with patch("browser_share_consent.require_clean", side_effect=OutboundRefused(RESPONSE)), \
                    self.assertRaises(actions.BrowserActionRefused) as caught:
                a.runner.create_share(selected)
            self.assertFalse(RESPONSE in str(caught.exception), "screening failure disclosed response")
            self.assertEqual(len(a.boundary.calls), 0)

    def test_source_packet_selection_and_execution_drift_refuse(self):
        for drift in ("source", "packet", "candidate", "request", "options", "selection"):
            with self.subTest(drift=drift), admitted() as a:
                selected = ticket(a)
                runner = a.runner
                if drift == "source":
                    runner._action_submission[1]["prompt"] += "changed"
                elif drift == "packet":
                    runner.packet_metadata["packet_sha256"] = "f" * 64
                elif drift == "candidate":
                    runner.packet_metadata["subject"] = {"kind": "candidate", "candidate_sha256": "f" * 64}
                elif drift == "request":
                    runner._action_submission = (*runner._action_submission[:3], "f" * 32, 1000)
                elif drift == "options":
                    runner.selectors["share_button"] = "changed"
                else:
                    runner._share_selection["purpose"] += " changed"
                with self.assertRaises((actions.BrowserActionRefused, SystemExit)):
                    a.runner.create_share(selected)
                self.assertEqual(len(a.boundary.calls), 0)

    def test_screening_decoded_earlier_response_and_final_representation(self):
        for target in ("earlier", "response", "representation"):
            secret = 'password: "synthetic-private-value"'
            content = None if target == "representation" else (0 if target == "earlier" else -1, secret)
            with self.subTest(target=target), admitted(content=content) as a:
                observed = a.boundary.observation
                if target == "representation":
                    observed["representation"] += secret
                with self.assertRaises(actions.BrowserActionRefused) as caught:
                    consent(a)
                self.assertFalse(secret in str(caught.exception), "refusal disclosed content")
                self.assertEqual(len(a.boundary.calls), 0)

    def test_callback_changes_rechecked_before_atomic_effect(self):
        for stage in ("observe", "create"):
            with self.subTest(stage=stage), admitted() as a:
                selected = ticket(a)
                def change():
                    a.boundary.observation["document_id"] = "replaced-document"
                setattr(a.boundary, "on_" + stage, change)
                with self.assertRaises(actions.BrowserActionRefused):
                    a.runner.create_share(selected)
                self.assertEqual(len(a.boundary.calls), 0)

    def test_source_changes_after_observation_and_intent_callbacks_refuse(self):
        for stage in ("observe", "intent"):
            with self.subTest(stage=stage):
                slot = []
                def change(event=None):
                    if event is None or event["event"] == "invocation-intent":
                        slot[0].runner.packet_metadata["packet_sha256"] = "f" * 64
                with admitted(observers=(change,) if stage == "intent" else ()) as a:
                    slot.append(a)
                    selected = ticket(a)
                    if stage == "observe":
                        a.boundary.on_observe = change
                    with self.assertRaises(actions.BrowserActionRefused):
                        a.runner.create_share(selected)
                    self.assertEqual(len(a.boundary.calls), 0)

    def test_original_input_file_changes_are_checked_after_callbacks(self):
        for stage in ("before", "observe"):
            with self.subTest(stage=stage), admitted(tracked_input=True) as a:
                selected = ticket(a)
                def change():
                    a.input_path.write_bytes(b"changed original source bytes")
                if stage == "before":
                    change()
                else:
                    a.boundary.on_observe = change
                with self.assertRaises((actions.BrowserActionRefused, SystemExit)):
                    a.runner.create_share(selected)
                self.assertEqual(len(a.boundary.calls), 0)

    def test_registered_boundary_and_callback_replacement_refuse(self):
        for name in ("observe", "create", "result", "boundary"):
            with self.subTest(method=name), admitted() as a:
                selected = ticket(a)
                if name == "boundary":
                    a.adapter._share_boundary = Boundary(a.runner._share_selection)
                else:
                    setattr(a.boundary, name, lambda *args, **kwargs: self.fail("replacement callback reached"))
                with self.assertRaises(actions.BrowserActionRefused):
                    a.runner.create_share(selected)
                self.assertEqual(len(a.boundary.calls), 0)

    def test_ticket_expiry_after_observation_refuses_before_create(self):
        with admitted() as a:
            selected = a.parent.authorize_create_share(purpose="independent review", expires_at=a.clock() + 1,
                                                       consent=consent(a))
            def advance():
                a.clock.now += 2
            a.boundary.on_observe = advance
            with self.assertRaises(actions.BrowserActionRefused):
                a.runner.create_share(selected)
            self.assertEqual(len(a.boundary.calls), 0)

    def test_original_persisted_admission_is_rechecked_after_intent_callback(self):
        for field in ("admission_sha256", "request_id", "amount"):
            slot = []
            def substitute(event):
                if event["event"] != "invocation-intent":
                    return
                path = slot[0].ledger.root / "ledger.json"
                document = json.loads(path.read_bytes())
                attempt, = document["attempts"].values()
                if field == "amount":
                    attempt["amount"]["effect_calls"] = 2
                    attempt["charge"]["effect_calls"] = 2
                else:
                    attempt[field] = ("browser-action:" if field == "request_id" else "") + "f" * 64
                path.write_text(json.dumps(document), encoding="utf-8")
            with self.subTest(binding=field), admitted(observers=(substitute,)) as a:
                slot.append(a)
                selected = ticket(a)
                with self.assertRaises((actions.BrowserActionRefused, InvocationLedgerError)):
                    a.runner.create_share(selected)
                self.assertEqual(len(a.boundary.calls), 0)

    def test_known_wrong_preexisting_result_refuses_before_effect(self):
        with admitted() as a:
            selected = ticket(a)
            a.boundary.observation["existing_share"] = {"url": SHARE_URL, "document_id": "stale-document",
                "conversation_url": URL, "action_sha256": "f" * 64}
            with self.assertRaises(actions.BrowserActionRefused):
                a.runner.create_share(selected)
            self.assertEqual(len(a.boundary.calls), 0)

    def test_wrong_returned_or_observed_url_is_post_effect_unknown(self):
        for drift in ("returned", "observed", "document", "action", "exception"):
            with self.subTest(drift=drift), admitted() as a:
                selected = ticket(a)
                if drift == "returned":
                    a.boundary.returned = "https://chatgpt.com/share/wrong-result"
                elif drift == "observed":
                    a.boundary.result_url = "https://example.invalid/share/result"
                elif drift == "exception":
                    a.boundary.failure = RuntimeError(RESPONSE)
                else:
                    def change():
                        key = "document_id" if drift == "document" else "action_sha256"
                        a.boundary.observation["existing_share"][key] = "changed"
                    a.boundary.on_result = change
                with self.assertRaises(actions.BrowserActionRefused) as caught:
                    a.runner.create_share(selected)
                self.assertFalse(RESPONSE in str(caught.exception), "refusal disclosed response")
                self.assertEqual(len(a.boundary.calls), 1)
                attempt, = attempts(a)
                self.assertEqual(attempt["outcome"], "unknown")
                self.assertEqual(attempt["charge"], attempt["amount"])
                with self.assertRaises((actions.BrowserActionRefused, InvocationLedgerError)):
                    a.runner.create_share(selected)
                self.assertEqual(len(a.boundary.calls), 1)

    def test_share_action_replay_and_opaque_results(self):
        output = io.StringIO()
        with admitted() as a, redirect_stdout(output), redirect_stderr(output):
            selected = ticket(a)
            result = a.runner.create_share(selected)
            for replay in (selected, ticket(a)):
                with self.assertRaises((actions.BrowserActionRefused, InvocationLedgerError)):
                    a.runner.create_share(replay)
            self.assertEqual(len(a.boundary.calls), 1)
            rendered = output.getvalue() + repr(result) + repr(selected) + json.dumps(attempts(a))
            self.assertFalse(RESPONSE in rendered or PROMPT in rendered, "private disclosure escaped")


if __name__ == "__main__":
    unittest.main()
