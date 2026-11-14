"""Separate sharing consumer against rendered, networkless browser fixtures.

Playwright remains optional for ordinary test environments. Gate images supply
its pinned test dependency and distro Chromium; every page request is routed
or aborted and no account, external profile or network service is used.
"""
from __future__ import annotations

import contextlib
import copy
import base64
import hashlib
import html
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import chatgpt_browser_review as browser  # noqa: E402
from browser_action_dispatch import BrowserActionRefused, RegisteredBrowserParent  # noqa: E402
from cwo_core import audit  # noqa: E402
from cwo_core.invocation_ledger import InvocationLedger, InvocationLedgerError  # noqa: E402
from cwo_core.outbound_screen import require_clean  # noqa: E402
from tests import test_chatgpt_snapshot_dom as dom  # noqa: E402
from tests.browser_connected_fixture import packet_input  # noqa: E402
from tests.test_invocation_ledger import FakeClock, FakeOwners  # noqa: E402

REQUEST_ID = "0123456789abcdef0123456789abcdef"
PURPOSE = "independent offline review"
RESPONSE = "Synthetic private response café.\nKeep these two  spaces."
EARLIER = "Synthetic earlier private question."
SHARE_URL = "https://chatgpt.com/share/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
CONVERSATION_ID = "0123abcd-4567-89ef"
REFUSALS = (BrowserActionRefused, InvocationLedgerError, SystemExit)


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def digest(value):
    return hashlib.sha256(canonical(value).encode("utf-8")).hexdigest()


def conversation(submitted):
    return {"origin": "https://chatgpt.com", "conversation_id": CONVERSATION_ID, "purpose": PURPOSE,
            "messages": [{"message_id": "u0", "role": "user", "content": EARLIER},
                         {"message_id": "a0", "role": "assistant", "content": "Synthetic earlier answer."},
                         {"message_id": "u1", "role": "user", "content": submitted},
                         {"message_id": "a1", "role": "assistant", "content": RESPONSE}]}


def plaintext_turn(item):
    marker = dom.MARKER if item["role"] == "assistant" else ""
    return (f'<article data-testid="conversation-turn"><div data-message-author-role="{item["role"]}" '
            f'data-message-id="{item["message_id"]}"><pre>{html.escape(item["content"])}</pre></div>'
            f'{marker}</article>')


@unittest.skipUnless(dom.AVAILABLE, "Playwright and a Chromium executable are required")
class ShareDOMTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from playwright.sync_api import sync_playwright

        cls.playwright = sync_playwright().start()
        cls.browser = cls.playwright.chromium.launch(
            executable_path=dom.CHROMIUM, headless=True, args=["--disable-dev-shm-usage"])

    @classmethod
    def tearDownClass(cls):
        cls.browser.close()
        cls.playwright.stop()

    def setUp(self):
        self.page = self.browser.new_page()
        self.addCleanup(self.page.close)
        self.page.route("**/*", lambda route: route.abort())

    def open_conversation(self, selection):
        messages = "".join(plaintext_turn(item) for item in selection["messages"])
        body = f"""<!doctype html><html><head><meta charset="utf-8"></head><body>
<main data-cwo-offline-share-fixture="complete" data-conversation-id="{CONVERSATION_ID}"
      data-share-purpose="{PURPOSE}">{messages}</main>
<pre data-cwo-share-representation>{html.escape(canonical(selection))}</pre>
<textarea id="composer"></textarea><button data-testid="send-button" id="send">Send</button>
<button data-cwo-create-share id="create">Create share</button>
<button id="copy">Copy link</button><button id="social">Social</button>
<script>
window.__effects = {{create: 0, copy: 0, clipboard: 0, social: 0, send: 0}};
window.__nextShareURL = {json.dumps(SHARE_URL)};
document.getElementById('send').addEventListener('click', () => window.__effects.send++);
document.getElementById('copy').addEventListener('click', () => window.__effects.copy++);
document.getElementById('social').addEventListener('click', () => window.__effects.social++);
Object.defineProperty(navigator, 'clipboard', {{value: {{
  writeText: async () => {{window.__effects.clipboard++;}},
  readText: async () => {{window.__effects.clipboard++; return window.__nextShareURL;}}
}}}});
const execCommand = document.execCommand.bind(document);
document.execCommand = (command, ...args) => {{
  if (command === 'copy') window.__effects.clipboard++;
  return execCommand(command, ...args);
}};
window.open = () => {{ window.__effects.social++; return null; }};
document.getElementById('create').addEventListener('click', event => {{
  window.__effects.create++;
  const output = document.createElement('output');
  output.setAttribute('data-cwo-share-result', '');
  for (const attribute of ['data-document-id', 'data-conversation-url', 'data-action-sha256']) {{
    output.setAttribute(attribute, event.currentTarget.getAttribute(attribute));
  }}
  output.textContent = window.__nextShareURL;
  document.body.appendChild(output);
  if (window.__afterCreate) window.__afterCreate(output);
}});
</script></body></html>"""
        self.page.route(dom.CONVERSATION_URL, lambda route: route.fulfill(
            status=200, content_type="text/html; charset=utf-8", body=body))
        self.page.goto(dom.CONVERSATION_URL)

    def assert_effects(self, *, create=0):
        self.assertEqual(self.page.evaluate("window.__effects"),
                         {"create": create, "copy": 0, "clipboard": 0, "social": 0, "send": 0})

    def disclosure_digest(self):
        snapshot = self.page.evaluate(browser._SNAPSHOT_SCRIPT, [browser.DEFAULT_COMPLETION_MARKER_SELECTOR])
        representation = self.page.locator('[data-cwo-share-representation]').text_content()
        return digest({"url": snapshot["url"], "messages": snapshot["messages"], "representation": representation})

    def change_coverage(self, coverage):
        self.page.evaluate("value => document.querySelector('[data-cwo-offline-share-fixture]')"
                           ".setAttribute('data-cwo-offline-share-fixture', value)", coverage)

    def set_existing_share(self, url):
        self.page.evaluate("""value => {
          const output = document.createElement('output');
          output.setAttribute('data-cwo-share-result', '');
          output.textContent = value;
          document.body.appendChild(output);
        }""", url)

    def return_url(self, url):
        self.page.evaluate("value => { window.__nextShareURL = value; }", url)

    @contextlib.contextmanager
    def admitted(self, *, observers=(), earlier=EARLIER):
        """Original source, packet, parent and boundary; no guard is substituted."""
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            packet, args, log = packet_input(directory)
            sources = []
            with patch.object(audit, "AUDIT_LOG", log):
                prompt, metadata = browser.load_prompt_from_args(args, prepared_sources=sources)
            runner = browser.PlaywrightChatGPTRunner({"selectors": {"prompt_box": "#composer"}})
            runner.prepared_sources, runner.packet_metadata = tuple(sources), metadata
            submitted = browser.bound_request(prompt, REQUEST_ID)
            source, capture = runner._capture_submission_source(prompt)
            prepared = capture.bind(source, require_clean(submitted, surface="ChatGPT browser Send"))
            selection = conversation(submitted)
            selection["messages"][0]["content"] = earlier
            self.open_conversation(selection)
            boundary = browser.OfflineDOMShareBoundary(self.page)
            runner._action_submission = prepared, source, submitted, REQUEST_ID, 5000
            runner._action_limits = {"timeout_seconds": 60, "max_output_bytes": 4 * 1024 * 1024, "max_send_probes": 4}
            runner._share_selection = selection
            adapter = browser.BrowserRunnerAdapter(runner, share_boundary=boundary)
            clock = FakeClock()
            ledger = InvocationLedger(directory / "ledger", clock=clock, owner_probe=FakeOwners())
            parent = RegisteredBrowserParent(prepared, ledger=ledger, adapter=adapter, observers=observers,
                aggregate_scope={"aggregate_id": "offline-share-dom", "purpose": "browser-review"},
                aggregate_limits={"effect_calls": 8, "payload_bytes": 100_000_000,
                                  "output_bytes": 100_000_000, "runtime_milliseconds": 100_000_000})
            runner._action_parent = adapter.parent = parent
            runner._send_ticket = parent.issue_send(expires_at=clock() + 1000)
            adapter.ticket = runner._send_ticket
            yield SimpleNamespace(runner=runner, parent=parent, boundary=boundary, adapter=adapter,
                                  clock=clock, ledger=ledger, packet=packet, args=args, source=source,
                                  prepared=prepared, selection=selection, submitted=submitted, log=log)

    def consent(self, fixture):
        return fixture.parent.consent_to_share(purpose=PURPOSE, expires_at=fixture.clock() + 100)

    def ticket(self, fixture, consent):
        return fixture.parent.authorize_create_share(
            purpose=PURPOSE, expires_at=fixture.clock() + 100, consent=consent)

    def attempts(self, fixture):
        return list(json.loads((fixture.ledger.root / "ledger.json").read_bytes())["attempts"].values())

    def assert_private_failure(self, failure, fixture):
        rendered = str(failure) + repr(getattr(failure, "__notes__", []))
        self.assertFalse(RESPONSE in rendered)
        self.assertFalse(EARLIER in rendered)
        self.assertFalse(fixture.submitted in rendered)

    def assert_refused(self, fixture, operation):
        output, errors = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors), \
                self.assertRaises(REFUSALS) as caught:
            operation()
        self.assert_private_failure(caught.exception, fixture)
        self.assertFalse(RESPONSE in output.getvalue() + errors.getvalue())
        self.assertFalse(EARLIER in output.getvalue() + errors.getvalue())

    def test_exact_fresh_complete_disclosure_creates_once(self):
        with self.admitted() as fixture:
            observed = self.page.evaluate(browser._SNAPSHOT_SCRIPT, [browser.DEFAULT_COMPLETION_MARKER_SELECTOR])
            messages = [{"message_id": item["id"], "role": item["role"], "content": item["text"]}
                        for item in observed["messages"]]
            self.assertEqual(len(messages), 4)
            self.assertEqual(digest(messages), digest(fixture.selection["messages"]))
            ticket = self.ticket(fixture, self.consent(fixture))
            result = fixture.runner.create_share(ticket)
            self.assertEqual(result.status, "created")
            self.assertEqual(result.output_sha256, hashlib.sha256(SHARE_URL.encode("utf-8")).hexdigest())
            self.assertFalse(result.remote_usage_known)
            self.assert_private_failure(result, fixture)
            self.assert_refused(fixture, lambda: fixture.runner.create_share(ticket))
            self.assert_effects(create=1)
            attempt = self.attempts(fixture)[0]
            self.assertEqual(attempt["observed_usage"]["effect_calls"], 1)
            self.assertEqual(attempt["outcome"], "completed")

    def test_styled_div_pre_wrap_complete_disclosure_creates_once(self):
        with self.admitted() as fixture:
            before = self.disclosure_digest()
            self.page.evaluate("""() => {
              for (const pre of document.querySelectorAll('[data-message-author-role] > pre')) {
                const div = document.createElement('div');
                div.setAttribute('style', 'white-space: pre-wrap');
                div.textContent = pre.textContent;
                pre.replaceWith(div);
              }
            }""")
            self.assertEqual(self.disclosure_digest(), before)
            result = fixture.runner.create_share(self.ticket(fixture, self.consent(fixture)))
            self.assertEqual(result.status, "created")
            self.assertEqual(result.output_sha256, hashlib.sha256(SHARE_URL.encode("utf-8")).hexdigest())
            self.assert_effects(create=1)

    def test_unknown_or_additional_style_refuses_before_and_after_consent(self):
        for style in ("white-space: pre-wrap; color: red", "white-space: pre-wrap; --unknown: value", "white-space: normal"):
            for after_consent in (False, True):
                with self.subTest(style=style, after_consent=after_consent), self.admitted() as fixture:
                    ticket = self.ticket(fixture, self.consent(fixture)) if after_consent else None
                    self.page.evaluate("""style => {
                      const pre = document.querySelector('[data-message-author-role] > pre');
                      const div = document.createElement('div');
                      div.setAttribute('style', style);
                      div.textContent = pre.textContent;
                      pre.replaceWith(div);
                    }""", style)
                    operation = (lambda: fixture.runner.create_share(ticket)) if after_consent else lambda: self.consent(fixture)
                    self.assert_refused(fixture, operation)
                    self.assert_effects()

    def test_missing_copied_serialized_and_expired_consent_refuse(self):
        for kind in ("missing", "copied", "serialized", "expired"):
            with self.subTest(consent=kind), self.admitted() as fixture:
                consent = self.consent(fixture)
                if kind == "missing":
                    consent = None
                elif kind == "copied":
                    consent = copy.copy(consent)
                elif kind == "serialized":
                    consent = {"consent": True, "coverage": "complete", "success": True}
                else:
                    fixture.clock.now += 101
                self.assert_refused(fixture, lambda: self.ticket(fixture, consent))
                self.assert_effects()

    def test_earlier_insertion_edit_order_and_response_change_refuse(self):
        changes = {
            "earlier insertion": """() => {
              const first = document.querySelector('article');
              const added = first.cloneNode(true);
              added.querySelector('[data-message-id]').setAttribute('data-message-id', 'inserted');
              first.before(added);
            }""",
            "earlier edit": "() => { document.querySelector('[data-message-id=u0] pre').textContent += ' changed'; }",
            "response edit": "() => { document.querySelector('[data-message-id=a1] pre').textContent += ' changed'; }",
            "message order": "() => { document.querySelector('main').append(document.querySelector('article')); }",
            "missing earlier": "() => { document.querySelector('article').remove(); }",
        }
        for kind, script in changes.items():
            with self.subTest(change=kind), self.admitted() as fixture:
                ticket = self.ticket(fixture, self.consent(fixture))
                self.page.evaluate(script)
                self.assert_refused(fixture, lambda: fixture.runner.create_share(ticket))
                self.assert_effects()

    def test_wrong_conversation_and_reused_packet_new_conversation_refuse(self):
        with self.admitted() as fixture:
            ticket = self.ticket(fixture, self.consent(fixture))
            original_packet = fixture.runner.packet_metadata["packet_sha256"]
            self.page.evaluate("() => history.pushState({}, '', '/c/ffffffff-0000-1111')")
            self.assertEqual(fixture.runner.packet_metadata["packet_sha256"], original_packet)
            self.assert_refused(fixture, lambda: fixture.runner.create_share(ticket))
            self.assert_effects()

    def test_incomplete_coverage_cannot_issue_consent(self):
        with self.admitted() as fixture:
            self.change_coverage("unknown")
            self.assert_refused(fixture, lambda: self.consent(fixture))
            self.assert_effects()

    def test_lost_coverage_after_consent_has_zero_next_effect(self):
        with self.admitted() as fixture:
            ticket = self.ticket(fixture, self.consent(fixture))
            self.change_coverage("incomplete")
            self.assert_refused(fixture, lambda: fixture.runner.create_share(ticket))
            self.assert_effects()

    def test_opaque_earlier_content_refuses_even_when_plaintext_is_unchanged(self):
        for tag in ("img", "video", "audio", "iframe", "object", "input"):
            with self.subTest(surface=tag), self.admitted() as fixture:
                ticket = self.ticket(fixture, self.consent(fixture))
                before = self.disclosure_digest()
                self.page.evaluate("""tag => {
                  const element = document.createElement(tag);
                  if (tag === 'input') element.type = 'file';
                  document.querySelector('[data-message-id=u0]').appendChild(element);
                }""", tag)
                self.assertEqual(self.disclosure_digest(), before)
                self.assert_refused(fixture, lambda: fixture.runner.create_share(ticket))
                self.assert_effects()

    def test_stale_consent_after_ticket_has_zero_next_effect(self):
        with self.admitted() as fixture:
            ticket = self.ticket(fixture, self.consent(fixture))
            # The original action timeout caps consent freshness at 60 s;
            # the 100 s action ticket itself is still unexpired here.
            fixture.clock.now += 61
            self.assert_refused(fixture, lambda: fixture.runner.create_share(ticket))
            self.assert_effects()

    def test_far_future_consent_expiry_cannot_extend_freshness(self):
        with self.admitted() as fixture:
            consent = fixture.parent.consent_to_share(purpose=PURPOSE, expires_at=fixture.clock() + 100000)
            ticket = self.ticket(fixture, consent)
            fixture.clock.now += 61
            self.assert_refused(fixture, lambda: fixture.runner.create_share(ticket))
            self.assert_effects()

    def test_replaced_document_with_identical_content_refuses(self):
        with self.admitted() as fixture:
            ticket = self.ticket(fixture, self.consent(fixture))
            before = self.disclosure_digest()
            self.page.set_content(self.page.content())
            self.assertEqual(self.disclosure_digest(), before)
            self.assert_refused(fixture, lambda: fixture.runner.create_share(ticket))
            self.assert_effects()

    def test_intent_callback_document_replacement_has_zero_next_effect(self):
        callbacks = []

        def replace_document(event):
            if event["event"] == "invocation-intent":
                before = self.disclosure_digest()
                self.page.set_content(self.page.content())
                callbacks.append(self.disclosure_digest() == before)

        with self.admitted(observers=(replace_document,)) as fixture:
            ticket = self.ticket(fixture, self.consent(fixture))
            self.assert_refused(fixture, lambda: fixture.runner.create_share(ticket))
            self.assertEqual(callbacks, [True])
            self.assert_effects()

    def test_replaced_registered_callback_refuses_before_create(self):
        with self.admitted() as fixture:
            ticket = self.ticket(fixture, self.consent(fixture))
            fixture.boundary.create = lambda *args, **kwargs: self.fail("replacement callback reached")
            self.assert_refused(fixture, lambda: fixture.runner.create_share(ticket))
            self.assert_effects()

    def test_known_bad_share_url_has_zero_create_effects(self):
        for url in ("https://hostile.example/share/wrong", "https://chatgpt.com/share/unbound"):
            with self.subTest(supported_origin=url.startswith("https://chatgpt.com/")), self.admitted() as fixture:
                ticket = self.ticket(fixture, self.consent(fixture))
                self.set_existing_share(url)
                self.assert_refused(fixture, lambda: fixture.runner.create_share(ticket))
                self.assert_effects()

    def test_invalid_returned_url_is_charged_unknown_and_never_retried(self):
        with self.admitted() as fixture:
            ticket = self.ticket(fixture, self.consent(fixture))
            self.return_url("https://hostile.example/share/wrong")
            self.assert_refused(fixture, lambda: fixture.runner.create_share(ticket))
            self.assert_effects(create=1)
            attempt = self.attempts(fixture)[0]
            self.assertEqual(attempt["outcome"], "unknown")
            self.assertEqual(attempt["charge"], attempt["amount"])
            self.assert_refused(fixture, lambda: fixture.runner.create_share(ticket))
            self.assert_effects(create=1)

    def test_wrong_returned_conversation_or_action_is_unknown_and_no_next_effect(self):
        for attribute in ("data-conversation-url", "data-document-id", "data-action-sha256"):
            with self.subTest(binding=attribute), self.admitted() as fixture:
                ticket = self.ticket(fixture, self.consent(fixture))
                self.page.evaluate("""attribute => {
                  window.__afterCreate = output => output.setAttribute(attribute, 'wrong-binding');
                }""", attribute)
                self.assert_refused(fixture, lambda: fixture.runner.create_share(ticket))
                self.assert_effects(create=1)
                attempt = self.attempts(fixture)[0]
                self.assertEqual(attempt["outcome"], "unknown")
                self.assertEqual(attempt["charge"], attempt["amount"])
                self.assert_refused(fixture, lambda: fixture.runner.create_share(ticket))
                self.assert_effects(create=1)
    def test_request_and_source_drift_refuse_before_effect(self):
        for kind in ("packet", "request", "source", "purpose"):
            with self.subTest(binding=kind), self.admitted() as fixture:
                ticket = self.ticket(fixture, self.consent(fixture))
                if kind == "packet":
                    fixture.runner.packet_metadata["packet_sha256"] = "f" * 64
                elif kind == "request":
                    original = fixture.runner._action_submission
                    fixture.runner._action_submission = (*original[:3], "f" * 32, original[4])
                elif kind == "source":
                    fixture.runner.config["model_label"] = "changed offline model"
                else:
                    fixture.selection["purpose"] = "changed disclosure purpose"
                self.assert_refused(fixture, lambda: fixture.runner.create_share(ticket))
                self.assert_effects()

    def test_invalid_packet_refuses_before_send_or_share(self):
        with self.admitted() as fixture:
            packet_path = Path(fixture.args.packet)
            packet = json.loads(packet_path.read_bytes())
            packet["packet_sha256"] = "f" * 64
            packet_path.write_text(json.dumps(packet), encoding="utf-8")
            self.assert_refused(fixture, lambda: browser.load_prompt_from_args(fixture.args))
            self.assert_refused(fixture, lambda: fixture.runner._submit_prompt(
                self.page, fixture.submitted, 5000, REQUEST_ID,
                prepared=fixture.prepared, source=fixture.source))
            self.assert_effects()

    def test_decoded_earlier_message_is_screened_before_consent(self):
        secret = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
        encoded = base64.b64encode(secret.encode("ascii")).decode("ascii")
        for content in (secret, f"data:text/plain;base64,{encoded}"):
            with self.subTest(encoded=content != secret), self.admitted(earlier=content) as fixture:
                with self.assertRaises(REFUSALS) as caught:
                    self.consent(fixture)
                self.assert_private_failure(caught.exception, fixture)
                self.assertFalse(secret in str(caught.exception))
                self.assertFalse(encoded in str(caught.exception))
                self.assert_effects()


if __name__ == "__main__":
    unittest.main()
