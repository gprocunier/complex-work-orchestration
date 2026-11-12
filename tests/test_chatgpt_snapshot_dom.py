"""The browser snapshot script against offline DOM fixtures.

These tests run the real ``_SNAPSHOT_SCRIPT`` in headless Chromium through
Playwright, and drive a full capture against a page served from a Playwright
route, so no network, account or browser profile is involved. They are
skipped when Playwright or a Chromium executable is unavailable, as in the
default test environment.
"""

from __future__ import annotations

import importlib.util
import json
import shutil
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from chatgpt_browser_review import (  # noqa: E402
    DEFAULT_COMPLETION_MARKER_SELECTOR,
    PlaywrightChatGPTRunner,
    _SNAPSHOT_SCRIPT,
    bound_request,
)

CHROMIUM = next((found for found in map(shutil.which, ("chromium-browser", "chromium", "google-chrome")) if found), None)
AVAILABLE = importlib.util.find_spec("playwright") is not None and CHROMIUM is not None
CONVERSATION_URL = "https://chatgpt.com/c/0123abcd-4567-89ef"
MARKER = '<button data-testid="copy-turn-action-button" aria-label="Copy">Copy</button>'


def turn(role: str, message_id: str | None, text: str, *, marker: bool = False, container: str = "article") -> str:
    identity = f' data-message-id="{message_id}"' if message_id else ""
    body = f'<div data-message-author-role="{role}"{identity}><div style="white-space: pre-wrap">{text}</div></div>'
    actions = f"<div>{MARKER}</div>" if marker else ""
    if container == "article":
        return f'<article data-testid="conversation-turn">{body}{actions}</article>'
    return f'<div data-testid="conversation-turn-7">{body}{actions}</div>'


@unittest.skipUnless(AVAILABLE, "Playwright and a Chromium executable are required")
class SnapshotScriptTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        from playwright.sync_api import sync_playwright

        cls.playwright = sync_playwright().start()
        cls.browser = cls.playwright.chromium.launch(executable_path=CHROMIUM, headless=True, args=["--disable-dev-shm-usage"])

    @classmethod
    def tearDownClass(cls) -> None:
        cls.browser.close()
        cls.playwright.stop()

    def setUp(self) -> None:
        self.page = self.browser.new_page()
        self.addCleanup(self.page.close)

    def snapshot(self, body: str) -> dict:
        self.page.set_content(f"<!doctype html><html><body><nav></nav><main>{body}</main></body></html>")
        return self.page.evaluate(_SNAPSHOT_SCRIPT, [DEFAULT_COMPLETION_MARKER_SELECTOR])

    def marks(self, snapshot: dict) -> dict:
        return {item["id"]: item["marked"] for item in snapshot["messages"]}

    def test_marker_marks_only_its_own_turn(self) -> None:
        snapshot = self.snapshot(turn("user", "u1", "Question") + turn("assistant", "a1", "Answer", marker=True))
        self.assertEqual(self.marks(snapshot), {"u1": False, "a1": True})
        self.assertFalse(snapshot["stopping"])

    def test_marker_in_an_older_turn_does_not_mark_the_reply(self) -> None:
        body = (turn("user", "u0", "Old question") + turn("assistant", "a0", "Old answer", marker=True)
                + turn("user", "u1", "Question") + turn("assistant", "a1", "Partial answer"))
        self.assertEqual(self.marks(self.snapshot(body)), {"u0": False, "a0": True, "u1": False, "a1": False})

    def test_marker_outside_any_turn_marks_nothing(self) -> None:
        body = f"<aside>{MARKER}</aside>" + turn("user", "u1", "Question") + turn("assistant", "a1", "Answer")
        self.assertEqual(self.marks(self.snapshot(body)), {"u1": False, "a1": False})

    def test_messages_without_a_turn_container_are_never_marked(self) -> None:
        body = ('<div data-message-author-role="user" data-message-id="u1">Question</div>'
                '<div data-message-author-role="assistant" data-message-id="a1">Partial answer</div>' + MARKER)
        self.assertEqual(self.marks(self.snapshot(body)), {"u1": False, "a1": False})
        wrapped = '<section><div data-message-author-role="assistant" data-message-id="a1">Partial</div>' + MARKER + "</section>"
        self.assertEqual(self.marks(self.snapshot(wrapped)), {"a1": False})

    def test_a_turn_shared_by_two_messages_marks_neither(self) -> None:
        body = ('<article data-testid="conversation-turn"><div data-message-author-role="user" data-message-id="u1">Q</div>'
                '<div data-message-author-role="assistant" data-message-id="a1">Partial</div>' + MARKER + "</article>")
        self.assertEqual(self.marks(self.snapshot(body)), {"u1": False, "a1": False})

    def test_snapshot_reads_the_submission_stamp(self) -> None:
        self.assertIsNone(self.snapshot(turn("assistant", "a1", "Answer"))["stamp"])
        self.page.evaluate("() => { window.__cwoSubmission = 'f'.repeat(32); }")
        self.assertEqual(self.page.evaluate(_SNAPSHOT_SCRIPT, [DEFAULT_COMPLETION_MARKER_SELECTOR])["stamp"], "f" * 32)

    def test_missing_marker_leaves_the_reply_unmarked(self) -> None:
        self.assertEqual(self.marks(self.snapshot(turn("assistant", "a1", "Answer"))), {"a1": False})

    def test_turn_containers_other_than_article_are_recognised(self) -> None:
        body = turn("assistant", "a1", "Answer", marker=True, container="div") + turn("assistant", "a2", "Other", container="div")
        self.assertEqual(self.marks(self.snapshot(body)), {"a1": True, "a2": False})

    def test_generation_controls_mean_stopping(self) -> None:
        reply = turn("assistant", "a1", "Answer", marker=True)
        for control in ('<button aria-label="Stop streaming"></button>', '<button data-testid="stop-button"></button>',
                        '<div role="button">Stop generating</div>', '<button aria-label="Stop answering"></button>'):
            with self.subTest(control=control):
                self.assertTrue(self.snapshot(reply + control)["stopping"])
        for control in ('<button data-testid="send-button" aria-label="Send prompt"></button>', '<button>Stop</button>'):
            with self.subTest(control=control):
                self.assertFalse(self.snapshot(reply + control)["stopping"])

    def test_messages_keep_order_identity_and_exact_text(self) -> None:
        submitted = bound_request("Review this plan.\n\n    keep = 'two  spaces'", "0123456789abcdef0123456789abcdef")
        snapshot = self.snapshot(turn("user", "u1", submitted) + turn("assistant", None, "Answer"))
        messages = snapshot["messages"]
        self.assertEqual([(item["role"], item["id"]) for item in messages], [("user", "u1"), ("assistant", None)])
        self.assertEqual(PlaywrightChatGPTRunner._request_text(messages[0]["text"]), submitted)


# A minimal ChatGPT-like application: a composer, a send control enabled
# shortly after input, and a click handler that appends the user turn, moves a
# new chat to its conversation URL and then appends a finished reply. Every
# input and click is recorded in window.__events, so a test can show that a
# page received nothing. The look-alike copy keeps its send control enabled,
# as a hostile page would.
APP = """<!doctype html><html><body>
<main id="thread">%(before)s</main>
%(composer)s
<button data-testid="send-button" id="send" %(send)s>Send</button>
<script>
  window.__events = [];
  const composer = document.getElementById('composer');
  const send = document.getElementById('send');
  const read = () => composer.value !== undefined ? composer.value : composer.innerText;
  composer.addEventListener('input', () => {
    window.__events.push('input');
    if (window.__navigateOnInput) { location.href = window.__navigateOnInput; return; }
    setTimeout(() => { send.disabled = read().trim() === ''; }, 300);
  });
  send.addEventListener('click', () => {
    window.__events.push('click');
    const text = read();
    const user = document.createElement('article');
    user.setAttribute('data-testid', 'conversation-turn');
    user.innerHTML = '<div data-message-author-role="user" data-message-id="u1"><div style="white-space: pre-wrap"></div></div>';
    user.querySelector('div div').textContent = text;
    document.getElementById('thread').appendChild(user);
    if (composer.value !== undefined) composer.value = ''; else composer.textContent = '';
    setTimeout(() => {
      if (!location.pathname.startsWith('/c/')) history.pushState({}, '', '/c/aaaaaaaa-0000-1111');
    }, 100);
    setTimeout(() => {
      if (window.__replyHtml === undefined) return;
      document.getElementById('thread').insertAdjacentHTML('beforeend', window.__replyHtml);
    }, 300);
  });
</script></body></html>"""
# A hostile page that tampers with the prototypes a script receiving arguments
# would touch, recording every string that passes through them.
HOSTILE = """<script>
  window.__captured = [];
  const keep = (value) => { if (typeof value === 'string') window.__captured.push(value); };
  const keepAll = (list) => { for (let i = 0; i < list.length; i++) keep(list[i]); };
  const iterate = Array.prototype[Symbol.iterator];
  Array.prototype[Symbol.iterator] = function () { keepAll(this); return iterate.call(this); };
  for (const name of ['includes', 'indexOf', 'slice', 'map', 'forEach', 'concat', 'join']) {
    const original = Array.prototype[name];
    Array.prototype[name] = function (...args) { keepAll(this); keepAll(args); return name === 'includes' ? true : original.apply(this, args); };
  }
  const stringIncludes = String.prototype.includes;
  String.prototype.includes = function (search) { keep(String(this)); keep(search); return true; };
  const stringify = JSON.stringify;
  JSON.stringify = function (value, ...rest) { const text = stringify.call(JSON, value, ...rest); keep(text); return text; };
</script>"""
REPLY = turn("assistant", "a1", "Findings: add a key.", marker=True)
TEXTAREA = '<textarea id="composer"></textarea>'
EDITABLE = '<div id="composer" contenteditable="true"></div>'


@unittest.skipUnless(AVAILABLE, "Playwright and a Chromium executable are required")
class OfflineSubmissionTests(unittest.TestCase):
    """Submission, pinning and capture against pages served from Playwright routes."""

    REQUEST_ID = "0123456789abcdef0123456789abcdef"

    @classmethod
    def setUpClass(cls) -> None:
        from playwright.sync_api import sync_playwright

        cls.playwright = sync_playwright().start()
        cls.browser = cls.playwright.chromium.launch(executable_path=CHROMIUM, headless=True, args=["--disable-dev-shm-usage"])

    @classmethod
    def tearDownClass(cls) -> None:
        cls.browser.close()
        cls.playwright.stop()

    def setUp(self) -> None:
        self.page = self.browser.new_page()
        self.addCleanup(self.page.close)
        before = turn("user", "u0", "Earlier question") + turn("assistant", "a0", "Earlier answer", marker=True)
        self.composer = TEXTAREA
        self.page.route("https://chatgpt.com/**", lambda route: route.fulfill(
            status=200, content_type="text/html", body=APP % {"before": before, "composer": self.composer, "send": "disabled"}))
        self.page.route("https://chatgpt.com.example/**", lambda route: route.fulfill(
            status=200, content_type="text/html", body=APP % {"before": "", "composer": self.composer, "send": ""}))
        self.page.route("https://hostile.example/**", lambda route: route.fulfill(
            status=200, content_type="text/html", body=HOSTILE + APP % {"before": "", "composer": self.composer, "send": ""}))
        self.runner = PlaywrightChatGPTRunner({"selectors": {"prompt_box": "#composer"}})
        self.submitted = bound_request("Review this plan.", self.REQUEST_ID)

    def open(self, url: str, *, reply: str | None = REPLY) -> dict:
        self.page.goto(url)
        if reply is not None:
            self.page.evaluate("(html) => { window.__replyHtml = html; }", reply)
        return self.runner._message_snapshot(self.page)

    def submit_and_capture(self, url: str, *, reply: str | None = REPLY) -> dict:
        before = self.open(url, reply=reply)
        self.runner._submit_prompt(self.page, self.submitted, 5000, self.REQUEST_ID)
        pinned = self.runner._pin_conversation(self.page, self.REQUEST_ID, before["url"], 5000)
        self.page.wait_for_timeout(500)
        return self.runner._capture_assistant_response(self.page, "", "", before_messages=before, prompt=self.submitted,
                                                       request_id=self.REQUEST_ID, before_url=before["url"],
                                                       pinned_conversation_id=pinned)

    def test_submission_in_an_open_conversation_is_a_complete_capture(self) -> None:
        captured = self.submit_and_capture(CONVERSATION_URL)
        self.assertTrue(captured["capture_complete"], json.dumps(captured["checks"]))
        self.assertEqual((captured["text"], captured["user_message_id"], captured["message_id"]), ("Findings: add a key.", "u1", "a1"))
        self.assertEqual(captured["conversation_id"], "0123abcd-4567-89ef")
        self.assertEqual(self.page.evaluate("window.__events"), ["input", "click"])

    def test_submission_from_a_new_chat_pins_the_conversation_it_creates(self) -> None:
        captured = self.submit_and_capture("https://chatgpt.com/")
        self.assertTrue(captured["capture_complete"], json.dumps(captured["checks"]))
        self.assertEqual(captured["conversation_id"], "aaaaaaaa-0000-1111")

    def test_nothing_is_typed_or_sent_on_another_origin(self) -> None:
        self.open("https://chatgpt.com.example/")
        with self.assertRaises(SystemExit) as raised:
            self.runner._submit_prompt(self.page, self.submitted, 2000, self.REQUEST_ID)
        self.assertIn("not on a ChatGPT origin", str(raised.exception))
        self.assertEqual(self.page.evaluate("window.__events"), [])
        self.assertEqual(self.page.evaluate("document.getElementById('composer').innerText"), "")

    def test_hostile_page_script_never_sees_the_prompt(self) -> None:
        self.open("https://hostile.example/")
        with self.assertRaises(SystemExit) as raised:
            self.runner._submit_prompt(self.page, self.submitted, 2000, self.REQUEST_ID)
        self.assertIn("not on a ChatGPT origin", str(raised.exception))
        captured = self.page.evaluate("JSON.parse(JSON.stringify({values: window.__captured})).values")
        self.assertFalse([value for value in captured if "Review this plan" in value or self.REQUEST_ID in value], captured[-5:])
        self.assertEqual(self.page.evaluate("window.__events"), [])
        self.assertEqual(self.page.evaluate("document.getElementById('composer').value"), "")
        # Positive control: a script destructuring an array argument here is observed.
        self.page.evaluate("([secret]) => secret.length", ["probe-secret"])
        self.assertIn("probe-secret", self.page.evaluate("JSON.parse(JSON.stringify({values: window.__captured})).values"))

    def test_navigation_between_insertion_and_send_sends_nothing(self) -> None:
        self.open(CONVERSATION_URL)
        self.page.evaluate("() => { window.__navigateOnInput = 'https://chatgpt.com.example/'; }")
        with self.assertRaises(SystemExit) as raised:
            self.runner._submit_prompt(self.page, self.submitted, 3000, self.REQUEST_ID)
        self.assertIn("the prompt was not sent", str(raised.exception))
        self.page.wait_for_url("https://chatgpt.com.example/**")
        self.page.wait_for_timeout(500)
        self.assertEqual(self.page.evaluate("window.__events"), [], "the replacing document received no input and no click")

    def test_contenteditable_composer_receives_the_text_in_its_own_document(self) -> None:
        self.composer = EDITABLE
        self.open(CONVERSATION_URL)
        self.runner._submit_prompt(self.page, self.submitted, 5000, self.REQUEST_ID)
        events = self.page.evaluate("window.__events")
        self.assertEqual((events[-1], events.count("click")), ("click", 1))
        self.assertIn("input", events)
        sent = self.page.evaluate("document.querySelector('[data-message-id=u1]').innerText")
        # The editor's own line handling decides the exact whitespace; the words arrive intact.
        self.assertEqual(sent.split(), self.submitted.split())

    def test_reply_still_generating_is_incomplete(self) -> None:
        captured = self.submit_and_capture(
            CONVERSATION_URL, reply=REPLY + '<button data-testid="stop-button" aria-label="Stop streaming"></button>')
        self.assertFalse(captured["capture_complete"])
        self.assertIn("completion_confirmed", captured["incomplete_reasons"])

    def test_reply_without_its_own_marker_is_incomplete(self) -> None:
        captured = self.submit_and_capture(CONVERSATION_URL, reply=turn("assistant", "a1", "Findings: add"))
        self.assertFalse(captured["capture_complete"])
        self.assertIn("completion_confirmed", captured["incomplete_reasons"])

    def test_reply_in_a_replaced_document_is_incomplete(self) -> None:
        before = self.open(CONVERSATION_URL)
        self.runner._submit_prompt(self.page, self.submitted, 5000, self.REQUEST_ID)
        pinned = self.runner._pin_conversation(self.page, self.REQUEST_ID, before["url"], 5000)
        # A full reload of the same conversation drops the submission stamp.
        self.page.goto(CONVERSATION_URL)
        self.page.evaluate("(html) => document.getElementById('thread').insertAdjacentHTML('beforeend', html)",
                           turn("user", "u1", self.submitted) + REPLY)
        captured = self.runner._capture_assistant_response(self.page, "", "", before_messages=before, prompt=self.submitted,
                                                           request_id=self.REQUEST_ID, before_url=before["url"],
                                                           pinned_conversation_id=pinned)
        self.assertFalse(captured["capture_complete"])
        self.assertIn("conversation_stable", captured["incomplete_reasons"])


if __name__ == "__main__":
    unittest.main()
