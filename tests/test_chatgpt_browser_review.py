from __future__ import annotations

import json
import re
import contextlib
import io
import os
import subprocess
import stat
import sys
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import chatgpt_browser_review  # noqa: E402
from chatgpt_browser_review import (  # noqa: E402
    ChatGPTBrowserReviewError,
    DEFAULT_SCROLL_TO_BOTTOM_SELECTOR,
    DEFAULT_MODEL_LABEL,
    DEFAULT_REASONING_LABEL,
    EXECUTOR_KEY,
    PlaywrightChatGPTRunner,
    bound_request,
    build_result,
    config_summary,
    enforce_prompt_size,
    extract_chatgpt_share_url,
    load_browser_config,
    load_prompt_from_args,
    main as chatgpt_browser_main,
    resolve_response_dir,
    valid_chatgpt_share_url,
    write_private_response,
)
from build_contractor_packet import build_packet  # noqa: E402
import cwo_core.audit as audit_lib  # noqa: E402


from chatgpt_browser_review import CONVERSATION_ID_RE  # noqa: E402
from urllib.parse import urlparse  # noqa: E402


def setUpModule() -> None:
    # These tests exercise live browser dispatch with fake pages and runners;
    # the route itself is disabled in shipped code until issue #41 is resolved.
    global _ROUTE_PATCH
    _ROUTE_PATCH = patch.object(chatgpt_browser_review, "BROWSER_DISPATCH_AVAILABLE", True)
    _ROUTE_PATCH.start()


def tearDownModule() -> None:
    _ROUTE_PATCH.stop()


class _ShareFixtureClock:
    """Scripted fake-page elapsed time, including sleeps and explicit pauses."""

    def __init__(self, pauses_before_reads: dict[int, float] | None = None) -> None:
        self.now = 0.0
        self.reads = 0
        self.sleeps: list[float] = []
        self.pauses_before_reads = dict(pauses_before_reads or {})

    def monotonic(self) -> float:
        self.reads += 1
        self.now += self.pauses_before_reads.get(self.reads, 0.0)
        return self.now

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += seconds


class ChatGPTBrowserReviewTests(unittest.TestCase):
    def write_config(self, directory: Path, mode: int = 0o600) -> Path:
        path = directory / "chatgpt-browser.json"
        path.write_text(
            json.dumps(
                {
                    "chrome_user_data_dir": str(directory / "profile"),
                    "model_label": "ChatGPT Pro 5.5",
                    "reasoning_label": "Extended Reasoning",
                }
            ),
            encoding="utf-8",
        )
        os.chmod(path, mode)
        return path

    def write_confirmation_config(self, directory: Path, mode: int = 0o600) -> Path:
        path = self.write_config(directory, mode=mode)
        data = json.loads(path.read_text(encoding="utf-8"))
        data["selectors"] = {
            "model_label_confirmation_selector": "[data-testid='model-switcher']",
            "reasoning_label_confirmation_selector": "[data-testid='reasoning-switcher']",
        }
        path.write_text(json.dumps(data), encoding="utf-8")
        os.chmod(path, mode)
        return path

    def test_config_summary_does_not_include_profile_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = self.write_config(Path(tmpdir))
            config = load_browser_config(path)
            summary = config_summary(config, path)
        rendered = json.dumps(summary, sort_keys=True)
        self.assertTrue(summary["config_present"])
        self.assertTrue(summary["config_external_to_repo"])
        self.assertTrue(summary["chrome_user_data_dir_configured"])
        self.assertEqual(summary["clipboard_fallback"], "removed")
        self.assertEqual(summary["share_creation"], "unavailable")
        self.assertFalse(summary["share_link_required"])
        self.assertTrue(summary["require_model_confirmation"])
        self.assertFalse(summary["model_confirmation_configured"])
        self.assertEqual(
            summary["model_confirmation_missing_selectors"],
            ["model_label_confirmation_selector", "reasoning_label_confirmation_selector"],
        )
        self.assertNotIn(str(path), rendered)
        self.assertNotIn(str(Path(tmpdir)), rendered)
        self.assertNotIn(str(Path(tmpdir) / "profile"), rendered)

    def test_playwright_cleanup_keeps_completed_result_on_python314_loop_error(self) -> None:
        class CleanupRaises:
            def stop(self) -> None:
                raise RuntimeError("This event loop is already running")

        runner = PlaywrightChatGPTRunner({"selectors": {}, "local_clipboard_fallback": False})
        runner._stop_playwright(CleanupRaises())

    def test_playwright_cleanup_preserves_unexpected_runtime_errors(self) -> None:
        class CleanupRaises:
            def stop(self) -> None:
                raise RuntimeError("transport failed")

        runner = PlaywrightChatGPTRunner({"selectors": {}, "local_clipboard_fallback": False})
        with self.assertRaises(RuntimeError):
            runner._stop_playwright(CleanupRaises())

    def test_config_summary_reports_confirmation_selectors(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = self.write_config(Path(tmpdir))
            data = json.loads(path.read_text(encoding="utf-8"))
            data["selectors"] = {
                "model_label_confirmation_selector": "[data-testid='model-switcher']",
                "reasoning_label_confirmation_selector": "[data-testid='reasoning-switcher']",
            }
            path.write_text(json.dumps(data), encoding="utf-8")
            config = load_browser_config(path)
            summary = config_summary(config, path)
        self.assertTrue(summary["model_confirmation_configured"])

    def test_config_null_model_labels_default_to_required_labels(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            path = self.write_config(tmp)
            data = json.loads(path.read_text(encoding="utf-8"))
            data["model_label"] = None
            data["reasoning_label"] = ""
            path.write_text(json.dumps(data), encoding="utf-8")
            config = load_browser_config(path)
        self.assertEqual(config["model_label"], DEFAULT_MODEL_LABEL)
        self.assertEqual(config["reasoning_label"], DEFAULT_REASONING_LABEL)
        self.assertTrue(config["require_model_confirmation"])

    def test_browser_config_refusal_variants(self) -> None:
        variants = (
            ('test_config_rejects_credential_fields', 'google_password', 'not-a-real-password'),
            ('test_config_rejects_remote_cdp_attach_url', 'connect_over_cdp_url', 'http://example.com:9222'),
        )
        for original, field, value in variants:
            with self.subTest(original=original):
                with tempfile.TemporaryDirectory() as tmpdir:
                    tmp = Path(tmpdir)
                    path = self.write_config(tmp)
                    data = json.loads(path.read_text(encoding="utf-8"))
                    data[field] = value
                    path.write_text(json.dumps(data), encoding="utf-8")
                    with self.assertRaises(SystemExit):
                        load_browser_config(path)

    def test_config_accepts_local_cdp_attach_url(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            path = self.write_config(tmp)
            data = json.loads(path.read_text(encoding="utf-8"))
            data["connect_over_cdp_url"] = "http://127.0.0.1:9222"
            path.write_text(json.dumps(data), encoding="utf-8")
            config = load_browser_config(path)
            summary = config_summary(config, path)
        self.assertEqual(config["connect_over_cdp_url"], "http://127.0.0.1:9222")
        self.assertTrue(summary["connect_over_cdp_configured"])
        self.assertNotIn("127.0.0.1:9222", json.dumps(summary))


    def test_config_rejects_group_or_world_access(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = self.write_config(Path(tmpdir), mode=0o644)
            with self.assertRaises(SystemExit):
                load_browser_config(path)

    def test_config_rejects_repo_local_file(self) -> None:
        path = ROOT / "tmp-chatgpt-browser-test.json"
        try:
            path.write_text(json.dumps({"chrome_user_data_dir": "/tmp/cwo-profile"}), encoding="utf-8")
            os.chmod(path, 0o600)
            with self.assertRaises(SystemExit):
                load_browser_config(path)
        finally:
            path.unlink(missing_ok=True)

    def test_prompt_size_guard_rejects_oversized_browser_prompt(self) -> None:
        with self.assertRaises(SystemExit) as context:
            enforce_prompt_size("x" * 51, {"max_prompt_chars": 50})
        self.assertIn("Build a compact packet", str(context.exception))

    def test_dry_run_audit_records_sanitized_browser_telemetry(self) -> None:
        original_audit = audit_lib.AUDIT_LOG
        original_argv = sys.argv[:]
        prompt_path = ROOT / "tmp-chatgpt-browser-prompt-test.md"
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            config_path = self.write_confirmation_config(tmp)
            audit_lib.AUDIT_LOG = tmp / "audit.jsonl"
            prompt_path.write_text("Review this bounded packet.", encoding="utf-8")
            try:
                sys.argv = [
                    "chatgpt_browser_review.py",
                    "--prompt-file",
                    str(prompt_path),
                    "--config",
                    str(config_path),
                    "--dispatch-id",
                    "dispatch-browser-dry-run",
                    "--bead",
                    "cwo-browser",
                    "--packet-sha256",
                    "abc123",
                    "--allow-degraded-packet",
                    "--allow-unlinked-packet",
                    "--waiver-reason",
                    "test browser rehearsal",
                    "--rehearsal",
                    "--dry-run",
                    "--json",
                ]
                with contextlib.redirect_stdout(io.StringIO()):
                    chatgpt_browser_main()
                events = [json.loads(line) for line in audit_lib.AUDIT_LOG.read_text(encoding="utf-8").splitlines()]
                self.assertEqual(events[0]["event_type"], "chatgpt_browser_dispatch")
                self.assertEqual(events[0]["telemetry_kind"], "browser_rehearsal")
                self.assertEqual(events[0]["agent_model_calls"], 0)
                self.assertEqual(events[0]["model_label"], "ChatGPT Pro 5.5")
                self.assertTrue(events[0]["waiver_required"])
                self.assertEqual(
                    events[0]["waiver_flags"],
                    ["--allow-degraded-packet", "--allow-unlinked-packet"],
                )
                self.assertEqual(events[0]["waiver_reason"], "test browser rehearsal")
                self.assertEqual(events[0]["prompt_chars"], len("Review this bounded packet."))
                self.assertNotIn("prompt", events[0])
                self.assertNotIn("share_url", events[0])
            finally:
                audit_lib.AUDIT_LOG = original_audit
                sys.argv = original_argv
                prompt_path.unlink(missing_ok=True)

    def test_valid_chatgpt_share_url_accepts_share_shapes(self) -> None:
        self.assertTrue(valid_chatgpt_share_url("https://chatgpt.com/s/t_abc"))
        self.assertTrue(valid_chatgpt_share_url("https://chatgpt.com/share/abc"))
        self.assertFalse(valid_chatgpt_share_url("https://example.com/s/t_abc"))

    def test_extract_chatgpt_share_url_accepts_embedded_and_encoded_urls(self) -> None:
        self.assertEqual(
            extract_chatgpt_share_url("Copied: https://chatgpt.com/s/t_abc."),
            "https://chatgpt.com/s/t_abc",
        )
        social = "https://x.com/intent/tweet?url=https%3A%2F%2Fchatgpt.com%2Fs%2Ft_abc&text=Review"
        self.assertEqual(extract_chatgpt_share_url(social), "https://chatgpt.com/s/t_abc")

    def test_social_intent_parser_extracts_chatgpt_share_url(self) -> None:
        runner = PlaywrightChatGPTRunner({"selectors": {}, "local_clipboard_fallback": False})
        value = "https://twitter.com/intent/tweet?url=https%3A%2F%2Fchatgpt.com%2Fs%2Ft_abc"
        self.assertEqual(runner._share_url_from_social_intent(value), "https://chatgpt.com/s/t_abc")

    def test_create_share_link_does_not_read_clipboard(self) -> None:
        class FakeLocator:
            def click(self, timeout: int, force: bool = False) -> None:
                return None

            @property
            def first(self) -> "FakeLocator":
                return self

            def evaluate(self, script: str) -> bool:
                return True

            def input_value(self, timeout: int) -> str:
                raise RuntimeError("no input")

            def get_attribute(self, name: str, timeout: int) -> str | None:
                return None

        class FakePage:
            def __init__(self) -> None:
                self.evaluated = False

            def locator(self, selector: str) -> FakeLocator:
                return FakeLocator()

            def evaluate(self, script: str) -> str:
                self.evaluated = True
                raise AssertionError("clipboard read should not be attempted")

        page = FakePage()
        runner = PlaywrightChatGPTRunner({"selectors": {}, "local_clipboard_fallback": False})
        clock = _ShareFixtureClock()
        with patch.object(chatgpt_browser_review, "time", clock):
            self.assertEqual(runner._create_share_link(page, 1, TimeoutError), "")
        self.assertFalse(page.evaluated)

    def test_create_share_link_clicks_scroll_to_bottom_before_share(self) -> None:
        class FakeLocator:
            def __init__(self, page: "FakePage", selector: str) -> None:
                self.page = page
                self.selector = selector

            @property
            def first(self) -> "FakeLocator":
                return self

            def click(self, timeout: int, force: bool = False) -> None:
                self.page.clicks.append(self.selector)
                self.page.click_timeouts.append(timeout)

            def evaluate(self, script: str) -> bool:
                return True

            def input_value(self, timeout: int) -> str:
                raise RuntimeError("no input")

            def get_attribute(self, name: str, timeout: int) -> str | None:
                return None

        class FakePage:
            def __init__(self) -> None:
                self.clicks: list[str] = []
                self.click_timeouts: list[int] = []

            def locator(self, selector: str) -> FakeLocator:
                return FakeLocator(self, selector)

        page = FakePage()
        runner = PlaywrightChatGPTRunner(
            {
                "selectors": {
                    "scroll_to_bottom_button": "button[aria-label='Jump to latest']",
                    "share_button": "button[aria-label='Share']",
                },
                "local_clipboard_fallback": False,
            }
        )
        clock = _ShareFixtureClock()
        with patch.object(chatgpt_browser_review, "time", clock):
            self.assertEqual(runner._create_share_link(page, 1, TimeoutError), "")
        self.assertEqual(page.clicks[:2], ["button[aria-label='Jump to latest']", "button[aria-label='Jump to latest']"])
        self.assertIn("button[aria-label='Share']", page.clicks)
        self.assertEqual(page.click_timeouts, [750, 750, 750, 1])
        self.assertEqual(clock.sleeps, [0.5, 0.5, 0.5])

    def _share_readiness_page(self, *, disabled: bool = False):
        class Locator:
            def __init__(self, page, selector):
                self.page, self.selector = page, selector

            @property
            def first(self):
                return self

            def click(self, timeout, force=False):
                self.page.clicks.append((self.selector, timeout))

            def is_visible(self):
                return True

            def is_disabled(self):
                return disabled and self.selector == "share"

            def evaluate(self, script):
                return True

            def input_value(self, timeout):
                raise RuntimeError("EXAMPLE no share URL input")

            def get_attribute(self, name, timeout):
                return None

        class Page:
            def __init__(self):
                self.clicks = []
                self.share_probes = 0

            def locator(self, selector):
                if selector == "share":
                    self.share_probes += 1
                return Locator(self, selector)

        return Page()

    def test_share_readiness_disabled_button_expires_with_scripted_sleep(self) -> None:
        page = self._share_readiness_page(disabled=True)
        runner = PlaywrightChatGPTRunner({"selectors": {
            "scroll_to_bottom_button": "scroll", "share_button": "share"}})
        clock = _ShareFixtureClock()
        with patch.object(chatgpt_browser_review, "time", clock), self.assertRaisesRegex(
            SystemExit, "ChatGPT share button did not become ready before timeout"
        ):
            runner._create_share_link(page, 1, TimeoutError)
        self.assertEqual(page.clicks, [("scroll", 750), ("scroll", 750)])
        self.assertEqual(page.share_probes, 1)
        self.assertEqual(clock.sleeps, [0.5, 0.5, 1])
        self.assertEqual(clock.now, 2.0)

    def test_share_readiness_exact_deadline_expires_before_first_ready_probe(self) -> None:
        page = self._share_readiness_page()
        runner = PlaywrightChatGPTRunner({"selectors": {
            "scroll_to_bottom_button": "scroll", "share_button": "share"}})
        clock = _ShareFixtureClock({2: 0.001})
        with patch.object(chatgpt_browser_review, "time", clock), self.assertRaisesRegex(
            SystemExit, "ChatGPT share button did not become ready before timeout"
        ):
            runner._create_share_link(page, 1, TimeoutError)
        self.assertEqual(page.clicks, [("scroll", 750)])
        self.assertEqual(page.share_probes, 0)
        self.assertEqual(clock.reads, 2)
        self.assertEqual(clock.sleeps, [0.5])
        self.assertEqual(clock.now, 0.501)

    def test_default_scroll_selector_includes_unlabeled_floating_button(self) -> None:
        self.assertIn(
            "button[aria-hidden='true'][tabindex='-1'].btn-secondary",
            DEFAULT_SCROLL_TO_BOTTOM_SELECTOR,
        )

    def test_click_share_button_prefers_visible_response_share_control(self) -> None:
        class FakeShareButton:
            def __init__(
                self, page: "FakePage", name: str, *, aria_label: str = "", data_testid: str = "", rect: tuple[int, int, int, int] = (0, 0, 10, 10)
            ) -> None:
                self.page = page
                self.name = name
                self.aria_label = aria_label
                self.data_testid = data_testid
                self.rect = rect

            def is_visible(self) -> bool:
                return True

            def click(self, timeout: int, force: bool = False) -> None:
                self.page.clicked.append(self.name)

            def get_attribute(self, name: str, timeout: int = 0) -> str | None:
                if name == "aria-label":
                    return self.aria_label
                if name == "data-testid":
                    return self.data_testid
                return ""

            def evaluate(self, script: str) -> bool:
                x, y, w, h = self.rect
                return w > 0 and h > 0 and x < 1000 and x + w > 0 and y < 600 and y + h > 0

        class FakeShareLocator:
            def __init__(self, buttons: list[FakeShareButton]) -> None:
                self.buttons = buttons

            @property
            def first(self) -> "FakeShareButton":
                return self.buttons[0]

            def count(self) -> int:
                return len(self.buttons)

            def nth(self, index: int) -> FakeShareButton:
                return self.buttons[index]

        class FakePage:
            def __init__(self) -> None:
                self.clicked: list[str] = []
                self.locator_buttons = [
                    FakeShareButton(self, "conversation", data_testid="share-chat-button"),
                    FakeShareButton(self, "response", aria_label="Share"),
                ]

            def locator(self, selector: str) -> FakeShareLocator:
                return FakeShareLocator(self.locator_buttons)

        page = FakePage()
        runner = PlaywrightChatGPTRunner({"selectors": {}, "local_clipboard_fallback": False})
        runner._click_share_button(page, 1, TimeoutError)
        self.assertEqual(page.clicked, ["response"])

    def test_click_share_button_falls_back_to_conversation_share_when_response_share_not_visible(self) -> None:
        class FakeShareButton:
            def __init__(
                self,
                page: "FakePage",
                name: str,
                *,
                aria_label: str = "",
                data_testid: str = "",
                rect: tuple[int, int, int, int] = (0, 0, 10, 10),
            ) -> None:
                self.page = page
                self.name = name
                self.aria_label = aria_label
                self.data_testid = data_testid
                self.rect = rect

            def is_visible(self) -> bool:
                return True

            def click(self, timeout: int, force: bool = False) -> None:
                self.page.clicked.append(self.name)

            def get_attribute(self, name: str, timeout: int = 0) -> str | None:
                if name == "aria-label":
                    return self.aria_label
                if name == "data-testid":
                    return self.data_testid
                return ""

            def evaluate(self, script: str) -> bool:
                x, y, w, h = self.rect
                return w > 0 and h > 0 and x < 1000 and x + w > 0 and y < 600 and y + h > 0

        class FakeShareLocator:
            def __init__(self, buttons: list[FakeShareButton]) -> None:
                self.buttons = buttons

            @property
            def first(self) -> FakeShareButton:
                return self.buttons[0]

            def count(self) -> int:
                return len(self.buttons)

            def nth(self, index: int) -> FakeShareButton:
                return self.buttons[index]

        class FakePage:
            def __init__(self) -> None:
                self.clicked: list[str] = []
                self.locator_buttons = [
                    FakeShareButton(self, "conversation", data_testid="share-chat-button", rect=(0, 0, 10, 10)),
                    FakeShareButton(self, "response", aria_label="Share", rect=(0, 2000, 10, 10)),
                ]

            def locator(self, selector: str) -> FakeShareLocator:
                return FakeShareLocator(self.locator_buttons)

        page = FakePage()
        runner = PlaywrightChatGPTRunner({"selectors": {}, "local_clipboard_fallback": False})
        runner._click_share_button(page, 1, TimeoutError)
        self.assertEqual(page.clicked, ["conversation"])

    def test_click_share_button_prefers_viewport_response_share_over_offscreen_response_share(self) -> None:
        class FakeShareButton:
            def __init__(
                self,
                page: "FakePage",
                name: str,
                *,
                aria_label: str = "",
                data_testid: str = "",
                rect: tuple[int, int, int, int] = (0, 0, 10, 10),
            ) -> None:
                self.page = page
                self.name = name
                self.aria_label = aria_label
                self.data_testid = data_testid
                self.rect = rect

            def is_visible(self) -> bool:
                return True

            def click(self, timeout: int, force: bool = False) -> None:
                self.page.clicked.append(self.name)

            def get_attribute(self, name: str, timeout: int = 0) -> str | None:
                if name == "aria-label":
                    return self.aria_label
                if name == "data-testid":
                    return self.data_testid
                return ""

            def evaluate(self, script: str) -> bool:
                x, y, w, h = self.rect
                return w > 0 and h > 0 and x < 1000 and x + w > 0 and y < 600 and y + h > 0

        class FakeShareLocator:
            def __init__(self, buttons: list[FakeShareButton]) -> None:
                self.buttons = buttons

            @property
            def first(self) -> FakeShareButton:
                return self.buttons[0]

            def count(self) -> int:
                return len(self.buttons)

            def nth(self, index: int) -> FakeShareButton:
                return self.buttons[index]

        class FakePage:
            def __init__(self) -> None:
                self.clicked: list[str] = []
                self.locator_buttons = [
                    FakeShareButton(self, "conversation", data_testid="share-chat-button", rect=(0, 0, 10, 10)),
                    FakeShareButton(
                        self,
                        "response-offscreen",
                        aria_label="Share",
                        rect=(0, 2000, 10, 10),
                    ),
                    FakeShareButton(self, "response-viewport", aria_label="Share", rect=(0, 120, 10, 10)),
                ]

            def locator(self, selector: str) -> FakeShareLocator:
                return FakeShareLocator(self.locator_buttons)

        page = FakePage()
        runner = PlaywrightChatGPTRunner({"selectors": {}, "local_clipboard_fallback": False})
        runner._click_share_button(page, 1, TimeoutError)
        self.assertEqual(page.clicked, ["response-viewport"])

    def test_model_confirmation_requires_explicit_selectors(self) -> None:
        runner = PlaywrightChatGPTRunner(
            {
                "selectors": {},
                "model_label": DEFAULT_MODEL_LABEL,
                "reasoning_label": DEFAULT_REASONING_LABEL,
                "require_model_confirmation": True,
            }
        )
        with self.assertRaises(SystemExit):
            runner._confirm_configured_labels(object(), 1)

    def test_model_confirmation_records_attestation(self) -> None:
        class FakeLocator:
            @property
            def first(self) -> "FakeLocator":
                return self

            def wait_for(self, timeout: int) -> None:
                return None

            def inner_text(self, timeout: int) -> str:
                return "ChatGPT Pro 5.5 Extended Reasoning"

            def get_attribute(self, name: str, timeout: int) -> str | None:
                return None

        class FakePage:
            def locator(self, selector: str) -> FakeLocator:
                return FakeLocator()

        runner = PlaywrightChatGPTRunner(
            {
                "selectors": {
                    "model_label_confirmation_selector": "[data-testid='model-switcher']",
                    "reasoning_label_confirmation_selector": "[data-testid='reasoning-switcher']",
                },
                "model_label": DEFAULT_MODEL_LABEL,
                "reasoning_label": DEFAULT_REASONING_LABEL,
                "require_model_confirmation": True,
            }
        )
        attestation = runner._confirm_configured_labels(FakePage(), 1)
        self.assertEqual(attestation["status"], "confirmed")
        self.assertEqual(attestation["labels"]["model_label"]["expected"], DEFAULT_MODEL_LABEL)
        self.assertEqual(attestation["labels"]["reasoning_label"]["expected"], DEFAULT_REASONING_LABEL)

    def test_model_confirmation_rejects_mismatched_visible_label(self) -> None:
        class FakeLocator:
            @property
            def first(self) -> "FakeLocator":
                return self

            def wait_for(self, timeout: int) -> None:
                return None

            def inner_text(self, timeout: int) -> str:
                return "ChatGPT 5.5 Instant"

            def get_attribute(self, name: str, timeout: int) -> str | None:
                return None

        class FakePage:
            def locator(self, selector: str) -> FakeLocator:
                return FakeLocator()

        runner = PlaywrightChatGPTRunner(
            {
                "selectors": {
                    "model_label_confirmation_selector": "[data-testid='model-switcher']",
                    "reasoning_label_confirmation_selector": "[data-testid='reasoning-switcher']",
                },
                "model_label": DEFAULT_MODEL_LABEL,
                "reasoning_label": DEFAULT_REASONING_LABEL,
                "require_model_confirmation": True,
            }
        )
        with self.assertRaises(SystemExit):
            runner._confirm_configured_labels(FakePage(), 1)

    def test_model_confirmation_requires_selected_attribute_when_configured(self) -> None:
        class FakeLocator:
            @property
            def first(self) -> "FakeLocator":
                return self

            def wait_for(self, *args: object, **kwargs: object) -> None:
                return None

            def inner_text(self, timeout: int) -> str:
                return "Pro • Extended"

            def get_attribute(self, name: str, timeout: int) -> str | None:
                if name == "aria-checked":
                    return "true"
                return None

        class FakePage:
            def locator(self, selector: str) -> FakeLocator:
                return FakeLocator()

        runner = PlaywrightChatGPTRunner(
            {
                "selectors": {
                    "model_label_confirmation_selector": "[data-testid='model-switcher-gpt-5-5-pro']",
                    "reasoning_label_confirmation_selector": "[data-testid='model-switcher-gpt-5-5-pro']",
                    "model_label_confirmation_text": "Pro",
                    "model_label_confirmation_attribute": "aria-checked",
                    "model_label_confirmation_attribute_value": "true",
                    "reasoning_label_confirmation_text": "Extended",
                },
                "model_label": DEFAULT_MODEL_LABEL,
                "reasoning_label": DEFAULT_REASONING_LABEL,
                "require_model_confirmation": True,
            }
        )
        attestation = runner._confirm_configured_labels(FakePage(), 1)
        self.assertEqual(attestation["labels"]["model_label"]["attribute"], "aria-checked")
        self.assertEqual(attestation["labels"]["model_label"]["attribute_value"], "true")

    def test_selection_opens_menu_before_clicking_option(self) -> None:
        class FakeLocator:
            def __init__(self, page: "FakePage", selector: str) -> None:
                self.page = page
                self.selector = selector

            @property
            def first(self) -> "FakeLocator":
                return self

            def wait_for(self, *args: object, **kwargs: object) -> None:
                if self.selector == "[data-testid='model-switcher-gpt-5-5-pro']" and not self.page.menu_open:
                    raise TimeoutError("not visible")

            def click(self, timeout: int) -> None:
                if self.selector == "button:has-text('Extended')":
                    self.page.menu_open = True
                if self.selector == "[data-testid='model-switcher-gpt-5-5-pro']":
                    self.page.option_clicked = True

        class FakePage:
            def __init__(self) -> None:
                self.menu_open = False
                self.option_clicked = False

            def locator(self, selector: str) -> FakeLocator:
                return FakeLocator(self, selector)

        page = FakePage()
        runner = PlaywrightChatGPTRunner(
            {
                "selectors": {
                    "model_label_open_selector": "button:has-text('Extended')",
                    "model_label_selector": "[data-testid='model-switcher-gpt-5-5-pro']",
                },
                "model_label": DEFAULT_MODEL_LABEL,
                "reasoning_label": "",
                "require_model_confirmation": True,
            }
        )
        runner._select_configured_labels(page, 1, TimeoutError)
        self.assertTrue(page.menu_open)
        self.assertTrue(page.option_clicked)

    def test_selection_does_not_click_loose_text_when_confirmation_required(self) -> None:
        class FakePage:
            def __init__(self) -> None:
                self.loose_text_clicked = False

            def get_by_text(self, label: str, exact: bool = False) -> object:
                self.loose_text_clicked = True
                raise AssertionError("loose text selection should not be used")

        page = FakePage()
        runner = PlaywrightChatGPTRunner(
            {
                "selectors": {},
                "model_label": DEFAULT_MODEL_LABEL,
                "reasoning_label": DEFAULT_REASONING_LABEL,
                "require_model_confirmation": True,
            }
        )
        runner._select_configured_labels(page, 1, TimeoutError)
        self.assertFalse(page.loose_text_clicked)

    def test_prompt_file_dispatch_metadata_uses_executor_without_leaking_prompt(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT) as tmpdir:
            prompt_path = Path(tmpdir) / "prompt.md"
            prompt_path.write_text("Review this final plan.", encoding="utf-8")
            args = Namespace(
                packet=None,
                prompt_file=str(prompt_path),
                allow_degraded_packet=True,
                allow_unlinked_packet=True,
                rehearsal=True,
                dispatch_id="dispatch-chatgpt",
                bead="cwo-1",
                epic="cwo",
                packet_sha256="packet-sha",
                share_boundary="redacted-packet",
            )
            prompt, metadata = load_prompt_from_args(args)
            result = build_result(
                prompt=prompt,
                metadata=metadata,
                config={
                    "chrome_user_data_dir": str(Path(tmpdir) / "profile"),
                    "response_timeout_seconds": 1800,
                    "share_link_required": True,
                },
                config_path=Path(tmpdir) / "config.json",
                browser_result={"share_url": "https://chatgpt.com/s/t_abc", "response_chars": 42},
                status="completed",
            )
        self.assertEqual(metadata["executor"], EXECUTOR_KEY)
        self.assertEqual(result["share_url"], "https://chatgpt.com/s/t_abc")
        self.assertNotIn("Review this final plan.", json.dumps(result))

    def test_packet_built_from_alias_is_accepted_by_prompt_loader(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT) as tmpdir:
            packet_path = Path(tmpdir) / "packet.json"
            packet = build_packet(
                bead_id="cwo-1",
                bead_json={
                    "id": "cwo-1",
                    "title": "ChatGPT Pro master plan review",
                    "labels": ["contractor-only", "no-codex-exec", "contract-jd-master-plan-review"],
                },
                executor=EXECUTOR_KEY,
                requested_executor="chatgpt_pro_5_5_extended_reasoning_browser",
                share_boundary="redacted-packet",
                job_description_label="contract-jd-master-plan-review",
                allowed_files=[],
                inline_snippets=["Review this final plan."],
                dispatch_id="dispatch-chatgpt",
                external_opt_in=True,
                opt_in_basis="cli-flag",
            )
            packet_path.write_text(json.dumps(packet), encoding="utf-8")
            args = Namespace(
                packet=str(packet_path),
                prompt_file=None,
                allow_degraded_packet=False,
                allow_unlinked_packet=True,
                rehearsal=True,
                dispatch_id=None,
                bead=None,
                epic=None,
                packet_sha256=None,
                share_boundary=None,
            )

            prompt, metadata = load_prompt_from_args(args)

        self.assertIn("Review this final plan.", prompt)
        self.assertEqual(packet["requested_executor"], "chatgpt_pro_5_5_extended_reasoning_browser")
        self.assertEqual(packet["canonical_executor"], EXECUTOR_KEY)
        self.assertEqual(metadata["executor"], EXECUTOR_KEY)

    def test_prompt_file_refusal_variants(self) -> None:
        variants = (
            ('test_prompt_file_requires_explicit_degraded_operator_flag',
             'Review this final plan.',
             False,
             True),
            ('test_prompt_file_rejects_unlinked_packet_hash_by_default', 'Review this final plan.', True, False),
            ('test_prompt_file_rejects_residual_secret_like_context', 'private_key=abc123', True, True),
        )
        for original, prompt_text, allow_degraded, allow_unlinked in variants:
            with self.subTest(original=original):
                with tempfile.TemporaryDirectory(dir=ROOT) as tmpdir:
                    prompt_path = Path(tmpdir) / "prompt.md"
                    prompt_path.write_text(prompt_text, encoding="utf-8")
                    args = Namespace(
                        packet=None,
                        prompt_file=str(prompt_path),
                        allow_degraded_packet=allow_degraded,
                        allow_unlinked_packet=allow_unlinked,
                        rehearsal=True,
                        dispatch_id="dispatch-chatgpt",
                        bead="cwo-1",
                        epic="cwo",
                        packet_sha256="packet-sha",
                        share_boundary="redacted-packet",
                    )
                    with self.assertRaises(SystemExit):
                        load_prompt_from_args(args)



    def test_failed_live_cli_writes_structured_failure_output(self) -> None:
        with tempfile.TemporaryDirectory() as cfgdir, tempfile.TemporaryDirectory(dir=ROOT) as promptdir:
            tmp = Path(cfgdir)
            config = self.write_confirmation_config(tmp)
            packet_path = Path(promptdir) / "packet.json"
            output = tmp / "result.json"
            packet = build_packet(
                bead_id="cwo-1",
                bead_json={
                    "id": "cwo-1",
                    "title": "ChatGPT Pro master plan review",
                    "labels": ["contractor-only", "no-codex-exec", "contract-jd-master-plan-review"],
                },
                executor=EXECUTOR_KEY,
                share_boundary="redacted-packet",
                job_description_label="contract-jd-master-plan-review",
                allowed_files=[],
                inline_snippets=["Review this final plan."],
                dispatch_id="dispatch-chatgpt",
                external_opt_in=True,
                opt_in_basis="cli-flag",
            )
            packet_path.write_text(json.dumps(packet), encoding="utf-8")
            failure = ChatGPTBrowserReviewError(
                "share-link",
                "ChatGPT share-link creation failed",
                {
                    "response_chars": 123,
                    "share_link_method": "social-intent",
                    "model_attestation": {"required": True, "status": "confirmed", "labels": {}},
                },
            )
            with patch.object(
                sys,
                "argv",
                [
                    "chatgpt_browser_review.py",
                    "--packet",
                    str(packet_path),
                    "--allow-unlinked-packet",
                    "--config",
                    str(config),
                    "--output",
                    str(output),
                    "--no-audit",
                    "--rehearsal",
                    "--waiver-reason",
                    "test browser no-audit rehearsal",
                ],
            ):
                import chatgpt_browser_review

                with patch.object(PlaywrightChatGPTRunner, "run", side_effect=failure):
                    with patch.object(
                        chatgpt_browser_review,
                        "enforce_contracting_quota",
                        return_value={
                            "quota_checked": True,
                            "quota_event_type": "external_manual_dispatch",
                            "quota_remaining": 4,
                            "executor_external": True,
                        },
                    ):
                        with self.assertRaises(SystemExit):
                            chatgpt_browser_review.main()
            result = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["failure_stage"], "share-link")
        self.assertEqual(result["share_link_method"], "social-intent")
        self.assertNotIn("Review this final plan.", json.dumps(result))

    URL = "https://chatgpt.com/c/0123abcd-4567-89ef"
    PROMPT = "Review this plan.\n\n    keep = 'two  spaces'"
    REQUEST_ID = "0123456789abcdef0123456789abcdef"
    SUBMITTED = bound_request(PROMPT, REQUEST_ID)

    @staticmethod
    def _state(messages: list, *, url: str | None = None, stopping: bool = False, stamp: str | None = "0123456789abcdef0123456789abcdef") -> dict:
        return {"url": url or ChatGPTBrowserReviewTests.URL, "stamp": stamp, "stopping": stopping, "messages": messages}

    @staticmethod
    def _message(role: str, message_id: str | None, text: str, marked: bool = True) -> dict:
        return {"role": role, "id": message_id, "text": text, "marked": marked}

    def _dom(self, timeline: list) -> object:
        """A fake conversation whose state advances on every page read.

        It answers both the single snapshot script and the separate message,
        text and turn-state reads used before round 4, from the same states, so
        one timeline can be replayed against either implementation.
        """

        class Locator:
            def __init__(self, dom: "Dom", message_id: str) -> None:
                self.dom, self.message_id = dom, message_id

            def inner_text(self, timeout: int = 0) -> str:
                state = self.dom.read()
                for item in state["messages"]:
                    if item["id"] == self.message_id:
                        return item["text"]
                raise RuntimeError("no such message")

        class Dom:
            def __init__(self) -> None:
                self.timeline = list(timeline)
                self.reads = 0

            def peek(self) -> dict:
                return self.timeline[min(self.reads, len(self.timeline) - 1)]

            def read(self) -> dict:
                state = self.peek()
                self.reads += 1
                if isinstance(state, Exception):
                    raise state
                return state

            @property
            def url(self) -> str:
                state = self.peek()
                return state["url"] if isinstance(state, dict) else ""

            def evaluate(self, script: str, arg: object = None) -> object:
                state = self.read()
                if "location.href" in script:
                    return json.loads(json.dumps(state))
                if "closest(" in script:
                    message_id = arg[0]
                    for item in state["messages"]:
                        if item["id"] == message_id:
                            return {"found": True, "terminal": item["marked"] and not state["stopping"]}
                    return {"found": False, "terminal": False}
                return [{"role": item["role"], "id": item["id"]} for item in state["messages"]]

            def locator(self, selector: str) -> Locator:
                found = re.match(r"\[data-message-id='([^']+)'\]$", selector)
                if not found:
                    raise AssertionError(selector)
                return Locator(self, found.group(1))

        return Dom()

    BEFORE = [{"role": "user", "id": "u0", "text": "Earlier question", "marked": True},
              {"role": "assistant", "id": "a0", "text": "Old reply", "marked": True}]

    def _complete_state(self, reply: str = "New findings: add a key.", **overrides: object) -> dict:
        messages = self.BEFORE + [self._message("user", "u1", self.SUBMITTED), self._message("assistant", "a1", reply)]
        return self._state(messages, **overrides)

    def _capture(self, timeline: list, *, prompt: str | None = None, before_url: str | None = None,
                 request_id: str | None = REQUEST_ID, before: list | None = None, pinned: str | None = "") -> dict:
        runner = PlaywrightChatGPTRunner({"selectors": {}})
        page = self._dom(timeline)
        before_messages = {"available": True, "messages": self.BEFORE if before is None else before}
        if pinned == "":
            # By default the conversation pinned at Send is the one the first read shows.
            first = next((state for state in timeline if isinstance(state, dict)), None)
            found = CONVERSATION_ID_RE.search(urlparse(first["url"]).path) if first else None
            pinned = found.group(1) if found else None
        return runner._capture_assistant_response(page, "before", "before conversation", before_messages=before_messages,
                                                  prompt=self.SUBMITTED if prompt is None else prompt,
                                                  request_id=request_id,
                                                  before_url=self.URL if before_url is None else before_url,
                                                  pinned_conversation_id=pinned)

    def test_verified_capture_is_complete(self) -> None:
        captured = self._capture([self._complete_state()])
        self.assertEqual(captured["text"], "New findings: add a key.")
        self.assertEqual((captured["extraction"], captured["message_id"], captured["user_message_id"]), ("assistant-message", "a1", "u1"))
        self.assertEqual(captured["conversation_id"], "0123abcd-4567-89ef")
        self.assertTrue(captured["capture_complete"], captured["incomplete_reasons"])

    def test_regeneration_between_reads_never_yields_partial_complete_text(self) -> None:
        full, partial = self._complete_state(), self._complete_state("New findings: add", stopping=True)
        partial["messages"][-1]["marked"] = False
        # Terminal for three reads, regenerating (identical partial text) for three, then terminal again.
        captured = self._capture([full, full, full, partial, partial, partial, full])
        self.assertFalse(captured["capture_complete"] and captured["text"] == "New findings: add",
                         "partial text must never be a complete return")
        regenerating = self._capture([full, partial])
        self.assertFalse(regenerating["capture_complete"])
        self.assertIn("content_stable", regenerating["incomplete_reasons"])

    def test_navigation_between_reads_is_refused(self) -> None:
        other = self._complete_state(url="https://chatgpt.com/c/ffffffff-1111-2222")
        captured = self._capture([self._complete_state(), other])
        self.assertFalse(captured["capture_complete"])
        self.assertIn("conversation_stable", captured["incomplete_reasons"])
        moved = self._capture([other, other])
        self.assertFalse(moved["capture_complete"])

    def test_request_whitespace_is_significant(self) -> None:
        for prompt in ("Review this plan.\n\n  keep = 'two  spaces'", "Review this plan.\n\n    keep = 'two spaces'"):
            with self.subTest(prompt=prompt):
                captured = self._capture([self._complete_state()], prompt=bound_request(prompt, self.REQUEST_ID))
                self.assertFalse(captured["capture_complete"])
                self.assertIn("request_turn", captured["incomplete_reasons"])
        crlf = self._capture([self._complete_state()], prompt=self.SUBMITTED.replace("\n", "\r\n") + "\n")
        self.assertTrue(crlf["capture_complete"], "only line-ending style and surrounding whitespace are ignored")

    def test_unverified_captures_are_incomplete(self) -> None:
        cases = {
            "no new assistant turn": (self._state(self.BEFORE + [self._message("user", "u1", self.SUBMITTED)]), "response_turn"),
            "older answer precedes the prompt": (self._state(self.BEFORE + [self._message("assistant", "a9", "History"),
                                                                            self._message("user", "u1", self.SUBMITTED)]), "response_turn"),
            "two new user turns": (self._state(self.BEFORE + [self._message("user", "ux", "x"), self._message("assistant", "ax", "y"),
                                                              self._message("user", "u1", self.SUBMITTED), self._message("assistant", "a1", "z")]),
                                   "request_turn"),
            "missing assistant id": (self._state(self.BEFORE + [self._message("user", "u1", self.SUBMITTED),
                                                                self._message("assistant", None, "z")]), "response_turn"),
            "missing user id": (self._state(self.BEFORE + [self._message("user", None, self.SUBMITTED),
                                                           self._message("assistant", "a1", "z")]), "request_turn"),
            "completion marker absent": (self._state(self.BEFORE + [self._message("user", "u1", self.SUBMITTED),
                                                                    self._message("assistant", "a1", "z", marked=False)]), "completion_confirmed"),
            "generation running": (self._complete_state(stopping=True), "completion_confirmed"),
            "probe fails": (RuntimeError("evaluate failed"), "response_turn"),
            "no conversation identity": (self._complete_state(url="https://chatgpt.com/"), "conversation_stable"),
        }
        for label, (state, reason) in cases.items():
            with self.subTest(case=label):
                captured = self._capture([state])
                self.assertFalse(captured["capture_complete"])
                self.assertIn(reason, captured["incomplete_reasons"])
        changed = self._capture([self._complete_state()], before_url="https://chatgpt.com/c/ffffffff-0000")
        self.assertIn("conversation_stable", changed["incomplete_reasons"])

    def test_new_chat_cannot_bind_another_conversation_with_the_same_prompt(self) -> None:
        # Sent from a new chat, nothing identifies the conversation in advance;
        # only the request id carried by the submitted turn binds the reply.
        new_chat, empty = "https://chatgpt.com/", []
        elsewhere = self._state([self._message("user", "b1", self.PROMPT), self._message("assistant", "b2", "A reply to someone else")],
                                url="https://chatgpt.com/c/bbbbbbbb-0000-1111")
        captured = self._capture([elsewhere], before_url=new_chat, before=empty)
        self.assertFalse(captured["capture_complete"])
        self.assertIn("request_turn", captured["incomplete_reasons"])
        own = self._state([self._message("user", "u1", self.SUBMITTED), self._message("assistant", "a1", "Our reply")],
                          url="https://chatgpt.com/c/aaaaaaaa-0000-1111")
        captured = self._capture([own], before_url=new_chat, before=empty)
        self.assertTrue(captured["capture_complete"], captured["incomplete_reasons"])
        self.assertEqual((captured["user_message_id"], captured["conversation_id"]), ("u1", "aaaaaaaa-0000-1111"))

    def test_capture_without_a_request_binding_is_incomplete(self) -> None:
        for request_id in (None, "", "0123", "0123456789ABCDEF0123456789ABCDEF"):
            with self.subTest(request_id=request_id):
                captured = self._capture([self._complete_state()], request_id=request_id)
                self.assertFalse(captured["capture_complete"])
                self.assertIn("request_turn", captured["incomplete_reasons"])
        # The id must be carried by the submitted turn and by no other user message.
        state = self._complete_state()
        state["messages"][0] = self._message("user", "u0", "Earlier question " + self.REQUEST_ID)
        captured = self._capture([state])
        self.assertFalse(captured["capture_complete"])
        self.assertIn("request_turn", captured["incomplete_reasons"])
        captured = self._capture([self._complete_state()], request_id="f" * 32)
        self.assertIn("request_turn", captured["incomplete_reasons"])

    def test_capture_on_another_origin_is_incomplete(self) -> None:
        path = "/c/0123abcd-4567-89ef"
        for origin in ("https://chatgpt.com.example", "https://example.com", "http://chatgpt.com",
                       "https://chatgpt.com:8443", "https://user@chatgpt.com", "https://chat.openai.com"):
            with self.subTest(origin=origin):
                captured = self._capture([self._complete_state(url=origin + path)])
                self.assertFalse(captured["capture_complete"])
                self.assertIn("conversation_stable", captured["incomplete_reasons"])
        for origin in ("https://chatgpt.com.example", "http://chatgpt.com"):
            with self.subTest(both_sides=origin):
                captured = self._capture([self._complete_state(url=origin + path)], before_url=origin + path)
                self.assertFalse(captured["capture_complete"])
                self.assertIn("conversation_stable", captured["incomplete_reasons"])
        same = self._capture([self._complete_state(url="https://chat.openai.com" + path)], before_url="https://chat.openai.com/")
        self.assertTrue(same["capture_complete"], same["incomplete_reasons"])

    def test_capture_must_match_the_pinned_conversation_and_stamped_document(self) -> None:
        complete = self._capture([self._complete_state()])
        self.assertTrue(complete["capture_complete"], complete["incomplete_reasons"])
        for label, kwargs, state in (
            ("no pinned conversation", {"pinned": None}, self._complete_state()),
            ("another pinned conversation", {"pinned": "ffffffff-0000-1111"}, self._complete_state()),
            ("unstamped document", {}, self._complete_state(stamp=None)),
            ("another submission's stamp", {}, self._complete_state(stamp="f" * 32)),
        ):
            with self.subTest(case=label):
                captured = self._capture([state], **kwargs)
                self.assertFalse(captured["capture_complete"])
                self.assertIn("conversation_stable", captured["incomplete_reasons"])

    def test_fallback_text_is_diagnostic_only(self) -> None:
        class Page:
            url = "https://chatgpt.com/"

            def evaluate(self, script: str, arg: object = None) -> object:
                raise RuntimeError("no page script")

            def locator(self, selector: str) -> object:
                raise RuntimeError("no assistant element")

        runner = PlaywrightChatGPTRunner({"selectors": {}})
        captured = runner._capture_assistant_response(Page(), "Earlier text", "Earlier text\nPrompt\nReply body")
        self.assertEqual(captured["text"], "Prompt\nReply body")
        self.assertEqual(captured["extraction"], "conversation-delta")
        self.assertFalse(captured["capture_complete"])

    def test_progress_probe_failure_never_confirms_completion(self) -> None:
        runner = PlaywrightChatGPTRunner({"selectors": {}})
        texts = iter(["before"] + ["before plus a long enough response body"] * 50)
        with patch.object(runner, "_conversation_text", side_effect=lambda page: next(texts)), patch.object(
            runner, "_response_in_progress", return_value=None
        ), patch.object(chatgpt_browser_review.time, "sleep"), patch.object(
            chatgpt_browser_review.time, "monotonic", side_effect=[float(i) for i in range(0, 400, 2)]
        ):
            runner._wait_for_stable_response(object(), "before", response_timeout=300, stable_wait=4)
        self.assertFalse(runner.completion_confirmed)

    def _run_live_cli(self, browser_result: dict, tmp: Path, promptdir: Path, *, audit: bool = False,
                      run: object = None) -> tuple[dict, Path, BaseException | None]:
        config = self.write_confirmation_config(tmp)
        packet_path = promptdir / "packet.json"
        output = tmp / "result.json"
        response_dir = tmp / "returns"
        packet = build_packet(
            bead_id="cwo-1",
            bead_json={
                "id": "cwo-1",
                "title": "ChatGPT Pro master plan review",
                "labels": ["contractor-only", "no-codex-exec", "contract-jd-master-plan-review"],
            },
            executor=EXECUTOR_KEY,
            share_boundary="redacted-packet",
            job_description_label="contract-jd-master-plan-review",
            allowed_files=[],
            inline_snippets=["Review this final plan."],
            dispatch_id="dispatch-chatgpt",
            external_opt_in=True,
            opt_in_basis="cli-flag",
        )
        packet_path.write_text(json.dumps(packet), encoding="utf-8")
        argv = [
            "chatgpt_browser_review.py",
            "--packet",
            str(packet_path),
            "--allow-unlinked-packet",
            "--config",
            str(config),
            "--output",
            str(output),
            "--response-dir",
            str(response_dir),
            *([] if audit else ["--no-audit", "--rehearsal"]),
            "--waiver-reason",
            "test browser no-audit rehearsal",
        ]
        raised: BaseException | None = None
        with patch.object(sys, "argv", argv):
            import chatgpt_browser_review

            run_patch = (patch.object(PlaywrightChatGPTRunner, "run", autospec=True, side_effect=run) if run is not None
                         else patch.object(PlaywrightChatGPTRunner, "run", return_value=browser_result))
            with run_patch, patch.object(
                chatgpt_browser_review,
                "enforce_contracting_quota",
                return_value={"quota_checked": True, "quota_event_type": "x", "quota_remaining": 4, "executor_external": True},
            ):
                try:
                    chatgpt_browser_review.main()
                except SystemExit as exc:
                    raised = exc
        return json.loads(output.read_text(encoding="utf-8")), response_dir, raised

    def test_live_cli_keeps_the_complete_response_in_a_private_artifact(self) -> None:
        response_text = "Assistant findings: add duplicate-job protection before enabling retries."
        browser_result = {
            "share_url": "",
            "response_chars": len(response_text),
            "model_attestation": {"required": True, "status": "confirmed", "labels": {}},
            "share_link_method": None,
            "response_text": response_text,
            "response_extraction": "assistant-message",
            "assistant_message_id": "msg-9",
            "user_message_id": "msg-8",
            "conversation_url": "https://chatgpt.com/c/0123abcd-4567",
            "conversation_id": "0123abcd-4567",
            "conversation_text_sha256": "a" * 64,
            **self.VERIFIED,
        }
        with tempfile.TemporaryDirectory() as cfgdir, tempfile.TemporaryDirectory(dir=ROOT) as promptdir:
            result, response_dir, raised = self._run_live_cli(browser_result, Path(cfgdir), Path(promptdir))
            self.assertIsNone(raised)
            artifact = result["response_artifact"]
            response_path = Path(artifact["response_path"])
            provenance_path = Path(artifact["provenance_path"])
            self.assertEqual(stat.S_IMODE(response_dir.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(response_path.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(provenance_path.stat().st_mode), 0o600)
            self.assertEqual(response_path.read_text(encoding="utf-8"), response_text)
            provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
            from ingest_chatgpt_share_return import load_private_response

            ingested, ingested_provenance, _ = load_private_response(
                provenance_path, packet_sha256=result["packet_sha256"], dispatch_id="dispatch-chatgpt", bead_id="cwo-1"
            )
        self.assertEqual(result["status"], "completed")
        self.assertEqual(provenance["artifact_type"], "chatgpt-browser-private-response")
        self.assertTrue(provenance["capture_complete"])
        self.assertEqual(provenance["response_sha256"], artifact["response_sha256"])
        self.assertEqual(provenance["conversation_id"], "0123abcd-4567")
        self.assertEqual((provenance["request_id"], provenance["submitted_sha256"]), ("0123456789abcdef0123456789abcdef", "c" * 64))
        self.assertEqual(ingested, response_text)
        self.assertEqual(ingested_provenance["assistant_message_id"], "msg-9")
        rendered = json.dumps(result)
        self.assertNotIn(response_text, rendered, "the response text must stay out of the dispatch result")
        self.assertNotIn("Review this final plan.", rendered)

    VERIFIED = {
        "request_id": "0123456789abcdef0123456789abcdef",
        "submitted_sha256": "c" * 64,
        "capture_complete": True,
        "capture_checks": {name: True for name in chatgpt_browser_review.CAPTURE_CHECKS},
        "capture_incomplete_reasons": [],
    }

    def _browser_result(self, **overrides: object) -> dict:
        result = {
            "share_url": "",
            "response_chars": 10,
            "model_attestation": {"required": True, "status": "confirmed", "labels": {}},
            "share_link_method": None,
            "response_text": "Findings: retry needs a key.",
            "response_extraction": "assistant-message",
            "assistant_message_id": "msg-9",
            "user_message_id": "msg-8",
            "conversation_url": "https://chatgpt.com/c/0123abcd-4567",
            "conversation_id": "0123abcd-4567",
            "conversation_text_sha256": "a" * 64,
            **self.VERIFIED,
        }
        result.update(overrides)
        return result

    def test_unverified_capture_is_kept_as_incomplete_diagnostic(self) -> None:
        browser_result = self._browser_result(
            capture_complete=False,
            capture_checks={**self.VERIFIED["capture_checks"], "response_turn": False},
            capture_incomplete_reasons=["response_turn"],
        )
        with tempfile.TemporaryDirectory() as cfgdir, tempfile.TemporaryDirectory(dir=ROOT) as promptdir:
            result, response_dir, raised = self._run_live_cli(browser_result, Path(cfgdir), Path(promptdir))
            provenance_path = Path(result["response_artifact"]["provenance_path"])
            provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
            from ingest_chatgpt_share_return import load_private_response

            with self.assertRaises(SystemExit):
                load_private_response(provenance_path, packet_sha256=None, dispatch_id=None, bead_id=None)
        self.assertIsNotNone(raised)
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["failure_reason"], "capture-incomplete: response_turn")
        self.assertFalse(provenance["capture_complete"])
        self.assertFalse(provenance["capture_checks"]["response_turn"])

    def test_capture_without_request_binding_is_not_a_complete_artifact(self) -> None:
        for request_id in (None, "0123"):
            with self.subTest(request_id=request_id):
                browser_result = self._browser_result(request_id=request_id)
                with tempfile.TemporaryDirectory() as cfgdir, tempfile.TemporaryDirectory(dir=ROOT) as promptdir:
                    result, _, raised = self._run_live_cli(browser_result, Path(cfgdir), Path(promptdir))
                    provenance = json.loads(Path(result["response_artifact"]["provenance_path"]).read_text(encoding="utf-8"))
                self.assertIsNotNone(raised)
                self.assertEqual(result["status"], "failed")
                self.assertFalse(provenance["capture_complete"])
                self.assertIn("request-binding-missing", provenance["capture_incomplete_reasons"])

    def test_storage_failures_are_reported_and_delete_nothing(self) -> None:
        from cwo_core.private_artifact import PrivateArtifactError, PrivateDirectory

        real_write = PrivateDirectory.write

        def fail_provenance(self: object, name: str, data: bytes) -> Path:
            raise PrivateArtifactError("cannot write artifact: No space left on device")

        def fail_response(self: object, name: str, data: bytes) -> Path:
            if name.endswith(".response.txt"):
                raise PrivateArtifactError("cannot write artifact: Permission denied")
            return real_write(self, name, data)

        for label, failure in (("provenance", fail_provenance), ("response", fail_response)):
            with self.subTest(stage=label), tempfile.TemporaryDirectory() as cfgdir, tempfile.TemporaryDirectory(dir=ROOT) as promptdir:
                with patch.object(PrivateDirectory, "write", failure):
                    result, response_dir, raised = self._run_live_cli(self._browser_result(), Path(cfgdir), Path(promptdir))
                leftovers = sorted(p.name for p in response_dir.iterdir()) if response_dir.exists() else []
                self.assertIsNotNone(raised)
                self.assertEqual((result["status"], result["failure_stage"]), ("failed", "response-capture"))
                self.assertIsNone(result["response_artifact"])
                self.assertFalse(any(name.endswith(".response.txt") or name.startswith(".") for name in leftovers),
                                 "no response text or temporary file is left")
                if label == "provenance":
                    self.assertEqual(leftovers, [])
                else:
                    # Provenance went first and stays; it holds no response text and is reported.
                    self.assertEqual(len(leftovers), 1)
                    self.assertTrue(leftovers[0].endswith(".provenance.json"))
                    self.assertIn(leftovers[0], result["failure_reason"])
                    self.assertIn("retained", result["failure_reason"])

    def test_storage_failure_is_still_audited(self) -> None:
        from cwo_core.private_artifact import PrivateArtifactError, PrivateDirectory

        events: list[dict] = []
        with tempfile.TemporaryDirectory() as cfgdir, tempfile.TemporaryDirectory(dir=ROOT) as promptdir:
            with patch.object(PrivateDirectory, "write", side_effect=PrivateArtifactError("disk full")), patch.object(
                chatgpt_browser_review, "record_audit_event", side_effect=lambda event, **_: events.append(event)
            ):
                result, _, raised = self._run_live_cli(self._browser_result(), Path(cfgdir), Path(promptdir), audit=True)
        self.assertIsNotNone(raised)
        self.assertEqual([(e["status"], e["failure_stage"]) for e in events], [("failed", "response-capture")])
        self.assertNotIn("Findings: retry needs a key.", json.dumps(events))

    def test_handled_failures_report_the_send_state(self) -> None:
        for state, expected in (("submitted", "the prompt was submitted"),
                                ("may-have-been-submitted", "the prompt may have been submitted"),
                                ("not-sent", None)):
            def run(runner: PlaywrightChatGPTRunner, prompt: str, state: str = state) -> dict:
                runner.send_state = state
                raise ChatGPTBrowserReviewError("response-wait", "timed out waiting for the response")

            with self.subTest(state=state), tempfile.TemporaryDirectory() as cfgdir, \
                    tempfile.TemporaryDirectory(dir=ROOT) as promptdir:
                result, _, raised = self._run_live_cli(self._browser_result(), Path(cfgdir), Path(promptdir), run=run)
            message = str(raised.code)
            self.assertTrue(message.startswith("response-wait: timed out waiting for the response"), message)
            if expected:
                self.assertIn(expected, message)
            else:
                self.assertNotIn("submitted", message)
            self.assertEqual((result["status"], result.get("send_state")), ("failed", state))

    def test_capture_failures_after_send_report_the_submission(self) -> None:
        from cwo_core.private_artifact import PrivateArtifactError, PrivateDirectory

        def run(runner: PlaywrightChatGPTRunner, prompt: str) -> dict:
            runner.send_state = "submitted"
            return self._browser_result()

        with tempfile.TemporaryDirectory() as cfgdir, tempfile.TemporaryDirectory(dir=ROOT) as promptdir, \
                patch.object(PrivateDirectory, "write", side_effect=PrivateArtifactError("disk full")):
            result, _, raised = self._run_live_cli(self._browser_result(), Path(cfgdir), Path(promptdir), run=run)
        self.assertRegex(str(raised.code), r"^response-capture: .*disk full; the prompt was submitted")
        self.assertEqual((result["status"], result["failure_stage"], result.get("send_state")),
                         ("failed", "response-capture", "submitted"))

    def test_a_late_refusal_shows_its_notes_on_stderr(self) -> None:
        """A SystemExit after the response is published (here, --output names a directory) must still say on
        stderr that the prompt was submitted and which private files exist: Python prints only its code."""
        import textwrap

        with tempfile.TemporaryDirectory() as cfgdir, tempfile.TemporaryDirectory(dir=ROOT) as promptdir:
            tmp = Path(cfgdir)
            packet_path = Path(promptdir) / "packet.json"
            packet_path.write_text(json.dumps(build_packet(
                bead_id="cwo-1", bead_json={"id": "cwo-1", "title": "Plan review",
                                            "labels": ["contractor-only", "no-codex-exec", "contract-jd-master-plan-review"]},
                executor=EXECUTOR_KEY, share_boundary="redacted-packet", job_description_label="contract-jd-master-plan-review",
                allowed_files=[], inline_snippets=["Review this final plan."], dispatch_id="dispatch-chatgpt",
                external_opt_in=True, opt_in_basis="cli-flag",
            )), encoding="utf-8")
            (tmp / "out").mkdir()
            response_dir = tmp / "returns"
            argv = ["chatgpt_browser_review.py", "--packet", str(packet_path), "--allow-unlinked-packet",
                    "--config", str(self.write_confirmation_config(tmp)), "--output", str(tmp / "out"),
                    "--response-dir", str(response_dir), "--no-audit", "--rehearsal", "--waiver-reason", "late refusal test"]
            driver = tmp / "driver.py"
            driver.write_text(textwrap.dedent(f"""\
                import json, sys
                from unittest.mock import patch
                sys.path.insert(0, {str(ROOT / "scripts")!r})
                import chatgpt_browser_review as cli
                cli.BROWSER_DISPATCH_AVAILABLE = True  # as setUpModule does in-process; shipped code keeps it off
                browser_result = json.loads({json.dumps(json.dumps(self._browser_result()))})
                def run(runner, prompt):
                    runner.send_state = "submitted"
                    return browser_result
                sys.argv = {argv!r}
                quota = {{"quota_checked": True, "quota_event_type": "x", "quota_remaining": 4, "executor_external": True}}
                with patch.object(cli.PlaywrightChatGPTRunner, "run", run), \\
                        patch.object(cli, "enforce_contracting_quota", return_value=quota):
                    cli.main()
                """), encoding="utf-8")
            completed = subprocess.run([sys.executable, "-I", str(driver)], capture_output=True, text=True, timeout=120,
                                       cwd=ROOT)
            files = sorted(path.name for path in response_dir.iterdir())
        self.assertEqual(completed.returncode, 1, completed.stderr)
        self.assertIn("refusing to overwrite directory output path", completed.stderr)
        self.assertIn("the prompt was submitted", completed.stderr)
        self.assertIn("private response files present after the failure", completed.stderr)
        self.assertEqual(len(files), 2, files)
        for name in files:
            self.assertIn(name, completed.stderr)

    def test_a_closed_stdout_pipe_still_reports_the_effects(self) -> None:
        """The result is printed into a buffer; with the read end of stdout closed, the failure must come
        while the effects can still be reported, not at interpreter exit."""
        import textwrap

        with tempfile.TemporaryDirectory() as cfgdir, tempfile.TemporaryDirectory(dir=ROOT) as promptdir:
            tmp = Path(cfgdir)
            packet_path = Path(promptdir) / "packet.json"
            packet_path.write_text(json.dumps(build_packet(
                bead_id="cwo-1", bead_json={"id": "cwo-1", "title": "Plan review",
                                            "labels": ["contractor-only", "no-codex-exec", "contract-jd-master-plan-review"]},
                executor=EXECUTOR_KEY, share_boundary="redacted-packet", job_description_label="contract-jd-master-plan-review",
                allowed_files=[], inline_snippets=["Review this final plan."], dispatch_id="dispatch-chatgpt",
                external_opt_in=True, opt_in_basis="cli-flag",
            )), encoding="utf-8")
            response_dir = tmp / "returns"
            argv = ["chatgpt_browser_review.py", "--packet", str(packet_path), "--allow-unlinked-packet",
                    "--config", str(self.write_confirmation_config(tmp)), "--response-dir", str(response_dir),
                    "--no-audit", "--rehearsal", "--waiver-reason", "closed pipe test"]
            driver = tmp / "driver.py"
            driver.write_text(textwrap.dedent(f"""\
                import json, sys
                from unittest.mock import patch
                sys.path.insert(0, {str(ROOT / "scripts")!r})
                import chatgpt_browser_review as cli
                cli.BROWSER_DISPATCH_AVAILABLE = True  # as setUpModule does in-process; shipped code keeps it off
                browser_result = json.loads({json.dumps(json.dumps(self._browser_result()))})
                def run(runner, prompt):
                    runner.send_state = "submitted"
                    return browser_result
                sys.argv = {argv!r}
                quota = {{"quota_checked": True, "quota_event_type": "x", "quota_remaining": 4, "executor_external": True}}
                with patch.object(cli.PlaywrightChatGPTRunner, "run", run), \\
                        patch.object(cli, "enforce_contracting_quota", return_value=quota):
                    cli.main()
                """), encoding="utf-8")
            read_end, write_end = os.pipe()
            os.close(read_end)
            try:
                completed = subprocess.run([sys.executable, "-I", str(driver)], stdout=write_end, stderr=subprocess.PIPE,
                                           text=True, timeout=120, cwd=ROOT)
            finally:
                os.close(write_end)
            files = sorted(path.name for path in response_dir.iterdir())
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("BrokenPipeError", completed.stderr)
        self.assertIn("the prompt was submitted", completed.stderr)
        self.assertEqual(len(files), 2, files)
        for name in files:
            self.assertIn(name, completed.stderr)

    def test_an_interruption_at_the_final_exit_reports_the_effects(self) -> None:
        import inspect

        source, first = inspect.getsourcelines(chatgpt_browser_review.main)
        lines = {text.strip(): first + index for index, text in enumerate(source)}
        code = chatgpt_browser_review.main.__code__
        incomplete = self._browser_result(capture_complete=False,
                                          capture_checks={**self.VERIFIED["capture_checks"], "response_turn": False},
                                          capture_incomplete_reasons=["response_turn"])
        # The last statement of the protected block, for a handled failure and for a completed run, and the
        # handled failure's own exit. (CPython leaves a function's return outside a try's protected range, so
        # the block ends without one: by then the written result already carries the Send state and the files.)
        cases = (("if exit_message:", incomplete), ("raise SystemExit(exit_message)", incomplete),
                 ("if exit_message:", self._browser_result()))
        for statement, browser_result in cases:
            target = lines[statement]

            def tracer(frame: object, event: str, arg: object, target: int = target) -> object:
                if frame.f_code is not code:  # type: ignore[attr-defined]
                    return None

                def local(frame: object, event: str, arg: object) -> object:
                    if event == "line" and frame.f_lineno == target:  # type: ignore[attr-defined]
                        raise KeyboardInterrupt  # published (and, for a handled failure, about to exit)
                    return local
                return local

            def submitted(runner: PlaywrightChatGPTRunner, prompt: str, browser_result: dict = browser_result) -> dict:
                runner.send_state = "submitted"
                return browser_result

            with self.subTest(statement=statement, complete=browser_result.get("capture_complete")), \
                    tempfile.TemporaryDirectory() as cfgdir, tempfile.TemporaryDirectory(dir=ROOT) as promptdir:
                sys.settrace(tracer)
                try:
                    with self.assertRaises(KeyboardInterrupt) as raised:
                        self._run_live_cli(browser_result, Path(cfgdir), Path(promptdir), run=submitted)
                finally:
                    sys.settrace(None)
                names = sorted(path.name for path in (Path(cfgdir) / "returns").iterdir())
            notes = " ".join(getattr(raised.exception, "__notes__", []))
            self.assertIn("the prompt was submitted", notes, statement)
            self.assertEqual(len(names), 2, statement)
            for name in names:
                self.assertIn(name, notes, statement)

    def test_invalid_packet_never_reaches_send(self) -> None:
        with tempfile.TemporaryDirectory() as cfgdir, tempfile.TemporaryDirectory(dir=ROOT) as promptdir:
            config = self.write_confirmation_config(Path(cfgdir))
            packet_path = Path(promptdir) / "packet.json"
            packet_path.write_text(json.dumps({"packet_type": "not-a-contractor-packet"}), encoding="utf-8")
            argv = ["chatgpt_browser_review.py", "--packet", str(packet_path), "--allow-unlinked-packet", "--config", str(config),
                    "--no-audit", "--rehearsal", "--waiver-reason", "test invalid packet"]
            with patch.object(sys, "argv", argv), patch.object(PlaywrightChatGPTRunner, "run") as run:
                with self.assertRaises(SystemExit):
                    chatgpt_browser_review.main()
        run.assert_not_called()

    def test_empty_capture_fails_without_writing_an_artifact(self) -> None:
        browser_result = {
            "share_url": "",
            "response_chars": 0,
            "model_attestation": None,
            "share_link_method": None,
            "response_text": "   ",
            "response_extraction": "conversation-delta",
        }
        with tempfile.TemporaryDirectory() as cfgdir, tempfile.TemporaryDirectory(dir=ROOT) as promptdir:
            result, response_dir, raised = self._run_live_cli(browser_result, Path(cfgdir), Path(promptdir))
            leftovers = sorted(p.name for p in response_dir.iterdir()) if response_dir.exists() else []
        self.assertIsNotNone(raised)
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["failure_stage"], "response-capture")
        self.assertIsNone(result["response_artifact"])
        self.assertEqual(leftovers, [])

    def _fake_playwright_modules(self) -> dict:
        import types

        class Context:
            pages: list = []

            def close(self) -> None:
                return None

        class Chromium:
            def launch_persistent_context(self, *args: object, **kwargs: object) -> Context:
                return Context()

        class Playwright:
            chromium = Chromium()

            def stop(self) -> None:
                return None

        class Manager:
            def start(self) -> Playwright:
                return Playwright()

        sync_api = types.ModuleType("playwright.sync_api")
        sync_api.TimeoutError = type("FakeTimeout", (Exception,), {})
        sync_api.sync_playwright = lambda: Manager()
        return {"playwright": types.ModuleType("playwright"), "playwright.sync_api": sync_api}

    def _drive_fake_browser(self, config: dict, *, page_url: str = "https://chatgpt.com/c/0123abcd-4567",
                            snapshot: dict | None = None, prompt: str = "Prompt") -> tuple[object, dict]:
        """Run the browser flow against fakes; return (result or raised error, mocks)."""

        class Page:
            url = page_url

            def goto(self, *args: object, **kwargs: object) -> None:
                return None

        runner = PlaywrightChatGPTRunner(config)
        captured = {
            "text": "Reply body",
            "extraction": "assistant-message",
            "message_id": "msg-1",
            "user_message_id": "msg-0",
            "conversation_url": Page.url,
            "conversation_id": "0123abcd-4567",
            "checks": {name: True for name in chatgpt_browser_review.CAPTURE_CHECKS},
            "capture_complete": True,
            "incomplete_reasons": [],
        }
        with patch.dict(sys.modules, self._fake_playwright_modules()), patch.object(
            runner, "_select_page", return_value=Page()
        ), patch.object(runner, "_wait_for_prompt"), patch.object(runner, "_select_configured_labels"), patch.object(
            runner, "_confirm_configured_labels", return_value={"status": "confirmed"}
        ), patch.object(runner, "_conversation_text", return_value="before"), patch.object(
            runner, "_message_snapshot", return_value=snapshot or {"available": True, "messages": []}
        ), patch.object(
            runner, "_submit_prompt"
        ) as submit, patch.object(runner, "_pin_conversation", return_value="0123abcd-4567") as pin, patch.object(
            runner, "_wait_for_stable_response", return_value="before Prompt Reply body"
        ), patch.object(
            runner, "_capture_assistant_response", return_value=captured
        ) as capture, patch.object(
            runner, "_create_share_link", side_effect=AssertionError("share creation must not be reached")
        ) as create_share, patch.object(
            runner, "_try_social_share_url", side_effect=AssertionError("social share must not be reached")
        ):
            try:
                outcome: object = runner.run(prompt)
            except ChatGPTBrowserReviewError as exc:
                outcome = exc
        self.assertEqual(create_share.call_count, 0)
        return outcome, {"submit": submit, "capture": capture, "pin": pin}

    def _run_with_fake_browser(self, config: dict) -> dict:
        result, _ = self._drive_fake_browser(config)
        self.assertIsInstance(result, dict)
        return result

    def test_valid_packet_final_send_screen_refuses_encoded_context(self) -> None:
        from cwo_core.outbound_screen import screen_outbound
        from tests.test_outbound_screen import packet_with, with_provenance

        config = {"selectors": {}, "chrome_user_data_dir": "/tmp/profile"}
        snippets = (
            ("ordinary", "Review the plan.", False),
            ("escaped JSON", r'Inspect {"\u0070assword":"VelvetSunset42!"}', True),
            ("data URI", "Inspect data:text/plain;base64,cGFzc3dvcmQ9VmVsdmV0U3Vuc2V0NDIh", True),
        )
        for label, snippet, refused in snippets:
            with self.subTest(case=label), tempfile.TemporaryDirectory() as tmpdir:
                packet = packet_with(snippet)
                path = Path(tmpdir) / "packet.json"
                path.write_text(json.dumps(packet), encoding="utf-8")
                # Exercise normal packet content AND provenance checks, without a waiver.
                with with_provenance(packet):
                    prompt, _ = chatgpt_browser_review.load_prompt_from_args(Namespace(
                        packet=str(path), prompt_file=None, allow_degraded_packet=False, allow_unlinked_packet=False))
                scans = []
                real_screen = chatgpt_browser_review.require_clean

                def record_screen(text, **kwargs):
                    scans.append(text)
                    return real_screen(text, **kwargs)

                with patch.object(chatgpt_browser_review.secrets, "token_hex", return_value="0123456789abcdef0123456789abcdef"), \
                        patch.object(chatgpt_browser_review, "require_clean", side_effect=record_screen):
                    outcome, mocks = self._drive_fake_browser(config, prompt=prompt)
                final = bound_request(prompt, "0123456789abcdef0123456789abcdef")
                screened = screen_outbound(final, surface="ChatGPT browser Send")
                self.assertEqual(bool(screened.findings), refused)
                if refused:
                    self.assertEqual(mocks["submit"].call_count, 0, "refused final bytes must never reach fake Send")
                    self.assertIsInstance(outcome, ChatGPTBrowserReviewError, "valid encoded context must reach final-byte refusal")
                    self.assertIn("outbound screening refused ChatGPT browser Send", outcome.reason)
                    self.assertNotIn("VelvetSunset42!", outcome.reason)
                    self.assertEqual(mocks["capture"].call_count, 0)
                    self.assertEqual(scans, [final], "screen the actual request-ID-appended Send bytes")
                else:
                    self.assertIsInstance(outcome, dict)
                    self.assertEqual(mocks["submit"].call_count, 1, "matched clean fake Send must function")
                    self.assertEqual(mocks["submit"].call_args.args[1].encode("utf-8"), screened.data)
                    self.assertEqual(outcome["submitted_sha256"], screened.sha256)
                    self.assertEqual(mocks["capture"].call_args.kwargs["prompt"], final)

    def test_submission_carries_a_fresh_request_id_bound_into_the_capture(self) -> None:
        config = {"selectors": {}, "chrome_user_data_dir": "/tmp/profile"}
        seen = []
        for _ in range(2):
            result, mocks = self._drive_fake_browser(config, prompt="Review this.")
            self.assertEqual(mocks["submit"].call_count, 1)
            submitted = mocks["submit"].call_args.args[1]
            self.assertEqual(submitted, bound_request("Review this.", result["request_id"]))
            self.assertEqual(result["submitted_sha256"], chatgpt_browser_review.artifact_hash(submitted))
            self.assertEqual(mocks["submit"].call_args.args[3], result["request_id"])
            kwargs = mocks["capture"].call_args.kwargs
            self.assertEqual((kwargs["prompt"], kwargs["request_id"]), (submitted, result["request_id"]))
            self.assertEqual(kwargs["pinned_conversation_id"], "0123abcd-4567")
            self.assertEqual(mocks["pin"].call_args.args[1], result["request_id"])
            seen.append(result["request_id"])
        self.assertNotEqual(seen[0], seen[1])

    def test_prompt_is_not_typed_outside_a_chatgpt_origin_or_unreadable_conversation(self) -> None:
        config = {"selectors": {}, "chrome_user_data_dir": "/tmp/profile"}
        cases = {
            "look-alike host": {"page_url": "https://chatgpt.com.example/"},
            "plain http": {"page_url": "http://chatgpt.com/"},
            "blank page": {"page_url": "about:blank"},
            "snapshot names another origin": {"snapshot": {"available": True, "messages": [], "url": "https://example.com/"}},
            "conversation unreadable": {"snapshot": {"available": False, "messages": [], "url": ""}},
        }
        for label, overrides in cases.items():
            with self.subTest(case=label):
                outcome, mocks = self._drive_fake_browser(config, **overrides)
                self.assertIsInstance(outcome, ChatGPTBrowserReviewError)
                self.assertEqual(outcome.stage, "prompt-submit")
                self.assertIn("the prompt was not sent", outcome.reason)
                self.assertEqual(mocks["submit"].call_count, 0)
                self.assertEqual(mocks["capture"].call_count, 0)

    class _Handle:
        """A fake element handle in a frame at ``url``; its scripts are answered by ``answer(script, arg)``."""

        def __init__(self, answer: object, url: object) -> None:
            self.answer, self.url = answer, url
            self.scripts: list[tuple[str, object]] = []

        def owner_frame(self) -> object:
            url = self.url() if callable(self.url) else self.url
            return type("Frame", (), {"url": url})()

        def evaluate(self, script: str, arg: object = None) -> object:
            self.scripts.append((script, arg))
            return self.answer(script, arg)

        def evaluate_handle(self, script: str, arg: object = None) -> object:
            self.scripts.append((script, arg))
            return self.answer(script, arg)

        def as_element(self) -> object:
            return self

    def _submit_with(self, *, box_url: object = "https://chatgpt.com/c/0123abcd-4567", button_url: object = None,
                     insert: object = None, find: object = None, press: object = None, timeout_ms: int = 2000) -> tuple[object, dict]:
        """Drive _submit_prompt against fake handles with no keyboard, mouse or locator."""
        results: list[object] = []

        def press_answer(script: str, arg: object) -> object:
            result = (press or (lambda count: "pressed"))(len(results) + 1)
            results.append(result)
            return result

        button = self._Handle(press_answer, box_url if button_url is None else button_url)

        def box_answer(script: str, arg: object) -> object:
            if script in (chatgpt_browser_review._STAMP_SCRIPT, chatgpt_browser_review._FILL_SCRIPT):
                return (insert or (lambda script, arg: True))(script, arg)
            if script == chatgpt_browser_review._SEND_BUTTON_SCRIPT:
                return (find or (lambda handle: handle))(button)
            raise AssertionError(script)

        box = self._Handle(box_answer, box_url)

        class Page:
            def query_selector_all(self, selector: str) -> list:
                return [object(), box]

        runner = PlaywrightChatGPTRunner({"selectors": {}})
        with patch.object(chatgpt_browser_review.time, "sleep"):
            try:
                outcome: object = runner._submit_prompt(Page(), "Prompt text", timeout_ms, "0123456789abcdef0123456789abcdef")
            except SystemExit as exc:
                outcome = exc
        return outcome, {"box": box, "button": button, "results": results}

    def test_submit_inserts_and_presses_send_inside_the_checked_document(self) -> None:
        outcome, seen = self._submit_with(press=lambda count: "waiting" if count < 3 else "pressed")
        self.assertEqual(outcome, "pressed")
        self.assertEqual([script for script, _ in seen["box"].scripts[:2]],
                         [chatgpt_browser_review._STAMP_SCRIPT, chatgpt_browser_review._FILL_SCRIPT])
        self.assertEqual(seen["box"].scripts[0][1], "0123456789abcdef0123456789abcdef")
        self.assertEqual(seen["box"].scripts[1][1], "Prompt text", "the prompt is passed as one primitive argument")
        self.assertEqual([arg for _, arg in seen["button"].scripts], ["0123456789abcdef0123456789abcdef"] * 3)
        self.assertEqual(len(seen["results"]), 3, "Send waits until the control is enabled")

    def test_no_script_receives_the_prompt_outside_a_chatgpt_frame(self) -> None:
        for url in ("https://chatgpt.com.example/", "http://chatgpt.com/", "about:blank", "https://user@chatgpt.com/"):
            with self.subTest(url=url):
                outcome, seen = self._submit_with(box_url=url)
                self.assertIsInstance(outcome, SystemExit)
                self.assertIn("not on a ChatGPT origin", str(outcome))
                self.assertEqual(seen["box"].scripts, [], "no script ran in that document")

    def test_submit_never_reaches_another_document(self) -> None:
        def destroyed(*_: object) -> object:
            raise RuntimeError("Execution context was destroyed, most likely because of a navigation")

        cases = {
            "frame cannot be read": {"box_url": lambda: destroyed()},
            "replaced before insertion": {"insert": destroyed},
            "composer left the page": {"insert": lambda script, arg: False},
            "replaced before Send": {"find": destroyed},
            "send control in another frame origin": {"button_url": "https://chatgpt.com.example/"},
            "send script refuses the stamp": {"press": lambda count: "refused"},
            "Send never enabled": {"press": lambda count: "waiting"},
        }
        for label, overrides in cases.items():
            with self.subTest(case=label):
                outcome, seen = self._submit_with(timeout_ms=1, **overrides)
                self.assertIsInstance(outcome, SystemExit)
                self.assertIn("the prompt was not sent", str(outcome))
                self.assertNotIn("pressed", seen["results"], "Send was never pressed")

    def test_failure_inside_the_send_script_is_reported_as_uncertain(self) -> None:
        def pressed_then_lost(count: int) -> object:
            if count < 2:
                return "waiting"
            raise RuntimeError("Target page, context or browser has been closed")

        outcome, _ = self._submit_with(press=pressed_then_lost)
        self.assertIsInstance(outcome, SystemExit)
        self.assertIn("may have been submitted", str(outcome))
        self.assertNotIn("not sent", str(outcome))

    def test_interruption_while_pressing_send_keeps_its_type_and_says_so(self) -> None:
        def pressed_then_interrupted(count: int) -> object:
            if count < 2:
                return "waiting"
            raise KeyboardInterrupt  # the click happened; its answer never came back

        with self.assertRaises(KeyboardInterrupt) as raised:
            self._submit_with(press=pressed_then_interrupted)
        notes = " ".join(getattr(raised.exception, "__notes__", []))
        self.assertIn("may have been submitted", notes)

    def test_any_failure_in_run_after_send_says_the_prompt_went_out(self) -> None:
        cases = {
            "interrupted while pressing": ("may-have-been-submitted", "may have been submitted"),
            "interrupted after pressing (for example in teardown)": ("submitted", "the prompt was submitted"),
            "interrupted before Send": ("not-sent", None),
        }
        for label, (state, expected) in cases.items():
            with self.subTest(case=label):
                runner = PlaywrightChatGPTRunner({"selectors": {}})
                runner.send_state = "submitted"  # left over from an earlier run; run() starts afresh

                def fail_after(prompt: str, state: str = state) -> object:
                    runner.send_state = state
                    raise KeyboardInterrupt

                with patch.object(runner, "_run", side_effect=fail_after):
                    with self.assertRaises(KeyboardInterrupt) as raised:
                        runner.run("Prompt")
                notes = " ".join(getattr(raised.exception, "__notes__", []))
                if expected:
                    self.assertIn(expected, notes)
                else:
                    self.assertNotIn("submitted", notes)

    def test_submit_uses_no_page_level_input(self) -> None:
        import ast
        import inspect
        import textwrap

        tree = ast.parse(textwrap.dedent(inspect.getsource(PlaywrightChatGPTRunner._submit_prompt)))
        used = {node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)}
        self.assertFalse(used & {"keyboard", "mouse", "locator", "fill", "click", "type", "press", "insert_text"}, used)

    def _pin_with(self, timeline: list, before_url: str) -> str | None:
        runner = PlaywrightChatGPTRunner({"selectors": {}})
        page = self._dom(timeline)
        clock = iter(float(tick) for tick in range(1000))
        with patch.object(chatgpt_browser_review.time, "sleep"), \
                patch.object(chatgpt_browser_review.time, "monotonic", side_effect=lambda: next(clock)):
            return runner._pin_conversation(page, self.REQUEST_ID, before_url, 20_000)

    def test_conversation_is_pinned_when_the_submitted_turn_first_appears(self) -> None:
        turn = [self._message("user", "u1", self.SUBMITTED)]
        new_chat = self._state(turn, url="https://chatgpt.com/")
        landed = self._state(turn, url="https://chatgpt.com/c/aaaaaaaa-0000-1111")
        moved = self._state(turn, url="https://chatgpt.com/c/bbbbbbbb-0000-1111")
        self.assertEqual(self._pin_with([new_chat, landed, moved], "https://chatgpt.com/"), "aaaaaaaa-0000-1111")
        self.assertEqual(self._pin_with([landed], self.URL), None, "an already open conversation must be the one pinned")
        self.assertEqual(self._pin_with([self._state(turn, url=self.URL)], self.URL), "0123abcd-4567-89ef")
        replaced = self._state(turn, url="https://chatgpt.com/c/aaaaaaaa-0000-1111", stamp=None)
        self.assertIsNone(self._pin_with([new_chat, replaced], "https://chatgpt.com/"), "a replaced document breaks the binding")
        elsewhere = self._state(turn, url="https://chat.openai.com/c/aaaaaaaa-0000-1111")
        self.assertIsNone(self._pin_with([elsewhere], "https://chatgpt.com/"))
        doubled = self._state(turn + turn, url="https://chatgpt.com/c/aaaaaaaa-0000-1111")
        self.assertIsNone(self._pin_with([doubled], "https://chatgpt.com/"))

    def test_waiting_continues_until_the_bound_reply_is_terminal(self) -> None:
        runner = PlaywrightChatGPTRunner({"selectors": {}})
        texts = iter(["before"] + ["before plus a long enough response body"] * 200)
        for terminal, confirmed in ((True, True), (False, False)):
            with self.subTest(terminal=terminal), patch.object(runner, "_conversation_text", side_effect=lambda page: next(texts)), \
                    patch.object(runner, "_response_in_progress", return_value=False), \
                    patch.object(runner, "_bound_reply_terminal", return_value=terminal) as probe, \
                    patch.object(chatgpt_browser_review.time, "sleep"), \
                    patch.object(chatgpt_browser_review.time, "monotonic", side_effect=[float(i) for i in range(0, 800, 2)]):
                runner._wait_for_stable_response(object(), "before", response_timeout=300, stable_wait=4, request_id=self.REQUEST_ID)
            self.assertEqual(runner.completion_confirmed, confirmed)
            self.assertTrue(probe.called)

    def test_waiting_and_capture_share_the_generation_predicate(self) -> None:
        scripts: list[str] = []

        class Page:
            def evaluate(self, script: str, arg: object = None) -> object:
                scripts.append(script)
                return False

        PlaywrightChatGPTRunner({"selectors": {}})._response_in_progress(Page())
        self.assertIn(chatgpt_browser_review._GENERATING_JS, scripts[0])
        self.assertIn(chatgpt_browser_review._GENERATING_JS, chatgpt_browser_review._SNAPSHOT_SCRIPT)

    def test_config_refuses_a_target_outside_chatgpt(self) -> None:
        for url in ("https://chatgpt.com.example/", "http://chatgpt.com/", "https://example.com/c/abc"):
            with self.subTest(url=url), tempfile.TemporaryDirectory() as tmpdir:
                path = self.write_config(Path(tmpdir))
                data = json.loads(path.read_text(encoding="utf-8"))
                data["chatgpt_url"] = url
                path.write_text(json.dumps(data), encoding="utf-8")
                with self.assertRaises(SystemExit):
                    load_browser_config(path)

    def test_response_dir_is_read_the_way_the_writer_reads_it(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir).resolve()
            (base / "outside" / "nested").mkdir(parents=True)
            repo = base / "repo"
            repo.mkdir()
            (repo / "alias").symlink_to(base / "outside" / "nested")
            with patch.object(chatgpt_browser_review, "REPO_ROOT", repo):
                # Resolving gives <outside>/returns; collapsing gives <repo>/returns.
                with self.assertRaises(SystemExit) as raised:
                    resolve_response_dir(str(repo / "alias" / ".." / "returns"))
                self.assertIn("..", str(raised.exception))
                with self.assertRaises(SystemExit):
                    resolve_response_dir(str(repo / "alias" / "returns"))
                self.assertEqual(resolve_response_dir(str(base / "outside" / "returns")), base / "outside" / "returns")

    def test_interrupted_response_write_reports_the_retained_provenance(self) -> None:
        from cwo_core.private_artifact import PrivateDirectory

        browser_result = {
            "response_text": "Reply body",
            "capture_complete": True,
            "capture_checks": {name: True for name in chatgpt_browser_review.CAPTURE_CHECKS},
        }
        real_write = PrivateDirectory.write

        def interrupt_response(handle: PrivateDirectory, name: str, data: bytes) -> Path:
            if name.endswith(".response.txt"):
                raise KeyboardInterrupt
            return real_write(handle, name, data)

        with tempfile.TemporaryDirectory() as tmpdir:
            response_dir = Path(tmpdir) / "returns"
            with patch.object(PrivateDirectory, "write", interrupt_response):
                with self.assertRaises(KeyboardInterrupt) as raised:
                    write_private_response(response_dir, metadata={"dispatch_id": "dispatch-1"}, prompt="Prompt",
                                           browser_result=browser_result)
            leftovers = [path.name for path in response_dir.iterdir()]
        self.assertEqual(len(leftovers), 1)
        self.assertTrue(leftovers[0].endswith(".provenance.json"))
        notes = getattr(raised.exception, "__notes__", [])
        self.assertTrue(any(leftovers[0] in note and "retained" in note for note in notes), notes)

    def test_failure_after_response_publication_reports_both_files(self) -> None:
        import errno

        import cwo_core.private_artifact as module
        from ingest_chatgpt_share_return import load_private_response

        browser_result = {
            "response_text": "Reply body",
            "request_id": "0123456789abcdef0123456789abcdef",
            "submitted_sha256": "c" * 64,
            "conversation_url": "https://chatgpt.com/c/0123abcd-4567",
            "conversation_id": "0123abcd-4567",
            "assistant_message_id": "msg-9",
            "user_message_id": "msg-8",
            "response_extraction": "assistant-message",
            "capture_complete": True,
            "capture_checks": {name: True for name in chatgpt_browser_review.CAPTURE_CHECKS},
        }
        real_fsync, real_open = os.fsync, module.PrivateDirectory.open
        directory_fds: set[int] = set()
        syncs: list[int] = []

        def open_directory(path: Path, *, create: bool = False) -> object:
            handle = real_open(path, create=create)
            directory_fds.add(handle.descriptor)
            return handle

        def fsync(fd: int) -> None:
            if fd in directory_fds:
                syncs.append(fd)
                if len(syncs) == 2:  # the directory sync after the response is linked
                    raise OSError(errno.EIO, "Input/output error")
            real_fsync(fd)

        with tempfile.TemporaryDirectory() as tmpdir:
            response_dir = Path(tmpdir) / "returns"
            with patch.object(module.PrivateDirectory, "open", side_effect=open_directory), \
                    patch.object(module.os, "fsync", side_effect=fsync):
                with self.assertRaises(SystemExit) as raised:
                    write_private_response(response_dir, metadata={"dispatch_id": "dispatch-1", "packet_sha256": "a" * 64},
                                           prompt="Prompt", browser_result=browser_result)
            message = str(raised.exception)
            names = sorted(path.name for path in response_dir.iterdir())
            self.assertEqual(len(names), 2)
            self.assertIn("are both retained", message)
            provenance = next(response_dir / name for name in names if name.endswith(".provenance.json"))
            text, _, _ = load_private_response(provenance, packet_sha256=None, dispatch_id=None, bead_id=None)
        self.assertEqual(text, "Reply body", "a complete, verifiable pair remains ingestible")

    def test_reply_whitespace_survives_capture_and_ingest(self) -> None:
        from ingest_chatgpt_share_return import load_private_response

        reply = "\n    def code():\n        return 1\n"
        captured = self._capture([self._complete_state(reply=reply)])
        self.assertTrue(captured["capture_complete"], captured["incomplete_reasons"])
        self.assertEqual(captured["text"], reply)
        browser_result = {
            "response_text": captured["text"],
            "request_id": "0123456789abcdef0123456789abcdef",
            "submitted_sha256": "c" * 64,
            "conversation_url": "https://chatgpt.com/c/0123abcd-4567",
            "conversation_id": "0123abcd-4567",
            "assistant_message_id": "a1",
            "user_message_id": "u1",
            "response_extraction": "assistant-message",
            "capture_complete": True,
            "capture_checks": {name: True for name in chatgpt_browser_review.CAPTURE_CHECKS},
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            artifact = write_private_response(Path(tmpdir) / "returns", metadata={"dispatch_id": "dispatch-1", "packet_sha256": "a" * 64},
                                              prompt="Prompt", browser_result=browser_result)
            text, _, _ = load_private_response(Path(artifact["provenance_path"]), packet_sha256=None, dispatch_id=None, bead_id=None)
            import ingest_chatgpt_share_return
            from cwo_core.packets import fenced_block

            stdout = io.StringIO()
            with patch.object(sys, "argv", ["ingest_chatgpt_share_return.py", "--private-artifact", artifact["provenance_path"]]), \
                    contextlib.redirect_stdout(stdout):
                ingest_chatgpt_share_return.main()
        self.assertEqual(text, reply)
        self.assertIn(fenced_block(reply, "text"), stdout.getvalue(), "the rendered return carries the reply unchanged")

    def test_failures_after_publication_name_the_artifact(self) -> None:
        for stage in ("audit", "output"):
            with self.subTest(stage=stage), tempfile.TemporaryDirectory() as cfgdir, \
                    tempfile.TemporaryDirectory(dir=ROOT) as promptdir:
                patches = []
                if stage == "audit":
                    patches.append(patch.object(chatgpt_browser_review, "record_audit_event", side_effect=OSError(28, "No space left on device")))
                else:
                    patches.append(patch.object(chatgpt_browser_review, "atomic_write_text", side_effect=OSError(28, "No space left on device")))
                with contextlib.ExitStack() as stack:
                    for item in patches:
                        stack.enter_context(item)
                    with self.assertRaises(OSError) as raised:
                        self._run_live_cli(self._browser_result(), Path(cfgdir), Path(promptdir), audit=(stage == "audit"))
                response_dir = Path(cfgdir) / "returns"
                names = sorted(path.name for path in response_dir.iterdir())
                notes = " ".join(getattr(raised.exception, "__notes__", []))
                self.assertEqual(len(names), 2)
                for name in names:
                    self.assertIn(name, notes)

    def test_writer_failure_then_audit_failure_still_names_the_files(self) -> None:
        import errno

        import cwo_core.private_artifact as module

        real_fsync, real_open = os.fsync, module.PrivateDirectory.open
        directory_fds: set[int] = set()
        syncs: list[int] = []

        def open_directory(path: Path, *, create: bool = False) -> object:
            handle = real_open(path, create=create)
            directory_fds.add(handle.descriptor)
            return handle

        def fsync(fd: int) -> None:
            if fd in directory_fds:
                syncs.append(fd)
                if len(syncs) == 2:  # the directory sync after the response is linked
                    raise OSError(errno.EIO, "Input/output error")
            real_fsync(fd)

        with tempfile.TemporaryDirectory() as cfgdir, tempfile.TemporaryDirectory(dir=ROOT) as promptdir:
            with patch.object(module.PrivateDirectory, "open", side_effect=open_directory), \
                    patch.object(module.os, "fsync", side_effect=fsync), \
                    patch.object(chatgpt_browser_review, "record_audit_event", side_effect=OSError(28, "No space left on device")):
                with self.assertRaises(OSError) as raised:
                    self._run_live_cli(self._browser_result(), Path(cfgdir), Path(promptdir), audit=True)
            names = sorted(path.name for path in (Path(cfgdir) / "returns").iterdir())
        notes = " ".join(getattr(raised.exception, "__notes__", []))
        self.assertEqual(len(names), 2)
        for name in names:
            self.assertIn(name, notes)

    def test_interruption_between_publication_and_bookkeeping_names_the_files(self) -> None:
        from cwo_core.private_artifact import PrivateDirectory

        real_write = PrivateDirectory.write
        names = ("EXAMPLE.provenance.json", "EXAMPLE.response.txt")
        for interrupted_name in names:
            for move_file in (False, True):
                with self.subTest(name=interrupted_name, move_file=move_file), tempfile.TemporaryDirectory() as tmpdir:
                    response_dir = Path(tmpdir) / "returns"
                    moved = Path(tmpdir) / "EXAMPLE-moved"
                    written: list[tuple[Path, bytes]] = []
                    retained: list[str] = []
                    primary = KeyboardInterrupt("EXAMPLE interruption after successful write")

                    def write_then_interrupt(handle: PrivateDirectory, name: str, data: bytes) -> Path:
                        path = real_write(handle, name, data)
                        written.append((path, data))
                        if name == interrupted_name:
                            if move_file:
                                path.rename(moved)
                                self.assertIs(handle.contains(name), False)
                                self.assertFalse(path.exists())
                            raise primary  # the real writer returned, but caller bookkeeping has not run
                        return path

                    with patch.object(PrivateDirectory, "write", write_then_interrupt):
                        with self.assertRaises(KeyboardInterrupt) as raised:
                            write_private_response(response_dir, metadata={"dispatch_id": "EXAMPLE"}, prompt="EXAMPLE prompt",
                                                   browser_result=self._browser_result(), retained=retained, names=names)
                    self.assertIs(raised.exception, primary)
                    self.assertEqual(len(written), names.index(interrupted_name) + 1)
                    self.assertEqual(retained, [str(path) for path, _ in written])
                    notes = " ".join(getattr(primary, "__notes__", []))
                    for path, data in written:
                        self.assertIn(str(path), notes)
                        was_moved = move_file and path.name == interrupted_name
                        if was_moved:
                            self.assertIn(f"{path} was published, but is no longer at that path", notes)
                            self.assertNotIn(f"{path} was published and is retained", notes)
                        actual = moved if was_moved else path
                        self.assertEqual(actual.read_bytes(), data)
                        self.assertEqual(stat.S_IMODE(actual.stat().st_mode), 0o600)

    def test_interruption_at_the_writers_return_names_both_files(self) -> None:
        import inspect

        source, first = inspect.getsourcelines(write_private_response)
        target = first + next(index for index, text in enumerate(source) if text.strip() == "return reference")
        code = write_private_response.__code__

        def tracer(frame: object, event: str, arg: object) -> object:
            if frame.f_code is not code:  # type: ignore[attr-defined]
                return None

            def local(frame: object, event: str, arg: object) -> object:
                if event == "line" and frame.f_lineno == target:  # type: ignore[attr-defined]
                    raise KeyboardInterrupt  # both files published, the reference not yet returned
                return local
            return local

        with tempfile.TemporaryDirectory() as tmpdir:
            response_dir = Path(tmpdir) / "returns"
            sys.settrace(tracer)
            try:
                with self.assertRaises(KeyboardInterrupt) as raised:
                    write_private_response(response_dir, metadata={"dispatch_id": "dispatch-1"}, prompt="Prompt",
                                           browser_result=self._browser_result())
            finally:
                sys.settrace(None)
            names = sorted(path.name for path in response_dir.iterdir())
        notes = " ".join(getattr(raised.exception, "__notes__", []))
        self.assertEqual(len(names), 2)
        for name in names:
            self.assertIn(name, notes)

    def interrupt_on_the_way_into_cleanup(self, function: object, call: object) -> BaseException:
        """Raise KeyboardInterrupt at the first line inside ``function``'s ``finally`` block, after publication."""
        import inspect

        source, first = inspect.getsourcelines(function)  # type: ignore[arg-type]
        target = first + next(index for index, text in enumerate(source) if text.strip() == "finally:") + 1
        code = function.__code__  # type: ignore[attr-defined]
        fired: list[int] = []

        def tracer(frame: object, event: str, arg: object) -> object:
            if frame.f_code is not code:  # type: ignore[attr-defined]
                return None

            def local(frame: object, event: str, arg: object) -> object:
                if event == "line" and frame.f_lineno == target and not fired:  # type: ignore[attr-defined]
                    fired.append(target)
                    raise KeyboardInterrupt  # published; cleanup has not run
                return local
            return local

        sys.settrace(tracer)
        try:
            with self.assertRaises(KeyboardInterrupt) as raised:
                call()  # type: ignore[operator]
        finally:
            sys.settrace(None)
        self.assertEqual(fired, [target], "the interruption reached the cleanup entry")
        return raised.exception

    def test_an_interruption_on_the_way_into_cleanup_names_the_files(self) -> None:
        from cwo_core.private_artifact import write_private_artifact

        with tempfile.TemporaryDirectory() as tmpdir:
            response_dir = Path(tmpdir) / "returns"
            exc = self.interrupt_on_the_way_into_cleanup(write_private_response, lambda: write_private_response(
                response_dir, metadata={"dispatch_id": "dispatch-1"}, prompt="Prompt", browser_result=self._browser_result()))
            names = sorted(path.name for path in response_dir.iterdir())
            notes = " ".join(getattr(exc, "__notes__", []))
            self.assertEqual(len(names), 2)
            for name in names:
                self.assertIn(name, notes)
            artifact_dir = Path(tmpdir) / "artifacts"
            exc = self.interrupt_on_the_way_into_cleanup(write_private_artifact,
                                                         lambda: write_private_artifact(artifact_dir, "run.txt", b"data"))
            self.assertIn(f"{artifact_dir / 'run.txt'} was published and is retained", getattr(exc, "__notes__", []))

    def test_a_moved_directory_does_not_hide_what_was_published(self) -> None:
        """Another process moves the private directory after publication; a failure that follows still reports
        the files the writer knows it published, as no longer at their paths."""
        from cwo_core.private_artifact import PrivateDirectory, write_private_artifact

        real_close = PrivateDirectory.close

        def move_then_interrupt(handle: PrivateDirectory) -> None:
            real_close(handle)
            handle.path.rename(handle.path.with_name(handle.path.name + "-moved"))
            raise KeyboardInterrupt  # cleanup interrupted after the directory moved

        with tempfile.TemporaryDirectory() as tmpdir:
            response_dir = Path(tmpdir) / "returns"
            with patch.object(PrivateDirectory, "close", move_then_interrupt), self.assertRaises(KeyboardInterrupt) as raised:
                write_private_response(response_dir, metadata={"dispatch_id": "dispatch-1"}, prompt="Prompt",
                                       browser_result=self._browser_result())
            moved = sorted(path.name for path in (Path(tmpdir) / "returns-moved").iterdir())
            notes = " ".join(getattr(raised.exception, "__notes__", []))
            self.assertEqual(len(moved), 2)
            for name in moved:
                self.assertIn(f"{response_dir / name} was published, but is no longer at that path", notes)
            artifact_dir = Path(tmpdir) / "artifacts"
            with patch.object(PrivateDirectory, "close", move_then_interrupt), self.assertRaises(KeyboardInterrupt) as raised:
                write_private_artifact(artifact_dir, "run.txt", b"data")
            self.assertIn(f"{artifact_dir / 'run.txt'} was published, but is no longer at that path",
                          " ".join(getattr(raised.exception, "__notes__", [])))

    def test_a_moved_directory_and_a_later_failure_still_report_the_publication(self) -> None:
        def submitted(runner: PlaywrightChatGPTRunner, prompt: str) -> dict:
            runner.send_state = "submitted"
            return self._browser_result()

        def move_then_fail(event: dict, **_: object) -> None:
            returns = Path(cfgdir) / "returns"
            returns.rename(returns.with_name("returns-moved"))
            raise OSError("audit log unavailable")

        with tempfile.TemporaryDirectory() as cfgdir, tempfile.TemporaryDirectory(dir=ROOT) as promptdir:
            with patch.object(chatgpt_browser_review, "record_audit_event", side_effect=move_then_fail), \
                    self.assertRaises(OSError) as raised:
                self._run_live_cli(self._browser_result(), Path(cfgdir), Path(promptdir), audit=True, run=submitted)
            moved = sorted(path.name for path in (Path(cfgdir) / "returns-moved").iterdir())
        notes = " ".join(getattr(raised.exception, "__notes__", []))
        self.assertIn("the prompt was submitted", notes)
        self.assertEqual(len(moved), 2)
        for name in moved:
            self.assertIn(f"{name} (published, but no longer at that path)", notes)

    def test_interruption_after_the_writer_returns_names_the_files_and_the_submission(self) -> None:
        from cwo_core.private_artifact import PrivateDirectory

        real_writer, real_write = chatgpt_browser_review.write_private_response, PrivateDirectory.write

        def submitted(runner: PlaywrightChatGPTRunner, prompt: str) -> dict:
            runner.send_state = "submitted"
            return self._browser_result()

        for stage in ("response-return", ".provenance.json", ".response.txt"):
            with self.subTest(stage=stage), tempfile.TemporaryDirectory() as cfgdir, \
                    tempfile.TemporaryDirectory(dir=ROOT) as promptdir:
                moved = Path(cfgdir) / "EXAMPLE-moved"
                written: list[tuple[Path, bytes]] = []
                retained_lists: list[list[str]] = []
                primary = KeyboardInterrupt("EXAMPLE interruption after successful write")

                def write_then_move(handle: PrivateDirectory, name: str, data: bytes) -> Path:
                    path = real_write(handle, name, data)
                    written.append((path, data))
                    if name.endswith(stage):
                        path.rename(moved)
                        self.assertIs(handle.contains(name), False)
                        self.assertFalse(path.exists())
                        raise primary  # main must retain this fact despite both absent lookups
                    return path

                def write_then_interrupt(*args: object, **kwargs: object) -> object:
                    retained_lists.append(kwargs["retained"])  # type: ignore[arg-type]
                    real_writer(*args, **kwargs)
                    raise primary  # original case: returned, but main has not recorded the reference

                with patch.object(PrivateDirectory, "write", write_then_move), \
                        patch.object(chatgpt_browser_review, "write_private_response", side_effect=write_then_interrupt):
                    with self.assertRaises(KeyboardInterrupt) as raised:
                        self._run_live_cli(self._browser_result(), Path(cfgdir), Path(promptdir), run=submitted)
                self.assertIs(raised.exception, primary)
                self.assertEqual(len(written), 1 if stage == ".provenance.json" else 2)
                self.assertEqual(retained_lists, [[str(path) for path, _ in written]])
                notes = " ".join(getattr(primary, "__notes__", []))
                self.assertIn("the prompt was submitted", notes)
                for path, data in written:
                    self.assertIn(str(path), notes)
                    was_moved = path.name.endswith(stage)
                    if was_moved:
                        self.assertIn(f"{path.name} (published, but no longer at that path)", notes)
                        self.assertNotIn(f"{path} was published and is retained", notes)
                    actual = moved if was_moved else path
                    self.assertEqual(actual.read_bytes(), data)
                    self.assertEqual(stat.S_IMODE(actual.stat().st_mode), 0o600)

    def test_interruption_before_send_names_nothing(self) -> None:
        def interrupted(runner: PlaywrightChatGPTRunner, prompt: str) -> dict:
            raise KeyboardInterrupt

        with tempfile.TemporaryDirectory() as cfgdir, tempfile.TemporaryDirectory(dir=ROOT) as promptdir:
            with self.assertRaises(KeyboardInterrupt) as raised:
                self._run_live_cli(self._browser_result(), Path(cfgdir), Path(promptdir), run=interrupted)
            returns = Path(cfgdir) / "returns"
            self.assertEqual(sorted(returns.iterdir()) if returns.exists() else [], [])
        self.assertEqual(getattr(raised.exception, "__notes__", []), [])

    def test_interrupted_directory_close_reports_both_publications(self) -> None:
        import cwo_core.private_artifact as module

        browser_result = {
            "response_text": "Reply body",
            "request_id": "0123456789abcdef0123456789abcdef",
            "capture_complete": True,
            "capture_checks": {name: True for name in chatgpt_browser_review.CAPTURE_CHECKS},
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            response_dir = Path(tmpdir) / "returns"
            with patch.object(module.PrivateDirectory, "close", side_effect=KeyboardInterrupt):
                with self.assertRaises(KeyboardInterrupt) as raised:
                    write_private_response(response_dir, metadata={"dispatch_id": "dispatch-1"}, prompt="Prompt",
                                           browser_result=browser_result)
            names = sorted(path.name for path in response_dir.iterdir())
        notes = " ".join(getattr(raised.exception, "__notes__", []))
        self.assertEqual(len(names), 2)
        for name in names:
            self.assertIn(name, notes)

    def test_directory_close_failure_keeps_the_references(self) -> None:
        import cwo_core.private_artifact as module

        browser_result = {
            "response_text": "Reply body",
            "request_id": "0123456789abcdef0123456789abcdef",
            "capture_complete": True,
            "capture_checks": {name: True for name in chatgpt_browser_review.CAPTURE_CHECKS},
        }
        real_close, real_open = os.close, module.PrivateDirectory.open
        directory_fds: set[int] = set()

        def open_directory(path: Path, *, create: bool = False) -> object:
            handle = real_open(path, create=create)
            directory_fds.add(handle.descriptor)
            return handle

        def close(fd: int) -> None:
            real_close(fd)
            if fd in directory_fds:
                directory_fds.discard(fd)
                raise OSError(5, "Input/output error")

        with tempfile.TemporaryDirectory() as tmpdir:
            response_dir = Path(tmpdir) / "returns"
            with patch.object(module.PrivateDirectory, "open", side_effect=open_directory), \
                    patch.object(module.os, "close", side_effect=close):
                artifact = write_private_response(response_dir, metadata={"dispatch_id": "dispatch-1"}, prompt="Prompt",
                                                  browser_result=browser_result)
            self.assertEqual(directory_fds, set(), "the failing close was exercised")
            self.assertTrue(Path(artifact["response_path"]).is_file())
            self.assertTrue(Path(artifact["provenance_path"]).is_file())
            self.assertTrue(artifact["capture_complete"])

    def test_default_run_never_creates_a_share(self) -> None:
        result = self._run_with_fake_browser({"selectors": {}, "chrome_user_data_dir": "/tmp/profile"})
        self.assertEqual(result["share_url"], "")
        self.assertEqual(result["response_text"], "Reply body")
        self.assertEqual(
            result["share"],
            {"created": False, "available": False, "reason": "share-consent-contract-unavailable", "requested_by_config": False},
        )

    def test_legacy_share_link_required_config_is_reported_but_not_honored(self) -> None:
        result = self._run_with_fake_browser(
            {"selectors": {}, "chrome_user_data_dir": "/tmp/profile", "share_link_required": True, "local_clipboard_fallback": True}
        )
        self.assertEqual(result["share_url"], "")
        self.assertFalse(result["share"]["created"])
        self.assertTrue(result["share"]["requested_by_config"])

    def test_browser_module_has_no_clipboard_access(self) -> None:
        import chatgpt_browser_review

        source = Path(chatgpt_browser_review.__file__).read_text(encoding="utf-8")
        for token in ("wl-paste", "xclip", "xsel", "klipper", "read_local_clipboard_share_url", "local_clipboard_fallback"):
            with self.subTest(token=token):
                self.assertNotIn(token, source)

    def test_dry_run_cli_validates_config_without_audit(self) -> None:
        with tempfile.TemporaryDirectory() as cfgdir, tempfile.TemporaryDirectory(dir=ROOT) as promptdir:
            tmp = Path(cfgdir)
            config = self.write_confirmation_config(tmp)
            prompt = Path(promptdir) / "prompt.md"
            prompt.write_text("Review this final plan.", encoding="utf-8")
            with patch.object(
                sys,
                "argv",
                [
                    "chatgpt_browser_review.py",
                    "--prompt-file",
                    str(prompt),
                    "--allow-degraded-packet",
                    "--allow-unlinked-packet",
                    "--dispatch-id",
                    "dispatch-chatgpt",
                    "--bead",
                    "cwo-1",
                    "--packet-sha256",
                    "packet-sha",
                    "--config",
                    str(config),
                    "--dry-run",
                    "--rehearsal",
                    "--json",
                    "--no-audit",
                    "--waiver-reason",
                    "test browser no-audit rehearsal",
                ],
            ):
                with patch("builtins.print") as mocked_print:
                    import chatgpt_browser_review

                    chatgpt_browser_review.main()
        self.assertTrue(mocked_print.called)

    def test_dry_run_json_refuses_missing_confirmation_selectors(self) -> None:
        with tempfile.TemporaryDirectory() as cfgdir, tempfile.TemporaryDirectory(dir=ROOT) as promptdir:
            tmp = Path(cfgdir)
            config = self.write_config(tmp)
            prompt = Path(promptdir) / "prompt.md"
            prompt.write_text("Review this final plan.", encoding="utf-8")
            with patch.object(
                sys,
                "argv",
                [
                    "chatgpt_browser_review.py",
                    "--prompt-file",
                    str(prompt),
                    "--allow-degraded-packet",
                    "--allow-unlinked-packet",
                    "--dispatch-id",
                    "dispatch-chatgpt",
                    "--bead",
                    "cwo-1",
                    "--packet-sha256",
                    "packet-sha",
                    "--config",
                    str(config),
                    "--dry-run",
                    "--rehearsal",
                    "--json",
                    "--no-audit",
                    "--waiver-reason",
                    "test browser no-audit rehearsal",
                ],
            ):
                with self.assertRaises(SystemExit) as context:
                    import chatgpt_browser_review

                    chatgpt_browser_review.main()

        self.assertIn("missing confirmation selectors", str(context.exception))
        self.assertIn("model_label_confirmation_selector", str(context.exception))

    def test_confirm_only_cli_records_model_attestation_without_submission(self) -> None:
        with tempfile.TemporaryDirectory() as cfgdir, tempfile.TemporaryDirectory(dir=ROOT) as promptdir:
            tmp = Path(cfgdir)
            config = self.write_confirmation_config(tmp)
            prompt = Path(promptdir) / "prompt.md"
            prompt.write_text("Review this final plan.", encoding="utf-8")
            with patch.object(
                sys,
                "argv",
                [
                    "chatgpt_browser_review.py",
                    "--prompt-file",
                    str(prompt),
                    "--allow-degraded-packet",
                    "--allow-unlinked-packet",
                    "--dispatch-id",
                    "dispatch-chatgpt",
                    "--bead",
                    "cwo-1",
                    "--packet-sha256",
                    "packet-sha",
                    "--config",
                    str(config),
                    "--confirm-only",
                    "--rehearsal",
                    "--json",
                    "--no-audit",
                    "--waiver-reason",
                    "test browser no-audit rehearsal",
                ],
            ):
                with patch.object(
                    PlaywrightChatGPTRunner,
                    "confirm_model_only",
                    return_value={
                        "model_attestation": {
                            "required": True,
                            "status": "confirmed",
                            "labels": {},
                        }
                    },
                ):
                    with patch("builtins.print") as mocked_print:
                        import chatgpt_browser_review

                        chatgpt_browser_review.main()
        rendered = mocked_print.call_args.args[0]
        self.assertIn('"status": "model-confirmed"', rendered)
        self.assertIn('"model_attestation"', rendered)


if __name__ == "__main__":
    unittest.main()
