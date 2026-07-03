from __future__ import annotations

import json
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

from chatgpt_browser_review import (  # noqa: E402
    ChatGPTBrowserReviewError,
    DEFAULT_MODEL_LABEL,
    DEFAULT_REASONING_LABEL,
    EXECUTOR_KEY,
    PlaywrightChatGPTRunner,
    build_result,
    config_summary,
    extract_chatgpt_share_url,
    load_browser_config,
    load_prompt_from_args,
    main as chatgpt_browser_main,
    read_local_clipboard_share_url,
    valid_chatgpt_share_url,
)
from build_contractor_packet import build_packet  # noqa: E402
import cwo_core.audit as audit_lib  # noqa: E402


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

    def test_config_summary_does_not_include_profile_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = self.write_config(Path(tmpdir))
            config = load_browser_config(path)
            summary = config_summary(config, path)
        rendered = json.dumps(summary, sort_keys=True)
        self.assertTrue(summary["config_present"])
        self.assertTrue(summary["config_external_to_repo"])
        self.assertTrue(summary["chrome_user_data_dir_configured"])
        self.assertTrue(summary["local_clipboard_fallback"])
        self.assertTrue(summary["require_model_confirmation"])
        self.assertFalse(summary["model_confirmation_configured"])
        self.assertNotIn(str(path), rendered)
        self.assertNotIn(str(Path(tmpdir)), rendered)
        self.assertNotIn(str(Path(tmpdir) / "profile"), rendered)

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

    def test_config_rejects_credential_fields(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            path = self.write_config(tmp)
            data = json.loads(path.read_text(encoding="utf-8"))
            data["google_password"] = "not-a-real-password"
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

    def test_config_rejects_remote_cdp_attach_url(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            path = self.write_config(tmp)
            data = json.loads(path.read_text(encoding="utf-8"))
            data["connect_over_cdp_url"] = "http://example.com:9222"
            path.write_text(json.dumps(data), encoding="utf-8")
            with self.assertRaises(SystemExit):
                load_browser_config(path)

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

    def test_dry_run_audit_records_sanitized_browser_telemetry(self) -> None:
        original_audit = audit_lib.AUDIT_LOG
        original_argv = sys.argv[:]
        prompt_path = ROOT / "tmp-chatgpt-browser-prompt-test.md"
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            config_path = self.write_config(tmp)
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

            def evaluate(self, script: str) -> bool:
                return True

            def input_value(self, timeout: int) -> str:
                raise RuntimeError("no input")

            def get_attribute(self, name: str, timeout: int) -> str | None:
                return None

        class FakePage:
            def __init__(self) -> None:
                self.clicks: list[str] = []

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
        self.assertEqual(runner._create_share_link(page, 1, TimeoutError), "")
        self.assertEqual(page.clicks[:2], ["button[aria-label='Jump to latest']", "button[aria-label='Jump to latest']"])
        self.assertIn("button[aria-label='Share']", page.clicks)

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

    def test_read_local_clipboard_accepts_only_chatgpt_share_urls(self) -> None:
        completed = type("Completed", (), {"stdout": "https://chatgpt.com/share/abc\n"})()
        with patch("shutil.which", return_value="/usr/bin/wl-paste"):
            with patch("subprocess.run", return_value=completed):
                self.assertEqual(read_local_clipboard_share_url(), "https://chatgpt.com/share/abc")

    def test_read_local_clipboard_accepts_qdbus_klipper_urls(self) -> None:
        completed = type("Completed", (), {"stdout": "https://chatgpt.com/s/t_abc\n"})()
        seen: list[list[str]] = []

        def fake_run(command: list[str], **_: object) -> object:
            seen.append(command)
            return completed

        with patch("shutil.which", return_value="/usr/bin/qdbus"):
            with patch("subprocess.run", side_effect=fake_run):
                self.assertEqual(read_local_clipboard_share_url(), "https://chatgpt.com/s/t_abc")
        self.assertEqual(seen[0][0], "qdbus")

    def test_read_local_clipboard_falls_back_after_timeout(self) -> None:
        completed = type("Completed", (), {"stdout": "share https://chatgpt.com/s/t_fallback"})()
        calls = 0

        def fake_run(command: list[str], **_: object) -> object:
            nonlocal calls
            calls += 1
            if command[0] == "qdbus":
                raise subprocess.TimeoutExpired(command, timeout=2)
            return completed

        with patch("shutil.which", return_value="/usr/bin/tool"):
            with patch("subprocess.run", side_effect=fake_run):
                self.assertEqual(read_local_clipboard_share_url(), "https://chatgpt.com/s/t_fallback")
        self.assertEqual(calls, 2)

    def test_read_local_clipboard_ignores_non_share_clipboard(self) -> None:
        completed = type("Completed", (), {"stdout": "plain private clipboard text"})()
        with patch("shutil.which", return_value="/usr/bin/wl-paste"):
            with patch("subprocess.run", return_value=completed):
                self.assertEqual(read_local_clipboard_share_url(), "")

    def test_create_share_link_rejects_unchanged_clipboard_without_copy_signal(self) -> None:
        class FakeLocator:
            @property
            def first(self) -> "FakeLocator":
                return self

            def click(self, timeout: int, force: bool = False) -> None:
                return None

            def evaluate(self, script: str) -> bool:
                return True

            def inner_text(self, timeout: int) -> str:
                return "share dialog still open"

        class FakePage:
            def locator(self, selector: str) -> FakeLocator:
                return FakeLocator()

        runner = PlaywrightChatGPTRunner({"selectors": {}, "local_clipboard_fallback": True})
        stale = "https://chatgpt.com/s/t_stale"
        with patch("chatgpt_browser_review.read_local_clipboard_share_url", return_value=stale):
            with patch.object(runner, "_click_scroll_to_bottom_if_present", return_value=None):
                with patch.object(runner, "_wait_for_share_ready", return_value=None):
                    with patch.object(runner, "_click_share_button", return_value=None):
                        with patch.object(runner, "_extract_share_url_from_page", return_value=""):
                            with patch.object(runner, "_try_social_share_url", return_value=""):
                                with patch("chatgpt_browser_review.time.monotonic", side_effect=[0, 1, 11]):
                                    with patch("chatgpt_browser_review.time.sleep", return_value=None):
                                        self.assertEqual(runner._create_share_link(FakePage(), 1, TimeoutError), "")

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

    def test_prompt_file_requires_explicit_degraded_operator_flag(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT) as tmpdir:
            prompt_path = Path(tmpdir) / "prompt.md"
            prompt_path.write_text("Review this final plan.", encoding="utf-8")
            args = Namespace(
                packet=None,
                prompt_file=str(prompt_path),
                allow_degraded_packet=False,
                allow_unlinked_packet=True,
                rehearsal=True,
                dispatch_id="dispatch-chatgpt",
                bead="cwo-1",
                epic="cwo",
                packet_sha256="packet-sha",
                share_boundary="redacted-packet",
            )
            with self.assertRaises(SystemExit):
                load_prompt_from_args(args)

    def test_prompt_file_rejects_unlinked_packet_hash_by_default(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT) as tmpdir:
            prompt_path = Path(tmpdir) / "prompt.md"
            prompt_path.write_text("Review this final plan.", encoding="utf-8")
            args = Namespace(
                packet=None,
                prompt_file=str(prompt_path),
                allow_degraded_packet=True,
                allow_unlinked_packet=False,
                rehearsal=True,
                dispatch_id="dispatch-chatgpt",
                bead="cwo-1",
                epic="cwo",
                packet_sha256="packet-sha",
                share_boundary="redacted-packet",
            )
            with self.assertRaises(SystemExit):
                load_prompt_from_args(args)

    def test_prompt_file_rejects_residual_secret_like_context(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT) as tmpdir:
            prompt_path = Path(tmpdir) / "prompt.md"
            prompt_path.write_text("private_key=abc123", encoding="utf-8")
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
            with self.assertRaises(SystemExit):
                load_prompt_from_args(args)

    def test_failed_live_cli_writes_structured_failure_output(self) -> None:
        with tempfile.TemporaryDirectory() as cfgdir, tempfile.TemporaryDirectory(dir=ROOT) as promptdir:
            tmp = Path(cfgdir)
            config = self.write_config(tmp)
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

    def test_dry_run_cli_validates_config_without_audit(self) -> None:
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
                ],
            ):
                with patch("builtins.print") as mocked_print:
                    import chatgpt_browser_review

                    chatgpt_browser_review.main()
        self.assertTrue(mocked_print.called)

    def test_confirm_only_cli_records_model_attestation_without_submission(self) -> None:
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
                    "--confirm-only",
                    "--rehearsal",
                    "--json",
                    "--no-audit",
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
