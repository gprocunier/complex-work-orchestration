from __future__ import annotations

import json
import os
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
    DEFAULT_MODEL_LABEL,
    DEFAULT_REASONING_LABEL,
    EXECUTOR_KEY,
    PlaywrightChatGPTRunner,
    build_result,
    config_summary,
    load_browser_config,
    load_prompt_from_args,
    read_local_clipboard_share_url,
    valid_chatgpt_share_url,
)


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
        self.assertTrue(summary["chrome_user_data_dir_configured"])
        self.assertTrue(summary["local_clipboard_fallback"])
        self.assertTrue(summary["require_model_confirmation"])
        self.assertFalse(summary["model_confirmation_configured"])
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

    def test_valid_chatgpt_share_url_accepts_share_shapes(self) -> None:
        self.assertTrue(valid_chatgpt_share_url("https://chatgpt.com/s/t_abc"))
        self.assertTrue(valid_chatgpt_share_url("https://chatgpt.com/share/abc"))
        self.assertFalse(valid_chatgpt_share_url("https://example.com/s/t_abc"))

    def test_create_share_link_does_not_read_clipboard(self) -> None:
        class FakeLocator:
            def click(self, timeout: int) -> None:
                return None

            @property
            def first(self) -> "FakeLocator":
                return self

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

    def test_read_local_clipboard_ignores_non_share_clipboard(self) -> None:
        completed = type("Completed", (), {"stdout": "plain private clipboard text"})()
        with patch("shutil.which", return_value="/usr/bin/wl-paste"):
            with patch("subprocess.run", return_value=completed):
                self.assertEqual(read_local_clipboard_share_url(), "")

    def test_prompt_file_dispatch_metadata_uses_executor_without_leaking_prompt(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            prompt_path = Path(tmpdir) / "prompt.md"
            prompt_path.write_text("Review this final plan.", encoding="utf-8")
            args = Namespace(
                packet=None,
                prompt_file=str(prompt_path),
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

    def test_dry_run_cli_validates_config_without_audit(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            config = self.write_config(tmp)
            prompt = tmp / "prompt.md"
            prompt.write_text("Review this final plan.", encoding="utf-8")
            with patch.object(
                sys,
                "argv",
                [
                    "chatgpt_browser_review.py",
                    "--prompt-file",
                    str(prompt),
                    "--config",
                    str(config),
                    "--dry-run",
                    "--json",
                    "--no-audit",
                ],
            ):
                with patch("builtins.print") as mocked_print:
                    import chatgpt_browser_review

                    chatgpt_browser_review.main()
        self.assertTrue(mocked_print.called)


if __name__ == "__main__":
    unittest.main()
