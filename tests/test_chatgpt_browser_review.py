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
    EXECUTOR_KEY,
    build_result,
    config_summary,
    load_browser_config,
    load_prompt_from_args,
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
        self.assertNotIn(str(Path(tmpdir) / "profile"), rendered)

    def test_config_rejects_credential_fields(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            path = self.write_config(tmp)
            data = json.loads(path.read_text(encoding="utf-8"))
            data["google_password"] = "not-a-real-password"
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
                    "--no-audit",
                ],
            ):
                with patch("builtins.print") as mocked_print:
                    import chatgpt_browser_review

                    chatgpt_browser_review.main()
        self.assertTrue(mocked_print.called)


if __name__ == "__main__":
    unittest.main()
