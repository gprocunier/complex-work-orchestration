from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from configure_codex_beads_hooks import (  # noqa: E402
    ConfigurationError,
    build_managed_hooks,
    detect_visibility_hint_support,
    merge_hooks,
)


class ConfigureCodexBeadsHooksTests(unittest.TestCase):
    def test_detect_visibility_hint_support_uses_installed_binary_signal(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            codex = Path(tmpdir) / "codex"
            codex.write_bytes(b"prefix visibilityHint middle HookVisibilityHint suffix")
            codex.chmod(0o755)
            support = detect_visibility_hint_support(str(codex))
        self.assertTrue(support["visibility_hint_supported"])
        self.assertEqual(support["support_signal"], "binary contains visibilityHint and HookVisibilityHint")

    def test_quiet_profile_fails_closed_without_visibility_hint_support(self) -> None:
        with self.assertRaises(ConfigurationError) as context:
            build_managed_hooks(mode="quiet", visibility_hint_supported=False)
        self.assertIn("refusing to render quiet/verbose hooks", str(context.exception))

    def test_full_context_preserves_beads_codex_hook_commands_without_visibility_hint(self) -> None:
        managed, warnings = build_managed_hooks(mode="full-context", visibility_hint_supported=False)
        session_hook = managed["SessionStart"][0]["hooks"][0]
        self.assertEqual(session_hook["command"], "bd codex-hook SessionStart")
        self.assertNotIn("visibilityHint", session_hook)
        self.assertTrue(any("preserves automatic Beads context injection" in warning for warning in warnings))

    def test_quiet_profile_keeps_commands_and_adds_display_hint_when_supported(self) -> None:
        managed, warnings = build_managed_hooks(mode="quiet", visibility_hint_supported=True)
        self.assertEqual(warnings, [])
        for event, groups in managed.items():
            hook = groups[0]["hooks"][0]
            self.assertEqual(hook["command"], f"bd codex-hook {event}")
            self.assertEqual(hook["visibilityHint"], "quiet")

    def test_merge_preserves_unrelated_hooks_and_replaces_managed_beads_hooks(self) -> None:
        existing = {
            "hooks": {
                "SessionStart": [
                    {"matcher": "startup", "hooks": [{"type": "command", "command": "echo keep"}]},
                    {
                        "matcher": "startup|resume|clear",
                        "hooks": [{"type": "command", "command": "bd codex-hook SessionStart"}],
                    },
                ],
                "Stop": [{"hooks": [{"type": "command", "command": "echo stop"}]}],
            }
        }
        managed, _ = build_managed_hooks(mode="quiet", visibility_hint_supported=True)
        merged = merge_hooks(existing, managed)
        session_groups = merged["hooks"]["SessionStart"]
        self.assertEqual(session_groups[0]["hooks"][0]["command"], "echo keep")
        self.assertEqual(session_groups[1]["hooks"][0]["command"], "bd codex-hook SessionStart")
        self.assertEqual(session_groups[1]["hooks"][0]["visibilityHint"], "quiet")
        self.assertEqual(merged["hooks"]["Stop"][0]["hooks"][0]["command"], "echo stop")

    def test_compact_degraded_requires_explicit_acknowledgement(self) -> None:
        with self.assertRaises(ConfigurationError) as context:
            build_managed_hooks(mode="compact-degraded", visibility_hint_supported=False)
        self.assertIn("reduces automatic Beads context", str(context.exception))

    def test_cli_json_reports_unsupported_quiet_without_writing(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            result = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "scripts" / "configure_codex_beads_hooks.py"),
                    "--project-dir",
                    tmpdir,
                    "--codex-bin",
                    "/bin/true",
                    "--mode",
                    "quiet",
                    "--json",
                ],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            payload = json.loads(result.stdout)
            hooks_file = Path(tmpdir) / ".codex" / "hooks.json"
        self.assertEqual(result.returncode, 2)
        self.assertFalse(hooks_file.exists())
        self.assertFalse(payload["visibility_hint_supported"])
        self.assertIn("refusing to render quiet/verbose hooks", payload["error"])


if __name__ == "__main__":
    unittest.main()
