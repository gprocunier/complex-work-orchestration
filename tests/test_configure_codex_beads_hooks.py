from __future__ import annotations

import io
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import configure_codex_beads_hooks as config_module  # noqa: E402
from configure_codex_beads_hooks import (  # noqa: E402
    ConfigurationError,
    assert_safe_hooks_file_path,
    build_managed_hooks,
    detect_visibility_hint_support,
    file_has_visibility_hint,
    merge_hooks,
)


class ConfigureCodexBeadsHooksTests(unittest.TestCase):
    def test_valid_preview_never_writes_and_apply_persists_exact_managed_commands(self) -> None:
        for apply in (False, True):
            with self.subTest(apply=apply), tempfile.TemporaryDirectory() as directory:
                project = Path(directory)
                target = project / ".codex" / "hooks.json"
                argv = ["configure_codex_beads_hooks.py", "--project-dir", str(project),
                        "--mode", "full-context", "--json"]
                if apply:
                    argv.append("--apply")
                output = io.StringIO()
                with patch.object(sys, "argv", argv), patch.object(sys, "stdout", output), \
                        patch.object(config_module, "detect_visibility_hint_support",
                                     return_value=config_module.unprobed_support_info("EXAMPLE")), \
                        patch.object(config_module, "write_hooks", wraps=config_module.write_hooks) as write, \
                        patch("subprocess.Popen") as process:
                    self.assertEqual(config_module.main(), 0)
                rendered = json.loads(output.getvalue())
                self.assertEqual(write.call_count, int(apply), "preview reached persistence")
                self.assertEqual(target.exists(), apply)
                process.assert_not_called()
                self.assertEqual(rendered["applied"], apply)
                self.assertEqual({event: groups[0]["hooks"][0]["command"]
                                  for event, groups in rendered["rendered_hooks"]["hooks"].items()},
                                 {event: spec["command"] for event, spec in config_module.MANAGED_EVENTS.items()})
                if apply:
                    write.assert_called_once_with(target, rendered["rendered_hooks"])
                    self.assertEqual(json.loads(target.read_text()), rendered["rendered_hooks"])
                    self.assertEqual(list(target.parent.iterdir()), [target])

    def test_detect_visibility_hint_support_uses_installed_binary_signal(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            codex = Path(tmpdir) / "codex"
            codex.write_bytes(b"prefix visibilityHint middle HookVisibilityHint suffix")
            codex.chmod(0o755)
            support = detect_visibility_hint_support(str(codex))
        self.assertTrue(support["visibility_hint_supported"])
        self.assertEqual(support["support_signal"], "binary contains visibilityHint and HookVisibilityHint")

    def test_visibility_hint_probe_is_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            codex = Path(tmpdir) / "codex"
            codex.write_bytes(b"prefix visibilityHint" + b"x" * 32 + b"HookVisibilityHint")
            codex.chmod(0o755)
            with patch("configure_codex_beads_hooks.MAX_VISIBILITY_PROBE_BYTES", 24):
                self.assertFalse(file_has_visibility_hint(codex))

    def test_visibility_hint_probe_skips_symlink_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            real = Path(tmpdir) / "real-codex"
            real.write_bytes(b"prefix visibilityHint middle HookVisibilityHint suffix")
            real.chmod(0o755)
            link = Path(tmpdir) / "codex"
            link.symlink_to(real)
            self.assertFalse(file_has_visibility_hint(link))
            self.assertTrue(file_has_visibility_hint(real))

    def test_hook_configuration_requires_explicit_supported_mode(self) -> None:
        variants = (
            ('test_quiet_profile_fails_closed_without_visibility_hint_support',
             'quiet',
             'refusing to render quiet/verbose hooks'),
            ('test_compact_degraded_requires_explicit_acknowledgement',
             'compact-degraded',
             'reduces automatic Beads context'),
        )
        for original, mode, diagnostic in variants:
            with self.subTest(original=original):
                with self.assertRaises(ConfigurationError) as context:
                    build_managed_hooks(mode=mode, visibility_hint_supported=False)
                self.assertIn(diagnostic, str(context.exception))

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


    def test_hooks_path_guard_allows_project_codex_hooks_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            project = Path(tmpdir)
            hooks = assert_safe_hooks_file_path(project / ".codex" / "hooks.json", project_dir=project)
        self.assertEqual(hooks, (project / ".codex" / "hooks.json").resolve(strict=False))

    def test_hooks_path_guard_rejects_wrong_name_and_symlink_parent(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            project = Path(tmpdir)
            with self.assertRaises(ConfigurationError):
                assert_safe_hooks_file_path(project / ".codex" / "settings.json", project_dir=project)

            real_parent = project / "real"
            real_parent.mkdir()
            symlink_parent = project / ".codex"
            symlink_parent.symlink_to(real_parent, target_is_directory=True)
            with self.assertRaises(ConfigurationError) as context:
                assert_safe_hooks_file_path(symlink_parent / "hooks.json", project_dir=project)
        self.assertIn("symlink", str(context.exception))

    def test_hooks_path_guard_rejects_escape_outside_project_and_home(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir, tempfile.TemporaryDirectory() as outside:
            project = Path(tmpdir)
            outside_codex = Path(outside) / ".codex"
            outside_codex.mkdir()
            with self.assertRaises(ConfigurationError):
                assert_safe_hooks_file_path(outside_codex / "hooks.json", project_dir=project)

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
