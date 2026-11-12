from __future__ import annotations

import json
import sys
import tempfile
import unittest
from io import StringIO
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from configure_codex_beads_hooks import main  # noqa: E402
import configure_codex_beads_hooks as config_module  # noqa: E402


class ProbeOrderingTests(unittest.TestCase):
    """Negative tests: probe-independent refusals must not invoke detection or persistence."""

    def test_enforcement_hook_refusal_does_not_invoke_probe_or_write(self) -> None:
        """
        Existing hooks file contains a refused enforcement hook (PreToolUse).
        This is an existing-file validation failure, probe-independent.
        Assert for both preview and --apply modes:
        - Detection functions are never called
        - Persistence functions are never called
        - Hooks file bytes are unchanged
        - Exit code is 2
        - --json output contains the structured error with file path and no content
        """
        for apply_mode in [False, True]:
            with self.subTest(apply_mode=apply_mode):
                with tempfile.TemporaryDirectory() as tmpdir:
                    tmpdir_path = Path(tmpdir)
                    project_dir = tmpdir_path / "project"
                    project_dir.mkdir()
                    codex_dir = project_dir / ".codex"
                    codex_dir.mkdir()
                    hooks_file = codex_dir / "hooks.json"

                    # Create existing hooks with enforcement hook that should be refused
                    enforcement_hooks = {
                        "hooks": {
                            "PreToolUse": [
                                {
                                    "matcher": ".*",
                                    "hooks": [
                                        {
                                            "type": "command",
                                            "command": "echo block",
                                        }
                                    ],
                                }
                            ]
                        }
                    }
                    hooks_file.write_text(json.dumps(enforcement_hooks), encoding="utf-8")

                    # Fake codex executable
                    codex_bin = tmpdir_path / "codex"
                    codex_bin.write_text("#!/bin/sh\necho 'Codex 0.163.0'\nexit 0\n", encoding="utf-8")
                    codex_bin.chmod(0o755)

                    # Snapshot filesystem state
                    hooks_content_before = hooks_file.read_bytes()
                    project_files_before = sorted(project_dir.rglob("*"))

                    # Spy on detection and persistence functions
                    with (
                        patch.object(config_module, "detect_visibility_hint_support", wraps=config_module.detect_visibility_hint_support) as spy_detect,
                        patch.object(config_module, "file_has_visibility_hint", wraps=config_module.file_has_visibility_hint) as spy_file_check,
                        patch.object(config_module, "run_codex_version", wraps=config_module.run_codex_version) as spy_run_version,
                        patch.object(config_module, "write_hooks", wraps=config_module.write_hooks) as spy_write,
                        patch("sys.stdout", StringIO()) as captured_stdout,
                    ):
                        argv = [
                            "configure_codex_beads_hooks.py",
                            "--project-dir", str(project_dir),
                            "--codex-bin", str(codex_bin),
                            "--json",
                        ]
                        if apply_mode:
                            argv.append("--apply")

                        with patch.object(sys, "argv", argv):
                            exit_code = main()

                        output = captured_stdout.getvalue()

                        # Assert: exit code 2
                        self.assertEqual(exit_code, 2, f"Expected exit code 2 for refused configuration (apply={apply_mode})")

                        # Assert: detection functions were never called (probe-independent refusal)
                        spy_detect.assert_not_called()
                        spy_file_check.assert_not_called()
                        spy_run_version.assert_not_called()

                        # Assert: write function was never called
                        spy_write.assert_not_called()

                        # Assert: hooks file was not modified
                        hooks_content_after = hooks_file.read_bytes()
                        self.assertEqual(
                            hooks_content_before,
                            hooks_content_after,
                            f"Hooks file was modified despite refused configuration (apply={apply_mode})",
                        )

                        # Assert: no new files were created
                        project_files_after = sorted(project_dir.rglob("*"))
                        self.assertEqual(project_files_before, project_files_after, "Filesystem was modified")

                        # Assert: JSON output is valid and contains error with file path
                        result = json.loads(output)
                        self.assertIn("error", result, f"No error field in JSON output: {result}")
                        self.assertIsNotNone(result["error"], "error field is null")
                        self.assertIn("PreToolUse", result["error"], "Error does not mention PreToolUse")
                        self.assertIn(str(hooks_file), result["error"], "Error does not name the file")

    def test_compact_degraded_refusal_does_not_invoke_probe_or_write(self) -> None:
        """
        Request compact-degraded mode without --allow-degraded-context.
        This is a probe-independent mode refusal.
        Assert for both preview and --apply modes:
        - Detection functions are never called
        - Persistence functions are never called
        - Hooks file bytes are unchanged
        - Exit code is 2
        - --json output contains the structured error
        """
        for apply_mode in [False, True]:
            with self.subTest(apply_mode=apply_mode):
                with tempfile.TemporaryDirectory() as tmpdir:
                    tmpdir_path = Path(tmpdir)
                    project_dir = tmpdir_path / "project"
                    project_dir.mkdir()
                    codex_dir = project_dir / ".codex"
                    codex_dir.mkdir()
                    hooks_file = codex_dir / "hooks.json"

                    # No existing hooks
                    hooks_file.write_text('{"hooks": {}}', encoding="utf-8")

                    # Fake codex executable
                    codex_bin = tmpdir_path / "codex"
                    codex_bin.write_text("#!/bin/sh\necho 'Codex 0.163.0'\nexit 0\n", encoding="utf-8")
                    codex_bin.chmod(0o755)

                    # Snapshot filesystem state
                    hooks_content_before = hooks_file.read_bytes()
                    project_files_before = sorted(project_dir.rglob("*"))

                    # Spy on detection and persistence functions
                    with (
                        patch.object(config_module, "detect_visibility_hint_support", wraps=config_module.detect_visibility_hint_support) as spy_detect,
                        patch.object(config_module, "file_has_visibility_hint", wraps=config_module.file_has_visibility_hint) as spy_file_check,
                        patch.object(config_module, "run_codex_version", wraps=config_module.run_codex_version) as spy_run_version,
                        patch.object(config_module, "write_hooks", wraps=config_module.write_hooks) as spy_write,
                        patch("sys.stdout", StringIO()) as captured_stdout,
                    ):
                        argv = [
                            "configure_codex_beads_hooks.py",
                            "--project-dir", str(project_dir),
                            "--codex-bin", str(codex_bin),
                            "--mode", "compact-degraded",
                            "--json",
                        ]
                        if apply_mode:
                            argv.append("--apply")

                        with patch.object(sys, "argv", argv):
                            exit_code = main()

                        output = captured_stdout.getvalue()

                        # Assert: exit code 2
                        self.assertEqual(exit_code, 2, f"Expected exit code 2 for compact-degraded without acknowledgement (apply={apply_mode})")

                        # Assert: detection functions were never called (probe-independent refusal)
                        spy_detect.assert_not_called()
                        spy_file_check.assert_not_called()
                        spy_run_version.assert_not_called()

                        # Assert: write function was never called
                        spy_write.assert_not_called()

                        # Assert: hooks file was not modified
                        hooks_content_after = hooks_file.read_bytes()
                        self.assertEqual(
                            hooks_content_before,
                            hooks_content_after,
                            f"Hooks file was modified despite refused configuration (apply={apply_mode})",
                        )

                        # Assert: no new files were created
                        project_files_after = sorted(project_dir.rglob("*"))
                        self.assertEqual(project_files_before, project_files_after, "Filesystem was modified")

                        # Assert: JSON output is valid and contains error about acknowledgement
                        result = json.loads(output)
                        self.assertIn("error", result, f"No error field in JSON output: {result}")
                        self.assertIsNotNone(result["error"], "error field is null")
                        self.assertIn("compact-degraded", result["error"], "Error does not mention compact-degraded")
                        self.assertIn("allow-degraded-context", result["error"], "Error does not mention acknowledgement flag")

    def test_invalid_utf8_yields_structured_json_refusal(self) -> None:
        """
        Hooks file contains invalid UTF-8.
        This is an existing-file validation failure, probe-independent.
        Assert for both preview and --apply modes:
        - No UnicodeDecodeError traceback
        - --json output is valid JSON with error field mentioning UTF-8 and file path
        - Exit code is 2
        - Detection and persistence functions are never called
        - Hooks file is not modified
        """
        for apply_mode in [False, True]:
            with self.subTest(apply_mode=apply_mode):
                with tempfile.TemporaryDirectory() as tmpdir:
                    tmpdir_path = Path(tmpdir)
                    project_dir = tmpdir_path / "project"
                    project_dir.mkdir()
                    codex_dir = project_dir / ".codex"
                    codex_dir.mkdir()
                    hooks_file = codex_dir / "hooks.json"

                    # Write invalid UTF-8 bytes (0xFF is not valid UTF-8)
                    hooks_file.write_bytes(b'{"hooks": "invalid-\xff-utf8"}')

                    codex_bin = tmpdir_path / "codex"
                    codex_bin.write_text("#!/bin/sh\necho 'Codex 0.163.0'\n", encoding="utf-8")
                    codex_bin.chmod(0o755)

                    # Snapshot filesystem state
                    hooks_content_before = hooks_file.read_bytes()
                    project_files_before = sorted(project_dir.rglob("*"))

                    # Spy on detection and persistence functions
                    with (
                        patch.object(config_module, "detect_visibility_hint_support", wraps=config_module.detect_visibility_hint_support) as spy_detect,
                        patch.object(config_module, "file_has_visibility_hint", wraps=config_module.file_has_visibility_hint) as spy_file_check,
                        patch.object(config_module, "run_codex_version", wraps=config_module.run_codex_version) as spy_run_version,
                        patch.object(config_module, "write_hooks", wraps=config_module.write_hooks) as spy_write,
                        patch("sys.stdout", StringIO()) as captured_stdout,
                    ):
                        argv = [
                            "configure_codex_beads_hooks.py",
                            "--project-dir", str(project_dir),
                            "--codex-bin", str(codex_bin),
                            "--json",
                        ]
                        if apply_mode:
                            argv.append("--apply")

                        with patch.object(sys, "argv", argv):
                            exit_code = main()

                        output = captured_stdout.getvalue()

                        # Assert: exit code 2
                        self.assertEqual(exit_code, 2, f"Expected exit code 2 for invalid UTF-8 (apply={apply_mode})")

                        # Assert: detection functions were never called (probe-independent refusal)
                        spy_detect.assert_not_called()
                        spy_file_check.assert_not_called()
                        spy_run_version.assert_not_called()

                        # Assert: write function was never called
                        spy_write.assert_not_called()

                        # Assert: hooks file was not modified
                        hooks_content_after = hooks_file.read_bytes()
                        self.assertEqual(
                            hooks_content_before,
                            hooks_content_after,
                            f"Hooks file was modified despite invalid UTF-8 (apply={apply_mode})",
                        )

                        # Assert: no new files were created
                        project_files_after = sorted(project_dir.rglob("*"))
                        self.assertEqual(project_files_before, project_files_after, "Filesystem was modified")

                        # Assert: output is valid JSON
                        try:
                            result = json.loads(output)
                        except json.JSONDecodeError as exc:
                            self.fail(f"Output is not valid JSON: {exc}\nOutput: {output}")

                        # Assert: error field is present and mentions the UTF-8 problem and file path
                        self.assertIn("error", result, f"No error field in JSON output: {result}")
                        self.assertIsNotNone(result["error"], "error field is null")
                        error_msg = result["error"]
                        self.assertIn("utf", error_msg.lower(), f"Error does not mention UTF-8: {error_msg}")
                        self.assertIn(str(hooks_file), error_msg, f"Error does not name the file: {error_msg}")

    def test_invalid_utf8_does_not_echo_file_content(self) -> None:
        """
        Hooks file contains invalid UTF-8 with sensitive-looking data.
        Assert a structured, content-free refusal and unchanged fixture bytes/paths.
        Assert all four detection/persistence boundaries remain unreached.
        Test both preview and --apply modes.
        """
        for apply_mode in [False, True]:
            with self.subTest(apply_mode=apply_mode):
                with tempfile.TemporaryDirectory() as tmpdir:
                    tmpdir_path = Path(tmpdir)
                    project_dir = tmpdir_path / "project"
                    project_dir.mkdir()
                    codex_dir = project_dir / ".codex"
                    codex_dir.mkdir()
                    hooks_file = codex_dir / "hooks.json"

                    # Write invalid UTF-8 with a recognizable pattern
                    sentinel = b"SECRET_TOKEN_12345"
                    hooks_file.write_bytes(b'{"data": "' + sentinel + b'-\xff"}')

                    codex_bin = tmpdir_path / "codex"
                    codex_bin.write_text("#!/bin/sh\necho 'Codex 0.163.0'\n", encoding="utf-8")
                    codex_bin.chmod(0o755)

                    # Snapshot every fixture path and every regular file's bytes.
                    fixture_paths_before = sorted(tmpdir_path.rglob("*"))
                    fixture_bytes_before = {
                        path: path.read_bytes()
                        for path in fixture_paths_before if path.is_file()
                    }
                    hooks_content_before = hooks_file.read_bytes()

                    # Spy on detection and persistence functions
                    with (
                        patch.object(config_module, "detect_visibility_hint_support", wraps=config_module.detect_visibility_hint_support) as spy_detect,
                        patch.object(config_module, "file_has_visibility_hint", wraps=config_module.file_has_visibility_hint) as spy_file_check,
                        patch.object(config_module, "run_codex_version", wraps=config_module.run_codex_version) as spy_run_version,
                        patch.object(config_module, "write_hooks", wraps=config_module.write_hooks) as spy_write,
                        patch("sys.stdout", StringIO()) as captured_stdout,
                        patch("sys.stderr", StringIO()) as captured_stderr,
                    ):
                        argv = [
                            "configure_codex_beads_hooks.py",
                            "--project-dir", str(project_dir),
                            "--codex-bin", str(codex_bin),
                            "--json",
                        ]
                        if apply_mode:
                            argv.append("--apply")

                        with patch.object(sys, "argv", argv):
                            with self.assertRaises(config_module.ConfigurationError) as refusal:
                                config_module.load_existing_hooks(hooks_file)
                            self.assertEqual(
                                str(refusal.exception),
                                f"{hooks_file} contains invalid UTF-8 encoding",
                            )
                            exit_code = main()

                        output = captured_stdout.getvalue()

                        # Assert: exit code 2
                        self.assertEqual(exit_code, 2, f"Expected exit code 2 for invalid UTF-8 (apply={apply_mode})")

                        # Assert: all four detection and persistence boundaries were unreached
                        spy_detect.assert_not_called()
                        spy_file_check.assert_not_called()
                        spy_run_version.assert_not_called()
                        spy_write.assert_not_called()

                        self.assertEqual(
                            hooks_content_before,
                            hooks_file.read_bytes(),
                            "Hooks file bytes changed",
                        )
                        self.assertEqual(
                            fixture_paths_before,
                            sorted(tmpdir_path.rglob("*")),
                            "Fixture directory contents changed",
                        )
                        self.assertEqual(
                            fixture_bytes_before,
                            {
                                path: path.read_bytes()
                                for path in tmpdir_path.rglob("*") if path.is_file()
                            },
                            "Fixture file bytes changed",
                        )

                        try:
                            result = json.loads(output)
                        except json.JSONDecodeError as exc:
                            self.fail(f"Output is not valid JSON: {exc}\nOutput: {output}")
                        self.assertIsInstance(result, dict)
                        self.assertEqual(result["error"], str(refusal.exception))
                        self.assertEqual(result["hooks_file"], str(hooks_file))
                        self.assertEqual(result["project_dir"], str(project_dir))
                        self.assertIs(result["applied"], False)
                        self.assertIsNone(result["rendered_hooks"])

                        # Assert: sentinel does not appear in output
                        self.assertNotIn(
                            sentinel.decode("ascii"),
                            output,
                            "Error message echoed file content",
                        )
                        self.assertNotIn(sentinel.decode("ascii"), captured_stderr.getvalue())

    def test_invalid_utf8_content_refusal_assertions_reject_mutations(self) -> None:
        """Controlled mutations must fail the real preview and --apply assertions."""
        real_main = main
        for mutation, expected_message in (
            ("hooks-bytes", "Hooks file bytes changed"),
            ("fixture-bytes", "Fixture file bytes changed"),
            ("directory-contents", "Fixture directory contents changed"),
            ("malformed-json", "Output is not valid JSON"),
        ):
            with self.subTest(mutation=mutation):
                def mutated_main() -> int:
                    exit_code = real_main()
                    project_dir = Path(sys.argv[sys.argv.index("--project-dir") + 1])
                    if mutation == "hooks-bytes":
                        (project_dir / ".codex" / "hooks.json").write_bytes(b"changed")
                    elif mutation == "fixture-bytes":
                        (project_dir.parent / "codex").write_bytes(b"inert fixture mutation\n")
                    elif mutation == "directory-contents":
                        (project_dir / "unexpected").mkdir()
                    else:
                        print("invalid-json")
                    return exit_code

                outcome = unittest.TestResult()
                with patch(f"{__name__}.main", side_effect=mutated_main):
                    ProbeOrderingTests("test_invalid_utf8_does_not_echo_file_content").run(outcome)
                self.assertEqual(outcome.testsRun, 1)
                self.assertEqual(outcome.errors, [])
                self.assertEqual(len(outcome.failures), 2, outcome.failures)
                for _, traceback in outcome.failures:
                    self.assertIn(expected_message, traceback)


if __name__ == "__main__":
    unittest.main()
