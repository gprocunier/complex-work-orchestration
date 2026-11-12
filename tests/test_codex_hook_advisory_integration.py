"""Behavioral regressions for the advisory-only hook boundary.

Every counterexample goes through the public surfaces that act on hooks: the
writer (write_hooks), the CLI (configure_codex_beads_hooks.py, in process and as
a subprocess, with --json and --apply) and the access profile registry. Each
refusal is checked for its exact reason and for zero filesystem effects. All
files live in temporary directories; no hook command is ever executed.
"""
from __future__ import annotations

import contextlib
import copy
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any, Callable
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "configure_codex_beads_hooks.py"
sys.path.insert(0, str(ROOT / "scripts"))

import configure_codex_beads_hooks as writer  # noqa: E402
from cwo_core import access_profiles  # noqa: E402
from cwo_core.errors import CWOValidationError  # noqa: E402

PINNED = (
    "hook-based enforcement is unsupported on pinned Codex versions ['0.163.0', '0.162.0']; "
    "PreToolUse leaves should_block=false on execution/JSON failures, stdin skips PreToolUse, "
    "and PermissionRequest fallthrough is not equivalent to PreToolUse; enforcement mode refused"
)
EVENTS = "['PostCompact', 'PreCompact', 'SessionStart', 'UserPromptSubmit']"
SESSION_COMMANDS = "['bd codex-hook SessionStart', 'bd prime --memories-only --hook-json']"
SESSION_MATCHER = "startup|resume|clear"
PROFILE = "codex-connected-shell"
SUPPORT = {
    "codex_bin": "codex",
    "codex_version": None,
    "visibility_hint_supported": False,
    "candidate_paths": [],
    "matching_paths": [],
    "support_signal": "not detected",
}


def session(*hooks: dict[str, Any], matcher: str = SESSION_MATCHER) -> dict[str, Any]:
    return {"hooks": {"SessionStart": [{"matcher": matcher, "hooks": list(hooks)}]}}


def command(text: str, **extra: Any) -> dict[str, Any]:
    return {"type": "command", "command": text, **extra}


def session_command_refusal(text: str) -> Callable[[str], str]:
    return lambda ctx: (
        f"{ctx} event 'SessionStart' group 0 hook 0: command {text!r} is not an allowlisted advisory "
        f"command for SessionStart; allowed: {SESSION_COMMANDS}; refused"
    )


# name -> (payload, reason(context), applies to a profile's hooks field)
COUNTEREXAMPLES: dict[str, tuple[Any, Callable[[str], str], bool]] = {
    "session_start_grant_permission_command": (
        session(command("grant-permission")),
        session_command_refusal("grant-permission"),
        True,
    ),
    "custom_event_untrusted_helper": (
        {"hooks": {"CustomEvent": [{"hooks": [command("untrusted-helper")]}]}},
        lambda ctx: f"{ctx}: hook event 'CustomEvent' is not an allowlisted advisory event {EVENTS}; refused",
        True,
    ),
    "shell_chain_after_trusted_command": (
        session(command("bd codex-hook SessionStart && untrusted-helper")),
        session_command_refusal("bd codex-hook SessionStart && untrusted-helper"),
        True,
    ),
    "comment_containing_trusted_command": (
        session(command("untrusted-helper # bd codex-hook SessionStart")),
        session_command_refusal("untrusted-helper # bd codex-hook SessionStart"),
        True,
    ),
    "mismatched_event_argument": (
        session(command("bd codex-hook PreCompact")),
        session_command_refusal("bd codex-hook PreCompact"),
        True,
    ),
    "permission_field_on_trusted_command": (
        session(command("bd codex-hook SessionStart", grant_permission=True)),
        lambda ctx: (
            f"{ctx} event 'SessionStart' group 0 hook 0: hook contains permission-granting field(s) "
            "['grant_permission']; advisory hooks cannot issue authority; refused"
        ),
        True,
    ),
    "unlisted_hook_type": (
        session({"type": "prompt", "command": "bd codex-hook SessionStart"}),
        lambda ctx: (
            f"{ctx} event 'SessionStart' group 0 hook 0: hook type 'prompt' is not an allowlisted advisory "
            "hook type ['command']; refused"
        ),
        True,
    ),
    "unlisted_matcher": (
        session(command("bd codex-hook SessionStart"), matcher="*"),
        lambda ctx: (
            f"{ctx} event 'SessionStart' group 0: matcher '*' does not match the allowlisted matcher "
            f"'{SESSION_MATCHER}'; refused"
        ),
        True,
    ),
    "pre_tool_use_groups_as_object": (
        {"hooks": {"PreToolUse": {"hooks": [command("guard")]}}},
        lambda ctx: f"{ctx}: hook event(s) ['PreToolUse'] refused: {PINNED}",
        True,
    ),
    "permission_request_with_no_groups": (
        {"hooks": {"PermissionRequest": []}},
        lambda ctx: f"{ctx}: hook event(s) ['PermissionRequest'] refused: {PINNED}",
        True,
    ),
    "hooks_as_list_of_pairs": (
        {"hooks": [["PreToolUse", [{"hooks": [command("guard")]}]]]},
        lambda ctx: (
            f"{ctx}: 'hooks' must be an object mapping event names to hook groups, not list; refused"
        ),
        True,
    ),
    "hooks_as_string": (
        {"hooks": "PreToolUse"},
        lambda ctx: (
            f"{ctx}: 'hooks' must be an object mapping event names to hook groups, not str; refused"
        ),
        True,
    ),
    "root_not_an_object": (
        [{"PreToolUse": "guard"}],
        lambda ctx: f"{ctx}: hook configuration must be a JSON object, not list; refused",
        False,
    ),
    "unknown_top_level_key": (
        {"hooks": {}, "enforcement": {"PreToolUse": "guard"}},
        lambda ctx: f"{ctx}: unsupported top-level key(s) ['enforcement']; only 'hooks' is allowed; refused",
        False,
    ),
    "mixed_group_with_unmanaged_control": (
        session(command("bd codex-hook SessionStart"), command("audit-control")),
        lambda ctx: (
            f"{ctx} event 'SessionStart' group 0 hook 1: command 'audit-control' is not an allowlisted "
            f"advisory command for SessionStart; allowed: {SESSION_COMMANDS}; refused"
        ),
        True,
    ),
}

MIXED_ALLOWLISTED = session(command("bd codex-hook SessionStart"), command("bd prime --memories-only --hook-json"))
MIXED_REFUSAL = (
    "existing SessionStart hook group 0 mixes the managed Beads command 'bd codex-hook SessionStart' with other "
    "hook entries; replacing it would remove those entries, so it is refused. Split the group or remove the "
    "other entries first."
)


def snapshot(root: Path) -> dict[str, bytes | None]:
    tree: dict[str, bytes | None] = {}
    for dirpath, _dirnames, filenames in os.walk(root):
        base = Path(dirpath)
        tree[f"{base.relative_to(root)}/"] = None
        for name in filenames:
            tree[str((base / name).relative_to(root))] = (base / name).read_bytes()
    return tree


class ScratchProject:
    """A temporary project whose .codex/hooks.json holds the given payload."""

    def __init__(self, payload: Any | None = None, *, raw: str | None = None) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name).resolve()
        self.hooks_file = self.root / ".codex" / "hooks.json"
        if payload is not None or raw is not None:
            self.hooks_file.parent.mkdir()
            self.hooks_file.write_text(raw if raw is not None else json.dumps(payload), encoding="utf-8")

    def __enter__(self) -> "ScratchProject":
        return self

    def __exit__(self, *exc: object) -> None:
        self._tmp.cleanup()


def run_main(project: Path, *extra: str) -> tuple[int, str, str, Mock, Mock]:
    """Run the CLI in process with every filesystem write counted."""
    argv = [str(SCRIPT), "--project-dir", str(project), "--codex-bin", "codex", *extra]
    out, err = io.StringIO(), io.StringIO()
    atomic = Mock(name="atomic_write_text")
    real_mkdir = Path.mkdir
    with patch.object(sys, "argv", argv), \
            patch.object(writer, "detect_visibility_hint_support", return_value=dict(SUPPORT)), \
            patch.object(writer, "atomic_write_text", atomic), \
            patch.object(Path, "mkdir", autospec=True, side_effect=real_mkdir) as mkdir, \
            contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = writer.main()
    return rc, out.getvalue(), err.getvalue(), atomic, mkdir


def run_cli(project: Path, *extra: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), "--project-dir", str(project), "--codex-bin", "/bin/true", *extra],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


class WriterRefusalTests(unittest.TestCase):
    def test_writer_refuses_each_counterexample_without_creating_anything(self) -> None:
        for name, (payload, reason, _profile) in COUNTEREXAMPLES.items():
            with self.subTest(name), tempfile.TemporaryDirectory() as tmpdir:
                root = Path(tmpdir).resolve()
                target = root / "new" / ".codex" / "hooks.json"
                before = snapshot(root)
                atomic = Mock(name="atomic_write_text")
                with patch.object(writer, "atomic_write_text", atomic):
                    with self.assertRaises(CWOValidationError) as context:
                        writer.write_hooks(target, copy.deepcopy(payload))
                self.assertEqual(str(context.exception), reason(f"hooks file {target}"))
                atomic.assert_not_called()
                self.assertFalse((root / "new").exists())
                self.assertEqual(snapshot(root), before)


class CliRefusalTests(unittest.TestCase):
    def assert_refused_in_process(self, project: ScratchProject, expected: str, *extra: str) -> None:
        before = snapshot(project.root)
        rc, out, err, atomic, mkdir = run_main(project.root, *extra)
        self.assertEqual(rc, 2, out + err)
        self.assertNotIn("Traceback", err)
        if "--json" in extra:
            payload = json.loads(out)
            self.assertEqual(payload["error"], expected)
            self.assertFalse(payload["applied"])
            self.assertIsNone(payload["rendered_hooks"])
        else:
            self.assertIn(f"error: {expected}", err)
        atomic.assert_not_called()
        self.assertEqual(mkdir.call_count, 0)
        self.assertEqual(snapshot(project.root), before)

    def test_cli_refuses_each_counterexample_with_zero_writes(self) -> None:
        for name, (payload, reason, _profile) in COUNTEREXAMPLES.items():
            for extra in (("--json",), ("--json", "--apply"), ("--apply",)):
                with self.subTest(name, extra=extra), ScratchProject(payload) as project:
                    expected = reason(f"existing hooks file {project.hooks_file}")
                    self.assert_refused_in_process(project, expected, *extra)

    def test_cli_refuses_mixed_group_instead_of_dropping_its_other_entries(self) -> None:
        for extra in (("--json",), ("--json", "--apply")):
            with self.subTest(extra=extra), ScratchProject(MIXED_ALLOWLISTED) as project:
                self.assert_refused_in_process(project, MIXED_REFUSAL, *extra)

    def test_cli_refuses_duplicate_json_keys(self) -> None:
        raw = '{"hooks": {"PreToolUse": [{"hooks": [{"type": "command", "command": "guard"}]}]}, "hooks": {}}'
        with ScratchProject(raw=raw) as project:
            expected = f"{project.hooks_file} contains duplicate JSON key 'hooks'; refusing ambiguous hooks configuration"
            self.assert_refused_in_process(project, expected, "--json", "--apply")

    def test_cli_subprocess_reports_structured_refusal_and_leaves_file_unchanged(self) -> None:
        for name, (payload, reason, _profile) in COUNTEREXAMPLES.items():
            for extra in (("--json",), ("--json", "--apply")):
                with self.subTest(name, extra=extra), ScratchProject(payload) as project:
                    before = snapshot(project.root)
                    result = run_cli(project.root, *extra)
                    self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                    self.assertNotIn("Traceback", result.stderr)
                    body = json.loads(result.stdout)
                    self.assertEqual(body["error"], reason(f"existing hooks file {project.hooks_file}"))
                    self.assertFalse(body["applied"])
                    self.assertIsNone(body["rendered_hooks"])
                    self.assertEqual(snapshot(project.root), before)

    def test_cli_subprocess_mixed_group_is_refused_and_entries_survive(self) -> None:
        with ScratchProject(MIXED_ALLOWLISTED) as project:
            before = snapshot(project.root)
            result = run_cli(project.root, "--json", "--apply")
            self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
            self.assertEqual(json.loads(result.stdout)["error"], MIXED_REFUSAL)
            self.assertEqual(snapshot(project.root), before)
            entries = json.loads(project.hooks_file.read_text())["hooks"]["SessionStart"][0]["hooks"]
            self.assertEqual([hook["command"] for hook in entries],
                             ["bd codex-hook SessionStart", "bd prime --memories-only --hook-json"])


class MergeRefusalTests(unittest.TestCase):
    def test_merge_refuses_mixed_group_with_unmanaged_control(self) -> None:
        existing = session(command("bd codex-hook SessionStart"), command("audit-control"))
        managed, _ = writer.build_managed_hooks(mode="full-context", visibility_hint_supported=False)
        with self.assertRaises(writer.ConfigurationError) as context:
            writer.merge_hooks(existing, managed)
        self.assertEqual(str(context.exception), MIXED_REFUSAL)

    def test_merge_refuses_malformed_structure_instead_of_discarding_it(self) -> None:
        managed, _ = writer.build_managed_hooks(mode="full-context", visibility_hint_supported=False)
        cases = {
            "root list": ([], "existing hooks configuration must be a JSON object; refusing to replace it"),
            "hooks list of pairs": (
                {"hooks": [["SessionStart", []]]},
                "existing hooks configuration 'hooks' must be an object; refusing to replace it",
            ),
            "groups object": (
                {"hooks": {"SessionStart": {"hooks": [command("audit-control")]}}},
                "existing SessionStart hooks must be a list of groups; refusing to replace them",
            ),
        }
        for name, (existing, expected) in cases.items():
            with self.subTest(name):
                with self.assertRaises(writer.ConfigurationError) as context:
                    writer.merge_hooks(existing, managed)
                self.assertEqual(str(context.exception), expected)


class CliAdvisoryApplyTests(unittest.TestCase):
    def test_apply_writes_only_allowlisted_hooks_and_is_idempotent(self) -> None:
        with ScratchProject() as project:
            first = run_cli(project.root, "--json", "--apply")
            self.assertEqual(first.returncode, 0, first.stderr)
            written = project.hooks_file.read_bytes()
            managed, _ = writer.build_managed_hooks(mode="full-context", visibility_hint_supported=False)
            self.assertEqual(json.loads(written), {"hooks": managed})
            second = run_cli(project.root, "--json", "--apply")
            self.assertEqual(second.returncode, 0, second.stderr)
            self.assertEqual(project.hooks_file.read_bytes(), written)

    def test_switching_modes_preserves_allowlisted_unmanaged_group(self) -> None:
        with ScratchProject() as project:
            degraded = run_cli(project.root, "--json", "--apply", "--mode", "compact-degraded",
                               "--allow-degraded-context", "--waiver-reason", "scratch regression")
            self.assertEqual(degraded.returncode, 0, degraded.stderr)
            full = run_cli(project.root, "--json", "--apply")
            self.assertEqual(full.returncode, 0, full.stderr)
            session_groups = json.loads(project.hooks_file.read_text())["hooks"]["SessionStart"]
            self.assertEqual([group["hooks"][0]["command"] for group in session_groups],
                             ["bd prime --memories-only --hook-json", "bd codex-hook SessionStart"])


class RegistryRefusalTests(unittest.TestCase):
    def registry_with(self, **fields: Any) -> dict[str, Any]:
        registry = copy.deepcopy(access_profiles.access_profile_registry())
        registry["profiles"][PROFILE].update(copy.deepcopy(fields))
        return registry

    def errors_for(self, registry: dict[str, Any]) -> list[str]:
        with patch.object(access_profiles, "access_profile_registry", return_value=registry):
            return access_profiles.validate_access_profile_registry()

    def test_profile_hooks_go_through_the_complete_entry_validation(self) -> None:
        for name, (payload, reason, applies) in COUNTEREXAMPLES.items():
            if not applies:
                continue
            with self.subTest(name):
                errors = self.errors_for(self.registry_with(hooks=payload["hooks"]))
                expected = reason(f"access profile '{PROFILE}' hooks")
                self.assertEqual(errors, [f"access profile '{PROFILE}' hook validation failed: {expected}"])

    def test_profile_enforcement_hooks_field_is_refused(self) -> None:
        errors = self.errors_for(self.registry_with(enforcement_hooks={"PreToolUse": []}))
        self.assertEqual(errors, [
            f"access profile '{PROFILE}' hook validation failed: access profile '{PROFILE}' declares "
            "enforcement_hooks; hook-based enforcement is unsupported on pinned Codex versions"
        ])

    def test_profile_with_allowlisted_hooks_validates(self) -> None:
        managed, _ = writer.build_managed_hooks(mode="full-context", visibility_hint_supported=False)
        self.assertEqual(self.errors_for(self.registry_with(hooks=managed)), [])


if __name__ == "__main__":
    unittest.main()
