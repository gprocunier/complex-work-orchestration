from __future__ import annotations

import subprocess
import json
import sys
import shutil
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from cwo_core.workspace import (  # noqa: E402
    capture_tracked_workspace_state,
    diff_workspace_state,
)
from tests.real_beads_fixture import configure_git_fixture
from tests.test_workspace_inert_inspection import expected_transition_record


class WorkspaceMutationGuardTests(unittest.TestCase):
    def make_repo(self) -> Path:
        root = Path(tempfile.mkdtemp(prefix="cwo-workspace-guard-"))
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        subprocess.run(["git", "init"], cwd=root, check=True, capture_output=True)
        configure_git_fixture(root)
        subprocess.run(["git", "config", "user.email", "test@example.invalid"], cwd=root, check=True)
        subprocess.run(["git", "config", "user.name", "CWO Test"], cwd=root, check=True)
        (root / "tracked.txt").write_text("before\n", encoding="utf-8")
        subprocess.run(["git", "add", "tracked.txt"], cwd=root, check=True)
        subprocess.run(["git", "commit", "-m", "initial"], cwd=root, check=True, capture_output=True)
        return root

    def test_detects_unexpected_tracked_file_mutation(self) -> None:
        root = self.make_repo()
        before = capture_tracked_workspace_state(root)
        (root / "tracked.txt").write_text("after\n", encoding="utf-8")
        after = capture_tracked_workspace_state(root)
        report = diff_workspace_state(before, after)

        self.assertTrue(report["mutation_detected"])
        self.assertTrue(report["unexpected_mutation_detected"])
        self.assertEqual(report["unexpected_mutations"][0]["path"], "tracked.txt")
        self.assertFalse(report["reverted"])

    def test_allowed_path_is_not_unexpected(self) -> None:
        root = self.make_repo()
        before = capture_tracked_workspace_state(root)
        (root / "tracked.txt").write_text("after\n", encoding="utf-8")
        after = capture_tracked_workspace_state(root)
        report = diff_workspace_state(before, after, allowed_paths=["tracked.txt"])

        self.assertTrue(report["mutation_detected"])
        self.assertFalse(report["unexpected_mutation_detected"])
        self.assertEqual(report["allowed_mutations"][0]["path"], "tracked.txt")

    def test_untracked_files_are_ignored_by_default(self) -> None:
        root = self.make_repo()
        before = capture_tracked_workspace_state(root)
        (root / "new.txt").write_text("untracked\n", encoding="utf-8")
        after = capture_tracked_workspace_state(root)
        report = diff_workspace_state(before, after)

        self.assertEqual(report["status_scope"], "tracked")
        self.assertFalse(report["mutation_detected"])
        self.assertFalse(report["unexpected_mutation_detected"])

    def test_include_untracked_detects_untracked_files(self) -> None:
        root = self.make_repo()
        before = capture_tracked_workspace_state(root, include_untracked=True)
        (root / "new.txt").write_text("untracked\n", encoding="utf-8")
        after = capture_tracked_workspace_state(root, include_untracked=True)
        report = diff_workspace_state(before, after)

        self.assertEqual(report["status_scope"], "tracked-and-untracked")
        self.assertTrue(report["mutation_detected"])
        self.assertTrue(report["unexpected_mutation_detected"])
        self.assertEqual(report["unexpected_mutations"][0]["path"], "new.txt")

    def test_explicit_transition_reaches_cli_comparator(self) -> None:
        root = self.make_repo()
        before = capture_tracked_workspace_state(root)
        subprocess.run(["git", "config", "core.sshCommand", "approved"], cwd=root, check=True)
        after = capture_tracked_workspace_state(root)
        record = expected_transition_record(before, after)
        with tempfile.TemporaryDirectory() as tmpdir:
            before_path = Path(tmpdir) / "before.json"
            record_path = Path(tmpdir) / "expected.json"
            before_path.write_text(json.dumps(before), encoding="utf-8")
            record_path.write_text(json.dumps(record), encoding="utf-8")
            command = [sys.executable, str(ROOT / "scripts" / "workspace_mutation_guard.py"),
                       "--workspace-root", str(root), "--compare", str(before_path)]
            ordinary = subprocess.run(command, check=True, capture_output=True, text=True)
            approved = subprocess.run(command + ["--expected-git-transition", str(record_path)],
                                      check=True, capture_output=True, text=True)
            record_path.write_text("null", encoding="utf-8")
            invalid = subprocess.run(command + ["--expected-git-transition", str(record_path)],
                                     check=False, capture_output=True, text=True)
        self.assertTrue(json.loads(ordinary.stdout)["unexpected_mutation_detected"])
        report = json.loads(approved.stdout)
        self.assertFalse(report["unexpected_mutation_detected"])
        self.assertEqual(report["expected_git_transition"]["status"], "accepted")
        self.assertNotEqual(invalid.returncode, 0)

    def test_transition_option_requires_compare(self) -> None:
        result = subprocess.run([sys.executable, str(ROOT / "scripts" / "workspace_mutation_guard.py"),
                                 "--snapshot", "--expected-git-transition", "unused.json"],
                                capture_output=True, text=True, check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("requires --compare", result.stderr)


if __name__ == "__main__":
    unittest.main()
