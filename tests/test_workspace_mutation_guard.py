from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from orchestration_lib import capture_tracked_workspace_state, diff_workspace_state  # noqa: E402


class WorkspaceMutationGuardTests(unittest.TestCase):
    def make_repo(self) -> Path:
        root = Path(tempfile.mkdtemp(prefix="cwo-workspace-guard-"))
        subprocess.run(["git", "init"], cwd=root, check=True, capture_output=True)
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


if __name__ == "__main__":
    unittest.main()
