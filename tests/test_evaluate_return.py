from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from orchestration_lib import make_acceptance_decision  # noqa: E402


class EvaluateReturnTests(unittest.TestCase):
    def test_missing_sections_lower_score(self) -> None:
        result = make_acceptance_decision("Status: complete\nSummary: shallow\n")
        self.assertLess(result["score"], 85)
        self.assertTrue(result["missing_sections"])

    def test_structured_boundary_violation_forces_reject(self) -> None:
        text = (ROOT / "examples" / "sample-contractor-return.md").read_text(encoding="utf-8")
        result = make_acceptance_decision(text + "\nBoundary violation: yes\n")
        self.assertEqual(result["verdict"], "reject")
        self.assertIn("boundary violation", result["hard_disqualifiers"])

    def test_negative_boundary_phrase_does_not_false_reject(self) -> None:
        text = (ROOT / "examples" / "sample-contractor-return.md").read_text(encoding="utf-8")
        result = make_acceptance_decision(text + "\nBoundary violation: no boundary violation observed\n")
        self.assertNotIn("boundary violation", result["hard_disqualifiers"])

    def test_patch_branch_requires_files_and_commands(self) -> None:
        text = (ROOT / "examples" / "sample-contractor-return.md").read_text(encoding="utf-8")
        result = make_acceptance_decision(text, share_boundary="patch-branch")
        self.assertEqual(result["verdict"], "reject")
        self.assertIn("patch branch return missing files changed or commands run", result["hard_disqualifiers"])


if __name__ == "__main__":
    unittest.main()
