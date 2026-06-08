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

    def test_boundary_violation_forces_reject(self) -> None:
        text = (ROOT / "examples" / "sample-contractor-return.md").read_text(encoding="utf-8")
        result = make_acceptance_decision(text + "\nRisks or gaps: boundary violation\n")
        self.assertEqual(result["verdict"], "reject")
        self.assertIn("boundary violation", result["hard_disqualifiers"])


if __name__ == "__main__":
    unittest.main()
