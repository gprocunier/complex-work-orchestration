from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from orchestration_lib import make_acceptance_decision  # noqa: E402


class AcceptanceTests(unittest.TestCase):
    def test_complete_return_accepts(self) -> None:
        text = (ROOT / "examples" / "sample-contractor-return.md").read_text(encoding="utf-8")
        result = make_acceptance_decision(text, bead_id="example", dispatch_id="dispatch-example")
        self.assertEqual(result["verdict"], "accept")
        self.assertGreaterEqual(result["score"], 85)
        self.assertNotIn("scope compliance field is unclear", result["penalty_reasons"])
        self.assertIn("malpractice_score", result)
        self.assertIn("peer_review_required", result)
        self.assertEqual(result["recommended_disposition"], "accept-findings")

    def test_weak_return_clarifies_or_rejects(self) -> None:
        result = make_acceptance_decision("Status: complete\nSummary: Looks fine.\n")
        self.assertIn(result["verdict"], {"clarify", "partial-accept", "reject"})
        self.assertLess(result["score"], 85)

    def test_secret_spill_hard_rejects(self) -> None:
        text = (ROOT / "examples" / "sample-contractor-return.md").read_text(encoding="utf-8")
        result = make_acceptance_decision(text + "\npassword=supersecret\n")
        self.assertEqual(result["verdict"], "reject")
        self.assertTrue(result["hard_disqualifiers"])


if __name__ == "__main__":
    unittest.main()
