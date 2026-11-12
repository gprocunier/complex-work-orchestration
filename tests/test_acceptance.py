from __future__ import annotations

import sys
import unittest
from pathlib import Path
from typing import Callable, NamedTuple

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from cwo_core.returns import make_acceptance_decision  # noqa: E402


class AcceptanceRow(NamedTuple):
    original_id: str
    text: str
    options: dict[str, str]
    oracle: Callable[[dict], None]


class AcceptanceTests(unittest.TestCase):
    def assert_complete_return(self, result: dict) -> None:
        self.assertEqual(result["verdict"], "accept")
        self.assertGreaterEqual(result["score"], 85)
        self.assertNotIn("scope compliance field is unclear", result["penalty_reasons"])
        self.assertIn("malpractice_score", result)
        self.assertIn("peer_review_required", result)
        self.assertEqual(result["recommended_disposition"], "accept-findings")

    def assert_secret_spill(self, result: dict) -> None:
        self.assertEqual(result["verdict"], "reject")
        self.assertTrue(result["hard_disqualifiers"])

    def test_acceptance_return_family(self) -> None:
        text = (ROOT / "examples" / "sample-contractor-return.md").read_text(encoding="utf-8")
        rows = (
            AcceptanceRow("tests.test_acceptance.AcceptanceTests.test_complete_return_accepts", text,
                          {"bead_id": "example", "dispatch_id": "dispatch-example"}, self.assert_complete_return),
            AcceptanceRow("tests.test_acceptance.AcceptanceTests.test_secret_spill_hard_rejects", text + "\npassword=supersecret\n",
                          {}, self.assert_secret_spill),
        )
        for row in rows:
            with self.subTest(original_id=row.original_id):
                result = make_acceptance_decision(row.text, **row.options)
                row.oracle(result)

    def test_weak_return_clarifies_or_rejects(self) -> None:
        result = make_acceptance_decision("Status: complete\nSummary: Looks fine.\n")
        self.assertIn(result["verdict"], {"clarify", "partial-accept", "reject"})
        self.assertLess(result["score"], 85)


if __name__ == "__main__":
    unittest.main()
