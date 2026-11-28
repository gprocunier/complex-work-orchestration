from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from cwo_core.return_boundary import redacted_boundary_taint_findings  # noqa: E402


class RedactedBoundaryClassificationTests(unittest.TestCase):
    def test_direct_inspection_negation_applies_to_its_own_clause(self) -> None:
        pairs = (
            (
                "I claimed that I inspected the repository.",
                "I did not claim that I inspected the repository.",
            ),
            (
                "I did not access the checkout, but I inspected the repository.",
                "I did not access the checkout, and I did not inspect the repository.",
            ),
            (
                "I inspected the repository without running tests.",
                "I reviewed the supplied summary without inspecting the repository.",
            ),
            (
                "I inspected the repository and did not run tests.",
                "I did not inspect the repository and did not run tests.",
            ),
            (
                "No runtime tests were executed; all files were inspected in the local workspace.",
                "No runtime tests were executed; all files were not inspected in the local workspace.",
            ),
            (
                "I did not run tests and all files were inspected in the local workspace.",
                "I did not run tests and no files were inspected in the local workspace.",
            ),
            (
                "I did not inspect the repository, then opened the workspace.",
                "I did not inspect the repository or open the workspace.",
            ),
        )
        for asserted, denied in pairs:
            with self.subTest(asserted=asserted, denied=denied):
                self.assertTrue(redacted_boundary_taint_findings(asserted, {}, share_boundary="redacted-packet"))
                self.assertEqual(redacted_boundary_taint_findings(denied, {}, share_boundary="redacted-packet"), [])

    def test_validation_attribution_follows_the_source_of_the_claim(self) -> None:
        pairs = (
            ("I confirmed that the tests passed.", "The packet confirms that the tests passed."),
            ("Packet validation evidence: I ran the tests.", "Packet validation evidence: tests passed."),
            ("The tests passed, so I read the supplied summary.", "According to the supplied summary, the tests passed."),
            (
                "The tests passed after I reviewed the packet.",
                "The tests passed, the packet says.",
            ),
            (
                "The packet says I executed the unit tests.",
                "The packet says its publisher executed the unit tests.",
            ),
            (
                "According to the packet, the tests were executed by us.",
                "According to the packet, the tests were executed by its publisher.",
            ),
            (
                "The attachment reports that the tests passed, but I ran the tests again.",
                "The attachment reports that the tests passed, but I only reviewed the report.",
            ),
            (
                "I verified the tests passed following the packet instructions.",
                "I verified the tests passed against the packet results.",
            ),
        )
        for asserted, reported in pairs:
            with self.subTest(asserted=asserted, reported=reported):
                for clause, unsupported in ((asserted, True), (reported, False)):
                    findings = redacted_boundary_taint_findings(
                        clause, {"Validation result": clause}, share_boundary="redacted-packet",
                    )
                    self.assertEqual(
                        "redacted packet return claims unsupported validation" in findings, unsupported, clause,
                    )


if __name__ == "__main__":
    unittest.main()
