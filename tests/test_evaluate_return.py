from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from orchestration_lib import make_acceptance_decision, parse_return_sections  # noqa: E402


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
        self.assertIn("patch branch return missing patch proposal or direct-change evidence", result["hard_disqualifiers"])

    def test_parser_accepts_markdown_headings_and_bold_labels(self) -> None:
        text = """### Status
complete

**Contractor job description:** contract-jd-security-reasoning
## Summary:
Reviewed the packet.
### Evidence
- policy excerpt
"""
        sections = parse_return_sections(text)
        self.assertEqual(sections["Status"], "complete")
        self.assertEqual(sections["Contractor job description"], "contract-jd-security-reasoning")
        self.assertEqual(sections["Summary"], "Reviewed the packet.")
        self.assertIn("policy excerpt", sections["Evidence"])

    def test_parser_ignores_headers_inside_fenced_code(self) -> None:
        text = """Status: complete
Evidence:
```text
Summary: this is code, not a section
```
Recommended next bead: Keep current task closed.
"""
        sections = parse_return_sections(text)
        self.assertIn("Summary: this is code", sections["Evidence"])
        self.assertNotEqual(sections.get("Summary"), "this is code, not a section")

    def test_aliases_satisfy_required_sections(self) -> None:
        text = """Status: complete
Contractor job description: contract-jd-security-reasoning
Summary: Reviewed the packet.
Validation result: Reviewed supplied evidence.
Evidence: policy excerpt and packet summary.
Evidence provenance: packet.
Attestation/repro note: reproducible from the packet.
Share boundary conformance: stayed inside redacted packet.
Peer review disposition: not required for this sample.
Alternatives considered: none.
Confidence: medium
Risks or gaps: no repo access.
Recommended next bead: No follow-up implementation bead needed.
Escalation needed: no
"""
        result = make_acceptance_decision(text, job_description_label="contract-jd-security-reasoning")
        self.assertEqual(result["missing_sections"], [])

    def test_patch_branch_proposal_does_not_require_direct_mutation(self) -> None:
        text = (ROOT / "examples" / "sample-contractor-return.md").read_text(encoding="utf-8")
        text = text.replace(
            "Patch authorization: no patch access requested or used",
            "Patch authorization: patch proposal only; no direct workspace mutation authorized",
        ).replace(
            "Evidence:\n",
            "Evidence:\n- Proposed patch artifact: docs-refresh.diff.\n",
        )
        result = make_acceptance_decision(text, share_boundary="patch-branch")
        self.assertNotIn("patch branch return missing patch proposal or direct-change evidence", result["hard_disqualifiers"])

    def test_workspace_mutation_report_rejects_unexpected_changes(self) -> None:
        text = (ROOT / "examples" / "sample-contractor-return.md").read_text(encoding="utf-8")
        mutation = {
            "mutation_detected": True,
            "unexpected_mutation_detected": True,
            "unexpected_mutations": [{"path": "docs/styles.css", "before": None, "after": " M docs/styles.css"}],
            "allowed_mutations": [],
        }
        result = make_acceptance_decision(text, workspace_mutation=mutation)
        self.assertEqual(result["verdict"], "quarantine")
        self.assertIn("unexpected tracked-file mutation", result["hard_disqualifiers"])
        self.assertTrue(result["quarantine_recommended"])

    def test_peer_review_required_cannot_be_dismissed(self) -> None:
        text = (ROOT / "examples" / "sample-contractor-return.md").read_text(encoding="utf-8")
        result = make_acceptance_decision(
            text,
            peer_review_required=True,
            provider_conflict_domains=["frontier-ai-development"],
        )
        self.assertIn("peer review incorrectly dismissed", result["hard_disqualifiers"])
        self.assertEqual(result["recommended_disposition"], "reject")


if __name__ == "__main__":
    unittest.main()
