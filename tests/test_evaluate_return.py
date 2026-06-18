from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from cwo_core.returns import (  # noqa: E402
    classify_patch_authorization,
    make_acceptance_decision,
    normalize_contractor_return,
    parse_return_sections,
)


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

    def test_policy_aliases_are_authoritative(self) -> None:
        text = """Status: complete
Contractor job description: contract-jd-security-reasoning
Summary: Reviewed the packet.
Validation result: Reviewed supplied evidence.
Evidence: policy excerpt and packet summary.
Evidence provenance: packet.
Attestation or reproduction note: reproducible from the packet.
Share boundary conformance: stayed inside redacted packet.
Peer review disposition: not required for this sample.
Alternatives considered: none.
Confidence: medium
Risks and gaps: no repo access.
Recommended next action: No follow-up implementation bead needed.
Escalation needed: no
"""
        sections = parse_return_sections(text)
        self.assertIn("Attestation or reproducibility note", sections)
        self.assertIn("Risks or gaps", sections)
        self.assertIn("Recommended next bead", sections)

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

    def test_patch_authorization_classifier_distinguishes_proposal_and_direct_allow(self) -> None:
        self.assertEqual(
            classify_patch_authorization("patch proposal only; no direct workspace mutation authorized"),
            "proposal-only",
        )
        self.assertEqual(
            classify_patch_authorization("Direct workspace mutation explicitly authorized by the operator"),
            "explicit-allow",
        )
        self.assertEqual(classify_patch_authorization("unauthorized patch access was not used"), "explicit-deny")
        self.assertEqual(classify_patch_authorization("yes"), "ambiguous")

    def test_redacted_packet_changed_file_claim_requires_direct_authorization(self) -> None:
        text = (ROOT / "examples" / "sample-contractor-return.md").read_text(encoding="utf-8")
        text = text.replace("Files changed: none", "Files changed: scripts/example.py")
        text = text.replace(
            "Evidence:\n",
            "Evidence:\n- Proposed patch artifact: example.diff.\n",
        )
        result = make_acceptance_decision(text, share_boundary="redacted-packet")
        self.assertIn("unapproved patch or repo access", result["hard_disqualifiers"])

    def test_redacted_packet_command_execution_claim_rejects_even_with_boundary_compliance(self) -> None:
        text = (ROOT / "examples" / "sample-contractor-return.md").read_text(encoding="utf-8")
        text = text.replace(
            "Commands run: none",
            "Commands run:\n- python scripts/validate_repository.py\n- python -m unittest discover -s tests -v",
        ).replace(
            "Validation result: Reviewed provided packet manifest and selected snippets; no runtime command was executed.",
            "Validation result: passed (repository validation verified and all unit tests passed)",
        )
        result = make_acceptance_decision(text, share_boundary="redacted-packet")
        self.assertEqual(result["verdict"], "reject")
        self.assertEqual(result["boundary_taint_status"], "boundary-tainted")
        self.assertIn("redacted packet return claims command or test execution", result["hard_disqualifiers"])
        self.assertIn("redacted packet return claims unsupported validation", result["hard_disqualifiers"])

    def test_redacted_packet_repo_inspection_preamble_rejects(self) -> None:
        text = (ROOT / "examples" / "sample-contractor-return.md").read_text(encoding="utf-8")
        text = "I am analyzing the repository directory structure before returning.\n" + text
        result = make_acceptance_decision(text, share_boundary="redacted-packet")
        self.assertEqual(result["verdict"], "reject")
        self.assertIn(
            "redacted packet return claims direct repository or workspace inspection",
            result["boundary_taint_findings"],
        )

    def test_redacted_packet_packet_reported_validation_is_allowed(self) -> None:
        text = (ROOT / "examples" / "sample-contractor-return.md").read_text(encoding="utf-8")
        text = text.replace(
            "Validation result: Reviewed provided packet manifest and selected snippets; no runtime command was executed.",
            "Validation result: passed based on packet validation evidence: repository validator, site validator, and 248 unit tests.",
        )
        result = make_acceptance_decision(text, share_boundary="redacted-packet")
        self.assertNotIn("redacted packet return claims unsupported validation", result["hard_disqualifiers"])
        self.assertEqual(result["boundary_taint_status"], "clear")

    def test_chatgpt_share_ingest_wrapper_command_is_not_boundary_taint(self) -> None:
        text = (ROOT / "examples" / "sample-contractor-return.md").read_text(encoding="utf-8")
        text = text.replace(
            "Commands run: none",
            "Commands run: chatgpt-share-local-reader/scripts/read_chatgpt_share.py direct-to-ChatGPT/local parser.",
        ).replace(
            "Validation result: Reviewed provided packet manifest and selected snippets; no runtime command was executed.",
            "Validation result: Share page parsed with the local ChatGPT share reader.",
        )
        result = make_acceptance_decision(text, share_boundary="redacted-packet")
        self.assertEqual(result["boundary_taint_status"], "clear")
        self.assertFalse(result["boundary_taint_findings"])

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

    def test_pending_peer_review_blocks_implementation_until_review_runs(self) -> None:
        text = (ROOT / "examples" / "sample-contractor-return.md").read_text(encoding="utf-8")
        text = text.replace(
            "Peer-review disposition: not required for this sample return.",
            "Peer-review disposition: Required peer review is pending.",
        )
        result = make_acceptance_decision(text, peer_review_required=True)
        self.assertEqual(result["verdict"], "reject")
        self.assertIn("peer review required before implementation use", result["hard_disqualifiers"])
        self.assertEqual(result["recommended_disposition"], "run-peer-review")

    def test_local_worker_acceptance_decision_carries_provider_provenance(self) -> None:
        text = (ROOT / "examples" / "sample-contractor-return.md").read_text(encoding="utf-8")
        result = make_acceptance_decision(text, executor="openshift_ai_vllm_worker")

        self.assertEqual(result["executor"], "openshift_ai_vllm_worker")
        self.assertEqual(result["provider_key"], "openshift_ai_vllm")
        self.assertEqual(result["provider_trust_tier"], "local-platform")
        self.assertEqual(result["dispatch_mode"], "local_openai_compatible")
        self.assertEqual(result["local_profile"], "openshift-ai-vllm")
        self.assertEqual(result["provenance_class"], "local-worker")
        self.assertFalse(result["provider_external"])

    def test_normalized_local_worker_bundle_carries_provider_provenance(self) -> None:
        text = (ROOT / "examples" / "sample-contractor-return.md").read_text(encoding="utf-8")
        bundle = normalize_contractor_return(text, executor="openshift_ai_vllm_secure_reviewer")

        self.assertEqual(bundle["executor"], "openshift_ai_vllm_secure_reviewer")
        self.assertEqual(bundle["provider_key"], "openshift_ai_vllm")
        self.assertEqual(bundle["provider_trust_tier"], "local-platform")
        self.assertEqual(bundle["dispatch_mode"], "local_secure_review")
        self.assertEqual(bundle["local_profile"], "openshift-ai-vllm")
        self.assertEqual(bundle["provenance_class"], "local-worker")
        self.assertFalse(bundle["provider_external"])

    def test_structurally_complete_generic_return_is_not_accepted(self) -> None:
        text = (ROOT / "examples" / "sample-contractor-return.md").read_text(encoding="utf-8")
        text = text.replace(
            "- Included artifacts list contains assignment summary and selected snippets only.\n"
            "- Excluded artifacts list explicitly names full Bead JSON and secrets.",
            "- Looks good and appears reasonable.\n- No issues found.",
        ).replace(
            "Evidence provenance: packet manifest and selected snippets supplied in the contractor packet.",
            "Evidence provenance: reviewer judgment.",
        )

        result = make_acceptance_decision(text, executor="gemini_3_1_pro_preview_agy")

        self.assertNotEqual(result["verdict"], "accept")
        self.assertLess(result["evidence_quality_score"], 85)
        self.assertIn("claim_only_evidence", result["evidence_quality_signal_categories"])
        self.assertIn("vague_evidence", result["evidence_quality_signal_categories"])
        self.assertNotEqual(result["recommended_synthesis_use"], "primary")

    def test_gemini_high_quality_return_defaults_to_salvage_only(self) -> None:
        text = (ROOT / "examples" / "sample-contractor-return.md").read_text(encoding="utf-8")
        result = make_acceptance_decision(text, executor="gemini_3_1_pro_preview_agy")

        self.assertEqual(result["verdict"], "accept")
        self.assertEqual(result["evidence_quality_score"], 100)
        self.assertEqual(result["recommended_synthesis_use"], "salvage-only")

    def test_file_and_packet_evidence_remains_primary_quality(self) -> None:
        text = (ROOT / "examples" / "sample-contractor-return.md").read_text(encoding="utf-8")
        result = make_acceptance_decision(text, executor="claude_opus_4_6_architecture_critic")

        self.assertEqual(result["evidence_quality_score"], 100)
        self.assertEqual(result["evidence_quality_signal_categories"], [])
        self.assertEqual(result["recommended_synthesis_use"], "primary")

    def test_normalized_bundle_carries_evidence_quality(self) -> None:
        text = (ROOT / "examples" / "sample-contractor-return.md").read_text(encoding="utf-8")
        bundle = normalize_contractor_return(text)

        self.assertIn("evidence_quality_score", bundle)
        self.assertIn("evidence_quality_signals", bundle)
        self.assertIn("evidence_quality_signal_categories", bundle)


if __name__ == "__main__":
    unittest.main()
