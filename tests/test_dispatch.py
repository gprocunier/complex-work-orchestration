from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from generate_manual_dispatch_prompt import render_packet_prompt, render_prompt  # noqa: E402
from build_contractor_packet import build_packet  # noqa: E402
from orchestration_lib import classify_work, require_valid_contractor_packet, validate_contractor_packet  # noqa: E402


class DispatchTests(unittest.TestCase):
    def test_manual_prompt_contains_no_blind_acceptance_rule(self) -> None:
        task = "Security review the contractor redaction flow."
        route = classify_work(task, external_ok=True, share_boundary="redacted-packet", requested_roles=["security"])
        prompt = render_prompt(task, route)
        self.assertIn("outside model contractor", prompt)
        self.assertIn("scored by an evaluator", prompt)
        self.assertIn("Share boundary", prompt)
        self.assertIn("CONTRACTOR RETURN TEMPLATE - COPY EXACTLY", prompt)
        self.assertIn("Output only the contractor return", prompt)
        self.assertIn("Do not include a preamble", prompt)

    def test_packet_prompt_contains_assignment_and_required_sections(self) -> None:
        packet = {
            "dispatch_id": "dispatch-test",
            "executor": "claude_code_manual",
            "bead_id": "cwo-1",
            "job_description_label": "contract-jd-security-reasoning",
            "share_boundary": "redacted-packet",
            "degraded_context_justification": "",
            "boundary_description": "Share only redacted snippets.",
            "bead_summary": {"id": "cwo-1", "title": "Security review"},
            "included_artifacts": [{"type": "assignment_summary", "sha256": "abc"}],
            "selected_snippets": [{"path": "policy/share-boundaries.yaml", "content": "token=[REDACTED]"}],
            "required_return_sections": ["Status", "Evidence", "Recommended next bead"],
            "packet_sha256": "def",
        }
        prompt = render_packet_prompt(packet)
        self.assertIn("Dispatch ID: dispatch-test", prompt)
        self.assertIn("contract-jd-security-reasoning", prompt)
        self.assertIn("Recommended next bead", prompt)
        self.assertIn("CONTRACTOR RETURN TEMPLATE - COPY EXACTLY", prompt)
        self.assertIn("Patch authorization:", prompt)
        self.assertIn("Do not mutate the active checkout", prompt)
        self.assertIn("do not claim peer review is unnecessary", prompt)
        self.assertIn("token=[REDACTED]", prompt)

    def test_packet_prompt_contains_degraded_justification(self) -> None:
        packet = {
            "dispatch_id": "dispatch-test",
            "executor": "claude_code_manual",
            "bead_id": "cwo-1",
            "job_description_label": "contract-jd-security-reasoning",
            "share_boundary": "redacted-packet",
            "degraded_context_justification": "The user explicitly requested a minimal packet.",
            "boundary_description": "Share only redacted snippets.",
            "bead_summary": {"id": "cwo-1", "title": "Security review"},
            "included_artifacts": [{"type": "assignment_summary", "sha256": "abc"}],
            "selected_snippets": [],
            "required_return_sections": ["Status", "Evidence", "Recommended next bead"],
            "packet_sha256": "def",
            "expert_profile": None,
            "expert_profile_included": False,
        }
        prompt = render_packet_prompt(packet)
        self.assertIn("Degraded-context justification:", prompt)
        self.assertIn("minimal packet", prompt)

    def test_dispatch_packet_validation_accepts_built_packet(self) -> None:
        packet = build_packet(
            bead_id="cwo-1",
            bead_json={"id": "cwo-1", "title": "Security review", "labels": ["contractor-only", "no-codex-exec"]},
            executor="claude_code_manual",
            share_boundary="redacted-packet",
            job_description_label="contract-jd-security-reasoning",
            allowed_files=[],
            inline_snippets=["token=[REDACTED]"],
            dispatch_id="dispatch-valid",
            external_opt_in=True,
            opt_in_basis="cli-flag",
        )
        require_valid_contractor_packet(packet)

    def test_dispatch_packet_validation_rejects_tampering(self) -> None:
        packet = build_packet(
            bead_id="cwo-1",
            bead_json={"id": "cwo-1", "title": "Security review", "labels": ["contractor-only", "no-codex-exec"]},
            executor="claude_code_manual",
            share_boundary="redacted-packet",
            job_description_label="contract-jd-security-reasoning",
            allowed_files=[],
            inline_snippets=[],
            dispatch_id="dispatch-tampered",
            external_opt_in=True,
            opt_in_basis="cli-flag",
        )
        packet["executor"] = "frontier_architect"
        errors = validate_contractor_packet(packet)
        self.assertTrue(any("packet_sha256" in error for error in errors))
        self.assertTrue(any("not an outside contractor" in error for error in errors))

    def test_degraded_packet_requires_explicit_override(self) -> None:
        with self.assertRaises(SystemExit):
            build_packet(
                bead_id="cwo-1",
                bead_json={"id": "cwo-1", "title": "Security review", "labels": ["contractor-only", "no-codex-exec"]},
                executor="claude_code_manual",
                share_boundary="redacted-packet",
                job_description_label="contract-jd-security-reasoning",
                allowed_files=[],
                inline_snippets=[],
                dispatch_id="dispatch-degraded-missing-reason",
                include_expert_profile=False,
                external_opt_in=True,
                opt_in_basis="cli-flag",
            )

        packet = build_packet(
            bead_id="cwo-1",
            bead_json={"id": "cwo-1", "title": "Security review", "labels": ["contractor-only", "no-codex-exec"]},
            executor="claude_code_manual",
            share_boundary="redacted-packet",
            job_description_label="contract-jd-security-reasoning",
            allowed_files=[],
            inline_snippets=[],
            dispatch_id="dispatch-degraded",
            include_expert_profile=False,
            degraded_context_justification="The user requested a profile-free compatibility check.",
            external_opt_in=True,
            opt_in_basis="cli-flag",
        )
        self.assertTrue(validate_contractor_packet(packet))
        self.assertFalse(validate_contractor_packet(packet, allow_degraded_packet=True))


if __name__ == "__main__":
    unittest.main()
