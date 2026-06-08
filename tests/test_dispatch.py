from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from generate_manual_dispatch_prompt import render_packet_prompt, render_prompt  # noqa: E402
from orchestration_lib import classify_work  # noqa: E402


class DispatchTests(unittest.TestCase):
    def test_manual_prompt_contains_no_blind_acceptance_rule(self) -> None:
        task = "Security review the contractor redaction flow."
        route = classify_work(task, external_ok=True, share_boundary="redacted-packet", requested_roles=["security"])
        prompt = render_prompt(task, route)
        self.assertIn("outside model contractor", prompt)
        self.assertIn("scored by an evaluator", prompt)
        self.assertIn("Share boundary", prompt)

    def test_packet_prompt_contains_assignment_and_required_sections(self) -> None:
        packet = {
            "dispatch_id": "dispatch-test",
            "executor": "claude_code_manual",
            "bead_id": "cwo-1",
            "job_description_label": "contract-jd-security-reasoning",
            "share_boundary": "redacted-packet",
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
        self.assertIn("token=[REDACTED]", prompt)


if __name__ == "__main__":
    unittest.main()
