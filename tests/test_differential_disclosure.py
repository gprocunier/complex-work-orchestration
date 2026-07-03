from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from build_contractor_packet import build_packet, validate_gate  # noqa: E402
from cwo_core.util import packet_payload_hash  # noqa: E402
from cwo_core.packets import validate_contractor_packet  # noqa: E402


class DifferentialDisclosureTests(unittest.TestCase):
    def test_repo_readonly_requires_explicit_disclosure_escalation(self) -> None:
        labels = ["contractor-only", "no-codex-exec", "contract-jd-security-reasoning"]
        with self.assertRaises(SystemExit):
            validate_gate(
                "claude_code_manual",
                "repo-readonly",
                labels,
                "contract-jd-security-reasoning",
                external_ok=True,
                opt_in_record=None,
            )
        basis = validate_gate(
            "claude_code_manual",
            "repo-readonly",
            labels,
            "contract-jd-security-reasoning",
            external_ok=True,
            opt_in_record=None,
            allow_disclosure_escalation=True,
        )
        self.assertEqual(basis, "cli-flag")

    def test_packet_validation_rejects_unapproved_repo_readonly_disclosure(self) -> None:
        packet = build_packet(
            bead_id="cwo-1",
            bead_json={
                "id": "cwo-1",
                "title": "Security review",
                "labels": ["contractor-only", "no-codex-exec", "contract-jd-security-reasoning"],
            },
            executor="claude_code_manual",
            share_boundary="repo-readonly",
            job_description_label="contract-jd-security-reasoning",
            allowed_files=[],
            inline_snippets=["approved snippet"],
            dispatch_id="dispatch-disclosure",
            external_opt_in=True,
            opt_in_basis="cli-flag",
            disclosure_escalation_approved=False,
        )
        packet["packet_sha256"] = packet_payload_hash(packet)
        errors = validate_contractor_packet(packet)
        self.assertTrue(any("requires disclosure escalation approval" in error for error in errors))


if __name__ == "__main__":
    unittest.main()
