from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from build_contractor_packet import build_packet  # noqa: E402


class PacketProfileInclusionTests(unittest.TestCase):
    def test_packet_includes_expert_profile_by_default(self) -> None:
        bead = json.loads((ROOT / "examples" / "sample-bead.json").read_text(encoding="utf-8"))
        packet = build_packet(
            bead_id=bead["id"],
            bead_json=bead,
            executor="claude_code_manual",
            share_boundary="redacted-packet",
            job_description_label="contract-jd-security-reasoning",
            allowed_files=[],
            inline_snippets=[],
            dispatch_id="dispatch-profile-test",
        )
        self.assertTrue(packet["expert_profile_included"])
        self.assertEqual(packet["expert_profile"]["path"], "experts/security.md")
        self.assertIn("Security Distinguished Engineer", packet["expert_profile"]["content"])
        artifact_types = {item["type"] for item in packet["included_artifacts"]}
        self.assertIn("expert_profile", artifact_types)

    def test_packet_can_explicitly_omit_expert_profile(self) -> None:
        bead = json.loads((ROOT / "examples" / "sample-bead.json").read_text(encoding="utf-8"))
        packet = build_packet(
            bead_id=bead["id"],
            bead_json=bead,
            executor="claude_code_manual",
            share_boundary="redacted-packet",
            job_description_label="contract-jd-security-reasoning",
            allowed_files=[],
            inline_snippets=[],
            dispatch_id="dispatch-no-profile-test",
            include_expert_profile=False,
            degraded_context_justification="The operator requested a minimal compatibility packet.",
        )
        self.assertFalse(packet["expert_profile_included"])
        self.assertIsNone(packet["expert_profile"])
        self.assertIn("minimal compatibility", packet["degraded_context_justification"])

    def test_caller_selected_profile_must_stay_under_experts(self) -> None:
        bead = json.loads((ROOT / "examples" / "sample-bead.json").read_text(encoding="utf-8"))
        with self.assertRaises(SystemExit) as exc:
            build_packet(
                bead_id=bead["id"],
                bead_json=bead,
                executor="claude_code_manual",
                share_boundary="redacted-packet",
                job_description_label="contract-jd-security-reasoning",
                allowed_files=[],
                inline_snippets=[],
                dispatch_id="dispatch-profile-test",
                expert_profile_path="README.md",
            )
        self.assertIn("expert profile must be", str(exc.exception))


if __name__ == "__main__":
    unittest.main()
