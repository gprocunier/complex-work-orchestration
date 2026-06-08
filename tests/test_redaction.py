from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from build_contractor_packet import build_packet  # noqa: E402


class RedactionTests(unittest.TestCase):
    def test_redacted_packet_omits_full_bead_comments(self) -> None:
        bead = json.loads((ROOT / "examples" / "sample-bead.json").read_text(encoding="utf-8"))
        packet = build_packet(
            bead_id=bead["id"],
            bead_json=bead,
            executor="claude_code_manual",
            share_boundary="redacted-packet",
            job_description_label="contract-jd-security-reasoning",
            allowed_files=[],
            inline_snippets=["token=abc123 should be redacted"],
            dispatch_id="dispatch-test",
        )
        rendered = json.dumps(packet, sort_keys=True)
        self.assertNotIn("This comment must not appear", rendered)
        self.assertNotIn("token=abc123", rendered)
        self.assertIn("[REDACTED]", rendered)
        self.assertEqual(packet["share_boundary"], "redacted-packet")
        self.assertTrue(packet["packet_sha256"])


if __name__ == "__main__":
    unittest.main()
