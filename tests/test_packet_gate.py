from __future__ import annotations

import tempfile
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from build_contractor_packet import validate_gate  # noqa: E402


class PacketGateTests(unittest.TestCase):
    def test_external_packet_requires_explicit_opt_in(self) -> None:
        labels = ["contractor-only", "no-codex-exec", "contract-jd-security-reasoning"]
        with self.assertRaises(SystemExit):
            validate_gate(
                "claude_code_manual",
                "redacted-packet",
                labels,
                "contract-jd-security-reasoning",
                external_ok=False,
                opt_in_record=None,
            )

    def test_opt_in_record_is_accepted(self) -> None:
        labels = ["contractor-only", "no-codex-exec", "contract-jd-security-reasoning"]
        with tempfile.NamedTemporaryFile() as handle:
            basis = validate_gate(
                "claude_code_manual",
                "redacted-packet",
                labels,
                "contract-jd-security-reasoning",
                external_ok=False,
                opt_in_record=handle.name,
            )
        self.assertEqual(basis, "audit-record")


if __name__ == "__main__":
    unittest.main()
