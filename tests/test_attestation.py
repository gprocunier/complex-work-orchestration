from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from orchestration_lib import artifact_hash, make_attestation, verify_attestation  # noqa: E402


class AttestationTests(unittest.TestCase):
    def test_attestation_verifies_subject_hash(self) -> None:
        subject = "packet payload"
        attestation = make_attestation(
            subject_type="contractor-packet",
            subject_sha256=artifact_hash(subject),
            subject_id="dispatch-1",
        )
        self.assertTrue(verify_attestation(subject, attestation)["valid"])

    def test_attestation_rejects_tampered_subject(self) -> None:
        attestation = make_attestation(
            subject_type="contractor-packet",
            subject_sha256=artifact_hash("packet payload"),
            subject_id="dispatch-1",
        )
        result = verify_attestation("changed payload", attestation)
        self.assertFalse(result["valid"])
        self.assertTrue(result["errors"])


if __name__ == "__main__":
    unittest.main()
