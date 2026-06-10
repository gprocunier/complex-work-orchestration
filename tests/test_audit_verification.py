from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from orchestration_lib import record_audit_event, verify_audit_log  # noqa: E402


class AuditVerificationTests(unittest.TestCase):
    def test_hash_chained_audit_log_verifies(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            audit_file = Path(tmp) / "audit.jsonl"
            first = record_audit_event({"event_type": "packet_built", "dispatch_id": "d1", "bead_id": "b1"}, audit_file)
            second = record_audit_event({"event_type": "return_evaluated", "dispatch_id": "d1", "bead_id": "b1"}, audit_file)
            self.assertEqual(second["previous_event_hash"], first["event_hash"])
            self.assertTrue(verify_audit_log(audit_file)["valid"])

    def test_hash_chained_audit_log_rejects_tamper(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            audit_file = Path(tmp) / "audit.jsonl"
            record_audit_event({"event_type": "packet_built", "dispatch_id": "d1", "bead_id": "b1"}, audit_file)
            event = json.loads(audit_file.read_text(encoding="utf-8").splitlines()[0])
            event["bead_id"] = "changed"
            audit_file.write_text(json.dumps(event, sort_keys=True) + "\n", encoding="utf-8")
            result = verify_audit_log(audit_file)
            self.assertFalse(result["valid"])
            self.assertTrue(any("event_hash mismatch" in error for error in result["errors"]))


if __name__ == "__main__":
    unittest.main()
