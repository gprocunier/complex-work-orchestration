from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from orchestration_lib import record_audit_event  # noqa: E402


class AuditTests(unittest.TestCase):
    def test_audit_event_records_jsonl(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            audit = Path(tmp) / "audit.jsonl"
            event = record_audit_event(
                {
                    "event_type": "packet_built",
                    "dispatch_id": "dispatch-test",
                    "bead_id": "example",
                },
                audit,
            )
            lines = audit.read_text(encoding="utf-8").splitlines()
            self.assertEqual(len(lines), 1)
            loaded = json.loads(lines[0])
            self.assertEqual(loaded["dispatch_id"], "dispatch-test")
            self.assertEqual(loaded["event_hash"], event["event_hash"])


if __name__ == "__main__":
    unittest.main()
