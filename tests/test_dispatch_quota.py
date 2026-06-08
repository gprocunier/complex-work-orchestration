from __future__ import annotations

import tempfile
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import orchestration_lib as lib  # noqa: E402


class DispatchQuotaTests(unittest.TestCase):
    def test_external_quota_enforced_per_epic(self) -> None:
        original_audit = lib.AUDIT_LOG
        with tempfile.TemporaryDirectory() as tmp:
            lib.AUDIT_LOG = Path(tmp) / "audit.jsonl"
            try:
                first = lib.enforce_contracting_quota("epic-1", "claude_code_manual", "external-contract")
                self.assertTrue(first["quota_checked"])
                self.assertEqual(first["quota_remaining"], 4)
                for index in range(5):
                    lib.record_audit_event(
                        {
                            "event_type": "dispatch_prepared",
                            "quota_event_type": "external_manual_dispatch",
                            "dispatch_id": f"dispatch-{index}",
                            "epic_id": "epic-1",
                            "executor_external": True,
                        }
                    )
                with self.assertRaises(SystemExit):
                    lib.enforce_contracting_quota("epic-1", "claude_code_manual", "external-contract")
            finally:
                lib.AUDIT_LOG = original_audit

    def test_same_dispatch_id_does_not_double_count(self) -> None:
        original_audit = lib.AUDIT_LOG
        with tempfile.TemporaryDirectory() as tmp:
            lib.AUDIT_LOG = Path(tmp) / "audit.jsonl"
            try:
                lib.record_audit_event(
                    {
                        "event_type": "packet_built",
                        "quota_event_type": "external_manual_dispatch",
                        "dispatch_id": "dispatch-same",
                        "epic_id": "epic-1",
                        "executor_external": True,
                    }
                )
                result = lib.enforce_contracting_quota(
                    "epic-1",
                    "claude_code_manual",
                    "external-contract",
                    dispatch_id="dispatch-same",
                )
                self.assertEqual(result["quota_remaining"], 4)
            finally:
                lib.AUDIT_LOG = original_audit


if __name__ == "__main__":
    unittest.main()
