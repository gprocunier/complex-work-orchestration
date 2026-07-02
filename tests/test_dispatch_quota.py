from __future__ import annotations

import json
import tempfile
import sys
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import dispatch_work  # noqa: E402
import cwo_core.audit as lib  # noqa: E402


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
                        "quota_stage": "reserved",
                        "dispatch_id": "dispatch-same",
                        "epic_id": "epic-1",
                        "executor_external": True,
                        "packet_sha256": "packet-sha",
                    }
                )
                result = lib.enforce_contracting_quota(
                    "epic-1",
                    "claude_code_manual",
                    "external-contract",
                    dispatch_id="dispatch-same",
                    packet_sha256="packet-sha",
                )
                self.assertEqual(result["quota_remaining"], 4)
            finally:
                lib.AUDIT_LOG = original_audit

    def test_reused_dispatch_id_counts_multiple_consumed_dispatch_rows(self) -> None:
        original_audit = lib.AUDIT_LOG
        with tempfile.TemporaryDirectory() as tmp:
            lib.AUDIT_LOG = Path(tmp) / "audit.jsonl"
            try:
                for index in range(2):
                    lib.record_audit_event(
                        {
                            "event_type": "dispatch_prepared",
                            "quota_event_type": "external_manual_dispatch",
                            "quota_stage": "consumed",
                            "dispatch_id": "dispatch-reused",
                            "epic_id": "epic-1",
                            "executor_external": True,
                            "packet_sha256": f"packet-{index}",
                        }
                    )
                result = lib.enforce_contracting_quota(
                    "epic-1",
                    "claude_code_manual",
                    "external-contract",
                    dispatch_id="dispatch-reused",
                    packet_sha256="packet-new",
                )
                self.assertEqual(result["quota_remaining"], 2)
            finally:
                lib.AUDIT_LOG = original_audit

    def test_direct_dispatch_uses_stable_dispatch_id_for_quota_and_audit(self) -> None:
        original_audit = lib.AUDIT_LOG
        original_argv = sys.argv[:]
        with tempfile.TemporaryDirectory() as tmp:
            lib.AUDIT_LOG = Path(tmp) / "audit.jsonl"
            try:
                sys.argv = [
                    "dispatch_work.py",
                    "Documentation review for public README examples.",
                    "--local-ok",
                    "--prefer-local",
                    "--share-boundary",
                    "no-outside-sharing",
                    "--requested-role",
                    "documentation",
                    "--bead",
                    "bead-1",
                    "--epic",
                    "epic-1",
                    "--dispatch-id",
                    "dispatch-fixed",
                    "--json",
                ]
                output = StringIO()
                with redirect_stdout(output):
                    dispatch_work.main()
                artifact = json.loads(output.getvalue())
                self.assertEqual(artifact["dispatch_id"], "dispatch-fixed")
                self.assertEqual(artifact["quota_event_type"], "local_worker_dispatch")
                events = lib.iter_audit_events(lib.AUDIT_LOG)
                self.assertEqual(events[-1]["dispatch_id"], "dispatch-fixed")
                self.assertEqual(events[-1]["quota_event_type"], "local_worker_dispatch")
            finally:
                sys.argv = original_argv
                lib.AUDIT_LOG = original_audit


if __name__ == "__main__":
    unittest.main()
