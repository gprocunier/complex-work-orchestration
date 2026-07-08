from __future__ import annotations

import json
import tempfile
import sys
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import dispatch_work  # noqa: E402
import build_contractor_packet  # noqa: E402
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

    def test_pre_submission_chatgpt_browser_failures_do_not_consume_quota(self) -> None:
        original_audit = lib.AUDIT_LOG
        with tempfile.TemporaryDirectory() as tmp:
            lib.AUDIT_LOG = Path(tmp) / "audit.jsonl"
            try:
                for index in range(5):
                    lib.record_audit_event(
                        {
                            "event_type": "chatgpt_browser_dispatch",
                            "quota_event_type": "external_manual_dispatch",
                            "quota_stage": "consumed",
                            "telemetry_status": "failed",
                            "failure_stage": "prompt-submit",
                            "dispatch_id": f"dispatch-browser-{index}",
                            "epic_id": "epic-1",
                            "executor_external": True,
                            "packet_sha256": f"packet-{index}",
                            "response_chars": 0,
                            "share_url_present": False,
                        }
                    )
                result = lib.enforce_contracting_quota(
                    "epic-1",
                    "chatgpt_pro_browser_master_reviewer",
                    "external-contract",
                )
                self.assertEqual(result["quota_remaining"], 4)
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

    def test_packet_build_infers_epic_scope_from_bead_parent(self) -> None:
        original_audit = lib.AUDIT_LOG
        original_argv = sys.argv[:]
        with tempfile.TemporaryDirectory() as tmp:
            lib.AUDIT_LOG = Path(tmp) / "audit.jsonl"
            output_path = Path(tmp) / "packet.json"
            bead_json = [
                {
                    "id": "cwo-review-1",
                    "parent": "cwo-epic-1",
                    "title": "ChatGPT Pro review",
                    "labels": [
                        "contractor-only",
                        "no-codex-exec",
                        "contract-jd-master-plan-review",
                    ],
                }
            ]
            try:
                sys.argv = [
                    "build_contractor_packet.py",
                    "--bead",
                    "cwo-review-1",
                    "--executor",
                    "chatgpt_pro_browser_master_reviewer",
                    "--share-boundary",
                    "redacted-packet",
                    "--external-ok",
                    "--format",
                    "json",
                    "--output",
                    str(output_path),
                ]
                with patch.object(build_contractor_packet, "show_bead_json", return_value=bead_json):
                    build_contractor_packet.main()

                packet = json.loads(output_path.read_text(encoding="utf-8"))
                self.assertEqual(packet["epic_id"], "cwo-epic-1")
                self.assertEqual(packet["quota_remaining"], 4)
                events = lib.iter_audit_events(lib.AUDIT_LOG)
                self.assertEqual(events[-1]["epic_id"], "cwo-epic-1")
                self.assertEqual(events[-1]["quota_event_type"], "external_manual_dispatch")
                self.assertEqual(events[-1]["quota_stage"], "reserved")
            finally:
                sys.argv = original_argv
                lib.AUDIT_LOG = original_audit

    def test_packet_build_accepts_matching_explicit_epic_scope(self) -> None:
        original_audit = lib.AUDIT_LOG
        original_argv = sys.argv[:]
        with tempfile.TemporaryDirectory() as tmp:
            lib.AUDIT_LOG = Path(tmp) / "audit.jsonl"
            output_path = Path(tmp) / "packet.json"
            bead_json = [
                {
                    "id": "cwo-review-1",
                    "parent": "cwo-epic-1",
                    "title": "ChatGPT Pro review",
                    "labels": [
                        "contractor-only",
                        "no-codex-exec",
                        "contract-jd-master-plan-review",
                    ],
                }
            ]
            try:
                sys.argv = [
                    "build_contractor_packet.py",
                    "--bead",
                    "cwo-review-1",
                    "--epic",
                    "cwo-epic-1",
                    "--executor",
                    "chatgpt_pro_browser_master_reviewer",
                    "--share-boundary",
                    "redacted-packet",
                    "--external-ok",
                    "--format",
                    "json",
                    "--output",
                    str(output_path),
                ]
                with patch.object(build_contractor_packet, "show_bead_json", return_value=bead_json):
                    build_contractor_packet.main()

                packet = json.loads(output_path.read_text(encoding="utf-8"))
                self.assertEqual(packet["epic_id"], "cwo-epic-1")
                events = lib.iter_audit_events(lib.AUDIT_LOG)
                self.assertEqual(events[-1]["epic_id"], "cwo-epic-1")
            finally:
                sys.argv = original_argv
                lib.AUDIT_LOG = original_audit

    def test_packet_build_preserves_global_scope_for_parentless_bead_without_epic(self) -> None:
        original_audit = lib.AUDIT_LOG
        original_argv = sys.argv[:]
        with tempfile.TemporaryDirectory() as tmp:
            lib.AUDIT_LOG = Path(tmp) / "audit.jsonl"
            output_path = Path(tmp) / "packet.json"
            bead_json = [
                {
                    "id": "cwo-review-1",
                    "title": "ChatGPT Pro review",
                    "labels": [
                        "contractor-only",
                        "no-codex-exec",
                        "contract-jd-master-plan-review",
                    ],
                }
            ]
            try:
                sys.argv = [
                    "build_contractor_packet.py",
                    "--bead",
                    "cwo-review-1",
                    "--executor",
                    "chatgpt_pro_browser_master_reviewer",
                    "--share-boundary",
                    "redacted-packet",
                    "--external-ok",
                    "--format",
                    "json",
                    "--output",
                    str(output_path),
                ]
                with patch.object(build_contractor_packet, "show_bead_json", return_value=bead_json):
                    build_contractor_packet.main()

                packet = json.loads(output_path.read_text(encoding="utf-8"))
                self.assertIsNone(packet["epic_id"])
                self.assertEqual(packet["quota_remaining"], 4)
                events = lib.iter_audit_events(lib.AUDIT_LOG)
                self.assertIsNone(events[-1].get("epic_id"))
            finally:
                sys.argv = original_argv
                lib.AUDIT_LOG = original_audit

    def test_packet_build_rejects_conflicting_explicit_epic_scope(self) -> None:
        original_audit = lib.AUDIT_LOG
        original_argv = sys.argv[:]
        with tempfile.TemporaryDirectory() as tmp:
            lib.AUDIT_LOG = Path(tmp) / "audit.jsonl"
            output_path = Path(tmp) / "packet.json"
            bead_json = [
                {
                    "id": "cwo-review-1",
                    "parent": "cwo-epic-1",
                    "title": "ChatGPT Pro review",
                    "labels": [
                        "contractor-only",
                        "no-codex-exec",
                        "contract-jd-master-plan-review",
                    ],
                }
            ]
            try:
                sys.argv = [
                    "build_contractor_packet.py",
                    "--bead",
                    "cwo-review-1",
                    "--epic",
                    "wrong-epic",
                    "--executor",
                    "chatgpt_pro_browser_master_reviewer",
                    "--share-boundary",
                    "redacted-packet",
                    "--external-ok",
                    "--format",
                    "json",
                    "--output",
                    str(output_path),
                ]
                with patch.object(build_contractor_packet, "show_bead_json", return_value=bead_json):
                    with self.assertRaises(SystemExit) as raised:
                        build_contractor_packet.main()

                self.assertIn("does not match assigned Bead parent", str(raised.exception))
                self.assertFalse(output_path.exists())
                self.assertEqual(lib.iter_audit_events(lib.AUDIT_LOG), [])
            finally:
                sys.argv = original_argv
                lib.AUDIT_LOG = original_audit

    def test_epic_inference_supports_nested_parent_and_dependency_parent(self) -> None:
        self.assertEqual(
            build_contractor_packet.infer_epic_id_from_bead(
                [{"id": "cwo-review-1", "parent": {"id": "cwo-epic-1"}}]
            ),
            "cwo-epic-1",
        )
        self.assertEqual(
            build_contractor_packet.infer_epic_id_from_bead(
                [
                    {
                        "id": "cwo-review-1",
                        "dependencies": [
                            {
                                "type": "parent-child",
                                "issue_id": "cwo-review-1",
                                "depends_on_id": "cwo-epic-1",
                            }
                        ],
                    }
                ]
            ),
            "cwo-epic-1",
        )
        self.assertIsNone(
            build_contractor_packet.infer_epic_id_from_bead(
                [
                    {
                        "id": "cwo-review-1",
                        "dependencies": [
                            {
                                "type": "parent-child",
                                "issue_id": "cwo-review-1",
                            }
                        ],
                    }
                ]
            )
        )


if __name__ == "__main__":
    unittest.main()
