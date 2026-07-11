from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import build_contractor_packet  # noqa: E402
import cwo_core.audit as lib  # noqa: E402
from cwo_core.audit import record_audit_event  # noqa: E402


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

    def test_audit_event_sanitizes_sensitive_fields_and_computes_total_tokens(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            audit = Path(tmp) / "audit.jsonl"
            record_audit_event(
                {
                    "event_type": "dispatch",
                    "dispatch_id": "dispatch-sanitize",
                    "bead_id": "example",
                    "prompt": "LEAK_PROMPT",
                    "response": {"content": "LEAK_RESPONSE"},
                    "share_url": "https://chatgpt.com/s/t_secret",
                    "unsafe_new_field": "not in the reporting contract",
                    "input_tokens": 8,
                    "output_tokens": 13,
                },
                audit,
            )
            loaded = json.loads(audit.read_text(encoding="utf-8").splitlines()[0])
            self.assertNotIn("prompt", loaded)
            self.assertNotIn("response", loaded)
            self.assertNotIn("share_url", loaded)
            self.assertNotIn("unsafe_new_field", loaded)
            self.assertEqual(loaded["total_tokens"], 21)

    def test_audit_event_does_not_infer_total_tokens_from_partial_usage(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            audit = Path(tmp) / "audit.jsonl"
            record_audit_event(
                {
                    "event_type": "dispatch",
                    "dispatch_id": "dispatch-partial-usage",
                    "bead_id": "example",
                    "input_tokens": 8,
                },
                audit,
            )
            loaded = json.loads(audit.read_text(encoding="utf-8").splitlines()[0])
            self.assertEqual(loaded["input_tokens"], 8)
            self.assertNotIn("total_tokens", loaded)

    def test_sol_breakfix_authorization_fields_survive_sanitization(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            audit = Path(tmp) / "audit.jsonl"
            record_audit_event(
                {
                    "event_type": "sol_breakfix_authorized",
                    "bead_id": "project-123",
                    "operator_approval_ref": "current-chat-turn",
                    "sol_breakfix_incident_kind": "self-hosting-orchestration",
                    "sol_breakfix_scope": "repair native worker controls",
                    "sol_breakfix_expiry": "project-123",
                    "swimlane_violation": True,
                    "automatic_selection_forbidden": True,
                    "session_disposition": "quarantined",
                    "artifact_disposition": "independent-validation-required",
                    "artifact_validation": {
                        "eligible": True,
                        "max_attempts": 1,
                        "attempts_used": 0,
                        "outcome": "not-run",
                        "reason": "budget-only hard overrun",
                    },
                },
                audit,
            )
            loaded = json.loads(audit.read_text(encoding="utf-8").splitlines()[0])
            self.assertEqual(loaded["operator_approval_ref"], "current-chat-turn")
            self.assertEqual(loaded["sol_breakfix_incident_kind"], "self-hosting-orchestration")
            self.assertEqual(loaded["sol_breakfix_scope"], "repair native worker controls")
            self.assertEqual(loaded["sol_breakfix_expiry"], "project-123")
            self.assertTrue(loaded["swimlane_violation"])
            self.assertTrue(loaded["automatic_selection_forbidden"])
            self.assertEqual(loaded["session_disposition"], "quarantined")
            self.assertEqual(loaded["artifact_disposition"], "independent-validation-required")
            self.assertTrue(loaded["artifact_validation"]["eligible"])

    def test_audit_event_sanitizes_workspace_mutation_object(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            audit = Path(tmp) / "audit.jsonl"
            record_audit_event(
                {
                    "event_type": "return_evaluated",
                    "dispatch_id": "dispatch-workspace-mutation",
                    "bead_id": "example",
                    "workspace_mutation": {
                        "workspace_mutation_report_type": "git-status-diff",
                        "version": 1,
                        "status_scope": "tracked",
                        "mutation_detected": True,
                        "unexpected_mutation_detected": True,
                        "before": {"tracked_status": ["LEAK_BEFORE"]},
                        "after": {"tracked_status": ["LEAK_AFTER"]},
                        "sensitive_file_content": "LEAK_SECRET",
                        "unexpected_mutations": [
                            {
                                "path": "docs/styles.css",
                                "before": None,
                                "after": " M docs/styles.css",
                                "secret": "LEAK_NESTED",
                            }
                        ],
                    },
                },
                audit,
            )
            loaded = json.loads(audit.read_text(encoding="utf-8").splitlines()[0])
            mutation = loaded["workspace_mutation"]
            self.assertEqual(mutation["workspace_mutation_report_type"], "git-status-diff")
            self.assertEqual(mutation["version"], 1)
            self.assertTrue(mutation["mutation_detected"])
            self.assertEqual(
                mutation["unexpected_mutations"],
                [{"after": "M docs/styles.css", "before": None, "path": "docs/styles.css"}],
            )
            self.assertNotIn("before", mutation)
            self.assertNotIn("after", mutation)
            self.assertNotIn("sensitive_file_content", mutation)
            self.assertNotIn("secret", json.dumps(mutation))

    def test_record_audit_event_cli_accepts_telemetry_flags(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            audit = Path(tmp) / "audit.jsonl"
            result = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "scripts" / "record_audit_event.py"),
                    "--event-type",
                    "dispatch",
                    "--dispatch-id",
                    "dispatch-cli",
                    "--bead",
                    "example",
                    "--telemetry-kind",
                    "manual_dispatch",
                    "--telemetry-source",
                    "operator-sidecar",
                    "--model",
                    "claude-opus-4-6",
                    "--provider-family",
                    "anthropic",
                    "--agent-model-calls",
                    "1",
                    "--input-tokens",
                    "20",
                    "--output-tokens",
                    "5",
                    "--audit-file",
                    str(audit),
                ],
                cwd=ROOT,
                check=True,
                capture_output=True,
                text=True,
            )
            payload = json.loads(result.stdout)
            self.assertEqual(payload["telemetry_kind"], "manual_dispatch")
            self.assertEqual(payload["telemetry_source"], "operator-sidecar")
            self.assertEqual(payload["provider_family"], "anthropic")
            self.assertEqual(payload["total_tokens"], 25)

    def test_packet_build_audits_by_default(self) -> None:
        original_audit = lib.AUDIT_LOG
        original_argv = sys.argv[:]
        with tempfile.TemporaryDirectory() as tmp:
            lib.AUDIT_LOG = Path(tmp) / "audit.jsonl"
            output = Path(tmp) / "packet.json"
            try:
                sys.argv = [
                    "build_contractor_packet.py",
                    "--bead",
                    "complex-work-orchestration-example",
                    "--bead-json-file",
                    str(ROOT / "examples" / "sample-bead.json"),
                    "--executor",
                    "claude_code_manual",
                    "--share-boundary",
                    "redacted-packet",
                    "--external-ok",
                    "--dispatch-id",
                    "dispatch-default-audit",
                    "--format",
                    "json",
                    "--output",
                    str(output),
                ]
                build_contractor_packet.main()
                events = [json.loads(line) for line in lib.AUDIT_LOG.read_text(encoding="utf-8").splitlines()]
                self.assertEqual(events[0]["event_type"], "packet_built")
                self.assertEqual(events[0]["dispatch_id"], "dispatch-default-audit")
                self.assertEqual(events[0]["telemetry_kind"], "packet_build")
                self.assertEqual(events[0]["provider_family"], "anthropic")
                self.assertEqual(events[0]["job_description_label"], "contract-jd-security-reasoning")
                self.assertIn("expert_profile_path", events[0])
                self.assertIn("included_artifacts_count", events[0])
                self.assertNotIn("selected_snippets", events[0])
            finally:
                lib.AUDIT_LOG = original_audit
                sys.argv = original_argv

    def test_packet_build_no_audit_suppresses_default_event(self) -> None:
        original_audit = lib.AUDIT_LOG
        original_argv = sys.argv[:]
        with tempfile.TemporaryDirectory() as tmp:
            lib.AUDIT_LOG = Path(tmp) / "audit.jsonl"
            output = Path(tmp) / "packet.json"
            try:
                sys.argv = [
                    "build_contractor_packet.py",
                    "--bead",
                    "complex-work-orchestration-example",
                    "--bead-json-file",
                    str(ROOT / "examples" / "sample-bead.json"),
                    "--executor",
                    "claude_code_manual",
                    "--share-boundary",
                    "redacted-packet",
                    "--external-ok",
                    "--dispatch-id",
                    "dispatch-no-audit",
                    "--format",
                    "json",
                    "--output",
                    str(output),
                    "--no-audit",
                    "--rehearsal",
                    "--waiver-reason",
                    "test packet build without audit",
                ]
                build_contractor_packet.main()
                self.assertFalse(lib.AUDIT_LOG.exists())
            finally:
                lib.AUDIT_LOG = original_audit
                sys.argv = original_argv

    def test_packet_build_no_audit_requires_rehearsal(self) -> None:
        original_audit = lib.AUDIT_LOG
        original_argv = sys.argv[:]
        with tempfile.TemporaryDirectory() as tmp:
            lib.AUDIT_LOG = Path(tmp) / "audit.jsonl"
            output = Path(tmp) / "packet.json"
            try:
                sys.argv = [
                    "build_contractor_packet.py",
                    "--bead",
                    "complex-work-orchestration-example",
                    "--bead-json-file",
                    str(ROOT / "examples" / "sample-bead.json"),
                    "--executor",
                    "claude_code_manual",
                    "--share-boundary",
                    "redacted-packet",
                    "--external-ok",
                    "--dispatch-id",
                    "dispatch-no-audit-blocked",
                    "--format",
                    "json",
                    "--output",
                    str(output),
                    "--no-audit",
                ]
                with self.assertRaises(SystemExit) as context:
                    build_contractor_packet.main()
                self.assertIn("--rehearsal", str(context.exception))
                self.assertFalse(output.exists())
            finally:
                lib.AUDIT_LOG = original_audit
                sys.argv = original_argv

    def test_packet_build_does_not_write_artifacts_when_audit_fails(self) -> None:
        original_audit = lib.AUDIT_LOG
        original_argv = sys.argv[:]
        with tempfile.TemporaryDirectory() as tmp:
            lib.AUDIT_LOG = Path(tmp) / "audit.jsonl"
            output = Path(tmp) / "packet.json"
            try:
                sys.argv = [
                    "build_contractor_packet.py",
                    "--bead",
                    "complex-work-orchestration-example",
                    "--bead-json-file",
                    str(ROOT / "examples" / "sample-bead.json"),
                    "--executor",
                    "claude_code_manual",
                    "--share-boundary",
                    "redacted-packet",
                    "--external-ok",
                    "--dispatch-id",
                    "dispatch-audit-fails",
                    "--format",
                    "json",
                    "--output",
                    str(output),
                    "--attest-packet",
                ]
                with patch("build_contractor_packet.record_audit_event", side_effect=RuntimeError("audit unavailable")):
                    with self.assertRaises(RuntimeError):
                        build_contractor_packet.main()
                self.assertFalse(output.exists())
                self.assertFalse(output.with_suffix(output.suffix + ".attestation.json").exists())
            finally:
                lib.AUDIT_LOG = original_audit
                sys.argv = original_argv


if __name__ == "__main__":
    unittest.main()
