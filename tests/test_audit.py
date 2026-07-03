from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

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
                    "input_tokens": 8,
                    "output_tokens": 13,
                },
                audit,
            )
            loaded = json.loads(audit.read_text(encoding="utf-8").splitlines()[0])
            self.assertNotIn("prompt", loaded)
            self.assertNotIn("response", loaded)
            self.assertNotIn("share_url", loaded)
            self.assertEqual(loaded["total_tokens"], 21)

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
                ]
                build_contractor_packet.main()
                self.assertFalse(lib.AUDIT_LOG.exists())
            finally:
                lib.AUDIT_LOG = original_audit
                sys.argv = original_argv


if __name__ == "__main__":
    unittest.main()
