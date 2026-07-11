from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class ImportExecutionTelemetryTests(unittest.TestCase):
    def test_cli_imports_usage_sidecar_as_sanitized_audit_event(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            temp = Path(tmp)
            audit = temp / "audit.jsonl"
            audit.write_text(
                json.dumps(
                    {
                        "event_type": "external_manual_dispatch",
                        "dispatch_id": "dispatch-usage",
                        "bead_id": "cwo-usage",
                        "executor_key": "claude_opus",
                        "provider_key": "anthropic",
                        "event_hash": "target-hash",
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            sidecar = temp / "usage.json"
            sidecar.write_text(
                json.dumps(
                    {
                        "source_label": "operator-sidecar",
                        "records": [
                            {
                                "dispatch_id": "dispatch-usage",
                                "usage": {"prompt_tokens": 10, "completion_tokens": 5},
                                "elapsed_seconds": 3.5,
                                "retry_count": 0,
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            result = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "scripts" / "import_execution_telemetry.py"),
                    "--file",
                    str(sidecar),
                    "--audit-file",
                    str(audit),
                    "--json",
                ],
                cwd=ROOT,
                check=True,
                capture_output=True,
                text=True,
            )

            payload = json.loads(result.stdout)
            self.assertEqual(payload["imported"], 1)
            events = [json.loads(line) for line in audit.read_text(encoding="utf-8").splitlines()]
            self.assertEqual(len(events), 2)
            imported = events[1]
            self.assertEqual(imported["event_type"], "execution_telemetry_import")
            self.assertEqual(imported["telemetry_kind"], "usage_import")
            self.assertEqual(imported["telemetry_source"], "operator-sidecar")
            self.assertEqual(imported["telemetry_target_event_hash"], "target-hash")
            self.assertEqual(imported["total_tokens"], 15)
            self.assertNotIn("usage", imported)

    def test_cli_rejects_sensitive_sidecar_fields(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            temp = Path(tmp)
            audit = temp / "audit.jsonl"
            audit.write_text(
                json.dumps(
                    {
                        "event_type": "dispatch",
                        "dispatch_id": "dispatch-sensitive",
                        "bead_id": "cwo-sensitive",
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            sidecar = temp / "usage.json"
            sidecar.write_text(
                json.dumps(
                    {
                        "dispatch_id": "dispatch-sensitive",
                        "input_tokens": 1,
                        "prompt": "do not import",
                    }
                ),
                encoding="utf-8",
            )

            result = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "scripts" / "import_execution_telemetry.py"),
                    "--file",
                    str(sidecar),
                    "--audit-file",
                    str(audit),
                    "--json",
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("sensitive field", result.stderr)
            self.assertEqual(len(audit.read_text(encoding="utf-8").splitlines()), 1)

    def test_cli_imports_workerbee_delegation_sidecar(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            temp = Path(tmp)
            audit = temp / "audit.jsonl"
            audit.write_text(
                json.dumps(
                    {
                        "event_type": "dispatch",
                        "dispatch_id": "dispatch-workerbee",
                        "bead_id": "cwo-workerbee",
                        "executor_key": "frontier_architect",
                        "event_hash": "target-hash",
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            sidecar = temp / "workerbee.json"
            sidecar.write_text(
                json.dumps(
                    {
                        "dispatch_id": "dispatch-workerbee",
                        "workerbee_planned_mode": "implementation-capable",
                        "workerbee_planned_model": "gpt-5.3-codex-spark",
                        "workerbee_planned_lanes": ["packet-surface", "delegation-reporting"],
                        "workerbee_actual_mode": "implementation-capable",
                        "workerbee_actual_model": "gpt-5.3-codex-spark",
                        "workerbee_actual_lanes": ["delegation-reporting"],
                        "workerbee_delegation_status": "partial",
                        "workerbee_delegation_gap_reasons": ["packet-surface-not-launched"],
                    }
                ),
                encoding="utf-8",
            )

            result = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "scripts" / "import_execution_telemetry.py"),
                    "--file",
                    str(sidecar),
                    "--audit-file",
                    str(audit),
                    "--json",
                ],
                cwd=ROOT,
                check=True,
                capture_output=True,
                text=True,
            )

            payload = json.loads(result.stdout)
            self.assertEqual(payload["imported"], 1)
            events = [json.loads(line) for line in audit.read_text(encoding="utf-8").splitlines()]
            imported = events[1]
            self.assertEqual(imported["workerbee_delegation_status"], "partial")
            self.assertEqual(imported["workerbee_actual_lanes"], ["delegation-reporting"])
            self.assertEqual(imported["workerbee_planned_lanes"], ["packet-surface", "delegation-reporting"])

    def test_cli_imports_nested_workerbee_planned_delegation_sidecar(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            temp = Path(tmp)
            audit = temp / "audit.jsonl"
            audit.write_text(
                json.dumps(
                    {
                        "event_type": "dispatch",
                        "dispatch_id": "dispatch-workerbee-nested",
                        "bead_id": "cwo-workerbee-nested",
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            sidecar = temp / "workerbee-nested.json"
            sidecar.write_text(
                json.dumps(
                    {
                        "dispatch_id": "dispatch-workerbee-nested",
                        "workerbee_planned_delegation": {
                            "mode": "review-only",
                            "model": "gpt-5.3-codex-spark",
                            "lanes": ["policy-routing-review"],
                        },
                    }
                ),
                encoding="utf-8",
            )

            result = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "scripts" / "import_execution_telemetry.py"),
                    "--file",
                    str(sidecar),
                    "--audit-file",
                    str(audit),
                    "--json",
                ],
                cwd=ROOT,
                check=True,
                capture_output=True,
                text=True,
            )

            payload = json.loads(result.stdout)
            self.assertEqual(payload["imported"], 1)
            imported = [json.loads(line) for line in audit.read_text(encoding="utf-8").splitlines()][1]
            self.assertEqual(imported["workerbee_planned_mode"], "review-only")
            self.assertEqual(imported["workerbee_planned_model"], "gpt-5.3-codex-spark")
            self.assertEqual(imported["workerbee_planned_lanes"], ["policy-routing-review"])

    def test_cli_imports_native_disposition_sidecar(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            temp = Path(tmp)
            audit = temp / "audit.jsonl"
            audit.write_text(
                json.dumps(
                    {
                        "event_type": "dispatch",
                        "dispatch_id": "dispatch-native",
                        "bead_id": "cwo-native",
                        "model": "gpt-5.3-codex-spark",
                        "event_hash": "target-hash",
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            sidecar = temp / "native.json"
            sidecar.write_text(
                json.dumps(
                    {
                        "dispatch_id": "dispatch-native",
                        "session_disposition": "quarantined",
                        "artifact_disposition": "independent-validation-required",
                        "artifact_validation": {
                            "eligible": True,
                            "max_attempts": 1,
                            "attempts_used": 0,
                            "outcome": "not-run",
                            "reason": "budget-only hard overrun",
                        },
                    }
                ),
                encoding="utf-8",
            )

            result = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "scripts" / "import_execution_telemetry.py"),
                    "--file",
                    str(sidecar),
                    "--audit-file",
                    str(audit),
                    "--json",
                ],
                cwd=ROOT,
                check=True,
                capture_output=True,
                text=True,
            )

            self.assertEqual(json.loads(result.stdout)["imported"], 1)
            imported = [json.loads(line) for line in audit.read_text(encoding="utf-8").splitlines()][1]
            self.assertEqual(imported["session_disposition"], "quarantined")
            self.assertEqual(imported["artifact_disposition"], "independent-validation-required")
            self.assertTrue(imported["artifact_validation"]["eligible"])


if __name__ == "__main__":
    unittest.main()
