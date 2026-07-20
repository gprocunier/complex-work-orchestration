from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from cwo_core.native_pool_contracts import write_private_artifact  # noqa: E402
from cwo_core.native_pool_reporting import (  # noqa: E402
    build_pool_status_report,
    native_pool_audit_summary,
    record_pool_audit_event,
)
from tests.test_native_pool_contracts import (  # noqa: E402
    accepting_receipt,
    closed_state,
    pool_contract,
    released_lease,
)


class NativePoolReportingTests(unittest.TestCase):
    @staticmethod
    def artifacts() -> tuple[dict, dict, dict]:
        contract, _ = pool_contract(cap=2)
        leases = [released_lease(contract, index) for index in range(2)]
        state = closed_state(contract, leases)
        receipt = accepting_receipt(contract, state, leases)
        return contract, state, receipt

    def test_status_reports_absolute_capacity_usage_timing_leases_and_dispositions(self) -> None:
        contract, state, receipt = self.artifacts()
        report = build_pool_status_report(contract, state, receipt)
        self.assertEqual(report["capacity"]["configured_workers"], 2)
        self.assertEqual(report["capacity"]["terminal_workers"], 2)
        self.assertEqual(report["aggregate_usage"]["tool_calls"], {"used": 0, "limit": 56, "remaining": 56})
        self.assertEqual(report["timing"]["poll_interval_ms"], 1000)
        self.assertEqual([item["lifecycle_state"] for item in report["leases"]], ["released", "released"])
        self.assertEqual([item["session_disposition"] for item in report["children"]], ["accepted", "accepted"])
        self.assertTrue(report["accepting"])

    def test_audit_projection_excludes_paths_and_preserves_pool_telemetry(self) -> None:
        contract, state, receipt = self.artifacts()
        report = build_pool_status_report(contract, state, receipt)
        summary = native_pool_audit_summary(report)
        self.assertNotIn("children", summary)
        self.assertNotIn("leases", summary)
        self.assertEqual(summary["aggregate_tool_calls"], 0)
        self.assertEqual(summary["lease_states"], ["released", "released"])
        with tempfile.TemporaryDirectory() as temporary:
            audit_file = Path(temporary) / "audit.jsonl"
            event = record_pool_audit_event(
                report,
                event_type="native_pool_terminal",
                bead_id="complex-work-orchestration-18w.4",
                audit_file=audit_file,
            )
            self.assertEqual(event["native_pool_summary"], summary)
            self.assertNotIn("state_file", json.dumps(event))

    def test_cli_status_and_interrupt_emit_private_bound_artifacts(self) -> None:
        contract, state, receipt = self.artifacts()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            contract_path = root / "contract.json"
            state_path = root / "state.json"
            receipt_path = root / "receipt.json"
            audit_path = root / "audit.jsonl"
            for path, value in (
                (contract_path, contract),
                (state_path, state),
                (receipt_path, receipt),
            ):
                write_private_artifact(path, value)
            status = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "scripts" / "supervise_native_pool.py"),
                    "status",
                    "--contract",
                    str(contract_path),
                    "--state",
                    str(state_path),
                    "--receipt",
                    str(receipt_path),
                    "--audit-file",
                    str(audit_path),
                    "--bead-id",
                    "complex-work-orchestration-18w.4",
                ],
                cwd=ROOT,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(status.returncode, 0, status.stdout + status.stderr)
            report = json.loads(status.stdout)
            self.assertEqual(report["pool_disposition"], "accepted")
            self.assertTrue(audit_path.is_file())

            interrupt_path = root / "interrupt.json"
            interrupt = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "scripts" / "supervise_native_pool.py"),
                    "interrupt",
                    "--contract",
                    str(contract_path),
                    "--state",
                    str(state_path),
                    "--output",
                    str(interrupt_path),
                    "--reason",
                    "late operator request",
                ],
                cwd=ROOT,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(interrupt.returncode, 2)
            self.assertFalse(interrupt_path.exists())

            state_link = root / "state-link.json"
            state_link.symlink_to(state_path)
            symlink_status = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "scripts" / "supervise_native_pool.py"),
                    "status",
                    "--contract",
                    str(contract_path),
                    "--state",
                    str(state_link),
                ],
                cwd=ROOT,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(symlink_status.returncode, 2)
            self.assertIn("symlink", symlink_status.stdout)


if __name__ == "__main__":
    unittest.main()
