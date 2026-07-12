from __future__ import annotations

import sys
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from cwo_core.execution_status_report import build_execution_status_report, render_terminal
from cwo_core.telemetry import sanitize_audit_event


class EnhancementTelemetryTest(unittest.TestCase):
    def test_sanitizer_preserves_progress_and_checked_command_fields(self):
        event = sanitize_audit_event({
            "event_type": "execution_telemetry_import", "telemetry_kind": "native_progress",
            "native_progress_outcome": "pm-realignment", "native_progress_pm_action": "material-split",
            "planned_tool_calls_p90": 20, "observed_tool_calls": 28, "observed_tokens": 1000,
            "observed_context_reads": 12, "observed_mutations": 2, "retained_productive_artifacts": 1,
            "progress_pure_waste": False, "native_progress_reasons": ["new-work"],
            "tool_call_calibration_error": 8, "runtime_calibration_error_seconds": -160,
        })
        self.assertEqual(event["native_progress_outcome"], "pm-realignment")
        self.assertEqual(event["observed_tokens"], 1000)
        self.assertEqual(event["native_progress_reasons"], ["new-work"])
        self.assertEqual(event["runtime_calibration_error_seconds"], -160)

        command = sanitize_audit_event({
            "event_type": "execution_telemetry_import", "telemetry_kind": "checked_command",
            "checked_command_id": "cmd-1", "checked_command_preflight_status": "failed",
            "checked_command_failure_class": "command-construction-failed",
            "checked_command_execution_started": False, "checked_command_quarantine_required": False,
            "checked_command_quoting_error_prevented": True, "checked_command_avoided_retry_cycles": 1,
        })
        self.assertEqual(command["checked_command_id"], "cmd-1")
        self.assertTrue(command["checked_command_quoting_error_prevented"])

    def test_report_and_dashboard_show_calibration_and_command_value(self):
        report = build_execution_status_report(audit_events=[
            {
                "event_type": "execution_telemetry_import", "telemetry_kind": "native_progress",
                "native_progress_outcome": "pm-realignment", "native_progress_pm_action": "material-split",
                "planned_tool_calls_p90": 20, "observed_tool_calls": 28,
                "planned_runtime_seconds_p90": 240, "observed_runtime_seconds": 80,
                "observed_tokens": 1000, "observed_context_reads": 12, "observed_mutations": 2,
                "observed_tests_run": 1, "observed_artifacts_completed": 1,
                "retained_productive_artifacts": 1, "progress_pure_waste": False,
                "tool_call_calibration_error": 8, "runtime_calibration_error_seconds": -160,
            },
            {
                "event_type": "execution_telemetry_import", "telemetry_kind": "checked_command",
                "checked_command_id": "cmd-1", "checked_command_preflight_status": "failed",
                "checked_command_failure_class": "command-construction-failed",
                "checked_command_execution_started": False, "checked_command_quarantine_required": False,
                "checked_command_hash_match": True, "checked_command_quoting_error_prevented": True,
                "checked_command_avoided_retry_cycles": 1, "checked_command_mutation_started": False,
            },
        ])
        self.assertEqual(report["native_progress_summary"]["pm_actions"]["material-split"], 1)
        self.assertEqual(report["native_progress_summary"]["retained_productive_artifacts"], 1)
        self.assertEqual(report["checked_command_summary"]["construction_failures"], 1)
        self.assertEqual(report["checked_command_summary"]["avoided_retry_cycles"], 1)
        dashboard = render_terminal(report, width=120)
        self.assertIn("Autonomy:", dashboard)
        self.assertIn("Commands:", dashboard)


if __name__ == "__main__":
    unittest.main()
