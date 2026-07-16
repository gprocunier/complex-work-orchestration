from __future__ import annotations

import sys
from pathlib import Path
import unittest
import json

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from cwo_core.execution_status_report import build_execution_status_report, render_terminal
from cwo_core.epic_convergence import CALL_CATEGORIES, GRAPH_COUNTER_FIELDS
from cwo_core.telemetry import sanitize_audit_event, telemetry_fields


SCHEMA_PATH = ROOT / "schemas" / "execution-telemetry-import.schema.json"


class EnhancementTelemetryTest(unittest.TestCase):
    def test_schema_declares_nullable_canonical_call_category_and_graph_counters_contract(self):
        with SCHEMA_PATH.open() as handle:
            schema = json.load(handle)
        record_props = schema["$defs"]["record"]["properties"]
        call_category = record_props["call_category"]

        expected_call_category = set(CALL_CATEGORIES) | {None}
        self.assertEqual(set(call_category["enum"]), expected_call_category)
        self.assertEqual(call_category["type"], ["string", "null"])

        graph_counters = record_props["graph_counters"]
        self.assertFalse(graph_counters["additionalProperties"])
        self.assertEqual(set(graph_counters["properties"].keys()), set(GRAPH_COUNTER_FIELDS))

    def test_sanitize_audit_event_and_telemetry_fields_preserve_identity_usage_and_graph_counters(self):
        event = {
            "event_type": "execution_telemetry_import",
            "epic_id": "epic-1",
            "work_unit_id": "work-1",
            "packet_id": "packet-1",
            "session_id": "session-1",
            "phase": "planning",
            "event": "native-progress",
            "call_category": "productive",
            "usage": {
                "input": 1000,
                "tool_calls": 3,
                "runtime_seconds": 12.5,
                "context_compactions": 1,
                "full_suite_runs": 0,
                "total_tokens": 400,
            },
            "graph_counters": {
                "beads_total": 3,
                "beads_open": 1,
                "beads_closed": 2,
                "graph_depth": 2,
                "work_units_total": 4,
                "work_units_open": 2,
                "work_units_closed": 2,
                "routine_repair_children": 0,
                "worker_sessions": None,
            },
        }

        sanitized = sanitize_audit_event(event)
        self.assertEqual(sanitized["epic_id"], "epic-1")
        self.assertEqual(sanitized["phase"], "planning")
        self.assertEqual(sanitized["call_category"], "productive")
        self.assertEqual(sanitized["usage"]["runtime_seconds"], 12.5)
        self.assertEqual(sanitized["graph_counters"]["worker_sessions"], None)
        self.assertEqual(sanitized["graph_counters"]["graph_depth"], 2)

        fields = telemetry_fields(**event)
        self.assertEqual(fields["epic_id"], "epic-1")
        self.assertEqual(fields["usage"], event["usage"])
        self.assertEqual(fields["graph_counters"]["worker_sessions"], None)
        self.assertEqual(fields["call_category"], "productive")

    def test_sanitize_audit_event_omits_invalid_values_and_unknown_graph_counters(self):
        test_cases = [
            {"graph_counters": {"beads_total": True}, "label": "bool"},
            {"graph_counters": {"beads_total": -1}, "label": "negative"},
            {"graph_counters": {"beads_total": 1.5}, "label": "noninteger"},
            {"graph_counters": {"unexpected": 1}, "label": "unknown-key"},
        ]
        for case in test_cases:
            with self.subTest(case["label"]):
                event = {
                    "event_type": "execution_telemetry_import",
                    "call_category": "not-a-category",
                    "beads_total": 1,
                    **case,
                }
                sanitized = sanitize_audit_event(event)
                self.assertNotIn("call_category", sanitized)
                self.assertNotIn("graph_counters", sanitized)

    def test_legacy_event_still_sanitizes_without_adding_fallbacks(self):
        legacy_event = {
            "event_type": "execution_telemetry_import",
            "telemetry_source": "legacy-control-plane",
            "telemetry_missing_reason": "pre-convergence",
            "call_category": "architect",
            "agent_model_calls": 2,
            "observed_tool_calls": 4,
            "graph_counters": {"beads_total": 1, "unexpected_metric": 9},
            "usage": {"tool_calls": 1, "context_compactions": 0, "input_tokens": 64},
            "epic_id": "legacy-epic",
        }

        sanitized = sanitize_audit_event(legacy_event)
        expected = {
            "telemetry_source": "legacy-control-plane",
            "telemetry_missing_reason": "pre-convergence",
            "agent_model_calls": 2,
            "epic_id": "legacy-epic",
            "call_category": "architect",
            "event_type": "execution_telemetry_import",
            "observed_tool_calls": 4,
            "usage": {"tool_calls": 1, "context_compactions": 0, "input_tokens": 64},
        }
        self.assertEqual(sanitized, expected)

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

    def test_sanitizer_preserves_only_strict_path_free_native_pool_summary(self):
        summary = {
            "version": 1,
            "pool_id": "pool-1",
            "pool_epoch": "epoch-1",
            "contract_sha256": "a" * 64,
            "state_sha256": "b" * 64,
            "receipt_sha256": None,
            "status": "running",
            "max_active_workers": 2,
            "configured_workers": 2,
            "admitted_workers": 2,
            "executing_workers": 2,
            "terminal_workers": 0,
            "aggregate_tool_calls": 3,
            "aggregate_runtime_seconds": 9,
            "aggregate_compactions": 0,
            "aggregate_full_suite_runs": 0,
            "aggregate_mutations": 1,
            "pool_wall_seconds": 5.5,
            "worker_seconds": 9,
            "poll_overhead_seconds": 0.2,
            "lease_states": ["active", "active"],
            "session_dispositions": [],
            "artifact_dispositions": [],
            "pool_disposition": None,
            "accepting": None,
        }
        event = sanitize_audit_event({"event_type": "native_pool_status", "native_pool_summary": summary})
        self.assertEqual(event["native_pool_summary"], summary)
        invalid = dict(summary)
        invalid["worktree"] = "/private/path"
        self.assertNotIn(
            "native_pool_summary",
            sanitize_audit_event({"event_type": "native_pool_status", "native_pool_summary": invalid}),
        )

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
