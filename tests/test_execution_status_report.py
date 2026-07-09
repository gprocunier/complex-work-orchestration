from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from cwo_core.execution_status_report import (  # noqa: E402
    _lane_matches_workerbee_plan,
    build_execution_status_report,
    render_terminal,
)


def sample_audit_events() -> list[dict[str, object]]:
    return [
        {
            "dispatch_id": "main-architect-1",
            "event_type": "dispatch",
            "timestamp": "2026-07-03T12:00:00Z",
            "bead_id": "cwo-1",
            "executor_key": "frontier_architect",
            "provider_key": "openai_internal",
            "provider_family": "openai",
            "executor_external": False,
            "lane": "architect",
            "expert_profile": "architecture",
            "model": "codex-5.6-sol",
            "calls": 1,
            "retry_count": 0,
            "input_tokens": 500,
            "output_tokens": 200,
            "elapsed_seconds": 30,
            "status": "completed",
            "raw_prompt": "LEAK_RAW_PROMPT",
            "chain_of_thought": "LEAK_CHAIN_OF_THOUGHT",
        },
        {
            "dispatch_id": "opus-review-1",
            "event_type": "external_manual_dispatch",
            "timestamp": "2026-07-03T12:05:00Z",
            "bead_id": "cwo-2",
            "executor_key": "claude_opus",
            "provider_key": "anthropic",
            "provider_family": "anthropic",
            "executor_external": True,
            "lane": "second-opinion-review",
            "expert_profile": "contract-jd-operator-calibrated-execution",
            "model": "claude-opus-4-6",
            "retry_count": 1,
            "usage": {"input_tokens": 1000, "output_tokens": 500},
            "duration_seconds": 90,
            "status": "completed",
        },
    ]


def sample_acceptance_decisions() -> list[dict[str, object]]:
    return [
        {
            "dispatch_id": "opus-review-1",
            "bead_id": "cwo-2",
            "executor": "claude_opus",
            "provider_key": "anthropic",
            "provider_family": "anthropic",
            "provider_external": True,
            "provenance_class": "external-contractor",
            "verdict": "partial-accept",
            "score": 86,
            "accepted_findings": ["Preserve unavailable telemetry as ?."],
            "rejected_findings": ["Render raw transcript text."],
            "evidence_quality_score": 72,
            "sabotage_score": 0,
            "malpractice_score": 0,
            "peer_review_required": True,
            "human_adjudication_required": True,
            "recommended_disposition": "partial-accept",
            "recommended_synthesis_use": "salvage-only",
            "followup_beads": ["cwo-3"],
        }
    ]


def sample_return_bundles() -> list[dict[str, object]]:
    return [
        {
            "bundle_type": "contractor-return-bundle",
            "version": 1,
            "dispatch_id": "gemini-review-1",
            "bead_id": "cwo-4",
            "executor": "gemini",
            "provider_key": "google",
            "provider_family": "google",
            "provider_external": True,
            "provenance_class": "external-contractor",
            "job_description_label": "contract-jd-sabotage-review",
            "evidence_quality_score": 42,
            "sabotage_score": 1,
            "malpractice_score": 2,
            "quarantine_recommended": True,
            "required_sections_missing": [],
            "raw_transcript": "LEAK_RAW_TRANSCRIPT",
        }
    ]


class ExecutionStatusReportTests(unittest.TestCase):
    def test_status_prepared_from_dispatch_events_counts_as_started(self) -> None:
        report = build_execution_status_report(
            audit_events=[
                {
                    "dispatch_id": "started-1",
                    "event_type": "dispatch_prepared",
                    "timestamp": "2026-07-03T12:00:00Z",
                    "bead_id": "cwo-started-1",
                    "executor_key": "frontier_architect",
                    "provider_key": "openai_internal",
                    "provider_family": "openai",
                    "executor_external": False,
                    "lane": "architect",
                    "expert_profile": "architecture",
                    "model": "codex-5.6-sol",
                },
                {
                    "dispatch_id": "skip-1",
                    "event_type": "dispatch",
                    "timestamp": "2026-07-03T12:01:00Z",
                    "bead_id": "cwo-started-2",
                    "executor_key": "claude_opus",
                    "status": "deferred",
                    "lane": "second-opinion",
                    "expert_profile": "operator-calibrated",
                    "model": "claude-opus-4-6",
                },
            ]
        )

        self.assertEqual(report["executive_summary"]["started"], 1)
        self.assertEqual(report["executive_summary"]["deferred"], 1)

    def test_workerbee_accountability_tracks_planned_vs_actual_lanes(self) -> None:
        report = build_execution_status_report(
            audit_events=[
                {
                    "dispatch_id": "delegation-plan",
                    "event_type": "dispatch_prepared",
                    "timestamp": "2026-07-03T12:00:00Z",
                    "bead_id": "cwo-account-1",
                    "lane": "policy-routing-review",
                    "executor_key": "frontier_architect",
                    "workerbee_planned_delegation": {
                        "mode": "review-only",
                        "model": "gpt-5.3-codex-spark",
                        "lanes": ["policy-routing-review", "docs-flow-review", "publish-sanitization-review"],
                    },
                },
                {
                    "dispatch_id": "delegation-complete",
                    "event_type": "dispatch",
                    "timestamp": "2026-07-03T12:05:00Z",
                    "bead_id": "cwo-account-1",
                    "lane": "policy-routing-review",
                    "executor_key": "frontier_architect",
                    "status": "completed",
                    "workerbee_planned_delegation": {
                        "mode": "review-only",
                        "model": "gpt-5.3-codex-spark",
                        "lanes": ["policy-routing-review", "docs-flow-review", "publish-sanitization-review"],
                    },
                },
                {
                    "dispatch_id": "delegation-other",
                    "event_type": "dispatch",
                    "timestamp": "2026-07-03T12:10:00Z",
                    "bead_id": "cwo-account-2",
                    "lane": "other-lane",
                    "executor_key": "frontier_architect",
                    "telemetry_status": "started",
                },
            ],
        )

        accountability = report["workerbee_delegation_accountability"]
        planned = accountability["planned"]
        self.assertEqual(planned["mode"], "review-only")
        self.assertEqual(planned["model"], "gpt-5.3-codex-spark")
        self.assertEqual(planned["lanes"], ["policy-routing-review", "docs-flow-review", "publish-sanitization-review"])
        planned_rows = accountability["planned_vs_actual"]
        self.assertTrue(any(row["lane"] == "policy-routing-review" for row in planned_rows))
        for row in planned_rows:
            if row["lane"] == "policy-routing-review":
                self.assertEqual(row["started"], 1)
                self.assertEqual(row["completed"], 1)
            elif row["lane"] != "docs-flow-review" and row["lane"] != "publish-sanitization-review":
                self.fail(f"Unexpected planned lane row: {row['lane']}")

    def test_workerbee_accountability_uses_actual_lane_lists(self) -> None:
        report = build_execution_status_report(
            audit_events=[
                {
                    "dispatch_id": "delegation-list-complete",
                    "event_type": "execution_telemetry_import",
                    "timestamp": "2026-07-03T12:05:00Z",
                    "bead_id": "cwo-account-1",
                    "workerbee_planned_mode": "implementation-capable",
                    "workerbee_planned_model": "gpt-5.3-codex-spark",
                    "workerbee_planned_lanes": ["packet-surface", "delegation-reporting"],
                    "workerbee_actual_mode": "implementation-capable",
                    "workerbee_actual_model": "gpt-5.3-codex-spark",
                    "workerbee_actual_lanes": ["packet-surface", "delegation-reporting"],
                    "workerbee_delegation_status": "completed",
                }
            ],
        )

        rows = {
            row["lane"]: row
            for row in report["workerbee_delegation_accountability"]["planned_vs_actual"]
        }
        self.assertEqual(rows["packet-surface"]["completed"], 1)
        self.assertEqual(rows["packet-surface"]["unavailable"], 0)
        self.assertEqual(rows["delegation-reporting"]["completed"], 1)
        self.assertEqual(rows["delegation-reporting"]["unavailable"], 0)
        self.assertEqual(report["workerbee_delegation_summary"]["unfulfilled_lane_count"], 0)

    def test_workerbee_lane_matching_uses_token_boundaries(self) -> None:
        self.assertTrue(_lane_matches_workerbee_plan("expert-review-policy-routing-review", "policy-routing-review"))
        self.assertTrue(_lane_matches_workerbee_plan("policy-routing-review", "policy-routing-review"))
        self.assertFalse(_lane_matches_workerbee_plan("implementation", "pm"))
        self.assertFalse(_lane_matches_workerbee_plan("approval", "pr"))

    def test_aggregates_complete_telemetry_from_explicit_records(self) -> None:
        report = build_execution_status_report(
            audit_events=sample_audit_events(),
            acceptance_decisions=sample_acceptance_decisions(),
            return_bundles=sample_return_bundles(),
            readiness_plan={
                "workstreams": [
                    {"name": "validation", "owner": "reliability", "status": "deferred"},
                ]
            },
        )

        self.assertEqual(report["result_type"], "cwo-execution-status-report")
        summary = report["executive_summary"]
        self.assertEqual(summary["work_units"], 4)
        self.assertEqual(summary["completed"], 3)
        self.assertEqual(summary["deferred"], 1)
        self.assertEqual(summary["agent_model_calls"], "2")
        self.assertEqual(summary["total_tokens"], "2200")
        self.assertEqual(summary["elapsed_seconds"], "120")
        self.assertEqual(summary["second_opinion_calls"], "1")

        quality = report["quality_malpractice_sabotage_summary"]
        self.assertEqual(quality["totals"]["low_evidence_quality"], 1)
        self.assertEqual(quality["totals"]["sabotage_concerns"], 1)
        self.assertEqual(quality["totals"]["malpractice_concerns"], 1)
        self.assertEqual(quality["totals"]["quarantine_recommended"], 1)
        self.assertEqual(report["evidence_disposition_summary"]["salvage-only"], 1)
        self.assertEqual(report["evidence_disposition_summary"]["accepted_findings"], 1)
        self.assertEqual(report["evidence_disposition_summary"]["rejected_findings"], 1)

    def test_process_holds_are_reported_separately_from_quarantine_and_reject(self) -> None:
        report = build_execution_status_report(
            acceptance_decisions=[
                {
                    "dispatch_id": "held-review-1",
                    "bead_id": "cwo-6",
                    "executor": "glm-5.2",
                    "provider_key": "openshift_ai_vllm",
                    "provider_family": "local",
                    "provider_external": False,
                    "provenance_class": "local-worker",
                    "verdict": "accept",
                    "score": 91,
                    "evidence_quality_score": 80,
                    "sabotage_score": 0,
                    "malpractice_score": 0,
                    "peer_review_required": True,
                    "peer_review_status": "pending",
                    "implementation_blocked": True,
                    "hold_reasons": ["peer-review-pending"],
                    "hold_classification": "peer-review-pending",
                    "human_adjudication_required": True,
                    "recommended_disposition": "run-peer-review",
                    "recommended_synthesis_use": "open-risk",
                }
            ]
        )

        quality = report["quality_malpractice_sabotage_summary"]
        self.assertEqual(quality["totals"]["implementation_blocked"], 1)
        self.assertEqual(quality["totals"]["quarantine_recommended"], 0)
        self.assertIn("process-hold", quality["events"][0]["signals"])
        evidence = report["evidence_disposition_summary"]
        self.assertEqual(evidence["process-hold"], 1)
        self.assertEqual(evidence["reject"], 0)
        self.assertEqual(evidence["quarantine"], 0)

    def test_missing_telemetry_remains_unavailable(self) -> None:
        report = build_execution_status_report(
            audit_events=[
                {
                    "dispatch_id": "missing-telemetry",
                    "event_type": "dispatch",
                    "timestamp": "2026-07-03T12:00:00Z",
                    "bead_id": "cwo-5",
                    "executor_key": "frontier_architect",
                    "status": "completed",
                }
            ],
        )

        summary = report["executive_summary"]
        self.assertEqual(summary["agent_model_calls"], "1")
        self.assertEqual(summary["total_tokens"], "?")
        self.assertEqual(summary["elapsed_seconds"], "?")
        self.assertGreater(summary["missing_telemetry_cells"], 0)
        rendered = render_terminal(report, width=80)
        self.assertIn("Dashboard", rendered)
        self.assertIn("Top gaps:", rendered)
        self.assertIn("?", rendered)

    def test_partial_token_usage_does_not_report_misleading_total(self) -> None:
        report = build_execution_status_report(
            audit_events=[
                {
                    "dispatch_id": "partial-token-usage",
                    "event_type": "dispatch",
                    "timestamp": "2026-07-03T12:00:00Z",
                    "bead_id": "cwo-5",
                    "executor_key": "frontier_architect",
                    "status": "completed",
                    "calls": 1,
                    "input_tokens": 500,
                }
            ],
        )

        summary = report["executive_summary"]
        self.assertEqual(summary["agent_model_calls"], "1")
        self.assertEqual(summary["total_tokens"], "?")
        gaps = report["telemetry_gaps"]
        self.assertEqual(gaps["fields"]["total_tokens"]["missing_records"], 1)

    def test_expanded_renderer_fans_out_long_values_without_ellipsis(self) -> None:
        long_profile = "contract-jd-operator-calibrated-execution"
        long_agent = "chatgpt_pro_browser_master_reviewer"
        report = build_execution_status_report(
            audit_events=[
                {
                    "dispatch_id": "browser-review-1",
                    "event_type": "dispatch",
                    "bead_id": "cwo-6",
                    "executor_key": long_agent,
                    "lane": "browser_automation",
                    "expert_profile": long_profile,
                    "calls": 1,
                    "status": "completed",
                },
                {
                    "dispatch_id": "browser-review-2",
                    "event_type": "dispatch",
                    "bead_id": "cwo-7",
                    "executor_key": long_agent,
                    "lane": "chatgpt-browser-master-review",
                    "expert_profile": long_profile,
                    "calls": 1,
                    "status": "failed",
                },
            ],
        )

        detail_rows = report["expert_profile_utilization_details"]
        self.assertEqual(len(detail_rows), 2)
        self.assertEqual({row["role"] for row in detail_rows}, {"browser_automation", "chatgpt-browser-master-review"})

        rendered = render_terminal(report, width=120, layout="expanded")
        self.assertIn("browser_automation", rendered)
        self.assertIn("chatgpt-browser-master-review", rendered)
        self.assertIn(long_agent, rendered)
        self.assertNotIn("...", rendered)

    def test_usage_import_supplements_matching_dispatch_without_double_counting(self) -> None:
        report = build_execution_status_report(
            audit_events=[
                {
                    "dispatch_id": "manual-review-1",
                    "event_type": "external_manual_dispatch",
                    "bead_id": "cwo-usage",
                    "executor_key": "claude_opus",
                    "provider_key": "anthropic",
                    "executor_external": True,
                    "status": "completed",
                },
                {
                    "dispatch_id": "manual-review-1",
                    "event_type": "execution_telemetry_import",
                    "telemetry_kind": "usage_import",
                    "bead_id": "cwo-usage",
                    "agent_model_calls": 1,
                    "retry_count": 0,
                    "input_tokens": 120,
                    "output_tokens": 30,
                    "elapsed_seconds": 12,
                    "telemetry_source": "manual-sidecar",
                },
            ],
        )

        summary = report["executive_summary"]
        self.assertEqual(summary["work_units"], 1)
        self.assertEqual(summary["dispatches"], 1)
        self.assertEqual(summary["agent_model_calls"], "1")
        self.assertEqual(summary["total_tokens"], "150")
        self.assertEqual(summary["elapsed_seconds"], "12")
        self.assertEqual(report["source_counts"]["audit_events"], 2)
        self.assertEqual(report["source_counts"]["telemetry_imports"], 1)
        self.assertEqual(report["telemetry_gaps"]["records_considered"], 1)
        self.assertEqual(report["telemetry_gaps"]["fields"]["total_tokens"]["missing_records"], 0)

    def test_workerbee_delegation_summary_reports_planned_actual_and_gaps(self) -> None:
        report = build_execution_status_report(
            audit_events=[
                {
                    "dispatch_id": "architect-plan",
                    "event_type": "dispatch",
                    "bead_id": "cwo-workerbee-plan",
                    "lane": "architect",
                    "executor_key": "frontier_architect",
                    "status": "completed",
                    "workerbee_planned_mode": "implementation-capable",
                    "workerbee_planned_model": "gpt-5.3-codex-spark",
                    "workerbee_planned_lanes": ["part-1-packet-surface", "part-2-delegation-reporting"],
                },
                {
                    "dispatch_id": "spark-part-2",
                    "event_type": "dispatch",
                    "bead_id": "cwo-workerbee-actual",
                    "lane": "implementation",
                    "executor_key": "codex_workerbee",
                    "model": "gpt-5.3-codex-spark",
                    "status": "completed",
                    "workerbee_actual_mode": "implementation-capable",
                    "workerbee_actual_model": "gpt-5.3-codex-spark",
                    "workerbee_actual_lanes": ["part-2-delegation-reporting"],
                    "workerbee_delegation_status": "completed",
                    "workerbee_delegation_source": "subagent-log",
                },
            ],
        )

        summary = report["workerbee_delegation_summary"]
        self.assertEqual(summary["planned_records"], 1)
        self.assertEqual(summary["actual_records"], 1)
        self.assertEqual(summary["unfulfilled_lane_count"], 1)
        self.assertIn("part-1-packet-surface", summary["unfulfilled_lanes"])
        self.assertIn("completed:1", summary["status_summary"])
        self.assertIn("planned-no-actual-telemetry:1", summary["status_summary"])
        details = report["workerbee_delegation_details"]
        self.assertTrue(all("_planned" not in row for row in details))

        rendered = render_terminal(report, width=100)
        self.assertIn("Workerbees:", rendered)
        self.assertIn("unfulfilled 1", rendered)

    def test_telemetry_gaps_report_missing_fields_by_source_kind(self) -> None:
        report = build_execution_status_report(
            audit_events=[
                {
                    "dispatch_id": "missing-token-time",
                    "event_type": "dispatch",
                    "bead_id": "cwo-8",
                    "executor_key": "frontier_architect",
                    "status": "completed",
                    "calls": 1,
                }
            ],
        )

        gaps = report["telemetry_gaps"]
        self.assertEqual(gaps["records_considered"], 1)
        self.assertTrue(gaps["source_artifacts_supplied"])
        self.assertEqual(gaps["fields"]["agent_model_calls"]["available_records"], 1)
        self.assertEqual(gaps["fields"]["total_tokens"]["missing_records"], 1)
        self.assertEqual(gaps["fields"]["total_tokens"]["not_applicable_records"], 0)
        self.assertEqual(gaps["fields"]["total_tokens"]["missing_source_kinds"], ["audit_event"])
        self.assertEqual(gaps["fields"]["total_tokens"]["missing_reasons"], {"not-recorded": 1})

    def test_readiness_telemetry_is_not_applicable_not_missing(self) -> None:
        report = build_execution_status_report(
            readiness_plan={
                "workstreams": [
                    {"name": "validation", "owner": "reliability", "status": "completed"},
                ]
            },
        )

        gaps = report["telemetry_gaps"]
        self.assertEqual(gaps["records_considered"], 1)
        for field in ["agent_model_calls", "total_tokens", "elapsed_seconds"]:
            self.assertEqual(gaps["fields"][field]["missing_records"], 0)
            self.assertEqual(gaps["fields"][field]["not_applicable_records"], 1)
        self.assertEqual(report["executive_summary"]["missing_telemetry_cells"], 0)
        self.assertEqual(report["executive_summary"]["total_tokens"], "n/a")

    def test_mixed_missing_and_not_applicable_telemetry_are_counted_separately(self) -> None:
        report = build_execution_status_report(
            audit_events=[
                {
                    "dispatch_id": "missing-token-time",
                    "event_type": "dispatch",
                    "bead_id": "cwo-8",
                    "executor_key": "frontier_architect",
                    "status": "completed",
                    "calls": 1,
                }
            ],
            readiness_plan={
                "workstreams": [
                    {"name": "validation", "owner": "reliability", "status": "completed"},
                ]
            },
        )

        gaps = report["telemetry_gaps"]
        self.assertEqual(gaps["records_considered"], 2)
        self.assertEqual(gaps["fields"]["total_tokens"]["missing_records"], 1)
        self.assertEqual(gaps["fields"]["total_tokens"]["not_applicable_records"], 1)
        rendered = render_terminal(report, width=100, layout="expanded")
        self.assertIn("?", rendered)
        self.assertIn("n/a", rendered)

    def test_terminal_dashboard_degrades_for_narrow_width(self) -> None:
        report = build_execution_status_report(
            audit_events=sample_audit_events(),
            acceptance_decisions=sample_acceptance_decisions(),
        )

        rendered = render_terminal(report, width=60)
        self.assertIn("CWO Execution Status Report", rendered)
        self.assertIn("Dashboard", rendered)
        self.assertIn("Top gaps:", rendered)
        self.assertTrue(all(len(line) <= 60 for line in rendered.splitlines()))

    def test_expanded_terminal_keeps_full_detail_sections(self) -> None:
        report = build_execution_status_report(
            audit_events=sample_audit_events(),
            acceptance_decisions=sample_acceptance_decisions(),
        )

        rendered = render_terminal(report, width=80, layout="expanded")
        self.assertIn("Executive Summary", rendered)
        self.assertIn("Second-Opinion Review Lane Productivity", rendered)

    def test_outputs_do_not_expose_raw_prompts_transcripts_or_chain_of_thought(self) -> None:
        report = build_execution_status_report(
            audit_events=sample_audit_events(),
            acceptance_decisions=sample_acceptance_decisions(),
            return_bundles=sample_return_bundles(),
        )

        payload = json.dumps(report, sort_keys=True)
        rendered = render_terminal(report, width=100, layout="expanded")
        for forbidden in ["LEAK_RAW_PROMPT", "LEAK_CHAIN_OF_THOUGHT", "LEAK_RAW_TRANSCRIPT"]:
            self.assertNotIn(forbidden, payload)
            self.assertNotIn(forbidden, rendered)

    def test_cli_json_output_contract(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            temp = Path(tempdir)
            audit_log = temp / "audit.jsonl"
            audit_log.write_text("\n".join(json.dumps(event) for event in sample_audit_events()) + "\n", encoding="utf-8")
            decision = temp / "decision.json"
            decision.write_text(json.dumps(sample_acceptance_decisions()[0]), encoding="utf-8")

            result = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "scripts" / "render_execution_status_report.py"),
                    "--audit-log",
                    str(audit_log),
                    "--acceptance-decision",
                    str(decision),
                    "--format",
                    "json",
                ],
                cwd=ROOT,
                check=True,
                capture_output=True,
                text=True,
            )

        payload = json.loads(result.stdout)
        self.assertEqual(payload["result_type"], "cwo-execution-status-report")
        for key in [
            "executive_summary",
            "expert_profile_utilization",
            "expert_profile_utilization_details",
            "agent_model_utilization",
            "agent_model_utilization_details",
            "main_thread_architect_productivity",
            "workerbee_delegation_accountability",
            "workerbee_delegation_summary",
            "workerbee_delegation_details",
            "second_opinion_review_lane_productivity",
            "second_opinion_review_lane_productivity_details",
            "telemetry_gaps",
            "quality_malpractice_sabotage_summary",
            "evidence_disposition_summary",
        ]:
            self.assertIn(key, payload)

    def test_schema_required_keys_are_emitted(self) -> None:
        schema = json.loads((ROOT / "schemas" / "execution-status-report.schema.json").read_text(encoding="utf-8"))
        report = build_execution_status_report(audit_events=sample_audit_events())

        self.assertEqual(schema["properties"]["result_type"]["const"], "cwo-execution-status-report")
        for key in schema["required"]:
            self.assertIn(key, report)
        for field, summary in report["telemetry_gaps"]["fields"].items():
            with self.subTest(field=field):
                self.assertIn("available_records", summary)
                self.assertIn("missing_records", summary)
                self.assertIn("not_applicable_records", summary)


if __name__ == "__main__":
    unittest.main()
