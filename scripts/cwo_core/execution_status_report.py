from __future__ import annotations

import json
import math
import re
import shutil
import textwrap
from pathlib import Path
from typing import Any

from .audit import iter_audit_events
from .paths import AUDIT_LOG
from .execution_enhancement_metrics import checked_command_details, checked_command_summary, native_progress_details, native_progress_summary
from .policy import native_authorized_worker_models

UNAVAILABLE = "?"
NATIVE_DISPOSITION_MODELS = frozenset(native_authorized_worker_models())
NOT_APPLICABLE = "n/a"
REPORT_TYPE = "cwo-execution-status-report"
REPORT_VERSION = 6

STATUS_KEYS = (
    "completed",
    "failed",
    "skipped",
    "blocked",
    "deferred",
    "started",
    "unavailable",
)
WORKERBEE_ACCOUNTABILITY_STATUS_KEYS = ("started", "completed", "skipped", "deferred", "unavailable")
METRIC_KEYS = (
    "agent_model_calls",
    "retries",
    "input_tokens",
    "output_tokens",
    "total_tokens",
    "active_seconds",
    "elapsed_seconds",
    "accepted_findings",
    "rejected_findings",
    "followup_beads",
)
TELEMETRY_GAP_KEYS = (
    "agent_model_calls",
    "retries",
    "input_tokens",
    "output_tokens",
    "total_tokens",
    "active_seconds",
    "elapsed_seconds",
)
SYNTHESIS_DISPOSITIONS = (
    "primary",
    "salvage-only",
    "open-risk",
    "partial-only",
    "process-hold",
    "reject",
    "quarantine",
    "unknown",
    "unavailable",
)
DISPATCH_EVENT_TYPES = {
    "chatgpt_browser_dispatch",
    "external_manual_dispatch",
    "local_worker_dispatch",
    "manual_dispatch",
    "dispatch",
    "dispatch_rendered",
    "work_dispatched",
}
USAGE_IMPORT_EVENT_TYPES = {
    "execution_telemetry_import",
    "telemetry_import",
    "usage_import",
}
USAGE_IMPORT_MERGE_KEYS = (
    "agent_model_calls",
    "retry_count",
    "retries",
    "input_tokens",
    "output_tokens",
    "total_tokens",
    "active_seconds",
    "elapsed_seconds",
    "model",
    "model_label",
    "provider_family",
    "provider_key",
    "provider",
    "provider_retention_class",
    "job_description_label",
    "expert_profile",
    "expert_profile_path",
    "telemetry_missing_reason",
    "telemetry_missing_reasons",
    "telemetry_source",
    "telemetry_target_event_hash",
    "workerbee_planned_mode",
    "workerbee_planned_model",
    "workerbee_planned_lanes",
    "workerbee_actual_mode",
    "workerbee_actual_model",
    "workerbee_actual_lanes",
    "workerbee_delegation_status",
    "workerbee_delegation_source",
    "workerbee_delegation_gap_reasons",
)


def load_json_document(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path}: JSON document must be an object")
    return value


def load_json_documents(paths: list[Path]) -> list[dict[str, Any]]:
    return [load_json_document(path) for path in paths]


def load_audit_events(paths: list[Path] | None = None) -> list[dict[str, Any]]:
    audit_paths = paths if paths is not None else ([AUDIT_LOG] if AUDIT_LOG.exists() else [])
    events: list[dict[str, Any]] = []
    for path in audit_paths:
        events.extend(iter_audit_events(path))
    return events


def _merge_usage_imports(events: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], int]:
    usage_imports = [event for event in events if _is_usage_import_event(event)]
    if not usage_imports:
        return list(events), 0

    merged = [dict(event) for event in events if not _is_usage_import_event(event)]
    dispatch_index: dict[str, int] = {}
    bead_index: dict[str, list[int]] = {}
    for index, event in enumerate(merged):
        if not _is_usage_import_target(event):
            continue
        dispatch_id = _clean(event.get("dispatch_id"))
        bead_id = _clean(event.get("bead_id"))
        if dispatch_id:
            dispatch_index[dispatch_id] = index
        if bead_id:
            bead_index.setdefault(bead_id, []).append(index)

    for usage_import in usage_imports:
        target_index = None
        dispatch_id = _clean(usage_import.get("dispatch_id"))
        bead_id = _clean(usage_import.get("bead_id"))
        if dispatch_id and dispatch_id in dispatch_index:
            target_index = dispatch_index[dispatch_id]
        elif bead_id and len(bead_index.get(bead_id, [])) == 1:
            target_index = bead_index[bead_id][0]

        if target_index is None:
            merged.append(dict(usage_import))
            continue

        target = dict(merged[target_index])
        for key in USAGE_IMPORT_MERGE_KEYS:
            if _import_value_present(usage_import.get(key)):
                target[key] = usage_import[key]
        merged[target_index] = target

    return merged, len(usage_imports)


def _is_usage_import_event(record: dict[str, Any]) -> bool:
    event_type = str(record.get("event_type") or "").strip().lower()
    telemetry_kind = str(record.get("telemetry_kind") or "").strip().lower()
    return event_type in USAGE_IMPORT_EVENT_TYPES or telemetry_kind == "usage_import"


def _is_usage_import_target(record: dict[str, Any]) -> bool:
    if _is_usage_import_event(record):
        return False
    telemetry_kind = _telemetry_kind(record, "audit_event")
    return telemetry_kind in {"browser_dispatch", "dispatch", "local_dispatch", "manual_dispatch"}


def _import_value_present(value: Any) -> bool:
    return value not in [None, "", []]


def build_execution_status_report(
    *,
    audit_events: list[dict[str, Any]] | None = None,
    acceptance_decisions: list[dict[str, Any]] | None = None,
    return_bundles: list[dict[str, Any]] | None = None,
    readiness_plan: dict[str, Any] | None = None,
    source_files: dict[str, list[str] | str | None] | None = None,
) -> dict[str, Any]:
    raw_events = audit_events or []
    events, telemetry_imports = _merge_usage_imports(raw_events)
    decisions = acceptance_decisions or []
    bundles = return_bundles or []
    readiness_records = _readiness_records(readiness_plan or {})
    records = (
        [_record_view(item, "audit_event") for item in events]
        + [_record_view(item, "acceptance_decision") for item in decisions]
        + [_record_view(item, "contractor_return_bundle") for item in bundles]
        + readiness_records
    )

    source_counts = {
        "audit_events": len(raw_events),
        "telemetry_imports": telemetry_imports,
        "acceptance_decisions": len(decisions),
        "return_bundles": len(bundles),
        "readiness_records": len(readiness_records),
    }
    report: dict[str, Any] = {
        "result_type": REPORT_TYPE,
        "version": REPORT_VERSION,
        "authority": "projection",
        "canonical_source": "explicit-beads-audit-and-evaluator-artifacts",
        "source_counts": source_counts,
        "source_files": source_files or {},
        "warnings": _report_warnings(source_counts),
        "executive_summary": _executive_summary(records),
        "workerbee_delegation_accountability": _workerbee_accountability(records),
        "expert_profile_utilization": _expert_profile_rows(records),
        "expert_profile_utilization_details": _expert_profile_detail_rows(records),
        "agent_model_utilization": _agent_model_rows(records),
        "agent_model_utilization_details": _agent_model_detail_rows(records),
        "main_thread_architect_productivity": _main_thread_summary(records),
        "workerbee_delegation_summary": _workerbee_delegation_summary(records),
        "workerbee_delegation_details": _workerbee_delegation_detail_rows(records),
        "native_disposition_summary": _native_disposition_summary(records),
        "native_disposition_details": _native_disposition_detail_rows(records),
        "native_supervision_summary": _native_supervision_summary(records),
        "native_supervision_details": _native_supervision_detail_rows(records),
        "native_progress_summary": native_progress_summary(records),
        "native_progress_details": native_progress_details(records),
        "checked_command_summary": checked_command_summary(records),
        "checked_command_details": checked_command_details(records),
        "sol_breakfix_summary": _sol_breakfix_summary(records),
        "second_opinion_review_lane_productivity": _second_opinion_rows(records),
        "second_opinion_review_lane_productivity_details": _second_opinion_detail_rows(records),
        "telemetry_gaps": _telemetry_gaps(records, source_counts),
        "quality_malpractice_sabotage_summary": _quality_summary(records),
        "evidence_disposition_summary": _evidence_disposition_summary(records),
    }
    report["executive_summary"]["missing_telemetry_cells"] = _telemetry_missing_total(report["telemetry_gaps"])
    return report


def render_terminal(report: dict[str, Any], *, width: int | None = None, layout: str = "dashboard") -> str:
    term_width = width or shutil.get_terminal_size((100, 24)).columns
    term_width = max(48, min(term_width, 160))
    if layout == "dashboard":
        lines: list[str] = []
        lines.extend(_header("CWO Execution Status Report", "dashboard projection", term_width))
        lines.extend(_dashboard_lines(report, term_width))
        return "\n".join(lines) + "\n"
    expanded = layout != "summary"
    lines: list[str] = []
    lines.extend(_header("CWO Execution Status Report", "explicit artifact projection", term_width))
    lines.extend(_executive_lines(report, term_width))
    if expanded:
        lines.extend(
            _detail_rows(
                "Expert Profile Utilization",
                [
                    ("Profile", "profile"),
                    ("Role", "role"),
                    ("Agent/Model", "agent_model"),
                    ("Participation", "participation"),
                    ("Work", "work_units"),
                    ("Done", "completed"),
                    ("Fail", "failed"),
                    ("Calls", "agent_model_calls"),
                    ("Tokens", "total_tokens"),
                    ("Time", "elapsed_seconds"),
                ],
                report.get("expert_profile_utilization_details", []),
                term_width,
            )
        )
        lines.extend(
            _detail_rows(
                "Agent / Model Utilization",
                [
                    ("Agent/Model", "agent_model"),
                    ("Provider", "provider"),
                    ("Provider family", "provider_family"),
                    ("Provenance", "provenance_class"),
                    ("Lane", "lane"),
                    ("Dispatches", "dispatches"),
                    ("Calls", "agent_model_calls"),
                    ("Retries", "retries"),
                    ("Tokens", "total_tokens"),
                    ("Use", "recommended_synthesis_use"),
                ],
                report.get("agent_model_utilization_details", []),
                term_width,
            )
        )
    else:
        lines.extend(
            _table(
                "Expert Profile Utilization",
                ["Profile", "Role", "Work", "Done", "Fail", "Calls", "Tokens", "Time", "Agents/Models"],
                [
                    [
                        row.get("profile"),
                        row.get("role"),
                        row.get("work_units"),
                        row.get("completed"),
                        row.get("failed"),
                        row.get("agent_model_calls"),
                        row.get("total_tokens"),
                        row.get("elapsed_seconds"),
                        row.get("agents_models"),
                    ]
                    for row in report.get("expert_profile_utilization", [])
                ],
                term_width,
            )
        )
        lines.extend(
            _table(
                "Agent / Model Utilization",
                ["Agent/Model", "Provider", "Prov.", "Lane", "Dispatches", "Calls", "Retries", "Tokens", "Use"],
                [
                    [
                        row.get("agent_model"),
                        row.get("provider"),
                        row.get("provenance_class"),
                        row.get("lane"),
                        row.get("dispatches"),
                        row.get("agent_model_calls"),
                        row.get("retries"),
                        row.get("total_tokens"),
                        row.get("recommended_synthesis_use"),
                    ]
                    for row in report.get("agent_model_utilization", [])
                ],
                term_width,
            )
        )
    lines.extend(_key_value_box("Main Thread / Architect Productivity", report.get("main_thread_architect_productivity", {}), term_width))
    lines.extend(_key_value_box("Workerbee Delegation Summary", report.get("workerbee_delegation_summary", {}), term_width))
    lines.extend(_key_value_box("Native Session / Artifact Disposition", report.get("native_disposition_summary", {}), term_width))
    lines.extend(
        _key_value_box(
            "Native Worker Live Supervision",
            report.get("native_supervision_summary", {}),
            term_width,
            label_overrides={
                "first_attempt_completion_rate_percent": "First attempt completion %",
            },
        )
    )
    lines.extend(_key_value_box("Sol Break-Fix Exceptions", report.get("sol_breakfix_summary", {}), term_width))
    if expanded:
        lines.extend(
            _detail_rows(
                "Workerbee Delegation Details",
                [
                    ("Dispatch", "dispatch_id"),
                    ("Bead", "bead_id"),
                    ("Lane", "lane"),
                    ("Planned", "planned"),
                    ("Actual", "actual"),
                    ("Status", "status"),
                    ("Gaps", "gap_reasons"),
                ],
                report.get("workerbee_delegation_details", []),
                term_width,
            )
        )
        lines.extend(
            _detail_rows(
                "Native Disposition Details",
                [
                    ("Dispatch", "dispatch_id"),
                    ("Bead", "bead_id"),
                    ("Lane", "lane"),
                    ("Session", "session_disposition"),
                    ("Artifact", "artifact_disposition"),
                    ("Validation", "validation"),
                ],
                report.get("native_disposition_details", []),
                term_width,
            )
        )
        lines.extend(
            _detail_rows(
                "Native Supervision Details",
                [
                    ("State", "state_id"),
                    ("Bead", "bead_id"),
                    ("Lane", "lane"),
                    ("Model", "model"),
                    ("Status", "status"),
                    ("Decision", "decision"),
                    ("Calls actual/interrupt/hard", "calls"),
                    ("Runtime actual/interrupt/hard", "runtime"),
                    ("Compactions", "compactions"),
                    ("Full suites", "full_suite_runs"),
                    ("Armed before dispatch", "armed_before_dispatch"),
                    ("Arm to dispatch ms", "arm_to_dispatch_ms"),
                    ("First poll ms", "first_poll_ms"),
                    ("Max poll gap ms", "max_poll_gap_ms"),
                    ("Late polls", "late_polls"),
                    ("Receipts", "control_receipts"),
                    ("Reasons", "reasons"),
                ],
                report.get("native_supervision_details", []),
                term_width,
            )
        )
    if expanded:
        lines.extend(
            _detail_rows(
                "Second-Opinion Review Lane Productivity",
                [
                    ("Lane", "lane"),
                    ("Profile", "profile"),
                    ("Agent/Model", "agent_model"),
                    ("Calls", "agent_model_calls"),
                    ("Accepted", "accepted_findings"),
                    ("Rejected", "rejected_findings"),
                    ("Quality", "evidence_quality_scores"),
                    ("Use", "recommended_synthesis_use"),
                    ("Signals", "signals"),
                ],
                report.get("second_opinion_review_lane_productivity_details", []),
                term_width,
            )
        )
    else:
        lines.extend(
            _table(
                "Second-Opinion Review Lane Productivity",
                ["Lane", "Profile", "Calls", "Accepted", "Rejected", "Quality", "Use", "Signals"],
                [
                    [
                        row.get("lane"),
                        row.get("profile"),
                        row.get("agent_model_calls"),
                        row.get("accepted_findings"),
                        row.get("rejected_findings"),
                        row.get("evidence_quality_scores"),
                        row.get("recommended_synthesis_use"),
                        row.get("signals"),
                    ]
                    for row in report.get("second_opinion_review_lane_productivity", [])
                ],
                term_width,
            )
        )
    lines.extend(_telemetry_gap_lines(report.get("telemetry_gaps", {}), term_width))
    quality = report.get("quality_malpractice_sabotage_summary", {})
    lines.extend(_key_value_box("Quality / Malpractice / Sabotage Summary", quality.get("totals", {}), term_width))
    lines.extend(
        _workerbee_accountability_lines(
            report.get("workerbee_delegation_accountability", {}),
            term_width,
        )
    )
    if expanded:
        lines.extend(
            _detail_rows(
                "Quality Events",
                [
                    ("Dispatch", "dispatch_id"),
                    ("Bead", "bead_id"),
                    ("Provider", "provider"),
                    ("Signals", "signals"),
                    ("Disposition", "recommended_disposition"),
                ],
                quality.get("events", []),
                term_width,
            )
        )
    else:
        lines.extend(
            _table(
                "Quality Events",
                ["Dispatch", "Bead", "Provider", "Signals", "Disposition"],
                [
                    [
                        row.get("dispatch_id"),
                        row.get("bead_id"),
                        row.get("provider"),
                        row.get("signals"),
                        row.get("recommended_disposition"),
                    ]
                    for row in quality.get("events", [])
                ],
                term_width,
            )
        )
    lines.extend(_key_value_box("Evidence Disposition Summary", report.get("evidence_disposition_summary", {}), term_width))
    warnings = _strings(report.get("warnings"))
    if warnings:
        lines.extend(_text_box("Warnings", [f"! {warning}" for warning in warnings], term_width))
    return "\n".join(lines) + "\n"


def _workerbee_accountability_lines(accountability: Any, width: int) -> list[str]:
    if not isinstance(accountability, dict):
        return []
    planned = accountability.get("planned")
    if not isinstance(planned, dict):
        return []
    plan = {
        "Planned mode": _clean(planned.get("mode")) or UNAVAILABLE,
        "Planned model": _clean(planned.get("model")) or UNAVAILABLE,
        "Planned lanes": ", ".join(_unique_items(planned.get("lanes") or [])) or UNAVAILABLE,
    }
    lines: list[str] = _key_value_box("Workerbee Delegation Plan", plan, width)
    rows = accountability.get("planned_vs_actual")
    if not isinstance(rows, list) or not rows:
        return lines
    lines.extend(
        _detail_rows(
            "Workerbee Delegation Accountability (Planned vs Actual)",
            [
                ("Lane", "lane"),
                ("Started", "started"),
                ("Completed", "completed"),
                ("Skipped", "skipped"),
                ("Deferred", "deferred"),
                ("Unavailable", "unavailable"),
            ],
            rows,
            width,
        )
    )
    return lines


def _record_view(record: dict[str, Any], source_kind: str) -> dict[str, Any]:
    provider_external = record.get("provider_external")
    if provider_external is None:
        provider_external = record.get("executor_external")
    provenance_class = _clean(record.get("provenance_class"))
    if provider_external is None and provenance_class == "external-contractor":
        provider_external = True
    job_label = _clean(
        record.get("job_description_label")
        or record.get("job_description")
        or record.get("contract_job_description")
    )
    expert_profile = _clean(
        record.get("expert_profile")
        or record.get("expert_profile_path")
        or record.get("persona_file")
        or record.get("expert")
        or job_label
    )
    executor = _clean(record.get("executor_key") or record.get("executor") or record.get("agent"))
    model = _clean(record.get("model") or record.get("model_name") or record.get("model_label") or record.get("local_profile"))
    provider = _clean(record.get("provider_key") or record.get("provider"))
    lane = _clean(record.get("lane") or record.get("role") or record.get("dispatch_mode") or provenance_class)
    telemetry_kind = _telemetry_kind(record, source_kind)
    metrics = {
        "agent_model_calls": _calls_from_record(record),
        "retries": _numeric(record, ("retry_count", "retries", "attempt_retries")),
        "input_tokens": _tokens(record, ("input_tokens", "prompt_tokens"), "input"),
        "output_tokens": _tokens(record, ("output_tokens", "completion_tokens"), "output"),
        "total_tokens": _total_tokens(record),
        "active_seconds": _numeric(record, ("active_seconds", "model_active_seconds", "compute_seconds")),
        "elapsed_seconds": _numeric(record, ("elapsed_seconds", "duration_seconds", "wall_time_seconds", "wall_clock_seconds")),
    }
    for field, value in list(metrics.items()):
        if value is None and not _telemetry_metric_expected(record, source_kind, telemetry_kind, field):
            metrics[field] = NOT_APPLICABLE
    workerbee_planned = _workerbee_planned_from_record(record)
    workerbee_actual = _workerbee_actual_from_record(record)
    view = {
        "source_kind": source_kind,
        "telemetry_kind": telemetry_kind,
        "bead_id": _clean(record.get("bead_id") or record.get("work_unit_id")),
        "dispatch_id": _clean(record.get("dispatch_id")),
        "event_type": _clean(record.get("event_type")),
        "workerbee_planned_delegation": record.get("workerbee_planned_delegation")
        if isinstance(record.get("workerbee_planned_delegation"), dict)
        else None,
        "route": record.get("route") if isinstance(record.get("route"), dict) else None,
        "work_unit_status": _status_from_record(record),
        "executor": executor,
        "model": model,
        "provider": provider,
        "provider_family": _clean(record.get("provider_family")),
        "provider_external": provider_external if isinstance(provider_external, bool) else None,
        "provenance_class": provenance_class,
        "lane": lane,
        "job_description_label": job_label,
        "expert_profile": expert_profile,
        "agent_model": _agent_model_name(executor, model),
        **metrics,
        "accepted_findings": _count_items(record.get("accepted_findings"), record.get("accepted_findings_count")),
        "rejected_findings": _count_items(record.get("rejected_findings"), record.get("rejected_findings_count")),
        "followup_beads": _count_items(record.get("followup_beads"), record.get("followup_beads_count")),
        "evidence_quality_score": _numeric(record, ("evidence_quality_score",)),
        "research_evidence_score": _numeric(record, ("research_evidence_score",)),
        "sabotage_score": _numeric(record, ("sabotage_score",)),
        "malpractice_score": _numeric(record, ("malpractice_score",)),
        "quarantine_recommended": record.get("quarantine_recommended") if isinstance(record.get("quarantine_recommended"), bool) else None,
        "sabotage_review_recommended": record.get("sabotage_review_recommended")
        if isinstance(record.get("sabotage_review_recommended"), bool)
        else None,
        "malpractice_review_recommended": record.get("malpractice_review_recommended")
        if isinstance(record.get("malpractice_review_recommended"), bool)
        else None,
        "peer_review_required": record.get("peer_review_required") if isinstance(record.get("peer_review_required"), bool) else None,
        "implementation_blocked": record.get("implementation_blocked")
        if isinstance(record.get("implementation_blocked"), bool)
        else None,
        "hold_reasons": _strings(record.get("hold_reasons")),
        "hold_classification": _clean(record.get("hold_classification")),
        "human_adjudication_required": record.get("human_adjudication_required")
        if isinstance(record.get("human_adjudication_required"), bool)
        else None,
        "recommended_disposition": _clean(record.get("recommended_disposition") or record.get("disposition")),
        "recommended_synthesis_use": _synthesis_use(record),
        "workerbee_planned_mode": workerbee_planned["mode"],
        "workerbee_planned_model": workerbee_planned["model"],
        "workerbee_planned_lanes": workerbee_planned["lanes"],
        "workerbee_actual_mode": workerbee_actual["mode"],
        "workerbee_actual_model": workerbee_actual["model"],
        "workerbee_actual_lanes": workerbee_actual["lanes"],
        "workerbee_delegation_status": _clean(record.get("workerbee_delegation_status")),
        "workerbee_delegation_source": _clean(record.get("workerbee_delegation_source")),
        "workerbee_delegation_gap_reasons": _strings(record.get("workerbee_delegation_gap_reasons")),
        "session_disposition": _clean(record.get("session_disposition")),
        "artifact_disposition": _clean(record.get("artifact_disposition")),
        "artifact_validation": record.get("artifact_validation")
        if isinstance(record.get("artifact_validation"), dict)
        else None,
        "sol_breakfix_exception": record.get("event_type") == "sol_breakfix_authorized"
        or record.get("sol_breakfix_exception") is True,
        "sol_breakfix_approval_source": _clean(
            record.get("operator_approval_ref") or record.get("sol_breakfix_approval_source")
        ),
        "sol_breakfix_scope": _clean(record.get("sol_breakfix_scope")),
        "sol_breakfix_expiry": _clean(record.get("sol_breakfix_expiry")),
        "sol_breakfix_automatic_selection_forbidden": record.get("automatic_selection_forbidden")
        if isinstance(record.get("automatic_selection_forbidden"), bool)
        else None,
        "native_supervision_state_id": _clean(record.get("native_supervision_state_id")),
        "native_supervision_status": _clean(record.get("native_supervision_status")),
        "native_supervision_decision": _clean(record.get("native_supervision_decision")),
        "native_supervision_reasons": _strings(record.get("native_supervision_reasons")),
        "validation_lineage_attempt": _numeric(record, ("validation_lineage_attempt",)),
        "control_action": _clean(record.get("control_action")),
        "control_receipts": _strings(record.get("control_receipts")),
        "planned_tool_calls_hard": _numeric(record, ("planned_tool_calls_hard",)),
        "interrupt_tool_calls_threshold": _numeric(record, ("interrupt_tool_calls_threshold",)),
        "observed_tool_calls": _numeric(record, ("observed_tool_calls",)),
        "planned_runtime_seconds_hard": _numeric(record, ("planned_runtime_seconds_hard",)),
        "interrupt_runtime_seconds_threshold": _numeric(record, ("interrupt_runtime_seconds_threshold",)),
        "observed_runtime_seconds": _numeric(record, ("observed_runtime_seconds",)),
        "observed_context_compactions": _numeric(record, ("observed_context_compactions",)),
        "observed_full_suite_runs": _numeric(record, ("observed_full_suite_runs",)),
        "monitor_armed_before_dispatch": record.get("monitor_armed_before_dispatch")
        if isinstance(record.get("monitor_armed_before_dispatch"), bool)
        else None,
        "arm_to_dispatch_ms": _numeric(record, ("arm_to_dispatch_ms",)),
        "dispatch_to_first_poll_ms": _numeric(record, ("dispatch_to_first_poll_ms",)),
        "max_poll_gap_ms": _numeric(record, ("max_poll_gap_ms",)),
        "late_poll_count": _numeric(record, ("late_poll_count",)),
        "control_turn_id": _clean(record.get("control_turn_id")),
    }
    enhancement_fields = (
        "native_progress_outcome",
        "native_progress_pm_action",
        "native_progress_reasons",
        "native_progress_warnings",
        "progress_validation_complete",
        "progress_pure_waste",
        "planned_tool_calls_p50",
        "planned_tool_calls_p90",
        "planned_runtime_seconds_p50",
        "planned_runtime_seconds_p90",
        "observed_tokens",
        "planned_context_reads",
        "observed_context_reads",
        "planned_mutations",
        "observed_mutations",
        "observed_tests_run",
        "observed_artifacts_completed",
        "projected_tool_calls",
        "projected_runtime_seconds",
        "planned_read_to_mutation_ratio",
        "actual_read_to_mutation_ratio",
        "retained_productive_artifacts",
        "retained_artifacts",
        "tool_call_calibration_error",
        "runtime_calibration_error_seconds",
        "checked_command_id",
        "checked_command_spec_sha256",
        "checked_command_mode",
        "checked_command_preflight_status",
        "checked_command_linter",
        "checked_command_execution_status",
        "checked_command_failure_class",
        "checked_command_linted_sha256",
        "checked_command_executed_sha256",
        "checked_command_hash_match",
        "checked_command_execution_started",
        "checked_command_mutation_started",
        "checked_command_quarantine_required",
        "checked_command_quoting_error_prevented",
        "checked_command_complexity_score",
        "checked_command_exit_code",
        "checked_command_avoided_retry_cycles",
        "checked_command_complexity_reasons",
        "checked_command_mutated_paths",
    )
    for field in enhancement_fields:
        if field in record:
            view[field] = record[field]

    return view


def _workerbee_accountability(records: list[dict[str, Any]]) -> dict[str, Any]:
    planned = {}
    for record in records:
        candidate = _normalize_workerbee_plan(record)
        if (
            candidate
            and (
                candidate.get("mode") != "none"
                or candidate.get("model") is not None
                or bool(candidate.get("lanes"))
            )
        ):
            planned = candidate
    planned_lanes = _unique_items(planned.get("lanes") or [])
    planned_lanes = [lane for lane in planned_lanes if lane]
    actual_by_lane = {lane: _new_workerbee_status_counter() for lane in planned_lanes}
    unmatched: dict[str, dict[str, int]] = {}
    for record in records:
        status = _status_from_record(record) or _clean(record.get("workerbee_delegation_status"))
        if status not in WORKERBEE_ACCOUNTABILITY_STATUS_KEYS:
            continue
        actual_lanes = _workerbee_actual_accountability_lanes(record)
        if not actual_lanes:
            continue
        for lane in actual_lanes:
            matched = False
            for planned_lane in planned_lanes:
                if _lane_matches_workerbee_plan(lane, planned_lane):
                    actual_by_lane.setdefault(planned_lane, _new_workerbee_status_counter())
                    actual_by_lane[planned_lane][status] += 1
                    matched = True
                    break
            if matched:
                continue
            unmatched.setdefault(
                lane,
                _new_workerbee_status_counter(),
            )[status] += 1
    for lane in planned_lanes:
        if all(actual_by_lane[lane][key] == 0 for key in WORKERBEE_ACCOUNTABILITY_STATUS_KEYS):
            actual_by_lane[lane]["unavailable"] += 1
    planned_rows = [
        {
            "lane": lane,
            **actual_by_lane.get(lane, _new_workerbee_status_counter()),
        }
        for lane in planned_lanes
    ]
    return {
        "planned": {
            "mode": planned.get("mode") or "none",
            "model": planned.get("model"),
            "lanes": planned_lanes,
        },
        "planned_vs_actual": planned_rows,
        "unplanned_activity": unmatched,
    }


def _workerbee_actual_accountability_lanes(record: dict[str, Any]) -> list[str]:
    explicit = [
        lane
        for lane in _unique_items(record.get("workerbee_actual_lanes") or [])
        if lane and lane != UNAVAILABLE and lane.lower() != "n/a"
    ]
    if explicit:
        return explicit
    lane = _clean(record.get("lane"))
    if not lane or lane == UNAVAILABLE or lane.lower() == "n/a":
        return []
    return [lane]


def _lane_matches_workerbee_plan(actual_lane: str, planned_lane: str) -> bool:
    if not actual_lane or not planned_lane:
        return False
    actual = actual_lane.lower().strip()
    planned = planned_lane.lower().strip()
    if actual == planned:
        return True
    if actual.startswith(f"expert-review-{planned}"):
        return True
    if f" {planned} " in f" {actual} ":
        return True
    actual_tokens = [token for token in re.split(r"[^a-z0-9]+", actual) if token]
    planned_tokens = [token for token in re.split(r"[^a-z0-9]+", planned) if token]
    if len(planned_tokens) < 2:
        return False
    width = len(planned_tokens)
    return any(actual_tokens[index : index + width] == planned_tokens for index in range(len(actual_tokens) - width + 1))


def _normalize_workerbee_plan(record: dict[str, Any]) -> dict[str, Any]:
    planned = record.get("workerbee_planned_delegation")
    if not isinstance(planned, dict):
        route = record.get("route")
        if isinstance(route, dict):
            planned = route.get("workerbee_planned_delegation")
        if not isinstance(planned, dict):
            planned = {
                "mode": _clean(record.get("workerbee_planned_mode")),
                "model": _clean(record.get("workerbee_planned_model")),
                "lanes": record.get("workerbee_planned_lanes"),
            }
    mode = str(planned.get("mode") or planned.get("recommended_mode") or "none") if isinstance(planned, dict) else "none"
    model = planned.get("model") if isinstance(planned, dict) else None
    if model is None and isinstance(planned, dict):
        model = planned.get("recommended_model")
    if isinstance(model, str) and not model.strip():
        model = None
    raw_lanes = planned.get("lanes") if isinstance(planned, dict) else None
    if not isinstance(raw_lanes, list):
        raw_lanes = []
    lanes = _unique_items(raw_lanes)
    return {
        "mode": mode,
        "model": model,
        "lanes": [str(lane) for lane in lanes if str(lane).strip()],
    }


def _new_workerbee_status_counter() -> dict[str, int]:
    return {key: 0 for key in WORKERBEE_ACCOUNTABILITY_STATUS_KEYS}


def _telemetry_kind(record: dict[str, Any], source_kind: str) -> str:
    explicit = _clean(record.get("telemetry_kind"))
    if explicit:
        return explicit
    event_type = str(record.get("event_type") or "").strip().lower()
    dispatch_mode = str(record.get("dispatch_mode") or "").strip().lower()
    if source_kind == "readiness_workstream":
        return "readiness"
    if source_kind in {"acceptance_decision", "readiness_adjudication_record"}:
        return "evaluation"
    if source_kind == "contractor_return_bundle":
        return "return_bundle"
    if event_type in USAGE_IMPORT_EVENT_TYPES:
        return "usage_import"
    if event_type == "packet_built":
        return "packet_build"
    if event_type == "return_evaluated":
        return "evaluation"
    if event_type == "chatgpt_browser_dispatch":
        return "browser_dispatch"
    if event_type == "harness_dispatch_rendered":
        return "harness_render"
    if event_type.startswith("native_supervision_"):
        return "native_supervision"
    if event_type == "dispatch_prepared":
        if dispatch_mode in {"local_openai_compatible", "local_secure_review"}:
            return "local_dispatch"
        if record.get("executor_external") is True or dispatch_mode == "manual_ui":
            return "manual_dispatch"
        return "dispatch"
    if event_type in DISPATCH_EVENT_TYPES or event_type.endswith("_dispatch"):
        return "dispatch"
    return "artifact"


def _telemetry_metric_expected(
    record: dict[str, Any],
    source_kind: str,
    telemetry_kind: str,
    field: str,
) -> bool:
    if source_kind.startswith("readiness_"):
        return False
    if telemetry_kind in {
        "packet_build",
        "evaluation",
        "readiness",
        "return_bundle",
        "harness_render",
        "usage_import",
        "browser_confirmation",
        "browser_rehearsal",
        "artifact",
        "native_supervision",
    }:
        return False
    if telemetry_kind == "local_dispatch" and record.get("execution_enabled") is False:
        return field in {"agent_model_calls", "retries"}
    return True


def _readiness_records(plan: dict[str, Any]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for item in _dict_items(plan.get("workstreams")):
        records.append(
            {
                "source_kind": "readiness_workstream",
                "telemetry_kind": "readiness",
                "bead_id": _clean(item.get("bead_id") or item.get("source_bead") or item.get("name")),
                "dispatch_id": None,
                "event_type": "readiness_workstream",
                "work_unit_status": _normalize_status(item.get("status")),
                "executor": _clean(item.get("owner")),
                "model": None,
                "provider": None,
                "provider_family": None,
                "provider_external": None,
                "provenance_class": "internal",
                "lane": _clean(item.get("owner")),
                "job_description_label": _clean(item.get("job_description_label")),
                "expert_profile": _clean(item.get("expert_profile") or item.get("owner")),
                "agent_model": _clean(item.get("owner")) or UNAVAILABLE,
                "agent_model_calls": NOT_APPLICABLE,
                "retries": NOT_APPLICABLE,
                "input_tokens": NOT_APPLICABLE,
                "output_tokens": NOT_APPLICABLE,
                "total_tokens": NOT_APPLICABLE,
                "active_seconds": NOT_APPLICABLE,
                "elapsed_seconds": NOT_APPLICABLE,
                "accepted_findings": None,
                "rejected_findings": None,
                "followup_beads": None,
                "evidence_quality_score": None,
                "research_evidence_score": None,
                "sabotage_score": None,
                "malpractice_score": None,
                "quarantine_recommended": None,
                "sabotage_review_recommended": None,
                "malpractice_review_recommended": None,
                "peer_review_required": None,
                "human_adjudication_required": None,
                "recommended_disposition": None,
                "recommended_synthesis_use": None,
            }
        )
    for item in _dict_items(plan.get("provider_provenance")):
        records.append(_record_view(item, "readiness_provider_provenance"))
    adjudication = plan.get("adjudication_record")
    if isinstance(adjudication, dict):
        records.append(_record_view(adjudication, "readiness_adjudication_record"))
    return records


def _executive_summary(records: list[dict[str, Any]]) -> dict[str, Any]:
    group = _new_group("executive")
    for record in records:
        _add_record(group, record)
    summary = _finalize_group(group)
    main = _new_group("main")
    second = _new_group("second-opinion")
    for record in records:
        _add_record(second if _is_second_opinion(record) else main, record)
    summary.update(
        {
            "main_thread_calls": _finalize_group(main)["agent_model_calls"],
            "second_opinion_calls": _finalize_group(second)["agent_model_calls"],
            "missing_telemetry_cells": UNAVAILABLE,
        }
    )
    return summary


def _expert_profile_rows(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    groups: dict[str, dict[str, Any]] = {}
    for record in records:
        key = record.get("expert_profile") or record.get("job_description_label") or UNAVAILABLE
        if not key:
            key = UNAVAILABLE
        group = groups.setdefault(str(key), _new_group(str(key)))
        _add_record(group, record)
        _collect(group, "roles", record.get("lane"))
        _collect(group, "labels", record.get("job_description_label"))
        _collect(group, "agents_models", record.get("agent_model"))
        _collect(group, "participation", "second-opinion" if _is_second_opinion(record) else "main-thread")
    rows: list[dict[str, Any]] = []
    for key, group in sorted(groups.items()):
        row = _finalize_group(group)
        row.update(
            {
                "profile": key,
                "role": _joined(group, "roles"),
                "job_description_labels": _joined(group, "labels"),
                "agents_models": _joined(group, "agents_models"),
                "participation": _joined(group, "participation"),
            }
        )
        rows.append(row)
    return rows


def _expert_profile_detail_rows(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    groups: dict[str, dict[str, Any]] = {}
    for record in records:
        profile = _present(record.get("expert_profile") or record.get("job_description_label"))
        role = _present(record.get("lane"))
        agent_model = _present(record.get("agent_model"))
        participation = "second-opinion" if _is_second_opinion(record) else "main-thread"
        key = (profile, role, agent_model, participation)
        group = groups.setdefault("|".join(key), _new_group("|".join(key)))
        group["detail_key"] = key
        _add_record(group, record)
        _collect(group, "labels", record.get("job_description_label"))
    rows: list[dict[str, Any]] = []
    for group in sorted(groups.values(), key=lambda item: item["detail_key"]):
        profile, role, agent_model, participation = group["detail_key"]
        row = _finalize_group(group)
        row.update(
            {
                "profile": profile,
                "role": role,
                "job_description_labels": _joined(group, "labels"),
                "agent_model": agent_model,
                "agents_models": agent_model,
                "participation": participation,
            }
        )
        rows.append(row)
    return rows


def _agent_model_rows(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    groups: dict[str, dict[str, Any]] = {}
    for record in records:
        key = str(record.get("agent_model") or UNAVAILABLE)
        group = groups.setdefault(key, _new_group(key))
        _add_record(group, record)
        _collect(group, "providers", record.get("provider"))
        _collect(group, "families", record.get("provider_family"))
        _collect(group, "provenance", record.get("provenance_class"))
        _collect(group, "lanes", record.get("lane"))
        _collect(group, "synthesis", record.get("recommended_synthesis_use"))
    rows: list[dict[str, Any]] = []
    for key, group in sorted(groups.items()):
        row = _finalize_group(group)
        row.update(
            {
                "agent_model": key,
                "provider": _joined(group, "providers"),
                "provider_family": _joined(group, "families"),
                "provenance_class": _joined(group, "provenance"),
                "lane": _joined(group, "lanes"),
                "recommended_synthesis_use": _joined(group, "synthesis"),
            }
        )
        rows.append(row)
    return rows


def _agent_model_detail_rows(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    groups: dict[str, dict[str, Any]] = {}
    for record in records:
        agent_model = _present(record.get("agent_model"))
        provider = _present(record.get("provider"))
        provider_family = _present(record.get("provider_family"))
        provenance_class = _present(record.get("provenance_class"))
        lane = _present(record.get("lane"))
        synthesis_use = _present(record.get("recommended_synthesis_use"))
        key = (agent_model, provider, provider_family, provenance_class, lane, synthesis_use)
        group = groups.setdefault("|".join(key), _new_group("|".join(key)))
        group["detail_key"] = key
        _add_record(group, record)
    rows: list[dict[str, Any]] = []
    for group in sorted(groups.values(), key=lambda item: item["detail_key"]):
        agent_model, provider, provider_family, provenance_class, lane, synthesis_use = group["detail_key"]
        row = _finalize_group(group)
        row.update(
            {
                "agent_model": agent_model,
                "provider": provider,
                "provider_family": provider_family,
                "provenance_class": provenance_class,
                "lane": lane,
                "recommended_synthesis_use": synthesis_use,
            }
        )
        rows.append(row)
    return rows


def _main_thread_summary(records: list[dict[str, Any]]) -> dict[str, Any]:
    group = _new_group("main-thread")
    for record in records:
        if not _is_second_opinion(record):
            _add_record(group, record)
    return _finalize_group(group)


def _second_opinion_rows(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    groups: dict[str, dict[str, Any]] = {}
    for record in records:
        if not _is_second_opinion(record):
            continue
        key = str(record.get("agent_model") or record.get("lane") or UNAVAILABLE)
        group = groups.setdefault(key, _new_group(key))
        _add_record(group, record)
        _collect(group, "profiles", record.get("expert_profile") or record.get("job_description_label"))
        _collect(group, "synthesis", record.get("recommended_synthesis_use"))
        _collect_numeric(group, "evidence_quality_scores", record.get("evidence_quality_score"))
        for signal in _record_quality_signals(record):
            _collect(group, "signals", signal)
    rows: list[dict[str, Any]] = []
    for key, group in sorted(groups.items()):
        row = _finalize_group(group)
        row.update(
            {
                "lane": key,
                "profile": _joined(group, "profiles"),
                "recommended_synthesis_use": _joined(group, "synthesis"),
                "evidence_quality_scores": _joined(group, "evidence_quality_scores"),
                "signals": _joined(group, "signals"),
            }
        )
        rows.append(row)
    return rows


def _second_opinion_detail_rows(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    groups: dict[str, dict[str, Any]] = {}
    for record in records:
        if not _is_second_opinion(record):
            continue
        lane = _present(record.get("agent_model") or record.get("lane"))
        profile = _present(record.get("expert_profile") or record.get("job_description_label"))
        agent_model = _present(record.get("agent_model"))
        synthesis_use = _present(record.get("recommended_synthesis_use"))
        key = (lane, profile, agent_model, synthesis_use)
        group = groups.setdefault("|".join(key), _new_group("|".join(key)))
        group["detail_key"] = key
        _add_record(group, record)
        _collect_numeric(group, "evidence_quality_scores", record.get("evidence_quality_score"))
        for signal in _record_quality_signals(record):
            _collect(group, "signals", signal)
    rows: list[dict[str, Any]] = []
    for group in sorted(groups.values(), key=lambda item: item["detail_key"]):
        lane, profile, agent_model, synthesis_use = group["detail_key"]
        row = _finalize_group(group)
        row.update(
            {
                "lane": lane,
                "profile": profile,
                "agent_model": agent_model,
                "recommended_synthesis_use": synthesis_use,
                "evidence_quality_scores": _joined(group, "evidence_quality_scores"),
                "signals": _joined(group, "signals"),
            }
        )
        rows.append(row)
    return rows


def _workerbee_delegation_summary(records: list[dict[str, Any]]) -> dict[str, Any]:
    details = _workerbee_delegation_detail_rows(records, include_internal=True)
    planned_lanes: set[str] = set()
    actual_lanes: set[str] = set()
    planned_models: set[str] = set()
    actual_models: set[str] = set()
    status_counts: dict[str, int] = {}
    gap_counts: dict[str, int] = {}
    planned_records = 0
    actual_records = 0
    for row in details:
        planned = row.get("_planned") if isinstance(row.get("_planned"), dict) else {}
        actual = row.get("_actual") if isinstance(row.get("_actual"), dict) else {}
        if _workerbee_plan_present(planned):
            planned_records += 1
        row_status = _clean(row.get("status"))
        if row_status != "planned-no-actual-telemetry" and (
            _workerbee_actual_present(actual)
            or (isinstance(row_status, str) and row_status in WORKERBEE_ACCOUNTABILITY_STATUS_KEYS)
        ):
            actual_records += 1
        planned_lanes.update(_strings(planned.get("lanes")))
        actual_lanes.update(_strings(actual.get("lanes")))
        planned_model = _clean(planned.get("model"))
        actual_model = _clean(actual.get("model"))
        if planned_model:
            planned_models.add(planned_model)
        if actual_model:
            actual_models.add(actual_model)
        status = _clean(row.get("status")) or "unknown"
        status_counts[status] = status_counts.get(status, 0) + 1
        for reason in _strings(row.get("_gap_reasons")):
            gap_counts[reason] = gap_counts.get(reason, 0) + 1

    unfulfilled = sorted(planned_lanes - actual_lanes)
    return {
        "records_considered": len(details),
        "planned_records": planned_records,
        "actual_records": actual_records,
        "planned_lanes": _joined_values(planned_lanes),
        "actual_lanes": _joined_values(actual_lanes),
        "planned_models": _joined_values(planned_models),
        "actual_models": _joined_values(actual_models),
        "unfulfilled_lane_count": len(unfulfilled),
        "unfulfilled_lanes": _joined_values(unfulfilled),
        "status_summary": _count_summary(status_counts),
        "gap_reasons": _count_summary(gap_counts),
    }


def _native_disposition_detail_rows(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for record in _native_disposition_records(records):
        session = _clean(record.get("session_disposition"))
        artifact = _clean(record.get("artifact_disposition"))
        validation = record.get("artifact_validation")
        if not _is_native_disposition_record(record):
            continue
        validation_text = UNAVAILABLE
        if isinstance(validation, dict):
            validation_text = "/".join(
                [
                    _present(validation.get("outcome")),
                    f"attempts={_present(validation.get('attempts_used'))}/{_present(validation.get('max_attempts'))}",
                    f"eligible={_present(validation.get('eligible'))}",
                ]
            )
        rows.append(
            {
                "dispatch_id": record.get("dispatch_id") or UNAVAILABLE,
                "bead_id": record.get("bead_id") or UNAVAILABLE,
                "lane": record.get("lane") or UNAVAILABLE,
                "session_disposition": session or UNAVAILABLE,
                "artifact_disposition": artifact or UNAVAILABLE,
                "validation": validation_text,
            }
        )
    return rows


def _native_disposition_summary(records: list[dict[str, Any]]) -> dict[str, Any]:
    session_counts = {key: 0 for key in ("accepted", "accepted-with-warning", "quarantined", "unknown")}
    artifact_counts = {
        key: 0
        for key in (
            "accepted",
            "independent-validation-required",
            "architect-adjudication-required",
            "rejected",
            "unknown",
        )
    }
    eligible = 0
    considered = 0
    for record in _native_disposition_records(records):
        session = _clean(record.get("session_disposition"))
        artifact = _clean(record.get("artifact_disposition"))
        validation = record.get("artifact_validation")
        if not _is_native_disposition_record(record):
            continue
        considered += 1
        session_counts[session if session in session_counts else "unknown"] += 1
        artifact_counts[artifact if artifact in artifact_counts else "unknown"] += 1
        if isinstance(validation, dict) and validation.get("eligible") is True:
            eligible += 1
    return {
        "records_considered": considered,
        "session_accepted": session_counts["accepted"],
        "session_warning": session_counts["accepted-with-warning"],
        "session_quarantined": session_counts["quarantined"],
        "session_unknown": session_counts["unknown"],
        "artifact_accepted": artifact_counts["accepted"],
        "artifact_validation_required": artifact_counts["independent-validation-required"],
        "artifact_adjudication_required": artifact_counts["architect-adjudication-required"],
        "artifact_rejected": artifact_counts["rejected"],
        "artifact_unknown": artifact_counts["unknown"],
        "validation_eligible": eligible,
    }


def _native_disposition_records(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    ordinary: list[dict[str, Any]] = []
    supervised: dict[str, dict[str, Any]] = {}
    for record in records:
        state_id = _clean(record.get("native_supervision_state_id"))
        if state_id:
            supervised[state_id] = record
        else:
            ordinary.append(record)
    return [*ordinary, *[supervised[key] for key in sorted(supervised)]]


def _native_supervision_states(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[str, dict[str, Any]] = {}
    for record in records:
        state_id = _clean(record.get("native_supervision_state_id"))
        if not state_id:
            continue
        row = grouped.setdefault(
            state_id,
            {
                "state_id": state_id,
                "bead_id": UNAVAILABLE,
                "dispatch_id": UNAVAILABLE,
                "lane": UNAVAILABLE,
                "model": UNAVAILABLE,
                "status": UNAVAILABLE,
                "decision": UNAVAILABLE,
                "planned_tool_calls_hard": None,
                "interrupt_tool_calls_threshold": None,
                "observed_tool_calls": None,
                "planned_runtime_seconds_hard": None,
                "interrupt_runtime_seconds_threshold": None,
                "observed_runtime_seconds": None,
                "compactions": 0,
                "validation_lineage_attempt": None,
                "full_suite_runs": 0,
                "monitor_armed_before_dispatch": None,
                "arm_to_dispatch_ms": None,
                "dispatch_to_first_poll_ms": None,
                "max_poll_gap_ms": None,
                "late_poll_count": 0,
                "control_receipts": [],
                "reasons": [],
            },
        )
        for source, target in (
            ("bead_id", "bead_id"),
            ("dispatch_id", "dispatch_id"),
            ("lane", "lane"),
            ("model", "model"),
            ("native_supervision_status", "status"),
            ("native_supervision_decision", "decision"),
            ("planned_tool_calls_hard", "planned_tool_calls_hard"),
            ("interrupt_tool_calls_threshold", "interrupt_tool_calls_threshold"),
            ("observed_tool_calls", "observed_tool_calls"),
            ("validation_lineage_attempt", "validation_lineage_attempt"),
            ("planned_runtime_seconds_hard", "planned_runtime_seconds_hard"),
            ("interrupt_runtime_seconds_threshold", "interrupt_runtime_seconds_threshold"),
            ("observed_runtime_seconds", "observed_runtime_seconds"),
            ("observed_context_compactions", "compactions"),
            ("observed_full_suite_runs", "full_suite_runs"),
            ("monitor_armed_before_dispatch", "monitor_armed_before_dispatch"),
            ("arm_to_dispatch_ms", "arm_to_dispatch_ms"),
            ("dispatch_to_first_poll_ms", "dispatch_to_first_poll_ms"),
            ("max_poll_gap_ms", "max_poll_gap_ms"),
            ("late_poll_count", "late_poll_count"),
        ):
            value = record.get(source)
            if value not in (None, "", []):
                row[target] = value
        if row["validation_lineage_attempt"] is None:
            lineage = record.get("validation_lineage")
            if isinstance(lineage, dict) and "attempt" in lineage:
                row["validation_lineage_attempt"] = lineage.get("attempt")
        row["control_receipts"] = _unique_items([*row["control_receipts"], *_strings(record.get("control_receipts"))])
        row["reasons"] = _unique_items([*row["reasons"], *_strings(record.get("native_supervision_reasons"))])
    return [grouped[key] for key in sorted(grouped)]


def _native_supervision_detail_rows(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for state in _native_supervision_states(records):
        observed_calls = state["observed_tool_calls"]
        threshold_calls = state["interrupt_tool_calls_threshold"]
        hard_calls = state["planned_tool_calls_hard"]
        observed_runtime = state["observed_runtime_seconds"]
        threshold_runtime = state["interrupt_runtime_seconds_threshold"]
        hard_runtime = state["planned_runtime_seconds_hard"]
        rows.append(
            {
                "state_id": state["state_id"],
                "bead_id": state["bead_id"],
                "dispatch_id": state["dispatch_id"],
                "lane": state["lane"],
                "model": state["model"],
                "status": state["status"],
                "decision": state["decision"],
                "calls": f"{_present(observed_calls)}/{_present(threshold_calls)}/{_present(hard_calls)}",
                "runtime": f"{_present(observed_runtime)}/{_present(threshold_runtime)}/{_present(hard_runtime)}",
                "compactions": state["compactions"],
                "full_suite_runs": state["full_suite_runs"],
                "armed_before_dispatch": _present(state["monitor_armed_before_dispatch"]),
                "arm_to_dispatch_ms": _present(state["arm_to_dispatch_ms"]),
                "first_poll_ms": _present(state["dispatch_to_first_poll_ms"]),
                "max_poll_gap_ms": _present(state["max_poll_gap_ms"]),
                "late_polls": state["late_poll_count"],
                "control_receipts": _joined_values(state["control_receipts"]),
                "reasons": _joined_values(state["reasons"]),
            }
        )
    return rows


def _native_supervision_summary(records: list[dict[str, Any]]) -> dict[str, Any]:
    states = _native_supervision_states(records)
    complete = sum(state["status"] == "completed" for state in states)
    interrupted = sum(
        state["decision"] in {"interrupt", "control-lost"}
        or state["status"] in {"closed", "control-failed"}
        for state in states
    )
    control_lost_workers = sum(state["decision"] == "control-lost" for state in states)
    completion_rate = _percentage_ratio(complete, len(states))
    hard_overruns = sum(
        isinstance(state["observed_tool_calls"], (int, float))
        and isinstance(state["planned_tool_calls_hard"], (int, float))
        and state["observed_tool_calls"] > state["planned_tool_calls_hard"]
        for state in states
    )
    hard_limit_breach_rate = _percentage_ratio(hard_overruns, len(states))
    reserve_stops = sum(
        state["decision"] == "interrupt"
        and isinstance(state["observed_tool_calls"], (int, float))
        and isinstance(state["planned_tool_calls_hard"], (int, float))
        and state["observed_tool_calls"] <= state["planned_tool_calls_hard"]
        for state in states
    )
    planned_tool_calls_hard = sum(
        state["planned_tool_calls_hard"] for state in states if isinstance(state["planned_tool_calls_hard"], (int, float))
    )
    observed_tool_calls = sum(
        state["observed_tool_calls"] for state in states if isinstance(state["observed_tool_calls"], (int, float))
    )
    compaction_workers = sum(int(state["compactions"] or 0) > 0 for state in states)
    compaction_rate = _percentage_ratio(compaction_workers, len(states))
    first_attempt_workers = sum(
        isinstance(state["validation_lineage_attempt"], (int, float)) and state["validation_lineage_attempt"] == 0
        for state in states
    )
    first_attempt_completed = sum(
        state["status"] == "completed"
        and isinstance(state["validation_lineage_attempt"], (int, float))
        and state["validation_lineage_attempt"] == 0
        for state in states
    )
    first_attempt_completion_rate = _percentage_ratio(first_attempt_completed, first_attempt_workers)
    control_loss_rate = _percentage_ratio(control_lost_workers, len(states))
    hard_budget_utilization = _percentage_ratio(observed_tool_calls, planned_tool_calls_hard)
    return {
        "workers_supervised": len(states),
        "completed": complete,
        "interrupted_or_control_lost": interrupted,
        "completion_rate_percent": completion_rate,
        "control_lost_workers": control_lost_workers,
        "control_loss_rate_percent": control_loss_rate,
        "reserve_stops_before_hard_limit": reserve_stops,
        "hard_limit_overruns": hard_overruns,
        "hard_limit_breach_rate_percent": hard_limit_breach_rate,
        "planned_tool_calls_hard": planned_tool_calls_hard,
        "observed_tool_calls": observed_tool_calls,
        "hard_budget_utilization_percent": hard_budget_utilization,
        "compaction_workers": compaction_workers,
        "compaction_worker_rate_percent": compaction_rate,
        "first_attempt_workers": first_attempt_workers,
        "first_attempt_completed": first_attempt_completed,
        "first_attempt_completion_rate_percent": first_attempt_completion_rate,
        "context_compactions": sum(int(state["compactions"] or 0) for state in states),
        "full_suite_runs": sum(int(state["full_suite_runs"] or 0) for state in states),
        "armed_before_dispatch": sum(state["monitor_armed_before_dispatch"] is True for state in states),
        "late_poll_workers": sum(int(state["late_poll_count"] or 0) > 0 for state in states),
        "late_poll_count": sum(int(state["late_poll_count"] or 0) for state in states),
        "max_dispatch_to_first_poll_ms": max(
            [state["dispatch_to_first_poll_ms"] for state in states if isinstance(state["dispatch_to_first_poll_ms"], (int, float))]
            or [0]
        ),
        "max_poll_gap_ms": max(
            [state["max_poll_gap_ms"] for state in states if isinstance(state["max_poll_gap_ms"], (int, float))]
            or [0]
        ),
    }


def _is_native_disposition_record(record: dict[str, Any]) -> bool:
    if record.get("session_disposition") or record.get("artifact_disposition"):
        return True
    if isinstance(record.get("artifact_validation"), dict):
        return True
    model = _clean(record.get("model")) or _clean(record.get("workerbee_actual_model"))
    return model in NATIVE_DISPOSITION_MODELS


def _sol_breakfix_summary(records: list[dict[str, Any]]) -> dict[str, Any]:
    by_bead: dict[str, dict[str, Any]] = {}
    for index, record in enumerate(records):
        if record.get("sol_breakfix_exception") is not True:
            continue
        key = _clean(record.get("bead_id")) or f"unlinked-{index}"
        previous = by_bead.get(key)
        if previous is None or record.get("sol_breakfix_approval_source"):
            by_bead[key] = record
    exceptions = list(by_bead.values())
    return {
        "authorization_count": len(exceptions),
        "automatic_selection_forbidden": all(
            record.get("sol_breakfix_automatic_selection_forbidden") is True for record in exceptions
        )
        if exceptions
        else True,
        "beads": _joined_values([record.get("bead_id") for record in exceptions]),
        "approval_sources": _joined_values(
            [record.get("sol_breakfix_approval_source") for record in exceptions]
        ),
        "scopes": _joined_values([record.get("sol_breakfix_scope") for record in exceptions]),
        "expiries": _joined_values([record.get("sol_breakfix_expiry") for record in exceptions]),
    }


def _workerbee_delegation_detail_rows(records: list[dict[str, Any]], *, include_internal: bool = False) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for record in records:
        planned = {
            "mode": record.get("workerbee_planned_mode"),
            "model": record.get("workerbee_planned_model"),
            "lanes": record.get("workerbee_planned_lanes"),
        }
        actual = {
            "mode": record.get("workerbee_actual_mode"),
            "model": record.get("workerbee_actual_model"),
            "lanes": record.get("workerbee_actual_lanes"),
        }
        status = _clean(record.get("workerbee_delegation_status"))
        gap_reasons = _strings(record.get("workerbee_delegation_gap_reasons"))
        if _workerbee_plan_present(planned) and not _workerbee_actual_present(actual, status):
            gap_reasons = [*gap_reasons, "planned-workerbee-not-accounted"]
            status = status or "planned-no-actual-telemetry"
        elif _workerbee_actual_present(actual, status):
            status = status or "actual-recorded"
        if not (_workerbee_plan_present(planned) or _workerbee_actual_present(actual, status) or gap_reasons):
            continue
        row = {
            "dispatch_id": record.get("dispatch_id") or UNAVAILABLE,
            "bead_id": record.get("bead_id") or UNAVAILABLE,
            "lane": record.get("lane") or UNAVAILABLE,
            "planned": _workerbee_format(planned),
            "actual": _workerbee_format(actual),
            "status": status or UNAVAILABLE,
            "source": record.get("workerbee_delegation_source") or UNAVAILABLE,
            "gap_reasons": _joined_values(gap_reasons),
            "_planned": planned,
            "_actual": actual,
            "_gap_reasons": gap_reasons,
        }
        rows.append(row)
    rows.sort(key=lambda row: (str(row.get("bead_id")), str(row.get("dispatch_id")), str(row.get("lane"))))
    if include_internal:
        return rows
    rows = [{key: value for key, value in row.items() if not key.startswith("_")} for row in rows]
    return rows


def _workerbee_planned_from_record(record: dict[str, Any]) -> dict[str, Any]:
    nested = record.get("workerbee_planned_delegation")
    mode = _clean(record.get("workerbee_planned_mode"))
    model = _clean(record.get("workerbee_planned_model"))
    lanes = _strings(record.get("workerbee_planned_lanes"))
    if isinstance(nested, dict):
        mode = mode or _clean(nested.get("mode") or nested.get("recommended_mode"))
        model = model or _clean(nested.get("model") or nested.get("recommended_model"))
        lanes = lanes or _strings(nested.get("lanes") or nested.get("suggested_lanes"))
    return {"mode": mode, "model": model, "lanes": lanes}


def _workerbee_actual_from_record(record: dict[str, Any]) -> dict[str, Any]:
    nested = record.get("workerbee_actual_delegation")
    mode = _clean(record.get("workerbee_actual_mode"))
    model = _clean(record.get("workerbee_actual_model"))
    lanes = _strings(record.get("workerbee_actual_lanes"))
    if isinstance(nested, dict):
        mode = mode or _clean(nested.get("mode"))
        model = model or _clean(nested.get("model"))
        lanes = lanes or _strings(nested.get("lanes"))
    return {"mode": mode, "model": model, "lanes": lanes}


def _workerbee_plan_present(value: dict[str, Any]) -> bool:
    mode = _clean(value.get("mode"))
    return bool((mode and mode != "none") or _strings(value.get("lanes")) or _clean(value.get("model")))


def _workerbee_actual_present(value: dict[str, Any], status: Any = None) -> bool:
    mode = _clean(value.get("mode"))
    return bool(
        (mode and mode != "none")
        or _strings(value.get("lanes"))
        or _clean(value.get("model"))
        or _clean(status)
    )


def _workerbee_format(value: dict[str, Any]) -> str:
    mode = _clean(value.get("mode")) or NOT_APPLICABLE
    model = _clean(value.get("model")) or NOT_APPLICABLE
    lanes = _joined_values(_strings(value.get("lanes")))
    return f"mode={mode}; model={model}; lanes={lanes}"


def _joined_values(values: Any) -> str:
    if isinstance(values, set):
        items = sorted(str(item) for item in values if str(item).strip())
    elif isinstance(values, list):
        items = sorted({str(item) for item in values if str(item).strip()})
    else:
        items = []
    return ", ".join(items) if items else NOT_APPLICABLE


def _count_summary(counts: dict[str, int]) -> str:
    if not counts:
        return NOT_APPLICABLE
    return ", ".join(f"{key}:{counts[key]}" for key in sorted(counts))


def _telemetry_gaps(records: list[dict[str, Any]], source_counts: dict[str, int]) -> dict[str, Any]:
    fields: dict[str, dict[str, Any]] = {}
    for field in TELEMETRY_GAP_KEYS:
        fields[field] = {
            "available_records": 0,
            "missing_records": 0,
            "not_applicable_records": 0,
            "missing_source_kinds": [],
            "missing_reasons": {},
            "by_source_kind": {},
        }

    for record in records:
        source_kind = _present(record.get("source_kind"))
        for field in TELEMETRY_GAP_KEYS:
            field_summary = fields[field]
            by_source = field_summary["by_source_kind"].setdefault(
                source_kind,
                {"available_records": 0, "missing_records": 0, "not_applicable_records": 0},
            )
            value = record.get(field)
            if value == NOT_APPLICABLE:
                field_summary["not_applicable_records"] += 1
                by_source["not_applicable_records"] += 1
            elif _has_numeric_metric(value):
                field_summary["available_records"] += 1
                by_source["available_records"] += 1
            else:
                field_summary["missing_records"] += 1
                by_source["missing_records"] += 1
                for reason in _telemetry_missing_reasons(record):
                    missing_reasons = field_summary["missing_reasons"]
                    missing_reasons[reason] = missing_reasons.get(reason, 0) + 1

    for field_summary in fields.values():
        field_summary["missing_source_kinds"] = sorted(
            source for source, counts in field_summary["by_source_kind"].items() if counts["missing_records"]
        )
    missing_fields = sorted(field for field, summary in fields.items() if summary["missing_records"])
    return {
        "records_considered": len(records),
        "source_artifacts_supplied": any(count > 0 for count in source_counts.values()),
        "fields_with_missing_values": missing_fields,
        "fields": fields,
    }


def _telemetry_missing_reasons(record: dict[str, Any]) -> list[str]:
    reasons = _strings(record.get("telemetry_missing_reasons"))
    single = _clean(record.get("telemetry_missing_reason"))
    if single:
        reasons.append(single)
    normalized = sorted({reason for reason in reasons if reason})
    return normalized or ["not-recorded"]


def _quality_summary(records: list[dict[str, Any]]) -> dict[str, Any]:
    totals = {
        "low_evidence_quality": 0,
        "sabotage_concerns": 0,
        "malpractice_concerns": 0,
        "quarantine_recommended": 0,
        "peer_review_required": 0,
        "implementation_blocked": 0,
        "human_adjudication_required": 0,
    }
    events: list[dict[str, Any]] = []
    for record in records:
        signals = _record_quality_signals(record)
        if "low-evidence-quality" in signals:
            totals["low_evidence_quality"] += 1
        if "sabotage-concern" in signals:
            totals["sabotage_concerns"] += 1
        if "malpractice-concern" in signals:
            totals["malpractice_concerns"] += 1
        if "quarantine-recommended" in signals:
            totals["quarantine_recommended"] += 1
        if record.get("peer_review_required") is True:
            totals["peer_review_required"] += 1
        if record.get("implementation_blocked") is True:
            totals["implementation_blocked"] += 1
        if record.get("human_adjudication_required") is True:
            totals["human_adjudication_required"] += 1
        if signals:
            events.append(
                {
                    "dispatch_id": record.get("dispatch_id") or UNAVAILABLE,
                    "bead_id": record.get("bead_id") or UNAVAILABLE,
                    "provider": record.get("provider") or UNAVAILABLE,
                    "signals": ", ".join(signals),
                    "recommended_disposition": record.get("recommended_disposition")
                    or record.get("recommended_synthesis_use")
                    or UNAVAILABLE,
                }
            )
    return {"totals": totals, "events": events}


def _evidence_disposition_summary(records: list[dict[str, Any]]) -> dict[str, Any]:
    summary: dict[str, Any] = {key: 0 for key in SYNTHESIS_DISPOSITIONS}
    accepted = 0
    rejected = 0
    followups = 0
    for record in records:
        use = "process-hold" if record.get("implementation_blocked") is True else record.get("recommended_synthesis_use")
        if not use:
            use = "unavailable"
        elif use not in summary:
            use = "unknown"
        summary[str(use)] += 1
        accepted += int(record.get("accepted_findings") or 0)
        rejected += int(record.get("rejected_findings") or 0)
        followups += int(record.get("followup_beads") or 0)
    summary.update(
        {
            "accepted_findings": accepted,
            "rejected_findings": rejected,
            "followup_beads": followups,
        }
    )
    return summary


def _new_group(name: str) -> dict[str, Any]:
    return {
        "name": name,
        "work_units": set(),
        "dispatches": set(),
        "records": 0,
        "status_known": False,
        "statuses": {key: 0 for key in STATUS_KEYS},
        "metrics": {},
        "metric_known": set(),
        "metric_missing": set(),
        "metric_not_applicable": set(),
    }


def _add_record(group: dict[str, Any], record: dict[str, Any]) -> None:
    group["records"] += 1
    if record.get("bead_id"):
        group["work_units"].add(record["bead_id"])
    if record.get("dispatch_id"):
        group["dispatches"].add(record["dispatch_id"])
    status = record.get("work_unit_status")
    if status in STATUS_KEYS:
        group["status_known"] = True
        group["statuses"][status] += 1
    for key in METRIC_KEYS:
        value = record.get(key)
        if _has_numeric_metric(value):
            group["metrics"][key] = group["metrics"].get(key, 0) + value
            group["metric_known"].add(key)
        elif value == NOT_APPLICABLE:
            group["metric_not_applicable"].add(key)
        else:
            group["metric_missing"].add(key)


def _finalize_group(group: dict[str, Any]) -> dict[str, Any]:
    row: dict[str, Any] = {
        "work_units": len(group["work_units"]) if group["work_units"] else UNAVAILABLE,
        "records": group["records"],
        "dispatches": len(group["dispatches"]) if group["dispatches"] else UNAVAILABLE,
    }
    for status in STATUS_KEYS:
        row[status] = group["statuses"][status] if group["status_known"] else UNAVAILABLE
    for key in METRIC_KEYS:
        if key in group["metric_known"]:
            row[key] = _format_number(group["metrics"].get(key))
        elif key in group["metric_not_applicable"] and key not in group["metric_missing"]:
            row[key] = NOT_APPLICABLE
        else:
            row[key] = UNAVAILABLE
    return row


def _collect(group: dict[str, Any], key: str, value: Any) -> None:
    if value in [None, ""]:
        return
    group.setdefault(key, set()).add(str(value))


def _collect_numeric(group: dict[str, Any], key: str, value: Any) -> None:
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        group.setdefault(key, set()).add(_format_number(value))


def _joined(group: dict[str, Any], key: str) -> str:
    values = sorted(str(item) for item in group.get(key, set()) if str(item).strip())
    return ", ".join(values) if values else UNAVAILABLE


def _present(value: Any) -> str:
    return _clean(value) or UNAVAILABLE


def _has_numeric_metric(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _percentage_ratio(numerator: Any, denominator: Any) -> float:
    if not _has_numeric_metric(numerator) or not _has_numeric_metric(denominator) or denominator <= 0:
        return 0.0
    return round(100 * float(numerator) / float(denominator), 1)


def _is_second_opinion(record: dict[str, Any]) -> bool:
    if record.get("provider_external") is True:
        return True
    if record.get("provenance_class") in {"external-contractor", "local-worker"}:
        return True
    lane = " ".join(
        str(record.get(key) or "").lower()
        for key in ["lane", "executor", "agent_model", "job_description_label", "expert_profile", "event_type"]
    )
    return any(
        term in lane
        for term in [
            "contractor",
            "second-opinion",
            "review",
            "synthesis",
            "claude",
            "opus",
            "gemini",
            "chatgpt",
            "local-worker",
        ]
    )


def _record_quality_signals(record: dict[str, Any]) -> list[str]:
    signals: list[str] = []
    quality = record.get("evidence_quality_score")
    if isinstance(quality, (int, float)) and quality < 60:
        signals.append("low-evidence-quality")
    sabotage = record.get("sabotage_score")
    if (isinstance(sabotage, (int, float)) and sabotage > 0) or record.get("sabotage_review_recommended") is True:
        signals.append("sabotage-concern")
    malpractice = record.get("malpractice_score")
    if (isinstance(malpractice, (int, float)) and malpractice > 0) or record.get("malpractice_review_recommended") is True:
        signals.append("malpractice-concern")
    if record.get("quarantine_recommended") is True or record.get("recommended_synthesis_use") == "quarantine":
        signals.append("quarantine-recommended")
    if record.get("implementation_blocked") is True:
        signals.append("process-hold")
    if record.get("peer_review_required") is True:
        signals.append("peer-review-required")
    if record.get("human_adjudication_required") is True:
        signals.append("architect-adjudication-required")
    return signals


def _status_from_record(record: dict[str, Any]) -> str | None:
    for key in ["work_unit_status", "status", "telemetry_status"]:
        status = _normalize_status(record.get(key))
        if status:
            return status
    event_type = str(record.get("event_type") or "").strip().lower()
    if event_type == "dispatch_prepared":
        return "started"
    verdict = str(record.get("verdict") or "").strip().lower()
    if verdict in {"accept", "partial-accept"}:
        return "completed"
    if verdict == "reject":
        return "failed"
    if verdict in {"clarify", "escalate", "quarantine"}:
        return "blocked"
    disposition = str(record.get("recommended_disposition") or record.get("disposition") or "").strip().lower()
    return _normalize_status(disposition)


def _normalize_status(value: Any) -> str | None:
    normalized = str(value or "").strip().lower().replace("_", "-")
    if normalized in {"prepared", "prepare", "preparing", "started", "start", "in-progress", "inprogress", "running"}:
        return "started"
    if normalized in {"complete", "completed", "success", "succeeded", "accepted", "accept", "done", "passed"}:
        return "completed"
    if normalized in {"fail", "failed", "failure", "error", "errored", "rejected", "reject"}:
        return "failed"
    if normalized in {"skip", "skipped"}:
        return "skipped"
    if normalized in {"block", "blocked", "quarantine", "quarantined", "clarify", "escalate"}:
        return "blocked"
    if normalized in {"unavailable", "not-available", "not_available", "na", "n/a", "notapplicable", "not-applicable"}:
        return "unavailable"
    if normalized in {"defer", "deferred"}:
        return "deferred"
    return None


def _synthesis_use(record: dict[str, Any]) -> str | None:
    value = _clean(record.get("recommended_synthesis_use") or record.get("synthesis_use") or record.get("disposition"))
    if not value:
        return None
    return value if value in SYNTHESIS_DISPOSITIONS else "unknown"


def _calls_from_record(record: dict[str, Any]) -> int | float | None:
    explicit = _numeric(record, ("agent_model_calls", "model_calls", "call_count", "calls"))
    if explicit is not None:
        return explicit
    event_type = str(record.get("event_type") or "").strip().lower()
    if event_type in {"packet_built", "return_evaluated", "harness_dispatch_rendered"}:
        return None
    quota_event_type = str(record.get("quota_event_type") or "").strip().lower()
    if event_type in DISPATCH_EVENT_TYPES or event_type.endswith("_dispatch") or quota_event_type.endswith("_dispatch"):
        return 1
    return None


def _tokens(record: dict[str, Any], scalar_keys: tuple[str, ...], usage_key: str) -> int | float | None:
    scalar = _numeric(record, scalar_keys)
    if scalar is not None:
        return scalar
    for container_key in ["usage", "token_usage", "tokens"]:
        container = record.get(container_key)
        if isinstance(container, dict):
            nested = _numeric(container, (usage_key, f"{usage_key}_tokens"))
            if nested is not None:
                return nested
    return None


def _total_tokens(record: dict[str, Any]) -> int | float | None:
    total = _numeric(record, ("total_tokens", "tokens_total"))
    if total is not None:
        return total
    for container_key in ["usage", "token_usage", "tokens"]:
        container = record.get(container_key)
        if isinstance(container, dict):
            nested = _numeric(container, ("total", "total_tokens"))
            if nested is not None:
                return nested
    input_tokens = _tokens(record, ("input_tokens", "prompt_tokens"), "input")
    output_tokens = _tokens(record, ("output_tokens", "completion_tokens"), "output")
    if input_tokens is None or output_tokens is None:
        return None
    return input_tokens + output_tokens


def _numeric(record: dict[str, Any], keys: tuple[str, ...]) -> int | float | None:
    for key in keys:
        value = record.get(key)
        if isinstance(value, bool):
            continue
        if isinstance(value, (int, float)) and math.isfinite(float(value)):
            return value
    return None


def _count_items(value: Any, explicit: Any = None) -> int | None:
    if isinstance(explicit, int) and not isinstance(explicit, bool):
        return explicit
    if isinstance(value, list):
        return len(value)
    return None


def _dict_items(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _strings(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if str(item).strip()]


def _unique_items(values: Any) -> list[str]:
    if not isinstance(values, list):
        return []
    return list(dict.fromkeys([str(item).strip() for item in values if str(item).strip()]))


def _clean(value: Any) -> str | None:
    if value in [None, ""]:
        return None
    if isinstance(value, (str, int, float, bool)):
        text = str(value).strip()
        return text or None
    return None


def _agent_model_name(executor: str | None, model: str | None) -> str:
    if executor and model:
        return f"{executor}/{model}"
    return executor or model or UNAVAILABLE


def _format_number(value: Any) -> str:
    if isinstance(value, float):
        if value.is_integer():
            return str(int(value))
        return f"{value:.2f}".rstrip("0").rstrip(".")
    return str(value)


def _report_warnings(source_counts: dict[str, int]) -> list[str]:
    if any(value > 0 for value in source_counts.values()):
        return [
            "Totals are scoped to explicit records supplied to this projection; expected missing telemetry remains '?' and non-applicable telemetry remains 'n/a'.",
        ]
    return [
        "No explicit execution artifacts were supplied; telemetry is unavailable.",
    ]


def _telemetry_missing_total(gaps: dict[str, Any]) -> int:
    fields = gaps.get("fields") if isinstance(gaps, dict) else None
    if not isinstance(fields, dict):
        return 0
    total = 0
    for summary in fields.values():
        if isinstance(summary, dict) and isinstance(summary.get("missing_records"), int):
            total += summary["missing_records"]
    return total


def _header(title: str, subtitle: str, width: int) -> list[str]:
    inner = width - 2
    return [
        "╔" + "═" * inner + "╗",
        "║" + _fit(title.center(inner), inner) + "║",
        "║" + _fit(subtitle.center(inner), inner) + "║",
        "╚" + "═" * inner + "╝",
    ]


def _executive_lines(report: dict[str, Any], width: int) -> list[str]:
    summary = report.get("executive_summary", {})
    values = {
        "work_units": summary.get("work_units"),
        "completed": "✓ " + str(summary.get("completed")),
        "failed": "✗ " + str(summary.get("failed")),
        "skipped": summary.get("skipped"),
        "blocked": "! " + str(summary.get("blocked")),
        "deferred": summary.get("deferred"),
        "calls": summary.get("agent_model_calls"),
        "main_calls": summary.get("main_thread_calls"),
        "review_calls": summary.get("second_opinion_calls"),
        "retries": summary.get("retries"),
        "tokens": summary.get("total_tokens"),
        "elapsed": summary.get("elapsed_seconds"),
        "missing": summary.get("missing_telemetry_cells"),
    }
    return _key_value_box("Executive Summary", values, width)


def _dashboard_lines(report: dict[str, Any], width: int) -> list[str]:
    summary = report.get("executive_summary", {}) if isinstance(report.get("executive_summary"), dict) else {}
    quality = report.get("quality_malpractice_sabotage_summary", {})
    quality_totals = quality.get("totals", {}) if isinstance(quality, dict) and isinstance(quality.get("totals"), dict) else {}
    evidence = report.get("evidence_disposition_summary", {})
    evidence = evidence if isinstance(evidence, dict) else {}
    workerbees = report.get("workerbee_delegation_summary", {})
    workerbees = workerbees if isinstance(workerbees, dict) else {}
    dispositions = report.get("native_disposition_summary", {})
    dispositions = dispositions if isinstance(dispositions, dict) else {}
    sol_breakfix = report.get("sol_breakfix_summary", {})
    sol_breakfix = sol_breakfix if isinstance(sol_breakfix, dict) else {}
    supervision = report.get("native_supervision_summary", {})
    supervision = supervision if isinstance(supervision, dict) else {}
    gaps = _top_gap_summaries(report.get("telemetry_gaps", {}), limit=2)
    progress = report.get("native_progress_summary", {}) if isinstance(report.get("native_progress_summary"), dict) else {}
    commands = report.get("checked_command_summary", {}) if isinstance(report.get("checked_command_summary"), dict) else {}

    status_line = "  ".join(
        [
            f"Work {_cell(summary.get('work_units'))}",
            f"Done {_cell(summary.get('completed'))}",
            f"Fail {_cell(summary.get('failed'))}",
            f"Block {_cell(summary.get('blocked'))}",
            f"Calls {_cell(summary.get('agent_model_calls'))}",
            f"Missing {_cell(summary.get('missing_telemetry_cells'))}",
        ]
    )
    resource_line = "  ".join(
        [
            f"Tokens {_cell(summary.get('total_tokens'))}",
            f"Elapsed {_cell(summary.get('elapsed_seconds'))}",
            f"Retries {_cell(summary.get('retries'))}",
            f"Main {_cell(summary.get('main_thread_calls'))}",
            f"Review {_cell(summary.get('second_opinion_calls'))}",
        ]
    )
    if gaps:
        gap_line = "Top gaps: " + "; ".join(gaps)
    else:
        gap_line = "Top gaps: none recorded"
    quality_line = "Quality: " + "  ".join(
        [
            f"sabotage {_cell(quality_totals.get('sabotage_concerns'))}",
            f"malpractice {_cell(quality_totals.get('malpractice_concerns'))}",
            f"quarantine {_cell(quality_totals.get('quarantine_recommended'))}",
            f"peer {_cell(quality_totals.get('peer_review_required'))}",
            f"hold {_cell(quality_totals.get('implementation_blocked'))}",
            f"adjudicate {_cell(quality_totals.get('human_adjudication_required'))}",
        ]
    )
    evidence_line = "Evidence: " + "  ".join(
        [
            f"primary {_cell(evidence.get('primary'))}",
            f"salvage {_cell(evidence.get('salvage-only'))}",
            f"hold {_cell(evidence.get('process-hold'))}",
            f"reject {_cell(evidence.get('reject'))}",
            f"quarantine {_cell(evidence.get('quarantine'))}",
            f"unavailable {_cell(evidence.get('unavailable'))}",
        ]
    )
    workerbee_line = "Workerbees: " + "  ".join(
        [
            f"planned {_cell(workerbees.get('planned_records'))}",
            f"actual {_cell(workerbees.get('actual_records'))}",
            f"unfulfilled {_cell(workerbees.get('unfulfilled_lane_count'))}",
            f"status {_cell(workerbees.get('status_summary'))}",
        ]
    )
    disposition_line = "Dispositions: " + "  ".join(
        [
            f"session ok {_cell(dispositions.get('session_accepted'))}",
            f"warn {_cell(dispositions.get('session_warning'))}",
            f"quarantine {_cell(dispositions.get('session_quarantined'))}",
            f"artifact ok {_cell(dispositions.get('artifact_accepted'))}",
            f"validate {_cell(dispositions.get('artifact_validation_required'))}",
            f"adjudicate {_cell(dispositions.get('artifact_adjudication_required'))}",
            f"reject {_cell(dispositions.get('artifact_rejected'))}",
            f"Sol break-fix {_cell(sol_breakfix.get('authorization_count'))}",
        ]
    )
    supervision_line = "Supervision: " + "  ".join(
        [
            f"workers {_cell(supervision.get('workers_supervised'))}",
            f"complete {_cell(supervision.get('completed'))}",
            f"util {_cell(supervision.get('hard_budget_utilization_percent'))}%",
            f"stopped {_cell(supervision.get('interrupted_or_control_lost'))}",
            f"control-loss {_cell(supervision.get('control_loss_rate_percent'))}%",
            f"reserve-stop {_cell(supervision.get('reserve_stops_before_hard_limit'))}",
            f"overrun {_cell(supervision.get('hard_limit_overruns'))}",
            f"calls {_cell(supervision.get('observed_tool_calls'))}/{_cell(supervision.get('planned_tool_calls_hard'))}",
            f"first-poll {_cell(supervision.get('max_dispatch_to_first_poll_ms'))}ms",
            f"max-gap {_cell(supervision.get('max_poll_gap_ms'))}ms",
            f"late {_cell(supervision.get('late_poll_count'))}",
        ]
    )
    autonomy_line = "Autonomy: " + "  ".join([f"records {_cell(progress.get('records'))}", f"realign {_cell(progress.get('outcomes', {}).get('pm-realignment'))}", f"protected {_cell(progress.get('outcomes', {}).get('protected-stop'))}", f"calls {_cell(progress.get('actual_tool_calls'))}/{_cell(progress.get('planned_tool_calls_p90'))}", f"retained {_cell(progress.get('retained_productive_artifacts'))}", f"waste {_cell(progress.get('pure_waste_records'))}"])
    command_line = "Commands: " + "  ".join([f"checked {_cell(commands.get('commands'))}", f"preflight {_cell(commands.get('preflight_passed'))}", f"prevented {_cell(commands.get('quoting_errors_prevented'))}", f"avoided retries {_cell(commands.get('avoided_retry_cycles'))}", f"quarantine {_cell(commands.get('quarantined'))}"])
    next_line = "Hint: import usage sidecars for collectible ? fields; --layout expanded shows lane detail."

    lines = [_section_top("Dashboard", width)]
    for line in [status_line, resource_line, gap_line, quality_line, evidence_line, workerbee_line, supervision_line, disposition_line, autonomy_line, command_line, next_line]:
        lines.extend(_wrapped_box_lines(line, width))
    lines.append(_section_bottom(width))
    return lines


def _top_gap_summaries(gaps: Any, *, limit: int) -> list[str]:
    if not isinstance(gaps, dict):
        return []
    fields = gaps.get("fields")
    if not isinstance(fields, dict):
        return []
    rows: list[tuple[int, str, str, str]] = []
    for field, summary in fields.items():
        if not isinstance(summary, dict):
            continue
        missing = summary.get("missing_records")
        if not isinstance(missing, int) or missing <= 0:
            continue
        sources = ", ".join(_strings(summary.get("missing_source_kinds"))) or UNAVAILABLE
        reasons = _missing_reason_summary(summary.get("missing_reasons"))
        rows.append((missing, str(field), sources, reasons))
    rows.sort(key=lambda row: (-row[0], row[1]))
    return [
        f"{field} {missing} ({sources}/{reasons})"
        for missing, field, sources, reasons in rows[:limit]
    ]


def _missing_reason_summary(reasons: Any, *, limit: int = 2) -> str:
    if not isinstance(reasons, dict) or not reasons:
        return UNAVAILABLE
    pairs = sorted(
        ((count, str(reason)) for reason, count in reasons.items() if isinstance(count, int)),
        key=lambda item: (-item[0], item[1]),
    )
    if not pairs:
        return UNAVAILABLE
    shown = [f"{reason}:{count}" for count, reason in pairs[:limit]]
    if len(pairs) > limit:
        shown.append("more")
    return ",".join(shown)


def _key_value_box(
    title: str,
    mapping: Any,
    width: int,
    *,
    label_overrides: dict[str, str] | None = None,
) -> list[str]:
    if not isinstance(mapping, dict):
        mapping = {}
    labels = label_overrides or {}
    rows = [[labels.get(key, _label(key)), _cell(value)] for key, value in mapping.items()]
    return _table(title, ["Metric", "Value"], rows, width)


def _text_box(title: str, body_lines: list[str], width: int) -> list[str]:
    lines = [_section_top(title, width)]
    for line in body_lines or ["None recorded."]:
        lines.extend(_wrapped_box_lines(line, width))
    lines.append(_section_bottom(width))
    return lines


def _detail_rows(title: str, fields: list[tuple[str, str]], rows: Any, width: int) -> list[str]:
    if not isinstance(rows, list):
        rows = []
    lines = [_section_top(title, width)]
    if not rows:
        lines.extend(_wrapped_box_lines("None recorded.", width))
        lines.append(_section_bottom(width))
        return lines

    for index, row in enumerate(rows, start=1):
        if not isinstance(row, dict):
            row = {}
        for field_index, (label, key) in enumerate(fields):
            prefix = f"{index}. {label}: " if field_index == 0 else f"   {label}: "
            lines.extend(_wrapped_box_lines(prefix + _cell(row.get(key)), width))
        if index < len(rows):
            lines.append("│ " + "".ljust(width - 4) + " │")
    lines.append(_section_bottom(width))
    return lines


def _telemetry_gap_lines(gaps: Any, width: int) -> list[str]:
    if not isinstance(gaps, dict):
        gaps = {}
    fields = gaps.get("fields")
    if not isinstance(fields, dict):
        fields = {}
    rows: list[dict[str, Any]] = []
    for field, summary in sorted(fields.items()):
        if not isinstance(summary, dict):
            continue
        rows.append(
            {
                "field": field,
                "available_records": summary.get("available_records"),
                "missing_records": summary.get("missing_records"),
                "not_applicable_records": summary.get("not_applicable_records"),
                "missing_source_kinds": ", ".join(_strings(summary.get("missing_source_kinds"))),
                "missing_reasons": _missing_reason_summary(summary.get("missing_reasons"), limit=4),
            }
        )
    return _detail_rows(
        "Telemetry Gaps",
        [
            ("Field", "field"),
            ("Available records", "available_records"),
            ("Missing records", "missing_records"),
            ("Not applicable records", "not_applicable_records"),
            ("Missing source kinds", "missing_source_kinds"),
            ("Missing reasons", "missing_reasons"),
        ],
        rows,
        width,
    )


def _wrapped_box_lines(text: str, width: int) -> list[str]:
    inner = width - 4
    wrapper = textwrap.TextWrapper(
        width=inner,
        break_long_words=True,
        break_on_hyphens=False,
        replace_whitespace=False,
        drop_whitespace=False,
    )
    wrapped = wrapper.wrap(text) or [""]
    return ["│ " + line.ljust(inner) + " │" for line in wrapped]


def _table(title: str, headers: list[str], rows: list[list[Any]], width: int) -> list[str]:
    lines = [_section_top(title, width)]
    rows = rows or [["None recorded."] + [""] * (len(headers) - 1)]
    if width < 78 and len(headers) > 2:
        for index, row in enumerate(rows, start=1):
            lines.append("│ " + _fit(f"{index}. {_cell(row[0])}", width - 4).ljust(width - 4) + " │")
            for header, value in zip(headers[1:], row[1:]):
                text = f"   {_label(header)}: {_cell(value)}"
                lines.append("│ " + _fit(text, width - 4).ljust(width - 4) + " │")
        lines.append(_section_bottom(width))
        return lines

    widths = _column_widths(headers, rows, width)
    lines.append(_table_line(headers, widths))
    lines.append(_table_rule(widths))
    for row in rows:
        lines.append(_table_line([_cell(item) for item in row], widths))
    lines.append(_section_bottom(width))
    return lines


def _column_widths(headers: list[str], rows: list[list[Any]], width: int) -> list[int]:
    count = len(headers)
    available = max(count * 4, width - (3 * count + 1))
    widths = [max(4, len(header)) for header in headers]
    for row in rows:
        for index, value in enumerate(row[:count]):
            widths[index] = max(widths[index], min(len(_cell(value)), 32))
    while sum(widths) > available:
        largest = max(range(count), key=lambda index: widths[index])
        if widths[largest] <= 4:
            break
        widths[largest] -= 1
    return widths


def _table_line(values: list[Any], widths: list[int]) -> str:
    cells = [_fit(_cell(value), widths[index]).ljust(widths[index]) for index, value in enumerate(values[: len(widths)])]
    return "│ " + " │ ".join(cells) + " │"


def _table_rule(widths: list[int]) -> str:
    return "├" + "┼".join("─" * (width + 2) for width in widths) + "┤"


def _section_top(title: str, width: int) -> str:
    label = f" {title} "
    if len(label) > width - 2:
        label = " " + _fit(title, width - 4) + " "
    return "╭" + label + "─" * max(0, width - len(label) - 2) + "╮"


def _section_bottom(width: int) -> str:
    return "╰" + "─" * (width - 2) + "╯"


def _cell(value: Any) -> str:
    if value in [None, ""]:
        return UNAVAILABLE
    if isinstance(value, list):
        return ", ".join(str(item) for item in value) or UNAVAILABLE
    if isinstance(value, dict):
        return ", ".join(f"{key}={item}" for key, item in value.items()) or UNAVAILABLE
    return str(value)


def _label(value: Any) -> str:
    text = str(value).replace("_", " ").replace("-", " ").strip()
    return text[:1].upper() + text[1:]


def _fit(text: str, width: int) -> str:
    if width <= 0:
        return ""
    if len(text) <= width:
        return text
    if width <= 3:
        return text[:width]
    return text[: width - 3] + "..."
