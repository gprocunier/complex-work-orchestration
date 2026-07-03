from __future__ import annotations

import json
import math
import shutil
import textwrap
from pathlib import Path
from typing import Any

from .audit import iter_audit_events
from .paths import AUDIT_LOG

UNAVAILABLE = "?"
NOT_APPLICABLE = "n/a"
REPORT_TYPE = "cwo-execution-status-report"
REPORT_VERSION = 3

STATUS_KEYS = ("completed", "failed", "skipped", "blocked", "deferred")
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


def build_execution_status_report(
    *,
    audit_events: list[dict[str, Any]] | None = None,
    acceptance_decisions: list[dict[str, Any]] | None = None,
    return_bundles: list[dict[str, Any]] | None = None,
    readiness_plan: dict[str, Any] | None = None,
    source_files: dict[str, list[str] | str | None] | None = None,
) -> dict[str, Any]:
    events = audit_events or []
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
        "audit_events": len(events),
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
        "expert_profile_utilization": _expert_profile_rows(records),
        "expert_profile_utilization_details": _expert_profile_detail_rows(records),
        "agent_model_utilization": _agent_model_rows(records),
        "agent_model_utilization_details": _agent_model_detail_rows(records),
        "main_thread_architect_productivity": _main_thread_summary(records),
        "second_opinion_review_lane_productivity": _second_opinion_rows(records),
        "second_opinion_review_lane_productivity_details": _second_opinion_detail_rows(records),
        "telemetry_gaps": _telemetry_gaps(records, source_counts),
        "quality_malpractice_sabotage_summary": _quality_summary(records),
        "evidence_disposition_summary": _evidence_disposition_summary(records),
    }
    report["executive_summary"]["missing_telemetry_cells"] = _telemetry_missing_total(report["telemetry_gaps"])
    return report


def render_terminal(report: dict[str, Any], *, width: int | None = None, layout: str = "expanded") -> str:
    term_width = width or shutil.get_terminal_size((100, 24)).columns
    term_width = max(48, min(term_width, 160))
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
    view = {
        "source_kind": source_kind,
        "telemetry_kind": telemetry_kind,
        "bead_id": _clean(record.get("bead_id") or record.get("work_unit_id")),
        "dispatch_id": _clean(record.get("dispatch_id")),
        "event_type": _clean(record.get("event_type")),
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
        "human_adjudication_required": record.get("human_adjudication_required")
        if isinstance(record.get("human_adjudication_required"), bool)
        else None,
        "recommended_disposition": _clean(record.get("recommended_disposition") or record.get("disposition")),
        "recommended_synthesis_use": _synthesis_use(record),
    }
    return view


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
    if event_type == "packet_built":
        return "packet_build"
    if event_type == "return_evaluated":
        return "evaluation"
    if event_type == "chatgpt_browser_dispatch":
        return "browser_dispatch"
    if event_type == "harness_dispatch_rendered":
        return "harness_render"
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
        "browser_confirmation",
        "browser_rehearsal",
        "artifact",
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


def _telemetry_gaps(records: list[dict[str, Any]], source_counts: dict[str, int]) -> dict[str, Any]:
    fields: dict[str, dict[str, Any]] = {}
    for field in TELEMETRY_GAP_KEYS:
        fields[field] = {
            "available_records": 0,
            "missing_records": 0,
            "not_applicable_records": 0,
            "missing_source_kinds": [],
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


def _quality_summary(records: list[dict[str, Any]]) -> dict[str, Any]:
    totals = {
        "low_evidence_quality": 0,
        "sabotage_concerns": 0,
        "malpractice_concerns": 0,
        "quarantine_recommended": 0,
        "peer_review_required": 0,
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
        use = record.get("recommended_synthesis_use")
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
    if record.get("peer_review_required") is True:
        signals.append("peer-review-required")
    if record.get("human_adjudication_required") is True:
        signals.append("architect-adjudication-required")
    return signals


def _status_from_record(record: dict[str, Any]) -> str | None:
    for key in ["work_unit_status", "status"]:
        status = _normalize_status(record.get(key))
        if status:
            return status
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
    if normalized in {"complete", "completed", "success", "succeeded", "accepted", "accept", "done", "passed"}:
        return "completed"
    if normalized in {"fail", "failed", "failure", "error", "errored", "rejected", "reject"}:
        return "failed"
    if normalized in {"skip", "skipped"}:
        return "skipped"
    if normalized in {"block", "blocked", "quarantine", "quarantined", "clarify", "escalate"}:
        return "blocked"
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
    if input_tokens is None and output_tokens is None:
        return None
    return (input_tokens or 0) + (output_tokens or 0)


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


def _key_value_box(title: str, mapping: Any, width: int) -> list[str]:
    if not isinstance(mapping, dict):
        mapping = {}
    rows = [[_label(key), _cell(value)] for key, value in mapping.items()]
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
