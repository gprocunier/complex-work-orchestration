#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

from cwo_core.routing import current_authority_file_arguments

from cwo_core.beads import (
    add_dependency,
    create_bead,
    normalize_dependency_type,
)
from cwo_core.coach import (
    _normalize_workerbee_planned_delegation,
    prompt_coach_level,
    prompt_coach_parallel_workerbee_signal,
)
from cwo_core.epic_convergence import CLOSURE_DISPOSITIONS, evaluate_closure_pressure
from cwo_core.errors import CWOError
from cwo_core.model_identities import LUNA_MODEL, SPARK_MODEL
from cwo_core.risk_features import add_risk_narrowing_arguments, refuse_risk_narrowing_arguments
from cwo_core.routing import (
    classify_work,
    expert_covers,
    expert_review_labels,
    expert_review_lane,
    expert_review_metadata,
    expert_uses_external_contract,
    experts_with_required,
    risk_required_expert_names,
    unmet_required_experts,
    unmet_required_experts_message,
)
from cwo_core.synthesis import synthesis_lane_enabled
from cwo_core.util import read_text_arg, read_text_segments
from cwo_core.waivers import add_waiver_reason_argument, require_waiver_reason
from cwo_core.workgraph_markdown import (
    FIELD_DEPENDS_ON_LANES,
    FIELD_LABELS,
    FIELD_LANE,
    FIELD_SKILLS,
    FIELD_STATUS,
    FIELD_TYPE,
    WORKGRAPH_FALLBACK_MARKER,
)

SPARK_WORKER_MODEL = SPARK_MODEL
SPARK_WORKER_MODE = "implementation-capable"
OPERATIONAL_WORKER_BEAD_LANES = {
    "implementation",
    "validation",
    "publish-sanitization",
    "docs",
    "wrap-up-report",
    "dashboard-report",
}
# Lanes that produce deliverable content. Every final review (validation,
# editorial and pre-release gates, publish sanitization) follows all of them,
# and reporting follows the final reviews, so no check covers stale content.
CONTENT_LANES = ("implementation", "docs")
# Review stages that examine the finished content.
FINAL_REVIEW_STAGES = ("pre-validation", "pre-release")
OPERATIONAL_SPARK_LABELS = ["no-sol-exec", "spark-operative-owner"]
OPERATIONAL_FALLBACK_LABELS = ["no-sol-exec", "fallback-operative-owner"]
SPARK_DISPATCH_METADATA_FIELDS = (
    "status",
    "requested_model",
    "requested_route",
    "failed_native_capability_check",
    "failed_native_capability_check_justification",
)


def _load_optional_json(path: str | None) -> dict[str, Any] | None:
    if not path:
        return None
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise SystemExit(f"{path} must contain a JSON object")
    return value


def body(purpose: str, expected: str) -> str:
    return f"""Purpose:
{purpose}

Scope:
Bounded to this Bead and parent epic.

Inputs:
- Parent epic
- Route result
- Current repository state

Allowed changes:
Only changes required by this lane.

Do not touch:
Secrets, production systems, release tags, destructive commands, or unrelated files.

Expected output:
{expected}

Validation required:
Report commands, evidence, and residual risk.

Escalation triggers:
Architecture change, scope change, security risk, missing context, destructive action, or conflicting evidence.

Handoff format:
Beads comment with findings, validation, and next action.
Before meaningful closure, add a final closure-memory comment with disposition,
who was involved, what changed, why closed, how validated, when closed, where
executed, key decisions, evidence, residual risk, and follow-up."""


def unique_strings(items: list[object]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for item in items:
        if item is None:
            continue
        text = str(item).strip()
        if text and text not in seen:
            seen.add(text)
            result.append(text)
    return result


def _route_prefers_spark_operational(route: dict[str, Any]) -> bool:
    planned = route.get("workerbee_planned_delegation")
    if not isinstance(planned, dict):
        return False
    return (
        bool(planned.get("spark_operational_worker"))
        and str(planned.get("mode") or "") == SPARK_WORKER_MODE
        and str(planned.get("model") or "") == SPARK_WORKER_MODEL
    )


def _route_spark_dispatch_status(route: dict[str, Any]) -> str:
    planned = route.get("workerbee_planned_delegation")
    if not isinstance(planned, dict):
        return ""
    spark_dispatch = planned.get("spark_dispatch")
    if not isinstance(spark_dispatch, dict):
        return ""
    return str(spark_dispatch.get("status") or "").strip().lower()


def _route_prefers_native_spark_operational(route: dict[str, Any]) -> bool:
    if not _route_prefers_spark_operational(route):
        return False
    if _route_has_spark_hard_stop(route):
        return False
    dispatch_status = _route_spark_dispatch_status(route)
    return dispatch_status == "native-first"


def _route_prefers_native_operational(route: dict[str, Any]) -> bool:
    planned = route.get("workerbee_planned_delegation")
    operative = route.get("operative_route")
    if not isinstance(operative, dict):
        return _route_prefers_native_spark_operational(route)
    return bool(
        isinstance(planned, dict)
        and str(planned.get("mode") or "") == SPARK_WORKER_MODE
        and operative.get("dispatch_authorized") is True
        and operative.get("selected_model")
    )


def _route_has_spark_hard_stop(route: dict[str, Any]) -> bool:
    planned = route.get("workerbee_planned_delegation")
    if not isinstance(planned, dict):
        return False
    operative = route.get("operative_route")
    operative_blocked = bool(
        isinstance(operative, dict)
        and operative.get("availability_evidence")
        and operative.get("dispatch_authorized") is not True
    )
    return (
        bool(planned.get("hard_stop"))
        or bool(planned.get("registry_tool_mismatch"))
        or _route_spark_dispatch_status(route) == "hard-stop"
        or operative_blocked
    )


def _sanitize_workerbee_spark_dispatch(value: object) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    return {
        field: value[field]
        for field in SPARK_DISPATCH_METADATA_FIELDS
        if field in value
    }


def _route_planned_workerbee_delegation(
    route: dict[str, Any], lane: str
) -> dict[str, Any]:
    planned = route.get("workerbee_planned_delegation")
    if not isinstance(planned, dict):
        lanes: list[str] = []
        return {
            "workerbee_planned_delegation": {
                "mode": "none",
                "model": None,
                "lanes": lanes,
            },
            "workerbee_planned_mode": "none",
            "workerbee_planned_model": "",
            "workerbee_planned_lanes": lanes,
            "workerbee_operational_owner": "",
            "workerbee_registry_tool_mismatch": False,
            "spark_operational_worker": False,
            "workerbee_spark_dispatch": {},
        }
    spark_dispatch = _sanitize_workerbee_spark_dispatch(planned.get("spark_dispatch"))
    if _route_has_spark_hard_stop(route):
        lanes: list[str] = []
        return {
            "workerbee_planned_delegation": {
                "mode": "blocked",
                "model": None,
                "lanes": lanes,
            },
            "workerbee_planned_mode": "blocked",
            "workerbee_planned_model": "",
            "workerbee_planned_lanes": lanes,
            "workerbee_operational_owner": "",
            "workerbee_registry_tool_mismatch": bool(planned.get("registry_tool_mismatch")),
            "spark_operational_worker": False,
            "workerbee_spark_dispatch": spark_dispatch,
        }
    lanes = unique_strings([item for item in planned.get("lanes", [])])
    mode = str(planned.get("mode") or "none")
    model = planned.get("model")
    model = model if not (model is not None and not str(model).strip()) else None
    if _route_prefers_native_operational(route):
        is_operative_lane = lane in OPERATIONAL_WORKER_BEAD_LANES
    else:
        is_operative_lane = False
    if is_operative_lane:
        mode = SPARK_WORKER_MODE
        operative = route.get("operative_route")
        model = operative.get("selected_model") if isinstance(operative, dict) else SPARK_WORKER_MODEL
    if model is None:
        workerbee_operational_owner = ""
    else:
        if is_operative_lane and model == SPARK_WORKER_MODEL:
            workerbee_operational_owner = "spark"
        elif is_operative_lane:
            operative = route.get("operative_route")
            selected_executor = operative.get("selected_executor") if isinstance(operative, dict) else None
            workerbee_operational_owner = f"fallback:{selected_executor or model}"
        else:
            workerbee_operational_owner = ""
    return {
        "workerbee_planned_delegation": {
            "mode": mode,
            "model": model,
            "lanes": lanes,
        },
        "workerbee_planned_mode": mode,
        "workerbee_planned_model": str(model) if model is not None else "",
        "workerbee_planned_lanes": lanes,
        "workerbee_operational_owner": workerbee_operational_owner,
        "workerbee_registry_tool_mismatch": bool(planned.get("registry_tool_mismatch")),
        "spark_operational_worker": bool(planned.get("spark_operational_worker")),
        "workerbee_spark_dispatch": spark_dispatch,
    }


def bullet_list(items: list[object], fallback: str) -> str:
    values = unique_strings(items)
    if not values:
        values = [fallback]
    return "\n".join(f"- {item}" for item in values)


def route_notes(route: dict[str, Any]) -> str:
    experts = [str(item.get("name")) for item in experts_with_required(route, 5) if item.get("name")]
    lines = [
        f"Route: {route.get('route')}",
        f"Task class: {route.get('task_class')}",
        f"Risk: {route.get('risk_level')}",
        f"Data sensitivity: {route.get('data_sensitivity')}",
        f"Data sensitivity source: {route.get('data_sensitivity_source')}",
        f"Share boundary: {route.get('share_boundary')}",
        f"Execution environment: {route.get('execution_environment')}",
        f"Architecture authority: {route.get('architecture_authority')}",
        f"Project manager executor: {route.get('project_manager_executor')}",
        f"Primary architect executor: {route.get('primary_architect_executor')}",
        f"Architecture counter-review executor: {route.get('architecture_counter_review_executor')}",
        f"Scaffold size: {route.get('scaffold_size', 'full')}",
        f"Beads context depth: {route.get('beads_context_depth', 'focused')}",
        f"Beads context source: {route.get('beads_context_depth_source', 'autosized')}",
        f"Recommended executor: {route.get('recommended_executor')}",
        f"Peer review required: {bool(route.get('peer_review_required'))}",
        f"Provider conflict detected: {bool(route.get('provider_conflict_detected'))}",
        "Selected experts: " + (", ".join(experts) if experts else "none"),
    ]
    required = risk_required_expert_names(route)
    if required:
        lines.append("Risk-required experts: " + ", ".join(required))
    synthesis = route.get("model_synthesis") if isinstance(route.get("model_synthesis"), dict) else None
    if synthesis and synthesis.get("recommended_mode") != "none":
        conflict_flags = synthesis.get("provider_conflict_flags") or []
        partial_policy = synthesis.get("partial_synthesis_policy") or {}
        lines.extend(
            [
                f"Model synthesis: {synthesis.get('recommended_mode')} active={bool(synthesis.get('active'))}",
                f"Synthesis pattern: {synthesis.get('synthesis_pattern')}",
                f"Synthesis owner: {synthesis.get('synthesis_owner')}",
                f"Synthesis provider conflict flags: {len(conflict_flags)}",
                f"Synthesis partial policy: allow_partial={bool(partial_policy.get('allow_partial'))}",
            ]
        )
    if route.get("blocking_review_required"):
        lines.extend(
            [
                f"Blocking review gate: {route.get('blocking_review_gate')}",
                f"Blocking review active: {bool(route.get('blocking_review_active'))}",
                f"Blocking review executor: {route.get('blocking_review_executor')}",
                f"Blocking review job: {route.get('blocking_review_job_description_label')}",
                f"Blocking review failure behavior: {route.get('blocking_review_failure_behavior')}",
            ]
        )
    if isinstance(route.get("workerbee_planned_delegation"), dict):
        planned = route["workerbee_planned_delegation"]
        mode = str(planned.get("mode") or "none")
        model = str(planned.get("model") or "unassigned")
        lanes = ", ".join(unique_strings([item for item in planned.get("lanes", [])])) or "none"
        lines.append(f"Planned workerbee delegation: mode={mode}, model={model}, lanes=[{lanes}]")
        spark_dispatch = planned.get("spark_dispatch")
        if not isinstance(spark_dispatch, dict):
            spark_dispatch = planned.get("workerbee_spark_dispatch")
        if not isinstance(spark_dispatch, dict):
            spark_dispatch = {}
        if isinstance(spark_dispatch, dict):
            lines.append(
                "Spark dispatch metadata: "
                f"status={spark_dispatch.get('status', 'not-applicable')} | "
                f"requested_route={spark_dispatch.get('requested_route', '') or 'none'} | "
                f"requested_model={spark_dispatch.get('requested_model', '') or ''} | "
                f"failed_check={spark_dispatch.get('failed_native_capability_check', '') or ''}"
            )
    operative = route.get("operative_route")
    if isinstance(operative, dict):
        lines.extend(
            [
                f"Operative primary: {operative.get('primary_model')} via {operative.get('primary_executor')}",
                f"Operative availability: {operative.get('availability_status')} ({operative.get('availability_reason')})",
                f"Operative selected: {operative.get('selected_model') or 'none'} via {operative.get('selection_source') or 'none'}",
                f"Operative dispatch authorized: {bool(operative.get('dispatch_authorized'))}",
            ]
        )
    return "\n".join(lines)


def _planned_workerbee_metadata(route: dict[str, Any]) -> dict[str, Any]:
    return _route_planned_workerbee_delegation(route, "non-operational")


def _lane_metadata(
    route: dict[str, Any], lane: str, metadata: dict[str, Any] | None = None
) -> dict[str, Any]:
    merged = dict(metadata or {})
    merged.update(_route_planned_workerbee_delegation(route, lane))
    closure_pressure = route.get("closure_pressure")
    if not isinstance(closure_pressure, dict):
        closure_pressure = {}
    merged["closure_pressure"] = closure_pressure
    merged["closure_pressure_active"] = bool(closure_pressure.get("active"))
    merged["routine_repair_child_forbidden"] = bool(closure_pressure.get("active"))
    merged["dependency_semantics_version"] = 1
    merged["ready_set_admission_required"] = lane in OPERATIONAL_WORKER_BEAD_LANES
    merged["operative_route"] = route.get("operative_route", {})
    merged["critic_route"] = route.get("critic_route", {})
    merged["peer_review_route"] = route.get("peer_review_route", {})
    operative = route.get("operative_route") if isinstance(route.get("operative_route"), dict) else {}
    if operative.get("version") == 3:
        merged.update({
            "operative_routing_version": 3,
            "operative_dispatch_authorized": operative.get("dispatch_authorized") is True,
            "operative_primary_model": LUNA_MODEL,
            "operative_selected_model": operative.get("selected_model"),
            "operative_selection_source": "task-sized-qualified-luna-first",
            "operative_recommended_model": operative.get("selected_model"),
            "operative_recommended_executor": operative.get("selected_executor"),
            "operative_work_estimate_sha256": operative.get("work_estimate_sha256"),
            "operative_fit_record_sha256": operative.get("fit_record_sha256"),
            "operative_qualification_sha256": operative.get("qualification_sha256"),
            "operative_policy_sha256": operative.get("policy_sha256"),
            "operative_aggregate_budget": operative.get("aggregate_budget"),
            "operative_stop_reason": operative.get("stop_reason"),
        })
        return merged
    merged["operative_primary_model"] = operative.get("primary_model")
    merged["operative_selected_model"] = operative.get("selected_model")
    merged["operative_selection_source"] = operative.get("selection_source")
    merged["operative_recommended_model"] = operative.get("recommended_model")
    merged["operative_recommended_executor"] = operative.get("recommended_executor")
    merged["operative_work_estimate_sha256"] = operative.get("work_estimate_sha256")
    merged["operative_fallback_fit_sha256"] = operative.get("fallback_fit_sha256")
    merged["operative_capability_evidence_sha256"] = operative.get("capability_evidence_sha256")
    merged["operative_policy_sha256"] = operative.get("policy_sha256")
    merged["operative_aggregate_budget"] = operative.get("aggregate_budget", {})
    merged["operative_fallback_selection"] = (
        operative.get("fallback", {}).get("selection")
        if isinstance(operative.get("fallback"), dict)
        else None
    )
    fallback_selection = (
        merged["operative_fallback_selection"]
        if isinstance(merged["operative_fallback_selection"], dict)
        else {}
    )
    merged["operative_selection_scope"] = fallback_selection.get("scope")
    merged["operative_selection_expires_when"] = fallback_selection.get("expires_when")
    selected_candidate = next(
        (
            item
            for item in operative.get("fallback", {}).get("candidates", [])
            if isinstance(item, dict)
            and item.get("model") == operative.get("selected_model")
            and item.get("executor") == operative.get("selected_executor")
        ),
        {},
    )
    merged["operative_task_fit_warning"] = selected_candidate.get("task_fit_warning")
    merged["operative_task_fit_acknowledgement_required"] = selected_candidate.get(
        "acknowledgement_required", False
    )
    return merged


def _normalize_closure_pressure(route: dict[str, Any]) -> dict[str, Any]:
    source = route.get("closure_pressure")
    if source is None:
        source = {}
    if not isinstance(source, dict):
        raise TypeError("route['closure_pressure'] must be a mapping when set")

    raw_active = source.get("active", False)
    if not isinstance(raw_active, bool):
        raise TypeError("route['closure_pressure'].active must be boolean when set")
    active = bool(raw_active)
    action = source.get("action") or "scaffold-workgraph"
    if not isinstance(action, str) or not action.strip():
        raise TypeError("route['closure_pressure'].action must be a non-empty string when set")
    action = action.strip()
    raw_disposition = source.get("disposition")
    if raw_disposition is not None and not isinstance(raw_disposition, str):
        raise TypeError(
            "route['closure_pressure'].disposition must be canonical string when set"
        )
    disposition = raw_disposition
    decision = evaluate_closure_pressure(active, action, disposition)
    return {
        **decision,
        "closure_pressure_active": bool(decision["active"]),
        "routine_repair_child_forbidden": bool(decision["active"]),
    }


def _lane_labels(route: dict[str, Any], lane: str, labels: list[str]) -> list[str]:
    if _route_has_spark_hard_stop(route):
        return unique_strings([label for label in labels if label not in OPERATIONAL_SPARK_LABELS])
    lane_labels = list(labels)
    if _route_prefers_native_operational(route) and lane in OPERATIONAL_WORKER_BEAD_LANES:
        operative = route.get("operative_route")
        if isinstance(operative, dict) and operative.get("selected_model") == SPARK_WORKER_MODEL:
            lane_labels.extend(OPERATIONAL_SPARK_LABELS)
        else:
            lane_labels.extend(OPERATIONAL_FALLBACK_LABELS)
    return unique_strings(lane_labels)


LANE_FIELDS: dict[str, dict[str, object]] = {
    "architect": {
        "skills": ["architecture", "complex-work-orchestration", "beads"],
        "acceptance": "Architecture boundaries, decomposition, acceptance gates, and escalation triggers are explicit.",
        "design": "Frame the work before implementation and keep final architecture and release judgment with the architect.",
    },
    "pm": {
        "skills": ["project-management", "beads", "handoff"],
        "acceptance": "Dependencies, assignment status, stale work, evidence, and handoff state are current in Beads.",
        "design": "Coordinate the graph without taking architecture or implementation authority.",
    },
    "implementation": {
        "skills": ["implementation", "python", "complex-work-orchestration"],
        "acceptance": "The scoped code change is complete, compatible with existing behavior, and ready for validation.",
        "design": "Make the smallest code changes needed for the accepted design and preserve established interfaces.",
    },
    "validation": {
        "skills": ["validation", "testing", "repository-validation"],
        "acceptance": "Focused tests, repository validation, and residual-risk evidence are recorded.",
        "design": "Validate behavior from the public helper interface and generated Beads output.",
    },
    "publish-sanitization": {
        "skills": ["publish-sanitization", "public-artifact-review", "validation"],
        "acceptance": "Published artifacts were inspected and are free of local-only, transient, duplicate, circular, or non-fresh-deploy content; anything found went back to the content lanes and was checked again.",
        "design": "Inspect only, after all content work, validation and any editorial gate, before push, release, tag, or public handoff. Change nothing in this lane: a removal or fix goes back to implementation or docs, and the checks that covered that content run again. The result covers only the checked content.",
    },
    "docs": {
        "skills": ["documentation", "operator-guides"],
        "acceptance": "Docs and examples match the implemented behavior, and every documentation change is finished before validation and the final editorial and publication checks.",
        "design": "Keep the skill entrypoint concise and place durable operator detail in README and references. This lane produces content; handoff reporting belongs to the wrap-up report.",
    },
    "wrap-up-report": {
        "skills": ["run-readiness", "wrap-up-status", "handoff", "operator-calibrated-execution"],
        "acceptance": "Wrap-up/status projection and handoff are rendered from accepted evidence after the final checks, and record validation, residual risk, and next-version deferrals.",
        "design": "Use Beads/readiness evidence as source of truth; do not invent missing telemetry or closeout claims. Report only: a relevant change to code, docs or examples found here reopens that work and the checks and approvals that covered it.",
    },
    "dashboard-report": {
        "skills": ["execution-status-report", "telemetry", "dashboard", "operator-calibrated-execution"],
        "acceptance": "Execution status dashboard and expanded layout are rendered with lane/model telemetry gaps shown as ? or n/a.",
        "design": "Render compact terminal status first, then expanded output for long expert, role, and agent/model identifiers.",
    },
    "final-dispatch": {
        "skills": ["contractor-control", "beads", "packet-dispatch"],
        "acceptance": "Final review packets are built from the finished content, within the route's disclosure boundary, opt-in basis, and no-codex-exec handling.",
        "design": "Dispatch final-stage reviews only after implementation and docs are complete; a later relevant change needs a new final review.",
    },
    "final-peer-review": {
        "skills": ["peer-review", "contractor-control", "acceptance"],
        "acceptance": "Independent peer-review disposition of the final-stage review returns is recorded before they are evaluated.",
        "design": "Apply the route's peer-review requirement to final-stage returns as to earlier ones, isolated from normal Codex pickup.",
    },
    "final-evaluation": {
        "skills": ["evaluation", "acceptance", "contractor-control"],
        "acceptance": "Final-stage review returns about the finished content are scored and dispositioned before validation.",
        "design": "Use evaluator outputs as evidence for architect adjudication, not as direct authority.",
    },
    "final-adjudication": {
        "skills": ["architecture", "adjudication", "acceptance"],
        "acceptance": "The architect accepts, rejects, or quarantines final-stage review findings; a required fix reopens implementation or docs and the checks that covered them.",
        "design": "Final decision on final-stage reviews stays with the architect, after their evaluation and before validation.",
    },
    "external-dispatch": {
        "skills": ["contractor-control", "beads", "packet-dispatch"],
        "acceptance": "Dispatch prerequisites, share boundary, opt-in basis, and no-codex-exec handling are explicit.",
        "design": "Prepare contract work only after policy gates and user opt-in allow it.",
    },
    "peer-review": {
        "skills": ["peer-review", "contractor-control", "acceptance"],
        "acceptance": "Independent peer-review disposition is recorded before contractor/local-worker findings influence implementation.",
        "design": "Keep peer-review work isolated from normal Codex pickup and require architect adjudication.",
    },
    "evaluation": {
        "skills": ["evaluation", "acceptance", "contractor-control"],
        "acceptance": "Contractor or local-worker returns are scored and dispositioned before follow-up implementation work is created.",
        "design": "Use evaluator outputs as evidence for architect adjudication, not as direct implementation authority.",
    },
    "model-synthesis": {
        "skills": ["synthesis", "adjudication", "contractor-control", "beads"],
        "acceptance": "Consensus, material disagreements, unsupported claims, risk deltas, input evaluator dispositions, provider conflict flags, partial or missing lane summaries, evidence provenance, and recommended plan revisions are recorded.",
        "design": "Preserve independent model outputs as evidence, synthesize only after the required review/evaluation gates, carry rejected/quarantined/missing inputs as dispositions, and leave final authority with architect adjudication.",
    },
    "architect-adjudication": {
        "skills": ["architecture", "adjudication", "acceptance"],
        "acceptance": "The architect accepts, rejects, quarantines, or converts findings into normal follow-up Beads.",
        "design": "Final decision stays with the architect after evaluation and any peer-review gates.",
    },
}


def lane_fields(
    lane: str, route: dict[str, Any], metadata: dict[str, Any] | None = None
) -> dict[str, object]:
    defaults = {
        "skills": ["complex-work-orchestration", "beads"],
        "acceptance": f"The {lane} lane is complete, evidenced, validated as applicable, and ready for handoff.",
        "design": f"Execute the {lane} lane within the parent epic boundary and escalate scope or risk changes.",
    }
    fields = {**defaults, **LANE_FIELDS.get(lane, {})}
    return {
        "skills": unique_strings([*fields["skills"], "beads"]),
        "acceptance": str(fields["acceptance"]),
        "design": str(fields["design"]),
        "notes": route_notes(route),
        "metadata": _lane_metadata(route, lane, metadata),
    }


def expert_fields(expert: dict[str, Any], route: dict[str, Any]) -> dict[str, object]:
    acceptance_checks = expert.get("acceptance_checks", [])
    output_contract = expert.get("output_contract", [])
    display_name = str(expert.get("display_name") or expert.get("name") or "Expert reviewer")
    job_label = str(expert.get("job_description_label", "contract-jd-general-reasoning"))
    stage = str(expert.get("review_stage", "pre-implementation"))
    notes = route_notes(route) + "\nOutput contract:\n" + bullet_list(
        list(output_contract), "Findings, confidence, residual risk, and recommended next Beads."
    )
    contract = expert.get("contractor_contract") if isinstance(expert.get("contractor_contract"), dict) else {}
    if contract.get("manual_command"):
        notes += f"\nManual dispatch command:\n- {contract['manual_command']}"
    if contract.get("claude_effort"):
        notes += f"\nClaude effort:\n- {contract['claude_effort']}"
    return {
        "skills": unique_strings(
            [
                "expert-review",
                "complex-work-orchestration",
                "beads",
                expert.get("discipline"),
                expert.get("name"),
                job_label,
            ]
        ),
        "acceptance": "Review is complete when these checks pass:\n"
        + bullet_list(list(acceptance_checks), "Findings are scoped, evidenced, and actionable."),
        "design": (
            f"Apply the {display_name} lens during {stage}. "
            f"Honor job-description label {job_label}, share boundary {route.get('share_boundary')}, "
            "and the Codex pickup rule recorded in metadata."
        ),
        "notes": notes,
    }


def architecture_critic_experts(route: dict[str, Any]) -> list[dict[str, Any]]:
    contracts = route.get("architecture_critic_contracts", [])
    if not isinstance(contracts, list) or not contracts:
        return []
    base = next(
        (expert for expert in route.get("ranked_experts", []) if expert.get("name") == "architecture"),
        {
            "display_name": "Architecture Distinguished Engineer",
            "discipline": "architecture",
            "persona_file": "experts/architecture.md",
            "job_description_label": "contract-jd-architecture-reasoning",
            "task_class": "architecture-review",
            "review_stage": "pre-implementation",
            "output_contract": [
                "target boundaries",
                "tradeoffs",
                "rejected alternatives",
                "migration risk",
                "rollback path",
                "follow-up beads",
            ],
            "acceptance_checks": [
                "boundary impact is explicit",
                "migration path is reversible",
                "compatibility risk is named",
            ],
            "escalation_rules": [
                "system-wide redesign",
                "public contract change",
                "persistent state migration",
                "release blocker",
            ],
        },
    )
    experts: list[dict[str, Any]] = []
    for contract in contracts:
        if not isinstance(contract, dict):
            continue
        executor = str(contract.get("executor") or "")
        if not executor:
            continue
        slug = re.sub(r"[^a-z0-9]+", "-", executor.lower()).strip("-")
        expert = dict(base)
        expert.update(
            {
                "name": f"architecture-critic-{slug}",
                "display_name": f"{contract.get('display_name', executor)}",
                "preferred_executors": [executor],
                "recommended_executor": executor,
                "selected_executor": contract.get("selected_executor"),
                "executor_policy_violations": [],
                "contractor_contract": contract,
                # A named critic stands in for the architecture review it replaces.
                "covers_expert": "architecture",
            }
        )
        experts.append(expert)
    return experts


def selected_source_experts(route: dict[str, Any], scaffold_size: str) -> list[dict[str, Any]]:
    """The experts that get review lanes. Tight scaffolding limits optional fan-out, never a risk-required expert."""
    critic_contracts = route.get("architecture_critic_contracts", [])
    source_experts = [
        expert
        for expert in route.get("ranked_experts", [])
        if not (critic_contracts and expert.get("name") == "architecture" and expert_uses_external_contract(expert))
    ]
    source_experts.extend(architecture_critic_experts(route))
    required = set(risk_required_expert_names(route))
    if scaffold_size != "tight":
        selected = source_experts
    else:
        primary_name = source_experts[0].get("name") if source_experts else None
        selected = []
        seen_lanes: set[str] = set()
        for expert in source_experts:
            lane = expert_review_lane(expert)
            if lane in seen_lanes:
                continue
            metadata = expert_review_metadata(expert, route)
            is_primary = bool(primary_name and expert.get("name") == primary_name)
            is_required_gate = bool(metadata.get("validation_gate_required"))
            is_named_critic = bool(expert.get("contractor_contract"))
            is_risk_required = expert.get("name") in required
            if is_primary or is_required_gate or is_named_critic or is_risk_required:
                selected.append(expert)
                seen_lanes.add(lane)
        if not selected and source_experts:
            selected.append(source_experts[0])
    # A risk-required expert that an earlier filter removed and nothing stands in for comes back.
    covered = set().union(*(expert_covers(expert) for expert in selected)) if selected else set()
    selected_lanes = {expert_review_lane(expert) for expert in selected}
    for expert in route.get("ranked_experts", []):
        name = expert.get("name")
        if name in required and name not in covered and expert_review_lane(expert) not in selected_lanes:
            selected = [*selected, expert]
            covered.add(str(name))
            selected_lanes.add(expert_review_lane(expert))
    return selected


def planned_graph(title: str, route: dict[str, Any], scaffold_size: str = "full") -> list[dict[str, Any]]:
    if scaffold_size not in {"full", "tight"}:
        raise ValueError("scaffold_size must be 'full' or 'tight'")
    route = {**route, "scaffold_size": scaffold_size}
    closure_pressure = _normalize_closure_pressure(route)
    if not closure_pressure["allowed"]:
        raise ValueError(f"closure-pressure blocked: {closure_pressure['reason']}")
    route = {**route, "closure_pressure": closure_pressure}
    expert_items: list[dict[str, Any]] = []
    acceptance_review_lanes: list[str] = []
    final_acceptance_lanes: list[str] = []
    final_dispatch_required = False
    implementation_blocker_lanes: list[str] = []
    validation_blocker_lanes: list[str] = []
    editor_gate_lanes: list[str] = []

    source_experts = selected_source_experts(route, scaffold_size)
    unmet = unmet_required_experts(route, source_experts)
    if unmet:
        raise ValueError(unmet_required_experts_message(unmet) + "; no work graph planned")
    for expert in source_experts:
        lane = expert_review_lane(expert)
        metadata = expert_review_metadata(expert, route)
        depends_on = ["architect"]
        pickup_forbidden = metadata.get("codex_pickup") == "forbidden"
        final_stage = bool(metadata.get("validation_gate_required")) or expert.get("review_stage") in FINAL_REVIEW_STAGES
        if metadata.get("acceptance_bead_required") and final_stage:
            # A final-stage review routed through an acceptance bead examines
            # the finished content, so it is dispatched, evaluated and
            # adjudicated after implementation and docs, before validation.
            final_acceptance_lanes.append(lane)
            depends_on.extend(CONTENT_LANES)
            if pickup_forbidden:
                depends_on.append("final-dispatch")
                final_dispatch_required = True
        else:
            if pickup_forbidden:
                depends_on.append("external-dispatch")
            if metadata.get("acceptance_bead_required"):
                acceptance_review_lanes.append(lane)
            elif metadata.get("validation_gate_required"):
                editor_gate_lanes.append(lane)
                validation_blocker_lanes.append(lane)
                depends_on.extend(CONTENT_LANES)
            elif expert.get("review_stage") in ["pre-implementation", "implementation-review"]:
                implementation_blocker_lanes.append(lane)
            elif expert.get("review_stage") in FINAL_REVIEW_STAGES:
                validation_blocker_lanes.append(lane)
                depends_on.extend(CONTENT_LANES)

        expert_items.append(
            {
                "title": f"{expert['display_name']}: {title}",
                "type": "task",
                "lane": lane,
                "labels": expert_review_labels(expert, route),
                "depends_on_lanes": depends_on,
                **lane_fields(lane, route, metadata=metadata),
                **expert_fields(expert, route),
            }
        )

    peer_review_required = bool(route.get("peer_review_required"))
    if final_acceptance_lanes:
        validation_blocker_lanes.append("final-adjudication")
    publish_sanitization_required = bool(route.get("editor_gate_required"))
    model_synthesis_required = synthesis_lane_enabled(route.get("model_synthesis"))
    needs_external_acceptance = bool(acceptance_review_lanes) or route.get("route") in ["external-contract", "local-worker"]
    needs_internal_acceptance = bool(
        not needs_external_acceptance
        and (route.get("architect_adjudication_required") or peer_review_required)
    )
    graph: list[dict[str, Any]] = [
        {
            "title": title,
            "type": "epic",
            "labels": ["orchestration", "policy-routed"],
            "metadata": {
                "orchestration_route": route,
                "closure_pressure": closure_pressure,
                "closure_pressure_active": bool(closure_pressure.get("active")),
                "routine_repair_child_forbidden": bool(closure_pressure.get("active")),
            },
            "skills": ["complex-work-orchestration", "architecture", "project-management", "beads", "validation"],
            "acceptance": "All lane work is complete, validated, evaluated, adjudicated, and ready for handoff.",
            "design": "Policy-routed epic that coordinates architect, PM, workerbee, review, validation, and handoff lanes through Beads.",
            "notes": route_notes(route),
        },
        {
            "title": f"Architect frame: {title}",
            "type": "task",
            "lane": "architect",
            "labels": ["architect", "framing"],
            **lane_fields("architect", route),
        },
        {
            "title": f"PM coordinate: {title}",
            "type": "task",
            "lane": "pm",
            "labels": ["pm", "coordination"],
            **lane_fields("pm", route),
        },
        {
            "title": f"Implement: {title}",
            "type": "task",
            "lane": "implementation",
            "labels": _lane_labels(
                route,
                "implementation",
                ["workerbee", "implementation"],
            ),
            "depends_on_lanes": ["architect", *implementation_blocker_lanes],
            **lane_fields("implementation", route),
        },
        {
            "title": f"Docs: {title}",
            "type": "task",
            "lane": "docs",
            "labels": _lane_labels(
                route,
                "docs",
                ["docs"],
            ),
            "depends_on_lanes": ["implementation"],
            **lane_fields("docs", route),
        },
        {
            "title": f"Validate: {title}",
            "type": "task",
            "lane": "validation",
            "labels": _lane_labels(
                route,
                "validation",
                ["workerbee", "validation"],
            ),
            "depends_on_lanes": [*CONTENT_LANES, *validation_blocker_lanes],
            **lane_fields("validation", route),
        },
    ]
    final_check_lane = "validation"
    if publish_sanitization_required:
        graph.append(
            {
                "title": f"Publish sanitization: {title}",
                "type": "task",
                "lane": "publish-sanitization",
                "labels": _lane_labels(
                    route,
                    "publish-sanitization",
                    ["publish-sanitization", "public-artifact-review"],
                ),
                "depends_on_lanes": ["validation", *editor_gate_lanes],
                **lane_fields("publish-sanitization", route, metadata={"inspect_only": True}),
            }
        )
        final_check_lane = "publish-sanitization"

    graph.extend(
        [
            {
                "title": f"Wrap-up report and handoff: {title}",
                "type": "task",
                "lane": "wrap-up-report",
                "labels": _lane_labels(
                    route,
                    "wrap-up-report",
                    ["reporting", "wrap-up-status", "handoff"],
                ),
                "depends_on_lanes": [final_check_lane],
                **lane_fields("wrap-up-report", route, metadata={"inspect_only": True}),
            },
            {
                "title": f"Dashboard report: {title}",
                "type": "task",
                "lane": "dashboard-report",
                "labels": _lane_labels(
                    route,
                    "dashboard-report",
                    ["reporting", "dashboard"],
                ),
                "depends_on_lanes": ["validation"],
                **lane_fields("dashboard-report", route),
            },
        ]
    )
    if final_acceptance_lanes:
        final_lanes: list[dict[str, Any]] = []
        if final_dispatch_required:
            final_lanes.append(
                {
                    "title": f"Dispatch final reviews: {title}",
                    "type": "task",
                    "lane": "final-dispatch",
                    "labels": unique_strings(["dispatch", "final-review", route["route"], *(route.get("guard_labels") or [])]),
                    "depends_on_lanes": list(CONTENT_LANES),
                    **lane_fields(
                        "final-dispatch",
                        route,
                        metadata={
                            "codex_pickup": "forbidden",
                            "guard_labels": list(route.get("guard_labels") or []),
                            "route": route.get("route"),
                            "share_boundary": route.get("share_boundary"),
                            "architect_review_required": True,
                        },
                    ),
                }
            )
        final_evaluation_dependencies = list(final_acceptance_lanes)
        if peer_review_required:
            final_lanes.append(
                {
                    "title": f"Peer review final returns: {title}",
                    "type": "task",
                    "lane": "final-peer-review",
                    "labels": [
                        *(route.get("peer_review_labels")
                          or ["peer-review-required", "contractor-peer-review", "sabotage-review", "no-codex-exec"]),
                        "contract-jd-peer-review",
                        "final-review",
                    ],
                    "depends_on_lanes": list(final_acceptance_lanes),
                    **lane_fields(
                        "final-peer-review",
                        route,
                        metadata={
                            "job_description_label": "contract-jd-peer-review",
                            "peer_review_count": route.get("peer_review_count", 1),
                            "provider_diversity_required": route.get("provider_diversity_required", True),
                            "provider_conflict_domains": route.get("provider_conflict_domains", []),
                            "local_secure_review_executor": route.get("local_secure_review_executor"),
                            "codex_pickup": "forbidden",
                            "architect_review_required": True,
                        },
                    ),
                }
            )
            final_evaluation_dependencies = ["final-peer-review"]
        final_lanes.extend(
            [
                {
                    "title": f"Evaluate final reviews: {title}",
                    "type": "task",
                    "lane": "final-evaluation",
                    "labels": ["evaluation", "contractor-evaluator", "final-review"],
                    "depends_on_lanes": final_evaluation_dependencies,
                    **lane_fields("final-evaluation", route),
                },
                {
                    "title": f"Architect adjudication of final reviews: {title}",
                    "type": "task",
                    "lane": "final-adjudication",
                    "labels": ["architect", "adjudication", "final-review"],
                    "depends_on_lanes": ["final-evaluation"],
                    **lane_fields("final-adjudication", route),
                },
            ]
        )
        graph.extend(final_lanes)
    if needs_external_acceptance:
        peer_review_lanes = ["peer-review"] if peer_review_required else []
        dispatch_guard_labels = list(route.get("guard_labels") or [])
        dispatch_metadata = {
            "codex_pickup": "forbidden",
            "guard_labels": dispatch_guard_labels,
            "route": route.get("route"),
            "share_boundary": route.get("share_boundary"),
            "architect_review_required": True,
        }
        acceptance_lanes: list[dict[str, Any]] = [
            {
                "title": f"Dispatch: {title}",
                "type": "task",
                "lane": "external-dispatch",
                "labels": unique_strings(["dispatch", route["route"], *dispatch_guard_labels]),
                "depends_on_lanes": ["pm"],
                **lane_fields("external-dispatch", route, metadata=dispatch_metadata),
            },
            *(
                [
                    {
                        "title": f"Peer review return: {title}",
                        "type": "task",
                        "lane": "peer-review",
                        "labels": [
                            *(route.get("peer_review_labels")
                              or ["peer-review-required", "contractor-peer-review", "sabotage-review", "no-codex-exec"]),
                            "contract-jd-peer-review",
                        ],
                        "depends_on_lanes": ["external-dispatch"],
                        **lane_fields(
                            "peer-review",
                            route,
                            metadata={
                                "job_description_label": "contract-jd-peer-review",
                                "peer_review_count": route.get("peer_review_count", 1),
                                "provider_diversity_required": route.get("provider_diversity_required", True),
                                "provider_conflict_domains": route.get("provider_conflict_domains", []),
                                "local_secure_review_executor": route.get("local_secure_review_executor"),
                                "codex_pickup": "forbidden",
                                "architect_review_required": True,
                            },
                        ),
                    }
                ]
                if peer_review_required
                else []
            ),
            {
                "title": f"Evaluate return: {title}",
                "type": "task",
                "lane": "evaluation",
                "labels": ["evaluation", "contractor-evaluator"],
                "depends_on_lanes": ["external-dispatch", *peer_review_lanes, *acceptance_review_lanes],
                **lane_fields("evaluation", route),
            },
        ]
        adjudication_dependencies = ["evaluation"]
        if model_synthesis_required:
            acceptance_lanes.append(
                {
                    "title": f"Model synthesis: {title}",
                    "type": "task",
                    "lane": "model-synthesis",
                    "labels": ["synthesis", "adjudication-support"],
                    "depends_on_lanes": ["evaluation"],
                    **lane_fields(
                        "model-synthesis",
                        route,
                        metadata={"model_synthesis": route.get("model_synthesis")},
                    ),
                }
            )
            adjudication_dependencies = ["model-synthesis"]
        acceptance_lanes.append(
            {
                "title": f"Architect adjudication: {title}",
                "type": "task",
                "lane": "architect-adjudication",
                "labels": ["architect", "adjudication"],
                "depends_on_lanes": adjudication_dependencies,
                **lane_fields("architect-adjudication", route),
            }
        )
        graph.extend(acceptance_lanes)
        for item in graph:
            if item.get("lane") == "implementation":
                item.setdefault("depends_on_lanes", []).append("architect-adjudication")
    elif needs_internal_acceptance:
        internal_gate_lanes: list[dict[str, Any]] = []
        adjudication_dependencies = ["architect"]
        if peer_review_required:
            internal_gate_lanes.extend(
                [
                    {
                        "title": f"Peer review return: {title}",
                        "type": "task",
                        "lane": "peer-review",
                        "labels": [
                            *(route.get("peer_review_labels")
                              or ["peer-review-required", "contractor-peer-review", "sabotage-review", "no-codex-exec"]),
                            "contract-jd-peer-review",
                        ],
                        "depends_on_lanes": ["architect"],
                        **lane_fields(
                            "peer-review",
                            route,
                            metadata={
                                "job_description_label": "contract-jd-peer-review",
                                "peer_review_count": route.get("peer_review_count", 1),
                                "provider_diversity_required": route.get("provider_diversity_required", True),
                                "provider_conflict_domains": route.get("provider_conflict_domains", []),
                                "local_secure_review_executor": route.get("local_secure_review_executor"),
                                "codex_pickup": "forbidden",
                                "architect_review_required": True,
                            },
                        ),
                    },
                    {
                        "title": f"Evaluate return: {title}",
                        "type": "task",
                        "lane": "evaluation",
                        "labels": ["evaluation", "contractor-evaluator"],
                        "depends_on_lanes": ["peer-review"],
                        **lane_fields("evaluation", route),
                    },
                ]
            )
            adjudication_dependencies = ["evaluation"]
        if model_synthesis_required:
            internal_gate_lanes.append(
                {
                    "title": f"Model synthesis: {title}",
                    "type": "task",
                    "lane": "model-synthesis",
                    "labels": ["synthesis", "adjudication-support"],
                    "depends_on_lanes": adjudication_dependencies,
                    **lane_fields(
                        "model-synthesis",
                        route,
                        metadata={"model_synthesis": route.get("model_synthesis")},
                    ),
                }
            )
            adjudication_dependencies = ["model-synthesis"]
        internal_gate_lanes.append(
            {
                "title": f"Architect adjudication: {title}",
                "type": "task",
                "lane": "architect-adjudication",
                "labels": ["architect", "adjudication"],
                "depends_on_lanes": adjudication_dependencies,
                **lane_fields("architect-adjudication", route),
            }
        )
        graph.extend(internal_gate_lanes)
        for item in graph:
            if item.get("lane") == "implementation":
                item.setdefault("depends_on_lanes", []).append("architect-adjudication")
    elif model_synthesis_required:
        graph.extend(
            [
                {
                    "title": f"Model synthesis: {title}",
                    "type": "task",
                    "lane": "model-synthesis",
                    "labels": ["synthesis", "adjudication-support"],
                    "depends_on_lanes": ["architect", *implementation_blocker_lanes],
                    **lane_fields(
                        "model-synthesis",
                        route,
                        metadata={"model_synthesis": route.get("model_synthesis")},
                    ),
                },
                {
                    "title": f"Architect adjudication: {title}",
                    "type": "task",
                    "lane": "architect-adjudication",
                    "labels": ["architect", "adjudication"],
                    "depends_on_lanes": ["model-synthesis"],
                    **lane_fields("architect-adjudication", route),
                },
            ]
        )
        for item in graph:
            if item.get("lane") == "implementation":
                item.setdefault("depends_on_lanes", []).append("architect-adjudication")

    graph.extend(expert_items)
    return graph


def item_key(item: dict[str, Any], index: int) -> str:
    if index == 0:
        return "epic"
    return str(item.get("lane") or f"item-{index}")


def item_priority(item: dict[str, Any], index: int) -> int:
    if index == 0:
        return 1
    lane = str(item.get("lane") or "")
    if lane in ["architect", "pm", "external-dispatch", "evaluation", "model-synthesis", "architect-adjudication",
                "final-dispatch", "final-evaluation", "final-adjudication"]:
        return 1
    return 2


def dependency_spec(value: object) -> tuple[str, str]:
    """Normalize legacy lane strings and explicit typed relationships."""

    if isinstance(value, str):
        lane = value.strip()
        dependency_type = "blocks"
    elif isinstance(value, dict):
        lane = str(value.get("lane") or value.get("key") or "").strip()
        dependency_type = normalize_dependency_type(
            str(value.get("type") or value.get("dependency_type") or "blocks")
        )
    else:
        raise ValueError("dependency entry must be a lane string or mapping")
    if not lane:
        raise ValueError("dependency lane must be a non-empty string")
    return lane, dependency_type


def _workgraph_metadata_json(value: object) -> str:
    try:
        return json.dumps(value, sort_keys=True)
    except RecursionError as exc:
        raise ValueError(
            f"work graph metadata exceeds native JSON serialization depth: {exc}"
        ) from exc


def string_metadata(item: dict[str, Any]) -> dict[str, str]:
    result = {
        "cwo_lane": str(item.get("lane") or "epic"),
        "cwo_depends_on_lanes": _workgraph_metadata_json(item.get("depends_on_lanes", [])),
        "cwo_skills": _workgraph_metadata_json(item.get("skills", [])),
        "cwo_acceptance": str(item.get("acceptance", "")),
        "cwo_design": str(item.get("design", "")),
        "cwo_notes": str(item.get("notes", "")),
    }
    for key, value in dict(item.get("metadata") or {}).items():
        metadata_key = f"cwo_metadata_{key}"
        if key == "orchestration_route" and isinstance(value, dict):
            result[metadata_key] = _workgraph_metadata_json(
                {
                    "route": value.get("route"),
                    "task_class": value.get("task_class"),
                    "risk_level": value.get("risk_level"),
                    "share_boundary": value.get("share_boundary"),
                    "execution_environment": value.get("execution_environment"),
                    "architecture_authority": value.get("architecture_authority"),
                    "project_manager_executor": value.get("project_manager_executor"),
                    "primary_architect_executor": value.get("primary_architect_executor"),
                    "architecture_counter_review_executor": value.get("architecture_counter_review_executor"),
                    "recommended_executor": value.get("recommended_executor"),
                    "peer_review_required": bool(value.get("peer_review_required")),
                    "provider_conflict_detected": bool(value.get("provider_conflict_detected")),
                    "scaffold_size": value.get("scaffold_size", "full"),
                    "model_synthesis": (
                        value.get("model_synthesis", {}).get("recommended_mode")
                        if isinstance(value.get("model_synthesis"), dict)
                        else None
                    ),
                },
            )
        elif isinstance(value, (str, int, float, bool)) or value is None:
            result[metadata_key] = "" if value is None else str(value)
        else:
            result[metadata_key] = _workgraph_metadata_json(value)
    return result


def _validate_workgraph_labels(labels: object, index: int) -> None:
    if not isinstance(labels, (list, tuple)) or any(not isinstance(label, str) for label in labels):
        raise ValueError(f"work graph item {index} labels must be a list of text values")


def _validate_workgraph_item(item: object, index: int) -> None:
    if not isinstance(item, dict):
        raise ValueError(f"work graph item {index} must be a mapping")
    lane = item.get("lane")
    if lane is not None and not isinstance(lane, (str, int, float, bool)):
        raise ValueError(f"work graph item {index} has an invalid lane shape")
    _validate_workgraph_labels(item.get("labels", []), index)
    if not isinstance(item.get("skills", []), (str, list, tuple)):
        raise ValueError(f"work graph item {index} has an invalid skills shape")


def _validate_creation_fields(plan: list[dict[str, Any]]) -> None:
    for index, item in enumerate(plan):
        if not isinstance(item.get("title"), str):
            raise ValueError(f"work graph item {index} must have a text title")
        required = ("labels", "skills", "acceptance", "design", "notes")
        if index == 0:
            required += ("metadata",)
        for field in required:
            if field not in item:
                raise ValueError(f"work graph item {index} is missing creation field {field}")
        metadata = item.get("metadata")
        if metadata is not None and not isinstance(metadata, dict):
            raise ValueError(f"work graph item {index} metadata must be a mapping")
        try:
            json.dumps(metadata, sort_keys=True)
        except (TypeError, ValueError, RecursionError) as exc:
            raise ValueError(f"work graph item {index} has invalid creation metadata: {exc}") from exc


def _workgraph_relationships(
    plan: list[dict[str, Any]], keys: list[str]
) -> list[tuple[str, str, str]]:
    known_keys = set(keys)
    relationships: list[tuple[str, str, str]] = []
    for key, item in zip(keys, plan):
        dependencies = item.get("depends_on_lanes", [])
        if not isinstance(dependencies, (list, tuple)):
            raise ValueError(f"work graph key {key!r} dependencies must be a list")
        for dependency in dependencies:
            target, dependency_type = dependency_spec(dependency)
            if target not in known_keys:
                raise ValueError(f"work graph key {key!r} has missing dependency reference {target!r}")
            relationships.append((key, target, dependency_type))
    return relationships


def _validate_readiness_cycles(
    keys: list[str], relationships: list[tuple[str, str, str]]
) -> None:
    remaining = dict.fromkeys(keys, 0)
    followers: dict[str, list[str]] = {key: [] for key in keys}
    for key, target, dependency_type in relationships:
        if dependency_type in {"blocks", "until"}:
            remaining[key] += 1
            followers[target].append(key)
    pending = [key for key in keys if remaining[key] == 0]
    visited = 0
    while pending:
        key = pending.pop()
        visited += 1
        for follower in followers[key]:
            remaining[follower] -= 1
            if remaining[follower] == 0:
                pending.append(follower)
    if visited != len(keys):
        raise ValueError("work graph has a readiness dependency cycle")


def validate_workgraph_plan(
    plan: list[dict[str, Any]], *, for_creation: bool = False
) -> list[tuple[str, str, str]]:
    """Validate graph references and readiness before output or writes."""
    if not isinstance(plan, (list, tuple)):
        raise ValueError("work graph plan must be a list")
    if for_creation and not plan:
        raise ValueError("work graph plan is empty; an epic is required")
    keys: list[str] = []
    known_keys: set[str] = set()
    for index, item in enumerate(plan):
        _validate_workgraph_item(item, index)
        key = item_key(item, index)
        if key in known_keys:
            raise ValueError(f"work graph has duplicate node key {key!r}")
        keys.append(key)
        known_keys.add(key)
    if for_creation:
        _validate_creation_fields(plan)
    relationships = _workgraph_relationships(plan, keys)
    _validate_readiness_cycles(keys, relationships)
    return relationships


def beads_graph_plan(plan: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    relationships = validate_workgraph_plan(plan)
    nodes: list[dict[str, Any]] = []

    for index, item in enumerate(plan):
        if "title" not in item:
            raise ValueError(f"work graph item {index} must have a title")
        metadata = item.get("metadata")
        if metadata is not None and not isinstance(metadata, dict):
            raise ValueError(f"work graph item {index} metadata must be a mapping")
        try:
            node_metadata = string_metadata(item)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"work graph item {index} has invalid export metadata: {exc}") from exc
        key = item_key(item, index)
        node = {
            "key": key,
            "title": str(item["title"]),
            "type": str(item.get("type") or "task"),
            "priority": item_priority(item, index),
            "labels": list(item.get("labels", [])),
            "metadata": node_metadata,
        }
        if index > 0:
            node["parent_key"] = "epic"
        nodes.append(node)

    edges = [
        {"from_key": key, "to_key": target, "type": dependency_type}
        for key, target, dependency_type in relationships
    ]
    return {"nodes": nodes, "edges": edges}


def markdown_inline_list(items: list[object]) -> str:
    values = unique_strings(items)
    if not values:
        return "none"
    return ", ".join(f"`{value}`" for value in values)


def markdown_block(value: object) -> str:
    text = str(value or "").strip()
    return text if text else "None."


def markdown_workgraph_plan(title: str, plan: list[dict[str, Any]]) -> str:
    validate_workgraph_plan(plan)
    lines = [
        f"# {title}",
        "",
        f"> {WORKGRAPH_FALLBACK_MARKER}: Beads is unavailable or not in use. This "
        "Markdown workgraph preserves the task shape for operator resume, but "
        "it does not provide ready-work filtering, shared comments, "
        "contractor-only semantics, dependency enforcement, or durable "
        "external handoff.",
        "",
        "Generated by `scripts/scaffold_workgraph.py --dry-run --format markdown-workgraph`.",
        "",
        "## Resume",
        "",
        "- Treat this file as temporary fallback state until Beads or an equivalent tracker is available.",
        "- Resume with `python3 scripts/summarize_resume_state.py --markdown-workgraph <path>`.",
        "- Move the work into Beads before claiming shared durable handoff or contractor dispatch readiness.",
        "",
        "## Work Items",
        "",
    ]
    for index, item in enumerate(plan):
        key = item_key(item, index)
        title_text = str(item.get("title") or key)
        lines.extend(
            [
                f"### {key}: {title_text}",
                "",
                f"- {FIELD_TYPE}: `{item.get('type', 'task')}`",
                f"- {FIELD_STATUS}: `{item.get('status', 'open')}`",
                f"- {FIELD_LANE}: `{item.get('lane', 'epic')}`",
                f"- {FIELD_LABELS}: {markdown_inline_list(list(item.get('labels', [])))}",
                f"- {FIELD_DEPENDS_ON_LANES}: {markdown_inline_list(list(item.get('depends_on_lanes', [])))}",
                f"- {FIELD_SKILLS}: {markdown_inline_list(list(item.get('skills', [])))}",
                "",
                "#### Acceptance",
                "",
                markdown_block(item.get("acceptance")),
                "",
                "#### Design",
                "",
                markdown_block(item.get("design")),
                "",
                "#### Notes",
                "",
                markdown_block(item.get("notes")),
                "",
            ]
        )
    return "\n".join(lines).rstrip() + "\n"


def _render_dry_run_workgraph(
    title: str, plan: list[dict[str, Any]], output_format: str
) -> str:
    try:
        if output_format == "markdown-workgraph":
            return markdown_workgraph_plan(title, plan)
        output = beads_graph_plan(plan) if output_format == "beads-graph" else plan
    except (TypeError, ValueError) as exc:
        raise SystemExit(f"could not render work graph: {exc}") from exc
    try:
        return json.dumps(output, indent=2, sort_keys=True) + "\n"
    except (TypeError, ValueError, RecursionError) as exc:
        raise SystemExit(f"could not render work graph JSON: {exc}") from exc


def try_dep(
    blocked: str,
    blocker: str,
    dependency_type: str = "blocks",
) -> None:
    try:
        add_dependency(
            blocked,
            blocker,
            dependency_type=dependency_type,
        )
    except (SystemExit, Exception) as exc:
        raise SystemExit(
            f"could not add dependency {blocked} -> {blocker} "
            f"({dependency_type}): {exc}"
        ) from exc


def recovery_summary(created: dict[str, str], failed_step: str, error: object) -> str:
    lines = [
        "Partial Beads graph creation detected.",
        f"Failed step: {failed_step}",
        f"Error: {error}",
        "Created IDs:",
    ]
    for lane, bead_id in created.items():
        lines.append(f"- {lane}: {bead_id}")
    lines.extend(
        [
            "Recommended recovery:",
            "- Inspect created work with `bd show <id> --json`.",
            "- Prefer `--dry-run --format beads-graph` plus `bd create --graph` for the next attempt.",
            "- Close, reuse, or delete partial work explicitly; this helper will not silently reuse existing Beads.",
        ]
    )
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="Create a policy-shaped Beads graph for complex work.")
    parser.add_argument("--title", required=True)
    parser.add_argument("--description", default="")
    parser.add_argument("--file")
    parser.add_argument("--external-ok", action="store_true")
    parser.add_argument(
        "--allow-disclosure-escalation",
        action="store_true",
        help="Explicitly approve repo-readonly or patch-branch disclosure routing.",
    )
    parser.add_argument("--local-ok", action="store_true", help="Permit low-risk local worker dispatch.")
    parser.add_argument("--prefer-local", action="store_true", help="Prefer local worker routing when policy permits it.")
    parser.add_argument("--local-profile", help="Require a named local executor profile, for example openshift-ai-vllm.")
    parser.add_argument("--share-boundary", default="no-outside-sharing")
    parser.add_argument(
        "--data-sensitivity",
        choices=["public", "redacted", "internal", "restricted"],
        help="Declare known input data sensitivity; overrides the advisory text heuristic.",
    )
    parser.add_argument("--requested-role", action="append", default=[])
    parser.add_argument(
        "--execution-environment",
        help="Select a CWO execution environment profile such as connected-codex-glm-primary.",
    )
    parser.add_argument(
        "--model-synthesis",
        action="store_true",
        help="Treat model synthesis as accepted opt-in and activate the CWO-native synthesis lane.",
    )
    parser.add_argument(
        "--scaffold-size",
        choices=["full", "tight"],
        default="full",
        help="Select full graph expansion or a tight chain that limits optional expert fan-out.",
    )
    parser.add_argument(
        "--tight-chain",
        action="store_const",
        const="tight",
        dest="scaffold_size",
        help="Shortcut for --scaffold-size tight.",
    )
    parser.add_argument(
        "--beads-context-depth",
        choices=["none", "summary", "focused", "heavy", "audit"],
        help="Override the autosized Beads context depth for internal Codex/subagent briefing.",
    )
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--operative-capabilities", help="Trusted live operative capability evidence JSON.")
    parser.add_argument("--operative-work-estimate", help="Validated native work-estimate v2 JSON.")
    parser.add_argument("--operative-fallback-fit", help="Strict hash-bound fallback-fitness evidence JSON.")
    parser.add_argument("--fallback-selection", help="Explicit user fallback selection JSON.")
    parser.add_argument("--operative-context", help="Current Bead/wave/fresh-segment context JSON.")
    parser.add_argument("--aggregate-budget", help="Original aggregate budget JSON; never reset on fallback.")
    parser.add_argument("--operative-evaluated-at", help="ISO-8601 routing evaluation time for deterministic automation.")
    parser.add_argument(
        "--format",
        choices=["cwo", "beads-graph", "markdown-workgraph"],
        default="cwo",
        help=(
            "Dry-run output format. 'cwo' is the internal scaffold; "
            "'beads-graph' can be used with bd create --graph; "
            "'markdown-workgraph' is a reduced-durability fallback."
        ),
    )
    parser.add_argument("--closure-pressure-active", action="store_true")
    parser.add_argument(
        "--closure-action",
        default="scaffold-workgraph",
        help="Use when closure-pressure should be enforced.",
    )
    parser.add_argument(
        "--closure-disposition",
        choices=CLOSURE_DISPOSITIONS,
        help="Closure disposition required when closure-pressure is active.",
    )
    add_waiver_reason_argument(parser)
    parser.add_argument("--current-authority", help="Current v3 routing evidence JSON; not a dispatch grant.")
    add_risk_narrowing_arguments(parser)
    args = parser.parse_args()
    refuse_risk_narrowing_arguments(args, source="scaffold_workgraph.py")
    require_waiver_reason(args, ["allow_disclosure_escalation"])

    context = read_text_arg(f"{args.title}\n\n{args.description}".strip(), args.file)
    # The title, the description and any --file contents are separate segments for routing risk features.
    context_segments = [part for part in (args.title, args.description) if part and part.strip()]
    context_segments += read_text_segments(None, args.file) if args.file else []
    try:
        route = classify_work(
            context,
            text_segments=context_segments,
            external_ok=args.external_ok,
            allow_disclosure_escalation=args.allow_disclosure_escalation,
            local_ok=args.local_ok,
            prefer_local=args.prefer_local,
            local_profile=args.local_profile,
            share_boundary=args.share_boundary,
            data_sensitivity=args.data_sensitivity,
            requested_roles=args.requested_role,
            execution_environment=args.execution_environment,
            model_synthesis=args.model_synthesis,
            beads_context_depth=args.beads_context_depth,
            operative_capabilities=_load_optional_json(args.operative_capabilities),
            operative_work_estimate=_load_optional_json(args.operative_work_estimate),
            operative_fallback_fit=_load_optional_json(args.operative_fallback_fit),
            fallback_selection=_load_optional_json(args.fallback_selection),
            operative_context=_load_optional_json(args.operative_context),
            aggregate_budget=_load_optional_json(args.aggregate_budget),
            operative_evaluated_at=args.operative_evaluated_at,
            **current_authority_file_arguments(args.current_authority),
        )
    except CWOError as exc:
        raise SystemExit(str(exc))
    closure_pressure = _normalize_closure_pressure(
        {
            "closure_pressure": {
                "active": bool(args.closure_pressure_active),
                "action": args.closure_action,
                "disposition": args.closure_disposition,
            }
        }
    )
    if not closure_pressure["allowed"]:
        parser.error(f"closure-pressure blocked: {closure_pressure['reason']}")
    workerbee_parallelism = prompt_coach_parallel_workerbee_signal(context, prompt_coach_level(route, context), route)
    route = {
        **route,
        "workerbee_parallelism": workerbee_parallelism,
        "workerbee_planned_delegation": _normalize_workerbee_planned_delegation(workerbee_parallelism),
        "closure_pressure": closure_pressure,
    }
    try:
        plan = planned_graph(args.title, route, scaffold_size=args.scaffold_size)
        relationships = validate_workgraph_plan(plan, for_creation=True)
    except ValueError as exc:
        raise SystemExit(str(exc))
    if args.dry_run:
        rendered = _render_dry_run_workgraph(args.title, plan, args.format)
        print(rendered, end="")
        return
    if args.format != "cwo":
        parser.error(
            "--format beads-graph or markdown-workgraph requires --dry-run; "
            "normal execution creates Beads directly."
        )

    created: dict[str, str] = {}
    failed_step = "create epic"
    try:
        epic_plan = plan[0]
        epic = create_bead(
            epic_plan["title"],
            issue_type="epic",
            priority=1,
            labels=epic_plan["labels"],
            skills=epic_plan["skills"],
            description=args.description or "Policy-routed complex work epic.",
            acceptance=str(epic_plan["acceptance"]),
            design=str(epic_plan["design"]),
            notes=str(epic_plan["notes"]),
            metadata=epic_plan["metadata"],
        )
        created["epic"] = epic["id"]
        print(f"Created epic: {epic['id']}")

        for index, item in enumerate(plan[1:], start=1):
            key = item_key(item, index)
            failed_step = f"create {key}"
            bead = create_bead(
                item["title"],
                parent=epic["id"],
                # One priority rule for direct creation and the Beads graph plan.
                priority=item_priority(item, index),
                labels=item["labels"],
                skills=item["skills"],
                description=body(f"Complete the {key} lane.", f"Evidence and result for {key}."),
                acceptance=str(item["acceptance"]),
                design=str(item["design"]),
                notes=str(item["notes"]),
                metadata=item.get("metadata"),
            )
            created[key] = bead["id"]
            print(f"Created task: {bead['id']} {bead['title']}")

        for key, blocker_key, dependency_type in relationships:
            blocked = created.get(key)
            blocker = created.get(blocker_key)
            if blocked and blocker:
                failed_step = (
                    f"add dependency {key} -> {blocker_key} "
                    f"({dependency_type})"
                )
                try_dep(blocked, blocker, dependency_type)
    except SystemExit as exc:
        if created:
            print(recovery_summary(created, failed_step, exc), file=sys.stderr)
        raise


if __name__ == "__main__":
    main()
