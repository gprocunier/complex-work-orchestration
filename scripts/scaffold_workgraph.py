#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from typing import Any

from orchestration_lib import (
    add_dependency,
    classify_work,
    create_bead,
    expert_review_labels,
    expert_review_lane,
    expert_review_metadata,
    read_text_arg,
)


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
Beads comment with findings, validation, and next action."""


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


def bullet_list(items: list[object], fallback: str) -> str:
    values = unique_strings(items)
    if not values:
        values = [fallback]
    return "\n".join(f"- {item}" for item in values)


def route_notes(route: dict[str, Any]) -> str:
    experts = [str(item.get("name")) for item in route.get("ranked_experts", [])[:5] if item.get("name")]
    return "\n".join(
        [
            f"Route: {route.get('route')}",
            f"Task class: {route.get('task_class')}",
            f"Risk: {route.get('risk_level')}",
            f"Share boundary: {route.get('share_boundary')}",
            f"Recommended executor: {route.get('recommended_executor')}",
            f"Peer review required: {bool(route.get('peer_review_required'))}",
            f"Provider conflict detected: {bool(route.get('provider_conflict_detected'))}",
            "Selected experts: " + (", ".join(experts) if experts else "none"),
        ]
    )


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
        "acceptance": "Published artifacts are free of local-only, transient, duplicate, circular, or non-fresh-deploy content.",
        "design": "Run after validation and any editorial gate before push, release, tag, or public handoff.",
    },
    "docs": {
        "skills": ["documentation", "operator-guides", "handoff"],
        "acceptance": "Docs, examples, and handoff instructions match the implemented behavior.",
        "design": "Keep the skill entrypoint concise and place durable operator detail in README and references.",
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
    "architect-adjudication": {
        "skills": ["architecture", "adjudication", "acceptance"],
        "acceptance": "The architect accepts, rejects, quarantines, or converts findings into normal follow-up Beads.",
        "design": "Final decision stays with the architect after evaluation and any peer-review gates.",
    },
}


def lane_fields(lane: str, route: dict[str, Any]) -> dict[str, object]:
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
    }


def expert_fields(expert: dict[str, Any], route: dict[str, Any]) -> dict[str, object]:
    acceptance_checks = expert.get("acceptance_checks", [])
    output_contract = expert.get("output_contract", [])
    display_name = str(expert.get("display_name") or expert.get("name") or "Expert reviewer")
    job_label = str(expert.get("job_description_label", "contract-jd-general-reasoning"))
    stage = str(expert.get("review_stage", "pre-implementation"))
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
        "notes": route_notes(route)
        + "\nOutput contract:\n"
        + bullet_list(list(output_contract), "Findings, confidence, residual risk, and recommended next Beads."),
    }


def planned_graph(title: str, route: dict[str, Any]) -> list[dict[str, Any]]:
    expert_items: list[dict[str, Any]] = []
    acceptance_review_lanes: list[str] = []
    implementation_blocker_lanes: list[str] = []
    validation_blocker_lanes: list[str] = []
    editor_gate_lanes: list[str] = []

    for expert in route.get("ranked_experts", []):
        lane = expert_review_lane(expert)
        metadata = expert_review_metadata(expert, route)
        depends_on = ["architect"]
        if metadata.get("codex_pickup") == "forbidden":
            depends_on.append("external-dispatch")
        if metadata.get("acceptance_bead_required"):
            acceptance_review_lanes.append(lane)
        elif metadata.get("validation_gate_required"):
            editor_gate_lanes.append(lane)
            validation_blocker_lanes.append(lane)
        elif expert.get("review_stage") in ["pre-implementation", "implementation-review"]:
            implementation_blocker_lanes.append(lane)
        elif expert.get("review_stage") in ["pre-validation", "pre-release"]:
            validation_blocker_lanes.append(lane)

        expert_items.append(
            {
                "title": f"{expert['display_name']}: {title}",
                "type": "task",
                "lane": lane,
                "labels": expert_review_labels(expert, route),
                "metadata": metadata,
                "depends_on_lanes": depends_on,
                **expert_fields(expert, route),
            }
        )

    needs_acceptance = bool(acceptance_review_lanes) or route.get("route") in ["external-contract", "local-worker"]
    peer_review_required = bool(route.get("peer_review_required"))
    publish_sanitization_required = bool(route.get("editor_gate_required"))
    graph: list[dict[str, Any]] = [
        {
            "title": title,
            "type": "epic",
            "labels": ["orchestration", "policy-routed"],
            "metadata": {"orchestration_route": route},
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
            "labels": ["workerbee", "implementation"],
            "depends_on_lanes": ["architect", *implementation_blocker_lanes],
            **lane_fields("implementation", route),
        },
        {
            "title": f"Validate: {title}",
            "type": "task",
            "lane": "validation",
            "labels": ["workerbee", "validation"],
            "depends_on_lanes": ["implementation", *validation_blocker_lanes],
            **lane_fields("validation", route),
        },
    ]
    docs_dependency = "validation"
    if publish_sanitization_required:
        graph.append(
            {
                "title": f"Publish sanitization: {title}",
                "type": "task",
                "lane": "publish-sanitization",
                "labels": ["publish-sanitization", "public-artifact-review"],
                "depends_on_lanes": ["validation", *editor_gate_lanes],
                **lane_fields("publish-sanitization", route),
            }
        )
        docs_dependency = "publish-sanitization"

    graph.append(
        {
            "title": f"Docs and handoff: {title}",
            "type": "task",
            "lane": "docs",
            "labels": ["docs", "handoff"],
            "depends_on_lanes": [docs_dependency],
            **lane_fields("docs", route),
        }
    )
    if needs_acceptance:
        peer_review_lanes = ["peer-review"] if peer_review_required else []
        graph.extend(
            [
                {
                    "title": f"Dispatch: {title}",
                    "type": "task",
                    "lane": "external-dispatch",
                    "labels": ["dispatch", route["route"]],
                    "depends_on_lanes": ["pm"],
                    **lane_fields("external-dispatch", route),
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
                            "metadata": {
                                "job_description_label": "contract-jd-peer-review",
                                "peer_review_count": route.get("peer_review_count", 1),
                                "provider_diversity_required": route.get("provider_diversity_required", True),
                                "provider_conflict_domains": route.get("provider_conflict_domains", []),
                                "local_secure_review_executor": route.get("local_secure_review_executor"),
                                "codex_pickup": "forbidden",
                                "architect_review_required": True,
                            },
                            "depends_on_lanes": ["external-dispatch"],
                            **lane_fields("peer-review", route),
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
                {
                    "title": f"Architect adjudication: {title}",
                    "type": "task",
                    "lane": "architect-adjudication",
                    "labels": ["architect", "adjudication"],
                    "depends_on_lanes": ["evaluation"],
                    **lane_fields("architect-adjudication", route),
                },
            ]
        )
        for item in graph:
            if item.get("lane") == "implementation":
                item.setdefault("depends_on_lanes", []).append("architect-adjudication")

    graph.extend(expert_items)
    return graph


def try_dep(blocked: str, blocker: str) -> None:
    try:
        add_dependency(blocked, blocker)
    except SystemExit as exc:
        print(f"warning: could not add dependency {blocked} -> {blocker}: {exc}")


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
    parser.add_argument("--requested-role", action="append", default=[])
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    context = read_text_arg(f"{args.title}\n\n{args.description}".strip(), args.file)
    route = classify_work(
        context,
        external_ok=args.external_ok,
        allow_disclosure_escalation=args.allow_disclosure_escalation,
        local_ok=args.local_ok,
        prefer_local=args.prefer_local,
        local_profile=args.local_profile,
        share_boundary=args.share_boundary,
        requested_roles=args.requested_role,
    )
    plan = planned_graph(args.title, route)
    if args.dry_run:
        print(json.dumps(plan, indent=2, sort_keys=True))
        return

    created: dict[str, str] = {}
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

    for item in plan[1:]:
        bead = create_bead(
            item["title"],
            parent=epic["id"],
            priority=1 if item["lane"] in ["architect", "pm", "external-dispatch", "evaluation", "architect-adjudication"] else 2,
            labels=item["labels"],
            skills=item["skills"],
            description=body(f"Complete the {item['lane']} lane.", f"Evidence and result for {item['lane']}."),
            acceptance=str(item["acceptance"]),
            design=str(item["design"]),
            notes=str(item["notes"]),
            metadata=item.get("metadata"),
        )
        created[item["lane"]] = bead["id"]
        print(f"Created task: {bead['id']} {bead['title']}")

    for item in plan[1:]:
        blocked = created.get(item["lane"])
        if not blocked:
            continue
        for blocker_lane in item.get("depends_on_lanes", []):
            blocker = created.get(blocker_lane)
            if blocker:
                try_dep(blocked, blocker)


if __name__ == "__main__":
    main()
