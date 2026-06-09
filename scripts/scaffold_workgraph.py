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


def planned_graph(title: str, route: dict[str, Any]) -> list[dict[str, Any]]:
    expert_items: list[dict[str, Any]] = []
    acceptance_review_lanes: list[str] = []
    implementation_blocker_lanes: list[str] = []
    validation_blocker_lanes: list[str] = []

    for expert in route.get("ranked_experts", []):
        lane = expert_review_lane(expert)
        metadata = expert_review_metadata(expert, route)
        depends_on = ["architect"]
        if metadata.get("codex_pickup") == "forbidden":
            depends_on.append("external-dispatch")
        if metadata.get("acceptance_bead_required"):
            acceptance_review_lanes.append(lane)
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
            }
        )

    needs_acceptance = bool(acceptance_review_lanes) or route.get("route") in ["external-contract", "local-worker"]
    graph: list[dict[str, Any]] = [
        {"title": title, "type": "epic", "labels": ["orchestration", "policy-routed"], "metadata": {"orchestration_route": route}},
        {"title": f"Architect frame: {title}", "type": "task", "lane": "architect", "labels": ["architect", "framing"]},
        {"title": f"PM coordinate: {title}", "type": "task", "lane": "pm", "labels": ["pm", "coordination"]},
        {
            "title": f"Implement: {title}",
            "type": "task",
            "lane": "implementation",
            "labels": ["workerbee", "implementation"],
            "depends_on_lanes": ["architect", *implementation_blocker_lanes],
        },
        {
            "title": f"Validate: {title}",
            "type": "task",
            "lane": "validation",
            "labels": ["workerbee", "validation"],
            "depends_on_lanes": ["implementation", *validation_blocker_lanes],
        },
        {
            "title": f"Docs and handoff: {title}",
            "type": "task",
            "lane": "docs",
            "labels": ["docs", "handoff"],
            "depends_on_lanes": ["validation"],
        },
    ]
    if needs_acceptance:
        graph.extend(
            [
                {
                    "title": f"Dispatch: {title}",
                    "type": "task",
                    "lane": "external-dispatch",
                    "labels": ["dispatch", route["route"]],
                    "depends_on_lanes": ["pm"],
                },
                {
                    "title": f"Evaluate return: {title}",
                    "type": "task",
                    "lane": "evaluation",
                    "labels": ["evaluation", "contractor-evaluator"],
                    "depends_on_lanes": ["external-dispatch", *acceptance_review_lanes],
                },
                {
                    "title": f"Architect adjudication: {title}",
                    "type": "task",
                    "lane": "architect-adjudication",
                    "labels": ["architect", "adjudication"],
                    "depends_on_lanes": ["evaluation"],
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
    parser.add_argument("--local-ok", action="store_true", help="Permit low-risk local worker dispatch.")
    parser.add_argument("--prefer-local", action="store_true", help="Prefer local worker routing when policy permits it.")
    parser.add_argument("--share-boundary", default="no-outside-sharing")
    parser.add_argument("--requested-role", action="append", default=[])
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    context = read_text_arg(f"{args.title}\n\n{args.description}".strip(), args.file)
    route = classify_work(
        context,
        external_ok=args.external_ok,
        local_ok=args.local_ok,
        prefer_local=args.prefer_local,
        share_boundary=args.share_boundary,
        requested_roles=args.requested_role,
    )
    plan = planned_graph(args.title, route)
    if args.dry_run:
        print(json.dumps(plan, indent=2, sort_keys=True))
        return

    created: dict[str, str] = {}
    epic = create_bead(
        args.title,
        issue_type="epic",
        priority=1,
        labels=["orchestration", "policy-routed"],
        description=args.description or "Policy-routed complex work epic.",
        acceptance="All lane work is complete, validated, evaluated, adjudicated, and ready for handoff.",
        metadata={"orchestration_route": route},
    )
    created["epic"] = epic["id"]
    print(f"Created epic: {epic['id']}")

    for item in plan[1:]:
        bead = create_bead(
            item["title"],
            parent=epic["id"],
            priority=1 if item["lane"] in ["architect", "pm", "external-dispatch", "evaluation", "architect-adjudication"] else 2,
            labels=item["labels"],
            description=body(f"Complete the {item['lane']} lane.", f"Evidence and result for {item['lane']}."),
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
