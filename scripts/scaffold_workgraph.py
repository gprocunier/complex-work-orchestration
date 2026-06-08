#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from typing import Any

from orchestration_lib import add_dependency, classify_work, create_bead, read_text_arg


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
    graph: list[dict[str, Any]] = [
        {"title": title, "type": "epic", "labels": ["orchestration", "policy-routed"], "metadata": {"orchestration_route": route}},
        {"title": f"Architect frame: {title}", "type": "task", "lane": "architect", "labels": ["architect", "framing"]},
        {"title": f"PM coordinate: {title}", "type": "task", "lane": "pm", "labels": ["pm", "coordination"]},
        {"title": f"Implement: {title}", "type": "task", "lane": "implementation", "labels": ["workerbee", "implementation"]},
        {"title": f"Validate: {title}", "type": "task", "lane": "validation", "labels": ["workerbee", "validation"]},
        {"title": f"Docs and handoff: {title}", "type": "task", "lane": "docs", "labels": ["docs", "handoff"]},
    ]
    if route.get("route") in ["external-contract", "local-worker"]:
        graph.extend(
            [
                {"title": f"Dispatch: {title}", "type": "task", "lane": "external-dispatch", "labels": ["dispatch", route["route"]]},
                {"title": f"Evaluate return: {title}", "type": "task", "lane": "evaluation", "labels": ["evaluation", "contractor-evaluator"]},
                {"title": f"Architect adjudication: {title}", "type": "task", "lane": "architect-adjudication", "labels": ["architect", "adjudication"]},
            ]
        )
    for expert in route.get("ranked_experts", []):
        labels = ["expert-review", expert["job_description_label"], expert["review_stage"]]
        if route.get("route") == "external-contract":
            labels = ["contractor-only", "no-codex-exec", expert["job_description_label"], expert["review_stage"]]
        graph.append(
            {
                "title": f"{expert['display_name']}: {title}",
                "type": "task",
                "lane": expert["review_stage"],
                "labels": labels,
                "metadata": {
                    "expert": expert["name"],
                    "discipline": expert["discipline"],
                    "job_description_label": expert["job_description_label"],
                    "review_stage": expert["review_stage"],
                    "share_boundary": route["share_boundary"],
                    "executor": route["recommended_executor"],
                    "codex_pickup": "forbidden" if route.get("route") == "external-contract" else "allowed",
                    "architect_review_required": True,
                    "acceptance_bead_required": route.get("route") in ["external-contract", "local-worker"],
                },
            }
        )
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
    parser.add_argument("--share-boundary", default="no-outside-sharing")
    parser.add_argument("--requested-role", action="append", default=[])
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    context = read_text_arg(f"{args.title}\n\n{args.description}".strip(), args.file)
    route = classify_work(
        context,
        external_ok=args.external_ok,
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

    if "implementation" in created and "architect" in created:
        try_dep(created["implementation"], created["architect"])
    if "validation" in created and "implementation" in created:
        try_dep(created["validation"], created["implementation"])
    if "external-dispatch" in created and "pm" in created:
        try_dep(created["external-dispatch"], created["pm"])
    if "evaluation" in created and "external-dispatch" in created:
        try_dep(created["evaluation"], created["external-dispatch"])
    if "architect-adjudication" in created and "evaluation" in created:
        try_dep(created["architect-adjudication"], created["evaluation"])
    if "implementation" in created and "architect-adjudication" in created:
        try_dep(created["implementation"], created["architect-adjudication"])


if __name__ == "__main__":
    main()
