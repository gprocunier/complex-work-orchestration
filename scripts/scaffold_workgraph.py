#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from typing import Any

from orchestration_lib import add_dependency, classify_work, create_bead, read_text_arg


def work_task_body(purpose: str, expected: str) -> str:
    return f"""Purpose:
{purpose}

Scope:
Bounded to the parent epic and assigned lane.

Inputs:
- Parent epic
- Current repository state
- Policy route summary

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


def contractor_body(expert: dict[str, Any], share_boundary: str) -> str:
    return f"""Purpose:
Perform {expert['display_name']} work for the parent epic.

Scope:
Use the assigned job-description label and do not broaden into a whole-project review.

Inputs:
- Assigned Bead JSON
- Contractor packet
- references/contractor-brief.md

Allowed changes:
No direct repo changes unless the Bead explicitly allows a patch branch.

Do not touch:
Secrets, private credentials, production systems, release tags, parent epics, or files outside the explicit scope.

Expected output:
Findings, evidence, confidence, risks or gaps, and recommended next beads.

Validation required:
State whether each finding is based on code, documentation, command output, or inference from the assignment packet.

Escalation triggers:
Missing context, suspected secret exposure, scope changes, architecture changes, destructive commands, production impact, release impact, or conflicting evidence.

Handoff format:
Beads comment or approved patch branch using the required contractor return format.

Contractor job description:
{expert['display_name']}

Contract labels:
contractor-only,no-codex-exec,{expert['job_description_label']}

Share boundary:
{share_boundary}

Codex handling rule:
Codex agents may coordinate, brief, and review this bead, but must not execute or close it as contractor work."""


def print_plan(plan: list[dict[str, Any]]) -> None:
    print(json.dumps(plan, indent=2, sort_keys=True))


def try_dep(blocked: str, blocker: str) -> None:
    try:
        add_dependency(blocked, blocker)
    except SystemExit as exc:
        print(f"warning: could not add dependency {blocked} -> {blocker}: {exc}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Create a policy-shaped Beads graph for complex work.")
    parser.add_argument("--title", required=True, help="Epic title.")
    parser.add_argument("--description", default="", help="Epic description.")
    parser.add_argument("--file", help="Read additional task context from a file.")
    parser.add_argument("--external-ok", action="store_true", help="User has opted in to third-party contracting.")
    parser.add_argument(
        "--share-boundary",
        default="no-outside-sharing",
        help="One of: no-outside-sharing, redacted-packet, repo-readonly, patch-branch.",
    )
    parser.add_argument("--dry-run", action="store_true", help="Print planned Beads without creating them.")
    args = parser.parse_args()

    context = read_text_arg(f"{args.title}\n\n{args.description}".strip(), args.file)
    route = classify_work(context, external_ok=args.external_ok, share_boundary=args.share_boundary)
    metadata = {"orchestration_route": route}

    planned: list[dict[str, Any]] = [
        {
            "title": args.title,
            "type": "epic",
            "labels": ["orchestration", "policy-routed"],
            "metadata": metadata,
        },
        {"title": f"Architect frame: {args.title}", "type": "task", "labels": ["architect", "framing"]},
        {"title": f"PM coordinate: {args.title}", "type": "task", "labels": ["pm", "coordination"]},
        {"title": f"Implement: {args.title}", "type": "task", "labels": ["workerbee", "implementation"]},
        {"title": f"Validate: {args.title}", "type": "task", "labels": ["workerbee", "validation"]},
        {"title": f"Docs and handoff: {args.title}", "type": "task", "labels": ["docs", "handoff"]},
    ]

    for expert in route.get("required_experts", []):
        if route["route"] == "external-contract":
            labels = ["contractor-only", "no-codex-exec", expert["job_description_label"]]
            lane = "external contract"
        else:
            labels = ["expert-review", expert["job_description_label"]]
            lane = "internal expert review"
        planned.append(
            {
                "title": f"{expert['display_name']}: {args.title}",
                "type": "task",
                "lane": lane,
                "labels": labels,
                "metadata": {
                    "expert": expert["name"],
                    "discipline": expert["discipline"],
                    "job_description_label": expert["job_description_label"],
                    "share_boundary": args.share_boundary,
                    "codex_pickup": "forbidden" if route["route"] == "external-contract" else "allowed",
                    "architect_review_required": True,
                },
            }
        )

    if args.dry_run:
        print_plan(planned)
        return

    epic = create_bead(
        args.title,
        issue_type="epic",
        priority=1,
        labels=["orchestration", "policy-routed"],
        description=args.description or "Policy-routed complex work epic.",
        acceptance="All lane work is complete, validated, reviewed, and ready for user handoff.",
        metadata=metadata,
    )
    print(f"Created epic: {epic['id']}")

    architect = create_bead(
        f"Architect frame: {args.title}",
        parent=epic["id"],
        priority=1,
        labels=["architect", "framing"],
        description=work_task_body("Frame decomposition, constraints, risks, and acceptance.", "Architecture notes and acceptance criteria."),
    )
    pm = create_bead(
        f"PM coordinate: {args.title}",
        parent=epic["id"],
        priority=1,
        labels=["pm", "coordination"],
        description=work_task_body("Maintain dependencies, status, assignments, and handoffs.", "Graph hygiene and resume instructions."),
    )
    implementation = create_bead(
        f"Implement: {args.title}",
        parent=epic["id"],
        priority=2,
        labels=["workerbee", "implementation"],
        description=work_task_body("Make the bounded implementation changes.", "Patch and implementation evidence."),
    )
    validation = create_bead(
        f"Validate: {args.title}",
        parent=epic["id"],
        priority=2,
        labels=["workerbee", "validation"],
        description=work_task_body("Run syntax, smoke, install, and behavior checks.", "Validation commands and outcomes."),
    )
    docs = create_bead(
        f"Docs and handoff: {args.title}",
        parent=epic["id"],
        priority=2,
        labels=["docs", "handoff"],
        description=work_task_body("Update user-facing docs and final handoff.", "Documentation updates and resume notes."),
    )

    for task in [architect, pm, implementation, validation, docs]:
        print(f"Created task: {task['id']} {task['title']}")

    try_dep(implementation["id"], architect["id"])
    try_dep(validation["id"], implementation["id"])
    try_dep(docs["id"], validation["id"])

    for expert in route.get("required_experts", []):
        external = route["route"] == "external-contract"
        labels = (
            ["contractor-only", "no-codex-exec", expert["job_description_label"]]
            if external
            else ["expert-review", expert["job_description_label"]]
        )
        bead = create_bead(
            f"{expert['display_name']}: {args.title}",
            parent=epic["id"],
            priority=1,
            labels=labels,
            description=contractor_body(expert, args.share_boundary) if external else work_task_body(
                f"Perform {expert['display_name']} before acceptance.",
                "Findings, evidence, confidence, and recommended next beads.",
            ),
            metadata={
                "executor": expert.get("preferred_external_executor") if external else "internal_worker",
                "expert": expert["name"],
                "discipline": expert["discipline"],
                "job_description_label": expert["job_description_label"],
                "share_boundary": args.share_boundary,
                "codex_pickup": "forbidden" if external else "allowed",
                "architect_review_required": True,
            },
        )
        print(f"Created review task: {bead['id']} {bead['title']}")
        try_dep(implementation["id"], bead["id"])


if __name__ == "__main__":
    main()
