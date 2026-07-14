#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from cwo_core.beads import run_bd
from summarize_resume_state import coerce_items, parse_markdown_workgraph

RESULT_TYPE = "complex-work-orchestration-sprint-continuation"
MODELING_NOTE = "Beads has native epics and issues, not native stories or sprints."
CODEX_BLOCKING_LABELS = {"contractor-only", "local-worker-only", "no-codex-exec"}
CLOSED_STATUSES = {"closed", "done", "completed", "resolved"}
VALIDATION_LABELS = {"validation", "test", "testing", "acceptance"}
FOLLOWUP_LABELS = {"follow-up", "followup", "carry-forward", "carried-forward"}
NON_BLOCKING_DEPENDENCY_TYPES = {"parent-child"}


def bd_json(args: list[str]) -> Any:
    return json.loads(run_bd(args))


def as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def string_list(value: Any) -> list[str]:
    if isinstance(value, str):
        return [item.strip() for item in value.split(",") if item.strip()]
    return [str(item).strip() for item in as_list(value) if str(item).strip()]


def normalized_dependency_type(value: Any) -> str:
    return str(value or "").strip().lower().replace("_", "-")


def dependency_entry_ids(value: Any) -> list[str]:
    if isinstance(value, str):
        return [item.strip() for item in value.split(",") if item.strip()]
    if not isinstance(value, dict):
        return string_list(value)
    if normalized_dependency_type(value.get("type") or value.get("dependency_type")) in NON_BLOCKING_DEPENDENCY_TYPES:
        return []
    for name in ["depends_on_id", "depends_on", "dependency_id", "blocked_by", "blocker_id", "id", "key"]:
        candidate = value.get(name)
        if candidate is not None and str(candidate).strip():
            return [str(candidate).strip()]
    return []


def dependency_list(value: Any) -> list[str]:
    dependencies: list[str] = []
    for entry in as_list(value):
        for dependency in dependency_entry_ids(entry):
            if dependency not in dependencies:
                dependencies.append(dependency)
    return dependencies


def field(item: dict[str, Any], *names: str) -> Any:
    for name in names:
        if item.get(name) is not None:
            return item[name]
    metadata = item.get("metadata")
    if isinstance(metadata, dict):
        for name in names:
            if metadata.get(name) is not None:
                return metadata[name]
    return None


def issue_id(item: dict[str, Any]) -> str:
    value = field(item, "id", "issue_id", "key")
    return str(value or "").strip()


def issue_title(item: dict[str, Any]) -> str:
    value = field(item, "title", "summary", "name")
    return str(value or "").strip()


def issue_status(item: dict[str, Any]) -> str:
    value = field(item, "status", "state")
    return str(value or "open").strip().lower()


def issue_labels(item: dict[str, Any]) -> list[str]:
    return string_list(field(item, "labels") or [])


def issue_type(item: dict[str, Any]) -> str:
    value = field(item, "type", "issue_type", "cwo_type")
    return str(value or "issue").strip()


def issue_priority(item: dict[str, Any]) -> int:
    value = field(item, "priority", "rank")
    try:
        return int(value)
    except (TypeError, ValueError):
        return 50


def issue_dependencies(item: dict[str, Any]) -> list[str]:
    dependencies: list[str] = []
    for name in [
        "dependencies",
        "depends_on",
        "depends_on_ids",
        "blocked_by",
        "blockers",
        "depends_on_lanes",
    ]:
        for value in dependency_list(field(item, name) or []):
            if value not in dependencies:
                dependencies.append(value)
    return dependencies


def is_closed(item: dict[str, Any]) -> bool:
    return issue_status(item) in CLOSED_STATUSES


def normalize_item(item: dict[str, Any]) -> dict[str, Any]:
    labels = issue_labels(item)
    return {
        "id": issue_id(item),
        "title": issue_title(item),
        "type": issue_type(item),
        "status": issue_status(item),
        "labels": labels,
        "priority": issue_priority(item),
        "dependencies": issue_dependencies(item),
        "raw": item,
    }


def belongs_to_epic(item: dict[str, Any], epic_id: str) -> bool:
    candidates = string_list(field(item, "parent", "parent_id", "epic", "epic_id") or [])
    return epic_id in candidates


def load_beads_items(epic_id: str) -> list[dict[str, Any]]:
    payload = bd_json(["list", "--json", "--all", "--limit", "0"])
    all_items = coerce_items(payload)
    items = [item for item in all_items if issue_id(item) == epic_id or belongs_to_epic(item, epic_id)]
    dependency_ids = {
        dependency
        for item in items
        for dependency in issue_dependencies(item)
    }
    seen = {issue_id(item) for item in items}
    items.extend(
        item
        for item in all_items
        if issue_id(item) in dependency_ids and issue_id(item) not in seen
    )
    if not items:
        raise SystemExit(f"no Beads issues found for epic {epic_id!r}")
    return items


def load_markdown_items(path: Path, epic_id: str) -> list[dict[str, Any]]:
    items = parse_markdown_workgraph(path)
    if not any(issue_id(item) == epic_id for item in items):
        items.insert(
            0,
            {
                "id": epic_id,
                "title": epic_id,
                "type": "epic",
                "status": "markdown-fallback",
                "labels": ["orchestration"],
            },
        )
    return items


def dependency_lookup(items: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    lookup: dict[str, list[dict[str, Any]]] = {}
    for item in items:
        keys = [item["id"], str(field(item["raw"], "lane") or "")]
        for key in keys:
            stripped = key.strip()
            if not stripped:
                continue
            lookup.setdefault(stripped, []).append(item)
    return lookup


def blocker_reasons(item: dict[str, Any], lookup: dict[str, list[dict[str, Any]]]) -> list[str]:
    reasons: list[str] = []
    label_set = set(item["labels"])
    for label in sorted(label_set & CODEX_BLOCKING_LABELS):
        reasons.append(f"guard label {label} prevents normal Codex pickup")
    for dependency in item["dependencies"]:
        blockers = lookup.get(dependency, [])
        open_blockers = [blocker for blocker in blockers if blocker["id"] != item["id"] and not is_closed(blocker)]
        if open_blockers:
            for blocker in open_blockers:
                reasons.append(f"depends on {blocker['id']} ({blocker['status']})")
        elif not blockers:
            reasons.append(f"depends on unknown work item {dependency}")
    return reasons


def unblocks_count(item: dict[str, Any], items: list[dict[str, Any]]) -> int:
    item_keys = {item["id"], str(field(item["raw"], "lane") or "")}
    return sum(
        1
        for candidate in items
        if candidate["id"] != item["id"]
        and not is_closed(candidate)
        and item_keys.intersection(candidate["dependencies"])
    )


def label_rank(labels: list[str]) -> int:
    label_set = set(labels)
    if label_set & VALIDATION_LABELS:
        return 0
    if label_set & FOLLOWUP_LABELS:
        return 2
    return 1


def rank_ready_issues(ready: list[dict[str, Any]], items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(
        ready,
        key=lambda item: (
            item["priority"],
            -unblocks_count(item, items),
            label_rank(item["labels"]),
            item["id"],
        ),
    )


def issue_summary(item: dict[str, Any], *, reasons: list[str] | None = None) -> dict[str, Any]:
    result = {
        "id": item["id"],
        "title": item["title"],
        "type": item["type"],
        "status": item["status"],
        "labels": item["labels"],
        "priority": item["priority"],
        "dependencies": item["dependencies"],
    }
    if reasons is not None:
        result["blockers"] = reasons
    return result


def infer_sprint_goal(epic: dict[str, Any] | None, sprint_id: str | None) -> str:
    if sprint_id:
        return f"Continue sprint {sprint_id}"
    if epic:
        title = epic.get("title") or epic.get("id")
        return f"Continue {title}"
    return "Continue the current CWO sprint"


def definition_checks(
    *,
    epic_id: str,
    sprint_goal: str,
    items: list[dict[str, Any]],
    blocked: list[dict[str, Any]],
) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    ready = [
        {
            "criterion": "Epic/objective is named",
            "status": "met" if epic_id else "missing",
            "evidence": epic_id or "no epic supplied",
        },
        {
            "criterion": "Sprint goal is specific",
            "status": "met" if sprint_goal else "missing",
            "evidence": sprint_goal or "no sprint goal inferred",
        },
        {
            "criterion": "Issue graph is small enough to execute",
            "status": "met" if 1 <= len(items) <= 12 else "review",
            "evidence": f"{len(items)} work items loaded",
        },
        {
            "criterion": "Dependencies and blockers are explicit",
            "status": "met" if any(item["dependencies"] for item in items) or not blocked else "review",
            "evidence": f"{len(blocked)} blocked work items reported",
        },
        {
            "criterion": "Validation and evidence expectations are known",
            "status": "met",
            "evidence": "continuation brief lists validation and closeout evidence",
        },
    ]
    done = [
        {
            "criterion": "Relevant issues are closed or carried forward",
            "status": "pending",
            "evidence": "close with closure-memory comments or file follow-up issues",
        },
        {
            "criterion": "Evidence and results are captured",
            "status": "pending",
            "evidence": "record commands, outputs, artifacts, and residual risk",
        },
        {
            "criterion": "Project artifacts and handoff are updated",
            "status": "pending",
            "evidence": "update docs/templates/tests and commit or handoff as requested",
        },
    ]
    return ready, done


def build_continuation_brief(
    raw_items: list[dict[str, Any]],
    *,
    epic_id: str,
    sprint_id: str | None = None,
    source: str = "beads",
    markdown_workgraph_path: str | None = None,
) -> dict[str, Any]:
    items = [normalize_item(item) for item in raw_items if issue_id(item)]
    lookup = dependency_lookup(items)
    epic = next((item for item in items if item["id"] == epic_id or item["type"] == "epic"), None)
    open_items = [
        item
        for item in items
        if not is_closed(item) and item["id"] != epic_id and item["type"].strip().lower() != "epic"
    ]
    blocked_pairs = [(item, blocker_reasons(item, lookup)) for item in open_items]
    blocked = [(item, reasons) for item, reasons in blocked_pairs if reasons]
    ready = [item for item, reasons in blocked_pairs if not reasons]
    ranked_ready = rank_ready_issues(ready, items)
    recommended = ranked_ready[0] if ranked_ready else None
    sprint_goal = infer_sprint_goal(epic, sprint_id)
    dor, dod = definition_checks(epic_id=epic_id, sprint_goal=sprint_goal, items=items, blocked=[item for item, _ in blocked])
    blocked_summaries = [issue_summary(item, reasons=reasons) for item, reasons in blocked]
    ready_summaries = [issue_summary(item) for item in ranked_ready]
    carry_forward = [
        issue_summary(item)
        for item in items
        if set(item["labels"]) & FOLLOWUP_LABELS and not is_closed(item)
    ]
    durability = "reduced" if source == "markdown-workgraph" else "durable"
    resume_commands = [
        "bd ready --exclude-label contractor-only --exclude-label local-worker-only --exclude-label no-codex-exec --json",
        f"python3 scripts/cwo.py continue --epic {epic_id}",
    ]
    if source == "markdown-workgraph":
        workgraph_path = markdown_workgraph_path or "<path>"
        resume_commands = [
            f"python3 scripts/cwo.py continue --epic {epic_id} --markdown-workgraph {workgraph_path}",
            "move this reduced-durability workgraph into Beads before shared handoff",
        ]
    warnings = [MODELING_NOTE]
    if source == "markdown-workgraph":
        warnings.append("Markdown fallback has no durable ready filtering, comments, or shared Beads handoff.")
    if not recommended and blocked:
        warnings.append("No ready issue is available; resolve the first blocker before implementation.")
    result = {
        "continuation_result_type": RESULT_TYPE,
        "version": 2,
        "source": source,
        "durability": durability,
        "epic_id": epic_id,
        "sprint_id": sprint_id,
        "sprint_goal": sprint_goal,
        "modeling_note": MODELING_NOTE,
        "recommended_next_issue": issue_summary(recommended) if recommended else None,
        "why_next": why_next(recommended, items) if recommended else "No ready work item is available.",
        "ready_issues": ready_summaries,
        "blocked_issues": blocked_summaries,
        "carry_forward": carry_forward,
        "definition_of_ready": dor,
        "definition_of_done": dod,
        "evidence_expectations": [
            "commands and validation output",
            "changed artifacts or Beads issue ids",
            "closure-memory comment for meaningful issue closure",
            "residual risk and follow-up issue ids when work carries forward",
        ],
        "resume_commands": resume_commands,
        "warnings": warnings,
    }
    result["operator_handoff_packet"] = operator_handoff_packet(result)
    return result


def operator_handoff_packet(result: dict[str, Any]) -> dict[str, str]:
    recommended = result.get("recommended_next_issue")
    if recommended:
        next_bead = f"{recommended['id']} {recommended['title']}".strip()
        action = "CONTINUE"
        action_to_send = (
            "Use $complex-work-orchestration to continue from Bead "
            f"{recommended['id']} under its recorded scope and authority. Apply any "
            "domain skill named by the Bead, use the smallest appropriate execution "
            "shape, skip coach unless execution is genuinely ambiguous, and stop at a "
            "recorded escalation boundary."
        )
    elif result.get("blocked_issues"):
        next_bead = "none - blocked"
        action = "DECIDE"
        action_to_send = (
            f"Review the blockers under epic {result['epic_id']} and present the one "
            "operator decision needed to unblock the highest-value Bead. Do not start "
            "implementation."
        )
    else:
        next_bead = "none - stop condition met"
        action = "STOP"
        action_to_send = "No action. The epic has no ready or blocked work."
    return {
        "recommended_operator_action": action,
        "action_to_send": action_to_send,
        "next_executable_bead": next_bead,
        "why_it_is_next": result.get("why_next") or "No ready work item is available.",
        "what_must_not_run_yet": (
            "Do not run blocked, contractor-only, local-worker-only, no-codex-exec, "
            "unsafe, or unapproved lanes until their guard clears."
        ),
        "commit_push_status": "not evaluated by continuation helper; report current repo closeout status in the final response",
        "validation_status": "pending for the next lane; use the Definition of Done and evidence expectations above",
        "escalation_rule": "stop and ask the operator if no ready issue exists, a guard label blocks pickup, or validation cannot run",
    }


def why_next(item: dict[str, Any] | None, items: list[dict[str, Any]]) -> str:
    if item is None:
        return "No ready work item is available."
    reasons = [f"priority {item['priority']}"]
    count = unblocks_count(item, items)
    if count:
        reasons.append(f"unblocks {count} downstream item(s)")
    label_set = set(item["labels"])
    if label_set & VALIDATION_LABELS:
        reasons.append("closes validation evidence")
    elif label_set & FOLLOWUP_LABELS:
        reasons.append("tracks carry-forward work")
    else:
        reasons.append("has no unmet dependencies")
    return "; ".join(reasons)


def print_text(result: dict[str, Any], *, include_blocked: bool = False) -> None:
    print("# Sprint Continuation Brief\n")
    print(f"Epic: {result['epic_id']}")
    if result.get("sprint_id"):
        print(f"Sprint: {result['sprint_id']}")
    print(f"Goal: {result['sprint_goal']}")
    print(f"Durability: {result['durability']} ({result['source']})")
    print(f"Modeling note: {result['modeling_note']}\n")
    recommended = result.get("recommended_next_issue")
    print("## Recommended Next Issue")
    if recommended:
        print(f"- {recommended['id']} {recommended['title']}")
        print(f"  Why: {result['why_next']}")
    else:
        print("- none")
        print(f"  Why: {result['why_next']}")
    print("\n## Ready Issues")
    for item in result.get("ready_issues", [])[:10]:
        print(f"- {item['id']} {item['title']} [{','.join(item['labels'])}]")
    if not result.get("ready_issues"):
        print("- none")
    blocked = result.get("blocked_issues", [])
    print("\n## Blocked Issues")
    display_blocked = blocked if include_blocked else blocked[:5]
    for item in display_blocked:
        print(f"- {item['id']} {item['title']}")
        for reason in item.get("blockers", []):
            print(f"  - {reason}")
    if not blocked:
        print("- none")
    elif not include_blocked and len(blocked) > len(display_blocked):
        print(f"- {len(blocked) - len(display_blocked)} more blocked issue(s); pass --include-blocked to show all.")
    print("\n## Evidence Expectations")
    for item in result.get("evidence_expectations", []):
        print(f"- {item}")
    packet = result.get("operator_handoff_packet") or {}
    print("\n## Operator Handoff Packet")
    print(f"- Recommended operator action: {packet.get('recommended_operator_action', '')}")
    print(f"- Action to send: {packet.get('action_to_send', '')}")
    print(f"- Next executable Bead: {packet.get('next_executable_bead', '')}")
    print(f"- Why it is next: {packet.get('why_it_is_next', '')}")
    print(f"- What must NOT run yet: {packet.get('what_must_not_run_yet', '')}")
    print(f"- Commit/push status: {packet.get('commit_push_status', '')}")
    print(f"- Validation status: {packet.get('validation_status', '')}")
    print(f"- Escalation rule: {packet.get('escalation_rule', '')}")
    warnings = result.get("warnings") or []
    if warnings:
        print("\n## Warnings")
        for item in warnings:
            print(f"- {item}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Recommend the next executable issue for a planned CWO sprint.")
    parser.add_argument("--epic", required=True, help="Native Beads epic id or Markdown fallback epic key.")
    parser.add_argument("--sprint", help="Optional sprint artifact slug or name.")
    parser.add_argument(
        "--markdown-workgraph",
        type=Path,
        help="Use a reduced-durability Markdown workgraph fallback instead of Beads state.",
    )
    parser.add_argument("--format", choices=["text", "json"], default="text")
    parser.add_argument("--include-blocked", action="store_true", help="Show all blocked issues in text output.")
    args = parser.parse_args()

    if args.markdown_workgraph:
        raw_items = load_markdown_items(args.markdown_workgraph, args.epic)
        source = "markdown-workgraph"
    else:
        raw_items = load_beads_items(args.epic)
        source = "beads"
    result = build_continuation_brief(
        raw_items,
        epic_id=args.epic,
        sprint_id=args.sprint,
        source=source,
        markdown_workgraph_path=str(args.markdown_workgraph) if args.markdown_workgraph else None,
    )
    if args.format == "json":
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print_text(result, include_blocked=args.include_blocked)


if __name__ == "__main__":
    main()
