#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from cwo_core.beads import run_bd
from cwo_core.beads_ready_set import (
    CONTAINER_LABELS,
    CONTAINER_TYPES,
    MAX_PHASE1_CANDIDATE_WORKERS,
    build_ready_set_evidence,
    markdown_fallback_evidence,
)
from summarize_resume_state import coerce_items, parse_markdown_workgraph

RESULT_TYPE = "complex-work-orchestration-sprint-continuation"
MODELING_NOTE = "Beads has native epics and issues, not native stories or sprints."
CODEX_BLOCKING_LABELS = {"contractor-only", "local-worker-only", "no-codex-exec"}
CLOSED_STATUSES = {"closed", "done", "completed", "resolved"}
VALIDATION_LABELS = {"validation", "test", "testing", "acceptance"}
FOLLOWUP_LABELS = {"follow-up", "followup", "carry-forward", "carried-forward"}
HARD_BLOCKING_DEPENDENCY_TYPES = {"blocks", "until"}


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
    dependency_type = normalized_dependency_type(
        value.get("type") or value.get("dependency_type") or "blocks"
    )
    if dependency_type not in HARD_BLOCKING_DEPENDENCY_TYPES:
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
    """Load exact issue projections while taking readiness only from ``bd ready``."""

    ready_payload = bd_json(
        [
            "ready",
            "--json",
            "--parent",
            epic_id,
            "--unassigned",
            "--limit",
            "0",
        ]
    )
    ready_items = coerce_items(ready_payload)
    ready_order: list[str] = []
    for item in ready_items:
        item_id = issue_id(item)
        if item_id and item_id not in ready_order:
            ready_order.append(item_id)
    ready_ids = set(ready_order)
    ready_rank = {item_id: rank for rank, item_id in enumerate(ready_order)}

    discovered_ids = {epic_id, *ready_ids}
    pending_parents = [epic_id]
    queried_parents: set[str] = set()
    while pending_parents:
        parent_id = pending_parents.pop(0)
        if parent_id in queried_parents:
            continue
        queried_parents.add(parent_id)
        children = coerce_items(
            bd_json(
                [
                    "list",
                    "--json",
                    "--all",
                    "--parent",
                    parent_id,
                    "--limit",
                    "0",
                ]
            )
        )
        for child in children:
            child_id = issue_id(child)
            if child_id:
                discovered_ids.add(child_id)
                if child_id not in queried_parents and child_id not in pending_parents:
                    pending_parents.append(child_id)

    exact_items: list[dict[str, Any]] = []
    exact_ids = sorted(discovered_ids)
    for start in range(0, len(exact_ids), 50):
        chunk = exact_ids[start : start + 50]
        exact_items.extend(coerce_items(bd_json(["show", *chunk, "--json"])))
    exact_by_id = {issue_id(item): item for item in exact_items if issue_id(item)}
    missing = sorted(discovered_ids - set(exact_by_id))
    if missing:
        raise SystemExit(
            "Beads exact-show enrichment omitted issue(s): " + ", ".join(missing)
        )

    parent_ids = {
        str(field(item, "parent", "parent_id") or "").strip()
        for item in exact_items
        if str(field(item, "parent", "parent_id") or "").strip()
    }
    result: list[dict[str, Any]] = []
    for item_id in exact_ids:
        enriched = dict(exact_by_id[item_id])
        enriched["_cwo_canonical_ready"] = item_id in ready_ids
        enriched["_cwo_canonical_ready_rank"] = ready_rank.get(item_id)
        enriched["_cwo_executable_leaf"] = item_id not in parent_ids
        result.append(enriched)
    return result


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
    if item["status"] == "blocked":
        reasons.append("status blocked requires operator decision")
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
    requested_workers: int = MAX_PHASE1_CANDIDATE_WORKERS,
    policy_document: dict[str, Any] | None = None,
) -> dict[str, Any]:
    items = [normalize_item(item) for item in raw_items if issue_id(item)]
    lookup = dependency_lookup(items)
    epic = next((item for item in items if item["id"] == epic_id or item["type"] == "epic"), None)
    open_items = [
        item
        for item in items
        if not is_closed(item) and item["id"] != epic_id and item["type"].strip().lower() != "epic"
    ]
    canonical_ready_mode = any(
        "_cwo_canonical_ready" in item["raw"] for item in items
    )
    blocked_pairs: list[tuple[dict[str, Any], list[str]]] = []
    canonical_ready_items: list[dict[str, Any]] = []
    for item in open_items:
        reasons = blocker_reasons(item, lookup)
        if canonical_ready_mode:
            canonical_ready = item["raw"].get("_cwo_canonical_ready") is True
            executable_leaf = item["raw"].get("_cwo_executable_leaf") is not False
            executable_container = (
                item["type"].strip().lower() in CONTAINER_TYPES
                or (
                    bool(set(item["labels"]) & CONTAINER_LABELS)
                    and item["type"].strip().lower()
                    not in {"task", "bug", "chore"}
                )
            )
            if canonical_ready and executable_leaf:
                canonical_ready_items.append(item)
                if executable_container:
                    reasons.append(
                        "grouping container or publication parent is not executable work"
                    )
            elif canonical_ready:
                reasons.append("grouping container has descendant work items")
            elif not reasons:
                reasons.append(
                    "not returned by canonical Beads readiness "
                    f"({item['status']})"
                )
        blocked_pairs.append((item, reasons))
    blocked = [(item, reasons) for item, reasons in blocked_pairs if reasons]
    ready = [item for item, reasons in blocked_pairs if not reasons]
    ranked_ready = rank_ready_issues(ready, items)
    ranked_candidate_input = rank_ready_issues(
        canonical_ready_items if canonical_ready_mode else ready,
        items,
    )
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
        f"bd ready --json --parent {epic_id} --unassigned --limit 0",
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
        warnings.append("Markdown fallback cannot authorize or evidence native-pool fanout.")
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
    if source == "markdown-workgraph":
        ready_set = markdown_fallback_evidence(ranked_ready)
    else:
        ready_set = build_ready_set_evidence(
            ranked_candidate_input,
            epic_id=epic_id,
            requested_workers=requested_workers,
            policy_document=policy_document,
            scope_items=open_items,
        )
    ready_by_id = {item["id"]: issue_summary(item) for item in ranked_candidate_input}
    ready_set["ranked_ready_issues"] = [
        ready_by_id[item_id]
        for item_id in ready_set["ranked_ready_issues"]
        if item_id in ready_by_id
    ]
    result.update(ready_set)
    result["operator_handoff_packet"] = operator_handoff_packet(result)
    return result


def operator_handoff_packet(result: dict[str, Any]) -> dict[str, str]:
    recommended = result.get("recommended_next_issue")
    resume_commands = result.get("resume_commands") or []
    resume = resume_commands[0] if resume_commands else "bd ready --json"
    if recommended:
        next_bead = f"{recommended['id']} {recommended['title']}".strip()
        execution_prompt = (
            "Use $complex-work-orchestration to continue "
            f"{recommended['id']} under epic {result['epic_id']}; start with "
            f"`{resume}` and execute only that bounded lane."
        )
    elif result.get("blocked_issues"):
        next_bead = "none - blocked"
        execution_prompt = (
            f"DECIDE: epic {result['epic_id']} has no ready issue; resolve the "
            "first recorded blocker before implementation."
        )
    else:
        next_bead = "none - stop condition met"
        execution_prompt = (
            f"STOP: epic {result['epic_id']} has no ready or blocked work; do not "
            "start another lane."
        )
    if result.get("fanout_decision") == "pool":
        execution_prompt += (
            " A bounded pool candidate is available as evidence only; do not "
            "dispatch it until P1-13B completes Beads claims, full drift and "
            "capability revalidation, proportionality, operative lease acquisition, "
            "and native-pool preflight."
        )
    return {
        "next_executable_bead": next_bead,
        "why_it_is_next": result.get("why_next") or "No ready work item is available.",
        "exact_command_resume": resume,
        "execution_prompt": execution_prompt,
        "what_must_not_run_yet": (
            "Do not run blocked, contractor-only, local-worker-only, no-codex-exec, "
            "unsafe, or unapproved lanes until their guard clears. Ready-set "
            "candidate evidence is never dispatch authority."
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
    print("\n## Bounded Ready-Set Candidate")
    print(f"- Decision: {result.get('fanout_decision', 'blocked')}")
    print(f"- Authority: {result.get('ready_set_authority', 'candidate-evidence-only')}")
    print(f"- Dispatch authorized: {str(bool(result.get('dispatch_authorized'))).lower()}")
    snapshot_sha256 = result.get("beads_readiness_snapshot_sha256")
    print(f"- Beads readiness snapshot: {snapshot_sha256 or 'unavailable'}")
    selected = result.get("recommended_ready_set") or []
    if selected:
        print("- Selected candidate IDs: " + ", ".join(item["id"] for item in selected))
    else:
        print("- Selected candidate IDs: none")
    print(
        "- Compatible safe cohorts: "
        + str(len(result.get("compatible_ready_sets") or []))
    )
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
    print("\n## Resume Commands")
    for item in result.get("resume_commands", []):
        print(f"- `{item}`")
    packet = result.get("operator_handoff_packet") or {}
    print("\n## Operator Handoff Packet")
    print(f"- Next executable Bead: {packet.get('next_executable_bead', '')}")
    print(f"- Why it is next: {packet.get('why_it_is_next', '')}")
    print(f"- Exact command/resume: {packet.get('exact_command_resume', '')}")
    print(f"- Execution prompt: {packet.get('execution_prompt', '')}")
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
    parser.add_argument(
        "--requested-workers",
        type=int,
        default=MAX_PHASE1_CANDIDATE_WORKERS,
        help=(
            "Requested bounded candidate size. Capacity policy and the Phase 1 "
            "ceiling still apply; this never grants dispatch authority."
        ),
    )
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
        requested_workers=args.requested_workers,
    )
    if args.format == "json":
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print_text(result, include_blocked=args.include_blocked)


if __name__ == "__main__":
    main()
