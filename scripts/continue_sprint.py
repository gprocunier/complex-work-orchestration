#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import shlex
from pathlib import Path
from typing import Any

from cwo_core.beads import bead_id_operand, run_bd
from cwo_core.beads_ready_set import (
    CONTAINER_LABELS,
    CONTAINER_TYPES,
    MAX_PHASE1_CANDIDATE_WORKERS,
    build_ready_set_evidence,
    markdown_fallback_evidence,
)
from cwo_core.util import artifact_hash, atomic_write_text, metadata_json
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


def _parent_query(parent_id: str, *, ready: bool) -> Any:
    # Beads accepts option-like parent values as literal filters. Reject them
    # before either query rather than treating an empty result as valid work.
    try:
        parent = bead_id_operand(parent_id)
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc
    args = ["ready" if ready else "list", "--json"]
    if not ready:
        args.append("--all")
    args.extend(["--parent", parent])
    if ready:
        args.append("--unassigned")
    return bd_json([*args, "--limit", "0"])


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
    return list(dict.fromkeys(dependency for entry in as_list(value) for dependency in dependency_entry_ids(entry)))


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
    names = ("dependencies", "depends_on", "depends_on_ids", "blocked_by", "blockers", "depends_on_lanes")
    return list(dict.fromkeys(value for name in names for value in dependency_list(field(item, name) or [])))


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


def load_beads_items(epic_id: str) -> list[dict[str, Any]]:
    """Load exact issue projections while taking readiness only from ``bd ready``."""

    ready_payload = _parent_query(epic_id, ready=True)
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
        children = coerce_items(_parent_query(parent_id, ready=False))
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
        exact_items.extend(coerce_items(bd_json(["show", "--json", "--", *chunk])))
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
                "title": markdown_project_title(path),
                "type": "epic",
                "status": "markdown-fallback",
                "labels": ["orchestration"],
            },
        )
    return items


def markdown_project_title(path: Path) -> str:
    try:
        with path.open(encoding="utf-8") as workgraph:
            return next((line[2:].strip() for line in workgraph if line.startswith(("# ", "#\t"))), "")
    except OSError as exc:
        raise SystemExit(f"could not read Markdown workgraph {path}: {exc}") from exc


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
        reasons.append("status is blocked")
    label_set = set(item["labels"])
    for label in sorted(label_set & CODEX_BLOCKING_LABELS):
        reasons.append(f"guard label {label} prevents normal Codex pickup")
    for dependency in item["dependencies"]:
        blockers = lookup.get(dependency, [])
        open_blockers = [blocker for blocker in blockers if blocker["id"] != item["id"] and not is_closed(blocker)]
        if open_blockers:
            for blocker in open_blockers:
                reasons.append(dependency_blocker(blocker))
        elif not blockers:
            reasons.append(f"depends on unknown work item {dependency}")
    return reasons


def affected_issues(item: dict[str, Any], items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    item_keys = {item["id"], str(field(item["raw"], "lane") or "")}
    return [
        candidate
        for candidate in items
        if candidate["id"] != item["id"]
        and not is_closed(candidate)
        and item_keys.intersection(candidate["dependencies"])
    ]


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
            -len(affected_issues(item, items)),
            label_rank(item["labels"]),
            item["id"],
        ),
    )


def issue_summary(item: dict[str, Any], *, reasons: list[str] | None = None) -> dict[str, Any]:
    fields = ("id", "title", "type", "status", "labels", "priority", "dependencies")
    result = {key: item[key] for key in fields}
    if reasons is not None:
        result["blockers"] = reasons
    return result


def issue_reference(item: dict[str, Any]) -> str:
    title = " ".join(issue_title(item).split())
    return f"{title or 'Untitled work item'} ({item['id']})"


def dependency_blocker(item: dict[str, Any]) -> str:
    return f"depends on {issue_reference(item)} ({item['status']})"


def infer_project_goal(items: list[dict[str, Any]], epic_id: str) -> str:
    epic = next((item for item in items if issue_id(item) == epic_id), {})
    title = issue_title(epic)
    return " ".join(title.split()) if title != issue_id(epic) else ""


def sprint_work_items(items: list[dict[str, Any]], epic_id: str) -> list[dict[str, Any]]:
    return [item for item in items if item["id"] != epic_id and item["type"].lower() != "epic"]


def definition_checks(
    *,
    epic_id: str,
    sprint_goal: str,
    items: list[dict[str, Any]],
    blocked: list[dict[str, Any]],
) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    has_dependencies = any(item["dependencies"] for item in items)
    ready = [
        ("Epic/objective is named", "met" if epic_id else "missing", epic_id or "no epic supplied"),
        ("Sprint goal is specific", "met" if sprint_goal else "missing", sprint_goal or "no sprint goal inferred"),
        ("Issue graph is small enough to execute", "met" if 1 <= len(items) <= 12 else "review",
         f"{len(items)} work items loaded"),
        ("Dependencies and blockers are explicit", "met" if has_dependencies or not blocked else "review",
         f"{len(blocked)} blocked work items reported"),
        ("Validation and evidence expectations are known", "met", "continuation brief lists validation and closeout evidence"),
    ]
    done = [
        ("Relevant issues are closed or carried forward", "close with closure-memory comments or file follow-up issues"),
        ("Evidence and results are captured", "record commands, outputs, artifacts, and residual risk"),
        ("Project artifacts and handoff are updated", "update docs/templates/tests and commit or handoff as requested"),
    ]
    return (
        [{"criterion": name, "status": status, "evidence": evidence} for name, status, evidence in ready],
        [{"criterion": name, "status": "pending", "evidence": evidence} for name, evidence in done],
    )


def continuation_commands(epic_id: str, sprint_id: str | None, source: str, path: str | None) -> list[str]:
    epic = shlex.quote(epic_id)
    command = f"python3 scripts/cwo.py continue --epic {epic}"
    if sprint_id:
        command += f" --sprint {shlex.quote(sprint_id)}"
    if source == "markdown-workgraph":
        workgraph = shlex.quote(path) if path else "<path>"
        return [
            f"{command} --markdown-workgraph {workgraph}",
            "move this reduced-durability workgraph into Beads before shared handoff",
        ]
    return [command, f"bd ready --json --parent {epic} --unassigned --limit 0"]


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
    work_items = sprint_work_items(items, epic_id)
    open_items = [item for item in work_items if not is_closed(item)]
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
    sprint_goal = infer_project_goal(items, epic_id)
    dor, dod = definition_checks(epic_id=epic_id, sprint_goal=sprint_goal, items=items, blocked=[item for item, _ in blocked])
    blocked_summaries = [issue_summary(item, reasons=reasons) for item, reasons in blocked]
    ready_summaries = [issue_summary(item) for item in ranked_ready]
    carry_forward = [
        issue_summary(item)
        for item in items
        if set(item["labels"]) & FOLLOWUP_LABELS and not is_closed(item)
    ]
    durability = "reduced" if source == "markdown-workgraph" else "durable"
    resume_commands = continuation_commands(epic_id, sprint_id, source, markdown_workgraph_path)
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
    result["status_summary"] = readable_status(result, work_items)
    return result


def operator_handoff_packet(result: dict[str, Any]) -> dict[str, str | None]:
    recommended = result.get("recommended_next_issue")
    blocked = handoff_blockers(result["blocked_issues"])
    resume_commands = result.get("resume_commands") or []
    resume = resume_commands[0] if resume_commands else "bd ready --json"
    next_action = None
    waiting_on = None
    if blocked:
        waiting_on = blocked_description(blocked[0])
    if recommended:
        next_bead = issue_reference(recommended)
        next_action = f"Continue {next_bead}"
        execution_prompt = (
            "Use $complex-work-orchestration to continue "
            f"{next_bead} under epic {result['epic_id']}; start with "
            f"`{resume}` and execute only that bounded lane."
        )
    elif blocked:
        next_bead = "none - blocked"
        execution_prompt = (
            f"BLOCKED: epic {result['epic_id']} has no ready issue. Review the "
            "recorded blocker before starting implementation."
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
            "dispatch it until the dispatch checks complete Beads claims, full drift and "
            "capability revalidation, proportionality, operative lease acquisition, "
            "and native-pool preflight."
        )
    return {
        "next_action": next_action,
        "waiting_on": waiting_on,
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
        "escalation_rule": "Record blockers and continue independent work. Bring operator decisions required by project rules to the operator.",
    }


def why_next(item: dict[str, Any] | None, items: list[dict[str, Any]]) -> str:
    if item is None:
        return "No ready work item is available."
    reasons = [f"priority {item['priority']}"]
    affected = affected_issues(item, items)
    if affected:
        reasons.append("removes a blocker for " + ", ".join(map(issue_reference, affected)))
    label_set = set(item["labels"])
    if label_set & VALIDATION_LABELS:
        reasons.append("closes validation evidence")
    elif label_set & FOLLOWUP_LABELS:
        reasons.append("tracks carry-forward work")
    else:
        reasons.append("has no unmet dependencies")
    return "; ".join(reasons)


def handoff_blockers(blocked: list[dict[str, Any]]) -> list[dict[str, Any]]:
    actionable = [
        item for item in blocked
        if any(not reason.startswith("grouping container") for reason in item["blockers"])
    ]
    return actionable or blocked


def blocked_description(item: dict[str, Any]) -> str:
    return f"{issue_reference(item)}: {', '.join(item['blockers'])}"


def readable_status(result: dict[str, Any], work_items: list[dict[str, Any]]) -> dict[str, str]:
    goal = result["sprint_goal"] or "Project goal is missing from the work graph."
    completed = [f"{issue_reference(item)} [{item['status']}]" for item in work_items if is_closed(item)]
    completed_text = (
        f"The work graph lists these closed tasks: {', '.join(completed)}. Verification was not checked."
        if completed else "No work is recorded as closed. Verification was not checked."
    )
    blocked = result["blocked_issues"]
    recommended = result["recommended_next_issue"]
    obstacles = [blocked_description(item) + "." for item in handoff_blockers(blocked)]
    return {
        **readable_next_step(recommended, blocked, work_items, bool(completed), goal),
        "goal": goal,
        "completed_and_verified": completed_text,
        "what_stands_in_the_way": " ".join(obstacles) if obstacles else "No blockers are recorded.",
    }


def readable_next_step(
    recommended: dict[str, Any] | None,
    blocked: list[dict[str, Any]],
    work_items: list[dict[str, Any]],
    has_closed_work: bool,
    goal: str,
) -> dict[str, str]:
    reader_action = "No decision is needed from you right now."
    if recommended:
        work_item = next(item for item in work_items if item["id"] == recommended["id"])
        task = issue_reference(recommended)
        return {
            "outcome": "The project has open work and a task is ready.",
            "next_step": f"The project team can continue {task}.",
            "what_it_enables": what_next_enables(work_item, work_items, blocked, goal),
            "reader_action": reader_action,
        }
    if blocked:
        item = handoff_blockers(blocked)[0]
        task = issue_reference(item)
        raw = next(work_item["raw"] for work_item in work_items if work_item["id"] == item["id"])
        assignee = field(raw, "assignee", "owner")
        prefix = f"{assignee} can" if assignee else "No owner is recorded. The next step is to"
        return {
            "outcome": "Work is blocked and no tasks are ready.",
            "next_step": f"{prefix} check what must change before {task} can proceed.",
            "what_it_enables": f"Resolving the recorded blocker lets the team reassess {task} for readiness.",
            "reader_action": "No decision is recorded for you.",
        }
    return {
        "outcome": "All tracked tasks have a closed status." if has_closed_work else "The work graph has no tasks to report.",
        "next_step": "No next step is needed.",
        "what_it_enables": "No further work depends on a next step in this scope.",
        "reader_action": reader_action,
    }


def what_next_enables(
    selected: dict[str, Any],
    work_items: list[dict[str, Any]],
    blocked: list[dict[str, Any]],
    goal: str,
) -> str:
    affected = affected_issues(selected, work_items)
    if not affected:
        return f"Finishing this step advances the project goal: {goal}"
    blockers_by_id = {item["id"]: item["blockers"] for item in blocked}
    removed = dependency_blocker(selected)
    effects = []
    for item in affected:
        reference = issue_reference(item)
        remaining = [reason for reason in blockers_by_id[item["id"]] if reason != removed]
        if remaining:
            effects.append(f"Finishing this step removes a blocker for {reference}. Other blockers: {', '.join(remaining)}.")
        else:
            effects.append(f"Finishing this step clears the only recorded blocker for {reference}.")
    return " ".join(effects)


def print_status_summary(summary: dict[str, str]) -> None:
    print("### Status Summary\n")
    for field in (
        "outcome", "goal", "completed_and_verified", "what_stands_in_the_way",
        "next_step", "what_it_enables", "reader_action",
    ):
        print(f"- {field.replace('_', ' ').capitalize()}: {summary[field]}")


def print_handoff_details(packet: dict[str, Any]) -> None:
    for field in (
        "Next action", "Waiting on", "Next executable Bead", "Why it is next", "Exact command/resume",
        "Execution prompt", "What must NOT run yet", "Commit/push status", "Validation status", "Escalation rule",
    ):
        key = field.lower().replace("/", " ").replace(" ", "_")
        print(f"- {field}: {packet[key]}")
    if "run_id" in packet:
        print(f"- Run ID: {packet['run_id']}")


def print_text(result: dict[str, Any], *, include_blocked: bool = False) -> None:
    print("# Sprint Continuation Brief\n")
    print("## Operator Handoff Packet\n")
    print_status_summary(result["status_summary"])
    print("\n### Execution Details\n")
    print(f"Epic: {result['epic_id']}")
    if result.get("sprint_id"):
        print(f"Sprint: {result['sprint_id']}")
    print(f"Durability: {result['durability']} ({result['source']})")
    print(f"Modeling note: {result['modeling_note']}\n")
    print_handoff_details(result["operator_handoff_packet"])
    recommended = result.get("recommended_next_issue")
    print("\n### Recommended Next Issue")
    if recommended:
        print(f"- {issue_reference(recommended)}")
        print(f"  Why: {result['why_next']}")
    else:
        print("- none")
        print(f"  Why: {result['why_next']}")
    print("\n### Ready Issues")
    for item in result.get("ready_issues", [])[:10]:
        print(f"- {issue_reference(item)} [{','.join(item['labels'])}]")
    if not result.get("ready_issues"):
        print("- none")
    print("\n### Bounded Ready-Set Candidate")
    print(f"- Decision: {result.get('fanout_decision', 'blocked')}")
    print(f"- Authority: {result.get('ready_set_authority', 'candidate-evidence-only')}")
    print(f"- Dispatch authorized: {str(bool(result.get('dispatch_authorized'))).lower()}")
    snapshot_sha256 = result.get("beads_readiness_snapshot_sha256")
    print(f"- Beads readiness snapshot: {snapshot_sha256 or 'unavailable'}")
    selected = result.get("recommended_ready_set") or []
    if selected:
        ready_by_id = {item["id"]: item for item in result["ranked_ready_issues"]}
        print("- Selected candidates: " + ", ".join(issue_reference(ready_by_id[item["id"]]) for item in selected))
    else:
        print("- Selected candidates: none")
    print(
        "- Compatible safe cohorts: "
        + str(len(result.get("compatible_ready_sets") or []))
    )
    blocked = result.get("blocked_issues", [])
    print("\n### Blocked Issues")
    display_blocked = blocked if include_blocked else blocked[:5]
    for item in display_blocked:
        print(f"- {issue_reference(item)}")
        for reason in item.get("blockers", []):
            print(f"  - {reason}")
    if not blocked:
        print("- none")
    elif not include_blocked and len(blocked) > len(display_blocked):
        print(f"- {len(blocked) - len(display_blocked)} more blocked issue(s); pass --include-blocked to show all.")
    print("\n### Evidence Expectations")
    for item in result.get("evidence_expectations", []):
        print(f"- {item}")
    print("\n### Resume Commands")
    for item in result.get("resume_commands", []):
        print(f"- `{item}`")
    warnings = result.get("warnings") or []
    if warnings:
        print("\n### Warnings")
        for item in warnings:
            print(f"- {item}")


def coach_decisions(coach: Any) -> list[str]:
    if not isinstance(coach, dict):
        raise ValueError("coach result must be a JSON object")
    required = coach.get("requires_user_selection_before_plan")
    decisions = coach.get("selection_before_plan_question_ids")
    if coach.get("coach_result_type") != "complex-work-orchestration-prompt-coach" or type(required) is not bool:
        raise ValueError("expected a CWO coach JSON result with a selection gate")
    if not required:
        return []
    if not isinstance(decisions, list) or not decisions or not all(
        isinstance(item, str) and re.fullmatch(r"[a-z0-9_-]+", item) for item in decisions
    ):
        raise ValueError("coach selection gate needs decision IDs")
    return decisions


def record_run(args: argparse.Namespace, result: dict[str, Any], decisions: list[str]) -> None:
    workspace = Path.cwd()
    workgraph = args.markdown_workgraph.resolve() if args.markdown_workgraph else None
    scope = [str(workspace), args.epic, args.sprint, str(workgraph) if workgraph else None]
    run_id = artifact_hash(metadata_json({"scope": scope}))
    path = workspace / ".orchestration-audit" / "active-runs" / f"{run_id}.json"
    if path.parent.resolve() != path.parent:
        raise ValueError("the active run directory must be local to the current workspace")
    command = ["python3", str(Path(__file__).with_name("cwo.py").resolve()), "continue", "--record-run"]
    options = vars(args)
    for name in ("epic", "sprint", "markdown_workgraph", "coach", "requested_workers", "format"):
        if (value := options[name]) is not None:
            command.append(f"--{name.replace('_', '-')}={value}")
    if args.include_blocked:
        command.append("--include-blocked")
    next_issue = result["recommended_next_issue"]
    blocked = handoff_blockers(result["blocked_issues"])
    gate = "ready" if next_issue else "blocked" if result["blocked_issues"] else "no-work"
    step = next_issue or (blocked[0] if blocked else None)
    state = {
        "version": 1,
        "run_id": run_id,
        "current_step": "coach" if decisions else (step["id"] if step else None),
        "current_gate": "operator-selection" if decisions else gate,
        "operator_decision_frontier": decisions,
        "resume_command": f"cd {shlex.quote(str(workspace))} && {shlex.join(command)}",
    }
    atomic_write_text(path, json.dumps(state, indent=2, sort_keys=True) + "\n")
    result.update(run_state=state, run_state_path=str(path))
    result["resume_commands"][0] = state["resume_command"]
    packet = result["operator_handoff_packet"] = operator_handoff_packet(result)
    packet["run_id"] = run_id
    if decisions:
        reason = "The coach is waiting for operator selections."
        packet.update(
            next_action=None,
            waiting_on="Operator selection: " + ", ".join(decisions),
            next_executable_bead="none - operator selection required",
            why_it_is_next=reason,
            execution_prompt="Resolve the current coach selections and rerun continuation with the updated coach result.",
        )
        result.update(recommended_next_issue=None, why_next=reason)
        result["status_summary"].update(
            outcome=reason,
            what_stands_in_the_way=packet["waiting_on"],
            next_step="Resolve the coach selections (coach-selection) and update the coach result.",
            what_it_enables="An updated coach result lets the team reassess the plan.",
            reader_action="Please resolve: " + ", ".join(decisions),
        )


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
    parser.add_argument("--record-run", action="store_true", help="Save the current continuation in the ignored run directory.")
    parser.add_argument("--coach", type=Path, help="Current coach JSON result for the recorded operator decision frontier.")
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
    if args.coach and not args.record_run:
        parser.error("--coach requires --record-run")
    try:
        decisions = coach_decisions(json.loads(args.coach.read_text(encoding="utf-8"))) if args.coach else []
    except (OSError, ValueError) as exc:
        parser.error(str(exc))

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
    if args.record_run:
        try:
            record_run(args, result, decisions)
        except (OSError, ValueError) as exc:
            parser.error(str(exc))
    if args.format == "json":
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print_text(result, include_blocked=args.include_blocked)
        if args.record_run:
            print(f"\nRun gate: {result['run_state']['current_gate']}")
            print(f"Run state: {result['run_state_path']}")


if __name__ == "__main__":
    main()
