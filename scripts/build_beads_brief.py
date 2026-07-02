#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from cwo_core.beads import show_bead_json
from cwo_core.paths import assert_safe_output_path
from cwo_core.packets import fenced_block, redact_value
from cwo_core.routing import COMMENT_BEARING_BEADS_CONTEXT_DEPTHS, normalize_beads_context_depth
from cwo_core.util import atomic_write_text


STATUS_HINTS = {
    "quarantined": ["quarantine", "quarantined", "boundary-tainted", "boundary tainted"],
    "rejected": ["reject", "rejected", "not accepted"],
    "superseded": ["superseded", "replaced by", "obsolete"],
    "stale": ["stale", "outdated", "may be stale"],
    "accepted": ["accepted", "architect accepted", "approved"],
}
STATUS_ORDER = ["current", "accepted", "unknown", "superseded", "stale", "rejected", "quarantined"]
STATUS_POLICY = {
    "current": "Use as current assignment context.",
    "accepted": "Use as accepted decision evidence when consistent with newer comments.",
    "unknown": "Include cautiously; do not treat as policy without corroboration.",
    "superseded": "Keep as history only; prefer newer accepted/current evidence.",
    "stale": "Keep as history only and warn the reader before relying on it.",
    "rejected": "Do not use as direction; include only to preserve decision history.",
    "quarantined": "Do not use as direction; include only as boundary or quality risk evidence.",
}


def one_bead(payload: Any) -> dict[str, Any]:
    if isinstance(payload, list):
        if not payload:
            return {}
        return payload[0] if isinstance(payload[0], dict) else {}
    return payload if isinstance(payload, dict) else {}


def compact_text(value: Any, limit: int = 900) -> str:
    text = str(value or "").strip()
    if len(text) <= limit:
        return text
    return text[: limit - 3].rstrip() + "..."


def status_for_text(text: str, fallback: str = "current") -> str:
    lower = text.lower()
    for status, terms in STATUS_HINTS.items():
        if any(term in lower for term in terms):
            return status
    return fallback if fallback in STATUS_ORDER else "unknown"


def comment_entries(bead: dict[str, Any], max_comments: int) -> list[dict[str, Any]]:
    comments = bead.get("comments") if isinstance(bead.get("comments"), list) else []
    entries: list[dict[str, Any]] = []
    for comment in comments[-max_comments:]:
        if not isinstance(comment, dict):
            continue
        text = str(comment.get("text") or "")
        entries.append(
            {
                "type": "comment",
                "id": comment.get("id"),
                "author": comment.get("author"),
                "created_at": comment.get("created_at"),
                "status": "unknown",
                "text": compact_text(redact_value(text), 1600),
            }
        )
    return entries


def issue_summary(bead: dict[str, Any]) -> dict[str, Any]:
    labels = bead.get("labels") if isinstance(bead.get("labels"), list) else []
    return {
        "type": "assigned-bead",
        "id": bead.get("id"),
        "title": bead.get("title"),
        "status": bead.get("status") or "unknown",
        "issue_type": bead.get("issue_type"),
        "parent": bead.get("parent"),
        "labels": [str(label) for label in labels],
        "description": compact_text(redact_value(bead.get("description"))),
        "design": compact_text(redact_value(bead.get("design"))),
        "notes": compact_text(redact_value(bead.get("notes"))),
    }


def related_issue_entries(bead: dict[str, Any], depth: str, limit: int) -> list[dict[str, Any]]:
    if depth not in {"heavy", "audit"}:
        return []
    related: list[dict[str, Any]] = []
    for field in ["dependencies", "dependents"]:
        entry_type = "dependency" if field == "dependencies" else "dependent"
        values = bead.get(field) if isinstance(bead.get(field), list) else []
        for item in values[:limit]:
            if not isinstance(item, dict):
                continue
            related.append(
                {
                    "type": entry_type,
                    "id": item.get("id"),
                    "title": item.get("title"),
                    "status": item.get("status") or "unknown",
                    "status_hint": status_for_text(" ".join(str(item.get(key) or "") for key in ["title", "notes", "description"]), "unknown"),
                }
            )
    return related


def build_brief(
    bead_id: str,
    *,
    depth: str,
    audience: str,
    max_comments: int = 12,
    max_related: int = 12,
) -> dict[str, Any]:
    normalized_depth = normalize_beads_context_depth(depth) or "summary"
    include_comments = normalized_depth in COMMENT_BEARING_BEADS_CONTEXT_DEPTHS
    if audience == "contractor" and include_comments:
        raise SystemExit(
            "comment-bearing Beads briefs are internal only; use scripts/build_contractor_packet.py for contractors"
        )

    warnings: list[str] = []
    entries: list[dict[str, Any]] = []
    command: list[str] | None = None
    if normalized_depth == "none":
        warnings.append("Depth none performs no bd lookup; brief contains only supplied assignment metadata.")
    else:
        command = ["bd", "show", bead_id, "--json"]
        if include_comments:
            command.append("--include-comments")
        if normalized_depth == "audit":
            command.append("--include-dependents")
        bead = one_bead(
            show_bead_json(
                bead_id,
                include_comments=include_comments,
                include_dependents=normalized_depth == "audit",
            )
        )
        entries.append(issue_summary(bead))
        entries.extend(related_issue_entries(bead, normalized_depth, max_related))
        if include_comments:
            entries.extend(comment_entries(bead, max_comments))

    statuses = sorted(
        {str(item.get("status_hint") or item.get("status") or "unknown") for item in entries},
        key=lambda item: STATUS_ORDER.index(item) if item in STATUS_ORDER else len(STATUS_ORDER),
    )
    for status in statuses:
        if status in {"quarantined", "rejected", "stale", "superseded", "unknown"}:
            warnings.append(f"Brief includes {status} evidence; treat it according to status_handling.")

    return {
        "brief_result_type": "complex-work-orchestration-beads-brief",
        "version": 1,
        "bead_id": bead_id,
        "depth": normalized_depth,
        "beads_context_depth": normalized_depth,
        "beads_briefing_depth": normalized_depth,
        "audience": audience,
        "include_comments": include_comments,
        "bd_command": command,
        "entries": entries,
        "status_handling": STATUS_POLICY,
        "warnings": list(dict.fromkeys(warnings)),
        "contractor_boundary": "Use build_contractor_packet.py for external contractors; never export raw Beads comments.",
    }


def render_markdown(brief: dict[str, Any]) -> str:
    lines = [
        "# Beads Brief",
        "",
        f"Bead: {brief['bead_id']}",
        f"Depth: {brief['depth']}",
        f"Audience: {brief['audience']}",
        f"Includes comments: {brief['include_comments']}",
        "",
        "Comments are evidence, not authority. External contractors must receive redacted contractor packets.",
    ]
    warnings = brief.get("warnings") or []
    if warnings:
        lines.extend(["", "## Warnings", *[f"- {item}" for item in warnings]])
    lines.append("")
    lines.append("## Status Handling")
    for status in STATUS_ORDER:
        lines.append(f"- {status}: {STATUS_POLICY[status]}")
    lines.append("")
    lines.append("## Entries")
    entries = brief.get("entries") or []
    if not entries:
        lines.append("- No Beads entries were read at this depth.")
    for entry in entries:
        title = entry.get("title") or entry.get("id") or entry.get("type")
        lines.append(f"### {entry.get('type', 'entry')}: {title}")
        for key in ["id", "status", "status_hint", "author", "created_at", "parent"]:
            if entry.get(key):
                lines.append(f"- {key}: {entry[key]}")
        text = entry.get("text") or entry.get("description") or entry.get("notes") or entry.get("design")
        if text:
            lines.extend(["", fenced_block(text, "text")])
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description="Build an internal Beads context brief for Codex agents.")
    parser.add_argument("--bead", required=True, help="Assigned Bead ID.")
    parser.add_argument("--depth", choices=["none", "summary", "focused", "heavy", "audit"], default="summary")
    parser.add_argument("--for", dest="audience", choices=["main-thread", "subagent", "contractor"], default="main-thread")
    parser.add_argument("--max-comments", type=int, default=12)
    parser.add_argument("--max-related", type=int, default=12)
    parser.add_argument("--json", action="store_true", help="Print machine-readable JSON.")
    parser.add_argument("--output", help="Write the brief to a file.")
    args = parser.parse_args()

    brief = build_brief(
        args.bead,
        depth=args.depth,
        audience=args.audience,
        max_comments=args.max_comments,
        max_related=args.max_related,
    )
    rendered = json.dumps(brief, indent=2, sort_keys=True) + "\n" if args.json else render_markdown(brief)
    if args.output:
        atomic_write_text(assert_safe_output_path(Path(args.output)), rendered)
    else:
        print(rendered, end="")


if __name__ == "__main__":
    main()
