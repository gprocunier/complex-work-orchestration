#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

from cwo_core.beads import run_bd
from cwo_core.workgraph_markdown import (
    FIELD_DEPENDS_ON_LANES,
    FIELD_LABELS,
    FIELD_LANE,
    FIELD_STATUS,
    FIELD_TYPE,
    WORKGRAPH_FALLBACK_MARKER,
    WORKGRAPH_ITEMS_HEADING,
    normalize_field_label,
)

WORKGRAPH_HEADING_RE = re.compile(r"^###\s+([^:\n]+):\s*(.+?)\s*$")
WORKGRAPH_FIELD_RE = re.compile(r"^-\s+([^:]+):\s*(.+?)\s*$")
WORKGRAPH_SCALAR_FIELDS = {FIELD_TYPE.lower(): "type", FIELD_STATUS.lower(): "status", FIELD_LANE.lower(): "lane"}
WORKGRAPH_LIST_FIELDS = {FIELD_LABELS.lower(): "labels", FIELD_DEPENDS_ON_LANES.lower(): "depends_on_lanes"}
WORKGRAPH_ROUTE_NOTES = {"Route": "route", "Share boundary": "share_boundary", "Risk": "risk_level"}


def bd_json(args: list[str]) -> Any:
    return json.loads(run_bd(args))


def coerce_items(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]
    if isinstance(value, dict):
        for key in ["issues", "items", "data"]:
            if isinstance(value.get(key), list):
                return [item for item in value[key] if isinstance(item, dict)]
    return []


def labels(item: dict[str, Any]) -> str:
    raw = item.get("labels", [])
    return ",".join(str(label) for label in raw) if isinstance(raw, list) else str(raw)


def field(item: dict[str, Any], *names: str) -> str:
    for name in names:
        if item.get(name) is not None:
            return str(item[name])
    return ""


def summarize(title: str, items: list[dict[str, Any]], limit: int) -> None:
    print(f"## {title}")
    if not items:
        print("None reported.\n")
        return
    for item in items[:limit]:
        print(f"- {field(item, 'id', 'issue_id')} {field(item, 'title', 'summary')} [{field(item, 'status') or 'unknown'}; {labels(item)}]")
    print()


def markdown_values(value: str) -> list[str]:
    if value.strip() == "none":
        return []
    return [match.strip() for match in re.findall(r"`([^`]+)`", value)]


def read_workgraph_field(current: dict[str, Any], line: str) -> None:
    if match := WORKGRAPH_FIELD_RE.match(line):
        name = normalize_field_label(match.group(1))
        value = match.group(2).strip()
        if name in WORKGRAPH_LIST_FIELDS:
            current[WORKGRAPH_LIST_FIELDS[name]] = markdown_values(value)
        elif name in WORKGRAPH_SCALAR_FIELDS:
            current[WORKGRAPH_SCALAR_FIELDS[name]] = ", ".join(markdown_values(value)) or value


def parse_markdown_workgraph(path: Path, *, include_route: bool = False) -> list[dict[str, Any]]:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise SystemExit(f"could not read Markdown workgraph {path}: {exc}") from exc

    if WORKGRAPH_FALLBACK_MARKER not in text or WORKGRAPH_ITEMS_HEADING not in text:
        raise SystemExit(f"{path} is not a CWO Markdown workgraph fallback")

    items: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    in_notes = False
    for raw_line in text.splitlines():
        line = raw_line.strip()
        heading = WORKGRAPH_HEADING_RE.match(line)
        if heading:
            current = {
                "id": heading.group(1).strip(),
                "title": heading.group(2).strip(),
                "status": "markdown-fallback",
                "labels": [],
            }
            items.append(current)
            in_notes = False
            continue
        if current is None:
            continue
        if include_route and line.startswith("#### "):
            in_notes = line == "#### Notes"
        if in_notes:
            label, _, value = line.partition(": ")
            if label in WORKGRAPH_ROUTE_NOTES:
                current.setdefault("orchestration_route", {})[WORKGRAPH_ROUTE_NOTES[label]] = value
        read_workgraph_field(current, line)

    if not items:
        raise SystemExit(f"{path} does not contain any Markdown workgraph items")
    return items


def summarize_markdown_workgraph(path: Path, limit: int) -> None:
    print("## Markdown workgraph fallback")
    print(
        "Beads state was unavailable, so this summary is reduced-durability fallback state. "
        "Do not treat it as shared ready-work or contractor handoff authority.\n"
    )
    print(f"Resume fallback: `python3 scripts/summarize_resume_state.py --markdown-workgraph {path}`\n")
    summarize("Markdown workgraph items", parse_markdown_workgraph(path), limit)


def main() -> None:
    parser = argparse.ArgumentParser(description="Summarize Beads state for orchestration resume.")
    parser.add_argument("--ready-limit", type=int, default=10)
    parser.add_argument("--open-limit", type=int, default=20)
    parser.add_argument(
        "--markdown-workgraph",
        type=Path,
        help="Summarize a reduced-durability Markdown workgraph when Beads state is unavailable.",
    )
    args = parser.parse_args()

    print("# Orchestration Resume State\n")
    print("Workerbee-ready: `bd ready --exclude-label contractor-only --exclude-label local-worker-only --exclude-label no-codex-exec --json`")
    print("Contractor dispatch: `bd ready --label contractor-only --json`")
    print("Local-worker dispatch: `bd ready --label local-worker-only --json`")
    print("Evaluation/adjudication: `bd ready --label evaluation --json` and `bd ready --label adjudication --json`\n")

    commands = [
        (
            "Codex-ready work",
            [
                "ready",
                "--exclude-label",
                "contractor-only",
                "--exclude-label",
                "local-worker-only",
                "--exclude-label",
                "no-codex-exec",
                "--json",
            ],
            args.ready_limit,
        ),
        ("Contractor-only work", ["ready", "--label", "contractor-only", "--json"], args.ready_limit),
        ("Local-worker work", ["ready", "--label", "local-worker-only", "--json"], args.ready_limit),
        ("Evaluation gates", ["ready", "--label", "evaluation", "--json"], args.ready_limit),
        ("Architect adjudication gates", ["ready", "--label", "adjudication", "--json"], args.ready_limit),
        ("Open graph", ["list", "--json"], args.open_limit),
    ]
    beads_unavailable = False
    for title, command, limit in commands:
        try:
            summarize(title, coerce_items(bd_json(command)), limit)
        except SystemExit as exc:
            beads_unavailable = True
            print(f"## {title}\nUnable to read: {exc}\n")
    if beads_unavailable and args.markdown_workgraph:
        summarize_markdown_workgraph(args.markdown_workgraph, args.open_limit)


if __name__ == "__main__":
    main()
