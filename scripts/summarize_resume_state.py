#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from typing import Any

from orchestration_lib import run_bd


def bd_json(args: list[str]) -> Any:
    output = run_bd(args)
    return json.loads(output)


def coerce_items(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]
    if isinstance(value, dict):
        for key in ["issues", "items", "data"]:
            items = value.get(key)
            if isinstance(items, list):
                return [item for item in items if isinstance(item, dict)]
    return []


def field(item: dict[str, Any], *names: str) -> str:
    for name in names:
        value = item.get(name)
        if value is not None:
            return str(value)
    return ""


def summarize_items(title: str, items: list[dict[str, Any]], limit: int) -> None:
    print(f"## {title}")
    if not items:
        print("None reported.")
        print()
        return
    for item in items[:limit]:
        labels = item.get("labels", [])
        if isinstance(labels, list):
            label_text = ",".join(str(label) for label in labels)
        else:
            label_text = str(labels)
        print(
            f"- {field(item, 'id', 'issue_id')} "
            f"{field(item, 'title', 'summary')} "
            f"[{field(item, 'status') or 'unknown'}; {label_text}]"
        )
    print()


def main() -> None:
    parser = argparse.ArgumentParser(description="Summarize Beads state for session resume.")
    parser.add_argument("--ready-limit", type=int, default=10, help="Maximum ready items to show.")
    parser.add_argument("--open-limit", type=int, default=20, help="Maximum open items to show.")
    args = parser.parse_args()

    print("# Orchestration Resume State")
    print()
    print("Workerbee-ready command:")
    print("`bd ready --exclude-label contractor-only --exclude-label no-codex-exec --json`")
    print()
    print("Contractor dispatch command:")
    print("`bd ready --label contractor-only --json`")
    print()

    try:
        ready = coerce_items(bd_json(["ready", "--exclude-label", "contractor-only", "--exclude-label", "no-codex-exec", "--json"]))
        summarize_items("Codex-ready work", ready, args.ready_limit)
    except SystemExit as exc:
        print(f"## Codex-ready work\nUnable to read ready work: {exc}\n")

    try:
        contractors = coerce_items(bd_json(["ready", "--label", "contractor-only", "--json"]))
        summarize_items("Contractor-only work", contractors, args.ready_limit)
    except SystemExit as exc:
        print(f"## Contractor-only work\nUnable to read contractor work: {exc}\n")

    try:
        open_items = coerce_items(bd_json(["list", "--json"]))
        summarize_items("Open graph", open_items, args.open_limit)
    except SystemExit as exc:
        print(f"## Open graph\nUnable to read open graph: {exc}\n")


if __name__ == "__main__":
    main()
