#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from typing import Any

from cwo_core.beads import run_bd


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


def main() -> None:
    parser = argparse.ArgumentParser(description="Summarize Beads state for orchestration resume.")
    parser.add_argument("--ready-limit", type=int, default=10)
    parser.add_argument("--open-limit", type=int, default=20)
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
    for title, command, limit in commands:
        try:
            summarize(title, coerce_items(bd_json(command)), limit)
        except SystemExit as exc:
            print(f"## {title}\nUnable to read: {exc}\n")


if __name__ == "__main__":
    main()
