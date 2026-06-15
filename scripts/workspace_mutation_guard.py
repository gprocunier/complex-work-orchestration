#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

from cwo_core.workspace import (
    capture_tracked_workspace_state,
    diff_workspace_state,
)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Capture or compare tracked git workspace state around an external contractor run."
    )
    parser.add_argument("--workspace-root", default=".", help="Git workspace root to inspect.")
    parser.add_argument("--snapshot", action="store_true", help="Capture current tracked-file state.")
    parser.add_argument("--compare", metavar="BEFORE_JSON", help="Compare a prior snapshot with current state.")
    parser.add_argument("--allow-path", action="append", default=[], help="Path prefix allowed to change.")
    parser.add_argument(
        "--include-untracked",
        action="store_true",
        help="Include untracked files in the snapshot/compare. Default is tracked files only.",
    )
    parser.add_argument(
        "--require-clean",
        action="store_true",
        help="Treat any pre-existing tracked-file change in the before snapshot as unexpected.",
    )
    parser.add_argument("--output", help="Write JSON output to this path instead of stdout.")
    args = parser.parse_args()

    if bool(args.snapshot) == bool(args.compare):
        raise SystemExit("choose exactly one of --snapshot or --compare BEFORE_JSON")

    if args.snapshot:
        result = capture_tracked_workspace_state(Path(args.workspace_root), include_untracked=args.include_untracked)
    else:
        before = json.loads(Path(args.compare).read_text(encoding="utf-8"))
        after = capture_tracked_workspace_state(Path(args.workspace_root), include_untracked=args.include_untracked)
        result = diff_workspace_state(
            before,
            after,
            allowed_paths=args.allow_path,
            require_clean=args.require_clean,
        )

    rendered = json.dumps(result, indent=2, sort_keys=True)
    if args.output:
        Path(args.output).write_text(rendered + "\n", encoding="utf-8")
    else:
        print(rendered)


if __name__ == "__main__":
    main()
