#!/usr/bin/env python3
from __future__ import annotations

import runpy
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent

COMMANDS = {
    "coach": "coach_prompt.py",
    "route": "route_work.py",
    "scaffold": "scaffold_workgraph.py",
    "beads-brief": "build_beads_brief.py",
    "build-packet": "build_contractor_packet.py",
    "dispatch": "dispatch_work.py",
    "manual-prompt": "generate_manual_dispatch_prompt.py",
    "browser-review": "chatgpt_browser_review.py",
    "ingest-share": "ingest_chatgpt_share_return.py",
    "evaluate": "evaluate_return.py",
    "harness": "render_harness_dispatch.py",
    "import-telemetry": "import_execution_telemetry.py",
    "status-report": "render_execution_status_report.py",
    "close-bead": "close_bead_with_summary.py",
    "cleanup-stale-agents": "cleanup_stale_agents.py",
    "continue": "continue_sprint.py",
}


def print_help() -> None:
    print("Usage: python3 scripts/cwo.py <command> [args...]")
    print()
    print("Commands:")
    for command in sorted(COMMANDS):
        print(f"  {command}")
    print()
    print("Run `python3 scripts/cwo.py <command> --help` for command-specific help.")


def main(argv: list[str] | None = None) -> None:
    args = list(sys.argv[1:] if argv is None else argv)
    if not args or args[0] in {"-h", "--help"}:
        print_help()
        return
    command = args.pop(0)
    target = COMMANDS.get(command)
    if target is None:
        print(f"unknown cwo command: {command}", file=sys.stderr)
        print("Run `python3 scripts/cwo.py --help` for available commands.", file=sys.stderr)
        raise SystemExit(2)
    script = SCRIPT_DIR / target
    sys.argv = [str(script), *args]
    runpy.run_path(str(script), run_name="__main__")


if __name__ == "__main__":
    main()
