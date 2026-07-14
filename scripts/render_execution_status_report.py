#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from cwo_core.execution_status_report import (
    build_execution_status_report,
    load_audit_events,
    load_json_document,
    load_json_documents,
    render_terminal,
)
from cwo_core.paths import AUDIT_LOG


def _path_list(values: list[str] | None) -> list[Path]:
    return [Path(value) for value in values or []]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Render a CWO end-of-plan execution status report from explicit "
            "audit, readiness, evaluator, and return-bundle artifacts."
        )
    )
    parser.add_argument("--audit-log", action="append", help="Audit JSONL path. Defaults to .orchestration-audit/audit.jsonl when present.")
    parser.add_argument("--readiness-plan", help="Optional run-readiness JSON plan.")
    parser.add_argument("--acceptance-decision", action="append", help="Acceptance-decision JSON artifact. May be repeated.")
    parser.add_argument("--return-bundle", action="append", help="Contractor/local return-bundle JSON artifact. May be repeated.")
    parser.add_argument(
        "--convergence-summary",
        action="append",
        help="Epic-convergence replay summary JSON artifact. May be repeated; the latest is projected.",
    )
    parser.add_argument("--format", choices=["terminal", "json"], default="terminal")
    parser.add_argument(
        "--layout",
        choices=["dashboard", "expanded", "summary"],
        default="dashboard",
        help="Terminal layout. dashboard is the compact default; expanded fans out long utilization cells; summary uses grouped tables.",
    )
    parser.add_argument("--width", type=int, help="Terminal render width. Defaults to the current terminal width.")
    args = parser.parse_args(argv)

    audit_paths = _path_list(args.audit_log)
    if not audit_paths and AUDIT_LOG.exists():
        audit_paths = [AUDIT_LOG]

    try:
        audit_events = load_audit_events(audit_paths)
        readiness_plan = load_json_document(Path(args.readiness_plan)) if args.readiness_plan else None
        decisions = load_json_documents(_path_list(args.acceptance_decision))
        bundles = load_json_documents(_path_list(args.return_bundle))
        convergence_summaries = load_json_documents(_path_list(args.convergence_summary))
    except (OSError, ValueError, json.JSONDecodeError, SystemExit) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    source_files = {
        "audit_logs": [str(path) for path in audit_paths],
        "readiness_plan": args.readiness_plan,
        "acceptance_decisions": args.acceptance_decision or [],
        "return_bundles": args.return_bundle or [],
        "convergence_summaries": args.convergence_summary or [],
    }
    report = build_execution_status_report(
        audit_events=audit_events,
        acceptance_decisions=decisions,
        return_bundles=bundles,
        readiness_plan=readiness_plan,
        convergence_summaries=convergence_summaries,
        source_files=source_files,
    )
    if args.format == "json":
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(render_terminal(report, width=args.width, layout=args.layout), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
