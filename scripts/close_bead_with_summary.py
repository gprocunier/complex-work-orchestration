#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from typing import Any

from orchestration_lib import run_bd

NO_VALUE = "None recorded."


def clean_text(value: str) -> str:
    return value.strip().replace("\\n", "\n")


def require_text(value: str, field_name: str) -> str:
    text = clean_text(value)
    if not text:
        raise ValueError(f"{field_name} is required")
    return text


def format_bullets(title: str, values: list[str], fallback: str = NO_VALUE) -> list[str]:
    items = [clean_text(value) for value in values if clean_text(value)]
    if not items:
        items = [fallback]

    lines = [f"{title}:"]
    for item in items:
        item_lines = item.splitlines() or [""]
        lines.append(f"- {item_lines[0]}")
        for line in item_lines[1:]:
            lines.append(f"  {line}")
    return lines


def render_closure_summary(
    *,
    bead: str,
    disposition: str,
    why: str,
    decisions: list[str],
    evidence: list[str],
    residual_risk: list[str],
    follow_up: list[str],
) -> str:
    bead = require_text(bead, "bead")
    disposition = require_text(disposition, "disposition")
    why = require_text(why, "why")

    lines = [
        "Closure summary:",
        f"- Bead: {bead}",
        f"- Disposition: {disposition}",
        f"- Why: {why}",
        "",
        *format_bullets("Key decisions", decisions),
        "",
        *format_bullets("Evidence", evidence),
        "",
        *format_bullets("Residual risk", residual_risk),
        "",
        *format_bullets("Follow-up", follow_up),
    ]
    return "\n".join(lines).rstrip() + "\n"


def default_close_reason(disposition: str, why: str) -> str:
    return f"{clean_text(disposition)}: {clean_text(why)}"


def execute(args: argparse.Namespace) -> dict[str, Any]:
    summary = render_closure_summary(
        bead=args.bead,
        disposition=args.disposition,
        why=args.why,
        decisions=args.decision or [],
        evidence=args.evidence or [],
        residual_risk=args.residual_risk or [],
        follow_up=args.follow_up or [],
    )
    close_reason = clean_text(args.close_reason) if args.close_reason else default_close_reason(args.disposition, args.why)
    result = {
        "bead": clean_text(args.bead),
        "summary": summary,
        "dry_run": bool(args.dry_run),
        "comment_posted": False,
        "close_requested": bool(args.close),
        "closed": False,
        "close_reason": close_reason,
    }

    if args.dry_run:
        return result

    run_bd(["comment", clean_text(args.bead), summary])
    result["comment_posted"] = True

    if args.close:
        run_bd(["close", clean_text(args.bead), "--reason", close_reason])
        result["closed"] = True

    return result


def parser() -> argparse.ArgumentParser:
    cli = argparse.ArgumentParser(
        description="Add a final closure-memory comment to a Bead and optionally close it."
    )
    cli.add_argument("--bead", required=True, help="Bead ID to comment on.")
    cli.add_argument("--disposition", required=True, help="completed, rejected, superseded, abandoned, split, or similar.")
    cli.add_argument("--why", required=True, help="Short reason the Bead is being closed.")
    cli.add_argument("--decision", action="append", default=[], help="Key decision to preserve. Repeatable.")
    cli.add_argument("--evidence", action="append", default=[], help="Evidence, command, commit, file, or artifact. Repeatable.")
    cli.add_argument("--residual-risk", action="append", default=[], help="Residual risk future agents should know. Repeatable.")
    cli.add_argument("--follow-up", action="append", default=[], help="Follow-up Bead, action, or 'none'. Repeatable.")
    cli.add_argument("--close", action="store_true", help="Close the Bead after posting the closure comment.")
    cli.add_argument("--close-reason", help="Short bd close reason. Defaults to '<disposition>: <why>'.")
    cli.add_argument("--dry-run", action="store_true", help="Print what would be posted without calling bd.")
    cli.add_argument("--json", action="store_true", help="Print structured result JSON.")
    return cli


def main(argv: list[str] | None = None) -> None:
    cli = parser()
    args = cli.parse_args(argv)
    try:
        result = execute(args)
    except (ValueError, SystemExit) as exc:
        print(f"close_bead_with_summary failed: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc

    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
        return

    print(result["summary"], end="")
    if args.dry_run:
        if args.close:
            print(f"\nDry run: would close {result['bead']} with reason: {result['close_reason']}")
        return
    if args.close:
        print(f"\nClosed {result['bead']} with reason: {result['close_reason']}")
    else:
        print(f"\nPosted closure summary to {result['bead']}.")


if __name__ == "__main__":
    main()
