#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from typing import Any

from cwo_core.beads import run_bd

NO_VALUE = "None recorded."
MEANINGFUL_REQUIRED_FIELDS = {
    "who_involved": "who was involved",
    "what_changed": "what changed",
    "how_validated": "how validated",
    "when_closed": "when closed",
    "where_executed": "where executed",
    "evidence": "evidence",
    "residual_risk": "residual risk",
    "follow_up": "follow-up",
}


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


def clean_items(values: list[str] | None) -> list[str]:
    return [clean_text(value) for value in (values or []) if clean_text(value)]


def closure_memory_missing_fields(
    *,
    who_involved: list[str] | None = None,
    what_changed: list[str] | None = None,
    how_validated: list[str] | None = None,
    when_closed: list[str] | None = None,
    where_executed: list[str] | None = None,
    evidence: list[str] | None = None,
    residual_risk: list[str] | None = None,
    follow_up: list[str] | None = None,
) -> list[str]:
    values = {
        "who_involved": who_involved,
        "what_changed": what_changed,
        "how_validated": how_validated,
        "when_closed": when_closed,
        "where_executed": where_executed,
        "evidence": evidence,
        "residual_risk": residual_risk,
        "follow_up": follow_up,
    }
    missing = [
        MEANINGFUL_REQUIRED_FIELDS[field]
        for field, field_values in values.items()
        if not clean_items(field_values)
    ]
    return missing


def closure_memory_warnings(missing_fields: list[str]) -> list[str]:
    if not missing_fields:
        return []
    return [
        "closure-memory is incomplete for meaningful work; missing "
        + ", ".join(missing_fields)
    ]


def render_closure_summary(
    *,
    bead: str,
    disposition: str,
    why: str,
    who_involved: list[str] | None = None,
    what_changed: list[str] | None = None,
    how_validated: list[str] | None = None,
    when_closed: list[str] | None = None,
    where_executed: list[str] | None = None,
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
        *format_bullets("Who was involved", who_involved or []),
        "",
        *format_bullets("What changed", what_changed or []),
        "",
        *format_bullets("How validated", how_validated or []),
        "",
        *format_bullets("When closed", when_closed or []),
        "",
        *format_bullets("Where executed", where_executed or []),
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
    who_involved = getattr(args, "who_involved", []) or []
    what_changed = getattr(args, "what_changed", []) or []
    how_validated = getattr(args, "how_validated", []) or []
    when_closed = getattr(args, "when_closed", []) or []
    where_executed = getattr(args, "where_executed", []) or []
    evidence = args.evidence or []
    residual_risk = args.residual_risk or []
    follow_up = args.follow_up or []
    missing_fields = closure_memory_missing_fields(
        who_involved=who_involved,
        what_changed=what_changed,
        how_validated=how_validated,
        when_closed=when_closed,
        where_executed=where_executed,
        evidence=evidence,
        residual_risk=residual_risk,
        follow_up=follow_up,
    )
    if getattr(args, "meaningful", False) and missing_fields:
        raise ValueError("meaningful closure missing required fields: " + ", ".join(missing_fields))

    summary = render_closure_summary(
        bead=args.bead,
        disposition=args.disposition,
        why=args.why,
        who_involved=who_involved,
        what_changed=what_changed,
        how_validated=how_validated,
        when_closed=when_closed,
        where_executed=where_executed,
        decisions=args.decision or [],
        evidence=evidence,
        residual_risk=residual_risk,
        follow_up=follow_up,
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
        "meaningful": bool(getattr(args, "meaningful", False)),
        "closure_memory_quality": "complete" if not missing_fields else "incomplete",
        "closure_memory_missing_fields": missing_fields,
        "warnings": closure_memory_warnings(missing_fields),
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
    cli.add_argument("--who", dest="who_involved", action="append", default=[], help="Who was involved: agent, reviewer, operator, model lane, or team. Repeatable.")
    cli.add_argument("--what", dest="what_changed", action="append", default=[], help="What changed: file, behavior, result, or scope. Repeatable.")
    cli.add_argument("--how", dest="how_validated", action="append", default=[], help="How it was validated: command, review, CI, install smoke, or manual check. Repeatable.")
    cli.add_argument("--when", dest="when_closed", action="append", default=[], help="When it closed: date, branch, commit, run ID, or timeline marker. Repeatable.")
    cli.add_argument("--where", dest="where_executed", action="append", default=[], help="Where it ran: repo path, branch, environment, Beads local-only/Dolt-backed mode. Repeatable.")
    cli.add_argument("--decision", action="append", default=[], help="Key decision to preserve. Repeatable.")
    cli.add_argument("--evidence", action="append", default=[], help="Evidence, command, commit, file, or artifact. Repeatable.")
    cli.add_argument("--residual-risk", action="append", default=[], help="Residual risk future agents should know. Repeatable.")
    cli.add_argument("--follow-up", action="append", default=[], help="Follow-up Bead, action, or 'none'. Repeatable.")
    cli.add_argument("--meaningful", action="store_true", help="Require full closure-memory fields for non-trivial Beads.")
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
    if result["warnings"]:
        print("\nClosure-memory warnings:")
        for warning in result["warnings"]:
            print(f"- {warning}")
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
