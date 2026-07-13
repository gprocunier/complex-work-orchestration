#!/usr/bin/env python3
"""Render a control-effectiveness report from the local audit log.

The report turns supervisor and return-evaluation audit events into the
proof-period rubric metrics used to tune CWO controls from evidence.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from cwo_core.control_effectiveness import build_control_effectiveness_report
from cwo_core.paths import AUDIT_LOG


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Aggregate audit events into a control-effectiveness report."
    )
    parser.add_argument(
        "--audit-file",
        default=str(AUDIT_LOG),
        help="Audit JSONL file to aggregate (default: local orchestration audit log).",
    )
    parser.add_argument("--json", action="store_true", help="Emit the JSON report.")
    return parser.parse_args()


def render_text(report: dict) -> str:
    supervision = report["supervision"]
    losses = supervision["control_losses"]
    poll = supervision["poll_health"]
    returns = report["returns"]
    rubric = report["rubric"]
    lines = [
        "CWO Control Effectiveness Report",
        f"Audit file: {report['audit_file']}",
        f"Events: {report['event_counts']['total']} total, "
        f"{report['event_counts']['native_supervision']} supervision, "
        f"{report['event_counts']['return_evaluated']} return evaluations",
        "",
        f"Supervised dispatches: {supervision['supervised_dispatches']}",
        f"Final decisions: {supervision['final_decisions'] or 'none'}",
        f"Control losses: {losses['total']} "
        f"(control-plane {losses['spurious_control_plane']}, "
        f"substantive {losses['substantive']}, unclassified {losses['unclassified']})",
        f"Interrupt reasons: {supervision['interrupt_reasons'] or 'none'}",
        f"Poll health: late-poll states {poll['late_poll_states']}, "
        f"max poll gap {poll['max_poll_gap_ms']}ms, "
        f"max dispatch-to-first-poll {poll['max_dispatch_to_first_poll_ms']}ms",
        f"Compaction-breach states: {supervision['compaction_breach_states']}",
        "",
        f"Returns evaluated: {returns['evaluated']} "
        f"(quarantine recommended {returns['quarantine_recommended']}, "
        f"max sabotage score {returns['max_sabotage_score']})",
        "",
        f"Control-loss rate: {rubric['control_loss_rate_pct']}% "
        f"(target <= {rubric['control_loss_target_pct']}%, "
        f"meets target: {rubric['meets_control_loss_target']})",
    ]
    if report["tuning_hints"]:
        lines.append("")
        lines.append("Tuning hints:")
        lines.extend(f"- {hint}" for hint in report["tuning_hints"])
    return "\n".join(lines)


def main() -> int:
    args = parse_args()
    audit_file = Path(args.audit_file).expanduser()
    if not audit_file.is_file():
        raise SystemExit(f"audit file not found: {audit_file}")
    report = build_control_effectiveness_report(audit_file)
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(render_text(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
