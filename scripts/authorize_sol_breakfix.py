#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import subprocess
import sys

from cwo_core.audit import record_audit_event
from cwo_core.util import make_dispatch_id
from cwo_core.waivers import add_waiver_reason_argument, require_waiver_reason, waiver_audit_fields


WARNING = (
    "WARNING: Sol operative execution violates normal CWO architect/worker swimlanes. "
    "This authorization is manual, exceptional, scoped, audited, and never an automatic fallback."
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Record an operator-approved Sol break-fix exception.")
    parser.add_argument("--allow-sol-breakfix", action="store_true")
    parser.add_argument("--operator-approval-ref", required=True)
    parser.add_argument("--bead", required=True)
    parser.add_argument("--incident-kind", choices=["self-hosting-orchestration"], required=True)
    parser.add_argument("--scope", required=True)
    parser.add_argument("--expires-after-bead", required=True)
    parser.add_argument("--dry-run", action="store_true")
    add_waiver_reason_argument(parser)
    args = parser.parse_args()
    if not args.allow_sol_breakfix:
        raise SystemExit("Sol break-fix is forbidden without --allow-sol-breakfix")
    require_waiver_reason(args, ["allow_sol_breakfix"])
    if args.expires_after_bead.strip() != args.bead.strip():
        raise SystemExit("--expires-after-bead must equal --bead; Sol break-fix cannot outlive its authorized Bead")
    return args


def main() -> None:
    args = parse_args()
    payload = {
        "dispatch_id": make_dispatch_id(f"sol-breakfix-{args.bead}"),
        "event_type": "sol_breakfix_authorized",
        "bead_id": args.bead,
        "operator_approval_ref": args.operator_approval_ref.strip(),
        "sol_breakfix_incident_kind": args.incident_kind,
        "sol_breakfix_scope": args.scope.strip(),
        "sol_breakfix_expiry": args.expires_after_bead.strip(),
        "swimlane_violation": True,
        "automatic_selection_forbidden": True,
        "warning": WARNING,
        **waiver_audit_fields(args, ["allow_sol_breakfix"]),
    }
    if not all((payload["operator_approval_ref"], payload["sol_breakfix_scope"], payload["sol_breakfix_expiry"])):
        raise SystemExit("approval reference, scope, and expiry must be non-empty")
    print(WARNING, file=sys.stderr)
    if not args.dry_run:
        note = (
            f"SOL BREAK-FIX AUTHORIZED: approval={payload['operator_approval_ref']}; "
            f"incident_kind={payload['sol_breakfix_incident_kind']}; "
            f"scope={payload['sol_breakfix_scope']}; expiry={payload['sol_breakfix_expiry']}; "
            f"waiver_reason={payload['waiver_reason']}; swimlane_violation=true; "
            "automatic_selection_forbidden=true."
        )
        subprocess.run(
            ["bd", "update", args.bead, "--add-label", "sol-breakfix-approved", "--append-notes", note],
            check=True,
        )
        payload = record_audit_event(payload)
    print(json.dumps(payload, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
