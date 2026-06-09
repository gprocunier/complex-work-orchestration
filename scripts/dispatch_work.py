#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

from generate_manual_dispatch_prompt import render_packet_prompt, render_prompt
from orchestration_lib import (
    classify_work,
    enforce_contracting_quota,
    read_text_arg,
    record_audit_event,
    require_valid_contractor_packet,
)


def main() -> None:
    parser = argparse.ArgumentParser(description="Prepare a manual dispatch artifact from a route result or packet.")
    parser.add_argument("text", nargs="*")
    parser.add_argument("--file")
    parser.add_argument("--packet", help="Boundary-gated JSON contractor packet from build_contractor_packet.py.")
    parser.add_argument(
        "--allow-degraded-packet",
        action="store_true",
        help="Allow dispatch of a packet that omits the expert profile after validation.",
    )
    parser.add_argument("--mode", choices=["manual"], default="manual")
    parser.add_argument("--external-ok", action="store_true")
    parser.add_argument("--local-ok", action="store_true", help="Permit low-risk local worker dispatch.")
    parser.add_argument("--prefer-local", action="store_true", help="Prefer local worker routing when policy permits it.")
    parser.add_argument("--share-boundary", default="no-outside-sharing")
    parser.add_argument("--requested-role", action="append", default=[])
    parser.add_argument("--bead")
    parser.add_argument("--epic")
    parser.set_defaults(audit=True)
    parser.add_argument("--audit", dest="audit", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--no-audit", dest="audit", action="store_false", help="Do not append the default audit event.")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    if args.packet:
        packet = json.loads(Path(args.packet).read_text(encoding="utf-8"))
        require_valid_contractor_packet(packet, allow_degraded_packet=args.allow_degraded_packet)
        quota_info = enforce_contracting_quota(
            packet.get("epic_id") or args.epic,
            packet["executor"],
            "external-contract",
            dispatch_id=packet.get("dispatch_id"),
        )
        artifact = {
            "dispatch_id": packet.get("dispatch_id"),
            "bead_id": packet.get("bead_id"),
            "epic_id": packet.get("epic_id") or args.epic,
            "executor_key": packet.get("executor"),
            "dispatch_mode": "manual_ui",
            "share_boundary": packet.get("share_boundary"),
            "packet_sha256": packet.get("packet_sha256"),
            "manual_prompt": render_packet_prompt(packet),
            **quota_info,
        }
        if args.audit:
            record_audit_event(
                {
                    "event_type": "dispatch_prepared",
                    "quota_event_type": quota_info.get("quota_event_type"),
                    "dispatch_id": artifact["dispatch_id"],
                    "bead_id": artifact["bead_id"],
                    "epic_id": artifact["epic_id"],
                    "executor_key": artifact["executor_key"],
                    "executor_external": quota_info.get("executor_external"),
                    "dispatch_mode": artifact["dispatch_mode"],
                    "share_boundary": artifact["share_boundary"],
                    "quota_remaining": quota_info.get("quota_remaining"),
                    "packet_sha256": artifact["packet_sha256"],
                }
            )
        if args.json:
            print(json.dumps(artifact, indent=2, sort_keys=True))
        else:
            print(artifact["manual_prompt"])
        return

    task = read_text_arg(" ".join(args.text).strip() or None, args.file)
    route = classify_work(
        task,
        external_ok=args.external_ok,
        local_ok=args.local_ok,
        prefer_local=args.prefer_local,
        share_boundary=args.share_boundary,
        requested_roles=args.requested_role,
    )
    quota_info = enforce_contracting_quota(args.epic, route["recommended_executor"], route["route"])
    artifact = {
        "bead_id": args.bead,
        "epic_id": args.epic,
        "route": route,
        "dispatch_mode": route["selected_executor"]["dispatch_mode"],
        "manual_prompt": render_prompt(task, route) if route["selected_executor"]["dispatch_mode"] == "manual_ui" else None,
        "local_envelope": {
            "task": task,
            "constraints": "low-risk, reversible, evaluator review required",
        }
        if route["selected_executor"]["dispatch_mode"] == "local_openai_compatible"
        else None,
        **quota_info,
    }
    if args.audit:
        record_audit_event(
            {
                "event_type": "dispatch_prepared",
                "quota_event_type": quota_info.get("quota_event_type"),
                "dispatch_id": f"dispatch-{args.bead or 'unassigned'}",
                "bead_id": args.bead,
                "epic_id": args.epic,
                "executor_key": route["recommended_executor"],
                "executor_external": quota_info.get("executor_external"),
                "dispatch_mode": artifact["dispatch_mode"],
                "share_boundary": args.share_boundary,
                "quota_remaining": quota_info.get("quota_remaining"),
            }
        )
    if args.json:
        print(json.dumps(artifact, indent=2, sort_keys=True))
    else:
        print(artifact["manual_prompt"] or json.dumps(artifact["local_envelope"] or artifact["route"], indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
