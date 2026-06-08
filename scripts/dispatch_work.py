#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

from generate_manual_dispatch_prompt import render_packet_prompt, render_prompt
from orchestration_lib import classify_work, read_text_arg, record_audit_event


def main() -> None:
    parser = argparse.ArgumentParser(description="Prepare a manual dispatch artifact from a route result or packet.")
    parser.add_argument("text", nargs="*")
    parser.add_argument("--file")
    parser.add_argument("--packet", help="Boundary-gated JSON contractor packet from build_contractor_packet.py.")
    parser.add_argument("--mode", choices=["manual"], default="manual")
    parser.add_argument("--external-ok", action="store_true")
    parser.add_argument("--share-boundary", default="no-outside-sharing")
    parser.add_argument("--requested-role", action="append", default=[])
    parser.add_argument("--bead")
    parser.add_argument("--audit", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    if args.packet:
        packet = json.loads(Path(args.packet).read_text(encoding="utf-8"))
        artifact = {
            "dispatch_id": packet.get("dispatch_id"),
            "bead_id": packet.get("bead_id"),
            "executor_key": packet.get("executor"),
            "dispatch_mode": "manual_ui",
            "share_boundary": packet.get("share_boundary"),
            "packet_sha256": packet.get("packet_sha256"),
            "manual_prompt": render_packet_prompt(packet),
        }
        if args.audit:
            record_audit_event(
                {
                    "event_type": "dispatch_prepared",
                    "dispatch_id": artifact["dispatch_id"],
                    "bead_id": artifact["bead_id"],
                    "executor_key": artifact["executor_key"],
                    "dispatch_mode": artifact["dispatch_mode"],
                    "share_boundary": artifact["share_boundary"],
                    "packet_sha256": artifact["packet_sha256"],
                }
            )
        if args.json:
            print(json.dumps(artifact, indent=2, sort_keys=True))
        else:
            print(artifact["manual_prompt"])
        return

    task = read_text_arg(" ".join(args.text).strip() or None, args.file)
    route = classify_work(task, external_ok=args.external_ok, share_boundary=args.share_boundary, requested_roles=args.requested_role)
    artifact = {
        "bead_id": args.bead,
        "route": route,
        "dispatch_mode": route["selected_executor"]["dispatch_mode"],
        "manual_prompt": render_prompt(task, route) if route["selected_executor"]["dispatch_mode"] == "manual_ui" else None,
        "local_envelope": {
            "task": task,
            "constraints": "low-risk, reversible, evaluator review required",
        }
        if route["selected_executor"]["dispatch_mode"] == "local_openai_compatible"
        else None,
    }
    if args.audit:
        record_audit_event(
            {
                "event_type": "dispatch_prepared",
                "dispatch_id": f"dispatch-{args.bead or 'unassigned'}",
                "bead_id": args.bead,
                "executor_key": route["recommended_executor"],
                "dispatch_mode": artifact["dispatch_mode"],
                "share_boundary": args.share_boundary,
            }
        )
    if args.json:
        print(json.dumps(artifact, indent=2, sort_keys=True))
    else:
        print(artifact["manual_prompt"] or json.dumps(artifact["local_envelope"] or artifact["route"], indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
