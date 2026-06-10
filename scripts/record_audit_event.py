#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

from orchestration_lib import record_audit_event


def main() -> None:
    parser = argparse.ArgumentParser(description="Append an orchestration audit event.")
    parser.add_argument("--event-type", required=True)
    parser.add_argument("--dispatch-id", required=True)
    parser.add_argument("--bead", required=True)
    parser.add_argument("--executor")
    parser.add_argument("--provider")
    parser.add_argument("--provider-trust-tier")
    parser.add_argument("--share-boundary")
    parser.add_argument("--disclosure-stage")
    parser.add_argument("--packet-sha256")
    parser.add_argument("--verdict")
    parser.add_argument("--sabotage-score", type=int)
    parser.add_argument("--quarantine-recommended", action="store_true")
    parser.add_argument("--audit-file")
    args = parser.parse_args()

    event = record_audit_event(
        {
            "event_type": args.event_type,
            "dispatch_id": args.dispatch_id,
            "bead_id": args.bead,
            "executor_key": args.executor,
            "provider_key": args.provider,
            "provider_trust_tier": args.provider_trust_tier,
            "share_boundary": args.share_boundary,
            "disclosure_stage": args.disclosure_stage,
            "packet_sha256": args.packet_sha256,
            "verdict": args.verdict,
            "sabotage_score": args.sabotage_score,
            "quarantine_recommended": args.quarantine_recommended or None,
        },
        Path(args.audit_file) if args.audit_file else None,
    )
    print(json.dumps(event, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
