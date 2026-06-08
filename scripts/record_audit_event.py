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
    parser.add_argument("--share-boundary")
    parser.add_argument("--packet-sha256")
    parser.add_argument("--verdict")
    parser.add_argument("--audit-file")
    args = parser.parse_args()

    event = record_audit_event(
        {
            "event_type": args.event_type,
            "dispatch_id": args.dispatch_id,
            "bead_id": args.bead,
            "executor_key": args.executor,
            "share_boundary": args.share_boundary,
            "packet_sha256": args.packet_sha256,
            "verdict": args.verdict,
        },
        Path(args.audit_file) if args.audit_file else None,
    )
    print(json.dumps(event, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
