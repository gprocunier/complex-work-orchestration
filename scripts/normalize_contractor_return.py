#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

from cwo_core.returns import normalize_contractor_return


def main() -> None:
    parser = argparse.ArgumentParser(description="Normalize a contractor return into a scored return bundle.")
    parser.add_argument("--file", required=True, help="Contractor return text file.")
    parser.add_argument("--bead", help="Assigned Beads ID.")
    parser.add_argument("--dispatch-id", help="Dispatch ID to link the return to a packet.")
    parser.add_argument("--share-boundary", help="Share boundary used for the dispatch.")
    parser.add_argument("--job-description", help="Expected job-description label.")
    parser.add_argument("--packet-sha256", help="Packet hash the return is responding to.")
    parser.add_argument("--executor", help="Executor key that produced the return.")
    parser.add_argument(
        "--workspace-mutation-report",
        help="JSON report from scripts/workspace_mutation_guard.py comparing pre/post contractor workspace state.",
    )
    parser.add_argument("--output", help="Optional JSON output path.")
    args = parser.parse_args()
    workspace_mutation = (
        json.loads(Path(args.workspace_mutation_report).read_text(encoding="utf-8"))
        if args.workspace_mutation_report
        else None
    )

    bundle = normalize_contractor_return(
        Path(args.file).read_text(encoding="utf-8"),
        bead_id=args.bead,
        dispatch_id=args.dispatch_id,
        share_boundary=args.share_boundary,
        job_description_label=args.job_description,
        packet_sha256=args.packet_sha256,
        executor=args.executor,
        workspace_mutation=workspace_mutation,
    )
    rendered = json.dumps(bundle, indent=2, sort_keys=True)
    if args.output:
        Path(args.output).write_text(rendered + "\n", encoding="utf-8")
    else:
        print(rendered)


if __name__ == "__main__":
    main()
