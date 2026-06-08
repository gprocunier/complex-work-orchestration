#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

from orchestration_lib import make_acceptance_decision, record_audit_event


def print_human(result: dict[str, object]) -> None:
    print(f"Verdict: {result['verdict']}")
    print(f"Score: {result['score']}")
    print(f"Architect review required: {result['architect_review_required']}")
    print(f"Escalation flagged: {result['escalation_flagged']}")

    missing = result.get("missing_sections") or []
    print("\nMissing sections:")
    if missing:
        for section in missing:  # type: ignore[assignment]
            print(f"- {section}")
    else:
        print("- none")

    penalties = result.get("penalty_reasons") or []
    print("\nPenalty reasons:")
    if penalties:
        for reason in penalties:  # type: ignore[assignment]
            print(f"- {reason}")
    else:
        print("- none")

    hard = result.get("hard_disqualifiers") or []
    print("\nHard disqualifiers:")
    if hard:
        for reason in hard:  # type: ignore[assignment]
            print(f"- {reason}")
    else:
        print("- none")


def main() -> None:
    parser = argparse.ArgumentParser(description="Score a contractor/local-worker return against acceptance policy.")
    parser.add_argument("--file", required=True, help="Contractor return text file.")
    parser.add_argument("--bead", help="Assigned Beads ID.")
    parser.add_argument("--dispatch-id", help="Dispatch ID to link audit records.")
    parser.add_argument("--share-boundary", help="Share boundary used for the dispatch.")
    parser.add_argument("--job-description", help="Expected job-description label.")
    parser.add_argument("--audit", action="store_true", help="Append an audit event.")
    parser.add_argument("--audit-file", help="Audit JSONL path; defaults to .orchestration-audit/audit.jsonl.")
    parser.add_argument("--json", action="store_true", help="Print machine-readable JSON.")
    args = parser.parse_args()

    result = make_acceptance_decision(
        Path(args.file).read_text(encoding="utf-8"),
        bead_id=args.bead,
        dispatch_id=args.dispatch_id,
        share_boundary=args.share_boundary,
        job_description_label=args.job_description,
    )
    if args.audit:
        audit_path = Path(args.audit_file) if args.audit_file else None
        record_audit_event(
            {
                "event_type": "return_evaluated",
                "dispatch_id": args.dispatch_id,
                "bead_id": args.bead,
                "share_boundary": args.share_boundary,
                "verdict": result["verdict"],
                "acceptance_score": result["score"],
            },
            audit_path,
        )

    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print_human(result)


if __name__ == "__main__":
    main()
