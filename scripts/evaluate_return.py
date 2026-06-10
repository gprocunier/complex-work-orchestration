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
    print(f"Sabotage score: {result.get('sabotage_score', 0)}")
    print(f"Malpractice score: {result.get('malpractice_score', 0)}")
    print(f"Peer review required: {result.get('peer_review_required', False)}")
    print(f"Peer review status: {result.get('peer_review_status', 'not-run')}")
    print(f"Human adjudication required: {result.get('human_adjudication_required', False)}")
    print(f"Recommended disposition: {result.get('recommended_disposition', 'unknown')}")
    print(f"Quarantine recommended: {result.get('quarantine_recommended', False)}")

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

    sabotage = result.get("sabotage_signals") or []
    print("\nSabotage signals:")
    if sabotage:
        for signal in sabotage:  # type: ignore[assignment]
            print(f"- {signal.get('category')}: {signal.get('reason')} ({signal.get('weight')})")
    else:
        print("- none")

    malpractice = result.get("malpractice_signals") or []
    print("\nMalpractice signals:")
    if malpractice:
        for signal in malpractice:  # type: ignore[assignment]
            print(f"- {signal.get('category')}: {signal.get('reason')} ({signal.get('weight')})")
    else:
        print("- none")


def main() -> None:
    parser = argparse.ArgumentParser(description="Score a contractor/local-worker return against acceptance policy.")
    parser.add_argument("--file", required=True, help="Contractor return text file.")
    parser.add_argument("--bead", help="Assigned Beads ID.")
    parser.add_argument("--dispatch-id", help="Dispatch ID to link audit records.")
    parser.add_argument("--share-boundary", help="Share boundary used for the dispatch.")
    parser.add_argument("--job-description", help="Expected job-description label.")
    parser.add_argument(
        "--peer-review-required",
        action="store_true",
        help="Mark this return as requiring independent peer review before implementation use.",
    )
    parser.add_argument(
        "--peer-review-status",
        default="not-run",
        choices=["not-run", "pending", "passed", "failed", "disagreement", "blocked"],
    )
    parser.add_argument(
        "--provider-conflict-domain",
        action="append",
        default=[],
        help="Provider conflict domain attached to the dispatch route.",
    )
    parser.add_argument("--sabotage-review-threshold", type=int, help="Override sabotage peer-review threshold.")
    parser.add_argument("--sabotage-quarantine-threshold", type=int, help="Override sabotage quarantine threshold.")
    parser.add_argument("--malpractice-review-threshold", type=int, help="Override malpractice peer-review threshold.")
    parser.add_argument("--malpractice-reject-threshold", type=int, help="Override malpractice reject threshold.")
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
        peer_review_required=args.peer_review_required,
        peer_review_status=args.peer_review_status,
        provider_conflict_domains=args.provider_conflict_domain,
        sabotage_review_threshold=args.sabotage_review_threshold,
        sabotage_quarantine_threshold=args.sabotage_quarantine_threshold,
        malpractice_review_threshold=args.malpractice_review_threshold,
        malpractice_reject_threshold=args.malpractice_reject_threshold,
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
                "sabotage_score": result.get("sabotage_score"),
                "malpractice_score": result.get("malpractice_score"),
                "peer_review_required": result.get("peer_review_required"),
                "peer_review_status": result.get("peer_review_status"),
                "human_adjudication_required": result.get("human_adjudication_required"),
                "recommended_disposition": result.get("recommended_disposition"),
                "provider_conflict_domains": result.get("provider_conflict_domains"),
                "quarantine_recommended": result.get("quarantine_recommended"),
            },
            audit_path,
        )

    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print_human(result)


if __name__ == "__main__":
    main()
