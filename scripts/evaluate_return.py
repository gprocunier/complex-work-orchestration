#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

from cwo_core.returns import make_acceptance_decision
from cwo_core.audit import record_audit_event
from cwo_core.policy import resolve_executor_key
from cwo_core.telemetry import telemetry_fields
from cwo_core.waivers import add_waiver_reason_argument, require_waiver_reason, waiver_audit_fields


def print_human(result: dict[str, object]) -> None:
    print(f"Verdict: {result['verdict']}")
    print(f"Score: {result['score']}")
    print(f"Architect review required: {result['architect_review_required']}")
    print(f"Escalation flagged: {result['escalation_flagged']}")
    print(f"Sabotage score: {result.get('sabotage_score', 0)}")
    print(f"Evidence quality score: {result.get('evidence_quality_score', 0)}")
    print(f"Malpractice score: {result.get('malpractice_score', 0)}")
    print(f"Peer review required: {result.get('peer_review_required', False)}")
    print(f"Peer review status: {result.get('peer_review_status', 'not-run')}")
    print(f"Implementation blocked: {result.get('implementation_blocked', False)}")
    print(f"Hold classification: {result.get('hold_classification', 'none')}")
    hold_reasons = result.get("hold_reasons") or []
    print("Hold reasons: " + (", ".join(str(item) for item in hold_reasons) if hold_reasons else "none"))
    print(f"Human adjudication required: {result.get('human_adjudication_required', False)}")
    print(f"Recommended disposition: {result.get('recommended_disposition', 'unknown')}")
    print(f"Recommended synthesis use: {result.get('recommended_synthesis_use', 'unknown')}")
    print(f"Quarantine recommended: {result.get('quarantine_recommended', False)}")
    print(f"Provider: {result.get('provider_key') or 'unknown'} ({result.get('provider_trust_tier') or 'unknown'})")
    print(f"Provenance class: {result.get('provenance_class') or 'unknown'}")
    workspace_mutation = result.get("workspace_mutation") or {}
    if isinstance(workspace_mutation, dict) and workspace_mutation:
        print(f"Workspace mutation detected: {workspace_mutation.get('mutation_detected', False)}")
        print(f"Unexpected workspace mutation: {workspace_mutation.get('unexpected_mutation_detected', False)}")

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

    evidence_quality = result.get("evidence_quality_signals") or []
    print("\nEvidence quality signals:")
    if evidence_quality:
        for signal in evidence_quality:  # type: ignore[assignment]
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
    parser.add_argument("--executor", help="Executor key that produced the return.")
    parser.add_argument("--provider-key", help="Provider key from the dispatch envelope or packet.")
    parser.add_argument("--provider-trust-tier", help="Provider trust tier from the dispatch envelope or packet.")
    parser.add_argument("--dispatch-mode", help="Dispatch mode from the route, packet, or local envelope.")
    parser.add_argument("--local-profile", help="Local executor profile, for example openshift-ai-vllm.")
    parser.add_argument("--model-profile", help="Model profile key from the dispatch envelope or execution harness.")
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
    parser.add_argument(
        "--workspace-mutation-report",
        help="JSON report from scripts/workspace_mutation_guard.py comparing pre/post contractor workspace state.",
    )
    parser.add_argument(
        "--mutation-strategy",
        choices=["reject", "warn"],
        default="reject",
        help="How to handle unexpected tracked-file mutations when a workspace mutation report is supplied.",
    )
    parser.set_defaults(audit=True)
    parser.add_argument("--audit", dest="audit", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--no-audit", dest="audit", action="store_false", help="Do not append the default audit event.")
    parser.add_argument("--audit-file", help="Audit JSONL path; defaults to .orchestration-audit/audit.jsonl.")
    parser.add_argument("--json", action="store_true", help="Print machine-readable JSON.")
    add_waiver_reason_argument(parser)
    args = parser.parse_args()
    require_waiver_reason(args, ["audit"])
    if args.executor:
        args.executor = resolve_executor_key(args.executor)

    workspace_mutation = (
        json.loads(Path(args.workspace_mutation_report).read_text(encoding="utf-8"))
        if args.workspace_mutation_report
        else None
    )

    result = make_acceptance_decision(
        Path(args.file).read_text(encoding="utf-8"),
        bead_id=args.bead,
        dispatch_id=args.dispatch_id,
        share_boundary=args.share_boundary,
        job_description_label=args.job_description,
        executor=args.executor,
        provider_key=args.provider_key,
        provider_trust_tier=args.provider_trust_tier,
        dispatch_mode=args.dispatch_mode,
        local_profile=args.local_profile,
        model_profile=args.model_profile,
        peer_review_required=args.peer_review_required,
        peer_review_status=args.peer_review_status,
        provider_conflict_domains=args.provider_conflict_domain,
        sabotage_review_threshold=args.sabotage_review_threshold,
        sabotage_quarantine_threshold=args.sabotage_quarantine_threshold,
        malpractice_review_threshold=args.malpractice_review_threshold,
        malpractice_reject_threshold=args.malpractice_reject_threshold,
        workspace_mutation=workspace_mutation,
        mutation_strategy=args.mutation_strategy,
    )
    if args.audit:
        audit_path = Path(args.audit_file) if args.audit_file else None
        record_audit_event(
            {
                "event_type": "return_evaluated",
                "dispatch_id": args.dispatch_id,
                "bead_id": args.bead,
                "share_boundary": args.share_boundary,
                "executor_key": result.get("executor"),
                "executor": result.get("executor"),
                "provider_key": result.get("provider_key"),
                "provider_trust_tier": result.get("provider_trust_tier"),
                "provider_external": result.get("provider_external"),
                "provenance_class": result.get("provenance_class"),
                "dispatch_mode": result.get("dispatch_mode"),
                "local_profile": result.get("local_profile"),
                "verdict": result["verdict"],
                "acceptance_score": result["score"],
                "sabotage_score": result.get("sabotage_score"),
                "evidence_quality_score": result.get("evidence_quality_score"),
                "malpractice_score": result.get("malpractice_score"),
                "peer_review_required": result.get("peer_review_required"),
                "peer_review_status": result.get("peer_review_status"),
                "implementation_blocked": result.get("implementation_blocked"),
                "hold_reasons": result.get("hold_reasons"),
                "hold_classification": result.get("hold_classification"),
                "human_adjudication_required": result.get("human_adjudication_required"),
                "recommended_disposition": result.get("recommended_disposition"),
                "recommended_synthesis_use": result.get("recommended_synthesis_use"),
                "provider_conflict_domains": result.get("provider_conflict_domains"),
                "quarantine_recommended": result.get("quarantine_recommended"),
                "workspace_mutation": result.get("workspace_mutation"),
                **waiver_audit_fields(args, ["audit"]),
                **telemetry_fields(
                    telemetry_kind="evaluation",
                    telemetry_status=result["verdict"],
                    job_description_label=args.job_description,
                    provider_family=result.get("provider_family"),
                    provider_retention_class=result.get("provider_retention_class"),
                ),
            },
            audit_path,
        )

    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print_human(result)


if __name__ == "__main__":
    main()
