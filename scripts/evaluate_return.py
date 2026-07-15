#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from cwo_core.returns import make_acceptance_decision
from cwo_core.audit import record_audit_event
from cwo_core.errors import CWOPolicyError
from cwo_core.policy import resolve_executor_key
from cwo_core.packets import (
    contractor_packet_evaluation_metadata,
    local_dispatch_language_metadata,
    require_valid_contractor_packet,
)
from cwo_core.telemetry import telemetry_fields
from cwo_core.waivers import add_waiver_reason_argument, require_waiver_reason, waiver_audit_fields


def print_human(result: dict[str, object]) -> None:
    print(f"Verdict: {result['verdict']}")
    print(f"Score: {result['score']}")
    print(f"Review surface: {result.get('review_surface') or 'n/a'}")
    print(f"Source inspection: {result.get('source_inspection') or 'n/a'}")
    print(f"Packet-only go hold: {result.get('master_review_packet_only_go_hold', False)}")
    print(f"Architect review required: {result['architect_review_required']}")
    print(f"Escalation flagged: {result['escalation_flagged']}")
    print(f"Sabotage score: {result.get('sabotage_score', 0)}")
    print(f"Expected return language: {result.get('expected_return_language') or 'not enforced'}")
    print(f"Return language status: {result.get('return_language_status', 'not-enforced')}")
    print(f"Detected letter scripts: {', '.join(str(item) for item in (result.get('detected_letter_scripts') or [])) or 'none'}")
    print(f"Unexpected script ratio: {result.get('unexpected_script_ratio', 0)}")
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


def _as_str(value: Any) -> str | None:
    if isinstance(value, str):
        value = value.strip()
        return value or None
    return None


def _as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _load_local_dispatch_metadata(path: Path) -> dict[str, Any]:
    try:
        artifact = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise SystemExit(f"Failed to parse --local-dispatch-result JSON: {exc}") from exc
    if not isinstance(artifact, dict):
        raise SystemExit("--local-dispatch-result must contain a JSON object")

    route = _as_dict(artifact.get("route"))
    selected_executor = _as_dict(route.get("selected_executor"))
    ranked_experts = route.get("ranked_experts")
    primary_expert = ranked_experts[0] if isinstance(ranked_experts, list) and ranked_experts else {}
    primary_expert_label = _as_str(_as_dict(primary_expert).get("job_description_label"))
    local_envelope = _as_dict(artifact.get("local_envelope"))
    local_response = _as_dict(artifact.get("local_response"))
    expected_return_language: str | None = None
    expected_return_language_source: str | None = None
    if local_envelope:
        try:
            expected_return_language, expected_return_language_source = local_dispatch_language_metadata(
                local_envelope
            )
        except CWOPolicyError as exc:
            raise SystemExit(f"Invalid local dispatch language metadata: {exc}") from exc
    raw_finish_reasons = local_response.get("finish_reasons")
    if isinstance(raw_finish_reasons, list):
        finish_reasons = [str(item) for item in raw_finish_reasons if isinstance(item, (str, int, float, bool))]
    elif raw_finish_reasons is None:
        finish_reasons = []
    else:
        finish_reasons = [str(raw_finish_reasons)]

    return {
        "dispatch_id": _as_str(artifact.get("dispatch_id")),
        "bead_id": _as_str(artifact.get("bead_id")),
        "bead": _as_str(artifact.get("bead_id")),
        "share_boundary": _as_str(route.get("share_boundary")),
        "executor": (
            _as_str(selected_executor.get("key"))
            or _as_str(selected_executor.get("executor_key"))
            or _as_str(route.get("recommended_executor"))
            or _as_str(route.get("executor"))
            or _as_str(artifact.get("executor"))
            or _as_str(artifact.get("executor_key"))
        ),
        "provider_key": (
            _as_str(selected_executor.get("provider_key"))
            or _as_str(route.get("provider_key"))
            or _as_str(local_envelope.get("provider_key"))
            or _as_str(artifact.get("provider_key"))
        ),
        "provider_trust_tier": (
            _as_str(selected_executor.get("provider_trust_tier"))
            or _as_str(route.get("provider_trust_tier"))
            or _as_str(local_envelope.get("provider_trust_tier"))
            or _as_str(artifact.get("provider_trust_tier"))
        ),
        "dispatch_mode": (
            _as_str(route.get("dispatch_mode"))
            or _as_str(artifact.get("dispatch_mode"))
            or _as_str(selected_executor.get("dispatch_mode"))
            or _as_str(local_envelope.get("dispatch_mode"))
        ),
        "job_description": (
            primary_expert_label
            or _as_str(selected_executor.get("job_description_label"))
            or _as_str(route.get("job_description_label"))
            or _as_str(route.get("job_description"))
        ),
        "local_profile": (
            _as_str(selected_executor.get("local_profile"))
            or _as_str(local_envelope.get("local_profile"))
        ),
        "model_profile": (
            _as_str(selected_executor.get("model_profile"))
            or _as_str(local_envelope.get("model_profile"))
        ),
        "expected_return_language": expected_return_language,
        "expected_return_language_source": expected_return_language_source,
        "local_response_truncated": (
            bool(local_response.get("response_truncated"))
            if isinstance(local_response.get("response_truncated"), bool)
            else False
        ),
        "local_finish_reasons": finish_reasons,
        "local_reasoning_malformed": (
            bool(local_response.get("reasoning_malformed"))
            if isinstance(local_response.get("reasoning_malformed"), bool)
            else False
        ),
        "local_completion_status": _as_str(local_response.get("completion_status")),
        "local_usable_final_content": (
            bool(local_response.get("usable_final_content"))
            if isinstance(local_response.get("usable_final_content"), bool)
            else None
        ),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Score a contractor/local-worker return against acceptance policy.")
    parser.add_argument("--file", required=True, help="Contractor return text file.")
    parser.add_argument("--bead", help="Assigned Beads ID.")
    parser.add_argument("--dispatch-id", help="Dispatch ID to link audit records.")
    parser.add_argument("--packet-sha256", help="Packet hash linked to the contractor return.")
    parser.add_argument("--contractor-packet", help="Validated contractor packet JSON supplying authenticated return metadata.")
    parser.add_argument("--share-boundary", help="Share boundary used for the dispatch.")
    parser.add_argument("--job-description", help="Expected job-description label.")
    parser.add_argument("--executor", help="Executor key that produced the return.")
    parser.add_argument("--provider-key", help="Provider key from the dispatch envelope or packet.")
    parser.add_argument("--provider-trust-tier", help="Provider trust tier from the dispatch envelope or packet.")
    parser.add_argument("--dispatch-mode", help="Dispatch mode from the route, packet, or local envelope.")
    parser.add_argument("--local-profile", help="Local executor profile, for example openshift-ai-vllm.")
    parser.add_argument("--model-profile", help="Model profile key from the dispatch envelope or execution harness.")
    parser.add_argument("--expected-return-language", help="Expected return language when dispatch metadata does not supply it.")
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
    parser.add_argument(
        "--local-dispatch-result",
        help="Path to dispatch_work artifact containing local_response and route metadata.",
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
    if args.contractor_packet and args.local_dispatch_result:
        raise SystemExit("--contractor-packet and --local-dispatch-result are mutually exclusive")
    local_dispatch_metadata = (
        _load_local_dispatch_metadata(Path(args.local_dispatch_result))
        if args.local_dispatch_result
        else {}
    )
    contractor_packet_metadata: dict[str, Any] = {}
    if args.contractor_packet:
        packet = json.loads(Path(args.contractor_packet).read_text(encoding="utf-8"))
        require_valid_contractor_packet(packet)
        contractor_packet_metadata = contractor_packet_evaluation_metadata(packet)
    dispatch_metadata = contractor_packet_metadata or local_dispatch_metadata

    def _cli_or_metadata(name: str) -> str | None:
        explicit = getattr(args, name, None)
        metadata_value = dispatch_metadata.get(name)
        if (
            contractor_packet_metadata
            and explicit is not None
            and explicit != ""
            and isinstance(metadata_value, str)
            and metadata_value
            and explicit != metadata_value
        ):
            raise SystemExit(f"--{name.replace('_', '-')} conflicts with authenticated contractor packet metadata")
        if explicit is not None and explicit != "":
            return explicit
        return metadata_value if isinstance(metadata_value, str) else None

    dispatch_id = _cli_or_metadata("dispatch_id")
    packet_sha256 = _cli_or_metadata("packet_sha256")
    bead_id = _cli_or_metadata("bead")
    share_boundary = _cli_or_metadata("share_boundary")
    job_description_label = _cli_or_metadata("job_description")
    executor = _cli_or_metadata("executor")
    provider_key = _cli_or_metadata("provider_key")
    provider_trust_tier = _cli_or_metadata("provider_trust_tier")
    dispatch_mode = _cli_or_metadata("dispatch_mode")
    local_profile = _cli_or_metadata("local_profile")
    model_profile = _cli_or_metadata("model_profile")
    expected_return_language = _cli_or_metadata("expected_return_language")
    expected_return_language_source = _cli_or_metadata("expected_return_language_source")
    if executor:
        executor = resolve_executor_key(executor)

    workspace_mutation = (
        json.loads(Path(args.workspace_mutation_report).read_text(encoding="utf-8"))
        if args.workspace_mutation_report
        else None
    )
    local_response_truncated = bool(local_dispatch_metadata.get("local_response_truncated", False))
    local_finish_reasons = local_dispatch_metadata.get("local_finish_reasons")
    local_reasoning_malformed = bool(local_dispatch_metadata.get("local_reasoning_malformed", False))
    local_completion_status = local_dispatch_metadata.get("local_completion_status")
    local_usable_final_content = local_dispatch_metadata.get("local_usable_final_content")

    result = make_acceptance_decision(
        Path(args.file).read_text(encoding="utf-8"),
        bead_id=bead_id,
        dispatch_id=dispatch_id,
        packet_sha256=packet_sha256,
        share_boundary=share_boundary,
        job_description_label=job_description_label,
        executor=executor,
        provider_key=provider_key,
        provider_trust_tier=provider_trust_tier,
        dispatch_mode=dispatch_mode,
        local_profile=local_profile,
        model_profile=model_profile,
        expected_return_language=expected_return_language,
        expected_return_language_source=expected_return_language_source,
        peer_review_required=args.peer_review_required,
        peer_review_status=args.peer_review_status,
        provider_conflict_domains=args.provider_conflict_domain,
        sabotage_review_threshold=args.sabotage_review_threshold,
        sabotage_quarantine_threshold=args.sabotage_quarantine_threshold,
        malpractice_review_threshold=args.malpractice_review_threshold,
        malpractice_reject_threshold=args.malpractice_reject_threshold,
        workspace_mutation=workspace_mutation,
        mutation_strategy=args.mutation_strategy,
        local_response_truncated=local_response_truncated,
        local_finish_reasons=local_finish_reasons if isinstance(local_finish_reasons, list) else None,
        local_reasoning_malformed=local_reasoning_malformed,
        local_completion_status=(
            local_completion_status if isinstance(local_completion_status, str) else None
        ),
        local_usable_final_content=(
            local_usable_final_content if isinstance(local_usable_final_content, bool) else None
        ),
    )
    if args.audit:
        audit_path = Path(args.audit_file) if args.audit_file else None
        record_audit_event(
            {
                "event_type": "return_evaluated",
                "dispatch_id": dispatch_id,
                "bead_id": bead_id,
                "packet_sha256": packet_sha256,
                "share_boundary": share_boundary,
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
                    job_description_label=job_description_label,
                    review_surface=result.get("review_surface"),
                    source_inspection=result.get("source_inspection"),
                    sources_inspected=result.get("sources_inspected"),
                    sources_not_inspected=result.get("sources_not_inspected"),
                    independent_verification=result.get("independent_verification"),
                    packet_reported_claims=result.get("packet_reported_claims"),
                    review_surface_mismatch=result.get("review_surface_mismatch"),
                    review_surface_required_evidence_missing=result.get("review_surface_required_evidence_missing"),
                    review_surface_mismatch_reasons=result.get("review_surface_mismatch_reasons"),
                    master_review_packet_only_go_hold=result.get("master_review_packet_only_go_hold"),
                    provider_family=result.get("provider_family"),
                    provider_retention_class=result.get("provider_retention_class"),
                    expected_return_language=result.get("expected_return_language"),
                    expected_return_language_source=result.get("expected_return_language_source"),
                    return_language_status=result.get("return_language_status"),
                    return_language_finding_count=len(result.get("return_language_findings") or []),
                    detected_letter_scripts=result.get("detected_letter_scripts"),
                    unexpected_script_ratio=result.get("unexpected_script_ratio"),
                    unicode_normalization_changed=result.get("unicode_normalization_changed"),
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
