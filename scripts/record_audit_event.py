#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

from cwo_core.audit import record_audit_event
from cwo_core.telemetry import telemetry_fields


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
    parser.add_argument("--telemetry-kind")
    parser.add_argument("--telemetry-status")
    parser.add_argument("--telemetry-missing-reason")
    parser.add_argument("--telemetry-source")
    parser.add_argument("--model")
    parser.add_argument("--model-label")
    parser.add_argument("--provider-family")
    parser.add_argument("--provider-retention-class")
    parser.add_argument("--job-description-label")
    parser.add_argument("--expert-profile")
    parser.add_argument("--agent-model-calls", type=int)
    parser.add_argument("--retry-count", type=int)
    parser.add_argument("--input-tokens", type=int)
    parser.add_argument("--output-tokens", type=int)
    parser.add_argument("--total-tokens", type=int)
    parser.add_argument("--active-seconds", type=float)
    parser.add_argument("--elapsed-seconds", type=float)
    parser.add_argument("--workerbee-planned-mode")
    parser.add_argument("--workerbee-planned-model")
    parser.add_argument("--workerbee-planned-lane", action="append", default=[])
    parser.add_argument("--workerbee-actual-mode")
    parser.add_argument("--workerbee-actual-model")
    parser.add_argument("--workerbee-actual-lane", action="append", default=[])
    parser.add_argument("--workerbee-delegation-status")
    parser.add_argument("--workerbee-delegation-source")
    parser.add_argument("--workerbee-delegation-gap-reason", action="append", default=[])
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
            **telemetry_fields(
                telemetry_kind=args.telemetry_kind,
                telemetry_status=args.telemetry_status,
                telemetry_missing_reason=args.telemetry_missing_reason,
                telemetry_source=args.telemetry_source,
                model=args.model,
                model_label=args.model_label,
                provider_family=args.provider_family,
                provider_retention_class=args.provider_retention_class,
                job_description_label=args.job_description_label,
                expert_profile=args.expert_profile,
                agent_model_calls=args.agent_model_calls,
                retry_count=args.retry_count,
                input_tokens=args.input_tokens,
                output_tokens=args.output_tokens,
                total_tokens=args.total_tokens,
                active_seconds=args.active_seconds,
                elapsed_seconds=args.elapsed_seconds,
                workerbee_planned_mode=args.workerbee_planned_mode,
                workerbee_planned_model=args.workerbee_planned_model,
                workerbee_planned_lanes=args.workerbee_planned_lane,
                workerbee_actual_mode=args.workerbee_actual_mode,
                workerbee_actual_model=args.workerbee_actual_model,
                workerbee_actual_lanes=args.workerbee_actual_lane,
                workerbee_delegation_status=args.workerbee_delegation_status,
                workerbee_delegation_source=args.workerbee_delegation_source,
                workerbee_delegation_gap_reasons=args.workerbee_delegation_gap_reason,
            ),
        },
        Path(args.audit_file) if args.audit_file else None,
    )
    print(json.dumps(event, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
