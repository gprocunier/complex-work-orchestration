#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

from cwo_core.paths import assert_safe_output_path
from cwo_core.packets import contractor_packet_evaluation_metadata, require_valid_contractor_packet
from cwo_core.policy import resolve_executor_key
from cwo_core.returns import normalize_contractor_return
from cwo_core.util import atomic_write_text


def main() -> None:
    parser = argparse.ArgumentParser(description="Normalize a contractor return into a scored return bundle.")
    parser.add_argument("--file", required=True, help="Contractor return text file.")
    parser.add_argument("--bead", help="Assigned Beads ID.")
    parser.add_argument("--dispatch-id", help="Dispatch ID to link the return to a packet.")
    parser.add_argument("--share-boundary", help="Share boundary used for the dispatch.")
    parser.add_argument("--job-description", help="Expected job-description label.")
    parser.add_argument("--packet-sha256", help="Packet hash the return is responding to.")
    parser.add_argument("--contractor-packet", help="Validated contractor packet JSON supplying authenticated return metadata.")
    parser.add_argument("--expected-return-language", help="Expected return language when no contractor packet supplies it.")
    parser.add_argument("--executor", help="Executor key that produced the return.")
    parser.add_argument("--provider-key", help="Provider key from the dispatch envelope or packet.")
    parser.add_argument("--provider-trust-tier", help="Provider trust tier from the dispatch envelope or packet.")
    parser.add_argument("--dispatch-mode", help="Dispatch mode from the route, packet, or local envelope.")
    parser.add_argument("--local-profile", help="Local executor profile, for example openshift-ai-vllm.")
    parser.add_argument("--model-profile", help="Model profile key from the dispatch envelope or execution harness.")
    parser.add_argument(
        "--workspace-mutation-report",
        help="JSON report from scripts/workspace_mutation_guard.py comparing pre/post contractor workspace state.",
    )
    parser.add_argument("--output", help="Optional JSON output path.")
    args = parser.parse_args()
    packet_metadata: dict[str, object] = {}
    if args.contractor_packet:
        packet = json.loads(Path(args.contractor_packet).read_text(encoding="utf-8"))
        require_valid_contractor_packet(packet)
        packet_metadata = contractor_packet_evaluation_metadata(packet)

    def merge_metadata(explicit: str | None, key: str, flag: str) -> str | None:
        packet_value = packet_metadata.get(key)
        packet_text = str(packet_value) if packet_value not in {None, ""} else None
        if explicit is not None and packet_text is not None and explicit != packet_text:
            raise SystemExit(f"{flag} conflicts with authenticated contractor packet metadata")
        return explicit or packet_text

    args.bead = merge_metadata(args.bead, "bead", "--bead")
    args.dispatch_id = merge_metadata(args.dispatch_id, "dispatch_id", "--dispatch-id")
    args.share_boundary = merge_metadata(args.share_boundary, "share_boundary", "--share-boundary")
    args.job_description = merge_metadata(args.job_description, "job_description", "--job-description")
    args.packet_sha256 = merge_metadata(args.packet_sha256, "packet_sha256", "--packet-sha256")
    args.executor = merge_metadata(args.executor, "executor", "--executor")
    args.provider_key = merge_metadata(args.provider_key, "provider_key", "--provider-key")
    args.provider_trust_tier = merge_metadata(
        args.provider_trust_tier,
        "provider_trust_tier",
        "--provider-trust-tier",
    )
    args.dispatch_mode = merge_metadata(args.dispatch_mode, "dispatch_mode", "--dispatch-mode")
    args.expected_return_language = merge_metadata(
        args.expected_return_language,
        "expected_return_language",
        "--expected-return-language",
    )
    expected_language_source = (
        str(packet_metadata.get("expected_return_language_source"))
        if packet_metadata.get("expected_return_language_source")
        else ("explicit" if args.expected_return_language else None)
    )
    if args.executor:
        args.executor = resolve_executor_key(args.executor)
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
        provider_key=args.provider_key,
        provider_trust_tier=args.provider_trust_tier,
        dispatch_mode=args.dispatch_mode,
        local_profile=args.local_profile,
        model_profile=args.model_profile,
        expected_return_language=args.expected_return_language,
        expected_return_language_source=expected_language_source,
        workspace_mutation=workspace_mutation,
    )
    rendered = json.dumps(bundle, indent=2, sort_keys=True)
    if args.output:
        atomic_write_text(assert_safe_output_path(Path(args.output)), rendered + "\n")
    else:
        print(rendered)


if __name__ == "__main__":
    main()
