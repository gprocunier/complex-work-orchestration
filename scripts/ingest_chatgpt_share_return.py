#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from cwo_core.browser_provenance import (
    ACCESS_LIMIT, PRIVATE_RESPONSE_ARTIFACT_TYPE, PRIVATE_RESPONSE_VERSION,
    PrivateCaptureExpectation, add_candidate_arguments, candidate_context,
    provenance_errors, select_private_capture, validate_private_capture, verify_provenance_pin,
)
from cwo_core.private_artifact import PrivateArtifactError, PrivateDirectory, artifact_path, sha256_bytes
from cwo_core.util import atomic_write_text, artifact_hash

DEFAULT_EXECUTOR = "chatgpt_pro_browser_master_reviewer"
MAX_PROVENANCE_BYTES = 1024 * 1024


def _provenance_errors(provenance: dict[str, Any]) -> list[str]:
    return provenance_errors(provenance)


def _read_provenance(directory: PrivateDirectory, name: str) -> tuple[bytes, dict[str, Any]]:
    try:
        raw = directory.read(name, max_bytes=MAX_PROVENANCE_BYTES)
        record = json.loads(raw.decode("utf-8"))
    except (PrivateArtifactError, UnicodeError, ValueError):
        raise SystemExit("private response provenance is unreadable") from None
    if not isinstance(record, dict) or record.get("artifact_type") != PRIVATE_RESPONSE_ARTIFACT_TYPE:
        raise SystemExit("private response provenance has an unexpected artifact type")
    return raw, record


def _check_private_record(record: dict[str, Any], identities: dict[str, str | None]) -> str:
    if type(record.get("version")) is not int or record["version"] != PRIVATE_RESPONSE_VERSION:
        raise SystemExit("private response provenance has an unsupported historical version")
    if record.get("capture_complete") is not True:
        raise SystemExit("private response capture is incomplete; it cannot be ingested as a complete return")
    errors = _provenance_errors(record)
    if errors:
        raise SystemExit("private response provenance is incomplete: " + "; ".join(errors))
    response_file = record["response_file"]
    if "/" in response_file or response_file.startswith("."):
        raise SystemExit("private response provenance names an unsafe response file")
    for key, value in identities.items():
        if value is not None and record.get(key) != value:
            raise SystemExit(f"private response {key} does not match the requested {key}")
    return response_file


def load_private_response(
    provenance_path: Path, *, expected: PrivateCaptureExpectation | None = None,
    packet_sha256: str | None = None, dispatch_id: str | None = None, bead_id: str | None = None,
) -> tuple[str, dict[str, Any], str]:
    """Read pinned owner-only files and validate the independently selected current chain.

    Same-user access to both artifacts and the audit store can rewrite both;
    the API result's access_limit documents that authentication limitation.
    """
    try:
        absolute = artifact_path(provenance_path)
        directory = PrivateDirectory.open(absolute.parent)
    except PrivateArtifactError as exc:
        raise SystemExit(f"private response directory is unusable: {exc}") from exc
    with directory:
        raw, record = _read_provenance(directory, absolute.name)
        verify_provenance_pin(raw, expected)
        response_file = _check_private_record(record, {"packet_sha256": packet_sha256,
                                                      "dispatch_id": dispatch_id, "bead_id": bead_id})
        try:
            response_bytes = directory.read(response_file)
        except PrivateArtifactError as exc:
            raise SystemExit(f"private response file is unreadable: {exc}") from exc
    decoded = validate_private_capture(record, response_bytes, expected=expected, provenance_bytes=raw)
    return decoded, {**record, "access_limit": ACCESS_LIMIT}, sha256_bytes(raw)


def add_private_capture_arguments(parser) -> None:
    add_candidate_arguments(parser)
    parser.add_argument("--packet-source-sha256", help="Original packet-load PreparedSource identity.")
    parser.add_argument("--capture-event", help="Exact persisted chatgpt_browser_dispatch event_hash.")


def read_private_capture_packet(packet_path: str) -> dict[str, Any]:
    try:
        packet = json.loads(Path(packet_path).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError):
        raise SystemExit("current contractor packet is unreadable or malformed") from None
    if not isinstance(packet, dict):
        raise SystemExit("current contractor packet must be an object")
    return packet


def private_capture_expectation(args, packet_path: str | None) -> PrivateCaptureExpectation:
    if not packet_path or not args.packet_source_sha256 or not args.capture_event:
        raise SystemExit("private intake requires the contractor packet, --packet-source-sha256 and --capture-event")
    packet = read_private_capture_packet(packet_path)
    return select_private_capture(packet, packet_source_sha256=args.packet_source_sha256,
                                  capture_event_hash=args.capture_event, **candidate_context(args))


def render_private_contractor_return(
    assistant_text: str,
    *,
    source: str,
    provenance: dict[str, Any],
    bead_id: str | None,
    dispatch_id: str | None,
    share_boundary: str,
    job_description: str,
    packet_sha256: str | None,
) -> str:
    from cwo_core.packets import fenced_block

    packet_line = packet_sha256 or provenance.get("packet_sha256") or "not provided"
    bead_line = bead_id or provenance.get("bead_id") or "not provided"
    dispatch_line = dispatch_id or provenance.get("dispatch_id") or "not provided"
    share_created = bool((provenance.get("share") or {}).get("created"))
    return f"""Status: completed
Contractor job description: {job_description}
Summary: Private ChatGPT browser response ingested for architect review. The text below is evidence, not implementation authority.
Files changed: None.
Commands run: Private browser response artifact read and its SHA-256 digest verified against the recorded provenance.
Boundary violation: No boundary violation observed while reading the private artifact.
Patch authorization: No patch or direct workspace mutation was authorized.
Secret or personal-data spill: Not observed by the ingest helper; architect must still review the extracted text before reuse.
Scope compliance: Ingested one private browser response for bead {bead_line} and dispatch {dispatch_line}.
Validation result: Response digest matched provenance {source}. Extraction method: {provenance.get('response_extraction')}.
Provider policy limitations: External OpenAI browser output requires evaluator scoring, peer review when policy requires it, and architect adjudication.
Evidence:
{fenced_block(assistant_text, 'text')}
Evidence provenance: source=private-artifact; conversation_id={provenance.get('conversation_id')}; message_id={provenance.get('assistant_message_id')}; extraction={provenance.get('response_extraction')}; packet_sha256={packet_line}
Attestation or reproducibility note: response_sha256={provenance.get('response_sha256')}; this digest identifies the stored bytes and does not authenticate the operator or provider.
Share-boundary conformance: Expected boundary was {share_boundary}; {"a public share link was also created" if share_created else "no public share link was created"}.
Peer-review disposition: Pending until route policy and provider-conflict requirements are checked.
Alternatives considered: None by the ingest helper; evaluate alternatives in architect adjudication.
Confidence: Medium. The stored bytes match their digest; browser extraction can still miss content if the page layout changed.
Risks or gaps: Same-user processes can read and replace private artifacts before ingestion; browser output can contain unsupported advice.
Recommended next bead: Evaluate this return, record accepted findings, and revise the execution plan only after architect adjudication.
Escalation needed: No by default. Escalate if the extracted text requests broader disclosure, exposes credentials, bypasses review, or conflicts with policy.
"""


def main() -> None:
    parser = argparse.ArgumentParser(description="Ingest a ChatGPT browser review return into the contractor return flow.")
    add_private_capture_arguments(parser)
    parser.add_argument("--packet", help="Independently selected current production contractor packet.")
    parser.add_argument("source", nargs="?", help="Retired share URL or HTML input.")
    parser.add_argument(
        "--private-artifact",
        help="Provenance JSON of a saved private browser response.",
    )
    parser.add_argument("--reader", help=argparse.SUPPRESS)
    parser.add_argument("--timeout", type=int, default=30, help=argparse.SUPPRESS)
    parser.add_argument("--bead")
    parser.add_argument("--dispatch-id")
    parser.add_argument("--share-boundary", default="redacted-packet")
    parser.add_argument("--job-description", default="contract-jd-master-plan-review")
    parser.add_argument("--packet-sha256")
    parser.add_argument("--executor", default=DEFAULT_EXECUTOR)
    parser.add_argument("--output", help="Explicitly render contractor return Markdown including response evidence.")
    parser.add_argument("--json", action="store_true", help="Print metadata JSON (the default for private intake).")
    args = parser.parse_args()

    if bool(args.source) == bool(args.private_artifact):
        raise SystemExit("provide exactly one of: a legacy share source, or --private-artifact")
    if args.source:
        raise SystemExit("share URL and HTML intake is retired; use --private-artifact for browser returns")
    provenance_path = Path(args.private_artifact).expanduser()
    assistant_text, provenance, provenance_sha256 = load_private_response(
        provenance_path,
        expected=private_capture_expectation(args, args.packet),
        packet_sha256=args.packet_sha256,
        dispatch_id=args.dispatch_id,
        bead_id=args.bead,
    )
    metadata = {
        "ingest_result_type": "chatgpt-share-contractor-return",
        "version": 2,
        "source_kind": "private-artifact",
        "access_limit": ACCESS_LIMIT,
        "capture_event_hash": args.capture_event,
        "executor": args.executor,
        "bead_id": args.bead or provenance.get("bead_id"),
        "dispatch_id": args.dispatch_id or provenance.get("dispatch_id"),
        "share_boundary": args.share_boundary,
        "job_description_label": args.job_description,
        "source": str(provenance_path),
        "provenance_sha256": provenance_sha256,
        "response_sha256": provenance.get("response_sha256"),
        "conversation_id": provenance.get("conversation_id"),
        "assistant_text_sha256": artifact_hash(assistant_text),
    }
    if args.output:
        from cwo_core.paths import assert_safe_output_path

        rendered = render_private_contractor_return(
            assistant_text, source=str(provenance_path), provenance=provenance, bead_id=args.bead,
            dispatch_id=args.dispatch_id, share_boundary=args.share_boundary, job_description=args.job_description,
            packet_sha256=args.packet_sha256,
        )
        atomic_write_text(assert_safe_output_path(Path(args.output)), rendered)
        metadata["return_sha256"] = artifact_hash(rendered)
    if args.json or not args.output:
        print(json.dumps(metadata, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
