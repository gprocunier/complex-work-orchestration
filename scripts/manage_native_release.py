#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Any

from cwo_core.native_release import (
    authorize_operative_packet,
    build_canary_release_evidence,
    validate_native_release_evidence,
    write_release_evidence,
)
from cwo_core.paths import is_cwo_temp_path
from cwo_core.util import atomic_write_text


def _load(path_value: str, label: str) -> dict[str, Any]:
    path = Path(path_value).expanduser().resolve()
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"{label} is unreadable: {exc}") from exc
    if not isinstance(value, dict):
        raise SystemExit(f"{label} must contain one JSON object")
    return value


def _write_private_payload(path_value: str, value: dict[str, Any]) -> Path:
    path = Path(path_value).expanduser().resolve()
    if path.is_symlink() or not is_cwo_temp_path(path):
        raise ValueError("authorized packet artifact must be under a CWO-owned temp directory")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.parent.stat().st_uid != os.getuid():
        raise ValueError("authorized packet directory must be owned by the current user")
    atomic_write_text(path, json.dumps(value, indent=2, sort_keys=True) + "\n")
    path.chmod(0o600)
    return path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Issue or validate CWO native release evidence.")
    commands = parser.add_subparsers(dest="command", required=True)
    canary = commands.add_parser("issue-canary")
    canary.add_argument("--packet-id", required=True)
    canary.add_argument("--attempt-nonce", required=True)
    canary.add_argument("--work-plan", required=True)
    canary.add_argument("--workdir", required=True)
    canary.add_argument("--output", required=True)
    canary.add_argument("--ttl-seconds", type=int, default=900)
    canary.add_argument("--now")
    operative = commands.add_parser("authorize-packet")
    operative.add_argument("--candidate-packet", required=True)
    operative.add_argument("--adjudication", required=True)
    operative.add_argument("--canary-receipt", required=True)
    operative.add_argument("--output", required=True)
    operative.add_argument("--ttl-seconds", type=int, default=900)
    operative.add_argument("--now")
    validate = commands.add_parser("validate")
    validate.add_argument("--evidence", required=True)
    validate.add_argument("--operation")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        if args.command == "issue-canary":
            evidence = build_canary_release_evidence(
                packet_id=args.packet_id,
                attempt_nonce=args.attempt_nonce,
                work_plan=_load(args.work_plan, "work plan"),
                workdir=args.workdir,
                ttl_seconds=args.ttl_seconds,
                now=args.now,
            )
            path = write_release_evidence(args.output, evidence)
            print(json.dumps({"evidence_file": str(path), **evidence}, sort_keys=True))
            return 0
        if args.command == "authorize-packet":
            from prepare_native_worker import validate_native_worker_packet

            candidate = _load(args.candidate_packet, "candidate packet")
            candidate_errors = validate_native_worker_packet(candidate)
            if candidate_errors:
                raise ValueError("candidate packet is invalid: " + "; ".join(candidate_errors))
            packet = authorize_operative_packet(
                candidate_packet=candidate,
                adjudication=_load(args.adjudication, "operative adjudication"),
                canary_receipt=_load(args.canary_receipt, "canary precommit receipt"),
                ttl_seconds=args.ttl_seconds,
                now=args.now,
            )
            packet_errors = validate_native_worker_packet(packet, dispatchable=True)
            if packet_errors:
                raise ValueError("authorized packet is invalid: " + "; ".join(packet_errors))
            path = _write_private_payload(args.output, packet)
            print(
                json.dumps(
                    {
                        "authorized_packet_file": str(path),
                        "packet_id": packet["packet_id"],
                        "release_evidence_sha256": packet["release_evidence_sha256"],
                    },
                    sort_keys=True,
                )
            )
            return 0
        evidence = _load(args.evidence, "native release evidence")
        errors = validate_native_release_evidence(evidence, operation=args.operation)
        if errors:
            raise ValueError("; ".join(errors))
        print("native release evidence valid")
        return 0
    except ValueError as exc:
        raise SystemExit(f"native release failed closed: {exc}") from exc


if __name__ == "__main__":
    raise SystemExit(main())
