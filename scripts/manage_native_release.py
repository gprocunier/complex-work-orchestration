#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from cwo_core.native_release import (
    build_canary_release_evidence,
    validate_native_release_evidence,
    write_release_evidence,
)


def _load(path_value: str, label: str) -> dict[str, Any]:
    path = Path(path_value).expanduser().resolve()
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"{label} is unreadable: {exc}") from exc
    if not isinstance(value, dict):
        raise SystemExit(f"{label} must contain one JSON object")
    return value


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
