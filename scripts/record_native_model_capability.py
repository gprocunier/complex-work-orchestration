#!/usr/bin/env python3
"""Build or validate native model capability receipts from supplied evidence."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Any

from cwo_core.native_capability import (
    build_capability_receipt,
    validate_capability_receipt,
)


def _load_object(path: str, label: str) -> dict[str, Any]:
    with Path(path).open("r", encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a JSON object")
    return value


def _write_json_atomic(path: str, payload: dict[str, Any]) -> None:
    target = Path(path).resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_name(f".{target.name}.{os.getpid()}.tmp")
    try:
        with temporary.open("x", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True, ensure_ascii=True)
            handle.write("\n")
        os.chmod(temporary, 0o600)
        os.replace(temporary, target)
    finally:
        temporary.unlink(missing_ok=True)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Record or validate trusted native model capability evidence; this command never spawns a model."
    )
    commands = parser.add_subparsers(dest="command", required=True)
    build = commands.add_parser("build", help="Build a receipt from supplied trusted evidence.")
    build.add_argument("--evidence", required=True)
    build.add_argument("--authorized-model", action="append", required=True, dest="authorized_models")
    build.add_argument("--issued-at", required=True)
    build.add_argument("--expires-at", required=True)
    build.add_argument("--output", required=True)
    validate = commands.add_parser("validate", help="Validate an existing receipt.")
    validate.add_argument("--receipt", required=True)
    return parser


def main() -> int:
    args = _parser().parse_args()
    try:
        if args.command == "build":
            evidence = _load_object(args.evidence, "evidence")
            receipt = build_capability_receipt(
                evidence,
                args.authorized_models,
                issued_at=args.issued_at,
                expires_at=args.expires_at,
            )
            errors = validate_capability_receipt(receipt)
            if errors:
                raise ValueError("receipt validation failed: " + "; ".join(errors))
            _write_json_atomic(args.output, receipt)
            print(json.dumps({"status": "recorded", "output": str(Path(args.output).resolve()), "authority": receipt["authority"]}, sort_keys=True))
            return 0
        receipt = _load_object(args.receipt, "receipt")
        errors = validate_capability_receipt(receipt)
        print(json.dumps({"status": "valid" if not errors else "invalid", "errors": errors}, sort_keys=True))
        return 0 if not errors else 1
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(json.dumps({"status": "error", "error": str(exc)}, sort_keys=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
