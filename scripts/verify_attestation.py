#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

from cwo_core.packets import verify_attestation


def main() -> None:
    parser = argparse.ArgumentParser(description="Verify a SHA-256 subject attestation.")
    parser.add_argument("--file", required=True, help="Subject file to verify.")
    parser.add_argument("--attestation", required=True, help="Attestation JSON file.")
    parser.add_argument("--json", action="store_true", help="Print machine-readable JSON.")
    args = parser.parse_args()

    subject_bytes = Path(args.file).read_bytes()
    attestation = json.loads(Path(args.attestation).read_text(encoding="utf-8"))
    result = verify_attestation(subject_bytes, attestation)
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print("Attestation valid: " + ("yes" if result["valid"] else "no"))
        for error in result["errors"]:
            print(f"- {error}")
    if not result["valid"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
