#!/usr/bin/env python3
"""Accept the exact delivered candidate after hand review and close its Bead."""
from __future__ import annotations

import argparse
import json
import sys

from cwo_core import manual_delivery


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bead", required=True, help="Delivered Bead ID.")
    manual_delivery.add_delivery_arguments(parser, required=True)
    parser.add_argument("--reviewed-candidate", required=True, help="The SHA-256 digest of the candidate you reviewed.")
    parser.add_argument("--note", required=True, help="What you reviewed or where the evidence is (up to 240 characters).")
    parser.add_argument("--json", action="store_true", help="Print the closure and audit references as JSON.")
    args = parser.parse_args(argv)
    try:
        result = manual_delivery.accept_delivery(args)
    except (ValueError, OSError, SystemExit) as exc:
        print(f"accept_delivery: {exc}", file=sys.stderr)
        return 1
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(f"Accepted {result['candidate_sha256']} and closed {result['bead_id']}.")
        print(f"Host audit receipt {result['closure_event']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
