#!/usr/bin/env python3
"""Generate bounded external trace data or check an explicitly selected release review."""
import argparse
import json
from pathlib import Path

from cwo_core import release_effect_routes as routes


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--evidence-dir", type=Path, required=True)
    parser.add_argument("--generate-trace", action="store_true")
    parser.add_argument("--review", help="Relative to evidence-dir; operator selection, not authentication")
    parser.add_argument("--review-sha256")
    args = parser.parse_args()
    try:
        result = (routes.write_trace(args.root, args.evidence_dir) if args.generate_trace else
                  routes.check(args.root, args.evidence_dir, args.review, args.review_sha256))
    except (routes.Refused, OSError, ValueError, KeyError, TypeError, SyntaxError) as exc:
        print(json.dumps({"contract_valid": False, "complete_effect_trace": False, "f8_complete": False,
                          "error": str(exc)}))
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
