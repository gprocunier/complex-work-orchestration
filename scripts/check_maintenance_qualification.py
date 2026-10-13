#!/usr/bin/env python3
"""Read one observed qualification bundle. This CLI has NO dispatch authority."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from cwo_core.maintenance_qualification import inspect_observation  # noqa: E402


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--observation-sha256", required=True)
    parser.add_argument("--nonce", required=True)
    args = parser.parse_args(argv)
    try:
        if len(args.nonce) != 32 or any(c not in "0123456789abcdef" for c in args.nonce):
            raise ValueError("qualification-checker-invalid-nonce")
        summary = inspect_observation(root=args.root, observation_sha256=args.observation_sha256)
        print(json.dumps({**summary, "nonce": args.nonce}, sort_keys=True, separators=(",", ":")))
        return 0
    except (OSError, ValueError, TypeError) as exc:
        print("check_maintenance_qualification: " + str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
