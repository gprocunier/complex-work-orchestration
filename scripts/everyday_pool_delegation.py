#!/usr/bin/env python3
"""Run one protected ordinary contained pool from its approved project."""
from __future__ import annotations

import argparse
from pathlib import Path
import sys

from registered_native_pool_client import validate_structure
from run_admitted_native_pool_transaction import _load_pool_request, main as run_pool_request


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pool-request", required=True, type=Path)
    parser.add_argument("--validate-only", action="store_true")
    args = parser.parse_args(argv)
    try:
        request = _load_pool_request(args.pool_request)
        validate_structure(request)
        from registered_contained_pool_host import open_approved_pool

        host = open_approved_pool(Path.cwd(), request["pool_id"])
        forwarded = ["--pool-request", str(args.pool_request)]
        if args.validate_only:
            forwarded.append("--validate-only")
        return run_pool_request(forwarded, host=host)
    except (OSError, RuntimeError, ValueError) as failure:
        print(f"delegate-pool: {failure}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
