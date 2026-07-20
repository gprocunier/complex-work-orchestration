#!/usr/bin/env python3
"""Check or regenerate pool schema limits from canonical capacity policy."""

from __future__ import annotations

import argparse

from cwo_core.native_pool_capacity import (
    capacity_schema_errors,
    load_pool_capacity,
    write_capacity_schema_documents,
)


def main() -> int:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--check",
        action="store_true",
        help="verify capacity-bound schemas without changing files (default)",
    )
    mode.add_argument(
        "--write",
        action="store_true",
        help="rewrite capacity-bound schemas; default is a read-only check",
    )
    args = parser.parse_args()
    limits = load_pool_capacity()
    if args.write:
        changed = write_capacity_schema_documents(limits=limits)
        for relative in changed:
            print(relative)
    errors = capacity_schema_errors(limits=limits)
    if errors:
        for error in errors:
            print(error)
        return 1
    print(
        "Native pool capacity schemas match policy: "
        f"default={limits.default_max_active_workers} "
        f"released={limits.released_max_active_workers} "
        f"hard={limits.hard_max_active_workers}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
