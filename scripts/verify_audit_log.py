#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

from orchestration_lib import verify_audit_log


def main() -> None:
    parser = argparse.ArgumentParser(description="Verify orchestration audit JSONL hashes and hash-chain links.")
    parser.add_argument("--audit-file", help="Audit JSONL path; defaults to .orchestration-audit/audit.jsonl.")
    parser.add_argument("--json", action="store_true", help="Print machine-readable JSON.")
    args = parser.parse_args()

    result = verify_audit_log(Path(args.audit_file) if args.audit_file else None)
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print("Audit log valid: " + ("yes" if result["valid"] else "no"))
        print(f"Events: {result['event_count']}")
        if result.get("unlinked_event_count"):
            print(f"Legacy unlinked events: {result['unlinked_event_count']}")
        for error in result["errors"]:
            print(f"- {error}")
    if not result["valid"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
