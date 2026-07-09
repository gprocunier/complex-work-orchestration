#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from typing import Any

from cwo_core.access_profiles import (
    access_profile_runtime_status,
    access_profiles,
    sanitized_access_profile,
    validate_access_profile_registry,
)


def profile_record(profile_key: str) -> dict[str, Any]:
    return {
        "access_profile": profile_key,
        "details": sanitized_access_profile(profile_key),
        "runtime_readiness": access_profile_runtime_status(profile_key),
    }


def render_table(records: list[dict[str, Any]]) -> str:
    lines = [
        "Access Profile | Status | Ready | Required Env | Optional Env",
        "--- | --- | --- | --- | ---",
    ]
    for record in records:
        details = record.get("details") if isinstance(record.get("details"), dict) else {}
        readiness = record.get("runtime_readiness") if isinstance(record.get("runtime_readiness"), dict) else {}
        required = [
            f"{item.get('name')}={'set' if item.get('configured') else 'missing'}"
            for item in readiness.get("required_env", [])
            if isinstance(item, dict)
        ]
        optional = [
            f"{item.get('name')}={'set' if item.get('configured') else 'unset'}"
            for item in readiness.get("optional_env", [])
            if isinstance(item, dict)
        ]
        lines.append(
            " | ".join(
                [
                    str(record.get("access_profile")),
                    str(details.get("status")),
                    "yes" if readiness.get("ready") else "no",
                    ", ".join(required) or "-",
                    ", ".join(optional) or "-",
                ]
            )
        )
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="Render redacted CWO access profile readiness.")
    parser.add_argument("--profile", action="append", help="Access profile key to render. May be repeated.")
    parser.add_argument("--require-configured", action="store_true", help="Exit nonzero if any selected required env var is missing.")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    validation_errors = validate_access_profile_registry()
    if validation_errors:
        print("\n".join(validation_errors), file=sys.stderr)
        raise SystemExit(1)

    registry = access_profiles()
    selected = args.profile or sorted(registry)
    unknown = [profile_key for profile_key in selected if profile_key not in registry]
    if unknown:
        print("unknown access profile(s): " + ", ".join(sorted(unknown)), file=sys.stderr)
        raise SystemExit(1)

    records = [profile_record(profile_key) for profile_key in selected]
    missing_required = [
        f"{record['access_profile']}:{name}"
        for record in records
        for name in (record.get("runtime_readiness") or {}).get("missing_required_env", [])
    ]

    if args.json:
        print(json.dumps({"profiles": records}, indent=2, sort_keys=True))
    else:
        print(render_table(records))

    if args.require_configured and missing_required:
        print("missing required env: " + ", ".join(missing_required), file=sys.stderr)
        raise SystemExit(2)


if __name__ == "__main__":
    main()
