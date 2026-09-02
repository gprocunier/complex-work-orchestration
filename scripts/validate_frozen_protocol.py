#!/usr/bin/env python3
"""Validate a frozen experiment protocol and optionally clean safe cache drift."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from pathlib import PurePosixPath
from typing import Any

from cwo_core.frozen_protocol import (
    NEW_PROTOCOL_REQUIRED,
    PROTOCOL_READY,
    evaluate_frozen_protocol,
    inspect_python_cache_drift,
    repair_python_cache_drift,
)


def _load(path: Path, label: str) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"{label} is unreadable: {exc}") from exc


def _cache_root(base_dir: Path, value: str) -> Path:
    if not value or "\\" in value or "\x00" in value:
        raise SystemExit("cache root must be a normalized relative POSIX path")
    relative = PurePosixPath(value)
    if (
        relative.is_absolute()
        or value != relative.as_posix()
        or any(part in {"", ".", ".."} for part in relative.parts)
    ):
        raise SystemExit("cache root must be a normalized relative POSIX path")
    base = base_dir.resolve()
    path = base
    for part in relative.parts:
        path = path / part
        if path.is_symlink():
            raise SystemExit("cache root must not traverse a symlink")
    path = path.resolve(strict=False)
    try:
        path.relative_to(base)
    except ValueError as exc:
        raise SystemExit("cache root must remain beneath --base-dir") from exc
    return path


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("lock", type=Path)
    parser.add_argument("--run-spec", required=True, type=Path)
    parser.add_argument("--base-dir", default=".", type=Path)
    parser.add_argument("--cache-root", action="append", default=[])
    parser.add_argument("--repair-derived-cache", action="store_true")
    args = parser.parse_args()
    if args.repair_derived_cache and not args.cache_root:
        parser.error("--repair-derived-cache requires at least one --cache-root")

    lock = _load(args.lock, "protocol lock")
    run_spec = _load(args.run_spec, "run specification")
    protocol = evaluate_frozen_protocol(
        lock,
        run_spec,
        base_dir=args.base_dir,
    )
    steering = run_spec.get("steering") if isinstance(run_spec, dict) else None
    cache_repair_authorized = (
        protocol["decision"] == PROTOCOL_READY
        and isinstance(steering, dict)
        and steering.get("classification") == "same-scope-repair"
        and steering.get("repair_class") == "mechanical-derived-cache"
    )
    cache_reports: list[dict[str, Any]] = []
    for value in args.cache_root:
        root = _cache_root(args.base_dir, value)
        if args.repair_derived_cache and not cache_repair_authorized:
            observed = inspect_python_cache_drift(root)
            report = {
                "status": "repair-blocked",
                "reason": "typed same-scope mechanical-derived-cache repair is required",
                "before": observed,
                "removed_files": [],
                "removed_directories": [],
                "after": observed,
            }
        else:
            report = (
                repair_python_cache_drift(root)
                if args.repair_derived_cache
                else inspect_python_cache_drift(root)
            )
        cache_reports.append(report)

    decision = protocol["decision"]
    cache_blocked = False
    for report in cache_reports:
        final = report.get("after") if "after" in report else report
        if (
            report.get("status") == "repair-blocked"
            or not isinstance(final, dict)
            or final.get("status") != "clean"
        ):
            cache_blocked = True
    if cache_blocked and decision == PROTOCOL_READY:
        decision = "protocol-blocked"

    result = {
        "schema_version": "cwo-frozen-protocol-cli-result:v1",
        "decision": decision,
        "protocol": protocol,
        "cache": cache_reports,
    }
    print(json.dumps(result, indent=2, sort_keys=True))
    if decision != PROTOCOL_READY:
        raise SystemExit(3 if decision == NEW_PROTOCOL_REQUIRED else 2)


if __name__ == "__main__":
    main()
