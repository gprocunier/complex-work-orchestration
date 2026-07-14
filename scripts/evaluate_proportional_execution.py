"""CLI entry point for proportional proportional execution evaluation."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from cwo_core.proportional_execution import evaluate_proportional_execution


def _fail(message: str, code: int) -> None:
    print(message, file=sys.stderr)
    raise SystemExit(code)


def _safe_load_json(path: str, label: str) -> Any:
    try:
        value = Path(path).expanduser().resolve().read_text(encoding="utf-8")
    except OSError as exc:
        _fail(f"could not read {label}: {exc}", 2)
    try:
        return json.loads(value)
    except json.JSONDecodeError as exc:
        _fail(f"invalid {label}: {exc}", 2)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Evaluate a cwo-proportional-execution-brief for native fast-path dispatch.",
    )
    parser.add_argument("--brief", required=True, help="Path to proportional execution brief JSON")
    parser.add_argument("--capability-receipt", help="Optional existing capability receipt JSON")
    parser.add_argument("--at", help="Optional ISO timestamp for assessment time")
    parser.add_argument("--json", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    brief = _safe_load_json(args.brief, "brief")
    receipt = None
    if args.capability_receipt:
        receipt = _safe_load_json(args.capability_receipt, "capability receipt")
    result = evaluate_proportional_execution(brief, receipt, at=args.at)
    if args.json:
        print(json.dumps(result, sort_keys=True, indent=2))
    else:
        print(json.dumps(result, sort_keys=True))
    return 0 if result.get("dispatchable") else 2


if __name__ == "__main__":
    raise SystemExit(main())

