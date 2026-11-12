#!/usr/bin/env python3
"""Validate, schedule and score the three-arm comparative evaluation offline.

Every subcommand reads frozen data, the study lock or recorded fixture runs.
None runs a model, opens a network connection or starts a process. ``score``
reads, verifies and parses the files the study lock binds itself (controller,
protocol, scorer, hidden checks and build freeze) and refuses unless each
still has its locked digest; while a build freeze slot is empty no run is
evidence. ``run`` exists only to refuse: running an
arm is a held external effect with no authorization in this version. Every
``run`` invocation that parses exits 3 before reading anything; ``run --help``
prints usage and exits 0, and a malformed option exits 2 from the argument
parser. None of the three starts anything.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from cwo_core.comparative_evaluation import (
    LOCKED_PATHS,
    HeldEffectRefused,
    blank_results_template,
    build_freeze_errors,
    build_frozen_protocol_lock,
    build_schedule,
    json_string_errors,
    load_json,
    preregistration_digest,
    refuse_arm_execution,
    runtime_binding_errors,
    score_under_study_lock,
    unbound_build_slots,
    validate_protocol,
)
from cwo_core.frozen_protocol import file_sha256


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_ROOT = REPO_ROOT / "evaluation" / "three-arm"
EXIT_INVALID = 1
EXIT_UNREADABLE = 2
EXIT_REFUSED = 3


def _load(path: Path, label: str) -> Any:
    try:
        return load_json(path)
    except (OSError, ValueError) as exc:
        print(f"{label} is unreadable: {exc}", file=sys.stderr)
        raise SystemExit(EXIT_UNREADABLE) from exc


def _print(value: Any) -> None:
    try:
        if errors := json_string_errors(value, "output"):
            raise ValueError("; ".join(errors))
        rendered = json.dumps(value, indent=2, sort_keys=True, allow_nan=False)
    except (ValueError, OverflowError) as exc:
        print(json.dumps({"errors": [f"output cannot be represented as finite JSON: {exc}"]}))
        raise SystemExit(EXIT_INVALID) from exc
    print(rendered)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=DEFAULT_ROOT, help="protocol directory")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("validate", help="validate the frozen protocol and its bound files")
    commands.add_parser("digest", help="print the computed pre-registration digest")
    commands.add_parser("schedule", help="print the blocked, randomized run order")
    score = commands.add_parser("score", help="score recorded runs under the original study lock")
    score.add_argument("runs", type=Path)
    score.add_argument("--lock", type=Path, required=True, help="the study lock emitted by 'lock' at study freeze")
    commands.add_parser("lock", help="print the study as a frozen-protocol lock")
    commands.add_parser("template", help="print the blank analysis template")
    run = commands.add_parser("run", help="refused: running an arm is a held external effect")
    run.add_argument("--arm", help="ignored; every arm is refused")
    run.add_argument("--authorization", help="ignored; no authorization is recognized")
    args, extra = parser.parse_known_args(argv)
    if extra and args.command != "run":
        parser.error(f"unrecognized arguments: {' '.join(extra)}")
    return args


def _score(args: argparse.Namespace, root: Path) -> int:
    """Score from the locked files alone; the controller passes no protocol or hidden checks of its own."""

    lock = _load(args.lock, "study lock")
    errors = runtime_binding_errors(lock, controller_path=Path(__file__))
    if errors:
        _print({"valid": False, "errors": errors})
        return EXIT_INVALID
    result = score_under_study_lock(_load(args.runs, "runs"), lock, root.parents[1])
    _print(result)
    return EXIT_INVALID if "errors" in result else 0


def _lock(root: Path, protocol: Any, freeze: Any) -> int:
    repo = root.parents[1]
    unbound = unbound_build_slots(freeze)
    if unbound:
        print(
            f"note: build freeze slot(s) {', '.join(unbound)} are empty; every run scored under this lock "
            "is excluded-build-unbound until the slots are filled and the lock is emitted again",
            file=sys.stderr,
        )
    _print(build_frozen_protocol_lock(protocol, {path: file_sha256(repo / path) for path in LOCKED_PATHS}))
    return 0


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if args.command == "run":
        # Refuse before reading anything. Arguments that reach this point never
        # change the outcome; --help and malformed options end in the parser first.
        try:
            refuse_arm_execution(args.arm, args.authorization)
        except HeldEffectRefused as exc:
            print(f"refused: {exc}", file=sys.stderr)
            return EXIT_REFUSED
    root = args.root.resolve()
    if args.command == "score":
        return _score(args, root)
    protocol = _load(root / "protocol.json", "protocol")
    hidden = _load(root / "hidden" / "checks.json", "hidden checks")
    if args.command == "digest":
        try:
            print(preregistration_digest(protocol))
        except ValueError as exc:
            _print({"valid": False, "errors": [f"protocol digest cannot be produced: {exc}"]})
            return EXIT_INVALID
        return 0
    freeze = _load(root / "build-freeze.json", "build freeze")
    errors = validate_protocol(protocol, hidden, root=root) + build_freeze_errors(freeze)
    if errors:
        _print({"valid": False, "errors": errors})
        return EXIT_INVALID
    if args.command == "validate":
        _print(
            {
                "valid": True,
                "protocol_id": protocol["protocol_id"],
                "digest": protocol["preregistration"]["digest"],
                "build_freeze_complete": not unbound_build_slots(freeze),
                "unbound_builds": unbound_build_slots(freeze),
            }
        )
        return 0
    if args.command == "schedule":
        _print(build_schedule(protocol))
        return 0
    if args.command == "template":
        _print(blank_results_template(protocol))
        return 0
    return _lock(root, protocol, freeze)


if __name__ == "__main__":
    raise SystemExit(main())
