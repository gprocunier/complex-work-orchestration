#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from cwo_core.native_precommit import (
    arm_precommit,
    check_precommit,
    create_precommit_state,
    finalize_precommit,
    issue_precommit_receipt,
    make_deterministic_receipt,
    mark_fit_dispatched,
    render_fit_prompt,
    validate_precommit_receipt,
)


def _load(path_value: str, label: str) -> dict[str, Any]:
    path = Path(path_value).expanduser().resolve()
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"{label} is unreadable: {exc}") from exc
    if not isinstance(value, dict):
        raise SystemExit(f"{label} must contain one JSON object")
    return value


def _emit(value: dict[str, Any], *, compact: bool = False) -> None:
    if compact:
        print(json.dumps(value, sort_keys=True, separators=(",", ":")))
    else:
        print(json.dumps(value, indent=2, sort_keys=True))


def _common_create(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--packet-id", required=True)
    parser.add_argument("--attempt-nonce")
    parser.add_argument("--work-plan", required=True)
    parser.add_argument("--session-id", required=True)
    parser.add_argument("--session-file", required=True)
    parser.add_argument("--agent-id", required=True)
    parser.add_argument("--workdir", required=True)
    parser.add_argument("--state-file")
    parser.add_argument("--owner-pid", type=int)
    parser.add_argument("--control-execution-handle")
    parser.add_argument("--audit-file")
    parser.add_argument("--now")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Supervise a zero-tool native Spark fit before candidate packet construction."
    )
    commands = parser.add_subparsers(dest="command", required=True)
    render = commands.add_parser("render-fit-prompt")
    render.add_argument("--work-plan", required=True)
    create = commands.add_parser("create")
    _common_create(create)
    arm = commands.add_parser("arm")
    arm.add_argument("--state-file", required=True)
    arm.add_argument("--control-turn-id", required=True)
    arm.add_argument("--now")
    dispatched = commands.add_parser("mark-dispatched")
    dispatched.add_argument("--state-file", required=True)
    dispatched.add_argument("--control-turn-id", required=True)
    dispatched.add_argument("--submission-id", required=True)
    dispatched.add_argument("--now")
    check = commands.add_parser("check")
    check.add_argument("--state-file", required=True)
    check.add_argument("--control-turn-id", required=True)
    check.add_argument("--now")
    finalize = commands.add_parser("finalize")
    finalize.add_argument("--state-file", required=True)
    finalize.add_argument("--control-turn-id", required=True)
    finalize.add_argument("--control-action", required=True, choices=[
        "worker-completed",
        "interrupt-confirmed",
        "close-confirmed",
        "control-failed",
    ])
    finalize.add_argument("--now")
    receipt = commands.add_parser("issue-receipt")
    receipt.add_argument("--state-file", required=True)
    receipt.add_argument("--receipt-file")
    validate = commands.add_parser("validate-receipt")
    validate.add_argument("--receipt", required=True)
    validate.add_argument("--work-plan")
    validate.add_argument("--packet-id")
    validate.add_argument("--live", action="store_true")
    validate.add_argument("--require-accepting", action="store_true")
    deterministic = commands.add_parser("deterministic-receipt")
    _common_create(deterministic)
    deterministic.add_argument("--fit-result", required=True)
    deterministic.add_argument("--control-turn-id", required=True)
    deterministic.add_argument("--receipt-file")
    parser.add_argument("--compact", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        if args.command == "render-fit-prompt":
            print(render_fit_prompt(_load(args.work_plan, "work plan")), end="")
            return 0
        if args.command == "create":
            result = create_precommit_state(
                packet_id=args.packet_id,
                attempt_nonce=args.attempt_nonce,
                work_plan=_load(args.work_plan, "work plan"),
                session_id=args.session_id,
                session_file=args.session_file,
                agent_id=args.agent_id,
                workdir=args.workdir,
                state_file=args.state_file,
                owner_pid=args.owner_pid,
                control_execution_handle=args.control_execution_handle,
                audit_file=args.audit_file,
                now=args.now,
            )
            _emit(result, compact=args.compact)
            return 0
        if args.command == "arm":
            _emit(arm_precommit(args.state_file, args.control_turn_id, now=args.now), compact=args.compact)
            return 0
        if args.command == "mark-dispatched":
            result, code = mark_fit_dispatched(
                args.state_file,
                args.control_turn_id,
                args.submission_id,
                now=args.now,
            )
            _emit(result, compact=args.compact)
            return code
        if args.command == "check":
            result, code = check_precommit(args.state_file, args.control_turn_id, now=args.now)
            _emit(result, compact=args.compact)
            return code
        if args.command == "finalize":
            result = finalize_precommit(
                args.state_file,
                args.control_turn_id,
                args.control_action,
                now=args.now,
            )
            _emit(result, compact=args.compact)
            return 0
        if args.command == "issue-receipt":
            _emit(
                issue_precommit_receipt(args.state_file, receipt_file=args.receipt_file),
                compact=args.compact,
            )
            return 0
        if args.command == "validate-receipt":
            receipt = _load(args.receipt, "precommit receipt")
            plan = _load(args.work_plan, "work plan") if args.work_plan else None
            errors = validate_precommit_receipt(
                receipt,
                plan,
                expected_packet_id=args.packet_id,
                live=args.live,
                require_accepting=args.require_accepting,
            )
            if errors:
                raise ValueError("; ".join(errors))
            print("precommit receipt valid")
            return 0
        if args.command == "deterministic-receipt":
            result = make_deterministic_receipt(
                packet_id=args.packet_id,
                attempt_nonce=args.attempt_nonce,
                work_plan=_load(args.work_plan, "work plan"),
                session_id=args.session_id,
                session_file=args.session_file,
                agent_id=args.agent_id,
                workdir=args.workdir,
                fit_result=_load(args.fit_result, "fit result"),
                control_turn_id=args.control_turn_id,
                state_file=args.state_file,
                receipt_file=args.receipt_file,
                owner_pid=args.owner_pid,
                control_execution_handle=args.control_execution_handle,
                audit_file=args.audit_file,
                now=args.now,
            )
            _emit(result, compact=args.compact)
            return 0
    except ValueError as exc:
        raise SystemExit(f"precommit supervision failed closed: {exc}") from exc
    raise SystemExit(f"unsupported command {args.command!r}")


if __name__ == "__main__":
    raise SystemExit(main())
