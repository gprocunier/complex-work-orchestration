#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from cwo_core.native_control import build_control_turn_contract, validate_control_turn_contract


def _error(message: str) -> int:
    print(message, file=sys.stderr)
    return 1


def _require_state_fields(state: dict[str, Any], agent_id: str) -> tuple[str | None, int | None]:
    if state.get("status") != "created":
        return "state-status-invalid", None
    if state.get("submission_id") is not None:
        return "state-submission-id-must-be-null", None
    if state.get("control_turn_id") is not None:
        return "state-control-turn-id-must-be-null", None
    if state.get("control_turn_required") is not True:
        return "state-control-turn-required-false", None
    if state.get("decision") != "continue":
        return "state-decision-invalid", None
    if state.get("agent_id") != agent_id:
        return "state-agent-id-mismatch", None
    poll_interval_ms = state.get("poll_interval_ms")
    if not isinstance(poll_interval_ms, int) or isinstance(poll_interval_ms, bool) or poll_interval_ms <= 0:
        return "state-poll-interval-ms-invalid", None
    return None, poll_interval_ms


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Render one native control-turn contract.")
    parser.add_argument("--state-file", required=True)
    parser.add_argument("--agent-id", required=True)
    parser.add_argument("--control-turn-id", required=True)
    parser.add_argument("--task-sha256", required=True)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    state_path = Path(args.state_file).expanduser().resolve()
    try:
        state = json.loads(state_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return _error(f"malformed-state-json:{exc.msg}")
    except OSError as exc:
        return _error(f"state-file-read-failed:{exc}")
    if not isinstance(state, dict):
        return _error("state-file-must-contain-object")

    state_error, poll_interval_ms = _require_state_fields(state, args.agent_id)
    if state_error:
        return _error(state_error)
    assert poll_interval_ms is not None
    try:
        contract = build_control_turn_contract(
            state_file=str(state_path),
            agent_id=args.agent_id,
            control_turn_id=args.control_turn_id,
            task_sha256=args.task_sha256,
            poll_interval_ms=poll_interval_ms,
        )
    except ValueError as exc:
        return _error(str(exc))
    errors = validate_control_turn_contract(contract)
    if errors:
        return _error("invalid-control-turn-contract:" + ";".join(errors))
    print(json.dumps(contract, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
