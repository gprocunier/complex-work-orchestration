#!/usr/bin/env python3
"""Render, validate, inspect, and interrupt bounded native supervision pools."""

from __future__ import annotations

import argparse
import datetime as dt
import json
from pathlib import Path
import uuid
from typing import Any

from cwo_core.native_pool_config import (
    NativePoolConfigError,
    RENDER_REQUEST_TYPE,
    build_pool_contract,
    validate_pool_render_request,
)
from cwo_core.native_pool_contracts import (
    CAPABILITY_RECEIPT_TYPE,
    POOL_CONTROL_REQUEST_SCHEMA,
    POOL_CONTROL_REQUEST_TYPE,
    VERSION,
    seal_artifact,
    validate_capability_receipt,
    validate_pool_artifact,
    validate_pool_contract,
    validate_pool_control_request,
    validate_pool_state,
    write_private_artifact,
)
from cwo_core.native_pool_leases import PoolLeaseRegistry
from cwo_core.native_pool_reporting import (
    NativePoolReportingError,
    build_pool_status_report,
    record_pool_audit_event,
)


def _load_object(path_value: str, label: str) -> dict[str, Any]:
    path = Path(path_value).expanduser().absolute()
    if path.is_symlink():
        raise ValueError(f"{label} path is a symlink")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"{label} is unreadable") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{label} must contain one JSON object")
    return value


def _utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Manage strict native supervision pool artifacts. Connected native callbacks "
            "remain in the host process through cwo_core.native_pool.NativePoolCoordinator."
        )
    )
    commands = parser.add_subparsers(dest="command", required=True)

    render = commands.add_parser("render", help="Render a hash-bound fixed-cohort pool contract.")
    render.add_argument("--request", required=True)
    render.add_argument("--output", required=True)
    render.add_argument("--capability-receipt")
    render.add_argument("--enable-concurrency", action="store_true")
    render.add_argument("--owner-pid", type=int, required=True)

    validate = commands.add_parser("validate", help="Strictly validate one pool artifact.")
    validate.add_argument("--artifact", required=True)
    validate.add_argument("--contract")
    validate.add_argument("--state")

    status = commands.add_parser("status", help="Report absolute pool, worker, timing, lease, and disposition state.")
    status.add_argument("--contract", required=True)
    status.add_argument("--state", required=True)
    status.add_argument("--receipt")
    status.add_argument("--audit-file")
    status.add_argument("--bead-id")

    interrupt = commands.add_parser("interrupt", help="Write a state-bound mode-0600 interrupt request.")
    interrupt.add_argument("--contract", required=True)
    interrupt.add_argument("--state", required=True)
    interrupt.add_argument("--output", required=True)
    interrupt.add_argument("--reason", required=True)
    interrupt.add_argument("--request-id")
    interrupt.add_argument("--audit-file")
    interrupt.add_argument("--bead-id")

    cleanup = commands.add_parser("cleanup-leases", help="Clean only dead-owner leases with terminal evidence.")
    cleanup.add_argument("--registry", required=True)
    cleanup.add_argument("--terminal-state", action="append", default=[])
    return parser


def _validate_command(args: argparse.Namespace) -> dict[str, Any]:
    artifact = _load_object(args.artifact, "artifact")
    contract = _load_object(args.contract, "contract") if args.contract else None
    state = _load_object(args.state, "state") if args.state else None
    if artifact.get("request_type") == RENDER_REQUEST_TYPE:
        errors = validate_pool_render_request(artifact)
    elif artifact.get("receipt_type") == CAPABILITY_RECEIPT_TYPE:
        errors = validate_capability_receipt(artifact, expected_contract=contract)
    else:
        errors = validate_pool_artifact(artifact, contract=contract, state=state)
    return {
        "status": "valid" if not errors else "invalid",
        "errors": errors,
    }


def _audit_requested(args: argparse.Namespace) -> bool:
    if bool(args.audit_file) != bool(args.bead_id):
        raise ValueError("--audit-file and --bead-id must be supplied together")
    return bool(args.audit_file)


def main() -> int:
    args = _parser().parse_args()
    try:
        if args.command == "render":
            request = _load_object(args.request, "render request")
            capability = _load_object(args.capability_receipt, "capability receipt") if args.capability_receipt else None
            contract = build_pool_contract(
                request,
                capability_receipt=capability,
                enable_concurrency=args.enable_concurrency,
                owner_pid=args.owner_pid,
            )
            output = Path(args.output).expanduser().resolve()
            write_private_artifact(output, contract)
            print(
                json.dumps(
                    {
                        "status": "rendered",
                        "output": str(output),
                        "pool_id": contract["pool_id"],
                        "max_active_workers": contract["max_active_workers"],
                        "contract_sha256": contract["contract_sha256"],
                    },
                    sort_keys=True,
                )
            )
            return 0

        if args.command == "validate":
            result = _validate_command(args)
            print(json.dumps(result, sort_keys=True))
            return 0 if result["status"] == "valid" else 1

        if args.command == "status":
            audited = _audit_requested(args)
            contract = _load_object(args.contract, "contract")
            state = _load_object(args.state, "state")
            receipt = _load_object(args.receipt, "receipt") if args.receipt else None
            report = build_pool_status_report(contract, state, receipt)
            if audited:
                event_type = "native_pool_terminal" if receipt is not None else "native_pool_status"
                event = record_pool_audit_event(
                    report,
                    event_type=event_type,
                    bead_id=args.bead_id,
                    audit_file=Path(args.audit_file).expanduser().resolve(),
                )
                report["audit_event_hash"] = event["event_hash"]
            print(json.dumps(report, indent=2, sort_keys=True))
            return 0

        if args.command == "interrupt":
            audited = _audit_requested(args)
            contract = _load_object(args.contract, "contract")
            state = _load_object(args.state, "state")
            contract_errors = validate_pool_contract(contract)
            state_errors = validate_pool_state(state, contract=contract)
            if contract_errors or state_errors:
                raise ValueError("bound pool artifacts are invalid: " + ";".join([*contract_errors, *state_errors]))
            if state.get("status") in {"closed", "control-failed"}:
                raise ValueError("terminal pool state cannot accept a control request")
            request = seal_artifact(
                {
                    "request_type": POOL_CONTROL_REQUEST_TYPE,
                    "version": VERSION,
                    "schema": POOL_CONTROL_REQUEST_SCHEMA,
                    "request_id": args.request_id or f"interrupt-{uuid.uuid4().hex}",
                    "pool_id": contract["pool_id"],
                    "pool_epoch": contract["pool_epoch"],
                    "contract_sha256": contract["contract_sha256"],
                    "observed_state_sequence": state["state_sequence"],
                    "observed_state_sha256": state["state_sha256"],
                    "action": "interrupt",
                    "reason": args.reason,
                    "created_at": _utc_now(),
                },
                "request_sha256",
            )
            request_errors = validate_pool_control_request(request, contract=contract, state=state)
            if request_errors:
                raise ValueError("control request is invalid: " + ";".join(request_errors))
            output = Path(args.output).expanduser().resolve()
            write_private_artifact(output, request)
            result: dict[str, Any] = {
                "status": "interrupt-requested",
                "output": str(output),
                "request_id": request["request_id"],
                "request_sha256": request["request_sha256"],
            }
            if audited:
                report = build_pool_status_report(contract, state)
                event = record_pool_audit_event(
                    report,
                    event_type="native_pool_interrupt_requested",
                    bead_id=args.bead_id,
                    audit_file=Path(args.audit_file).expanduser().resolve(),
                )
                result["audit_event_hash"] = event["event_hash"]
            print(json.dumps(result, sort_keys=True))
            return 0

        terminal_states: dict[str, dict[str, Any]] = {}
        for path in args.terminal_state:
            state = _load_object(path, "terminal state")
            pool_id = state.get("pool_id")
            if not isinstance(pool_id, str) or not pool_id:
                raise ValueError("terminal state is missing pool_id")
            if pool_id in terminal_states:
                raise ValueError(f"duplicate terminal state for pool {pool_id}")
            terminal_states[pool_id] = state
        registry = PoolLeaseRegistry(Path(args.registry).expanduser().resolve())
        changed = registry.cleanup_stale(terminal_states)
        print(
            json.dumps(
                {
                    "status": "cleaned",
                    "changed": len(changed),
                    "leases": [
                        {
                            "lease_id": lease["lease_id"],
                            "pool_id": lease["pool_id"],
                            "lifecycle_state": lease["lifecycle_state"],
                            "lease_sha256": lease["lease_sha256"],
                        }
                        for lease in changed
                    ],
                },
                sort_keys=True,
            )
        )
        return 0
    except (NativePoolConfigError, NativePoolReportingError, ValueError, OSError) as exc:
        print(json.dumps({"status": "error", "error": str(exc)}, sort_keys=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
