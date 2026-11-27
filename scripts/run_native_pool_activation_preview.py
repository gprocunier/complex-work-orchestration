#!/usr/bin/env python3
"""Prepare and validate the fixed native activation preview offline."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys
from typing import Any, Mapping, NoReturn


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from cwo_core import native_live_availability  # noqa: E402
from cwo_core.native_activation_ledger import NativeActivationLedgerStore  # noqa: E402
from cwo_core.native_activation_preview import (  # noqa: E402
    PROFILE,
    activation_dry_run,
    approve_activation_plan,
    generate_activation_key,
    prepare_activation_plan,
)
from cwo_core.native_pool_admission import BeadsClaimAdapter  # noqa: E402
from cwo_core.native_tool_activation import TOOL_ENFORCEMENT_OVERRIDE_RISK  # noqa: E402
from cwo_core.supervision.live_thread import LiveThreadAdapter as LiveThreadAdapter  # noqa: E402
from cwo_core.supervision.transport.app_server import AppServer  # noqa: E402
from cwo_core.supervision.transport.errors import AppServerError as AppServerError  # noqa: E402


# Retain the shipped state and error contract for existing callers.
live_availability = native_live_availability
LIVE_ACTIVATION_AVAILABLE = False
LIVE_ACTIVATION_UNAVAILABLE = (
    "live activation is unavailable: the database-identity hold or its native N1/pool route is held in installed source. "
    "Nothing was claimed, started or written. "
    "keygen, prepare, approve and run --dry-run remain available."
)


class LiveActivationUnavailable(RuntimeError):
    """Live activation refused before any claim, RPC or Beads write."""


def _require_live_activation(profile: str | None = None) -> NoReturn:
    raise LiveActivationUnavailable(LIVE_ACTIVATION_UNAVAILABLE)


class ActivationLedgerTransport:
    """Refuse the retired preview's model-facing transport entry points."""

    def __init__(
        self,
        server: AppServer,
        ledger: NativeActivationLedgerStore,
        *,
        pending_allocation_intents: Mapping[str, str] | None = None,
    ) -> None:
        self.thread_roles: dict[str, str] = {}
        self.pending_allocation_intents = dict(pending_allocation_intents or {})

    def start_thread(
        self,
        cwd: Path,
        *,
        mutable: bool,
        role: str | None = None,
        permitted_tools: list[str] | None = None,
        allowlist_parameter: str | None = None,
    ) -> tuple[dict[str, Any], float]:
        _require_live_activation()

    def start_turn(
        self,
        thread_id: str,
        prompt: str,
        *,
        timeout: float = 30,
        ambiguity_timeout: float = 5,
    ) -> tuple[dict[str, Any], float]:
        _require_live_activation()


def _write_worker_contracts(
    plan: Mapping[str, Any],
    reservation: Mapping[str, Any],
    transport: ActivationLedgerTransport,
    server: AppServer,
) -> NoReturn:
    _require_live_activation()


def _start_activation_server(profile: str) -> AppServer:
    _require_live_activation()


def _close_accepted_activation_beads(
    plan: Mapping[str, Any],
    reservation: Mapping[str, Any],
    pool_receipt: Mapping[str, Any],
    adapter: BeadsClaimAdapter,
    *,
    pool_receipt_sha256: str,
) -> dict[str, Any]:
    _require_live_activation()


def run_live_activation(
    plan_path: Path,
    approval_path: Path,
    *,
    control_root: Path,
    actor_id: str,
    identity_source: str,
) -> dict[str, Any]:
    _require_live_activation()


def parser() -> argparse.ArgumentParser:
    command = argparse.ArgumentParser(
        description=(
            "Offline native pool activation preview."
        )
    )
    subcommands = command.add_subparsers(dest="command", required=True)

    keygen = subcommands.add_parser("keygen")
    keygen.add_argument("--control-root", type=Path, required=True)

    prepare = subcommands.add_parser("prepare")
    prepare.add_argument("--control-root", type=Path, required=True)
    prepare.add_argument(
        "--profile",
        choices=tuple(PROFILE),
        required=True,
    )
    prepare.add_argument("--source-repo", type=Path, required=True)

    approve = subcommands.add_parser("approve")
    approve.add_argument("--control-root", type=Path, required=True)
    approve.add_argument("--prepared", type=Path, required=True)
    approve.add_argument("--operator-id", required=True)
    approve.add_argument("--identity-source", required=True)
    approve.add_argument(
        "--ttl-seconds",
        type=int,
        default=600,
    )
    approve.add_argument(
        "--accept-risk",
        choices=(TOOL_ENFORCEMENT_OVERRIDE_RISK,),
        required=True,
    )

    run = subcommands.add_parser("run")
    run.add_argument("--control-root", type=Path, required=True)
    run.add_argument("--prepared", type=Path, required=True)
    run.add_argument("--approval", type=Path, required=True)
    run.add_argument("--operator-id", required=True)
    run.add_argument("--identity-source", required=True)
    mode = run.add_mutually_exclusive_group(required=True)
    mode.add_argument("--dry-run", action="store_true")
    mode.add_argument("--enable-tech-preview", action="store_true")
    return command


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        if args.command == "keygen":
            result = generate_activation_key(args.control_root)
        elif args.command == "prepare":
            from model_catalog_startup import configure_cli_model_catalog
            from cwo_core.model_identities import OPERATIVE_ROLES

            configure_cli_model_catalog(OPERATIVE_ROLES)
            path, plan = prepare_activation_plan(
                args.control_root,
                profile=args.profile,
                source_repository=args.source_repo,
            )
            result = {
                "status": "prepared",
                "prepared": str(path),
                "activation_id": plan["activation_id"],
                "profile": plan["profile"],
                "plan_sha256": plan["plan_sha256"],
                "live": False,
            }
        elif args.command == "approve":
            path, receipt = approve_activation_plan(
                args.prepared,
                control_root=args.control_root,
                actor_id=args.operator_id,
                identity_source=args.identity_source,
                ttl_seconds=args.ttl_seconds,
                risk_acknowledgement=args.accept_risk,
            )
            result = {
                "status": "approved",
                "approval": str(path),
                "approval_id": receipt["approval_id"],
                "expires_at": receipt["expires_at"],
                "live": False,
            }
        elif args.dry_run:
            result = activation_dry_run(
                args.prepared,
                args.approval,
                control_root=args.control_root,
                actor_id=args.operator_id,
                identity_source=args.identity_source,
            )
        else:
            result = run_live_activation(
                args.prepared,
                args.approval,
                control_root=args.control_root,
                actor_id=args.operator_id,
                identity_source=args.identity_source,
            )
        print(json.dumps(result, sort_keys=True))
        return 0
    except BaseException as exc:
        rejection = {
            "status": "rejected",
            "failure_class": type(exc).__name__,
            "failure_message_sha256": hashlib.sha256(
                str(exc).encode("utf-8")
            ).hexdigest(),
        }
        if isinstance(exc, LiveActivationUnavailable):
            # A fixed message with no run content, so it is shown in full.
            rejection["failure_message"] = str(exc)
        print(json.dumps(rejection, sort_keys=True), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
