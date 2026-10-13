#!/usr/bin/env python3
"""Run one parameterized readiness-first admitted native-pool transaction."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys
from typing import Any, Mapping

from cwo_core.native_pool_transaction import (
    TransactionRuntime,
    execute_native_pool_transaction,
    require_recovery_authority,
    validate_transaction_plan,
    write_transaction_result,
)


def _load_json(path: Path, label: str) -> dict[str, Any]:
    if not path.is_file() or path.is_symlink():
        raise ValueError(f"{label} must be a regular non-symlink file")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"{label} is not valid JSON: {exc}") from exc
    if type(value) is not dict:
        raise ValueError(f"{label} must contain one JSON object")
    return value


def _load_runtime(plan: Mapping[str, Any], *, maintenance_operation=None,
                  maintenance_verifier=None, trusted_factories=None,
                  controller_context=None) -> TransactionRuntime:
    """Load ONLY owner-selected code after independently checked authority.

    The CLI's submitted plan cannot supply trust configuration. Maintenance
    capabilities and legacy factory maps are injected by the embedding trusted
    controller, never read from caller-selected JSON/files/environment.
    """
    from dataclasses import replace
    from types import ModuleType
    from cwo_core.native_pool_transaction import MAINTENANCE_PLAN_VERSION
    if plan.get("version") == MAINTENANCE_PLAN_VERSION:
        from cwo_core.maintenance_authority import require_maintenance_operation
        capability = require_maintenance_operation(
            maintenance_operation, plan=plan, verifier=maintenance_verifier,
            require_claimed=False)
        capability.claim()  # Durable one-shot ownership precedes module effects.
        source = capability.read_adapter_source()
        path = capability.adapter_path
    else:
        # Ordinary finite budgets are unchanged. Their adapter authority must
        # originate in the controller's closed registry, not adapter code itself.
        descriptor = (trusted_factories or {}).get(plan.get("runtime_adapter_path"))
        if descriptor != plan.get("runtime_adapter_sha256"):
            raise ValueError("transaction-controller-adapter-authority-missing")
        path = Path(plan["runtime_adapter_path"])
        if any(q.is_symlink() for q in (path, *path.parents)) or not path.is_file():
            raise ValueError("runtime adapter must be an owned regular file")
        source = path.read_bytes()
        if hashlib.sha256(source).hexdigest() != descriptor:
            raise ValueError("runtime adapter does not match the trusted registry")
    module = ModuleType("cwo_native_pool_transaction_runtime_adapter")
    module.__file__ = str(path)
    exec(compile(source, str(path), "exec"), module.__dict__)
    builder = getattr(module, "build_transaction_runtime", None)
    if not callable(builder):
        raise ValueError("runtime adapter must export build_transaction_runtime")
    if controller_context is not None and plan.get("version") == 8:
        binder = getattr(controller_context, "bind_operation", None)
        if not callable(binder):
            raise ValueError("maintenance controller context must bind its operation")
        binder(capability, maintenance_verifier, dict(plan))
    runtime = (builder(dict(plan)) if controller_context is None else
               builder(dict(plan), controller_context))
    if type(runtime) is not TransactionRuntime:
        raise ValueError("runtime adapter returned the wrong exact runtime type")
    if plan.get("version") == MAINTENANCE_PLAN_VERSION:
        runtime = replace(runtime, maintenance_operation=capability,
                          maintenance_verifier=maintenance_verifier)
    require_recovery_authority(plan, runtime)
    return runtime


def validate_authorized_plan(plan, *, maintenance_operation=None,
                             maintenance_verifier=None, trusted_factories=None):
    """Check admission WITHOUT importing an adapter or consuming its identity."""
    errors = validate_transaction_plan(plan)
    if errors:
        raise ValueError("transaction plan is invalid: " + "; ".join(errors))
    if plan.get("version") == 8:
        from cwo_core.maintenance_authority import require_maintenance_operation
        require_maintenance_operation(maintenance_operation, plan=plan,
            verifier=maintenance_verifier, require_claimed=False)
    else:
        descriptor = (trusted_factories or {}).get(plan["runtime_adapter_path"])
        if descriptor != plan["runtime_adapter_sha256"]:
            raise ValueError("transaction-controller-adapter-authority-missing")
        path = Path(plan["runtime_adapter_path"])
        if any(q.is_symlink() for q in (path, *path.parents)) or not path.is_file():
            raise ValueError("runtime adapter must be an owned regular file")
        if hashlib.sha256(path.read_bytes()).hexdigest() != descriptor:
            raise ValueError("runtime adapter does not match the trusted registry")
    return {"validation_passed": True, "mode": "validate-only",
            "dispatch_authorized": False, "runtime_loaded": False,
            "transaction_id": plan["transaction_id"], "plan_sha256": plan["plan_sha256"]}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Validate or execute one N=1..3 transaction through "
            "run_admitted_native_pool."
        )
    )
    parser.add_argument("--plan", required=True, type=Path)
    parser.add_argument("--journal", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--validate-only", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        plan = _load_json(args.plan.expanduser().resolve(), "transaction plan")
        errors = validate_transaction_plan(plan)
        if errors:
            raise ValueError("transaction plan is invalid: " + "; ".join(errors))
        if args.validate_only:
            print(json.dumps(validate_authorized_plan(plan), indent=2, sort_keys=True))
            return 0
        runtime = _load_runtime(plan)
        if args.journal is None or args.output is None:
            raise ValueError("execution requires --journal and --output")
        result = execute_native_pool_transaction(
            plan,
            runtime,
            journal_path=args.journal,
        )
        write_transaction_result(args.output, result)
        print(
            json.dumps(
                {
                    "accepted": result["accepted"],
                    "state": result["state"],
                    "transaction_id": result["transaction_id"],
                    "plan_sha256": result["plan_sha256"],
                    "readiness_sha256": result["readiness_sha256"],
                    "output": str(args.output.expanduser().resolve()),
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 0 if result["accepted"] else 2
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"run_admitted_native_pool_transaction: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
