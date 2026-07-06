from __future__ import annotations

import argparse
from typing import Any


def add_waiver_reason_argument(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--waiver-reason",
        default="",
        help="Required when using bypass or no-audit flags; recorded in audit artifacts when audit is enabled.",
    )


def _flag_name(dest: str) -> str:
    if dest == "audit":
        return "--no-audit"
    return "--" + dest.replace("_", "-")


def active_waiver_flags(args: argparse.Namespace, flag_dests: list[str]) -> list[str]:
    flags: list[str] = []
    for dest in flag_dests:
        if not hasattr(args, dest):
            raise SystemExit(f"waiver-controlled flag destination {dest!r} is not defined on parsed args")
        value = getattr(args, dest)
        active = value is False if dest == "audit" else bool(value)
        if active:
            flags.append(_flag_name(dest))
    return flags


def require_waiver_reason(args: argparse.Namespace, flag_dests: list[str]) -> list[str]:
    flags = active_waiver_flags(args, flag_dests)
    if flags and not str(getattr(args, "waiver_reason", "")).strip():
        raise SystemExit("--waiver-reason is required when using " + ", ".join(flags))
    return flags


def waiver_audit_fields(args: argparse.Namespace, flag_dests: list[str]) -> dict[str, Any]:
    flags = active_waiver_flags(args, flag_dests)
    return {
        "waiver_required": bool(flags),
        "waiver_flags": flags,
        "waiver_reason": str(getattr(args, "waiver_reason", "")).strip() or None,
    }
