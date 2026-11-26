"""Argument groups shared by the route, prompt coach, and scaffold commands."""

from __future__ import annotations

import argparse
from typing import Any

from cwo_core.routing import current_authority_file_arguments
from cwo_core.util import load_optional_json


def add_route_access_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--local-ok", action="store_true", help="Permit low-risk local worker dispatch.")
    parser.add_argument("--prefer-local", action="store_true", help="Prefer local worker routing when policy permits it.")
    parser.add_argument("--local-profile", help="Require a named local executor profile, for example openshift-ai-vllm.")
    parser.add_argument("--share-boundary", default="no-outside-sharing")
    parser.add_argument(
        "--data-sensitivity",
        choices=["public", "redacted", "internal", "restricted"],
        help="Declare known input data sensitivity; overrides the advisory text heuristic.",
    )


def add_route_selection_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--execution-environment",
        help="Select a CWO execution environment profile such as connected-codex-glm-primary.",
    )
    parser.add_argument(
        "--model-synthesis",
        action="store_true",
        help="Treat model synthesis as accepted opt-in and activate the CWO-native synthesis lane.",
    )


def add_beads_context_depth_argument(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--beads-context-depth",
        choices=["none", "summary", "focused", "heavy", "audit"],
        help="Override the autosized Beads context depth for internal Codex/subagent briefing.",
    )


def add_operative_route_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--operative-capabilities", help="Trusted live operative capability evidence JSON.")
    parser.add_argument("--operative-work-estimate", help="Validated native work-estimate v2 JSON.")
    parser.add_argument("--operative-fallback-fit", help="Strict hash-bound fallback-fitness evidence JSON.")
    parser.add_argument("--fallback-selection", help="Explicit user fallback selection JSON.")
    parser.add_argument("--operative-context", help="Current Bead/wave/fresh-segment context JSON.")
    parser.add_argument("--aggregate-budget", help="Original aggregate budget JSON; never reset on fallback.")
    parser.add_argument("--operative-evaluated-at", help="ISO-8601 routing evaluation time for deterministic automation.")


def routing_options(args: argparse.Namespace) -> dict[str, Any]:
    return dict(
        external_ok=args.external_ok,
        allow_disclosure_escalation=args.allow_disclosure_escalation,
        local_ok=args.local_ok,
        prefer_local=args.prefer_local,
        local_profile=args.local_profile,
        share_boundary=args.share_boundary,
        data_sensitivity=args.data_sensitivity,
        requested_roles=args.requested_role,
        execution_environment=args.execution_environment,
        model_synthesis=args.model_synthesis,
        beads_context_depth=args.beads_context_depth,
        operative_capabilities=load_optional_json(args.operative_capabilities),
        operative_work_estimate=load_optional_json(args.operative_work_estimate),
        operative_fallback_fit=load_optional_json(args.operative_fallback_fit),
        fallback_selection=load_optional_json(args.fallback_selection),
        operative_context=load_optional_json(args.operative_context),
        aggregate_budget=load_optional_json(args.aggregate_budget),
        operative_evaluated_at=args.operative_evaluated_at,
        **current_authority_file_arguments(args.current_authority),
    )
