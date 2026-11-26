#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json

from cwo_core.coach import coach_orchestration_prompt
from cwo_core.errors import CWOError
from cwo_core.risk_features import add_risk_narrowing_arguments, refuse_risk_narrowing_arguments
from cwo_core.util import read_text_segments
from cwo_core.waivers import add_waiver_reason_argument, require_waiver_reason

from routing_cli_options import (
    add_beads_context_depth_argument,
    add_operative_route_arguments,
    add_route_access_arguments,
    add_route_selection_arguments,
    routing_options,
)


def print_execution_availability(result: dict[str, object], *, prefix: str) -> None:
    """Dispatch availability after every gate, native containment included, with the reasons it is denied."""
    availability = result.get("execution_availability")
    if not isinstance(availability, dict):
        print(f"{prefix}Model dispatch available: unknown (no execution availability recorded)")
        return
    available = availability.get("dispatch_authorized") is True
    print(f"{prefix}Model dispatch available: {'yes' if available else 'no'}")
    if not available:
        stops = [str(stop) for stop in availability.get("stops") or []]
        print(f"{prefix}Dispatch denied by: {', '.join(stops) or 'no authorized operative route'}")


def print_human(result: dict[str, object]) -> None:
    print(f"Recommended orchestration: {result['recommended_orchestration_level']}")
    print(f"Beads tracking required: {result['beads_tracking_required']}")

    operative = result.get("operative_route") if isinstance(result.get("operative_route"), dict) else {}
    if operative:
        print("\nOperative route:")
        print(f"- Primary model: {operative.get('primary_model')}")
        print(f"- Spark availability: {operative.get('availability_status')}")
        print(f"- Selected model: {operative.get('selected_model') or 'none'}")
        print(f"- Selection source: {operative.get('selection_source') or 'none'}")
        print_execution_availability(result, prefix="- ")
        if operative.get("stop_reason"):
            print(f"- Stop reason: {operative.get('stop_reason')}")
        fallback = operative.get("fallback") if isinstance(operative.get("fallback"), dict) else {}
        if fallback.get("decision_required"):
            print(f"- Recommended fallback: {fallback.get('recommended_model') or 'Wait for Spark'}")
            print(f"- Recommendation reason: {fallback.get('recommendation_reason')}")
            for candidate in fallback.get("candidates", []):
                state = "eligible" if candidate.get("eligible") else "excluded"
                reasons = candidate.get("inclusion_reasons") if candidate.get("eligible") else candidate.get("exclusion_reasons")
                print(f"  - {candidate.get('model')}: {state}; {', '.join(str(item) for item in reasons or [])}")

    print("\nRationale:")
    for item in result.get("rationale", []):  # type: ignore[assignment]
        print(f"- {item}")

    warnings = result.get("warnings") or []
    if warnings:
        print("\nWarnings:")
        for item in warnings:  # type: ignore[assignment]
            print(f"- {item}")

    availability = result.get("execution_availability")
    if isinstance(availability, dict) and availability.get("summary"):
        print("\nExecution availability (separate from the planning recommendation):")
        print(f"- {availability['summary']}")

    questions = result.get("missing_questions") or []
    print("\nMissing questions:")
    if questions:
        for item in questions:  # type: ignore[assignment]
            print(f"- {item.get('question')} Default: {item.get('default')}")
    else:
        print("- none")

    interactive_questions = result.get("interactive_questions") or []
    if interactive_questions:
        print("\nInteractive choices:")
        for item in interactive_questions:  # type: ignore[assignment]
            print(f"- {item.get('question')}")
            for option in item.get("options", []):
                print(f"  - {option.get('label')}: {option.get('description')}")

    print("\nEnabled levers:")
    for item in result.get("enabled_levers", []):  # type: ignore[assignment]
        print(f"- {item}")

    print("\nDisabled levers:")
    for item in result.get("disabled_levers", []):  # type: ignore[assignment]
        print(f"- {item}")

    print("\nRecommended launch prompt:")
    print(result["paste_ready_prompt"])


def print_brief(result: dict[str, object]) -> None:
    route = result.get("route") if isinstance(result.get("route"), dict) else {}
    selected = route.get("selected_executor") if isinstance(route, dict) else {}
    executor = selected.get("key") if isinstance(selected, dict) else route.get("recommended_executor")
    print(f"Recommended orchestration: {result['recommended_orchestration_level']}")
    print(f"Route: {route.get('route')}")
    print(f"Task class: {route.get('task_class')}")
    print(f"Risk: {route.get('risk_level')}")
    print(f"Sensitivity: {route.get('data_sensitivity')}")
    print(f"Sensitivity source: {route.get('data_sensitivity_source')}")
    print(f"Executor: {executor}")
    operative = result.get("operative_route") if isinstance(result.get("operative_route"), dict) else {}
    print(f"Operative primary: {operative.get('primary_model')}")
    print(f"Spark availability: {operative.get('availability_status')}")
    print(f"Operative selected model: {operative.get('selected_model') or 'none'}")
    print_execution_availability(result, prefix="")
    fallback = operative.get("fallback") if isinstance(operative.get("fallback"), dict) else {}
    if fallback.get("decision_required"):
        print(f"Recommended fallback: {fallback.get('recommended_model') or 'Wait for Spark'}")
    print(f"Beads context depth: {result.get('beads_context_depth')}")
    print(
        "Execution gate: "
        + (
            "present coach options and wait before plan creation"
            if result.get("requires_user_selection_before_plan")
            else "conservative defaults allowed unless the user explicitly asked for coach options"
        )
    )
    if result.get("selection_before_plan_reason"):
        print(f"Gate reason: {result.get('selection_before_plan_reason')}")
    interactive_questions = result.get("interactive_questions") or []
    if interactive_questions:
        print("Coach options:")
        for item in interactive_questions:  # type: ignore[assignment]
            print(f"- {item.get('question')}")
            for option in item.get("options", []):
                print(f"  - {option.get('label')}: {option.get('description')}")
    warnings = result.get("warnings") or []
    if warnings:
        print("Warnings:")
        for item in warnings:  # type: ignore[assignment]
            print(f"- {item}")


def main() -> None:
    from model_catalog_startup import configure_cli_model_catalog

    parser = argparse.ArgumentParser(
        description="Compile a right-sized prompt for complex-work-orchestration before launching the harness."
    )
    parser.add_argument("text", nargs="*", help="Task text to coach.")
    parser.add_argument("--file", help="Read task text from a file.")
    parser.add_argument("--external-ok", action="store_true", help="User has opted in to third-party contracting.")
    parser.add_argument(
        "--allow-disclosure-escalation",
        action="store_true",
        help="Explicitly approve repo-readonly or patch-branch disclosure routing.",
    )
    add_route_access_arguments(parser)
    parser.add_argument("--requested-role", action="append", default=[], help="Explicit expert role requested by the user.")
    parser.add_argument("--file-path", action="append", default=[], help="Relevant repository path for path-pattern scoring.")
    parser.add_argument("--stage", help="Review stage such as pre-implementation, implementation-review, or pre-release.")
    parser.add_argument("--unattended", action="store_true", help="Penalize manual dispatch executors.")
    add_route_selection_arguments(parser)
    parser.add_argument(
        "--scaffold-size",
        choices=["full", "tight"],
        help="Record an accepted graph-size choice for the coached launch prompt.",
    )
    add_beads_context_depth_argument(parser)
    parser.add_argument("--json", action="store_true", help="Print machine-readable JSON.")
    add_operative_route_arguments(parser)
    parser.add_argument("--brief", action="store_true", help="Print a compact human summary instead of the launch prompt.")
    add_waiver_reason_argument(parser)
    parser.add_argument("--current-authority", help="Trusted task-fit and allocation evidence JSON for current routing.")
    add_risk_narrowing_arguments(parser)
    args = parser.parse_args()
    refuse_risk_narrowing_arguments(args, source="coach_prompt.py")
    require_waiver_reason(args, ["allow_disclosure_escalation"])
    configure_cli_model_catalog()

    text_segments = read_text_segments(" ".join(args.text).strip() or None, args.file)
    text = "\n\n".join(text_segments)
    try:
        result = coach_orchestration_prompt(
            text,
            text_segments=text_segments,
            file_paths=args.file_path,
            stage=args.stage,
            unattended=args.unattended,
            scaffold_size=args.scaffold_size,
            **routing_options(args),
        )
    except CWOError as exc:
        raise SystemExit(str(exc))
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    elif args.brief:
        print_brief(result)
    else:
        print_human(result)


if __name__ == "__main__":
    main()
