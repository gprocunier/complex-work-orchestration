#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json

from cwo_core.coach import coach_orchestration_prompt
from cwo_core.util import read_text_arg
from cwo_core.waivers import add_waiver_reason_argument, require_waiver_reason


def print_human(result: dict[str, object]) -> None:
    print(f"Recommended orchestration: {result['recommended_orchestration_level']}")
    print(f"Beads tracking required: {result['beads_tracking_required']}")

    print("\nRationale:")
    for item in result.get("rationale", []):  # type: ignore[assignment]
        print(f"- {item}")

    warnings = result.get("warnings") or []
    if warnings:
        print("\nWarnings:")
        for item in warnings:  # type: ignore[assignment]
            print(f"- {item}")

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
    print(f"Beads context depth: {result.get('beads_context_depth')}")
    warnings = result.get("warnings") or []
    if warnings:
        print("Warnings:")
        for item in warnings:  # type: ignore[assignment]
            print(f"- {item}")


def main() -> None:
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
    parser.add_argument("--local-ok", action="store_true", help="Permit low-risk local worker dispatch.")
    parser.add_argument("--prefer-local", action="store_true", help="Prefer local worker routing when policy permits it.")
    parser.add_argument("--local-profile", help="Require a named local executor profile, for example openshift-ai-vllm.")
    parser.add_argument("--share-boundary", default="no-outside-sharing")
    parser.add_argument(
        "--data-sensitivity",
        choices=["public", "redacted", "internal", "restricted"],
        help="Declare known input data sensitivity; overrides the advisory text heuristic.",
    )
    parser.add_argument("--requested-role", action="append", default=[], help="Explicit expert role requested by the user.")
    parser.add_argument("--file-path", action="append", default=[], help="Relevant repository path for path-pattern scoring.")
    parser.add_argument("--stage", help="Review stage such as pre-implementation, implementation-review, or pre-release.")
    parser.add_argument("--unattended", action="store_true", help="Penalize manual dispatch executors.")
    parser.add_argument(
        "--execution-environment",
        help="Select a CWO execution environment profile such as connected-codex-glm-primary.",
    )
    parser.add_argument(
        "--model-synthesis",
        action="store_true",
        help="Treat model synthesis as accepted opt-in and activate the CWO-native synthesis lane.",
    )
    parser.add_argument(
        "--scaffold-size",
        choices=["full", "tight"],
        help="Record an accepted graph-size choice for the coached launch prompt.",
    )
    parser.add_argument(
        "--beads-context-depth",
        choices=["none", "summary", "focused", "heavy", "audit"],
        help="Override the autosized Beads context depth for internal Codex/subagent briefing.",
    )
    parser.add_argument("--json", action="store_true", help="Print machine-readable JSON.")
    parser.add_argument("--brief", action="store_true", help="Print a compact human summary instead of the launch prompt.")
    add_waiver_reason_argument(parser)
    args = parser.parse_args()
    require_waiver_reason(args, ["allow_disclosure_escalation"])

    text = read_text_arg(" ".join(args.text).strip() or None, args.file)
    result = coach_orchestration_prompt(
        text,
        external_ok=args.external_ok,
        allow_disclosure_escalation=args.allow_disclosure_escalation,
        local_ok=args.local_ok,
        prefer_local=args.prefer_local,
        local_profile=args.local_profile,
        share_boundary=args.share_boundary,
        data_sensitivity=args.data_sensitivity,
        requested_roles=args.requested_role,
        file_paths=args.file_path,
        stage=args.stage,
        unattended=args.unattended,
        execution_environment=args.execution_environment,
        model_synthesis=args.model_synthesis,
        scaffold_size=args.scaffold_size,
        beads_context_depth=args.beads_context_depth,
    )
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    elif args.brief:
        print_brief(result)
    else:
        print_human(result)


if __name__ == "__main__":
    main()
