#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json

from orchestration_lib import classify_work, read_text_arg


def print_human(route: dict[str, object]) -> None:
    print(f"Route: {route['route']}")
    print(f"Task class: {route['task_class']}")
    print(f"Risk: {route['risk_level']}")
    print(f"Data sensitivity: {route['data_sensitivity']}")
    print(f"Share boundary: {route['share_boundary']}")
    print(f"Recommended executor: {route['recommended_executor']}")
    print(f"Architect review required: {route['architect_review_required']}")
    print(f"External contract allowed: {route['external_contract_allowed']}")

    experts = route.get("required_experts", [])
    if experts:
        print("\nRequired experts:")
        for expert in experts:  # type: ignore[assignment]
            print(
                "- {display_name} ({job_description_label}); matched: {terms}".format(
                    display_name=expert["display_name"],
                    job_description_label=expert["job_description_label"],
                    terms=", ".join(expert["matched_terms"]),
                )
            )
    else:
        print("\nRequired experts: none")

    labels = route.get("guard_labels", [])
    if labels:
        print("\nContract labels:")
        print(",".join(labels))  # type: ignore[arg-type]

    print("\nReasons:")
    for reason in route.get("reasons", []):  # type: ignore[assignment]
        print(f"- {reason}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Classify a work request against the orchestration policy.")
    parser.add_argument("text", nargs="*", help="Task text to classify.")
    parser.add_argument("--file", help="Read task text from a file.")
    parser.add_argument("--external-ok", action="store_true", help="User has opted in to third-party contracting.")
    parser.add_argument(
        "--share-boundary",
        default="no-outside-sharing",
        help="One of: no-outside-sharing, redacted-packet, repo-readonly, patch-branch.",
    )
    parser.add_argument("--json", action="store_true", help="Print machine-readable JSON.")
    args = parser.parse_args()

    text = read_text_arg(" ".join(args.text).strip() or None, args.file)
    route = classify_work(text, external_ok=args.external_ok, share_boundary=args.share_boundary)
    if args.json:
        print(json.dumps(route, indent=2, sort_keys=True))
    else:
        print_human(route)


if __name__ == "__main__":
    main()
