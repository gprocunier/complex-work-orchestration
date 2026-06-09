#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json

from orchestration_lib import classify_work, read_text_arg


def print_human(route: dict[str, object], top_n: int) -> None:
    print(f"Route: {route['route']}")
    print(f"Task class: {route['task_class']}")
    print(f"Risk: {route['risk_level']}")
    print(f"Data sensitivity: {route['data_sensitivity']}")
    print(f"Dispatch sensitivity: {route['dispatch_sensitivity']}")
    print(f"Share boundary: {route['share_boundary']}")
    print(f"Recommended executor: {route['recommended_executor']}")
    print(f"External contract allowed: {route['external_contract_allowed']}")
    print(f"Local worker allowed: {route['local_worker_allowed']}")
    print(f"Prefer local worker: {route['prefer_local_worker']}")
    print(f"Evaluator required: {route['evaluator_required']}")
    print(f"Architect adjudication required: {route['architect_adjudication_required']}")

    hard_stops = route.get("hard_stops") or []
    if hard_stops:
        print("\nHard stops:")
        for stop in hard_stops:  # type: ignore[assignment]
            print(f"- {stop}")

    print("\nRanked experts:")
    for expert in route.get("ranked_experts", [])[:top_n]:  # type: ignore[index]
        selected = expert.get("selected_executor", {})
        executor = expert.get("recommended_executor") or selected.get("key") or "unknown"
        external = selected.get("external")
        violations = "; ".join(expert.get("executor_policy_violations", [])) or "none"
        print(
            f"- {expert['name']} score={expert['score']} label={expert['job_description_label']} "
            f"executor={executor} external={external} violations={violations}"
        )

    print("\nRanked executors:")
    for executor in route.get("ranked_executors", [])[:top_n]:  # type: ignore[index]
        violations = "; ".join(executor.get("policy_violations", [])) or "none"
        print(f"- {executor['key']} score={executor['score']} mode={executor['dispatch_mode']} violations={violations}")

    labels = route.get("guard_labels", [])
    if labels:
        print("\nContract labels:")
        print(",".join(labels))  # type: ignore[arg-type]


def main() -> None:
    parser = argparse.ArgumentParser(description="Classify work against orchestration policy and rank experts/executors.")
    parser.add_argument("text", nargs="*", help="Task text to classify.")
    parser.add_argument("--file", help="Read task text from a file.")
    parser.add_argument("--external-ok", action="store_true", help="User has opted in to third-party contracting.")
    parser.add_argument("--local-ok", action="store_true", help="Permit low-risk local worker dispatch.")
    parser.add_argument("--prefer-local", action="store_true", help="Prefer local worker routing when policy permits it.")
    parser.add_argument("--share-boundary", default="no-outside-sharing")
    parser.add_argument("--requested-role", action="append", default=[], help="Explicit expert role requested by the user.")
    parser.add_argument("--file-path", action="append", default=[], help="Relevant repository path for path-pattern scoring.")
    parser.add_argument("--stage", help="Review stage such as pre-implementation, implementation-review, or pre-release.")
    parser.add_argument("--unattended", action="store_true", help="Penalize manual dispatch executors.")
    parser.add_argument("--top-n", type=int, default=5)
    parser.add_argument("--json", action="store_true", help="Print machine-readable JSON.")
    args = parser.parse_args()

    text = read_text_arg(" ".join(args.text).strip() or None, args.file)
    route = classify_work(
        text,
        external_ok=args.external_ok,
        local_ok=args.local_ok,
        prefer_local=args.prefer_local,
        share_boundary=args.share_boundary,
        requested_roles=args.requested_role,
        file_paths=args.file_path,
        stage=args.stage,
        unattended=args.unattended,
    )
    if args.json:
        print(json.dumps(route, indent=2, sort_keys=True))
    else:
        print_human(route, args.top_n)


if __name__ == "__main__":
    main()
