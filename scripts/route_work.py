#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

from cwo_core.routing import current_authority_file_arguments

from cwo_core.errors import CWOError
from cwo_core.routing import classify_work
from cwo_core.util import read_text_arg
from cwo_core.waivers import add_waiver_reason_argument, require_waiver_reason


def _load_optional_json(path: str | None) -> dict[str, object] | None:
    if not path:
        return None
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise SystemExit(f"{path} must contain a JSON object")
    return value


def print_human(route: dict[str, object], top_n: int) -> None:
    print(f"Route: {route['route']}")
    print(f"Task class: {route['task_class']}")
    print(f"Risk: {route['risk_level']}")
    print(f"Data sensitivity: {route['data_sensitivity']}")
    print(f"Data sensitivity source: {route.get('data_sensitivity_source')}")
    print(f"Data sensitivity heuristic: {route.get('data_sensitivity_heuristic')}")
    print(f"Dispatch sensitivity: {route['dispatch_sensitivity']}")
    print(f"Share boundary: {route['share_boundary']}")
    print(f"Execution environment: {route.get('execution_environment')}")
    if route.get("project_manager_executor"):
        print(f"Project manager executor: {route.get('project_manager_executor')}")
    if route.get("primary_architect_executor"):
        print(f"Primary architect executor: {route.get('primary_architect_executor')}")
    if route.get("architecture_counter_review_executor"):
        print(f"Architecture counter-review executor: {route.get('architecture_counter_review_executor')}")
    print(f"Recommended executor: {route['recommended_executor']}")
    print(f"Provider conflict detected: {route.get('provider_conflict_detected')}")
    conflicts = route.get("provider_conflict_domains") or []
    if conflicts:
        print(f"Provider conflict domains: {', '.join(str(item) for item in conflicts)}")
    print(f"Peer review required: {route.get('peer_review_required')}")
    print(f"Peer review count: {route.get('peer_review_count')}")
    synthesis = route.get("model_synthesis") if isinstance(route.get("model_synthesis"), dict) else {}
    if synthesis:
        print(f"Model synthesis: {synthesis.get('recommended_mode')} active={synthesis.get('active')}")
        if synthesis.get("provider_conflict_flags"):
            print(f"Model synthesis provider flags: {len(synthesis.get('provider_conflict_flags', []))}")
    print(f"Zero-trust consensus required: {route.get('zero_trust_consensus_required')}")
    if route.get("zero_trust_consensus_required"):
        print(f"Zero-trust minimum domains: {route.get('zero_trust_minimum_independent_domains')}")
        for reason in route.get("zero_trust_consensus_trigger_reasons", []):  # type: ignore[assignment]
            print(f"- zero-trust trigger: {reason}")
    print(f"Beads context depth: {route.get('beads_context_depth')}")
    print(f"Beads context source: {route.get('beads_context_depth_source')}")
    print(f"External contract allowed: {route['external_contract_allowed']}")
    print(f"Local worker allowed: {route['local_worker_allowed']}")
    print(f"Prefer local worker: {route['prefer_local_worker']}")
    if route.get("local_profile"):
        print(f"Local profile: {route['local_profile']}")
    if route.get("requested_architecture_critic_executors"):
        print(
            "Requested architecture critics: "
            + ", ".join(str(item) for item in route.get("requested_architecture_critic_executors", []))
        )
        print(f"Architecture review complexity: {route.get('architecture_review_complexity')}")
        print(f"Claude architecture effort: {route.get('claude_architecture_effort')}")
    print(f"Has external expert contracts: {route.get('has_external_expert_contracts')}")
    print(f"Has local worker contracts: {route.get('has_local_worker_contracts')}")
    print(f"Editor gate required: {route.get('editor_gate_required')}")
    if route.get("editor_gate_experts"):
        print(f"Editor gate experts: {', '.join(str(item) for item in route.get('editor_gate_experts', []))}")
    print(f"Evaluator required: {route['evaluator_required']}")
    print(f"Architect adjudication required: {route['architect_adjudication_required']}")

    operative = route.get("operative_route") if isinstance(route.get("operative_route"), dict) else {}
    if operative:
        print("\nOperative route:")
        print(f"- Primary model: {operative.get('primary_model')}")
        print(f"- Spark availability: {operative.get('availability_status')}")
        print(f"- Selected model: {operative.get('selected_model') or 'none'}")
        print(f"- Selection source: {operative.get('selection_source') or 'none'}")
        print(f"- Dispatch authorized: {operative.get('dispatch_authorized')}")
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
            print("- Explicit fallback choice required:")
            for option in fallback.get("options", []):
                print(f"  - {option.get('label')}: {option.get('description')}")

    critic = route.get("critic_route") if isinstance(route.get("critic_route"), dict) else {}
    peer = route.get("peer_review_route") if isinstance(route.get("peer_review_route"), dict) else {}
    if critic:
        print(f"Critic route is evidence-only: {critic.get('evidence_only')}")
    if peer:
        print(f"Peer-review route is evidence-only: {peer.get('evidence_only')}")

    mixed_summary = [
        ("External experts", route.get("external_experts") or []),
        ("Local worker experts", route.get("local_worker_experts") or []),
        ("Internal experts", route.get("internal_experts") or []),
        ("Acceptance required experts", route.get("acceptance_required_experts") or []),
    ]
    for title, experts in mixed_summary:
        if experts:
            print(f"{title}: {', '.join(str(item) for item in experts)}")

    hard_stops = route.get("hard_stops") or []
    if hard_stops:
        print("\nHard stops:")
        for stop in hard_stops:  # type: ignore[assignment]
            print(f"- {stop}")

    critic_contracts = route.get("architecture_critic_contracts") or []
    if critic_contracts:
        print("\nArchitecture critic contracts:")
        for contract in critic_contracts:  # type: ignore[assignment]
            print(
                f"- {contract.get('executor')} provider={contract.get('provider_key')} "
                f"command={contract.get('manual_command', 'manual dispatch')}"
            )

    print("\nRanked experts:")
    for expert in route.get("ranked_experts", [])[:top_n]:  # type: ignore[index]
        selected = expert.get("selected_executor", {})
        executor = expert.get("recommended_executor") or selected.get("key") or "unknown"
        external = selected.get("external")
        violations = "; ".join(expert.get("executor_policy_violations", [])) or "none"
        print(
            f"- {expert['name']} score={expert['score']} label={expert['job_description_label']} "
            f"executor={executor} external={external} provider={selected.get('provider_key')} violations={violations}"
        )

    print("\nRanked executors:")
    for executor in route.get("ranked_executors", [])[:top_n]:  # type: ignore[index]
        violations = "; ".join(executor.get("policy_violations", [])) or "none"
        print(
            f"- {executor['key']} score={executor['score']} mode={executor['dispatch_mode']} "
            f"provider={executor.get('provider_key')} violations={violations}"
        )

    labels = route.get("guard_labels", [])
    if labels:
        print("\nContract labels:")
        print(",".join(labels))  # type: ignore[arg-type]


def main() -> None:
    parser = argparse.ArgumentParser(description="Classify work against orchestration policy and rank experts/executors.")
    parser.add_argument("text", nargs="*", help="Task text to classify.")
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
        "--beads-context-depth",
        choices=["none", "summary", "focused", "heavy", "audit"],
        help="Override the autosized Beads context depth for internal Codex/subagent briefing.",
    )
    parser.add_argument("--top-n", type=int, default=5)
    parser.add_argument("--operative-capabilities", help="Trusted live operative capability evidence JSON.")
    parser.add_argument("--operative-work-estimate", help="Validated native work-estimate v2 JSON.")
    parser.add_argument("--operative-fallback-fit", help="Strict hash-bound fallback-fitness evidence JSON.")
    parser.add_argument("--fallback-selection", help="Explicit user fallback selection JSON.")
    parser.add_argument("--operative-context", help="Current Bead/wave/fresh-segment context JSON.")
    parser.add_argument("--aggregate-budget", help="Original aggregate budget JSON; never reset on fallback.")
    parser.add_argument("--operative-evaluated-at", help="ISO-8601 routing evaluation time for deterministic automation.")
    parser.add_argument("--json", action="store_true", help="Print machine-readable JSON.")
    add_waiver_reason_argument(parser)
    parser.add_argument("--current-authority", help="Current v3 routing evidence JSON; not a dispatch grant.")
    args = parser.parse_args()
    require_waiver_reason(args, ["allow_disclosure_escalation"])

    text = read_text_arg(" ".join(args.text).strip() or None, args.file)
    try:
        route = classify_work(
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
            beads_context_depth=args.beads_context_depth,
            operative_capabilities=_load_optional_json(args.operative_capabilities),
            operative_work_estimate=_load_optional_json(args.operative_work_estimate),
            operative_fallback_fit=_load_optional_json(args.operative_fallback_fit),
            fallback_selection=_load_optional_json(args.fallback_selection),
            operative_context=_load_optional_json(args.operative_context),
            aggregate_budget=_load_optional_json(args.aggregate_budget),
            operative_evaluated_at=args.operative_evaluated_at,
            **current_authority_file_arguments(args.current_authority),
        )
    except CWOError as exc:
        raise SystemExit(str(exc))
    if args.json:
        print(json.dumps(route, indent=2, sort_keys=True))
    else:
        print_human(route, args.top_n)


if __name__ == "__main__":
    main()
