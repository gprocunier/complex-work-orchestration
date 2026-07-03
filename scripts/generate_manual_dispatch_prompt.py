#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from cwo_core.packets import fenced_block, redact_text, require_valid_contractor_packet
from cwo_core.routing import classify_work
from cwo_core.util import read_text_arg


RETURN_TEMPLATE_SECTIONS = [
    "Status",
    "Contractor job description",
    "Summary",
    "Files changed",
    "Commands run",
    "Boundary violation",
    "Patch authorization",
    "Secret or personal-data spill",
    "Scope compliance",
    "Validation result",
    "Provider policy limitations",
    "Evidence",
    "Evidence provenance",
    "Attestation or reproducibility note",
    "Share-boundary conformance",
    "Peer-review disposition",
    "Alternatives considered",
    "Confidence",
    "Risks or gaps",
    "Recommended next bead",
    "Escalation needed",
]


def contractor_return_template(required_sections: list[str] | None = None) -> str:
    ordered: list[str] = []
    for section in RETURN_TEMPLATE_SECTIONS + list(required_sections or []):
        if section not in ordered:
            ordered.append(section)
    return "\n".join(f"{section}:" for section in ordered)


def manual_command_for_route(route: dict[str, object]) -> str:
    selected = route.get("selected_executor", {})
    if not isinstance(selected, dict):
        return ""
    transport = selected.get("transport", {})
    if not isinstance(transport, dict):
        return ""
    command = str(transport.get("default_command", "")).strip()
    if selected.get("key") == "claude_opus_4_6_architecture_critic":
        effort = str(route.get("claude_architecture_effort") or transport.get("minimum_effort") or "high")
        command = command.replace("--effort high", f"--effort {effort}")
    return command


def architecture_critic_contract_lines(route: dict[str, object]) -> str:
    contracts = route.get("architecture_critic_contracts", [])
    if not isinstance(contracts, list) or not contracts:
        return "- none"
    lines: list[str] = []
    for contract in contracts:
        if not isinstance(contract, dict):
            continue
        command = contract.get("manual_command") or "manual dispatch command not recorded"
        lines.append(f"- {contract.get('display_name', contract.get('executor'))}: {command}")
    return "\n".join(lines) if lines else "- none"


def render_prompt(task: str, route: dict[str, object]) -> str:
    expert_lines = "\n".join(
        f"- {expert['display_name']} ({expert['job_description_label']})"
        for expert in route.get("ranked_experts", [])[:3]  # type: ignore[index]
    )
    manual_command = manual_command_for_route(route)
    command_line = f"Manual dispatch command: {manual_command}\n" if manual_command else ""
    return f"""You are an outside model contractor for one bounded Beads assignment.

Executor: {route['recommended_executor']}
Provider: {route.get('selected_executor', {}).get('provider_key')}
Route: {route['route']}
Share boundary: {route['share_boundary']}
Provider conflict domains: {', '.join(route.get('provider_conflict_domains', [])) or 'none'}
Peer review required: {route.get('peer_review_required')}
Data sensitivity: {route['data_sensitivity']}
Dispatch sensitivity: {route['dispatch_sensitivity']}
{command_line}Architecture critic contracts:
{architecture_critic_contract_lines(route)}

Assignment:
{task}

Required expert lenses:
{expert_lines}

CONTRACTOR RETURN TEMPLATE - COPY EXACTLY:
Output only the contractor return below. Do not include a preamble, internal action narration, hidden chain-of-thought, or step-by-step planning.

{contractor_return_template()}

Rules:
- Work only this assignment.
- Do not ask for or expose secrets, credentials, production access, or private data.
- Do not request broader disclosure than the assigned share boundary.
- Do not re-plan the whole project.
- Do not publish, release, tag, or run destructive commands.
- If the share boundary is patch-branch, return a diff, patch proposal, or branch reference by default. Do not mutate the active checkout unless direct workspace mutation is explicitly authorized.
- If peer review is required or provider conflict domains are listed, do not claim peer review is unnecessary.
- For research-style claims, add optional Research evidence, Research contradictions, and Research reflection sections with source locators, citation spans or short excerpts, reliability/relevance scores, support type, access status, contradiction handling, and replan notes.
- Return conclusions, evidence, alternatives considered, confidence, risks or gaps, and recommended next Beads.
- Your output will be scored by an evaluator and adjudicated by the architect before implementation.
"""


def render_packet_prompt(packet: dict[str, Any]) -> str:
    included_lines = "\n".join(
        f"- {item.get('type')}: {item.get('path', 'assignment')} sha256={item.get('sha256', 'n/a')}"
        for item in packet.get("included_artifacts", [])
    )
    required_return_sections = list(packet.get("required_return_sections", []))
    required_sections = "\n".join(f"- {section}" for section in required_return_sections)
    snippets = []
    for item in packet.get("selected_snippets", []):
        snippets.append(f"### {item.get('path')}\n\n{fenced_block(item.get('content', ''), 'text')}")
    snippet_text = "\n\n".join(snippets) if snippets else "No file snippets were included."
    profile = packet.get("expert_profile") or {}
    if profile:
        profile_text = f"""Distinguished Engineer calibration profile:
Path: {profile.get('path')}
SHA-256: {profile.get('sha256')}

{fenced_block(profile.get('content', ''), 'markdown')}"""
    else:
        justification = packet.get("degraded_context_justification", "")
        profile_text = f"""Distinguished Engineer calibration profile: not included. Treat this as degraded context and say so in the return.

Degraded-context justification:
{justification}"""
    manual_command = packet.get("manual_command")
    command_line = f"Manual dispatch command: {manual_command}\n" if manual_command else ""
    return f"""You are an outside model contractor for one bounded Beads assignment.

Dispatch ID: {packet['dispatch_id']}
Executor: {packet['executor']}
Provider: {packet.get('provider_key')} ({packet.get('provider_trust_tier')})
Assigned bead: {packet['bead_id']}
Job-description label: {packet['job_description_label']}
Share boundary: {packet['share_boundary']}
Disclosure stage: {packet.get('disclosure_stage')}
Packet SHA-256: {packet.get('packet_sha256', 'not-recorded')}
{command_line}

Boundary:
{packet.get('boundary_description', 'No boundary description provided.')}

Bead summary:
{fenced_block(json.dumps(packet.get('bead_summary', {}), indent=2, sort_keys=True), 'json')}

Included artifacts:
{included_lines or '- assignment summary only'}

Selected snippets:
{snippet_text}

{profile_text}

Required return sections:
{required_sections}

CONTRACTOR RETURN TEMPLATE - COPY EXACTLY:
Output only the contractor return below. Do not include a preamble, internal action narration, hidden chain-of-thought, or step-by-step planning.

{contractor_return_template(required_return_sections)}

Rules:
- Use the Distinguished Engineer calibration profile as your operating lens.
- Do not return generic review output. Stay inside the assigned job-description label and the assigned Bead.
- Work only this assignment.
- Do not ask for or expose secrets, credentials, production access, or private data.
- Do not request broader disclosure than the assigned share boundary.
- Do not re-plan the whole project.
- Do not publish, release, tag, or run destructive commands.
- If the share boundary is patch-branch, return a diff, patch proposal, or branch reference by default. Do not mutate the active checkout unless direct workspace mutation is explicitly authorized in the assignment.
- If peer review is required or provider conflict domains are listed, do not claim peer review is unnecessary.
- For research-style claims, add optional Research evidence, Research contradictions, and Research reflection sections with source locators, citation spans or short excerpts, reliability/relevance scores, support type, access status, contradiction handling, and replan notes.
- Return conclusions, evidence, alternatives considered, confidence, risks or gaps, and recommended next Beads.
- Your output will be scored by an evaluator and adjudicated by the architect before implementation.
"""


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate a copy-paste prompt for manual UI dispatch.")
    parser.add_argument("text", nargs="*")
    parser.add_argument("--file")
    parser.add_argument("--packet", help="Boundary-gated contractor packet JSON to render.")
    parser.add_argument(
        "--allow-degraded-packet",
        action="store_true",
        help="Allow rendering a valid packet that omits the expert profile after validation.",
    )
    parser.add_argument(
        "--allow-raw-manual-prompt",
        action="store_true",
        help="Operator-only degraded path: render an external manual prompt without a validated packet.",
    )
    parser.add_argument(
        "--rehearsal",
        action="store_true",
        help="Permit degraded prompt rendering only as a local rehearsal; do not use as production dispatch evidence.",
    )
    parser.add_argument("--external-ok", action="store_true")
    parser.add_argument(
        "--allow-disclosure-escalation",
        action="store_true",
        help="Explicitly approve repo-readonly or patch-branch disclosure routing.",
    )
    parser.add_argument("--local-ok", action="store_true", help="Permit low-risk local worker dispatch.")
    parser.add_argument("--prefer-local", action="store_true", help="Prefer local worker routing when policy permits it.")
    parser.add_argument("--share-boundary", default="redacted-packet")
    parser.add_argument("--requested-role", action="append", default=[])
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    if args.packet:
        packet = json.loads(Path(args.packet).read_text(encoding="utf-8"))
        require_valid_contractor_packet(packet, allow_degraded_packet=args.allow_degraded_packet)
        prompt = render_packet_prompt(packet)
        if args.json:
            print(json.dumps({"packet": packet, "prompt": prompt}, indent=2, sort_keys=True))
        else:
            print(prompt)
        return

    task = read_text_arg(" ".join(args.text).strip() or None, args.file)
    route = classify_work(
        task,
        external_ok=args.external_ok,
        allow_disclosure_escalation=args.allow_disclosure_escalation,
        local_ok=args.local_ok,
        prefer_local=args.prefer_local,
        share_boundary=args.share_boundary,
        requested_roles=args.requested_role,
    )
    if route.get("route") == "external-contract" and not args.allow_raw_manual_prompt:
        raise SystemExit(
            "external manual prompts require --packet; pass --allow-raw-manual-prompt only for an operator-only degraded dispatch"
        )
    if route.get("route") == "external-contract" and args.allow_raw_manual_prompt and not args.rehearsal:
        raise SystemExit("--allow-raw-manual-prompt requires --rehearsal and must not be used as production dispatch evidence")
    prompt = render_prompt(redact_text(task) if args.allow_raw_manual_prompt else task, route)
    if args.json:
        print(json.dumps({"route": route, "prompt": prompt}, indent=2, sort_keys=True))
    else:
        print(prompt)


if __name__ == "__main__":
    main()
