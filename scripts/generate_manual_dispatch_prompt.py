#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import Any

from routing_cli_options import (
    DISCLOSURE_ESCALATION_HELP, add_local_route_arguments, add_route_boundary_arguments, route_decision_options,
)
from cwo_core.routing import current_authority_file_arguments

from cwo_core.dispatch_workload import WorkloadRefused, read_export_workload, validate_export_workload
from cwo_core.errors import CWOError
from cwo_core.prepared_outbound import PreparedOutbound, PreparedSource
from cwo_core.outbound_screen import (
    ScreenedPayload, ScreeningArgumentParser, refuse_attachments, require_clean, require_text_disclosure, withheld_diagnostics,
)
from cwo_core.risk_features import add_risk_narrowing_arguments, refuse_risk_narrowing_arguments
from cwo_core.packet_provenance import label_rehearsal, rehearsal_result, require_packet_export_approval
from cwo_core.packets import fenced_block, redact_text
from cwo_core.policy import manual_dispatch_command
from cwo_core.routing import classify_work, experts_with_required
from cwo_core.waivers import add_waiver_reason_argument, require_waiver_reason


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
    return manual_dispatch_command(transport)


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
        for expert in experts_with_required(route, 3)  # type: ignore[arg-type]
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
    refuse_attachments(packet, surface="manual/browser packet")
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
    review_surface_contract = packet.get("review_surface_contract") if isinstance(packet.get("review_surface_contract"), dict) else {}
    if review_surface_contract:
        review_surface_text = f"""Review surface contract:
{fenced_block(json.dumps(review_surface_contract, indent=2, sort_keys=True), 'json')}
"""
    else:
        review_surface_text = """Review surface contract:
No explicit review-surface contract was included. Treat the packet as packet-only unless the assignment says otherwise.
"""
    return f"""You are an outside model contractor for one bounded Beads assignment.

Dispatch ID: {packet['dispatch_id']}
Executor: {packet['executor']}
Provider: {packet.get('provider_key')} ({packet.get('provider_trust_tier')})
Assigned bead: {packet['bead_id']}
Job-description label: {packet['job_description_label']}
Share boundary: {packet['share_boundary']}
Disclosure stage: {packet.get('disclosure_stage')}
Expected return language: {packet.get('expected_return_language', 'policy-default')}
Packet SHA-256: {packet.get('packet_sha256', 'not-recorded')}
{command_line}

Boundary:
{packet.get('boundary_description', 'No boundary description provided.')}

{review_surface_text}

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
- If PR, merge, readiness, source, or diff inspection is required but not included in this packet, do not return an unconditional GO. Return conditional GO based on packet evidence, open-risk, request broader review surface, or NO-GO.
- Do not publish, release, tag, or run destructive commands.
- If the share boundary is patch-branch, return a diff, patch proposal, or branch reference by default. Do not mutate the active checkout unless direct workspace mutation is explicitly authorized in the assignment.
- If peer review is required or provider conflict domains are listed, do not claim peer review is unnecessary.
- For research-style claims, add optional Research evidence, Research contradictions, and Research reflection sections with source locators, citation spans or short excerpts, reliability/relevance scores, support type, access status, contradiction handling, and replan notes.
- Return conclusions, evidence, alternatives considered, confidence, risks or gaps, and recommended next Beads.
- Your output will be scored by an evaluator and adjudicated by the architect before implementation.
"""


def read_input_file(path: str, label: str, *, captures: list | None = None) -> str:
    """Read a file named on the command line. The path is caller input that no screen has
    seen, so an error names it only by digest and does not chain the original exception."""
    try:
        raw = Path(path).read_bytes()
        text = raw.decode("utf-8").replace("\r\n", "\n").replace("\r", "\n")
        if captures is not None:
            captures.append((str(Path(path).absolute()), raw))
        return text
    except (OSError, UnicodeError) as exc:
        digest = hashlib.sha256(str(path).encode("utf-8", errors="surrogatepass")).hexdigest()[:12]
        reason = exc.strerror if isinstance(exc, OSError) and exc.strerror else type(exc).__name__
        raise SystemExit(f"cannot read the {label} (path sha256 {digest}): {reason}") from None


def load_packet_file(path: str, *, captures: list | None = None) -> dict[str, Any]:
    """The contractor packet in ``path``; unreadable or malformed files refuse with digest-only diagnostics."""
    text = read_input_file(path, "packet file", captures=captures)
    try:
        packet = json.loads(text)
    except (ValueError, RecursionError) as exc:
        digest = hashlib.sha256(str(path).encode("utf-8", errors="surrogatepass")).hexdigest()[:12]
        where = f"line {exc.lineno} column {exc.colno}" if isinstance(exc, json.JSONDecodeError) else type(exc).__name__
        raise SystemExit(f"the packet file is not valid JSON (path sha256 {digest}): {where}") from None
    if not isinstance(packet, dict):
        raise SystemExit("the packet file must hold a JSON object")
    return packet


def read_task_segments(text: str | None, file_path: str | None, *, captures: list | None = None) -> list[str]:
    """The task text and the --file contents appended to it, as separate segments in order, read with
    digest-only file errors. Routing assesses each segment and the append history, not only the joined text."""
    parts = [text] if text else []
    if file_path:
        parts.append(read_input_file(file_path, "task file", captures=captures))
    if not parts:
        raise SystemExit("provide task text or --file")
    return parts


def read_task(text: str | None, file_path: str | None) -> str:
    """The task from the command line and an optional --file, read with digest-only file errors."""
    return "\n\n".join(read_task_segments(text, file_path))


def content_free_route(route: Any) -> Any:
    """The route as exported for copying out. Credential references become a count: each access
    profile's ``credential_sources`` (the names of the environment variables it reads) and each
    transport's ``api_key_env`` (the name of the variable holding its API key) are replaced by
    ``credential_source_count``, the number of names they held. No export carries a credential-named
    field with text in it, so the screen needs no exemption for one."""
    if isinstance(route, dict):
        exported: dict[str, Any] = {}
        sources: int | None = None
        for key, value in route.items():
            if key == "credential_sources" and isinstance(value, dict):
                sources = (sources or 0) + sum(len(names) for names in value.values() if isinstance(names, list))
            elif key == "api_key_env" and (value is None or isinstance(value, str)):
                sources = (sources or 0) + (1 if value else 0)
            else:
                exported[key] = content_free_route(value)
        if sources is not None:
            exported["credential_source_count"] = sources
        return exported
    if isinstance(route, list):
        return [content_free_route(item) for item in route]
    return route


def screen_export(text: str, *, as_json: bool) -> ScreenedPayload:
    """Screen exactly the bytes a manual export will print (output plus newline)."""
    text = require_text_disclosure(text, surface="manual export")
    return require_clean(text + "\n", surface="manual export", content_type="application/json" if as_json else "text/plain")


def write_export(screened: ScreenedPayload, *, prepared: PreparedOutbound | None = None, source: Any = None) -> None:
    """Write screened bytes to the byte stream under stdout.

    No text encoding, error handler or newline translation can change them.
    A text-only stream (as in tests) stores the string itself, unencoded.
    """
    raw = screened.require_unchanged(screened.data)
    if prepared is not None:
        prepared.require_unchanged(source, raw)
    buffer = getattr(sys.stdout, "buffer", None)
    if buffer is None:
        sys.stdout.write(screened.text())
        return
    sys.stdout.flush()
    if prepared is not None:
        prepared.require_unchanged(source, raw)
    buffer.write(screened.require_unchanged(raw))
    buffer.flush()


def export_screened(text: str, *, as_json: bool, capture: PreparedSource | None = None, source: Any = None) -> None:
    """Screen exactly the bytes about to be printed for copying, then write those bytes."""
    capture = capture or PreparedSource.capture({"text": text, "as_json": as_json})
    source = {"text": text, "as_json": as_json} if source is None else source
    screened = screen_export(text, as_json=as_json)
    prepared = capture.bind(source, screened)
    write_export(screened, prepared=prepared, source=source)


def require_packet_workload(path, packet, prompt, files, *, rehearsal=False, wire_text=None):
    if rehearsal:
        return None
    transport = packet.get("executor_transport") or {}
    try:
        return validate_export_workload(
            read_export_workload(path, files), request_text=prompt, wire_text=wire_text,
            executor=packet["executor"], provider=packet["provider_key"], bead_id=packet["bead_id"],
            model=transport.get("model") or transport.get("default_model_label"),
            effort=transport.get("effort") or transport.get("default_reasoning_label"), captures=files,
        )
    except WorkloadRefused as exc:
        raise SystemExit(str(exc)) from exc


def main() -> None:
    # Diagnostics before the final screen can repeat caller input; withhold any the screen refuses.
    with withheld_diagnostics("generate_manual_dispatch_prompt"):
        _main()


def _main() -> None:
    parser = ScreeningArgumentParser("generate_manual_dispatch_prompt", description="Generate a copy-paste prompt for manual UI dispatch.")
    parser.add_argument("text", nargs="*")
    parser.add_argument("--file")
    parser.add_argument("--packet", help="Boundary-gated contractor packet JSON to render.")
    parser.add_argument("--workload", help="Whole-route sizing JSON and selected node for a managed packet export.")
    parser.add_argument(
        "--allow-degraded-packet",
        action="store_true",
        help="Allow rendering a valid packet that omits the expert profile after validation.",
    )
    parser.add_argument(
        "--allow-raw-manual-prompt",
        action="store_true",
        help="Render an external manual prompt without a packet for local rehearsal.",
    )
    parser.add_argument(
        "--rehearsal",
        action="store_true",
        help="Permit degraded prompt rendering only as a local rehearsal; do not use as production dispatch evidence.",
    )
    parser.add_argument("--external-ok", action="store_true")
    parser.add_argument("--allow-disclosure-escalation", action="store_true", help=DISCLOSURE_ESCALATION_HELP)
    add_local_route_arguments(parser, profile=False)
    add_route_boundary_arguments(parser, boundary_help="Disclosure boundary for routing; outside disclosure must be chosen explicitly.")
    parser.add_argument("--requested-role", action="append", default=[])
    parser.add_argument("--json", action="store_true")
    add_waiver_reason_argument(parser)
    parser.add_argument("--current-authority", help="Current v3 routing evidence JSON; not a dispatch grant.")
    add_risk_narrowing_arguments(parser)
    args = parser.parse_args()
    refuse_risk_narrowing_arguments(args, source="generate_manual_dispatch_prompt.py")
    require_waiver_reason(args, ["allow_degraded_packet", "allow_raw_manual_prompt", "allow_disclosure_escalation"])

    files: list = []
    if args.packet:
        packet = load_packet_file(args.packet, captures=files)
        source = {"packet": packet, "options": vars(args)}
        capture = PreparedSource.capture(source, files)
        require_packet_export_approval(packet, allow_degraded_packet=args.allow_degraded_packet,
                                       rehearsal=args.rehearsal)
        captured = capture.value()
        prompt = label_rehearsal(render_packet_prompt(captured["packet"]), args.rehearsal)
        capture.require_unchanged(captured)
        artifact = {"packet": captured["packet"], "prompt": prompt, **rehearsal_result(args.rehearsal)}
        screened = screen_export(json.dumps(artifact, indent=2, sort_keys=True) if args.json else prompt, as_json=args.json)
        require_packet_workload(args.workload, captured["packet"], prompt, files, rehearsal=args.rehearsal)
        capture.require_unchanged(source)
        prepared = PreparedSource.capture(source, files).bind(source, screened)
        write_export(screened, prepared=prepared, source=source)
        return

    task_segments = read_task_segments(" ".join(args.text).strip() or None, args.file, captures=files)
    task = "\n\n".join(task_segments)
    from model_catalog_startup import configure_cli_model_catalog

    configure_cli_model_catalog()
    try:
        route = classify_work(
            task,
            text_segments=task_segments,
            **route_decision_options(args),
            **current_authority_file_arguments(args.current_authority),
        )
    except CWOError as exc:
        raise SystemExit(str(exc))
    if route.get("route") == "external-contract" and not args.allow_raw_manual_prompt:
        raise SystemExit(
            "external manual prompts require --packet; for local rehearsal use --allow-raw-manual-prompt with --rehearsal"
        )
    if route.get("route") == "external-contract" and args.allow_raw_manual_prompt and not args.rehearsal:
        raise SystemExit("--allow-raw-manual-prompt requires --rehearsal and must not be used as production dispatch evidence")
    source = {"task": task, "segments": task_segments, "route": route, "options": vars(args)}
    capture = PreparedSource.capture(source, files)
    captured = capture.value()
    prompt = render_prompt(redact_text(captured["task"]) if args.allow_raw_manual_prompt else captured["task"], captured["route"])
    prompt = label_rehearsal(prompt, args.rehearsal)
    capture.require_unchanged(captured)
    if args.json:
        export_screened(json.dumps({"route": content_free_route(captured["route"]), "prompt": prompt,
                                    **rehearsal_result(args.rehearsal)}, indent=2, sort_keys=True),
                        as_json=True, capture=capture, source=source)
    else:
        export_screened(prompt, as_json=False, capture=capture, source=source)


if __name__ == "__main__":
    main()
