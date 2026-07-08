#!/usr/bin/env python3
from __future__ import annotations

import argparse
import datetime as dt
import json
from pathlib import Path
from typing import Any

from cwo_core.paths import (
    REPO_ROOT,
    assert_repo_safe_path,
    assert_safe_output_path,
)
from cwo_core.util import (
    atomic_write_text,
    artifact_hash,
    make_dispatch_id,
    packet_payload_hash,
)
from cwo_core.policy import (
    boundary_allows_external,
    boundary_config,
    executor_config,
    load_policy,
    provider_metadata_for_executor,
    share_boundary_disclosure_stage,
    share_boundary_requires_escalation,
)
from cwo_core.audit import (
    enforce_contracting_quota,
    record_audit_event,
)
from cwo_core.telemetry import telemetry_fields
from cwo_core.waivers import add_waiver_reason_argument, require_waiver_reason, waiver_audit_fields
from cwo_core.packets import (
    fenced_block,
    file_snippet,
    load_expert_profile,
    make_attestation,
    redact_text,
    sanitize_bead,
    validate_contractor_packet,
    validate_opt_in_record,
)
from cwo_core.beads import show_bead_json


def extract_labels(bead: Any) -> list[str]:
    if isinstance(bead, list) and len(bead) == 1:
        bead = bead[0]
    if isinstance(bead, dict):
        source = bead.get("issue") if isinstance(bead.get("issue"), dict) else bead
        labels = source.get("labels") or source.get("label_names") or []
        if isinstance(labels, list):
            return [str(label) for label in labels]
    return []


def _single_bead_object(bead: Any) -> dict[str, Any]:
    if isinstance(bead, list) and len(bead) == 1:
        bead = bead[0]
    if isinstance(bead, dict):
        source = bead.get("issue") if isinstance(bead.get("issue"), dict) else bead
        return source if isinstance(source, dict) else bead
    return {}


def infer_epic_id_from_bead(bead: Any) -> str | None:
    source = _single_bead_object(bead)
    parent = source.get("parent")
    if isinstance(parent, str) and parent.strip():
        return parent.strip()
    if isinstance(parent, dict):
        parent_id = parent.get("id") or parent.get("issue_id")
        if isinstance(parent_id, str) and parent_id.strip():
            return parent_id.strip()
    dependencies = source.get("dependencies")
    if isinstance(dependencies, list):
        for item in dependencies:
            if not isinstance(item, dict):
                continue
            dependency_type = str(item.get("type") or item.get("dependency_type") or "").strip()
            if dependency_type != "parent-child":
                continue
            candidate = item.get("depends_on_id") or item.get("id")
            if isinstance(candidate, str) and candidate.strip():
                return candidate.strip()
    return None


def resolve_effective_epic_id(explicit_epic_id: str | None, bead: Any) -> str | None:
    explicit = explicit_epic_id.strip() if isinstance(explicit_epic_id, str) and explicit_epic_id.strip() else None
    inferred = infer_epic_id_from_bead(bead)
    if explicit and inferred and explicit != inferred:
        raise SystemExit(
            f"--epic {explicit!r} does not match assigned Bead parent {inferred!r}; "
            "use the parent epic or move the Bead before building a contractor packet"
        )
    return explicit or inferred


def find_job_label(labels: list[str]) -> str:
    job_labels = [label for label in labels if label.startswith("contract-jd-")]
    if len(job_labels) > 1:
        raise SystemExit("assigned Bead must have exactly one primary job-description label; found: " + ", ".join(job_labels))
    for label in job_labels:
        return label
    return "contract-jd-general-reasoning"


def persona_for_job_label(job_description_label: str) -> str | None:
    for profile in load_policy("expert-registry").get("experts", {}).values():
        if profile.get("job_description_label") == job_description_label:
            return profile.get("persona_file")
    return None


def validate_gate(
    executor: str,
    share_boundary: str,
    labels: list[str],
    job_description_label: str,
    *,
    external_ok: bool,
    opt_in_record: str | None,
    bead_id: str | None = None,
    epic_id: str | None = None,
    allow_disclosure_escalation: bool = False,
) -> str:
    executor_info = executor_config(executor)
    if not executor_info.get("external"):
        raise SystemExit(f"executor {executor!r} is not an outside contractor executor")
    if not external_ok and not opt_in_record:
        raise SystemExit("external packet build requires --external-ok or an opt-in record")
    if opt_in_record:
        validate_opt_in_record(
            opt_in_record,
            executor=executor,
            share_boundary=share_boundary,
            bead_id=bead_id,
            epic_id=epic_id,
        )
    if not boundary_allows_external(share_boundary):
        raise SystemExit(f"share boundary {share_boundary!r} does not allow external contracting")
    if share_boundary_requires_escalation(share_boundary) and not allow_disclosure_escalation:
        raise SystemExit(
            f"share boundary {share_boundary!r} requires --allow-disclosure-escalation before external packet build"
        )
    missing = [label for label in ["contractor-only", "no-codex-exec"] if label not in labels]
    if missing:
        raise SystemExit(f"assigned Bead is missing contractor guard labels: {', '.join(missing)}")
    job_labels = [label for label in labels if label.startswith("contract-jd-")]
    if len(job_labels) > 1:
        raise SystemExit("assigned Bead must have exactly one primary job-description label; found: " + ", ".join(job_labels))
    if job_description_label not in labels:
        raise SystemExit(f"assigned Bead is missing job-description label: {job_description_label}")
    return "cli-flag" if external_ok else "audit-record"


def collect_snippets(paths: list[str], max_lines: int) -> list[dict[str, Any]]:
    snippets: list[dict[str, Any]] = []
    for raw in paths:
        snippets.append(file_snippet((REPO_ROOT / raw).resolve(), max_lines=max_lines))
    return snippets


def inline_snippet(snippet: str, *, index: int, max_lines: int, path: str | None = None) -> dict[str, Any]:
    redacted = redact_text(snippet)
    lines = redacted.splitlines()
    if max_lines and len(lines) > max_lines:
        label = path or f"inline snippet {index}"
        raise SystemExit(f"{label} exceeds boundary line limit {max_lines}")
    return {
        "type": "inline_snippet",
        "path": path or f"inline-{index}",
        "line_count": len(lines),
        "truncated": False,
        "sha256": artifact_hash(redacted),
        "content": redacted,
    }


def build_packet(
    *,
    bead_id: str,
    bead_json: Any,
    executor: str,
    share_boundary: str,
    job_description_label: str,
    allowed_files: list[str],
    inline_snippets: list[str],
    snippet_files: list[str] | None = None,
    dispatch_id: str | None = None,
    expert_profile_path: str | None = None,
    include_expert_profile: bool = True,
    degraded_context_justification: str = "",
    external_opt_in: bool = False,
    opt_in_basis: str = "not-recorded",
    epic_id: str | None = None,
    quota_info: dict[str, Any] | None = None,
    disclosure_escalation_approved: bool = False,
    requested_executor: str | None = None,
) -> dict[str, Any]:
    boundary = boundary_config(share_boundary)
    executor_info = load_policy("executor-registry").get("executors", {}).get(executor, {})
    provider_metadata = provider_metadata_for_executor(executor_info)
    transport = executor_info.get("transport") if isinstance(executor_info.get("transport"), dict) else {}
    manual_command = str(transport.get("default_command", "")).strip()
    now = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    dispatch_id = dispatch_id or make_dispatch_id(bead_id, now.replace("-", "").replace(":", ""))
    bead_summary = sanitize_bead(bead_json, share_boundary)
    selected_snippets = collect_snippets(allowed_files, int(boundary.get("snippet_line_limit", 80)))
    profile_path = expert_profile_path or persona_for_job_label(job_description_label)
    expert_profile = load_expert_profile(profile_path) if include_expert_profile and profile_path else {}
    if not expert_profile and not degraded_context_justification.strip():
        raise SystemExit("degraded packet requires --degraded-context-justification")
    snippet_files = snippet_files or []
    for index, snippet in enumerate(inline_snippets, 1):
        selected_snippets.append(
            inline_snippet(snippet, index=index, max_lines=int(boundary.get("snippet_line_limit", 80)))
        )
    offset = len(inline_snippets)
    for index, raw_path in enumerate(snippet_files, 1):
        candidate = (REPO_ROOT / raw_path) if not Path(raw_path).is_absolute() else Path(raw_path)
        if not candidate.exists():
            raise SystemExit(f"snippet file not found: {raw_path}")
        path = assert_repo_safe_path(candidate)
        display_path = path.relative_to(REPO_ROOT).as_posix()
        try:
            content = path.read_text(encoding="utf-8")
        except UnicodeDecodeError as exc:
            raise SystemExit(f"refusing non-UTF-8 snippet file: {display_path}") from exc
        selected_snippets.append(
            inline_snippet(
                content,
                index=offset + index,
                max_lines=int(boundary.get("snippet_line_limit", 80)),
                path=display_path,
            )
        )

    included = [
        {"type": "assignment_summary", "sha256": artifact_hash(json.dumps(bead_summary, sort_keys=True))},
        *[{key: item[key] for key in ["type", "path", "line_count", "truncated", "sha256"]} for item in selected_snippets],
    ]
    if expert_profile:
        included.append(
            {
                "type": "expert_profile",
                "path": expert_profile["path"],
                "sha256": expert_profile["sha256"],
            }
        )
    excluded = [
        {"type": "full_bead_json", "reason": "forbidden in boundary-aware packets"},
        {"type": "secrets", "reason": "never-share category"},
        {"type": "production_access", "reason": "never-share category"},
    ]
    review_surface = "packet-only" if share_boundary == "redacted-packet" else share_boundary
    review_surface_contract = {
        "review_surface": review_surface,
        "source_inspection": review_surface,
        "allowed_actions": [
            "read this packet",
            "read included snippets and summaries",
        ],
        "forbidden_actions": [
            "shell execution",
            "local checkout access",
            "repo mutation",
            "merge or release action",
            "credential or production access",
        ],
        "go_rule": (
            "If PR, merge, readiness, source, or diff inspection is required but not included in this packet, "
            "do not return an unconditional GO. Return conditional GO based on packet evidence, open-risk, "
            "request broader review surface, or NO-GO."
        ),
        "required_disclosures": [
            "Review surface",
            "Source inspection",
            "Sources inspected",
            "Sources not inspected",
            "Independent verification",
            "Packet-reported claims",
        ],
    }
    required_return_sections = list(load_policy("acceptance-policy").get("contractor_return_required_sections", []))
    for section in review_surface_contract["required_disclosures"]:
        if section not in required_return_sections:
            required_return_sections.append(section)
    packet: dict[str, Any] = {
        "dispatch_id": dispatch_id,
        "generated_at": now,
        "bead_id": bead_id,
        "epic_id": epic_id,
        "executor": executor,
        "provider_key": provider_metadata.get("provider_key"),
        "provider_family": provider_metadata.get("provider_family"),
        "provider_trust_tier": provider_metadata.get("provider_trust_tier"),
        "provider_retention_class": provider_metadata.get("provider_retention_class"),
        "executor_transport": transport or None,
        "manual_command": manual_command or None,
        "share_boundary": share_boundary,
        "disclosure_stage": share_boundary_disclosure_stage(share_boundary),
        "disclosure_escalation_approved": bool(disclosure_escalation_approved),
        "job_description_label": job_description_label,
        "expert_profile": expert_profile or None,
        "expert_profile_included": bool(expert_profile),
        "degraded_context_justification": degraded_context_justification.strip(),
        "external_opt_in": external_opt_in,
        "opt_in_basis": opt_in_basis,
        "boundary_description": boundary.get("description"),
        "bead_summary": bead_summary,
        "selected_snippets": selected_snippets,
        "included_artifacts": included,
        "excluded_artifacts": excluded,
        "review_surface_contract": review_surface_contract,
        "required_return_sections": required_return_sections,
        "acceptance_rule": "Evaluator scoring and architect adjudication are required before implementation.",
    }
    if requested_executor and requested_executor != executor:
        packet["requested_executor"] = requested_executor
        packet["canonical_executor"] = executor
    packet.update(quota_info or {"quota_checked": False, "quota_remaining": None})
    packet["packet_sha256"] = packet_payload_hash(packet)
    return packet


def packet_markdown(packet: dict[str, Any]) -> str:
    snippets = []
    for item in packet.get("selected_snippets", []):
        snippets.append(
            f"### {item['path']}\n\n{fenced_block(item['content'], 'text')}"
        )
    profile = packet.get("expert_profile") or {}
    if profile:
        profile_block = f"""## Expert Profile

Path: {profile['path']}
SHA-256: {profile['sha256']}

{fenced_block(profile['content'], 'markdown')}
"""
    else:
        profile_block = f"""## Expert Profile

No expert profile included. This is a degraded packet.

Justification:
{packet.get('degraded_context_justification', '')}
"""
    return f"""# Contractor Packet

Dispatch ID: {packet['dispatch_id']}
Assigned bead: {packet['bead_id']}
Executor: {packet['executor']}
Provider: {packet.get('provider_key')} ({packet.get('provider_trust_tier')})
Job-description label: {packet['job_description_label']}
Share boundary: {packet['share_boundary']}
Disclosure stage: {packet['disclosure_stage']}
Disclosure escalation approved: {packet['disclosure_escalation_approved']}
Packet SHA-256: {packet['packet_sha256']}

## Boundary

{packet.get('boundary_description')}

## Bead Summary

{fenced_block(json.dumps(packet['bead_summary'], indent=2, sort_keys=True), 'json')}

## Included Artifacts

{fenced_block(json.dumps(packet['included_artifacts'], indent=2, sort_keys=True), 'json')}

## Excluded Artifacts

{fenced_block(json.dumps(packet['excluded_artifacts'], indent=2, sort_keys=True), 'json')}

## Review Surface Contract

{fenced_block(json.dumps(packet.get('review_surface_contract') or {}, indent=2, sort_keys=True), 'json')}

## Selected Snippets

{chr(10).join(snippets) if snippets else 'No file snippets included.'}

{profile_block}

## Required Return Sections

{chr(10).join('- ' + section for section in packet['required_return_sections'])}

## Acceptance Rule

{packet['acceptance_rule']}
"""


def main() -> None:
    parser = argparse.ArgumentParser(description="Build a boundary-aware contractor packet.")
    parser.add_argument("--bead", required=True)
    parser.add_argument("--executor", default="openai_deep_research_manual")
    parser.add_argument("--share-boundary", default="redacted-packet")
    parser.add_argument(
        "--allow-disclosure-escalation",
        action="store_true",
        help="Explicitly approve repo-readonly or patch-branch disclosure stage for this packet.",
    )
    parser.add_argument("--job-description")
    parser.add_argument("--bead-json-file")
    parser.add_argument("--external-ok", action="store_true")
    parser.add_argument("--opt-in-record")
    parser.add_argument("--epic", help="Epic quota scope. Defaults to the assigned Bead parent when present.")
    parser.add_argument("--expert-profile")
    profile_group = parser.add_mutually_exclusive_group()
    profile_group.add_argument("--include-expert-profile", dest="include_expert_profile", action="store_true", default=True)
    profile_group.add_argument("--no-include-expert-profile", dest="include_expert_profile", action="store_false")
    parser.add_argument("--degraded-context-justification", default="")
    parser.add_argument("--allowed-file", action="append", default=[])
    parser.add_argument("--snippet", action="append", default=[], help="Inline snippet to include after redaction.")
    parser.add_argument("--snippet-file", action="append", default=[], help="Text file to include as a redacted inline snippet.")
    parser.add_argument("--dispatch-id")
    parser.add_argument("--format", choices=["markdown", "json"], default="markdown")
    parser.add_argument("--output")
    parser.add_argument(
        "--attest-packet",
        action="store_true",
        help="Write a packet attestation sidecar when --output is used.",
    )
    parser.set_defaults(audit=True)
    parser.add_argument("--audit", dest="audit", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--no-audit", dest="audit", action="store_false", help="Do not append the default audit event.")
    parser.add_argument("--rehearsal", action="store_true", help="Allow no-audit packet rehearsals that must not consume audit quota.")
    add_waiver_reason_argument(parser)
    args = parser.parse_args()
    if not args.audit and not args.rehearsal:
        raise SystemExit("--no-audit is allowed only with --rehearsal for packet build tests or rehearsals")
    require_waiver_reason(args, ["allow_disclosure_escalation", "audit"])
    executor_info = executor_config(args.executor)
    requested_executor = executor_info.get("requested_key")
    args.executor = str(executor_info.get("key", args.executor))

    bead_json = json.loads(Path(args.bead_json_file).read_text(encoding="utf-8")) if args.bead_json_file else show_bead_json(args.bead)
    effective_epic_id = resolve_effective_epic_id(args.epic, bead_json)
    labels = extract_labels(bead_json)
    job_label = args.job_description or find_job_label(labels)
    opt_in_basis = validate_gate(
        args.executor,
        args.share_boundary,
        labels,
        job_label,
        external_ok=args.external_ok,
        opt_in_record=args.opt_in_record,
        bead_id=args.bead,
        epic_id=effective_epic_id,
        allow_disclosure_escalation=args.allow_disclosure_escalation,
    )
    dispatch_id = args.dispatch_id or make_dispatch_id(args.bead)
    quota_info = enforce_contracting_quota(
        effective_epic_id,
        args.executor,
        "external-contract",
        dispatch_id=dispatch_id,
    )
    packet = build_packet(
        bead_id=args.bead,
        bead_json=bead_json,
        executor=args.executor,
        share_boundary=args.share_boundary,
        job_description_label=job_label,
        allowed_files=args.allowed_file,
        inline_snippets=args.snippet,
        snippet_files=args.snippet_file,
        dispatch_id=dispatch_id,
        expert_profile_path=args.expert_profile,
        include_expert_profile=args.include_expert_profile,
        degraded_context_justification=args.degraded_context_justification,
        external_opt_in=True,
        opt_in_basis=opt_in_basis,
        epic_id=effective_epic_id,
        quota_info=quota_info,
        disclosure_escalation_approved=args.allow_disclosure_escalation,
        requested_executor=requested_executor,
    )
    packet_errors = validate_contractor_packet(
        packet,
        allow_degraded_packet=not args.include_expert_profile,
    )
    if packet_errors:
        raise SystemExit("contractor packet validation failed before render: " + "; ".join(packet_errors))
    rendered = json.dumps(packet, indent=2, sort_keys=True) if args.format == "json" else packet_markdown(packet)
    if args.audit:
        included_artifacts = packet.get("included_artifacts") if isinstance(packet.get("included_artifacts"), list) else []
        selected_snippets = packet.get("selected_snippets") if isinstance(packet.get("selected_snippets"), list) else []
        profile = packet.get("expert_profile") if isinstance(packet.get("expert_profile"), dict) else {}
        record_audit_event(
            {
                "event_type": "packet_built",
                "quota_event_type": quota_info.get("quota_event_type"),
                "quota_stage": "reserved",
                "dispatch_id": packet["dispatch_id"],
                "bead_id": args.bead,
                "epic_id": effective_epic_id,
                "executor_key": packet["executor"],
                "requested_executor_key": packet.get("requested_executor"),
                "executor_external": quota_info.get("executor_external"),
                "share_boundary": args.share_boundary,
                "disclosure_stage": packet.get("disclosure_stage"),
                "opt_in_basis": opt_in_basis,
                "quota_remaining": quota_info.get("quota_remaining"),
                "packet_sha256": packet["packet_sha256"],
                **waiver_audit_fields(args, ["allow_disclosure_escalation", "audit"]),
                **telemetry_fields(
                    telemetry_kind="packet_build",
                    telemetry_status="completed",
                    provider_family=packet.get("provider_family"),
                    provider_retention_class=packet.get("provider_retention_class"),
                    job_description_label=packet.get("job_description_label"),
                    expert_profile=profile.get("path"),
                    expert_profile_path=profile.get("path"),
                    expert_profile_included=bool(packet.get("expert_profile_included")),
                    degraded_packet=not bool(packet.get("expert_profile_included")),
                    disclosure_escalation_approved=bool(packet.get("disclosure_escalation_approved")),
                    included_artifacts_count=len(included_artifacts),
                    included_artifact_types=[item.get("type") for item in included_artifacts if isinstance(item, dict)],
                    selected_snippets_count=len(selected_snippets),
                    selected_snippet_paths=[item.get("path") for item in selected_snippets if isinstance(item, dict) and item.get("path")],
                    selected_snippet_lines=sum(
                        int(item.get("line_count") or 0) for item in selected_snippets if isinstance(item, dict)
                    ),
                    packet_output_sha256=artifact_hash(rendered),
                ),
            }
        )
    if args.output:
        output_path = assert_safe_output_path(Path(args.output))
        atomic_write_text(output_path, rendered)
        if args.attest_packet:
            attestation_path = assert_safe_output_path(output_path.with_suffix(output_path.suffix + ".attestation.json"))
            attestation = make_attestation(
                subject_type="contractor-packet",
                subject_sha256=artifact_hash(rendered),
                subject_id=packet["dispatch_id"],
                predicate={
                    "bead_id": args.bead,
                    "executor": packet["executor"],
                    "requested_executor": packet.get("requested_executor"),
                    "share_boundary": args.share_boundary,
                    "disclosure_stage": packet["disclosure_stage"],
                    "packet_sha256": packet["packet_sha256"],
                },
            )
            atomic_write_text(attestation_path, json.dumps(attestation, indent=2, sort_keys=True))
    else:
        print(rendered)


if __name__ == "__main__":
    main()
