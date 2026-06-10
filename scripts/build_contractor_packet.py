#!/usr/bin/env python3
from __future__ import annotations

import argparse
import datetime as dt
import json
from pathlib import Path
from typing import Any

from orchestration_lib import (
    REPO_ROOT,
    artifact_hash,
    boundary_allows_external,
    boundary_config,
    enforce_contracting_quota,
    file_snippet,
    load_expert_profile,
    load_policy,
    make_attestation,
    make_dispatch_id,
    packet_payload_hash,
    provider_metadata_for_executor,
    record_audit_event,
    redact_text,
    sanitize_bead,
    share_boundary_disclosure_stage,
    share_boundary_requires_escalation,
    show_bead_json,
    validate_opt_in_record,
)


def extract_labels(bead: Any) -> list[str]:
    if isinstance(bead, dict):
        source = bead.get("issue") if isinstance(bead.get("issue"), dict) else bead
        labels = source.get("labels") or source.get("label_names") or []
        if isinstance(labels, list):
            return [str(label) for label in labels]
    return []


def find_job_label(labels: list[str]) -> str:
    for label in labels:
        if label.startswith("contract-jd-"):
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
    allow_disclosure_escalation: bool = False,
) -> str:
    executors = load_policy("executor-registry").get("executors", {})
    if executor not in executors:
        raise SystemExit(f"unknown executor {executor!r}; see policy/executor-registry.yaml")
    if not executors[executor].get("external"):
        raise SystemExit(f"executor {executor!r} is not an outside contractor executor")
    if not external_ok and not opt_in_record:
        raise SystemExit("external packet build requires --external-ok or an opt-in record")
    if opt_in_record:
        validate_opt_in_record(opt_in_record, executor=executor, share_boundary=share_boundary)
    if not boundary_allows_external(share_boundary):
        raise SystemExit(f"share boundary {share_boundary!r} does not allow external contracting")
    if share_boundary_requires_escalation(share_boundary) and not allow_disclosure_escalation:
        raise SystemExit(
            f"share boundary {share_boundary!r} requires --allow-disclosure-escalation before external packet build"
        )
    missing = [label for label in ["contractor-only", "no-codex-exec"] if label not in labels]
    if missing:
        raise SystemExit(f"assigned Bead is missing contractor guard labels: {', '.join(missing)}")
    if job_description_label not in labels:
        raise SystemExit(f"assigned Bead is missing job-description label: {job_description_label}")
    return "cli-flag" if external_ok else "audit-record"


def collect_snippets(paths: list[str], max_lines: int) -> list[dict[str, Any]]:
    snippets: list[dict[str, Any]] = []
    for raw in paths:
        snippets.append(file_snippet((REPO_ROOT / raw).resolve(), max_lines=max_lines))
    return snippets


def inline_snippet(snippet: str, *, index: int, max_lines: int) -> dict[str, Any]:
    redacted = redact_text(snippet)
    lines = redacted.splitlines()
    if max_lines and len(lines) > max_lines:
        raise SystemExit(f"inline snippet {index} exceeds boundary line limit {max_lines}")
    return {
        "type": "inline_snippet",
        "path": f"inline-{index}",
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
    dispatch_id: str | None = None,
    expert_profile_path: str | None = None,
    include_expert_profile: bool = True,
    degraded_context_justification: str = "",
    external_opt_in: bool = False,
    opt_in_basis: str = "not-recorded",
    epic_id: str | None = None,
    quota_info: dict[str, Any] | None = None,
    disclosure_escalation_approved: bool = False,
) -> dict[str, Any]:
    boundary = boundary_config(share_boundary)
    executor_config = load_policy("executor-registry").get("executors", {}).get(executor, {})
    provider_metadata = provider_metadata_for_executor(executor_config)
    now = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    dispatch_id = dispatch_id or make_dispatch_id(bead_id, now.replace("-", "").replace(":", ""))
    bead_summary = sanitize_bead(bead_json, share_boundary)
    selected_snippets = collect_snippets(allowed_files, int(boundary.get("snippet_line_limit", 80)))
    profile_path = expert_profile_path or persona_for_job_label(job_description_label)
    expert_profile = load_expert_profile(profile_path) if include_expert_profile and profile_path else {}
    if not expert_profile and not degraded_context_justification.strip():
        raise SystemExit("degraded packet requires --degraded-context-justification")
    for index, snippet in enumerate(inline_snippets, 1):
        selected_snippets.append(
            inline_snippet(snippet, index=index, max_lines=int(boundary.get("snippet_line_limit", 80)))
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
        "required_return_sections": load_policy("acceptance-policy").get("contractor_return_required_sections", []),
        "acceptance_rule": "Evaluator scoring and architect adjudication are required before implementation.",
    }
    packet.update(quota_info or {"quota_checked": False, "quota_remaining": None})
    packet["packet_sha256"] = packet_payload_hash(packet)
    return packet


def packet_markdown(packet: dict[str, Any]) -> str:
    snippets = []
    for item in packet.get("selected_snippets", []):
        snippets.append(
            f"### {item['path']}\n\n```text\n{item['content']}\n```"
        )
    profile = packet.get("expert_profile") or {}
    if profile:
        profile_block = f"""## Expert Profile

Path: {profile['path']}
SHA-256: {profile['sha256']}

```markdown
{profile['content']}
```
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

```json
{json.dumps(packet['bead_summary'], indent=2, sort_keys=True)}
```

## Included Artifacts

```json
{json.dumps(packet['included_artifacts'], indent=2, sort_keys=True)}
```

## Excluded Artifacts

```json
{json.dumps(packet['excluded_artifacts'], indent=2, sort_keys=True)}
```

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
    parser.add_argument("--epic")
    parser.add_argument("--expert-profile")
    profile_group = parser.add_mutually_exclusive_group()
    profile_group.add_argument("--include-expert-profile", dest="include_expert_profile", action="store_true", default=True)
    profile_group.add_argument("--no-include-expert-profile", dest="include_expert_profile", action="store_false")
    parser.add_argument("--degraded-context-justification", default="")
    parser.add_argument("--allowed-file", action="append", default=[])
    parser.add_argument("--snippet", action="append", default=[], help="Inline snippet to include after redaction.")
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
    args = parser.parse_args()

    bead_json = json.loads(Path(args.bead_json_file).read_text(encoding="utf-8")) if args.bead_json_file else show_bead_json(args.bead)
    labels = extract_labels(bead_json)
    job_label = args.job_description or find_job_label(labels)
    opt_in_basis = validate_gate(
        args.executor,
        args.share_boundary,
        labels,
        job_label,
        external_ok=args.external_ok,
        opt_in_record=args.opt_in_record,
        allow_disclosure_escalation=args.allow_disclosure_escalation,
    )
    dispatch_id = args.dispatch_id or make_dispatch_id(args.bead)
    quota_info = enforce_contracting_quota(
        args.epic,
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
        dispatch_id=dispatch_id,
        expert_profile_path=args.expert_profile,
        include_expert_profile=args.include_expert_profile,
        degraded_context_justification=args.degraded_context_justification,
        external_opt_in=True,
        opt_in_basis=opt_in_basis,
        epic_id=args.epic,
        quota_info=quota_info,
        disclosure_escalation_approved=args.allow_disclosure_escalation,
    )
    rendered = json.dumps(packet, indent=2, sort_keys=True) if args.format == "json" else packet_markdown(packet)
    if args.output:
        output_path = Path(args.output)
        output_path.write_text(rendered, encoding="utf-8")
        if args.attest_packet:
            attestation = make_attestation(
                subject_type="contractor-packet",
                subject_sha256=artifact_hash(rendered),
                subject_id=packet["dispatch_id"],
                predicate={
                    "bead_id": args.bead,
                    "executor": args.executor,
                    "share_boundary": args.share_boundary,
                    "disclosure_stage": packet["disclosure_stage"],
                    "packet_sha256": packet["packet_sha256"],
                },
            )
            output_path.with_suffix(output_path.suffix + ".attestation.json").write_text(
                json.dumps(attestation, indent=2, sort_keys=True),
                encoding="utf-8",
            )
    else:
        print(rendered)
    if args.audit:
        record_audit_event(
            {
                "event_type": "packet_built",
                "quota_event_type": quota_info.get("quota_event_type"),
                "dispatch_id": packet["dispatch_id"],
                "bead_id": args.bead,
                "epic_id": args.epic,
                "executor_key": args.executor,
                "executor_external": quota_info.get("executor_external"),
                "share_boundary": args.share_boundary,
                "opt_in_basis": opt_in_basis,
                "quota_remaining": quota_info.get("quota_remaining"),
                "packet_sha256": packet["packet_sha256"],
            }
        )


if __name__ == "__main__":
    main()
