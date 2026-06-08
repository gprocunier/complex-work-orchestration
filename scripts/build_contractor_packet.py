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
    file_snippet,
    load_policy,
    record_audit_event,
    redact_text,
    sanitize_bead,
    show_bead_json,
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


def validate_gate(executor: str, share_boundary: str, labels: list[str], job_description_label: str) -> None:
    executors = load_policy("executor-registry").get("executors", {})
    if executor not in executors:
        raise SystemExit(f"unknown executor {executor!r}; see policy/executor-registry.yaml")
    if not executors[executor].get("external"):
        raise SystemExit(f"executor {executor!r} is not an outside contractor executor")
    if not boundary_allows_external(share_boundary):
        raise SystemExit(f"share boundary {share_boundary!r} does not allow external contracting")
    missing = [label for label in ["contractor-only", "no-codex-exec"] if label not in labels]
    if missing:
        raise SystemExit(f"assigned Bead is missing contractor guard labels: {', '.join(missing)}")
    if job_description_label not in labels:
        raise SystemExit(f"assigned Bead is missing job-description label: {job_description_label}")


def collect_snippets(paths: list[str], max_lines: int) -> list[dict[str, Any]]:
    snippets: list[dict[str, Any]] = []
    for raw in paths:
        snippets.append(file_snippet((REPO_ROOT / raw).resolve(), max_lines=max_lines))
    return snippets


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
) -> dict[str, Any]:
    boundary = boundary_config(share_boundary)
    now = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    dispatch_id = dispatch_id or f"dispatch-{bead_id}-{now.replace(':', '').replace('-', '')}"
    bead_summary = sanitize_bead(bead_json, share_boundary)
    selected_snippets = collect_snippets(allowed_files, int(boundary.get("snippet_line_limit", 80)))
    for index, snippet in enumerate(inline_snippets, 1):
        redacted = redact_text(snippet)
        selected_snippets.append(
            {
                "type": "inline_snippet",
                "path": f"inline-{index}",
                "line_count": len(redacted.splitlines()),
                "truncated": False,
                "sha256": artifact_hash(redacted),
                "content": redacted,
            }
        )

    included = [
        {"type": "assignment_summary", "sha256": artifact_hash(json.dumps(bead_summary, sort_keys=True))},
        *[{key: item[key] for key in ["type", "path", "line_count", "truncated", "sha256"]} for item in selected_snippets],
    ]
    excluded = [
        {"type": "full_bead_json", "reason": "forbidden in boundary-aware packets"},
        {"type": "secrets", "reason": "never-share category"},
        {"type": "production_access", "reason": "never-share category"},
    ]
    packet: dict[str, Any] = {
        "dispatch_id": dispatch_id,
        "generated_at": now,
        "bead_id": bead_id,
        "executor": executor,
        "share_boundary": share_boundary,
        "job_description_label": job_description_label,
        "boundary_description": boundary.get("description"),
        "bead_summary": bead_summary,
        "selected_snippets": selected_snippets,
        "included_artifacts": included,
        "excluded_artifacts": excluded,
        "required_return_sections": load_policy("acceptance-policy").get("contractor_return_required_sections", []),
        "acceptance_rule": "Evaluator scoring and architect adjudication are required before implementation.",
    }
    packet["packet_sha256"] = artifact_hash(json.dumps(packet, sort_keys=True))
    return packet


def packet_markdown(packet: dict[str, Any]) -> str:
    snippets = []
    for item in packet.get("selected_snippets", []):
        snippets.append(
            f"### {item['path']}\n\n```text\n{item['content']}\n```"
        )
    return f"""# Contractor Packet

Dispatch ID: {packet['dispatch_id']}
Assigned bead: {packet['bead_id']}
Executor: {packet['executor']}
Job-description label: {packet['job_description_label']}
Share boundary: {packet['share_boundary']}
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
    parser.add_argument("--job-description")
    parser.add_argument("--bead-json-file")
    parser.add_argument("--allowed-file", action="append", default=[])
    parser.add_argument("--snippet", action="append", default=[], help="Inline snippet to include after redaction.")
    parser.add_argument("--dispatch-id")
    parser.add_argument("--format", choices=["markdown", "json"], default="markdown")
    parser.add_argument("--output")
    parser.add_argument("--audit", action="store_true")
    args = parser.parse_args()

    bead_json = json.loads(Path(args.bead_json_file).read_text(encoding="utf-8")) if args.bead_json_file else show_bead_json(args.bead)
    labels = extract_labels(bead_json)
    job_label = args.job_description or find_job_label(labels)
    validate_gate(args.executor, args.share_boundary, labels, job_label)
    packet = build_packet(
        bead_id=args.bead,
        bead_json=bead_json,
        executor=args.executor,
        share_boundary=args.share_boundary,
        job_description_label=job_label,
        allowed_files=args.allowed_file,
        inline_snippets=args.snippet,
        dispatch_id=args.dispatch_id,
    )
    rendered = json.dumps(packet, indent=2, sort_keys=True) if args.format == "json" else packet_markdown(packet)
    if args.output:
        Path(args.output).write_text(rendered, encoding="utf-8")
    else:
        print(rendered)
    if args.audit:
        record_audit_event(
            {
                "event_type": "packet_built",
                "dispatch_id": packet["dispatch_id"],
                "bead_id": args.bead,
                "executor_key": args.executor,
                "share_boundary": args.share_boundary,
                "packet_sha256": packet["packet_sha256"],
            }
        )


if __name__ == "__main__":
    main()
