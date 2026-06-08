#!/usr/bin/env python3
from __future__ import annotations

import argparse
import datetime as dt
import json
from pathlib import Path
from typing import Any

from orchestration_lib import REPO_ROOT, boundary_allows_external, load_policy, show_bead_json


def extract_labels(bead: Any) -> list[str]:
    if isinstance(bead, dict):
        for key in ["labels", "label_names"]:
            labels = bead.get(key)
            if isinstance(labels, list):
                return [str(label) for label in labels]
        issue = bead.get("issue")
        if isinstance(issue, dict):
            labels = issue.get("labels")
            if isinstance(labels, list):
                return [str(label) for label in labels]
    return []


def find_job_label(labels: list[str]) -> str:
    for label in labels:
        if label.startswith("contract-jd-"):
            return label
    return "contract-jd-general-reasoning"


def validate_bead_labels(labels: list[str], job_description_label: str) -> None:
    missing = [label for label in ["contractor-only", "no-codex-exec"] if label not in labels]
    if missing:
        raise SystemExit(f"assigned Bead is missing contractor guard labels: {', '.join(missing)}")
    if job_description_label not in labels:
        raise SystemExit(f"assigned Bead is missing job-description label: {job_description_label}")


def validate_gate(executor: str, share_boundary: str) -> None:
    executors = load_policy("executor-registry").get("executors", {})
    if executor not in executors:
        raise SystemExit(f"unknown executor {executor!r}; see policy/executor-registry.yaml")
    if not executors[executor].get("external"):
        raise SystemExit(f"executor {executor!r} is not an outside contractor executor")
    if not boundary_allows_external(share_boundary):
        raise SystemExit(f"share boundary {share_boundary!r} does not allow external contracting")


def build_packet(
    *,
    bead_id: str,
    bead_json: Any,
    executor: str,
    share_boundary: str,
    job_description_label: str,
) -> str:
    brief_path = REPO_ROOT / "references" / "contractor-brief.md"
    brief = brief_path.read_text(encoding="utf-8")
    boundaries = load_policy("share-boundaries").get("boundaries", {})
    boundary = boundaries.get(share_boundary, {})
    now = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    return f"""# Contractor Packet

Generated: {now}
Assigned bead: {bead_id}
Executor: {executor}
Job-description label: {job_description_label}
Share boundary: {share_boundary}

## Gate Checks

- Outside executor is registered: yes
- Share boundary allows external contracting: yes
- Codex pickup rule: forbidden for contractor-only work
- Architect review required before implementation: yes

## Share Boundary

{boundary.get('description', 'No boundary description found.')}

Never share: {', '.join(load_policy('share-boundaries').get('never_share', []))}

## Assigned Bead JSON

```json
{json.dumps(bead_json, indent=2, sort_keys=True)}
```

## Contractor Brief

{brief}
"""


def main() -> None:
    parser = argparse.ArgumentParser(description="Build a gated packet for an outside model contractor.")
    parser.add_argument("--bead", required=True, help="Assigned Beads ID.")
    parser.add_argument("--executor", default="external_reasoner", help="Executor key from policy/executor-registry.yaml.")
    parser.add_argument("--share-boundary", default="redacted-packet", help="Approved sharing boundary.")
    parser.add_argument("--job-description", help="Override the contract job-description label.")
    parser.add_argument("--bead-json-file", help="Use saved bead JSON instead of calling bd show.")
    parser.add_argument("--output", help="Write packet to this path instead of stdout.")
    args = parser.parse_args()

    validate_gate(args.executor, args.share_boundary)
    if args.bead_json_file:
        bead_json = json.loads(Path(args.bead_json_file).read_text(encoding="utf-8"))
    else:
        bead_json = show_bead_json(args.bead)
    labels = extract_labels(bead_json)
    job_label = args.job_description or find_job_label(labels)
    validate_bead_labels(labels, job_label)
    packet = build_packet(
        bead_id=args.bead,
        bead_json=bead_json,
        executor=args.executor,
        share_boundary=args.share_boundary,
        job_description_label=job_label,
    )

    if args.output:
        Path(args.output).write_text(packet, encoding="utf-8")
    else:
        print(packet)


if __name__ == "__main__":
    main()
