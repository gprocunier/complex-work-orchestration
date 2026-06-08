#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from typing import Any

from orchestration_lib import classify_work, read_text_arg


def render_prompt(task: str, route: dict[str, object]) -> str:
    expert_lines = "\n".join(
        f"- {expert['display_name']} ({expert['job_description_label']})"
        for expert in route.get("ranked_experts", [])[:3]  # type: ignore[index]
    )
    return f"""You are an outside model contractor for one bounded Beads assignment.

Executor: {route['recommended_executor']}
Route: {route['route']}
Share boundary: {route['share_boundary']}
Data sensitivity: {route['data_sensitivity']}
Dispatch sensitivity: {route['dispatch_sensitivity']}

Assignment:
{task}

Required expert lenses:
{expert_lines}

Rules:
- Work only this assignment.
- Do not ask for or expose secrets, credentials, production access, or private data.
- Do not re-plan the whole project.
- Do not publish, release, tag, or run destructive commands.
- Return conclusions, evidence, alternatives considered, confidence, risks or gaps, and recommended next Beads.
- Your output will be scored by an evaluator and adjudicated by the architect before implementation.
"""


def render_packet_prompt(packet: dict[str, Any]) -> str:
    included_lines = "\n".join(
        f"- {item.get('type')}: {item.get('path', 'assignment')} sha256={item.get('sha256', 'n/a')}"
        for item in packet.get("included_artifacts", [])
    )
    required_sections = "\n".join(f"- {section}" for section in packet.get("required_return_sections", []))
    snippets = []
    for item in packet.get("selected_snippets", []):
        snippets.append(f"### {item.get('path')}\n\n```text\n{item.get('content', '')}\n```")
    snippet_text = "\n\n".join(snippets) if snippets else "No file snippets were included."
    return f"""You are an outside model contractor for one bounded Beads assignment.

Dispatch ID: {packet['dispatch_id']}
Executor: {packet['executor']}
Assigned bead: {packet['bead_id']}
Job-description label: {packet['job_description_label']}
Share boundary: {packet['share_boundary']}
Packet SHA-256: {packet.get('packet_sha256', 'not-recorded')}

Boundary:
{packet.get('boundary_description', 'No boundary description provided.')}

Bead summary:
```json
{json.dumps(packet.get('bead_summary', {}), indent=2, sort_keys=True)}
```

Included artifacts:
{included_lines or '- assignment summary only'}

Selected snippets:
{snippet_text}

Required return sections:
{required_sections}

Rules:
- Work only this assignment.
- Do not ask for or expose secrets, credentials, production access, or private data.
- Do not re-plan the whole project.
- Do not publish, release, tag, or run destructive commands.
- Return conclusions, evidence, alternatives considered, confidence, risks or gaps, and recommended next Beads.
- Your output will be scored by an evaluator and adjudicated by the architect before implementation.
"""


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate a copy-paste prompt for manual UI dispatch.")
    parser.add_argument("text", nargs="*")
    parser.add_argument("--file")
    parser.add_argument("--external-ok", action="store_true")
    parser.add_argument("--share-boundary", default="redacted-packet")
    parser.add_argument("--requested-role", action="append", default=[])
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    task = read_text_arg(" ".join(args.text).strip() or None, args.file)
    route = classify_work(task, external_ok=args.external_ok, share_boundary=args.share_boundary, requested_roles=args.requested_role)
    prompt = render_prompt(task, route)
    if args.json:
        print(json.dumps({"route": route, "prompt": prompt}, indent=2, sort_keys=True))
    else:
        print(prompt)


if __name__ == "__main__":
    main()
