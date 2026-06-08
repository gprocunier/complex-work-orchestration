#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from typing import Any

from orchestration_lib import classify_work, create_bead, read_text_arg


def expert_description(expert: dict[str, Any], external: bool, share_boundary: str) -> str:
    focus = "\n".join(f"- {item}" for item in expert.get("output_focus", []))
    if external:
        labels = f"contractor-only,no-codex-exec,{expert['job_description_label']}"
        codex_rule = "Codex agents may coordinate, brief, and review this bead, but must not execute or close it as contractor work."
    else:
        labels = f"expert-review,{expert['job_description_label']}"
        codex_rule = "Codex agents may execute this as an internal expert-review task."
    return f"""Purpose:
Perform {expert['display_name']} for the parent work item.

Scope:
Stay within this assigned review lens and the parent Bead context.

Review focus:
{focus}

Expected output:
Findings, evidence, confidence, risks or gaps, and recommended next beads.

Validation required:
State whether findings are based on code, documentation, command output, or inference.

Contract labels:
{labels}

Share boundary:
{share_boundary}

Codex handling rule:
{codex_rule}"""


def main() -> None:
    parser = argparse.ArgumentParser(description="Create expert review Beads from the routing policy.")
    parser.add_argument("text", nargs="*", help="Task text to classify.")
    parser.add_argument("--file", help="Read task text from a file.")
    parser.add_argument("--parent", help="Parent Beads ID.")
    parser.add_argument("--title-prefix", default="Expert review", help="Prefix for created review tasks.")
    parser.add_argument("--external-ok", action="store_true", help="User has opted in to third-party contracting.")
    parser.add_argument("--share-boundary", default="no-outside-sharing", help="Approved sharing boundary.")
    parser.add_argument("--dry-run", action="store_true", help="Print planned reviews without creating Beads.")
    args = parser.parse_args()

    text = read_text_arg(" ".join(args.text).strip() or None, args.file)
    route = classify_work(text, external_ok=args.external_ok, share_boundary=args.share_boundary)
    external = route["route"] == "external-contract"
    reviews = []

    for expert in route.get("required_experts", []):
        labels = (
            ["contractor-only", "no-codex-exec", expert["job_description_label"]]
            if external
            else ["expert-review", expert["job_description_label"]]
        )
        review = {
            "title": f"{args.title_prefix}: {expert['display_name']}",
            "labels": labels,
            "metadata": {
                "executor": expert.get("preferred_external_executor") if external else "internal_worker",
                "expert": expert["name"],
                "discipline": expert["discipline"],
                "job_description_label": expert["job_description_label"],
                "share_boundary": args.share_boundary,
                "codex_pickup": "forbidden" if external else "allowed",
                "architect_review_required": True,
            },
            "description": expert_description(expert, external, args.share_boundary),
        }
        reviews.append(review)

    if args.dry_run:
        print(json.dumps({"route": route, "planned_reviews": reviews}, indent=2, sort_keys=True))
        return

    if not reviews:
        print("No expert triggers matched; no review Beads created.")
        return

    for review in reviews:
        bead = create_bead(
            review["title"],
            parent=args.parent,
            priority=1,
            labels=review["labels"],
            description=review["description"],
            metadata=review["metadata"],
        )
        print(f"Created review task: {bead['id']} {bead['title']}")


if __name__ == "__main__":
    main()
