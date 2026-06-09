#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json

from orchestration_lib import (
    classify_work,
    create_bead,
    expert_review_labels,
    expert_review_metadata,
    expert_uses_external_contract,
    read_text_arg,
)


def review_body(expert: dict[str, object], route: dict[str, object]) -> str:
    return f"""Purpose:
Perform {expert['display_name']} review for the assigned Bead.

Review stage:
{expert['review_stage']}

Job-description label:
{expert['job_description_label']}

Output contract:
{chr(10).join('- ' + str(item) for item in expert.get('output_contract', []))}

Acceptance checks:
{chr(10).join('- ' + str(item) for item in expert.get('acceptance_checks', []))}

Escalation rules:
{chr(10).join('- ' + str(item) for item in expert.get('escalation_rules', []))}

Share boundary:
{route['share_boundary']}

Codex handling rule:
{"Codex may brief and evaluate this Bead, but must not execute it as contractor work." if expert_uses_external_contract(expert, route.get('recommended_executor')) else "Codex may execute this as an internal expert-review task."}
"""


def main() -> None:
    parser = argparse.ArgumentParser(description="Create expert review Beads from ranked routing.")
    parser.add_argument("text", nargs="*")
    parser.add_argument("--file")
    parser.add_argument("--parent")
    parser.add_argument("--title-prefix", default="Expert review")
    parser.add_argument("--external-ok", action="store_true")
    parser.add_argument("--local-ok", action="store_true", help="Permit low-risk local worker dispatch.")
    parser.add_argument("--prefer-local", action="store_true", help="Prefer local worker routing when policy permits it.")
    parser.add_argument("--share-boundary", default="no-outside-sharing")
    parser.add_argument("--requested-role", action="append", default=[])
    parser.add_argument("--top-n", type=int, default=3)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    text = read_text_arg(" ".join(args.text).strip() or None, args.file)
    route = classify_work(
        text,
        external_ok=args.external_ok,
        local_ok=args.local_ok,
        prefer_local=args.prefer_local,
        share_boundary=args.share_boundary,
        requested_roles=args.requested_role,
    )
    reviews = []
    for expert in route.get("ranked_experts", [])[: args.top_n]:
        reviews.append(
            {
                "title": f"{args.title_prefix}: {expert['display_name']}",
                "labels": expert_review_labels(expert, route),
                "metadata": expert_review_metadata(expert, route),
                "description": review_body(expert, route),
            }
        )

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
