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


def control_review_body(kind: str, route: dict[str, object]) -> str:
    return f"""Purpose:
Perform {kind} for the contractor or local-worker return before findings are used for implementation.

Share boundary:
{route['share_boundary']}

Provider conflict domains:
{', '.join(str(item) for item in route.get('provider_conflict_domains', [])) or 'none'}

Expected output:
- decision: pass, fail, disagreement, or blocked
- evidence for that decision
- boundary or provider-conflict concerns
- quarantine recommendation if applicable

Codex handling rule:
Codex may brief and evaluate this Bead, but must not execute it as contractor or local-worker review work.
"""


def control_review_tasks(title_prefix: str, route: dict[str, object]) -> list[dict[str, object]]:
    tasks: list[dict[str, object]] = []
    if route.get("peer_review_required"):
        tasks.append(
            {
                "title": f"{title_prefix}: Peer review gate",
                "labels": [
                    "local-worker-only",
                    "no-codex-exec",
                    "peer-review-required",
                    "contractor-peer-review",
                    "contract-jd-peer-review",
                ],
                "metadata": {
                    "job_description_label": "contract-jd-peer-review",
                    "executor": route.get("local_secure_review_executor"),
                    "provider_conflict_domains": route.get("provider_conflict_domains", []),
                    "peer_review_count": route.get("peer_review_count", 1),
                    "provider_diversity_required": route.get("provider_diversity_required", True),
                    "codex_pickup": "forbidden",
                    "acceptance_bead_required": True,
                    "architect_review_required": True,
                },
                "description": control_review_body("independent peer review", route),
            }
        )
    if route.get("provider_conflict_detected"):
        tasks.append(
            {
                "title": f"{title_prefix}: Sabotage review gate",
                "labels": [
                    "local-worker-only",
                    "no-codex-exec",
                    "sabotage-review",
                    "contract-jd-sabotage-review",
                ],
                "metadata": {
                    "job_description_label": "contract-jd-sabotage-review",
                    "executor": route.get("local_secure_review_executor"),
                    "provider_conflict_domains": route.get("provider_conflict_domains", []),
                    "codex_pickup": "forbidden",
                    "acceptance_bead_required": True,
                    "architect_review_required": True,
                },
                "description": control_review_body("sabotage and malpractice review", route),
            }
        )
    return tasks


def main() -> None:
    parser = argparse.ArgumentParser(description="Create expert review Beads from ranked routing.")
    parser.add_argument("text", nargs="*")
    parser.add_argument("--file")
    parser.add_argument("--parent")
    parser.add_argument("--title-prefix", default="Expert review")
    parser.add_argument("--external-ok", action="store_true")
    parser.add_argument("--local-ok", action="store_true", help="Permit low-risk local worker dispatch.")
    parser.add_argument("--prefer-local", action="store_true", help="Prefer local worker routing when policy permits it.")
    parser.add_argument("--local-profile", help="Require a named local executor profile, for example openshift-ai-vllm.")
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
        local_profile=args.local_profile,
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
    reviews.extend(control_review_tasks(args.title_prefix, route))

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
