#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from validate_run_readiness_plan import load_plan, validate_plan

PROJECTION_TYPES = {"run-sheet", "wrap-up-status", "next-version"}
PROJECTION_ALIASES = {
    "run-sheet": "run-sheet",
    "wrap-up": "wrap-up-status",
    "wrap-up-status": "wrap-up-status",
    "next-version": "next-version",
}


def _items(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _strings(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if str(item).strip()]


def _projection_contract(plan: dict[str, Any], projection_type: str) -> dict[str, Any]:
    authority = plan.get("artifact_authority") if isinstance(plan.get("artifact_authority"), dict) else {}
    for item in _items(authority.get("projections")):
        if item.get("type") == projection_type:
            return item
    return {}


def _base_projection(plan: dict[str, Any], projection_type: str, source_path: Path) -> dict[str, Any]:
    beads_scope = plan.get("beads_scope") if isinstance(plan.get("beads_scope"), dict) else {}
    return {
        "result_type": "cwo-run-projection",
        "projection_type": projection_type,
        "authority": "projection",
        "canonical_source": "beads",
        "projection_source": "run-readiness-plan",
        "beads_derivation": "declared-by-validated-readiness-plan",
        "projection_contract": _projection_contract(plan, projection_type),
        "source_plan": str(source_path),
        "run_id": plan.get("run_id"),
        "plan_version": plan.get("version"),
        "epic_id": beads_scope.get("epic_id"),
        "implementation_bead": beads_scope.get("implementation_bead"),
        "dolt_remote": beads_scope.get("dolt_remote"),
    }


def build_projection(plan: dict[str, Any], projection_type: str, source_path: Path) -> dict[str, Any]:
    if projection_type not in PROJECTION_TYPES:
        raise ValueError(f"unsupported projection type: {projection_type}")

    projection = _base_projection(plan, projection_type, source_path)
    authority = plan.get("artifact_authority") if isinstance(plan.get("artifact_authority"), dict) else {}
    adjudication = plan.get("adjudication_record") if isinstance(plan.get("adjudication_record"), dict) else {}

    if projection_type == "run-sheet":
        projection.update(
            {
                "title": f"CWO Run Sheet Projection: {plan.get('run_id')}",
                "purpose": "Worker handoff view generated from a validated run readiness plan.",
                "artifact_authority": authority,
                "workstreams": _items(plan.get("workstreams")),
                "rubric": plan.get("rubric") if isinstance(plan.get("rubric"), dict) else {},
                "criterion_evidence_matrix": _items(plan.get("criterion_evidence_matrix")),
                "handoff_evidence_requirements": _strings(plan.get("handoff_evidence_requirements")),
            }
        )
    elif projection_type == "wrap-up-status":
        projection.update(
            {
                "title": f"CWO Wrap-Up/Status Projection: {plan.get('run_id')}",
                "purpose": "Major-run closure view generated from readiness, validation, and adjudication evidence.",
                "accepted_findings": _strings(adjudication.get("accepted_findings")),
                "rejected_findings": _strings(adjudication.get("rejected_findings")),
                "quarantined_findings": _strings(adjudication.get("quarantined_findings")),
                "provider_provenance": _items(plan.get("provider_provenance")),
                "quarantine_rules": _items(plan.get("quarantine_rules")),
                "validation_evidence": _items(plan.get("criterion_evidence_matrix")),
                "next_version_rail": _items(plan.get("next_version_rail")),
                "handoff_evidence_requirements": _strings(plan.get("handoff_evidence_requirements")),
            }
        )
    else:
        projection.update(
            {
                "title": f"CWO Next-Version Rail Projection: {plan.get('run_id')}",
                "purpose": "Deferred-work view generated from typed next-version entries in the readiness plan.",
                "next_version_rail": _items(plan.get("next_version_rail")),
                "patrol_stopping_rule": plan.get("patrol_stopping_rule")
                if isinstance(plan.get("patrol_stopping_rule"), dict)
                else {},
            }
        )

    return projection


def _bullet_lines(items: list[str]) -> list[str]:
    return [f"- {item}" for item in items] or ["- None recorded."]


def _render_table(headers: list[str], rows: list[list[str]]) -> list[str]:
    rendered = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join("---" for _ in headers) + " |",
    ]
    if not rows:
        rendered.append("| " + " | ".join("None recorded." if index == 0 else "" for index, _ in enumerate(headers)) + " |")
        return rendered
    for row in rows:
        rendered.append("| " + " | ".join(cell.replace("\n", " ") for cell in row) + " |")
    return rendered


def render_markdown(projection: dict[str, Any]) -> str:
    lines = [
        f"# {projection['title']}",
        "",
        f"- Run ID: `{projection.get('run_id')}`",
        f"- Epic: `{projection.get('epic_id')}`",
        f"- Authority: `{projection.get('authority')}` from `{projection.get('canonical_source')}`",
        f"- Source plan: `{projection.get('source_plan')}`",
        "",
        projection["purpose"],
        "",
    ]

    projection_type = projection["projection_type"]
    if projection_type == "run-sheet":
        lines.extend(["## Workstreams", ""])
        rows = [
            [
                str(item.get("name", "")),
                str(item.get("owner", "")),
                str(item.get("exit_condition", "")),
                ", ".join(_strings(item.get("validation_refs"))),
                ", ".join(_strings(item.get("handoff_evidence"))),
            ]
            for item in _items(projection.get("workstreams"))
        ]
        lines.extend(_render_table(["Name", "Owner", "Exit", "Validation", "Handoff"], rows))
        rubric = projection.get("rubric") if isinstance(projection.get("rubric"), dict) else {}
        lines.extend(
            [
                "",
                "## Rubric",
                "",
                f"- Version: `{rubric.get('version')}`",
                f"- Owner: `{rubric.get('owner')}`",
                f"- Schema: `{rubric.get('schema_ref')}`",
                f"- Immutable per run: `{rubric.get('immutable_per_run')}`",
                f"- Evaluation uses version: `{rubric.get('evaluation_uses_version')}`",
                "",
                "## Criterion Evidence Matrix",
                "",
            ]
        )
        rows = [
            [
                str(item.get("criterion", "")),
                str(item.get("evidence_type", "")),
                str(item.get("evidence", "")),
                str(item.get("owner", "")),
            ]
            for item in _items(projection.get("criterion_evidence_matrix"))
        ]
        lines.extend(_render_table(["Criterion", "Evidence type", "Evidence", "Owner"], rows))
        lines.extend(["", "## Handoff Evidence Requirements", ""])
        lines.extend(_bullet_lines(_strings(projection.get("handoff_evidence_requirements"))))

    elif projection_type == "wrap-up-status":
        lines.extend(["## Architect Adjudication", "", "### Accepted", ""])
        lines.extend(_bullet_lines(_strings(projection.get("accepted_findings"))))
        lines.extend(["", "### Rejected", ""])
        lines.extend(_bullet_lines(_strings(projection.get("rejected_findings"))))
        lines.extend(["", "### Quarantined", ""])
        lines.extend(_bullet_lines(_strings(projection.get("quarantined_findings"))))
        lines.extend(["", "## Provider Provenance", ""])
        rows = [
            [
                str(item.get("provider_key", "")),
                str(item.get("provider_family", "")),
                str(item.get("provenance_class", "")),
                str(item.get("disposition", "")),
            ]
            for item in _items(projection.get("provider_provenance"))
        ]
        lines.extend(_render_table(["Provider", "Family", "Provenance", "Disposition"], rows))
        lines.extend(["", "## Validation Evidence", ""])
        rows = [
            [
                str(item.get("criterion", "")),
                str(item.get("evidence_type", "")),
                str(item.get("evidence", "")),
                str(item.get("owner", "")),
            ]
            for item in _items(projection.get("validation_evidence"))
        ]
        lines.extend(_render_table(["Criterion", "Evidence type", "Evidence", "Owner"], rows))
        lines.extend(["", "## Next-Version Rail", ""])
        lines.extend(_render_next_version_items(_items(projection.get("next_version_rail"))))

    else:
        lines.extend(["## Deferred Items", ""])
        lines.extend(_render_next_version_items(_items(projection.get("next_version_rail"))))
        patrol = projection.get("patrol_stopping_rule") if isinstance(projection.get("patrol_stopping_rule"), dict) else {}
        lines.extend(
            [
                "",
                "## Patrol Stopping Rule",
                "",
                f"- Research only until accepted: `{patrol.get('research_only_until_accepted')}`",
                "- Required acceptance evidence:",
            ]
        )
        lines.extend(_bullet_lines(_strings(patrol.get("required_acceptance_evidence"))))

    lines.append("")
    return "\n".join(lines)


def _render_next_version_items(items: list[dict[str, Any]]) -> list[str]:
    rows = [
        [
            str(item.get("item", "")),
            str(item.get("reason_type", "")),
            str(item.get("followup_bead", "")),
        ]
        for item in items
    ]
    return _render_table(["Item", "Reason", "Follow-up Bead"], rows)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Render projection views from a validated CWO run readiness plan.")
    parser.add_argument("path", help="Path to a run-readiness JSON plan.")
    parser.add_argument("--projection", choices=sorted(PROJECTION_ALIASES), default="run-sheet")
    parser.add_argument("--format", choices=["markdown", "json"], default="markdown")
    args = parser.parse_args(argv)

    path = Path(args.path)
    try:
        plan = load_plan(path)
        errors = validate_plan(plan)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        errors = [str(exc)]
        plan = {}

    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1

    projection_type = PROJECTION_ALIASES[args.projection]
    projection = build_projection(plan, projection_type, path)
    if args.format == "json":
        print(json.dumps(projection, indent=2, sort_keys=True))
    else:
        print(render_markdown(projection))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
