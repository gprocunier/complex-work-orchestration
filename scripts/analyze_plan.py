#!/usr/bin/env python3
"""Compare saved CWO plan artifacts without contacting the tracker."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from continue_sprint import VALIDATION_LABELS, coach_decisions, field, issue_labels, issue_type
from cwo_core.epic_convergence import load_records
from cwo_core.execution_status_report import load_json_document
from scaffold_workgraph import validate_workgraph_plan
from summarize_resume_state import parse_markdown_workgraph
from validate_operator_handoff import validate_text
from validate_run_readiness_plan import validate_plan


def load_workgraph(path: Path) -> list[dict[str, Any]]:
    if path.suffix.lower() == ".md":
        return parse_markdown_workgraph(path, include_route=True)
    graph = json.loads(path.read_text(encoding="utf-8"))
    validate_workgraph_plan(graph)
    if not graph or graph[0].get("type") != "epic":
        raise ValueError("provide the CWO scaffold JSON with an epic first")
    return graph


def route_errors(epic: dict[str, Any], route: dict[str, Any]) -> list[str]:
    planned = field(epic, "orchestration_route") or {}
    if not isinstance(planned, dict) or not isinstance(planned.get("route"), str):
        return ["Workgraph epic has no comparable route metadata."]
    if not isinstance(route.get("route"), str):
        return ["Supplied route has no comparable route identifier."]
    return [
        f"The route and workgraph disagree on {key}."
        for key in ("route", "share_boundary", "risk_level")
        if key in route and route[key] != planned.get(key)
    ]


def readiness_errors(plan: dict[str, Any]) -> list[str]:
    if errors := validate_plan(plan):
        return errors
    known = {f"criterion:{row['criterion'].strip()}" for row in plan["criterion_evidence_matrix"]}
    for row in plan["workstreams"]:
        missing = sorted({value for value in row["validation_refs"] if isinstance(value, str) and value.startswith("criterion:")} - known)
        if missing:
            errors.append(f"{row['name']} refers to missing validation evidence: {', '.join(missing)}")
    return errors


def analyze(args: argparse.Namespace) -> dict[str, Any]:
    graph = load_workgraph(args.workgraph)
    epic = next((item for item in graph if issue_type(item) == "epic"), {})
    findings: list[dict[str, Any]] = []
    coverage = {"workgraph_items": len(graph), "convergence_records": None, "artifacts": []}

    def check(finding_id: str, artifact: Path, errors: list[str], recommendation: str, *, severity: str = "error") -> None:
        if errors:
            findings.append({"id": finding_id, "severity": severity, "artifact": str(artifact),
                             "evidence": errors, "recommendation": recommendation})

    validation = [item for item in graph if VALIDATION_LABELS.intersection(issue_labels(item))]
    coverage["validation_lanes"] = len(validation)
    coverage["artifacts"] = [str(path) for path in vars(args).values() if path is not None]
    check("validation-lane-missing", args.workgraph, [] if validation else ["Workgraph has no validation lane."],
          "Add a validation lane with explicit evidence expectations.")
    if args.coach:
        coach = load_json_document(args.coach)
        check("operator-selection-open", args.coach, coach_decisions(coach), "Resolve the listed coach decisions before planning.")
        if isinstance(route := coach.get("route"), dict):
            check("coach-workgraph-mismatch", args.coach, route_errors(epic, route),
                  "Check that the saved coach result and workgraph describe the same scope.")
    if args.route:
        check("route-workgraph-mismatch", args.route, route_errors(epic, load_json_document(args.route)),
              "Check that the saved route and workgraph describe the same scope.")
    if args.readiness_plan:
        plan = load_json_document(args.readiness_plan)
        check("readiness-invalid", args.readiness_plan, readiness_errors(plan),
              "Repair the listed readiness and evidence requirements.")
        compare_readiness_scope(epic, plan, args.readiness_plan, check)
    if args.handoff:
        check("handoff-invalid", args.handoff, validate_text(args.handoff.read_text(encoding="utf-8")),
              "Complete the missing or invalid operator continuation fields.")
    if args.convergence_ledger:
        if not args.convergence_ledger.is_file():
            raise ValueError(f"convergence ledger does not exist: {args.convergence_ledger}")
        coverage["convergence_records"] = len(load_records(args.convergence_ledger))
    return {"findings": sorted(findings, key=lambda finding: (finding["severity"], finding["id"])), "coverage": coverage}


def compare_readiness_scope(epic: dict[str, Any], plan: dict[str, Any], path: Path, check: Any) -> None:
    scope = plan.get("beads_scope")
    plan_epic = scope.get("epic_id") if isinstance(scope, dict) else None
    graph_epic = field(epic, "id", "issue_id")
    if not isinstance(graph_epic, str) or graph_epic in {"", "epic"}:
        check("readiness-scope-unverified", path, ["The workgraph has no concrete epic ID to compare."],
              "Use a workgraph with the current epic ID to compare readiness scope.", severity="warning")
    elif isinstance(plan_epic, str) and plan_epic != graph_epic:
        check("readiness-workgraph-mismatch", path, ["The readiness plan and workgraph name different epic IDs."],
              "Use the readiness plan for the workgraph's epic.")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workgraph", type=Path, required=True, help="CWO scaffold JSON or Markdown fallback.")
    for artifact in ("coach", "route", "readiness-plan", "handoff", "convergence-ledger"):
        parser.add_argument(f"--{artifact}", type=Path)
    try:
        report = analyze(parser.parse_args())
    except (OSError, TypeError, ValueError) as exc:
        parser.error(str(exc))
    print(json.dumps(report, indent=2, sort_keys=True))
    raise SystemExit(any(finding["severity"] == "error" for finding in report["findings"]))


if __name__ == "__main__":
    main()
