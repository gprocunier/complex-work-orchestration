#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

REQUIRED_TOP_LEVEL = [
    "plan_type",
    "version",
    "run_id",
    "beads_scope",
    "artifact_authority",
    "workstreams",
    "rubric",
    "criterion_evidence_matrix",
    "provider_provenance",
    "quarantine_rules",
    "boundary_negative_tests",
    "next_version_rail",
    "patrol_stopping_rule",
    "handoff_evidence_requirements",
    "adjudication_record",
]
REQUIRED_BOUNDARY_TEST_INPUTS = {
    "raw_comments",
    "secrets",
    "full_bead_json",
    "unauthorized_mutation_claim",
    "unsupported_command_execution_claim",
}
REQUIRED_PROJECTION_TYPES = {"run-sheet", "wrap-up-status", "next-version"}
ALLOWED_PROVIDER_PROVENANCE_CLASSES = {
    "internal",
    "external-contractor",
    "local-worker",
    "unknown",
}
ALLOWED_PROVIDER_DISPOSITIONS = {
    "primary",
    "salvage-only",
    "rejected",
    "quarantined",
    "not-used",
}
ALLOWED_BOUNDARY_EXPECTED_RESULTS = {"reject", "quarantine", "fail-closed"}
ALLOWED_NEXT_VERSION_REASONS = {
    "out-of-scope",
    "needs-credential",
    "needs-research",
    "hardening",
    "later-version",
    "blocked",
}
REQUIRED_PATROL_EVIDENCE = {
    "ownership",
    "locking",
    "history",
    "failure_containment",
    "provider_neutral_execution",
}


def _nonempty_string(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def validate_plan(plan: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    for field in REQUIRED_TOP_LEVEL:
        if field not in plan:
            errors.append(f"missing required top-level field: {field}")

    if plan.get("plan_type") != "cwo-run-readiness-plan":
        errors.append("plan_type must be cwo-run-readiness-plan")
    if not isinstance(plan.get("version"), int) or isinstance(plan.get("version"), bool) or plan.get("version", 0) < 1:
        errors.append("version must be an integer greater than or equal to 1")
    if not _nonempty_string(plan.get("run_id")):
        errors.append("run_id is required")

    beads_scope = _dict(plan.get("beads_scope"))
    if beads_scope.get("canonical_source") != "beads":
        errors.append("beads_scope.canonical_source must be beads")
    if not _nonempty_string(beads_scope.get("epic_id")):
        errors.append("beads_scope.epic_id is required")

    authority = _dict(plan.get("artifact_authority"))
    if authority.get("canonical_source") != "beads":
        errors.append("artifact_authority.canonical_source must be beads")
    if authority.get("external_returns") != "evidence":
        errors.append("artifact_authority.external_returns must be evidence")
    if authority.get("final_authority") != "architect-adjudication":
        errors.append("artifact_authority.final_authority must be architect-adjudication")
    projection_types: set[str] = set()
    for index, item in enumerate(_list(authority.get("projections"))):
        projection = _dict(item)
        prefix = f"artifact_authority.projections[{index}]"
        if not _nonempty_string(projection.get("name")):
            errors.append(f"{prefix}.name is required")
        if projection.get("authority") != "projection":
            errors.append(f"{prefix}.authority must be projection")
        projection_type = projection.get("type")
        if projection_type in REQUIRED_PROJECTION_TYPES:
            projection_types.add(str(projection_type))
        else:
            errors.append(
                f"{prefix}.type must be one of: "
                + ", ".join(sorted(REQUIRED_PROJECTION_TYPES))
            )
        if projection.get("canonical_source") != "beads":
            errors.append(f"{prefix}.canonical_source must be beads")
        if not _nonempty_string(projection.get("source_command")) and not _nonempty_string(projection.get("source_bead")):
            errors.append(f"{prefix} must declare source_command or source_bead")
    missing_projections = sorted(REQUIRED_PROJECTION_TYPES - projection_types)
    if missing_projections:
        errors.append("artifact_authority.projections missing required projection type(s): " + ", ".join(missing_projections))

    workstreams = _list(plan.get("workstreams"))
    if not workstreams:
        errors.append("workstreams must contain at least one workstream")
    for index, item in enumerate(workstreams):
        workstream = _dict(item)
        prefix = f"workstreams[{index}]"
        for field in ["name", "owner", "exit_condition"]:
            if not _nonempty_string(workstream.get(field)):
                errors.append(f"{prefix}.{field} is required")
        if not _list(workstream.get("validation_refs")):
            errors.append(f"{prefix}.validation_refs must not be empty")
        if not _list(workstream.get("handoff_evidence")):
            errors.append(f"{prefix}.handoff_evidence must not be empty")

    rubric = _dict(plan.get("rubric"))
    for field in ["version", "owner", "schema_ref"]:
        if not _nonempty_string(rubric.get(field)):
            errors.append(f"rubric.{field} is required")
    if rubric.get("immutable_per_run") is not True:
        errors.append("rubric.immutable_per_run must be true")
    if rubric.get("evaluation_uses_version") is not True:
        errors.append("rubric.evaluation_uses_version must be true")
    rubric_criterion_ids = {
        str(item).strip()
        for item in _list(rubric.get("criterion_ids"))
        if str(item).strip()
    }
    if not rubric_criterion_ids:
        errors.append("rubric.criterion_ids must not be empty")

    matrix = _list(plan.get("criterion_evidence_matrix"))
    if not matrix:
        errors.append("criterion_evidence_matrix must contain at least one criterion")
    matrix_criteria: set[str] = set()
    for index, item in enumerate(matrix):
        criterion = _dict(item)
        prefix = f"criterion_evidence_matrix[{index}]"
        for field in ["criterion", "evidence", "owner"]:
            if not _nonempty_string(criterion.get(field)):
                errors.append(f"{prefix}.{field} is required")
        if _nonempty_string(criterion.get("criterion")):
            matrix_criteria.add(str(criterion.get("criterion")).strip())
        if criterion.get("evidence_type") not in {"artifact", "validator", "review-gate"}:
            errors.append(f"{prefix}.evidence_type must be artifact, validator, or review-gate")
    missing_matrix_criteria = sorted(rubric_criterion_ids - matrix_criteria)
    if missing_matrix_criteria:
        errors.append("criterion_evidence_matrix missing rubric criterion id(s): " + ", ".join(missing_matrix_criteria))
    extra_matrix_criteria = sorted(matrix_criteria - rubric_criterion_ids)
    if rubric_criterion_ids and extra_matrix_criteria:
        errors.append("criterion_evidence_matrix has criterion id(s) not declared in rubric: " + ", ".join(extra_matrix_criteria))

    if not _list(plan.get("provider_provenance")):
        errors.append("provider_provenance must record at least one provider or internal source")
    for index, item in enumerate(_list(plan.get("provider_provenance"))):
        source = _dict(item)
        prefix = f"provider_provenance[{index}]"
        for field in ["provider_key", "provider_family"]:
            if not _nonempty_string(source.get(field)):
                errors.append(f"{prefix}.{field} is required")
        if source.get("provenance_class") not in ALLOWED_PROVIDER_PROVENANCE_CLASSES:
            errors.append(
                f"{prefix}.provenance_class must be one of: "
                + ", ".join(sorted(ALLOWED_PROVIDER_PROVENANCE_CLASSES))
            )
        if source.get("disposition") not in ALLOWED_PROVIDER_DISPOSITIONS:
            errors.append(
                f"{prefix}.disposition must be one of: "
                + ", ".join(sorted(ALLOWED_PROVIDER_DISPOSITIONS))
            )

    quarantine_rules = _list(plan.get("quarantine_rules"))
    if not quarantine_rules:
        errors.append("quarantine_rules must contain at least one rule")
    for index, item in enumerate(quarantine_rules):
        rule = _dict(item)
        prefix = f"quarantine_rules[{index}]"
        if not _nonempty_string(rule.get("trigger")):
            errors.append(f"{prefix}.trigger is required")
        if rule.get("disposition") != "quarantine-until-adjudicated":
            errors.append(f"{prefix}.disposition must be quarantine-until-adjudicated")
        if not _nonempty_string(rule.get("release_condition")):
            errors.append(f"{prefix}.release_condition is required")

    boundary_inputs = {
        str(item.get("prohibited_input"))
        for item in _list(plan.get("boundary_negative_tests"))
        if isinstance(item, dict)
    }
    for index, item in enumerate(_list(plan.get("boundary_negative_tests"))):
        boundary_test = _dict(item)
        prefix = f"boundary_negative_tests[{index}]"
        for field in ["name", "validator"]:
            if not _nonempty_string(boundary_test.get(field)):
                errors.append(f"{prefix}.{field} is required")
        if boundary_test.get("expected_result") not in ALLOWED_BOUNDARY_EXPECTED_RESULTS:
            errors.append(
                f"{prefix}.expected_result must be one of: "
                + ", ".join(sorted(ALLOWED_BOUNDARY_EXPECTED_RESULTS))
            )
    missing_boundary = sorted(REQUIRED_BOUNDARY_TEST_INPUTS - boundary_inputs)
    if missing_boundary:
        errors.append("boundary_negative_tests missing prohibited input(s): " + ", ".join(missing_boundary))

    for index, item in enumerate(_list(plan.get("next_version_rail"))):
        entry = _dict(item)
        prefix = f"next_version_rail[{index}]"
        if entry.get("reason_type") not in ALLOWED_NEXT_VERSION_REASONS:
            errors.append(f"{prefix}.reason_type must be one of: " + ", ".join(sorted(ALLOWED_NEXT_VERSION_REASONS)))
        if not _nonempty_string(entry.get("followup_bead")):
            errors.append(f"{prefix}.followup_bead is required")

    patrol = _dict(plan.get("patrol_stopping_rule"))
    if patrol.get("research_only_until_accepted") is not True:
        errors.append("patrol_stopping_rule.research_only_until_accepted must be true")
    patrol_evidence = {
        str(item)
        for item in _list(patrol.get("required_acceptance_evidence"))
        if str(item).strip()
    }
    if not patrol_evidence:
        errors.append("patrol_stopping_rule.required_acceptance_evidence must not be empty")
    missing_patrol_evidence = sorted(REQUIRED_PATROL_EVIDENCE - patrol_evidence)
    if missing_patrol_evidence:
        errors.append(
            "patrol_stopping_rule.required_acceptance_evidence missing required evidence type(s): "
            + ", ".join(missing_patrol_evidence)
        )
    unknown_patrol_evidence = sorted(patrol_evidence - REQUIRED_PATROL_EVIDENCE)
    if unknown_patrol_evidence:
        errors.append(
            "patrol_stopping_rule.required_acceptance_evidence has unknown evidence type(s): "
            + ", ".join(unknown_patrol_evidence)
        )

    if not _list(plan.get("handoff_evidence_requirements")):
        errors.append("handoff_evidence_requirements must not be empty")

    adjudication = _dict(plan.get("adjudication_record"))
    if adjudication.get("decision_owner") != "architect":
        errors.append("adjudication_record.decision_owner must be architect")
    for field in ["accepted_findings", "rejected_findings", "quarantined_findings"]:
        if not isinstance(adjudication.get(field), list):
            errors.append(f"adjudication_record.{field} must be a list")

    return errors


def load_plan(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("run readiness plan must be a JSON object")
    return data


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate a CWO run readiness plan.")
    parser.add_argument("path", help="Path to a run-readiness JSON plan.")
    parser.add_argument("--json", action="store_true", help="Emit JSON result.")
    args = parser.parse_args(argv)

    path = Path(args.path)
    try:
        errors = validate_plan(load_plan(path))
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        errors = [str(exc)]

    result = {
        "result_type": "cwo-run-readiness-validation",
        "path": str(path),
        "valid": not errors,
        "errors": errors,
    }
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    elif errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
    else:
        print("Run readiness plan validation passed.")
    return 0 if not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
