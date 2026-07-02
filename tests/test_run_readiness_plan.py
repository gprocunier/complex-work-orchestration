from __future__ import annotations

import copy
import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from validate_run_readiness_plan import validate_plan  # noqa: E402


def sample_plan() -> dict[str, object]:
    return json.loads((ROOT / "examples" / "sample-run-readiness-plan.json").read_text(encoding="utf-8"))


class RunReadinessPlanTests(unittest.TestCase):
    def test_sample_plan_is_valid(self) -> None:
        self.assertEqual(validate_plan(sample_plan()), [])

    def test_workstreams_require_owner_exit_and_handoff_evidence(self) -> None:
        plan = copy.deepcopy(sample_plan())
        plan["workstreams"][0]["owner"] = ""
        plan["workstreams"][0]["exit_condition"] = ""
        plan["workstreams"][0]["handoff_evidence"] = []

        errors = validate_plan(plan)
        rendered = "\n".join(errors)
        self.assertIn("workstreams[0].owner is required", rendered)
        self.assertIn("workstreams[0].exit_condition is required", rendered)
        self.assertIn("workstreams[0].handoff_evidence must not be empty", rendered)

    def test_top_level_version_and_run_id_match_schema_constraints(self) -> None:
        plan = copy.deepcopy(sample_plan())
        plan["version"] = 0
        plan["run_id"] = ""

        errors = "\n".join(validate_plan(plan))
        self.assertIn("version must be an integer greater than or equal to 1", errors)
        self.assertIn("run_id is required", errors)

    def test_boundary_negative_tests_cover_required_failure_modes(self) -> None:
        plan = copy.deepcopy(sample_plan())
        plan["boundary_negative_tests"] = [
            item for item in plan["boundary_negative_tests"] if item["prohibited_input"] != "raw_comments"
        ]

        errors = validate_plan(plan)
        self.assertTrue(any("raw_comments" in error for error in errors))

    def test_boundary_negative_tests_validate_expected_result_enum(self) -> None:
        plan = copy.deepcopy(sample_plan())
        plan["boundary_negative_tests"][0]["expected_result"] = "ignore"

        errors = "\n".join(validate_plan(plan))
        self.assertIn("boundary_negative_tests[0].expected_result must be one of:", errors)
        self.assertIn("fail-closed", errors)

    def test_provider_provenance_validates_schema_enums(self) -> None:
        plan = copy.deepcopy(sample_plan())
        plan["provider_provenance"][0]["provenance_class"] = "friend"
        plan["provider_provenance"][0]["disposition"] = "maybe"

        errors = "\n".join(validate_plan(plan))
        self.assertIn("provider_provenance[0].provenance_class must be one of:", errors)
        self.assertIn("external-contractor", errors)
        self.assertIn("provider_provenance[0].disposition must be one of:", errors)
        self.assertIn("salvage-only", errors)

    def test_rubric_must_be_immutable_per_run(self) -> None:
        plan = copy.deepcopy(sample_plan())
        plan["rubric"]["immutable_per_run"] = False

        self.assertIn("rubric.immutable_per_run must be true", validate_plan(plan))

    def test_artifact_authority_requires_typed_beads_projections(self) -> None:
        plan = copy.deepcopy(sample_plan())
        plan["artifact_authority"]["projections"] = [
            item for item in plan["artifact_authority"]["projections"] if item["type"] != "next-version"
        ]

        errors = "\n".join(validate_plan(plan))
        self.assertIn("missing required projection type(s): next-version", errors)

    def test_projection_requires_beads_source_pointer(self) -> None:
        plan = copy.deepcopy(sample_plan())
        projection = plan["artifact_authority"]["projections"][0]
        projection["canonical_source"] = "flat-file"
        projection.pop("source_command")

        errors = "\n".join(validate_plan(plan))
        self.assertIn("artifact_authority.projections[0].canonical_source must be beads", errors)
        self.assertIn("artifact_authority.projections[0] must declare source_command or source_bead", errors)

    def test_adjudication_findings_require_bound_evidence_refs(self) -> None:
        plan = copy.deepcopy(sample_plan())
        plan["adjudication_record"].pop("evidence_refs", None)

        errors = "\n".join(validate_plan(plan))
        self.assertIn("adjudication_record.evidence_refs must bind adjudicated findings", errors)

    def test_adjudication_evidence_refs_require_known_type_and_sha(self) -> None:
        plan = copy.deepcopy(sample_plan())
        plan["adjudication_record"]["evidence_refs"][0]["artifact_type"] = "note"
        plan["adjudication_record"]["evidence_refs"][0]["sha256"] = "not-a-sha"

        errors = "\n".join(validate_plan(plan))
        self.assertIn("adjudication_record.evidence_refs[0].artifact_type must be one of:", errors)
        self.assertIn("adjudication_record.evidence_refs[0].sha256 must be a lowercase SHA-256 hex digest", errors)

    def test_rubric_criterion_ids_must_match_evidence_matrix(self) -> None:
        plan = copy.deepcopy(sample_plan())
        plan["rubric"]["criterion_ids"].append("missing-criterion")
        plan["criterion_evidence_matrix"].append(
            {
                "criterion": "undeclared-criterion",
                "evidence_type": "validator",
                "evidence": "python scripts/validate_run_readiness_plan.py examples/sample-run-readiness-plan.json",
                "owner": "validation",
            }
        )

        errors = "\n".join(validate_plan(plan))
        self.assertIn("criterion_evidence_matrix missing rubric criterion id(s): missing-criterion", errors)
        self.assertIn("criterion_evidence_matrix has criterion id(s) not declared in rubric: undeclared-criterion", errors)

    def test_next_version_reason_type_must_use_allowed_enum(self) -> None:
        plan = copy.deepcopy(sample_plan())
        plan["next_version_rail"][0]["reason_type"] = "maybe-later"

        errors = "\n".join(validate_plan(plan))
        self.assertIn("next_version_rail[0].reason_type must be one of:", errors)
        self.assertIn("needs-research", errors)

    def test_patrol_acceptance_evidence_must_cover_required_types(self) -> None:
        plan = copy.deepcopy(sample_plan())
        plan["patrol_stopping_rule"]["required_acceptance_evidence"] = ["ownership", "unexpected"]

        errors = "\n".join(validate_plan(plan))
        self.assertIn("missing required evidence type(s):", errors)
        self.assertIn("provider_neutral_execution", errors)
        self.assertIn("has unknown evidence type(s): unexpected", errors)

    def test_cli_validates_sample_plan(self) -> None:
        result = subprocess.run(
            [
                sys.executable,
                str(ROOT / "scripts" / "validate_run_readiness_plan.py"),
                str(ROOT / "examples" / "sample-run-readiness-plan.json"),
                "--json",
            ],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        )

        payload = json.loads(result.stdout)
        self.assertTrue(payload["valid"])
        self.assertEqual(payload["errors"], [])


if __name__ == "__main__":
    unittest.main()
