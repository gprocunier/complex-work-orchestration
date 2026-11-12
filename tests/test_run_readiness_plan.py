from __future__ import annotations

import copy
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from cwo_core import requirement_baseline as rb  # noqa: E402
import validate_run_readiness_plan as readiness  # noqa: E402
from validate_run_readiness_plan import validate_plan  # noqa: E402


def sample_plan() -> dict[str, object]:
    return json.loads((ROOT / "examples" / "sample-run-readiness-plan.json").read_text(encoding="utf-8"))


class RunReadinessPlanTests(unittest.TestCase):
    def test_plan_contract_rows(self) -> None:
        rows = (
            ("test_sample_plan_is_valid", None, None, (), ()),
            ("test_workstreams_require_owner_exit_and_handoff_evidence", None,
             lambda plan: plan["workstreams"][0].update(owner="", exit_condition="", handoff_evidence=[]), (
                 "workstreams[0].owner is required",
                 "workstreams[0].exit_condition is required",
                 "workstreams[0].handoff_evidence must not be empty",
             ), ()),
            ("test_top_level_version_and_run_id_match_schema_constraints", None,
             lambda plan: plan.update(version=0, run_id=""), (
                 "version must be an integer greater than or equal to 1", "run_id is required",
             ), ()),
            ("test_boundary_negative_tests_cover_required_failure_modes", None,
             lambda plan: plan.update(boundary_negative_tests=[
                 item for item in plan["boundary_negative_tests"] if item["prohibited_input"] != "raw_comments"
             ]), (), ("raw_comments",)),
            ("test_readiness_plan_enum_refusal_variants",
             "test_boundary_negative_tests_validate_expected_result_enum",
             lambda plan: plan["boundary_negative_tests"][0].update(expected_result="ignore"), (
                 "boundary_negative_tests[0].expected_result must be one of:", "fail-closed",
             ), ()),
            ("test_readiness_plan_enum_refusal_variants",
             "test_next_version_reason_type_must_use_allowed_enum",
             lambda plan: plan["next_version_rail"][0].update(reason_type="maybe-later"), (
                 "next_version_rail[0].reason_type must be one of:", "needs-research",
             ), ()),
            ("test_provider_provenance_validates_schema_enums", None,
             lambda plan: plan["provider_provenance"][0].update(provenance_class="friend", disposition="maybe"), (
                 "provider_provenance[0].provenance_class must be one of:", "external-contractor",
                 "provider_provenance[0].disposition must be one of:", "salvage-only",
             ), ()),
            ("test_rubric_must_be_immutable_per_run", None,
             lambda plan: plan["rubric"].update(immutable_per_run=False), (), ()),
            ("test_artifact_authority_requires_typed_beads_projections", None,
             lambda plan: plan["artifact_authority"].update(projections=[
                 item for item in plan["artifact_authority"]["projections"] if item["type"] != "next-version"
             ]), ("missing required projection type(s): next-version",), ()),
            ("test_projection_requires_beads_source_pointer", None,
             lambda plan: (
                 plan["artifact_authority"]["projections"][0].update(canonical_source="flat-file"),
                 plan["artifact_authority"]["projections"][0].pop("source_command"),
             ), (
                 "artifact_authority.projections[0].canonical_source must be beads",
                 "artifact_authority.projections[0] must declare source_command or source_bead",
             ), ()),
            ("test_adjudication_findings_require_bound_evidence_refs", None,
             lambda plan: plan["adjudication_record"].pop("evidence_refs", None), (
                 "adjudication_record.evidence_refs must bind adjudicated findings",
             ), ()),
            ("test_adjudication_evidence_refs_require_known_type_and_sha", None,
             lambda plan: plan["adjudication_record"]["evidence_refs"][0].update(artifact_type="note", sha256="not-a-sha"), (
                 "adjudication_record.evidence_refs[0].artifact_type must be one of:",
                 "adjudication_record.evidence_refs[0].sha256 must be a lowercase SHA-256 hex digest",
             ), ()),
            ("test_rubric_criterion_ids_must_match_evidence_matrix", None,
             lambda plan: (
                 plan["rubric"]["criterion_ids"].append("missing-criterion"),
                 plan["criterion_evidence_matrix"].append({
                     "criterion": "undeclared-criterion",
                     "evidence_type": "validator",
                     "evidence": "python scripts/validate_run_readiness_plan.py examples/sample-run-readiness-plan.json",
                     "owner": "validation",
                 }),
             ), (
                 "criterion_evidence_matrix missing rubric criterion id(s): missing-criterion",
                 "criterion_evidence_matrix has criterion id(s) not declared in rubric: undeclared-criterion",
             ), ()),
            ("test_patrol_acceptance_evidence_must_cover_required_types", None,
             lambda plan: plan["patrol_stopping_rule"].update(required_acceptance_evidence=["ownership", "unexpected"]), (
                 "missing required evidence type(s):", "provider_neutral_execution",
                 "has unknown evidence type(s): unexpected",
             ), ()),
        )
        template = sample_plan()
        for original, variant, mutate, contains, any_contains in rows:
            with self.subTest(original=original, variant=variant):
                plan = copy.deepcopy(template)
                if mutate is not None:
                    mutate(plan)
                errors = validate_plan(plan)
                if mutate is None:
                    self.assertEqual(errors, [])
                if original == "test_rubric_must_be_immutable_per_run":
                    self.assertIn("rubric.immutable_per_run must be true", errors)
                rendered = "\n".join(errors)
                for diagnostic in contains:
                    self.assertIn(diagnostic, rendered)
                for diagnostic in any_contains:
                    self.assertTrue(any(diagnostic in error for error in errors))

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


BASELINE_FIXTURES = ROOT / "tests" / "fixtures" / "requirement-baseline"


def baseline_fixture(name: str) -> dict:
    return json.loads((BASELINE_FIXTURES / name).read_text(encoding="utf-8"))


def baseline_digest(record: dict) -> str:
    payload = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def plan_following(record: dict) -> dict:
    """The sample plan, rewritten to follow ``record``: its rubric lists exactly the required criteria."""
    plan = copy.deepcopy(sample_plan())
    required = [item for item in record["criteria"] if item["applicability"] == "required"]
    plan["requirement_baseline"] = {
        "record_type": "cwo-requirement-baseline",
        "bead_id": record["bead_id"],
        "version": record["baseline_version"],
        "digest": baseline_digest(record),
    }
    plan["rubric"]["criterion_ids"] = [item["id"] for item in required]
    plan["criterion_evidence_matrix"] = [
        {"criterion": item["id"], "evidence_type": item["evidence_kind"], "evidence": "planned: " + item["expected_outcome"],
         "owner": "validation"}
        for item in required
    ]
    return plan


class RequirementBaselineContinuityTests(unittest.TestCase):
    """A plan that names a requirement baseline is checked against it, never only against itself."""

    def setUp(self) -> None:
        self.baseline = baseline_fixture("baseline-v1.json")
        self.amendment = baseline_fixture("amendment-adds-criterion.json")
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)

    def write(self, name: str, value: object) -> str:
        path = self.root / name
        path.write_text(json.dumps(value), encoding="utf-8")
        return str(path)

    def validate(self, plan: dict, *extra: str) -> tuple[int, dict]:
        result = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "validate_run_readiness_plan.py"), self.write("plan.json", plan), "--json", *extra],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )
        try:
            payload = json.loads(result.stdout)
        except json.JSONDecodeError:
            payload = {"errors": [result.stderr]}
        return result.returncode, payload

    def assert_refused(self, plan: dict, expected: str, *extra: str) -> None:
        code, payload = self.validate(plan, *extra)
        self.assertEqual(code, 1, payload)
        self.assertFalse(payload.get("valid"), payload)
        self.assertIn(expected, "\n".join(payload["errors"]))

    def utf8_chain_paths(self) -> tuple[Path, Path, dict]:
        baseline = copy.deepcopy(self.baseline)
        baseline["criteria"][0]["requirement"] += " Le café reste lisible."
        amendment = copy.deepcopy(self.amendment)
        amendment["baseline"]["criteria"][0] = copy.deepcopy(baseline["criteria"][0])
        amendment["prior_digest"] = baseline_digest(baseline)
        amendment["rationale"] = "Ajout après révision."
        self.assertEqual(rb.baseline_errors(baseline), [])
        self.assertEqual(rb.amendment_errors(baseline, amendment), [])
        baseline_path = self.root / "utf8-baseline.json"
        amendment_path = self.root / "utf8-amendment.json"
        for path, record in ((baseline_path, baseline), (amendment_path, amendment)):
            path.write_text(json.dumps(record, ensure_ascii=False), encoding="utf-8")
        chain = rb.resolve_chain(baseline, [amendment])
        self.assertEqual(readiness.load_baseline_chain(baseline_path, []), rb.resolve_chain(baseline))
        self.assertEqual(readiness.load_baseline_chain(baseline_path, [amendment_path]), chain)
        self.assertEqual(chain["version"], 2)
        self.assertEqual(chain["amendment_ids"], ["add-changelog"])
        return baseline_path, amendment_path, chain

    def test_utf8_chain_read_failures_are_domain_errors_before_resolution(self) -> None:
        baseline_path, _, _ = self.utf8_chain_paths()
        invalid_path = self.root / "invalid-utf8.json"
        invalid_path.write_bytes(b'{"version":"\xff"}')
        for initial, amendments in ((invalid_path, []), (baseline_path, [invalid_path])):
            with self.subTest(initial=initial.name, amendments=amendments):
                with patch.object(readiness, "resolve_chain", wraps=rb.resolve_chain) as resolve:
                    failure = None
                    try:
                        readiness.load_baseline_chain(initial, amendments)
                    except (rb.RequirementBaselineError, UnicodeDecodeError) as exc:
                        failure = exc
                    resolve.assert_not_called()
                    self.assertIsInstance(failure, rb.RequirementBaselineError)
                    self.assertIsInstance(failure.__cause__, UnicodeDecodeError)
                    self.assertEqual(failure.errors, [f"cannot read input {invalid_path}: {failure.__cause__}"])

    def test_a_plan_naming_a_baseline_cannot_pass_without_it(self) -> None:
        self.assert_refused(plan_following(self.baseline), "supply it with --baseline")

    def test_a_plan_that_follows_its_baseline_passes_and_reports_it(self) -> None:
        code, payload = self.validate(plan_following(self.baseline), "--baseline", self.write("b.json", self.baseline))
        self.assertEqual((code, payload["errors"]), (0, []))
        self.assertEqual(payload["requirement_baseline"]["digest"], baseline_digest(self.baseline))
        self.assertEqual(payload["requirement_baseline"]["amendment_ids"], [])

    def test_readiness_main_reports_utf8_domain_refusals(self) -> None:
        baseline_path, amendment_path, chain = self.utf8_chain_paths()
        plan = plan_following(chain["baseline"])
        code, payload = self.validate(
            plan, "--baseline", str(baseline_path), "--amendment", str(amendment_path),
        )
        self.assertEqual((code, payload["errors"]), (0, []))
        self.assertEqual(payload["requirement_baseline"]["digest"], chain["digest"])
        self.assertEqual(payload["requirement_baseline"]["amendment_ids"], ["add-changelog"])
        invalid = self.root / "invalid-utf8.json"
        invalid.write_bytes(b"\xff")
        for initial, amendments in ((invalid, []), (baseline_path, [invalid])):
            with self.subTest(initial=initial.name, amendments=amendments):
                extra = ["--baseline", str(initial)]
                for path in amendments:
                    extra.extend(["--amendment", str(path)])
                code, payload = self.validate(plan, *extra)
                self.assertEqual(code, 1)
                self.assertIs(payload["valid"], False)
                self.assertEqual(payload["result_type"], "cwo-run-readiness-validation")
                self.assertNotIn("requirement_baseline", payload)
                self.assertEqual(len(payload["errors"]), 1)
                self.assertTrue(
                    payload["errors"][0].startswith(f"requirement baseline: cannot read input {invalid}: "),
                )

    def test_a_plan_that_follows_an_amended_baseline_passes(self) -> None:
        plan = plan_following(self.amendment["baseline"])
        code, payload = self.validate(
            plan, "--baseline", self.write("b.json", self.baseline), "--amendment", self.write("a.json", self.amendment)
        )
        self.assertEqual((code, payload["errors"]), (0, []))
        self.assertEqual(payload["requirement_baseline"]["version"], 2)
        self.assertEqual(payload["requirement_baseline"]["amendment_ids"], ["add-changelog"])

    def test_missing_record_paths_keep_oserror_before_resolution(self) -> None:
        baseline_path, _, _ = self.utf8_chain_paths()
        missing = self.root / "missing-record.json"
        for initial, amendments in ((missing, []), (baseline_path, [missing])):
            with self.subTest(initial=initial.name, amendments=amendments), \
                    patch.object(readiness, "resolve_chain", wraps=rb.resolve_chain) as resolve:
                with self.assertRaises(FileNotFoundError) as caught:
                    readiness.load_baseline_chain(initial, amendments)
                resolve.assert_not_called()
                self.assertEqual(caught.exception.filename, str(missing))

    def test_requirement_criterion_refusal_rows(self) -> None:
        rows = (
            ("test_an_omitted_required_criterion_is_refused", "omit", ("omits required baseline criterion service-retired",)),
            ("test_a_replaced_or_invented_criterion_is_refused", "replace", (
                "rename-in-code, which is not in the requirement baseline",
                "omits required baseline criterion rename-complete",
            )),
            ("test_a_not_applicable_criterion_is_not_planned_as_required", "not-applicable", ("which the baseline marks not-applicable",)),
            ("test_evidence_of_another_kind_is_refused", "evidence-kind", ("requires 'review-gate' evidence for docs-name-reviewed",)),
        )
        baseline = self.write("b.json", self.baseline)
        for row_id, kind, diagnostics in rows:
            with self.subTest(row=row_id):
                plan = plan_following(self.baseline)
                if kind == "omit":
                    plan["rubric"]["criterion_ids"].remove("service-retired")
                    plan["criterion_evidence_matrix"] = [row for row in plan["criterion_evidence_matrix"] if row["criterion"] != "service-retired"]
                elif kind == "replace":
                    plan["rubric"]["criterion_ids"] = ["rename-in-code" if item == "rename-complete" else item for item in plan["rubric"]["criterion_ids"]]
                    for row in plan["criterion_evidence_matrix"]:
                        if row["criterion"] == "rename-complete":
                            row["criterion"] = "rename-in-code"
                elif kind == "not-applicable":
                    plan["rubric"]["criterion_ids"].append("windows-installer")
                    plan["criterion_evidence_matrix"].append(
                        {"criterion": "windows-installer", "evidence_type": "artifact", "evidence": "installer", "owner": "validation"}
                    )
                else:
                    for row in plan["criterion_evidence_matrix"]:
                        if row["criterion"] == "docs-name-reviewed":
                            row["evidence_type"] = "validator"
                for diagnostic in diagnostics:
                    self.assert_refused(plan, diagnostic, "--baseline", baseline)

    def test_a_stale_or_different_baseline_is_refused(self) -> None:
        baseline = self.write("b.json", self.baseline)
        amendment = self.write("a.json", self.amendment)
        self.assert_refused(plan_following(self.baseline), "resolves to", "--baseline", baseline, "--amendment", amendment)
        self.assert_refused(plan_following(self.amendment["baseline"]), "resolves to", "--baseline", baseline)
        other = copy.deepcopy(self.baseline)
        other["bead_id"] = "proj-other"
        self.assert_refused(plan_following(self.baseline), "baseline is for 'proj-other'", "--baseline", self.write("o.json", other))

    def test_a_supplied_baseline_must_be_the_one_the_plan_names(self) -> None:
        self.assert_refused(sample_plan(), "the plan does not name one", "--baseline", self.write("b.json", self.baseline))
        self.assert_refused(sample_plan(), "--amendment needs --baseline", "--amendment", self.write("a.json", self.amendment))

    def test_an_unsupported_amendment_is_refused(self) -> None:
        new = copy.deepcopy(self.baseline)
        new["baseline_version"] = 2
        new["criteria"] = [item for item in new["criteria"] if item["id"] != "service-retired"]
        amendment = dict(
            self.amendment,
            removed_criterion_ids=["service-retired"],
            added_criterion_ids=[],
            baseline=new,
        )
        self.assert_refused(
            plan_following(new),
            "only amendments that add criteria are supported",
            "--baseline",
            self.write("b.json", self.baseline),
            "--amendment",
            self.write("a.json", amendment),
        )

    def test_a_malformed_reference_is_refused_by_plan_validation(self) -> None:
        cases = {
            "not an object": "sha256:" + "0" * 64,
            "short digest": {"record_type": "cwo-requirement-baseline", "bead_id": "proj-abc", "version": 1, "digest": "sha256:00"},
            "no bead": {"record_type": "cwo-requirement-baseline", "version": 1, "digest": "sha256:" + "0" * 64},
            "boolean version": {"record_type": "cwo-requirement-baseline", "bead_id": "proj-abc", "version": True,
                                "digest": "sha256:" + "0" * 64},
            "extra field": {**plan_following(self.baseline)["requirement_baseline"], "status": "passed"},
        }
        for name, reference in cases.items():
            with self.subTest(case=name):
                plan = copy.deepcopy(sample_plan())
                plan["requirement_baseline"] = reference
                self.assertTrue(any("requirement_baseline" in error for error in validate_plan(plan)))

    def test_a_plan_without_a_baseline_still_validates_as_before(self) -> None:
        self.assertEqual(validate_plan(sample_plan()), [])
        code, payload = self.validate(sample_plan())
        self.assertEqual((code, payload["errors"]), (0, []))
        self.assertNotIn("requirement_baseline", payload)


if __name__ == "__main__":
    unittest.main()
