"""Requirement baselines, amendments and their Bead references (issue #37).

Every check here is read-only: fake Bead projections stand in for Beads, and the Beads adapter and subprocess are
patched to fail if anything reaches them.
"""
from __future__ import annotations

import contextlib
import copy
import hashlib
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from cwo_core import requirement_baseline as rb  # noqa: E402
from validate_run_readiness_plan import load_baseline_chain  # noqa: E402

FIXTURES = ROOT / "tests" / "fixtures" / "requirement-baseline"
HAS_JSONSCHEMA = importlib.util.find_spec("jsonschema") is not None


@contextlib.contextmanager
def native_integer_conversion_limit():
    """Exercise the real decoder with a finite test-only limit, restoring it on exit."""
    previous = sys.get_int_max_str_digits()
    try:
        sys.set_int_max_str_digits(4300)
        yield
    finally:
        sys.set_int_max_str_digits(previous)


def fixture(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def independent_digest(record: dict) -> str:
    """The documented serialization, computed here rather than by the module."""
    payload = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def criterion(record: dict, criterion_id: str) -> dict:
    return next(item for item in record["criteria"] if item["id"] == criterion_id)


def amend(prior: dict, new: dict, **overrides: object) -> dict:
    """A consistent amendment from ``prior`` to ``new``; overrides replace fields afterwards."""
    before = {item["id"]: item for item in prior["criteria"]}
    after = {item["id"]: item for item in new["criteria"]}
    record = {
        "record_type": "cwo-requirement-amendment",
        "version": 1,
        "bead_id": prior["bead_id"],
        "amendment_id": "amendment-1",
        "prior_digest": independent_digest(prior),
        "prior_baseline_version": prior["baseline_version"],
        "added_criterion_ids": sorted(set(after) - set(before)),
        "removed_criterion_ids": sorted(set(before) - set(after)),
        "changed_criterion_ids": sorted(key for key in set(before) & set(after) if before[key] != after[key]),
        "rationale": "scope changed after review",
        "authority": {"role": "operator", "reference": "decision record"},
        "baseline": new,
    }
    record.update(overrides)
    return record


def next_version(prior: dict) -> dict:
    new = copy.deepcopy(prior)
    new["baseline_version"] = prior["baseline_version"] + 1
    return new


def bead(bead_id: str, *texts: str) -> dict:
    """A fake ``bd show --json --include-comments`` projection."""
    return {
        "id": bead_id,
        "status": "in_progress",
        "comments": [{"id": index + 1, "author": "lead", "text": text} for index, text in enumerate(texts)],
    }


class BaselineRecordTests(unittest.TestCase):
    def setUp(self) -> None:
        self.baseline = fixture("baseline-v1.json")

    def test_loader_preserves_supported_large_baseline_versions(self) -> None:
        for version in (1, 2**100):
            with self.subTest(version=version):
                record = dict(self.baseline, baseline_version=version)
                loaded = rb.load_record(json.dumps(record))
                self.assertEqual(loaded, record)
                self.assertEqual(rb.baseline_errors(loaded), [])
                self.assertEqual(rb.record_digest(loaded), independent_digest(record))

    def test_loader_preserves_existing_structured_diagnostics(self) -> None:
        with self.assertRaises(rb.RequirementBaselineError) as duplicate:
            rb.load_record('{"bead_id": "a", "bead_id": "b"}')
        self.assertEqual(duplicate.exception.errors, ["duplicate key(s) bead_id"])
        self.assertIsNone(duplicate.exception.__cause__)
        with self.assertRaises(rb.RequirementBaselineError) as malformed:
            rb.load_record("{")
        self.assertIsInstance(malformed.exception.__cause__, json.JSONDecodeError)
        self.assertEqual(malformed.exception.errors, [f"not JSON: {malformed.exception.__cause__}"])
        for text in ("[]", "null", "1"):
            with self.subTest(text=text), self.assertRaises(rb.RequirementBaselineError) as caught:
                rb.load_record(text)
            self.assertEqual(caught.exception.errors, ["a record must be a JSON object"])

    def test_native_integer_conversion_failure_is_a_structured_loader_refusal(self) -> None:
        text = json.dumps(self.baseline).replace(
            '"baseline_version": 1', '"baseline_version": ' + "9" * 4400, 1)
        with native_integer_conversion_limit():
            with self.assertRaises(ValueError) as native:
                json.loads(text)
            with self.assertRaises(rb.RequirementBaselineError) as caught:
                rb.load_record(text)
        self.assertIs(type(native.exception), ValueError)
        self.assertIs(type(caught.exception.__cause__), ValueError)
        self.assertEqual(caught.exception.errors, [f"not JSON: {native.exception}"])
        self.assertEqual(str(caught.exception.__cause__), str(native.exception))

    def test_readiness_chain_refuses_native_integer_failures_before_resolution(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            baseline_path = Path(directory) / "baseline.json"
            amendment_path = Path(directory) / "amendment.json"
            invalid_path = Path(directory) / "invalid.json"
            baseline_path.write_text(json.dumps(self.baseline), encoding="utf-8")
            amendment = fixture("amendment-adds-criterion.json")
            amendment_path.write_text(json.dumps(amendment), encoding="utf-8")
            invalid_path.write_text('{"baseline_version": ' + "9" * 4400 + "}", encoding="utf-8")
            self.assertEqual(
                load_baseline_chain(baseline_path, [amendment_path]),
                rb.resolve_chain(self.baseline, [amendment]),
            )
            for initial, amendments in ((invalid_path, []), (baseline_path, [invalid_path])):
                with self.subTest(initial=initial.name, amendments=amendments):
                    with patch("validate_run_readiness_plan.resolve_chain", wraps=rb.resolve_chain) as resolve:
                        with native_integer_conversion_limit():
                            with self.assertRaises(rb.RequirementBaselineError) as caught:
                                load_baseline_chain(initial, amendments)
                        resolve.assert_not_called()
                        self.assertIs(type(caught.exception.__cause__), ValueError)
                        self.assertEqual(caught.exception.errors, [f"not JSON: {caught.exception.__cause__}"])

    def test_a_complete_baseline_is_accepted(self) -> None:
        self.assertEqual(rb.baseline_errors(self.baseline), [])
        self.assertEqual(rb.required_criterion_ids(self.baseline), ["rename-complete", "service-retired", "docs-name-reviewed"])

    def test_the_digest_is_the_documented_deterministic_serialization(self) -> None:
        digest = rb.record_digest(self.baseline)
        self.assertEqual(digest, independent_digest(self.baseline))
        self.assertEqual(digest, "sha256:a6bfbb11e22599467f86398b54f9e6bc72db04dce9fb524f257436d35348aa97")
        reordered = json.loads(json.dumps(self.baseline, sort_keys=True))
        reordered["criteria"] = [dict(reversed(list(item.items()))) for item in reordered["criteria"]]
        self.assertEqual(rb.record_digest(reordered), digest)

    def test_any_change_to_an_obligation_changes_the_digest(self) -> None:
        digest = rb.record_digest(self.baseline)
        for criterion_index, item in enumerate(self.baseline["criteria"]):
            for field in item:
                with self.subTest(criterion=item["id"], field=field):
                    changed = copy.deepcopy(self.baseline)
                    changed["criteria"][criterion_index][field] = item[field] + "x"
                    self.assertNotEqual(rb.record_digest(changed), digest)

    def test_result_fields_are_refused_because_a_baseline_holds_obligations_only(self) -> None:
        for key, value in (("status", "passed"), ("observed", "renamed"), ("evidence", "ci run 7"), ("candidate", "abc")):
            with self.subTest(key=key):
                record = copy.deepcopy(self.baseline)
                record["criteria"][0][key] = value
                errors = "\n".join(rb.baseline_errors(record))
                self.assertIn("obligations, not results", errors)
        record = copy.deepcopy(self.baseline)
        record["results"] = []
        self.assertIn("obligations, not results", "\n".join(rb.baseline_errors(record)))

    def test_each_criterion_needs_its_requirement_reference_and_expected_outcome(self) -> None:
        for field in ("requirement", "reference", "expected_outcome", "applicability", "evidence_kind", "id"):
            for value in (None, "", "   "):
                with self.subTest(field=field, value=value):
                    record = copy.deepcopy(self.baseline)
                    if value is None:
                        del record["criteria"][0][field]
                    else:
                        record["criteria"][0][field] = value
                    self.assertTrue(rb.baseline_errors(record))

    def test_criterion_ids_are_stable_and_unique_regardless_of_case(self) -> None:
        for bad in ("1rename", "rename complete", "rename--complete", "rename.", "-rename", "r" * 65, 7):
            with self.subTest(criterion_id=bad):
                record = copy.deepcopy(self.baseline)
                record["criteria"][0]["id"] = bad
                self.assertIn("stable ID", "\n".join(rb.baseline_errors(record)))
        record = copy.deepcopy(self.baseline)
        record["criteria"][1]["id"] = "Rename-Complete"
        self.assertIn("repeats", "\n".join(rb.baseline_errors(record)))

    def test_not_applicable_needs_a_reason_and_required_cannot_carry_one(self) -> None:
        record = copy.deepcopy(self.baseline)
        del criterion(record, "windows-installer")["not_applicable_reason"]
        self.assertIn("needs not_applicable_reason", "\n".join(rb.baseline_errors(record)))
        record = copy.deepcopy(self.baseline)
        criterion(record, "rename-complete")["not_applicable_reason"] = "not needed"
        self.assertIn("cannot carry not_applicable_reason", "\n".join(rb.baseline_errors(record)))
        record = copy.deepcopy(self.baseline)
        for item in record["criteria"]:
            item["applicability"] = "not-applicable"
            item["not_applicable_reason"] = "skipped"
        self.assertIn("no required criterion", "\n".join(rb.baseline_errors(record)))
        record = copy.deepcopy(self.baseline)
        criterion(record, "rename-complete")["applicability"] = "optional"
        self.assertIn("applicability must be one of", "\n".join(rb.baseline_errors(record)))

    def test_unsupported_record_versions_and_types_are_refused(self) -> None:
        for field, value in (("version", 2), ("version", True), ("version", "1"), ("record_type", "cwo-acceptance")):
            with self.subTest(field=field, value=value):
                record = copy.deepcopy(self.baseline)
                record[field] = value
                self.assertTrue(rb.baseline_errors(record))
        for value in (0, True, "1"):
            with self.subTest(baseline_version=value):
                record = copy.deepcopy(self.baseline)
                record["baseline_version"] = value
                self.assertIn("baseline_version", "\n".join(rb.baseline_errors(record)))
        self.assertTrue(rb.baseline_errors([]))
        self.assertTrue(rb.baseline_errors({**self.baseline, "criteria": []}))

    def test_evidence_kind_reuses_the_readiness_evidence_types(self) -> None:
        record = copy.deepcopy(self.baseline)
        record["criteria"][0]["evidence_kind"] = "narrative"
        self.assertIn("evidence_kind must be one of: artifact, validator, review-gate", "\n".join(rb.baseline_errors(record)))

    def test_control_and_text_direction_characters_are_refused(self) -> None:
        for character in ("\x1b", "\u202e", "\x00"):
            with self.subTest(character=repr(character)):
                record = copy.deepcopy(self.baseline)
                record["criteria"][0]["expected_outcome"] = "renamed" + character
                self.assertIn("control", "\n".join(rb.baseline_errors(record)))

    def test_records_with_duplicate_keys_or_no_object_are_refused_when_loaded(self) -> None:
        with self.assertRaisesRegex(rb.RequirementBaselineError, "duplicate key"):
            rb.load_record('{"bead_id": "a", "bead_id": "b"}')
        with self.assertRaises(rb.RequirementBaselineError):
            rb.load_record("[]")
        with self.assertRaises(rb.RequirementBaselineError):
            rb.load_record("{")
        self.assertEqual(rb.load_record(json.dumps(self.baseline)), self.baseline)


class AmendmentTests(unittest.TestCase):
    def setUp(self) -> None:
        self.baseline = fixture("baseline-v1.json")
        self.amendment = fixture("amendment-adds-criterion.json")

    def refused(self, *amendments: dict) -> str:
        with self.assertRaises(rb.RequirementBaselineError) as caught:
            rb.resolve_chain(self.baseline, list(amendments))
        return str(caught.exception)

    def test_a_baseline_alone_is_its_own_chain(self) -> None:
        chain = rb.resolve_chain(self.baseline)
        self.assertEqual(chain["digest"], independent_digest(self.baseline))
        self.assertEqual(chain["version"], 1)
        self.assertEqual(chain["amendment_ids"], [])

    def test_an_amendment_that_adds_a_criterion_is_applied(self) -> None:
        chain = rb.resolve_chain(self.baseline, [self.amendment])
        self.assertEqual(chain["version"], 2)
        self.assertEqual(chain["digest"], independent_digest(self.amendment["baseline"]))
        self.assertEqual(chain["amendment_ids"], ["add-changelog"])
        self.assertEqual([entry["version"] for entry in chain["baselines"]], [1, 2])
        self.assertIn("changelog-entry", rb.required_criterion_ids(chain["baseline"]))

    def test_removing_a_criterion_is_refused_even_when_declared_and_authorized(self) -> None:
        new = next_version(self.baseline)
        new["criteria"] = [item for item in new["criteria"] if item["id"] != "service-retired"]
        message = self.refused(amend(self.baseline, new))
        self.assertIn("removes or changes criteria service-retired", message)
        self.assertIn("only amendments that add criteria are supported", message)
        self.assertIn(independent_digest(self.baseline), message)

    def test_changing_a_criterion_is_refused_because_a_weakening_cannot_be_told_apart(self) -> None:
        changes = {
            "expected_outcome": lambda item: item.update(expected_outcome="legacy-sync is stopped."),
            "applicability": lambda item: item.update(applicability="not-applicable", not_applicable_reason="later"),
            "requirement": lambda item: item.update(requirement=item["requirement"] + " (clarified)"),
            "evidence_kind": lambda item: item.update(evidence_kind="review-gate"),
        }
        for name, change in changes.items():
            with self.subTest(change=name):
                new = next_version(self.baseline)
                change(criterion(new, "service-retired"))
                self.assertIn("removes or changes criteria service-retired", self.refused(amend(self.baseline, new)))

    def test_replacing_a_criterion_is_refused(self) -> None:
        new = next_version(self.baseline)
        replacement = dict(criterion(new, "rename-complete"), id="rename-in-code")
        replacement["expected_outcome"] = "No Python module contains old-name."
        new["criteria"] = [replacement if item["id"] == "rename-complete" else item for item in new["criteria"]]
        self.assertIn("removes or changes criteria rename-complete", self.refused(amend(self.baseline, new)))

    def test_an_amendment_must_declare_exactly_what_it_changes(self) -> None:
        new = copy.deepcopy(self.amendment["baseline"])
        criterion(new, "service-retired")["expected_outcome"] = "legacy-sync is stopped."
        silent = amend(self.baseline, new, changed_criterion_ids=[])
        message = self.refused(silent)
        self.assertIn("must name exactly what it changes", message)
        overstated = dict(self.amendment, added_criterion_ids=["changelog-entry", "service-retired"])
        self.assertIn("must name exactly what it changes", self.refused(overstated))

    def test_a_stale_wrong_or_inconsistent_amendment_is_refused(self) -> None:
        cases = {
            "stale prior digest": {"prior_digest": "sha256:" + "0" * 64},
            "prior version": {"prior_baseline_version": 2},
            "other bead": {"bead_id": "proj-other"},
            "no rationale": {"rationale": " "},
            "no authority": {"authority": {"role": "", "reference": "x"}},
            "authority not an object": {"authority": "architect"},
            "version 2": {"version": 2},
            "bad id": {"amendment_id": "1 bad"},
            "results smuggled": {"status": "passed"},
        }
        for name, override in cases.items():
            with self.subTest(case=name):
                self.refused(dict(self.amendment, **override))
        skipped = copy.deepcopy(self.amendment)
        skipped["baseline"]["baseline_version"] = 3
        self.assertIn("version must be 2", self.refused(skipped))
        other = copy.deepcopy(self.amendment)
        other["baseline"]["bead_id"] = "proj-other"
        self.assertIn("not 'proj-abc'", self.refused(other))
        missing = dict(self.amendment)
        del missing["removed_criterion_ids"]
        self.assertIn("missing removed_criterion_ids", self.refused(missing))
        missing_id = dict(self.amendment)
        del missing_id["amendment_id"]
        refusal = None
        try:
            rb.resolve_chain(self.baseline, [missing_id])
        except Exception as exc:
            refusal = exc
        self.assertIsInstance(refusal, rb.RequirementBaselineError,
                              "Malformed public amendment input needs a controlled baseline refusal")
        self.assertIn("missing amendment_id", str(refusal))

    def test_an_amendment_that_changes_nothing_or_repeats_is_refused(self) -> None:
        self.assertIn("changes no criterion", self.refused(amend(self.baseline, next_version(self.baseline))))
        later = next_version(self.amendment["baseline"])
        later["criteria"].append(dict(criterion(later, "changelog-entry"), id="release-note"))
        second = amend(self.amendment["baseline"], later, amendment_id="add-changelog")
        self.assertIn("appears twice", self.refused(self.amendment, second))
        second["amendment_id"] = "add-release-note"
        self.assertEqual(rb.resolve_chain(self.baseline, [self.amendment, second])["version"], 3)

    def test_amendments_must_apply_in_order(self) -> None:
        later = next_version(self.amendment["baseline"])
        later["criteria"].append(dict(criterion(later, "changelog-entry"), id="release-note"))
        second = amend(self.amendment["baseline"], later, amendment_id="add-release-note")
        self.assertIn("not the current baseline", self.refused(second, self.amendment))

    def test_a_chain_starts_at_version_one(self) -> None:
        with self.assertRaisesRegex(rb.RequirementBaselineError, "a chain starts at version 1"):
            rb.resolve_chain(self.amendment["baseline"])
        with self.assertRaisesRegex(rb.RequirementBaselineError, "initial baseline"):
            rb.resolve_chain({**self.baseline, "version": 2})


class BeadReferenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.baseline = fixture("baseline-v1.json")
        self.amendment = fixture("amendment-adds-criterion.json")
        self.chain = rb.resolve_chain(self.baseline, [self.amendment])
        self.lines = [rb.reference_line("proj-abc", entry["version"], entry["digest"]) for entry in self.chain["baselines"]]

    def test_the_reference_line_names_the_bead_version_and_digest(self) -> None:
        self.assertEqual(
            self.lines[0],
            "cwo-requirement-baseline bead=proj-abc version=1 digest=" + independent_digest(self.baseline),
        )

    def test_a_chain_recorded_on_the_bead_in_order_is_retained(self) -> None:
        projection = bead("proj-abc", "claimed", self.lines[0], "progress note", self.lines[1], self.lines[1])
        self.assertEqual(rb.bead_reference_errors(projection, self.chain), [])

    def test_an_unrecorded_version_is_refused(self) -> None:
        errors = "\n".join(rb.bead_reference_errors(bead("proj-abc", self.lines[0]), self.chain))
        self.assertIn("baseline version 2", errors)
        self.assertIn("is not recorded on proj-abc", errors)
        self.assertTrue(rb.bead_reference_errors(bead("proj-abc"), self.chain))

    def test_a_baseline_recorded_outside_the_chain_is_an_unamended_replacement(self) -> None:
        replacement = copy.deepcopy(self.baseline)
        replacement["criteria"] = replacement["criteria"][:1]
        other = rb.reference_line("proj-abc", 1, independent_digest(replacement))
        errors = "\n".join(rb.bead_reference_errors(bead("proj-abc", self.lines[0], other, self.lines[1]), self.chain))
        self.assertIn("replaced or diverged without an amendment", errors)
        alone = rb.resolve_chain(replacement)
        self.assertIn("replaced or diverged", "\n".join(rb.bead_reference_errors(bead("proj-abc", self.lines[0], other), alone)))

    def test_references_out_of_order_malformed_or_for_another_bead_are_refused(self) -> None:
        self.assertIn("not in version order", "\n".join(rb.bead_reference_errors(bead("proj-abc", self.lines[1], self.lines[0]), self.chain)))
        for text in (self.lines[0] + " (approved)", self.lines[0] + "\nsee notes", "cwo-requirement-baseline v1"):
            with self.subTest(text=text):
                errors = "\n".join(rb.bead_reference_errors(bead("proj-abc", text, *self.lines), self.chain))
                self.assertIn("is not one", errors)
        foreign = self.lines[0].replace("bead=proj-abc", "bead=proj-xyz")
        self.assertIn("Bead proj-xyz", "\n".join(rb.bead_reference_errors(bead("proj-abc", foreign, *self.lines), self.chain)))
        self.assertIn("not 'proj-abc'", "\n".join(rb.bead_reference_errors(bead("proj-xyz", *self.lines), self.chain)))
        self.assertTrue(rb.bead_reference_errors({"id": "proj-abc"}, self.chain))
        self.assertTrue(rb.bead_reference_errors([], self.chain))

    def test_a_reference_inside_a_longer_comment_is_refused(self) -> None:
        other = rb.reference_line("proj-abc", 9, "sha256:" + "9" * 64)
        cases = {
            "after a note": "Note\n" + other,
            "indented after a note": "Recorded the baseline:\n    " + other,
            "inside a sentence": "superseded by " + other + " last week",
            "different letter case": other.upper(),
            "after a note, other case": "Note\n" + other.replace("cwo-requirement-baseline", "CWO-Requirement-Baseline"),
        }
        for name, text in cases.items():
            with self.subTest(case=name):
                errors = "\n".join(rb.bead_reference_errors(bead("proj-abc", *self.lines, text), self.chain))
                self.assertIn("is not one", errors)

    def test_prose_that_only_mentions_the_prefix_is_not_a_reference(self) -> None:
        prose = "the cwo-requirement-baseline comments above record versions 1 and 2"
        self.assertEqual(rb.bead_reference_errors(bead("proj-abc", self.lines[0], prose, self.lines[1]), self.chain), [])

    def test_no_check_runs_a_command_or_touches_beads(self) -> None:
        def refuse(*args: object, **kwargs: object) -> None:
            raise AssertionError("a requirement baseline check reached Beads or a subprocess")

        with patch("cwo_core.beads.run_bd", side_effect=refuse), patch("cwo_core.beads.run_bd_structured", side_effect=refuse), \
                patch("subprocess.run", side_effect=refuse), patch("subprocess.Popen", side_effect=refuse):
            chain = rb.resolve_chain(self.baseline, [self.amendment])
            self.assertEqual(rb.bead_reference_errors(bead("proj-abc", *self.lines), chain), [])
            with self.assertRaises(rb.RequirementBaselineError):
                rb.resolve_chain(self.baseline, [dict(self.amendment, prior_digest="sha256:" + "1" * 64)])


class SchemaParityTests(unittest.TestCase):
    def schema(self, name: str) -> dict:
        return json.loads((ROOT / "schemas" / name).read_text(encoding="utf-8"))

    def test_the_schemas_match_the_runtime_contract(self) -> None:
        baseline = self.schema("requirement-baseline.schema.json")
        self.assertEqual(baseline["required"], list(rb.BASELINE_FIELDS))
        self.assertFalse(baseline["additionalProperties"])
        item = baseline["properties"]["criteria"]["items"]
        self.assertEqual(item["required"], list(rb.CRITERION_FIELDS))
        self.assertEqual(set(item["properties"]), {*rb.CRITERION_FIELDS, rb.NOT_APPLICABLE_REASON})
        self.assertEqual(item["properties"]["applicability"]["enum"], list(rb.APPLICABILITY))
        self.assertEqual(item["properties"]["evidence_kind"]["enum"], list(rb.EVIDENCE_KINDS))
        amendment = self.schema("requirement-amendment.schema.json")
        self.assertEqual(amendment["required"], list(rb.AMENDMENT_FIELDS))
        self.assertEqual(amendment["properties"]["removed_criterion_ids"]["maxItems"], 0)
        self.assertEqual(amendment["properties"]["changed_criterion_ids"]["maxItems"], 0)
        readiness = self.schema("run-readiness-plan.schema.json")
        self.assertNotIn("requirement_baseline", readiness["required"])
        self.assertEqual(readiness["properties"]["requirement_baseline"]["properties"]["record_type"]["const"], rb.BASELINE_RECORD_TYPE)

    @unittest.skipUnless(HAS_JSONSCHEMA, "jsonschema is not installed")
    def test_the_schema_refuses_a_baseline_with_no_required_criterion_as_the_runtime_does(self) -> None:
        from jsonschema import Draft202012Validator

        schema = self.schema("requirement-baseline.schema.json")
        Draft202012Validator.check_schema(schema)
        validator = Draft202012Validator(schema)
        baseline = fixture("baseline-v1.json")
        self.assertTrue(validator.is_valid(baseline))
        for item in baseline["criteria"]:
            if item["applicability"] == "required":
                item["applicability"] = "not-applicable"
                item["not_applicable_reason"] = "skipped"
        self.assertIn("the baseline has no required criterion", rb.baseline_errors(baseline))
        self.assertFalse(validator.is_valid(baseline))
        self.assertTrue(validator.is_valid(fixture("amendment-adds-criterion.json")["baseline"]))

    def test_the_amended_fixture_does_not_contradict_the_rename_it_amends(self) -> None:
        amended = fixture("amendment-adds-criterion.json")["baseline"]
        rename = criterion(amended, "rename-complete")["expected_outcome"]
        changelog = criterion(amended, "changelog-entry")["expected_outcome"]
        self.assertIn("No tracked file", rename)
        self.assertNotIn("naming both old-name", changelog)
        self.assertIn("does not contain old-name", changelog)

    def test_the_fixtures_satisfy_the_runtime_checks(self) -> None:
        self.assertEqual(rb.baseline_errors(fixture("baseline-v1.json")), [])
        self.assertEqual(rb.amendment_errors(fixture("baseline-v1.json"), fixture("amendment-adds-criterion.json")), [])


if __name__ == "__main__":
    unittest.main()
