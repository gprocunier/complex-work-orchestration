"""Offline numeric-range and canonical JSON type regressions using fixture copies."""

from __future__ import annotations

import contextlib
import copy
import io
import json
import tempfile
import unittest

from tests.test_comparative_evaluation_locked_inputs import (
    StudyCopy,
    ce,
    cli,
    find,
    reporting_amendment,
    reseal,
    row_of,
)


class NumericAndTypedHistoryTests(unittest.TestCase):
    def score(self, study, runs, lock):
        try:
            return study.score(runs, lock)
        except Exception as exc:
            self.fail(f"controller escaped structured refusal: {type(exc).__name__}: {exc}")

    def refused(self, code, report):
        self.assertEqual(code, 1, report)
        self.assertIsInstance(report, dict)
        self.assertTrue(report.get("errors"), report)
        for field in ("runs", "summary", "estimands"):
            self.assertNotIn(field, report)

    def test_ordinary_integer_float_and_null_telemetry_still_scores(self):
        with tempfile.TemporaryDirectory() as temp:
            study = StudyCopy(temp)
            lock = study.lock()
            original = study.records(lock)
            for value in (0, 1, 1.5, None):
                with self.subTest(value=value):
                    runs = copy.deepcopy(original)
                    find(runs, "r17-overhead-slugify-baseline")["telemetry"]["wall_seconds"] = value
                    code, report = self.score(study, runs, lock)
                    self.assertEqual(code, 0, report)
                    expected = "unknown" if value is None else value
                    self.assertEqual(row_of(report, "r17-overhead-slugify-baseline")["telemetry"]["wall_seconds"], expected)
                    json.dumps(report, allow_nan=False)

    def test_unsupported_integer_refuses_every_telemetry_field_without_escaping(self):
        with tempfile.TemporaryDirectory() as temp:
            study = StudyCopy(temp)
            lock = study.lock()
            original = study.records(lock)
            for key in ce.TELEMETRY_FIELDS:
                with self.subTest(field=key):
                    runs = copy.deepcopy(original)
                    find(runs, "r17-overhead-slugify-baseline")["telemetry"][key] = 10**400
                    code, report = self.score(study, runs, lock)
                    self.refused(code, report)
                    self.assertTrue(any(key in error for error in report["errors"]), report)

    def test_actual_started_run_aggregates_refuse_in_controller_and_direct_consumer(self):
        with tempfile.TemporaryDirectory() as temp:
            study = StudyCopy(temp)
            lock = study.lock()
            original = study.records(lock)
            for key in ("wall_seconds", "input_tokens"):
                with self.subTest(field=key):
                    runs = copy.deepcopy(original)
                    started = [run for run in runs if run["terminal"]["disposition"] != "not-run"]
                    self.assertEqual(len(started), 17)
                    for index, run in enumerate(started):
                        run["telemetry"][key] = 10**308 if key == "input_tokens" and index == 0 else 1e308
                    for run in runs:
                        self.assertEqual(ce._validate_run(run, "fixture", study.protocol()), [])
                    code, report = self.score(study, runs, lock)
                    self.refused(code, report)
                    bundle, errors = ce.load_locked_bundle(lock, study.repo)
                    self.assertEqual(errors, [])
                    try:
                        direct = ce._score_runs(
                            bundle["protocol"], bundle["hidden"], runs,
                            study_lock_sha256=lock["lock_sha256"],
                            build_freeze=bundle["build_freeze"],
                        )
                    except Exception as exc:
                        self.fail(f"direct consumer escaped structured refusal: {type(exc).__name__}: {exc}")
                    self.refused(1 if "errors" in direct else 0, direct)

    def test_final_output_refuses_nonfinite_values_before_printing_rows(self):
        for value in (float("inf"), float("nan")):
            with self.subTest(value=value):
                out = io.StringIO()
                with contextlib.redirect_stdout(out):
                    with self.assertRaises(SystemExit) as stopped:
                        cli._print({"runs": [{"telemetry": {"wall_seconds": value}}]})
                self.assertEqual(stopped.exception.code, 1)
                self.refused(stopped.exception.code, json.loads(out.getvalue()))

    def write_revision(self, study, first, second):
        study.write_json("history/v1.json", first)
        study.write_json("protocol.json", reseal(second))

    def test_reporting_chain_preserves_scores_and_object_order_but_refuses_typed_task_drift(self):
        with tempfile.TemporaryDirectory() as temp:
            study = StudyCopy(temp)
            first = study.protocol()
            first["tasks"][0]["harness_setup"]["numeric_fixture"] = {"flag": False, "number": 1, "array": [False, 0]}
            study.write_json("protocol.json", reseal(first))
            lock = study.lock()
            runs = study.records(lock)
            code, before = self.score(study, runs, lock)
            self.assertEqual(code, 0, before)
            second = reporting_amendment(first)
            second["tasks"][0]["harness_setup"]["numeric_fixture"] = dict(reversed(list(first["tasks"][0]["harness_setup"]["numeric_fixture"].items())))
            self.write_revision(study, first, second)
            code, after = self.score(study, runs, lock)
            self.assertEqual(code, 0, after)
            for field in ("runs", "summary", "estimands"):
                self.assertEqual(after[field], before[field])
            self.assertEqual(after["reporting_revision"]["version"], 2)
            for key, value in (("flag", 0), ("number", 1.0), ("array", [0, False])):
                with self.subTest(field=key):
                    bad = copy.deepcopy(second)
                    bad["tasks"][0]["harness_setup"]["numeric_fixture"][key] = value
                    self.write_revision(study, first, bad)
                    code, report = self.score(study, runs, lock)
                    self.refused(code, report)

    def test_fixed_boolean_and_integer_fields_refuse_numeric_type_substitution(self):
        with tempfile.TemporaryDirectory() as temp:
            study = StudyCopy(temp)
            lock = study.lock()
            first = study.protocol()
            second = reporting_amendment(first)
            self.write_revision(study, first, second)
            code, good = self.score(study, study.records(lock), lock)
            self.assertEqual(code, 0, good)
            for field, value in (("favorable_result_required", 0), ("interim_looks", 0.0)):
                with self.subTest(field=field):
                    bad = copy.deepcopy(second)
                    destination = bad["analysis"]["decision_rule"] if field == "favorable_result_required" else bad["analysis"]
                    destination[field] = value
                    self.write_revision(study, first, bad)
                    code, report = self.score(study, study.records(lock), lock)
                    self.refused(code, report)

    def test_registration_metadata_comparison_preserves_json_types(self):
        with tempfile.TemporaryDirectory() as temp:
            study = StudyCopy(temp)
            first = study.protocol()
            first["preregistration"]["numeric_fixture"] = {"flag": False, "number": 1}
            study.write_json("protocol.json", reseal(first))
            lock = study.lock()
            second = reporting_amendment(first)
            self.write_revision(study, first, second)
            code, good = self.score(study, study.records(lock), lock)
            self.assertEqual(code, 0, good)
            for field, value in (("flag", 0), ("number", 1.0)):
                with self.subTest(field=field):
                    bad = copy.deepcopy(second)
                    bad["preregistration"]["numeric_fixture"][field] = value
                    self.write_revision(study, first, bad)
                    code, report = self.score(study, study.records(lock), lock)
                    self.refused(code, report)

    def test_amendment_prefix_cannot_retype_an_earlier_record(self):
        with tempfile.TemporaryDirectory() as temp:
            study = StudyCopy(temp)
            lock = study.lock()
            first = study.protocol()
            second = reporting_amendment(first)
            third = reporting_amendment(second)
            study.write_json("history/v1.json", first)
            study.write_json("history/v2.json", second)
            study.write_json("protocol.json", third)
            code, good = self.score(study, study.records(lock), lock)
            self.assertEqual(code, 0, good)
            third["preregistration"]["amendments"][0]["version"] = 2.0
            reseal(third)
            errors = ce.amendment_errors(second, third, observed_outcomes=1)
            self.assertTrue(any("earlier records" in error for error in errors), errors)
            study.write_json("protocol.json", third)
            code, report = self.score(study, study.records(lock), lock)
            self.refused(code, report)

    def test_observed_configuration_type_drift_keeps_existing_exclusion_rules(self):
        with tempfile.TemporaryDirectory() as temp:
            study = StudyCopy(temp)
            lock = study.lock()
            original = study.records(lock)
            cases = (
                ("budget", "retries", False, "excluded-budget-drift"),
                ("tools", "web_search", 0, "excluded-identity-drift"),
            )
            for section, key, value, status in cases:
                with self.subTest(section=section):
                    runs = copy.deepcopy(original)
                    run = find(runs, "r17-overhead-slugify-baseline")
                    run["observed_identity"][section][key] = value
                    code, report = self.score(study, runs, lock)
                    self.assertEqual(code, 0, report)
                    self.assertEqual(row_of(report, run["run_id"])["comparison"], status)


if __name__ == "__main__":
    unittest.main()
