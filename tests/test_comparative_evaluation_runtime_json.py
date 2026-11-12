"""Offline regressions for runtime source bindings and supported JSON strings."""

from __future__ import annotations

import contextlib
import copy
import io
import json
import subprocess
import sys
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


class RuntimeJsonTests(unittest.TestCase):
    def call(self, function, *args, **kwargs):
        try:
            return function(*args, **kwargs)
        except Exception as exc:
            self.fail(f"unexpected exception instead of semantic result: {type(exc).__name__}: {exc}")

    def refused(self, report):
        self.assertIsInstance(report, dict)
        self.assertTrue(report.get("errors"), report)
        for field in ("runs", "summary", "estimands"):
            self.assertNotIn(field, report)

    def score(self, study, runs, lock):
        code, report = self.call(study.score, runs, lock)
        self.assertEqual(code, 1 if "errors" in report else 0, report)
        return code, report

    def test_identical_disposable_copy_keeps_direct_and_controller_results(self):
        with tempfile.TemporaryDirectory() as temp:
            study = StudyCopy(temp)
            lock = study.lock()
            runs = study.records(lock)
            code, report = self.score(study, runs, lock)
            self.assertEqual(code, 0, report)
            direct = self.call(ce.score_under_study_lock, runs, lock, study.repo)
            self.assertEqual(direct, report)
            bundle, errors = self.call(ce.load_locked_bundle, lock, study.repo)
            self.assertEqual(errors, [])
            self.assertIsNotNone(bundle)
            self.assertEqual(row_of(report, "r17-overhead-slugify-baseline")["comparison"], "included")

    def test_foreign_bound_runtime_sources_refuse_before_rows(self):
        for label, relative in (
            ("controller", ce.CONTROLLER_PATH),
            ("scorer", ce.SCORER_PATH),
            ("scorer-dependency", ce.SCORER_DEPENDENCY_PATH),
        ):
            with self.subTest(binding=label), tempfile.TemporaryDirectory() as temp:
                study = StudyCopy(temp)
                source = study.repo / relative
                text = source.read_text(encoding="utf-8")
                if label == "scorer":
                    before = "return canonical_json_bytes(actual) == canonical_json_bytes(expected)"
                    self.assertEqual(text.count(before), 1)
                    text = text.replace(before, "return actual == expected")
                else:
                    text += "\n# distinct prospective fixture source\n"
                source.write_text(text, encoding="utf-8")
                lock = study.lock()
                runs = study.records(lock)
                find(runs, "r17-overhead-slugify-baseline")["observed_identity"]["budget"]["retries"] = False
                code, report = self.score(study, runs, lock)
                self.assertEqual(code, 1, report)
                self.refused(report)
                self.assertTrue(any(f"binding {label} runtime source" in error for error in report["errors"]), report)
                direct = self.call(ce.score_under_study_lock, runs, lock, study.repo)
                self.refused(direct)
                bundle, errors = self.call(ce.load_locked_bundle, lock, study.repo)
                self.assertIsNone(bundle)
                self.assertTrue(errors)

    def test_prospective_changed_scorer_works_when_that_source_is_loaded(self):
        with tempfile.TemporaryDirectory() as temp:
            study = StudyCopy(temp)
            source = study.repo / ce.SCORER_PATH
            text = source.read_text(encoding="utf-8")
            before = "return canonical_json_bytes(actual) == canonical_json_bytes(expected)"
            self.assertEqual(text.count(before), 1)
            source.write_text(text.replace(before, "return actual == expected"), encoding="utf-8")
            lock = study.lock()
            runs = study.records(lock)
            find(runs, "r17-overhead-slugify-baseline")["observed_identity"]["budget"]["retries"] = False
            runs_path, lock_path = study.temp / "fresh-runs.json", study.temp / "fresh-lock.json"
            runs_path.write_text(json.dumps(runs), encoding="utf-8")
            lock_path.write_text(json.dumps(lock), encoding="utf-8")
            completed = self.call(
                subprocess.run,
                [sys.executable, "-B", str(study.repo / ce.CONTROLLER_PATH),
                 "--root", str(study.study), "score", str(runs_path), "--lock", str(lock_path)],
                cwd=study.repo, capture_output=True, text=True, timeout=30,
            )
            self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            report = json.loads(completed.stdout)
            self.assertEqual(row_of(report, "r17-overhead-slugify-baseline")["comparison"], "included")

    def test_decoded_surrogates_refuse_every_run_string_channel(self):
        with tempfile.TemporaryDirectory() as temp:
            study = StudyCopy(temp)
            lock = study.lock()
            original = study.records(lock)
            protocol = study.protocol()
            hidden = ce.load_json(study.study / "hidden" / "checks.json")
            freeze = ce.load_json(study.study / "build-freeze.json")
            for field in ("schema_version", "permissions", "budget", "transcript", "final_files", "event_key"):
                for value in ("\ud800", "\udfff"):
                    with self.subTest(field=field, value=repr(value)):
                        runs = copy.deepcopy(original)
                        run = find(runs, "r17-overhead-slugify-baseline")
                        if field == "schema_version":
                            run[field] = value
                        elif field in ("permissions", "budget"):
                            run["observed_identity"][field]["unsupported"] = {"nested": [value]}
                        elif field == "transcript":
                            run[field] = [{"role": "assistant", "text": value}]
                        elif field == "final_files":
                            run["observation"][field] = {"fixture.txt": value}
                        else:
                            run["observation"]["events"] = {value: []}
                        code, report = self.score(study, runs, lock)
                        self.assertEqual(code, 1, report)
                        self.refused(report)
                        self.assertTrue(any("surrogate" in error for error in report["errors"]), report)
                        self.refused(self.call(ce.score_under_study_lock, runs, lock, study.repo))
                        self.refused(self.call(
                            ce._score_runs, protocol, hidden, runs,
                            study_lock_sha256=lock["lock_sha256"], build_freeze=freeze,
                        ))
                        self.assertTrue(self.call(ce._validate_run, run, "fixture", protocol))

    def test_normal_unicode_and_valid_reporting_preserve_scoring(self):
        with tempfile.TemporaryDirectory() as temp:
            study = StudyCopy(temp)
            lock = study.lock()
            runs = study.records(lock)
            run = find(runs, "r17-overhead-slugify-baseline")
            run["transcript"] = [{"role": "assistant", "text": "café 世界 \U0001f642"}]
            code, before = self.score(study, runs, lock)
            self.assertEqual(code, 0, before)
            first = study.protocol()
            second = reporting_amendment(first)
            second["reporting"]["public_release_note"] += " café 世界 \U0001f642"
            study.write_json("history/v1.json", first)
            study.write_json("protocol.json", reseal(second))
            code, after = self.score(study, runs, lock)
            self.assertEqual(code, 0, after)
            for field in ("runs", "summary", "estimands"):
                self.assertEqual(after[field], before[field])
            self.assertEqual(after["reporting_revision"]["version"], 2)
            self.assertTrue(ce._same_json({"é": [False, 1, 1.5, None]}, {"é": [False, 1, 1.5, None]}))
            self.assertFalse(ce._same_json("\ud800", "\ud800"))

    def test_unsupported_strings_in_locked_inputs_and_current_reporting_refuse(self):
        with tempfile.TemporaryDirectory() as temp:
            study = StudyCopy(temp)
            lock = study.lock()
            first = study.protocol()
            second = reporting_amendment(first)
            second["reporting"]["public_release_note"] = "\ud800"
            study.write_json("history/v1.json", first)
            # Write decoded JSON without calling the digest producer on unsupported data.
            study.write_json("protocol.json", second)
            code, report = self.score(study, study.records(lock), lock)
            self.assertEqual(code, 1, report)
            self.refused(report)
            self.assertTrue(self.call(ce.validate_protocol, second, ce.load_json(study.study / "hidden/checks.json"), history=[first]))
            bad_lock = copy.deepcopy(lock)
            bad_lock["protocol_id"] = "\ud800"
            bundle, errors = self.call(ce.load_locked_bundle, bad_lock, study.repo)
            self.assertIsNone(bundle)
            self.assertTrue(any("surrogate" in error for error in errors), errors)
            with self.assertRaisesRegex(ValueError, "surrogate"):
                ce.preregistration_digest(second)
            self.assertTrue(self.call(ce.amendment_errors, first, second, observed_outcomes=1))

    def test_final_serialization_refuses_surrogates_without_rows(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            with self.assertRaises(SystemExit) as stopped:
                self.call(cli._print, {"runs": [{"run_id": "\ud800"}]})
        self.assertEqual(stopped.exception.code, 1)
        self.refused(json.loads(out.getvalue()))

    def test_malformed_current_arm_ids_refuse_with_valid_reporting_control(self):
        with tempfile.TemporaryDirectory() as temp:
            study = StudyCopy(temp)
            lock = study.lock()
            runs = study.records(lock)
            first = study.protocol()
            second = reporting_amendment(first)
            study.write_json("history/v1.json", first)
            study.write_json("protocol.json", second)
            code, good = self.score(study, runs, lock)
            self.assertEqual(code, 0, good)
            for value in ([], {}, None, False, 0, "", " ", ["baseline-codex"]):
                with self.subTest(value=value):
                    bad = copy.deepcopy(second)
                    bad["arms"][0]["id"] = value
                    study.write_json("protocol.json", reseal(bad))
                    code, report = self.score(study, runs, lock)
                    self.assertEqual(code, 1, report)
                    self.refused(report)
                    self.assertTrue(any("arms[0].id" in error for error in report["errors"]), report)
                    self.refused(self.call(ce.score_under_study_lock, runs, lock, study.repo))


if __name__ == "__main__":
    unittest.main()
