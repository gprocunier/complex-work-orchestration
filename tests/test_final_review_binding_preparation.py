"""Final-review preparation fixtures; real observations and EXAMPLE review context only."""
from __future__ import annotations

import contextlib
import copy
import hashlib
import io
import json
import os
import socket
import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import close_bead_with_summary as closure  # noqa: E402
import prepare_artifact_acceptance as artifacts  # noqa: E402
import prepare_final_review_binding as binding  # noqa: E402
from tests import test_artifact_acceptance_preparation as fixtures  # noqa: E402
from cwo_core import candidate_identity as ci  # noqa: E402
from cwo_core import requirement_baseline as rb  # noqa: E402
CLOSURE_EXECUTE = closure.execute


class FinalReviewBindingTests(unittest.TestCase):
    def setUp(self) -> None:
        fixtures.ArtifactPreparationTests.setUp(self)
        stack = contextlib.ExitStack()
        self.addCleanup(stack.close)
        targets = ("cwo_core.beads.run_bd", "cwo_core.beads.run_bd_structured",
                   "close_bead_with_summary.run_bd", "close_bead_with_summary.execute",
                   f"{os.__name__}.system", f"{socket.__name__}.socket.connect")
        self.effect_spies = [stack.enter_context(patch(target, side_effect=AssertionError("EXAMPLE blocked effect")))
                             for target in targets]
        native_popen = subprocess.Popen

        def process(*args, **kwargs):
            command = args[0] if args else kwargs.get("args")
            if not isinstance(command, (list, tuple)) or not command or Path(command[0]).name != "git":
                raise AssertionError("EXAMPLE model or review process is forbidden")
            return native_popen(*args, **kwargs)

        self.process_guard = stack.enter_context(patch("subprocess.Popen", side_effect=process))

    def start(self, record: dict | None = None, *, amendments=()) -> None:
        fixtures.ArtifactPreparationTests.begin(self, record, amendments=amendments)
        self.record_review()

    def record_review(self, *, verdict="APPROVE", findings=None) -> None:
        observed = binding.observe(str(self.repo), self.initial, self.candidate, self.projection, self.amendments)
        self.assertFalse(observed["errors"])
        snapshot = observed["snapshot"]
        context = {"review_id": "EXAMPLE-final-review-1", "reviewer": "EXAMPLE reviewer, not authenticated",
                   "verdict": verdict, "snapshot": copy.deepcopy(snapshot)}
        review = {"record_type": "cwo-experimental-final-review", "version": 1, "context": copy.deepcopy(context),
                  "findings": copy.deepcopy(findings or []), "summary": "EXAMPLE fixture review; approval remains unverified."}
        path = self.tmp / "EXAMPLE-review.json"
        path.write_text(json.dumps(review, ensure_ascii=False), encoding="utf-8")
        expected_bytes = path.read_bytes()
        self.raw = artifacts._document(str(path))
        self.expected = {"record_type": "cwo-experimental-final-review-expectation", "version": 1,
                         "context": context, "raw_review_sha256": "sha256:" + hashlib.sha256(expected_bytes).hexdigest()}

    def assert_held(self, result: dict) -> None:
        for key in binding.FALSE_FIELDS:
            self.assertIs(result[key], False)
        for name in ("W06", "#37", "W07", "M1a"):
            self.assertIn(name, result["remaining_open"])
        for spy in self.effect_spies:
            spy.assert_not_called()

    def prepare(self, **overrides) -> dict:
        options = {"root": str(self.repo), "initial": self.initial,
                   "candidate": self.candidate, "bead": self.projection,
                   "raw": self.raw, "expected": self.expected, "amendments": self.amendments}
        options.update(overrides)
        result = binding.prepare(**options)
        self.assert_held(result)
        return result

    def consume(self, prepared: dict, **overrides) -> dict:
        options = {"root": str(self.repo), "initial": self.initial,
                   "candidate": self.candidate, "bead": self.projection,
                   "raw": self.raw, "expected": self.expected, "amendments": self.amendments}
        options.update(overrides)
        result = binding.consume(prepared, **options)
        self.assert_held(result)
        return result

    def replace_review(self, review: dict, *, expect=True) -> None:
        self.raw = json.dumps(review, ensure_ascii=False).encode("utf-8")
        if expect:
            self.expected["raw_review_sha256"] = "sha256:" + hashlib.sha256(self.raw).hexdigest()

    def cli(self, mode: str, prepared=None, override=None) -> tuple[int, dict]:
        inputs = {"baseline": self.initial, "candidate": self.candidate, "bead-json": self.projection}
        if mode != "observe":
            inputs["expected-context"] = self.expected
        if mode == "check":
            inputs["prepared"] = prepared
        argv = [mode, "--root", str(self.repo)]
        files = {}
        for name, value in inputs.items():
            path = self.tmp / f"EXAMPLE-{name}.json"
            path.write_text(json.dumps(value, ensure_ascii=False), encoding="utf-8")
            files[name] = path
            argv.extend(("--" + name, str(path)))
        for index, change in enumerate(self.amendments):
            path = self.tmp / f"EXAMPLE-amendment-{index}.json"
            path.write_text(json.dumps(change), encoding="utf-8")
            argv.extend(("--amendment", str(path)))
        if mode != "observe":
            path = self.tmp / "EXAMPLE-current-review.json"
            path.write_bytes(self.raw)
            files["review"] = path
            argv.extend(("--review", str(path)))
        if override is not None:
            name, data = override
            files[name].write_bytes(data)
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = binding.main(argv)
        self.assertEqual(stderr.getvalue(), "")
        result = json.loads(stdout.getvalue())
        self.assert_held(result)
        return code, result

    def test_matching_complete_snapshot_has_a_real_non_authoritative_positive(self) -> None:
        self.start()
        prepared = self.prepare()
        self.assertTrue(prepared["binding_consistent"])
        self.assertEqual(prepared["binding"]["raw_review"].encode("utf-8"), self.raw)
        self.assertEqual(prepared["binding"]["expected"], self.expected)
        self.assertIs(prepared["artifact_observations_complete"], True)
        self.assertIs(self.consume(copy.deepcopy(prepared))["binding_consistent"], True)
        code, result = self.cli("prepare")
        self.assertEqual(code, 0)
        self.assertEqual(result, prepared)
        code, result = self.cli("check", prepared)
        self.assertEqual(code, 0)
        self.assertTrue(result["binding_consistent"])

    def test_guards_have_positive_controls_before_supported_observation(self) -> None:
        for spy in self.effect_spies:
            with self.assertRaises(AssertionError):
                spy()
            spy.reset_mock()
        with self.assertRaises(AssertionError):
            subprocess.Popen(["EXAMPLE-model-review-command"])
        self.start()
        self.assertTrue(self.prepare()["binding_consistent"])

    def test_file_permission_and_untracked_changes_invalidate_public_consumers(self) -> None:
        self.start()
        prepared = self.prepare()
        path = self.repo / "src/new.txt"
        mode = path.stat().st_mode & 0o7777
        changes = (
            (lambda: path.write_bytes(b"EXAMPLE edited content\n"), lambda: path.write_bytes(fixtures.NEW)),
            (lambda: path.chmod(mode ^ 0o020), lambda: path.chmod(mode)),
            (lambda: (self.repo / "src/EXAMPLE-extra").write_bytes(b"EXAMPLE"), lambda: (self.repo / "src/EXAMPLE-extra").unlink()),
        )
        for change, restore in changes:
            with self.subTest(change=change):
                change()
                try:
                    self.assertFalse(self.consume(prepared)["binding_consistent"])
                    code, result = self.cli("check", prepared)
                    self.assertEqual(code, 1)
                    self.assertFalse(result["binding_consistent"])
                finally:
                    restore()
                self.assertTrue(self.consume(prepared)["binding_consistent"])

    def test_edit_during_actual_artifact_observation_is_refused(self) -> None:
        self.start()
        prepared = self.prepare()
        original = artifacts._artifact

        def change(*args):
            result = original(*args)
            if args[1] == "src/new.txt":
                (self.repo / "src/new.txt").write_bytes(b"EXAMPLE changed after observation\n")
            return result

        with patch.object(artifacts, "_artifact", side_effect=change):
            result = self.consume(prepared)
        self.assertFalse(result["binding_consistent"])

    def test_additive_amendment_positive_and_prior_review_invalidation(self) -> None:
        prior = fixtures.baseline()
        current = fixtures.baseline(fixtures.criterion("EXAMPLE-added", {
            "op": "regular-file-sha256", "path": "src/anchor.txt", "sha256": hashlib.sha256(b"anchor\n").hexdigest()}))
        current["baseline_version"] = 2
        addition = fixtures.amendment(prior, current)
        (self.tmp / "EXAMPLE-planned-amendment.json").write_text(json.dumps(addition), encoding="utf-8")
        self.start(prior)
        old = self.prepare()
        self.amendments = [addition]
        self.chain = rb.resolve_chain(self.initial, self.amendments)
        self.candidate = ci.capture_candidate(self.repo, chain=self.chain, base_commit=self.base,
                                              scope_paths=("src",))
        self.projection = {"id": self.chain["bead_id"], "comments": [
            {"text": rb.reference_line(self.chain["bead_id"], entry["version"], entry["digest"])}
            for entry in self.chain["baselines"]]}
        self.projection["comments"].append({"text": ci.candidate_reference_line(
            self.chain["bead_id"], ci.candidate_digest(self.candidate))})
        self.assertFalse(self.consume(old)["binding_consistent"])
        self.record_review()
        current_prepared = self.prepare()
        self.assertTrue(current_prepared["binding_consistent"])
        self.assertTrue(self.consume(current_prepared)["binding_consistent"])

    def test_claimed_snapshot_cannot_replace_real_observation(self) -> None:
        self.start()
        prepared = self.prepare()
        def remove(snapshot):
            snapshot["criterion_inventory"].pop()

        def duplicate(snapshot):
            snapshot["resolved_baseline"]["baseline"]["criteria"].append(
                copy.deepcopy(snapshot["resolved_baseline"]["baseline"]["criteria"][0]))

        def replace(snapshot):
            snapshot["initial_baseline"]["criteria"][0]["expected_outcome"] = "EXAMPLE replaced obligation"

        def report(snapshot):
            snapshot["artifact_report"]["criteria"] = []
            snapshot["artifact_report"]["artifact_observations_complete"] = True
            snapshot["artifact_report"]["report_digest"] = "sha256:" + "0" * 64

        changes = (remove, duplicate, replace, report,
                   lambda value: value["candidate"].update(tree="0" * 40),
                   lambda value: value["bead_projection"]["comments"].append({"text": "EXAMPLE new projection"}))
        original_expected = copy.deepcopy(self.expected)
        original_review = json.loads(self.raw)
        for change in changes:
            with self.subTest(change=change):
                self.expected = copy.deepcopy(original_expected)
                change(self.expected["context"]["snapshot"])
                review = copy.deepcopy(original_review)
                review["context"] = copy.deepcopy(self.expected["context"])
                self.replace_review(review)
                self.assertFalse(self.prepare()["binding_consistent"])
                self.assertFalse(self.consume(prepared)["binding_consistent"])
                code, result = self.cli("prepare")
                self.assertEqual(code, 1)
                self.assertFalse(result["binding_consistent"])

    def test_invalid_current_baseline_is_refused_by_real_baseline_validation(self) -> None:
        self.start()
        prepared = self.prepare()
        for mutation in ("omitted", "replaced", "duplicate", "extra", "bool"):
            current = copy.deepcopy(self.initial)
            if mutation == "omitted": current["criteria"].pop()
            elif mutation == "replaced": current["criteria"][0]["requirement"] = "EXAMPLE replacement"
            elif mutation == "duplicate": current["criteria"].append(copy.deepcopy(current["criteria"][0]))
            elif mutation == "extra": current["criteria"][0]["unknown"] = "EXAMPLE unsupported"
            else: current["version"] = True
            with self.subTest(mutation=mutation):
                self.assertFalse(self.prepare(initial=current)["binding_consistent"])
                self.assertFalse(self.consume(prepared, initial=current)["binding_consistent"])

    def test_wrong_context_raw_bytes_and_verdict_refuse_every_wrapper(self) -> None:
        self.start()
        prepared = self.prepare()
        review = json.loads(self.raw)
        original = copy.deepcopy(self.expected)
        for field, value in (("review_id", "EXAMPLE other review"), ("reviewer", "EXAMPLE other reviewer"),
                             ("verdict", "REJECT")):
            with self.subTest(field=field):
                self.expected = copy.deepcopy(original)
                altered = copy.deepcopy(review)
                altered["context"][field] = value
                self.replace_review(altered)
                self.assertFalse(self.prepare()["binding_consistent"])
                code, result = self.cli("check", prepared)
                self.assertEqual(code, 1)
                self.assertFalse(result["binding_consistent"])
        self.expected = copy.deepcopy(original)
        altered = copy.deepcopy(review)
        altered["summary"] = "EXAMPLE altered full review observation"
        self.replace_review(altered)
        self.assertTrue(self.prepare()["binding_consistent"])
        self.assertFalse(self.consume(prepared)["binding_consistent"])
        self.expected = copy.deepcopy(original)
        self.raw = json.dumps(review).encode("utf-8")
        self.raw += b"\n"
        self.assertFalse(self.prepare()["binding_consistent"])
        self.assertFalse(self.consume(prepared)["binding_consistent"])
        code, result = self.cli("prepare")
        self.assertEqual(code, 1)
        self.assertFalse(result["binding_consistent"])

    def test_nonapproval_is_preserved_and_approve_with_open_blocker_is_refused(self) -> None:
        self.start()
        finding = {"id": "EXAMPLE-blocker", "blocking": True, "state": "OPEN", "text": "EXAMPLE unresolved finding"}
        for verdict in ("REQUEST_CHANGES", "REJECT", "ABSTAIN"):
            self.record_review(verdict=verdict, findings=[finding])
            prepared = self.prepare()
            self.assertTrue(prepared["binding_consistent"])
            self.assertEqual(prepared["review_verdict"], verdict)
            self.assertEqual(prepared["unresolved_blocking_finding_ids"], ["EXAMPLE-blocker"])
            self.assertTrue(self.consume(prepared)["binding_consistent"])
        self.record_review(findings=[finding])
        refused = self.prepare()
        self.assertFalse(refused["binding_consistent"])
        self.assertEqual(refused["unresolved_blocking_finding_ids"], ["EXAMPLE-blocker"])
        code, result = self.cli("prepare")
        self.assertEqual(code, 1)
        self.assertFalse(result["binding_consistent"])

    def test_unsupported_criteria_stay_unassessable_in_a_consistent_binding(self) -> None:
        self.start(fixtures.baseline(
            fixtures.criterion("EXAMPLE-validator", "EXAMPLE validator remains unavailable", "validator"),
            fixtures.criterion("EXAMPLE-review", "EXAMPLE substantive review remains unavailable", "review-gate")))
        prepared = self.prepare()
        self.assertTrue(prepared["binding_consistent"])
        self.assertFalse(prepared["artifact_observations_complete"])
        snapshot = prepared["binding"]["expected"]["context"]["snapshot"]
        statuses = {entry["id"]: entry["status"] for entry in snapshot["artifact_report"]["criteria"]}
        self.assertEqual(statuses["EXAMPLE-validator"], "UNASSESSABLE")
        self.assertEqual(statuses["EXAMPLE-review"], "UNASSESSABLE")
        self.assertFalse(self.consume(prepared)["artifact_observations_complete"])
        code, result = self.cli("check", prepared)
        self.assertEqual(code, 0)
        self.assertFalse(result["artifact_observations_complete"])

    def test_unavailable_supported_observation_refuses_and_unrelated_errors_remain_visible(self) -> None:
        self.start()
        with patch.object(artifacts, "_read_regular", side_effect=PermissionError("EXAMPLE unreadable")):
            result = self.prepare()
        self.assertFalse(result["binding_consistent"])
        with patch.object(artifacts, "prepare", side_effect=RuntimeError("EXAMPLE unrelated failure")):
            with self.assertRaisesRegex(RuntimeError, "EXAMPLE unrelated"):
                self.prepare()

    def test_closed_review_shapes_reject_aliases_and_unknown_fields(self) -> None:
        self.start()
        original = json.loads(self.raw)
        expected = copy.deepcopy(self.expected)
        def alias(review): review["version"] = True
        def extra(review): review["unknown"] = "EXAMPLE"
        def missing(review): del review["summary"]
        def finding_alias(review): review["findings"] = [
            {"id": "EXAMPLE-finding", "blocking": 1, "state": "OPEN", "text": "EXAMPLE finding"}]
        def duplicate(review):
            entry = {"id": "EXAMPLE-finding", "blocking": False, "state": "OPEN", "text": "EXAMPLE finding"}
            review["findings"] = [entry, dict(entry)]
        for change in (alias, extra, missing, finding_alias, duplicate):
            with self.subTest(change=change):
                review = copy.deepcopy(original)
                change(review)
                self.replace_review(review)
                self.assertFalse(self.prepare()["binding_consistent"])
                code, result = self.cli("prepare")
                self.assertEqual(code, 1)
                self.assertFalse(result["binding_consistent"])
        self.expected = copy.deepcopy(expected)
        self.raw = json.dumps(original).encode("utf-8")
        self.expected["version"] = True
        self.assertFalse(self.prepare()["binding_consistent"])

    def test_malformed_large_and_native_parser_inputs_refuse_before_observation(self) -> None:
        self.start()
        prepared = self.prepare()
        invalid = (
            b"\xff", b'{"x":1,"x":2}', b"{", b'{"x":' + b"[" * 40 + b"0" + b"]" * 40 + b"}",
            b'{"x":NaN}', b'{"x":1.5}', b'{"x":' + b"9" * 4400 + b"}",
            b'{"x":"\\ud800"}', b"x" * (artifacts.MAX_DOCUMENT + 1),
        )
        for data in invalid:
            for mode in ("prepare", "check"):
                with self.subTest(mode=mode, size=len(data)):
                    with patch.object(artifacts, "prepare", wraps=artifacts.prepare) as observer:
                        code, result = self.cli(mode, prepared, override=("expected-context", data))
                        self.assertEqual(code, 1)
                        self.assertFalse(result["binding_consistent"])
                        observer.assert_not_called()
        code, result = self.cli("prepare", override=("review", b'{"x":1,"x":2}'))
        self.assertEqual(code, 1)
        self.assertFalse(result["binding_consistent"])

    def test_library_depth_and_size_refuse_before_reader(self) -> None:
        self.start()
        deep = {}
        deep["loop"] = deep
        for expected in (deep, {"EXAMPLE": "x" * (artifacts.MAX_DOCUMENT + 1)}):
            with patch.object(artifacts, "prepare", wraps=artifacts.prepare) as observer:
                result = self.prepare(expected=expected)
            self.assertFalse(result["binding_consistent"])
            observer.assert_not_called()

    def test_caller_inputs_are_frozen_before_observer_reentry(self) -> None:
        self.start()
        original = artifacts.prepare
        saved = copy.deepcopy((self.initial, self.candidate, self.projection, self.expected))

        def reenter(*args, **kwargs):
            self.initial["criteria"].clear()
            self.candidate["tree"] = "0" * 40
            self.projection["comments"].clear()
            self.expected["context"]["verdict"] = "REJECT"
            result = original(*args, **kwargs)
            args[1]["criteria"].clear()
            return result

        with patch.object(artifacts, "prepare", side_effect=reenter):
            prepared = self.prepare()
        self.assertTrue(prepared["binding_consistent"])
        self.initial, self.candidate, self.projection, self.expected = saved
        self.assertTrue(self.consume(prepared)["binding_consistent"])

    def test_artifact_report_is_frozen_before_later_observation_helpers(self) -> None:
        self.start()
        original = artifacts.prepare
        predicate = artifacts._predicate
        borrowed = []

        def remember(*args, **kwargs):
            report = original(*args, **kwargs)
            borrowed.append(report)
            return report

        def reenter(*args, **kwargs):
            if borrowed:
                borrowed[0]["criteria"].clear()
            return predicate(*args, **kwargs)

        with patch.object(artifacts, "prepare", side_effect=remember), \
                patch.object(artifacts, "_predicate", side_effect=reenter):
            prepared = self.prepare()
        self.assertTrue(prepared["binding_consistent"])
        self.assertEqual(len(borrowed[0]["criteria"]), 0)
        self.assertTrue(self.consume(prepared)["binding_consistent"])

    def test_preparation_keeps_success_held_and_noncompletion_dry_run_usable(self) -> None:
        self.start()
        self.assertTrue(self.prepare()["binding_consistent"])
        args = closure.parser().parse_args(["--bead", "EXAMPLE-bead", "--disposition", "completed",
                                           "--why", "EXAMPLE delivered", "--close"])
        with self.assertRaisesRegex(ValueError, "successful closure is unavailable"):
            CLOSURE_EXECUTE(args)
        args = closure.parser().parse_args(["--bead", "EXAMPLE-bead", "--disposition", "pending-acceptance",
                                           "--why", "EXAMPLE review remains open", "--dry-run"])
        result = CLOSURE_EXECUTE(args)
        self.assertFalse(result["comment_posted"])
        self.assertFalse(result["closed"])
        self.assert_held(self.prepare())

    def test_cli_argument_bounds_refuse_before_reading(self) -> None:
        for argv in (["observe", "--amendment", "EXAMPLE"] * 40, ["EXAMPLE" * 12000], ["--help"]):
            stdout = io.StringIO()
            with patch.object(artifacts, "_document", wraps=artifacts._document) as reader, \
                    contextlib.redirect_stdout(stdout):
                code = binding.main(argv)
            self.assertEqual(code, 1)
            self.assert_held(json.loads(stdout.getvalue()))
            reader.assert_not_called()


if __name__ == "__main__":
    unittest.main()
