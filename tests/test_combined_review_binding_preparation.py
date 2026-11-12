"""Combined reliability observations with real producers and EXAMPLE review data."""
from __future__ import annotations

import contextlib
import copy
import hashlib
import io
import json
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import close_bead_with_summary as closure  # noqa: E402
import prepare_combined_review_binding as binding  # noqa: E402
import prepare_final_review_binding as final_review  # noqa: E402
import prepare_validator_receipts as validators  # noqa: E402
from cwo_core import candidate_identity as ci  # noqa: E402
from cwo_core import checked_command as cc  # noqa: E402
from cwo_core import requirement_baseline as rb  # noqa: E402
from tests import test_artifact_acceptance_preparation as af  # noqa: E402
from tests import test_validator_receipt_preparation as vf  # noqa: E402

CLOSURE_EXECUTE = closure.execute


class CombinedReviewBindingTests(unittest.TestCase):
    def test_bounded_text_preserves_exact_type_nonempty_and_printable_contract(self) -> None:
        class ExampleText(str):
            def strip(self):
                raise AssertionError("EXAMPLE subclasses must refuse before transformation")

        for limit in (64, 4000):
            for value in ("EXAMPLE", " EXAMPLE ", "EXAMPLE café", "x" * (limit - 1), "x" * limit):
                with self.subTest(limit=limit, length=len(value)):
                    self.assertIsNone(binding._text(value, limit))
            for value in (None, b"EXAMPLE", True, 0, ExampleText("EXAMPLE"), "", " " * limit,
                          "\tEXAMPLE", "EXAMPLE\n", "EXAMPLE\x00", "x" * (limit + 1)):
                with self.subTest(limit=limit, kind=type(value).__name__):
                    with self.assertRaisesRegex(
                            binding.PreparationError, "^review text must be nonempty bounded printable text$"):
                        binding._text(value, limit)

    def begin(self, variant="passed", *, extra=(), additive=False, artifact_bytes=vf.AFTER) -> None:
        self.workspace = vf.TempGit(self)
        self.repo = self.workspace.root
        self.specs = {
            "passed": vf.spec(self.repo, "EXAMPLE-command", "print('EXAMPLE validator output')\n"),
            "failed": vf.spec(self.repo, "EXAMPLE-failed", "raise SystemExit(7)\n"),
            "refused": vf.spec(self.repo, "EXAMPLE-refused", "def EXAMPLE_invalid(:\n"),
            "additional": vf.spec(self.repo, "EXAMPLE-additional", "print('EXAMPLE validator output')\n# EXAMPLE check\n"),
        }
        chosen = self.specs[variant]
        expected = vf.OUTPUT if variant == "passed" else b""
        item = af.criterion("EXAMPLE-artifact", {
            "op": "regular-file-sha256", "path": "src/item.txt", "sha256": vf.sha(vf.AFTER)})
        unused = vf.criterion("EXAMPLE-unused", "EXAMPLE unused review obligation.", "review-gate")
        unused.update(applicability="not-applicable", not_applicable_reason="EXAMPLE scope excludes this obligation.")
        self.initial = {
            "record_type": rb.BASELINE_RECORD_TYPE, "version": 1, "bead_id": "EXAMPLE-bead",
            "baseline_version": 1, "criteria": [item, vf.validator("EXAMPLE-validator", chosen, expected), unused, *extra],
        }
        self.amendments = []
        if additive:
            current = copy.deepcopy(self.initial)
            current["baseline_version"] = 2
            current["criteria"].append(vf.validator("EXAMPLE-added", self.specs["additional"], vf.OUTPUT))
            self.amendments = [vf.amendment(self.initial, current)]
        self.chain = rb.resolve_chain(self.initial, self.amendments)
        self.bead = {"id": self.chain["bead_id"], "comments": [
            {"text": rb.reference_line(self.chain["bead_id"], entry["version"], entry["digest"])}
            for entry in self.chain["baselines"]]}
        parent = self.repo.parent
        (parent / "EXAMPLE-baseline.json").write_text(json.dumps(self.initial), encoding="utf-8")
        (parent / "EXAMPLE-amendments.json").write_text(json.dumps(self.amendments), encoding="utf-8")
        (parent / "EXAMPLE-projection.json").write_text(json.dumps(self.bead), encoding="utf-8")
        (self.repo / "src/item.txt").write_bytes(artifact_bytes)
        self.candidate = ci.capture_candidate(self.repo, chain=self.chain, base_commit=self.workspace.base, scope_paths=["src"])
        self.bead["comments"].append({"text": ci.candidate_reference_line(
            self.chain["bead_id"], ci.candidate_digest(self.candidate))})
        self.receipts = {key: cc.execute_checked_command(command) for key, command in self.specs.items()}
        self.evidence = [self.wrapper("EXAMPLE-validator", variant)]
        if additive:
            self.evidence.append(self.wrapper("EXAMPLE-added", "additional"))
        self.evidence_path = parent / "EXAMPLE-receipts.json"
        self.evidence_path.write_text(json.dumps(self.evidence), encoding="utf-8")

    def wrapper(self, criterion_id: str, key: str) -> dict:
        return {
            "record_type": validators.EVIDENCE_TYPE, "version": 1, "criterion_id": criterion_id,
            "baseline_digest": self.chain["digest"], "candidate_digest": ci.candidate_digest(self.candidate),
            "spec": copy.deepcopy(self.specs[key]), "result": copy.deepcopy(self.receipts[key]),
        }

    def context(self) -> dict:
        return {
            "record_type": binding.INPUT_TYPE, "version": 1, "root": str(self.repo),
            "baseline": self.initial, "amendments": self.amendments, "candidate": self.candidate,
            "bead": self.bead, "validator_evidence": self.evidence,
        }

    def assert_held(self, result: dict) -> None:
        for field in binding.FALSE_FIELDS:
            self.assertIs(result[field], False)
        for gap in ("W06", "#37", "protected-custody", "W05-holds", "W09-holds", "W08-holds", "M1a"):
            self.assertIn(gap, result["remaining_open"])

    def call(self, mode, *, prepared=None, context=None, raw=None, expected=None) -> dict:
        data = self.context() if context is None else context
        watch = vf.EffectWatch(self, self.repo, self.specs["passed"])
        with watch.installed(require_capture=False):
            if mode == "observe":
                result = binding.observe(data)
            elif mode == "prepare":
                result = binding.prepare(data, self.raw if raw is None else raw, self.expected if expected is None else expected)
            else:
                result = binding.consume(prepared, data, self.raw if raw is None else raw,
                                         self.expected if expected is None else expected)
        self.assert_held(result)
        if result["snapshot"] is not None:
            self.assertGreaterEqual(watch.capture_calls, 2)
        return result

    def review(self, verdict="APPROVE", findings=None) -> None:
        observed = self.call("observe")
        self.assertEqual(observed["errors"], [])
        context = {"review_id": "EXAMPLE-combined-review", "reviewer": "EXAMPLE unauthenticated reviewer",
                   "verdict": verdict, "snapshot": copy.deepcopy(observed["snapshot"])}
        review = {"record_type": binding.REVIEW_TYPE, "version": 1, "context": copy.deepcopy(context),
                  "findings": copy.deepcopy([] if findings is None else findings),
                  "summary": "EXAMPLE reliability review with no production authority."}
        raw = json.dumps(review, ensure_ascii=False).encode("utf-8")
        path = self.repo.parent / "EXAMPLE-review.json"
        path.write_bytes(raw)
        self.raw = path.read_bytes()
        self.expected = {"record_type": binding.EXPECTATION_TYPE, "version": 1, "context": context,
                         "raw_review_sha256": "sha256:" + hashlib.sha256(self.raw).hexdigest()}

    def replace_review(self, review: dict) -> None:
        self.raw = json.dumps(review, ensure_ascii=False).encode("utf-8")
        self.expected["raw_review_sha256"] = "sha256:" + hashlib.sha256(self.raw).hexdigest()

    def cli(self, mode, prepared=None, *, data=None, args=()) -> tuple[int, dict]:
        if data is None:
            document = {"record_type": binding.CLI_TYPE, "version": 1, "mode": mode, "context": self.context()}
            if mode != "observe":
                document.update(raw_review=self.raw.decode("utf-8"), expected=self.expected)
            if mode == "check":
                document["prepared"] = prepared
            data = json.dumps(document, ensure_ascii=False).encode("utf-8")
        stdout, stderr = io.StringIO(), io.StringIO()
        with patch.object(sys, "stdin", SimpleNamespace(buffer=io.BytesIO(data))), \
                contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr), \
                vf.EffectWatch(self, self.repo, self.specs["passed"]).installed(require_capture=False):
            code = binding.main(list(args))
        self.assertEqual(stderr.getvalue(), "")
        result = json.loads(stdout.getvalue())
        self.assert_held(result)
        self.assertNotIn("snapshot", result)
        self.assertNotIn("binding", result)
        self.assertNotIn("EXAMPLE validator output", stdout.getvalue())
        return code, result

    def component_boundary(self) -> tuple[dict, bytes, int]:
        context = copy.deepcopy(self.context())
        document = {**context, "record_type": validators.INPUT_TYPE}
        envelope = {"record_type": binding.CLI_TYPE, "version": 1, "mode": "observe", "context": context}
        diagnostics = context["validator_evidence"][0]["result"]["diagnostics"]
        diagnostics["stderr"] = "EXAMPLE_"
        outer = len(json.dumps(envelope, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                               allow_nan=False).encode("utf-8"))
        spaced = len(json.dumps(document, ensure_ascii=False, allow_nan=False).encode("utf-8"))
        self.assertEqual(binding.MAX_DOCUMENT, 4 * 1024 * 1024)
        self.assertEqual(validators.MAX_INPUT, binding.MAX_DOCUMENT)
        self.assertGreater(spaced, outer)
        fill = binding.MAX_DOCUMENT - outer - 1
        self.assertGreater(fill, 0)
        diagnostics["stderr"] += "x" * fill
        raw = json.dumps(envelope, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                         allow_nan=False).encode("utf-8")
        producer_bytes = len(json.dumps(document, ensure_ascii=False, allow_nan=False).encode("utf-8"))
        self.assertEqual(len(raw), binding.MAX_DOCUMENT - 1)
        self.assertLessEqual(len(binding._encode(context)), binding.MAX_DOCUMENT)
        self.assertGreater(producer_bytes, validators.MAX_INPUT)
        return context, raw, producer_bytes

    def component_reports(self, context: dict) -> tuple[dict, dict]:
        with vf.EffectWatch(self, self.repo, self.specs["passed"]).installed():
            artifact = final_review.observe(context["root"], context["baseline"], context["candidate"],
                                            context["bead"], context["amendments"])
            validator = validators.prepare(context["root"], context["baseline"], context["candidate"],
                                           context["bead"], context["validator_evidence"], context["amendments"])
        return artifact, validator

    def assert_prerequisite_refusal(self, report: dict, *, cli=False) -> None:
        self.assert_held(report)
        self.assertEqual(report["errors"], [
            "validator observation prerequisite bindings are unavailable or malformed"])
        self.assertIs(report["binding_consistent"], False)
        self.assertIs(report["combined_observations_complete"], False)
        self.assertLessEqual(len(binding._encode(report)), 4096)
        if cli:
            self.assertIs(report["snapshot_available"], False)
        else:
            self.assertIsNone(report["snapshot"])
            self.assertIsNone(report["binding"])

    def test_real_component_spacing_refusal_is_bounded_for_library_and_cli(self) -> None:
        self.begin()
        context, raw, _ = self.component_boundary()
        artifact, validator = self.component_reports(context)
        self.assertEqual(artifact["errors"], [])
        self.assertIsInstance(artifact["snapshot"], dict)
        self.assertTrue(validator["errors"])
        self.assertEqual(validator["bindings"], {})
        self.assertEqual(validator["candidate_checks"], {"before": [], "after": []})
        with self.assertRaisesRegex(binding.PreparationError, "validator observation prerequisite bindings"):
            binding._prerequisite_bindings(validator, "validator")
        self.assert_prerequisite_refusal(self.call("observe", context=context))
        code, report = self.cli("observe", data=raw)
        self.assertEqual(code, 1)
        self.assert_prerequisite_refusal(report, cli=True)

    def test_nearby_real_producer_admission_keeps_honest_incomplete_observations(self) -> None:
        self.begin()
        context, _, producer_bytes = self.component_boundary()
        diagnostics = context["validator_evidence"][0]["result"]["diagnostics"]
        diagnostics["stderr"] = diagnostics["stderr"][:-(producer_bytes - validators.MAX_INPUT)]
        document = {**context, "record_type": validators.INPUT_TYPE}
        self.assertEqual(len(json.dumps(document, ensure_ascii=False, allow_nan=False).encode("utf-8")),
                         validators.MAX_INPUT)
        artifact, validator = self.component_reports(context)
        self.assertEqual(artifact["errors"], [])
        self.assertEqual(validator["errors"], [])
        self.assertEqual(validator["candidate_checks"], {"before": [], "after": []})
        self.assertIs(validator["observations_complete"], False)
        self.assertIs(artifact["artifact_observations_complete"], False)
        self.assertEqual(validator["criteria"][1]["state"], "INCONSISTENT")
        self.assertEqual(validator["criteria"][1]["reason"], "receipt diagnostics must retain bounded producer text")
        for component, report in (("artifact", artifact["snapshot"]["artifact_report"]), ("validator", validator)):
            binding._bindings(binding._prerequisite_bindings(report, component), context, self.chain)

    def test_real_component_spacing_refusal_reaches_prepare_and_consume(self) -> None:
        self.begin()
        self.review()
        prepared = self.call("prepare")
        self.assertTrue(prepared["binding_consistent"])
        self.assertTrue(prepared["combined_observations_complete"])
        context, _, _ = self.component_boundary()
        for mode in ("prepare", "check"):
            with self.subTest(mode=mode):
                result = self.call(mode, prepared=prepared, context=context)
                self.assert_prerequisite_refusal(result)
        self.assertTrue(self.call("check", prepared=prepared)["binding_consistent"])

    def test_real_component_binding_fields_require_available_exact_shapes(self) -> None:
        self.begin()
        artifact, validator = self.component_reports(self.context())
        for component, report in (("artifact", artifact["snapshot"]["artifact_report"]), ("validator", validator)):
            self.assertEqual(binding._prerequisite_bindings(report, component), report["bindings"])
            for field in report["bindings"]:
                for missing in (True, False):
                    with self.subTest(component=component, field=field, missing=missing):
                        changed = copy.deepcopy(report)
                        if missing:
                            del changed["bindings"][field]
                        else:
                            changed["bindings"][field] = None
                        with self.assertRaisesRegex(binding.PreparationError, "prerequisite bindings"):
                            binding._prerequisite_bindings(changed, component)
            for value in (None, False, [], {}, "EXAMPLE unavailable bindings"):
                changed = copy.deepcopy(report)
                changed["bindings"] = value
                with self.assertRaisesRegex(binding.PreparationError, "prerequisite bindings"):
                    binding._prerequisite_bindings(changed, component)
            changed = copy.deepcopy(report)
            del changed["bindings"]
            with self.assertRaisesRegex(binding.PreparationError, "prerequisite bindings"):
                binding._prerequisite_bindings(changed, component)

    def test_real_mixed_positive_retains_whole_reports_and_no_authority(self) -> None:
        self.begin(additive=True)
        self.review()
        with patch.object(final_review, "observe", wraps=final_review.observe) as fa, \
                patch.object(validators, "prepare", wraps=validators.prepare) as vr:
            prepared = self.call("prepare")
        self.assertEqual((fa.call_count, vr.call_count), (2, 2))
        self.assertTrue(prepared["binding_consistent"], prepared["errors"])
        self.assertTrue(prepared["combined_observations_complete"])
        snapshot = prepared["snapshot"]
        self.assertEqual(snapshot["input_context"], self.context())
        self.assertEqual(snapshot["criterion_inventory"], self.chain["baseline"]["criteria"])
        self.assertEqual(snapshot["required_criterion_ids"], rb.required_criterion_ids(self.chain["baseline"]))
        self.assertFalse(snapshot["artifact_observation"]["artifact_observations_complete"])
        self.assertFalse(snapshot["validator_observation"]["observations_complete"])
        self.assertEqual([entry["state"] for entry in snapshot["criteria"]],
                         ["PASSED", "OBSERVED_CONSISTENT", "NOT_APPLICABLE", "OBSERVED_CONSISTENT"])
        self.assertEqual(snapshot["criteria"][2]["reason"], self.initial["criteria"][2]["not_applicable_reason"])
        self.assertEqual(prepared["binding"]["raw_review"].encode("utf-8"), self.raw)
        self.assertEqual(prepared["binding"]["expected"], self.expected)
        self.assertTrue(self.call("check", prepared=prepared)["binding_consistent"])
        for mode in ("observe", "prepare", "check"):
            self.assertEqual(self.cli(mode, prepared)[0], 0)

    def test_real_failed_missing_unrun_and_unrelated_receipts_remain_incomplete(self) -> None:
        for variant in ("failed", "refused", "passed"):
            with self.subTest(variant=variant):
                self.begin(variant)
                if variant == "passed":
                    self.evidence = [self.wrapper("EXAMPLE-validator", "additional")]
                self.review("REQUEST_CHANGES")
                result = self.call("prepare")
                self.assertTrue(result["binding_consistent"], result["errors"])
                self.assertFalse(result["combined_observations_complete"])
                self.assertTrue(self.call("check", prepared=result)["binding_consistent"])
                self.review()
                self.assertFalse(self.call("prepare")["binding_consistent"])
        self.begin()
        self.evidence = []
        self.review("ABSTAIN")
        self.assertTrue(self.call("prepare")["binding_consistent"])
        self.assertFalse(self.call("prepare")["combined_observations_complete"])

    def test_receipt_context_source_spec_stdout_and_numeric_changes_never_complete(self) -> None:
        self.begin()
        original = copy.deepcopy(self.evidence)
        for field, value in (
            ("baseline_digest", "sha256:" + "0" * 64), ("candidate_digest", "sha256:" + "1" * 64),
            ("result.diagnostics.stdout", "EXAMPLE wrong stdout\n"), ("result.spec_sha256", "0" * 64),
            ("spec.source", "print('EXAMPLE other output')\n"), ("result.executed_sha256", "0" * 64),
            ("result.exit_code", False), ("result.execution_started", 1), ("result.version", True),
        ):
            self.evidence = copy.deepcopy(original)
            target = self.evidence[0]
            parts = field.split(".")
            for part in parts[:-1]:
                target = target[part]
            target[parts[-1]] = value
            with self.subTest(field=field):
                self.review("REJECT")
                self.assertFalse(self.call("prepare")["combined_observations_complete"])
                self.assertTrue(self.call("prepare")["binding_consistent"])

    def test_failed_and_missing_artifacts_and_unsupported_criteria_keep_original_inventory(self) -> None:
        missing = af.criterion("EXAMPLE-missing", {
            "op": "regular-file-sha256", "path": "src/missing.txt", "sha256": vf.sha(vf.AFTER)})
        cases = (
            (b"EXAMPLE wrong artifact\n", ()),
            (vf.AFTER, (missing,)),
            (vf.AFTER, (
                vf.criterion("EXAMPLE-service", "EXAMPLE service remains stopped."),
                vf.criterion("EXAMPLE-prose", "EXAMPLE readable artifact review.", "artifact"),
                vf.criterion("EXAMPLE-gate", "EXAMPLE independent review remains required.", "review-gate"))),
        )
        for content, extra in cases:
            with self.subTest(content=content, extra=len(extra)):
                self.begin(extra=extra, artifact_bytes=content)
                self.review("REQUEST_CHANGES")
                prepared = self.call("prepare")
                self.assertTrue(prepared["binding_consistent"], prepared["errors"])
                self.assertFalse(prepared["combined_observations_complete"])
                self.assertEqual(prepared["snapshot"]["criterion_inventory"], self.chain["baseline"]["criteria"])
                self.review()
                self.assertFalse(self.call("prepare")["binding_consistent"])

    def test_omitted_replaced_stale_baselines_and_weakening_amendments_refuse(self) -> None:
        self.begin(additive=True)
        self.review()
        prepared = self.call("prepare")
        for mutation in ("omitted", "replaced", "stale", "weakening"):
            context = copy.deepcopy(self.context())
            if mutation == "omitted":
                context["baseline"]["criteria"].pop(0)
            elif mutation == "replaced":
                context["baseline"]["criteria"][0]["expected_outcome"] = "EXAMPLE replacement obligation."
            elif mutation == "stale":
                context["candidate"]["baseline"] = {"version": 1, "digest": rb.record_digest(self.initial)}
            else:
                weakened = copy.deepcopy(self.chain["baseline"])
                weakened["baseline_version"] = 3
                weakened["criteria"].pop(0)
                context["amendments"].append(vf.amendment(self.chain["baseline"], weakened))
            with self.subTest(mutation=mutation):
                self.assertFalse(self.call("check", prepared=prepared, context=context)["binding_consistent"])

    def test_review_hash_context_and_old_artifact_only_types_refuse(self) -> None:
        self.begin()
        self.review()
        original = json.loads(self.raw)
        for field, value in (
            ("record_type", "cwo-experimental-final-review"), ("version", True),
            ("summary", None), ("unknown", "EXAMPLE unsupported field"),
        ):
            review = copy.deepcopy(original)
            review[field] = value
            self.replace_review(review)
            with self.subTest(field=field):
                self.assertFalse(self.call("prepare")["binding_consistent"])
        self.review()
        self.raw += b"\n"
        self.assertFalse(self.call("prepare")["binding_consistent"])
        self.review()
        review = json.loads(self.raw)
        review["context"]["reviewer"] = "EXAMPLE other reviewer"
        self.replace_review(review)
        self.assertFalse(self.call("prepare")["binding_consistent"])

    def test_findings_shapes_and_declared_approve_conflicts_refuse(self) -> None:
        self.begin()
        finding = {"id": "EXAMPLE-finding", "blocking": False, "state": "OPEN", "text": "EXAMPLE reliability finding."}
        for findings in (
            [{**finding, "blocking": 1}], [finding, {**finding, "id": "example-FINDING"}],
            [{**finding, "state": False}], [{"id": "EXAMPLE-incomplete"}], {"EXAMPLE": []},
        ):
            self.review(findings=findings)
            self.assertFalse(self.call("prepare")["binding_consistent"])
        blocker = {**finding, "blocking": True}
        for verdict in ("REQUEST_CHANGES", "REJECT", "ABSTAIN", "APPROVE"):
            self.review(verdict, [blocker])
            self.assertIs(self.call("prepare")["binding_consistent"], verdict != "APPROVE")

    def test_saved_report_review_and_expected_snapshot_changes_invalidate_whole_binding(self) -> None:
        self.begin()
        self.review()
        prepared = self.call("prepare")
        for key, value in (("binding_consistent", False), ("operative", True), ("combined_observations_complete", False)):
            changed = copy.deepcopy(prepared)
            changed[key] = value
            self.assertFalse(self.call("check", prepared=changed)["binding_consistent"])
        for field in ("criterion_inventory", "artifact_observation", "validator_observation"):
            self.review()
            changed = copy.deepcopy(self.expected["context"]["snapshot"])
            if field == "criterion_inventory": changed[field].pop()
            else: changed[field]["errors"].append("EXAMPLE saved report change")
            self.expected["context"]["snapshot"] = changed
            review = json.loads(self.raw)
            review["context"] = copy.deepcopy(self.expected["context"])
            self.replace_review(review)
            self.assertFalse(self.call("prepare")["binding_consistent"])
        self.review()
        self.raw += b"\n"
        self.assertFalse(self.call("check", prepared=prepared)["binding_consistent"])

    def test_real_post_review_file_mode_untracked_and_receipt_edits_invalidate(self) -> None:
        self.begin()
        self.review()
        prepared = self.call("prepare")
        path = self.repo / "src/item.txt"
        mode = path.stat().st_mode & 0o7777
        extra = self.repo / "src/EXAMPLE-later.txt"
        for mutate, restore in (
            (lambda: path.write_bytes(b"EXAMPLE later bytes\n"), lambda: path.write_bytes(vf.AFTER)),
            (lambda: path.chmod(mode ^ 0o020), lambda: path.chmod(mode)),
            (lambda: extra.write_bytes(b"EXAMPLE new file\n"), lambda: extra.unlink()),
        ):
            mutate()
            try:
                self.assertFalse(self.call("check", prepared=prepared)["binding_consistent"])
            finally:
                restore()
            self.assertTrue(self.call("check", prepared=prepared)["binding_consistent"])
        evidence = copy.deepcopy(self.evidence)
        evidence[0]["result"]["diagnostics"]["stdout"] = "EXAMPLE changed stored receipt\n"
        self.evidence_path.write_text(json.dumps(evidence), encoding="utf-8")
        self.evidence = json.loads(self.evidence_path.read_text(encoding="utf-8"))
        self.assertFalse(self.call("check", prepared=prepared)["binding_consistent"])

    def test_edits_between_real_component_observations_refuse(self) -> None:
        self.begin()
        self.review()
        prepare = validators.prepare
        count = 0
        def edit(*args, **kwargs):
            nonlocal count
            result = prepare(*args, **kwargs)
            count += 1
            if count == 1:
                vf.external_edit(self.repo / "src/item.txt", b"EXAMPLE between observations\n")
            return result
        with patch.object(validators, "prepare", side_effect=edit):
            self.assertFalse(self.call("prepare")["binding_consistent"])

    def test_freezing_precedes_parser_and_component_reentry(self) -> None:
        self.begin(additive=True)
        self.review()
        saved = copy.deepcopy(self.context())
        expected = copy.deepcopy(self.expected)
        loads = json.loads
        mutated = False
        def reenter(*args, **kwargs):
            nonlocal mutated
            if not mutated:
                mutated = True
                self.initial["criteria"].clear()
                self.candidate["tree"] = "0" * 40
                self.bead["comments"].clear()
                self.evidence.clear()
                self.amendments.clear()
                self.expected["context"]["verdict"] = "REJECT"
            return loads(*args, **kwargs)
        with patch.object(binding.validators.json, "loads", side_effect=reenter):
            prepared = self.call("prepare")
        self.assertTrue(prepared["binding_consistent"], prepared["errors"])
        self.initial, self.amendments, self.candidate, self.bead, self.evidence = (
            saved["baseline"], saved["amendments"], saved["candidate"], saved["bead"], saved["validator_evidence"])
        self.expected = expected
        self.assertTrue(self.call("check", prepared=prepared)["binding_consistent"])

    def test_component_reports_are_frozen_and_unrelated_exceptions_remain_visible(self) -> None:
        self.begin()
        self.review()
        observe, prepare = final_review.observe, validators.prepare
        borrowed = []
        def remember(*args, **kwargs):
            result = observe(*args, **kwargs)
            borrowed.append(result)
            return result
        def mutate(*args, **kwargs):
            if borrowed:
                borrowed[-1]["snapshot"]["artifact_report"]["criteria"].clear()
            return prepare(*args, **kwargs)
        with patch.object(final_review, "observe", side_effect=remember), \
                patch.object(validators, "prepare", side_effect=mutate):
            self.assertTrue(self.call("prepare")["binding_consistent"])
        for module, name in ((final_review, "observe"), (validators, "prepare")):
            for error_type in (RuntimeError, TypeError, ValueError, KeyError):
                failure = error_type("EXAMPLE unrelated implementation failure")
                with patch.object(module, name, side_effect=failure), self.assertRaises(error_type) as caught:
                    self.call("prepare")
                self.assertIs(caught.exception, failure)

    def test_malformed_bounded_and_non_object_inputs_refuse_before_producers(self) -> None:
        self.begin()
        self.review()
        previous = sys.get_int_max_str_digits()
        invalid = (
            b'{"x":1,"x":2}', b"\xff", b'{"x":"\\ud800"}', b'{"x":1.5}', b'{"x":NaN}',
            b'{"x":' + b"9" * 4400 + b"}", b'{"x":' + b"[" * 40 + b"0" + b"]" * 40 + b"}",
            b" " * (binding.MAX_DOCUMENT + 1), b"[]", b"{",
        )
        with patch.object(final_review, "observe", wraps=final_review.observe) as fa, \
                patch.object(validators, "prepare", wraps=validators.prepare) as vr:
            for data in invalid:
                self.assertEqual(self.cli("prepare", data=data)[0], 1)
                self.assertTrue(self.call("prepare", raw=data)["errors"])
            self.assertEqual(self.cli("prepare", data=b"{}", args=("--context", "EXAMPLE-file.json"))[0], 1)
            for bead in (None, False, 1, "EXAMPLE", [], [self.bead], list(self.bead.items())):
                context = copy.deepcopy(self.context())
                context["bead"] = bead
                self.assertFalse(self.call("observe", context=context)["binding_consistent"])
            for expected in ({"EXAMPLE": 1.5}, {"EXAMPLE": 2**64}, {"EXAMPLE": object()}):
                self.assertTrue(self.call("prepare", expected=expected)["errors"])
            cycle = {}
            cycle["EXAMPLE"] = cycle
            self.assertTrue(self.call("prepare", expected=cycle)["errors"])
            fa.assert_not_called()
            vr.assert_not_called()
        self.assertEqual(sys.get_int_max_str_digits(), previous)

    def test_supported_large_text_and_aggregate_output_bounds(self) -> None:
        self.begin()
        self.bead["EXAMPLE-sequence"] = 2**63 - 1
        self.review()
        review = json.loads(self.raw)
        review["findings"] = [
            {"id": f"EXAMPLE-finding-{index}", "blocking": False, "state": "RESOLVED", "text": "EXAMPLE " + "a" * 2000}
            for index in range(40)]
        self.replace_review(review)
        positive = self.call("prepare")
        self.assertTrue(positive["binding_consistent"])
        limit = max(len(self.raw), len(binding._encode(self.expected)),
                    len(binding._encode(positive["snapshot"]))) + 1000
        self.assertGreater(len(binding._encode(positive)), limit)
        with patch.object(binding, "MAX_DOCUMENT", limit):
            result = self.call("prepare")
        self.assertFalse(result["binding_consistent"])
        self.assertTrue(result["errors"])

    def test_existing_closure_holds_remain_usable_and_watched(self) -> None:
        self.begin()
        self.review()
        with vf.EffectWatch(self, self.repo, self.specs["passed"]).installed(require_capture=False):
            args = closure.parser().parse_args(["--bead", "EXAMPLE-bead", "--disposition", "completed",
                                               "--why", "EXAMPLE delivery", "--close"])
            with self.assertRaisesRegex(ValueError, "successful closure is unavailable"):
                CLOSURE_EXECUTE(args)
            args = closure.parser().parse_args(["--bead", "EXAMPLE-bead", "--disposition", "pending-acceptance",
                                               "--why", "EXAMPLE reliability review remains open", "--dry-run"])
            result = CLOSURE_EXECUTE(args)
            self.assertFalse(result["closed"])
            self.assertFalse(result["comment_posted"])
        self.assertTrue(self.call("prepare")["binding_consistent"])


if __name__ == "__main__":
    unittest.main()
