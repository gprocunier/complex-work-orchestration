"""Offline client reliability checks using original producers and EXAMPLE fake reviews."""
from __future__ import annotations

import builtins
import contextlib
import copy
import io
import json
import os
import socket
import sys
import threading
import unittest
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "tests"))

import close_bead_with_summary as closure  # noqa: E402
import offline_artifact_validation as native_validation  # noqa: E402
import prepare_combined_review_binding as combined  # noqa: E402
import prepare_delivery_closure as offline  # noqa: E402
import produce_validator_evidence as producer  # noqa: E402
import test_native_artifact_delivery_closure as native_cases  # noqa: E402
from cwo_core import beads  # noqa: E402
from cwo_core import checked_command as cc  # noqa: E402
from cwo_core import requirement_baseline as rb  # noqa: E402
from cwo_core import stage_completion  # noqa: E402
from tests import test_close_bead_with_summary as legacy  # noqa: E402
from tests import test_offline_delivery_closure as compact_cases  # noqa: E402


class OfflineClosureClientTests(unittest.TestCase):
    def setUp(self):
        self.effects = contextlib.ExitStack()
        self.addCleanup(self.effects.close)
        self.boundaries = []
        for module, name in ((beads, "run_bd"), (beads, "run_bd_structured"),
                             (closure, "run_bd"), (stage_completion, "consume"),
                             (socket, "socket"), (socket, "create_connection"),
                             (urllib.request, "urlopen")):
            watched = self.effects.enter_context(patch.object(
                module, name, side_effect=AssertionError("EXAMPLE reliability effect remains held")))
            self.boundaries.append(watched)
        self.audit_boundary = Mock(side_effect=AssertionError("EXAMPLE reliability audit effect remains held"))
        self.boundaries.append(self.audit_boundary)
        for module, name in ((builtins, "open"), (io, "open"), (os, "open"),
                             (os, "mkdir"), (os, "rename"), (os, "replace"), (os, "unlink")):
            self.effects.enter_context(patch.object(
                module, name, side_effect=self.audit_guard(getattr(module, name))))

    def audit_guard(self, original):
        def guarded(*args, **kwargs):
            for value in (*args, *kwargs.values()):
                if isinstance(value, (str, bytes, os.PathLike)):
                    if ".orchestration-audit" in Path(os.fsdecode(value)).parts:
                        self.audit_boundary()
            return original(*args, **kwargs)
        return guarded

    def tearDown(self):
        for boundary in self.boundaries:
            boundary.assert_not_called()

    def native(self, **options):
        case = native_cases.NativeArtifactDeliveryClosureTests(methodName="runTest")
        self.addCleanup(case.doCleanups)
        case.begin(**options)
        return case

    def compact(self, **options):
        case = compact_cases.OfflineDeliveryClosureTests(methodName="runTest")
        self.addCleanup(case.doCleanups)
        case.begin(**options)
        return case

    def call(self, bound, target, *, operation="EXAMPLE-operation", revision=0):
        return closure.execute_offline_completed(
            bound, target, operation_id=operation, expected_revision=revision)

    def held(self, report):
        for name in offline.AUTHORITY_FIELDS:
            self.assertIs(report[name], False)

    def refuse(self, bound, target, *, operation="EXAMPLE-operation", revision=0):
        before = target.snapshot()
        with patch.object(offline, "_persist", wraps=offline._persist) as persist, \
                patch.object(target, "_append_comment", wraps=target._append_comment) as comment, \
                patch.object(target, "_mark_closed", wraps=target._mark_closed) as close:
            result = self.call(bound, target, operation=operation, revision=revision)
        for spy in (persist, comment, close):
            spy.assert_not_called()
        self.assertEqual(target.snapshot(), before)
        self.assertEqual(result["state"], "REFUSED")
        self.assertEqual(result["current_applicability"], "REFUSED")
        self.assertFalse(result["fake_completed"])
        self.assertTrue(result["completion_unconfirmed"])
        self.assertEqual((result["new_comment_writes"], result["new_close_writes"]), (0, 0))
        self.assertTrue(result["errors"])
        self.held(result)
        return result

    def reject_observation(self, case, observation):
        with self.assertRaises(offline.ClosureError):
            offline.bind_review(observation, *case.review(observation))
        result = self.refuse(observation, case.target)
        self.assertEqual((result["comment_writes"], result["close_writes"]), (0, 0))

    def test_native_delivery_enters_original_client_with_complete_bindings(self):
        case = self.native()
        callbacks = copy.deepcopy(case.fixture.adapter.callback_latencies)
        actual = []
        execute = cc.execute_checked_command

        def remember(command):
            result = execute(command)
            actual.append(copy.deepcopy(result))
            return result

        with native_cases.native_fixtures.repository_write_boundaries(
                (case.host.target, case.host.worker)) as writes, \
                patch.object(cc, "execute_checked_command", side_effect=remember) as run, \
                patch.object(producer, "produce_mixed", wraps=producer.produce_mixed) as produce, \
                patch.object(native_validation, "validate_artifact", wraps=native_validation.validate_artifact) as validate, \
                patch.object(native_validation, "consume_validated", wraps=native_validation.consume_validated) as native_consume, \
                patch.object(combined, "consume", wraps=combined.consume) as consume, \
                patch.object(offline, "close_offline", wraps=offline.close_offline) as delegate:
            observation = case.observe()
            raw, expected = case.review(observation)
            bound = offline.bind_review(observation, raw, expected)
            first = self.call(bound, case.target)
            replay = self.call(bound, case.target)
        self.assertEqual(writes, [])
        produce.assert_called_once()
        validate.assert_called_once()
        run.assert_called_once()
        self.assertGreater(native_consume.call_count, 3)
        self.assertEqual(consume.call_count, 3)
        for call in consume.call_args_list:
            self.assertEqual(call.args, (bound.prepared, observation.context, raw, expected))
        self.assertEqual(delegate.call_count, 2)
        delegate.assert_called_with(bound, case.target, operation_id="EXAMPLE-operation", expected_revision=0)
        self.assertIs(type(bound), offline.BoundReview)
        self.assertIs(type(case.target), offline.MemoryClosureTarget)
        self.assertEqual(observation.production_mode, "mixed")
        self.assertEqual([entry["result"] for entry in observation.production["validator_evidence"]], actual)
        self.assertEqual(bound.prepared["snapshot"], observation.combined["snapshot"])
        self.assertEqual(bound.prepared["snapshot"]["criterion_inventory"], case.initial["criteria"])
        self.assertEqual(bound.prepared["snapshot"]["input_context"], observation.context)
        self.assertEqual(observation.production["required_criterion_ids"], rb.required_criterion_ids(case.initial))
        self.assertTrue(first["fake_completed"], first["errors"])
        self.assertEqual(first["state"], "FAKE_COMPLETED")
        self.assertIn("Offline memory closure summary:", first["summary"])
        self.assertEqual(replay, {**first, "new_comment_writes": 0, "new_close_writes": 0})
        state = case.target.snapshot()
        self.assertEqual((state["revision"], state["comment_writes"], state["close_writes"]), (2, 1, 1))
        expected_bead = copy.deepcopy(case.bead)
        expected_bead["comments"].append({"text": first["summary"]})
        expected_bead["status"] = "closed"
        self.assertEqual(state["bead"], expected_bead)
        self.assertEqual(case.fixture.server.sends, 1)
        self.assertEqual(case.fixture.adapter.callback_latencies, callbacks)
        for report in (observation.report, bound.report, first, replay, state):
            case.held(report)
        for root in (case.host.worker, case.host.target):
            self.assertFalse((root / ".beads").exists())
            self.assertFalse((root / ".orchestration-audit").exists())

    def test_missing_foreign_serialized_and_forged_bindings_refuse(self):
        case = self.compact()
        bound = case.bind()
        foreign = self.compact().bind()
        for value in (None, object(), foreign, bound.report, bound.prepared,
                      json.dumps(bound.report), json.dumps(bound.report).encode("utf-8"),
                      "EXAMPLE-binding", "sha256:" + "0" * 64, object.__new__(offline.BoundReview)):
            with self.subTest(kind=type(value).__name__):
                self.refuse(value, case.target)
        foreign_target = type("EXAMPLEForeignTarget", (offline.MemoryClosureTarget,), {})(case.bead)
        for target in (None, object(), case.bead, bound.report, foreign_target):
            with self.subTest(target=type(target).__name__), \
                    patch.object(offline, "_persist", wraps=offline._persist) as persist:
                result = self.call(bound, target)
                persist.assert_not_called()
                self.assertFalse(result["fake_completed"])
                self.assertEqual((result["new_comment_writes"], result["new_close_writes"]), (0, 0))
                self.held(result)
        self.assertEqual((case.target.snapshot()["comment_writes"], case.target.snapshot()["close_writes"]), (0, 0))

    def test_missing_failed_and_unrun_original_results_cannot_issue_client_binding(self):
        for variant in ("failed", "refused"):
            with self.subTest(variant=variant):
                case = self.compact(variant=variant)
                self.reject_observation(case, case.observe())
        case = self.compact()
        with patch.object(cc, "execute_checked_command", wraps=cc.execute_checked_command) as run:
            observation = case.observe(commands={})
            self.reject_observation(case, observation)
        run.assert_not_called()
        case = self.compact(two=True)
        execute, count = cc.execute_checked_command, 0

        def unavailable(command):
            nonlocal count
            count += 1
            if count == 2:
                raise RuntimeError("EXAMPLE reliability validator is unavailable")
            return execute(command)

        with patch.object(cc, "execute_checked_command", side_effect=unavailable):
            observation = case.observe()
        self.assertEqual(len(observation.production["validator_evidence"]), 1)
        self.assertTrue(observation.production["unobserved_criterion_ids"])
        self.reject_observation(case, observation)

    def test_original_criterion_candidate_and_command_mutations_refuse(self):
        case = self.compact()
        omitted = copy.deepcopy(case.initial)
        omitted["criteria"] = []
        replaced = copy.deepcopy(case.initial)
        replaced["criteria"][0]["id"] = "EXAMPLE-replaced"
        outcome = copy.deepcopy(case.initial)
        outcome["criteria"][0]["expected_outcome"] = "EXAMPLE reliability contradictory outcome"
        unrelated = copy.deepcopy(case.commands)
        unrelated["EXAMPLE-validator"]["source"] += "\n# EXAMPLE unrelated reliability check.\n"
        changes = ({"initial": omitted}, {"initial": replaced}, {"initial": outcome},
                   {"candidate": {**case.candidate, "commit": "0" * 40}},
                   {"candidate": {**case.candidate, "baseline": {"version": 1, "digest": "sha256:" + "0" * 64}}},
                   {"commands": unrelated}, {"bead": {**case.bead, "comments": []}})
        for change in changes:
            with self.subTest(fields=tuple(change)), \
                    patch.object(cc, "execute_checked_command", wraps=cc.execute_checked_command) as run:
                self.reject_observation(case, case.observe(**change))
                run.assert_not_called()

    def test_native_independent_expectation_failure_preserves_original_cause(self):
        case = self.native(policy_change={"size": len(native_cases.native_fixtures.OUTPUT) + 1})
        with patch.object(cc, "execute_checked_command", wraps=cc.execute_checked_command) as run:
            with self.assertRaises(offline.ClosureError) as caught:
                case.observe()
        run.assert_not_called()
        self.assertIsInstance(caught.exception.__cause__, native_validation.ValidationError)
        self.assertEqual(str(caught.exception), str(caught.exception.__cause__))
        self.assertFalse(caught.exception.__cause__.report["offline_validation_complete"])
        self.refuse(None, case.target)

    def test_unresolved_blocker_and_stale_review_cannot_issue_client_binding(self):
        case = self.compact()
        observation = case.observe()
        blocker = {"id": "EXAMPLE-blocker", "blocking": True, "state": "OPEN", "text": "EXAMPLE reliability blocker."}
        with self.assertRaises(offline.ClosureError):
            offline.bind_review(observation, *case.review(observation, findings=[blocker]))
        raw, expected = case.review(observation)
        for supplied, expectation in ((raw + b"\n", expected),
                                      (raw, {**expected, "raw_review_sha256": "sha256:" + "0" * 64})):
            with self.assertRaises(offline.ClosureError):
                offline.bind_review(observation, supplied, expectation)
        self.refuse(observation, case.target)

    def test_revision_and_bounded_operation_inputs_refuse_before_persistence(self):
        case = self.compact()
        bound = case.bind()
        for revision in (-1, True, "0", 1):
            with self.subTest(revision=revision):
                self.refuse(bound, case.target, revision=revision)
        for operation in (None, "", "EXAMPLE-" + "x" * 65, {"EXAMPLE": "reliability"}):
            with self.subTest(kind=type(operation).__name__):
                self.refuse(bound, case.target, operation=operation)

    def test_operation_length_refuses_before_strip_with_valid_boundary_control(self):
        case = self.compact()
        bound = case.bind()
        calls = []

        def profile(frame, event, function):
            if event == "c_call" and frame.f_code is combined._text.__code__:
                if getattr(function, "__name__", None) == "strip":
                    calls.append("strip")

        previous = sys.getprofile()
        try:
            sys.setprofile(profile)
            for size in (65, 1024 * 1024 + 1):
                result = self.refuse(bound, case.target, operation=" " * size)
                self.assertIn("review text must be nonempty bounded printable text", result["errors"][0])
                self.assertEqual(calls, [], "oversized input reached strip before the length guard")
            operation = " " + "EXAMPLE".ljust(62, "x") + " "
            self.assertEqual(len(operation), 64)
            result = self.call(bound, case.target, operation=operation)
        finally:
            sys.setprofile(previous)
        self.assertTrue(calls, "the valid control must observe the original strip call")
        self.assertTrue(result["fake_completed"], result["errors"])
        self.assertEqual((result["new_comment_writes"], result["new_close_writes"]), (1, 1))
        self.held(result)

    def test_client_and_direct_prototype_agree_on_current_and_stale_replay(self):
        case = self.compact(additive=True)
        bound = case.bind()
        direct_target = offline.MemoryClosureTarget(case.bead)
        with patch.object(cc, "execute_checked_command", wraps=cc.execute_checked_command) as run:
            first = self.call(bound, case.target)
            direct = offline.close_offline(bound, direct_target, operation_id="EXAMPLE-operation", expected_revision=0)
            self.assertTrue(first["fake_completed"], first["errors"])
            self.assertEqual(first, direct)
            self.assertEqual(self.call(bound, case.target), {**first, "new_comment_writes": 0, "new_close_writes": 0})
            (case.repo / "src/item.txt").write_bytes(b"EXAMPLE reliability post-review edit\n")
            stale = self.refuse(bound, case.target)
            direct = offline.close_offline(bound, direct_target, operation_id="EXAMPLE-operation", expected_revision=0)
        run.assert_not_called()
        self.assertEqual(stale, direct)
        self.assertTrue(stale["closed"])
        self.assertEqual((stale["comment_writes"], stale["close_writes"]), (1, 1))

    def test_mutated_replay_and_post_review_edit_have_no_new_writes(self):
        case = self.compact()
        observation = case.observe()
        bound = case.bind(observation)
        first = self.call(bound, case.target)
        self.assertTrue(first["fake_completed"])
        resolved = {"id": "EXAMPLE-resolved", "blocking": True, "state": "RESOLVED",
                    "text": "EXAMPLE reliability resolved finding."}
        changed = offline.bind_review(observation, *case.review(observation, findings=[resolved]))
        replay = self.refuse(changed, case.target)
        self.assertEqual((replay["comment_writes"], replay["close_writes"]), (1, 1))
        self.refuse(bound, case.target, revision=2)
        untouched = offline.MemoryClosureTarget(case.bead)
        (case.repo / "src/item.txt").write_bytes(b"EXAMPLE reliability later candidate\n")
        result = self.refuse(bound, untouched, operation="EXAMPLE-post-review")
        self.assertEqual((result["comment_writes"], result["close_writes"]), (0, 0))

    def test_close_failure_and_stale_partial_replay_retain_saved_effects(self):
        case = self.compact()
        bound = case.bind()
        error = SystemExit("EXAMPLE reliability close failure")
        with patch.object(case.target, "_mark_closed", side_effect=error) as close:
            first = self.call(bound, case.target)
        close.assert_called_once()
        self.assertEqual(first["state"], "PARTIAL_PERSISTENCE")
        self.assertTrue(first["partial_persistence"])
        self.assertTrue(first["comment_posted"])
        self.assertFalse(first["closed"])
        self.assertEqual((first["comment_writes"], first["close_writes"]), (1, 0))
        self.assertIn("SystemExit: EXAMPLE reliability close failure", first["errors"][0])
        replay = self.call(bound, case.target)
        self.assertEqual(replay, {**first, "new_comment_writes": 0, "new_close_writes": 0})
        state = case.target.snapshot()
        edited = state["bead"]
        edited["title"] = "EXAMPLE reliability later task edit"
        case.target.compare_and_swap(state["revision"], edited)
        stale = self.refuse(bound, case.target)
        for field in ("comment_posted", "closed", "partial_persistence", "comment_writes", "close_writes"):
            self.assertEqual(stale[field], first[field])
        self.assertEqual((stale["new_comment_writes"], stale["new_close_writes"]), (0, 0))

    def test_primary_interruption_propagates_without_retry_after_a_comment(self):
        case = self.compact()
        bound = case.bind()
        interruption = KeyboardInterrupt("EXAMPLE reliability first interruption")
        append = case.target._append_comment

        def stop(*args):
            append(*args)
            raise interruption

        with patch.object(case.target, "_append_comment", side_effect=stop) as comment, \
                patch.object(case.target, "_mark_closed", wraps=case.target._mark_closed) as close:
            with self.assertRaises(KeyboardInterrupt) as caught:
                self.call(bound, case.target)
        self.assertIs(caught.exception, interruption)
        comment.assert_called_once()
        close.assert_not_called()
        state = case.target.snapshot()
        self.assertEqual((state["comment_writes"], state["close_writes"]), (1, 0))
        self.assertFalse(state["closed"])

    def test_simultaneous_and_reentrant_client_calls_keep_one_fake_effect_pair(self):
        case = self.compact()
        bound = case.bind()
        barrier = threading.Barrier(2)

        def claim(_):
            barrier.wait(timeout=30)
            return self.call(bound, case.target)

        with ThreadPoolExecutor(max_workers=2) as workers:
            results = list(workers.map(claim, range(2)))
        self.assertTrue(all(result["fake_completed"] for result in results))
        self.assertEqual(sorted((result["new_comment_writes"], result["new_close_writes"]) for result in results),
                         [(0, 0), (1, 1)])
        target = offline.MemoryClosureTarget(case.bead)
        append = target._append_comment
        nested = []

        def reenter(*args):
            nested.append(self.call(bound, target, operation="EXAMPLE-nested"))
            append(*args)

        with patch.object(target, "_append_comment", side_effect=reenter):
            result = self.call(bound, target)
        self.assertTrue(result["fake_completed"], result["errors"])
        self.assertFalse(nested[0]["fake_completed"])
        self.assertIn("already active", " ".join(nested[0]["errors"]))
        self.assertEqual((nested[0]["new_comment_writes"], nested[0]["new_close_writes"]), (0, 0))
        self.assertEqual((target.snapshot()["comment_writes"], target.snapshot()["close_writes"]), (1, 1))

    def legacy_refusals(self):
        selectors = (
            (legacy.SuccessfulClosureUnavailableTests, "test_no_form_of_successful_closure_writes_to_beads"),
            (legacy.SuccessfulClosureUnavailableTests, "test_the_refusal_says_nothing_was_written_and_what_remains"),
            (legacy.SuccessfulClosureUnavailableTests, "test_the_command_line_refuses_before_beads"),
            (legacy.ReviewRoundTwoTests, "test_a_close_reason_override_is_refused_before_any_write"),
            (legacy.ReviewRoundTwoTests, "test_narrative_input_cannot_forge_summary_metadata"),
            (legacy.ReviewRoundThreeTests, "assert_formatted_narrative_cannot_pass_for_a_summary_field"),
            (legacy.ReviewRoundFourTests, "assert_markup_and_character_references_cannot_forge_a_field"),
            (legacy.ReviewRoundFiveTests, "test_display_control_characters_are_refused_before_any_write"),
            (legacy.ReviewRoundFiveTests, "assert_raw_lines_are_checked_as_well_as_rendered_ones"),
            (legacy.ReviewRoundSixTests, "assert_confusable_colons_arrows_and_symbols_separate_a_field"),
            (legacy.ReviewRoundSevenTests, "assert_unicode_dashes_separate_a_field"),
            (legacy.W06aFollowupOneTests, "assert_markdown_delimiters_are_refused"),
        )
        for kind, method in selectors:
            with self.subTest(legacy=kind.__name__, method=method):
                kind(methodName=method).debug()

    def test_legacy_refusals_remain_before_and_after_offline_success(self):
        self.legacy_refusals()
        case = self.compact()
        bound = case.bind()
        self.assertTrue(self.call(bound, case.target)["fake_completed"])
        self.legacy_refusals()
        for disposition in ("completed", "validated"):
            with self.subTest(disposition=disposition), self.assertRaisesRegex(ValueError, "successful closure is unavailable"):
                closure.execute(legacy.args(disposition=disposition, meaningful=True, source_valid=True,
                                            fake_completed=True, binding=bound, target=case.target))
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()), \
                    self.assertRaises(SystemExit) as caught:
                closure.main(["--bead", "EXAMPLE-bead", "--disposition", disposition,
                              "--why", "EXAMPLE reliability fixture", "--meaningful", "--close"])
            self.assertEqual(caught.exception.code, 1)

    def test_noncompletion_dry_run_and_default_cli_contracts_remain(self):
        for kind, method in (
            (legacy.SuccessfulClosureUnavailableTests, "test_open_outcomes_comment_but_never_close"),
            (legacy.SuccessfulClosureUnavailableTests, "test_closable_non_completion_outcomes_still_close"),
            (legacy.CloseBeadWithSummaryTests, "test_dry_run_does_not_call_bd"),
            (legacy.ReviewRoundTwoTests, "test_partial_persistence_is_reported_when_close_fails_after_the_comment"),
        ):
            with self.subTest(method=method):
                kind(methodName=method).debug()
        for option in ("--offline-completed", "--allow-completed", "--source-valid", "--fake-completed"):
            with self.subTest(option=option), contextlib.redirect_stdout(io.StringIO()), \
                    contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as caught:
                closure.main(["--bead", "EXAMPLE-bead", "--disposition", "completed",
                              "--why", "EXAMPLE reliability fixture", option])
            self.assertEqual(caught.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
