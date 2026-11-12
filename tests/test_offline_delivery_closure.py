"""Offline closure reliability tests with actual producers and explicit EXAMPLE review fixtures."""
from __future__ import annotations

import contextlib
import copy
import hashlib
import json
import sys
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import close_bead_with_summary as closure  # noqa: E402
import prepare_combined_review_binding as combined  # noqa: E402
import prepare_delivery_closure as offline  # noqa: E402
import prepare_validator_receipts as validators  # noqa: E402
import produce_validator_evidence as producer  # noqa: E402
from cwo_core import beads  # noqa: E402
from cwo_core import candidate_identity as ci  # noqa: E402
from cwo_core import checked_command as cc  # noqa: E402
from cwo_core import requirement_baseline as rb  # noqa: E402
from cwo_core import stage_completion  # noqa: E402
from tests import test_validator_receipt_preparation as fixtures  # noqa: E402


class OfflineDeliveryClosureTests(unittest.TestCase):
    def setUp(self) -> None:
        self.effects = contextlib.ExitStack()
        self.addCleanup(self.effects.close)
        self.boundaries = []
        for module, name in ((beads, "run_bd"), (beads, "run_bd_structured"),
                             (closure, "run_bd"), (stage_completion, "consume")):
            watched = self.effects.enter_context(patch.object(
                module, name, side_effect=AssertionError("EXAMPLE forbidden external reliability effect")))
            self.boundaries.append(watched)

    def tearDown(self) -> None:
        for boundary in self.boundaries:
            boundary.assert_not_called()

    def begin(self, *, variant="passed", two=False, additive=False, extra=(), bead_id="EXAMPLE-bead") -> None:
        self.workspace = fixtures.TempGit(self)
        self.repo = self.workspace.root
        checked = (
            "from pathlib import Path\n"
            "if Path('src/item.txt').read_bytes() != b'EXAMPLE after\\n':\n"
            "    raise SystemExit(7)\n"
            "print('EXAMPLE checked file outcome', flush=True)\n"
        )
        source = checked
        if variant == "refused":
            source = "def EXAMPLE_invalid(:\n"
        if variant == "timeout":
            source += ("import sys\nimport time\n"
                       "print('EXAMPLE timeout reliability diagnostic', file=sys.stderr, flush=True)\n"
                       "time.sleep(60)\n")
        chosen = fixtures.spec(self.repo, "EXAMPLE-command", source)
        if variant == "timeout":
            chosen["timeout_seconds"] = 1
        self.output = b"EXAMPLE checked file outcome\n"
        self.commands = {"EXAMPLE-validator": chosen}
        self.initial = {
            "record_type": rb.BASELINE_RECORD_TYPE, "version": 1, "bead_id": bead_id,
            "baseline_version": 1,
            "criteria": [fixtures.validator("EXAMPLE-validator", chosen, self.output), *copy.deepcopy(extra)],
        }
        for item in extra:
            self.commands[item["id"]] = fixtures.spec(
                self.repo, "EXAMPLE-extra-" + item["id"], checked)
        self.amendments = []
        if two or additive:
            second = fixtures.spec(self.repo, "EXAMPLE-second", checked + "# EXAMPLE second reliability check.\n")
            self.commands["EXAMPLE-second"] = second
            added = fixtures.validator("EXAMPLE-second", second, self.output)
            if additive:
                updated = copy.deepcopy(self.initial)
                updated["baseline_version"] = 2
                updated["criteria"].append(added)
                self.amendments = [fixtures.amendment(self.initial, updated)]
            else:
                self.initial["criteria"].append(added)
        self.chain = rb.resolve_chain(self.initial, self.amendments)
        self.bead = {"id": self.chain["bead_id"], "status": "open", "title": "EXAMPLE reliability task",
                     "comments": [{"text": rb.reference_line(self.chain["bead_id"],
                                  entry["version"], entry["digest"])} for entry in self.chain["baselines"]]}
        content = b"EXAMPLE wrong file outcome\n" if variant == "failed" else fixtures.AFTER
        (self.repo / "src/item.txt").write_bytes(content)
        self.candidate = ci.capture_candidate(
            self.repo, chain=self.chain, base_commit=self.workspace.base, scope_paths=["src"])
        self.bead["comments"].append({"text": ci.candidate_reference_line(
            self.chain["bead_id"], ci.candidate_digest(self.candidate))})
        self.target = offline.MemoryClosureTarget(self.bead)

    def arguments(self) -> dict:
        return {"root": str(self.repo), "initial": self.initial, "candidate": self.candidate,
                "bead": self.bead, "commands": self.commands, "amendments": self.amendments}

    def observe(self, **changes):
        arguments = self.arguments()
        arguments.update(changes)
        return offline.observe(**arguments)

    def review(self, observation, verdict="APPROVE", findings=()):
        context = {"review_id": "EXAMPLE-review", "reviewer": "EXAMPLE unauthenticated reviewer",
                   "verdict": verdict, "snapshot": observation.combined["snapshot"] or {}}
        document = {"record_type": combined.REVIEW_TYPE, "version": 1, "context": copy.deepcopy(context),
                    "findings": list(findings), "summary": "EXAMPLE reliability fixture without independence authority."}
        raw = json.dumps(document, ensure_ascii=False).encode("utf-8")
        expected = {"record_type": combined.EXPECTATION_TYPE, "version": 1, "context": context,
                    "raw_review_sha256": "sha256:" + hashlib.sha256(raw).hexdigest()}
        return raw, expected

    def bind(self, observation=None):
        if observation is None:
            observation = self.observe()
        raw, expected = self.review(observation)
        return offline.bind_review(observation, raw, expected)

    def close(self, bound, *, target=None, operation="EXAMPLE-operation", revision=0):
        return offline.close_offline(
            bound, self.target if target is None else target,
            operation_id=operation, expected_revision=revision)

    def assert_held(self, report) -> None:
        for name in offline.AUTHORITY_FIELDS:
            self.assertIs(report[name], False)

    def assert_empty(self, target=None) -> None:
        state = (self.target if target is None else target).snapshot()
        self.assertEqual((state["comment_writes"], state["close_writes"]), (0, 0))
        self.assertFalse(state["closed"])

    def assert_replay_refused(self, bound, saved, *, revision=0) -> dict:
        before = self.target.snapshot()
        with patch.object(self.target, "_append_comment", wraps=self.target._append_comment) as comment, \
                patch.object(self.target, "_mark_closed", wraps=self.target._mark_closed) as close:
            result = self.close(bound, revision=revision)
        comment.assert_not_called()
        close.assert_not_called()
        self.assertEqual(self.target.snapshot(), before)
        self.assert_held(result)
        self.assertTrue(result["persistence_known"])
        self.assertFalse(result["fake_completed"])
        self.assertTrue(result["completion_unconfirmed"])
        self.assertEqual(result["state"], "REFUSED")
        self.assertEqual(result["current_applicability"], "REFUSED")
        self.assertEqual((result["new_comment_writes"], result["new_close_writes"]), (0, 0))
        self.assertEqual(result["target_revision"], before["revision"])
        for name in ("comment_posted", "closed", "partial_persistence", "comment_writes", "close_writes",
                     "summary", "operation_id_digest", "operation_binding_digest",
                     "operation_expected_revision", "operation_target_revision"):
            self.assertEqual(result[name], saved[name])
        self.assertTrue(result["errors"])
        return result

    def reject_observation(self, observation) -> None:
        self.assert_held(observation.report)
        self.assertFalse(observation.production["observations_complete"]
                         and observation.combined["combined_observations_complete"])
        with self.assertRaises(offline.ClosureError):
            offline.bind_review(observation, *self.review(observation))
        self.assert_empty()

    def test_useful_compact_delivery_uses_actual_complete_bindings_and_one_fake_close(self) -> None:
        self.begin(additive=True)
        actual = []
        execute = cc.execute_checked_command
        def remember(command):
            result = execute(command)
            actual.append(copy.deepcopy(result))
            return result

        with patch.object(cc, "execute_checked_command", side_effect=remember) as calls, \
                patch.object(producer, "produce", wraps=producer.produce) as produce, \
                patch.object(combined, "observe", wraps=combined.observe) as observe, \
                patch.object(combined, "prepare", wraps=combined.prepare) as prepare, \
                patch.object(combined, "consume", wraps=combined.consume) as consume:
            observation = self.observe()
            blocker = {"id": "EXAMPLE-resolved", "blocking": True, "state": "RESOLVED", "text": "EXAMPLE reliability finding."}
            raw, expected = self.review(observation, findings=[blocker])
            bound = offline.bind_review(observation, raw, expected)
            result = self.close(bound)
        produce.assert_called_once()
        observe.assert_called_once()
        prepare.assert_called_once()
        self.assertEqual(calls.call_count, 2)
        self.assertEqual(consume.call_count, 2)
        for call in consume.call_args_list:
            self.assertEqual(call.args, (bound.prepared, observation.context, raw, expected))
        self.assert_held(observation.report)
        self.assert_held(bound.report)
        self.assert_held(result)
        self.assertTrue(result["fake_completed"], result["errors"])
        self.assertFalse(result["completion_unconfirmed"])
        wrappers = observation.production["validator_evidence"]
        self.assertEqual([entry["result"] for entry in wrappers], actual)
        for entry in wrappers:
            self.assertEqual(set(entry["result"]), validators.RESULT_FIELDS)
            self.assertEqual(entry["baseline_digest"], self.chain["digest"])
            self.assertEqual(entry["candidate_digest"], ci.candidate_digest(self.candidate))
        self.assertEqual(observation.context["validator_evidence"], wrappers)
        snapshot = bound.prepared["snapshot"]
        self.assertEqual(snapshot["criterion_inventory"], self.chain["baseline"]["criteria"])
        self.assertEqual(snapshot, observation.combined["snapshot"])
        state = self.target.snapshot()
        self.assertEqual((state["revision"], state["comment_writes"], state["close_writes"]), (2, 1, 1))
        self.assertTrue(state["closed"])
        expected_bead = copy.deepcopy(self.bead)
        expected_bead["comments"].append({"text": result["summary"]})
        expected_bead["status"] = "closed"
        self.assertEqual(state["bead"], expected_bead)
        self.assertIn(self.chain["digest"], result["summary"])
        self.assertIn(expected["raw_review_sha256"], result["summary"])
        for entry in wrappers:
            self.assertIn(rb.record_digest(entry), result["summary"])
        self.assertNotIn("independence authority", result["summary"])
        self.assertFalse((self.repo / ".beads").exists())
        self.assertFalse((self.repo / ".orchestration-audit").exists())

    def test_immutable_issued_states_refuse_forged_caller_json_and_arbitrary_targets(self) -> None:
        self.begin()
        observation = self.observe()
        bound = self.bind(observation)
        saved = observation.production
        saved["validator_evidence"].clear()
        observation.context["baseline"]["criteria"].clear()
        bound.prepared["binding_consistent"] = False
        self.assertTrue(observation.production["observations_complete"])
        self.assertTrue(bound.prepared["binding_consistent"])
        for kind in (offline.Observation, offline.BoundReview):
            with self.assertRaises(offline.ClosureError):
                kind()
        with self.assertRaises(AttributeError):
            observation.context = {}
        for forged in ({"fake_completed": True}, bound.report, object.__new__(offline.BoundReview)):
            self.assertFalse(self.close(forged)["fake_completed"])
        self.assertFalse(self.close(bound, target=object())["fake_completed"])
        with self.assertRaises(offline.ClosureError):
            offline.bind_review(object.__new__(offline.Observation), *self.review(observation))
        with self.assertRaises(TypeError):
            offline.observe(**self.arguments(), validator_evidence=[{"execution_status": "passed"}])
        self.assert_empty()
        self.assertTrue(self.close(bound)["fake_completed"])

    def test_omitted_replaced_stale_and_wrong_original_joins_have_zero_writes(self) -> None:
        self.begin()
        cases = (
            ("commands", {}),
            ("commands", {"EXAMPLE-replaced": self.commands["EXAMPLE-validator"]}),
            ("commands", {**self.commands, "EXAMPLE-unrelated": self.commands["EXAMPLE-validator"]}),
            ("initial.criteria", []),
            ("initial.criteria.0.id", "EXAMPLE-replaced"),
            ("initial.criteria.0.expected_outcome", "EXAMPLE replacement reliability outcome"),
            ("candidate.baseline.digest", "sha256:" + "0" * 64),
            ("candidate.commit", "0" * 40),
            ("bead.id", "EXAMPLE-other"),
            ("bead.comments", []),
            ("commands.EXAMPLE-validator.source", "print('EXAMPLE unrelated outcome')\n"),
            ("commands.EXAMPLE-validator.command_id", "EXAMPLE-other"),
            ("root", str(self.repo.parent)),
            ("amendments", [{}]),
        )
        for path, value in cases:
            with self.subTest(path=path):
                arguments = copy.deepcopy(self.arguments())
                destination = arguments
                parts = path.split(".")
                for part in parts[:-1]:
                    destination = destination[int(part) if part.isdigit() else part]
                last = parts[-1]
                destination[int(last) if last.isdigit() else last] = value
                with patch.object(cc, "execute_checked_command", wraps=cc.execute_checked_command) as run:
                    observed = offline.observe(**arguments)
                run.assert_not_called()
                self.reject_observation(observed)

    def test_baseline_first_unsupported_rows_keep_full_inventory_and_exact_refusal(self) -> None:
        for kind in ("artifact", "review-gate"):
            with self.subTest(kind=kind):
                extra = fixtures.criterion("EXAMPLE-extra", "EXAMPLE independently required reliability outcome", kind)
                self.begin(extra=[extra])
                with patch.object(cc, "execute_checked_command", wraps=cc.execute_checked_command) as run:
                    observation = self.observe()
                run.assert_not_called()
                self.assertIn("unsupported evidence kind", " ".join(observation.production["errors"]))
                self.assertEqual(observation.combined["snapshot"]["criterion_inventory"], self.chain["baseline"]["criteria"])
                self.reject_observation(observation)
        self.begin(extra=[fixtures.criterion("EXAMPLE-extra", "EXAMPLE unsupported validator reliability outcome")])
        with patch.object(cc, "execute_checked_command", wraps=cc.execute_checked_command) as run:
            observation = self.observe()
        run.assert_not_called()
        self.assertIn("independently predeclared", " ".join(observation.production["errors"]))
        self.reject_observation(observation)

    def test_real_failure_preflight_refusal_and_output_timeout_retain_original_results(self) -> None:
        for variant in ("failed", "refused", "timeout"):
            with self.subTest(variant=variant):
                self.begin(variant=variant)
                actual = []
                execute = cc.execute_checked_command
                def remember(command):
                    result = execute(command)
                    actual.append(copy.deepcopy(result))
                    return result

                with patch.object(cc, "execute_checked_command", side_effect=remember) as run:
                    observation = self.observe()
                run.assert_called_once()
                self.assertEqual(observation.production["validator_evidence"][0]["result"], actual[0])
                if variant == "refused":
                    self.assertFalse(actual[0]["execution_started"])
                else:
                    self.assertTrue(actual[0]["execution_started"])
                if variant == "timeout":
                    self.assertEqual(actual[0]["failure_class"], "execution-timeout")
                    self.assertIn("EXAMPLE checked file outcome", actual[0]["diagnostics"]["stdout"])
                    self.assertIn("EXAMPLE timeout reliability diagnostic", actual[0]["diagnostics"]["stderr"])
                self.reject_observation(observation)

    def test_unavailable_second_validator_retains_prior_result_and_unrun_criterion(self) -> None:
        self.begin(two=True)
        execute = cc.execute_checked_command
        count = 0
        def unavailable(command):
            nonlocal count
            count += 1
            if count == 2:
                raise RuntimeError("EXAMPLE validator reliability component is unavailable")
            return execute(command)

        with patch.object(cc, "execute_checked_command", side_effect=unavailable):
            observation = self.observe()
        self.assertEqual(len(observation.production["validator_evidence"]), 1)
        self.assertEqual(observation.production["unobserved_criterion_ids"], ["EXAMPLE-validator"])
        self.assertEqual(observation.combined["snapshot"]["required_criterion_ids"], rb.required_criterion_ids(self.chain["baseline"]))
        self.reject_observation(observation)

    def test_wrong_result_joins_and_unrelated_actual_success_never_complete(self) -> None:
        self.begin()
        produced = producer.produce(**self.arguments())
        unrelated = copy.deepcopy(self.commands["EXAMPLE-validator"])
        unrelated["command_id"] = "EXAMPLE-unrelated"
        unrelated["source"] += "# EXAMPLE unrelated reliability check.\n"
        unrelated_result = cc.execute_checked_command(unrelated)
        cases = (
            ("baseline_digest", "sha256:" + "0" * 64),
            ("candidate_digest", "sha256:" + "1" * 64),
            ("criterion_id", "EXAMPLE-unknown"),
            ("result", {"execution_status": "passed"}),
            ("result.exit_code", False),
            ("result.diagnostics.stdout", "EXAMPLE unrelated outcome\n"),
            ("result.execution_started", False),
            ("result.spec_sha256", "0" * 64),
        )
        for path, value in cases:
            changed = copy.deepcopy(produced)
            destination = changed["validator_evidence"][0]
            parts = path.split(".")
            for part in parts[:-1]:
                destination = destination[part]
            destination[parts[-1]] = value
            with self.subTest(path=path), patch.object(producer, "produce", return_value=changed):
                observation = self.observe()
                self.reject_observation(observation)
        for evidence in ([], [produced["validator_evidence"][0]] * 2,
                         [{**produced["validator_evidence"][0], "spec": unrelated, "result": unrelated_result}]):
            changed = copy.deepcopy(produced)
            changed["validator_evidence"] = evidence
            with patch.object(producer, "produce", return_value=changed):
                self.reject_observation(self.observe())

    def test_final_review_requires_exact_bytes_complete_snapshot_approve_and_resolved_blockers(self) -> None:
        self.begin()
        observation = self.observe()
        raw, expected = self.review(observation)
        blocker = {"id": "EXAMPLE-open", "blocking": True, "state": "OPEN", "text": "EXAMPLE unresolved reliability finding."}
        for verdict, findings in (("REQUEST_CHANGES", []), ("REJECT", []), ("ABSTAIN", []), ("APPROVE", [blocker])):
            with self.subTest(verdict=verdict), self.assertRaises(offline.ClosureError):
                offline.bind_review(observation, *self.review(observation, verdict, findings))
        for mutation in ("raw", "expectation", "snapshot", "context", "shape"):
            document = json.loads(raw)
            changed = copy.deepcopy(expected)
            supplied = raw
            if mutation == "raw":
                supplied += b"\n"
            elif mutation == "expectation":
                changed["raw_review_sha256"] = "sha256:" + "0" * 64
            elif mutation == "snapshot":
                document["context"]["snapshot"]["criterion_inventory"].clear()
                changed["context"] = copy.deepcopy(document["context"])
            elif mutation == "context":
                document["context"]["reviewer"] = "EXAMPLE changed reviewer"
            else:
                document["unexpected"] = "EXAMPLE unsupported reliability field"
            if mutation in ("snapshot", "context", "shape"):
                supplied = json.dumps(document).encode("utf-8")
                changed["raw_review_sha256"] = "sha256:" + hashlib.sha256(supplied).hexdigest()
            with self.subTest(mutation=mutation), self.assertRaises(offline.ClosureError):
                offline.bind_review(observation, supplied, changed)
        self.assert_empty()

    def test_post_review_relevant_file_mode_and_untracked_edits_prevent_any_fake_write(self) -> None:
        self.begin()
        bound = self.bind()
        path = self.repo / "src/item.txt"
        mode = path.stat().st_mode & 0o7777
        extra = self.repo / "src/EXAMPLE-later.txt"
        changes = (
            (lambda: path.write_bytes(b"EXAMPLE later reliability edit\n"), lambda: path.write_bytes(fixtures.AFTER)),
            (lambda: path.chmod(mode ^ 0o020), lambda: path.chmod(mode)),
            (lambda: extra.write_bytes(b"EXAMPLE untracked reliability edit\n"), lambda: extra.unlink()),
        )
        for index, (change, restore) in enumerate(changes):
            target = offline.MemoryClosureTarget(self.bead)
            change()
            try:
                result = self.close(bound, target=target, operation=f"EXAMPLE-edit-{index}")
                self.assertFalse(result["fake_completed"])
                self.assert_empty(target)
            finally:
                restore()
        self.assertTrue(self.close(bound)["fake_completed"])

    def test_exact_task_projection_and_revision_are_required_before_mutation(self) -> None:
        self.begin()
        bound = self.bind()
        for field, value in (("title", "EXAMPLE changed reliability task"), ("id", "EXAMPLE-other"), ("comments", [])):
            bead = copy.deepcopy(self.bead)
            bead[field] = value
            target = offline.MemoryClosureTarget(bead)
            self.assertFalse(self.close(bound, target=target)["fake_completed"])
            self.assert_empty(target)
        self.target.compare_and_swap(0, self.bead)
        self.assertFalse(self.close(bound)["fake_completed"])
        self.assert_empty()
        self.assertEqual(self.target.snapshot()["revision"], 1)

    def test_replay_returns_existing_status_and_mutated_operation_or_task_refuses(self) -> None:
        self.begin()
        bound = self.bind()
        first = self.close(bound)
        self.assertTrue(first["fake_completed"])
        self.assertTrue(first["persistence_known"])
        self.assertEqual(first["current_applicability"], "CURRENT")
        self.assertEqual(first["operation_id_digest"],
                         "sha256:" + hashlib.sha256(b"EXAMPLE-operation").hexdigest())
        self.assertIn(first["operation_binding_digest"], first["summary"])
        self.assertEqual((first["operation_expected_revision"], first["operation_target_revision"]), (0, 2))
        self.assertEqual((first["new_comment_writes"], first["new_close_writes"]), (1, 1))
        self.assertEqual(self.close(bound), {**first, "new_comment_writes": 0, "new_close_writes": 0})
        self.assertEqual((self.target.snapshot()["comment_writes"], self.target.snapshot()["close_writes"]), (1, 1))
        observed = self.observe()
        raw, expected = self.review(observed)
        document = json.loads(raw)
        document["context"]["review_id"] = "EXAMPLE-revised-review"
        expected["context"] = copy.deepcopy(document["context"])
        raw = json.dumps(document).encode("utf-8")
        expected["raw_review_sha256"] = "sha256:" + hashlib.sha256(raw).hexdigest()
        changed = offline.bind_review(observed, raw, expected)
        self.assert_replay_refused(changed, first)
        self.assert_replay_refused(bound, first, revision=2)
        self.assert_replay_refused(bound, first, revision=True)
        self.assert_replay_refused(object.__new__(offline.BoundReview), first)
        edited = self.target.snapshot()["bead"]
        edited["title"] = "EXAMPLE later task state"
        self.target.compare_and_swap(2, edited)
        self.assert_replay_refused(bound, first)
        self.assertEqual(self.target.snapshot()["comment_writes"], 1)

    def test_completed_replay_rechecks_current_candidate_without_more_writes(self) -> None:
        self.begin()
        bound = self.bind()
        first = self.close(bound)
        self.assertTrue(first["fake_completed"])
        (self.repo / "src/item.txt").write_bytes(b"EXAMPLE later reliability drift\n")
        result = self.assert_replay_refused(bound, first)
        self.assertTrue(result["closed"])
        self.assertTrue(result["comment_posted"])
        self.assertFalse(result["partial_persistence"])
        self.assertEqual((result["comment_writes"], result["close_writes"]), (1, 1))
        self.assertEqual((self.target.snapshot()["comment_writes"], self.target.snapshot()["close_writes"]), (1, 1))

    def test_partial_replay_after_task_drift_preserves_original_persistence(self) -> None:
        self.begin()
        bound = self.bind()
        with patch.object(self.target, "_mark_closed",
                          side_effect=RuntimeError("EXAMPLE close reliability failure")):
            first = self.close(bound)
        self.assertTrue(first["partial_persistence"])
        self.assertEqual((first["comment_writes"], first["close_writes"]), (1, 0))
        self.assertEqual((first["new_comment_writes"], first["new_close_writes"]), (1, 0))
        state = self.target.snapshot()
        edited = state["bead"]
        edited["title"] = "EXAMPLE later reliability task edit"
        self.target.compare_and_swap(state["revision"], edited)
        result = self.assert_replay_refused(bound, first)
        self.assertTrue(result["comment_posted"])
        self.assertTrue(result["partial_persistence"])
        self.assertFalse(result["closed"])
        self.assertEqual((result["comment_writes"], result["close_writes"]), (1, 0))
        self.assertEqual((result["operation_target_revision"], result["target_revision"]), (1, 2))
        self.assertIn({"text": first["summary"]}, self.target.snapshot()["bead"]["comments"])
        self.assertEqual((self.target.snapshot()["comment_writes"], self.target.snapshot()["close_writes"]), (1, 0))

    def test_other_operation_and_unlocated_binding_never_borrow_saved_persistence(self) -> None:
        self.begin()
        bound = self.bind()
        first = self.close(bound)
        self.assertTrue(first["fake_completed"])
        before = self.target.snapshot()
        operation = "EXAMPLE other reliability operation"
        with patch.object(self.target, "_append_comment", wraps=self.target._append_comment) as comment, \
                patch.object(self.target, "_mark_closed", wraps=self.target._mark_closed) as close:
            other = self.close(bound, operation=operation)
            unknown = self.close({"EXAMPLE-private": "EXAMPLE private reliability text"},
                                 operation="EXAMPLE-unlocated")
        comment.assert_not_called()
        close.assert_not_called()
        self.assertEqual(self.target.snapshot(), before)
        for result in (other, unknown):
            self.assert_held(result)
            self.assertFalse(result["fake_completed"])
            self.assertEqual(result["current_applicability"], "REFUSED")
            self.assertFalse(result["comment_posted"])
            self.assertFalse(result["closed"])
            self.assertFalse(result["partial_persistence"])
            self.assertIsNone(result["summary"])
            self.assertEqual((result["comment_writes"], result["close_writes"]), (0, 0))
            self.assertEqual((result["new_comment_writes"], result["new_close_writes"]), (0, 0))
            self.assertNotIn("EXAMPLE private reliability text", json.dumps(result))
            self.assertNotIn(operation, json.dumps(result))
        self.assertTrue(other["persistence_known"])
        self.assertNotEqual(other["operation_id_digest"], first["operation_id_digest"])
        self.assertEqual(other["target_revision"], before["revision"])
        self.assertFalse(unknown["persistence_known"])
        self.assertIsNone(unknown["operation_id_digest"])
        self.assertIsNone(unknown["operation_binding_digest"])
        self.assertIsNone(unknown["operation_expected_revision"])
        self.assertIsNone(unknown["operation_target_revision"])

    def test_concurrent_identical_claims_persist_at_most_once(self) -> None:
        self.begin()
        bound = self.bind()
        barrier = threading.Barrier(2)
        def claim(_):
            barrier.wait(timeout=30)
            return self.close(bound)

        with ThreadPoolExecutor(max_workers=2) as workers:
            results = list(workers.map(claim, range(2)))
        self.assertEqual({**results[0], "new_comment_writes": 0, "new_close_writes": 0},
                         {**results[1], "new_comment_writes": 0, "new_close_writes": 0})
        self.assertEqual(sorted([
            (results[0]["new_comment_writes"], results[0]["new_close_writes"]),
            (results[1]["new_comment_writes"], results[1]["new_close_writes"]),
        ]), [(0, 0), (1, 1)])
        self.assertTrue(results[0]["fake_completed"])
        self.assertEqual((self.target.snapshot()["comment_writes"], self.target.snapshot()["close_writes"]), (1, 1))

    def test_comment_and_close_failures_report_precise_persistence_and_never_retry(self) -> None:
        for phase in ("comment", "close", "comment-after-write"):
            with self.subTest(phase=phase):
                self.begin()
                bound = self.bind()
                original = self.target._append_comment
                def comment(*args):
                    original(*args)
                    raise RuntimeError("EXAMPLE reliability failure after the memory comment")

                name = "_mark_closed" if phase == "close" else "_append_comment"
                effect = comment if phase == "comment-after-write" else RuntimeError("EXAMPLE memory reliability failure")
                with patch.object(self.target, name, side_effect=effect):
                    result = self.close(bound)
                self.assertFalse(result["fake_completed"])
                self.assertTrue(result["completion_unconfirmed"])
                self.assertEqual(result["comment_posted"], phase != "comment")
                self.assertEqual(result["partial_persistence"], phase != "comment")
                self.assertEqual(result["close_writes"], 0)
                self.assertFalse(self.target.snapshot()["closed"])
                self.assertEqual(self.close(bound),
                                 {**result, "new_comment_writes": 0, "new_close_writes": 0})
                self.assertEqual(self.target.snapshot()["comment_writes"], int(phase != "comment"))

    def test_comment_callback_candidate_or_task_drift_prevents_close_and_preserves_partial_status(self) -> None:
        for drift in ("candidate", "task"):
            with self.subTest(drift=drift):
                self.begin()
                bound = self.bind()
                original = self.target._append_comment
                def comment(*args):
                    original(*args)
                    if drift == "candidate":
                        (self.repo / "src/item.txt").write_bytes(b"EXAMPLE interleaved candidate reliability drift\n")
                    else:
                        state = self.target.snapshot()
                        bead = state["bead"]
                        bead["comments"][0]["text"] = "EXAMPLE changed baseline reliability reference"
                        self.target.compare_and_swap(state["revision"], bead)

                with patch.object(self.target, "_append_comment", side_effect=comment), \
                        patch.object(self.target, "_mark_closed", wraps=self.target._mark_closed) as close:
                    result = self.close(bound)
                close.assert_not_called()
                self.assertTrue(result["partial_persistence"])
                self.assertTrue(result["completion_unconfirmed"])
                self.assertFalse(result["fake_completed"])
                self.assertFalse(self.target.snapshot()["closed"])
                self.assertEqual((result["comment_writes"], result["close_writes"]), (1, 0))

    def test_drift_during_final_candidate_check_is_caught_by_the_last_target_check(self) -> None:
        self.begin()
        bound = self.bind()
        check = ci.check_candidate
        edited = False
        def reenter(*args, **kwargs):
            nonlocal edited
            result = check(*args, **kwargs)
            if self.target.snapshot()["comment_writes"] == 1 and not edited:
                edited = True
                state = self.target.snapshot()
                bead = state["bead"]
                bead["title"] = "EXAMPLE interleaved reliability edit"
                self.target.compare_and_swap(state["revision"], bead)
            return result

        with patch.object(ci, "check_candidate", side_effect=reenter):
            result = self.close(bound)
        self.assertTrue(edited)
        self.assertTrue(result["partial_persistence"])
        self.assertFalse(result["fake_completed"])
        self.assertFalse(self.target.snapshot()["closed"])

    def test_reentrant_operation_is_refused_without_duplicate_writes(self) -> None:
        self.begin()
        bound = self.bind()
        original = self.target._append_comment
        nested = []
        def comment(*args):
            nested.append(self.close(bound, operation="EXAMPLE-nested"))
            original(*args)

        with patch.object(self.target, "_append_comment", side_effect=comment):
            result = self.close(bound)
        self.assertTrue(result["fake_completed"])
        self.assertFalse(nested[0]["fake_completed"])
        self.assertIn("already active", " ".join(nested[0]["errors"]))
        self.assertEqual((result["comment_writes"], result["close_writes"]), (1, 1))

    def test_real_production_success_refusal_and_truthful_dry_run_remain_unchanged(self) -> None:
        self.begin()
        args = closure.parser().parse_args(
            ["--bead", "EXAMPLE-bead", "--disposition", "completed",
             "--why", "EXAMPLE reliability fixture", "--close"])
        with self.assertRaises(ValueError) as caught:
            closure.execute(args)
        self.assertEqual(str(caught.exception), closure.SUCCESS_UNAVAILABLE + " (disposition given: 'completed')")
        args = closure.parser().parse_args(
            ["--bead", "EXAMPLE-bead", "--disposition", "pending-acceptance",
             "--why", "EXAMPLE reliability review remains open", "--dry-run"])
        result = closure.execute(args)
        self.assertFalse(result["closed"])
        self.assertFalse(result["comment_posted"])
        self.assert_empty()


if __name__ == "__main__":
    unittest.main()
