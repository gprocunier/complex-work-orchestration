"""Mixed offline closure reliability with real observations and explicit EXAMPLE review fixtures."""
from __future__ import annotations

import contextlib
import copy
import hashlib
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import close_bead_with_summary as closure  # noqa: E402
import prepare_combined_review_binding as combined  # noqa: E402
import prepare_delivery_closure as offline  # noqa: E402
import prepare_artifact_acceptance as artifacts  # noqa: E402
import prepare_validator_receipts as validators  # noqa: E402
import produce_validator_evidence as producer  # noqa: E402
from cwo_core import beads  # noqa: E402
from cwo_core import candidate_identity as ci  # noqa: E402
from cwo_core import checked_command as cc  # noqa: E402
from cwo_core import requirement_baseline as rb  # noqa: E402
from cwo_core import stage_completion  # noqa: E402
from tests import test_validator_receipt_preparation as fixtures  # noqa: E402


class MixedDeliveryClosureTests(unittest.TestCase):
    def setUp(self) -> None:
        self.effects = contextlib.ExitStack()
        self.addCleanup(self.effects.close)
        self.boundaries = []
        for module, name in ((beads, "run_bd"), (beads, "run_bd_structured"),
                             (closure, "run_bd"), (closure, "execute"), (stage_completion, "consume")):
            spy = self.effects.enter_context(patch.object(
                module, name, side_effect=AssertionError("EXAMPLE forbidden reliability effect")))
            self.boundaries.append(spy)

    def tearDown(self) -> None:
        for spy in self.boundaries:
            spy.assert_not_called()

    def begin(self, *, mixed=True, predicate=None, extra=(), content=fixtures.AFTER,
              source=None, timeout=10, count=1) -> None:
        self.workspace = fixtures.TempGit(self)
        self.repo = self.workspace.root
        checked = (
            "from pathlib import Path\n"
            "if Path('src/item.txt').read_bytes() != b'EXAMPLE after\\n':\n"
            "    raise SystemExit(7)\n"
            "print('EXAMPLE reliability checked bytes', flush=True)\n"
        )
        self.commands = {}
        criteria = []
        if mixed:
            predicate = predicate if predicate is not None else {
                "op": "regular-file-sha256", "path": "src/item.txt", "sha256": fixtures.sha(fixtures.AFTER),
            }
            criteria.append(fixtures.criterion(
                "EXAMPLE-artifact", artifacts.PREFIX + json.dumps(predicate), "artifact"))
        for index in range(count):
            name = f"EXAMPLE-validator-{index}"
            command = fixtures.spec(self.repo, f"EXAMPLE-command-{index}", checked if source is None else source)
            command["timeout_seconds"] = timeout
            self.commands[name] = command
            criteria.append(fixtures.validator(name, command, b"EXAMPLE reliability checked bytes\n"))
        for item in extra:
            if item["applicability"] == "required" and item["evidence_kind"] == "validator":
                self.commands[item["id"]] = fixtures.spec(self.repo, "EXAMPLE-extra-" + item["id"], checked)
        criteria.extend(copy.deepcopy(extra))
        self.initial = {
            "record_type": rb.BASELINE_RECORD_TYPE, "version": 1, "bead_id": "EXAMPLE-bead",
            "baseline_version": 1, "criteria": criteria,
        }
        self.amendments = []
        self.chain = rb.resolve_chain(self.initial, self.amendments)
        self.bead = {"id": self.chain["bead_id"], "status": "open", "title": "EXAMPLE reliability task",
                     "comments": [{"text": rb.reference_line(self.chain["bead_id"], entry["version"], entry["digest"])}
                                  for entry in self.chain["baselines"]]}
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
        return offline.observe_mixed(**arguments)

    def review(self, observation, findings=()):
        context = {"review_id": "EXAMPLE-review", "reviewer": "EXAMPLE reliability reviewer",
                   "verdict": "APPROVE", "snapshot": observation.combined["snapshot"] or {}}
        review = {"record_type": combined.REVIEW_TYPE, "version": 1, "context": copy.deepcopy(context),
                  "findings": list(findings), "summary": "EXAMPLE reliability review without authenticated independence."}
        raw = json.dumps(review, ensure_ascii=False).encode("utf-8")
        expected = {"record_type": combined.EXPECTATION_TYPE, "version": 1,
                    "context": context, "raw_review_sha256": "sha256:" + hashlib.sha256(raw).hexdigest()}
        return raw, expected

    def bind(self, observation):
        return offline.bind_review(observation, *self.review(observation))

    def close(self, bound):
        return offline.close_offline(
            bound, self.target, operation_id="EXAMPLE-operation", expected_revision=0)

    def held(self, report) -> None:
        for name in offline.AUTHORITY_FIELDS:
            if name in report:
                self.assertIs(report[name], False)
        for value in report.values():
            if type(value) is dict:
                self.held(value)
            elif type(value) is list:
                for item in value:
                    if type(item) is dict:
                        self.held(item)

    def empty(self) -> None:
        state = self.target.snapshot()
        self.assertEqual((state["comment_writes"], state["close_writes"]), (0, 0))
        self.assertFalse(state["closed"])

    def reject(self, observation) -> None:
        self.held(observation.report)
        with self.assertRaises(offline.ClosureError):
            offline.bind_review(observation, *self.review(observation))
        self.empty()

    def changed(self, original, path, value):
        result = copy.deepcopy(original)
        destination = result
        parts = path.split(".")
        for part in parts[:-1]:
            destination = destination[int(part) if part.isdigit() else part]
        destination[int(parts[-1]) if parts[-1].isdigit() else parts[-1]] = value
        return result

    def test_actual_mixed_requirements_bind_and_close_one_memory_task(self) -> None:
        optional = fixtures.criterion("EXAMPLE-optional", "EXAMPLE optional reliability review.", "review-gate")
        optional.update(applicability="not-applicable", not_applicable_reason="EXAMPLE optional reliability scope.")
        self.begin(extra=[optional])
        actual, consumers = [], []
        execute = cc.execute_checked_command
        consume = validators.prepare

        def run(spec):
            result = execute(spec)
            actual.append(copy.deepcopy(result))
            return result

        def read_receipts(*args, **kwargs):
            result = consume(*args, **kwargs)
            consumers.append(copy.deepcopy(result))
            return result

        with patch.object(cc, "execute_checked_command", side_effect=run) as calls, \
                patch.object(validators, "prepare", side_effect=read_receipts), \
                patch.object(producer, "produce_mixed", wraps=producer.produce_mixed) as produce, \
                patch.object(combined, "prepare", wraps=combined.prepare) as prepare, \
                patch.object(combined, "consume", wraps=combined.consume) as check:
            observation = self.observe()
            raw, expected = self.review(observation)
            bound = offline.bind_review(observation, raw, expected)
            result = self.close(bound)
        produce.assert_called_once()
        prepare.assert_called_once()
        calls.assert_called_once()
        self.assertEqual(check.call_count, 2)
        for call in check.call_args_list:
            self.assertEqual(call.args, (bound.prepared, observation.context, raw, expected))
        production = observation.production
        wrappers = production["validator_evidence"]
        self.assertEqual([entry["result"] for entry in wrappers], actual)
        self.assertEqual(production["consumer_diagnostic"], consumers[0])
        self.assertTrue(production["validator_observations_complete"])
        self.assertFalse(production["observations_complete"])
        self.assertFalse(production["combined_observations_complete"])
        self.assertFalse(consumers[0]["observations_complete"])
        self.assertEqual(consumers[0]["criteria"][0]["state"], "UNASSESSABLE")
        self.assertEqual(production["required_criterion_ids"], rb.required_criterion_ids(self.initial))
        self.assertEqual(production["required_validator_criterion_ids"], ["EXAMPLE-validator-0"])
        self.assertEqual(production["unobserved_validator_criterion_ids"], [])
        self.assertEqual(observation.context, {
            "record_type": combined.INPUT_TYPE, "version": 1,
            "root": str(self.repo), "baseline": self.initial,
            "amendments": self.amendments, "candidate": self.candidate,
            "bead": self.bead, "validator_evidence": wrappers,
        })
        for wrapper in wrappers:
            self.assertEqual(set(wrapper["result"]), validators.RESULT_FIELDS)
            self.assertEqual(wrapper["baseline_digest"], self.chain["digest"])
            self.assertEqual(wrapper["candidate_digest"], ci.candidate_digest(self.candidate))
            self.assertEqual(wrapper["spec"], self.commands[wrapper["criterion_id"]])
        snapshot = observation.combined["snapshot"]
        self.assertTrue(observation.combined["combined_observations_complete"])
        self.assertEqual(snapshot, bound.prepared["snapshot"])
        self.assertEqual(snapshot["criterion_inventory"], self.initial["criteria"])
        self.assertEqual(snapshot["required_criterion_ids"], rb.required_criterion_ids(self.initial))
        artifact = snapshot["artifact_observation"]["snapshot"]["artifact_report"]["criteria"][0]
        self.assertEqual(artifact["status"], "PASSED")
        self.assertEqual(artifact["observation"]["size"], len(fixtures.AFTER))
        self.assertEqual(artifact["observation"]["sha256"], fixtures.sha(fixtures.AFTER))
        self.assertEqual(snapshot["validator_observation"]["validator_evidence"], wrappers)
        for report in (observation.report, bound.report, result, self.target.snapshot()):
            self.held(report)
        self.assertTrue(result["fake_completed"], result["errors"])
        state = self.target.snapshot()
        self.assertEqual((state["revision"], state["comment_writes"], state["close_writes"]), (2, 1, 1))
        expected_bead = copy.deepcopy(self.bead)
        expected_bead["comments"].append({"text": result["summary"]})
        expected_bead["status"] = "closed"
        self.assertEqual(state["bead"], expected_bead)
        self.assertFalse((self.repo / ".beads").exists())
        self.assertFalse((self.repo / ".orchestration-audit").exists())

    def test_unsupported_requirements_and_malformed_artifact_contracts_run_no_commands(self) -> None:
        extras = (
            fixtures.criterion("EXAMPLE-service", "EXAMPLE reliability service must remain inactive."),
            fixtures.criterion("EXAMPLE-prose", "EXAMPLE reliability prose requires human assessment."),
            fixtures.criterion("EXAMPLE-review", "EXAMPLE reliability review is required.", "review-gate"),
        )
        for item in extras:
            with self.subTest(criterion=item["id"]):
                self.begin(extra=[item])
                with patch.object(cc, "execute_checked_command", wraps=cc.execute_checked_command) as run:
                    observation = self.observe()
                run.assert_not_called()
                expected = "unsupported evidence kind" if item["evidence_kind"] == "review-gate" else "independently predeclared"
                self.assertIn(expected, " ".join(observation.production["errors"]))
                self.reject(observation)
        for predicate in (
            {"op": "EXAMPLE-unsupported", "path": "src/item.txt"},
            {"op": "regular-file-sha256", "path": "src/item.txt", "sha256": "EXAMPLE-invalid-reliability-hash"},
        ):
            with self.subTest(predicate=predicate["op"]):
                self.begin(predicate=predicate)
                with patch.object(cc, "execute_checked_command", wraps=cc.execute_checked_command) as run:
                    observation = self.observe()
                run.assert_not_called()
                self.assertEqual(observation.production["artifact_diagnostic"]["criteria"][0]["status"], "UNASSESSABLE")
                self.reject(observation)

    def test_actual_failed_missing_and_unassessable_artifacts_never_complete(self) -> None:
        for predicate, status in (
            ({"op": "regular-file-sha256", "path": "src/item.txt", "sha256": fixtures.sha(b"EXAMPLE wrong reliability bytes\n")}, "FAILED"),
            ({"op": "regular-file-sha256", "path": "src/EXAMPLE-missing", "sha256": fixtures.sha(fixtures.AFTER)}, "FAILED"),
            ({"op": "path-absent", "path": "src/EXAMPLE-unbound"}, "UNASSESSABLE"),
        ):
            with self.subTest(status=status, path=predicate["path"]):
                self.begin(predicate=predicate)
                observation = self.observe()
                self.assertTrue(observation.production["validator_observations_complete"])
                self.assertEqual(observation.production["artifact_diagnostic"]["criteria"][0]["status"], status)
                self.assertFalse(observation.combined["combined_observations_complete"])
                self.reject(observation)

    def test_original_joins_and_exact_command_mapping_refuse_before_execution(self) -> None:
        self.begin()
        cases = (
            ("commands", {}),
            ("commands", {"EXAMPLE-replaced": self.commands["EXAMPLE-validator-0"]}),
            ("commands", {**self.commands, "EXAMPLE-extra": self.commands["EXAMPLE-validator-0"]}),
            ("initial.criteria", self.initial["criteria"][1:]),
            ("initial.criteria.0.id", "EXAMPLE-replaced"),
            ("initial.criteria.0.evidence_kind", "service"),
            ("initial.criteria.0.evidence_kind", "prose"),
            ("candidate.baseline.digest", "sha256:" + "0" * 64),
            ("candidate.commit", "0" * 40),
            ("bead.comments", []),
            ("bead.id", "EXAMPLE-other"),
            ("root", str(self.repo.parent)),
            ("amendments", [{}]),
        )
        for path, value in cases:
            with self.subTest(path=path):
                with patch.object(cc, "execute_checked_command", wraps=cc.execute_checked_command) as run:
                    observation = offline.observe_mixed(**self.changed(self.arguments(), path, value))
                run.assert_not_called()
                self.reject(observation)

    def test_old_validator_only_apis_work_and_old_mixed_input_precisely_refuses(self) -> None:
        self.begin(mixed=False)
        with patch.object(cc, "execute_checked_command", wraps=cc.execute_checked_command) as run:
            produced = producer.produce(**self.arguments())
            self.assertTrue(produced["observations_complete"])
            observation = offline.observe(**self.arguments())
            result = self.close(self.bind(observation))
        self.assertEqual(run.call_count, 2)
        self.assertTrue(result["fake_completed"], result["errors"])
        self.held(result)
        self.begin()
        arguments = self.arguments()
        arguments["commands"] = {**self.commands, "EXAMPLE-artifact": fixtures.spec(
            self.repo, "EXAMPLE-artifact-command", "print('EXAMPLE reliability unrelated bytes')\n")}
        with patch.object(cc, "execute_checked_command", wraps=cc.execute_checked_command) as run:
            produced = producer.produce(**arguments)
        run.assert_not_called()
        self.assertEqual(produced["errors"], [
            "production refused: PreparationError: unsupported evidence kind remains UNASSESSABLE"])
        self.empty()

    def test_failed_refused_timed_out_and_unrun_receipts_remain_incomplete(self) -> None:
        sources = (
            "raise SystemExit(7)\n",
            "def EXAMPLE_invalid(:\n",
            "import sys\nimport time\nprint('EXAMPLE reliability timeout', file=sys.stderr, flush=True)\ntime.sleep(60)\n",
        )
        for source in sources:
            with self.subTest(source=source.splitlines()[0]):
                self.begin(source=source, timeout=1)
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
                if "time.sleep" in source:
                    self.assertEqual(actual[0]["failure_class"], "execution-timeout")
                    self.assertIn("EXAMPLE reliability timeout", actual[0]["diagnostics"]["stderr"])
                self.assertFalse(observation.production["validator_observations_complete"])
                self.reject(observation)
        self.begin(count=2)
        execute = cc.execute_checked_command
        calls = 0

        def unavailable(command):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise RuntimeError("EXAMPLE reliability validator is unavailable")
            return execute(command)

        with patch.object(cc, "execute_checked_command", side_effect=unavailable):
            observation = self.observe()
        self.assertEqual(len(observation.production["validator_evidence"]), 1)
        self.assertEqual(observation.production["unobserved_validator_criterion_ids"], ["EXAMPLE-validator-1"])
        self.reject(observation)

    def test_forged_status_mode_json_and_wrong_or_unrelated_receipts_cannot_close(self) -> None:
        self.begin()
        produced = producer.produce_mixed(**self.arguments())
        unrelated = fixtures.spec(self.repo, "EXAMPLE-unrelated", "print('EXAMPLE reliability unrelated bytes')\n")
        unrelated_result = cc.execute_checked_command(unrelated)
        cases = (
            ("validator_evidence", []),
            ("validator_evidence.0.baseline_digest", "sha256:" + "0" * 64),
            ("validator_evidence.0.candidate_digest", "sha256:" + "1" * 64),
            ("validator_evidence.0.criterion_id", "EXAMPLE-unrelated"),
            ("validator_evidence.0.result.exit_code", False),
            ("validator_evidence.0.result.execution_started", False),
            ("validator_evidence.0.result", {"execution_status": "passed"}),
            ("validator_evidence.0.spec", unrelated),
            ("validator_evidence.0.result", unrelated_result),
            ("record_type", "cwo-validator-evidence-production"),
            ("production_mode", "validator-only"),
        )
        for path, value in cases:
            with self.subTest(path=path):
                changed = self.changed(produced, path, value)
                changed["observations_complete"] = True
                changed["validator_observations_complete"] = True
                with patch.object(producer, "produce_mixed", return_value=changed):
                    self.reject(self.observe())
        observation = self.observe()
        for forged in (observation.report, json.loads(json.dumps(observation.report)), object.__new__(offline.Observation)):
            with self.assertRaises(offline.ClosureError):
                offline.bind_review(forged, *self.review(observation))
        returned = observation.production
        returned["production_mode"] = "validator-only"
        self.assertEqual(observation.production_mode, "mixed")
        self.empty()

    def test_blockers_and_artifact_drift_after_review_preparation_prevent_binding(self) -> None:
        self.begin()
        observation = self.observe()
        blocker = {"id": "EXAMPLE-blocker", "blocking": True, "state": "OPEN", "text": "EXAMPLE reliability blocker."}
        with self.assertRaises(offline.ClosureError):
            offline.bind_review(observation, *self.review(observation, [blocker]))
        prepare = combined.prepare

        def drift(*args, **kwargs):
            result = prepare(*args, **kwargs)
            (self.repo / "src/item.txt").write_bytes(b"EXAMPLE reliability review drift\n")
            return result

        with patch.object(combined, "prepare", side_effect=drift), self.assertRaises(offline.ClosureError):
            self.bind(observation)
        self.empty()

    def test_relevant_post_review_and_immediate_pre_comment_drift_prevent_writes(self) -> None:
        for phase in ("after-review", "before-comment"):
            with self.subTest(phase=phase):
                self.begin()
                bound = self.bind(self.observe())
                if phase == "after-review":
                    (self.repo / "src/item.txt").write_bytes(b"EXAMPLE reliability later artifact\n")
                    result = self.close(bound)
                else:
                    summary = offline._summary

                    def drift(*args):
                        text = summary(*args)
                        (self.repo / "src/item.txt").write_bytes(b"EXAMPLE reliability persistence drift\n")
                        return text

                    with patch.object(offline, "_summary", side_effect=drift):
                        result = self.close(bound)
                self.assertFalse(result["fake_completed"])
                self.empty()

    def test_interleaved_command_and_artifact_observation_drift_prevent_writes(self) -> None:
        for component in ("command", "artifact"):
            with self.subTest(component=component):
                self.begin()
                module, name = (cc, "execute_checked_command") if component == "command" else (artifacts, "_artifact")
                original = getattr(module, name)

                def drift(*args, **kwargs):
                    result = original(*args, **kwargs)
                    (self.repo / "src/item.txt").write_bytes(b"EXAMPLE interleaved reliability drift\n")
                    return result

                with patch.object(module, name, side_effect=drift):
                    observation = self.observe()
                self.assertFalse(observation.combined["combined_observations_complete"])
                self.reject(observation)

    def test_mixed_replay_retains_completed_and_partial_persistence_after_drift(self) -> None:
        self.begin()
        bound = self.bind(self.observe())
        first = self.close(bound)
        self.assertTrue(first["fake_completed"])
        (self.repo / "src/item.txt").write_bytes(b"EXAMPLE reliability replay drift\n")
        replay = self.close(bound)
        self.assertFalse(replay["fake_completed"])
        self.assertTrue(replay["closed"])
        self.assertTrue(replay["comment_posted"])
        self.assertEqual((replay["new_comment_writes"], replay["new_close_writes"]), (0, 0))
        self.assertEqual((self.target.snapshot()["comment_writes"], self.target.snapshot()["close_writes"]), (1, 1))
        self.begin()
        bound = self.bind(self.observe())
        with patch.object(self.target, "_mark_closed", side_effect=RuntimeError("EXAMPLE reliability close failure")):
            first = self.close(bound)
        self.assertTrue(first["partial_persistence"])
        state = self.target.snapshot()
        edited = state["bead"]
        edited["title"] = "EXAMPLE reliability later task"
        self.target.compare_and_swap(state["revision"], edited)
        replay = self.close(bound)
        self.assertFalse(replay["fake_completed"])
        self.assertTrue(replay["comment_posted"])
        self.assertTrue(replay["partial_persistence"])
        self.assertFalse(replay["closed"])
        self.assertEqual((replay["comment_writes"], replay["close_writes"]), (1, 0))
        self.assertEqual((replay["new_comment_writes"], replay["new_close_writes"]), (0, 0))
        self.held(replay)


if __name__ == "__main__":
    unittest.main()
