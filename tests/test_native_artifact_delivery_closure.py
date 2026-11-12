"""Native artifact closure reliability with actual producers and EXAMPLE fake approvals."""
from __future__ import annotations

import contextlib
import copy
import hashlib
import json
import pickle
import socket
import sys
import unittest
import urllib.request
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "tests"))

import close_bead_with_summary as closure  # noqa: E402
import prepare_artifact_acceptance as artifacts  # noqa: E402
import prepare_combined_review_binding as combined  # noqa: E402
import prepare_delivery_closure as offline  # noqa: E402
import offline_artifact_validation as native_validation  # noqa: E402
import offline_n1_host as host_module  # noqa: E402
import test_offline_n1_host as native_fixtures  # noqa: E402
from cwo_core import beads  # noqa: E402
from cwo_core import candidate_identity as ci  # noqa: E402
from cwo_core import checked_command as cc  # noqa: E402
from cwo_core import requirement_baseline as rb  # noqa: E402
from cwo_core import stage_completion  # noqa: E402
from cwo_core.native_control import NativeControlTurn  # noqa: E402
from tests import test_validator_receipt_preparation as fixtures  # noqa: E402


class NativeCase:
    """Compose the existing useful reliability fixture without inheriting its test suite."""

    def __init__(self, test, outputs):
        helper = native_fixtures.OfflineN1HostTests(methodName="runTest")
        test.addCleanup(helper.doCleanups)

        def seed_source(helper):
            if len(outputs) > 1:
                for path, data in outputs.items():
                    if path != "result.txt":
                        destination = helper.source / path
                        destination.parent.mkdir(parents=True, exist_ok=True)
                        destination.write_bytes(data)
                helper.git(helper.source, "add", "-A")
                helper.git(helper.source, "commit", "--quiet", "-m", "EXAMPLE reliability inert baseline")

        helper.setUp(seed_source=seed_source)
        self.helper = helper
        self.case = helper.case()
        self.host, self.adapter, self.server, self.control = self.case


class NativeArtifactDeliveryClosureTests(unittest.TestCase):
    def setUp(self):
        self.effects = contextlib.ExitStack()
        self.addCleanup(self.effects.close)
        self.boundaries = []
        for module, name in ((beads, "run_bd"), (beads, "run_bd_structured"),
                             (closure, "run_bd"), (stage_completion, "consume"),
                             (socket, "socket"), (socket, "create_connection"),
                             (urllib.request, "urlopen")):
            self.boundaries.append(self.effects.enter_context(patch.object(
                module, name, side_effect=AssertionError("EXAMPLE reliability effect remains held"))))

    def tearDown(self):
        for boundary in self.boundaries:
            boundary.assert_not_called()

    def begin(self, *, outputs=None, omitted=(), extra=(), variant="passed", policy_change=None, mode="complete"):
        self.outputs = {"result.txt": native_fixtures.OUTPUT} if outputs is None else dict(outputs)
        self.fixture = NativeCase(self, self.outputs)
        self.host = self.fixture.host
        self.fixture.server.mode = mode
        self.commands = {}
        criteria = []
        for path, data in sorted(self.outputs.items()):
            if path not in omitted:
                predicate = {"op": "regular-file-sha256", "path": path,
                             "sha256": fixtures.sha(data)}
                criteria.append(fixtures.criterion(
                    "EXAMPLE-artifact-" + str(len(criteria)), artifacts.PREFIX + json.dumps(predicate), "artifact"))
        for index in range(2 if variant == "unrun" else 1):
            source = (
                "from pathlib import Path\n"
                f"assert Path('result.txt').read_bytes() == {native_fixtures.OUTPUT!r}\n"
                "print('EXAMPLE reliability checked result')\n"
            )
            if variant == "failed":
                source = "raise SystemExit(7)\n"
            if variant == "refused":
                source = "def EXAMPLE_invalid(:\n"
            name = f"EXAMPLE-validator-{index}"
            command = fixtures.spec(self.host.worker, f"EXAMPLE-command-{index}", source)
            self.commands[name] = command
            criteria.append(fixtures.validator(name, command, b"EXAMPLE reliability checked result\n"))
        self.initial = {
            "record_type": rb.BASELINE_RECORD_TYPE, "version": 1,
            "bead_id": "EXAMPLE-bead", "baseline_version": 1, "criteria": [*criteria, *copy.deepcopy(extra)]}
        self.amendments = []
        self.chain = rb.resolve_chain(self.initial, self.amendments)
        self.bead = {"id": self.chain["bead_id"], "status": "open", "title": "EXAMPLE reliability task",
                     "comments": [{"text": rb.reference_line(self.chain["bead_id"], entry["version"], entry["digest"])}
                                  for entry in self.chain["baselines"]]}
        self.specification = {"version": 1, "outputs": [
            {"path": path, "validator": "bytes", "size": len(data), "sha256": fixtures.sha(data)}
            for path, data in sorted(self.outputs.items())]}
        if policy_change:
            self.specification["outputs"][0].update(policy_change)
        self.policy = offline.freeze_native_policy(self.host, self.specification)
        if variant == "unrun":
            self.commands.pop("EXAMPLE-validator-1")
        self.base = self.fixture.helper.git(self.host.worker, "rev-parse", "HEAD").stdout.decode("ascii").strip()
        self.report = self.fixture.helper.run_case(self.fixture.case, outputs=tuple(self.outputs))
        self.expected_target = copy.deepcopy(self.report["binding"]["target"])
        scope = sorted(self.outputs) if self.report["status"] == "artifact-ready" else ["seed.txt"]
        self.candidate = ci.capture_candidate(
            self.host.worker, chain=self.chain, base_commit=self.base, scope_paths=scope)
        self.bead["comments"].append({"text": ci.candidate_reference_line(
            self.chain["bead_id"], ci.candidate_digest(self.candidate))})
        self.target = offline.MemoryClosureTarget(self.bead)

    def begin_with_replaced_repository(self, repository, component):
        run_case = native_fixtures.OfflineN1HostTests.run_case

        def replacement(helper, case, **options):
            host, adapter, server, control = case
            root = getattr(host, repository)
            relative = {"root": ".", "git": ".git", "objects": ".git/objects"}[component]
            original_path = root / relative
            replacement_path = helper.clone("EXAMPLE-replacement-repository") / relative
            saved = helper.root / "EXAMPLE-original-repository"
            produced = helper.root / "EXAMPLE-produced-repository"
            original_path.rename(saved)
            replacement_path.rename(original_path)
            try:
                replacement_host = host_module.OfflineN1Host(host.state, host.target, host.worker)
                report = run_case(helper, (replacement_host, adapter, server, control), **options)
                self.assertEqual(report["status"], "artifact-ready", report["error"])
            finally:
                original_path.rename(produced)
                saved.rename(original_path)
            for path, data in self.outputs.items():
                destination = host.worker / path
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(data)
            return report

        with patch.object(native_fixtures.OfflineN1HostTests, "run_case", new=replacement):
            self.begin()

    def assert_original_binding_refused(self, *fields):
        declared = json.loads(offline._declared(self.policy).initial)
        self.assertEqual(self.host._observe(), declared)
        self.assertEqual(self.host.status("fake-operation"), self.report)
        for name in fields:
            self.assertNotEqual(self.report["binding"][name], declared[name])
        with patch.object(native_validation, "validate_artifact", wraps=native_validation.validate_artifact) as validate, \
                patch.object(cc, "execute_checked_command", wraps=cc.execute_checked_command) as run, \
                patch.object(offline, "_issue", wraps=offline._issue) as issue:
            with self.assertRaisesRegex(offline.ClosureError, "complete original declaration"):
                self.observe()
        validate.assert_not_called()
        run.assert_not_called()
        issue.assert_not_called()
        self.assertEqual(self.fixture.server.sends, 1)
        self.empty()

    def arguments(self):
        return {"root": str(self.host.worker), "initial": self.initial,
                "candidate": self.candidate, "bead": self.bead, "commands": self.commands,
                "amendments": self.amendments, "host": self.host, "report": self.report,
                "expected_target": self.expected_target, "policy": self.policy}

    def observe(self, **changes):
        arguments = self.arguments()
        arguments.update(changes)
        return offline.observe_native_mixed(**arguments)

    def review(self, observation):
        context = {"review_id": "EXAMPLE-review", "reviewer": "EXAMPLE reliability fake reviewer",
                   "verdict": "APPROVE", "snapshot": observation.combined["snapshot"] or {}}
        document = {"record_type": combined.REVIEW_TYPE, "version": 1, "context": copy.deepcopy(context),
                    "findings": [], "summary": "EXAMPLE reliability fake approval without authenticated independence."}
        raw = json.dumps(document).encode("utf-8")
        expected = {"record_type": combined.EXPECTATION_TYPE, "version": 1,
                    "context": context, "raw_review_sha256": "sha256:" + hashlib.sha256(raw).hexdigest()}
        return raw, expected

    def bind(self, observation):
        return offline.bind_review(observation, *self.review(observation))

    def close(self, bound):
        return offline.close_offline(bound, self.target, operation_id="EXAMPLE-operation", expected_revision=0)

    def empty(self):
        state = self.target.snapshot()
        self.assertEqual((state["comment_writes"], state["close_writes"]), (0, 0))
        self.assertFalse(state["closed"])

    def held(self, report):
        for name in (*offline.AUTHORITY_FIELDS, *native_validation._FALSE):
            if name in report:
                self.assertIs(report[name], False)
        for value in report.values():
            if type(value) is dict:
                self.held(value)
            elif type(value) is list:
                for item in value:
                    if type(item) is dict:
                        self.held(item)

    def drift(self, kind):
        if kind == "worker":
            (self.host.worker / "result.txt").write_bytes(b"EXAMPLE reliability worker drift\n")
        elif kind == "candidate":
            (self.host.worker / "EXAMPLE-extra.txt").write_bytes(b"EXAMPLE reliability candidate drift\n")
        elif kind == "target":
            (self.host.target / "seed.txt").write_bytes(b"EXAMPLE reliability target drift\n")
        elif kind == "artifact":
            blob = self.host.state / "artifact" / "file-0000"
            blob.chmod(0o600)
            blob.write_bytes(b"EXAMPLE reliability artifact drift\n")
            blob.chmod(0o400)
        elif kind == "binding":
            self.host.worker = self.host.target
        elif kind == "root":
            self.host.worker.rename(self.fixture.helper.root / "EXAMPLE-moved-worker")
        elif kind == "report":
            (self.host.state / "operation.json").write_bytes(b"{}")

    def test_actual_native_artifact_mixed_review_and_memory_closure(self):
        self.begin()
        self.assertIs(host_module.NativeControlTurn, NativeControlTurn)
        self.assertIs(type(self.fixture.adapter), host_module.LiveThreadAdapter)
        callbacks = copy.deepcopy(self.fixture.adapter.callback_latencies)
        with native_fixtures.repository_write_boundaries((self.host.target, self.host.worker)) as writes:
            with patch.object(native_validation, "validate_artifact", wraps=native_validation.validate_artifact) as validate, \
                    patch.object(native_validation, "consume_validated", wraps=native_validation.consume_validated) as consume, \
                    patch.object(cc, "execute_checked_command", wraps=cc.execute_checked_command) as run, \
                    patch.object(combined, "prepare", wraps=combined.prepare) as prepare, \
                    patch.object(combined, "consume", wraps=combined.consume) as check:
                observation = self.observe()
                bound = self.bind(observation)
                first = self.close(bound)
                replay = self.close(bound)
            validate.assert_called_once()
            self.assertGreater(consume.call_count, 3)
            run.assert_called_once()
            prepare.assert_called_once()
            self.assertEqual(check.call_count, 3)
        self.assertEqual(writes, [])
        self.assertTrue(first["fake_completed"], first["errors"])
        self.assertEqual(replay, {**first, "new_comment_writes": 0, "new_close_writes": 0})
        self.assertEqual(self.fixture.server.sends, 1)
        self.assertEqual(self.fixture.adapter.callback_latencies, callbacks)
        self.assertEqual(observation.production_mode, "mixed")
        production = observation.production
        self.assertEqual(production["required_criterion_ids"], rb.required_criterion_ids(self.initial))
        self.assertEqual(production["checked_command_calls"], 1)
        self.assertTrue(production["validator_observations_complete"])
        self.assertFalse(production["observations_complete"])
        self.assertEqual(observation.combined["snapshot"], bound.prepared["snapshot"])
        self.assertEqual(bound.prepared["snapshot"]["criterion_inventory"], self.initial["criteria"])
        self.assertEqual(
            host_module._capture(self.host.target, (self.host.target, self.host.worker)), self.expected_target)
        state = self.target.snapshot()
        self.assertEqual((state["revision"], state["comment_writes"], state["close_writes"]), (2, 1, 1))
        expected = copy.deepcopy(self.bead)
        expected["comments"].append({"text": first["summary"]})
        expected["status"] = "closed"
        self.assertEqual(state["bead"], expected)
        for report in (observation.report, bound.report, first, state):
            self.held(report)
        self.assertFalse((self.host.worker / ".beads").exists())
        self.assertFalse((self.host.worker / ".orchestration-audit").exists())

    def test_genuine_reinitialized_replacement_worker_report_cannot_borrow_original_policy(self):
        self.begin_with_replaced_repository("worker", "root")
        self.assert_original_binding_refused("worker_identity")

    def test_genuine_replacement_repository_metadata_reports_cannot_borrow_original_policy(self):
        cases = (("worker", "git"), ("worker", "objects"),
                 ("target", "root"), ("target", "git"), ("target", "objects"))
        for repository, component in cases:
            with self.subTest(repository=repository, component=component):
                self.begin_with_replaced_repository(repository, component)
                self.assert_original_binding_refused(repository + "_identity")

    def test_genuine_changed_target_snapshot_report_cannot_borrow_original_policy(self):
        run_case = native_fixtures.OfflineN1HostTests.run_case

        def replacement(helper, case, **options):
            host, adapter, server, control = case
            path = host.target / "seed.txt"
            original = path.read_bytes()
            path.write_bytes(b"EXAMPLE reliability replacement target snapshot\n")
            try:
                replacement_host = host_module.OfflineN1Host(host.state, host.target, host.worker)
                report = run_case(helper, (replacement_host, adapter, server, control), **options)
                self.assertEqual(report["status"], "artifact-ready", report["error"])
                return report
            finally:
                path.write_bytes(original)

        with patch.object(native_fixtures.OfflineN1HostTests, "run_case", new=replacement):
            self.begin()
        self.assert_original_binding_refused("target")

    def test_wrong_original_inputs_and_missing_validators_refuse_without_writes(self):
        self.begin()
        other = host_module.OfflineN1Host(self.host.state, self.host.target, self.host.worker)
        changed = copy.deepcopy(self.report)
        changed["summary"]["EXAMPLE-reliability-drift"] = True
        target = copy.deepcopy(self.expected_target)
        target["complete"] = 1
        mismatched = copy.deepcopy(self.initial)
        mismatched["criteria"][0]["expected_outcome"] = artifacts.PREFIX + json.dumps({
            "op": "regular-file-sha256", "path": "result.txt",
            "sha256": fixtures.sha(b"EXAMPLE reliability unrelated bytes\n")})
        cases = (
            {"host": other},
            {"policy": native_validation.freeze_policy(self.specification)},
            {"report": changed},
            {"expected_target": target},
            {"root": str(self.host.target)},
            {"candidate": {**self.candidate, "commit": "0" * 40}},
            {"candidate": {**self.candidate, "delivery_scope": {"paths": ["seed.txt"], "live_resources": []}}},
            {"commands": {}},
            {"amendments": [{}]},
            {"initial": mismatched},
        )
        for changes in cases:
            with self.subTest(fields=sorted(changes)):
                with patch.object(cc, "execute_checked_command", wraps=cc.execute_checked_command) as run:
                    try:
                        observation = self.observe(**changes)
                    except offline.ClosureError:
                        pass
                    else:
                        with self.assertRaises(offline.ClosureError):
                            self.bind(observation)
                run.assert_not_called()
                self.empty()

    def test_all_outputs_need_original_named_criteria_and_supported_evidence(self):
        outputs = {"result.txt": native_fixtures.OUTPUT, "EXAMPLE-inert.txt": b"EXAMPLE reliability inert output\n"}
        for omitted in (("result.txt",), ("EXAMPLE-inert.txt",)):
            with self.subTest(omitted=omitted):
                self.begin(outputs=outputs, omitted=omitted)
                with patch.object(cc, "execute_checked_command", wraps=cc.execute_checked_command) as run, self.assertRaises(offline.ClosureError):
                    self.observe()
                run.assert_not_called()
                self.empty()
        self.begin(extra=[fixtures.criterion(
            "EXAMPLE-held-review", "EXAMPLE reliability approval remains required.", "review-gate")])
        with patch.object(cc, "execute_checked_command", wraps=cc.execute_checked_command) as run, self.assertRaises(offline.ClosureError):
            self.observe()
        run.assert_not_called()
        self.empty()

    def test_independent_validation_failure_retains_exact_original_cause_and_report(self):
        for change in ({"size": len(native_fixtures.OUTPUT) + 1}, {"sha256": fixtures.sha(b"EXAMPLE reliability mismatch\n")}):
            with self.subTest(change=change):
                self.begin(policy_change=change)
                with self.assertRaises(offline.ClosureError) as caught:
                    self.observe()
                failure = caught.exception.__cause__
                self.assertIsInstance(failure, native_validation.ValidationError)
                self.assertEqual(str(caught.exception), str(failure))
                self.assertFalse(failure.report["offline_validation_complete"])
                self.assertFalse(failure.report["files"][0]["passed"])
                self.held(failure.report)
                self.empty()
        self.begin(mode="failure")
        with self.assertRaises(offline.ClosureError) as caught:
            self.observe()
        self.assertIsInstance(caught.exception.__cause__, native_validation.ValidationError)
        self.assertEqual(self.report["status"], "reconciliation-required")
        self.assertEqual(self.fixture.server.sends, 1)
        self.empty()

    def test_failed_refused_and_unrun_real_validator_reports_remain_incomplete(self):
        for variant in ("failed", "refused", "unrun"):
            with self.subTest(variant=variant):
                self.begin(variant=variant)
                observation = self.observe()
                self.assertFalse(observation.production["validator_observations_complete"])
                self.assertEqual(observation.production["required_criterion_ids"], rb.required_criterion_ids(self.initial))
                if variant == "unrun":
                    self.assertEqual(observation.production["checked_command_calls"], 0)
                    self.assertEqual(
                        observation.production["unobserved_validator_criterion_ids"], ["EXAMPLE-validator-0", "EXAMPLE-validator-1"])
                else:
                    self.assertEqual(len(observation.production["validator_evidence"]), 1)
                with self.assertRaises(offline.ClosureError):
                    self.bind(observation)
                self.held(observation.report)
                self.empty()

    def test_issued_states_and_returned_copies_do_not_create_native_bindings(self):
        self.begin()
        observation = self.observe()
        for value in (self.policy.report, json.loads(json.dumps(self.policy.report)), object.__new__(offline.FrozenPolicy)):
            with self.assertRaises(offline.ClosureError):
                self.observe(policy=value)
        for value in (observation.report, json.loads(json.dumps(observation.report)), object.__new__(offline.Observation)):
            with self.assertRaises(offline.ClosureError):
                offline.bind_review(value, *self.review(observation))
        for convert in (copy.copy, pickle.dumps):
            with self.assertRaises((offline.ClosureError, TypeError)):
                convert(self.policy)
        with self.assertRaises((offline.ClosureError, TypeError)):
            copy.copy(observation)
        # Existing observations may serialize as inert bytes; reconstruction
        # still cannot issue an observation or recover its private registry state.
        serialized = pickle.dumps(observation)
        with self.assertRaises((offline.ClosureError, TypeError)):
            pickle.loads(serialized)
        with self.assertRaises(offline.ClosureError):
            offline.FrozenPolicy()
        with self.assertRaises(offline.ClosureError):
            offline.freeze_native_policy(self.host, self.specification)
        self.policy.report["outputs"].clear()
        observation.production["validator_evidence"].clear()
        observation.context["baseline"]["criteria"].clear()
        self.report["summary"].clear()
        self.expected_target.clear()
        bound = self.bind(observation)
        for forged in (bound.report, object.__new__(offline.BoundReview)):
            self.assertFalse(self.close(forged)["fake_completed"])
        self.empty()
        self.assertTrue(self.close(bound)["fake_completed"])

    def test_worker_candidate_target_root_artifact_and_report_drift_prevent_binding(self):
        for kind in ("worker", "candidate", "target", "root", "artifact", "binding", "report"):
            with self.subTest(kind=kind):
                self.begin()
                observation = self.observe()
                self.drift(kind)
                with self.assertRaises(offline.ClosureError):
                    self.bind(observation)
                self.empty()

    def test_drift_after_actual_review_preparation_refuses_binding(self):
        self.begin()
        observation = self.observe()
        prepare = combined.prepare
        def drift(*args, **kwargs):
            result = prepare(*args, **kwargs)
            self.drift("artifact")
            return result
        with patch.object(combined, "prepare", side_effect=drift), self.assertRaises(offline.ClosureError):
            self.bind(observation)
        self.empty()

    def test_post_review_and_immediate_pre_comment_native_drift_have_zero_writes(self):
        for phase in ("after-review", "before-comment"):
            for kind in ("worker", "target", "artifact", "binding"):
                with self.subTest(phase=phase, kind=kind):
                    self.begin()
                    bound = self.bind(self.observe())
                    summary = offline._summary
                    def drift(*args):
                        text = summary(*args)
                        self.drift(kind)
                        return text
                    if phase == "after-review":
                        self.drift(kind)
                        result = self.close(bound)
                    else:
                        with patch.object(offline, "_summary", side_effect=drift):
                            result = self.close(bound)
                    self.assertFalse(result["fake_completed"])
                    self.empty()

    def test_post_comment_native_drift_preserves_truthful_partial_persistence(self):
        for kind in ("worker", "artifact", "binding", "report"):
            with self.subTest(kind=kind):
                self.begin()
                bound = self.bind(self.observe())
                append = self.target._append_comment
                def drift(*args):
                    append(*args)
                    self.drift(kind)
                with patch.object(self.target, "_append_comment", side_effect=drift), patch.object(cc, "execute_checked_command", wraps=cc.execute_checked_command) as run:
                    first = self.close(bound)
                    replay = self.close(bound)
                run.assert_not_called()
                self.assertTrue(first["partial_persistence"])
                self.assertFalse(first["fake_completed"])
                self.assertEqual((first["comment_writes"], first["close_writes"]), (1, 0))
                self.assertEqual((replay["new_comment_writes"], replay["new_close_writes"]), (0, 0))
                for name in ("comment_posted", "closed", "partial_persistence", "comment_writes", "close_writes"):
                    self.assertEqual(replay[name], first[name])
                self.assertFalse(self.target.snapshot()["closed"])
                self.assertEqual(self.fixture.server.sends, 1)
                self.held(first)
                self.held(replay)

    def test_completed_native_replay_rechecks_integrity_without_new_effects(self):
        for kind in ("artifact", "binding", "report"):
            with self.subTest(kind=kind):
                self.begin()
                bound = self.bind(self.observe())
                first = self.close(bound)
                self.assertTrue(first["fake_completed"], first["errors"])
                self.drift(kind)
                before = self.target.snapshot()
                with patch.object(cc, "execute_checked_command", wraps=cc.execute_checked_command) as run:
                    replay = self.close(bound)
                run.assert_not_called()
                self.assertEqual(self.target.snapshot(), before)
                self.assertFalse(replay["fake_completed"])
                self.assertTrue(replay["comment_posted"])
                self.assertTrue(replay["closed"])
                self.assertEqual((replay["comment_writes"], replay["close_writes"]), (1, 1))
                self.assertEqual((replay["new_comment_writes"], replay["new_close_writes"]), (0, 0))
                self.assertEqual(self.fixture.server.sends, 1)

    def test_secondary_cleanup_diagnostics_never_replace_the_active_native_exception(self):
        for first in (BaseException("EXAMPLE reliability first failure"), SystemExit("EXAMPLE reliability first exit")):
            with self.subTest(kind=type(first).__name__):
                self.begin()
                close = native_validation._Stage.close
                def cleanup(stage):
                    close(stage)
                    raise RuntimeError("EXAMPLE reliability secondary cleanup diagnostic")
                with patch.object(native_validation, "_compare", side_effect=first), \
                        patch.object(native_validation._Stage, "close", cleanup):
                    with self.assertRaises(BaseException) as caught:
                        self.observe()
                observed = caught.exception
                self.assertIs(observed.__cause__ if isinstance(observed, offline.ClosureError) else observed, first)
                self.empty()


    def test_native_consumption_refusal_keeps_the_first_validation_error(self):
        self.begin()
        observation = self.observe()
        self.drift("artifact")
        consume = native_validation.consume_validated
        failures = []

        def remember(*args, **kwargs):
            try:
                return consume(*args, **kwargs)
            except native_validation.ValidationError as exc:
                failures.append(exc)
                raise

        with patch.object(native_validation, "consume_validated", side_effect=remember):
            with self.assertRaises(offline.ClosureError) as caught:
                self.bind(observation)
        self.assertIs(caught.exception.__cause__, failures[0])
        self.assertEqual(str(caught.exception), str(failures[0]))
        self.empty()

    def test_old_mixed_interface_and_legacy_success_refusal_keep_their_contracts(self):
        self.begin()
        arguments = self.arguments()
        for name in ("host", "report", "expected_target", "policy"):
            arguments.pop(name)
        legacy = offline.observe_mixed(**arguments)
        self.assertIsNone(offline._observed(legacy).native)
        arguments = closure.parser().parse_args([
            "--bead", "EXAMPLE-bead", "--disposition", "completed",
            "--why", "EXAMPLE reliability fixture", "--close"])
        with self.assertRaises(ValueError) as caught:
            closure.execute(arguments)
        self.assertEqual(str(caught.exception),
                         closure.SUCCESS_UNAVAILABLE + " (disposition given: 'completed')")
        self.empty()

if __name__ == "__main__":
    unittest.main()
