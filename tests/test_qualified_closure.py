"""Closure cases through real binders and the original fake bd boundary."""
from __future__ import annotations

import contextlib
import fcntl
import json
import os
import sys
import tempfile
import threading
import unittest
from functools import partial
from pathlib import Path
from typing import NamedTuple
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "tests"))

import close_bead_with_summary as closure  # noqa: E402
import prepare_delivery_closure as original  # noqa: E402
import qualified_closure as qualified  # noqa: E402
from cwo_core import beads  # noqa: E402
from tests import test_native_artifact_delivery_closure as native_cases  # noqa: E402
from tests import test_offline_delivery_closure as compact_cases  # noqa: E402
from tests import test_validator_receipt_preparation as fixtures  # noqa: E402
import signal
import time
import prepare_combined_review_binding as combined


ExampleBeads = qualified.ExampleBeadsBridge


class LiveAdapterRow(NamedTuple):
    original_id: str
    wrapped: bool
    message: str | None
    trap: str
    replay: bool


class QualifiedClosureTests(unittest.TestCase):
    def compact(self, **options):
        case = compact_cases.OfflineDeliveryClosureTests(methodName="runTest")
        self.addCleanup(case.doCleanups)
        case.begin(**options)
        return case

    def native(self):
        case = native_cases.NativeArtifactDeliveryClosureTests(methodName="runTest")
        self.addCleanup(case.doCleanups)
        case.begin()
        return case

    def write(self, directory, name, data):
        path = directory / name
        path.write_bytes(data)
        path.chmod(0o600)

    def provision(self, case, directory):
        value = {"record_type": "cwo-EXAMPLE-closure-custody", "version": 1,
                 "scope": "EXAMPLE-only", "root": str(case.repo if hasattr(case, "repo") else case.host.worker),
                 "initial": case.initial, "amendments": case.amendments,
                 "candidate": case.candidate, "bead": case.bead, "commands": case.commands}
        self.write(directory, "contract.json", original._freeze(value))
        return ExampleBeads(case.bead, directory)

    @contextlib.contextmanager
    def registered(self, case):
        with tempfile.TemporaryDirectory(prefix="EXAMPLE-supervisor-") as temporary:
            directory = Path(temporary)
            effects = self.provision(case, directory)
            with patch.object(closure, "run_bd", new=effects), qualified.example_custody(str(directory)) as host:
                yield host, effects, directory

    def reviewed(self, case, host, directory, *, native=False, verdict="APPROVE", findings=()):
        options = {}
        if native:
            options["native"] = {"host": case.host, "report": case.report,
                                 "expected_target": case.expected_target, "policy": case.policy}
        observation = qualified.observe(host, **options)
        raw, expected = (case.review(observation) if native else
                         case.review(observation, verdict=verdict, findings=findings))
        self.write(directory, "review.json", raw)
        self.write(directory, "expectation.json", original._freeze({
            "record_type": "cwo-EXAMPLE-qualified-review-source", "version": 1,
            "context": host.review_context, "expected": expected}))
        qualified.bind(host)
        return observation

    def test_r5_example_bridge_ignores_public_activation_flag_for_dry_run_and_close(self):
        case = self.compact(additive=True)
        with patch.object(qualified, "PUBLIC_ACTIVATION", True), \
                self.registered(case) as (host, effects, directory):
            observation = self.reviewed(case, host, directory)
            self.assertEqual(observation.combined["snapshot"]["resolved_baseline"], case.chain)
            result = closure.execute_qualified_completed(host, dry_run=True)
            self.assertEqual(result["state"], "VALIDATED_EXAMPLE")
            self.assertFalse(result["fake_completed"])
            self.assertEqual(effects.effects, [])
            self.assertTrue(closure.execute_qualified_completed(host)["fake_completed"])
            self.assertEqual(len(effects.effects), 2)
            self.assertFalse((directory / "EXAMPLE.db").exists())

    def test_worker_records_constructor_and_expired_host_do_not_register_authority(self):
        with self.assertRaises(original.ClosureError):
            qualified.Host()
        for value in ({"role": "architect", "verdict": "APPROVE"}, object.__new__(qualified.Host)):
            with self.assertRaises(original.ClosureError):
                closure.execute_qualified_completed(value)
        case = self.compact()
        with self.registered(case) as (host, effects, directory):
            self.reviewed(case, host, directory)
        with self.assertRaises(original.ClosureError):
            closure.execute_qualified_completed(host)
        self.assertEqual(effects.effects, [])

    def test_current_task_or_contract_drift_refuses_before_any_effect(self):
        for target in ("task", "contract", "candidate", "review"):
            with self.subTest(target=target):
                case = self.compact()
                with self.registered(case) as (host, effects, directory):
                    self.reviewed(case, host, directory)
                    if target == "task":
                        effects.bead["id"] = "EXAMPLE-other-task"
                    elif target == "contract":
                        value = json.loads((directory / "contract.json").read_bytes())
                        value["initial"]["criteria"].clear()
                        self.write(directory, "contract.json", original._freeze(value))
                    elif target == "candidate":
                        (case.repo / "src/item.txt").write_bytes(b"EXAMPLE changed after review\n")
                    else:
                        (directory / "review.json").unlink()
                    with self.assertRaises((original.ClosureError, FileNotFoundError, AssertionError)):
                        closure.execute_qualified_completed(host)
                    self.assertEqual(effects.effects, [])

    def test_failed_results_and_open_blocker_cannot_issue_qualified_completion(self):
        for variant in ("failed", "refused", "blocker"):
            with self.subTest(variant=variant):
                case = self.compact(variant="passed" if variant == "blocker" else variant)
                with self.registered(case) as (host, effects, directory):
                    findings = [{"id": "EXAMPLE-blocker", "blocking": True, "state": "OPEN", "text": "EXAMPLE required outcome incomplete"}]
                    with self.assertRaises(original.ClosureError):
                        self.reviewed(case, host, directory, findings=findings if variant == "blocker" else ())
                    with self.assertRaises(original.ClosureError):
                        closure.execute_qualified_completed(host)
                    self.assertEqual(effects.effects, [])

    def test_detected_read_refusal_is_not_erased_by_recovery(self):
        case = self.compact()
        with self.registered(case) as (host, effects, directory):
            self.reviewed(case, host, directory)
            error = RuntimeError("EXAMPLE failed authoritative task read")
            with patch.object(effects, "_show", side_effect=error):
                with self.assertRaises(RuntimeError) as caught:
                    closure.execute_qualified_completed(host)
            self.assertIs(caught.exception, error)
            with self.assertRaises(RuntimeError) as recovered:
                closure.execute_qualified_completed(host)
            self.assertIs(recovered.exception, error)
            self.assertEqual(effects.effects, [])

    def test_live_adapter_refusal_family(self):
        rows = (
            LiveAdapterRow("tests.test_qualified_closure.QualifiedClosureTests.test_restored_live_adapter_is_refused_before_any_subprocess", False,
                           "live Beads effects are disabled", "EXAMPLE no live subprocess", True),
        )
        for row in rows:
            with self.subTest(original_id=row.original_id):
                # Each refusal owns its original repository and live custody
                # context. Repository cleanup remains actual outer cleanup.
                case = self.compact()
                with self.registered(case) as (host, effects, directory):
                    self.reviewed(case, host, directory)
                    adapter = partial(beads.run_bd) if row.wrapped else beads.run_bd
                    with patch.object(closure, "run_bd", adapter), \
                            patch.object(beads.subprocess, "run", side_effect=AssertionError(row.trap)) as live:
                        refusal = (self.assertRaisesRegex(original.ClosureError, row.message)
                                   if row.message else self.assertRaises(original.ClosureError))
                        with refusal:
                            closure.execute_qualified_completed(host)
                    live.assert_not_called()
                    if row.replay:
                        with self.assertRaises(original.ClosureError):
                            closure.execute_qualified_completed(host)
                    self.assertEqual(effects.effects, [])

    def test_live_adapter_restoration_between_check_and_call_never_invokes_live(self):
        for effect in ("comment", "close"):
            with self.subTest(effect=effect):
                case = self.compact()
                with self.registered(case) as (host, effects, directory):
                    self.reviewed(case, host, directory)
                    checked, restored = threading.Event(), threading.Event()
                    at_effect, changed = False, False
                    need, boundary = qualified._need, qualified._bd
                    def check(condition, reason):
                        nonlocal changed
                        result = need(condition, reason)
                        if at_effect and not changed and reason.startswith("live Beads effects are disabled"):
                            changed = True
                            checked.set()
                            if not restored.wait(10):
                                raise AssertionError("EXAMPLE adapter restoration timed out")
                        return result
                    def dispatch(state, args):
                        nonlocal at_effect
                        at_effect = args[0] == effect
                        try:
                            return boundary(state, args)
                        finally:
                            at_effect = False
                    def restore():
                        if checked.wait(10):
                            closure.run_bd = beads.run_bd
                            restored.set()
                    with patch.object(qualified, "_need", side_effect=check), \
                            patch.object(qualified, "_bd", side_effect=dispatch), \
                            patch.object(beads.subprocess, "run", side_effect=AssertionError("EXAMPLE no live invocation")) as live:
                        restorer = threading.Thread(target=restore)
                        restorer.start()
                        try:
                            with self.assertRaises((original.ClosureError, AssertionError)):
                                closure.execute_qualified_completed(host)
                        finally:
                            restorer.join(10)
                    self.assertTrue(changed)
                    self.assertFalse(restorer.is_alive())
                    live.assert_not_called()
                    self.assertEqual([item[0] for item in effects.effects], ["comment"] if effect == "comment" else ["comment", "close"])

    def test_task_drift_during_last_candidate_check_prevents_each_effect(self):
        for validation_number in (2, 3):
            with self.subTest(validation_number=validation_number):
                case = self.compact()
                with self.registered(case) as (host, effects, directory):
                    self.reviewed(case, host, directory)
                    validate, task, candidate = qualified._validate, qualified._task, original._candidate
                    count, read, edited = 0, False, False
                    def checking(*args):
                        nonlocal count, read
                        count += 1
                        read = False
                        return validate(*args)
                    def reading(*args):
                        nonlocal read
                        result = task(*args)
                        read = True
                        return result
                    def changing(*args):
                        nonlocal edited
                        result = candidate(*args)
                        if count == validation_number and read and not edited:
                            effects.bead["title"] = "EXAMPLE drift during final candidate check"
                            edited = True
                        return result
                    with patch.object(qualified, "_validate", side_effect=checking), \
                            patch.object(qualified, "_task", side_effect=reading), \
                            patch.object(original, "_candidate", side_effect=changing):
                        with self.assertRaises(original.ClosureError):
                            closure.execute_qualified_completed(host)
                    self.assertTrue(edited)
                    self.assertEqual([item[0] for item in effects.effects], [] if validation_number == 2 else ["comment"])
                    self.assertEqual(effects.bead["status"], "open")

    def test_native_prerequisite_ownership_spans_final_checks_and_both_effects(self):
        for resource in ("target", "state"):
            for validation_number in (2, 3):
                with self.subTest(resource=resource, validation_number=validation_number):
                    case = self.native()
                    root = getattr(case.host, resource)
                    with self.registered(case) as (host, effects, directory):
                        self.reviewed(case, host, directory, native=True)
                        validate, task, candidate = qualified._validate, qualified._task, original._candidate
                        count, read, attempted, edited, blocked = 0, False, False, False, False
                        errors = []
                        def checking(*args):
                            nonlocal count, read
                            count += 1
                            read = False
                            return validate(*args)
                        def reading(*args):
                            nonlocal read
                            result = task(*args)
                            read = True
                            return result
                        def editing(*args):
                            nonlocal attempted, edited, blocked
                            result = candidate(*args)
                            if count == validation_number and read and not attempted:
                                attempted = True
                                descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
                                try:
                                    try:
                                        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                                    except BlockingIOError:
                                        blocked = True
                                    else:
                                        if resource == "state":
                                            blob = root / "artifact" / case.report["artifact"]["files"][0]["blob"]
                                            blob.chmod(0o600)
                                            try:
                                                blob.write_bytes(b"EXAMPLE native artifact changed after validation\n")
                                            finally:
                                                blob.chmod(0o400)
                                        else:
                                            (root / "EXAMPLE-native-prerequisite-edit.txt").write_bytes(b"EXAMPLE edit after native validation\n")
                                        edited = True
                                finally:
                                    os.close(descriptor)
                            return result
                        with patch.object(qualified, "_validate", side_effect=checking), \
                                patch.object(qualified, "_task", side_effect=reading), \
                                patch.object(original, "_candidate", side_effect=editing):
                            try:
                                result = closure.execute_qualified_completed(host)
                            except BaseException as error:
                                errors.append(error)
                        self.assertTrue(attempted)
                        self.assertFalse(edited, "EXAMPLE native prerequisite edited under its own ownership lock; effects=" + str([entry[0] for entry in effects.effects]))
                        self.assertTrue(blocked)
                        self.assertEqual(errors, [])
                        self.assertTrue(result["fake_completed"])
                        self.assertEqual([entry[0] for entry in effects.effects], ["comment", "close"])
                    descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
                    try:
                        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    finally:
                        os.close(descriptor)

    def test_native_selection_cannot_change_between_ownership_and_production(self):
        case = self.native()
        helper = case.fixture.helper
        (case.host.worker / "result.txt").unlink()
        helper.target = helper.clone("EXAMPLE-second-native-target")
        second = helper.case(name="EXAMPLE-second-native-state")
        second_policy = original.freeze_native_policy(second[0], case.specification)
        second_report = helper.run_case(second)
        self.assertEqual(second_report["status"], "artifact-ready", second_report["error"])
        supplied = {"host": case.host, "report": case.report,
                    "expected_target": case.expected_target, "policy": case.policy}
        replacement = {"host": second[0], "report": second_report,
                       "expected_target": second_report["binding"]["target"], "policy": second_policy}
        acquired, changed = threading.Event(), threading.Event()
        hold = qualified._hold_native
        def holding(state, selected):
            result = hold(state, selected)
            acquired.set()
            if not changed.wait(10):
                raise AssertionError("EXAMPLE native selection change timed out")
            return result
        def switch():
            if acquired.wait(10):
                supplied.update(replacement)
                changed.set()
        with self.registered(case) as (host, effects, directory):
            with patch.object(qualified, "_hold_native", side_effect=holding):
                selector = threading.Thread(target=switch)
                selector.start()
                try:
                    observation = qualified.observe(host, native=supplied)
                finally:
                    selector.join(10)
            self.assertTrue(changed.is_set())
            self.assertFalse(selector.is_alive())
            self.assertIs(supplied["policy"], second_policy)
            self.assertIs(original._observed(observation).native.policy, case.policy)
            raw, expected = case.review(observation)
            self.write(directory, "review.json", raw)
            self.write(directory, "expectation.json", original._freeze({
                "record_type": "cwo-EXAMPLE-qualified-review-source", "version": 1,
                "context": host.review_context, "expected": expected}))
            qualified.bind(host)
            self.assertTrue(closure.execute_qualified_completed(host)["fake_completed"])
            self.assertEqual([entry[0] for entry in effects.effects], ["comment", "close"])

    def test_not_applicable_artifact_keeps_validator_only_positive(self):
        row = fixtures.criterion("EXAMPLE-na-artifact", "EXAMPLE no artifact required", "artifact")
        row.update(applicability="not-applicable", not_applicable_reason="EXAMPLE contract is validator-only")
        case = self.compact(extra=(row,))
        case.commands.pop(row["id"])
        control = case.observe()
        original._current(original._observed(control))
        with self.registered(case) as (host, effects, directory):
            observation = self.reviewed(case, host, directory)
            self.assertEqual(observation.production_mode, "validator-only")
            self.assertTrue(closure.execute_qualified_completed(host)["fake_completed"])
            self.assertEqual(len(effects.effects), 2)

    def test_final_review_cannot_replay_into_another_registration_database(self):
        case = self.compact()
        with self.registered(case) as (host, effects, directory):
            self.reviewed(case, host, directory)
            raw = (directory / "review.json").read_bytes()
            expected = (directory / "expectation.json").read_bytes()
            self.assertTrue(closure.execute_qualified_completed(host)["fake_completed"])
        with self.registered(case) as (other, other_effects, other_directory):
            qualified.observe(other)
            self.write(other_directory, "review.json", raw)
            self.write(other_directory, "expectation.json", expected)
            with self.assertRaises(original.ClosureError):
                qualified.bind(other)
            self.assertEqual(other_effects.effects, [])

    def test_cooperative_ownership_excludes_a_second_registration_and_cross_thread_use(self):
        case = self.compact()
        with self.registered(case) as (host, effects, directory):
            self.reviewed(case, host, directory)
            with self.assertRaises(BlockingIOError):
                with qualified.example_custody(str(directory)):
                    self.fail("EXAMPLE custody lock was bypassed")
            results = []
            def close():
                try:
                    results.append(closure.execute_qualified_completed(host))
                except original.ClosureError:
                    pass
            threads = [threading.Thread(target=close) for _ in range(2)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
            self.assertEqual(len(results), 1)
            self.assertTrue(results[0]["fake_completed"])
            self.assertEqual(len(effects.effects), 2)
            self.assertFalse(host.report["partial_persistence"])
            self.assertTrue(host.report["fake_completed"])
            self.assertFalse(host.report["completion_unconfirmed"])
            self.assertEqual(host.report["current_applicability"], "REFUSED")

    def test_custody_exit_waits_for_inflight_comment_and_close(self):
        for effect in ("comment", "close"):
            with self.subTest(effect=effect):
                case = self.compact()
                with tempfile.TemporaryDirectory(prefix="EXAMPLE-lifetime-") as temporary:
                    directory = Path(temporary)
                    effects = self.provision(case, directory)
                    with patch.object(closure, "run_bd", new=effects):
                        context = qualified.example_custody(str(directory))
                        host = context.__enter__()
                        self.reviewed(case, host, directory)
                        paused, release, retiring, retired = (threading.Event() for _ in range(4))
                        late, failures = [], []
                        boundary = qualified._bd
                        def pause(state, args):
                            if args[0] == effect:
                                paused.set()
                                if not release.wait(10):
                                    raise AssertionError("EXAMPLE effect release timed out")
                                late.append(retired.is_set())
                            return boundary(state, args)
                        def consume():
                            try:
                                closure.execute_qualified_completed(host)
                            except BaseException as error:
                                failures.append(error)
                        def retire():
                            retiring.set()
                            try:
                                context.__exit__(None, None, None)
                            finally:
                                retired.set()
                        with patch.object(qualified, "_bd", side_effect=pause):
                            worker = threading.Thread(target=consume)
                            worker.start()
                            self.assertTrue(paused.wait(10))
                            supervisor = threading.Thread(target=retire)
                            supervisor.start()
                            self.assertTrue(retiring.wait(10))
                            exited_early = retired.wait(0.05)
                            release.set()
                            worker.join(10)
                            supervisor.join(10)
                        self.assertFalse(worker.is_alive())
                        self.assertFalse(supervisor.is_alive())
                        self.assertEqual(late, [False])
                        self.assertFalse(exited_early)
                        self.assertEqual(failures, [])
                        self.assertEqual([item[0] for item in effects.effects], ["comment", "close"])
                        with self.assertRaises(original.ClosureError):
                            closure.execute_qualified_completed(host)

    def test_outer_exception_handler_retains_inert_partial_and_ambiguous_reports(self):
        for effect in ("_close", "_comment"):
            with self.subTest(effect=effect):
                case = self.compact()
                error = SystemExit("EXAMPLE outer failure") if effect == "_close" else KeyboardInterrupt("EXAMPLE outer interruption")
                with self.assertRaises(type(error)) as caught:
                    with self.registered(case) as (host, effects, directory):
                        self.reviewed(case, host, directory)
                        original_effect = getattr(effects, effect)
                        def fail(command):
                            if effect == "_comment":
                                original_effect(command)
                            raise error
                        with patch.object(effects, effect, side_effect=fail):
                            closure.execute_qualified_completed(host)
                self.assertIs(caught.exception, error)
                report = host.report
                self.assertFalse(report["registration_active"])
                self.assertEqual(report["current_applicability"], "EXPIRED")
                self.assertTrue(report["completion_unconfirmed"])
                self.assertFalse(report["persistence_known"])
                self.assertEqual(report["partial_persistence"], effect == "_close")
                self.assertEqual(report["comment_posted"], effect == "_close")
                self.assertFalse(report["closed"])
                with self.assertRaises(original.ClosureError):
                    closure.execute_qualified_completed(host)

    def test_comment_success_close_failure_retains_partial_and_exception_identity(self):
        case = self.compact()
        with self.registered(case) as (host, effects, directory):
            self.reviewed(case, host, directory)
            error = SystemExit("EXAMPLE close response failed")
            def fail(command):
                effects.effects.append(tuple(command))
                raise error
            with patch.object(effects, "_close", side_effect=fail):
                with self.assertRaises(SystemExit) as caught:
                    closure.execute_qualified_completed(host)
            self.assertIs(caught.exception, error)
            result = host.report
            self.assertEqual(result["state"], "PARTIAL_PERSISTENCE")
            self.assertTrue(result["comment_posted"])
            self.assertTrue(result["partial_persistence"])
            self.assertTrue(result["completion_unconfirmed"])
            self.assertFalse(result["fake_completed"])
            self.assertEqual(effects.bead["status"], "open")
            with self.assertRaises(SystemExit) as replay:
                closure.execute_qualified_completed(host)
            self.assertIs(replay.exception, error)
            self.assertEqual(len(effects.effects), 2)

    def test_interrupted_retirement_keeps_ownership_and_original_body_exception(self):
        for body_error in (None, SystemExit("EXAMPLE supervisor body failure")):
            with self.subTest(body_error=type(body_error).__name__):
                case = self.compact()
                with tempfile.TemporaryDirectory(prefix="EXAMPLE-interrupted-retirement-") as temporary:
                    directory = Path(temporary)
                    effects = self.provision(case, directory)
                    paused, release = threading.Event(), threading.Event()
                    late, failures = [], []
                    boundary = qualified._bd
                    def guarded(state, args):
                        if args[0] == "comment":
                            paused.set()
                            if not release.wait(10):
                                raise AssertionError("EXAMPLE interruption release timed out")
                            try:
                                os.fstat(state.descriptor)
                                late.append(False)
                            except OSError:
                                late.append(True)
                        return boundary(state, args)
                    def consume():
                        try:
                            closure.execute_qualified_completed(host)
                        except BaseException as error:
                            failures.append(error)
                    def interrupt():
                        time.sleep(0.05)
                        signal.pthread_kill(threading.main_thread().ident, signal.SIGINT)
                        time.sleep(0.15)
                        release.set()
                    with patch.object(closure, "run_bd", new=effects), patch.object(qualified, "_bd", side_effect=guarded):
                        try:
                            with self.assertRaises(KeyboardInterrupt if body_error is None else SystemExit) as caught:
                                with qualified.example_custody(str(directory)) as host:
                                    self.reviewed(case, host, directory)
                                    worker = threading.Thread(target=consume)
                                    worker.start()
                                    self.assertTrue(paused.wait(10))
                                    interrupter = threading.Thread(target=interrupt)
                                    interrupter.start()
                                    if body_error is not None:
                                        raise body_error
                        finally:
                            release.set()
                            worker.join(10)
                            interrupter.join(10)
                    if body_error is not None:
                        self.assertIs(caught.exception, body_error)
                    self.assertEqual(late, [False])
                    self.assertEqual(failures, [])
                    self.assertTrue(host.report["retirement_interrupted"])
                    self.assertFalse(host.report["registration_active"])

    def test_native_positive_uses_original_producer_binder_and_close_adapter_once(self):
        case = self.native()
        with self.registered(case) as (host, effects, directory), \
                patch.object(original, "observe_native_mixed", wraps=original.observe_native_mixed) as produce, \
                patch.object(combined, "consume", wraps=combined.consume) as consume:
            observation = self.reviewed(case, host, directory, native=True)
            self.assertEqual(observation.combined["snapshot"]["criterion_inventory"], case.initial["criteria"])
            result = closure.execute_qualified_completed(host)
            self.assertTrue(result["fake_completed"])
            self.assertFalse(result["completion_unconfirmed"])
            self.assertEqual([effect[0] for effect in effects.effects], ["comment", "close"])
            self.assertEqual(effects.effects[0][2], case.bead["id"])
            self.assertEqual(effects.effects[1][-1], case.bead["id"])
            self.assertEqual(effects.bead["status"], "closed")
            produce.assert_called_once()
            self.assertGreaterEqual(consume.call_count, 3)
            for name in original.AUTHORITY_FIELDS:
                self.assertIs(result[name], False)
            with self.assertRaises(original.ClosureError):
                closure.execute_qualified_completed(host)
            self.assertEqual(len(effects.effects), 2)
            self.assertFalse(host.report["partial_persistence"])
            self.assertTrue(host.report["fake_completed"])
            self.assertFalse(host.report["completion_unconfirmed"])
            self.assertEqual(host.report["current_applicability"], "REFUSED")
        self.assertFalse(qualified.PUBLIC_ACTIVATION)


    def test_delegating_live_adapter_wrapper_is_refused_before_subprocess(self):
        case = self.compact()
        with self.registered(case) as (host, effects, directory):
            self.reviewed(case, host, directory)
            with patch.object(closure, "run_bd", partial(beads.run_bd)), \
                    patch.object(beads.subprocess, "run", side_effect=AssertionError("EXAMPLE no live wrapper subprocess")) as live:
                with self.assertRaises(original.ClosureError):
                    closure.execute_qualified_completed(host)
            live.assert_not_called()
            self.assertEqual(effects.effects, [])


    def test_relevant_edit_after_comment_prevents_close_and_retains_partial(self):
        case = self.compact()
        with self.registered(case) as (host, effects, directory):
            self.reviewed(case, host, directory)
            comment = effects._comment
            def drift(command):
                result = comment(command)
                (case.repo / "src/item.txt").write_bytes(b"EXAMPLE post-comment drift\n")
                return result
            with patch.object(effects, "_comment", side_effect=drift):
                with self.assertRaises(original.ClosureError):
                    closure.execute_qualified_completed(host)
            self.assertEqual([effect[0] for effect in effects.effects], ["comment"])
            self.assertEqual(host.report["state"], "PARTIAL_PERSISTENCE")
            self.assertTrue(host.report["partial_persistence"])
            self.assertFalse(host.report["closed"])
            self.assertEqual(effects.bead["status"], "open")

    def test_interrupt_during_comment_remains_ambiguous_without_retry(self):
        case = self.compact()
        with self.registered(case) as (host, effects, directory):
            self.reviewed(case, host, directory)
            error = KeyboardInterrupt("EXAMPLE interrupted after fake comment write")
            comment = effects._comment
            def interrupt(command):
                comment(command)
                raise error
            with patch.object(effects, "_comment", side_effect=interrupt):
                with self.assertRaises(KeyboardInterrupt) as caught:
                    closure.execute_qualified_completed(host)
            self.assertIs(caught.exception, error)
            self.assertTrue(host.report["comment_attempted"])
            self.assertFalse(host.report["comment_posted"])
            self.assertTrue(host.report["completion_unconfirmed"])
            self.assertFalse(host.report["persistence_known"])
            self.assertEqual([effect[0] for effect in effects.effects], ["comment"])
            with self.assertRaises(KeyboardInterrupt):
                closure.execute_qualified_completed(host)
            self.assertEqual(len(effects.effects), 1)

if __name__ == "__main__":
    unittest.main()
