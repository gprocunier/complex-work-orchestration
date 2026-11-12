"""Finite original producer-to-publication join with cooperative fake children."""
from __future__ import annotations

import builtins
import copy
import json
import signal
import subprocess
import sys
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "scripts"), str(ROOT / "tests")]

import qualified_n1_host as lifecycle  # noqa: E402
import test_linux_owned_children as children  # noqa: E402
import test_offline_effect_profile as fixtures  # noqa: E402
from test_offline_host_crash_matrix import cleanup_helper  # noqa: E402


class FiniteN1LifecycleTests(unittest.TestCase):
    def setUp(self):
        self.effects = fixtures.OfflineEffectProfileTests(methodName="runTest")
        self.addCleanup(cleanup_helper, self, self.effects)
        self.effects.setUp()
        self.original_popen = subprocess.Popen
        self.processes = children.ControllerTests(methodName="runTest")
        self.addCleanup(cleanup_helper, self, self.processes)

    def case(self, followups=(), *, writer=None):
        fixture = self.effects.case(followups)
        case = fixture.case
        self.processes.setUp()
        def capture_only(command, *args, **kwargs):
            host = lifecycle.admitted.native
            fixed = list(host.workspace_capture.INERT_GIT_CONFIG)
            tails = (["ls-files", "--stage", "-v", "--sparse", "--full-name", "-z"],
                     ["ls-files", "-z", "--others", "--ignored", "--exclude-standard", "--directory", "--full-name"])
            self.assertEqual(command[:2], [host.workspace_capture.trusted_git().path, "-C"])
            self.assertEqual(command[3:3 + len(fixed)], fixed)
            self.assertIn(command[3 + len(fixed):], tails)
            return self.original_popen(command, *args, **kwargs)
        subprocess.Popen.side_effect = capture_only
        table, controller = self.processes.make()
        executable = str(Path(sys.executable).resolve())
        controller._executable = controller._engine._executable = executable
        popen = table._popen

        def produce(argv, selected, workspace):
            self.assertEqual(tuple(argv), (executable, "-I", "-S", "-c", lifecycle.CHILD_PROGRAM))
            self.assertEqual((selected, workspace), (executable, str(case.host.worker)))
            self.assertEqual(case.server.ledger_intent["state"], "invocation-intent")
            self.assertEqual(case.server.intent_observed["status"], "reconciliation-required")
            child = popen(argv, selected, workspace)
            child.process.executable, child.process.cwd = selected, workspace
            # Fake process effect at the original controller's actual _popen seam.
            if writer is None:
                with (Path(workspace) / "result.txt").open("xb") as stream:
                    stream.write(b"EXAMPLE_RESULT: useful offline fixture output\n")
            else:
                writer(argv, workspace, child)
            return child

        table._popen = produce
        root = self.effects.repositories.root
        fake_state, fake_target = root / "EXAMPLE-promotion-state", root / "EXAMPLE-promotion-target"
        fake_state.mkdir(mode=0o700)
        fake_target.mkdir(mode=0o700)
        session = lifecycle.FiniteN1Lifecycle(
            case.receipt, case.route, case.node_id, ledger=case.ledger, host=case.host,
            adapter=case.adapter, controller=controller, contract=case.control,
            operation_id="EXAMPLE-finite-operation", configuration_pins=case.pins,
            fake_state=fake_state, fake_target=fake_target, initial_files={"unrelated.txt": b"EXAMPLE keep\n"})
        return fixture, table, session

    def program_writer(self, *, delayed=False):
        """Execute only the fixed child program with fake paths/time, not artifact code."""
        errors = []
        def writer(argv, workspace, _child):
            opened, release = threading.Event(), threading.Event()
            class Output:
                def __init__(self, stream):
                    self.stream = stream
                def write(self, data):
                    opened.set()
                    if delayed and not release.wait(1):
                        raise RuntimeError("EXAMPLE delayed child was not released")
                    return self.stream.write(data)
                def close(self):
                    return self.stream.close()
            class ChildPath:
                def __init__(self, name):
                    self.path = Path(workspace) / name
                def __fspath__(self):
                    return str(self.path)
                def open(self, mode):
                    return Output(self.path.open(mode))
                def unlink(self):
                    return self.path.unlink()
            def importing(name, *args, **kwargs):
                if name == "pathlib":
                    return SimpleNamespace(Path=ChildPath)
                if name == "time":
                    return SimpleNamespace(sleep=lambda _seconds: None)
                return builtins.__import__(name, *args, **kwargs)
            def produce():
                try:
                    exec(argv[-1], {"__builtins__": {**vars(builtins), "__import__": importing}})
                except BaseException as failure:
                    errors.append(failure)
            thread = threading.Thread(target=produce)
            self.addCleanup(thread.join, 1)
            thread.start()
            if delayed:
                self.assertTrue(opened.wait(1))
                timer = threading.Timer(0.05, release.set)
                self.addCleanup(timer.join, 1)
                timer.start()
            else:
                thread.join(1)
        return writer, errors

    def test_preexisting_correct_output_cannot_be_acknowledged_as_child_work(self):
        writer, _errors = self.program_writer()
        fixture, table, session = self.case(writer=writer)
        (fixture.case.host.worker / "result.txt").write_bytes(lifecycle.EXPECTED)
        with self.assertRaises(ValueError):
            session.run_offline()
        self.assertEqual(table.spawn_calls, [])
        self.assertIsNone(session.execution)
        self.assertFalse((fixture.case.host.state / "artifact").exists())
        self.assertFalse((session.target._target / "current.json").exists())

    def test_fixed_child_program_waits_for_delayed_write_and_close(self):
        writer, errors = self.program_writer(delayed=True)
        _fixture, table, session = self.case(writer=writer)
        failure = None
        try:
            result = session.run_offline()
        except ValueError as error:
            failure = error
        self.assertIsNone(failure, "EXAMPLE incomplete child bytes must wait for bounded readiness")
        self.assertTrue(result["fake_publication"]["fake_completion"])
        self.assertEqual(errors, [])
        self.assertEqual(len(table.spawn_calls), 1)

    def test_exceptional_registered_spawn_retains_issued_receipt_for_one_cleanup(self):
        fixture, table, session = self.case()
        primary = KeyboardInterrupt("EXAMPLE registered spawn interruption")
        original = self.processes.waitid_api.side_effect
        calls = []
        def wait(*args):
            if not calls:
                calls.append(True)
                raise primary
            return original(*args)
        self.processes.waitid_api.side_effect = wait
        with self.assertRaises(KeyboardInterrupt) as caught:
            session.run_offline()
        self.assertIs(caught.exception, primary)
        self.assertIs(session.spawn_report, primary.ownership_report)
        self.assertTrue(session.spawn_report["receipt_available"])
        self.assertEqual(table.children[0].process.signals, [signal.SIGTERM])
        self.assertTrue(session.termination_report["child_reaped"])
        self.assertFalse((fixture.case.host.state / "artifact").exists())

    def test_interrupted_termination_is_not_retried_and_retains_original_observations(self):
        fixture, table, session = self.case()
        primary = KeyboardInterrupt("EXAMPLE termination interruption")
        def fail():
            raise primary
        table.hooks["before_SIGTERM"] = fail
        calls = []
        previous, previous_threads = sys.getprofile(), threading.getprofile()
        def observe(frame, event, _value):
            if event == "call" and frame.f_code is lifecycle._TERMINATE.__code__:
                calls.append(True)
        try:
            sys.setprofile(observe)
            threading.setprofile(observe)
            with self.assertRaises(ValueError):
                session.run_offline()
        finally:
            sys.setprofile(previous)
            threading.setprofile(previous_threads)
        self.assertEqual(len(calls), 1)
        self.assertIs(session.termination_report, primary.ownership_report)
        self.assertEqual(table.children[0].process.signals, [])
        self.assertFalse((fixture.case.host.state / "artifact").exists())

    def test_pending_archive_termination_is_not_entered_again_by_caller_cleanup(self):
        fixture, table, session = self.case()
        entered, release = threading.Event(), threading.Event()
        def block():
            entered.set()
            if not release.wait(5):
                raise RuntimeError("EXAMPLE archive termination was not released")
        table.hooks["before_SIGTERM"] = block
        calls = []
        previous, previous_threads = sys.getprofile(), threading.getprofile()
        def observe(frame, event, _value):
            if event == "call" and frame.f_code is lifecycle._TERMINATE.__code__:
                calls.append(True)
        try:
            sys.setprofile(observe)
            threading.setprofile(observe)
            with self.assertRaises(ValueError) as caught:
                session.run_offline()
            self.assertTrue(entered.is_set())
            self.assertEqual(len(calls), 1)
            self.assertTrue(any("in-progress" in note for note in caught.exception.__notes__))
        finally:
            release.set()
            archive = fixture.case.adapter._staged_archive
            if archive is not None:
                self.assertTrue(archive._done.wait(1))
            sys.setprofile(previous)
            threading.setprofile(previous_threads)
        self.assertEqual(table.children[0].process.signals, [signal.SIGTERM])
        self.assertFalse((fixture.case.host.state / "artifact").exists())

    def test_useful_owned_lifetime_then_independent_validation_and_actual_fake_publication(self):
        fixture, table, session = self.case((*fixtures.effects.PROFILE["denied"],
                                           "EXAMPLE_ORDINARY_FAILURE", "EXAMPLE_EXPLICIT_ESCALATION"))
        case = fixture.case
        collect = lifecycle.admitted.native.OfflineN1Host._collect
        captures = []

        previous = sys.getprofile()
        def observe(frame, event, _value):
            if event == "call" and frame.f_code is collect.__code__:
                self.assertFalse(table.children[0].process.alive)
                self.assertTrue(session.termination_report["child_reaped"])
                self.assertEqual(session.termination_report["signals"], ["SIGTERM"])
                captures.append(True)
        try:
            sys.setprofile(observe)
            result = session.run_offline()
        finally:
            sys.setprofile(previous)
        self.assertTrue(captures)
        self.assertTrue(result["offline_completed"] and result["offline_validation_complete"])
        self.assertTrue(result["fake_publication"]["fake_completion"])
        self.assertEqual(session.target.snapshot()["files"], {
            "result.txt": b"EXAMPLE_RESULT: useful offline fixture output\n", "unrelated.txt": b"EXAMPLE keep\n"})
        self.assertEqual(session.target.snapshot()["revision"], 1)
        self.assertEqual(len(table.spawn_calls), 1)
        self.assertEqual(case.server.sends, 1)
        self.assertEqual(table.children[0].process.signals, [signal.SIGTERM])
        self.assertEqual(result["execution"]["attempt"]["charge"], json.loads(case.receipt.amounts_bytes))
        self.assertIsNone(result["execution"]["attempt"]["observed_usage"])
        self.assertEqual([session.runner.observations()["effect_calls"][x] for x in fixtures.effects.PROFILE["denied"]], [0]*4)
        for name in lifecycle._FALSE:
            self.assertIs(result[name], False)
        replay = session.publish_offline()
        self.assertEqual(replay["fake_publication"]["new_invocation"]["pointer_replacements"], 0)
        with self.assertRaisesRegex(ValueError, "redispatch"):
            session.run_offline()
        self.assertEqual((len(table.spawn_calls), case.server.sends), (1, 1))

    def test_lost_ownership_prevents_capture_validation_publication_and_release(self):
        fixture, table, session = self.case(("EXAMPLE_WRITE",))
        current = fixture.case.server.current_binding
        def replace_birth():
            if table.children:
                table.children[0].process.start_ticks = 9999
            return current()
        fixture.case.server.current_binding = replace_birth
        with self.assertRaises(ValueError):
            session.run_offline()
        self.assertFalse((fixture.case.host.state / "artifact").exists())
        self.assertIsNone(session.token)
        self.assertFalse((session.target._target / "current.json").exists())
        attempt = fixture.harness.assert_charged(fixture.case)
        self.assertEqual(attempt["outcome"], "unknown")
        self.assertEqual(len(table.spawn_calls), 1)
        self.assertEqual(table.children[0].process.signals, [])

    def test_execution_success_does_not_accept_output_changed_before_capture(self):
        fixture, table, session = self.case(("EXAMPLE_WRITE",))
        current = fixture.case.server.current_binding
        def change():
            if table.children:
                (fixture.case.host.worker / "result.txt").write_bytes(b"EXAMPLE rejected bytes\n")
            return current()
        fixture.case.server.current_binding = change
        with self.assertRaises(lifecycle.validation.ValidationError):
            session.run_offline()
        self.assertTrue(session.execution["offline_completed"])
        self.assertIsNone(session.token)
        self.assertFalse((session.target._target / "current.json").exists())
        self.assertTrue(session.termination_report["child_reaped"])
        fixture.harness.assert_charged(fixture.case)

    def test_fixed_policy_and_registered_lifetime_boundary_cannot_be_substituted(self):
        fixture, table, session = self.case()
        original = session.policy
        session.policy = lifecycle.validation.freeze_policy(original.report)
        with self.assertRaisesRegex(ValueError, "policy changed"):
            session.run_offline()
        self.assertEqual((len(table.spawn_calls), fixture.case.server.sends), (0, 0))
        self.assertFalse((fixture.case.host.state / "operation.json").exists())
        self.assertFalse((session.target._target / "current.json").exists())

    def test_identity_refusal_with_cleanup_reap_cannot_authorize_capture(self):
        fixture, table, session = self.case(("EXAMPLE_WRITE",))
        current = fixture.case.server.current_binding
        def change_identity():
            if table.children:
                process = table.children[0].process
                process.start_ticks = 9999
                table.hooks["waitid:observe"] = lambda: setattr(process, "alive", False)
            return current()
        fixture.case.server.current_binding = change_identity
        failure = None
        try:
            session.run_offline()
        except ValueError as error:
            failure = error
        self.assertEqual(session.termination_report["outcome"], "identity-mismatch")
        self.assertTrue(session.termination_report["child_exit_confirmed"])
        self.assertTrue(session.termination_report["child_reaped"])
        self.assertIsNotNone(failure, "EXAMPLE identity refusal cannot become successful capture through cleanup")
        self.assertIsNone(session.execution)
        self.assertIsNone(session.token)
        self.assertFalse((fixture.case.host.state / "artifact").exists())
        self.assertFalse((session.target._target / "current.json").exists())
        self.assertEqual(fixture.harness.assert_charged(fixture.case)["outcome"], "unknown")
        self.assertEqual(table.children[0].process.signals, [])

    def test_genuine_known_natural_exit_remains_useful_without_a_signal(self):
        fixture, table, session = self.case(("EXAMPLE_WRITE",))
        current = fixture.case.server.current_binding
        def finish():
            if table.children:
                table.children[0].process.alive = False
            return current()
        fixture.case.server.current_binding = finish
        result = session.run_offline()
        self.assertTrue(result["fake_publication"]["fake_completion"])
        self.assertEqual(session.termination_report["outcome"], "already-exited")
        self.assertTrue(session.termination_report["child_reaped"])
        self.assertEqual(table.children[0].process.signals, [])

    def test_publication_recovery_never_redispatches_or_releases_unknown_usage(self):
        fixture, table, session = self.case()
        record = session.target._new_record
        def fail(path, name, data, counts):
            if name == "receipt.json":
                raise OSError("EXAMPLE receipt unavailable")
            return record(path, name, data, counts)
        with patch.object(session.target, "_new_record", fail):
            with self.assertRaises(lifecycle.promotion.FakePromotionError) as caught:
                session.run_offline()
        saved = copy.deepcopy(caught.exception.report)
        self.assertEqual(saved["known_publication"]["saved_pointer_publications"], 1)
        self.assertFalse(saved["fake_completion"])
        result = session.publish_offline()
        self.assertTrue(result["fake_publication"]["fake_completion"])
        self.assertEqual(result["fake_publication"]["new_invocation"]["pointer_replacements"], 0)
        self.assertEqual((len(table.spawn_calls), fixture.case.server.sends), (1, 1))
        fixture.harness.assert_charged(fixture.case)
        self.assertFalse(saved["fake_completion"])

    def test_target_race_after_validation_refuses_actual_publication(self):
        fixture, table, session = self.case()
        promote = session.target.promote
        def drift(*args, **kwargs):
            (fixture.case.host.target / "EXAMPLE-race.txt").write_bytes(b"EXAMPLE target drift\n")
            return promote(*args, **kwargs)
        with patch.object(session.target, "promote", drift):
            with self.assertRaises(lifecycle.promotion.FakePromotionError):
                session.run_offline()
        self.assertTrue(session.execution["offline_completed"])
        self.assertIsNotNone(session.token)
        self.assertEqual(session.target.snapshot()["revision"], 0)
        self.assertEqual((len(table.spawn_calls), fixture.case.server.sends), (1, 1))


if __name__ == "__main__":
    unittest.main()
