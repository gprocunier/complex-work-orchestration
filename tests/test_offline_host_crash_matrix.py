"""Original offline admission, host, ledger and owned-child consumers.

EXAMPLE failures are injected at observed original boundaries. No model, service,
real child, retry, accepting receipt or recovery authority is manufactured here.
"""
from __future__ import annotations

import copy
import hashlib
import json
import sys
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "tests"))

import offline_artifact_validation as validation  # noqa: E402
import test_offline_admitted_n1 as fixtures  # noqa: E402
import test_linux_owned_children as children  # noqa: E402

client = fixtures.client
native = client.native
ledger_api = fixtures.ledger_api
Crash = fixtures.host_fixtures.FixtureCrash


def cleanup_helper(test, helper):
    """Report composed-helper cleanup errors through the running unittest outcome."""
    previous = helper._outcome
    helper._outcome = test._outcome
    try:
        if helper._outcome is None:
            raise AssertionError("EXAMPLE helper cleanup requires a running test outcome")
        helper.doCleanups()
    finally:
        helper._outcome = previous


class OfflineHostCrashMatrixTests(unittest.TestCase):
    def setUp(self):
        # Compose the original helpers, without inheriting their test suites.
        self.helper = fixtures.OfflineAdmittedN1Tests(methodName="runTest")
        self.addCleanup(cleanup_helper, self, self.helper)
        self.helper.setUp()

    def case(self, name="EXAMPLE", mode="complete"):
        return self.helper.case(name=name, mode=mode)

    def run_case(self, case, **changes):
        return self.helper.run_case(case, **changes)

    def restart(self, case):
        """Construct original readers only; never resume, repair or replace state."""
        host = native.OfflineN1Host(case.host.state, case.host.target, case.host.worker)
        ledger = ledger_api.InvocationLedger(case.ledger.root, clock=case.clock, owner_probe=case.owners)
        return host, ledger

    def attempt(self, case):
        return self.helper.assert_charged(case)

    def conservative(self, case, *, state, outcome=None):
        attempt = self.attempt(case)
        self.assertEqual((attempt["state"], attempt["outcome"]), (state, outcome))
        summary = case.ledger.summary(case.receipt.budget_id)
        self.assertEqual(summary["charged"], json.loads(case.receipt.amounts_bytes))
        self.assertEqual(summary["usage_unknown"], 1)
        self.assertIsNone(attempt["observed_usage"])
        return attempt

    def replay_refused(self, case, expected, *, report=None):
        host, ledger = self.restart(case)
        before = self.helper.disk(case)
        sends = case.server.sends
        if report is not None:
            self.assertEqual(host.status("FAKE_OPERATION"), report)
        with self.assertRaises(ValueError):
            self.run_case(case, host=host, ledger=ledger)
        self.assertEqual(self.helper.disk(case), before)
        self.assertEqual(ledger.attempt(expected["reservation_id"]), expected)
        self.assertEqual(case.server.sends, sends)
        self.assertEqual(ledger.recover(), [])
        self.assertEqual(ledger.summary(case.receipt.budget_id), case.ledger.summary(case.receipt.budget_id))

    def no_artifact(self, case, report):
        self.assertEqual(report["status"], "reconciliation-required")
        self.assertIsNone(report["artifact"])
        self.assertIsNone(report["result_sha256"])
        for flag in ("production_ready", "effect_authority", "accepted_for_use"):
            self.assertIs(report[flag], False)
        expected = report["binding"]["target"]
        self.assertFalse(case.host.verify_artifact(report, expected)["valid"])
        policy = validation.freeze_policy({"version": 1, "outputs": [{
            "path": "result.txt", "validator": "bytes",
            "size": len(fixtures.host_fixtures.OUTPUT),
            "sha256": hashlib.sha256(fixtures.host_fixtures.OUTPUT).hexdigest(),
        }]})
        with self.assertRaises(validation.ValidationError):
            validation.validate_artifact(case.host, report, expected, policy)

    def test_positive_missing_usage_retains_exact_completed_identity_after_restart(self):
        case = self.case()
        with fixtures.host_fixtures.repository_write_boundaries((case.host.target,)) as writes:
            result = self.run_case(case)
        self.assertEqual(writes, [])
        self.assertTrue(result["offline_completed"])
        self.assertEqual(case.server.sends, 1)
        self.assertEqual(case.server.ledger_intent["state"], "invocation-intent")
        self.assertEqual(case.server.intent_observed["status"], "reconciliation-required")
        attempt = self.conservative(case, state="terminal", outcome="completed")
        report = result["native_report"]
        self.assertEqual(report["receipt"]["submission_id"], case.adapter.turn_id)
        self.assertEqual(report["receipt"]["terminal_state"], "completed")
        self.assertEqual((case.host.worker / "result.txt").read_bytes(), fixtures.host_fixtures.OUTPUT)
        self.assertTrue(result["artifact_verification"]["valid"])
        for flag in client.FALSE_FIELDS:
            self.assertIs(result[flag], False)
        self.assertFalse(result["actual_quota_known"])
        self.assertFalse(result["actual_provider_billing_known"])
        self.replay_refused(case, attempt, report=report)

    def test_crash_after_reservation_before_intent_releases_only_known_unused_allowance(self):
        case = self.case()
        failure = Crash("EXAMPLE crash after durable reservation, before intent")
        original_sync = case.ledger._fsync
        seen = []

        def sync(descriptor):
            original_sync(descriptor)
            raw = self.helper.disk(case)
            if raw is not None and not seen:
                attempts = list(json.loads(raw)["attempts"].values())
                if len(attempts) == 1 and attempts[0]["state"] == "reserved":
                    seen.append(copy.deepcopy(attempts[0]))
                    raise failure

        case.ledger._fsync = sync
        with self.assertRaises(Crash) as caught:
            self.run_case(case)
        self.assertIs(caught.exception, failure)
        self.assertEqual(len(seen), 1)
        self.assertEqual(case.server.sends, 0)
        self.assertEqual(case.adapter.callback_latencies, {})
        self.assertFalse((case.host.state / "operation.json").exists())
        case.owners.crash()
        _host, ledger = self.restart(case)
        changes = ledger.recover()
        self.assertEqual([(value["from"], value["to"], value["outcome"]) for value in changes],
                         [("reserved", "terminal", "released")])
        attempt = ledger.attempt(seen[0]["reservation_id"])
        self.assertEqual(attempt["attempt_id"], seen[0]["attempt_id"])
        self.assertEqual(attempt["owner"], seen[0]["owner"])
        self.assertFalse(any(attempt["charge"].values()))
        self.assertIsNone(attempt["observed_usage"])
        self.assertEqual(ledger.summary(case.receipt.budget_id)["usage_unknown"], 0)
        self.assertEqual(ledger.recover(), [])
        self.assertEqual(case.server.sends, 0)

    def test_crashes_after_ledger_and_host_intent_never_resume_or_release(self):
        for stage in ("ledger-intent", "host-intent"):
            with self.subTest(stage=stage):
                case = self.case(name="EXAMPLE-" + stage)
                failure = Crash("EXAMPLE " + stage + " crash")

                def observer(event):
                    if event["event"] == "invocation-intent":
                        raise failure

                def crash():
                    raise failure

                options = {}
                if stage == "ledger-intent":
                    options["observer"] = observer
                    case.server.expected_observers = [observer.__qualname__]
                else:
                    case.server.on_send = crash
                with self.assertRaises(Crash) as caught:
                    self.run_case(case, **options)
                self.assertIs(caught.exception, failure)
                attempt = self.conservative(case, state="reconciliation-required")
                self.assertEqual(case.server.sends, int(stage == "host-intent"))
                report = None
                if stage == "host-intent":
                    report = case.host.status("FAKE_OPERATION")
                    self.assertIsNone(report["receipt"])
                    self.no_artifact(case, report)
                else:
                    self.assertFalse((case.host.state / "operation.json").exists())
                self.replay_refused(case, attempt, report=report)

    def test_server_loss_before_and_after_output_preserves_unknowns(self):
        for stage in ("before-output", "after-output"):
            with self.subTest(stage=stage):
                case = self.case(name="EXAMPLE-" + stage, mode="failure" if stage == "before-output" else "unclosed")
                with self.assertRaises(client.OfflineAdmittedN1Error) as caught:
                    self.run_case(case)
                report = case.host.status("FAKE_OPERATION")
                self.assertEqual(caught.exception.native_report, report)
                self.no_artifact(case, report)
                self.assertEqual((case.host.worker / "result.txt").exists(), stage == "after-output")
                attempt = self.conservative(case, state="terminal", outcome="unknown")
                self.replay_refused(case, attempt, report=report)

    def test_interruption_after_known_completion_preserves_both_terminal_identities(self):
        case = self.case()
        failure = Crash("EXAMPLE caller lost after completed terminal observation")

        def observer(event):
            if event["event"] == "terminal":
                raise failure

        case.server.expected_observers = [observer.__qualname__]
        with self.assertRaises(Crash) as caught:
            self.run_case(case, observer=observer)
        self.assertIs(caught.exception, failure)
        attempt = self.conservative(case, state="terminal", outcome="completed")
        report = case.host.status("FAKE_OPERATION")
        self.assertEqual(failure.native_report, report)
        self.assertEqual(failure.ledger_attempts, [attempt])
        self.assertEqual(report["status"], "artifact-ready")
        self.assertEqual(report["receipt"]["terminal_state"], "completed")
        self.assertEqual(report["receipt"]["submission_id"], case.adapter.turn_id)
        self.replay_refused(case, attempt, report=report)

    def test_blocked_callback_keeps_intent_charged_and_reconstructed_client_busy(self):
        case = self.case()
        entered, release = threading.Event(), threading.Event()
        failure = Crash("EXAMPLE callback ended with server loss")

        def block():
            entered.set()
            if not release.wait(10):
                raise AssertionError("EXAMPLE deadlock guard expired")
            raise failure

        case.server.on_send = block
        with ThreadPoolExecutor(max_workers=1) as pool:
            running = pool.submit(self.run_case, case)
            try:
                self.assertTrue(entered.wait(10))
                case.clock.now += 300
                owner = case.owners.me
                case.owners.unknown.add((owner["pid"], owner["start_ticks"]))
                attempt = self.conservative(case, state="invocation-intent")
                host, ledger = self.restart(case)
                self.assertEqual(ledger.recover(), [])
                before = self.helper.disk(case)
                with self.assertRaisesRegex(ValueError, "claim is busy"):
                    self.run_case(case, host=host, ledger=ledger)
                with self.assertRaisesRegex(ValueError, "claim is busy"):
                    host.status("FAKE_OPERATION")
                self.assertEqual(self.helper.disk(case), before)
                self.assertEqual(ledger.attempt(attempt["reservation_id"]), attempt)
                self.assertEqual(case.server.sends, 1)
                self.assertFalse((case.host.state / "artifact").exists())
                self.assertFalse(running.done())
            finally:
                release.set()
            with self.assertRaises(Crash) as caught:
                running.result(timeout=10)
        self.assertIs(caught.exception, failure)
        self.conservative(case, state="reconciliation-required")
        self.no_artifact(case, case.host.status("FAKE_OPERATION"))

    def test_reused_owner_pid_and_later_clock_never_reset_an_unresolved_budget(self):
        case = self.case(mode="crash")
        with self.assertRaises(Crash):
            self.run_case(case)
        attempt = self.conservative(case, state="reconciliation-required")
        original_owner = copy.deepcopy(case.owners.me)
        case.owners.gone.add((original_owner["pid"], original_owner["start_ticks"]))
        case.owners.me = {**original_owner, "start_ticks": original_owner["start_ticks"] + 1}
        case.clock.now += 10000
        host, ledger = self.restart(case)
        self.assertEqual(ledger.recover(), [])
        self.assertEqual(ledger.attempt(attempt["reservation_id"]), attempt)
        before = ledger.summary(case.receipt.budget_id)
        ledger.open_budget(case.receipt.budget_id, json.loads(case.receipt.limits_bytes),
                           scope_sha256=case.receipt.scope_sha256)
        self.assertEqual(ledger.summary(case.receipt.budget_id), before)
        with self.assertRaises(ValueError):
            ledger.release(attempt["reservation_id"])
        with self.assertRaises(ValueError):
            ledger.begin_invocation(attempt["reservation_id"], case.receipt.request_bytes)
        self.assertEqual(host.status("FAKE_OPERATION")["receipt"], None)
        self.assertEqual(case.server.sends, 1)

    def test_abrupt_loss_recovers_raw_intent_without_recreating_the_original_owner(self):
        for stage in ("ledger-intent", "host-intent"):
            with self.subTest(stage=stage):
                case = self.case(name="EXAMPLE-raw-" + stage)
                primary = Crash("EXAMPLE abrupt original owner loss")
                lost = []
                original_sync = case.ledger._fsync

                def lose_owner():
                    original = copy.deepcopy(case.owners.me)
                    lost.append(original)
                    case.owners.gone.add((original["pid"], original["start_ticks"]))
                    case.owners.me = {**original, "start_ticks": original["start_ticks"] + 1}
                    raise primary

                def sync(descriptor):
                    # The original writer cannot settle the attempt after losing
                    # its persistence boundary. A fresh original reader recovers it.
                    if lost:
                        raise OSError("EXAMPLE original writer unavailable after crash")
                    original_sync(descriptor)
                    raw = self.helper.disk(case)
                    if stage == "ledger-intent" and raw is not None:
                        attempts = json.loads(raw)["attempts"].values()
                        if any(value["state"] == "invocation-intent" for value in attempts):
                            lose_owner()

                case.ledger._fsync = sync
                if stage == "host-intent":
                    case.server.on_send = lose_owner
                with self.assertRaises(Crash) as caught:
                    self.run_case(case)
                self.assertIs(caught.exception, primary)
                self.assertEqual(len(lost), 1)
                intent = self.conservative(case, state="invocation-intent")
                self.assertEqual(intent["owner"], lost[0])
                self.assertTrue(any("original writer unavailable" in note for note in primary.__notes__))
                self.assertEqual(case.server.sends, int(stage == "host-intent"))
                host, ledger = self.restart(case)
                changes = ledger.recover()
                self.assertEqual([(value["from"], value["to"]) for value in changes],
                                 [("invocation-intent", "reconciliation-required")])
                recovered = ledger.attempt(intent["reservation_id"])
                for field in ("attempt_id", "reservation_id", "owner", "charge", "observed_usage"):
                    self.assertEqual(recovered[field], intent[field])
                report = host.status("FAKE_OPERATION") if stage == "host-intent" else None
                if report is not None:
                    self.no_artifact(case, report)
                else:
                    self.assertFalse((host.state / "operation.json").exists())
                self.replay_refused(case, recovered, report=report)

    def test_target_worker_and_native_method_drift_cannot_complete_or_validate(self):
        for drift in ("target", "worker", "native-method"):
            with self.subTest(drift=drift):
                case = self.case(name="EXAMPLE-" + drift)

                def change():
                    if drift == "native-method":
                        case.adapter.final_summary = lambda: {"archived": True}
                    else:
                        root = case.host.target if drift == "target" else case.host.worker
                        (root / ("changed.txt" if drift == "target" else "seed.txt")).write_text("EXAMPLE drift\n")

                case.server.on_send = change
                with self.assertRaises(ValueError):
                    self.run_case(case)
                report = case.host.status("FAKE_OPERATION")
                self.no_artifact(case, report)
                attempt = self.conservative(case, state="terminal", outcome="unknown")
                self.replay_refused(case, attempt, report=report)

    def test_host_crash_retains_child_partial_facts_diagnostics_and_rejects_reused_handle(self):
        for operation in ("signal", "wait"):
            with self.subTest(operation=operation):
                # Build repositories before installing guards against real child creation.
                case = self.case(name="EXAMPLE-child-" + operation)
                helper = children.ControllerTests(methodName="runTest")
                produced = []
                try:
                    primary = KeyboardInterrupt("EXAMPLE original child interruption")
                    secondary = RuntimeError("EXAMPLE secondary handle release failure")

                    def fail_child():
                        helper.setUp()
                        child = helper.pending_case(operation, "before-effect", integrated=True)
                        child.primary, child.table.close_error = primary, secondary
                        produced.append(child)
                        with child.capability_patch, child.signal_patch, child.poll_patch, child.release_patch:
                            child.action()

                    case.server.on_send = fail_child
                    with self.assertRaises(KeyboardInterrupt) as caught:
                        self.run_case(case)
                    self.assertIs(caught.exception, primary)
                    self.assertEqual(len(produced), 1)
                    child = produced[0]
                    helper.assert_pending_release(child, operation)
                    report = primary.ownership_report
                    self.assertEqual(report["signals"], ["SIGTERM"] if operation == "wait" else [])
                    self.assertEqual(report["child_exit_confirmed"], operation == "wait")
                    self.assertEqual(report["child_reaped"], operation == "wait")
                    self.assertFalse(report["receipt_available"])
                    self.assertTrue(any(str(secondary) in text for text in report["cleanup_errors"]))
                    self.assertTrue(any(str(secondary) in text for text in primary.__notes__))
                    fresh_table, fresh_controller = helper.make()
                    self.assertEqual(fresh_controller.terminate(child.receipt, 0, allow_kill=True)["signals"], [])
                    self.assertEqual(fresh_table.spawn_calls, [])
                    self.assertEqual(child.replacement.signals, [])
                    helper.tearDown()
                finally:
                    cleanup_helper(self, helper)
                attempt = self.conservative(case, state="reconciliation-required")
                host_report = case.host.status("FAKE_OPERATION")
                self.no_artifact(case, host_report)
                self.replay_refused(case, attempt, report=host_report)

    def test_server_loss_with_reused_child_pid_never_targets_the_replacement(self):
        case = self.case()
        helper = children.ControllerTests(methodName="runTest")
        observations = []
        failure = Crash("EXAMPLE original server child was reaped elsewhere")

        def reuse_child():
            helper.setUp()
            table, controller, receipt = helper.registered()
            original = table.procs[children.TARGET]
            original.alive = False
            original.status_consumed = True
            table.reuse(same_tick=True)
            replacement = table.procs[children.TARGET]
            with self.assertRaises(ChildProcessError):
                table.reap(table.births[0])
            report = controller.terminate(receipt, 0, allow_kill=True)
            controller.close()
            observations.append((original, replacement, report, table))
            raise failure

        case.server.on_send = reuse_child
        try:
            with self.assertRaises(Crash) as caught:
                self.run_case(case)
            self.assertIs(caught.exception, failure)
            self.assertEqual(len(observations), 1)
            original, replacement, report, table = observations[0]
            self.assertIsNot(original, replacement)
            self.assertEqual(original.pid, replacement.pid)
            self.assertEqual(report["outcome"], "ownership-lost")
            self.assertEqual(report["signals"], [])
            self.assertTrue(replacement.alive)
            self.assertEqual(replacement.signals, [])
            self.assertFalse(getattr(replacement, "status_consumed", False))
            self.assertEqual(table.children[0].waits, [])
            helper.tearDown()
        finally:
            cleanup_helper(self, helper)
        attempt = self.conservative(case, state="reconciliation-required")
        report = case.host.status("FAKE_OPERATION")
        self.no_artifact(case, report)
        self.replay_refused(case, attempt, report=report)


class HelperCleanupOutcomeTests(unittest.TestCase):
    def test_composed_helper_failures_reach_the_running_result_and_keep_primary_errors(self):
        for stage in ("repository", "child"):
            for with_primary in (False, True):
                with self.subTest(stage=stage, primary=with_primary):
                    secondary = RuntimeError("EXAMPLE composed helper cleanup failure")
                    primary = RuntimeError("EXAMPLE original test failure")
                    observed = []

                    def fail():
                        raise secondary

                    class Result(unittest.TestResult):
                        def addError(self, test, error):
                            observed.append(error[1])
                            super().addError(test, error)

                    class Probe(OfflineHostCrashMatrixTests):
                        def runTest(self):
                            if stage == "repository":
                                self.helper.addCleanup(fail)
                                if with_primary:
                                    raise primary
                                return
                            helper = children.ControllerTests(methodName="runTest")
                            helper.setUp()
                            try:
                                helper.addCleanup(fail)
                                if with_primary:
                                    raise primary
                            finally:
                                cleanup_helper(self, helper)

                    result = Result()
                    Probe(methodName="runTest").run(result)
                    self.assertEqual(result.testsRun, 1)
                    self.assertFalse(result.wasSuccessful())
                    self.assertCountEqual(observed, [secondary, primary] if with_primary else [secondary])
                    self.assertEqual(len(result.errors), len(observed))


if __name__ == "__main__":
    unittest.main()
