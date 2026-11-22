"""Finite fixture publication at the original wire and telemetry boundaries."""
from __future__ import annotations

import json
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from tests import test_registered_n1_factory as family
from tests import test_registered_finite_tool_wiring as wiring
from tests.test_finite_fixture_progress_acknowledgment import original_poll_ticket_clock


def _note_original_poll_refusal(factory, failure):
    """Keep the first recorded poll refusal alongside the worker exception."""
    add_note = family.runtime.admission.ledger_api.add_failure_note
    try:
        directory = factory.records / 'transport-observations'
        for path in sorted(directory.glob('observation-*.json'))[:256]:
            with path.open('rb') as stream:
                row = json.loads(stream.read(16384))
            if row['stage'] == 'finite-tool-refusal' and row['observation']['call'] == 'EXAMPLE-poll-call':
                observed = row['observation']
                add_note(failure, 'Original finite poll refusal: '
                         + str(observed['reason'])[:100] + ': ' + str(observed['message'])[:512])
                break
    except Exception:
        add_note(failure, 'Original finite poll refusal observation unavailable.')


class StartupPublicationTests(unittest.TestCase):
    def setUp(self):
        self.helper = wiring.RegisteredFiniteToolWiringTests('runTest')
        self.helper.setUp()
        self.addCleanup(family.cleanup_helper, self, self.helper)

    def test_session_precedes_turn_response_and_completion_preserves_identity(self):
        case = self.helper.fixture.case(archive_schedule='settled',
            finite_tool_mode='captured-host-tools', no_fake_scheduler=True)
        case.poll_prepared, case.poll_release = threading.Event(), threading.Event()
        original_request = case.receipt.request_bytes
        factory = self.helper.fixture.factory(case)
        result, published = [], []
        acknowledged = threading.Event()
        original_put = family.Lines.put

        def put(stream, frame, **kwargs):
            if frame.get('result') == {'turn': {'id': case.scenario.turn_id}}:
                path = case.scenario.path
                published.append((path.stat(), path.read_bytes()) if path.exists() else None)
                acknowledged.set()
            return original_put(stream, frame, **kwargs)

        def run():
            try:
                result.append(factory.run())
            except BaseException as failure:
                _note_original_poll_refusal(factory, failure)
                result.append(failure)

        with (
            original_poll_ticket_clock(lambda: getattr(factory.server, 'finite_tools', None)),
            self.helper._positive_finite_completion(case),
            patch.object(family, 'RpcProcess', wiring.DynamicRpcProcess),
            patch.object(family.Lines, 'put', put),
        ):
            worker = threading.Thread(target=run, daemon=True)
            self.addCleanup(family.finish_worker, self, worker, case.poll_release)
            worker.start()
            try:
                family.wait_for_startup(self, acknowledged, worker, result)
                self.assertEqual(len(published), 1)
                self.assertIsNotNone(published[0], 'trusted session must precede turn/start acknowledgment')
                identity, prefix = published[0]
                records = [json.loads(line) for line in prefix.splitlines()]
                context = next(row['payload'] for row in records if row['type'] == 'turn_context')
                self.assertEqual((context['model'], context['effort']), (case.spec['model'], case.spec['effort']))
                self.assertEqual(context['turn_id'], case.scenario.turn_id)
                binding = case.scenario.intent_observed['binding']
                self.assertEqual(binding['task'], factory.model_task_bytes().decode())
                self.assertEqual(case.receipt.request_bytes, original_request)
                self.assertEqual(binding['adapter_boundary']['planned_child'],
                                 json.loads(case.receipt.selected_node_bytes))
                self.assertEqual(binding['adapter_boundary']['adapter']['registered_task'],
                                 factory.model_task_binding())
                family.wait_for_startup(self, case.poll_prepared, worker, result)
                path = case.scenario.path
                self.assertEqual((path.stat().st_dev, path.stat().st_ino, path.read_bytes()),
                                 (identity.st_dev, identity.st_ino, prefix))
                self.assertTrue(worker.is_alive())
                self.assertEqual(self.helper.fixture.attempt(case)['state'], 'invocation-intent')
            finally:
                case.poll_release.set()
                worker.join(12)
            self.assertFalse(worker.is_alive())
            self.assertEqual(len(result), 1)
            if isinstance(result[0], BaseException):
                raise result[0]
            self.assertIsInstance(result[0], dict)
            self.assertEqual(result[0]['attempt']['outcome'], 'completed')
            self.assertEqual(case.poll_observation, {'stdout': 'EXAMPLE finite poll output\n', 'running': True})
            archived = case.scenario.archive / path.name
            self.assertEqual((archived.stat().st_dev, archived.stat().st_ino),
                             (identity.st_dev, identity.st_ino))
            self.assertTrue(archived.read_bytes().startswith(prefix))

    def test_explicit_absent_telemetry_still_refuses_before_poll(self):
        case = self.helper.fixture.case(finite_tool_mode='captured-host-tools', no_fake_scheduler=True,
                                       materialize_on_turn_start=False)
        case.command_prepared, case.command_release = threading.Event(), threading.Event()
        case.poll_prepared, case.poll_release = threading.Event(), threading.Event()
        factory = self.helper.fixture.factory(case)
        result, producers = [], []
        original_start = threading.Thread.start

        def start(worker):
            producers.append(worker)
            return original_start(worker)

        def run():
            try:
                result.append(factory.run())
            except BaseException as failure:
                result.append(failure)

        with patch.object(family, 'RpcProcess', wiring.DynamicRpcProcess), \
                patch.object(threading.Thread, 'start', start):
            worker = threading.Thread(target=run, daemon=True)
            worker.start()
            try:
                # Keep the original command/reply/completion producer held until
                # the observer has refused the deliberately absent session.
                self.assertFalse(case.scenario.path.exists())
                with self.assertRaisesRegex(family.runtime.native.OfflineHostError,
                        'post-submission-materialization-deadline-exceeded') as rejected:
                    family.wait_for_startup(self, case.poll_prepared, worker, result)
            finally:
                case.command_release.set()
                case.poll_release.set()
                worker.join(12)
                for producer in producers:
                    if producer is not worker and producer.ident is not None:
                        producer.join(2)
                self.assertFalse(any(producer.is_alive() for producer in producers),
                                 'original producer survived fixture cleanup')
        self.assertEqual(len(result), 1)
        self.assertIs(result[0], rejected.exception)
        primary = factory.adapter._first_action_failure
        self.assertIsInstance(primary, family.runtime.AppServerError)
        self.assertEqual(str(primary), 'post-submission-materialization-deadline-exceeded')
        self.assertIsNone(primary.__cause__)
        transport_failure = factory.server.transport_failure
        with self.assertRaises(family.runtime.AppServerError) as summary:
            factory.adapter.final_summary()
        self.assertIs(summary.exception, primary)
        self.assertIsNone(summary.exception.__cause__)
        self.assertIs(factory.server.transport_failure, transport_failure)
        self.assertFalse(case.poll_prepared.is_set())
        self.assertFalse(case.scenario.path.exists())
        self.assertIsNone(factory.token)
        attempt = self.helper.fixture.attempt(case)
        self.assertEqual(attempt['outcome'], 'unknown')
        self.assertEqual(attempt['charge'], attempt['amount'])

    def test_exceptional_projection_reaches_poll_without_condition_scheduler(self):
        original_case = self.helper.fixture.case

        def case(**changes):
            return original_case(no_fake_scheduler=True, **changes)

        with patch.object(self.helper.fixture, 'case', case):
            self.helper.test_exceptional_projection_during_poll_pipe_wait()

    def test_refusal_assertions_wait_for_original_input_consumer(self):
        entered, release, draining = (threading.Event() for _ in range(3))
        original_receive = wiring.DynamicRpcProcess.receive
        original_drain = family.Input.require_healthy
        result = []

        def receive(process, message):
            if message.get('id') == 'EXAMPLE-request-EXAMPLE-command-call' and 'error' in message:
                entered.set()
                self.assertTrue(release.wait(5))
            return original_receive(process, message)

        def drain(stream):
            if entered.is_set():
                draining.set()
            return original_drain(stream)

        def run():
            try:
                self.helper.test_capture_changed_after_command_output_refuses_before_reply()
                result.append(True)
            except BaseException as failure:
                result.append(failure)

        with patch.object(wiring.DynamicRpcProcess, 'receive', receive), patch.object(
                family.Input, 'require_healthy', drain):
            worker = threading.Thread(target=run, daemon=True)
            self.addCleanup(family.finish_worker, self, worker, release)
            worker.start()
            try:
                family.wait_for_startup(self, entered, worker, result)
                self.assertEqual(self.helper.fixture.spawned[0].replies, [])
                family.wait_for_startup(self, draining, worker, result)
            finally:
                release.set()
                family.finish_worker(self, worker, release)
            self.assertEqual(result, [True])

    def test_expired_command_release_cannot_publish_or_hide_as_refusal(self):
        self.spawned = []
        failures, sent, timeouts = [], [], []

        def expired(timeout):
            timeouts.append(timeout)
            return False

        owner = SimpleNamespace(fail=self.fail, spawned=self.spawned,
                                addCleanup=lambda *args: failures.append(args))
        case = SimpleNamespace(test=owner, scenario=object(), command_prepared=threading.Event(),
                               command_release=SimpleNamespace(wait=expired), spec={'command': 'EXAMPLE-command'})
        process = wiring.DynamicRpcProcess(SimpleNamespace(pid=991, alive=True), case)
        with patch.object(process, '_send_tool', lambda *_args: sent.append(True)), \
                self.assertRaisesRegex(AssertionError, 'release expired'):
            process.approve()
        self.assertEqual(timeouts, [5])
        self.assertEqual(sent, [])
        failures = [args for args in failures if args[0] == owner.fail]
        self.assertEqual(len(failures), 1)
        callback, message = failures[0]
        with self.assertRaisesRegex(AssertionError, 'release expired'):
            callback(message)


if __name__ == '__main__':
    unittest.main()
