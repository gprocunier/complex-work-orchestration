"""Original finite fixture preparation, archive and negative lifecycle controls."""
from contextlib import ExitStack
import queue
import threading
import time
import unittest
from unittest.mock import patch

from tests import test_registered_finite_tool_wiring as wiring
from tests import test_registered_fixture_lifecycle as lifecycle
from tests import test_registered_startup_publication as startup
import offline_n1_host as host

family = wiring.family


class FixturePreparationTests(unittest.TestCase):
    def run_fixture(self, kind, name, releases):
        owner, workers = kind(name), []
        original_start = threading.Thread.start

        def release_all():
            for release in releases:
                release()

        def drain_all():
            release_all()
            for worker in workers:
                if worker.ident is not None:
                    family.finish_worker(self, worker)

        def start(worker):
            workers.append(worker)
            owner.addCleanup(release_all)
            return original_start(worker)

        owner.addCleanup(drain_all)
        result = unittest.TestResult()
        try:
            with patch.object(threading.Thread, 'start', start), patch.object(
                    family, 'RpcProcess', wiring.DynamicRpcProcess):
                owner.run(result)
        finally:
            drain_all()
        self.assertFalse(any(worker.is_alive() for worker in workers))
        return result

    def stage_schedule(self, operation, kind, name, expected):
        cases, arrivals, facts, faults = [], [], [], []
        release, prepared, held = (threading.Event() for _ in range(3))
        selected = {}
        original_case = family.FactoryTests.case
        original_startup = wiring.RegisteredFiniteToolWiringTests.wait_for_startup
        original_wait = family.wait_for_release
        original_terminal = family.runtime._CoherentServerRequests._terminal
        original_fault = family.runtime._RegisteredServer._publish_transport_failure

        def case(owner, **changes):
            value = original_case(owner, **changes)
            cases.append(value)
            return value

        def startup_wait(owner, event, worker, outcome):
            known = (getattr(cases[-1], 'command_prepared', None),
                     getattr(cases[-1], 'poll_prepared', None))
            if event not in known:
                prepared.set()
                release.set()
            return original_startup(owner, event, worker, outcome)

        def wait(owner, event, timeout):
            if threading.current_thread().name == 'cwo-registered-tools':
                selected['release'] = event
            return original_wait(owner, event, timeout)

        def terminal(registry, *args):
            value = original_terminal(registry, *args)
            if 'release' in selected:
                facts.append((not selected['release'].is_set(), registry.lock._is_owned(),
                              registry.server.finite_input.output_bytes_seen))
            return value

        def fault(server, failure):
            if server.transport_failure is None:
                faults.append((type(failure), str(failure)))
            release.set()
            return original_fault(server, failure)

        def resume():
            release.set()
            if 'release' in selected:
                selected['release'].set()
            for value in cases:
                for key in ('command_release', 'poll_release'):
                    event = getattr(value, key, None)
                    if event is not None:
                        event.set()

        target = (family.runtime._Containment if operation == 'launch'
                  else wiring.finite_tools.RegisteredFiniteToolCalls)
        original_operation = getattr(target, operation)

        def operation_call(subject, *args, **kwargs):
            if operation != 'launch' or subject.role == 'tool':
                held.set()
                self.assertTrue(release.wait(12), 'original operation was not released')
                arrivals.append(prepared.is_set())
            return original_operation(subject, *args, **kwargs)

        with ExitStack() as patches:
            for obj, key, value in (
                    (family.FactoryTests, 'case', case),
                    (wiring.RegisteredFiniteToolWiringTests, 'wait_for_startup', startup_wait),
                    (family, 'wait_for_release', wait),
                    (family.runtime._CoherentServerRequests, '_terminal', terminal),
                    (family.runtime._RegisteredServer, '_publish_transport_failure', fault),
                    (target, operation, operation_call)):
                patches.enter_context(patch.object(obj, key, value))
            result = self.run_fixture(kind, name, [resume])
        self.assertTrue(result.wasSuccessful(), (result.failures, result.errors))
        self.assertTrue(held.is_set())
        self.assertTrue(prepared.is_set(), 'owner did not observe original preparation')
        self.assertEqual(arrivals, [True], 'selected operation did not follow owner preparation')
        self.assertTrue(facts)
        self.assertTrue(all(holding and locked for holding, locked, _bytes in facts))
        self.assertEqual(faults, [expected])
        if operation == '_poll':
            self.assertEqual([count for _holding, _locked, count in facts], [30])

    def test_owned_launch_preparation_precedes_selected_arrival_window(self):
        self.stage_schedule('launch', wiring.RegisteredFiniteToolWiringTests,
            'test_terminal_during_owned_tool_launch_contains_child',
            (wiring.gate_module.FiniteInputError, 'The finite reply item or turn ended.'))

    def test_poll_preparation_preserves_original_terminal_and_projection_refusals(self):
        rows = (
            (wiring.RegisteredFiniteToolWiringTests,
             'test_terminal_during_poll_wait_revokes_before_reply',
             (wiring.gate_module.FiniteInputError,
              'The poll deadline expired during pipe observation.')),
            (wiring.RegisteredFiniteToolWiringTests,
             'test_exceptional_projection_during_poll_pipe_wait',
             (family.runtime.protocol.PreparationError, 'registered-terminal-before-bound-turn')),
            (startup.StartupPublicationTests,
             'test_exceptional_projection_reaches_poll_without_condition_scheduler',
             (family.runtime.protocol.PreparationError, 'registered-terminal-before-bound-turn')),
        )
        for kind, name, expected in rows:
            with self.subTest(selector=name):
                self.stage_schedule('_poll', kind, name, expected)

    def test_identity_fixture_settles_original_archive_before_spending_close_steps(self):
        archive_type = wiring.live.StagedThreadArchive
        seen, release = threading.Event(), threading.Event()
        request_ids, exhausted, settled, pending = {}, [], [], []
        original_receive = family.RpcProcess.receive
        original_observe = family.runtime._RegisteredServer._observe_response
        original_start = archive_type.start
        original_require = archive_type.require_complete
        original_ready = archive_type.completion_ready
        original_interrupt = host.NativeControlTurn.request_interrupt

        def receive(process, message):
            if message.get('method') == 'thread/archive':
                request_ids[id(process.case.factory.server)] = message['id']
            return original_receive(process, message)

        def observe(server, message):
            if message.get('id') == request_ids.get(id(server)):
                seen.set()
                self.assertTrue(release.wait(12), 'original archive acceptance was not released')
            return original_observe(server, message)

        def start(archive):
            value = original_start(archive)
            self.assertTrue(seen.wait(5), 'original archive response was not read')
            return value

        def require(archive, *, timeout_seconds=wiring.live.STAGED_ARCHIVE_CLOSE_SETTLE_SECONDS):
            if timeout_seconds == 8:
                settled.append(timeout_seconds)
                release.set()
            return original_require(archive, timeout_seconds=timeout_seconds)

        def ready(archive):
            value = original_ready(archive)
            if not value:
                pending.append(True)
            return value

        def interrupt(turn, *args, **kwargs):
            exhausted.append(turn._phase)
            release.set()
            return original_interrupt(turn, *args, **kwargs)

        with ExitStack() as patches:
            for obj, key, value in (
                    (family.RpcProcess, 'receive', receive),
                    (family.runtime._RegisteredServer, '_observe_response', observe),
                    (archive_type, 'start', start), (archive_type, 'require_complete', require),
                    (archive_type, 'completion_ready', ready),
                    (host.NativeControlTurn, 'request_interrupt', interrupt)):
                patches.enter_context(patch.object(obj, key, value))
            result = self.run_fixture(startup.StartupPublicationTests,
                'test_session_precedes_turn_response_and_completion_preserves_identity', [release.set])
        self.assertTrue(result.wasSuccessful(), (result.failures, result.errors))
        self.assertTrue(seen.is_set())
        self.assertEqual(settled, [8])
        self.assertEqual(pending, [])
        self.assertEqual(exhausted, [])

    def test_catalog_refusal_waits_on_real_host_progress_before_original_error_reply(self):
        cases, faults, acknowledged = [], [], []
        waits = queue.Queue()
        original_case = family.FactoryTests.case
        original_wait = threading.Condition.wait
        original_commit = family.runtime._RegisteredServer._commit_tool_reply
        original_fault = family.runtime._RegisteredServer._publish_transport_failure

        def case(owner, **changes):
            value = original_case(owner, **changes)
            cases.append(value)
            return value

        def wait(condition, timeout=None):
            server = getattr(getattr(cases[-1], 'factory', None), 'server', None) if cases else None
            active = [True]
            if server is not None and condition is server.finite_input.lifecycle.condition:
                waits.put((condition, active))
            try:
                return original_wait(condition, timeout)
            finally:
                active[0] = False

        def commit(server, message, response, deadline, *, refusal=False):
            if refusal and message['id'] == 'EXAMPLE-request-EXAMPLE-command-call':
                end = time.monotonic() + 12
                while time.monotonic() < end:
                    entry = waits.get(timeout=max(.001, end - time.monotonic()))
                    if entry is None:
                        break
                    condition, active = entry
                    self.assertTrue(condition.acquire(timeout=3))
                    try:
                        if active[0] and condition._waiters:
                            acknowledged.append(True)
                            break
                    finally:
                        condition.release()
            return original_commit(server, message, response, deadline, refusal=refusal)

        def fault(server, failure):
            if server.transport_failure is None:
                faults.append((type(failure), str(failure)))
            waits.put(None)
            return original_fault(server, failure)

        with ExitStack() as patches:
            for obj, key, value in (
                    (family.FactoryTests, 'case', case), (threading.Condition, 'wait', wait),
                    (family.runtime._RegisteredServer, '_commit_tool_reply', commit),
                    (family.runtime._RegisteredServer, '_publish_transport_failure', fault)):
                patches.enter_context(patch.object(obj, key, value))
            result = self.run_fixture(startup.StartupPublicationTests,
                'test_refusal_assertions_wait_for_original_input_consumer', [lambda: waits.put(None)])
        self.assertTrue(result.wasSuccessful(), (result.failures, result.errors))
        self.assertEqual(acknowledged, [True])
        self.assertEqual(faults, [(wiring.finite_tools.FiniteToolError,
                                  'Captured fake-server catalog changed after registration.')])

    def lifecycle_schedule(self, name):
        cases, faults, acknowledged = [], [], []
        waits = queue.Queue()
        original_case = family.FactoryTests.case
        original_wait = threading.Condition.wait
        original_launch = family.runtime._Containment.launch
        original_fault = family.runtime._RegisteredServer._publish_transport_failure

        def case(owner, **changes):
            while not waits.empty():
                waits.get_nowait()
            value = original_case(owner, **changes)
            cases.append(value)
            return value

        def wait(condition, timeout=None):
            server = getattr(getattr(cases[-1], 'factory', None), 'server', None) if cases else None
            active = [True]
            if server is not None and condition is server.finite_input.lifecycle.condition:
                waits.put((condition, active))
            try:
                return original_wait(condition, timeout)
            finally:
                active[0] = False

        def launch(lifetime, *args, **kwargs):
            if lifetime.role == 'tool':
                end = time.monotonic() + 12
                while time.monotonic() < end:
                    entry = waits.get(timeout=max(.001, end - time.monotonic()))
                    if entry is None:
                        break
                    condition, active = entry
                    self.assertTrue(condition.acquire(timeout=3))
                    try:
                        if active[0] and condition._waiters:
                            acknowledged.append(True)
                            break
                    finally:
                        condition.release()
            return original_launch(lifetime, *args, **kwargs)

        def fault(server, failure):
            if server.transport_failure is None:
                faults.append((type(failure), str(failure)))
            waits.put(None)
            return original_fault(server, failure)

        def release():
            waits.put(None)
            for value in cases:
                value.poll_release.set()

        with ExitStack() as patches:
            for obj, key, value in (
                    (family.FactoryTests, 'case', case), (threading.Condition, 'wait', wait),
                    (family.runtime._Containment, 'launch', launch),
                    (family.runtime._RegisteredServer, '_publish_transport_failure', fault)):
                patches.enter_context(patch.object(obj, key, value))
            result = self.run_fixture(lifecycle.FixtureLifecycleTests, name, [release])
        self.assertTrue(result.wasSuccessful(), (result.failures, result.errors))
        self.assertEqual(len(acknowledged), len(cases))
        self.assertEqual(faults, [(wiring.finite_tools.FiniteToolError,
            'Stale, repeated or mismatched tool call.')] * len(cases))

    def test_held_poll_close_and_cancel_keep_original_lifecycle_refusal(self):
        self.lifecycle_schedule('test_held_poll_cannot_emit_after_original_child_containment')

    def test_delayed_poll_publication_keeps_original_close_refusal(self):
        self.lifecycle_schedule('test_poll_publication_rechecks_child_after_original_containment')
