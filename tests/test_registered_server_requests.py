"""Original registered caller/lifecycle regressions; EXAMPLE OS effects only."""
from __future__ import annotations

import os
import sys
import threading
import time
import unittest
from unittest.mock import patch

from tests import test_registered_n1_factory as family

runtime = family.runtime


def until(predicate, timeout=2):
    deadline = time.monotonic() + timeout
    while not predicate():
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.002)
    return True


class PipeLines:
    """Real bounded kernel stdout pipe; empty raw input means actual EOF."""
    def __init__(self):
        read, write = os.pipe()
        self.reader = os.fdopen(read, 'r', encoding='utf-8')
        self.writer = os.fdopen(write, 'w', encoding='utf-8', buffering=1)
        self.lines = self

    def put(self, value):
        if value == '':
            self.writer.close()
        else:
            data = value if type(value) is str else family.json.dumps(value) + '\n'
            self.writer.write(data)
            self.writer.flush()

    def readline(self, size=-1):
        return self.reader.readline(size)

    def close(self):
        self.writer.close()
        self.reader.close()


class RegisteredRequestsTests(unittest.TestCase):
    def setUp(self):
        self.fixture = family.FactoryTests(methodName='runTest')
        self.fixture.setUp()
        self.addCleanup(family.cleanup_helper, self, self.fixture)
        self._drivers = {}

    def pipe_case(self, **changes):
        fixture = self.fixture
        case = fixture.case(**changes)
        def attach():
            stream = PipeLines()
            fixture.spawned[0].stdout = stream
            self.addCleanup(stream.close)
        case.on_startup = attach
        return case

    def running(self, case):
        factory = self.fixture.factory(case)
        done, results = threading.Event(), []
        def run():
            try:
                results.append(factory.run())
            except BaseException as error:
                results.append(error)
            finally:
                done.set()
        thread = threading.Thread(target=run, name='EXAMPLE-original-control-driver', daemon=True)
        self._drivers[done] = thread
        thread.start()
        self.addCleanup(family.finish_worker, self, thread)
        return factory, done, results

    def wait_for_startup(self, event, done, results):
        return family.wait_for_startup(self, event, self._drivers[done], results)

    def test_blocked_decision_cannot_hold_terminal_or_eof_intake(self):
        entered, release = threading.Event(), threading.Event()
        original = runtime._RegisteredServer._decision
        def blocked(server, method, params):
            entered.set()
            release.wait(15)
            return original(server, method, params)
        with patch.object(runtime._RegisteredServer, '_decision', blocked):
            case = self.pipe_case()
            factory, done, results = self.running(case)
            try:
                self.assertTrue(self.wait_for_startup(entered, done, results), 'EXAMPLE decision was not reached')
                process = self.fixture.spawned[0]
                process.stdout.put({'method': 'turn/completed', 'params': {
                    'threadId': case.scenario.thread_id,
                    'turn': {'id': case.scenario.turn_id, 'status': 'interrupted'}}})
                process.stdout.lines.put('')
                self.assertTrue(until(lambda: factory.server.transport_failure is not None, .7),
                                'blocked decision prevented original terminal/EOF reader progress')
                self.assertTrue(done.wait(5), 'independent owned lifecycle did not contain the invocation')
            finally:
                release.set()
                done.wait(12)
            self.assertIsNone(factory.token)
            self.assertFalse(any(x.get('result') == {'decision': 'accept'} for x in process.replies))
            self.assertEqual(len(self.fixture.spawned), 1)
            self.assertIsInstance(results[0], BaseException)

    def blocked_final_callout(self, stage):
        entered, release = threading.Event(), threading.Event()
        original_write = runtime.native._write_new
        original_sync = runtime.native._sync
        written = threading.Event()
        def write(path, data, mode=0o600):
            approval = (path.parent.name == 'transport-observations' and
                        family.json.loads(data).get('stage') == 'approval')
            if approval and stage == 'record':
                entered.set()
                release.wait(15)
            result = original_write(path, data, mode)
            if approval:
                written.set()
            return result
        def sync(path):
            result = original_sync(path)
            if (path.name == 'transport-observations' and written.is_set()
                    and stage == 'authority'
                    and threading.current_thread().name == 'cwo-registered-decision'):
                entered.set()
                release.wait(15)
            return result
        with patch.object(runtime.native, '_write_new', write), patch.object(runtime.native, '_sync', sync):
            case = self.pipe_case()
            factory, done, results = self.running(case)
            try:
                self.assertTrue(self.wait_for_startup(entered, done, results), 'EXAMPLE final callout not reached')
                process = self.fixture.spawned[0]
                process.stdout.put({'method': 'turn/completed', 'params': {
                    'threadId': case.scenario.thread_id,
                    'turn': {'id': case.scenario.turn_id, 'status': 'interrupted'}}})
                self.assertTrue(until(lambda: any(x.get('result') == {'decision': 'cancel'}
                                                 for x in process.replies)))
                self.assertTrue(done.wait(5), 'terminal failed to contain blocked final callout')
            finally:
                release.set()
                done.wait(12)
            self.assertTrue(until(lambda: not factory.server.requests.threads[0].is_alive()))
            self.assertFalse(any(x.get('result') == {'decision': 'accept'} for x in process.replies))
            self.assertIsNone(factory.token)
            self.assertEqual(len(self.fixture.spawned), 1)
            lifecycle = factory.server.finite_input.lifecycle
            self.assertFalse(any(kind == 'reply-grant'
                                 for kind, _binding in lifecycle.authority_commits))
            self.assertTrue(lifecycle.authority_revocations)
            self.assertIsInstance(results[0], BaseException)

    def test_terminal_invalidates_a_blocked_record_callout(self):
        self.blocked_final_callout('record')

    def test_terminal_invalidates_after_final_authority_callout(self):
        self.blocked_final_callout('authority')

    def test_deadline_and_progress_notification_survive_blocked_decision(self):
        entered, release = threading.Event(), threading.Event()
        original = runtime._RegisteredServer._decision
        def blocked(server, method, params):
            entered.set()
            release.wait(15)
            return original(server, method, params)
        with patch.object(runtime._RegisteredServer, '_decision', blocked):
            case = self.pipe_case()
            factory, done, results = self.running(case)
            try:
                self.assertTrue(self.wait_for_startup(entered, done, results))
                process = self.fixture.spawned[0]
                process.stdout.put({'method': 'EXAMPLE/progress', 'params': {}})
                self.assertTrue(until(lambda: any(m['method'] == 'EXAMPLE/progress'
                                                 for _, m in factory.server._notifications), .5))
                self.assertTrue(done.wait(9), 'decision deadline did not contain original invocation')
            finally:
                release.set()
                done.wait(12)
            self.assertTrue(until(lambda: not factory.server.requests.threads[0].is_alive()))
            self.assertEqual(process.replies, [{'id': 'EXAMPLE-request', 'result': {'decision': 'decline'}}])
            self.assertIsNone(factory.token)
            self.assertTrue(factory.server.lifetime.contained)
            self.assertIsInstance(results[0], BaseException)

    def test_file_and_permission_refusals_preserve_typed_ids_before_useful_command(self):
        case = self.pipe_case(request_probes=[
            (7, runtime.protocol.FILE, {'reason': 'EXAMPLE renamed to reassuring text'}),
            ('7', runtime.protocol.PERMISSIONS, {'cwd': 'EXAMPLE-cwd', 'permissions': {'network': {'enabled': True}}}),
        ])
        factory = self.fixture.factory(case)
        try:
            factory.run()
        except BaseException as failure:
            try:
                adapter = factory.adapter
                archive = getattr(adapter, '_staged_archive', None)
                process = self.fixture.spawned[0]
                failure.add_note('EXAMPLE typed-request phase: ' + family.json.dumps({
                    'checks': adapter.check_count, 'max_steps': case.spec['max_steps'],
                    'phase': str(adapter._boundary_phase)[:80],
                    'rpc_methods': process.methods[-8:], 'reply_count': len(process.replies),
                    'pending': str(process.pending)[:80],
                    'archive_started': None if archive is None else archive._started,
                    'archive_done': None if archive is None else archive._done.is_set(),
                }, sort_keys=True))
            except BaseException as diagnostic_failure:
                failure.add_note('EXAMPLE typed-request diagnostic failed: '
                                 + type(diagnostic_failure).__name__)
            raise
        replies = self.fixture.spawned[0].replies
        self.assertEqual(replies[:2], [{'id': 7, 'result': {'decision': 'decline'}},
                                      {'id': '7', 'result': {'permissions': {}}}])
        self.assertEqual(replies[2]['result'], {'decision': 'accept'})
        self.assertIsNotNone(factory.token)

    def test_fresh_identical_actions_get_distinct_actual_decisions(self):
        case = self.pipe_case(defer_complete=True, request_probes=[
            ('EXAMPLE-first', runtime.protocol.COMMAND, {'approvalId': 'EXAMPLE-first-approval',
                'kind': 'command', 'command': family.fixtures.host_fixtures.FAKE_WRITE_COMMAND,
                'cwd': 'EXAMPLE-placeholder', 'availableDecisions': ['accept', 'decline']}),
        ])
        case.request_probes[0][2]['cwd'] = str(case.host.worker)
        factory = self.fixture.factory(case)
        factory.run()
        replies = self.fixture.spawned[0].replies
        self.assertEqual([r['result'] for r in replies], [{'decision': 'accept'}] * 2)
        entries = factory.server.requests.entries.values()
        self.assertEqual({e.correlation.approval_id for e in entries},
                         {'EXAMPLE-first-approval', 'EXAMPLE-approval'})
        self.assertEqual({e.delivery for e in entries}, {'sent'})
        self.assertEqual(len(factory.server.finite_input.lifecycle.original_accepts), 2)

    def wire_refusal(self, transform):
        original = family.RpcProcess.approve
        def approve(process):
            frames = []
            put = process.stdout.put
            with patch.object(process.stdout, 'put', frames.append):
                original(process)
            for frame in transform(frames):
                put(frame)
        with patch.object(family.RpcProcess, 'approve', approve):
            case = self.pipe_case()
            factory = self.fixture.factory(case)
            with self.assertRaises((ValueError, runtime.AppServerError)):
                factory.run()
            self.assertIsNone(factory.token)
            self.assertFalse(any(r.get('result') == {'decision': 'accept'}
                                 for r in self.fixture.spawned[0].replies))
            self.assertTrue(factory.server.lifetime.contained)
            self.assertEqual(len(self.fixture.spawned), 1)

    def test_reordered_approval_before_actual_item_is_refused(self):
        self.wire_refusal(lambda frames: list(reversed(frames)))

    def test_duplicate_typed_request_id_is_refused(self):
        def duplicate(frames):
            repeated = family.copy.deepcopy(frames[-1])
            repeated['params']['approvalId'] = 'EXAMPLE-fresh-approval-same-request'
            return [*frames, repeated]
        self.wire_refusal(duplicate)

    def test_cross_turn_request_is_refused(self):
        def changed(frames):
            frames[-1]['params']['turnId'] = 'EXAMPLE-other-turn'
            return frames
        self.wire_refusal(changed)

    def test_old_epoch_final_result_cannot_reach_fresh_registered_connection(self):
        entered, release = threading.Event(), threading.Event()
        old_fixture = self.fixture
        case = self.pipe_case()
        directory = case.host.state / 'records' / 'transport-observations'
        original_sync = runtime.native._sync
        def sync(path):
            result = original_sync(path)
            if path == directory and threading.current_thread().name == 'cwo-registered-decision':
                entered.set()
                release.wait(20)
            return result
        with patch.object(runtime.native, '_sync', sync):
            old, done, results = self.running(case)
            try:
                self.assertTrue(self.wait_for_startup(entered, done, results))
                old_process = old_fixture.spawned[0]
                old_process.stdout.lines.put('')
                self.assertTrue(done.wait(5))
                old_epoch = old.server.connection_epoch_sha256
                family.cleanup_helper(self, old_fixture)
                runtime.native._sync = original_sync
                self.fixture = family.FactoryTests(methodName='runTest')
                self.fixture.setUp()
                self.addCleanup(family.cleanup_helper, self, self.fixture)
                fresh_case = self.pipe_case()
                fresh = self.fixture.factory(fresh_case)
                fresh.run()
                self.assertNotEqual(old_epoch, fresh.server.connection_epoch_sha256)
                self.assertTrue(all(e.correlation.epoch == fresh.server.connection_epoch_sha256
                                    for e in fresh.server.requests.entries.values()))
            finally:
                release.set()
                done.wait(12)
            self.assertTrue(until(lambda: not old.server.requests.threads[0].is_alive()))
            self.assertFalse(any(r.get('result') == {'decision': 'accept'} for r in old_process.replies))
            self.assertEqual(len(self.fixture.spawned[0].replies), 1)
            self.assertIsNone(old.token)
            self.assertIsNotNone(fresh.token)
            with self.assertRaises(ValueError):
                old.run()
            self.assertIsInstance(results[0], BaseException)

    def test_latched_raw_fault_revokes_result_before_consumer_close_completes(self):
        entered, release = threading.Event(), threading.Event()
        closing, allow_close, scheduler = threading.Event(), threading.Event(), threading.Event()
        original = runtime._RegisteredServer._decision
        def blocked(server, method, params):
            result = original(server, method, params)
            entered.set()
            release.wait(15)
            return result
        with patch.object(runtime._RegisteredServer, '_decision', blocked):
            case = self.pipe_case(scheduler_gate=scheduler)
            factory, done, results = self.running(case)
            try:
                self.assertTrue(self.wait_for_startup(entered, done, results))
                server = factory.server
                original_close = server.requests.close
                def close():
                    if threading.current_thread() is server._reader_threads[0]:
                        closing.set()
                        allow_close.wait(15)
                    return original_close()
                with patch.object(server.requests, 'close', close):
                    process = self.fixture.spawned[0]
                    process.stdout.lines.put('EXAMPLE malformed JSON\n')
                    self.assertTrue(closing.wait(2))
                    self.assertIsNotNone(server.transport_failure)
                    release.set()
                    self.assertTrue(until(lambda: bool(process.replies), 3))
                    self.assertFalse(any(r.get('result') == {'decision': 'accept'} for r in process.replies),
                                     'latched raw fault permitted an accepting late result')
                    allow_close.set()
            finally:
                release.set()
                allow_close.set()
                scheduler.set()
                done.wait(12)
            self.assertTrue(done.is_set())
            self.assertIsNone(factory.token)
            self.assertIsInstance(results[0], BaseException)

    def test_terminal_intake_progresses_during_inflight_atomic_reply(self):
        deciding, decide, writing, write = (threading.Event() for _ in range(4))
        target = {}
        original_decision, original_write = runtime._RegisteredServer._decision, os.write
        def decision(server, method, params):
            result = original_decision(server, method, params)
            deciding.set()
            decide.wait(15)
            return result
        def atomic(descriptor, data):
            if (descriptor == target.get('fd')
                    and b'"decision":"accept"' in bytes(data)):
                writing.set()
                write.wait(15)
            return original_write(descriptor, data)
        with patch.object(runtime._RegisteredServer, '_decision', decision), patch.object(
                os, 'write', atomic):
            case = self.pipe_case()
            factory, done, results = self.running(case)
            try:
                self.assertTrue(self.wait_for_startup(deciding, done, results))
                server = factory.server
                target['fd'] = server.process.stdin.descriptor
                decide.set()
                self.assertTrue(writing.wait(5), 'atomic reply did not enter fake kernel')
                process = self.fixture.spawned[0]
                process.stdout.put({'method': 'turn/completed', 'params': {
                    'threadId': case.scenario.thread_id,
                    'turn': {'id': case.scenario.turn_id, 'status': 'interrupted'}}})
                self.assertTrue(until(lambda: server.finite_input.lifecycle.original_terminal, .7),
                                'stdout intake waited on the physical reply write')
                self.assertNotEqual(server.finite_input.lifecycle.original_output, 'published')
                write.set()
                self.assertTrue(done.wait(12))
            finally:
                write.set()
                decide.set()
                done.wait(12)
            self.assertIsInstance(results[0], BaseException)
            self.assertIsNone(factory.token)
            self.assertFalse(any(reply.get('result') == {'decision': 'accept'}
                                 for reply in process.replies),
                             'held-before-kernel accepting reply escaped terminal revocation')
            self.assertEqual(self.fixture.attempt(case)['charge'],
                             self.fixture.attempt(case)['amount'])

    def held_accept_outcome(self, event, kernel='write'):
        deciding, decide, writing, release = (threading.Event() for _ in range(4))
        target = {}
        original_decision, original_write = runtime._RegisteredServer._decision, os.write
        def decision(server, method, params):
            result = original_decision(server, method, params)
            deciding.set()
            decide.wait(15)
            return result
        def atomic(descriptor, data):
            if descriptor == target.get('fd') and b'"decision":"accept"' in bytes(data):
                sent = original_write(descriptor, data) if kernel == 'written' else None
                writing.set()
                release.wait(15)
                if kernel == 'written':
                    return sent
                if kernel == 'backpressure':
                    raise BlockingIOError('EXAMPLE atomic pipe backpressure')
                if kernel == 'partial':
                    return original_write(descriptor, data[:len(data) // 2])
            return original_write(descriptor, data)
        with patch.object(runtime._RegisteredServer, '_decision', decision), patch.object(
                os, 'write', atomic):
            case = self.pipe_case()
            factory, done, results = self.running(case)
            try:
                self.assertTrue(self.wait_for_startup(deciding, done, results))
                server = factory.server
                target['fd'] = server.process.stdin.descriptor
                decide.set()
                self.assertTrue(writing.wait(5))
                process = self.fixture.spawned[0]
                if event == 'raw-fault':
                    process.stdout.lines.put('EXAMPLE malformed JSON\n')
                    self.assertTrue(until(lambda: server.transport_failure is not None, .7))
                elif event == 'close':
                    server.requests.close()
                    self.assertTrue(server.requests.closed)
                elif event == 'deadline':
                    self.assertTrue(until(lambda: isinstance(server.transport_failure, TimeoutError), 5.7))
                elif event == 'terminal':
                    process.stdout.put({'method': 'turn/completed', 'params': {
                        'threadId': case.scenario.thread_id,
                        'turn': {'id': case.scenario.turn_id, 'status': 'interrupted'}}})
                    self.assertTrue(until(lambda: server.finite_input.lifecycle.original_terminal, .7))
                release.set()
                self.assertTrue(done.wait(12))
            finally:
                release.set()
                decide.set()
                done.wait(12)
            self.assertIsInstance(results[0], BaseException)
            self.assertIsNone(factory.token)
            accepts = [r for r in process.replies
                       if r.get('result') == {'decision': 'accept'}]
            self.assertEqual(len(accepts), int(kernel == 'written'))
            self.assertEqual(self.fixture.attempt(case)['charge'], self.fixture.attempt(case)['amount'])
            lifecycle = server.finite_input.lifecycle
            dispatch = [ticket for (kind, _binding), ticket in lifecycle.authority_commits.items()
                        if kind == 'reply-grant']
            self.assertEqual(len(dispatch), 1)
            self.assertLess(dispatch[0][0], lifecycle.authority_revocations[-1][0])
            if kernel == 'written':
                self.assertEqual(lifecycle.authority_outcomes[dispatch[0][1:]],
                                 'wire-sent-after-revocation')
            entry = next(iter(server.requests.entries.values()))
            self.assertEqual(entry.delivery, 'ambiguous')
            self.assertEqual(server.finite_input.lifecycle.original_deliveries[
                (str, 'EXAMPLE-request')], 'ambiguous')

    def _eagain_retry_terminal_order(self, negative_first, ready_after_eagain=False):
        """The real reply pipe exposes the no-byte/next-attempt boundary."""
        deciding, release_decision = threading.Event(), threading.Event()
        first_result, release_first = threading.Event(), threading.Event()
        second_written, release_second = threading.Event(), threading.Event()
        became_ready, release_ready = threading.Event(), threading.Event()
        thread_errors = []
        target, writes = {}, []
        original_decision = runtime._RegisteredServer._decision
        original_result = runtime._CoherentServerRequests._reply_result
        original_request_write = runtime.RegisteredServerRequests._write
        original_write = os.write

        def decision(server, method, params):
            value = original_decision(server, method, params)
            deciding.set()
            release_decision.wait(5)
            return value

        def result(requests, entry, dispatch, outcome):
            value = original_result(requests, entry, dispatch, outcome)
            if dispatch is not None and outcome == 'not-sent':
                first_result.set()
                if negative_first and not ready_after_eagain:
                    release_first.wait(3)
            return value

        def request_write(requests, entry):
            value = original_request_write(requests, entry)
            if (ready_after_eagain and value is False and entry.state == 'ready'
                    and entry.accepting and not became_ready.is_set()):
                became_ready.set()
                release_ready.wait(5)
            return value

        def atomic(descriptor, data):
            if descriptor == target.get('fd') and b'"decision":"accept"' in bytes(data):
                writes.append(bytes(data))
                if len(writes) == 1:
                    raise BlockingIOError('EXAMPLE confirmed no-byte EAGAIN')
                count = original_write(descriptor, data)
                if len(writes) == 2:
                    second_written.set()
                    release_second.wait(3)
                return count
            return original_write(descriptor, data)

        with patch.object(runtime._RegisteredServer, '_decision', decision), patch.object(
                runtime._CoherentServerRequests, '_reply_result', result), patch.object(
                runtime.RegisteredServerRequests, '_write', request_write), patch.object(
                threading, 'excepthook', lambda args: thread_errors.append(args.exc_value)), patch.object(
                os, 'write', atomic):
            case = self.pipe_case()
            factory = self.fixture.factory(case)
            done, outcomes = threading.Event(), []
            def run():
                try:
                    outcomes.append(factory.run())
                except BaseException as failure:
                    outcomes.append(failure)
                finally:
                    done.set()
            worker = threading.Thread(target=run, daemon=True)
            worker.start()
            try:
                self.assertTrue(family.wait_for_startup(self, deciding, worker, outcomes))
                server = factory.server
                target['fd'] = server.process.stdin.descriptor
                release_decision.set()
                self.assertTrue(first_result.wait(5))
                if ready_after_eagain:
                    self.assertTrue(became_ready.wait(5), 'accepting EAGAIN did not return to ready')
                lifecycle = server.finite_input.lifecycle
                key, first = next((key, ticket) for key, ticket in
                                  lifecycle.authority_commits.items()
                                  if key[0] == 'reply-grant')
                self.assertEqual(lifecycle.authority_attempt_results[first], 'not-sent')
                self.assertEqual(lifecycle.authority_outcomes[key], 'precommit-retry')
                entry = next(iter(server.requests.entries.values()))
                first_deadline = entry.deadline
                self.assertEqual(first[2], (
                    server.connection_epoch_sha256, entry.correlation.request_id,
                    case.scenario.thread_id, case.scenario.turn_id,
                    entry.correlation.item_id, entry.correlation.approval_id))
                if not negative_first:
                    self.assertTrue(second_written.wait(3))
                process = self.fixture.spawned[0]
                process.stdout.put({'method': 'turn/completed', 'params': {
                    'threadId': case.scenario.thread_id,
                    'turn': {'id': case.scenario.turn_id, 'status': 'interrupted'}}})
                self.assertTrue(until(lambda: bool(lifecycle.authority_revoked_turns), 2))
                revocation = next(order for order, kind, _target, _value in
                                  lifecycle.authority_revocations if kind == 'turn')
                if negative_first:
                    if ready_after_eagain:
                        self.assertEqual(entry.state, 'ready')
                        self.assertEqual(entry.accepting, False)
                        self.assertEqual(family.json.loads(entry.frame)['result'],
                                         {'decision': 'cancel'})
                    self.assertEqual(lifecycle.authority_commits[key], first)
                    self.assertEqual(lifecycle.authority_outcomes[key],
                                     'revoked-before-physical-send')
                else:
                    retry = lifecycle.authority_commits[key]
                    self.assertNotEqual(retry, first)
                    self.assertEqual(retry[2], first[2])
                    self.assertLess(first[0], retry[0])
                    self.assertLess(retry[0], revocation)
                    self.assertIsNone(lifecycle.authority_attempt_results[retry])
                    self.assertEqual(lifecycle.authority_outcomes[key],
                                     'ambiguous-after-revocation')
                release_first.set()
                release_ready.set()
                release_second.set()
                self.assertTrue(done.wait(12))
            finally:
                release_decision.set()
                release_first.set()
                release_ready.set()
                release_second.set()
                worker.join(12)
            self.assertFalse(worker.is_alive())
            self.assertEqual(thread_errors, [], 'unhandled action or fake-server thread error')
            self.assertEqual(len(outcomes), 1)
            self.assertIsInstance(outcomes[0], BaseException)
            self.assertIsNone(factory.token)
            self.assertEqual(len(writes), 1 if negative_first else 2)
            accepts = [reply for reply in process.replies
                       if reply.get('result') == {'decision': 'accept'}]
            self.assertEqual(len(accepts), 0 if negative_first else 1)
            if ready_after_eagain:
                self.assertEqual([r['result'] for r in process.replies
                                  if r.get('result') == {'decision': 'cancel'}],
                                 [{'decision': 'cancel'}])
                self.assertIn('Terminal event invalidated pending approval.',
                              str(server.transport_failure))
                self.assertIs(server.request_failure, server.transport_failure,
                              'host request failure lost the originating terminal refusal')
                self.assertNotIn('Unknown or completed protected dispatch intent.',
                                 str(outcomes[0]))
                self.assertTrue(server.lifetime.contained)
                self.assertTrue(server.lifetime.termination_recorded)
                self.assertTrue(server.lifetime._termination_finished.is_set())
                self.assertIsNotNone(server.lifetime._termination_owner)
            self.assertEqual(lifecycle.authority_attempt_results[first], 'not-sent')
            self.assertEqual(entry.deadline, first_deadline)
            if not negative_first:
                self.assertEqual(lifecycle.authority_attempt_results[retry], 'wire-sent')
                self.assertEqual(lifecycle.authority_outcomes[key],
                                 'wire-sent-after-revocation')
            attempt = self.fixture.attempt(case)
            self.assertEqual(attempt['outcome'], 'unknown')
            self.assertEqual(attempt['charge'], attempt['amount'])

    def test_eagain_retry_terminal_orders_on_registered_accept_pipe(self):
        for negative_first, ready_after_eagain in ((True, False), (False, False),
                                                   (True, True)):
            with self.subTest(negative_first=negative_first,
                              ready_after_eagain=ready_after_eagain):
                fixture = RegisteredRequestsTests(methodName='runTest')
                fixture.setUp()
                try:
                    fixture._eagain_retry_terminal_order(negative_first, ready_after_eagain)
                finally:
                    family.cleanup_helper(self, fixture)

    def test_raw_fault_fences_inflight_accept_and_keeps_full_charge(self):
        self.held_accept_outcome('raw-fault')

    def test_close_fences_inflight_accept_and_keeps_full_charge(self):
        self.held_accept_outcome('close')

    def test_prior_wire_send_then_terminal_is_ambiguous_and_fully_charged(self):
        # The fake server actually reads the reply before the writer returns.
        # This proves prior dispatch, not server-side effect rollback.
        self.held_accept_outcome('terminal', kernel='written')

    def test_deadline_fences_inflight_accept_and_keeps_full_charge(self):
        self.held_accept_outcome('deadline')

    def test_backpressure_after_terminal_does_not_retry_old_accept(self):
        self.held_accept_outcome('terminal', kernel='backpressure')

    def test_partial_write_result_is_ambiguous_and_keeps_full_charge(self):
        parse_errors = []
        failed_streams = []
        original = family.Input.consume
        def consume(stream, descriptor):
            try:
                original(stream, descriptor)
            except family.json.JSONDecodeError as error:
                parse_errors.append(error)
                failed_streams.append(stream)
        with patch.object(family.Input, 'consume', consume):
            self.held_accept_outcome('partial', kernel='partial')
        self.assertEqual(len(parse_errors), 1)
        stream, error = failed_streams[0], parse_errors[0]
        frame = (family.json.dumps({'id': 'EXAMPLE-request',
                    'result': {'decision': 'accept'}}, separators=(',', ':')) + '\n').encode()
        self.assertEqual(error.doc.encode(), frame[:len(frame) // 2])
        self.assertIs(stream.failure, error)
        self.assertEqual(stream.failed_input_frame, error.doc)
        stream.acknowledge_failure(error)
        self.assertIs(stream.failure, error)

    def test_close_then_fake_terminal_cannot_reopen_revoked_request(self):
        entered, release = threading.Event(), threading.Event()
        observing, resume = threading.Event(), threading.Event()
        original_decision = runtime._RegisteredServer._decision
        def decision(server, method, params):
            result = original_decision(server, method, params)
            entered.set()
            release.wait(15)
            return result
        with patch.object(runtime._RegisteredServer, '_decision', decision):
            case = self.pipe_case()
            factory, done, results = self.running(case)
            try:
                self.assertTrue(self.wait_for_startup(entered, done, results))
                server = factory.server
                original_observe = server.requests.observe
                def observe(message):
                    if message['method'] == 'turn/completed':
                        observing.set()
                        resume.wait(15)
                    return original_observe(message)
                with patch.object(server.requests, 'observe', observe):
                    process = self.fixture.spawned[0]
                    process.stdout.put({'method': 'turn/completed', 'params': {
                        'threadId': case.scenario.thread_id,
                        'turn': {'id': case.scenario.turn_id, 'status': 'interrupted'}}})
                    self.assertTrue(observing.wait(2))
                    server.requests.close()
                    self.assertTrue(all(e.state == 'revoked'
                                        for e in server.requests.entries.values()))
                    resume.set()
                    self.assertTrue(until(lambda: server.finite_input.lifecycle.original_terminal))
                    self.assertTrue(all(e.state == 'revoked'
                                        for e in server.requests.entries.values()),
                                    'late fake terminal revived a closed reply')
                release.set()
                self.assertTrue(done.wait(8))
            finally:
                resume.set()
                release.set()
                done.wait(12)
            self.assertFalse(any(r.get('result') == {'decision': 'accept'}
                                 for r in self.fixture.spawned[0].replies))
            self.assertIsNone(factory.token)
            self.assertIsInstance(results[0], BaseException)
            self.assertEqual(self.fixture.attempt(case)['charge'],
                             self.fixture.attempt(case)['amount'])

    def test_pending_required_reply_at_controlled_eof_refuses_capture(self):
        held, locked = [], threading.Event()
        original = family.RpcProcess.receive
        def receive(process, message):
            if message.get('method') == 'thread/archive':
                writer = process.stdin
                self.assertTrue(writer._lock.acquire(timeout=2))
                held.append(writer)
                process.stdout.put({'id': 'EXAMPLE-queued-at-archive',
                                    'method': 'item/tool/requestUserInput', 'params': {}})
                self.assertTrue(until(lambda: (str, 'EXAMPLE-queued-at-archive') in
                                      process.case.factory.server.requests.entries))
                locked.set()
            return original(process, message)
        with patch.object(family.RpcProcess, 'receive', receive):
            case = self.pipe_case()
            factory, done, results = self.running(case)
            try:
                self.assertTrue(self.wait_for_startup(locked, done, results))
                self.assertTrue(done.wait(8), 'pending error reply stalled controlled cleanup')
                self.assertTrue(isinstance(results[0], BaseException),
                                'unresolved required reply allowed successful artifact capture')
                self.assertIsNone(factory.token)
                self.assertFalse((case.host.state / 'artifact').exists())
            finally:
                for writer in held:
                    writer._lock.release()
                done.wait(12)

    def test_sent_required_error_before_fault_publication_refuses_capture(self):
        sent, release = threading.Event(), threading.Event()
        original_tick = runtime.RegisteredServerRequests._tick
        original_receive = family.RpcProcess.receive
        def tick(consumer):
            failure = original_tick(consumer)
            if failure is not None and str(failure) == 'Unknown required server request.':
                sent.set()
                release.wait(15)
            return failure
        def receive(process, message):
            if message.get('method') == 'thread/archive':
                process.stdout.put({'id': 'EXAMPLE-sent-at-archive',
                                    'method': 'item/tool/requestUserInput', 'params': {}})
                self.assertTrue(sent.wait(3))
            return original_receive(process, message)
        with patch.object(runtime.RegisteredServerRequests, '_tick', tick), patch.object(
                family.RpcProcess, 'receive', receive):
            case = self.pipe_case()
            factory, done, results = self.running(case)
            try:
                self.assertTrue(self.wait_for_startup(sent, done, results))
                self.assertTrue(done.wait(8))
                self.assertTrue(isinstance(results[0], BaseException),
                                'sent fatal reply allowed successful capture before fault publication')
                self.assertIsNone(factory.token)
                self.assertFalse((case.host.state / 'artifact').exists())
            finally:
                release.set()
                done.wait(12)

    def test_fault_between_delivery_validation_and_write_revokes_acceptance(self):
        validated, release = threading.Event(), threading.Event()
        original = runtime.RegisteredServerRequests._write
        def write(consumer, entry):
            if entry.frame is not None and family.json.loads(entry.frame).get('result') == {'decision': 'accept'}:
                validated.set()
                release.wait(15)
            return original(consumer, entry)
        with patch.object(runtime.RegisteredServerRequests, '_write', write):
            case = self.pipe_case()
            factory, done, results = self.running(case)
            try:
                self.assertTrue(self.wait_for_startup(validated, done, results))
                process = self.fixture.spawned[0]
                process.stdout.lines.put('EXAMPLE malformed after delivery validation\n')
                self.assertTrue(until(lambda: factory.server.transport_failure is not None))
                release.set()
                self.assertTrue(done.wait(12))
                self.assertFalse(any(r.get('result') == {'decision': 'accept'} for r in process.replies),
                                 'accepting write followed a latched transport fault')
                self.assertIsNone(factory.token)
                self.assertIsInstance(results[0], BaseException)
            finally:
                release.set()
                done.wait(12)

    def test_item_completion_before_item_start_refuses_later_approval(self):
        def reordered(frames):
            completion = family.copy.deepcopy(frames[0])
            completion['method'] = 'item/completed'
            completion['params']['item']['status'] = 'completed'
            return [completion, *frames]
        self.wire_refusal(reordered)

    def test_turn_completion_before_actual_turn_response_refuses_later_approval(self):
        original = family.RpcProcess.receive
        def receive(process, message):
            if message.get('method') == 'turn/start':
                process.stdout.put({'method': 'turn/completed', 'params': {
                    'threadId': process.case.scenario.thread_id,
                    'turn': {'id': process.case.scenario.turn_id, 'status': 'completed'}}})
            return original(process, message)
        with patch.object(family.RpcProcess, 'receive', receive):
            case = self.pipe_case()
            factory = self.fixture.factory(case)
            with self.assertRaises((ValueError, runtime.AppServerError)):
                factory.run()
            self.assertIsNone(factory.token)
            self.assertFalse(any(r.get('result') == {'decision': 'accept'}
                                 for r in self.fixture.spawned[0].replies))
            self.assertTrue(factory.server.lifetime.contained)

    def early_thread_terminal_refusal(self, method):
        original = family.RpcProcess.receive
        def receive(process, message):
            if message.get('method') == 'turn/start':
                process.stdout.put({'method': method, 'params': {
                    'threadId': process.case.scenario.thread_id}})
            return original(process, message)
        with patch.object(family.RpcProcess, 'receive', receive):
            case = self.pipe_case()
            factory = self.fixture.factory(case)
            with self.assertRaises((ValueError, runtime.AppServerError)):
                factory.run()
            self.assertIsNone(factory.token)
            self.assertFalse(any(r.get('result') == {'decision': 'accept'}
                                 for r in self.fixture.spawned[0].replies))

    def test_thread_closed_before_turn_response_refuses_later_approval(self):
        self.early_thread_terminal_refusal('thread/closed')

    def test_thread_archived_before_turn_response_refuses_later_approval(self):
        self.early_thread_terminal_refusal('thread/archived')

    def test_terminal_turn_start_response_refuses_later_approval(self):
        original = family.RpcProcess.result
        def result(process, method, params):
            value = original(process, method, params)
            if method == 'turn/start':
                value['turn']['status'] = 'completed'
            return value
        with patch.object(family.RpcProcess, 'result', result):
            case = self.pipe_case()
            factory = self.fixture.factory(case)
            with self.assertRaises((ValueError, runtime.AppServerError)):
                factory.run()
            self.assertIsNone(factory.token)
            self.assertFalse(any(r.get('result') == {'decision': 'accept'}
                                 for r in self.fixture.spawned[0].replies))

    def test_completed_item_in_turn_start_response_refuses_later_approval(self):
        original = family.RpcProcess.result
        def result(process, method, params):
            value = original(process, method, params)
            if method == 'turn/start':
                value['turn'].update(status='inProgress', items=[{
                    'id': 'EXAMPLE-item', 'type': 'commandExecution', 'status': 'completed'}])
            return value
        with patch.object(family.RpcProcess, 'result', result):
            case = self.pipe_case()
            factory = self.fixture.factory(case)
            with self.assertRaises((ValueError, runtime.AppServerError)):
                factory.run()
            self.assertIsNone(factory.token)
            self.assertFalse(any(r.get('result') == {'decision': 'accept'}
                                 for r in self.fixture.spawned[0].replies))

    def test_acknowledged_local_interrupt_revokes_blocked_decision(self):
        entered, release = threading.Event(), threading.Event()
        dispatched, resume = threading.Event(), threading.Event()
        caller = sys.modules[runtime.native.LiveThreadAdapter.__module__]
        original_write = caller.write_private_artifact
        original_decision = runtime._RegisteredServer._decision
        def write(path, data):
            if path.name.endswith('-dispatch.json'):
                dispatched.set()
                resume.wait(15)
            return original_write(path, data)
        def decision(server, method, params):
            value = original_decision(server, method, params)
            entered.set()
            release.wait(15)
            return value
        with patch.object(caller, 'write_private_artifact', write), patch.object(
                runtime._RegisteredServer, '_decision', decision):
            case = self.pipe_case()
            case.release_turn_response = True
            factory, done, results = self.running(case)
            try:
                self.assertTrue(self.wait_for_startup(entered, done, results))
                self.assertTrue(dispatched.wait(5), 'original send_input did not return its turn')
                self.assertEqual(factory.adapter.interrupt(), {'ack': 'interrupt-requested'})
                self.assertTrue(factory.adapter.interrupted)
                process = self.fixture.spawned[0]
                self.assertIn('turn/interrupt', process.methods)
                release.set()
                self.assertTrue(until(lambda: bool(process.replies)))
                self.assertFalse(any(r.get('result') == {'decision': 'accept'} for r in process.replies),
                                 'acknowledged original local interrupt permitted a late accepting write')
                self.assertIsNone(factory.token)
            finally:
                resume.set()
                release.set()
                done.wait(12)
            self.assertIsInstance(results[0], BaseException)

    def test_known_fatal_request_revokes_earlier_ready_acceptance(self):
        entered, release = threading.Event(), threading.Event()
        original = runtime._RegisteredServer._decision
        def decision(server, method, params):
            value = original(server, method, params)
            entered.set()
            release.wait(15)
            return value
        with patch.object(runtime._RegisteredServer, '_decision', decision):
            case = self.pipe_case()
            factory, done, results = self.running(case)
            held = False
            try:
                self.assertTrue(self.wait_for_startup(entered, done, results))
                writer = factory.server.process.stdin._lock
                self.assertTrue(writer.acquire(timeout=1))
                held = True
                process = self.fixture.spawned[0]
                process.stdout.put({'id': 'EXAMPLE-unsupported', 'method': 'EXAMPLE/unsupported', 'params': {}})
                self.assertTrue(until(lambda: len(factory.server.requests.entries) == 2))
                release.set()
                self.assertTrue(until(lambda: all(e.state == 'ready'
                                                 for e in factory.server.requests.entries.values())))
                writer.release()
                held = False
                self.assertTrue(done.wait(8))
                self.assertFalse(any(r.get('result') == {'decision': 'accept'} for r in process.replies),
                                 'known fatal request permitted an earlier command to commit acceptance')
                self.assertTrue(any(r.get('id') == 'EXAMPLE-unsupported' and
                                    r.get('error', {}).get('code') == -32601 for r in process.replies))
                self.assertIsNone(factory.token)
                self.assertIsInstance(results[0], BaseException)
            finally:
                if held:
                    writer.release()
                release.set()
                done.wait(12)

    def test_later_fatal_reply_cannot_extend_an_earlier_delivery_deadline(self):
        entered, release = threading.Event(), threading.Event()
        original = runtime._RegisteredServer._decision
        def decision(server, method, params):
            value = original(server, method, params)
            entered.set()
            release.wait(15)
            return value
        with patch.object(runtime._RegisteredServer, '_decision', decision):
            case = self.pipe_case()
            factory, done, _results = self.running(case)
            held = False
            try:
                self.assertTrue(self.wait_for_startup(entered, done, _results))
                first = next(iter(factory.server.requests.entries.values()))
                writer = factory.server.process.stdin._lock
                self.assertTrue(writer.acquire(timeout=1))
                held = True
                time.sleep(max(0, first.deadline - time.monotonic() - 1.5))
                self.fixture.spawned[0].stdout.put({'id': 'EXAMPLE-later-unsupported',
                                                  'method': 'EXAMPLE/unsupported', 'params': {}})
                self.assertTrue(until(lambda: len(factory.server.requests.entries) == 2))
                self.assertTrue(until(lambda: factory.server.transport_failure is not None,
                                     max(0, first.deadline - time.monotonic()) + .7),
                                'later fatal reply extended the earlier request delivery deadline')
                self.assertIsNone(factory.token)
            finally:
                if held:
                    writer.release()
                release.set()
                done.wait(12)

    def test_expired_cancellation_written_before_blocked_error_still_contains(self):
        entered, release, allow_error, driver_gate = (threading.Event() for _ in range(4))
        original_decision = runtime._RegisteredServer._decision
        original_write = os.write
        target = {}
        def write(descriptor, data):
            if (descriptor == target.get('fd') and b'"id":"EXAMPLE-later-unsupported"' in bytes(data)
                    and not allow_error.is_set()):
                raise BlockingIOError('EXAMPLE kernel cannot fit the later error')
            return original_write(descriptor, data)
        def decision(server, method, params):
            value = original_decision(server, method, params)
            entered.set()
            release.wait(15)
            return value
        with patch.object(os, 'write', write), patch.object(runtime._RegisteredServer, '_decision', decision):
            case = self.pipe_case()
            case.scheduler_gate = driver_gate
            factory, done, _results = self.running(case)
            try:
                self.assertTrue(self.wait_for_startup(entered, done, _results))
                first = next(iter(factory.server.requests.entries.values()))
                target['fd'] = factory.server.process.stdin.descriptor
                time.sleep(max(0, first.deadline - time.monotonic() - 1.5))
                process = self.fixture.spawned[0]
                process.stdout.put({'id': 'EXAMPLE-later-unsupported', 'method': 'EXAMPLE/unsupported', 'params': {}})
                self.assertTrue(until(lambda: len(factory.server.requests.entries) == 2))
                self.assertTrue(until(lambda: any(r.get('id') == 'EXAMPLE-request' for r in process.replies),
                                     max(0, first.deadline - time.monotonic()) + .7))
                self.assertTrue(until(lambda: factory.server.transport_failure is not None, .5),
                                'successful expired cancellation deferred containment to a later error deadline')
                self.assertFalse(any(r.get('result') == {'decision': 'accept'} for r in process.replies))
                self.assertIsNone(factory.token)
            finally:
                driver_gate.set()
                allow_error.set()
                release.set()
                done.wait(12)

    def test_original_control_failure_revokes_before_finalization_persistence(self):
        entered, release, finalizing, resume = (threading.Event() for _ in range(4))
        caller = sys.modules[runtime.native.LiveThreadAdapter.__module__]
        original_write = caller.write_private_artifact
        original_decision = runtime._RegisteredServer._decision
        def write(path, data):
            if path.name.endswith('-dispatch.json'):
                raise OSError('EXAMPLE dispatch persistence failure')
            if path.name.endswith('-finalize-control-failed.json'):
                finalizing.set()
                resume.wait(15)
            return original_write(path, data)
        def decision(server, method, params):
            value = original_decision(server, method, params)
            entered.set()
            release.wait(15)
            return value
        with patch.object(caller, 'write_private_artifact', write), patch.object(
                runtime._RegisteredServer, '_decision', decision):
            case = self.pipe_case()
            case.release_turn_response = entered
            factory, done, results = self.running(case)
            try:
                self.assertTrue(self.wait_for_startup(entered, done, results))
                self.assertTrue(finalizing.wait(5))
                release.set()
                process = self.fixture.spawned[0]
                self.assertTrue(until(lambda: bool(process.replies) or factory.server.requests.closed))
                self.assertFalse(any(r.get('result') == {'decision': 'accept'} for r in process.replies),
                                 'original control failure permitted accept during finalization persistence')
                self.assertTrue(until(lambda: factory.server.lifetime.contained))
                self.assertIsNone(factory.token)
            finally:
                release.set()
                resume.set()
                done.wait(12)
            self.assertIsInstance(results[0], BaseException)
            self.assertIn('callback-failed:OSError:EXAMPLE dispatch persistence failure',
                          results[0].native_report['receipt']['errors'])

    def test_original_host_scratch_failure_revokes_before_failure_persistence(self):
        entered, release, saving, resume = (threading.Event() for _ in range(4))
        original_write = runtime.native._write_new
        chosen = {}
        def write(path, data, mode=0o600):
            if path.parent.name == 'transport-observations' and family.json.loads(data).get('stage') == 'approval':
                os.environ['TMPDIR'] = chosen['worker']
                entered.set()
                release.wait(15)
            if path.name == 'operation.next' and 'Scratch' in (family.json.loads(data).get('error') or ''):
                saving.set()
                resume.wait(15)
            return original_write(path, data, mode)
        with patch.dict(os.environ, {}, clear=False), patch.object(runtime.native, '_write_new', write):
            case = self.pipe_case()
            chosen['worker'] = str(case.host.worker)
            case.release_turn_response = entered
            factory, done, results = self.running(case)
            try:
                self.assertTrue(self.wait_for_startup(entered, done, results), 'original final authority check did not reach approval persistence')
                self.assertTrue(saving.wait(5), 'original host scratch validation did not reach failure persistence')
                release.set()
                process = self.fixture.spawned[0]
                self.assertTrue(until(lambda: bool(process.replies) or factory.server.requests.closed))
                self.assertFalse(any(r.get('result') == {'decision': 'accept'} for r in process.replies),
                                 'original host failure permitted accept during failure persistence')
                self.assertTrue(until(lambda: factory.server.lifetime.contained))
                self.assertIsNone(factory.token)
            finally:
                release.set()
                resume.set()
                done.wait(12)
            self.assertIsInstance(results[0], BaseException)
            self.assertIn('Scratch candidates must stay outside both repositories', str(results[0]))

    def original_driver_interrupt(self, route, *, delayed_archive=False):
        entered, release = threading.Event(), threading.Event()
        original_decision = runtime._RegisteredServer._decision
        original_result = family.RpcProcess.result
        def decision(server, method, params):
            value = original_decision(server, method, params)
            entered.set()
            release.wait(15)
            return value
        def result(process, method, params):
            value = original_result(process, method, params)
            if method == 'turn/start' and route == 'check':
                case, scenario = process.case, process.case.scenario
                scenario.set_boundary('valid')
                records = [family.json.loads(line) for line in scenario.path.read_text().splitlines()]
                records[1]['payload'].update(model=case.spec['model'], effort=case.spec['effort'])
                records.append({'type': 'response_item', 'payload': {'type': 'function_call',
                    'name': 'EXAMPLE_forbidden_tool', 'call_id': 'EXAMPLE-forbidden-call', 'arguments': '{}'}})
                scenario.path.write_text(''.join(family.json.dumps(r) + '\n' for r in records))
            return value
        archive_type = sys.modules[runtime.RegisteredAdapter.finalize.__module__].StagedThreadArchive
        original_ready = archive_type.completion_ready
        def ready(archive):
            return False if delayed_archive else original_ready(archive)
        with patch.object(runtime._RegisteredServer, '_decision', decision), patch.object(
                family.RpcProcess, 'result', result), patch.object(archive_type, 'completion_ready', ready):
            case = self.pipe_case(max_steps=3 if route == 'exhaustion' else 64)
            case.release_turn_response = entered
            factory, done, results = self.running(case)
            try:
                self.assertTrue(self.wait_for_startup(entered, done, results))
                self.assertTrue(until(lambda: factory.adapter.interrupted or done.is_set(), 5))
                self.assertTrue(factory.adapter.interrupted, 'original driver did not acknowledge interruption')
                release.set()
                self.assertTrue(done.wait(12))
                process = self.fixture.spawned[0]
                self.assertIn('turn/interrupt', process.methods)
                self.assertFalse(any(r.get('result') == {'decision': 'accept'} for r in process.replies))
                self.assertIsNone(factory.token)
                expected = 'interrupt:control-lost' if route == 'exhaustion' else 'interrupt'
                self.assertIsNotNone(results[0].native_report, repr(results[0]) + repr(getattr(results[0], '__notes__', [])))
                self.assertIsNotNone(results[0].native_report['receipt'], 'Interrupted run lost its receipt')
                report = results[0].native_report
                receipt = report['receipt']
                self.assertIn(expected, receipt['decisions'])
                stored = family.json.loads((case.host.state / 'operation.json').read_bytes())
                self.assertEqual(stored['receipt'], receipt)
                self.assertEqual(factory.execution, report)
                self.assertEqual(report['status'], 'reconciliation-required')
                if delayed_archive:
                    self.assertEqual(receipt['terminal_state'], 'control-failed')
                    self.assertIn('interrupt-cleanup-step-bound-exhausted', receipt['errors'])
                    self.assertNotIn('finalize:close-confirmed', receipt['actions'])
            finally:
                release.set()
                done.wait(12)

    def test_original_check_decision_interrupt_revokes_pending_approval(self):
        """Original interrupt retains a persisted receipt and revokes approval."""
        self.original_driver_interrupt('check')

    def test_original_step_exhaustion_interrupt_revokes_pending_approval(self):
        """Retain the receipt even when archive cannot finish in eight cleanup polls."""
        self.original_driver_interrupt('exhaustion', delayed_archive=True)

    def test_r3_original_step_exhaustion_with_natural_archive_scheduling(self):
        self.original_driver_interrupt('exhaustion')

    def terminal_archive_fixture(self):
        entered, release, archive = threading.Event(), threading.Event(), threading.Event()
        original_decision = runtime._RegisteredServer._decision
        original_receive, original_result = family.RpcProcess.receive, family.RpcProcess.result
        held = []
        def decision(server, method, params):
            value = original_decision(server, method, params)
            if params.get('approvalId') == 'EXAMPLE-second-approval':
                entered.set()
                release.wait(15)
            return value
        def receive(process, message):
            if message.get('method') == 'thread/archive':
                held.append((process, message))
                archive.set()
                return
            original_receive(process, message)
            if message.get('id') == 'EXAMPLE-request' and message.get('result') == {'decision': 'accept'}:
                case = process.case
                process.stdout.put({'id': 'EXAMPLE-second', 'method': runtime.protocol.COMMAND,
                    'params': {'itemId': 'EXAMPLE-item', 'threadId': case.scenario.thread_id,
                        'turnId': case.scenario.turn_id, 'startedAtMs': 1001,
                        'approvalId': 'EXAMPLE-second-approval', 'kind': 'command',
                        'cwd': str(case.host.worker), 'command': case.spec['command'],
                        'availableDecisions': ['accept', 'decline']}})
        def result(process, method, params):
            value = original_result(process, method, params)
            if method == 'thread/read' and entered.is_set():
                value['thread']['turns'] = [{'id': process.case.scenario.turn_id,
                                            'status': 'inProgress', 'items': []}]
            return value
        return entered, release, archive, held, decision, receive, result, original_receive

    def test_trusted_terminal_and_stale_projection_revoke_before_archive_ack(self):
        entered, release, archive, held, decision, receive, result, original_receive = self.terminal_archive_fixture()
        with patch.object(runtime._RegisteredServer, '_decision', decision), patch.object(
                family.RpcProcess, 'receive', receive), patch.object(family.RpcProcess, 'result', result):
            case = self.pipe_case()
            case.scheduler_gate = entered
            factory, done, results = self.running(case)
            try:
                self.assertTrue(self.wait_for_startup(entered, done, results))
                self.assertTrue(until(lambda: archive.is_set() or done.is_set(), 5))
                if archive.is_set():
                    self.assertEqual(factory.adapter.interrupt(), {'ack': 'already-terminal'})
                release.set()
                process = self.fixture.spawned[0]
                self.assertTrue(until(lambda: any(r.get('id') == 'EXAMPLE-second' for r in process.replies)
                                     or factory.server.requests.closed))
                self.assertFalse(any(r.get('id') == 'EXAMPLE-second' and
                                     r.get('result') == {'decision': 'accept'} for r in process.replies),
                                 'trusted terminal evidence permitted a late accept while archive ACK was held')
                self.assertIsNone(factory.token)
            finally:
                release.set()
                for process, message in held:
                    original_receive(process, message)
                done.wait(12)

    def test_expired_trusted_cancellation_before_fault_publication_refuses_capture(self):
        entered, release, archive, held, decision, receive, result, original_receive = self.terminal_archive_fixture()
        expired_sent, publish, parked, driver = (threading.Event() for _ in range(4))
        original_tick, original_open = runtime.RegisteredServerRequests._tick, os.open
        def tick(consumer):
            second = next((e for e in consumer.entries.values() if e.request.request_id == 'EXAMPLE-second'), None)
            if second is not None and second.state == 'ready' and not second.expired:
                time.sleep(max(0, second.deadline - time.monotonic() + .02))
            failure = original_tick(consumer)
            if second is not None and second.expired and second.state == 'sent' and isinstance(failure, TimeoutError):
                expired_sent.set()
                publish.wait(15)
            return failure
        def opening(path, flags, mode=0o777, *, dir_fd=None):
            if threading.current_thread().name == 'EXAMPLE-original-control-driver' and archive.is_set():
                parked.set()
                driver.wait(15)
            return original_open(path, flags, mode, dir_fd=dir_fd)
        with patch.object(runtime._RegisteredServer, '_decision', decision), patch.object(
                family.RpcProcess, 'receive', receive), patch.object(family.RpcProcess, 'result', result), patch.object(
                runtime.RegisteredServerRequests, '_tick', tick), patch.object(os, 'open', opening):
            case = self.pipe_case()
            case.scheduler_gate = entered
            factory, done, results = self.running(case)
            try:
                self.assertTrue(self.wait_for_startup(entered, done, results))
                self.assertTrue(archive.wait(5))
                self.assertTrue(parked.wait(5))
                self.assertTrue(expired_sent.wait(8), 'actual expired cancellation was not sent before held publication')
                second = factory.server.requests.entries[(str, 'EXAMPLE-second')]
                self.assertTrue(second.expired)
                self.assertEqual(second.state, 'sent')
                self.assertIsNone(second.refusal)
                self.assertTrue(factory.server.requests.trusted_terminals)
                process, message = held.pop()
                original_receive(process, message)
                self.assertTrue(until(lambda: factory.server.archived or factory.server.transport_failure is not None))
                self.assertIsNotNone(factory.server.transport_failure,
                                     'controlled close reported healthy after observed sent cancellation expiry')
                self.assertFalse(factory.server.archived)
                driver.set()
                self.assertTrue(done.wait(5))
                self.assertIsInstance(results[0], BaseException,
                                      'controlled close discarded observed expiry and permitted capture')
                self.assertIsNone(factory.token)
                self.assertFalse((case.host.state / 'artifact').exists())
            finally:
                driver.set()
                publish.set()
                release.set()
                for process, message in held:
                    original_receive(process, message)
                done.wait(12)

    def test_projected_completed_item_revokes_pending_actual_approval(self):
        entered, release = threading.Event(), threading.Event()
        original_result = family.RpcProcess.result
        original_decision = runtime._RegisteredServer._decision
        def result(process, method, params):
            value = original_result(process, method, params)
            if method == 'thread/read' and process.pending is not None:
                case = process.case
                item = family.copy.deepcopy(case.factory.server._items[
                    (case.scenario.thread_id, case.scenario.turn_id, 'EXAMPLE-item')])
                item['status'] = 'completed'
                value['thread']['turns'] = [{'id': case.scenario.turn_id,
                                            'status': 'inProgress', 'items': [item]}]
            return value
        def decision(server, method, params):
            value = original_decision(server, method, params)
            entered.set()
            release.wait(15)
            return value
        with patch.object(family.RpcProcess, 'result', result), patch.object(
                runtime._RegisteredServer, '_decision', decision):
            case = self.pipe_case()
            factory, done, results = self.running(case)
            try:
                self.assertTrue(self.wait_for_startup(entered, done, results))
                try:
                    factory.server.read_thread(case.scenario.thread_id)
                except runtime.AppServerError:
                    pass
                release.set()
                self.assertTrue(done.wait(12))
                self.assertFalse(any(r.get('result') == {'decision': 'accept'}
                                     for r in self.fixture.spawned[0].replies),
                                 'completed projected item permitted an accepting callback result')
                self.assertIsNone(factory.token)
                self.assertTrue(isinstance(results[0], BaseException))
            finally:
                release.set()
                done.wait(12)

    def terminal_start_notification_refusal(self, method):
        original = family.RpcProcess.receive
        def receive(process, message):
            if message.get('method') == 'turn/start':
                scenario = process.case.scenario
                turn = {'id': scenario.turn_id, 'status': 'completed', 'items': []}
                params = ({'threadId': scenario.thread_id, 'turn': turn} if method == 'turn/started'
                          else {'thread': {'id': scenario.thread_id, 'turns': [turn]}})
                process.stdout.put({'method': method, 'params': params})
            return original(process, message)
        with patch.object(family.RpcProcess, 'receive', receive):
            case = self.pipe_case()
            factory = self.fixture.factory(case)
            with self.assertRaises((ValueError, runtime.AppServerError)):
                factory.run()
            self.assertIsNone(factory.token)
            self.assertFalse(any(r.get('result') == {'decision': 'accept'}
                                 for r in self.fixture.spawned[0].replies))

    def test_terminal_turn_data_in_started_notification_refuses_later_approval(self):
        self.terminal_start_notification_refusal('turn/started')

    def test_terminal_turn_data_in_thread_started_notification_refuses_later_approval(self):
        self.terminal_start_notification_refusal('thread/started')


if __name__ == '__main__':
    unittest.main()
