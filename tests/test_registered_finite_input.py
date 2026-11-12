"""Offline original registered host input gate with real fake-tool pipes."""
from __future__ import annotations

import json
from itertools import permutations
from contextlib import ExitStack, nullcontext
import os
import threading
import time
import unittest
from unittest.mock import patch

from tests import test_registered_n1_factory as family
import registered_finite_input as finite


class ToolLines:
    """Actual kernel output pipe on the original fake retained child."""

    def __init__(self):
        read, write = os.pipe()
        self.reader = os.fdopen(read, 'rb', buffering=0)
        self.writer = os.fdopen(write, 'wb', buffering=0)
        self.lines = self

    def fileno(self):
        return self.reader.fileno()

    def put(self, value):
        if value == '':
            self.writer.close()
        else:
            self.writer.write(value.encode())

    def close(self):
        self.reader.close()
        if not self.writer.closed:
            self.writer.close()


class FiniteInputTests(unittest.TestCase):
    def setUp(self):
        self.fixture = family.FactoryTests(methodName='runTest')
        self.fixture.setUp()
        self.addCleanup(family.cleanup_helper, self, self.fixture)

    def _active(self):
        from tests.test_registered_finite_tool_wiring import DynamicRpcProcess
        fixture = self.fixture
        case = fixture.case(finite_tool_mode='captured-host-tools', complete_after_refusal=True)
        case.poll_prepared, case.poll_release = threading.Event(), threading.Event()
        case.result_done = threading.Event()
        factory = fixture.factory(case)
        result = []
        patcher = patch.object(family, 'RpcProcess', DynamicRpcProcess)
        patcher.start()
        self.addCleanup(patcher.stop)

        def run():
            try:
                result.append(factory.run())
            except BaseException as error:
                result.append(error)
            finally:
                case.result_done.set()

        thread = threading.Thread(target=run, daemon=True)
        thread.start()
        self.addCleanup(family.finish_worker, self, thread, case.poll_release)
        self.addCleanup(case.poll_release.set)
        self.assertTrue(family.wait_for_startup(self, case.poll_prepared, thread, result),
                        'selected original command reply was not consumed')
        self.assertTrue(fixture.spawned[0].replies[0]['result']['success'])
        self.assertTrue(self._wait(lambda: (case.scenario.thread_id, case.scenario.turn_id,
                                           'EXAMPLE-command-call')
                                   in factory.server.requests.completed_items, 2),
                        'the original reader must observe command completion before item mutation')
        gate = factory.server.finite_input
        tool = factory.server.finite_tools.lifetime
        stream, read = case.tool_stream, case.tool_read
        self.assertIsNotNone(tool)
        self.assertEqual(gate.dynamic_command[:3],
                         (case.scenario.thread_id, case.scenario.turn_id, 'EXAMPLE-command-call'))
        self.assertEqual(os.read(gate.output_fd, 4096), b'EXAMPLE finite poll output\n')
        original_reserve = gate.reserve

        def observed_reserve(chars, *, thread_id, turn_id, item_id, approval_id, deadline):
            key = thread_id, turn_id, approval_id
            if (thread_id == case.scenario.thread_id and turn_id == case.scenario.turn_id
                    and item_id == 'EXAMPLE-command-call' and type(approval_id) is str
                    and approval_id != 'EXAMPLE-missing-item' and key not in factory.server._items
                    and gate.state == 'active' and factory.server.transport_failure is None
                    and factory.server.requests.cancelled_turn is None):
                text = chars.decode('utf-8', 'replace') if type(chars) is bytes else ''
                fixture.spawned[0].stdout.put({'method': 'item/started', 'params': {
                    'threadId': thread_id, 'turnId': turn_id,
                    'item': {'id': approval_id, 'type': 'dynamicToolCall', 'status': 'inProgress',
                             'tool': 'finite_poll', 'namespace': None,
                             'arguments': {'commandCallId': item_id, 'chars': text}}}})
                self.assertTrue(self._wait(lambda: key in factory.server._items, 2))
            return original_reserve(chars, thread_id=thread_id, turn_id=turn_id,
                                    item_id=item_id, approval_id=approval_id, deadline=deadline)

        gate_patch = patch.object(gate, 'reserve', observed_reserve)
        gate_patch.start()
        self.addCleanup(gate_patch.stop)
        self.assertIs(tool.birth.child.stdout, stream)
        self.assertIs(tool.birth.child.stdin, tool.process.stdin)
        self.assertEqual(factory.server.finite_input.output_fd, stream.fileno())
        return case, factory, tool, stream, read, case.poll_release, result

    def test_exact_empty_poll_reads_real_tool_pipe_and_preserves_useful_n1(self):
        case, factory, tool, stream, read, release, result = self._active()
        stream.put('EXAMPLE tool progress\n')
        gate = factory.server.finite_input
        self.assertTrue(factory.adapter._effective_boundary_armed, 'original send boundary not armed')
        self.assertEqual(factory.server._profile_response,
                         factory.adapter._effective_boundary['thread_response'], 'profile readback differs')
        ticket = gate.reserve(b'', thread_id=case.scenario.thread_id,
            turn_id=case.scenario.turn_id, item_id='EXAMPLE-command-call',
            approval_id='EXAMPLE-poll-1', deadline=time.monotonic() + 2)
        self.assertEqual(gate.poll(ticket), {'stdout': b'EXAMPLE tool progress\n',
                                             'stdin_bytes': b'', 'running': True})
        with self.assertRaises(finite.FiniteInputError):
            gate.poll(ticket)
        with self.assertRaises(BlockingIOError):
            os.read(read, 1)
        if not tool.contained:
            tool.terminate()
        release.set()
        self.assertTrue(self._wait(lambda: bool(result), 8))
        self.assertIsInstance(result[0], dict)
        self.assertEqual(result[0]['attempt']['outcome'], 'completed')
        self.assertIsNotNone(factory.issued_artifact())

    def test_nonempty_and_wrong_context_never_write_to_real_tool_stdin(self):
        case, factory, tool, _stream, read, release, result = self._active()
        gate = factory.server.finite_input
        for index, chars in enumerate((b'x', b'\x00', b'\xff')):
            with self.subTest(chars=chars), self.assertRaises(finite.FiniteInputError):
                gate.reserve(chars, thread_id=case.scenario.thread_id,
                    turn_id=case.scenario.turn_id, item_id='EXAMPLE-command-call',
                    approval_id='EXAMPLE-deny-' + str(index), deadline=time.monotonic() + 2)
        with self.assertRaises(finite.FiniteInputError):
            gate.reserve(b'', thread_id='EXAMPLE-old-thread', turn_id=case.scenario.turn_id,
                item_id='EXAMPLE-command-call', approval_id='EXAMPLE-wrong', deadline=time.monotonic() + 2)
        with self.assertRaises(BlockingIOError):
            os.read(read, 1)
        tool.terminate()
        release.set()
        self.assertTrue(self._wait(lambda: bool(result), 8))

    def test_missing_item_and_cancel_consume_poll_authority(self):
        case, factory, tool, _stream, read, release, result = self._active()
        gate = factory.server.finite_input
        identity = dict(thread_id=case.scenario.thread_id, turn_id=case.scenario.turn_id,
                        item_id='EXAMPLE-command-call', deadline=time.monotonic() + 2)
        original = factory.server._items.pop((identity['thread_id'], identity['turn_id'], identity['item_id']))
        with self.assertRaises(finite.FiniteInputError):
            gate.reserve(b'', approval_id='EXAMPLE-missing-item', **identity)
        factory.server._items[(identity['thread_id'], identity['turn_id'], identity['item_id'])] = original
        # The rejected call consumed time and identity; the next admission
        # needs its own current deadline before cancellation is tested.
        identity['deadline'] = time.monotonic() + 2
        ticket = gate.reserve(b'', approval_id='EXAMPLE-stale-item', **identity)
        factory.server.requests.cancel_turn(identity['thread_id'], identity['turn_id'])
        with self.assertRaises(finite.FiniteInputError):
            gate.poll(ticket)
        with self.assertRaises(BlockingIOError):
            os.read(read, 1)
        tool.terminate()
        release.set()
        self.assertTrue(self._wait(lambda: bool(result), 8))

    def test_original_terminal_and_transport_failure_revoke_before_poll(self):
        case, factory, tool, _stream, read, release, result = self._active()
        gate = factory.server.finite_input
        ticket = gate.reserve(b'', thread_id=case.scenario.thread_id,
            turn_id=case.scenario.turn_id, item_id='EXAMPLE-command-call',
            approval_id='EXAMPLE-terminal', deadline=time.monotonic() + 2)
        fixture_process = self.fixture.spawned[0]
        fixture_process.stdout.put({'method': 'turn/completed', 'params': {
            'threadId': case.scenario.thread_id,
            'turn': {'id': case.scenario.turn_id, 'status': 'completed'}}})
        self.assertTrue(self._wait(lambda: (case.scenario.thread_id, case.scenario.turn_id)
                                   in factory.server.requests.terminals, 2))
        with self.assertRaises(finite.FiniteInputError):
            gate.poll(ticket)
        factory.server._fail_transport(RuntimeError('EXAMPLE original control failure'))
        self.assertEqual(gate.state, 'revoked')
        self.assertTrue(tool._termination_finished.wait(8),
                        'the off-reader owned cleanup must finish')
        self.assertTrue(tool.contained and tool.termination_recorded)
        with self.assertRaises(BlockingIOError):
            os.read(read, 1)
        release.set()
        self.assertTrue(self._wait(lambda: bool(result), 8))
        self.assertIsNone(factory.token)

    def test_failed_owned_gate_close_latches_shared_fault_before_revoked_state(self):
        case, factory, tool, _stream, read, release, result = self._active()
        gate = factory.server.finite_input
        observed = []
        original = gate.lifecycle.authority_revoke

        def observe(kind, scope=None):
            if kind == 'fault':
                observed.append(gate.state)
            return original(kind, scope)

        primary = RuntimeError('EXAMPLE failed owned tool gate')
        with patch.object(gate.lifecycle, 'authority_revoke', observe):
            gate.close(primary)
        self.assertIn('active', observed)
        self.assertTrue(gate.lifecycle.authority_global_revoked)
        self.assertEqual(gate.state, 'revoked')
        with self.assertRaises(finite.FiniteInputError):
            gate.reserve(b'', thread_id=case.scenario.thread_id,
                turn_id=case.scenario.turn_id, item_id='EXAMPLE-command-call',
                approval_id='EXAMPLE-after-failed-close', deadline=time.monotonic() + 2)
        with self.assertRaises(BlockingIOError):
            os.read(read, 1)
        factory.server._fail_transport(primary)
        release.set()
        self.assertTrue(self._wait(lambda: bool(result), 8))
        self.assertIsInstance(result[0], BaseException)
        attempt = self.fixture.attempt(case)
        self.assertEqual(attempt['outcome'], 'unknown')
        self.assertEqual(attempt['charge'], attempt['amount'])

    def test_blocked_off_reader_cleanup_has_pending_then_contained_postcondition(self):
        case, factory, tool, _stream, _read, release_turn, result = self._active()
        gate = factory.server.finite_input
        entered, release_cleanup = threading.Event(), threading.Event()
        original = gate.close

        def blocked_close(failure=None):
            entered.set()
            release_cleanup.wait(5)
            return original(failure)

        self.addCleanup(release_cleanup.set)
        self.addCleanup(release_turn.set)
        self.assertEqual(gate.cleanup_phase(), 'owned-active')
        with patch.object(gate, 'close', blocked_close):
            factory.server._fail_transport(RuntimeError('EXAMPLE original transport fault'))
            self.assertTrue(entered.wait(2))
            self.assertEqual(gate.cleanup_phase(), 'cleanup-pending')
            self.assertFalse(tool.contained)
            with self.assertRaises(family.runtime.AppServerError):
                factory.server._require_healthy()
            release_cleanup.set()
            self.assertTrue(self._wait(lambda: gate.cleanup_phase() == 'contained', 8))
        release_turn.set()
        self.assertTrue(self._wait(lambda: bool(result), 8))
        attempt = self.fixture.attempt(case)
        self.assertEqual(attempt['outcome'], 'unknown')
        self.assertEqual(attempt['charge'], attempt['amount'])

    def test_unconfirmed_off_reader_cleanup_reports_unknown_without_qualification(self):
        case, factory, tool, _stream, _read, release_turn, result = self._active()
        gate = factory.server.finite_input
        self.addCleanup(release_turn.set)
        with patch.object(tool, 'cleanup_failure', lambda _failure: None):
            factory.server._fail_transport(RuntimeError('EXAMPLE original cleanup uncertainty'))
            self.assertTrue(self._wait(lambda: gate.cleanup_phase() == 'unknown', 8))
            self.assertFalse(tool.contained)
            with self.assertRaises(family.runtime.AppServerError):
                factory.server._require_healthy()
        release_turn.set()
        self.assertTrue(self._wait(lambda: bool(result), 8))
        attempt = self.fixture.attempt(case)
        self.assertEqual(attempt['outcome'], 'unknown')
        self.assertEqual(attempt['charge'], attempt['amount'])

    def test_terminal_during_poll_intent_record_cannot_issue_ticket(self):
        case, factory, tool, _stream, read, release, result = self._active()
        entered, resume = threading.Event(), threading.Event()
        original_record = factory.record
        outcome, persisted = [], []

        def blocked(stage, observation):
            if stage == 'finite-poll-intent':
                entered.set()
                resume.wait(5)
            value = original_record(stage, observation)
            persisted.append(stage)
            return value

        def reserve():
            try:
                outcome.append(factory.server.finite_input.reserve(b'',
                    thread_id=case.scenario.thread_id, turn_id=case.scenario.turn_id,
                    item_id='EXAMPLE-command-call', approval_id='EXAMPLE-racing',
                    deadline=time.monotonic() + 3))
            except BaseException as error:
                outcome.append(error)

        with patch.object(factory, 'record', blocked):
            thread = threading.Thread(target=reserve, daemon=True)
            thread.start()
            try:
                self.assertTrue(entered.wait(3))
                self.fixture.spawned[0].stdout.put({'method': 'turn/completed', 'params': {
                    'threadId': case.scenario.thread_id,
                    'turn': {'id': case.scenario.turn_id, 'status': 'completed'}}})
                self.assertTrue(self._wait(lambda: (case.scenario.thread_id, case.scenario.turn_id)
                    in factory.server.requests.terminals, 2))
            finally:
                resume.set()
                thread.join(5)
        self.assertEqual(len(outcome), 1)
        self.assertIsInstance(outcome[0], finite.FiniteInputError)
        # The reservation preceded terminal, so its late durable history is
        # paired with an abort. Neither record can issue a ticket or read.
        self.assertEqual(persisted.count('finite-poll-intent'), 1)
        self.assertEqual(persisted.count('finite-poll-intent-aborted'), 1)
        records = [json.loads(path.read_bytes()) for path in
                   (factory.records / 'transport-observations').iterdir()]
        reserved = next(row['observation'] for row in records
                        if row['stage'] == 'finite-poll-intent'
                        and row['observation']['approval_id'] == 'EXAMPLE-racing')
        aborted = next(row['observation'] for row in records
                       if row['stage'] == 'finite-poll-intent-aborted'
                       and row['observation']['call'] == 'EXAMPLE-racing')
        self.assertEqual(reserved['intent_state'], 'reserved')
        self.assertEqual(reserved['reservation_generation'],
                         aborted['reservation_generation'])
        self.assertLess(reserved['reservation_lifecycle_generation'],
                        aborted['abort_lifecycle_generation'])
        self.assertFalse(factory.server.finite_input.intent_reservations)
        self.assertEqual(factory.server.finite_input.output_bytes_seen, len(b'EXAMPLE finite command output\n'))
        with self.assertRaises(BlockingIOError):
            os.read(read, 1)
        tool.terminate()
        release.set()
        self.assertTrue(self._wait(lambda: bool(result), 8))

    def test_terminal_during_preintent_authority_callout_admits_no_poll_record(self):
        """A late callback cannot start an intent."""
        case, factory, tool, _stream, read, release, result = self._active()
        entered, resume = threading.Event(), threading.Event()
        original_effect, original_record = factory.require_effect, factory.record
        persisted, outcome = [], []
        reserver = None

        def blocked_effect():
            original_effect()
            if threading.current_thread() is reserver:
                entered.set()
                resume.wait(4)

        def observed_record(stage, observation):
            value = original_record(stage, observation)
            persisted.append(stage)
            return value

        def reserve():
            try:
                outcome.append(factory.server.finite_input.reserve(b'',
                    thread_id=case.scenario.thread_id, turn_id=case.scenario.turn_id,
                    item_id='EXAMPLE-command-call', approval_id='EXAMPLE-preintent',
                    deadline=time.monotonic() + 3))
            except BaseException as error:
                outcome.append(error)

        with patch.object(factory, 'require_effect', blocked_effect), patch.object(
                factory, 'record', observed_record):
            reserver = threading.Thread(target=reserve, daemon=True)
            reserver.start()
            try:
                self.assertTrue(entered.wait(3))
                self.fixture.spawned[0].stdout.put({'method': 'turn/completed', 'params': {
                    'threadId': case.scenario.thread_id,
                    'turn': {'id': case.scenario.turn_id, 'status': 'completed'}}})
                self.assertTrue(self._wait(lambda: factory.server.finite_input.lifecycle.phase
                                           == 'terminal', 2))
            finally:
                resume.set()
                reserver.join(5)
        self.assertEqual(len(outcome), 1)
        self.assertIsInstance(outcome[0], finite.FiniteInputError)
        self.assertNotIn('finite-poll-intent', persisted)
        self.assertNotIn('finite-poll-intent-aborted', persisted)
        self.assertFalse(factory.server.finite_input.intent_reservations)
        with self.assertRaises(BlockingIOError):
            os.read(read, 1)
        tool.settle_termination()
        self.assertTrue(tool._termination_finished.is_set())
        self.assertTrue(tool.contained and tool.termination_recorded)
        release.set()
        self.assertTrue(self._wait(lambda: bool(result), 8))

    def _denied_physical_read_schedule(self, event):
        """Revocation during readiness consumes zero bytes."""
        case, factory, tool, stream, read, release, result = self._active()
        gate = factory.server.finite_input
        ticket_deadline = time.monotonic() + (1 if event == 'deadline' else 3)
        ticket = gate.reserve(b'', thread_id=case.scenario.thread_id,
            turn_id=case.scenario.turn_id, item_id='EXAMPLE-command-call',
            approval_id='EXAMPLE-read-race-' + event.replace('/', '-'),
            deadline=ticket_deadline)
        stream.put('EXAMPLE unread after revocation')
        before_bytes = gate.output_bytes_seen
        before_success = sum(reply.get('result', {}).get('success') is True
                             for reply in self.fixture.spawned[0].replies)
        entered, resume = threading.Event(), threading.Event()
        original_select, original_read = finite.select.select, os.read
        physical_reads, outcome = [], []
        terminal = event in {'turn/completed', 'turn/failed', 'turn/interrupted',
                             'thread/closed', 'thread/archived'}
        termination_entered, finish_termination = threading.Event(), threading.Event()
        termination_calls = []
        original_terminate = tool.controller.terminate

        def paused_terminate(*args, **kwargs):
            termination_calls.append(threading.current_thread())
            termination_entered.set()
            if not finish_termination.wait(8):
                raise AssertionError('EXAMPLE owned termination was not released')
            return original_terminate(*args, **kwargs)

        def selected(fd):
            try:
                return gate._pipe_stat(fd) == gate.output_stat
            except (OSError, ValueError, finite.FiniteInputError):
                return False

        def paused(reads, writes, errors, timeout=None):
            if len(reads) == 1 and selected(reads[0]) and threading.current_thread() is worker:
                entered.set()
                resume.wait(4)
            return original_select(reads, writes, errors, timeout)

        def counted(fd, count):
            if selected(fd):
                physical_reads.append(count)
            return original_read(fd, count)

        def poll():
            try:
                outcome.append(gate.poll(ticket, timeout=.1))
            except BaseException as error:
                outcome.append(error)

        termination_patch = (patch.object(tool.controller, 'terminate', paused_terminate)
                             if terminal else nullcontext())
        with termination_patch, patch.object(finite.select, 'select', paused), patch.object(finite.os, 'read', counted):
            worker = threading.Thread(target=poll, daemon=True)
            worker.start()
            try:
                self.assertTrue(entered.wait(3), event)
                if terminal:
                    params = {'threadId': case.scenario.thread_id}
                    if event.startswith('turn/'):
                        params['turn'] = {'id': case.scenario.turn_id,
                                          'status': event.split('/')[1]}
                    self.fixture.spawned[0].stdout.put({'method': event, 'params': params})
                    self.assertTrue(self._wait(lambda: gate.lifecycle.phase == 'terminal', 2), event)
                    self.assertTrue(termination_entered.wait(5), event)
                    self.assertTrue(tool._ending, event)
                    self.assertFalse(tool.contained, event)
                    self.assertFalse(tool._termination_finished.is_set(), event)
                    self.assertEqual(gate.cleanup_phase(), 'cleanup-pending', event)
                elif event == 'read-projection':
                    # The original correlated request projection observer supplies
                    # negative evidence; the separate original caller test
                    # exercises the full thread/read RPC and host wakeup.
                    factory.server.requests.observe_response({'result': {'thread': {
                        'id': case.scenario.thread_id, 'turns': [{
                            'id': case.scenario.turn_id, 'status': 'completed', 'items': []}]}}})
                    self.assertIn((case.scenario.thread_id, case.scenario.turn_id),
                                  factory.server.requests.terminals)
                elif event == 'trusted-terminal':
                    factory.server.requests.observe_trusted_terminal(
                        case.scenario.thread_id, case.scenario.turn_id,
                        {'terminal_event': {'status': 'completed'}})
                elif event == 'cancellation':
                    factory.server.requests.cancel_turn(case.scenario.thread_id,
                                                        case.scenario.turn_id)
                elif event == 'fault':
                    factory.server._fail_transport(RuntimeError('EXAMPLE read race fault'))
                elif event == 'close':
                    gate.close()
                elif event == 'deadline':
                    time.sleep(max(0, ticket_deadline - time.monotonic()) + .02)
                else:
                    self.fail(event)
            finally:
                resume.set()
                release.set()
                finish_termination.set()
                worker.join(5)
        if terminal:
            self.assertTrue(tool._termination_finished.wait(8), event)
            self.assertEqual(len(termination_calls), 1, event)
            self.assertTrue(tool.contained, event)
        self.assertEqual(len(outcome), 1, event)
        self.assertIsInstance(outcome[0], finite.FiniteInputError, event)
        self.assertEqual(physical_reads, [], event)
        self.assertEqual(gate.output_bytes_seen, before_bytes, event)
        self.assertEqual(sum(reply.get('result', {}).get('success') is True
                             for reply in self.fixture.spawned[0].replies), before_success, event)
        with self.assertRaises(BlockingIOError):
            os.read(read, 1)
        self.assertTrue(self._wait(lambda: bool(result), 8), event)
        self.assertTrue(tool.contained, event)
        self.assertEqual(gate.cleanup_phase(), 'contained', event)
        attempt = self.fixture.attempt(case)
        self.assertEqual(attempt['outcome'], 'unknown', event)
        self.assertEqual(attempt['charge'], attempt['amount'], event)

    def _concurrent_cleanup_owner_schedule(self, *, uncertain):
        case, factory, tool, _stream, read, release_turn, result = self._active()
        gate = factory.server.finite_input
        primary = RuntimeError('EXAMPLE original transport failure')
        entered, release_owner, waiter_entered = (threading.Event() for _ in range(3))
        owner = None
        controller_calls = []
        original_terminate = tool.controller.terminate
        original_settle = tool.settle_termination
        before_bytes = gate.output_bytes_seen
        before_success = sum(reply.get('result', {}).get('success') is True
                             for reply in self.fixture.spawned[0].replies)

        def paused_terminate(*args, **kwargs):
            controller_calls.append(1)
            entered.set()
            if not release_owner.wait(8):
                raise AssertionError('EXAMPLE termination owner did not resume')
            if uncertain:
                raise RuntimeError('EXAMPLE same-handle termination uncertain')
            return original_terminate(*args, **kwargs)

        def observed_settle():
            if threading.current_thread() is not owner:
                waiter_entered.set()
            return original_settle()

        with patch.object(tool.controller, 'terminate', paused_terminate), patch.object(
                tool, 'settle_termination', observed_settle):
            owner = threading.Thread(target=tool.cleanup_failure, args=(primary,), daemon=True)
            owner.start()
            try:
                self.assertTrue(entered.wait(5))
                self.assertTrue(tool._ending)
                self.assertFalse(tool._termination_finished.is_set())
                factory.server._fail_transport(primary)
                self.assertTrue(waiter_entered.wait(5))
                self.assertEqual(gate.cleanup_phase(), 'cleanup-pending')
                self.assertFalse(gate.cleanup_attempted)
                self.assertFalse(tool.contained)
                with self.assertRaises(BlockingIOError):
                    os.read(read, 1)
            finally:
                release_owner.set()
                release_turn.set()
                owner.join(8)
        self.assertFalse(owner.is_alive())
        self.assertTrue(tool._termination_finished.wait(8))
        self.assertEqual(len(controller_calls), 1)
        expected = 'unknown' if uncertain else 'contained'
        self.assertTrue(self._wait(lambda: gate.cleanup_phase() == expected, 8))
        self.assertIs(tool.factory.server.transport_failure, primary)
        self.assertEqual(tool.contained, not uncertain)
        self.assertEqual(gate.output_bytes_seen, before_bytes)
        self.assertEqual(sum(reply.get('result', {}).get('success') is True
                             for reply in self.fixture.spawned[0].replies), before_success)
        if uncertain:
            self.assertIsInstance(tool._termination_error, RuntimeError)
            self.assertTrue(any('Owned containment cleanup failed' in note
                                for note in primary.__notes__))
        else:
            self.assertIsNone(tool._termination_error)
        with self.assertRaises(family.runtime.native.OfflineHostError):
            tool.terminate()
        self.assertTrue(self._wait(lambda: bool(result), 8))
        attempt = self.fixture.attempt(case)
        self.assertEqual(attempt['outcome'], 'unknown')
        self.assertEqual(attempt['charge'], attempt['amount'])

    def test_inflight_cleanup_owner_is_joined_once_after_transport_fault(self):
        for uncertain in (False, True):
            with self.subTest(uncertain=uncertain):
                fixture = FiniteInputTests(methodName='runTest')
                fixture.setUp()
                try:
                    fixture._concurrent_cleanup_owner_schedule(uncertain=uncertain)
                finally:
                    family.cleanup_helper(self, fixture)
        # The finalopsv3 pre-full selector also witnesses the newly reproduced
        # observer-result boundary, with both original caller styles.
        for gate_owner in (True, False):
            with self.subTest(gate_owner=gate_owner):
                fixture = FiniteInputTests(methodName='runTest')
                fixture.setUp()
                try:
                    fixture._late_owner_observation(gate_owner=gate_owner)
                finally:
                    family.cleanup_helper(self, fixture)

        # The final peer wait has its own ten-second failure boundary. Keep
        # this original-factory schedule in the approved pre-full selector.
        fixture = FiniteInputTests(methodName='runTest')
        fixture.setUp()
        try:
            fixture._final_peer_wait_expiry_schedule()
        finally:
            family.cleanup_helper(self, fixture)

        # Gate reservations are visible before either observer publishes.
        # Exercise both possible completion orders without another ten-second
        # sleep; _late_owner_observation above keeps the real timeout edge.
        for reverse in (False, True):
            with self.subTest(reverse_publication=reverse):
                fixture = FiniteInputTests(methodName='runTest')
                fixture.setUp()
                try:
                    fixture._publication_order_schedule(reverse=reverse)
                finally:
                    family.cleanup_helper(self, fixture)

    def _publication_order_schedule(self, *, reverse):
        case, factory, tool, _stream, read, release_turn, result = self._active()
        gate = factory.server.finite_input
        primary = RuntimeError('EXAMPLE original publication-order fault')
        owner_entered, owner_release = threading.Event(), threading.Event()
        observer_at_wait, timeout_release = threading.Event(), threading.Event()
        note_entered, note_release = threading.Event(), threading.Event()
        calls, errors = [], []
        second_errors = []
        second_waiting, second_done = threading.Event(), threading.Event()
        second = None
        original_effect = tool.controller.terminate
        original_wait = tool._termination_finished.wait
        original_note = family.runtime.admission.ledger_api.add_failure_note
        original_await = gate._await_cleanup_classification

        def observed_await(deadline):
            second_waiting.set()
            return original_await(deadline)

        def second_close():
            try:
                gate.close()
            except BaseException as error:
                second_errors.append(error)
            finally:
                second_done.set()

        def paused_effect(*args, **kwargs):
            calls.append(1)
            owner_entered.set()
            if not owner_release.wait(6):
                raise AssertionError('EXAMPLE owner release missing')
            return original_effect(*args, **kwargs)

        def controlled_wait(timeout=None):
            if threading.current_thread() is observer and timeout == 10:
                observer_at_wait.set()
                if not timeout_release.wait(6):
                    raise AssertionError('EXAMPLE observer result release missing')
                return False
            return original_wait(timeout)

        def held_note(failure, note):
            if failure is primary:
                note_entered.set()
                if not note_release.wait(6):
                    raise AssertionError('EXAMPLE note release missing')
            return original_note(failure, note)

        def direct_owner():
            try:
                tool.terminate()
            except BaseException as error:
                errors.append(error)

        def first_close():
            try:
                gate.close(primary)
            except BaseException as error:
                errors.append(error)

        self.addCleanup(owner_release.set)
        self.addCleanup(timeout_release.set)
        self.addCleanup(note_release.set)
        self.addCleanup(release_turn.set)
        with patch.object(tool.controller, 'terminate', paused_effect), patch.object(
                tool._termination_finished, 'wait', controlled_wait), patch.object(
                family.runtime.admission.ledger_api, 'add_failure_note', held_note), patch.object(
                gate, '_await_cleanup_classification', observed_await):
            owner = threading.Thread(target=direct_owner, daemon=True)
            observer = threading.Thread(target=first_close, daemon=True)
            owner.start()
            self.assertTrue(owner_entered.wait(3))
            observer.start()
            try:
                self.assertTrue(observer_at_wait.wait(3))
                if reverse:
                    owner_release.set()
                    owner.join(5)
                    self.assertEqual(gate.cleanup_phase(), 'cleanup-pending')
                    self.assertEqual(gate.lifecycle.cleanup, 'pending')
                    second = threading.Thread(target=second_close, daemon=True)
                    second.start()
                    self.assertTrue(second_waiting.wait(3))
                    self.assertFalse(second_done.is_set())
                    self.assertEqual(gate.cleanup_phase(), 'cleanup-pending')
                    timeout_release.set()
                    self.assertTrue(note_entered.wait(3))
                    self.assertTrue(second_done.wait(5))
                    self.assertEqual(len(second_errors), 1)
                    self.assertIsInstance(second_errors[0], finite.FiniteInputError)
                else:
                    timeout_release.set()
                    self.assertTrue(note_entered.wait(3))
                    owner_release.set()
                    owner.join(5)
                    with self.assertRaises(finite.FiniteInputError):
                        gate.close()
                self.assertEqual(gate.cleanup_phase(), 'unknown')
                self.assertEqual(gate.lifecycle.cleanup, 'unknown')
                self.assertTrue(gate.cleanup_unresolved)
                self.assertIn('timeout',
                              [item.kind for item in gate.cleanup_observations])
                with self.assertRaises(family.runtime.AppServerError):
                    factory.server._require_healthy()
                self.assertFalse(observer.is_alive() and note_release.is_set())
            finally:
                owner_release.set()
                timeout_release.set()
                note_release.set()
                release_turn.set()
                owner.join(5)
                observer.join(5)
                if second is not None:
                    second.join(5)
        self.assertFalse(owner.is_alive())
        self.assertFalse(observer.is_alive())
        if second is not None:
            self.assertFalse(second.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(calls, [1])
        self.assertTrue(tool.contained)
        self.assertTrue(tool.termination_recorded)
        self.assertEqual(gate.cleanup_phase(), 'unknown')
        self.assertEqual(gate.lifecycle.cleanup, 'unknown')
        with self.assertRaises(BlockingIOError):
            os.read(read, 1)
        self.assertTrue(case.result_done.wait(8))
        attempt = self.fixture.attempt(case)
        self.assertEqual(attempt['outcome'], 'unknown')
        self.assertEqual(attempt['charge'], attempt['amount'])
        self.assertTrue(any('Owned containment cleanup failed' in note
                            for note in primary.__notes__))

    def _final_peer_wait_expiry_schedule(self):
        case, factory, tool, _stream, read, release_turn, result = self._active()
        gate = factory.server.finite_input
        owner_entered, owner_release = threading.Event(), threading.Event()
        peer_reserved, peer_release = threading.Event(), threading.Event()
        first_done, peer_done = threading.Event(), threading.Event()
        errors, calls = {}, []
        original_effect = tool.controller.terminate
        original_settle = tool.settle_termination

        def effect(*args, **kwargs):
            calls.append(1)
            owner_entered.set()
            if not owner_release.wait(8):
                raise AssertionError('EXAMPLE owner release missing')
            return original_effect(*args, **kwargs)

        def settle():
            if threading.current_thread() is peer:
                peer_reserved.set()
                if not peer_release.wait(15):
                    raise AssertionError('EXAMPLE peer release missing')
            return original_settle()

        def close(name, done):
            try:
                gate.close()
            except BaseException as error:
                errors[name] = error
            finally:
                done.set()

        first = threading.Thread(target=close, args=('first', first_done), daemon=True)
        peer = threading.Thread(target=close, args=('peer', peer_done), daemon=True)
        self.addCleanup(owner_release.set)
        self.addCleanup(peer_release.set)
        self.addCleanup(release_turn.set)
        with patch.object(tool.controller, 'terminate', effect), patch.object(
                tool, 'settle_termination', settle):
            first.start()
            self.assertTrue(owner_entered.wait(3))
            peer.start()
            try:
                self.assertTrue(peer_reserved.wait(3))
                owner_release.set()
                self.assertTrue(first_done.wait(12))
                self.assertIsInstance(errors.get('first'), finite.FiniteInputError)
                self.assertEqual(gate.cleanup_phase(), 'unknown')
                self.assertEqual(gate.lifecycle.cleanup, 'unknown')
                self.assertTrue(tool.contained)
                self.assertTrue(tool.termination_recorded)
                self.assertIn('timeout', [item.kind for item in gate.cleanup_observations])
                with self.assertRaises(family.runtime.AppServerError):
                    factory.server._require_healthy()
            finally:
                owner_release.set()
                peer_release.set()
                release_turn.set()
                first.join(5)
                peer.join(5)
        self.assertFalse(first.is_alive())
        self.assertFalse(peer.is_alive())
        self.assertTrue(peer_done.is_set())
        self.assertEqual(calls, [1])
        self.assertEqual(gate.cleanup_phase(), 'unknown')
        self.assertEqual(gate.lifecycle.cleanup, 'unknown')
        self.assertTrue(tool.contained)
        self.assertTrue(tool.termination_recorded)
        with self.assertRaises(BlockingIOError):
            os.read(read, 1)
        self.assertTrue(case.result_done.wait(8))
        attempt = self.fixture.attempt(case)
        self.assertEqual(attempt['outcome'], 'unknown')
        self.assertEqual(attempt['charge'], attempt['amount'])

    def test_transport_observer_result_blocks_healthy_consumer_before_note_finishes(self):
        case, factory, tool, _stream, _read, release_turn, result = self._active()
        server = factory.server
        lifetime = server.lifetime
        primary = RuntimeError('EXAMPLE original transport observer fault')
        owner_entered, owner_release = threading.Event(), threading.Event()
        note_entered, note_release = threading.Event(), threading.Event()
        original_effect = lifetime.controller.terminate
        original_wait = lifetime._termination_finished.wait
        original_note = family.runtime.admission.ledger_api.add_failure_note
        calls, errors = [], []

        def paused_effect(*args, **kwargs):
            calls.append(1)
            owner_entered.set()
            if not owner_release.wait(6):
                raise AssertionError('EXAMPLE transport owner release missing')
            return original_effect(*args, **kwargs)

        def timed_out_wait(timeout=None):
            if threading.current_thread() is observer and timeout == 10:
                return False
            return original_wait(timeout)

        def held_note(failure, note):
            if failure is primary:
                note_entered.set()
                if not note_release.wait(6):
                    raise AssertionError('EXAMPLE transport note release missing')
            return original_note(failure, note)

        def owner_effect():
            try:
                lifetime.terminate()
            except BaseException as error:
                errors.append(error)

        def observe_failure():
            try:
                lifetime.cleanup_failure(primary)
            except BaseException as error:
                errors.append(error)

        self.addCleanup(owner_release.set)
        self.addCleanup(note_release.set)
        self.addCleanup(release_turn.set)
        with patch.object(lifetime.controller, 'terminate', paused_effect), patch.object(
                lifetime._termination_finished, 'wait', timed_out_wait), patch.object(
                family.runtime.admission.ledger_api, 'add_failure_note', held_note):
            owner = threading.Thread(target=owner_effect, daemon=True)
            observer = threading.Thread(target=observe_failure, daemon=True)
            owner.start()
            self.assertTrue(owner_entered.wait(3))
            observer.start()
            try:
                self.assertTrue(note_entered.wait(3))
                observation = lifetime.observation_snapshot()
                self.assertTrue(observation[2])
                self.assertFalse(observation[3])
                # Isolate the direct transport observer guard from a separate
                # reader fault that may be published after child termination.
                with patch.object(server, 'transport_failure', None):
                    with self.assertRaises(family.runtime.AppServerError) as raised:
                        server._require_healthy()
                self.assertEqual(str(raised.exception),
                                 'registered-transport-cleanup-unresolved')
                self.assertFalse(observer.is_alive() and note_release.is_set())
            finally:
                owner_release.set()
                note_release.set()
                release_turn.set()
                owner.join(5)
                observer.join(5)
        self.assertFalse(owner.is_alive())
        self.assertFalse(observer.is_alive())
        self.assertEqual(calls, [1])
        self.assertIn('timeout', [item.kind for item in lifetime.observation_snapshot()[0]])
        self.assertIsNone(factory.token)
        self.assertTrue(case.result_done.wait(8))
        attempt = self.fixture.attempt(case)
        self.assertEqual(attempt['outcome'], 'unknown')
        self.assertEqual(attempt['charge'], attempt['amount'])

    def test_failed_note_and_add_note_keep_primary_and_observer_uncertainty(self):
        case, factory, tool, _stream, read, release_turn, result = self._active()
        gate = factory.server.finite_input
        owner_entered, owner_release = threading.Event(), threading.Event()
        original_effect = tool.controller.terminate
        original_wait = tool._termination_finished.wait
        calls, errors = [], []

        class FailedNote(RuntimeError):
            def add_note(self, _message):
                raise OSError('EXAMPLE secondary note also failed')

        primary = FailedNote('EXAMPLE original failure')

        def paused_effect(*args, **kwargs):
            calls.append(1)
            owner_entered.set()
            if not owner_release.wait(6):
                raise AssertionError('EXAMPLE owner release missing')
            return original_effect(*args, **kwargs)

        def failed_wait(timeout=None):
            if threading.current_thread() is threading.main_thread() and timeout == 10:
                return False
            return original_wait(timeout)

        def direct_owner():
            try:
                tool.terminate()
            except BaseException as error:
                errors.append(error)

        self.addCleanup(owner_release.set)
        self.addCleanup(release_turn.set)
        with patch.object(tool.controller, 'terminate', paused_effect), patch.object(
                tool._termination_finished, 'wait', failed_wait), patch.object(
                family.runtime.admission.ledger_api, 'add_failure_note',
                side_effect=OSError('EXAMPLE note persistence failed')):
            owner = threading.Thread(target=direct_owner, daemon=True)
            owner.start()
            try:
                self.assertTrue(owner_entered.wait(3))
                gate.close(primary)
                self.assertEqual(gate.cleanup_phase(), 'unknown')
                self.assertEqual(gate.lifecycle.cleanup, 'unknown')
            finally:
                owner_release.set()
                release_turn.set()
                owner.join(5)
        self.assertFalse(owner.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(calls, [1])
        self.assertTrue(tool.contained)
        self.assertTrue(tool.termination_recorded)
        self.assertIn('timeout', [item.kind for item in gate.cleanup_observations])
        with self.assertRaises(finite.FiniteInputError):
            gate.close()
        with self.assertRaises(family.runtime.AppServerError):
            factory.server._require_healthy()
        with self.assertRaises(BlockingIOError):
            os.read(read, 1)
        self.assertTrue(case.result_done.wait(8))
        attempt = self.fixture.attempt(case)
        self.assertEqual(attempt['outcome'], 'unknown')
        self.assertEqual(attempt['charge'], attempt['amount'])

    def _late_owner_observation(self, *, gate_owner):
        case, factory, tool, _stream, read, release_turn, result = self._active()
        gate = factory.server.finite_input
        primary = RuntimeError('EXAMPLE original observer-edge fault')
        owner_entered, release_owner = threading.Event(), threading.Event()
        observer_entered, observer_done = threading.Event(), threading.Event()
        calls, errors = [], []
        original_effect = tool.controller.terminate
        original_wait = tool._termination_finished.wait
        initial_bytes = gate.output_bytes_seen

        def paused_effect(*args, **kwargs):
            calls.append(1)
            owner_entered.set()
            if not release_owner.wait(18):
                raise AssertionError('EXAMPLE owner release was missing')
            return original_effect(*args, **kwargs)

        def observed_timeout(timeout=None):
            if timeout == 10 and not observer_entered.is_set():
                observer_entered.set()
                # The gate-owner case uses the real ten-second Event.wait edge.
                # The direct-owner case fixes the same result with a barrier.
                if gate_owner:
                    self.assertFalse(original_wait(timeout))
                release_owner.set()
                self.assertTrue(original_wait(8))
                return False
            return original_wait(timeout)

        def direct_owner():
            try:
                tool.terminate()
            except BaseException as error:
                errors.append(error)

        def observing_close():
            try:
                gate.close(primary if gate_owner else None)
            except BaseException as error:
                errors.append(error)
            finally:
                observer_done.set()

        self.addCleanup(release_owner.set)
        self.addCleanup(release_turn.set)
        with patch.object(tool.controller, 'terminate', paused_effect), patch.object(
                tool._termination_finished, 'wait', observed_timeout):
            if gate_owner:
                factory.server._fail_transport(primary)
            else:
                owner = threading.Thread(target=direct_owner, daemon=True)
                owner.start()
            try:
                self.assertTrue(owner_entered.wait(5))
                closer = threading.Thread(target=observing_close, daemon=True)
                closer.start()
                self.assertTrue(observer_entered.wait(5))
                self.assertTrue(observer_done.wait(16))
            finally:
                release_owner.set()
                release_turn.set()
            closer.join(2)
            if not gate_owner:
                owner.join(2)
        self.assertFalse(closer.is_alive())
        self.assertEqual(calls, [1])
        self.assertTrue(tool._termination_finished.is_set())
        self.assertTrue(tool.contained)
        self.assertTrue(tool.termination_recorded)
        self.assertEqual(gate.cleanup_phase(), 'unknown')
        self.assertTrue(gate.cleanup_unresolved)
        self.assertIn('timeout', [observation.kind for observation in gate.cleanup_observations])
        if gate_owner:
            self.assertEqual(errors, [])
            self.assertIs(factory.server.transport_failure, primary)
            self.assertTrue(any('Owned containment cleanup failed' in note
                                for note in primary.__notes__))
        else:
            self.assertEqual(len(errors), 1)
            self.assertEqual(errors[0].kind, 'timeout')
            with self.assertRaises(family.runtime.AppServerError):
                factory.server._require_healthy()
        # A later successful observer sees the completed owner but cannot heal
        # the first failed observation or the original charged invocation.
        gate.close(primary)
        self.assertEqual(gate.cleanup_observations[-1].kind, 'completed')
        self.assertEqual(gate.cleanup_phase(), 'unknown')
        with self.assertRaises(BlockingIOError):
            os.read(read, 1)
        self.assertEqual(gate.output_bytes_seen, initial_bytes)
        self.assertTrue(case.result_done.wait(8))
        self.assertEqual(len(result), 1)
        attempt = self.fixture.attempt(case)
        self.assertEqual(attempt['outcome'], 'unknown')
        self.assertEqual(attempt['charge'], attempt['amount'])

    def _gate_owned_concurrent_closer(self, *, time_out):
        case, factory, tool, _stream, read, release_turn, result = self._active()
        gate = factory.server.finite_input
        primary = RuntimeError('EXAMPLE original transport fault')
        owner_entered = threading.Event()
        release_owner = threading.Event()
        waiter_entered = threading.Event()
        waiter_done = threading.Event()
        calls, secondary = [], []
        original_effect = tool.controller.terminate
        original_settle = tool.settle_termination
        before_bytes = gate.output_bytes_seen
        before_success = sum(reply.get('result', {}).get('success') is True
                             for reply in self.fixture.spawned[0].replies)

        def blocked_effect(*args, **kwargs):
            calls.append(threading.get_ident())
            owner_entered.set()
            if not release_owner.wait(18):
                raise AssertionError('EXAMPLE gate owner was not released')
            return original_effect(*args, **kwargs)

        def observed_settle():
            if tool._termination_owner != threading.get_ident():
                waiter_entered.set()
            return original_settle()

        def second_close():
            try:
                gate.close(primary)
            except BaseException as error:
                secondary.append(error)
            finally:
                waiter_done.set()

        with patch.object(tool.controller, 'terminate', blocked_effect), patch.object(
                tool, 'settle_termination', observed_settle):
            factory.server._fail_transport(primary)
            try:
                self.assertTrue(owner_entered.wait(5))
                self.assertTrue(tool._ending)
                self.assertFalse(tool._termination_finished.is_set())
                self.assertEqual(gate.cleanup_phase(), 'cleanup-pending')
                closer = threading.Thread(target=second_close, daemon=True)
                closer.start()
                self.assertTrue(waiter_entered.wait(5),
                                'the second gate closer must reach the owner observer')
                if time_out:
                    self.assertTrue(waiter_done.wait(11),
                                    'the second gate closer must finish within its ten-second observation bound')
                    self.assertEqual(gate.cleanup_phase(), 'unknown')
                    self.assertTrue(gate.cleanup_unresolved)
                else:
                    release_owner.set()
                    self.assertTrue(waiter_done.wait(5))
            finally:
                release_owner.set()
                release_turn.set()
            closer.join(2)
        self.assertFalse(closer.is_alive())
        self.assertEqual(secondary, [])
        self.assertTrue(tool._termination_finished.wait(8))
        self.assertEqual(len(calls), 1)
        self.assertTrue(tool.contained)
        self.assertTrue(tool.termination_recorded)
        self.assertEqual(gate.cleanup_phase(), 'unknown' if time_out else 'contained')
        self.assertIn('timeout' if time_out else 'completed',
                      [observation.kind for observation in gate.cleanup_observations])
        self.assertIs(factory.server.transport_failure, primary)
        self.assertEqual(gate.output_bytes_seen, before_bytes)
        self.assertEqual(sum(reply.get('result', {}).get('success') is True
                             for reply in self.fixture.spawned[0].replies), before_success)
        with self.assertRaises(BlockingIOError):
            os.read(read, 1)
        with self.assertRaises(family.runtime.native.OfflineHostError):
            tool.terminate()
        self.assertTrue(case.result_done.wait(8))
        self.assertEqual(len(result), 1)
        attempt = self.fixture.attempt(case)
        self.assertEqual(attempt['outcome'], 'unknown')
        self.assertEqual(attempt['charge'], attempt['amount'])

    def test_gate_owned_transport_fault_second_closer_joins_one_owner(self):
        self._gate_owned_concurrent_closer(time_out=False)

    def test_gate_owned_transport_fault_second_closer_times_out_before_owner_release(self):
        self._gate_owned_concurrent_closer(time_out=True)

    def test_two_finite_tool_closers_observe_one_inflight_owner(self):
        case, factory, tool, _stream, read, release_turn, result = self._active()
        producer = factory.server.finite_tools
        gate = factory.server.finite_input
        owner_entered, release_owner = threading.Event(), threading.Event()
        observer_entered = threading.Event()
        first_done, second_done = threading.Event(), threading.Event()
        original_effect, original_settle = tool.controller.terminate, tool.settle_termination
        calls, errors = [], []

        def blocked_effect(*args, **kwargs):
            calls.append(1)
            owner_entered.set()
            if not release_owner.wait(8):
                raise AssertionError('EXAMPLE finite-tool close owner was not released')
            return original_effect(*args, **kwargs)

        def observed_settle():
            if tool._termination_owner != threading.get_ident():
                observer_entered.set()
            return original_settle()

        def close(done):
            try:
                producer.close()
            except BaseException as error:
                errors.append(error)
            finally:
                done.set()

        with patch.object(tool.controller, 'terminate', blocked_effect), patch.object(
                tool, 'settle_termination', observed_settle):
            first = threading.Thread(target=close, args=(first_done,), daemon=True)
            first.start()
            try:
                self.assertTrue(owner_entered.wait(5))
                self.assertEqual(producer.state, 'closed')
                self.assertEqual(gate.cleanup_phase(), 'cleanup-pending')
                second = threading.Thread(target=close, args=(second_done,), daemon=True)
                second.start()
                self.assertTrue(observer_entered.wait(5))
                self.assertFalse(second_done.is_set(),
                                 'a closed producer cannot report healthy completion before its owner')
            finally:
                release_owner.set()
                release_turn.set()
            first.join(8)
            second.join(8)
        self.assertFalse(first.is_alive())
        self.assertFalse(second.is_alive())
        self.assertTrue(first_done.is_set())
        self.assertTrue(second_done.is_set())
        self.assertEqual(calls, [1])
        self.assertEqual(errors, [])
        self.assertTrue(tool.contained)
        self.assertTrue(tool.termination_recorded)
        self.assertEqual(gate.cleanup_phase(), 'contained')
        with self.assertRaises(BlockingIOError):
            os.read(read, 1)
        self.assertTrue(case.result_done.wait(8))
        self.assertEqual(len(result), 1)
        attempt = self.fixture.attempt(case)
        self.assertEqual(attempt['outcome'], 'unknown')
        self.assertEqual(attempt['charge'], attempt['amount'])

    def test_direct_termination_owner_is_observed_by_off_reader_gate_close(self):
        case, factory, tool, _stream, read, release_turn, result = self._active()
        gate = factory.server.finite_input
        primary = RuntimeError('EXAMPLE original transport fault')
        owner_entered, release_owner = threading.Event(), threading.Event()
        observer_entered, cleanup_done = threading.Event(), threading.Event()
        original_effect = tool.controller.terminate
        original_settle, original_close = tool.settle_termination, gate.close
        calls, owner_errors = [], []

        def blocked_effect(*args, **kwargs):
            calls.append(1)
            owner_entered.set()
            if not release_owner.wait(8):
                raise AssertionError('EXAMPLE direct owner was not released')
            return original_effect(*args, **kwargs)

        def observed_settle():
            if tool._termination_owner != threading.get_ident():
                observer_entered.set()
            return original_settle()

        def observed_close(failure=None):
            try:
                return original_close(failure)
            finally:
                cleanup_done.set()

        def direct_owner():
            try:
                tool.terminate()
            except BaseException as error:
                owner_errors.append(error)

        with patch.object(tool.controller, 'terminate', blocked_effect), patch.object(
                tool, 'settle_termination', observed_settle), patch.object(
                gate, 'close', observed_close):
            owner = threading.Thread(target=direct_owner, daemon=True)
            owner.start()
            try:
                self.assertTrue(owner_entered.wait(5))
                factory.server._fail_transport(primary)
                self.assertTrue(observer_entered.wait(5))
                self.assertEqual(gate.cleanup_phase(), 'cleanup-pending')
                self.assertFalse(gate.cleanup_attempted)
            finally:
                release_owner.set()
                release_turn.set()
            owner.join(8)
            self.assertTrue(cleanup_done.wait(8))
        self.assertFalse(owner.is_alive())
        self.assertEqual(owner_errors, [])
        self.assertEqual(calls, [1])
        self.assertTrue(tool.contained)
        self.assertTrue(tool.termination_recorded)
        self.assertEqual(gate.cleanup_phase(), 'contained')
        self.assertIs(factory.server.transport_failure, primary)
        with self.assertRaises(BlockingIOError):
            os.read(read, 1)
        self.assertTrue(case.result_done.wait(8))
        self.assertEqual(len(result), 1)
        attempt = self.fixture.attempt(case)
        self.assertEqual(attempt['outcome'], 'unknown')
        self.assertEqual(attempt['charge'], attempt['amount'])

    def test_termination_record_failure_keeps_physical_and_completion_facts_separate(self):
        case, factory, tool, _stream, read, release_turn, result = self._active()
        gate = factory.server.finite_input
        primary = RuntimeError('EXAMPLE original transport fault')
        cleanup_done = threading.Event()
        original_close, original_record = gate.close, factory.record

        def observed_close(failure=None):
            try:
                return original_close(failure)
            finally:
                cleanup_done.set()

        def failing_record(stage, observation):
            if stage == 'tool-terminated':
                raise OSError('EXAMPLE termination record failure')
            return original_record(stage, observation)

        with patch.object(gate, 'close', observed_close), patch.object(
                factory, 'record', failing_record):
            factory.server._fail_transport(primary)
            self.assertTrue(cleanup_done.wait(8))
        release_turn.set()
        self.assertTrue(tool._termination_finished.is_set())
        self.assertTrue(tool.contained)
        self.assertFalse(tool.termination_recorded)
        self.assertIsInstance(tool._termination_error, OSError)
        self.assertIn('record-failed',
                      [observation.kind for observation in gate.cleanup_observations])
        self.assertEqual(gate.cleanup_phase(), 'unknown')
        self.assertEqual(gate.lifecycle.cleanup, 'unknown')
        self.assertIs(factory.server.transport_failure, primary)
        with self.assertRaises(family.runtime.AppServerError):
            factory.server._require_healthy()
        with self.assertRaises(BlockingIOError):
            os.read(read, 1)
        self.assertTrue(case.result_done.wait(8))
        self.assertEqual(len(result), 1)
        attempt = self.fixture.attempt(case)
        self.assertEqual(attempt['outcome'], 'unknown')
        self.assertEqual(attempt['charge'], attempt['amount'])

    def test_same_thread_record_callback_cannot_join_its_own_termination(self):
        case, factory, tool, _stream, _read, release_turn, result = self._active()
        gate = factory.server.finite_input
        primary = RuntimeError('EXAMPLE original transport fault')
        cleanup_done = threading.Event()
        original_close, original_record = gate.close, factory.record
        callbacks = []

        def observed_close(failure=None):
            try:
                return original_close(failure)
            finally:
                cleanup_done.set()

        def reentrant_record(stage, observation):
            if stage == 'tool-terminated':
                callbacks.append(threading.get_ident())
                gate.close(primary)
            return original_record(stage, observation)

        with patch.object(gate, 'close', observed_close), patch.object(
                factory, 'record', reentrant_record):
            factory.server._fail_transport(primary)
            self.assertTrue(cleanup_done.wait(8))
            self.assertTrue(tool._termination_finished.wait(8))
        release_turn.set()
        self.assertEqual(len(callbacks), 1)
        self.assertIn('reentrant',
                      [observation.kind for observation in gate.cleanup_observations])
        self.assertTrue(tool.contained)
        self.assertTrue(tool.termination_recorded)
        self.assertEqual(gate.cleanup_phase(), 'unknown')
        self.assertTrue(gate.cleanup_unresolved)
        self.assertIs(factory.server.transport_failure, primary)
        self.assertTrue(case.result_done.wait(8))
        self.assertEqual(len(result), 1)
        attempt = self.fixture.attempt(case)
        self.assertEqual(attempt['outcome'], 'unknown')
        self.assertEqual(attempt['charge'], attempt['amount'])

    def test_all_original_terminal_notifications_deny_physical_read(self):
        for event in ('turn/completed', 'turn/failed', 'turn/interrupted',
                      'thread/closed', 'thread/archived'):
            with self.subTest(event=event):
                fixture = FiniteInputTests(methodName='runTest')
                fixture.setUp()
                try:
                    fixture._denied_physical_read_schedule(event)
                finally:
                    family.cleanup_helper(self, fixture)

    def test_trusted_cancel_fault_and_close_deny_physical_read(self):
        for event in ('read-projection', 'trusted-terminal', 'cancellation', 'fault',
                      'close', 'deadline'):
            with self.subTest(event=event):
                fixture = FiniteInputTests(methodName='runTest')
                fixture.setUp()
                try:
                    fixture._denied_physical_read_schedule(event)
                finally:
                    family.cleanup_helper(self, fixture)

    def test_swapped_tool_pipe_refuses_and_contains_owned_child(self):
        case, factory, tool, _stream, read, release, result = self._active()
        gate = factory.server.finite_input
        ticket = gate.reserve(b'', thread_id=case.scenario.thread_id,
            turn_id=case.scenario.turn_id, item_id='EXAMPLE-command-call',
            approval_id='EXAMPLE-pipe-swap', deadline=time.monotonic() + 2)
        substituted = ToolLines()
        self.addCleanup(substituted.close)
        tool.process.stdout = substituted
        with self.assertRaises(finite.FiniteInputError):
            gate.poll(ticket)
        self.assertIsNotNone(factory.server.transport_failure)
        self.assertTrue(tool._termination_finished.wait(8),
                        'off-reader cleanup must finish after the pipe fault')
        self.assertTrue(tool.contained)
        self.assertTrue(tool.termination_recorded)
        with self.assertRaises(BlockingIOError):
            os.read(read, 1)
        release.set()
        self.assertTrue(self._wait(lambda: bool(result), 8))

    def test_ready_pipe_drained_between_select_and_read_is_empty_poll(self):
        case, factory, tool, stream, read, release, result = self._active()
        gate = factory.server.finite_input
        ticket = gate.reserve(b'', thread_id=case.scenario.thread_id,
            turn_id=case.scenario.turn_id, item_id='EXAMPLE-command-call',
            approval_id='EXAMPLE-drain', deadline=time.monotonic() + 2)
        stream.put('X')
        original = finite.select.select

        def drained(reads, writes, errors, timeout=None):
            ready = original(reads, writes, errors, timeout)
            if len(reads) == 1 and gate._pipe_stat(reads[0]) == gate.output_stat and ready[0]:
                self.assertEqual(os.read(reads[0], 1), b'X')
            return ready

        with patch.object(finite.select, 'select', drained):
            self.assertEqual(gate.poll(ticket), {'stdout': b'', 'stdin_bytes': b'', 'running': True})
        self.assertIsNone(factory.server.transport_failure)
        with self.assertRaises(BlockingIOError):
            os.read(read, 1)
        tool.terminate()
        release.set()
        self.assertTrue(self._wait(lambda: bool(result), 8))
        self.assertIsInstance(result[0], dict)

    def test_deadline_crossing_at_pipe_wait_fails_without_stale_read(self):
        case, factory, tool, _stream, read, release, result = self._active()
        gate = factory.server.finite_input
        deadline = time.monotonic() + 1.5
        ticket = gate.reserve(b'', thread_id=case.scenario.thread_id,
            turn_id=case.scenario.turn_id, item_id='EXAMPLE-command-call',
            approval_id='EXAMPLE-deadline-cross', deadline=deadline)
        original = finite.select.select
        entered = threading.Event()

        def late(reads, writes, errors, timeout=None):
            if len(reads) == 1 and gate._pipe_stat(reads[0]) == gate.output_stat:
                entered.set()
                time.sleep(max(0, deadline - time.monotonic()) + .05)
                return [], [], []
            return original(reads, writes, errors, timeout)

        with patch.object(finite.select, 'select', late), self.assertRaises(finite.FiniteInputError):
            gate.poll(ticket, timeout=.1)
        self.assertTrue(entered.is_set(), 'the deadline schedule must cross the original pipe wait')
        self.assertTrue(tool._termination_finished.wait(8),
                        'the off-reader owned cleanup must finish')
        self.assertTrue(tool.contained and tool.termination_recorded)
        self.assertIsNotNone(factory.server.transport_failure)
        with self.assertRaises(BlockingIOError):
            os.read(read, 1)
        release.set()
        self.assertTrue(self._wait(lambda: bool(result), 8))

    def test_authority_drift_after_last_callout_consumes_poll_ticket(self):
        case, factory, tool, _stream, read, release, result = self._active()
        gate = factory.server.finite_input
        ticket = gate.reserve(b'', thread_id=case.scenario.thread_id,
            turn_id=case.scenario.turn_id, item_id='EXAMPLE-command-call',
            approval_id='EXAMPLE-authority-race', deadline=time.monotonic() + 2)
        original = factory.require_effect
        source = factory._source

        def drift_after_callout():
            original()
            factory._source = b'EXAMPLE-drift-after-authority'

        try:
            with patch.object(factory, 'require_effect', drift_after_callout), self.assertRaises(finite.FiniteInputError):
                gate.poll(ticket)
        finally:
            factory._source = source
        with self.assertRaises(finite.FiniteInputError):
            gate.poll(ticket)
        with self.assertRaises(BlockingIOError):
            os.read(read, 1)
        tool.terminate()
        release.set()
        self.assertTrue(self._wait(lambda: bool(result), 8))

    def test_cancel_during_pipe_wait_blocks_fresh_poll(self):
        case, factory, tool, stream, read, release, result = self._active()
        gate = factory.server.finite_input
        ticket = gate.reserve(b'', thread_id=case.scenario.thread_id,
            turn_id=case.scenario.turn_id, item_id='EXAMPLE-command-call',
            approval_id='EXAMPLE-before-cancel', deadline=time.monotonic() + 2)
        stream.put('EXAMPLE progress')
        entered, resume, cancelled = threading.Event(), threading.Event(), threading.Event()
        original = finite.select.select
        polled = []

        def paused(reads, writes, errors, timeout=None):
            if len(reads) == 1 and gate._pipe_stat(reads[0]) == gate.output_stat:
                entered.set()
                resume.wait(3)
            return original(reads, writes, errors, timeout)

        def poll():
            try:
                polled.append(gate.poll(ticket))
            except BaseException as error:
                polled.append(error)

        def cancel():
            factory.server.requests.cancel_turn(case.scenario.thread_id, case.scenario.turn_id)
            cancelled.set()

        with patch.object(finite.select, 'select', paused):
            worker = threading.Thread(target=poll, daemon=True)
            worker.start()
            self.assertTrue(entered.wait(3))
            revoker = threading.Thread(target=cancel, daemon=True)
            revoker.start()
            self.assertTrue(cancelled.wait(.5), 'cancellation must remain responsive during pipe wait')
            resume.set()
            worker.join(3)
            revoker.join(3)
        self.assertIsInstance(polled[0], finite.FiniteInputError)
        self.assertTrue(cancelled.is_set())
        with self.assertRaises(finite.FiniteInputError):
            gate.reserve(b'', thread_id=case.scenario.thread_id,
                turn_id=case.scenario.turn_id, item_id='EXAMPLE-command-call',
                approval_id='EXAMPLE-after-cancel', deadline=time.monotonic() + 2)
        with self.assertRaises(BlockingIOError):
            os.read(read, 1)
        tool.settle_termination()
        self.assertTrue(tool._termination_finished.is_set())
        self.assertTrue(tool.contained and tool.termination_recorded)
        release.set()
        self.assertTrue(self._wait(lambda: bool(result), 8))

    def test_close_during_pipe_wait_revokes_next_ticket(self):
        case, factory, tool, _stream, read, release, result = self._active()
        gate = factory.server.finite_input
        ticket = gate.reserve(b'', thread_id=case.scenario.thread_id,
            turn_id=case.scenario.turn_id, item_id='EXAMPLE-command-call',
            approval_id='EXAMPLE-before-close', deadline=time.monotonic() + 3)
        entered, resume, closed = threading.Event(), threading.Event(), threading.Event()
        original = finite.select.select
        polled = []

        def paused(reads, writes, errors, timeout=None):
            if len(reads) == 1 and gate._pipe_stat(reads[0]) == gate.output_stat:
                entered.set()
                resume.wait(3)
            return original(reads, writes, errors, timeout)

        def poll():
            try:
                polled.append(gate.poll(ticket))
            except BaseException as error:
                polled.append(error)

        def close():
            gate.close()
            closed.set()

        with patch.object(finite.select, 'select', paused):
            worker = threading.Thread(target=poll, daemon=True)
            worker.start()
            self.assertTrue(entered.wait(3))
            closer = threading.Thread(target=close, daemon=True)
            closer.start()
            self.assertTrue(closed.wait(.5), 'close must remain responsive during pipe wait')
            resume.set()
            worker.join(3)
            closer.join(3)
        self.assertIsInstance(polled[0], finite.FiniteInputError)
        self.assertTrue(closed.is_set())
        self.assertTrue(tool.contained)
        with self.assertRaises(finite.FiniteInputError):
            gate.reserve(b'', thread_id=case.scenario.thread_id,
                turn_id=case.scenario.turn_id, item_id='EXAMPLE-command-call',
                approval_id='EXAMPLE-after-close', deadline=time.monotonic() + 2)
        with self.assertRaises(BlockingIOError):
            os.read(read, 1)
        release.set()
        self.assertTrue(self._wait(lambda: bool(result), 8))

    def test_terminal_during_poll_authority_callout_refuses_at_fence(self):
        case, factory, tool, _stream, read, release, result = self._active()
        gate = factory.server.finite_input
        ticket = gate.reserve(b'', thread_id=case.scenario.thread_id,
            turn_id=case.scenario.turn_id, item_id='EXAMPLE-command-call',
            approval_id='EXAMPLE-authority-terminal', deadline=time.monotonic() + 3)
        entered, resume = threading.Event(), threading.Event()
        original = factory.require_effect
        polled = []

        def blocked():
            original()
            entered.set()
            resume.wait(3)

        def poll():
            try:
                polled.append(gate.poll(ticket))
            except BaseException as error:
                polled.append(error)

        with patch.object(factory, 'require_effect', blocked):
            worker = threading.Thread(target=poll, daemon=True)
            worker.start()
            try:
                self.assertTrue(entered.wait(3))
                self.fixture.spawned[0].stdout.put({'method': 'turn/completed', 'params': {
                    'threadId': case.scenario.thread_id,
                    'turn': {'id': case.scenario.turn_id, 'status': 'completed'}}})
                self.assertTrue(self._wait(lambda: (case.scenario.thread_id, case.scenario.turn_id)
                    in factory.server.requests.terminals, 2))
            finally:
                resume.set()
                worker.join(3)
        self.assertEqual(len(polled), 1)
        self.assertIsInstance(polled[0], finite.FiniteInputError)
        with self.assertRaises(BlockingIOError):
            os.read(read, 1)
        tool.settle_termination()
        self.assertTrue(tool._termination_finished.is_set())
        self.assertTrue(tool.contained and tool.termination_recorded)
        release.set()
        self.assertTrue(self._wait(lambda: bool(result), 8))

    def test_expiry_profile_drift_and_tool_eof_consume_poll_authority(self):
        case, factory, tool, stream, read, release, result = self._active()
        gate = factory.server.finite_input
        identity = dict(thread_id=case.scenario.thread_id, turn_id=case.scenario.turn_id,
                        item_id='EXAMPLE-command-call')
        expiring = gate.reserve(b'', approval_id='EXAMPLE-expiring',
                                deadline=time.monotonic() + 1, **identity)
        time.sleep(1.05)
        with self.assertRaises(finite.FiniteInputError):
            gate.poll(expiring)
        drifted = gate.reserve(b'', approval_id='EXAMPLE-drifted',
                               deadline=time.monotonic() + 2, **identity)
        selected = factory.server._profile_response['activePermissionProfile']
        old = selected['id']
        selected['id'] = 'EXAMPLE-other-profile'
        try:
            with self.assertRaises(finite.FiniteInputError):
                gate.poll(drifted)
        finally:
            selected['id'] = old
        with self.assertRaises(finite.FiniteInputError):
            gate.poll(drifted)
        eof = gate.reserve(b'', approval_id='EXAMPLE-eof',
                           deadline=time.monotonic() + 2, **identity)
        stream.put('')
        with self.assertRaises(finite.FiniteInputError):
            gate.poll(eof)
        self.assertEqual(gate.state, 'revoked')
        self.assertTrue(tool._termination_finished.wait(8))
        self.assertTrue(tool.contained and tool.termination_recorded)
        with self.assertRaises(BlockingIOError):
            os.read(read, 1)
        release.set()
        self.assertTrue(self._wait(lambda: bool(result), 8))

    @staticmethod
    def _wait(predicate, seconds):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            if predicate():
                return True
            time.sleep(.002)
        return False


    def test_selected_original_output_rejection_is_failed_and_fully_charged(self):
        case = self.fixture.case(bad_output=True)
        factory = self.fixture.factory(case)
        factory.select_controlled_failure()
        with self.assertRaises(family.runtime.validation.ValidationError) as caught:
            factory.run()
        self.assertEqual(self.fixture.attempt(case)['outcome'], 'failed')
        self.assertEqual(self.fixture.attempt(case)['charge'], self.fixture.attempt(case)['amount'])
        evidence = factory.controlled_failure(caught.exception)
        self.assertEqual(evidence['outcome'], 'failed')
        self.assertEqual(evidence, factory.controlled_failure())
        with self.assertRaises(ValueError):
            factory.controlled_failure(ValueError('EXAMPLE foreign error'))

    def test_reducer_reject_raise_and_wake_failure_cannot_publish_healthy_cleanup(self):
        for behavior in ('reject', 'raise', 'wake'):
            with self.subTest(behavior=behavior):
                fixture = FiniteInputTests(methodName='runTest')
                fixture.setUp()
                try:
                    fixture._reducer_publication_failure(behavior)
                finally:
                    family.cleanup_helper(self, fixture)


    def _reducer_publication_failure(self, behavior):
        case, factory, tool, _stream, read, release_turn, result = self._active()
        gate = factory.server.finite_input
        original_event = gate.lifecycle.cleanup_event
        original_effect = tool.controller.terminate
        calls = []

        def counted_effect(*args, **kwargs):
            calls.append(1)
            return original_effect(*args, **kwargs)

        def injected_event(phase):
            if phase == 'contained':
                if behavior == 'reject':
                    return False
                if behavior == 'raise':
                    raise RuntimeError('EXAMPLE reducer publication failed')
            return original_event(phase)

        wake_patch = (patch.object(gate.lifecycle.condition, 'notify_all',
                                  side_effect=RuntimeError('EXAMPLE reducer wake failed'))
                      if behavior == 'wake' else nullcontext())
        self.addCleanup(release_turn.set)
        with patch.object(tool.controller, 'terminate', counted_effect), patch.object(
                gate.lifecycle, 'cleanup_event', injected_event), wake_patch:
            with self.assertRaises(finite.FiniteInputError):
                gate.close()
            self.assertEqual(gate.cleanup_phase(), 'unknown')
            self.assertEqual(gate.lifecycle.cleanup, 'unknown')
            self.assertTrue(gate.cleanup_unresolved)
            with self.assertRaises(family.runtime.AppServerError):
                factory.server._require_healthy()
            with self.assertRaises(finite.FiniteInputError):
                gate.close()
        self.assertEqual(calls, [1])
        self.assertTrue(tool.contained)
        self.assertTrue(tool.termination_recorded)
        with self.assertRaises(BlockingIOError):
            os.read(read, 1)
        release_turn.set()
        self.assertTrue(case.result_done.wait(8))
        attempt = self.fixture.attempt(case)
        self.assertEqual(attempt['outcome'], 'unknown')
        self.assertEqual(attempt['charge'], attempt['amount'])


class FiniteLifecycleTests(unittest.TestCase):
    """Bounded schedules for every host progress edge and absorbing refusal."""

    TURN = ('EXAMPLE-thread', 'EXAMPLE-turn')
    COMMAND = ('str', 'EXAMPLE-command-request')
    POLL = ('str', 'EXAMPLE-poll-request')

    def machine(self):
        now = [0.0]
        machine = finite._FiniteLifecycle(clock=lambda: now[0])
        machine.select('EXAMPLE-epoch', self.TURN, 15.0)
        return machine, now

    def command(self, machine):
        machine.queue(self.COMMAND, 'finite_command', self.TURN,
                      'EXAMPLE-command', 15.0)
        for event in ('decide-command', 'command-intent', 'pending-birth',
                      'gate-closed', 'gate-release'):
            self.assertTrue(machine.move(event, key=self.COMMAND,
                                         call='EXAMPLE-command'))

    def test_eagain_retry_owner_keeps_ordered_attempt_results(self):
        binding = ('EXAMPLE-epoch', 'EXAMPLE-request', *self.TURN,
                   'EXAMPLE-item', 'EXAMPLE-approval')
        machine = finite._FiniteLifecycle()
        first = machine.authority_dispatch('reply-grant', binding)
        self.assertIsNone(machine.authority_dispatch('reply-grant', binding))
        self.assertEqual(machine.authority_result(first, 'not-sent'), 'precommit-retry')
        retry = machine.authority_dispatch('reply-grant', binding)
        self.assertEqual(retry[2], first[2])
        self.assertLess(first[0], retry[0])
        self.assertEqual(machine.authority_attempt_results[first], 'not-sent')
        self.assertIsNone(machine.authority_dispatch('reply-grant', binding))
        machine.authority_revoke('turn', self.TURN)
        self.assertEqual(machine.authority_outcomes[('reply-grant', binding)],
                         'ambiguous-after-revocation')
        self.assertLess(retry[0], machine.authority_revocations[-1][0])
        self.assertEqual(machine.authority_result(retry, 'wire-sent'),
                         'wire-sent-after-revocation')
        self.assertEqual(machine.authority_attempt_results[first], 'not-sent')
        self.assertEqual(machine.authority_attempt_results[retry], 'wire-sent')
        self.assertIsNone(machine.authority_dispatch('reply-grant', binding))

        for outcome in ('wire-partial', 'unknown-send', 'wire-sent'):
            with self.subTest(outcome=outcome):
                machine = finite._FiniteLifecycle()
                ticket = machine.authority_dispatch('reply-grant', binding)
                machine.authority_result(ticket, outcome)
                self.assertIsNone(machine.authority_dispatch('reply-grant', binding))
                self.assertEqual(machine.authority_attempt_results[ticket], outcome)
        machine = finite._FiniteLifecycle()
        first = machine.authority_dispatch('reply-grant', binding)
        machine.authority_result(first, 'not-sent')
        machine.authority_revoke('turn', self.TURN)
        self.assertIsNone(machine.authority_dispatch('reply-grant', binding))
        self.assertEqual(machine.authority_attempt_results[first], 'not-sent')

    def test_original_request_and_host_lifecycle_order_matrix(self):
        binding = ('EXAMPLE-epoch', 'EXAMPLE-request', *self.TURN,
                   'EXAMPLE-item', 'EXAMPLE-approval')
        key = (str, 'EXAMPLE-request')
        path = ('queued', 'deciding', 'authority', 'record', 'ready',
                'committing', 'sent')
        # Every prefix is interrupted by every negative transport edge.
        # Acceptance can commit only before that edge; closure is absorbing.
        for cut in range(len(path)):
            for negative in ('terminal', 'fault', 'closed'):
                with self.subTest(cut=cut, negative=negative):
                    machine = finite._FiniteLifecycle()
                    for state in path[:cut + 1]:
                        machine.original_request_event(
                            key, state, binding=binding, deadline=15.0,
                            accepted=state == 'sent')
                    machine.original_transport_event(negative)
                    if cut < len(path) - 1:
                        for state in path[cut + 1:]:
                            if state == 'sent':
                                with self.assertRaises(finite.FiniteInputError):
                                    machine.original_request_event(
                                        key, state, binding=binding, deadline=15.0,
                                        accepted=True)
                                break
                            machine.original_request_event(
                                key, state, binding=binding, deadline=15.0)
                    machine.original_request_event(
                        key, 'revoked', binding=binding, deadline=15.0)
                    with self.assertRaises(finite.FiniteInputError):
                        machine.original_request_event(
                            key, 'ready', binding=binding, deadline=15.0)
                    self.assertNotEqual(machine.original_output, 'published')

        for order in permutations(('terminal', 'fault', 'closed')):
            with self.subTest(order=order):
                machine = finite._FiniteLifecycle()
                for event in order:
                    machine.original_transport_event(event)
                self.assertTrue(machine.original_fault)
                self.assertTrue(machine.original_closed)
                self.assertTrue(machine.original_terminal)
                self.assertEqual(machine.original_output, 'revoked')

        machine = finite._FiniteLifecycle()
        machine.original_request_event(key, 'queued', binding=binding, deadline=15.0)
        with self.assertRaises(finite.FiniteInputError):
            machine.original_request_event(key, 'deciding', binding=binding,
                                           deadline=16.0)
        with self.assertRaises(finite.FiniteInputError):
            machine.original_request_event(key, 'deciding', binding=(*binding[:-1], 'foreign'),
                                           deadline=15.0)
        machine.original_request_event((int, 7), 'ready', deadline=15.0)
        machine.original_request_event((str, '7'), 'ready', deadline=15.0)
        self.assertEqual(len(machine.original_requests), 3)
        machine.original_request_event(key, 'ready', binding=binding,
                                       deadline=15.0, expired=True)
        self.assertIn(key, machine.original_expired)
        machine.original_cleanup_event('pending')
        machine.original_cleanup_event('unknown')
        machine.original_cleanup_event('contained')
        self.assertEqual(machine.original_cleanup, 'unknown')
        with self.assertRaises(finite.FiniteInputError):
            machine.original_output_event('published')

        machine = finite._FiniteLifecycle()
        for state in ('queued', 'deciding', 'authority', 'record', 'ready', 'committing'):
            machine.original_request_event(key, state, binding=binding, deadline=15.0)
        machine.original_transport_event('terminal')
        machine.original_request_event(key, 'revoked', binding=binding, deadline=15.0,
                                       delivery='ambiguous')
        machine.original_transport_event('closed')
        machine.original_cleanup_event('pending')
        machine.original_cleanup_event('contained')
        self.assertEqual(machine.original_deliveries[key], 'ambiguous')
        self.assertNotIn(key, machine.original_accepts)
        with self.assertRaises(finite.FiniteInputError):
            machine.original_output_event('published')

    def test_original_output_requires_sent_replies_closed_transport_and_cleanup(self):
        machine = finite._FiniteLifecycle()
        key = (str, 'EXAMPLE-request')
        for state in ('queued', 'deciding', 'authority', 'record',
                      'ready', 'committing', 'sent'):
            machine.original_request_event(key, state, deadline=15.0,
                                           accepted=state == 'sent')
        with self.assertRaises(finite.FiniteInputError):
            machine.original_output_event('published')
        machine.original_transport_event('closed')
        machine.original_cleanup_event('pending')
        with self.assertRaises(finite.FiniteInputError):
            machine.original_output_event('published')
        machine.original_cleanup_event('contained')
        machine.original_output_event('published')
        self.assertEqual(machine.original_output, 'published')
        self.assertEqual(machine.original_accepts, {key})
        machine.original_request_event(key, 'revoked', deadline=15.0)
        self.assertEqual(machine.original_output, 'published')

    def test_later_queued_poll_cannot_replace_blocked_command_deadline(self):
        machine, now = self.machine()
        self.command(machine)
        now[0] = 14.9
        machine.queue(self.POLL, 'finite_poll', self.TURN, 'EXAMPLE-poll', 29.9)
        self.assertEqual(machine.pending[self.COMMAND][2], 15.0)
        self.assertEqual(machine.pending[self.POLL][2], 29.9)
        now[0] = 15.01
        self.assertTrue(machine.wait())
        self.assertEqual(machine.phase, 'command-effect')

    def test_ready_before_wait_and_notification_during_wait(self):
        for event in ('terminal', 'refused', 'fault', 'closed'):
            with self.subTest(event=event):
                machine, _now = self.machine()
                self.assertTrue(machine.finish(event, turn=self.TURN))
                self.assertFalse(machine.wait())
                self.assertFalse(machine.queue(self.COMMAND, 'finite_command',
                                               self.TURN, 'EXAMPLE-command', 15))
                self.assertEqual(machine.phase, event)
        machine, now = self.machine()
        waiting = threading.Event()
        finished = []
        original = machine.condition.wait

        def observed_wait(timeout=None):
            waiting.set()
            return original(timeout)

        machine.condition.wait = observed_wait
        thread = threading.Thread(target=lambda: finished.append(machine.wait()))
        thread.start()
        self.assertTrue(waiting.wait(1))
        self.assertTrue(machine.finish('terminal', turn=self.TURN))
        thread.join(1)
        self.assertFalse(thread.is_alive())
        self.assertEqual(finished, [False])
        self.assertEqual(now[0], 0)

    def test_host_control_loss_while_queued_or_deciding_cannot_start_tool(self):
        for deciding in (False, True):
            with self.subTest(deciding=deciding):
                machine, _now = self.machine()
                machine.queue(self.COMMAND, 'finite_command', self.TURN,
                              'EXAMPLE-command', 15)
                if deciding:
                    machine.move('decide-command', key=self.COMMAND,
                                 call='EXAMPLE-command')
                # Original host step exhaustion arrives through the factory's
                # failure observer. Cleanup may still fail, but cannot replace
                # the primary control-loss state or grant a late birth.
                self.assertTrue(machine.finish('fault'))
                with self.assertRaises(finite.FiniteInputError):
                    machine.move('command-intent', key=self.COMMAND,
                                 call='EXAMPLE-command')
                with self.assertRaises(finite.FiniteInputError):
                    machine.move('pending-birth', key=self.COMMAND,
                                 call='EXAMPLE-command')
                self.assertFalse(machine.pending)
                self.assertFalse(machine.wait())
                self.assertTrue(machine.cleanup_event('pending'))
                self.assertTrue(machine.cleanup_event('unknown'))
                self.assertEqual(machine.phase, 'fault')

    def test_bounded_effect_phase_table_denies_stale_requests(self):
        """T03-T13 phase authority is checked at real effect callsites above."""
        machine, now = self.machine()
        machine.queue(self.COMMAND, 'finite_command', self.TURN,
                      'EXAMPLE-command', 15)
        effect_phases = ('command-intent', 'gate-closed', 'command-effect')
        self.assertFalse(machine.call_live('EXAMPLE-command', {'command-intent'}))
        for event in ('decide-command', 'command-intent', 'pending-birth',
                      'gate-closed', 'gate-release'):
            machine.move(event, key=self.COMMAND, call='EXAMPLE-command')
            for phase in effect_phases:
                self.assertEqual(machine.call_live('EXAMPLE-command', {phase}),
                                 machine.phase == phase, (event, phase))
            self.assertFalse(machine.call_live('EXAMPLE-foreign', {machine.phase}))
        now[0] = 15
        self.assertFalse(machine.call_live('EXAMPLE-command', {'command-effect'}))
        now[0] = 14
        machine.reply(self.COMMAND, 'finite_command', 'EXAMPLE-command', True)
        self.assertFalse(machine.call_live('EXAMPLE-command', {'command-effect'}))
        machine.complete(self.TURN, 'EXAMPLE-command')
        machine.queue(self.POLL, 'finite_poll', self.TURN, 'EXAMPLE-poll', 29)
        self.assertFalse(machine.call_live('EXAMPLE-poll', {'poll-intent'}))
        machine.move('decide-poll', key=self.POLL, call='EXAMPLE-poll')
        machine.move('poll-intent', key=self.POLL, call='EXAMPLE-poll')
        self.assertTrue(machine.call_live('EXAMPLE-poll', {'poll-intent'}))
        machine.move('poll-observe', key=self.POLL, call='EXAMPLE-poll')
        self.assertTrue(machine.call_live('EXAMPLE-poll', {'poll-observing'}))
        machine.finish('refused')
        self.assertFalse(machine.call_live('EXAMPLE-poll', {'poll-observing'}))
        self.assertFalse(machine.call_live('EXAMPLE-command', {'command-effect'}))

    def test_refusal_terminal_fault_and_cleanup_are_monotone(self):
        machine, _now = self.machine()
        machine.queue(self.COMMAND, 'finite_command', self.TURN,
                      'EXAMPLE-command', 15)
        machine.reply(self.COMMAND, 'finite_command', 'EXAMPLE-command', False)
        self.assertEqual(machine.phase, 'refused')
        self.assertFalse(machine.queue(self.POLL, 'finite_poll', self.TURN,
                                       'EXAMPLE-poll', 15))
        with self.assertRaises(finite.FiniteInputError):
            machine.move('decide-command', key=self.COMMAND,
                         call='EXAMPLE-command')
        self.assertFalse(machine.reply(self.COMMAND, 'finite_command',
                                       'EXAMPLE-command', True))
        self.assertFalse(machine.finish('terminal', turn=('EXAMPLE-foreign', 'turn')))
        self.assertTrue(machine.finish('terminal', turn=self.TURN))
        self.assertTrue(machine.finish('fault'))
        self.assertFalse(machine.finish('closed'))
        self.assertEqual(machine.phase, 'fault')
        self.assertTrue(machine.cleanup_event('pending'))
        self.assertTrue(machine.cleanup_event('unknown'))
        self.assertFalse(machine.cleanup_event('contained'))
        self.assertEqual(machine.cleanup, 'unknown')

    def test_invalid_identity_phase_and_expiry_refuse_before_effect(self):
        machine, now = self.machine()
        with self.assertRaises(finite.FiniteInputError):
            machine.select('EXAMPLE-epoch', self.TURN, 15)
        with self.assertRaises(finite.FiniteInputError):
            machine.queue(self.COMMAND, 'finite_command',
                          ('EXAMPLE-wrong', 'EXAMPLE-turn'), 'EXAMPLE-command', 15)
        with self.assertRaises(finite.FiniteInputError):
            machine.move('decide-command', key=self.COMMAND, call='EXAMPLE-command')
        machine.queue(self.COMMAND, 'finite_command', self.TURN,
                      'EXAMPLE-command', 15)
        with self.assertRaises(finite.FiniteInputError):
            machine.queue(self.COMMAND, 'finite_command', self.TURN,
                          'EXAMPLE-command', 15)
        with self.assertRaises(finite.FiniteInputError):
            machine.reply(self.POLL, 'finite_command', 'EXAMPLE-command', True)
        with self.assertRaises(finite.FiniteInputError):
            machine.complete(self.TURN, 'EXAMPLE-command')
        now[0] = 15
        with self.assertRaises(finite.FiniteInputError):
            machine.move('decide-command', key=self.COMMAND,
                         call='EXAMPLE-command')
        self.assertTrue(machine.wait())


    def test_all_success_edges_keep_original_request_and_postreply_bounds(self):
        machine, now = self.machine()
        self.command(machine)
        machine.tool_event('read', 2500)
        machine.tool_event('clean-exit')
        machine.tool_event('read', 1596)
        machine.tool_event('eof')
        self.assertEqual(machine.output_bytes, 4096)
        now[0] = 14.9
        self.assertTrue(machine.reply(self.COMMAND, 'finite_command',
                                      'EXAMPLE-command', True))
        self.assertEqual(machine.phase, 'command-replied')
        self.assertAlmostEqual(machine.edge_deadline, 29.9)
        now[0] = 15.1
        self.assertFalse(machine.wait(host_deadline=now[0]))
        machine.complete(self.TURN, 'EXAMPLE-command')
        self.assertEqual(machine.phase, 'command-completed')
        machine.queue(self.POLL, 'finite_poll', self.TURN, 'EXAMPLE-poll', 30.1)
        for event in ('decide-poll', 'poll-intent', 'poll-observe'):
            machine.move(event, key=self.POLL, call='EXAMPLE-poll')
        now[0] = 30.0
        machine.reply(self.POLL, 'finite_poll', 'EXAMPLE-poll', True)
        self.assertEqual(machine.phase, 'poll-replied')
        self.assertAlmostEqual(machine.edge_deadline, 45.0)
        self.assertTrue(machine.finish('terminal', turn=self.TURN))
        self.assertFalse(machine.wait())
        self.assertEqual(machine.phase, 'terminal')


class _ScheduledCleanupLifetime:
    """Finite fake facts consumed by the actual gate and reducer readers."""

    def __init__(self):
        self.results = []
        self.pending = 0
        self.failed = False
        self.owner_failed = False
        self.physical = False
        self.recorded = False
        self.ending = False

    def observation_snapshot(self):
        return (tuple(self.results), self.pending, self.failed,
                self.owner_failed, self.physical, self.recorded, self.ending)

    def _record_observation(self, *, kind):
        self.results.append(kind)
        self.failed = True


class CleanupPublicationScheduleTests(unittest.TestCase):
    """Enumerate every linearization of the bounded two-observer graph."""

    @staticmethod
    def _orders(prerequisites, prefix=()):
        if len(prefix) == len(prerequisites):
            yield prefix
            return
        done = set(prefix)
        for event, required in prerequisites.items():
            if event not in done and required <= done:
                yield from CleanupPublicationScheduleTests._orders(
                    prerequisites, (*prefix, event))

    @staticmethod
    def _graph(first, second, *, peer_expiry=False):
        graph = {
            'owner_start': set(),
            'effect_done': {'owner_start'},
            'record_done': {'effect_done'},
            'first_register': {'owner_start'},
            'first_capture': {'first_register'},
            'first_ack': {'first_capture'},
            'note_pause': {'first_capture'},
            'second_register': {'owner_start'},
            'second_capture': {'second_register'},
            'second_ack': {'second_capture'},
            'consumer': {'first_capture'},
            'note_resume': {'note_pause', 'consumer', 'second_ack'},
        }
        if peer_expiry:
            graph['peer_wait_expiry'] = {'first_ack', 'second_register'}
            graph['second_ack'].add('peer_wait_expiry')
        for name, kind in (('first', first), ('second', second)):
            if kind == 'completed':
                graph[name + '_capture'].add('record_done')
            elif kind == 'owner-failed':
                graph[name + '_capture'].add('effect_done')
            elif kind == 'record-failed':
                graph[name + '_capture'].add('record_done')
        return graph

    @staticmethod
    def _machine():
        gate = finite.RegisteredFiniteInput(object(), object())
        life = _ScheduledCleanupLifetime()
        gate.lifetime = life
        gate.state = 'active'
        return gate, life

    @staticmethod
    def _advance(event, gate, life, first, second, healthy):
        if event == 'owner_start':
            life.ending = True
        elif event == 'effect_done':
            life.physical = healthy or first == 'record-failed'
            life.owner_failed = first == 'owner-failed'
        elif event == 'record_done':
            life.recorded = healthy
        elif event.endswith('_register'):
            gate.state = 'revoked'
            gate._cleanup_inflight += 1
            life.pending += 1
            gate._publish_cleanup_event('pending')
        elif event.endswith('_capture'):
            kind = first if event.startswith('first') else second
            life.pending -= 1
            life.results.append(kind)
            life.failed |= kind != 'completed' or not life.physical or not life.recorded
        elif event == 'peer_wait_expiry':
            phase = gate._await_cleanup_classification(time.monotonic() - 1)
            assert phase == 'unknown'
        elif event.endswith('_ack'):
            gate._cleanup_inflight -= 1
            gate._cleanup_committed = True
            phase = gate.cleanup_phase()
            gate._publish_cleanup_event(
                'unknown' if phase == 'unknown' else
                'contained' if phase == 'contained' else 'pending')

    def _check_cut(self, gate, life, order, done):
        phase = gate.cleanup_phase()
        projection = {'unselected': 'none', 'owned-active': 'none',
                      'cleanup-pending': 'pending', 'contained': 'contained',
                      'unknown': 'unknown'}[phase]
        self.assertEqual(gate.lifecycle.cleanup, projection, order)
        if life.failed or life.owner_failed or gate._cleanup_publication_failed:
            self.assertEqual(phase, 'unknown', order)
        if phase == 'contained':
            self.assertTrue(life.physical and life.recorded and not life.pending
                            and not gate._cleanup_inflight and not life.failed, order)
        if 'consumer' in done and 'first_capture' in done and life.failed:
            self.assertNotEqual(phase, 'contained', order)

    def test_all_bounded_owner_observer_note_ack_and_consumer_orders(self):
        # These are all topological orders of the stated finite graph, not
        # randomized repetitions of one thread timing. Actual fake child/RPC
        # origin and reducer-failure cases are exercised above.
        outcomes = (
            ('timeout', 'completed', True),
            ('reentrant', 'completed', True),
            ('completed', 'timeout', True),
            ('completed', 'completed', True),
            ('owner-failed', 'owner-failed', False),
            ('record-failed', 'record-failed', False),
        )
        totals = {}
        for first, second, healthy in outcomes:
            count = 0
            for order in self._orders(self._graph(first, second)):
                gate, life = self._machine()
                done = set()
                for event in order:
                    self._advance(event, gate, life, first, second, healthy)
                    done.add(event)
                    self._check_cut(gate, life, order, done)
                count += 1
            totals[first, second] = count
        self.assertEqual(totals, {
            ('timeout', 'completed'): 5292,
            ('reentrant', 'completed'): 5292,
            ('completed', 'timeout'): 2664,
            ('completed', 'completed'): 1878,
            ('owner-failed', 'owner-failed'): 9474,
            ('record-failed', 'record-failed'): 1878,
        })

    def test_final_peer_wait_expiry_and_wait_failure_are_sticky(self):
        count = 0
        for order in self._orders(self._graph(
                'completed', 'completed', peer_expiry=True)):
            gate, life = self._machine()
            for event in order:
                self._advance(event, gate, life, 'completed', 'completed', True)
                self._check_cut(gate, life, order, set(order[:order.index(event) + 1]))
            self.assertEqual(gate.cleanup_phase(), 'unknown')
            self.assertIn('timeout', life.results)
            count += 1
        self.assertEqual(count, 2010)

        gate, life = self._machine()
        gate.state = 'revoked'
        gate._cleanup_committed = True
        gate._cleanup_inflight = 1
        life.results.append('completed')
        life.physical = life.recorded = True
        with patch.object(gate._cleanup_condition, 'wait',
                          side_effect=RuntimeError('EXAMPLE wait failed')):
            self.assertEqual(gate._await_cleanup_classification(
                time.monotonic() + 1), 'unknown')
        self.assertIn('observer-failed', life.results)
        gate._cleanup_inflight = 0
        life.results.append('completed')
        self.assertEqual(gate.cleanup_phase(), 'unknown')
        self.assertEqual(gate.lifecycle.cleanup, 'unknown')

    def test_final_peer_wait_notify_and_reducer_failures_stay_unknown(self):
        for behavior in ('gate-wake', 'reducer-reject', 'reducer-raise',
                         'reducer-wake'):
            with self.subTest(behavior=behavior):
                gate, life = self._machine()
                gate.state = 'revoked'
                gate._cleanup_committed = True
                gate._cleanup_inflight = 1
                life.results.append('completed')
                life.physical = life.recorded = True
                original_event = gate.lifecycle.cleanup_event

                def event(phase):
                    if phase == 'unknown' and behavior == 'reducer-reject':
                        return False
                    if phase == 'unknown' and behavior == 'reducer-raise':
                        raise RuntimeError('EXAMPLE reducer publication failed')
                    return original_event(phase)

                with ExitStack() as stack:
                    if behavior == 'gate-wake':
                        stack.enter_context(patch.object(
                            gate._cleanup_condition, 'notify_all',
                            side_effect=RuntimeError('EXAMPLE gate wake failed')))
                    if behavior == 'reducer-wake':
                        stack.enter_context(patch.object(
                            gate.lifecycle.condition, 'notify_all',
                            side_effect=RuntimeError('EXAMPLE reducer wake failed')))
                    stack.enter_context(patch.object(gate.lifecycle,
                                                     'cleanup_event', event))
                    self.assertEqual(gate._await_cleanup_classification(
                        time.monotonic() - 1), 'unknown')
                self.assertIn('timeout', life.results)
                gate._cleanup_inflight = 0
                life.results.append('completed')
                self.assertTrue(life.physical and life.recorded)
                self.assertEqual(gate.cleanup_phase(), 'unknown')
                self.assertEqual(gate.lifecycle.cleanup, 'unknown')
