"""Selected finite fixtures acknowledge original host waits before releasing work."""
from contextlib import ExitStack
import queue
import json
import os
from pathlib import Path
import threading
import time
import unittest
from unittest.mock import patch

from tests import test_registered_finite_tool_wiring as wiring

family = wiring.family


class FiniteFixtureProgressTests(unittest.TestCase):
    def run_owned_selector(self, method, releases):
        """Own every started worker before the original nested test can start it."""
        owner = wiring.RegisteredFiniteToolWiringTests(method)
        started = []
        original_start = threading.Thread.start

        def drain(worker):
            for release in releases:
                release()
            family.finish_worker(owner, worker)

        def start(worker):
            owner.addCleanup(drain, worker)
            started.append(worker)
            return original_start(worker)

        result = unittest.TestResult()
        try:
            with patch.object(threading.Thread, 'start', start):
                owner.run(result)
        finally:
            for worker in started:
                drain(worker)
        return result

    def test_success_consumers_wait_for_original_post_start_progress(self):
        methods = (
            'test_exit_between_initial_read_and_reply_drains_tail_atomically',
            'test_exit_between_poll_read_and_reply_carries_final_status_and_tail',
            'test_clean_exit_after_command_reply_preserves_fresh_empty_poll',
            'test_clean_exit_before_completed_item_still_allows_fresh_poll',
        )
        self.success_consumers(methods)

    def test_atomic_tail_joins_original_poll_publication(self):
        self.success_consumers((
            'test_exit_between_initial_read_and_reply_drains_tail_atomically',
        ), hold_intent=True)

    def test_completion_join_waits_for_original_poll_intent(self):
        self.success_consumers((
            'test_exit_between_initial_read_and_reply_drains_tail_atomically',
        ), hold_intent=True, hold_preintent=True)

    def test_atomic_intent_acknowledges_wait_before_command_consumer_returns(self):
        self.success_consumers((
            'test_exit_between_initial_read_and_reply_drains_tail_atomically',
        ), hold_intent=True, hold_consumer_return=True)

    def test_poll_consumers_wait_for_original_reply_reconciliation(self):
        self.success_consumers((
            'test_exit_between_initial_read_and_reply_drains_tail_atomically',
            'test_exit_between_poll_read_and_reply_carries_final_status_and_tail',
            'test_clean_exit_after_command_reply_preserves_fresh_empty_poll',
        ), hold_reply=True)

    def success_consumers(self, methods, *, hold_intent=False, hold_reply=False,
                          hold_consumer_return=False, hold_preintent=False):
        for method in methods:
            with self.subTest(method=method):
                waits, acknowledged, held, faults = queue.Queue(), [], [], []
                publication, publication_ack, intent_held, cases = queue.Queue(), [], [], []
                publication_kinds = []
                preintent_held, preintent_ack = [], []
                command_return_observed = threading.Event()
                reconciliation, reply_ack, reply_held, early_terminals = queue.Queue(), [], [], []
                host_joined, consumers = [], []
                intent_returned, consumer_held = threading.Event(), []
                consumer_returned = threading.Event()
                poll_refusals = []
                host = []
                original_turn = family.runtime._RegisteredServer.start_turn
                original_wait = threading.Condition.wait
                original_receive = wiring.DynamicRpcProcess.__mro__[1].receive
                original_fault = family.runtime._RegisteredServer._fail_transport
                original_fsync = os.fsync
                original_write = wiring.gate_module.RegisteredFiniteInput._write_reply_frame
                original_terminal = family.runtime._CoherentServerRequests.observe_trusted_terminal
                original_commit = family.runtime._RegisteredServer._commit_tool_reply
                original_send = wiring.DynamicRpcProcess._send_tool
                original_refusal = wiring.finite_tools.RegisteredFiniteToolCalls._cleanup_failed_call

                def start_turn(server, *args, **kwargs):
                    value = original_turn(server, *args, **kwargs)
                    host.append((server, threading.get_ident()))
                    return value

                def wait(condition, timeout=None):
                    selected = (host and threading.get_ident() == host[0][1]
                                and condition in (host[0][0]._condition,
                                    host[0][0].finite_input.lifecycle.condition))
                    active = [True]
                    if selected:
                        waits.put((condition, active))
                        if hold_intent:
                            publication.put((condition, active))
                    completion = getattr(cases[0], '_finite_success_consumed', None) if cases else None
                    if ((hold_intent or hold_reply) and host and threading.get_ident() == host[0][1]
                            and completion is not None and condition is completion._cond):
                        publication.put((condition, active))
                    if (hold_reply and reply_held and cases
                            and condition is cases[0].factory.server.finite_input.lifecycle.condition
                            and consumers and threading.get_ident() == consumers[0]):
                        reconciliation.put((condition, active))
                    try:
                        return original_wait(condition, timeout)
                    finally:
                        active[0] = False

                def receive(process, message):
                    value = original_receive(process, message)
                    if (hold_preintent and cases and process.case is cases[0]
                            and message.get('method') == 'thread/read'):
                        self.assertEqual(threading.get_ident(), consumers[0])
                        command_return_observed.set()
                    if (not process.validator and not process.is_tool
                            and message.get('id') == 'EXAMPLE-request-EXAMPLE-command-call'
                            and message.get('result', {}).get('success') is True):
                        held.append(True)
                        cases.append(process.case)
                        consumers.append(threading.get_ident())
                        end = time.monotonic() + 12
                        while time.monotonic() < end:
                            entry = waits.get(timeout=max(.001, end - time.monotonic()))
                            if entry is None:
                                break
                            condition, active = entry
                            self.assertTrue(condition.acquire(timeout=3))
                            try:
                                if active[0] and condition._waiters:
                                    acknowledged.append('rpc' if condition is host[0][0]._condition
                                                        else 'lifecycle')
                                    break
                            finally:
                                condition.release()
                    return value

                def refused(producer, tool, failure):
                    if (hold_intent and cases and tool == 'finite_poll'
                            and producer is cases[0].factory.server.finite_tools):
                        poll_refusals.append(failure)
                    return original_refusal(producer, tool, failure)

                def send(process, call, tool, arguments, scenario):
                    value = original_send(process, call, tool, arguments, scenario)
                    if hold_consumer_return and call == 'EXAMPLE-poll-call':
                        self.assertEqual(threading.get_ident(), consumers[0])
                        consumer_held.append(True)
                        try:
                            family.wait_for_release(self, intent_returned, 3)
                        finally:
                            consumer_returned.set()
                    return value

                def commit(server, message, response, deadline, *, refusal=False):
                    if (hold_reply and not host_joined
                            and message.get('params', {}).get('tool') == 'finite_poll'
                            and response.get('result', {}).get('success') is True):
                        # Prepare before the writer lock is acquired: the host
                        # can finish any real thread/read before joining the
                        # existing original-consumer completion observation.
                        condition, active = publication.get(timeout=3)
                        self.assertTrue(condition.acquire(timeout=3))
                        try:
                            self.assertTrue(active[0] and condition._waiters)
                            host_joined.append(True)
                        finally:
                            condition.release()
                    return original_commit(server, message, response, deadline, refusal=refusal)

                def write_reply(writer, frame, source, deadline):
                    if not hold_reply or reply_held:
                        return original_write(writer, frame, source, deadline)
                    message = json.loads(frame)
                    selected = (message.get('id') == 'EXAMPLE-request-EXAMPLE-poll-call'
                                and message.get('result', {}).get('success') is True)
                    if selected:
                        reply_held.append(True)
                    value = original_write(writer, frame, source, deadline)
                    if selected:
                        self.assertTrue(value)
                        entry = reconciliation.get(timeout=3)
                        if entry is not None:
                            condition, active = entry
                            self.assertTrue(condition.acquire(timeout=3))
                            try:
                                self.assertTrue(active[0] and condition._waiters)
                                key = family.runtime.protocol._id_key(message['id'])
                                self.assertIn(key, cases[0].factory.server.finite_input.lifecycle.pending)
                                reply_ack.append(True)
                            finally:
                                condition.release()
                    return value

                def terminal(requests, thread_id, turn_id, boundary):
                    if not hold_reply or not cases or requests is not cases[0].factory.server.requests:
                        return original_terminal(requests, thread_id, turn_id, boundary)
                    gate = requests.server.finite_input
                    key = family.runtime.protocol._id_key('EXAMPLE-request-EXAMPLE-poll-call')
                    with gate.lifecycle.condition:
                        pending_before = key in gate.lifecycle.pending
                    value = original_terminal(requests, thread_id, turn_id, boundary)
                    if (hold_reply and reply_held and cases
                            and requests is cases[0].factory.server.requests
                            and pending_before
                            and (thread_id, turn_id) in requests.trusted_terminals):
                        # Original terminal publication clears pending. Retain
                        # its pre-call fact, but release only after the actual
                        # original revocation has finished.
                        early_terminals.append(True)
                        reconciliation.put(None)
                    return value

                def fsync(descriptor):
                    value = original_fsync(descriptor)
                    if not hold_intent or not cases or intent_held:
                        return value
                    path = Path(os.readlink('/proc/self/fd/' + str(descriptor)))
                    if path.parent != cases[0].factory.records / 'transport-observations':
                        return value
                    record = json.loads(path.read_bytes())
                    preintent = (hold_preintent and record.get('stage') == 'finite-tool-decision'
                                 and record['observation'].get('tool') == 'finite_poll')
                    if preintent:
                        if preintent_held:
                            return value
                        preintent_held.append(True)
                        gate = cases[0].factory.server.finite_input
                        with gate.lifecycle.condition:
                            self.assertEqual(gate.lifecycle.phase, 'poll-queued')
                            self.assertNotIn('EXAMPLE-poll-call', gate.used_approvals)
                            self.assertFalse(any(item[0] == 'poll'
                                                 for item in gate.intent_reservations.values()))
                    elif record.get('stage') != 'finite-poll-intent':
                        return value
                    else:
                        intent_held.append(True)
                    # The host may already be in an original RPC/lifecycle
                    # wait before the command consumer returns. A completion
                    # join is not the only genuine progress acknowledgment.
                    end = time.monotonic() + 1.05
                    if preintent:
                        # This subsequent callback runs on the original single
                        # input consumer after its command callback returned.
                        self.assertTrue(command_return_observed.wait(
                            max(0, end - time.monotonic())))
                    try:
                        while (remaining := end - time.monotonic()) > 0:
                            try:
                                entry = publication.get(timeout=remaining)
                            except queue.Empty:
                                break
                            if entry is None:
                                break
                            condition, active = entry
                            remaining = end - time.monotonic()
                            if remaining <= 0 or not condition.acquire(timeout=min(3, remaining)):
                                break
                            try:
                                if not active[0] or not condition._waiters:
                                    continue
                                kind = ('rpc' if condition is host[0][0]._condition else
                                        'lifecycle' if condition is host[0][0].finite_input.lifecycle.condition
                                        else 'consumer')
                                if preintent:
                                    self.assertIn(kind, {'rpc', 'lifecycle'},
                                        'Original completion join began before poll intent.')
                                    preintent_ack.append(kind)
                                elif hold_consumer_return:
                                    self.assertFalse(consumer_returned.is_set())
                                    self.assertIn(kind, {'rpc', 'lifecycle'})
                                if not preintent:
                                    publication_ack.append(True)
                                    publication_kinds.append(kind)
                                break
                            finally:
                                condition.release()
                    finally:
                        if not preintent:
                            intent_returned.set()
                    return value

                def fail_transport(server, failure):
                    faults.append(repr(failure))
                    waits.put(None)
                    publication.put(None)
                    reconciliation.put(None)
                    return original_fault(server, failure)

                def release_publication():
                    intent_returned.set()
                    publication.put(None)
                    reconciliation.put(None)
                    if cases:
                        completion = getattr(cases[0], '_finite_success_consumed', None)
                        if completion is not None:
                            completion.set()

                with ExitStack() as patches:
                    patches.enter_context(patch.object(family.runtime._RegisteredServer,
                                                      'start_turn', start_turn))
                    patches.enter_context(patch.object(threading.Condition, 'wait', wait))
                    patches.enter_context(patch.object(wiring.DynamicRpcProcess.__mro__[1],
                                                      'receive', receive))
                    patches.enter_context(patch.object(family.runtime._RegisteredServer,
                                                      '_fail_transport', fail_transport))
                    patches.enter_context(patch.object(os, 'fsync', fsync))
                    patches.enter_context(patch.object(wiring.gate_module.RegisteredFiniteInput,
                                                      '_write_reply_frame', staticmethod(write_reply)))
                    patches.enter_context(patch.object(family.runtime._CoherentServerRequests,
                                                      'observe_trusted_terminal', terminal))
                    patches.enter_context(patch.object(family.runtime._RegisteredServer,
                                                      '_commit_tool_reply', commit))
                    patches.enter_context(patch.object(wiring.DynamicRpcProcess, '_send_tool', send))
                    patches.enter_context(patch.object(wiring.finite_tools.RegisteredFiniteToolCalls,
                                                      '_cleanup_failed_call', refused))
                    result = self.run_owned_selector(method, [lambda: waits.put(None),
                                                             release_publication])
                try:
                    if hold_consumer_return and not result.wasSuccessful():
                        self.assertEqual(len(poll_refusals), 1, (poll_refusals, faults))
                        self.assertIs(type(poll_refusals[0]), wiring.gate_module.FiniteInputError)
                        self.assertEqual(str(poll_refusals[0]),
                                         'The reserved poll ended during intent persistence.')
                        self.assertTrue(faults and faults[0].startswith(
                            "AssertionError('Lists differ: [False] != [True]"), faults)
                    if hold_reply and not result.wasSuccessful():
                        self.assertTrue(early_terminals,
                                        ('original terminal did not cross the held reply',
                                         result.failures, result.errors, faults))
                        self.assertEqual(faults[0] if faults else None,
                                         "FiniteInputError('The prior-inflight tool reply is ambiguous.')",
                                         'causal schedule missed the original prior-inflight guard')
                    self.assertTrue(result.wasSuccessful(), (result.failures, result.errors, faults))
                except self.failureException as failure:
                    replies = [case.test.spawned[0].replies for case in cases if case.test.spawned]
                    failure.add_note(f'Original tool reply frames: {replies!r}')
                    if hold_intent:
                        failure.add_note(f'Original finite-poll refusals: {poll_refusals!r}')
                    raise
                self.assertEqual(held, [True])
                self.assertEqual(len(acknowledged), 1, 'original post-start waiter was not acknowledged')
                self.assertEqual(faults, [])
                if hold_intent:
                    self.assertEqual(intent_held, [True])
                    self.assertEqual(publication_ack, [True])
                    self.assertEqual(poll_refusals, [])
                if hold_preintent:
                    self.assertEqual(preintent_held, [True])
                    self.assertEqual(len(preintent_ack), 1)
                    self.assertIn(preintent_ack[0], {'rpc', 'lifecycle'})
                if hold_consumer_return:
                    self.assertEqual(consumer_held, [True])
                    self.assertTrue(consumer_returned.is_set())
                    self.assertEqual(len(publication_kinds), 1)
                    self.assertIn(publication_kinds[0], {'rpc', 'lifecycle'})
                if hold_reply:
                    self.assertEqual(host_joined, [True])
                    self.assertEqual(reply_held, [True])
                    self.assertEqual(reply_ack, [True])
                    self.assertEqual(early_terminals, [])
                    replies = cases[0].test.spawned[0].replies
                    self.assertEqual([reply['id'] for reply in replies],
                                     ['EXAMPLE-request-EXAMPLE-command-call',
                                      'EXAMPLE-request-EXAMPLE-poll-call'])
                    self.assertEqual([reply.get('result', {}).get('success') for reply in replies],
                                     [True, True])

    def test_typed_id_owner_does_not_poll_a_parked_host(self):
        owner_thread = threading.get_ident()
        factories, polling, parked, release_ack = [], [], [], []
        original_factory = family.FactoryTests.factory
        original_wait = threading.Condition.wait
        original_sleep = time.sleep

        def factory(owner, case, **kwargs):
            value = original_factory(owner, case, **kwargs)
            factories.append((value, case))
            original_release = case.tool_spawn_release.set

            def release_spawn():
                try:
                    if case.tool_spawn_entered.is_set() and not case.tool_spawn_release.is_set():
                        condition = value.server.finite_input.lifecycle.condition
                        acquired = condition.acquire(timeout=3)
                        try:
                            release_ack.append(acquired and bool(parked and condition._waiters))
                        finally:
                            if acquired:
                                condition.release()
                finally:
                    original_release()

            case.tool_spawn_release.set = release_spawn
            return value

        def wait(condition, timeout=None):
            selected = (factories and factories[0][0].server is not None
                        and condition is factories[0][0].server.finite_input.lifecycle.condition
                        and threading.get_ident() != owner_thread)
            if selected:
                parked.append(threading.get_ident())
            try:
                return original_wait(condition, timeout)
            finally:
                if selected:
                    parked.pop()

        def sleep(seconds):
            if (threading.get_ident() == owner_thread and seconds == .01
                    and factories and factories[0][1].tool_spawn_entered.is_set()
                    and not factories[0][1].tool_spawn_release.is_set()):
                condition = factories[0][0].server.finite_input.lifecycle.condition
                self.assertTrue(condition.acquire(timeout=3))
                try:
                    if parked and condition._waiters:
                        polling.append(factories[0][0].adapter.check_count)
                finally:
                    condition.release()
            return original_sleep(seconds)

        def release():
            if factories:
                factories[0][1].tool_spawn_release.set()

        with ExitStack() as patches:
            patches.enter_context(patch.object(family.FactoryTests, 'factory', factory))
            patches.enter_context(patch.object(threading.Condition, 'wait', wait))
            patches.enter_context(patch.object(time, 'sleep', sleep))
            result = self.run_owned_selector('test_typed_integer_and_string_request_ids_remain_distinct',
                                             [release])
        self.assertTrue(result.wasSuccessful(), (result.failures, result.errors))
        self.assertEqual((len(polling), set(polling)), (0, set()),
                         'typed-ID owner polled check_count while the original host was parked')
        self.assertEqual(release_ack, [True], 'launch released without the original waiter lock acknowledgment')
