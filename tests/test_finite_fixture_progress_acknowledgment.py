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

    def success_consumers(self, methods, *, hold_intent=False):
        for method in methods:
            with self.subTest(method=method):
                waits, acknowledged, held, faults = queue.Queue(), [], [], []
                publication, publication_ack, intent_held, cases = queue.Queue(), [], [], []
                host = []
                original_turn = family.runtime._RegisteredServer.start_turn
                original_wait = threading.Condition.wait
                original_receive = wiring.DynamicRpcProcess.__mro__[1].receive
                original_fault = family.runtime._RegisteredServer._fail_transport
                original_fsync = os.fsync

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
                    completion = getattr(cases[0], '_finite_success_consumed', None) if cases else None
                    if (hold_intent and host and threading.get_ident() == host[0][1]
                            and completion is not None and condition is completion._cond):
                        publication.put((condition, active))
                    try:
                        return original_wait(condition, timeout)
                    finally:
                        active[0] = False

                def receive(process, message):
                    value = original_receive(process, message)
                    if (not process.validator and not process.is_tool
                            and message.get('id') == 'EXAMPLE-request-EXAMPLE-command-call'
                            and message.get('result', {}).get('success') is True):
                        held.append(True)
                        cases.append(process.case)
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

                def fsync(descriptor):
                    value = original_fsync(descriptor)
                    if not hold_intent or not cases or intent_held:
                        return value
                    path = Path(os.readlink('/proc/self/fd/' + str(descriptor)))
                    if path.parent != cases[0].factory.records / 'transport-observations':
                        return value
                    if json.loads(path.read_bytes()).get('stage') != 'finite-poll-intent':
                        return value
                    intent_held.append(True)
                    # The actual durable write has completed. Hold its return
                    # until the host joins the original consumer, or let the
                    # unchanged one-second ticket fence reject the old fixture.
                    try:
                        entry = publication.get(timeout=1.05)
                    except queue.Empty:
                        return value
                    if entry is not None:
                        condition, active = entry
                        self.assertTrue(condition.acquire(timeout=3))
                        try:
                            self.assertTrue(active[0] and condition._waiters)
                            publication_ack.append(True)
                        finally:
                            condition.release()
                    return value

                def fail_transport(server, failure):
                    faults.append(repr(failure))
                    waits.put(None)
                    publication.put(None)
                    return original_fault(server, failure)

                def release_publication():
                    publication.put(None)
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
                    result = self.run_owned_selector(method, [lambda: waits.put(None),
                                                             release_publication])
                try:
                    self.assertTrue(result.wasSuccessful(), (result.failures, result.errors, faults))
                except self.failureException as failure:
                    replies = [case.test.spawned[0].replies for case in cases if case.test.spawned]
                    failure.add_note(f'Original tool reply frames: {replies!r}')
                    raise
                self.assertEqual(held, [True])
                self.assertEqual(len(acknowledged), 1, 'original post-start waiter was not acknowledged')
                self.assertEqual(faults, [])
                if hold_intent:
                    self.assertEqual(intent_held, [True])
                    self.assertEqual(publication_ack, [True])

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
