"""Composed scheduling cleanup and fake child exit preserve original failures."""
import json
import os
import signal
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from tests import test_registered_n1_factory as family
from tests import test_registered_finite_tool_wiring as wiring
from tests import test_registered_finite_input as finite


class ToolPipePublicationTests(unittest.TestCase):
    def pair(self, *, output=None):
        self.spawned = []
        owner = self
        tools, workers = [], []
        class Case:
            test = owner
            scenario = SimpleNamespace(thread_id='EXAMPLE-thread', turn_id='EXAMPLE-turn')
            def stop(self):
                tool = tools[0]
                tool.process.alive = False
                tool.stdout.put('')
                return 'EXAMPLE late tool output\n'
            @property
            def poll_output(self):
                return self.stop() if output == 'poll' else 'EXAMPLE poll output\n'
            @property
            def command_output(self):
                return self.stop() if output == 'bootstrap' else 'EXAMPLE command output\n'
        case = Case()
        transport = wiring.DynamicRpcProcess(family.children.FakeProcess(991), case)
        self.spawned.append(transport)
        original_thread = threading.Thread
        def retain(*args, **kwargs):
            worker = original_thread(*args, **kwargs)
            workers.append(worker)
            return worker
        with patch.object(wiring.threading, 'Thread', side_effect=retain):
            tool = wiring.DynamicRpcProcess(family.children.FakeProcess(992), case)
        tools.append(tool)
        self.spawned.append(tool)
        self.addCleanup(setattr, tool.process, 'alive', False)
        self.assertEqual(tool.stdout.readline(), family.runtime._READY)
        return case, transport, tool, workers[0]

    def test_poll_reply_stopped_after_liveness_check_cannot_write_to_closed_tool_pipe(self):
        _case, transport, tool, _worker = self.pair(output='poll')
        sent = []
        transport._send_tool = lambda *args: sent.append(args)
        read, write = os.pipe()
        with os.fdopen(write, 'w') as stream:
            stream.write('1' + json.dumps({'id': 'EXAMPLE-request-EXAMPLE-command-call',
                                          'result': {'success': True}}) + '\n')
        transport.stdin.consume(read)
        transport.stdin.require_healthy()
        self.assertFalse(tool.process.alive)
        self.assertEqual(tool.stdout.reader.read(), b'')
        self.assertEqual(sent, [])
        self.assertIsNone(transport.stdin.failure)

    def test_bootstrap_stopped_after_gate_read_cannot_emit_useful_output(self):
        failures = []
        with patch.object(threading, 'excepthook', lambda args: failures.append(args.exc_value)):
            _case, _transport, tool, worker = self.pair(output='bootstrap')
            os.write(tool.stdin.fileno(), b'1')
            worker.join(1)
        self.assertFalse(worker.is_alive())
        self.assertTrue(tool.bootstrap_released.is_set())
        self.assertFalse(tool.process.alive)
        self.assertEqual(tool.stdout.reader.read(), b'')
        self.assertEqual(failures, [])

    def test_inflight_tool_write_completes_before_containment_closes_its_pipe(self):
        _case, _transport, tool, _bootstrap = self.pair()
        entered, resume, attempted, closed = (threading.Event() for _ in range(4))
        failures = []
        original = tool.stdout.writer
        def write(data):
            entered.set()
            self.assertTrue(resume.wait(2))
            return original.write(data)
        tool.stdout.writer = SimpleNamespace(write=write, close=original.close, closed=False)
        def publish():
            try:
                tool.stdout.put('EXAMPLE prior publication\n')
            except BaseException as error:
                failures.append(error)
        def contain():
            attempted.set()
            tool.process.alive = False
            tool.stdout.put('')
            closed.set()
        publisher = threading.Thread(target=publish, daemon=True)
        closer = threading.Thread(target=contain, daemon=True)
        try:
            publisher.start()
            self.assertTrue(entered.wait(1))
            closer.start()
            self.assertTrue(attempted.wait(1))
            self.assertFalse(closed.wait(.05), 'Containment bypassed the in-flight publication guard')
        finally:
            resume.set()
            publisher.join(1)
            closer.join(1)
            tool.stdout.writer = original
        self.assertFalse(publisher.is_alive() or closer.is_alive())
        self.assertEqual(failures, [])
        self.assertTrue(closed.is_set())
        self.assertEqual(tool.stdout.reader.read(), b'EXAMPLE prior publication\n')

    def test_live_tool_closed_writer_still_raises_before_dead_child_drop(self):
        _case, _transport, tool, _bootstrap = self.pair()
        tool.stdout.put('')
        with self.assertRaises(ValueError):
            tool.stdout.put('EXAMPLE live-child failure\n')
        tool.process.alive = False
        self.assertIs(tool.stdout.put('EXAMPLE contained child output\n'), False)



class FixtureLifecycleTests(unittest.TestCase):
    def test_startup_observer_preserves_worker_failure_and_has_bounded_expiry(self):
        fixture = wiring.RegisteredFiniteToolWiringTests(methodName='runTest')
        ready = threading.Event()
        primary = RuntimeError('EXAMPLE original worker failure')
        ended = SimpleNamespace(is_alive=lambda: False)
        with self.assertRaises(RuntimeError) as caught:
            fixture.wait_for_startup(ready, ended, [primary])
        self.assertIs(caught.exception, primary)
        with self.assertRaisesRegex(AssertionError, 'worker ended before'):
            fixture.wait_for_startup(ready, ended, [{}])
        running = SimpleNamespace(is_alive=lambda: True)
        with patch.object(wiring.time, 'monotonic', side_effect=[0, 51]), \
                self.assertRaisesRegex(AssertionError, 'startup observation expired'):
            fixture.wait_for_startup(ready, running, [])
        ready.set()
        self.assertTrue(fixture.wait_for_startup(ready, running, []))

    def test_worker_cleanup_releases_before_bounded_join_and_refuses_live_tail(self):
        released = threading.Event()
        calls = []
        def join(timeout):
            self.assertTrue(released.is_set())
            calls.append(timeout)
        worker = SimpleNamespace(join=join, is_alive=lambda: False)
        family.finish_worker(self, worker, released)
        self.assertEqual(calls, [12])
        family.finish_worker(self, worker, released, join_seconds=20)
        self.assertEqual(calls, [12, 20])
        worker.is_alive = lambda: True
        with self.assertRaisesRegex(AssertionError, 'worker did not stop before cleanup'):
            family.finish_worker(self, worker, released)

    def test_fake_input_retains_original_producer_error_for_fixture_outcome(self):
        primary = RuntimeError('EXAMPLE original producer error')
        def receive(_message):
            raise primary
        process = SimpleNamespace(receive=receive, case=SimpleNamespace(test=self),
                                  bootstrap_released=threading.Event())
        stream = family.Input(process)
        read, write = os.pipe()
        with os.fdopen(write, 'w') as output:
            output.write('1{}\n')
        with self.assertRaises(RuntimeError) as caught:
            stream.consume(read)
        self.assertIs(caught.exception, primary)
        self.assertTrue(process.bootstrap_released.is_set())
        self.assertIsNone(stream.failed_input_frame)
        self.assertIs(stream.failure, primary)
        with self.assertRaises(RuntimeError) as cleanup:
            stream.require_healthy()
        self.assertIs(cleanup.exception, primary)

    def test_nested_schedules_release_and_join_before_composed_cleanup_on_failure(self):
        original = wiring.RegisteredFiniteToolWiringTests
        methods = (
            'test_eagain_retry_terminal_orders_on_registered_tool_reply_pipe',
            'test_exceptional_projection_during_command_decision_and_intent',
            'test_all_original_terminal_notifications_wake_before_and_during_wait',
            'test_original_read_projection_wakes_before_and_during_wait',
            'test_original_split_terminal_publication_before_and_during_wait',
            'test_original_trusted_terminal_split_publication',
            'test_original_split_reply_publication_family',
            'test_partial_original_multiturn_and_multiitem_projection_wakes',
        )
        for method in methods:
            with self.subTest(method=method):
                groups, scheduled = [], []
                failure = RuntimeError('EXAMPLE original scheduling assertion')
                owner = self

                class Scheduled(unittest.TestCase):
                    def setUp(inner):
                        inner.events, inner.release = [], threading.Event()
                        groups.append(inner)
                        inner.fixture = unittest.TestCase()
                        inner.fixture.addCleanup(inner.events.append, 'factory')
                        inner.addCleanup(family.cleanup_helper, inner, inner.fixture)

                    def schedule(inner, *args, **kwargs):
                        entered = threading.Event()
                        def run():
                            entered.set()
                            owner.assertTrue(inner.release.wait(5))
                            inner.events.append('worker')
                        inner.worker = threading.Thread(target=run, daemon=True)
                        inner.worker.start()
                        owner.assertTrue(entered.wait(1))
                        def join():
                            inner.worker.join(1)
                            owner.assertFalse(inner.worker.is_alive())
                            inner.events.append('joined')
                        def release():
                            inner.events.append('release')
                            inner.release.set()
                        inner.addCleanup(join)
                        inner.addCleanup(release)
                        scheduled.append(inner)
                        raise failure

                for helper in ('_eagain_tool_reply_terminal_order', '_terminal_during_command',
                               '_terminal_wait_schedule', '_terminal_projection_schedule',
                               '_split_original_publication_schedule', '_split_reply_publication_schedule',
                               '_partial_original_projection_schedule'):
                    setattr(Scheduled, helper, Scheduled.schedule)
                outer = original(method)
                outer.setUp = lambda: None
                result = unittest.TestResult()
                try:
                    with patch.object(wiring, 'RegisteredFiniteToolWiringTests', Scheduled):
                        outer.run(result)
                    observed = [list(group.events) for group in groups]
                finally:
                    for group in groups:
                        group.release.set()
                    for group in groups:
                        if hasattr(group, 'worker'):
                            group.worker.join(1)
                        family.cleanup_helper(self, group)
                self.assertTrue(scheduled)
                self.assertEqual(len(result.errors), len(scheduled))
                self.assertTrue(all('EXAMPLE original scheduling assertion' in error
                                    for _case, error in result.errors))
                self.assertEqual(result.failures, [])
                self.assertEqual(observed, [['release', 'worker', 'joined', 'factory']]
                                 * len(scheduled))

    def test_live_output_and_closed_stream_error_remain_observable(self):
        self.spawned = []
        process = wiring.DynamicRpcProcess(SimpleNamespace(pid=991, alive=True),
                                           SimpleNamespace(test=self))
        self.assertEqual(process.stdout.readline(), family.runtime._READY)
        self.assertFalse(process.bootstrap_released.is_set())
        read, write = os.pipe()
        with os.fdopen(write, 'wb') as gate:
            gate.write(b'1')
        process.stdin.consume(read)
        self.assertTrue(process.bootstrap_released.is_set())
        scenario = SimpleNamespace(thread_id='EXAMPLE-thread', turn_id='EXAMPLE-turn')
        arguments = {'commandCallId': 'EXAMPLE-command-call', 'chars': ''}
        process._send_tool('EXAMPLE-poll-call', 'finite_poll', arguments, scenario)
        first, second = (json.loads(process.stdout.readline()) for _ in range(2))
        self.assertEqual(first['method'], 'item/started')
        self.assertEqual(second['params']['arguments'], arguments)
        process.stdout.close()
        with self.assertRaisesRegex(ValueError, '^EXAMPLE stream is closed$'):
            process._send_tool('EXAMPLE-poll-call', 'finite_poll', arguments, scenario)
        process.process.alive = False
        process._send_tool('EXAMPLE-poll-call', 'finite_poll', arguments, scenario)
        process.receive({'id': 'EXAMPLE-request-EXAMPLE-command-call',
                         'result': {'success': True}})
        with self.assertRaisesRegex(ValueError, '^EXAMPLE stream is closed$'):
            process.stdout.put({'EXAMPLE': 'closed stream still refuses'})

    def test_exit_during_held_rpc_stops_reply_and_preserves_live_failure(self):
        process = family.RpcProcess(family.children.FakeProcess(991), SimpleNamespace(test=self))
        entered, release, result = threading.Event(), threading.Event(), []
        def response(_method, _params):
            entered.set()
            self.assertTrue(release.wait(2))
            return {'EXAMPLE': 'reply'}
        process.result = response
        def receive():
            try:
                result.append(process.receive({'method': 'thread/read', 'params': {}, 'id': 1}))
            except BaseException as failure:
                result.append(failure)
        worker = threading.Thread(target=receive, daemon=True)
        worker.start()
        self.addCleanup(worker.join, 1)
        self.addCleanup(release.set)
        self.assertTrue(entered.wait(1))
        table = family.children.FakeTable()
        table.handles[88] = process.process
        table.send_signal(88, signal.SIGTERM)
        self.assertFalse(process.process.alive)
        self.assertEqual(process.process.signals, [signal.SIGTERM])
        process.stdout.close()
        queued = process.stdout.lines.qsize()
        release.set()
        worker.join(1)
        self.assertFalse(worker.is_alive())
        self.assertEqual(result, [None])
        self.assertEqual(process.stdout.lines.qsize(), queued)
        methods = list(process.methods)
        process.receive({'method': 'thread/read', 'params': {}, 'id': 2})
        process.approve()
        self.assertEqual(process.methods, methods)
        primary = RuntimeError('EXAMPLE original live producer failure')
        def fail(_method, _params):
            raise primary
        process.result = fail
        process.process.alive = True
        with self.assertRaises(RuntimeError) as caught:
            process.receive({'method': 'thread/read', 'params': {}, 'id': 3})
        self.assertIs(caught.exception, primary)

    def test_held_poll_cannot_emit_after_original_child_containment(self):
        for action in ('cancel', 'close'):
            with self.subTest(action=action):
                helper = finite.FiniteInputTests(methodName='runTest')
                helper.setUp()
                failures = []
                original_hook = threading.excepthook
                def hook(args):
                    failures.append(args.exc_value)
                    original_hook(args)
                try:
                    with patch.object(threading, 'excepthook', hook):
                        case, factory, _tool, _stream, _read, release, result = helper._active()
                        runner = helper.fixture.spawned[0]
                        if action == 'cancel':
                            factory.server.requests.cancel_turn(case.scenario.thread_id,
                                                                case.scenario.turn_id)
                        else:
                            factory.server.finite_input.close()
                        self.assertTrue(case.result_done.wait(8))
                        self.assertEqual(len(result), 1)
                        primary = result[0]
                        self.assertIsInstance(primary, BaseException)
                        self.assertFalse(runner.process.alive)
                        self.assertTrue(factory.server.lifetime.contained)
                        self.assertTrue(factory.server.lifetime.termination_recorded)
                        self.assertTrue(runner.stdout.closed)
                        queued = runner.stdout.lines.qsize()
                        release.set()
                        runner.stdin.stream.reader.join(1)
                        self.assertFalse(runner.stdin.stream.reader.is_alive())
                        self.assertEqual(runner.stdout.lines.qsize(), queued)
                        self.assertEqual(failures, [])
                        self.assertIs(result[0], primary)
                        self.assertIsNone(factory.token)
                        attempt = helper.fixture.attempt(case)
                        self.assertEqual(attempt['outcome'], 'unknown')
                        self.assertEqual(attempt['charge'], attempt['amount'])
                finally:
                    family.cleanup_helper(self, helper)

    def test_poll_publication_rechecks_child_after_original_containment(self):
        helper = finite.FiniteInputTests('runTest')
        helper.setUp()
        self.addCleanup(family.cleanup_helper, self, helper)
        failures, attempted = [], []
        entered, resume = threading.Event(), threading.Event()
        self.addCleanup(resume.set)
        with patch.object(threading, 'excepthook', lambda args: failures.append(args.exc_value)):
            case, factory, _tool, _stream, _read, release, result = helper._active()
            runner = helper.fixture.spawned[0]
            original_put = runner.stdout.put

            def put(frame, **kwargs):
                params = frame.get('params', {})
                if (params.get('item', {}).get('id') == 'EXAMPLE-poll-call'
                        or params.get('callId') == 'EXAMPLE-poll-call'):
                    attempted.append(frame)
                if (frame.get('method') == 'item/started'
                        and params.get('item', {}).get('id') == 'EXAMPLE-poll-call'):
                    entered.set()
                    self.assertTrue(resume.wait(15), 'EXAMPLE publication release missing')
                return original_put(frame, **kwargs)

            with patch.object(runner.stdout, 'put', put):
                release.set()
                self.assertTrue(entered.wait(5), 'EXAMPLE poll publication was not reached')
                self.assertTrue(runner.process.alive)
                self.assertFalse(runner.stdout.closed)
                factory.server.finite_input.close()
                self.assertTrue(case.result_done.wait(8))
                self.assertEqual(len(result), 1)
                self.assertIsInstance(result[0], BaseException)
                primary = result[0]
                self.assertFalse(runner.process.alive)
                self.assertTrue(factory.server.lifetime.contained)
                self.assertTrue(factory.server.lifetime.termination_recorded)
                self.assertTrue(runner.stdout.closed)
                queued = runner.stdout.lines.qsize()
                resume.set()
                runner.stdin.stream.reader.join(1)
                self.assertFalse(runner.stdin.stream.reader.is_alive())
                self.assertEqual(runner.stdout.lines.qsize(), queued)
                self.assertIs(result[0], primary)
                self.assertIsNone(factory.token)
                attempt = helper.fixture.attempt(case)
                self.assertEqual(attempt['outcome'], 'unknown')
                self.assertEqual(attempt['charge'], attempt['amount'])
                self.assertEqual(failures, [])
                self.assertEqual(len(attempted), 1)
