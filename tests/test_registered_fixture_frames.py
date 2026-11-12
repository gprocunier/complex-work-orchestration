"""Frozen full-pipe/parse/containment/delegation comparison, two original workflows."""
import json
import os
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from tests import test_registered_n1_factory as family
from tests import test_registered_finite_tool_wiring as wiring
from tests import test_registered_server_requests as requests

class FrameLifecycleTests(unittest.TestCase):
    def process(self, kind, active):
        self.spawned = []
        scenario = SimpleNamespace(thread_id='EXAMPLE-thread', turn_id='EXAMPLE-turn',
            begin_useful=lambda: active.append('useful'),
            record_refusal=lambda *args: active.append('record-refusal'))
        case = SimpleNamespace(test=self, scenario=scenario, effect_schedule=kind == 'effect',
            defer_complete=False, effect_responses={},
            tool_stream=SimpleNamespace(put=lambda value: active.append('tool-output')))
        cls = {'base': family.RpcProcess, 'dynamic': wiring.DynamicRpcProcess,
               'effect': family.RegisteredEffectRpcProcess}[kind]
        process = cls(family.children.FakeProcess(991), case)
        process.pending = 'requested'
        process.complete = lambda: active.append('complete')
        process._followup = lambda effect: active.append(('followup', effect))
        if kind == 'dynamic':
            original = process._send_tool
            def send(*args):
                active.append('send-tool')
                return original(*args)
            process._send_tool = send
        return process

    def test_dead_subclasses_retain_each_passive_reply_without_active_work(self):
        for kind in ('base', 'dynamic', 'effect'):
            for result in ({'decision': 'accept'}, {'decision': 'decline'},
                           {'decision': 'cancel'}, None):
                with self.subTest(kind=kind, result=result):
                    active = []
                    process = self.process(kind, active)
                    message = {'id': 'EXAMPLE-request'}
                    if result is None:
                        message['error'] = {'code': -32601, 'message': 'Unsupported server request'}
                    else:
                        message['result'] = result
                    process.process.alive = False
                    process.stdout.close()
                    queued = process.stdout.lines.qsize()
                    process.receive(message)
                    self.assertEqual(process.replies, [message])
                    self.assertIs(process.replies[0], message)
                    self.assertEqual(active, [])
                    self.assertEqual(process.case.effect_responses, {})
                    self.assertEqual(process.stdout.lines.qsize(), queued)
        for message in (
            {'id': 'EXAMPLE-request-EXAMPLE-command-call', 'result': {'success': True}},
            {'id': 'EXAMPLE-request-EXAMPLE-poll-call', 'result': {'success': True,
             'contentItems': [{'text': json.dumps({'stdout': '', 'running': False})}]}},
        ):
            with self.subTest(dynamic_success=message['id']):
                active = []
                process = self.process('dynamic', active)
                process.process.alive = False
                process.stdout.close()
                process.receive(message)
                self.assertEqual(process.replies, [message])
                self.assertIs(process.replies[0], message)
                self.assertEqual(active, [])
                self.assertFalse(hasattr(process.case, 'poll_observation'))

    def test_live_subclasses_keep_active_callbacks_and_original_errors(self):
        for kind in ('base', 'dynamic', 'effect'):
            with self.subTest(kind=kind):
                active = []
                process = self.process(kind, active)
                message = ({'id': 'EXAMPLE-request-EXAMPLE-command-call', 'result': {'success': True}}
                           if kind == 'dynamic' else
                           {'id': 'EXAMPLE-effect-request-network', 'result': {'permissions': {}}}
                           if kind == 'effect' else
                           {'id': 'EXAMPLE-request', 'result': {'decision': 'accept'}})
                process.receive(message)
                self.assertTrue(active)
                self.assertEqual(process.replies, [message])
                primary = RuntimeError('EXAMPLE original live callback error')
                def fail(*args):
                    raise primary
                setattr(process, {'base': 'complete', 'dynamic': '_send_tool',
                                  'effect': '_followup'}[kind], fail)
                with self.assertRaises(RuntimeError) as caught:
                    process.receive(message)
                self.assertIs(caught.exception, primary)
                self.assertEqual(process.replies, [message, message])

    def input_failure(self, raw, *, stream=None, callback_error=None):
        def receive(_message):
            if callback_error is not None:
                raise callback_error
        if stream is None:
            process = SimpleNamespace(receive=receive, case=SimpleNamespace(test=self))
            stream = family.Input(process)
        else:
            stream.process.receive = receive
        read, write = os.pipe()
        self.assertEqual(os.write(write, raw), len(raw))
        os.close(write)
        expected = type(callback_error) if callback_error is not None else json.JSONDecodeError
        with self.assertRaises(expected) as caught:
            stream.consume(read)
        return stream, caught.exception

    def test_acknowledgement_requires_existing_exact_decoder_error_and_keeps_evidence(self):
        empty = family.Input(SimpleNamespace(case=SimpleNamespace(test=self)))
        preemptive = json.JSONDecodeError('EXAMPLE', 'EXAMPLE', 0)
        for value in (None, preemptive):
            with self.assertRaisesRegex(ValueError, 'exact recorded input parse failure'):
                empty.acknowledge_failure(value)
        self.assertIsNone(empty.failure)
        raw = b'{"id":"EXAMPLE-partial","result":'
        stream, original = self.input_failure(raw)
        self.assertIs(stream.failure, original)
        self.assertEqual(original.doc.encode(), raw)
        wrong = json.JSONDecodeError(original.msg, original.doc, original.pos)
        with self.assertRaises(ValueError):
            stream.acknowledge_failure(wrong)
        with self.assertRaises(json.JSONDecodeError) as unacknowledged:
            stream.require_healthy()
        self.assertIs(unacknowledged.exception, original)
        stream.acknowledge_failure(original)
        stream.require_healthy()
        self.assertIs(stream.failure, original)
        self.assertIs(stream.acknowledged_failure, original)
        self.assertEqual(stream.failed_input_frame.encode(), raw)

    def test_live_callback_failures_cannot_be_acknowledged_as_input_parse_errors(self):
        for primary in (RuntimeError('EXAMPLE live callback'),
                        json.JSONDecodeError('EXAMPLE callback parser', 'EXAMPLE callback', 0)):
            with self.subTest(primary=type(primary).__name__):
                stream, caught = self.input_failure(b'{}\n', callback_error=primary)
                self.assertIs(caught, primary)
                self.assertIsNone(stream.failed_input_frame)
                with self.assertRaises(ValueError):
                    stream.acknowledge_failure(primary)
                with self.assertRaises(type(primary)) as cleanup:
                    stream.require_healthy()
                self.assertIs(cleanup.exception, primary)

    def test_prior_exact_acknowledgement_cannot_cover_a_later_live_failure(self):
        stream, original = self.input_failure(b'{"EXAMPLE":')
        stream.acknowledge_failure(original)
        stream.require_healthy()
        later = RuntimeError('EXAMPLE later unacknowledged callback')
        same_stream, caught = self.input_failure(b'{}\n', stream=stream, callback_error=later)
        self.assertIs(same_stream, stream)
        self.assertIs(caught, later)
        self.assertIs(stream.failure, later)
        self.assertIs(stream.acknowledged_failure, original)
        self.assertIsNone(stream.failed_input_frame)
        with self.assertRaises(RuntimeError) as cleanup:
            stream.require_healthy()
        self.assertIs(cleanup.exception, later)

    def test_nested_request_schedule_cleans_its_own_callbacks_on_failure(self):
        original_class = requests.RegisteredRequestsTests
        groups = []
        owner = self
        class Scheduled(unittest.TestCase):
            def setUp(inner):
                inner.events, inner.release = [], threading.Event()
                groups.append(inner)
                inner.fixture = unittest.TestCase()
                inner.fixture.addCleanup(inner.events.append, 'factory')
                inner.addCleanup(family.cleanup_helper, inner, inner.fixture)
            def _eagain_retry_terminal_order(inner, *args, **kwargs):
                def run():
                    owner.assertTrue(inner.release.wait(5))
                    inner.events.append('worker')
                inner.worker = threading.Thread(target=run, daemon=True)
                inner.worker.start()
                def join():
                    inner.worker.join(1)
                    owner.assertFalse(inner.worker.is_alive())
                    inner.events.append('joined')
                def release():
                    inner.events.append('release')
                    inner.release.set()
                inner.addCleanup(join)
                inner.addCleanup(release)
                raise RuntimeError('EXAMPLE original request scheduling assertion')
        outer = original_class('test_eagain_retry_terminal_orders_on_registered_accept_pipe')
        outer.setUp = lambda: None
        result = unittest.TestResult()
        try:
            with patch.object(requests, 'RegisteredRequestsTests', Scheduled):
                outer.run(result)
            observed = [list(group.events) for group in groups]
        finally:
            for group in groups:
                group.release.set()
                group.worker.join(1)
                family.cleanup_helper(self, group)
        self.assertEqual(len(result.errors), len(groups))
        self.assertTrue(all('EXAMPLE original request scheduling assertion' in error
                            for _case, error in result.errors))
        self.assertEqual(result.failures, [])
        self.assertTrue(groups)
        self.assertEqual(observed, [['release', 'worker', 'joined', 'factory']] * len(groups))

    def test_original_wire_parse_containment_and_delayed_callback(self):
        for kind in ('error', 'accept'):
            with self.subTest(kind=kind):
                helper = family.FactoryTests(methodName='runTest')
                helper.setUp()
                case = helper.case()
                factory = helper.factory(case)
                parsed, release, done, committed = (threading.Event() for _ in range(4))
                events, outcomes, frames, active = [], [], [], []
                original_receive = family.RpcProcess.receive
                original_put, original_write = family.Lines.put, os.write
                original_signal = family.children.FakeTable.send_signal
                original_complete = family.RpcProcess.complete
                started = time.monotonic()
                def record(event, **values):
                    events.append(dict(event=event, seconds=time.monotonic()-started, **values))
                def target(message):
                    return (message.get('id') == 'EXAMPLE-request'
                            and ('error' in message if kind == 'error'
                                 else message.get('result') == {'decision': 'accept'}))
                def receive(process, message):
                    if not process.validator and target(message):
                        record('parsed_complete_frame', alive=process.process.alive, message=message)
                        self.assertTrue(committed.wait(5), 'original full write return not observed')
                        frames.append(message)
                        parsed.set()
                        self.assertTrue(release.wait(12), 'delayed callback release not observed')
                        record('delegate_callback', alive=process.process.alive)
                    return original_receive(process, message)
                def write(descriptor, data):
                    count = original_write(descriptor, data)
                    if (helper.spawned and factory.server is not None
                            and descriptor == getattr(factory.server.process.stdin, 'descriptor', None)):
                        try:
                            message = json.loads(bytes(data))
                        except (ValueError, UnicodeError):
                            message = None
                        if type(message) is dict and target(message):
                            record('original_write_return', count=count, size=len(data),
                                   frame_hex=bytes(data).hex(), alive=helper.spawned[0].process.alive)
                            self.assertEqual(count, len(data))
                            committed.set()
                    return count
                def signal(table, descriptor, signum):
                    if helper.spawned and table.handles.get(descriptor) is helper.spawned[0].process:
                        self.assertTrue(parsed.wait(5), 'containment preceded actual parsed-frame boundary')
                        record('original_signal_enter', alive=helper.spawned[0].process.alive)
                    value = original_signal(table, descriptor, signum)
                    if helper.spawned and table.handles.get(descriptor) is helper.spawned[0].process:
                        record('original_signal_return', alive=helper.spawned[0].process.alive)
                    return value
                def complete(process):
                    active.append(process.process.alive)
                    record('active_complete', alive=process.process.alive)
                    return original_complete(process)
                def unsupported(stream, value):
                    if kind == 'error' and type(value) is dict and value.get('method') == family.runtime.protocol.COMMAND:
                        value = dict(value, method='EXAMPLE/unsupported')
                    return original_put(stream, value)
                def run():
                    try:
                        outcomes.append(factory.run())
                    except BaseException as failure:
                        outcomes.append(failure)
                    finally:
                        done.set()
                worker = threading.Thread(target=run, daemon=True)
                try:
                    with patch.object(family.RpcProcess, 'receive', receive), \
                            patch.object(family.RpcProcess, 'complete', complete), \
                            patch.object(family.Lines, 'put', unsupported), \
                            patch.object(family.children.FakeTable, 'send_signal', signal), \
                            patch.object(os, 'write', write):
                        worker.start()
                        deadline = time.monotonic()+50
                        while not parsed.is_set():
                            self.assertFalse(done.is_set(), repr(outcomes))
                            self.assertLess(time.monotonic(), deadline)
                            parsed.wait(.01)
                        if factory.server.transport_failure is None:
                            factory.server._fail_transport(ValueError('EXAMPLE after-full-write control failure'))
                        self.assertTrue(done.wait(12))
                        self.assertTrue(factory.server.lifetime.contained)
                        self.assertTrue(factory.server.lifetime.termination_recorded)
                        self.assertFalse(helper.spawned[0].process.alive)
                        record('original_containment_complete', failure=repr(factory.server.transport_failure))
                        release.set()
                        helper.spawned[0].stdin.stream.reader.join(2)
                        self.assertFalse(helper.spawned[0].stdin.stream.reader.is_alive())
                        worker.join(12)
                        self.assertFalse(worker.is_alive())
                        self.assertEqual(len(outcomes), 1)
                        self.assertIsInstance(outcomes[0], BaseException)
                        self.assertIsNone(factory.token)
                        self.assertFalse((case.host.state/'artifact').exists())
                        attempt = helper.attempt(case)
                        self.assertEqual(attempt['outcome'], 'unknown')
                        self.assertEqual(attempt['charge'], attempt['amount'])
                        observed = dict(kind=kind, events=events, parsed_frames=frames,
                            passive_replies=helper.spawned[0].replies,
                            active_callback_alive_states=active,
                            worker_result_exists=(case.host.worker/'result.txt').exists(),
                            input_failure=repr(getattr(helper.spawned[0].stdin.stream, 'failure', None)),
                            outcome=repr(outcomes[0]), full_charge=True, no_artifact=True)
                        self.assertEqual(observed['passive_replies'], observed['parsed_frames'])
                        self.assertEqual(len(observed['passive_replies']), 1)
                        self.assertIs(observed['passive_replies'][0], observed['parsed_frames'][0])
                        self.assertEqual(observed['active_callback_alive_states'], [])
                        self.assertFalse(observed['worker_result_exists'])
                finally:
                    release.set()
                    worker.join(12)
                    family.cleanup_helper(self, helper)

