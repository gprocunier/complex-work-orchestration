"""MINOR-5: idle fake output models a blocking pipe, with explicit bounded cleanup."""
import json
import os
import queue
import threading
import unittest
from unittest.mock import patch

from tests import test_registered_n1_factory as family


class FakeLinesTests(unittest.TestCase):
    def reader(self, stream, action=None):
        result = []
        def read():
            try:
                result.append((stream.readline if action is None else action)())
            except BaseException as failure:
                result.append(failure)
        thread = threading.Thread(target=read, daemon=True)
        thread.start()
        self.addCleanup(thread.join, 1)
        self.addCleanup(stream.close)
        return thread, result

    def test_idle_wait_has_no_synthetic_timeout_then_delivers_original_line(self):
        stream = family.Lines()
        entered = threading.Event()
        class ObservedQueue(queue.Queue):
            def get(inner, block=True, timeout=None):
                self.assertIsNone(timeout, 'idle output cannot invent a transport deadline')
                entered.set()
                return super().get(block, timeout)
        stream.lines = ObservedQueue()
        thread, result = self.reader(stream)
        self.assertTrue(entered.wait(1))
        self.assertEqual(result, [])
        stream.put({'EXAMPLE': 'line'})
        thread.join(1)
        self.assertFalse(thread.is_alive())
        self.assertEqual(result, [json.dumps({'EXAMPLE': 'line'}) + '\n'])

    def test_close_wakes_all_blocked_readers_and_stable_eof(self):
        stream = family.Lines()
        first, one = self.reader(stream)
        second, two = self.reader(stream)
        stream.close()
        stream.close()
        for thread in (first, second):
            thread.join(1)
            self.assertFalse(thread.is_alive())
        self.assertEqual(one, [''])
        self.assertEqual(two, [''])
        self.assertEqual(stream.readline(), '')
        self.assertEqual(stream.read(4096), b'')
        self.assertEqual(list(stream), [])
        with self.assertRaises(ValueError):
            stream.put({'EXAMPLE': 'after close'})

    def test_queued_bytes_precede_close_eof_and_callback_observes_only_bytes(self):
        stream = family.Lines()
        observed = []
        stream.on_line = observed.append
        stream.put({'EXAMPLE': 1})
        stream.put({'EXAMPLE': 2})
        stream.close()
        expected = [json.dumps({'EXAMPLE': n}) + '\n' for n in (1, 2)]
        self.assertEqual(list(stream), expected)
        self.assertEqual(observed, expected)
        self.assertEqual(stream.readline(), '')

    def test_original_raw_queue_eof_and_reader_error_are_not_masked(self):
        stream = family.Lines()
        stream.lines.put('EXAMPLE raw\n')
        stream.lines.put('')
        self.assertEqual(stream.read(4096), b'EXAMPLE raw\n')
        self.assertEqual(stream.readline(), '')
        with self.assertRaises(ValueError):
            stream.put({'EXAMPLE': 'after EOF'})
        failure = queue.Empty('EXAMPLE injected reader failure')
        class FailingQueue:
            def get(self):
                raise failure
        failed = family.Lines()
        failed.lines = FailingQueue()
        with self.assertRaises(queue.Empty) as caught:
            failed.readline()
        self.assertIs(caught.exception, failure)
        self.assertFalse(failed._eof)

    def test_idle_and_explicit_writer_eof_match_real_pipe(self):
        read, write = os.pipe()
        stream = os.fdopen(read, 'r')
        writer = os.fdopen(write, 'w')
        result, entered = [], threading.Event()
        def consume():
            entered.set()
            result.append(stream.readline())
        thread = threading.Thread(target=consume, daemon=True)
        thread.start()
        self.addCleanup(thread.join, 1)
        self.addCleanup(stream.close)
        self.addCleanup(writer.close)
        self.assertTrue(entered.wait(1))
        self.assertEqual(result, [])
        writer.close()
        thread.join(1)
        self.assertFalse(thread.is_alive())
        self.assertEqual(result, [''])

    def test_injected_reader_error_preserves_original_transport_failure_and_charge(self):
        helper = family.FactoryTests(methodName='runTest')
        helper.setUp()
        self.addCleanup(family.cleanup_helper, self, helper)
        case = helper.case()
        factory = helper.factory(case)
        failure = queue.Empty('EXAMPLE actual fake-reader failure')
        injected = []
        class FailingQueue(queue.Queue):
            def get(self, *args, **kwargs):
                value = super().get(*args, **kwargs)
                if value is failure:
                    raise failure
                return value
        class FailingProcess(family.RpcProcess):
            def __init__(self, process, current, validator=False):
                super().__init__(process, current, validator=validator)
                if not validator:
                    self.stderr.lines = FailingQueue()
            def result(self, method, params):
                result = super().result(method, params)
                if method == 'turn/start':
                    injected.append(method)
                    self.stderr.lines.put(failure)
                return result
        with patch.object(family, 'RpcProcess', FailingProcess), \
                self.assertRaises((ValueError, family.runtime.AppServerError)):
            factory.run()
        self.assertEqual(injected, ['turn/start'])
        self.assertIs(factory.server.transport_failure, failure)
        self.assertIs(factory.server.request_failure, failure)
        self.assertIsNone(factory.token)
        self.assertFalse((case.host.state / 'artifact').exists())
        self.assertEqual(helper.attempt(case)['outcome'], 'unknown')
        self.assertEqual(helper.attempt(case)['charge'], helper.attempt(case)['amount'])
        self.assertEqual(factory.execution['receipt']['terminal_state'], 'control-failed')
        # This route never selected captured tools; a fault cannot select them.
        self.assertEqual(factory.server.finite_input.lifecycle.phase, 'unselected')
