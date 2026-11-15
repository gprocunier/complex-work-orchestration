"""The original record producer must stop before factory cleanup returns."""
import threading
import unittest
from unittest.mock import patch

from tests import test_registered_n1_factory as family
from tests.test_registered_finite_tool_wiring import DynamicRpcProcess


class ToolWorkerOwnershipTests(unittest.TestCase):
    def test_original_record_writer_is_joined_before_factory_return(self):
        helper = family.FactoryTests('runTest')
        helper.setUp()
        self.addCleanup(family.cleanup_helper, self, helper)
        # This witness must not depend on the optional fixture scheduler or on
        # another test family's default for initial session publication.
        case = helper.case(finite_tool_mode='captured-host-tools',
                           materialize_on_turn_start=True)
        case.command_prepared, case.command_release = threading.Event(), threading.Event()
        factory = helper.factory(case)
        entered, release, done = (threading.Event() for _ in range(3))
        producers, writers, joined, outcome = [], [], [], []
        primary = RuntimeError('EXAMPLE original transport fault')
        original_record = factory.record
        original_start, original_join = threading.Thread.start, threading.Thread.join

        def record(stage, observation):
            if stage == 'finite-tool-command-intent':
                writers.append(threading.current_thread())
                entered.set()
                self.assertTrue(release.wait(12), 'original record writer was not released')
            return original_record(stage, observation)

        def start(worker):
            producers.append(worker)
            return original_start(worker)

        def join(worker, *args, **kwargs):
            if worker in writers:
                joined.append(worker)
                # Release at the owner's actual join, within its existing
                # cleanup bound; no elapsed-time guess stands in for a join.
                release.set()
            return original_join(worker, *args, **kwargs)

        def run():
            try:
                outcome.append(factory.run())
            except BaseException as failure:
                outcome.append(failure)
            finally:
                done.set()

        with patch.object(family, 'RpcProcess', DynamicRpcProcess), \
                patch.object(threading.Thread, 'start', start), \
                patch.object(threading.Thread, 'join', join):
            worker = threading.Thread(target=run, daemon=True)
            worker.start()
            try:
                family.wait_for_startup(self, case.command_prepared, worker, outcome)
                # Install only after original method admission, as in witness B.
                with patch.object(factory, 'record', record):
                    case.command_release.set()
                    family.wait_for_startup(self, entered, worker, outcome)
                    self.assertEqual(len(writers), 1)
                    self.assertIsNot(writers[0], worker)
                    factory.server._fail_transport(primary)
                    self.assertTrue(done.wait(5), 'factory cleanup did not finish within the witness bound')
                    self.assertFalse(writers[0].is_alive(),
                                     'original tool record writer outlived factory cleanup')
                    self.assertEqual(joined, writers)
                    self.assertIs(factory.server.transport_failure, primary)
                    self.assertIsInstance(outcome[0], BaseException)
                    self.assertIsNone(factory.token)
                    attempt = helper.attempt(case)
                    self.assertEqual(attempt['outcome'], 'unknown')
                    self.assertEqual(attempt['charge'], attempt['amount'])
            finally:
                case.command_release.set()
                release.set()
                # Retain and drain the exact original producers, including the
                # old runtime's unretained cleanup thread, before helper cleanup
                # can delete its TemporaryDirectory even on the expected red.
                original_join(worker, 12)
                for producer in producers:
                    if producer is not worker and producer.ident is not None:
                        original_join(producer, 2)
                self.assertFalse(any(producer.is_alive() for producer in producers),
                                 'original producer survived fixture cleanup')
