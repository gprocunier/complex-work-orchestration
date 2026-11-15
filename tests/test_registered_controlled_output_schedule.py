"""Selected output rejection with an original archive acknowledgment in flight."""
from __future__ import annotations

import json
import sys
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from tests import test_registered_finite_input as finite
from tests import test_registered_n1_factory as family


def _archive_frame(process, line, original_read):
    original_read(process, line)
    if line == family.runtime._READY and not process.bootstrap_released.is_set():
        return None
    return json.loads(line)


def _finish_archive_schedule(test, fixture, workers, primary):
    try:
        for worker in workers:
            worker.join(8)
        test.assertFalse(any(worker.is_alive() for worker in workers),
                         'EXAMPLE original archive worker survived cleanup')
        if not fixture.spawned:
            return
        process = fixture.spawned[0]
        case, server = process.case, process.case.factory.server
        if server is not None:
            archive = server.staged_archive(case.scenario.thread_id)
            if archive is not None:
                test.assertTrue(archive.completion_ready())
        stream = process.stdin if type(process.stdin) is family.Input else process.stdin.stream
        stream.require_healthy()
    except BaseException as secondary:
        if primary is None:
            raise
        primary.add_note('EXAMPLE original archive cleanup failed: ' + type(secondary).__name__)


class ControlledOutputScheduleTests(unittest.TestCase):
    def test_archive_observer_preserves_bootstrap_phase_and_rpc_failures(self):
        process = SimpleNamespace(bootstrap_released=threading.Event())
        original_read, stream = Mock(), family.Lines()
        self.addCleanup(stream.close)
        stream.on_line = lambda line: _archive_frame(process, line, original_read)
        stream.lines.put(family.runtime._READY)
        self.assertEqual(stream.readline(64), family.runtime._READY)
        original_read.assert_called_once_with(process, family.runtime._READY)
        process.bootstrap_released.set()
        for line in (family.runtime._READY, 'EXAMPLE malformed RPC\n'):
            with self.subTest(line=line), self.assertRaises(json.JSONDecodeError):
                _archive_frame(process, line, original_read)
        self.assertEqual(_archive_frame(process, '{"id": 7, "result": {}}\n', original_read),
                         {'id': 7, 'result': {}})

    def test_partial_construction_cleanup_preserves_primary_and_owned_workers(self):
        for cleanup_failure in (None, OSError('EXAMPLE original input cleanup failure')):
            with self.subTest(cleanup_failure=cleanup_failure):
                release = threading.Event()
                worker = threading.Thread(target=release.wait, daemon=True)
                worker.start()
                stream = Mock()
                stream.require_healthy.side_effect = cleanup_failure
                case = SimpleNamespace(factory=SimpleNamespace(server=None))
                fixture = SimpleNamespace(spawned=[SimpleNamespace(case=case,
                    stdin=SimpleNamespace(stream=stream))])
                primary = RuntimeError('EXAMPLE original startup failure')
                with self.assertRaises(RuntimeError) as caught:
                    try:
                        raise primary
                    finally:
                        release.set()
                        _finish_archive_schedule(self, fixture, [worker], primary)
                self.assertIs(caught.exception, primary)
                self.assertFalse(worker.is_alive())
                self.assertIsNone(case.factory.server)
                stream.require_healthy.assert_called_once_with()
                if cleanup_failure is not None:
                    self.assertIn('EXAMPLE original archive cleanup failed: OSError', primary.__notes__)

    def test_queued_archive_response_preserves_selected_original_rejection(self):
        original = finite.FiniteInputTests('runTest')
        original.setUp()
        self.addCleanup(family.cleanup_helper, self, original)
        fixture = original.fixture
        queued, release = threading.Event(), threading.Event()
        response, observations, archives, workers = {}, [], [], []
        archive_type = sys.modules[family.runtime.RegisteredAdapter.finalize.__module__].StagedThreadArchive
        turn_type = family.runtime.native.NativeControlTurn
        put, read = family.Lines.put, family.RpcProcess.read_line
        settle, interrupt = archive_type.require_complete, turn_type.request_interrupt
        run_archive = archive_type._run

        def produce(archive):
            workers.append(threading.current_thread())
            return run_archive(archive)

        def enqueue(stream, frame, **kwargs):
            selected = (fixture.spawned and stream is fixture.spawned[0].stdout
                        and fixture.spawned[0].methods[-1:] == ['thread/archive']
                        and frame.get('result') == {})
            if selected:
                response['id'] = frame['id']
            result = put(stream, frame, **kwargs)
            if selected:
                observations.append('archive-response-queued')
                queued.set()
            return result

        def consume(process, line):
            frame = _archive_frame(process, line, read)
            if frame is None:
                return
            if frame.get('id') == response.get('id') and 'id' in response:
                # The original producer has queued its real response. Leave
                # parsing/acknowledgment pending while the driver can advance.
                observations.append('archive-reader-held')
                family.wait_for_release(self, release, 8)

        def observe(archive, *, timeout_seconds):
            if timeout_seconds > 0:
                self.assertTrue(queued.wait(8))
                observations.append('blocking-archive-observation')
                release.set()
            archives.append(archive)
            return settle(archive, timeout_seconds=timeout_seconds)

        def control_lost(turn, reason='pool-interrupt'):
            if reason == 'control-lost':
                observations.append(('step-bound', turn._phase, list(turn._decisions)))
                release.set()
            return interrupt(turn, reason)

        with (patch.object(family.Lines, 'put', enqueue),
              patch.object(family.RpcProcess, 'read_line', consume),
              patch.object(archive_type, '_run', produce),
              patch.object(archive_type, 'require_complete', observe),
              patch.object(turn_type, 'request_interrupt', control_lost)):
            primary = None
            try:
                original.test_selected_original_output_rejection_is_failed_and_fully_charged()
            except BaseException as failure:
                primary = failure
                failure.add_note('EXAMPLE original archive schedule: ' + repr(observations))
                raise
            finally:
                release.set()
                _finish_archive_schedule(self, fixture, workers, primary)
        self.assertTrue(queued.is_set())
        self.assertIn('blocking-archive-observation', observations)
        self.assertFalse(any(isinstance(row, tuple) for row in observations), observations)
        self.assertTrue(archives)
        self.assertIsNone(fixture.spawned[0].pending)
        self.assertEqual(fixture.spawned[0].replies, [
            {'id': 'EXAMPLE-request', 'result': {'decision': 'accept'}}])
        case = fixture.spawned[0].case
        self.assertIsNone(case.factory.server.finite_tools)
        self.assertEqual(case.spec['max_steps'], 64)


if __name__ == '__main__':
    unittest.main()
