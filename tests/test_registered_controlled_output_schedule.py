"""Selected output rejection with an original archive acknowledgment in flight."""
from __future__ import annotations

import json
import sys
import threading
import unittest
from unittest.mock import patch

from tests import test_registered_finite_input as finite
from tests import test_registered_n1_factory as family


class ControlledOutputScheduleTests(unittest.TestCase):
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
            read(process, line)
            frame = json.loads(line)
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
            try:
                original.test_selected_original_output_rejection_is_failed_and_fully_charged()
            except BaseException as failure:
                failure.add_note('EXAMPLE original archive schedule: ' + repr(observations))
                raise
            finally:
                release.set()
                if fixture.spawned:
                    case = fixture.spawned[0].case
                    archive = case.factory.server.staged_archive(case.scenario.thread_id)
                    for worker in workers:
                        worker.join(8)
                    self.assertFalse(any(worker.is_alive() for worker in workers),
                                     'EXAMPLE original archive worker survived cleanup')
                    if archive is not None:
                        self.assertTrue(archive.completion_ready())
                    fixture.spawned[0].stdin.stream.require_healthy()
        self.assertTrue(queued.is_set())
        self.assertIn('blocking-archive-observation', observations)
        self.assertFalse(any(isinstance(row, tuple) for row in observations), observations)
        self.assertTrue(archives)
        self.assertIsNone(fixture.spawned[0].pending)
        self.assertEqual(fixture.spawned[0].replies, [
            {'id': 'EXAMPLE-request', 'result': {'decision': 'accept'}}])
        self.assertIsNone(case.factory.server.finite_tools)
        self.assertEqual(case.spec['max_steps'], 64)


if __name__ == '__main__':
    unittest.main()
