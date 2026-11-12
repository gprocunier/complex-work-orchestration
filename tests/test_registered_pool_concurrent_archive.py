"""Pool-level positive concurrent archive ordering, using the original N1 path.

Only fake RPC delivery and the cooperative polling clock are scheduled here.
Original host/control/adapter methods,64 steps, deadlines and close checks stay
intact. Real monotonic time still bounds repository inspection and RPC/cleanup.
"""
from __future__ import annotations

import contextvars
from contextlib import ExitStack
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from tests import test_registered_native_pool_host as pools


class _CooperativeClock:
    """Advance poll time only at declared waits; park a pending archive step."""

    def __init__(self, test, fixture, gates):
        self.test, self.fixture, self.gates = test, fixture, gates
        self.ns = 0
        self.waits = []

    def sleep(self, seconds):
        self.test.assertEqual(seconds, .002)
        for member, gate in zip(self.fixture.fixtures, self.gates):
            factory = member.workflow.factory
            adapter = None if factory is None else getattr(factory, 'adapter', None)
            archive = None if adapter is None else adapter._staged_archive
            if archive is None or archive._done.is_set():
                continue
            # One original close must really return pending. The first wait
            # after finalize is allowed; the following close-wait is parked.
            self.test.assertTrue(gate.entered.wait(8), 'concurrent archive RPC was not issued')
            if adapter.callback_latencies.get('close'):
                gate.clock_before = self.ns
                gate.pending.set()
                self.test.assertTrue(gate.resume.wait(8), 'concurrent archive clock was not resumed')
                self.test.assertTrue(archive._done.is_set(), 'poll clock resumed before actual archive completion')
        self.waits.append(seconds)
        self.ns += round(seconds * 1_000_000_000)


class ConcurrentArchivePoolTests(unittest.TestCase):
    def _observe(self, event, worker, outcome, label):
        deadline = time.monotonic() + pools.N.STARTUP_OBSERVATION_SECONDS
        while not event.is_set():
            self.assertTrue(worker.is_alive(), 'concurrent pool ended before ' + label + ': ' + repr(outcome))
            remaining = deadline - time.monotonic()
            self.assertGreater(remaining, 0, 'concurrent pool observation expired: ' + label)
            event.wait(min(.01, remaining))

    def test_original_pool_passes_after_observing_concurrent_archive_pending(self):
        with pools.F.WorkflowTests.read_only_source_family(self) as source, ExitStack() as cleanups:
            fixture = pools.PoolTests('runTest')
            fixture._outcome = self._outcome
            cleanups.callback(fixture.doCleanups)
            host = fixture.cohort(2, archive_schedule='concurrent', shared_source=True,
                                  source_evidence=source())
            gates = [SimpleNamespace(entered=threading.Event(), release=threading.Event(),
                                     pending=threading.Event(), resume=threading.Event(), clock_before=None)
                     for _ in fixture.fixtures]
            clock = _CooperativeClock(self, fixture, gates)
            original_result = pools.N.RpcProcess.result

            def rpc_result(process, method, params):
                if method == 'thread/archive':
                    index = next(index for index, member in enumerate(fixture.fixtures)
                                 if process.case is member.case)
                    gate = gates[index]
                    gate.entered.set()
                    self.assertTrue(gate.release.wait(8), 'concurrent archive RPC was not released')
                return original_result(process, method, params)

            outcome = []
            def run():
                try:
                    outcome.append(fixture.execute())
                except BaseException as failure:
                    outcome.append(failure)

            # Replace this module's wait dependency, never the shared time
            # module or a protected adapter/driver method. Inspection keeps its
            # original real monotonic bound; virtual poll advancement is exact.
            poll_time = SimpleNamespace(sleep=clock.sleep, monotonic=time.monotonic)
            with patch.object(pools.N.RpcProcess, 'result', rpc_result), patch.object(
                    pools.N.runtime.native, 'time', poll_time):
                context = contextvars.copy_context()
                worker = threading.Thread(target=context.run, args=(run,), daemon=True)
                worker.start()
                try:
                    for index, (member, gate) in enumerate(zip(fixture.fixtures, gates)):
                        self._observe(gate.entered, worker, outcome, 'archive request')
                        self._observe(gate.pending, worker, outcome, 'original close-pending')
                        adapter = member.workflow.factory.adapter
                        archive = adapter._staged_archive
                        self.assertFalse(getattr(member.case, '_original_archive_settlement', False))
                        self.assertTrue(archive._started)
                        self.assertFalse(archive._done.is_set())
                        self.assertFalse(adapter.archived)
                        self.assertEqual(len(adapter.callback_latencies['close']), 1)
                        self.assertEqual(host.rows[index], 'running')
                        self.assertEqual(outcome, [])
                        self.assertFalse((host.config.state / 'terminal.json').exists())
                        self.assertEqual(clock.ns, gate.clock_before)
                        for later in fixture.fixtures[index + 1:]:
                            self.assertFalse(getattr(later.fixture, 'spawned', []))
                        gate.release.set()
                        self.assertTrue(archive._done.wait(8), 'actual concurrent archive did not complete')
                        self.assertIsNone(archive._error)
                        gate.resume.set()
                    worker.join(15)
                finally:
                    for gate in gates:
                        gate.release.set()
                        gate.resume.set()
                    worker.join(15)
                self.assertFalse(worker.is_alive())

            self.assertEqual(len(outcome), 1)
            self.assertIsInstance(outcome[0], dict, repr(outcome[0]))
            report = outcome[0]
            self.assertEqual(report['states'], ['validated', 'validated'])
            self.assertEqual(report, host.status())
            self.assertFalse(report['publication_authorized'])
            fixture.assert_accounting(2)
            self.assertTrue(clock.waits)
            self.assertEqual(clock.ns, round(sum(clock.waits) * 1_000_000_000))
            for member in fixture.fixtures:
                factory = member.workflow.factory
                receipt = factory.execution['receipt']
                self.assertEqual(member.case.spec['max_steps'], 64)
                self.assertEqual(receipt['terminal_state'], 'completed')
                self.assertEqual(receipt['errors'], [])
                self.assertGreaterEqual(receipt['actions'].count('close'), 2)
                self.assertEqual(member.fixture.spawned[0].methods.count('thread/archive'), 1)
                self.assertEqual(len(member.fixture.spawned), 2)
                self.assertTrue(factory.adapter.archived)
                self.assertTrue(factory.server.lifetime.termination['child_reaped'])
                self.assertFalse((member.case.host.target / 'result.txt').exists())
            with self.assertRaisesRegex(ValueError, 'never redispatch'):
                host.run(host.config.request('execute'))


if __name__ == '__main__':
    unittest.main()
