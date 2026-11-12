"""Approved registered pool retry join; fake OS/RPC, original authority APIs.

Import fixture modules rather than concrete TestCases: original matrices remain
separately collected. Allowance assertions use immutable original receipts.
"""
from __future__ import annotations

import copy
import contextvars
import hashlib
import json
from pathlib import Path
import sys
import threading
from typing import NamedTuple
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / 'scripts'), str(ROOT / 'tests')]
import registered_native_pool_retry as A  # noqa: E402
import test_registered_native_pool_host as F  # noqa: E402
_PIPE_BACKEND = A.R._PipeBackend


class RetryRefusalRow(NamedTuple):
    original_id: str
    unknown: bool
    exact_quota: bool


class ApprovedRetryTests(unittest.TestCase):
    def cohort(self, *, exact_quota=False, unknown=False):
        self.pool = F.PoolTests('runTest')
        self.pool._outcome = self._outcome
        self.addCleanup(F.N.cleanup_helper, self, self.pool)
        self.pool.cohort(3, archive_schedule='settled', shared_source=True)
        p = self.pool
        self.amounts = [json.loads(c.receipt.amounts_bytes) for c in p.config.controllers]
        self.issued_amounts = []
        self.total = {k: sum(a[k] for a in self.amounts) for k in self.amounts[0]}
        # Protected bootstrap selection, bound before original pool intent.
        # Selection alone cannot turn an unknown failure into issued proof.
        p.config.controlled_failure_workers = (p.workers[1],)
        if exact_quota:
            p.config.limits = dict(self.total)
        p.config.binding = p.config.describe()
        if unknown:
            p.fixtures[1].case.drift = True
        else:
            p.fixtures[1].case.bad_output = True
        with self.assertRaises(ValueError):
            p.execute()
        self.assertEqual(p.host.status()['states'], ['validated', 'failed', 'held'])
        self.before = copy.deepcopy(p.attempts())
        self.member_before = [(c.ledger.root / A.R.admission.ledger_api.LEDGER_FILE).read_bytes()
                              if (c.ledger.root / A.R.admission.ledger_api.LEDGER_FILE).exists() else None
                              for c in p.config.controllers]
        self.sibling = p.config.workflows[0]._artifact
        return p

    def selected(self, retry_id='EXAMPLE-approved-retry'):
        p = self.pool
        root = p.state.parent / retry_id
        root.mkdir(mode=0o700)
        controller = A.issue_controller(p.config.workflows[1], retry_id=retry_id, state_directory=root)
        retry = A.ApprovedPoolRetry(p.host, worker_id=p.workers[1], retry_id=retry_id, controller=controller)
        self.issued_amounts.append(json.loads(controller.receipt.amounts_bytes))
        return retry

    def consent(self, retry):
        return {'boundary': 'local-only', 'allowed_effects': ['native-worker', 'target-publication'],
                'request_sha256': hashlib.sha256(retry.workflow.config.receipt.request_bytes).hexdigest()}

    def adopt(self, retry):
        return retry.adopt_execution(adoption_id='EXAMPLE_FRESH_RETRY_ADOPTION',
                                     disclosure_consent=self.consent(retry))

    def fake_retry(self, retry):
        # Rebind only the EXAMPLE kernel/RPC fixture to the freshly issued real
        # controller. Original adapters, admission and validators stay in use.
        fixture = self.pool.fixtures[1]
        case = copy.copy(fixture.case)
        c = retry.workflow.config
        case.host, case.receipt, case.route, case.node_id = c.host, c.receipt, c.route, c.node_id
        # A copied old-host settlement marker does not cover this fresh host.
        case._original_archive_settlement = False
        case.ledger, case.policy = c.ledger, c.policy
        case.spec = copy.deepcopy(c.native_bundle[0]['registered_n1'])
        case.home = c.host.state / 'fake-server' / 'codex-home'
        case.scenario = F.N.fixtures.AdmittedFakeServer(c.host.state / 'fake-server', c.host.worker,
                                                       c.receipt.request_bytes.decode())
        case.scenario.ledger, case.scenario.admission = c.ledger, c.receipt
        case.scenario.expected_observers = ['RegisteredN1Factory._observer']
        case.bad_output, case.drift = False, False
        def startup():
            outer = self.pool.attempts()
            following = [v for k, v in outer.items() if k not in self.before]
            self.assertEqual(len(following), 1)
            self.assertEqual(following[0]['state'], 'invocation-intent')
            self.assertEqual(following[0]['amount'], json.loads(c.receipt.amounts_bytes))
            self.assertTrue(all(outer[k] == v for k, v in self.before.items()))
            case.outer_intent = copy.deepcopy(following[0])
        case.on_startup = startup
        fixture.case, fixture.workflow = case, retry.workflow
        self.enterContext(patch.object(A.R, '_PipeBackend', _PIPE_BACKEND))
        fixture.fixture._boundaries(case)
        F.N.settle_original_archive(fixture.fixture, case)
        return fixture.fixture.spawned

    def assert_retained(self, new_attempts):
        p = self.pool
        attempts = p.attempts()
        self.assertEqual(len(attempts), len(self.before) + new_attempts)
        self.assertTrue(all(attempts[k] == v for k, v in self.before.items()))
        for c, before in zip(p.config.controllers, self.member_before):
            path = c.ledger.root / A.R.admission.ledger_api.LEDGER_FILE
            self.assertEqual(path.read_bytes() if path.exists() else None, before)
        # These layers account for the same effect, not additional provider cost.
        expected = {k: self.total[k] + sum(a[k] for a in self.issued_amounts[:new_attempts]) for k in self.total}
        self.assertEqual(p.ledger.summary(p.config.pool_id)['charged'], expected)
        host, token, report, target, policy = self.sibling
        self.assertEqual(A.W.V.consume_validated(host, token, report, target, policy),
                         (('result.txt', F.N.fixtures.host_fixtures.OUTPUT),))
        self.assertEqual(p.host.status()['states'], ['validated', 'failed', 'held'])

    def test_r2_explicit_retry_actual_fresh_invocation_retains_old_sibling_and_replays(self):
        self.cohort()
        retry = self.selected()
        spawned = self.fake_retry(retry)
        with self.assertRaisesRegex(ValueError, 'adoption'):
            retry.run()
        self.assertEqual(spawned, [])
        with self.assertRaisesRegex(ValueError, 'disclosure consent'):
            retry.adopt_execution(adoption_id='EXAMPLE_FRESH', disclosure_consent={'accepted': True})
        self.adopt(retry)
        result = retry.run()
        self.assertEqual((result['state'], result['outcome']), ('terminal', 'completed'))
        self.assertEqual(len(spawned), 2)
        self.assertIn('turn/start', spawned[0].methods)
        self.assertTrue(retry.workflow.factory.server.lifetime.contained)
        host, token, report, target, policy = retry.workflow._artifact
        self.assertEqual(A.W.V.consume_validated(host, token, report, target, policy),
                         (('result.txt', F.N.fixtures.host_fixtures.OUTPUT),))
        self.assertFalse((host.target / 'result.txt').exists())
        self.assertEqual(retry.run(), result)
        self.assertEqual(retry.status(), result)
        with patch.object(retry.parent, 'factory', None):
            self.assertEqual(A.observe_retry(A.P.RegisteredNativePoolHost(self.pool.config), retry.retry_id), result)
        self.assertEqual(len(spawned), 2)
        self.assertEqual(self.pool.fixtures[1].case.outer_intent['state'], 'invocation-intent')
        following = next(v for k, v in self.pool.attempts().items() if k not in self.before)
        parent = next(v for v in self.before.values() if v['request_id'] == self.pool.workers[1])
        self.assertEqual(following['lineage'], {'kind': 'retry', 'parent_attempt_id': parent['attempt_id']})
        self.assert_retained(1)

    def test_r2_retry_refusal_without_new_invocation_family(self):
        rows = (
            RetryRefusalRow('test_r2_unknown_parent_and_ordinary_replay_zero_new_invocation', True, False),
            RetryRefusalRow('test_r2_profile_drift_and_exhausted_original_quota_zero_new_invocation', False, True),
        )
        for row in rows:
            with self.subTest(original_id=row.original_id):
                try:
                    self.cohort(unknown=row.unknown, exact_quota=row.exact_quota)
                    retry = self.selected()
                    spawned = self.fake_retry(retry)
                    if row.unknown:
                        with self.assertRaises(ValueError):
                            self.adopt(retry)
                        with self.assertRaises(ValueError):
                            retry.run()
                        with self.assertRaises(ValueError):
                            self.pool.host.run(self.pool.config.request('execute'))
                    else:
                        self.adopt(retry)
                        spec = retry.workflow.config.native_bundle[0]['registered_n1']
                        original_profile = spec['thread_start']['permissions']
                        spec['thread_start']['permissions'] = 'EXAMPLE_WEAKER_PROFILE'
                        with self.assertRaises(ValueError):
                            retry.run()
                        spec['thread_start']['permissions'] = original_profile
                        with self.assertRaisesRegex(A.R.admission.ledger_api.InvocationLedgerError,
                                                    'aggregate allowance exhausted'):
                            retry.run()
                        self.assertEqual(retry.status()['state'], 'refused')
                    self.assertEqual(spawned, [])
                    self.assert_retained(0)
                finally:
                    self.doCleanups()

    def test_r2_concurrent_claim_and_mutated_replay_cannot_dispatch_twice(self):
        self.cohort()
        retry = self.selected()
        spawned = self.fake_retry(retry)
        self.adopt(retry)
        gate, results, adoptions = threading.Barrier(3), [], []
        def run():
            gate.wait()
            try:
                results.append(retry.run())
            except BlockingIOError:
                results.append('busy')
            except BaseException as failure:
                results.append(failure)
        def adopt():
            gate.wait()
            try:
                self.adopt(retry)
                adoptions.append('adopted')
            except BlockingIOError:
                adoptions.append('busy')
            except ValueError:
                adoptions.append('refused')
        threads = [threading.Thread(target=contextvars.copy_context().run, args=(run,)) for _ in range(2)] + [
            threading.Thread(target=contextvars.copy_context().run, args=(adopt,))]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(30)
        self.assertTrue(all(not t.is_alive() for t in threads))
        self.assertEqual(len(adoptions), 1)
        self.assertEqual(len(results), 2)
        self.assertTrue(all(type(r) is dict or r == 'busy' for r in results), results)
        # Adoption may win the lock while both concurrent runs observe busy.
        # This explicit subsequent call either starts the still-unused claim or
        # reads the winner's terminal; it must never cause a second invocation.
        self.assertEqual(retry.run()['state'], 'terminal')
        self.assertEqual(len(spawned), 2)
        retry.binding['retry_id'] = 'EXAMPLE-altered'
        with self.assertRaises(ValueError):
            retry.run()
        self.assertEqual(len(spawned), 2)
        self.assert_retained(1)

    def test_r2_retry_transport_uncertainty_and_parent_claim_never_resume(self):
        self.cohort()
        retry = self.selected()
        spawned = self.fake_retry(retry)
        self.pool.fixtures[1].case.drift = True
        self.adopt(retry)
        with self.assertRaises(ValueError):
            retry.run()
        self.assertEqual(len(spawned), 1)
        self.assertEqual(retry.status()['state'], 'unknown')
        self.assertEqual(retry.run()['state'], 'unknown')
        self.assertEqual(len(spawned), 1)
        # A different identity also cannot reclaim the original failed parent.
        other = self.selected('EXAMPLE-renamed-retry')
        self.adopt(other)
        with self.assertRaises(ValueError):
            other.run()
        self.assertEqual(len(spawned), 1)
        self.assert_retained(1)


if __name__ == '__main__':
    unittest.main()
