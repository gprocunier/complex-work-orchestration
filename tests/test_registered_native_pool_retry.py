"""Retired retry calls and original signed observation checks."""

from hashlib import sha256
import unittest
from unittest.mock import Mock, patch

from tests import test_registered_native_pool_host as fixtures
import registered_native_pool_retry as retry


class ApprovedRetryTests(unittest.TestCase):
    def setUp(self):
        self.retirement = 'registered-serial-pool-retry-retired'

    def test_retired_retry_refuses_before_effects(self):
        retired = object.__new__(retry.ApprovedPoolRetry)
        parent = Mock()
        host = Mock()
        for n1, pool, reason in (
            (False, False, 'native-pool-live-unavailable'),
            (False, True, 'native-n1-live-unavailable'),
            (True, True, 'registered-serial-pool-retry-retired'),
        ):
            expected = ValueError if n1 and pool else retry.R.live_availability.NativeLiveUnavailable
            with (self.subTest(n1=n1, pool=pool),
                  patch.multiple(retry.R.live_availability, N1_LIVE_AVAILABLE=n1, POOL_LIVE_AVAILABLE=pool),
                  self.assertRaisesRegex(expected, reason)):
                retired.run()
        with self.assertRaisesRegex(ValueError, self.retirement):
            retry.issue_controller(parent, retry_id='EXAMPLE-retry', state_directory=Mock())
        with self.assertRaisesRegex(ValueError, self.retirement):
            retry.ApprovedPoolRetry(host, worker_id='EXAMPLE-worker', retry_id='EXAMPLE-retry', controller=Mock())
        with self.assertRaisesRegex(ValueError, self.retirement):
            retired.adopt_execution(adoption_id='EXAMPLE-retired', disclosure_consent={})
        self.assertEqual(parent.mock_calls, [])
        self.assertEqual(host.mock_calls, [])

    def test_signed_retry_reads_only_original_bound_records(self):
        pool = fixtures.PoolTests('runTest')
        pool._outcome = self._outcome
        self.addCleanup(fixtures.N.cleanup_helper, self, pool)
        pool.cohort(1)
        retry_id, worker_id = 'EXAMPLE-retry', pool.workers[0]
        host = pool.host
        name = 'retry-' + sha256(retry_id.encode()).hexdigest()
        intent_name, terminal_name = name + '-intent.json', name + '-terminal.json'
        before = [member.settings['state_store'].read_state() for member in pool.fixtures]
        unknown = {'retry_id': retry_id, 'state': 'unknown', 'redispatch_permitted': False, **retry.R._FALSE}
        self.assertEqual(retry.observe_retry(host, retry_id), unknown)
        action = {'pool': pool.config.binding, 'worker_id': worker_id, 'retry_id': retry_id}
        intent = {'action': action, 'adoption': {'directive_id': 'EXAMPLE-adoption'}}
        intent_path = pool.signed_record(intent_name, intent)
        self.assertEqual(retry.observe_retry(host, retry_id), unknown)
        terminal = {'retry_id': retry_id, 'worker_id': worker_id, 'state': 'terminal', 'outcome': 'completed',
                    'intent_sha256': sha256(retry._encode(intent)).hexdigest(), **retry.R._FALSE}
        terminal_path = pool.signed_record(terminal_name, terminal)
        retained = {path: path.read_bytes() for path in (intent_path, terminal_path)}
        self.assertEqual(retry.observe_retry(retry.P.RegisteredNativePoolHost(pool.config), retry_id), terminal)
        self.assertEqual(retry.observe_retry(host, retry_id), terminal)
        self.assertEqual({path: path.read_bytes() for path in retained}, retained)
        self._assert_refuses_unbound_records(pool, host, retry_id, intent_name, terminal_name, intent, terminal)
        self.assertEqual([member.settings['state_store'].read_state() for member in pool.fixtures], before)
        self.assertFalse(pool.ledger.root.exists())
        for member in pool.fixtures:
            fixtures.N.assert_no_native_births(self, member.fixture)

    def _assert_refuses_unbound_records(self, pool, host, retry_id, intent_name, terminal_name, intent, terminal):
        for field, alternate in (('pool', {}), ('retry_id', 'EXAMPLE-different-retry')):
            with self.subTest(intent_field=field):
                pool.signed_record(intent_name, {**intent, 'action': {**intent['action'], field: alternate}})
                with self.assertRaisesRegex(ValueError, 'Original signed retry binding changed'):
                    retry.observe_retry(host, retry_id)
        pool.signed_record(intent_name, intent)
        for field, alternate in (('worker_id', 'EXAMPLE-different-worker'), ('intent_sha256', '0' * 64),
                                 ('retry_id', 'EXAMPLE-different-retry')):
            with self.subTest(terminal_field=field):
                pool.signed_record(terminal_name, {**terminal, field: alternate})
                with self.assertRaisesRegex(ValueError, 'Retry terminal belongs to another intent or member'):
                    retry.observe_retry(host, retry_id)
        pool.signed_record(terminal_name, {**terminal, 'outcome': 'failed'}, signed_body=terminal)
        with self.assertRaisesRegex(ValueError, 'maintenance-directive-verification-failed'):
            retry.observe_retry(host, retry_id)
        with (patch.object(host, '_load', side_effect=AssertionError('substituted reader reached')),
              self.assertRaisesRegex(ValueError, 'Original bound library methods')):
            retry.observe_retry(host, retry_id)
