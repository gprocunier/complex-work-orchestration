"""Ledger input/intent and lease pre-write boundaries with deterministic owners."""
from __future__ import annotations

import copy
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tests import test_invocation_ledger as ledger_fixtures
from tests import test_native_pool_leases as lease_fixtures
from cwo_core import invocation_ledger as ledger_api, native_pool_leases as leases
from cwo_core.native_pool_contracts import seal_artifact, validate_pool_contract


class F9InvocationLeaseGuards(unittest.TestCase):
    def ledger(self):
        fixture = ledger_fixtures.LedgerTestCase('runTest')
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        return fixture

    def test_F9_ba0eb918f629846d_154e19e7599a2613_type_and_clock_direct_bodies(self):
        document = ledger_api.empty_ledger()
        self.assertEqual(ledger_api.validate_ledger(document), [])
        self.assertTrue(ledger_api.validate_ledger({**document, 'ledger_type': 'EXAMPLE-other'}))
        with tempfile.TemporaryDirectory() as temporary:
            ledger = ledger_api.InvocationLedger(Path(temporary) / 'unused', clock=lambda: 1)
            self.assertEqual(ledger.current_time(), 1)
            for bad in (float('nan'), True, -1):
                with self.subTest(clock=bad), patch.object(ledger, 'clock', lambda: bad), \
                        self.assertRaises(ledger_api.InvocationLedgerError):
                    ledger.current_time()
            self.assertFalse(ledger.root.exists())

    def test_F9_9a053b39e255d6bd_terminal_attempt_cannot_supply_intent(self):
        fixture = self.ledger()
        reserved = fixture.reserve()
        fixture.ledger.begin_invocation(reserved['reservation_id'], ledger_fixtures.REQUEST)
        handle = ledger_api.InvocationHandle(fixture.ledger, reserved['reservation_id'], ledger_fixtures.REQUEST,
            lambda *_: self.fail('EXAMPLE unexpected observer'))
        self.assertEqual(handle.require_intent()['state'], 'invocation-intent')
        fixture.ledger.finish(reserved['reservation_id'], 'completed', reason='EXAMPLE terminal')
        before = (fixture.ledger.root / ledger_api.LEDGER_FILE).read_bytes()
        with self.assertRaisesRegex(ledger_api.InvocationLedgerError, 'not invocation-intent'):
            handle.require_intent()
        self.assertEqual((fixture.ledger.root / ledger_api.LEDGER_FILE).read_bytes(), before)
        attempt = fixture.ledger.attempt(reserved['reservation_id'])
        self.assertEqual(attempt['charge'], attempt['amount'])

    def test_F9_82c139a378edcb14_recovery_without_budget_filters_processes_all(self):
        fixture = self.ledger()
        reserved = fixture.reserve('intent', ttl=1)
        fixture.ledger.begin_invocation(reserved['reservation_id'], ledger_fixtures.REQUEST)
        fixture.ledger.open_budget('EXAMPLE-other-budget', fixture.limits, scope_sha256=ledger_fixtures.SCOPE)
        expired = fixture.reserve('expired', ttl=1, budget='EXAMPLE-other-budget')
        fixture.clock.now += 2
        fixture.owners.crash()
        changes = fixture.ledger.recover()
        self.assertEqual({entry['attempt_id'] for entry in changes}, {reserved['attempt_id'], expired['attempt_id']})
        intent = fixture.ledger.attempt(reserved['reservation_id'])
        unused = fixture.ledger.attempt(expired['reservation_id'])
        self.assertEqual(intent['state'], 'reconciliation-required')
        self.assertEqual(intent['charge'], intent['amount'])
        self.assertEqual(unused['outcome'], 'expired')
        self.assertFalse(any(unused['charge'].values()))
        self.assertEqual(fixture.ledger.recover(), [])

    def test_F9_80d3ae4a42a84331_bad_budget_limits_refuse_before_lock(self):
        with tempfile.TemporaryDirectory() as temporary:
            good = ledger_api.InvocationLedger(Path(temporary) / 'good', clock=lambda: 1)
            self.assertEqual(good.open_budget('EXAMPLE-budget', {'attempts': 1}, scope_sha256='a' * 64)['limits'], {'attempts': 1})
            bad = ledger_api.InvocationLedger(Path(temporary) / 'bad', clock=lambda: 1)
            with patch.object(bad, '_locked', side_effect=AssertionError('EXAMPLE bad limits reached lock')) as lock:
                with self.assertRaises(ledger_api.InvocationLedgerError):
                    bad.open_budget('EXAMPLE-budget', {'attempts': True}, scope_sha256='a' * 64)
                lock.assert_not_called()
            self.assertFalse(bad.root.exists())

    def test_F9_a79b196d797121ed_registry_symlink_refuses_before_setup_writes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / 'target'
            target.write_bytes(b'EXAMPLE protected bytes')
            parent = root / 'registry-parent'
            parent.mkdir(mode=0o755)
            path = parent / 'leases.json'
            path.symlink_to(target)
            registry = leases.PoolLeaseRegistry(path)
            before = parent.stat().st_mode
            with self.assertRaisesRegex(leases.PoolLeaseError, 'symlink'):
                registry.snapshot()
            self.assertEqual(parent.stat().st_mode, before)
            self.assertFalse(registry.lock_path.exists())
            self.assertEqual(target.read_bytes(), b'EXAMPLE protected bytes')
            path.unlink()
            self.assertEqual(registry.snapshot(), [])
            self.assertTrue(registry.lock_path.exists())
            self.assertEqual(parent.stat().st_mode & 0o777, 0o700)

    def test_F9_f576630b4ea22ed1_readonly_lease_cannot_share_mutable_worktree(self):
        mutable, _ = lease_fixtures.pool_contract(cap=1)
        readonly, _ = lease_fixtures.pool_contract(cap=1, read_only=True)
        readonly = copy.deepcopy(readonly)
        child = readonly['children'][0]
        child['worktree_identity'] = mutable['children'][0]['worktree_identity']
        child['child_id'], child['lease_id'] = 'EXAMPLE-readonly', 'EXAMPLE-readonly-lease'
        readonly = seal_artifact(readonly, 'contract_sha256')
        self.assertEqual(validate_pool_contract(readonly), [])
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            registry = leases.PoolLeaseRegistry(root / 'mixed.json', owner_alive=lambda _: True, now=lambda: lease_fixtures.NOW)
            registry.acquire(mutable, 'child-0')
            before = registry.path.read_bytes()
            with self.assertRaisesRegex(leases.PoolLeaseCollision, 'worktree'):
                registry.acquire(readonly, 'EXAMPLE-readonly')
            self.assertEqual(registry.path.read_bytes(), before)
            control, _ = lease_fixtures.pool_contract(read_only=True)
            shared = leases.PoolLeaseRegistry(root / 'shared.json', owner_alive=lambda _: True, now=lambda: lease_fixtures.NOW)
            shared.acquire_many(control, ['child-0', 'child-1'])
            self.assertEqual(len(shared.snapshot()), 2)
