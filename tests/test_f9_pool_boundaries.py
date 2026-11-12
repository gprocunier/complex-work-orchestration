"""Pool parser, pre-write refusal and late member-authority boundaries."""
from __future__ import annotations

from dataclasses import replace
import hashlib
import os
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from tests import test_f4_factory_pool_guards as fixtures
import registered_native_pool_host as pool


class NextBoundary(Exception):
    """A positive control reached the next boundary without running an effect."""


class F9PoolBoundaries(unittest.TestCase):
    def cohort(self):
        helper = fixtures.F4FactoryPoolGuardTests('runTest')
        helper._outcome = self._outcome
        self.addCleanup(helper.doCleanups)
        return helper.pool_fixture()

    def test_F9_c220e8a61ced072c_db872ee5b4324500_68280bbe0a1acf14_d65d074803d69109_ebd49dbcf8e21630_structure(self):
        request = dict(version=1, mode='validate-only', pool_id='EXAMPLE-pool', workers=['EXAMPLE-worker'])
        self.assertFalse(pool.validate_structure(request)['authority_validated'])
        cases = ({**request, 'factory': 'EXAMPLE-caller'}, {**request, 'pool_id': ''},
            {**request, 'workers': []}, {**request, 'workers': ['one'] * 2},
            {**request, 'workers': ['one', 'two', 'three', 'four']},
            {**request, 'workers': ('EXAMPLE-worker',)}, {**request, 'workers': ['invalid worker']})
        for changed in cases:
            with self.subTest(request=changed), self.assertRaises(ValueError):
                pool.validate_structure(changed)

    def test_F9_b356b88a29e9dfe4_constructor_requires_finite_integer_resource_limits(self):
        fixture = self.cohort()
        settings = dict(pool_id=fixture.config.pool_id,
            controllers=dict(zip(fixture.workers, fixture.config.controllers)),
            state_directory=fixture.state, ledger=fixture.ledger, enabled=True)

        def image():
            return {str(path.relative_to(fixture.state.parent)): (path.lstat().st_mode,
                hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None)
                for path in fixture.state.parent.rglob('*') if not path.is_symlink()}

        before = image()
        current = pool.PoolConfiguration(**settings, limits=dict(fixture.config.limits))
        self.assertIs(current.ledger, fixture.ledger)
        self.assertIs(type(current.ledger), pool.R.admission.ledger_api.InvocationLedger)
        self.assertEqual(current.controllers, fixture.config.controllers)
        self.assertIs(type(current.limits['tool_calls']), int)
        self.assertEqual(image(), before)
        fractional = {**fixture.config.limits, 'tool_calls': 1_000_000_000.5}
        with self.assertRaises(ValueError):
            pool.PoolConfiguration(**settings, limits=fractional)
        self.assertEqual(image(), before)

    def test_F9_fc000d476b9679ba_invalid_mode_before_pool_intent(self):
        fixture = self.cohort()
        self.assertTrue(fixture.host.run(fixture.config.request('validate-only'))['authority_validated'])
        with patch.object(fixture.host, '_locked', side_effect=NextBoundary) as lock:
            with self.assertRaisesRegex(ValueError, 'version or mode'):
                fixture.host.run(fixture.config.request('EXAMPLE-invalid'))
            lock.assert_not_called()
        self.assertFalse(list(fixture.state.iterdir()))
        self.assertFalse(fixture.ledger.root.exists())
        self.assertTrue(all(workflow.factory is None for workflow in fixture.config.workflows))

    def test_F9_8be8f93e0a3d8bf2_2e3a7045e15b70d3_cohort_and_state_identity(self):
        fixture = self.cohort()
        fixture.config.check()
        with patch.object(fixture.config, 'controllers', ()), self.assertRaisesRegex(ValueError, 'N=1..3'):
            fixture.config.check()
        moved = fixture.state.with_name('EXAMPLE-old-pool')
        fixture.state.rename(moved)
        fixture.state.mkdir(mode=0o700)
        with self.assertRaisesRegex(ValueError, 'Pool custody directory changed'):
            fixture.config.check()
        self.assertFalse(list(fixture.state.iterdir()))
        self.assertTrue(all(workflow.factory is None for workflow in fixture.config.workflows))

    def test_F9_a6e5b582cf4a5863_whole_route_admission_remains_exact(self):
        fixture = self.cohort()
        fixture.config.check()
        prepare = pool.R.admission.prepare
        def changed(*args, **kwargs):
            return replace(prepare(*args, **kwargs), budget_id='EXAMPLE-other-budget')
        with patch.object(pool.R.admission, 'prepare', side_effect=changed), \
                self.assertRaisesRegex(ValueError, 'whole-route admission differs'):
            fixture.config.check()
        self.assertFalse(list(fixture.state.iterdir()))

    def test_F9_90d38e52b508be3e_ownership_inode_overlap(self):
        fixture = self.cohort()
        fixture.config.check()
        ownership = pool._worktree_ownership
        def aliased(root):
            # Model one inode exposed through distinct mount paths; paths and Git metadata stay distinct.
            return ownership(root) | {(-1, 41)}
        with patch.object(pool, '_worktree_ownership', side_effect=aliased), \
                self.assertRaisesRegex(ValueError, 'write ownership overlaps'):
            fixture.config.check()
        self.assertFalse(list(fixture.state.iterdir()))

    def test_F9_eea387d50be29e29_aggregate_dimensions_match_every_member(self):
        fixture = self.cohort()
        fixture.config.check()
        with patch.object(fixture.config, 'limits', {**fixture.config.limits, 'EXAMPLE-extra': 1}), \
                self.assertRaisesRegex(ValueError, 'Aggregate dimensions'):
            fixture.config.check()
        self.assertFalse(fixture.ledger.root.exists())

    def test_F9_4bdc8d2f0088f855_open_pool_descriptor_identity_before_flock(self):
        fixture = self.cohort()
        with fixture.host._locked():
            pass
        real_open, real_stat = os.open, os.fstat
        opened = []
        def open_directory(path, flags, *args, **kwargs):
            fd = real_open(path, flags, *args, **kwargs)
            if path == fixture.config.state:
                opened.append(fd)
            return fd
        def metadata(fd):
            info = real_stat(fd)
            if fd in opened:
                return SimpleNamespace(st_dev=info.st_dev, st_ino=info.st_ino + 1, st_mode=info.st_mode)
            return info
        with patch.object(fixture.host, '_current'), patch.object(pool.os, 'open', side_effect=open_directory), \
                patch.object(pool.os, 'fstat', side_effect=metadata), patch.object(pool.fcntl, 'flock') as flock:
            with self.assertRaisesRegex(ValueError, 'Pool state descriptor changed'):
                with fixture.host._locked():
                    self.fail('EXAMPLE wrong directory locked')
            flock.assert_not_called()
        self.assertEqual(len(opened), 1)

    def test_F9_533809aaf713af1f_ordinary_failure_never_becomes_controlled(self):
        failure = RuntimeError('EXAMPLE original member failure')
        workflow = SimpleNamespace(run=Mock(side_effect=failure))
        with patch.object(pool.live_availability, 'require_pool_live'), patch.object(pool.live_availability, 'require_n1_live'), \
                patch.object(pool.RegisteredNativePoolHost, '_controlled_failure') as controlled:
            with self.assertRaises(RuntimeError) as raised:
                pool.RegisteredNativePoolHost._run_member(workflow, controlled=False)
            self.assertIs(raised.exception, failure)
            controlled.assert_not_called()
            self.assertFalse(hasattr(workflow, '_pool_failure'))
            self.assertEqual(pool.RegisteredNativePoolHost._run_member(workflow, controlled=True).status, 'failed')
            controlled.assert_called_once_with(workflow, failure)

    def test_F9_8950ff2012379f04_controlled_failure_keeps_member_verifier(self):
        fixture = self.cohort()
        fixture.config.controlled_failure_workers = tuple(fixture.workers)
        fixture.config.binding = fixture.config.describe()
        fixture.fixtures[0].case.bad_output = True
        with self.assertRaises(pool.R.validation.ValidationError) as raised:
            fixture.execute()
        workflow = fixture.config.workflows[0]
        self.assertEqual(pool.RegisteredNativePoolHost._controlled_failure(workflow, raised.exception)['outcome'], 'failed')
        with patch.object(workflow.config, 'verifier', object()), \
                self.assertRaisesRegex(ValueError, 'Original member factory, operation and admission binding'):
            pool.RegisteredNativePoolHost._controlled_failure(workflow, raised.exception)
