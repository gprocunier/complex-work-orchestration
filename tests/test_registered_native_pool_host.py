"""Registered cohort joins; fake OS/RPC, actual N1 APIs/validators.

Reuse producer fixture builders without collecting their test families here.
Only the new pool topology, accounting, replay and host-client cases are added.
"""
from __future__ import annotations

import copy
import contextvars
import hashlib
import json
import os
import subprocess
from pathlib import Path
import sys
import threading
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'scripts'), str(ROOT / 'tests')]
import registered_native_pool_host as P  # noqa: E402
from tests import test_registered_n1_workflow as F  # noqa: E402
from tests import test_registered_n1_factory as N  # noqa: E402
import run_admitted_native_pool_transaction as CLI  # noqa: E402
import test_native_pool_transaction as T  # noqa: E402
from test_run_admitted_native_pool_transaction import write_adapter  # noqa: E402


class PoolFixtureIdentityTests(unittest.TestCase):
    def test_pool_deferred_boundary_targets_the_actual_workflow_factory_class(self):
        self.assertIs(N, F.F)
        self.assertIs(N.FactoryTests, F.F.FactoryTests)

    def test_profile_retry_and_guard_consumers_share_the_same_producers(self):
        from tests import test_f4_factory_pool_guards as guards
        from tests import test_registered_native_pool_host as canonical
        from tests import test_registered_native_pool_profiles as profiles
        from tests import test_registered_native_pool_retry as retry
        self.assertIs(guards.N, N)
        self.assertIs(guards.pools, canonical)
        self.assertIs(profiles.F, canonical)
        self.assertIs(profiles.tools.family, N)
        self.assertIs(retry.F, canonical)
        self.assertIs(retry._PIPE_BACKEND, N._PIPE_BACKEND)

    def test_canonical_cohort_defers_every_actual_workflow_boundary(self):
        cohort = PoolTests('runTest')
        cohort._outcome = self._outcome
        self.addCleanup(N.cleanup_helper, self, cohort)
        cohort.cohort(2, archive_schedule='settled', shared_source=True)
        for member in cohort.fixtures:
            self.assertIs(type(member.fixture), N.FactoryTests)
            self.assertFalse(hasattr(member.fixture, 'spawned'))
            N.assert_no_native_births(self, member.fixture)
            self.assertIsNone(member.workflow.factory)
        report = cohort.host.run(cohort.config.request('validate-only'))
        self.assertIs(report['authority_validated'], True)
        self.assertFalse((cohort.ledger.root / P.R.admission.ledger_api.LEDGER_FILE).exists())


class PoolTests(unittest.TestCase):
    def cohort(self, size=3, *, enabled=True, archive_schedule='concurrent', shared_source=False,
               source_evidence=None):
        if archive_schedule not in ('concurrent', 'settled'):
            raise ValueError('Unknown original archive fixture schedule.')
        # only this fake-process cohort may cross the held route in tests.
        self.enterContext(patch.object(P.live_availability, 'POOL_LIVE_AVAILABLE', True))
        self.enterContext(patch.object(P.live_availability, 'N1_LIVE_AVAILABLE', True))
        self.fixtures = []
        self.enterContext(patch.object(P.os, 'getpid', return_value=N.children.CONTROLLER))
        # Build the original complete workflows, delaying only fake OS effects
        # until each member's actual namespace launch. No validator replacement.
        if source_evidence is not None:
            snapshot = F.evidence_snapshot(source_evidence[1])
            self.addCleanup(self.assert_source_retained, source_evidence[1], snapshot)
        with patch.object(N.FactoryTests, '_boundaries'):
            for _ in range(size):
                fixture = F.WorkflowTests('runTest')
                self.addCleanup(N.cleanup_helper, self, fixture)
                fixture.setUp(source_evidence=source_evidence)
                if archive_schedule == 'settled':
                    N.settle_original_archive(fixture.fixture, fixture.case)
                fixture.fixture._outcome = self._outcome
                self.fixtures.append(fixture)
                if shared_source and source_evidence is None:
                    # Borrow the exact original review identities. Each native
                    # host, authority, ledger and capability was still built
                    # privately above; no issued object is copied or rebound.
                    source_evidence = fixture.source_fixture, fixture.settings['evidence']
                    snapshot = F.evidence_snapshot(source_evidence[1])
                    self.addCleanup(self.assert_source_retained, source_evidence[1], snapshot)
        self.state = self.fixtures[0].case.host.state.parent / 'EXAMPLE_POOL_STATE'
        self.state.mkdir(mode=0o700)
        self.workers = ['EXAMPLE-worker-' + str(i) for i in range(size)]
        self.ledger = P.R.admission.ledger_api.InvocationLedger(self.state.parent / 'EXAMPLE_POOL_LEDGER',
            clock=self.fixtures[0].case.ledger.clock, owner_probe=self.fixtures[0].case.ledger.owner_probe)
        self.config = P.PoolConfiguration(pool_id='EXAMPLE-pool',
            controllers=dict(zip(self.workers, [f.workflow.config for f in self.fixtures])),
            state_directory=self.state, ledger=self.ledger,
            limits=dict.fromkeys(P.R.admission.planner.RESOURCES, 1_000_000_000), enabled=enabled)
        self.host = P.RegisteredNativePoolHost(self.config)
        for fixture, workflow in zip(self.fixtures, self.config.workflows):
            fixture.workflow = workflow
        active = set()
        original = P.R._Containment.launch
        backend = N._PIPE_BACKEND
        def launch(lifetime, *args, **kwargs):
            fixture = next(f for f in self.fixtures if f.case.host is lifetime.factory.host)
            if id(fixture) not in active:
                active.add(id(fixture))
                P.R._PipeBackend = backend
                fixture.fixture._boundaries(fixture.case)
            return original(lifetime, *args, **kwargs)
        self.enterContext(patch.object(P.R._Containment, 'launch', launch))
        return self.host

    def assert_source_retained(self, evidence, snapshot):
        self.assertIsNone(evidence.adjudication._refusal)
        self.assertEqual(F.evidence_snapshot(evidence), snapshot)

    def adopt(self):
        self.host.adopt_execution(adoption_id='EXAMPLE_POOL_ADOPTION', disclosure_consents={
            worker: {'boundary': 'local-only', 'allowed_effects': ['native-worker', 'target-publication'],
                            'request_sha256': hashlib.sha256(f.case.receipt.request_bytes).hexdigest()}
            for worker, f in zip(self.workers, self.fixtures)})

    def adoption_state(self):
        return [(copy.deepcopy(workflow._disclosure), copy.deepcopy(workflow._adoption),
                 workflow._selected_action, workflow.config._guard)
                for workflow in self.config.workflows]

    def assert_adoption_has_no_effects(self, authority):
        self.assertEqual(authority, [fixture.settings['state_store'].read_state()
                                     for fixture in self.fixtures])
        self.assertFalse(list(self.state.iterdir()))
        self.assertFalse(self.ledger.root.exists())
        for fixture in self.fixtures:
            N.assert_no_native_births(self, fixture.fixture)
            self.assertFalse(fixture.case.ledger.root.exists())

    def test_later_invalid_consent_preserves_entire_pool_adoption(self):
        self.cohort(2, archive_schedule='settled', shared_source=True)
        before, binding = self.adoption_state(), copy.deepcopy(self.config.binding)
        authority = [fixture.settings['state_store'].read_state() for fixture in self.fixtures]
        consents = {worker: {'boundary': 'local-only',
            'allowed_effects': ['native-worker', 'target-publication'],
            'request_sha256': hashlib.sha256(fixture.case.receipt.request_bytes).hexdigest()}
            for worker, fixture in zip(self.workers, self.fixtures)}
        consents[self.workers[1]] = {'accepted': True}
        with patch.object(P.W.A, 'sign_controller_directive', wraps=P.W.A.sign_controller_directive) as signer:
            with self.assertRaisesRegex(ValueError, 'disclosure consent'):
                self.host.adopt_execution(adoption_id='EXAMPLE_POOL_ADOPTION', disclosure_consents=consents)
        signer.assert_not_called()
        self.assert_adoption_has_no_effects(authority)
        self.assertEqual(self.config.binding, binding)
        self.assertEqual(self.adoption_state(), before)
        self.adopt()
        self.host._current()
        for workflow in self.config.workflows:
            workflow._require_execution()
        self.assert_adoption_has_no_effects(authority)

    def test_later_signer_failure_preserves_entire_pool_adoption(self):
        self.cohort(2, archive_schedule='settled', shared_source=True)
        before, binding = self.adoption_state(), copy.deepcopy(self.config.binding)
        authority = [fixture.settings['state_store'].read_state() for fixture in self.fixtures]
        original, calls = P.W.A.sign_controller_directive, []
        primary = OSError('EXAMPLE later member adoption signer failed')

        def sign(**kwargs):
            if kwargs['directive_id'] == 'EXAMPLE_POOL_ADOPTION':
                calls.append(kwargs['action_sha256'])
                if len(calls) == 2:
                    raise primary
            return original(**kwargs)

        with patch.object(P.W.A, 'sign_controller_directive', sign), self.assertRaises(OSError) as caught:
            self.adopt()
        self.assertIs(caught.exception, primary)
        self.assertEqual(len(calls), 2)
        self.assert_adoption_has_no_effects(authority)
        self.assertEqual(self.config.binding, binding)
        self.assertEqual(self.adoption_state(), before)
        self.adopt()
        self.host._current()
        for workflow in self.config.workflows:
            workflow._require_execution()
        self.assert_adoption_has_no_effects(authority)

    def execute(self):
        self.adopt()
        return self.host.run(self.config.request('execute'))

    def attempts(self):
        return json.loads((self.ledger.root / P.R.admission.ledger_api.LEDGER_FILE).read_bytes())['attempts']

    def assert_accounting(self, count):
        attempts = list(self.attempts().values())
        self.assertEqual(sum(a['state'] != 'reserved' for a in attempts), count)
        self.assertTrue(all(a['charge'] == a['amount'] for a in attempts))
        first = self.fixtures[0].case
        summary = self.ledger.summary(self.config.pool_id)
        self.assertEqual(summary['charged'], {key: sum(a['amount'][key] for a in attempts)
                                             for key in json.loads(first.receipt.amounts_bytes)})
        return summary

    def after_first_outer_reservation(self, action):
        original, fired = P.fcntl.flock, []

        def flock(descriptor, operation):
            result = original(descriptor, operation)
            lock = self.ledger.root / P.R.admission.ledger_api.LOCK_FILE
            if operation != P.fcntl.LOCK_UN or fired or not lock.exists():
                return result
            info, expected = os.fstat(descriptor), lock.stat()
            if (info.st_dev, info.st_ino) != (expected.st_dev, expected.st_ino):
                return result
            attempts = list(self.attempts().values())
            if len(attempts) == 1 and attempts[0]['request_id'] == self.workers[0]:
                fired.append(attempts[0])
                action(attempts[0])
            return result

        self.enterContext(patch.object(P.fcntl, 'flock', flock))
        return fired

    def assert_partial_reservation_is_held(self, count):
        before = copy.deepcopy(self.attempts())
        self.assertEqual(len(before), count)
        self.assertTrue(all(row['state'] == 'reserved' and row['charge'] == row['amount']
                            for row in before.values()))
        budget = self.ledger.summary(self.config.pool_id)
        self.assertEqual(budget['limits'], self.config.limits)
        self.assertTrue(self.host.status()['reconciliation_required'])
        self.assertFalse(self.host.status()['redispatch_permitted'])
        with self.assertRaises(ValueError):
            self.host.run(self.config.request('execute'))
        self.assertEqual(self.attempts(), before)
        self.assertIsNone(self.host.result)
        for fixture in self.fixtures:
            N.assert_no_native_births(self, fixture.fixture)
            self.assertFalse(fixture.case.ledger.root.exists())
            self.assertIsNone(fixture.workflow.factory)

    def test_competing_reservation_between_members_retains_both_original_charges(self):
        self.cohort(2, archive_schedule='settled', shared_source=True)
        self.adopt()
        start, done, errors = threading.Event(), threading.Event(), []

        def compete():
            try:
                self.assertTrue(start.wait(5))
                row = next(iter(self.attempts().values()))
                ledger = P.R.admission.ledger_api.InvocationLedger(self.ledger.root,
                    clock=self.ledger.clock, owner_probe=self.ledger.owner_probe)
                ledger.reserve(budget_id=self.config.pool_id, request_id='EXAMPLE-interleaved',
                    request_sha256='a' * 64, admission_sha256='b' * 64,
                    amount={key: limit - row['charge'][key] for key, limit in self.config.limits.items()},
                    expires_at=self.ledger.current_time() + 30)
            except BaseException as failure:
                errors.append(failure)
            finally:
                done.set()

        worker = threading.Thread(target=contextvars.copy_context().run, args=(compete,), daemon=True)
        worker.start()
        self.addCleanup(N.finish_worker, self, worker, start)
        def interleave(_attempt):
            start.set()
            self.assertTrue(done.wait(5))
        fired = self.after_first_outer_reservation(interleave)
        with self.assertRaisesRegex(ValueError, 'aggregate allowance exhausted'):
            self.host.run(self.config.request('execute'))
        worker.join(2)
        self.assertFalse(worker.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(len(fired), 1)
        self.assert_partial_reservation_is_held(2)

    def test_second_reservation_write_failure_preserves_first_and_replay_hold(self):
        self.cohort(2, archive_schedule='settled', shared_source=True)
        self.adopt()
        original, failures = os.replace, []
        primary = OSError('EXAMPLE second reservation persistence failed')

        def replace(source, target, *args, **kwargs):
            if Path(target) == self.ledger.root / P.R.admission.ledger_api.LEDGER_FILE:
                document = json.loads(Path(source).read_bytes())
                if len(document['attempts']) == 2:
                    failures.append(document)
                    raise primary
            return original(source, target, *args, **kwargs)

        with patch.object(os, 'replace', replace), self.assertRaises(OSError) as caught:
            self.host.run(self.config.request('execute'))
        self.assertIs(caught.exception, primary)
        self.assertEqual(len(failures), 1)
        self.assert_partial_reservation_is_held(1)

    def test_expiry_between_reservations_cannot_reopen_pool_or_dispatch_sibling(self):
        self.cohort(2, archive_schedule='settled', shared_source=True)
        self.adopt()
        def expire(_attempt):
            self.ledger.clock.now = self.config.controllers[1].receipt.expires_at
        fired = self.after_first_outer_reservation(expire)
        with self.assertRaisesRegex(ValueError, 'stale admission'):
            self.host.run(self.config.request('execute'))
        self.assertEqual(len(fired), 1)
        self.assert_partial_reservation_is_held(1)

    def assert_substituted_pool_is_held(self, retired, *, terminal_saved):
        attempts = copy.deepcopy(self.attempts())
        self.assertEqual(len(attempts), 1)
        row = next(iter(attempts.values()))
        self.assertEqual(row['outcome'], 'completed')
        self.assertEqual(row['charge'], row['amount'])
        self.assertTrue((retired / 'intent.json').is_file())
        self.assertEqual((retired / 'terminal.json').exists(), terminal_saved)
        self.assertFalse(list(self.state.iterdir()))
        self.assertIsNone(self.host.result)
        with self.assertRaises(ValueError):
            self.host.status()
        with self.assertRaises(ValueError):
            self.host.run(self.config.request('execute'))
        self.assertEqual(self.attempts(), attempts)
        factory = self.config.workflows[0].factory
        self.assertEqual(P.W.V.consume_validated(*factory.issued_artifact()),
                         (('result.txt', N.fixtures.host_fixtures.OUTPUT),))
        self.assertFalse((factory.host.target / 'result.txt').exists())

    def test_state_path_replacement_after_member_settlement_cannot_return_success(self):
        self.cohort(1, archive_schedule='settled', shared_source=True)
        self.adopt()
        original, changed = P.fcntl.flock, []
        retired = self.state.with_name(self.state.name + '-retired')

        def flock(descriptor, operation):
            result = original(descriptor, operation)
            lock = self.ledger.root / P.R.admission.ledger_api.LOCK_FILE
            if operation != P.fcntl.LOCK_UN or changed or not lock.exists():
                return result
            info, expected = os.fstat(descriptor), lock.stat()
            if (info.st_dev, info.st_ino) != (expected.st_dev, expected.st_ino):
                return result
            rows = list(self.attempts().values())
            if len(rows) == 1 and rows[0]['outcome'] == 'completed':
                self.state.rename(retired)
                self.state.mkdir(mode=0o700)
                changed.append(rows[0])
            return result

        with patch.object(P.fcntl, 'flock', flock), self.assertRaisesRegex(ValueError, 'Pool (custody|state)'):
            self.host.run(self.config.request('execute'))
        self.assertEqual(len(changed), 1)
        self.assert_substituted_pool_is_held(retired, terminal_saved=False)

    def test_state_path_replacement_during_terminal_sync_cannot_return_success(self):
        self.cohort(1, archive_schedule='settled', shared_source=True)
        self.adopt()
        original, changed = os.fsync, []
        retired = self.state.with_name(self.state.name + '-retired')
        identity = tuple(self.config.identity[:2])

        def sync(descriptor):
            result = original(descriptor)
            info = os.fstat(descriptor)
            if (not changed and (info.st_dev, info.st_ino) == identity
                    and (self.state / 'terminal.json').exists()):
                self.state.rename(retired)
                self.state.mkdir(mode=0o700)
                changed.append(True)
            return result

        with patch.object(os, 'fsync', sync), self.assertRaisesRegex(ValueError, 'Pool (custody|state)'):
            self.host.run(self.config.request('execute'))
        self.assertEqual(changed, [True])
        self.assert_substituted_pool_is_held(retired, terminal_saved=True)

    def test_state_path_guard_failure_preserves_original_write_error(self):
        self.cohort(1, archive_schedule='settled', shared_source=True)
        self.adopt()
        original, changed = os.write, []
        retired = self.state.with_name(self.state.name + '-retired')
        primary = OSError('EXAMPLE original pool intent write failed')

        def write(descriptor, data):
            intent = self.state / 'intent.json'
            if not changed and intent.exists():
                info, expected = os.fstat(descriptor), intent.stat()
                if (info.st_dev, info.st_ino) == (expected.st_dev, expected.st_ino):
                    self.state.rename(retired)
                    self.state.mkdir(mode=0o700)
                    changed.append(True)
                    raise primary
            return original(descriptor, data)

        with patch.object(os, 'write', write), self.assertRaises(OSError) as caught:
            self.host.run(self.config.request('execute'))
        self.assertIs(caught.exception, primary)
        self.assertEqual(changed, [True])
        self.assertTrue(any('Pool custody recheck failed' in note for note in primary.__notes__))
        self.assertEqual(self.attempts(), {})
        self.assertTrue((retired / 'intent.json').exists())
        self.assertFalse(list(self.state.iterdir()))
        self.assertIsNone(self.host.result)
        for fixture in self.fixtures:
            N.assert_no_native_births(self, fixture.fixture)
            self.assertFalse(fixture.case.ledger.root.exists())

    def test_r1_c1_host_positive_n1_n2_n3_original_workflows_and_replay(self):
        """Registered N=1/2/3 consumer checks; producer tests stay separate."""
        for size in (1, 2, 3):
            with self.subTest(size=size):
                self.cohort(size, archive_schedule='settled', shared_source=True)
                report = self.execute()
                self.assertEqual(report['states'], ['validated'] * size)
                self.assertEqual(self.host.status(), report)
                self.assert_accounting(size)
                for fixture in self.fixtures:
                    self.assertEqual(len(fixture.fixture.spawned), 2)
                    self.assertTrue(fixture.workflow.factory.server.lifetime.termination['child_reaped'])
                    self.assertFalse((fixture.case.host.target / 'result.txt').exists())
                with self.assertRaisesRegex(ValueError, 'never redispatch'):
                    self.host.run(self.config.request('execute'))
                self.doCleanups()

    def test_r1_worker_selected_imports_wrong_factory_and_serialized_authority_refuse(self):
        """New pool ingress refuses before actual registered factory startup."""
        self.cohort(2)
        for field in ('factory', 'runtime_adapter_path', 'controller', 'authority'):
            request = self.config.request('execute')
            request[field] = 'EXAMPLE-caller-import'
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.host.run(request)
        c = self.fixtures[1].workflow.config
        c.native_bundle[0]['runtime_adapter_path'] = str(Path(CLI.__file__).resolve())
        with self.assertRaises(ValueError):
            self.execute()
        self.assertFalse(list(self.state.iterdir()))

    def test_r1_overlapping_write_roots_and_shared_git_metadata_refuse(self):
        """New cross-member topology guard, beyond original per-N1 isolation."""
        self.cohort(2)
        second, first = self.fixtures[1].case, self.fixtures[0].case
        with patch.object(second.host, 'worker', first.host.worker), self.assertRaises(ValueError):
            self.config.check()
        # A cross-worker common store marker must refuse even after construction.
        shared = second.host.worker / '.git' / 'commondir'
        shared.write_text(str(first.host.worker / '.git'))
        with self.assertRaises(ValueError):
            self.execute()
        self.assertFalse(list(self.state.iterdir()))

    def test_r4_failed_member_holds_unstarted_sibling_retains_valid_evidence_and_charge(self):
        """Original partial cohort completion and no spend restoration on failure."""
        self.cohort(3, archive_schedule='settled', shared_source=True)
        self.fixtures[1].case.bad_output = True
        self.adopt()
        with self.assertRaises(ValueError):
            self.host.run(self.config.request('execute'))
        self.assertEqual(self.host.status()['states'], ['validated', 'failed', 'held'])
        summary = self.assert_accounting(2)
        self.assertEqual(summary['usage_unknown'], 2)
        self.assertIn('unknown', [a['outcome'] for a in self.attempts().values()])
        first = self.fixtures[0]
        artifact = first.workflow.factory.issued_artifact()
        self.assertEqual(P.W.V.consume_validated(*artifact), (('result.txt', N.fixtures.host_fixtures.OUTPUT),))
        self.assertFalse(first.case.host.target.joinpath('result.txt').exists())
        self.assertFalse(hasattr(self.fixtures[2].fixture, 'spawned'))
        N.assert_no_native_births(self, self.fixtures[2].fixture)
        before = copy.deepcopy(self.attempts())
        with self.assertRaisesRegex(ValueError, 'never redispatch'):
            self.host.run(self.config.request('execute'))
        self.assertEqual(self.attempts(), before)

    def test_r1_r4_pool_reservation_race_has_one_effect_owner(self):
        """New simultaneous host clients, one pool flock and durable intent."""
        self.cohort(1, archive_schedule='settled', shared_source=True)
        self.adopt()
        entered, release = threading.Event(), threading.Event()
        self.fixtures[0].case.on_startup = lambda: (entered.set(), self.assertTrue(release.wait(10)))
        outcome = []
        def run():
            try:
                outcome.append(self.host.run(self.config.request('execute')))
            except BaseException as error:
                outcome.append(error)
        context = contextvars.copy_context()
        worker = threading.Thread(target=context.run, args=(run,))
        worker.start()
        try:
            self.assertTrue(N.wait_for_startup(self, entered, worker, outcome))
            with self.assertRaises(BlockingIOError):
                P.RegisteredNativePoolHost(self.config).run(self.config.request('execute'))
        finally:
            release.set()
            worker.join(15)
        self.assertFalse(worker.is_alive())
        self.assertEqual(len(outcome), 1)
        self.assertIsInstance(outcome[0], dict, str(outcome[0]))
        self.assertIs(self.config.workflows[0].factory.host_records, self.config.host_records)
        self.assert_accounting(1)

    def test_r3_direct_public_cli_still_refuses_original_v8_without_authority(self):
        """C1 join retains direct CLI refusal and does not select caller imports."""
        self.cohort(1)
        root = self.state.parent / 'EXAMPLE-CLI'
        plan = T.transaction_plan(root, [T.bead('EXAMPLE-cli-worker', 'result.txt')])
        marker = root / 'EXAMPLE-import-marker'
        write_adapter(plan, marker)
        self.assertEqual(CLI.validate_transaction_plan(plan), [])
        filename = root / 'EXAMPLE-plan.json'
        filename.write_text(json.dumps(plan))
        for extra in ([], ['--validate-only']):
            result = subprocess.run([sys.executable, CLI.__file__, '--plan', str(filename),
                '--journal', str(root / 'EXAMPLE-journal'), '--output', str(root / 'EXAMPLE-output'), *extra],
                capture_output=True, text=True, timeout=15)
            self.assertEqual(result.returncode, 2)
            self.assertIn('controller-adapter-authority-missing', result.stderr)
            self.assertFalse(marker.exists())
            self.assertFalse((root / 'EXAMPLE-journal').exists())
            self.assertFalse((root / 'EXAMPLE-output').exists())
        self.assertFalse(list(self.state.iterdir()))

    def test_r1_sibling_git_metadata_mutation_holds_next_worker(self):
        """Original cross-member metadata mutation case after a useful sibling."""
        self.cohort(3, archive_schedule='settled', shared_source=True)
        target = self.fixtures[1].case.host.worker / '.git' / 'config'
        self.fixtures[0].case.on_startup = lambda: target.write_bytes(target.read_bytes() + b'\n# EXAMPLE sibling drift\n')
        self.adopt()
        with self.assertRaises(ValueError):
            self.host.run(self.config.request('execute'))
        self.assertEqual(self.host.result['states'], ['validated', 'failed', 'held'])
        self.assertEqual(len(self.fixtures[0].fixture.spawned), 2)
        self.assertFalse(hasattr(self.fixtures[1].fixture, 'spawned'))
        N.assert_no_native_births(self, self.fixtures[1].fixture)
        self.assert_accounting(1)
        # Drift refuses authenticated status; custody already issued to worker 0
        # remains independently verifiable, never erased to repair the pool.
        with self.assertRaises(ValueError):
            self.host.status()
        artifact = self.fixtures[0].workflow.factory.issued_artifact()
        self.assertTrue(P.W.V.consume_validated(*artifact))

    def test_r1_w15_each_member_denies_stdin_and_cannot_borrow_profile(self):
        """Pool joins preserve each exact finite native-policy profile without retry expansion."""
        self.cohort(2, archive_schedule='settled', shared_source=True)
        for fixture in self.fixtures:
            fixture.case.probe_approvals = [{'kind': 'writeStdin', 'reason': 'EXAMPLE_TOKEN_0001'}]
        report = self.execute()
        self.assertEqual(report['states'], ['validated', 'validated'])
        for fixture in self.fixtures:
            decisions = [reply['result']['decision'] for reply in fixture.fixture.spawned[0].replies]
            self.assertEqual(decisions, ['decline', 'accept'])
            self.assertEqual(fixture.workflow.factory.spec['pre_effect']['input_capability'], 'finite')
        self.assert_accounting(2)

    def test_r4_competing_aggregate_reservation_has_no_model_effect(self):
        """A competing real ledger reservation wins before cohort consumption."""
        self.cohort(2)
        self.adopt()
        self.ledger.open_budget(self.config.pool_id, self.config.limits, scope_sha256=P.R.canonical_sha256(self.config.binding))
        amount = dict(self.config.limits)
        self.ledger.reserve(budget_id=self.config.pool_id, request_id='EXAMPLE-competitor',
            request_sha256=hashlib.sha256(b'EXAMPLE request').hexdigest(),
            admission_sha256=hashlib.sha256(b'EXAMPLE admission').hexdigest(), amount=amount,
            expires_at=self.ledger.current_time() + 60, lineage={'kind': 'initial', 'parent_attempt_id': None})
        with self.assertRaises(ValueError):
            self.host.run(self.config.request('execute'))
        self.assertFalse(any(hasattr(f.fixture, 'spawned') for f in self.fixtures))
        for fixture in self.fixtures:
            N.assert_no_native_births(self, fixture.fixture)
        self.assertTrue(self.host.status()['reconciliation_required'])
        self.assertEqual(len(self.attempts()), 1)

    def test_r4_intent_directory_sync_and_close_preserve_primary_and_forbid_restart(self):
        """New pool persistence fault: actual fsync/close overlap, zero effects."""
        self.cohort(1)
        self.adopt()
        primary = KeyboardInterrupt('EXAMPLE pool intent sync interruption')
        original_sync, original_close = os.fsync, os.close
        identity = tuple(self.config.identity[:2])
        armed = []
        def matches(fd):
            info = os.fstat(fd)
            return (info.st_dev, info.st_ino) == identity
        def sync(fd):
            if matches(fd) and (self.state / 'intent.json').exists():
                armed.append(True)
                raise primary
            return original_sync(fd)
        def close(fd):
            fail = armed and matches(fd)
            result = original_close(fd)
            if fail:
                raise OSError('EXAMPLE secondary pool close')
            return result
        with patch.object(os, 'fsync', sync), patch.object(os, 'close', close):
            with self.assertRaises(KeyboardInterrupt) as caught:
                self.host.run(self.config.request('execute'))
        self.assertIs(caught.exception, primary)
        self.assertTrue(primary.__notes__)
        self.assertTrue(P.RegisteredNativePoolHost(self.config).status()['reconciliation_required'])
        with self.assertRaisesRegex(ValueError, 'never redispatch'):
            P.RegisteredNativePoolHost(self.config).run(self.config.request('execute'))
        self.assertFalse(hasattr(self.fixtures[0].fixture, 'spawned'))
        N.assert_no_native_births(self, self.fixtures[0].fixture)

    def test_r4_first_and_last_validation_failures_preserve_other_lifecycle_evidence(self):
        """Uncovered failure positions; middle is the original partial join above."""
        for index in (0, 2):
            with self.subTest(failed=index):
                self.cohort(3, archive_schedule='settled', shared_source=True)
                for member in self.fixtures:
                    member.case.settle_reply = True
                self.fixtures[index].case.bad_output = True
                self.adopt()
                with self.assertRaisesRegex(P.R.validation.ValidationError,
                                            'Independent expected output comparisons failed'):
                    self.host.run(self.config.request('execute'))
                self.assertEqual(self.host.status()['states'], ['validated'] * index + ['failed'] + ['held'] * (2 - index))
                self.assert_accounting(index + 1)
                for sibling in self.fixtures[:index]:
                    factory = sibling.workflow.factory
                    self.assertTrue(factory.server.lifetime.termination['child_reaped'])
                    self.assertTrue(P.W.V.consume_validated(*factory.issued_artifact()))
                for sibling in self.fixtures[index + 1:]:
                    self.assertFalse(hasattr(sibling.fixture, 'spawned'))
                    N.assert_no_native_births(self, sibling.fixture)
                failed = self.fixtures[index]
                self.assertTrue(failed.workflow.factory.server.lifetime.termination['child_reaped'])
                self.assertIsNone(failed.workflow.factory.token)
                self.doCleanups()

    def test_review_v1_worker_hardlink_to_sibling_worker_or_target_refuses_before_effects(self):
        """Reproduced P1: byte-identical hardlink must not reach an allowed write."""
        for surface in ('worker', 'target'):
            with self.subTest(surface=surface):
                self.cohort(2)
                first, sibling = self.fixtures
                own = first.case.host.worker / 'seed.txt'
                peer = getattr(sibling.case.host, surface) / 'seed.txt'
                peer.unlink()
                os.link(own, peer)
                before = peer.read_bytes()
                self.assertTrue(all(f.case.host._observe() == f.case.host._initial for f in self.fixtures))
                first.case.on_startup = lambda: own.write_bytes(b'EXAMPLE worker-local corruption\n')
                with self.assertRaises(ValueError):
                    self.execute()
                self.assertEqual(peer.read_bytes(), before)
                self.assertFalse(any(hasattr(f.fixture, 'spawned') for f in self.fixtures))
                for fixture in self.fixtures:
                    N.assert_no_native_births(self, fixture.fixture)
                self.assertFalse(self.ledger.root.exists())
                self.assertFalse(list(self.state.iterdir()))
                self.assertTrue(all(not f.settings['state_store'].read_state()['operations'] for f in self.fixtures))
                self.doCleanups()

    def test_review_v1_host_validation_refuses_expiry_and_both_consumed_operations(self):
        """Reproduced P2 plus publication counterpart through original verifier."""
        for condition in ('expired', 'native_bundle', 'publication_bundle'):
            with self.subTest(condition=condition):
                self.cohort(2)
                c = self.config.controllers[1]
                if condition == 'expired':
                    c.ledger.clock.now = c.receipt.expires_at
                else:
                    c.verifier.verify_operation(*getattr(c, condition)).claim()
                before = [f.settings['state_store'].read_state() for f in self.fixtures]
                issued = [dict(member.verifier._capabilities) for member in self.config.controllers]
                with self.assertRaises(ValueError):
                    self.host.run(self.config.request('validate-only'))
                self.assertEqual(before, [f.settings['state_store'].read_state() for f in self.fixtures])
                self.assertEqual(issued, [dict(member.verifier._capabilities) for member in self.config.controllers])
                self.assertFalse(self.ledger.root.exists())
                self.assertFalse(list(self.state.iterdir()))
                self.assertFalse(any(hasattr(f.fixture, 'spawned') for f in self.fixtures))
                for fixture in self.fixtures:
                    N.assert_no_native_births(self, fixture.fixture)
                self.doCleanups()

    def test_review_v1_git_ref_grammar_preserves_original_n1_positive_path(self):
        """Reproduced P2: ordinary Git branch punctuation is valid metadata."""
        self.cohort(1, archive_schedule='settled', shared_source=True)
        fixture = self.fixtures[0]
        fixture.fixture.repositories.git(fixture.case.host.worker, 'update-ref', 'refs/heads/review+topic', 'HEAD')
        self.assertEqual(fixture.case.host._observe(), fixture.case.host._initial)
        self.config = P.PoolConfiguration(pool_id=self.config.pool_id,
            controllers=dict(zip(self.workers, self.config.controllers)), state_directory=self.state,
            ledger=self.ledger, limits=self.config.limits, enabled=True)
        self.host = P.RegisteredNativePoolHost(self.config)
        fixture.workflow = self.config.workflows[0]
        self.assertEqual(self.execute()['states'], ['validated'])
        self.assert_accounting(1)

    def test_r4_state_machine_exhaustive_terminal_and_unknown_transitions(self):
        """All 36 known/unknown state pairs, independently stated legal edges."""
        edges = {('queued', 'running'), ('queued', 'held'),
                 ('running', 'validated'), ('running', 'failed')}
        states = ('queued', 'running', 'validated', 'failed', 'held', 'EXAMPLE-unknown')
        for source in states:
            for target in states:
                with self.subTest(source=source, target=target):
                    if (source, target) in edges:
                        self.assertEqual(P.transition(source, target), target)
                    else:
                        with self.assertRaises(ValueError):
                            P.transition(source, target)


    def test_r3_structural_and_host_authority_validate_only_zero_effects(self):
        """New local structural/host-authority split; actual verifier, no claim."""
        request = {'version': 1, 'pool_id': 'EXAMPLE-pool', 'workers': ['plan'], 'mode': 'validate-only'}
        self.assertFalse(P.validate_structure(request)['authority_validated'])
        self.cohort(2, enabled=False)
        before = [f.settings['state_store'].read_state() for f in self.fixtures]
        report = self.host.run(self.config.request('validate-only'))
        self.assertTrue(report['authority_validated'])
        self.assertEqual(report['model_calls'], 0)
        self.assertEqual(before, [f.settings['state_store'].read_state() for f in self.fixtures])
        self.assertFalse(list(self.state.iterdir()))
        self.assertFalse(self.fixtures[0].case.ledger.root.exists())
        self.assertFalse(self.ledger.root.exists())
        self.adopt()
        with self.assertRaisesRegex(ValueError, 'disabled'):
            self.host.run(self.config.request('execute'))
