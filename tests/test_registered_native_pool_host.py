"""Original serial pool validation, retirement and signed readback witnesses."""
from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
import sys
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
        self.fixtures = []
        self.enterContext(patch.object(P.os, 'getpid', return_value=N.children.CONTROLLER))
        # Build the exact original signed workflows without initializing launch fixtures.
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
        return self.host

    def assert_source_retained(self, evidence, snapshot):
        self.assertIsNone(evidence.adjudication._refusal)
        self.assertEqual(F.evidence_snapshot(evidence), snapshot)

    def assert_adoption_has_no_effects(self, authority):
        self.assertEqual(authority, [fixture.settings['state_store'].read_state()
                                     for fixture in self.fixtures])
        self.assertFalse(list(self.state.iterdir()))
        self.assertFalse(self.ledger.root.exists())
        for fixture in self.fixtures:
            N.assert_no_native_births(self, fixture.fixture)
            self.assertFalse(fixture.case.ledger.root.exists())

    def test_r1_worker_selected_imports_wrong_factory_and_serialized_authority_refuse(self):
        """New pool ingress refuses before actual registered factory startup."""
        self.cohort(2)
        for field in ('factory', 'runtime_adapter_path', 'controller', 'authority'):
            request = self.config.request('validate-only')
            request[field] = 'EXAMPLE-caller-import'
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.host.run(request)
        c = self.fixtures[1].workflow.config
        c.native_bundle[0]['runtime_adapter_path'] = str(Path(CLI.__file__).resolve())
        with self.assertRaises(ValueError):
            self.host.validate_authority(self.config.request('validate-only'))
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
            self.host.validate_authority(self.config.request('validate-only'))
        self.assertFalse(list(self.state.iterdir()))

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
                with self.assertRaises(ValueError):
                    self.host.validate_authority(self.config.request('validate-only'))
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
        self.assertTrue(self.host.validate_authority(self.config.request('validate-only'))['authority_validated'])
        self.assertFalse(self.ledger.root.exists())

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

    def signed_record(self, name, body, *, signed_body=None):
        workflow = self.config.workflows[0]
        directive = workflow._sign(body if signed_body is None else signed_body, 'pool-' + name,
                                   workflow.verifier._mission_hash)
        path = self.state / name
        path.unlink(missing_ok=True)
        path.write_bytes(P._encode({'body': body, 'directive': directive}))
        path.chmod(0o400)
        return path

    def test_legacy_pool_execute_and_adoption_refuse_before_effects(self):
        self.cohort(1)
        before = [fixture.settings['state_store'].read_state() for fixture in self.fixtures]
        from registered_native_pool_client import submit

        request = self.config.request('execute')
        with (patch.object(self.host, '_locked', side_effect=AssertionError('pool state reached')),
              patch.object(self.config, 'check', side_effect=AssertionError('pool config reached'))):
            for n1, pool, reason in (
                (False, False, 'native-pool-live-unavailable'),
                (False, True, 'native-n1-live-unavailable'),
                (True, True, 'registered-serial-pool-execution-retired'),
            ):
                expected = ValueError if pool and n1 else P.live_availability.NativeLiveUnavailable
                with (self.subTest(n1=n1, pool=pool),
                      patch.multiple(P.live_availability, N1_LIVE_AVAILABLE=n1, POOL_LIVE_AVAILABLE=pool),
                      self.assertRaisesRegex(expected, reason)):
                    submit(request, host=self.host)
            with self.assertRaisesRegex(ValueError, 'registered-serial-pool-execution-retired'):
                self.host.adopt_execution(adoption_id='EXAMPLE-retired', disclosure_consents={})
        self.assert_adoption_has_no_effects(before)

    def test_signed_status_reads_only_original_records(self):
        self.cohort(1)
        before = [fixture.settings['state_store'].read_state() for fixture in self.fixtures]
        with self.assertRaises(FileNotFoundError):
            self.host.status()
        intent = self.signed_record('intent.json', self.config.binding)
        status = self.host.status()
        self.assertIs(status['reconciliation_required'], True)
        self.assertIs(status['redispatch_permitted'], False)
        terminal = {'pool_id': self.config.pool_id, 'size': 1, 'states': ['validated'], 'workers': self.workers,
                    'aggregate': {'charged': {}}, 'publication_authorized': False, **P.R._FALSE}
        terminal_path = self.signed_record('terminal.json', terminal)
        retained = {path: path.read_bytes() for path in (intent, terminal_path)}
        for host in (self.host, P.RegisteredNativePoolHost(self.config)):
            self.assertEqual(host.status(), terminal)
        self.assertEqual({path: path.read_bytes() for path in retained}, retained)
        self.assertEqual([fixture.settings['state_store'].read_state() for fixture in self.fixtures], before)
        self.assertFalse(self.ledger.root.exists())
        for fixture in self.fixtures:
            N.assert_no_native_births(self, fixture.fixture)

    def test_signed_status_refuses_changed_signature_binding_and_source(self):
        self.cohort(1)
        original = self.config.binding
        changed = {**original, 'pool_id': 'EXAMPLE-different-pool'}
        self.signed_record('intent.json', changed, signed_body=original)
        with self.assertRaisesRegex(ValueError, 'maintenance-directive-verification-failed'):
            self.host.status()
        self.signed_record('intent.json', changed)
        with self.assertRaisesRegex(ValueError, 'Original pool intent binding changed'):
            self.host.status()
        self.signed_record('intent.json', original)
        with (patch.object(self.config, 'enabled', not self.config.enabled),
              self.assertRaisesRegex(ValueError, 'source or configuration changed')):
            self.host.status()
        with (patch.object(P.R, 'implementation_sha256', return_value='0' * 64),
              self.assertRaisesRegex(ValueError, 'source image changed')):
            self.host.status()
