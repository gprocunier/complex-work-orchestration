"""Prepare a known output through the ordinary protected controller."""
from hashlib import sha256
import json
from pathlib import Path
import shlex
import sys
import unittest
from contextlib import chdir
from unittest.mock import patch

from tests import test_delegate_internal_work as examples
from tests.test_candidate_identity import bead
from tests import test_offline_n1_host as offline
from tests import test_operative_routing as routing_fixture

import registered_delegation_preparation as preparation
from cwo_core import host_records, manual_delivery, requirement_baseline


class DelegationPreparationTests(unittest.TestCase):
    def setUp(self):
        repositories = offline.OfflineN1HostTests('runTest')
        repositories.setUp()
        self.addCleanup(repositories.doCleanups)
        self.root, self.project = repositories.root, repositories.target
        self.store = host_records.HostRecordStore.for_tests(self.root / 'EXAMPLE-host-records')
        self.enterContext(patch.object(host_records, 'configured_store', return_value=self.store))
        self.enterContext(patch.object(preparation.runtime, 'configured_store', return_value=self.store))
        self.database = sha256(b'EXAMPLE database').hexdigest()
        baseline = {'record_type': 'cwo-requirement-baseline', 'version': 1, 'bead_id': 'example-bead',
                    'baseline_version': 1, 'criteria': [{
                        'id': 'result-file', 'requirement': 'Produce the scoped result file.',
                        'reference': 'Example assignment', 'expected_outcome': 'Deliver the exact text.',
                        'applicability': 'required', 'evidence_kind': 'artifact'}]}
        self.chain = requirement_baseline.resolve_chain(baseline)
        reference = requirement_baseline.reference_line(self.chain['bead_id'], 1, self.chain['digest'])
        self.bead = bead(self.chain['bead_id'], reference)
        self.enterContext(patch.object(manual_delivery, 'project_beads', return_value=(self.database, self.read_bead)))
        self.home = self.root / 'EXAMPLE-worker-login'
        self.home.mkdir(mode=0o700)
        (self.home / 'auth.json').write_text('EXAMPLE authentication fixture', encoding='utf-8')
        (self.home / 'auth.json').chmod(0o600)
        self.enterContext(patch.object(preparation.workflow.login_config, 'read_worker_login_home', return_value=self.home))
        login_state = self.root / 'EXAMPLE-login-state'
        self.enterContext(patch.object(preparation.runtime.qualification, 'worker_login_state', return_value=login_state))
        self.enterContext(patch.object(preparation.shutil, 'which', return_value=str(Path(sys.executable).resolve())))

    def read_bead(self, arguments):
        self.assertEqual(arguments[0], 'show')
        return json.dumps([self.bead])

    def prepare(self, **changes):
        request = {'project': self.project, 'database': self.database,
                   'task': 'Update the project documentation for the scoped result file.',
                   'chain': self.chain, 'output_path': 'result.txt', 'output_text': "Literal 'text' $(ignored)\n"}
        return preparation.prepare(**dict(request, **changes))

    def test_prepare_builds_fresh_bounded_offer_without_signing_ops(self):
        original_sign = preparation.authority.sign_controller_directive
        with patch.object(preparation.authority, 'sign_controller_directive', wraps=original_sign) as sign:
            pending = self.prepare()
        self.assertIs(type(pending), preparation.approval.PendingDelegationApproval)
        self.assertEqual(sign.call_count, 1)
        plan, operation = json.loads(pending._plans)[0]
        spec = plan['registered_n1']
        self.assertEqual(spec['validation_policy']['outputs'][0]['sha256'], sha256(b"Literal 'text' $(ignored)\n").hexdigest())
        self.assertEqual(shlex.split(spec['command']),
                         ['/usr/bin/printf', '%s', "Literal 'text' $(ignored)\n", '>', 'result.txt'])
        self.assertEqual(operation['write_paths'], ['result.txt'])
        self.assertEqual(pending.approval_scope['target'], str(self.project))
        self.assertEqual(pending.approval_scope['baseline_sha256'], self.chain['digest'])
        self.assertEqual(pending.approval_scope['database_sha256'], self.database)
        self.assertEqual(pending.approval_scope['disclosure'], 'provider-only')
        self.assertFalse(pending._ledger.root.exists())
        self.assertFalse(pending._verifier._current()['operations'])
        self.assertFalse((self.project / 'result.txt').exists())
        self.assertFalse((pending._host.worker / 'result.txt').exists())
        self.assertFalse(pending._host.worker.is_relative_to(self.store.state_root))

    def test_prepare_refuses_unbound_or_unsafe_requests_before_key_creation(self):
        failures = ({'database': '0' * 64}, {'output_path': '../result.txt'}, {'output_path': '.beads/data'},
                    {'output_path': '.env'}, {'output_text': '\0'}, {'output_text': 'a' * 2049})
        for changes in failures:
            with self.subTest(changes=changes.keys()), self.assertRaises(ValueError):
                self.prepare(**changes)
        self.bead['comments'] = []
        with self.assertRaisesRegex(ValueError, 'baseline'):
            self.prepare()
        self.assertFalse(self.store.state_root.exists())

    def test_skipped_setup_refuses_before_project_lookup(self):
        with (patch.object(preparation.workflow.login_config, 'read_worker_login_home', return_value=None),
              patch.object(manual_delivery, 'project_beads', side_effect=AssertionError('unexpected Beads lookup')),
              self.assertRaisesRegex(ValueError, 'Delegation is not set up')):
            self.prepare()
        self.assertFalse(self.store.state_root.exists())

    def test_existing_identical_output_and_overwide_replacement_refuse_before_key_creation(self):
        for proposal in ({'output_path': 'seed.txt', 'output_text': 'FAKE_SEED\n'}, {'output_text': 'x\n' * 81}):
            with self.subTest(proposal=proposal), self.assertRaisesRegex(ValueError, 'proposed'):
                self.prepare(**proposal)
        self.assertFalse(self.store.state_root.exists())
        custody = self.store.state_root.with_name(self.store.state_root.name + '-delegation')
        self.assertEqual(list(custody.iterdir()), [])

    def test_prepared_assignment_reopens_with_same_project_key_and_original_scope(self):
        pending = self.prepare()
        another = self.prepare()
        self.assertEqual(pending._verifier._key, another._verifier._key)
        self.assertNotEqual(pending.approval_scope, another.approval_scope)
        workflow = self.fixture_redeem(pending)
        preparation.entry.retain_approved_assignment(workflow)
        task = json.loads(pending._receipt.selected_node_bytes)['prompt']
        with chdir(self.project):
            reopened = preparation.entry.open_assignment(task, self.chain)
        self.assertEqual(reopened.config._standing_approval()[0], pending.approval_scope)
        self.assertFalse(reopened.verifier._current()['operations'])
        self.assertIsNone(reopened.factory)
        with self.assertRaisesRegex(ValueError, 'Current delegation route refused'):
            reopened.delegate(task, database=self.database)
        self.assertFalse(reopened.verifier._current()['operations'])
        self.assertFalse(reopened.config.ledger.root.exists())

    def test_trusted_fixture_observation_passes_unchanged_operative_route_gate(self):
        known = routing_fixture.capability_evidence(operative_models=examples.operative_models())
        with (patch.object(preparation, '_capability_evidence', return_value=known),
              patch.object(examples.routing, '_now_iso', return_value=routing_fixture.NOW)):
            pending = self.prepare()
            workflow = self.fixture_redeem(pending)
            task = json.loads(pending._receipt.selected_node_bytes)['prompt']
            native, publication = [bundle[1] for bundle in json.loads(pending._plans)]
            delegation, packet = preparation.workflow.D.authorize(workflow, task, native, publication,
                                                                    database=self.database)
        self.assertEqual(delegation['dispatch']['executor'], 'internal_worker_luna')
        self.assertEqual(packet['scope']['allowed_paths'], ['result.txt'])
        self.assertFalse(workflow.verifier._current()['operations'])

    @staticmethod
    def fixture_redeem(pending):
        verifier = pending._verifier
        directive = preparation.authority.sign_controller_directive(
            verification_key=verifier._key, actor_id=verifier._actor, identity_source=verifier._identity,
            action_sha256=preparation.workflow.digest(pending.approval_scope), directive_id='EXAMPLE-human-fixture',
            parent_receipt_sha256=verifier._directive_hash)
        return pending.create_workflow(directive)
