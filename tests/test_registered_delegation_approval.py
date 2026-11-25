"""Exercise the protected standing-approval producer with disposable custody."""
from __future__ import annotations

from pathlib import Path
import subprocess
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from tests import test_delegate_internal_work as native

import registered_delegation_approval as approval


def fixture_preparation(inputs):
    configuration = inputs.workflow.config
    case = inputs.case
    specification = dict(configuration.native_bundle[0]['registered_n1'])
    specification.pop('admission_sha256')
    return dict(verifier=configuration.verifier, mission_directive=inputs.settings['mission_directive'],
                host=case.host, ledger=case.ledger, controller_state=configuration.state,
                publication_state=configuration.publication_state, registered_specification=specification,
                standing=configuration._standing_delegation, route=case.route, node_id=case.node_id,
                native_operation_id='EXAMPLE-origin-native', publication_operation_id='EXAMPLE-origin-review',
                cleanup_seconds=15, expires_at=case.receipt.expires_at)


def fixture_approval(inputs, pending, *, scope=None, **signing):
    signing.setdefault('parent', native.W.digest(inputs.settings['mission_directive']))
    return inputs.fixture.authority.sign(native.W.digest(pending.approval_scope if scope is None else scope),
                                         'EXAMPLE-original-standing-decision', **signing)


class RegisteredDelegationApprovalTests(unittest.TestCase):
    def setUp(self):
        self.inputs = native.make_workflow(self, from_setup=True)
        self.original = self.inputs.workflow
        self.settings = self.inputs.settings
        self.case = self.inputs.case
        self.preparation = fixture_preparation(self.inputs)

    def approve(self, pending, *, scope=None, **signing):
        return fixture_approval(self.inputs, pending, scope=scope, **signing)

    def assert_unstarted(self):
        self.assertFalse(self.original.config.store.read_state()['operations'])
        self.assertFalse(list(self.settings['controller_state'].iterdir()))
        self.assertFalse(self.case.ledger.root.exists())
        self.assertFalse(self.inputs.fixture.spawned)

    def test_exact_approval_creates_repeatable_pre_dispatch_workflow(self):
        with patch.object(subprocess, 'Popen', side_effect=AssertionError('unexpected process start')):
            pending = approval.prepare_assignment(**self.preparation)
            directive = self.approve(pending)
            workflow = pending.create_workflow(directive)
            rebuilt = pending.create_workflow(directive)
        self.assertIs(type(workflow), native.W.RegisteredN1Workflow)
        self.assertEqual(workflow.config._standing_approval()[0], pending.approval_scope)
        self.assertEqual(workflow.config.native_bundle, rebuilt.config.native_bundle)
        self.assertEqual(workflow.config.publication_bundle, rebuilt.config.publication_bundle)
        self.assertEqual(workflow._receipt, self.case.receipt)
        self.assertEqual(workflow._worker_login_home, self.original._worker_login_home)
        self.assertIsNone(workflow.factory)
        self.assertIsNone(workflow._delegation)
        self.assert_unstarted()

    def test_forged_wrong_scope_and_wrong_parent_refuse_before_issuing_operations(self):
        pending = approval.prepare_assignment(**self.preparation)
        substituted = dict(pending.approval_scope, database_sha256='0' * 64)
        invalid = (None, {}, self.approve(pending, key=b'EXAMPLE-wrong-key'),
                   self.approve(pending, scope=substituted), self.approve(pending, parent=None))
        with patch.object(native.W.A, 'sign_controller_directive', side_effect=AssertionError('unexpected signing')):
            for value in invalid:
                with self.subTest(value=value), self.assertRaisesRegex(ValueError, 'standing approval'):
                    pending.create_workflow(value)
        self.assert_unstarted()

    def test_expired_admission_and_replaced_custody_refuse_before_issuing_operations(self):
        pending = approval.prepare_assignment(**self.preparation)
        directive = self.approve(pending)
        with patch.object(native.W.A, 'sign_controller_directive', side_effect=AssertionError('unexpected signing')):
            original_time = self.case.ledger.clock.now
            self.case.ledger.clock.now = self.case.receipt.expires_at
            with self.assertRaisesRegex(ValueError, 'admission is expired'):
                pending.create_workflow(directive)
            self.case.ledger.clock.now = original_time
            directory = self.settings['controller_state']
            directory.rename(Path(str(directory) + '-original'))
            directory.mkdir(mode=0o700)
            with self.assertRaisesRegex(ValueError, 'Original controller custody changed'):
                pending.create_workflow(directive)
        self.assert_unstarted()

    def test_route_cannot_select_its_own_registered_profile(self):
        specification = dict(self.preparation['registered_specification'], command='EXAMPLE changed command')
        with self.assertRaisesRegex(ValueError, 'independently registered specification'):
            approval.prepare_assignment(**dict(self.preparation, registered_specification=specification))
        self.assert_unstarted()

    def test_unrelated_original_operation_cannot_inherit_the_standing_signature(self):
        pending = approval.prepare_assignment(**self.preparation)
        directive = self.approve(pending)
        different = approval.prepare_assignment(**dict(self.preparation, native_operation_id='EXAMPLE-other-operation'))
        with (patch.object(native.W.A, 'sign_controller_directive', side_effect=AssertionError('unexpected signing')),
              self.assertRaisesRegex(ValueError, 'standing approval')):
            different.create_workflow(directive)
        self.assert_unstarted()

    def test_created_workflow_uses_original_registered_path_with_fake_effects(self):
        pending = approval.prepare_assignment(**self.preparation)
        workflow = pending.create_workflow(self.approve(pending))

        class FactoryReference:
            @property
            def server(self):
                return workflow.factory.server

        self.case.factory = FactoryReference()
        inputs = SimpleNamespace(**{**vars(self.inputs), 'workflow': workflow})
        result = native.run_fixture(self, inputs)
        self.assertTrue(result['validation_complete'])
        self.assertEqual(workflow.factory.operation_id, self.preparation['native_operation_id'])
        dispatch = workflow.factory.host_records.require_dispatch(workflow.factory.dispatch_id)
        self.assertEqual(dispatch['evaluation_metadata']['delivery_database_sha256'], native.DATABASE)
        self.assertFalse((workflow.config.host.target / 'result.txt').exists())


if __name__ == '__main__':
    unittest.main()
