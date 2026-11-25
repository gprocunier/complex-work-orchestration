"""Everyday delegation against the original registered N=1 offline fixture."""
from __future__ import annotations

import copy
import ctypes
import hashlib
import json
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from tests import test_registered_n1_factory as F
from tests import test_registered_finite_tool_wiring as tools
from tests.test_operative_routing import NOW, cache_profile, capability_evidence, work_plan
from tests.test_registered_n1_workflow import original_finite_completion

import registered_n1_workflow as W
from cwo_core import operative_routing as routing
from cwo_core.model_identities import operative_models, resolve_model
from cwo_core.util import packet_payload_hash
from delegate_internal_work import StandingDelegation


TASK = 'Update the project documentation for the scoped result file.'
BASELINE = 'sha256:' + hashlib.sha256(b'EXAMPLE baseline').hexdigest()
DATABASE = hashlib.sha256(b'EXAMPLE original database').hexdigest()
_EXAMPLE_ROUTE = F.example_route


def _route(*, tiny):
    route = _EXAMPLE_ROUTE(tiny=tiny)
    node = route['nodes'][0]
    source = work_plan(requested_model=resolve_model('luna'), narrow=True)
    source.update(work_unit_id=node['id'], bead_id=route['parent_id'], write_paths=['result.txt'],
                  expected_artifacts=['result.txt'], context_manifest=node['estimate_source']['context_manifest'])
    source['task_profile']['source_mutation_paths'] = ['result.txt']
    node['estimate_source'] = source
    node['execution']['executor'] = 'internal_worker_luna'
    return route


def _settings(fixture, case):
    authority, runtime = fixture.authority, W.R
    authority.mission['scope']['workspace_roots'].append(str(case.host.target))
    authority.mission['scope']['factory_ids'].append('EXAMPLE-publication')
    publisher = Path(W.G.__file__).resolve()
    publisher_sha = hashlib.sha256(publisher.read_bytes()).hexdigest()
    authority.registry['EXAMPLE-publication'] = {'adapter_path': str(publisher), 'adapter_sha256': publisher_sha}
    authority.mission_hash = F.authorities.mission_sha256(authority.mission)
    authority.directive = authority.sign(authority.mission_hash, 'EXAMPLE_STANDING_APPROVAL')
    plan = case.capability.bound_plan()
    operation = case.capability.evidence()['operation']
    plan['authority_sha256'] = operation['mission_sha256'] = authority.mission_hash
    allowance = json.loads(case.receipt.amounts_bytes)
    operation['reservation'].update(tool_calls=allowance['tool_calls'], runtime_seconds=allowance['runtime_seconds'])
    native = (plan, operation, authority.reseal(plan, operation))
    pubplan, pubop = copy.deepcopy(plan), copy.deepcopy(operation)
    pubplan.pop('registered_n1')
    pubplan.update(transaction_id='EXAMPLE-publication', runtime_adapter_path=str(publisher),
                   runtime_adapter_sha256=publisher_sha)
    pubop.update(operation_id='EXAMPLE-publication', factory_id='EXAMPLE-publication', workspace=str(case.host.target))
    publication = (pubplan, pubop, authority.reseal(pubplan, pubop))
    root = case.host.state.parent
    state, pubstate, authstate = (root / name for name in ('EXAMPLE-controller', 'EXAMPLE-publish', 'EXAMPLE-standing'))
    for directory in (state, pubstate, authstate):
        directory.mkdir(mode=0o700)
    store = runtime.MaintenanceStateStore(authstate, mission_id=authority.mission['mission_id'],
                                          mission_sha256=authority.mission_hash)
    store.initialize()
    return dict(mission=authority.mission, mission_directive=authority.directive, verification_key=authority.key,
                actor_id=authority.actor, identity_source=authority.identity, factory_registry=authority.registry,
                state_store=store, native_bundle=native, publication_bundle=publication,
                policy_specification=case.policy.report, receipt=case.receipt, route=case.route,
                node_id=case.node_id, ledger=case.ledger, host=case.host, controller_state=state,
                publication_state=pubstate, evidence=None)


def _setup_worker_login(test, store, renameat2):
    from tests.test_setup_delegation import DelegationSetupTests

    setup = DelegationSetupTests('runTest')
    setup.setUp()
    test.addCleanup(F.cleanup_helper, test, setup)
    setup.store = store
    state = setup.worker_home.parent / 'EXAMPLE-worker-login-state'
    test.enterContext(patch.object(W.R.qualification, 'worker_login_state', return_value=state))
    with patch.object(ctypes.CDLL.return_value, 'renameat2', new=renameat2, create=True):
        status = setup.invoke()
    test.assertEqual(status, 0, setup.err.getvalue())
    setup.login.assert_called_once()
    setup.probe.assert_called_once()
    test.assertEqual(setup.configured(), setup.worker_home)
    return setup.worker_home


def make_workflow(test, *, baseline_sha256=BASELINE, task=TASK, configure_login=True,
                  capabilities=None, from_setup=False, separate_project=False):
    renameat2 = ctypes.CDLL(None, use_errno=True).renameat2 if from_setup else None
    fixture = F.FactoryTests('runTest')
    fixture.setUp()
    test.addCleanup(F.cleanup_helper, test, fixture)
    with patch.object(F, 'example_route', _route):
        case = fixture.case(production=True, production_model=resolve_model('luna'), production_effort='high',
                            task_prompt=task, no_fake_scheduler=True, archive_schedule='settled')
    project = fixture.repositories.clone('EXAMPLE-lead') if separate_project else None
    settings = _settings(fixture, case)
    test.enterContext(patch.object(routing, '_now_iso', return_value=NOW))
    if from_setup:
        saved_login = _setup_worker_login(test, fixture.host_records, renameat2)
    elif configure_login:
        home = case.host.state.parent / 'EXAMPLE-worker-login'
        home.mkdir(mode=0o700)
        auth = home / 'auth.json'
        auth.write_text('EXAMPLE worker authentication metadata only.\n')
        auth.chmod(0o600)
        test.enterContext(patch.object(W.R.qualification, 'worker_login_state',
                                       return_value=home.parent / 'EXAMPLE-worker-login-state'))
        settings['worker_login_home'] = home
    if configure_login or from_setup:
        case.scenario.initialize_home = W.R.qualification.LOGIN_MOUNT
    evidence = capability_evidence(operative_models=operative_models()) if capabilities is None else capabilities
    settings['standing_delegation'] = StandingDelegation(baseline_sha256=baseline_sha256, database_sha256=DATABASE,
        capability_evidence=evidence, cache_profile=cache_profile(total=8_000, stable=0),
        project=str(project) if project is not None else None)
    scope = settings['standing_delegation'].approval_scope(receipt=case.receipt,
        operation=settings['native_bundle'][1], publication=settings['publication_bundle'][1])
    settings['standing_directive'] = W.A.sign_controller_directive(verification_key=fixture.authority.key,
        actor_id=fixture.authority.actor, identity_source=fixture.authority.identity, action_sha256=W.digest(scope),
        directive_id='EXAMPLE-standing-delegation', parent_receipt_sha256=W.digest(settings['mission_directive']))
    workflow = W.RegisteredN1Workflow(W.ControllerConfiguration(**settings))
    if from_setup:
        test.assertNotIn('worker_login_home', settings)
        test.assertEqual(workflow._worker_login_home, saved_login)

    class FactoryReference:
        @property
        def server(self):
            return workflow.factory.server

    case.factory = FactoryReference()
    return SimpleNamespace(fixture=fixture, case=case, task=task, workflow=workflow, settings=settings)


def run_fixture(test, inputs, *, call=None):
    with (patch.object(F, 'RpcProcess', tools.NamespacedFiniteRpcProcess),
          patch.object(W.R.provider_network, '_dial_provider', side_effect=AssertionError('unexpected provider call')),
          patch.object(W.R.qualification.WorkerLoginMount, 'confirm', autospec=True),
          patch.object(W.R.qualification, '_campaign_directory', side_effect=AssertionError('unexpected campaign')),
          original_finite_completion(test, inputs.case, inputs.workflow)):
        try:
            return inputs.workflow.delegate(inputs.task, database=DATABASE) if call is None else call()
        except Exception as failure:
            tools._note_original_poll_refusal(inputs.workflow.factory, failure)
            raise


class EverydayDelegationTests(unittest.TestCase):
    def assert_unstarted(self, inputs):
        self.assertIsNone(inputs.workflow.factory)
        self.assertFalse(inputs.workflow.config.store.read_state()['operations'])
        self.assertFalse(inputs.fixture.spawned)

    def test_original_registered_dispatch_uses_approved_packet_and_baseline(self):
        inputs = make_workflow(self)
        result = run_fixture(self, inputs)
        self.assertTrue(result['validation_complete'])
        factory = inputs.workflow.factory
        record = factory.host_records.require_dispatch(factory.dispatch_id)
        self.assertEqual(record['bead_id'], inputs.case.route['parent_id'])
        self.assertEqual(record['executor'], 'internal_worker_luna')
        self.assertEqual(record['provider_key'], 'internal_codex')
        self.assertEqual(record['evaluation_metadata']['delivery_baseline_sha256'], BASELINE)
        self.assertEqual(record['evaluation_metadata']['delivery_database_sha256'], DATABASE)
        self.assertEqual(record['request_sha256'], hashlib.sha256(inputs.case.receipt.request_bytes).hexdigest())
        self.assertEqual(record['packet_sha256'], result['packet_sha256'])
        self.assertEqual(record['packet_sha256'], packet_payload_hash(result['packet']))
        self.assertEqual(result['packet']['scope']['allowed_paths'], ['result.txt'])
        self.assertTrue(result['packet']['operative_routing']['dispatch_authorized'])
        self.assertEqual(inputs.fixture.attempt(inputs.case)['outcome'], 'completed')
        self.assertFalse((inputs.case.host.target / 'result.txt').exists())
        with self.assertRaisesRegex(ValueError, 'independent hand review'):
            inputs.workflow.adopt_publication(adoption_id='EXAMPLE-unreviewed')
        with self.assertRaisesRegex(ValueError, 'independent hand review'):
            inputs.workflow.publish()
        with self.assertRaisesRegex(ValueError, 'fresh original standing delegation'):
            inputs.workflow.delegate(inputs.task, database=DATABASE)

    def test_changed_task_never_claims_approval_or_launches(self):
        inputs = make_workflow(self)
        with self.assertRaisesRegex(ValueError, 'original admitted task'):
            inputs.workflow.delegate(TASK + ' Extra instructions.', database=DATABASE)
        self.assert_unstarted(inputs)

    def test_changed_standing_baseline_cannot_issue_current_route_authority(self):
        inputs = make_workflow(self)
        standing = inputs.settings['standing_delegation']
        inputs.settings['standing_delegation'] = StandingDelegation(
            baseline_sha256='sha256:' + '0' * 64, database_sha256=DATABASE,
            capability_evidence=json.loads(standing.capability_bytes), cache_profile=json.loads(standing.cache_bytes))
        with (patch.object(W.RegisteredN1Workflow, '_sign', side_effect=AssertionError('unexpected signing')),
              self.assertRaisesRegex(ValueError, 'standing approval.*scope')):
            workflow = W.RegisteredN1Workflow(W.ControllerConfiguration(**inputs.settings))
            workflow.delegate(TASK, database=DATABASE)
        self.assert_unstarted(inputs)

    def test_advisory_route_does_not_acquire_ordinary_dispatch_authority(self):
        inputs = make_workflow(self, task='Review the security policy changes around permission checks.')
        with self.assertRaisesRegex(ValueError, 'normal router did not select an internal worker'):
            inputs.workflow.delegate(inputs.task, database=DATABASE)
        self.assert_unstarted(inputs)

    def test_missing_login_reports_setup_before_signing(self):
        inputs = make_workflow(self, configure_login=False)
        with (patch.object(inputs.workflow, '_sign', side_effect=AssertionError('unexpected signing')),
              self.assertRaisesRegex(ValueError, 'Delegation is not set up') as refusal):
            inputs.workflow.delegate(inputs.task, database=DATABASE)
        self.assertEqual(str(refusal.exception), W.delegation_setup_message())
        self.assert_unstarted(inputs)

    def test_unsafe_login_refuses_before_signing_and_same_workflow_can_retry(self):
        inputs = make_workflow(self)
        auth = inputs.settings['worker_login_home'] / 'auth.json'
        auth.chmod(0o644)
        with (patch.object(inputs.workflow, '_sign', side_effect=AssertionError('unexpected signing')),
              self.assertRaisesRegex(ValueError, 'private authentication file')):
            inputs.workflow.delegate(inputs.task, database=DATABASE)
        self.assert_unstarted(inputs)
        auth.chmod(0o600)
        self.assertTrue(run_fixture(self, inputs)['validation_complete'])

    def test_expired_admission_has_no_dispatch_authority(self):
        inputs = make_workflow(self)
        inputs.case.ledger.clock.now = inputs.case.receipt.expires_at
        with self.assertRaisesRegex(ValueError, 'admission is expired'):
            inputs.workflow.delegate(inputs.task, database=DATABASE)
        self.assert_unstarted(inputs)

    def test_drifted_route_refuses_before_signing_authority(self):
        inputs = make_workflow(self)
        inputs.workflow.config.route['acceptance'].append('EXAMPLE unapproved criterion')
        with (patch.object(inputs.workflow, '_sign', side_effect=AssertionError('unexpected signing')),
              self.assertRaisesRegex(ValueError, 'Original request or whole route changed')):
            inputs.workflow.delegate(inputs.task, database=DATABASE)
        self.assert_unstarted(inputs)

    def test_missing_exact_model_evidence_refuses_before_adoption(self):
        capabilities = capability_evidence(operative_models=operative_models())
        capabilities['operative_models'] = [record for record in capabilities['operative_models']
                                             if record['model'] != resolve_model('luna')]
        inputs = make_workflow(self, capabilities=capabilities)
        with self.assertRaisesRegex(ValueError, 'current-authority-bound-model-ineligible'):
            inputs.workflow.delegate(inputs.task, database=DATABASE)
        self.assert_unstarted(inputs)

    def test_packet_refusal_never_claims_operation_or_launches(self):
        inputs = make_workflow(self)
        with (patch.object(W.D, 'build_native_worker_packet', side_effect=SystemExit('EXAMPLE invalid packet')),
              self.assertRaisesRegex(ValueError, 'Native delegation packet refused')):
            inputs.workflow.delegate(inputs.task, database=DATABASE)
        self.assert_unstarted(inputs)

    def test_standing_configuration_refuses_direct_adoption_and_live_hold(self):
        inputs = make_workflow(self)
        with self.assertRaisesRegex(ValueError, 'requires the original lead assignment'):
            inputs.workflow.adopt_execution(adoption_id='EXAMPLE-direct', disclosure_consent={})
        availability = W.R.live_availability
        with (patch.object(availability, 'REGISTERED_N1_LIVE_AVAILABLE', False),
              self.assertRaisesRegex(availability.NativeLiveUnavailable, 'registered-n1-live-unavailable')):
            inputs.workflow.delegate(inputs.task, database=DATABASE)
        self.assert_unstarted(inputs)


if __name__ == '__main__':
    unittest.main()
