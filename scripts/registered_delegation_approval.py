"""Prepare one standing-approved assignment inside an existing protected controller.

The embedding controller supplies mission and custody and verifies the human's
standing decision before signing the offered scope. This module has no command
entry, identity enrollment, credential input or worker-launch effect.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from types import MethodType

import registered_n1_workflow as workflow

authority = workflow.A
runtime = workflow.R
admission = runtime.admission


def _factory_id(verifier, source):
    adapter = str(Path(source).resolve())
    matches = [name for name in verifier._mission['scope']['factory_ids']
               if verifier._factories[name]['adapter_path'] == adapter]
    workflow._need(len(matches) == 1, 'The original mission must register exactly one matching factory.')
    return matches[0]


def _operation(verifier, *, identity, factory, workspace, generation, model, paths, reservation, specification=None):
    descriptor = verifier._factories[factory]
    plan = {'transaction_id': identity, 'authority_sha256': verifier._mission_hash,
            'runtime_adapter_path': descriptor['adapter_path'], 'runtime_adapter_sha256': descriptor['adapter_sha256'],
            'selected_model': model, 'required_session_count': 1, 'budget': {'reserved_sessions': 1},
            'children': [{'requested_model': model, 'write_paths': paths, 'read_only': False}]}
    if specification is not None:
        plan['registered_n1'] = specification
    plan['plan_sha256'] = runtime.canonical_sha256(plan)
    operation = {'operation_id': identity, 'mission_id': verifier._mission['mission_id'],
                 'mission_sha256': verifier._mission_hash, 'revocation_generation': generation,
                 'plan_sha256': plan['plan_sha256'], 'factory_id': factory, 'workspace': str(workspace),
                 'model': model, 'role': 'product', 'write_paths': paths, 'reservation': reservation}
    verifier._validate_operation(plan, operation)
    return [plan, operation]


def _store(verifier):
    workflow._need(type(verifier) is authority.MaintenanceAuthorityVerifier,
                   'The original protected mission verifier is required.')
    reader = verifier._state_reader
    store = reader.__self__ if type(reader) is MethodType else None
    workflow._need(type(store) is authority.MaintenanceStateStore and reader == store.read_state
                   and verifier._claim == store.claim_operation,
                   'The original protected mission store is required.')
    return store


def _custody(host, ledger, store, controller_state, publication_state, project):
    roots = workflow.V._host(host)
    workflow._need(type(ledger) is admission.ledger_api.InvocationLedger, 'The original invocation ledger is required.')
    scripts = Path(runtime.__file__).resolve().parent
    private = (host.target, host.state, ledger.root, store.directory, controller_state, publication_state)
    if project != host.target:
        private = (*private, project)
    runtime._disjoint((*private, host.worker))
    runtime.require_private_roots(private, visible_paths=(scripts, scripts.parent / 'policy', scripts.parent / 'schemas'))
    states = tuple(tuple(workflow.H._identity(runtime._private(path)))
                   for path in (controller_state, publication_state, store.directory))
    return roots, states, ledger.root, workflow._encode(host._initial), workflow.H._identity(project)


def _registered_profile(receipt, specification, host, ledger):
    execution = json.loads(receipt.execution_bytes)
    specification = workflow._copy(specification)
    workflow._need(execution['options'] == {'registered_n1': specification}
                   and 'admission_sha256' not in specification
                   and all(execution.get(field) == specification.get(field) for field in ('model', 'effort', 'provider')),
                   'The admitted route must use the independently registered specification.')
    custody = {'state': str(host.state), 'worker': str(host.worker), 'target': str(host.target),
               'ledger': str(ledger.root), 'initial': host._initial, 'state_identity': host._state_identity}
    workflow._need(specification['custody'] == custody and specification['implementation_sha256'] == runtime.implementation_sha256(),
                   'The independently registered specification does not match original custody or source.')
    workflow._need(runtime.qualification.MODEL_SELECTION not in specification
                   and runtime.qualification.AUTHENTICATION not in specification
                   and specification['purpose'] == 'local-engineering',
                   'Standing delegation requires the registered product profile.')
    runtime._profile(specification)
    runtime._configuration(specification, host.worker)
    specification['admission_sha256'] = admission._receipt_sha256(receipt)
    return specification


@dataclass(frozen=True, slots=True)
class PendingDelegationApproval:
    """An exact scope offered by, and redeemable only inside, the original controller."""

    _verifier: authority.MaintenanceAuthorityVerifier
    _mission_directive: bytes
    _host: workflow.H.OfflineN1Host
    _ledger: admission.ledger_api.InvocationLedger
    _controller_state: Path
    _publication_state: Path
    _roots: tuple
    _receipt: admission.PreparedAdmission
    _standing: workflow.D.StandingDelegation
    _plans: bytes

    @property
    def approval_scope(self):
        (_, native), (_, publication) = json.loads(self._plans)
        return self._standing.approval_scope(receipt=self._receipt, operation=native, publication=publication)

    def create_workflow(self, standing_directive):
        """Verify the signed standing decision before deriving bounded operation authority."""
        verifier, store = self._verifier, _store(self._verifier)
        with store.guard_current_state():
            plans = json.loads(self._plans)
            try:
                directive = workflow._copy(standing_directive)
                authority._directive(directive, key=verifier._key, actor=verifier._actor, identity=verifier._identity,
                                     action=workflow.digest(self.approval_scope), parent=verifier._directive_hash)
            except (authority.MaintenanceAuthorityError, workflow.V.ValidationError) as exc:
                raise ValueError('The original signed standing approval is required for this exact assignment.') from exc
            self._validate_current(store, plans)
            native, publication = (self._signed_operation(plan, operation, directive) for plan, operation in plans)
            return self._workflow(store, native, publication, directive)

    def _validate_current(self, store, plans):
        project = workflow.D.project_checkout(self._host, self._standing)
        observed = _custody(self._host, self._ledger, store, self._controller_state, self._publication_state, project)
        workflow._need(observed == self._roots and not any(self._controller_state.iterdir()),
                       'Original controller custody changed or was already used.')
        admission._live(self._receipt, self._ledger)
        state = self._verifier._current()
        specification = plans[0][0]['registered_n1']
        workflow._need(specification['implementation_sha256'] == runtime.implementation_sha256(),
                       'The independently registered source changed since preparation.')
        for plan, operation in plans:
            self._verifier._validate_operation(plan, operation)
            workflow._need(operation['revocation_generation'] == state['revocation_generation']
                           and operation['operation_id'] not in state['operations'],
                           'Standing approval requires current, unused operation authority.')

    def _signed_operation(self, plan, operation, standing_directive):
        verifier = self._verifier
        operation_digest = workflow.digest(operation)
        nonce = workflow.digest({'standing': workflow.digest(standing_directive), 'operation': operation_digest})
        directive = authority.sign_controller_directive(
            verification_key=verifier._key, actor_id=verifier._actor, identity_source=verifier._identity,
            action_sha256=operation_digest, directive_id=operation['operation_id'],
            parent_receipt_sha256=verifier._directive_hash, issued_at=standing_directive['issued_at'], nonce=nonce)
        return plan, operation, directive

    def _workflow(self, store, native, publication, directive):
        verifier = self._verifier
        config = workflow.ControllerConfiguration(
            mission=verifier._mission, mission_directive=json.loads(self._mission_directive),
            verification_key=verifier._key, actor_id=verifier._actor, identity_source=verifier._identity,
            factory_registry=verifier._factories, state_store=store, native_bundle=native,
            publication_bundle=publication, policy_specification=native[0]['registered_n1']['validation_policy'],
            receipt=self._receipt, route=json.loads(self._receipt.route_input_bytes), node_id=self._receipt.node_id,
            ledger=self._ledger, host=self._host, controller_state=self._controller_state,
            publication_state=self._publication_state, evidence=None, standing_delegation=self._standing,
            standing_directive=directive)
        return workflow.RegisteredN1Workflow(config)


def prepare_assignment(*, verifier, mission_directive, host, ledger, controller_state, publication_state,
                       registered_specification, standing, route, node_id, native_operation_id,
                       publication_operation_id, cleanup_seconds, expires_at):
    """Compile a bounded offer from the protected controller's original inputs."""
    store = _store(verifier)
    workflow._need(type(mission_directive) is dict and workflow.digest(mission_directive) == verifier._directive_hash,
                   'The original protected mission directive is required.')
    workflow._need(type(standing) is workflow.D.StandingDelegation, 'Original standing scope inputs are required.')
    workflow._need(all(admission.ledger_api._is_id(identity) for identity in (native_operation_id, publication_operation_id))
                   and native_operation_id != publication_operation_id, 'Two distinct bounded operation identities are required.')
    controller_state, publication_state = map(workflow.H._path, (controller_state, publication_state))
    project = workflow.D.project_checkout(host, standing)
    roots = _custody(host, ledger, store, controller_state, publication_state, project)
    receipt = admission.prepare(route, node_id, now=ledger.current_time(), expires_at=expires_at)
    runtime.admitted._require_primary(receipt)
    specification = _registered_profile(receipt, registered_specification, host, ledger)
    native, publication = _assignment_operations(verifier, host, receipt, specification, native_operation_id,
                                                 publication_operation_id, cleanup_seconds)
    return PendingDelegationApproval(verifier, workflow._encode(mission_directive), host, ledger, controller_state,
                                     publication_state, roots, receipt, standing, workflow._encode([native, publication]))


def _assignment_operations(verifier, host, receipt, specification, native_id, publication_id, cleanup_seconds):
    route, node = json.loads(receipt.route_input_bytes), json.loads(receipt.selected_node_bytes)
    workflow.D._route(node, None)
    paths = node['unit_estimate']['write_paths']
    policy = workflow.V.freeze_policy(specification['validation_policy'])
    workflow._need(len(paths) == 1 and [output['path'] for output in policy.report['outputs']] == paths,
                   'The approved assignment must bind one output path and its registered validation.')
    amounts = json.loads(receipt.amounts_bytes)
    reservation = {'mode': 'finite-operation', 'sessions': 1, 'max_concurrency': 1, 'cleanup_seconds': cleanup_seconds,
                   'tool_calls': amounts['tool_calls'], 'runtime_seconds': amounts['runtime_seconds']}
    shared = {'generation': verifier._current()['revocation_generation'], 'model': specification['model'],
              'paths': paths, 'reservation': reservation}
    native = _operation(verifier, identity=native_id, factory=_factory_id(verifier, runtime.__file__),
                        workspace=host.worker, specification=specification, **shared)
    publication = _operation(verifier, identity=publication_id, factory=_factory_id(verifier, workflow.G.__file__),
                             workspace=host.target, **shared)
    runtime.require_production_scope(specification, *native, route)
    return native, publication
