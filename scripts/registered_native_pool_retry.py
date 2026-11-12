"""Explicit finite retry of one known failed member of an original pool.

Only a protected parent can select a fresh original signed controller. Neither
client JSON nor a serialized failure supplies authority. All spending uses the
original aggregate ledger and its immutable limits, including held siblings.
"""
from __future__ import annotations

import hashlib
import json
import weakref

import registered_native_pool_host as P

W, R, H = P.W, P.R, P.H
_need, _copy, _encode = P._need, P._copy, P._encode
_HOST = P.RegisteredNativePoolHost
_HOST_METHODS = R.admitted._method_table(_HOST)
_CONFIG_METHODS = R.admitted._method_table(W.ControllerConfiguration)
_WORKFLOW_METHODS = R.admitted._method_table(W.RegisteredN1Workflow)
_ISSUED = weakref.WeakKeyDictionary()


def _attempt(ledger, *, budget_id, admission_sha256):
    with ledger._locked() as (_directory, document):
        rows = [a for a in document['attempts'].values()
                if a['budget_id'] == budget_id and a['admission_sha256'] == admission_sha256]
        _need(len(rows) == 1, 'Exactly one original admitted attempt is required.')
        return _copy(rows[0])


def _failed(row, amounts):
    _need(row['state'] == 'terminal' and row['outcome'] == 'failed',
          'A known failed terminal is required; unknown/reconciled execution cannot retry.')
    _need(row['amount'] == amounts and all(row['charge'][k] >= v for k, v in amounts.items()),
          'Original independently admitted allowance and retained charge are required.')


def _cohort(host):
    c = host.config
    with c.ledger._locked() as (_directory, document):
        budget = document['budgets'][c.pool_id]
        _need(budget['limits'] == c.binding['limits']
              and budget['scope_sha256'] == R.canonical_sha256(c.binding),
              'Retry cannot replace or expand the original protected pool budget.')
        hashes = {hashlib.sha256(host._request_bytes(i)).hexdigest() for i in range(len(c.workers))}
        rows = {k: a for k, a in document['attempts'].items()
                if a['budget_id'] == c.pool_id and a['admission_sha256'] in hashes}
        _need(len(rows) == len(c.workers), 'Every original cohort reservation must remain recorded.')
        for index, controller in enumerate(c.controllers):
            digest = hashlib.sha256(host._request_bytes(index)).hexdigest()
            row = next(a for a in rows.values() if a['admission_sha256'] == digest)
            amounts = json.loads(controller.receipt.amounts_bytes)
            _need(row['amount'] == amounts and all(row['charge'][k] >= v for k, v in amounts.items()),
                  'Retry cannot use a released sibling allowance or erase original spend.')
        return _copy(rows)


def _same_operation(original, following):
    ignored = {'operation_id', 'plan_sha256'}
    _need({k: v for k, v in original.items() if k not in ignored}
          == {k: v for k, v in following.items() if k not in ignored},
          'Retry cannot expand original operation scope, reservation or authority.')
    _need(original['operation_id'] != following['operation_id'], 'Fresh operation identity is required.')


def _same_plan(original, following):
    ignored = {'transaction_id', 'plan_sha256', 'registered_n1'}
    _need({k: v for k, v in original.items() if k not in ignored}
          == {k: v for k, v in following.items() if k not in ignored},
          'Retry must preserve the original finite transaction and factory.')


def _same_profile(original, following):
    ignored = {'custody', 'admission_sha256'}
    _need({k: v for k, v in original.items() if k not in ignored}
          == {k: v for k, v in following.items() if k not in ignored},
          'Retry requires the exact current original native-policy profile, task and validation policy.')
    R._profile(following)


def _fresh_bundle(parent, bundle, retry_id, mission_directive, spec=None):
    plan, operation, _ = _copy(bundle)
    identity = hashlib.sha256(_encode([retry_id, operation['operation_id']])).hexdigest()
    plan['transaction_id'] = operation['operation_id'] = identity
    if spec is not None:
        plan['registered_n1'] = spec
    plan['plan_sha256'] = R.canonical_sha256({k: v for k, v in plan.items() if k != 'plan_sha256'})
    operation['plan_sha256'] = plan['plan_sha256']
    directive = W.A.sign_controller_directive(verification_key=parent.verifier._key,
        actor_id=parent.verifier._actor, identity_source=parent.verifier._identity,
        action_sha256=W.digest(operation), directive_id=identity,
        parent_receipt_sha256=W.digest(mission_directive))
    return plan, operation, directive


def issue_controller(parent, *, retry_id, state_directory):
    """Original parent issuance with no selectable model, profile or factory.

    Call from protected bootstrap only. A fresh inner N1 envelope accounts for
    the new invocation; ApprovedPoolRetry reserves the SAME effect against the
    original outer envelope before the controller can run. Nothing opens or
    increases that outer budget here. Unused issuance is not execution consent.
    """
    R.admitted._original_methods(parent, W.RegisteredN1Workflow, _WORKFLOW_METHODS)
    _need(R.admission.ledger_api._is_id(retry_id), 'A bounded retry identity is required.')
    parent._require_execution()
    c, v = parent.config, parent.verifier
    root = R._private(state_directory)
    _need(not list(root.iterdir()), 'Fresh empty protected retry storage is required.')
    R._disjoint([root, c.state, c.publication_state, c.host.state, c.ledger.root,
                 c.store.directory, c.host.worker, c.host.target])
    directories = {name: root / name for name in ('host', 'controller', 'publication', 'ledger')}
    for path in directories.values():
        path.mkdir(mode=0o700)
    host = H.OfflineN1Host(directories['host'], c.host.target, c.host.worker)
    for name in ('records', 'fake-server', 'fake-server/codex-home'):
        (host.state / name).mkdir(mode=0o700)
    ledger = R.admission.ledger_api.InvocationLedger(directories['ledger'], clock=c.ledger.clock,
        owner_probe=c.ledger.owner_probe)
    spec = _copy(c.native_bundle[0]['registered_n1'])
    spec.pop('admission_sha256')
    spec['custody'] = {'state': str(host.state), 'worker': str(host.worker), 'target': str(host.target),
                      'ledger': str(ledger.root), 'initial': host._initial, 'state_identity': host._state_identity}
    route = _copy(c.route)
    route['aggregate_id'] = 'retry-' + hashlib.sha256(retry_id.encode()).hexdigest()
    node = next(n for n in route['nodes'] if n['id'] == c.node_id)
    node['execution']['options'] = {'registered_n1': _copy(spec)}
    node['rendered_request'] = R.admission.planner.render_request(node)
    route['bound_input_sha256'] = R.admission.planner.input_sha256(route)
    receipt = R.admission.prepare(route, c.node_id, now=ledger.current_time(), expires_at=c.receipt.expires_at)
    spec['admission_sha256'] = R.admission._receipt_sha256(receipt)
    mission = parent._sign(v._mission, 'retry-mission-' + retry_id, None)
    native = _fresh_bundle(parent, c.native_bundle, retry_id, mission, spec)
    publication = _fresh_bundle(parent, c.publication_bundle, retry_id, mission)
    controller = W.ControllerConfiguration(mission=v._mission, mission_directive=mission,
        verification_key=v._key, actor_id=v._actor, identity_source=v._identity,
        factory_registry=v._factories, state_store=c.store, native_bundle=native,
        publication_bundle=publication, policy_specification=c.policy.report,
        receipt=receipt, route=route, node_id=c.node_id, ledger=ledger, host=host,
        controller_state=directories['controller'], publication_state=directories['publication'], evidence=c.evidence)
    _ISSUED[controller] = (parent, retry_id)
    return controller


def observe_retry(host, retry_id):
    """Read original signed retry status without adopting, issuing or dispatching.

    Lost in-memory failure custody forbids a fresh execution claim, but does
    not prevent the protected parent from inspecting durable observations.
    """
    R.admitted._original_methods(host, _HOST, _HOST_METHODS)
    _need(R.admission.ledger_api._is_id(retry_id), 'A bounded retry identity is required.')
    name = 'retry-' + hashlib.sha256(retry_id.encode()).hexdigest()
    with host._locked():
        unknown = {'retry_id': retry_id, 'state': 'unknown', 'redispatch_permitted': False, **R._FALSE}
        if not (host.config.state / (name + '-intent.json')).exists():
            return unknown
        intent = host._load(name + '-intent.json')
        _need(intent['action']['pool'] == host.config.binding
              and intent['action']['retry_id'] == retry_id, 'Original signed retry binding changed.')
        if not (host.config.state / (name + '-terminal.json')).exists():
            return unknown
        return _terminal(host, name + '-terminal.json', intent)


def _terminal(host, name, intent):
    terminal = host._load(name)
    _need(terminal['retry_id'] == intent['action']['retry_id']
          and terminal['worker_id'] == intent['action']['worker_id']
          and terminal['intent_sha256'] == hashlib.sha256(_encode(intent)).hexdigest(),
          'Retry terminal belongs to another intent or member.')
    return terminal


class ApprovedPoolRetry:
    """Protected selection; adopt and run are serialized by the original host.

    ``controller`` must be freshly issued by the original protected bootstrap,
    with fresh custody stores and signed operation identities. It reuses the
    failed member's worker/target and mission; no caller-supplied adapter or
    alternative profile is accepted. Construction and adoption make no calls.
    """

    def __init__(self, host, *, worker_id, retry_id, controller):
        R.admitted._original_methods(host, _HOST, _HOST_METHODS)
        _need(R.admission.ledger_api._is_id(retry_id), 'A bounded retry identity is required.')
        _need(worker_id in host.config.workers, 'Select an original configured member.')
        R.admitted._original_methods(controller, W.ControllerConfiguration, _CONFIG_METHODS)
        self.host, self.worker_id, self.retry_id = host, worker_id, retry_id
        self.index = host.config.workers.index(worker_id)
        self.parent = host.config.workflows[self.index]
        _need(_ISSUED.get(controller) == (self.parent, retry_id),
              'Only original protected retry issuance is accepted; substitutes refuse.')
        self.workflow = W.RegisteredN1Workflow(controller)
        self._adoption = self._selected = None
        self._name = 'retry-' + hashlib.sha256(retry_id.encode()).hexdigest()
        self._claim_name = 'retry-parent-' + hashlib.sha256(host._request_bytes(self.index)).hexdigest() + '.json'
        self._current()
        self.binding = self._action()

    def _current(self):
        host, old, new = self.host, self.parent.config, self.workflow.config
        R.admitted._original_methods(host, _HOST, _HOST_METHODS)
        host._current()
        _need(host.config.enabled is True, 'Registered pool host is disabled.')
        R.admitted._original_methods(new, W.ControllerConfiguration, _CONFIG_METHODS)
        R.admitted._original_methods(self.workflow, W.RegisteredN1Workflow, _WORKFLOW_METHODS)
        _need(self.parent is host.config.workflows[self.index]
              and self.worker_id == host.config.workers[self.index], 'Original member selection changed.')
        _need(_ISSUED.get(new) == (self.parent, self.retry_id), 'Original protected issuance changed.')
        new._bootstrap()
        _need(new.verifier._mission == old.verifier._mission
              and new.verifier._key == old.verifier._key
              and new.verifier._actor == old.verifier._actor
              and new.verifier._identity == old.verifier._identity
              and new.store is old.store, 'Original mission, issuer and durable authority store are required.')
        _need(new.host.worker == old.host.worker and new.host.target == old.host.target
              and new.policy.report == old.policy.report and new.evidence is old.evidence,
              'Retry cannot change the original worker, target, validation or evidence source.')
        self._fresh_bindings(old, new)

    def _fresh_bindings(self, old, new):
        for before, after in ((old.native_bundle, new.native_bundle),
                              (old.publication_bundle, new.publication_bundle)):
            oldplan, oldop, _ = W._operation(old.verifier, before)
            plan, operation, _ = W._operation(new.verifier, after)
            _same_plan(oldplan, plan)
            _same_operation(oldop, operation)
        _same_profile(old.native_bundle[0]['registered_n1'], new.native_bundle[0]['registered_n1'])
        R._configuration(new.native_bundle[0]['registered_n1'], new.host.worker)
        receipt = R.admitted._admission_snapshot(new.receipt)
        R.admitted._require_primary(receipt)
        fresh = R.admission.prepare(new.route, new.node_id, now=receipt.issued_at, expires_at=receipt.expires_at)
        _need(R.admission._same_admission(receipt, fresh), 'Original fresh whole-route admission is required.')
        self._same_route(old, new)
        roots = [new.state, new.publication_state, new.host.state, new.ledger.root]
        protected = [self.host.config.state, self.host.config.ledger.root]
        for c in self.host.config.controllers:
            protected.extend((c.state, c.publication_state, c.host.state, c.ledger.root,
                              c.store.directory, c.host.worker, c.host.target))
        R._disjoint(roots + protected[:2])
        for root in roots:
            self._separate(root, protected)

    @staticmethod
    def _separate(root, protected):
        for other in protected:
            R._disjoint([root, other])

    @staticmethod
    def _same_route(old, new):
        expected = _copy(old.route)
        expected['aggregate_id'] = new.route['aggregate_id']
        node = next(n for n in expected['nodes'] if n['id'] == old.node_id)
        spec = _copy(new.native_bundle[0]['registered_n1'])
        spec.pop('admission_sha256')
        node['execution']['options'] = {'registered_n1': spec}
        node['rendered_request'] = R.admission.planner.render_request(node)
        expected['bound_input_sha256'] = R.admission.planner.input_sha256(expected)
        _need(expected == new.route and old.receipt.limits_bytes == new.receipt.limits_bytes,
              'Retry must retain original task, estimates, dependencies and finite inner limits.')

    def _action(self):
        return {'purpose': 'approved-pool-retry-v1', 'pool': self.host.config.binding,
                'worker_id': self.worker_id, 'retry_id': self.retry_id,
                'parent': self.parent._action(), 'following': self.workflow._action()}

    def _parent_terminal(self):
        host, c = self.host, self.parent.config
        _need(self.worker_id in host.config.controlled_failure_workers,
              'The original host must explicitly select this controlled failure producer before execution.')
        _need(host._load('intent.json') == host.config.binding, 'Original immutable pool intent is required.')
        terminal = host._load('terminal.json')
        _need(terminal['workers'] == list(host.config.workers)
              and terminal['states'][self.index] == 'failed', 'Original member did not fail in this pool.')
        factory = self.parent.factory
        _need(type(factory) is R.RegisteredN1Factory and factory.host is c.host,
              'The original controlled failure producer must still be owned; restart is status only.')
        R.admitted._original_methods(factory, R.RegisteredN1Factory, R._FACTORY_METHODS)
        amounts = json.loads(c.receipt.amounts_bytes)
        inner = _attempt(c.ledger, budget_id=c.receipt.budget_id,
                         admission_sha256=R.admission._receipt_sha256(c.receipt))
        outer_hash = hashlib.sha256(host._request_bytes(self.index)).hexdigest()
        outer = _attempt(host.config.ledger, budget_id=host.config.pool_id, admission_sha256=outer_hash)
        _failed(inner, amounts)
        _failed(outer, amounts)
        evidence = host._controlled_failure(self.parent)
        return {'inner': inner, 'outer': outer, 'controlled': evidence, 'cohort': _cohort(host)}

    def adopt_execution(self, *, adoption_id, disclosure_consent):
        """Fresh explicit parent action, never inferred from wire reason text."""
        with self.host._locked():
            self._current()
            self._parent_terminal()
            _need(adoption_id != self.parent._adoption['directive_id'], 'A fresh retry adoption is required.')
            _need(not (self.host.config.state / (self._name + '-intent.json')).exists(),
                  'Existing retry intent permits observations only.')
            self.workflow.adopt_execution(adoption_id=adoption_id, disclosure_consent=disclosure_consent)
            self.binding = self._action()
            self._selected = _encode(self.binding)
            self._adoption = self.parent._sign(self.binding, adoption_id, self.parent.verifier._mission_hash)
            return _copy(self._adoption)

    def _require_adoption(self):
        self._current()
        _need(self._adoption is not None and _encode(self._action()) == self._selected,
              'Fresh exact retry adoption and disclosure consent are required.')
        self.parent._verify(self.binding, self._adoption, self.parent.verifier._mission_hash)
        self.workflow._require_execution()

    def run(self):
        """Claim once, reserve without releasing siblings, then invoke actual N1."""
        R.live_availability.require_pool_live()
        R.live_availability.require_n1_live()
        with self.host._locked() as directory:
            self._require_adoption()
            path = self.host.config.state / (self._name + '-intent.json')
            if path.exists():
                return self._status()
            parent = self._parent_terminal()
            self.host._validate_member_authority(self.workflow)
            intent = {'action': self.binding, 'adoption': self._adoption, 'parent': parent}
            _need(len(_encode(intent)) <= H.MAX_RECORD_BYTES - 4096,
                  'Retry intent exceeds the original bounded immutable record limit.')
            _need(not (self.host.config.state / self._claim_name).exists(),
                  'Original failed attempt already has a retry claim; never redispatch.')
            self.host._save(directory, self._claim_name, {'retry_id': self.retry_id, 'action': self.binding})
            self.host._save(directory, self._name + '-intent.json', intent)
            return self._dispatch(directory, intent)

    def _dispatch(self, directory, intent):
        c = self.host.config
        request = _encode(intent)
        digest = hashlib.sha256(request).hexdigest()
        result = {'retry_id': self.retry_id, 'worker_id': self.worker_id, 'state': 'unknown',
                  'intent_sha256': digest,
                  'redispatch_permitted': False, 'publication_authorized': False, **R._FALSE}
        reservation = None
        try:
            reservation = c.ledger.reserve(budget_id=c.pool_id, request_id=self._name,
                request_sha256=digest, admission_sha256=digest,
                amount=json.loads(self.workflow.config.receipt.amounts_bytes),
                expires_at=self.workflow.config.receipt.expires_at,
                lineage={'kind': 'retry', 'parent_attempt_id': intent['parent']['outer']['attempt_id']},
                refuse_while_unresolved=True)
            settled = c.ledger.invoke(reservation['reservation_id'], request,
                                     lambda _request, _report: self._effect(intent))
            result.update(state='terminal', outcome=settled['outcome'], reservation_id=reservation['reservation_id'])
            self.host._require_member_settlement(self.workflow, settled)
        except BaseException as primary:
            primary = self.host._primary_exception(self.workflow, primary)
            if reservation is None:
                self._reservation_failure(result, digest, primary)
            result['error'] = W.V._exception_text(primary)
            try:
                self.host._save(directory, self._name + '-terminal.json', result)
            except BaseException as secondary:
                R.admission.ledger_api.add_failure_note(primary, 'Retry evidence incomplete: ' + type(secondary).__name__)
            raise primary
        result['aggregate'] = c.ledger.summary(c.pool_id)
        self.host._save(directory, self._name + '-terminal.json', result)
        return _copy(result)

    def _reservation_failure(self, result, digest, primary):
        try:
            with self.host.config.ledger._locked() as (_directory, document):
                recorded = any(a['admission_sha256'] == digest for a in document['attempts'].values())
                if not recorded:
                    result['state'] = 'refused'
        except BaseException as secondary:
            R.admission.ledger_api.add_failure_note(primary,
                'Retry reservation remains unknown: ' + type(secondary).__name__)

    def _effect(self, intent):
        R.live_availability.require_pool_live()
        R.live_availability.require_n1_live()
        _need(_cohort(self.host) == intent['parent']['cohort'],
              'Original sibling settlement or reservation changed; retry requires reconciliation.')
        self._require_adoption()
        return P.RegisteredNativePoolHost._run_member(self.workflow, controlled=True)

    def _status(self):
        intent = self.host._load(self._name + '-intent.json')
        _need(intent['action'] == self.binding and intent['adoption'] == self._adoption,
              'Altered retry replay is refused.')
        path = self.host.config.state / (self._name + '-terminal.json')
        if not path.exists():
            return {'retry_id': self.retry_id, 'state': 'unknown', 'redispatch_permitted': False, **R._FALSE}
        return _terminal(self.host, path.name, intent)

    def status(self):
        with self.host._locked():
            self._require_adoption()
            return self._status()
