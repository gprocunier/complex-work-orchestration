"""Trusted embedding controller for finite registered local engineering.

Bootstrap inputs belong to the controller. No request selects Python imports,
keys, policy, factory registrations or custody locations. No CLI is installed.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import asdict
import fcntl
import hashlib
import json
import os
import stat

import registered_n1_factory as R
import registered_host_root_boundary as boundary
import guarded_artifact_target as G
import offline_artifact_validation as V
import qualified_workflow_adjudication as Q
from cwo_core import adjudication_source as S
from cwo_core import adjudication_binding as B
from cwo_core import maintenance_authority as A
from cwo_core.native_authority import canonical_authority_sha256 as digest

H = V.HOST
_encode = V._snapshot
_FACTORY = R.RegisteredN1Factory
_TARGET = G.GuardedArtifactTarget
_SOURCE = H.Path(__file__).resolve()


def _need(condition, message):
    if not condition:
        raise ValueError(message)


def _copy(value):
    return json.loads(_encode(value))


class EvidenceInputs:
    """Designated original invocation/adjudication observations, still evidence, never consent."""

    def __init__(self, root, source, context, adjudication_path, *, adjudication, observed_support=()):
        _need(type(adjudication) is Q.CompletedAdjudicationControl,
              "Original designated completed adjudication is required.")
        self.adjudication = self._control = adjudication
        try:
            self._initialize(root, source, context, adjudication_path, observed_support)
        except BaseException as failure:
            adjudication.refuse(failure)
            raise

    def _initialize(self, root, source, context, adjudication_path, observed_support):
        adjudication = self._control
        _need(type(source) is S.SourceObservation and type(context) is B.ExpectedContext,
              "Original produced source observations are required.")
        self.root, self.source, self.context = H._path(root), source, context
        self.path, self.support = adjudication_path, tuple(observed_support)
        self._observed = adjudication.current()
        self._producer, self._basis = adjudication.producer, adjudication.basis
        review_token = adjudication.host.completed(adjudication.ticket)
        review = adjudication.host.observe_completion(review_token)
        self._completed = tuple((host, token, observed, host._policy_bytes, host._routing)
            for host, token, observed in ((self._producer.host, self._producer.completion,
                                          self._producer.observed), (adjudication.host, review_token, review)))
        self._policies = self._policy_image()
        self._receipt = S.prepare_source(self.source, self.context, B._parse(self._observed.record_bytes),
                                        self.root, observed_support=self.support)
        _need(not self._receipt.prepared.errors, 'Original source preparation is unresolved.')

    def _policy_image(self):
        """All evaluator/route policy inputs, including the selected boundary roster."""
        return tuple((path.name, path.read_bytes()) for path in sorted(B.policy.POLICY_DIR.glob('*.yaml')))

    def _completion_current(self, host, token, observed, policies, routing):
        """Original identity/terminal ledger checks with byte-pinned route inputs."""
        ticket = observed.ticket
        with host._lock:
            _need(host._completed.get(token) is observed
                  and host._tickets.get(id(ticket)) is ticket
                  and host._prepared.get(id(ticket)) is ticket.prepared
                  and ticket.host is host and ticket.node_id == ticket.prepared.node_id,
                  'Original completed review registration changed.')
        _need(host._policy_bytes == policies == Q.review._policies() and host._routing == routing,
              'Original completed review policy or route changed.')
        attempt = B._parse(observed.attempt_bytes)
        _need(Q.review._bytes(host._ledger.attempt(attempt['reservation_id'])) == observed.attempt_bytes,
              'Original completed review ledger observation changed.')
        host.require_active_completion(ticket)

    def _completed_current(self):
        """Recheck actual original completions; never reevaluate a declared success."""
        control, producer = self._control, self._producer
        control.require_active()
        _need(self.adjudication is control, 'Original adjudication enrollment changed.')
        _need(control.producer is producer and control.basis == self._basis
              and control.support == self.support
              and control.reviewer_id == B._parse(self._observed.record_bytes)['adjudicator'],
              'Original designated source/reviewer binding changed.')
        source_host, source_token, source_observed, *_ = self._completed[0]
        review_host, _review_token, review_observed, *_ = self._completed[1]
        _need((producer.host, producer.completion, producer.observed, producer.expected,
               producer.evaluation, producer.raw, producer.dispatch_bytes, control.host, control.ticket)
              == (source_host, source_token, source_observed, self.context, self.source.evaluation,
                  self._observed.raw_return, self.source.dispatch_bytes, review_host, review_observed.ticket),
              'Original source or designated completion binding changed.')
        control.host.require_designated_review(control.ticket, self._basis)
        for completed in self._completed:
            self._completion_current(*completed)
        _need(B.read_support(self.root, producer.return_path) == self._observed.raw_return
              and producer.metadata == self._observed.evaluation_metadata_bytes,
              'Original source return or evaluation metadata changed.')
        return self._observed

    def current(self):
        control = self._control
        try:
            control.require_active()
            result = self._current()
            _need(self._control is control and self.adjudication is control,
                  'Original adjudication enrollment changed during consumption.')
            control.require_active()
            return result
        except BaseException as failure:
            control.refuse(failure)
            raise

    def _current(self):
        raw = B.read_support(self.root, self.path)
        observed = self._completed_current()
        producer = self._control.producer
        _need(self.root == producer.root and self.source == producer.observation
              and self.context == observed.context and self.support == observed.support
              and raw == observed.record_bytes,
              "Evidence must match the original produced source and designated adjudication.")
        _need(self._policy_image() == self._policies, 'Original source evaluation policy inputs changed.')
        record = B._parse(raw)
        receipt = self._receipt
        _need(B._supports(record, self.source.evaluation, self.support, self.root)
              == receipt.prepared.support_bytes, 'Original observed source support changed.')
        result = S.consume_source(receipt, self.context, self.root)
        _need(result['source_valid'] and result['inert_valid'] and not result['errors'],
              "Original source/adjudication evidence is stale or unresolved.")
        _need(result['decision'] == 'accepted' and not result['remaining_holds']
              and not result['adjudication_restrictions'], "Original adjudication holds remain.")
        self._control.require_active()
        for completed in self._completed:
            self._completion_current(*completed)
        _need(B.read_support(self.root, self.path) == raw and self._policy_image() == self._policies,
              "Original designated adjudication changed during evidence consumption.")
        return {'context': asdict(self.context), 'receipt_sha256': hashlib.sha256(receipt.binding_bytes).hexdigest(),
                'adjudication_sha256': hashlib.sha256(raw).hexdigest(), 'projection': result,
                'review_policy_sha256': B._sha(B._json([(name, B._sha(data)) for name, data in self._policies]))}


def _operation(verifier, bundle):
    plan, operation, directive = _copy(bundle)
    verifier._validate_operation(plan, operation)
    authority = A._directive(directive, key=verifier._key, actor=verifier._actor,
        identity=verifier._identity, action=digest(operation), parent=verifier._directive_hash)
    return plan, operation, authority


def _claimed_row(verifier, operation):
    state = verifier._current()
    _need(state['revocation_generation'] == operation['revocation_generation'], 'Authority was revoked.')
    expected = {'operation_sha256': digest(operation), 'plan_sha256': operation['plan_sha256'],
                'state': 'claimed', 'outcome': 'pending'}
    _need(state['operations'].get(operation['operation_id']) == expected,
          'Original durable claimed operation is required for recovery.')


def _recover_publication_claim(verifier, bundle):
    """Reenroll exactly one original claimed publisher; never native dispatch."""
    with verifier._serial():
        plan, operation, authority = _operation(verifier, bundle)
        _claimed_row(verifier, operation)
        _need(H.Path(plan['runtime_adapter_path']) == H.Path(G.__file__).resolve(),
              'Recovery can reenroll only the exact original publisher.')
        value = A.VerifiedMaintenanceOperation(verifier, plan, operation, authority, A._TOKEN)
        value._claimed = True
        verifier._capabilities[value._identity] = value
        verifier._check_capability(value, require_claimed=True)
        return value


class ControllerConfiguration:
    """Protected bootstrap, using the existing mission/state/registry authority.

    The parent selects signed operations and an independent policy before native
    output exists. This object must never be populated from a worker report.
    """

    def __init__(self, *, mission, mission_directive, verification_key, actor_id,
                 identity_source, factory_registry, state_store, native_bundle,
                 publication_bundle, policy_specification, receipt, route, node_id,
                 ledger, host, controller_state, publication_state, evidence):
        _need(type(evidence) is EvidenceInputs, 'Original source and designated adjudication evidence is required.')
        self.native_bundle, self.publication_bundle = _copy(list(native_bundle)), _copy(list(publication_bundle))
        self.policy = V.freeze_policy(policy_specification)
        self.receipt, self.route, self.node_id = receipt, _copy(route), node_id
        self.ledger, self.host, self.evidence = ledger, host, evidence
        self._evidence_control = evidence._control
        self.state, self.publication_state = H._path(controller_state), H._path(publication_state)
        self.store, self._guard = state_store, None
        self._check_private_roots()
        self.verifier = A.MaintenanceAuthorityVerifier(mission=mission, operator_directive=mission_directive,
            verification_key=verification_key, expected_actor_id=actor_id, expected_identity_source=identity_source,
            factory_registry=factory_registry, state_reader=state_store.read_state,
            claim_operation=state_store.claim_operation, current_check=self._current_check)
        self.initial = _copy(host._initial)
        self.roots = V._host(host)
        self.state_identity = H._identity(self.state)
        self.publication_identity = H._identity(self.publication_state)
        self._bootstrap()

    def _check_private_roots(self):
        scripts = H.Path(R.__file__).resolve().parent
        boundary.require_private_roots((self.host.target, self.host.state, self.ledger.root,
            self.store.directory, self.state, self.publication_state),
            visible_paths=(scripts, scripts.parent / 'policy', scripts.parent / 'schemas'))

    def _current_check(self):
        self._check_private_roots()
        if self._guard is not None:
            self._guard()

    def _bootstrap(self):
        native_plan, native_op, _ = _operation(self.verifier, self.native_bundle)
        publication_plan, publication_op, _ = _operation(self.verifier, self.publication_bundle)
        _need(H.Path(native_plan['runtime_adapter_path']) == H.Path(R.__file__).resolve(),
              'Protected configuration must select the original registered native factory.')
        _need(H.Path(publication_plan['runtime_adapter_path']) == H.Path(G.__file__).resolve(),
              'Native and publication capabilities require their own exact adapter sources.')
        _need(native_op['operation_id'] != publication_op['operation_id'], 'Distinct operation claims are required.')
        _need(native_plan['registered_n1']['purpose'] == 'local-engineering',
              'External execution purpose has no supported producer/consumer here.')
        _need(native_plan['registered_n1']['validation_policy'] == self.policy.report,
              'The independently configured policy differs from registered policy.')
        self.check_storage()

    def check_storage(self):
        self._check_private_roots()
        roots = [self.state, self.publication_state, self.host.state, self.host.worker,
                 self.host.target, self.ledger.root, self.store.directory]
        R._disjoint(roots)
        for path in (self.state, self.publication_state):
            info = os.lstat(path)
            _need(info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o700,
                  'Controller custody must remain private.')
        _need(H._identity(self.state) == self.state_identity
              and H._identity(self.publication_state) == self.publication_identity,
              'Controller custody directory changed.')
        _need(V._host(self.host) == self.roots, 'Original host roots changed.')


class RegisteredN1Workflow:
    """One native claim, explicit controller adoption and replay-only recovery."""

    def __init__(self, configuration):
        _need(type(configuration) is ControllerConfiguration, 'Protected controller bootstrap is required.')
        self.config = configuration
        self._source_control = configuration._evidence_control
        self.verifier = configuration.verifier
        self._adoption = self._publication = self._artifact = self.factory = None
        self._selected_action = None
        self._source = _SOURCE.read_bytes()
        self._image = R.implementation_sha256()
        self._receipt = R.admitted._admission_snapshot(configuration.receipt)
        self._intent = None
        self._disclosure = None
        self._started = False
        self._publication_ready = False
        if (configuration.state / 'intent.json').exists():
            self._restore_initial()

    def _restore_initial(self):
        action = self._load('intent.json')['action']
        c = self.config
        _need(action['roots'] == [[path, list(identity)] for path, identity in c.roots],
              'Original custody roots changed on restart.')
        original = action['initial']
        for field in ('worker_identity', 'target_identity'):
            _need(original[field] == c.initial[field], 'Original repository identity changed on restart.')
        c.initial = _copy(original)
        c.host._initial = _copy(original)

    @contextmanager
    def _descriptor(self, descriptor):
        try:
            yield descriptor
        except BaseException as primary:
            try:
                os.close(descriptor)
            except BaseException as cleanup:
                R.admission.ledger_api.add_failure_note(primary,
                    'Controller descriptor cleanup failed: ' + V._exception_text(cleanup))
            raise
        else:
            os.close(descriptor)

    @contextmanager
    def _state_directory(self):
        self.config.check_storage()
        with self._descriptor(os.open(self.config.state, H._FLAGS)) as fd:
            info = os.fstat(fd)
            _need([info.st_dev, info.st_ino, info.st_mode] == self.config.state_identity,
                  'Original controller directory changed during acquisition.')
            yield fd

    @contextmanager
    def _locked(self):
        with self._state_directory() as fd:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            primary = None
            try:
                yield
            except BaseException as error:
                primary = error
                raise
            finally:
                try:
                    fcntl.flock(fd, fcntl.LOCK_UN)
                except BaseException as cleanup:
                    if primary is None:
                        raise
                    R.admission.ledger_api.add_failure_note(primary,
                        'Controller unlock failed: ' + V._exception_text(cleanup))

    def _sign(self, action, identity, parent):
        return A.sign_controller_directive(verification_key=self.verifier._key,
            actor_id=self.verifier._actor, identity_source=self.verifier._identity,
            action_sha256=digest(action), directive_id=identity, parent_receipt_sha256=parent)

    def _verify(self, action, directive, parent):
        A._directive(directive, key=self.verifier._key, actor=self.verifier._actor,
            identity=self.verifier._identity, action=digest(action), parent=parent)

    def _save(self, name, body):
        H._relative(name)
        _need('/' not in name, 'Controller records require one literal name.')
        record = {'body': body, 'directive': self._sign(body, 'controller-' + name, self.verifier._mission_hash)}
        payload = _encode(record)
        with self._state_directory() as directory:
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
            with self._descriptor(os.open(name, flags, 0o600, dir_fd=directory)) as descriptor:
                remaining = memoryview(payload)
                while remaining:
                    count = os.write(descriptor, remaining)
                    _need(count > 0, 'Controller record write made no progress.')
                    remaining = remaining[count:]
                os.fchmod(descriptor, 0o400)
                os.fsync(descriptor)
            os.fsync(directory)

    def _load(self, name):
        record = json.loads(H._immutable_read(self.config.state, name, H.MAX_RECORD_BYTES))
        self._verify(record['body'], record['directive'], self.verifier._mission_hash)
        return record['body']

    def _sync_record(self, name):
        original = self._load(name)
        flags = os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC
        with self._state_directory() as directory:
            with self._descriptor(os.open(name, flags, dir_fd=directory)) as descriptor:
                _TARGET._file_kind(os.fstat(descriptor), H.MAX_RECORD_BYTES, {0o400}, True)
                os.fsync(descriptor)
            _need(self._load(name) == original, 'Original controller record changed during synchronization.')
            os.fsync(directory)

    def _action(self):
        try:
            return self._current_action()
        except BaseException as failure:
            self._source_control.refuse(failure)
            raise

    def _current_action(self):
        c = self.config
        c.check_storage()
        _need(_SOURCE.read_bytes() == self._source and R.implementation_sha256() == self._image,
              'Registered controller or installed source image changed.')
        _need(R.RegisteredN1Factory is _FACTORY and G.GuardedArtifactTarget is _TARGET,
              'Original factory or publisher changed.')
        _need(R.admission._receipt_sha256(c.receipt) == R.admission._receipt_sha256(self._receipt)
              and _encode(c.route) == self._receipt.route_input_bytes and c.node_id == self._receipt.node_id,
              'Original request or whole route changed.')
        _need(type(c.evidence) is EvidenceInputs and c.evidence._control is self._source_control,
              'Original source and designated adjudication evidence is required.')
        evidence = c.evidence.current()
        return {'purpose': 'registered-local-engineering-v1', 'request_sha256': hashlib.sha256(self._receipt.request_bytes).hexdigest(),
                'route': c.route, 'admission_sha256': R.admission._receipt_sha256(self._receipt),
                'native_bundle': c.native_bundle, 'publication_bundle': c.publication_bundle,
                'policy': c.policy.report, 'initial': c.initial,
                'roots': [[path, list(identity)] for path, identity in c.roots],
                'controller': [str(c.state), c.state_identity],
                'authority_store': [str(c.store.directory), H._identity(c.store.directory)],
                'publication': [str(c.publication_state), c.publication_identity],
                'source_image': self._image, 'evidence': evidence, 'disclosure': self._disclosure}

    def adopt_execution(self, *, adoption_id, disclosure_consent):
        """Current parent adoption, distinct from task-risk or evidence acceptance."""
        _need(type(adoption_id) is str and 0 < len(adoption_id) <= 80,
              'A bounded current adoption ID is required.')
        _need(disclosure_consent == {'boundary': 'local-only', 'allowed_effects': ['native-worker', 'target-publication'],
                                    'request_sha256': hashlib.sha256(self._receipt.request_bytes).hexdigest()},
              'Explicit exact local disclosure consent is required.')
        self._disclosure = _copy(disclosure_consent)
        action = self._action()
        self.verifier._current()
        self._selected_action = _encode(action)
        self._adoption = self._sign(action, adoption_id, self.verifier._mission_hash)
        self.config._guard = self._execution_current
        return _copy(self._adoption)

    def _execution_current(self):
        _need(self._adoption is not None and _encode(self._action()) == self._selected_action,
              'Distinct current execution adoption is required; source/adjudication drift refuses.')
        self._verify(json.loads(self._selected_action), self._adoption, self.verifier._mission_hash)

    def _require_execution(self):
        self._execution_current()
        self.verifier._current()

    def run(self, *, controlled_failure=False):
        """Original admitted native path; retained durable intent prevents redispatch."""
        R.live_availability.require_n1_live()
        _need(type(controlled_failure) is bool, 'Controlled failure selection must be Boolean.')
        with self._locked():
            self._require_execution()
            _need(not self._started and not list(self.config.state.iterdir()),
                  'Existing or unknown controller intent requires replay-only recovery, never redispatch.')
            self._started = True
            c = self.config
            native = self.verifier.verify_operation(*c.native_bundle)
            native.claim()
            publication = self.verifier.verify_operation(*c.publication_bundle)
            publication.claim()
            self._save('intent.json', {'action': json.loads(self._selected_action), 'adoption': self._adoption})
            self._intent = self._load('intent.json')
            self.factory = _FACTORY(native, self.verifier, receipt=c.receipt, route=c.route,
                node_id=c.node_id, ledger=c.ledger, host=c.host, policy=c.policy)
            if controlled_failure:
                _need('select_controlled_failure' in R._FACTORY_METHODS,
                      'The original controlled failure producer is unavailable.')
                R.admitted._original_methods(self.factory, _FACTORY, R._FACTORY_METHODS)
                self.factory.select_controlled_failure()
            self.factory.run()
            self._artifact = self.factory.issued_artifact()
            self._require_execution()
            self.target = _TARGET(c.publication_state, c.host, c.policy,
                                  operation=publication, verifier=self.verifier)
            self._retain_custody()
            self._publication_ready = True
            return self._observation()

    def _retain_custody(self):
        host, token, report, expected, policy = self._artifact
        body = V.publication_custody(host, report, expected, policy, token.report,
                                    self.target.operation)
        directive = self._sign(body, 'original-validated-custody', self.target.operation.operation_sha256)
        self._save('custody.json', {'custody': body, 'directive': directive,
            'ledger': self.factory.result, 'host_initial': self.config.initial})

    def adopt_publication(self, *, adoption_id):
        """Separate current adoption of the actual issued immutable artifact/target."""
        with self._locked():
            self._require_execution()
            _need(self._artifact is not None and self._publication_ready,
                  'Durable original custody is required before publication adoption; use authenticated recovery.')
            _host, token, report, _expected, _policy = self._artifact
            action = self.target.binding(self.config.publication_bundle[1]['operation_id'], token, report)
            directive = self._sign(action, adoption_id, self.target.operation.operation_sha256)
            self._save('publication.json', {'action': action, 'directive': directive})
            self._publication = directive
            return _copy(directive)

    def publish(self):
        with self._locked():
            self._require_execution()
            _need(self._artifact is not None and self._publication_ready and self._publication is not None,
                  'Separate publication execution consent is required.')
            _host, token, report, _expected, _policy = self._artifact
            result = self.target.publish(self.config.publication_bundle[1]['operation_id'],
                                         token, report, self._publication)
            return {**self._observation(), 'publication': result}

    def _observation(self):
        return {'execution_complete': self._artifact is not None,
                'validation_complete': self._artifact is not None,
                'evidence_acceptance_is_execution_authority': False, **G._FALSE}

    def recover(self):
        """Fresh bootstrap and objects; only authenticated known custody may replay."""
        with self._locked():
            self._require_execution()
            self._publication_ready = False
            self._publication = None
            intent = self._load('intent.json')
            _need(_encode(intent['action']) == self._selected_action,
                  'Mutated original controller scope refuses recovery.')
            self._verify(intent['action'], intent['adoption'], self.verifier._mission_hash)
            names = {path.name for path in self.config.state.iterdir()}
            _need(names in ({'intent.json', 'custody.json'},
                            {'intent.json', 'custody.json', 'publication.json'}),
                  'Unknown execution/output/journal state requires reconciliation.')
            self._recover_custody()
            if 'publication.json' not in names:
                return self._observation()
        return self.publish()

    def _recover_custody(self):
        c = self.config
        saved = self._load('custody.json')
        _plan, native_op, _authority = _operation(self.verifier, c.native_bundle)
        _claimed_row(self.verifier, native_op)
        _need(saved['host_initial'] == c.initial, 'Original host custody changed.')
        # Original durable admission result is compared; no settlement/release.
        result = saved['ledger']
        attempt = c.ledger.attempt(result['attempt']['reservation_id'])
        _need(attempt == result['attempt'] and attempt['outcome'] == 'completed',
              'Original completed admission accounting changed or is unknown.')
        publication = _recover_publication_claim(self.verifier, c.publication_bundle)
        body = saved['custody']
        token = V.reissue_publication_observation(c.host, body['report'], body['expected_target'],
            c.policy, body['observation'], operation=publication, verifier=self.verifier,
            custody_directive=saved['directive'])
        self._artifact = (c.host, token, body['report'], body['expected_target'], c.policy)
        self.target = _TARGET(c.publication_state, c.host, c.policy, operation=publication, verifier=self.verifier)
        if not (c.state / 'publication.json').exists():
            with self.target._guard():
                _need(not list(c.publication_state.iterdir()),
                      'Publication journal without adoption requires reconciliation.')
                V.consume_validated(c.host, token, body['report'], body['expected_target'], c.policy)
                self._sync_record('intent.json')
                self._sync_record('custody.json')
            self._publication_ready = True
            return
        adoption = self._load('publication.json')
        action = self.target.binding(c.publication_bundle[1]['operation_id'], token, body['report'])
        _need(action == adoption['action'], 'Original exact publication action changed.')
        self._verify(action, adoption['directive'], publication.operation_sha256)
        for name in ('intent.json', 'custody.json', 'publication.json'):
            self._sync_record(name)
        self._publication = adoption['directive']
        self._publication_ready = True
