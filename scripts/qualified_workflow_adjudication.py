"""Completed local reviews into existing adjudication, hold-clearance and risk validators.

Bootstrap owns the exact candidate, task, support and designated review tickets.
Only the original registered HTTP host can supply completions. These cooperative
in-process observations authenticate neither a live reviewer nor hostile hosts.
All public invocation flags remain disabled; no effect is launched here.
"""
from __future__ import annotations

from dataclasses import asdict
from pathlib import Path
import threading

import qualified_adjudication as qualified
import qualified_review_dispatch as review
import qualified_risk_use as risk_use
import prepare_risk_narrowing as narrowing
import validate_run_readiness_plan as readiness
from cwo_core import adjudication_binding as binding
from cwo_core import adjudication_source as source
from prepare_hold_clearance import use_evidence


def _need(condition, message):
    if not condition:
        raise ValueError(message)


def _host(host):
    _need(type(host) is review.RegisteredReviewHost, 'The original registered review host is required.')
    return host


def _publish(root, name, raw):
    _need(binding.path_components(name) == (name,), 'Observed output requires a single relative filename.')
    with (root / name).open('xb') as stream:
        stream.write(raw)
    (root / name).chmod(0o444)


def _metadata(observed):
    value = binding._parse(observed.result_bytes)
    wire = binding._parse(observed.binding_bytes)
    envelope, selected = wire['envelope'], wire['selected']
    metadata = dict(qualified.METADATA_DEFAULTS)
    metadata.update(wire['evaluation_requirements'])
    for name in ('share_boundary', 'job_description_label', 'local_profile', 'model_profile',
                 'expected_return_language'):
        metadata[name] = envelope[name]
    metadata.update(dispatch_mode=selected['dispatch_mode'],
        local_response_truncated=value['response_truncated'],
        local_finish_reasons=value['finish_reasons'],
        local_reasoning_malformed=value['reasoning_malformed'],
        local_completion_status=value['completion_status'],
        local_usable_final_content=value['usable_final_content'],
        local_expected_response_contract=wire['base_transport'].get('response_contract'),
        local_response_contract=value.get('response_contract'),
        local_response_contract_status=value.get('response_contract_status'),
        local_response_model_status=value['response_model_status'],
        local_model_preflight_status=(value['model_preflight'] or {}).get('status'),
        local_http_status=value['status_code'])
    return binding._json(metadata)


def source_basis(expected, task=None):
    """Pre-submission scope; the packet digest is derived from the actual request."""
    context = asdict(expected)
    context.pop('packet_sha256')
    scope = None if task is None else {key: value for key, value in narrowing._task_record(task).items()
                                      if key != 'context'}
    return binding._json({'purpose': 'observed-evidence-source', 'context': context, 'task_scope': scope})


class WorkflowSource:
    """Publish one exact original completion under independently declared scope.

    ExpectedContext is bootstrap configuration, never taken from output labels.
    Its dispatch/task/executor/packet identities must join the actual request.
    Optional task scope is an original TaskExpectation, not submitted JSON.
    """

    def __init__(self, root: Path, host, completion, expected, *, return_path, dispatch_path, task=None):
        self.root, self.host, self.completion = root.absolute(), _host(host), completion
        self.expected = expected
        self.observed = host.observe_completion(completion)
        self.return_path, self.dispatch_path = return_path, dispatch_path
        self._refusal = None
        wire = binding._parse(self.observed.binding_bytes)
        envelope = wire['envelope']
        _need(type(expected) is binding.ExpectedContext, 'An independent ExpectedContext is required.')
        actual = (envelope['bead_id'], envelope['dispatch_id'], envelope['executor_key'],
                  binding._sha(self.observed.ticket.prepared.request_bytes))
        _need(actual == (expected.task, expected.dispatch_id, expected.executor, expected.packet_sha256),
              'Expected source does not join the actual original dispatch/request.')
        request = binding._parse(self.observed.ticket.prepared.request_bytes)
        required = {'id': 'cwo-bound-source-context', 'text': source_basis(expected, task).decode()}
        _need(request['sources'].count(required) == 1,
              'Original submitted source request must bind the independently declared candidate/scope/task.')
        result = binding._parse(self.observed.result_bytes)
        self.raw = (result.get('normalized_return') or result['final_content']).encode('utf-8')
        _need(0 < len(self.raw) <= binding.MAX_SUPPORT_BYTES, 'Actual return is empty or exceeds the bound.')
        self.metadata = _metadata(self.observed)
        self.evaluation = qualified.evaluate_current(self.raw, expected, metadata_bytes=self.metadata)
        dispatch = {'record_type': 'cwo-dispatch-record', 'version': 1, **asdict(expected),
            'return_sha256': binding._sha(self.raw), 'provider_key': envelope['provider_key'],
            'evaluation_metadata': binding._parse(self.metadata),
            'original_review': {'registration_sha256': host.registration_sha256,
                'request_sha256': binding._sha(self.observed.ticket.prepared.request_bytes),
                'http_request_sha256': result['request_payload_sha256'],
                'raw_response_sha256': result['raw_response_sha256'],
                'result_sha256': binding._sha(self.observed.result_bytes),
                'attempt_sha256': binding._sha(self.observed.attempt_bytes)}}
        if task is not None:
            _need(type(task) is narrowing.TaskExpectation and task.context == expected,
                  'Original task scope must match the independently selected source.')
            dispatch.update({key: value for key, value in narrowing._task_record(task).items() if key != 'context'})
        self.dispatch_bytes = binding._json(dispatch)
        provenance = binding._dispatch_provenance(self.dispatch_bytes, self.raw, expected,
                                                 self.evaluation.policy_bytes)
        self.observation = source.SourceObservation(dispatch_path, self.dispatch_bytes,
                                                    self.evaluation, provenance)
        _publish(self.root, return_path, self.raw)
        _publish(self.root, dispatch_path, self.dispatch_bytes)
        self.current()

    def current(self):
        try:
            self.require_active()
            current = self._current()
            self.require_active()
            return current
        except Exception as exc:
            self._refusal = self._refusal or str(exc)
            raise

    def require_active(self):
        """Pure monotonic veto; do not run another evaluator or control callout."""
        _need(self._refusal is None, 'Original source refusal is terminal: ' + str(self._refusal))
        self.host.require_active_completion(self.observed.ticket)

    def _current(self):
        _need(self.host.observe_completion(self.completion) == self.observed,
              'Original completed source changed.')
        _need(binding.read_support(self.root, self.return_path) == self.raw,
              'Actual original return changed.')
        source._revalidate(self.observation, self.expected, self.root)
        current = qualified.evaluate_current(self.raw, self.expected, metadata_bytes=self.metadata)
        _need(current == self.evaluation, 'Original current evaluation changed.')
        _need(self.host.observe_completion(self.completion) == self.observed,
              'Original completed source changed after evaluation.')
        return self.observation


def _record_host_source(producer, store):
    """Persist an original immutable HTTP completion, never caller dispatch JSON."""
    from cwo_core.adjudication import dispatch_provenance
    from cwo_core.host_return_intake import record_received_return
    from cwo_core.policy import load_policy
    producer.current()
    observed = producer.host.observe_completion(producer.completion)
    _need(observed == producer.observed, 'Host source completion identity changed.')
    wire = binding._parse(observed.binding_bytes)
    envelope = wire['envelope']
    identity = dispatch_provenance(binding._parse(producer.dispatch_bytes))
    _need(identity['known'] is True, 'Host source provider provenance is unresolved.')
    provider, model_id = identity['provider_family'], envelope['model']
    registered = load_policy('provider-registry').get('review_models', {}).get(provider, {}).get(model_id)
    _need(type(registered) is dict, 'Host source model family is not registered.')
    metadata = binding._parse(producer.metadata)
    metadata = {key: value for key, value in metadata.items()
                if key not in ('peer_review_status', 'peer_review_reviewer', 'peer_review_record')}
    metadata['expected_return_language_source'] = 'registered-adjudication-control'
    fields = dict(dispatch_id=producer.expected.dispatch_id, dispatch_role='executor',
        bead_id=producer.expected.task, executor=producer.expected.executor,
        provider_key=envelope['provider_key'], provider=provider,
        model_family=registered['model_family'], model_id=model_id,
        reasoning_effort=envelope['request_options'].get('reasoning_effort'),
        session_id='http-request-' + binding._sha(observed.ticket.prepared.request_bytes),
        packet_sha256=producer.expected.packet_sha256,
        request_sha256=binding._parse(observed.result_bytes)['request_payload_sha256'],
        evaluation_metadata=metadata)
    prior = store.find('dispatch', dispatch_id=producer.expected.dispatch_id)
    if prior:
        recorded = store.require_dispatch(producer.expected.dispatch_id)
        if recorded.get('stage') == 'observed':
            _need(binding._json({key: recorded.get(key) for key in fields}) == binding._json(fields),
                  'Recorded host dispatch differs from original completion.')
        else:
            store.write_observed_dispatch(producer.expected.dispatch_id,
                prepared_record_sha256=recorded['_record_sha256'],
                observation_sha256=binding._sha(observed.result_bytes),
                **{key: value for key, value in fields.items() if key not in ('dispatch_id', 'dispatch_role')})
    else:
        store.write_dispatch(**fields)
    record_received_return(store, producer.expected.dispatch_id, producer.raw)
    producer.current()


def adjudication_basis(producer, support, reviewer_id):
    producer.current()
    _need(type(reviewer_id) is str and 0 < len(reviewer_id) <= 256,
          'Bootstrap must designate a bounded adjudicator identity.')
    _need(type(support) is tuple and len(support) <= binding.MAX_SUPPORT_FILES,
          'Bootstrap must designate bounded immutable support observations.')
    rows = []
    for item in support:
        _need(type(item) is binding.SupportObservation and type(item.raw) is bytes,
              'Original immutable observed support is required.')
        _need(binding.read_support(producer.root, item.artifact) == item.raw,
              'Designated support changed.')
        rows.append({'artifact': item.artifact, 'artifact_type': 'validation-log',
                     'sha256': binding._sha(item.raw), 'finding_ids': [item.finding_id]})
    return binding._json({'purpose': 'evidence-adjudication', 'context': asdict(producer.expected),
        'return_sha256': binding._sha(producer.raw),
        'evaluation_sha256': producer.evaluation.evaluation_sha256,
        'dispatch_sha256': binding._sha(producer.dispatch_bytes),
        'policy_sha256': binding._sha(producer.evaluation.policy_bytes),
        'return_text': producer.raw.decode('utf-8'),
        'evaluation': binding._parse(producer.evaluation.result_bytes),
        'dispatch': binding._parse(producer.dispatch_bytes),
        'observed_support': [{'artifact': item.artifact, 'text': item.raw.decode('utf-8')} for item in support],
        'supporting_evidence': rows, 'adjudicator': reviewer_id,
        'authority': {'rule': 'synthesis-input-adjudication'}})


def _pin_review(host, ticket, basis):
    _host(host)._registered(ticket)
    request = binding._parse(ticket.prepared.request_bytes)
    required = {'id': 'cwo-bound-review-basis', 'text': basis.decode('utf-8')}
    _need(request['sources'].count(required) == 1,
          'Original designated review request must contain the exact current bound basis.')
    host.designate_review(ticket, basis)


def _decision(host, ticket, basis, keys):
    observed = host.observe_completion(host.completed(ticket))
    host.require_designated_review(ticket, basis)
    request = binding._parse(observed.ticket.prepared.request_bytes)
    _need(request['sources'].count({'id': 'cwo-bound-review-basis', 'text': basis.decode()}) == 1,
          'Original completed review request lost its exact binding.')
    result = binding._parse(observed.result_bytes)
    raw = result['final_content'].encode('utf-8')
    _need(len(raw) <= 65536, 'Actual designated decision exceeds its bound.')
    decision = binding._parse(raw)
    _need(type(decision) is dict and set(decision) == set(keys),
          'Actual designated decision has missing, ambiguous or authority-asserting fields.')
    _need(decision['decision'] in ('accepted', 'accepted-with-changes', 'rejected', 'quarantined'),
          'Actual designated decision is unknown.')
    _need(type(decision['rationale']) is str and 0 < len(decision['rationale'].encode()) <= 4096,
          'Actual designated rationale is missing or too large.')
    return observed, decision


class CompletedAdjudicationControl:
    """Observe a designated actual completed review, then reuse the existing broker."""

    def __init__(self, producer, support, reviewer_id, host, ticket, control_id):
        self.producer, self.support, self.reviewer_id = producer, support, reviewer_id
        self.host, self.ticket, self.control_id = host, ticket, control_id
        self.basis = adjudication_basis(producer, support, reviewer_id)
        _pin_review(host, ticket, self.basis)
        self.owner = None
        self._state = 'open'
        self._refusal = None
        self._refusal_lock = threading.RLock()
        self._producer, self._host, self._ticket = producer, host, ticket
        self._binding = (support, reviewer_id, control_id, self.basis)
        self._acceptance_attempted = False
        self.acceptance_record = None

    def refuse(self, failure):
        """Irreversibly veto this enrollment; this API can never grant use.

        The original current checker and bounded consumers share this one
        open -> refused transition. Restored files or a fresh consumer wrapper
        cannot reset it. Keep the first failure without evaluating its text.
        """
        with self._refusal_lock:
            if self._state != 'refused':
                self._state = 'refused'
                self._refusal = failure

    def claim(self, owner):
        _need(self.owner is None, 'Completed adjudication control is already claimed.')
        self.owner = owner

    def observe(self, owner, control_id):
        _need(owner is self.owner and owner is not None and control_id == self.control_id,
              'Completed adjudication owner/control identity mismatch.')
        return self.current()

    def current(self):
        try:
            self.require_active()
            current = self._current()
            self._persist_completed_acceptance(current)
            return current
        except BaseException as failure:
            self.refuse(failure)
            raise

    def _current(self):
        _need(adjudication_basis(self.producer, self.support, self.reviewer_id) == self.basis,
              'Designated original adjudication basis changed.')
        observed, decision = _decision(self.host, self.ticket, self.basis,
            ('decision', 'rationale', 'finding_ids', 'accepted_excerpt'))
        producer = self.producer
        basis = binding._parse(self.basis)
        record = {'record_type': 'cwo-return-adjudication', 'version': 1,
            **asdict(producer.expected), **decision,
            'adjudication_id': 'review-' + binding._sha(observed.result_bytes),
            'return_sha256': binding._sha(producer.raw),
            'evaluation_sha256': producer.evaluation.evaluation_sha256,
            'adjudicator': basis['adjudicator'], 'authority': basis['authority'],
            'supporting_evidence': basis['supporting_evidence']}
        producer.current()
        self.host.observe_completion(self.host.completed(self.ticket))
        self.require_active()
        return qualified.ControlObservation(producer.expected, producer.return_path, producer.dispatch_path,
            producer.raw, producer.dispatch_bytes, producer.evaluation.result_bytes,
            producer.evaluation.policy_bytes, binding._json(record), self.support, producer.metadata,
            qualified.observe_boundary_policy(producer.metadata))

    def require_active(self):
        try:
            with self._refusal_lock:
                _need(self._state == 'open', 'Original adjudication refusal is terminal.')
                _need(self.producer is self._producer and self.host is self._host
                      and self.ticket is self._ticket,
                      'Original adjudication producer or completion identity changed.')
                _need((self.support, self.reviewer_id, self.control_id, self.basis) == self._binding,
                      'Original designated adjudication binding changed.')
            self.producer.require_active()
            self.host.require_active_completion(self.ticket)
            with self._refusal_lock:
                _need(self._state == 'open', 'Original adjudication refusal is terminal.')
        except BaseException as failure:
            self.refuse(failure)
            raise

    def record_acceptance(self, *, store=None):
        """Record this original completed CWO decision; held returns still refuse.

        The registered host and designated ticket were pinned before dispatch.
        Worker output cannot replace them with a callable or an approval file.
        """
        from cwo_core.host_acceptance import HostAcceptancePipeline, HostAdjudicationDecision, require_acceptance
        from cwo_core.host_records import configured_store
        from cwo_core.peer_review import pending_evaluation_sha256
        store = configured_store() if store is None else store
        self.require_active()
        selected = store.workspace_database()
        if selected is None:
            return None
        database_identity = selected[1]
        observed = self._current()
        if self.acceptance_record is not None:
            require_acceptance(store, self.acceptance_record, bead_id=self.producer.expected.task,
                return_sha256=binding._sha(self.producer.raw),
                evaluation_sha256=pending_evaluation_sha256(binding._parse(observed.evaluation_bytes)),
                database_identity=database_identity)
            return self._current_acceptance_record(store, selected)
        with self._refusal_lock:
            _need(not self._acceptance_attempted, 'Completed acceptance is already attempted.')
            self._acceptance_attempted = True
        observed = self._current()
        producer = self.producer
        expected = producer.expected
        record = binding._parse(observed.record_bytes)
        _need(record['decision'] == 'accepted', 'Closure requires an unconditional completed acceptance decision.')
        _need(record['finding_ids'] == [] and self.support == (),
              'Unresolved evidence findings must use their qualified clearance pipeline.')

        def decide(evaluation):
            current = self._current()
            _need(current == observed, 'Completed acceptance observation changed during evaluation.')
            expected_evaluation = binding._parse(current.evaluation_bytes)
            differences = sorted(key for key in set(expected_evaluation) | set(evaluation)
                                 if expected_evaluation.get(key) != evaluation.get(key))
            _need(not differences, 'Completed decision concerns another evaluation: ' + ','.join(differences))
            decision = binding._parse(current.record_bytes)
            return HostAdjudicationDecision(decision['decision'], decision['rationale'], self.control_id)

        _record_host_source(producer, store)
        pipeline = HostAcceptancePipeline(decide, store=store)
        metadata = binding._parse(producer.metadata)
        self.acceptance_record = pipeline.accept(producer.raw.decode('utf-8'), bead_id=expected.task,
            dispatch_id=expected.dispatch_id, database_identity=database_identity,
            peer_review_record=metadata.get('peer_review_record'))
        return self._current_acceptance_record(store, selected)

    def _current_acceptance_record(self, store, selected):
        _need(store.require_database_identity(selected[0]) == selected[1],
              'Workspace database changed during completed acceptance.')
        return self.acceptance_record

    def _persist_completed_acceptance(self, current):
        """The existing adjudication consumer records eligible accepted decisions."""
        evaluation = binding._parse(current.evaluation_bytes)
        if (binding._parse(current.record_bytes)['decision'] != 'accepted'
                or evaluation.get('accepted_for_use') is not True):
            return
        self.record_acceptance()

    def source_receipt(self):
        """Original informational SourceReceipt; never a task-risk or execution grant."""
        try:
            current = self.current()
            receipt = source.prepare_source(self.producer.current(), current.context,
                binding._parse(current.record_bytes), self.producer.root, observed_support=self.support)
            if receipt.prepared.errors:
                self.refuse(ValueError('Original source preparation refused.'))
            return receipt
        except BaseException as failure:
            self.refuse(failure)
            raise


def task_risk_basis(root, registered):
    """Reuse the existing task-risk producer's full independent authority basis."""
    return binding._json({'basis': risk_use._basis(root, registered),
        'scope_evidence': binding._parse(registered.scope.evidence_bytes),
        'documents': [{'path': name, 'text': raw.decode('utf-8')}
            for name, raw in zip(registered.task.paths, registered.scope.document_bytes)],
        'return_text': registered.receipt.source.evaluation.raw_return.decode('utf-8'),
        'source_adjudication': binding._parse(registered.adjudication_bytes)})


class CompletedTaskRiskControl:
    """Separate task-risk authority observed from its own designated original review."""

    def __init__(self, root, registered, host, ticket, control_id, *, adjudication):
        self.root, self.registered = root, registered
        _need(type(adjudication) is CompletedAdjudicationControl,
              'Task-risk use needs its original completed evidence adjudication.')
        self.adjudication = adjudication
        _need(adjudication.source_receipt() == registered.receipt,
              'Task-risk source is not the current original completed adjudication.')
        self.host, self.ticket, self.control_id = host, ticket, control_id
        self.basis = task_risk_basis(root, registered)
        _pin_review(host, ticket, self.basis)
        self.owner = None

    def claim(self, owner):
        _need(self.owner is None, 'Completed task-risk control is already claimed.')
        self.owner = owner

    def observe(self, owner, control_id):
        _need(owner is self.owner and owner is not None and control_id == self.control_id,
              'Completed task-risk owner/control identity mismatch.')
        return self.current()

    def current(self):
        _need(self.adjudication.source_receipt() == self.registered.receipt,
              'Original completed source changed before task-risk use.')
        _need(task_risk_basis(self.root, self.registered) == self.basis, 'Original task-risk basis changed.')
        _, decision = _decision(self.host, self.ticket, self.basis, ('decision', 'rationale'))
        raw = risk_use.produce_disposition(self.root, self.registered, **decision)
        self.host.observe_completion(self.host.completed(self.ticket))
        self.require_active()
        return risk_use.TaskRiskDecision(self.registered, raw)

    def require_active(self):
        self.adjudication.require_active()
        self.host.require_active_completion(self.ticket)

    def publish(self):
        """Persist actual controlled disposition bytes; original host validates at use."""
        observed = self.current()
        _publish(self.root, self.registered.disposition_path, observed.raw)
        return observed


def _readiness_binding(state):
    control = state.control
    return {'context': asdict(control.context), 'return_sha256': binding._sha(control.raw_return),
        'evaluation_sha256': binding._sha(control.evaluation_bytes),
        'adjudication_sha256': binding._sha(control.record_bytes)}


def _readiness_errors(record, state):
    if type(record) is not dict or state is None:
        return ['Readiness needs the actual issued current source.']
    selected = binding._parse(state.record_bytes)
    if (record.get('current_source') != _readiness_binding(state)
            or record.get('accepted_findings') != list(state.findings)
            or record.get('rejected_findings') != [] or record.get('quarantined_findings') != []
            or record.get('evidence_refs') != selected['supporting_evidence']):
        return ['Readiness differs from the exact original current adjudication/support.']
    return []


def _readiness_plan(plan, state):
    try:
        raw = binding._json(plan)
        current = binding._parse(raw)
        _need(type(current) is dict, 'Original current readiness requires a plan object.')
        errors = readiness.validate_plan(current)
        errors.extend(_readiness_errors(current.get('adjudication_record'), state))
        return raw, current, errors
    except source._REFUSALS as exc:
        return None, None, ['Original current readiness refused: ' + str(exc)]


def _readiness_drift(plan, current, raw):
    if raw is None:
        return []
    try:
        if binding._json(current) != raw or binding._json(plan) != raw:
            return ['Readiness input changed during current evidence use.']
    except source._REFUSALS as exc:
        return ['Readiness input became unreadable during current evidence use: ' + str(exc)]
    return []


def _held_readiness(view, errors):
    original = view['original_evaluation']
    return dict(view, evaluation=original, resolved_findings=[], synthesis=None,
        remaining_holds=(original['hold_reasons'] if original else view['remaining_holds']),
        affected_accepted_for_use=False, errors=errors)


def current_readiness(plan, broker, permit, expected, *, affected_findings):
    """Run original planning validation plus one exact, one-use current evidence use.

    Historical validate_plan remains a structural planning reader. This result
    never authorizes execution, task-risk changes or successful closure.
    """
    state = (broker._issued.get(permit)
        if type(broker) is qualified.QualifiedAdjudicationBroker and type(permit) is qualified.EvidencePermit else None)
    plan_bytes, current_plan, errors = _readiness_plan(plan, state)
    # Always spend through the original consumer, including malformed-plan
    # refusals. A later valid plan cannot revive this attempted evidence use.
    result = use_evidence(broker, permit, expected, affected_findings=affected_findings)
    view = result.projection()
    errors.extend(_readiness_drift(plan, current_plan, plan_bytes))
    if not view['affected_accepted_for_use'] or view['remaining_holds']:
        errors.append('Original current evidence remains held or restricted.')
    errors.extend(view.get('errors', []))
    if errors:
        view = _held_readiness(view, errors)
    return {'errors': errors, 'current_evidence_ready': not errors, 'evidence': view,
            'execution_permitted': False, 'completion_permitted': False}
