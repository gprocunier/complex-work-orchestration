"""Host/control-owned task-risk bootstrap for the original router.

The host pins a finite registration table and control adapter before submission.
The adapter observes the designated task-risk adjudicator; original validators
check its evidence. No default production control or effect authority exists.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import prepare_risk_narrowing as narrowing
from qualified_adjudication import check_control_revocation
from cwo_core import adjudication_binding as binding
from cwo_core import adjudication_source as source
from cwo_core import policy, risk_features as risk
from cwo_core.routing import classify_work


@dataclass(frozen=True, eq=False)
class TaskRiskRegistration:
    """Host-owned independent declaration, never reconstructed from a request.

    reviewer_id identifies the control's designated adjudicator, not an asserted
    JSON role. This in-process registry is cooperative custody, not identity
    authentication. Construction alone neither validates evidence nor permits use.
    """
    task: narrowing.TaskExpectation
    receipt: source.SourceReceipt
    scope: narrowing.ScopeObservation
    support: tuple[binding.SupportObservation, ...]
    return_path: str
    adjudication_path: str
    adjudication_bytes: bytes
    disposition_path: str
    reviewer_id: str


@dataclass(frozen=True)
class TaskRiskDecision:
    """Observation from the pinned control; a serialized copy cannot register."""
    registration: TaskRiskRegistration
    raw: bytes


def _source_plan(root, registered):
    if type(registered) is not TaskRiskRegistration:
        raise ValueError('task-risk registration must be the actual host object')
    if (type(registered.receipt) is not source.SourceReceipt
            or type(registered.scope) is not narrowing.ScopeObservation
            or type(registered.adjudication_bytes) is not bytes):
        raise ValueError('task-risk registration requires original producer objects')
    task, receipt = registered.task, registered.receipt
    if type(task) is not narrowing.TaskExpectation or registered.scope.task != task:
        raise ValueError('registered task-risk scope differs from original task')
    # Production source dispatch must name ALL task fields, unlike legacy inert
    # preparation's compatible partial dispatches.
    dispatch = binding._parse(receipt.source.dispatch_bytes)
    for name, value in narrowing._task_record(task).items():
        if name != 'context' and dispatch.get(name) != value:
            raise ValueError('task-risk dispatch must bind the complete original task: ' + name)
    if binding.read_support(root, registered.return_path) != receipt.source.evaluation.raw_return:
        raise ValueError('task-risk actual return differs from original source')
    record_raw = binding.read_support(root, registered.adjudication_path)
    if record_raw != registered.adjudication_bytes:
        raise ValueError('original source adjudication changed')
    current = source.prepare_source(receipt.source, task.context, binding._parse(record_raw), root,
        observed_support=registered.support)
    if current != receipt:
        raise ValueError('current original source adjudication differs from registered receipt')
    result = narrowing.plan_offline(receipt, task, narrowing.record_for(registered.scope), root,
        observation=registered.scope, observed_support=registered.support)
    if result['source']['remaining_holds']:
        raise ValueError('remaining original source hold refuses task-risk qualification: '
            + ', '.join(result['source']['remaining_holds']))
    if not result['offline_plan_ready']:
        raise ValueError('original task-risk validators refused: ' + '; '.join(result['errors']))
    return result


def _policies():
    """Pin current router policy bytes and detect stale loader caches at use."""
    rows = []
    for path in sorted(policy.POLICY_DIR.glob('*.yaml')):
        raw = binding.read_support(policy.POLICY_DIR, path.name)
        parsed = binding._parse(raw)
        loaded = binding._policy_call(policy.load_policy, path.stem)
        if binding._json(parsed) != binding._json(loaded):
            raise ValueError('task-risk current policy differs from loader cache: ' + path.name)
        rows.append((path.name, raw))
    return tuple(rows)


def _basis(root, registered):
    plan = _source_plan(root, registered)
    scope = registered.scope
    if (type(registered.reviewer_id) is not str or not registered.reviewer_id.strip()
            or len(registered.reviewer_id) > 256):
        raise ValueError('host must independently designate a bounded task-risk adjudicator')
    return {'purpose': 'task-risk-narrowing', 'version': 1,
        'task': narrowing._task_record(registered.task),
        'original_assessment_sha256': binding._sha(registered.task.assessment_bytes),
        'source': narrowing._source_record(registered.receipt),
        'original_adjudication': {'path': registered.adjudication_path,
            'sha256': binding._sha(registered.adjudication_bytes)},
        'return_path': registered.return_path,
        'scope_evidence': {'path': scope.evidence_path, 'sha256': binding._sha(scope.evidence_bytes)},
        'documents': [{'path': name, 'sha256': binding._sha(raw)}
            for name, raw in zip(registered.task.paths, scope.document_bytes)],
        'support': narrowing._support_rows(scope.source_support),
        'resolutions': [{'feature_id': name, 'resolution': 'documentation-reference-only'}
            for name in plan['resolved_feature_ids']],
        'policies': [{'path': name, 'sha256': binding._sha(raw)} for name, raw in _policies()],
        'adjudicator': registered.reviewer_id,
        'role': 'task-risk-adjudicator', 'authority': 'registered-task-risk-scope-only'}


def produce_disposition(root, registered, *, decision, rationale):
    """Dedicated producer called by the designated control, not by task input.

    This is data until observed through that pinned control and validated again.
    Neither this producer nor a self-hash registers an accepting disposition.
    """
    if decision not in ('accepted', 'rejected', 'quarantined'):
        raise ValueError('unknown task-risk decision')
    if type(rationale) is not str or not rationale.strip() or len(rationale.encode()) > 4096:
        raise ValueError('task-risk decision requires a bounded rationale')
    before = _basis(root, registered)
    value = dict(before, decision=decision, rationale=rationale)
    if _basis(root, registered) != before:
        raise ValueError('task-risk evidence changed during disposition production')
    return binding._json(value)


def _validate(root, registered, observed):
    if type(observed) is not TaskRiskDecision or observed.registration is not registered:
        raise ValueError('task-risk disposition is not from the registered control/task')
    if type(observed.raw) is not bytes or len(observed.raw) > binding.MAX_SUPPORT_BYTES:
        raise ValueError('task-risk disposition needs bounded immutable original bytes')
    raw = binding.read_support(root, registered.disposition_path)
    if raw != observed.raw:
        raise ValueError('task-risk disposition is missing or changed since control observation')
    value = binding._parse(raw)
    expected = produce_disposition(root, registered, decision=value['decision'], rationale=value['rationale'])
    if binding._json(value) != expected or value['decision'] != 'accepted':
        raise ValueError('task-risk disposition is conflicting, restricted or not accepting')
    if binding.read_support(root, registered.disposition_path) != raw:
        raise ValueError('task-risk disposition changed during validation')
    return raw


def _requirements(original, narrowed):
    """Risk advice cannot discharge any original workflow or dispatch gate."""
    for name in ('evaluator_required', 'architect_adjudication_required', 'architect_review_required',
            'peer_review_required', 'sabotage_review_required', 'editor_gate_required',
            'blocking_review_required', 'blocking_review_waiver_required', 'provider_diversity_required',
            'zero_trust_consensus_required'):
        narrowed[name] = original[name] or narrowed[name]
    for name in ('hard_stops', 'guard_labels', 'editor_gate_added_experts', 'editor_gate_experts',
            'blocking_review_required_evidence', 'zero_trust_consensus_trigger_reasons'):
        narrowed[name] = list(dict.fromkeys((*original[name], *narrowed[name])))
    # These are independent execution/review projections, never task-risk grants.
    for name in ('operative_route', 'critic_route', 'peer_review_route'):
        narrowed[name] = original[name]
    narrowed['peer_review_count'] = max(original['peer_review_count'], narrowed['peer_review_count'])
    narrowed['zero_trust_minimum_independent_domains'] = max(
        original['zero_trust_minimum_independent_domains'], narrowed['zero_trust_minimum_independent_domains'])
    narrowed['zero_trust_policy_version'] = original['zero_trust_policy_version']
    return narrowed


class TaskRiskHost:
    """Finite bootstrap and one-use original caller, with terminal refusals.

    claim/observe are the control boundary. They are not accepting validators.
    Request data cannot supply a registry, callback, reviewer or producer. The
    embedding host must own these objects and the cooperative filesystem for
    this finite call; hostile host replacement is outside the custody claim.
    """

    def __init__(self, root: Path, registrations, control):
        self._root = root.absolute()
        self._registered = dict(registrations)
        self._control = control
        self._owner = object()
        self._seen = set()
        control.claim(self._owner)

    def plan(self, control_id):
        result = {'plan': None, 'errors': [], 'original_assessment': None,
            'effective_assessment': None, 'production_ready': False, 'effect_authority': False,
            'accepted_for_use': False, 'trusted_host_authority': False,
            'implementation_blocked': True, 'controlled_plan_ready': False}
        try:
            return self._plan(control_id, result)
        except narrowing._REFUSALS as exc:
            result['errors'].append(str(exc))
            result['effective_assessment'] = result['original_assessment']
            return result

    def _plan(self, control_id, result):
        if type(control_id) is not str or control_id in self._seen:
            raise ValueError('task-risk control identity is missing or already attempted')
        self._seen.add(control_id)  # A detected refusal cannot be retried after restoration.
        registered = self._registered[control_id]
        result['original_assessment'] = binding._parse(registered.task.assessment_bytes)
        result['effective_assessment'] = result['original_assessment']
        observed = self._control.observe(self._owner, control_id)
        initial = _validate(self._root, registered, observed)
        policies = _policies()
        failed = []

        def check():
            if failed:
                raise ValueError('task-risk refusal is terminal: ' + failed[0])
            try:
                current = self._control.observe(self._owner, control_id)
                if current != observed or _validate(self._root, registered, current) != initial:
                    raise ValueError('task-risk designated control changed during original caller use')
                if _policies() != policies:
                    raise ValueError('task-risk policy changed during original caller use')
                original = binding._parse(registered.task.assessment_bytes)
                effective = narrowing._effective(original, registered.scope.resolved_feature_ids)
                assessment = risk.RiskAssessment({row['feature']: list(row['terms'])
                    for row in effective['features']}, effective['floor'], effective['floor_reasons'],
                    effective['required_experts'], effective['assessed_segments'], effective['assessed_prefixes'])
                check_control_revocation(self._control)
                return assessment
            except narrowing._REFUSALS as exc:
                failed.append(str(exc))
                raise

        task = registered.task
        segments = (task.original_text, *task.append_segments)
        text = ''.join(segments)
        baseline = classify_work(text, text_segments=list(segments), file_paths=list(task.paths))
        check()  # The original caller is a callout too.
        use = risk._register_task_risk_use(check, text, segments, task.paths)
        try:
            plan = classify_work(text, text_segments=list(segments), file_paths=list(task.paths), risk_use=use)
            effective = check().as_record()
        finally:
            risk._remove_task_risk_use(use)
        plan = _requirements(baseline, plan)
        result.update(plan=plan, effective_assessment=effective, controlled_plan_ready=True)
        return result
