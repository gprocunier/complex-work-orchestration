"""Offline structured risk narrowing from cooperative reliability evidence.

This adapter grants no production or effect authority.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from cwo_core import adjudication_binding as binding
from cwo_core import adjudication_source as source
from cwo_core import policy, risk_features as risk
from cwo_core.routing import ensure_risk_feature_experts
from cwo_core.errors import CWOError
from cwo_core.path_contract import path_components

_REFUSALS = (CWOError, ValueError, OSError, KeyError, TypeError, AttributeError,
             RecursionError, SystemExit)
_RESOLVABLE = frozenset({'environment:production'})
_MAX_SEGMENTS = 64
_MAX_EVIDENCE_PATH = 4096
_MAX_FEATURE_ID = 128
_MAX_DESCRIPTOR_BYTES = 64 * 1024
_DESCRIPTOR_FIELDS = frozenset({'record_type', 'version', 'evidence_path',
    'evidence_sha256', 'source_binding_sha256', 'resolved_feature_ids'})


def _risk_policy() -> bytes:
    """Check exact current reliability policy bytes and both existing caches."""
    raw = binding.read_support(policy.POLICY_DIR, 'risk-features.yaml')
    value = binding._parse(raw)
    canonical = binding._json(value)
    binding._policy_call(policy.validate_policy_document, 'risk-features.yaml', value)
    loaded = binding._json(binding._policy_call(policy.load_policy, 'risk-features'))
    assessed = binding._json(binding._policy_call(risk._policy))
    if canonical != loaded or canonical != assessed:
        raise ValueError('risk reliability policy cache differs from current bytes')
    return raw


def _paths(paths):
    if type(paths) is not tuple or not 1 <= len(paths) <= binding.MAX_SUPPORT_FILES:
        raise ValueError('risk reliability paths need a bounded nonempty tuple')
    for name in paths:
        parts = path_components(name) if isinstance(name, str) else None
        if not parts or '/'.join(parts) != name:
            raise ValueError('risk reliability path must be canonical and relative')
    if len(set(paths)) != len(paths):
        raise ValueError('risk reliability paths are ambiguous')


def _task_record(task):
    return {'context': asdict(task.context), 'original_text': task.original_text,
        'append_segments': list(task.append_segments), 'action': task.action,
        'paths': list(task.paths), 'environment': task.environment}


@dataclass(frozen=True)
class TaskExpectation:
    """Declare independent task scope before evidence or submission is authored.

    Strings retain exact text; append_segments contains only ordered appends.
    Paths are concrete relative files. This cooperative declaration is not
    authenticated custody. Construction snapshots the real retained assessment.
    """
    context: binding.ExpectedContext
    original_text: str
    action: str
    paths: tuple[str, ...]
    environment: str
    append_segments: tuple[str, ...] = ()
    policy_bytes: bytes = field(init=False, repr=False)
    assessment_bytes: bytes = field(init=False, repr=False)

    def __post_init__(self):
        if type(self.context) is not binding.ExpectedContext:
            raise ValueError('risk reliability context needs ExpectedContext')
        strings = (self.original_text, self.action, self.environment)
        if any(type(value) is not str or not value.strip() for value in strings):
            raise ValueError('risk reliability task fields need nonblank strings')
        if (type(self.append_segments) is not tuple or len(self.append_segments) > _MAX_SEGMENTS
                or any(type(value) is not str for value in self.append_segments)):
            raise ValueError('risk reliability appends need a bounded string tuple')
        for text in (self.original_text, *self.append_segments):
            text.encode('utf-8')
        _paths(self.paths)
        if len(binding._json(_task_record(self))) > binding.MAX_SUPPORT_BYTES:
            raise ValueError('risk reliability task exceeds the byte bound')
        before = _risk_policy()
        segments = [self.original_text, *self.append_segments]
        assessed = risk.assess_risk_features(''.join(segments), segments=segments)
        assessment = binding._json(assessed.as_record())
        if _risk_policy() != before:
            raise ValueError('risk reliability policy changed during assessment')
        object.__setattr__(self, 'policy_bytes', before)
        object.__setattr__(self, 'assessment_bytes', assessment)


def _current_task(task):
    current = TaskExpectation(task.context, task.original_text, task.action,
        task.paths, task.environment, task.append_segments)
    if current != task:
        raise ValueError('risk reliability task assessment or policy is stale')


def _supported(task):
    if task.action != 'documentation-edit' or task.environment != 'offline':
        raise ValueError('unsupported risk scope: requires documentation-edit in offline environment')
    if not all(name == 'README.md' or (name.startswith('docs/') and name.endswith('.md'))
               for name in task.paths):
        raise ValueError('unsupported risk paths: requires README.md or Markdown files below docs/')


def _resolution_ids(task, ids):
    if (type(ids) is not tuple or not 1 <= len(ids) <= binding.MAX_SUPPORT_FILES
            or any(type(name) is not str for name in ids) or len(set(ids)) != len(ids)):
        raise ValueError('risk resolution IDs are empty, malformed or ambiguous')
    known = set(binding._parse(task.policy_bytes)['features'])
    retained = {row['feature'] for row in binding._parse(task.assessment_bytes)['features']}
    if not set(ids) <= known:
        raise ValueError('unknown risk feature IDs')
    if not set(ids) <= retained:
        raise ValueError('risk resolution IDs are not prior retained features')
    if not set(ids) <= _RESOLVABLE:
        raise ValueError('unsupported risk reduction rows: ' + ', '.join(sorted(set(ids) - _RESOLVABLE)))


def _accepting(view):
    if (view['source_valid'] is not True or view['decision'] != 'accepted'
            or view['adjudication_restrictions'] != []):
        raise ValueError('risk reliability source needs valid accepting adjudication without restrictions')


def _retained_source(previous, current):
    if previous is None or previous['source_valid'] is True:
        return current
    retained = dict(previous if current['source_valid'] is True else current)
    for name in ('errors', 'adjudication_restrictions', 'remaining_holds'):
        retained[name] = list(dict.fromkeys((*previous[name], *current[name])))
    if current['decision'] in ('rejected', 'quarantined'):
        retained['decision'] = current['decision']
    elif retained['decision'] is None:
        retained['decision'] = previous['decision']
    return retained


@dataclass
class _SourceChecks:
    """Retain actual source reliability checks across observation boundaries."""
    receipt: source.SourceReceipt
    task: TaskExpectation
    root: Path
    latest: dict[str, Any] | None = field(default=None, init=False)

    def refresh(self):
        current = source.consume_source(self.receipt, self.task.context, self.root)
        self.latest = _retained_source(self.latest, current)
        return self.latest

    def require(self):
        _accepting(self.refresh())


def _finish_source(result, checks):
    try:
        checks.require()
    except _REFUSALS as exc:
        result['errors'].append(str(exc))
    result['source'] = checks.latest
    result['errors'] = list(dict.fromkeys((*result['errors'], *checks.latest['errors'])))


def _dispatch_scope(receipt, task):
    dispatch = binding._parse(receipt.source.dispatch_bytes)
    expected = _task_record(task)
    for name in ('action', 'paths', 'environment', 'original_text', 'append_segments'):
        if name in dispatch and binding._json(dispatch[name]) != binding._json(expected[name]):
            raise ValueError('actual dispatch conflicts with independent risk task: ' + name)


def _source_record(receipt):
    observed = receipt.source
    return {'binding_sha256': binding._sha(receipt.binding_bytes),
        'dispatch_path': observed.dispatch_path, 'dispatch_sha256': observed.dispatch_sha256,
        'return_sha256': observed.evaluation.return_sha256,
        'evaluation_sha256': observed.evaluation.evaluation_sha256,
        'evaluation_policy_sha256': binding._sha(observed.evaluation.policy_bytes),
        'candidate': observed.context.candidate,
        'provenance_sha256': binding._sha(observed.provenance_bytes)}


def _state(root, receipt, task, ids, checks, observed_support=()):
    try:
        checks.require()
        _current_task(task)
        _supported(task)
        _resolution_ids(task, ids)
        _dispatch_scope(receipt, task)
        documents = tuple(binding.read_support(root, name) for name in task.paths)
        value = {'kind': 'cwo-offline-scope-evidence-v1', 'task': _task_record(task),
            'source': _source_record(receipt), 'risk_policy_sha256': binding._sha(task.policy_bytes),
            'original_assessment_sha256': binding._sha(task.assessment_bytes),
            'documents': [{'path': name, 'sha256': binding._sha(raw)}
                for name, raw in zip(task.paths, documents)],
            'resolutions': [{'feature_id': name, 'resolution': 'documentation-reference-only',
                'paths': list(task.paths)} for name in ids]}
        if observed_support != ():
            value['source_support'] = _support_rows(_bound_support(root, receipt, observed_support))
        if documents != tuple(binding.read_support(root, name) for name in task.paths):
            raise ValueError('risk supporting document bytes changed during observation')
        _current_task(task)
    finally:
        checks.refresh()
    _accepting(checks.latest)
    return value, documents


def scope_evidence(root: Path, receipt: source.SourceReceipt, task: TaskExpectation,
                   resolved_feature_ids: tuple[str, ...], *,
                   observed_support: tuple[binding.SupportObservation, ...] = ()) -> dict[str, Any]:
    """Produce bounded fixture evidence from actual files and independent scope.

    The fixture writes this value to its independently selected evidence path.
    This records cooperative observations; it does not authenticate scope.
    """
    checks = _SourceChecks(receipt, task, root)
    return _state(root, receipt, task, resolved_feature_ids, checks, observed_support)[0]


@dataclass(frozen=True)
class ScopeObservation:
    """Immutable scope reliability snapshot, with no custody authentication."""
    task: TaskExpectation
    source_binding_bytes: bytes
    evidence_path: str
    evidence_bytes: bytes
    document_bytes: tuple[bytes, ...]
    resolved_feature_ids: tuple[str, ...]
    source_support: tuple[binding.SupportObservation, ...] = ()

    def __post_init__(self):
        _paths((self.evidence_path,))
        if (type(self.task) is not TaskExpectation or type(self.source_binding_bytes) is not bytes
                or type(self.evidence_bytes) is not bytes or type(self.document_bytes) is not tuple
                or any(type(raw) is not bytes for raw in self.document_bytes)):
            raise ValueError('risk scope reliability snapshots must be immutable')
        _resolution_ids(self.task, self.resolved_feature_ids)
        if self.source_support != _support_observations(self.source_support):
            raise ValueError('risk source support mapping must be canonical and immutable')


def _observed_ids(value):
    rows = value['resolutions']
    if type(rows) is not list or not 1 <= len(rows) <= binding.MAX_SUPPORT_FILES:
        raise ValueError('risk evidence resolution rows are empty or malformed')
    return tuple(row['feature_id'] for row in rows)


def observe_scope(root: Path, evidence_path: str, receipt: source.SourceReceipt,
                  task: TaskExpectation, *,
                  observed_support: tuple[binding.SupportObservation, ...] = ()) -> ScopeObservation:
    """Observe one independently selected relative evidence file for this task.

    receipt must be the actual adjudication receipt; task is an independently declared
    expectation, never scope inferred from caller flags or submitted prose.
    Bounded reads cover the evidence and every affected supporting document.
    Errors raise a reliability refusal; no observation is returned on failure.
    """
    return _observe_scope(root, evidence_path, receipt, task,
        _SourceChecks(receipt, task, root), observed_support)


def _observe_scope(root, evidence_path, receipt, task, checks, observed_support=()):
    try:
        checks.require()
        _paths((evidence_path,))
        raw = binding.read_support(root, evidence_path)
        value = binding._parse(raw)
        binding._json(value)
        ids = _observed_ids(value)
        expected, documents = _state(root, receipt, task, ids, checks, observed_support)
        if binding._json(value) != binding._json(expected):
            raise ValueError('risk evidence does not cover the exact source, task, scope and resolution rows')
        if binding.read_support(root, evidence_path) != raw:
            raise ValueError('risk evidence bytes changed during observation')
        _current_task(task)
    finally:
        checks.refresh()
    _accepting(checks.latest)
    return ScopeObservation(task, receipt.binding_bytes, evidence_path, raw, documents, ids,
        _support_observations(observed_support))


def record_for(observation: ScopeObservation) -> dict[str, Any]:
    """Build the submitted descriptor after independent scope observation."""
    return {'record_type': 'cwo-offline-risk-narrowing', 'version': 1,
        'evidence_path': observation.evidence_path,
        'evidence_sha256': binding._sha(observation.evidence_bytes),
        'source_binding_sha256': binding._sha(observation.source_binding_bytes),
        'resolved_feature_ids': list(observation.resolved_feature_ids)}


def _current_observation(root, receipt, task, observation, checks):
    if type(observation) is not ScopeObservation:
        raise ValueError('independent risk scope reliability observation is required')
    current = _observe_scope(root, observation.evidence_path, receipt, task, checks,
        observation.source_support)
    if observation != current:
        raise ValueError('saved risk scope reliability observation is stale')
    return current


def _bounded_string(value, limit):
    return type(value) is str and 1 <= len(value) <= limit


def _descriptor_strings(record):
    if not _bounded_string(record['evidence_path'], _MAX_EVIDENCE_PATH):
        raise ValueError('risk reliability evidence path exceeds its string bound')
    for name in ('evidence_sha256', 'source_binding_sha256'):
        value = record[name]
        if (not _bounded_string(value, 64) or len(value) != 64
                or any(char not in '0123456789abcdef' for char in value)):
            raise ValueError('risk reliability descriptor digest is malformed')
    _paths((record['evidence_path'],))


def _descriptor_ids(ids):
    if type(ids) is not list or not 1 <= len(ids) <= binding.MAX_SUPPORT_FILES:
        raise ValueError('risk reliability descriptor IDs exceed the list bound')
    local = list(ids)
    if (any(not _bounded_string(name, _MAX_FEATURE_ID) for name in local)
            or len(set(local)) != len(local)):
        raise ValueError('risk reliability descriptor IDs are malformed or ambiguous')
    return local


def _descriptor_shape(record):
    if type(record) is not dict or len(record) != len(_DESCRIPTOR_FIELDS):
        raise ValueError('risk reliability descriptor needs the closed field set')
    if any(type(name) is not str for name in record) or set(record) != _DESCRIPTOR_FIELDS:
        raise ValueError('risk reliability descriptor contains unknown fields')
    local = dict(record)
    if type(local['record_type']) is not str or local['record_type'] != 'cwo-offline-risk-narrowing':
        raise ValueError('risk reliability descriptor type is malformed')
    if type(local['version']) is not int or local['version'] != 1:
        raise ValueError('risk reliability descriptor version needs integer 1')
    _descriptor_strings(local)
    local['resolved_feature_ids'] = _descriptor_ids(local['resolved_feature_ids'])
    return local


def _snapshot_descriptor(record):
    local = _descriptor_shape(record)
    raw = binding._json(local)
    if len(raw) > _MAX_DESCRIPTOR_BYTES:
        raise ValueError('risk reliability descriptor snapshot exceeds its byte bound')
    return binding._parse(raw)


def _effective(original, ids):
    features = {row['feature']: list(row['terms']) for row in original['features']
                if row['feature'] not in ids}
    floor, reasons, experts = risk._floor(list(features))
    return risk.RiskAssessment(features, floor, reasons, experts,
        original['assessed_segments'], original['assessed_prefixes']).as_record()


def prepare(receipt: source.SourceReceipt, task: TaskExpectation, record: Any,
            root: Path, *, observation: ScopeObservation | None = None) -> dict[str, Any]:
    """Prepare an offline view, rechecking saved scope against current inputs.

    task must be the independent TaskExpectation, including exact original text,
    ordered appends and actual structured scope. record is untrusted JSON data.
    observation must come from observe_scope; a descriptor or hash cannot
    replace it. A changed expectation needs fresh evidence and observation.
    Every refusal retains the original assessment and prevents narrowed use.
    """
    original = binding._parse(task.assessment_bytes)
    result = {'scope': 'offline-risk-narrowing-only', 'narrowing_valid': False,
        'original_assessment': original,
        'effective_assessment': binding._parse(task.assessment_bytes),
        'resolved_feature_ids': [], 'unresolved_feature_ids': [row['feature'] for row in original['features']],
        'source': None, 'errors': [], 'evidence_sha256': None,
        'production_ready': False, 'effect_authority': False, 'accepted_for_use': False,
        'trusted_host_authority': False, 'implementation_blocked': True}
    checks = _SourceChecks(receipt, task, root)
    try:
        checks.require()
        local_record = _snapshot_descriptor(record)
        _current_task(task)
        _dispatch_scope(receipt, task)
        current = _current_observation(root, receipt, task, observation, checks)
        if binding._json(local_record) != binding._json(record_for(current)):
            raise ValueError('risk submission does not match the exact observed descriptor')
        effective = _effective(original, current.resolved_feature_ids)
        if _observe_scope(root, current.evidence_path, receipt, task, checks,
                          current.source_support) != current:
            raise ValueError('risk scope changed during preparation')
        _current_task(task)
    except _REFUSALS as exc:
        result['errors'] = [str(exc)]
    finally:
        _finish_source(result, checks)
    if not result['errors']:
        result.update(narrowing_valid=True, effective_assessment=effective,
            resolved_feature_ids=list(current.resolved_feature_ids),
            unresolved_feature_ids=[row['feature'] for row in effective['features']],
            evidence_sha256=binding._sha(current.evidence_bytes))
    return result


def _support_observations(observed_support):
    """Canonical identity order, independent of the adjudication evidence record order."""
    if (type(observed_support) is not tuple
            or len(observed_support) > binding.MAX_SUPPORT_FILES
            or any(type(item) is not binding.SupportObservation for item in observed_support)):
        raise ValueError('independent original adjudication support observations are required')
    canonical = []
    for item in observed_support:
        parts = path_components(item.artifact)
        if not parts or type(item.raw) is not bytes or type(item.finding_id) is not str:
            raise ValueError('original adjudication support observation is malformed')
        canonical.append(binding.SupportObservation('/'.join(parts), item.finding_id, item.raw))
    if canonical:
        _paths(tuple(item.artifact for item in canonical))
    return tuple(sorted(canonical, key=lambda item: item.artifact))


def _support_rows(observed_support):
    return [{'artifact': item.artifact, 'finding_id': item.finding_id,
             'sha256': binding._sha(item.raw)} for item in observed_support]


def _bound_support(root, receipt, observed_support):
    observed = _support_observations(observed_support)
    items = [{'artifact': item.artifact, 'finding_ids': [item.finding_id],
              'sha256': binding._sha(item.raw)} for item in observed]
    raw = binding._supports({'supporting_evidence': items}, receipt.source.evaluation, observed, root)
    if Counter(raw) != Counter(receipt.prepared.support_bytes):
        raise ValueError('support observations differ from the original adjudication preparation')
    return observed


def _current_support(receipt, root, observed_support, observation):
    observed = _support_observations(observed_support)
    if not observed or observed != observation.source_support:
        raise ValueError('original adjudication artifact/finding mapping differs from the bound scope observation')
    _bound_support(root, receipt, observed)


def _original_vetoes(view):
    evaluation = view['evaluation']
    if any(evaluation.get(name) in ('reject', 'rejected', 'quarantine', 'quarantined')
           for name in ('verdict', 'disposition')):
        raise ValueError('original evaluation rejection or quarantine refuses offline risk planning')
    if any(evaluation.get(name) == 'boundary-tainted'
           for name in ('boundary_taint_status', 'boundary_status', 'share_boundary_status')):
        raise ValueError('original evaluation boundary restriction refuses offline risk planning')


def _planning_registry():
    raw = binding.read_support(policy.POLICY_DIR, 'expert-registry.yaml')
    registry = binding._parse(raw)
    binding._policy_call(policy.validate_policy_document, 'expert-registry.yaml', registry)
    cached = binding._policy_call(policy.load_policy, 'expert-registry')
    if binding._json(registry) != binding._json(cached):
        raise ValueError('expert registry cache differs from current bytes')
    return raw, registry


def _risk_plan(task, effective, registry):
    """Use the original risk-feature expert selection and risk aggregation."""
    assessment = risk.RiskAssessment(
        {row['feature']: list(row['terms']) for row in effective['features']},
        effective['floor'], effective['floor_reasons'], effective['required_experts'],
        effective['assessed_segments'], effective['assessed_prefixes'])
    experts, unmet = ensure_risk_feature_experts([], registry, assessment)
    if unmet:
        raise ValueError('required risk experts are absent from the current registry')
    expert_risk = policy.rank_max([expert['default_risk'] for expert in experts],
        policy.RISK_ORDER, 'low')
    return {'action': task.action, 'paths': list(task.paths), 'environment': task.environment,
        'risk': policy.rank_max([expert_risk, assessment.floor or 'low'], policy.RISK_ORDER, 'low'),
        'required_experts': experts, 'risk_assessment': assessment.as_record()}


def _without_plan(result):
    result.update(narrowing_valid=False, effective_assessment=result['original_assessment'],
        resolved_feature_ids=[], evidence_sha256=None,
        unresolved_feature_ids=[row['feature'] for row in result['original_assessment']['features']])


def plan_offline(receipt: source.SourceReceipt, task: TaskExpectation, record: Any,
                 root: Path, *, observation: ScopeObservation | None = None,
                 observed_support: tuple[binding.SupportObservation, ...] = ()) -> dict[str, Any]:
    """Return one current offline risk-feature plan, never a route or effect grant.

    Consume original producers, not a caller's saved accepting projection. Reread
    support and reprepare immediately before returning the calculated plan. This
    stateless planner may be called again for the same unchanged independent task;
    a descriptor replayed for another task cannot supply that task's observation.
    """
    if type(task) is not TaskExpectation:
        raise ValueError('an independent TaskExpectation is required for offline risk planning')
    result = prepare(receipt, task, record, root, observation=observation)
    initial = dict(result)
    result.update(consumer_scope='offline-risk-feature-plan-only', offline_plan_ready=False, plan=None)
    checks = _SourceChecks(receipt, task, root)
    checks.latest = result['source']
    try:
        if result['errors']:
            raise ValueError('risk preparation refused offline planning')
        _original_vetoes(result['source'])
        registry_bytes, registry = _planning_registry()
        _current_support(receipt, root, observed_support, observation)
        plan = _risk_plan(task, result['effective_assessment'], registry)
        current = prepare(receipt, task, record, root, observation=observation)
        checks.latest = _retained_source(checks.latest, current['source'])
        if current != initial:
            result['errors'].extend(current['errors'])
            raise ValueError('risk bindings changed before the offline plan could be returned')
        _current_support(receipt, root, observed_support, observation)
        if _planning_registry()[0] != registry_bytes:
            raise ValueError('expert registry changed during offline risk planning')
    except _REFUSALS as exc:
        result['errors'].append(str(exc))
    finally:
        _finish_source(result, checks)
    if result['errors']:
        _without_plan(result)
    else:
        result.update(offline_plan_ready=True, plan=plan)
    return result
