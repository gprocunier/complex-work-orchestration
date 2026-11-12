"""Offline task-bound source observations for reliability checks.

These cooperative snapshots retain evidence and never grant production authority.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, replace
from pathlib import Path
from typing import Any

from . import adjudication_binding as binding
from .adjudication import possible_refusals
from .errors import CWOError
from .synthesis_inputs import digest, malformed_hold_reasons, parse_decision

_REFUSALS = (CWOError, ValueError, OSError, KeyError, TypeError, AttributeError, RecursionError)
_RESTRICTIVE = ('rejected', 'quarantined')


@dataclass(frozen=True)
class SourceObservation:
    """Immutable local reliability evidence, with no authenticated custody."""
    dispatch_path: str
    dispatch_bytes: bytes
    evaluation: binding.EvaluationObservation
    provenance_bytes: bytes

    @property
    def context(self) -> binding.ExpectedContext:
        return self.evaluation.context

    @property
    def dispatch_sha256(self) -> str:
        return binding._sha(self.dispatch_bytes)


@dataclass(frozen=True)
class SourceReceipt:
    """One cooperative reliability snapshot of a source and its preparation."""
    source: SourceObservation
    prepared: binding.PreparedAdjudication
    binding_bytes: bytes


def _dispatch_provenance(raw, raw_return, expected, policy_bytes):
    return binding._dispatch_provenance(raw, raw_return, expected, policy_bytes)


def observe_source(root: Path, dispatch_path: str, raw_return: bytes,
                   expected: binding.ExpectedContext) -> SourceObservation:
    """Read one selected dispatch and observe the real evaluator for reliability."""
    if not isinstance(dispatch_path, str) or type(raw_return) is not bytes:
        raise ValueError('dispatch path and immutable return bytes are required for reliability')
    before = binding._policies()
    raw = binding.read_support(root, dispatch_path)
    provenance = _dispatch_provenance(raw, raw_return, expected, before)
    evaluation = binding.observe_evaluation(raw_return, expected)
    if evaluation.policy_bytes != before or binding._policies() != before:
        raise ValueError('applicable reliability policy changed during source observation')
    return SourceObservation(dispatch_path, raw, evaluation, provenance)


def _revalidate(source, expected, root):
    if source.context != expected:
        raise ValueError('source reliability context is stale')
    current = binding._policies()
    if source.evaluation.policy_bytes != current:
        raise ValueError('source reliability policy is stale')
    raw = binding.read_support(root, source.dispatch_path)
    if raw != source.dispatch_bytes:
        raise ValueError('selected dispatch reliability bytes changed')
    provenance = _dispatch_provenance(raw, source.evaluation.raw_return, expected, current)
    if provenance != source.provenance_bytes:
        raise ValueError('observed dispatch reliability provenance changed')
    if binding._policies() != current:
        raise ValueError('applicable reliability policy changed during source validation')


def _source_errors(source, expected, root):
    try:
        _revalidate(source, expected, root)
        return ()
    except _REFUSALS as exc:
        return (str(exc),)


def _receipt_bytes(source, prepared):
    """Bind the complete reliability state without claiming authentication."""
    state = asdict(prepared)
    for name in ('evaluation_bytes', 'policy_bytes'):
        state[name] = binding._sha(state[name])
    state['support_bytes'] = [binding._sha(raw) for raw in prepared.support_bytes]
    return binding._json({'dispatch_path': source.dispatch_path,
        'dispatch_sha256': source.dispatch_sha256, 'context': asdict(source.context),
        'return_sha256': source.evaluation.return_sha256,
        'evaluation_sha256': source.evaluation.evaluation_sha256,
        'policy_sha256': binding._sha(source.evaluation.policy_bytes),
        'provenance_sha256': binding._sha(source.provenance_bytes), 'prepared': state})


def _invalidate_preparation(prepared, observation, record, errors):
    restrictions = tuple(dict.fromkeys((*prepared.adjudication_restrictions,
        *possible_refusals(parse_decision(record)))))
    return replace(prepared, errors=tuple(dict.fromkeys(errors)), resolved_findings=(),
        remaining_holds=tuple(binding._parse(observation.result_bytes)['hold_reasons']),
        decision=(prepared.decision if prepared.decision in _RESTRICTIVE
                  else _restrictive_decision(record)),
        adjudication_restrictions=restrictions)


def _record_snapshot(record):
    try:
        return binding._parse(binding._json(record)), ()
    except _REFUSALS as exc:
        return None, ('adjudication reliability snapshot refused: ' + str(exc),)


def prepare_source(source: SourceObservation, expected: binding.ExpectedContext, record: Any,
                   root: Path, *, observed_support: tuple[binding.SupportObservation, ...] = ()) -> SourceReceipt:
    """Prepare shared reliability state and preserve every refusal on source errors."""
    source_errors = _source_errors(source, expected, root)
    local_record, snapshot_errors = _record_snapshot(record)
    dispatch = binding.DispatchObservation(source.dispatch_path, source.dispatch_bytes,
        source.evaluation, source.provenance_bytes)
    prepared = binding.prepare_adjudication(source.evaluation, expected, local_record, root,
        observed_support=observed_support, observed_dispatch=dispatch)
    errors = (*source_errors, *snapshot_errors, *prepared.errors,
              *_source_errors(source, expected, root))
    if errors:
        prepared = _invalidate_preparation(prepared, source.evaluation, local_record, errors)
    return SourceReceipt(source, prepared, _receipt_bytes(source, prepared))


def _object_bytes(raw):
    if type(raw) is not bytes:
        raise ValueError('immutable reliability snapshot bytes are required')
    value = binding._parse(raw)
    binding._json(value)
    if type(value) is not dict:
        raise ValueError('reliability snapshot must be an object')
    return value


def _evaluation_result(raw):
    result = _object_bytes(raw)
    if malformed_hold_reasons(result.get('hold_reasons')):
        raise ValueError('original evaluation reliability holds are malformed')
    for name in ('implementation_blocked', 'accepted_for_use'):
        if type(result.get(name)) is not bool:
            raise ValueError('original evaluation reliability flags are malformed')
    if not isinstance(result.get('verdict'), str) or not result['verdict'].strip():
        raise ValueError('original evaluation reliability verdict is malformed')
    if bool(result['hold_reasons']) != result['implementation_blocked']:
        raise ValueError('original evaluation reliability holds and flag disagree')
    return result


def _evaluation_candidates(receipt):
    if type(receipt) is not SourceReceipt:
        return ()
    candidates = []
    source = getattr(receipt, 'source', None)
    if type(source) is SourceObservation:
        observation = getattr(source, 'evaluation', None)
        if type(observation) is binding.EvaluationObservation:
            candidates.append(getattr(observation, 'result_bytes', None))
    prepared = getattr(receipt, 'prepared', None)
    if type(prepared) is binding.PreparedAdjudication:
        candidates.append(getattr(prepared, 'evaluation_bytes', None))
    return candidates


def _original_evaluation(receipt, retained):
    state = retained['prepared']
    binding.ExpectedContext(**retained['context'])
    if type(state) is not dict:
        raise ValueError('original reliability context is unresolved')
    for name, field in (('return_sha256', 'return_sha256'),
            ('evaluation_sha256', 'evaluation_bytes'), ('policy_sha256', 'policy_bytes')):
        if digest(retained.get(name)) is None or state.get(field) != retained[name]:
            raise ValueError('original reliability binding is unresolved: ' + name)
    for raw in _evaluation_candidates(receipt):
        if type(raw) is bytes and binding._sha(raw) == retained['evaluation_sha256']:
            return _evaluation_result(raw)
    raise ValueError('original reliability evaluation bytes are unavailable')


def _receipt_parts(receipt):
    if type(receipt) is not SourceReceipt:
        raise ValueError('a reliability source receipt is required')
    source, prepared = receipt.source, receipt.prepared
    for value, kind in ((source, SourceObservation), (prepared, binding.PreparedAdjudication)):
        if type(value) is not kind:
            raise ValueError('reliability receipt state has the wrong type')
    if type(source.evaluation) is not binding.EvaluationObservation:
        raise ValueError('reliability evaluation observation has the wrong type')
    return source, prepared


def _prepared_sequences(prepared):
    for name, kind in (('errors', str), ('resolved_findings', str), ('remaining_holds', str),
            ('support_bytes', bytes), ('adjudication_restrictions', str)):
        values = getattr(prepared, name)
        if type(values) is not tuple or any(type(value) is not kind for value in values):
            raise ValueError('prepared reliability sequence is malformed: ' + name)
    if any(value not in _RESTRICTIVE for value in prepared.adjudication_restrictions):
        raise ValueError('prepared reliability restrictions are malformed')


def _snapshot_types(source, prepared):
    for context in (source.context, prepared.context):
        if type(context) is not binding.ExpectedContext:
            raise ValueError('reliability snapshot context has the wrong type')
    for raw in (source.dispatch_bytes, source.provenance_bytes, source.evaluation.raw_return,
            source.evaluation.result_bytes, source.evaluation.policy_bytes,
            prepared.evaluation_bytes, prepared.policy_bytes):
        if type(raw) is not bytes:
            raise ValueError('reliability snapshot evidence must be immutable bytes')
    _prepared_sequences(prepared)


def _receipt_errors(receipt, expected, root):
    errors = ()
    try:
        source, prepared = _receipt_parts(receipt)
        if type(expected) is not binding.ExpectedContext:
            raise ValueError('an independent reliability context is required')
        _snapshot_types(source, prepared)
        errors = _source_errors(source, expected, root)
        observation = source.evaluation
        if (prepared.context, prepared.return_sha256, prepared.evaluation_bytes, prepared.policy_bytes) != (
                observation.context, observation.return_sha256, observation.result_bytes, observation.policy_bytes):
            raise ValueError('receipt reliability state differs from its original evaluation')
        if receipt.binding_bytes != _receipt_bytes(source, prepared):
            raise ValueError('receipt reliability binding changed')
        errors = (*errors, *prepared.errors)
    except _REFUSALS as exc:
        errors = (*errors, 'source reliability validation refused: ' + str(exc))
    return errors


def _state_refusals(state):
    refusals = possible_refusals(parse_decision(state))
    restrictions = state.get('adjudication_restrictions')
    if type(restrictions) not in (list, tuple):
        return (*refusals, *_RESTRICTIVE)
    if any(type(value) is not str or value not in _RESTRICTIVE for value in restrictions):
        return (*refusals, *_RESTRICTIVE)
    return (*refusals, *restrictions)


def _restriction_states(receipt, retained):
    original = retained.get('prepared')
    original = original if type(original) is dict else {}
    prepared = getattr(receipt, 'prepared', None) if type(receipt) is SourceReceipt else None
    current = {}
    if type(prepared) is binding.PreparedAdjudication:
        current = {'decision': getattr(prepared, 'decision', None),
            'adjudication_restrictions': getattr(prepared, 'adjudication_restrictions', None)}
    return original, current


def _restrictive_decision(state):
    decision = parse_decision(state)
    return decision.value if decision.valid and decision.value in _RESTRICTIVE else None


def _invalid_restrictions(receipt, retained):
    original, current = _restriction_states(receipt, retained)
    restrictions = tuple(dict.fromkeys((*_state_refusals(original), *_state_refusals(current))))
    return _restrictive_decision(original) or _restrictive_decision(current), restrictions


def _dispatch_view(receipt):
    source = getattr(receipt, 'source', None) if type(receipt) is SourceReceipt else None
    if type(source) is not SourceObservation:
        return None, None
    path = getattr(source, 'dispatch_path', None)
    raw = getattr(source, 'dispatch_bytes', None)
    return path if type(path) is str else None, binding._sha(raw) if type(raw) is bytes else None


def _invalid_projection(receipt, retained, evaluation, errors):
    decision, restrictions = _invalid_restrictions(receipt, retained)
    if evaluation is None:
        restrictions = tuple(dict.fromkeys((*restrictions, *_RESTRICTIVE)))
    path, dispatch_sha256 = _dispatch_view(receipt)
    metadata = retained if evaluation is not None else {}
    holds = evaluation['hold_reasons'] if evaluation is not None else ['source-reliability-evaluation-unresolved']
    return {'scope': 'inert-preparation-only', 'source_valid': False, 'inert_valid': False,
        'context': metadata.get('context'), 'return_sha256': metadata.get('return_sha256'),
        'evaluation_sha256': metadata.get('evaluation_sha256'), 'policy_sha256': metadata.get('policy_sha256'),
        'support_sha256': [], 'evaluation': evaluation, 'decision': decision,
        'adjudication_restrictions': list(restrictions), 'resolved_findings': [],
        'remaining_holds': list(holds), 'errors': list(dict.fromkeys(errors)),
        'dispatch_path': path, 'dispatch_sha256': dispatch_sha256, 'provenance': None,
        'production_blockers': list(binding.MISSING_PRODUCTION), 'production_ready': False,
        'accepted_for_use': False, 'implementation_blocked': True, 'trusted_host_authority': False}


def _source_projection(receipt, expected, evaluation):
    prepared = receipt.prepared
    result = binding.synthesis_preparation(prepared, expected)
    if type(result) is not dict:
        raise ValueError('source reliability projection must be an object')
    checks = {'scope': 'inert-preparation-only', 'context': asdict(prepared.context),
        'return_sha256': prepared.return_sha256, 'evaluation_sha256': binding._sha(prepared.evaluation_bytes),
        'policy_sha256': binding._sha(prepared.policy_bytes),
        'support_sha256': [binding._sha(raw) for raw in prepared.support_bytes],
        'evaluation': evaluation, 'decision': prepared.decision,
        'adjudication_restrictions': list(prepared.adjudication_restrictions),
        'resolved_findings': list(prepared.resolved_findings), 'remaining_holds': list(prepared.remaining_holds),
        'production_blockers': list(binding.MISSING_PRODUCTION)}
    for name, value in checks.items():
        if result[name] != value:
            raise ValueError('source reliability projection changed: ' + name)
    if result['inert_valid'] is not True or type(result['errors']) is not list or result['errors']:
        raise ValueError('source reliability projection is invalid')
    if not parse_decision(result).valid:
        raise ValueError('source reliability projection decision is unresolved')
    return result


def consume_source(receipt: SourceReceipt, expected: binding.ExpectedContext, root: Path) -> dict[str, Any]:
    """Project valid cooperative reliability state or retain unresolved evidence and refusals."""
    retained, evaluation, errors = {}, None, ()
    try:
        if type(receipt) is not SourceReceipt:
            raise ValueError('a reliability source receipt is required')
        retained = _object_bytes(receipt.binding_bytes)
        evaluation = _original_evaluation(receipt, retained)
    except _REFUSALS as exc:
        errors = ('original reliability evidence is unresolved: ' + str(exc),)
    errors = (*errors, *_receipt_errors(receipt, expected, root))
    if not errors:
        try:
            result = _source_projection(receipt, expected, evaluation)
            provenance = _object_bytes(receipt.source.provenance_bytes)
            if provenance.get('known') is not True:
                raise ValueError('source reliability provenance is unresolved')
            path, dispatch_sha256 = _dispatch_view(receipt)
            result.update(source_valid=True, dispatch_path=path, dispatch_sha256=dispatch_sha256,
                provenance=provenance, production_ready=False, accepted_for_use=False,
                implementation_blocked=True, trusted_host_authority=False)
            return result
        except _REFUSALS as exc:
            errors = ('source reliability projection refused: ' + str(exc),)
    return _invalid_projection(receipt, retained, evaluation, errors)
