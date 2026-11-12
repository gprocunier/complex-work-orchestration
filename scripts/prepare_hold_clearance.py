"""Historical inert hold-clearance checks and the explicit registered evidence-use entry."""
from __future__ import annotations

from dataclasses import asdict, dataclass, replace
from pathlib import Path
from typing import Callable

from cwo_core import adjudication_binding as binding
from cwo_core import adjudication_source as source
from cwo_core.errors import CWOError
from evidence_use import use_evidence as use_evidence
from cwo_core.synthesis_inputs import ACCEPTING_DECISIONS, malformed_hold_reasons

MAX_AFFECTED_FINDINGS = 32
MAX_FINDING_LENGTH = 512
_UNKNOWN_HOLD = 'unreadable-original-hold-set'
_REFUSALS = (CWOError, ValueError, OSError, KeyError, TypeError, AttributeError, RecursionError)


@dataclass(frozen=True)
class PreparedAffectedUse:
    """One immutable offline reliability state; never production permission."""
    receipt: source.SourceReceipt | None
    expected: binding.ExpectedContext | None
    selected_root: Path | None
    affected_findings: tuple[str, ...]
    evaluation_bytes: bytes
    source_projection_bytes: bytes
    projection_bytes: bytes

    @property
    def affected_use_ready(self) -> bool:
        return binding._parse(self.projection_bytes)['offline_affected_use_ready'] is True


def _immutable_fields(receipt):
    observation, prepared = receipt.source.evaluation, receipt.prepared
    raw_values = (receipt.binding_bytes, receipt.source.dispatch_bytes,
        receipt.source.provenance_bytes, observation.raw_return, observation.result_bytes,
        observation.policy_bytes, prepared.evaluation_bytes, prepared.policy_bytes)
    if any(type(value) is not bytes for value in raw_values):
        raise ValueError('reliability snapshots require immutable bytes')
    for values, kind in ((prepared.errors, str), (prepared.resolved_findings, str),
            (prepared.remaining_holds, str), (prepared.adjudication_restrictions, str),
            (prepared.support_bytes, bytes)):
        if type(values) is not tuple or any(type(value) is not kind for value in values):
            raise ValueError('reliability snapshots require immutable typed tuples')
    if prepared.decision is not None and type(prepared.decision) is not str:
        raise ValueError('the reliability decision has a malformed type')


def _checked_receipt(receipt):
    if type(receipt) is not source.SourceReceipt:
        raise ValueError('an actual adjudication SourceReceipt is required for reliability')
    if type(receipt.source) is not source.SourceObservation:
        raise ValueError('an actual adjudication source observation is required for reliability')
    if type(receipt.prepared) is not binding.PreparedAdjudication:
        raise ValueError('an actual adjudication preparation is required for reliability')
    observation = receipt.source.evaluation
    types = ((observation, binding.EvaluationObservation),
        (observation.context, binding.ExpectedContext),
        (receipt.prepared.context, binding.ExpectedContext),
        (receipt.source.dispatch_path, str), (receipt.prepared.return_sha256, str))
    if any(type(value) is not kind for value, kind in types):
        raise ValueError('the reliability receipt has malformed immutable fields')
    _immutable_fields(receipt)
    return receipt


def _retained_evaluation(receipt):
    if type(receipt) is not source.SourceReceipt:
        return b'', None
    try:
        retained = source._object_bytes(receipt.binding_bytes)
        evaluation = source._original_evaluation(receipt, retained)
        for raw in source._evaluation_candidates(receipt):
            if type(raw) is bytes and binding._sha(raw) == retained['evaluation_sha256']:
                return raw, evaluation
    except _REFUSALS:
        pass
    return b'', None


def _baseline(receipt, raw, evaluation):
    known = type(evaluation) is dict and not malformed_hold_reasons(evaluation.get('hold_reasons'))
    holds = evaluation['hold_reasons'] if known else [_UNKNOWN_HOLD]
    try:
        retained = source._object_bytes(receipt.binding_bytes)
    except _REFUSALS:
        retained = {}
    decision, restrictions = source._invalid_restrictions(receipt, retained)
    return {'scope': 'inert-preparation-only', 'source_valid': False, 'inert_valid': False,
        'evaluation': evaluation, 'evaluation_sha256': binding._sha(raw) if known else None,
        'original_holds_known': known, 'remaining_holds': list(holds), 'resolved_findings': [],
        'decision': decision,
        'adjudication_restrictions': list(dict.fromkeys((*restrictions, 'rejected', 'quarantined'))),
        'errors': [], 'production_blockers': list(binding.MISSING_PRODUCTION)}


def _affected(value, holds):
    if type(value) is not list:
        raise ValueError('affected reliability findings require a nonempty bounded list')
    value = tuple(value)
    if not 1 <= len(value) <= MAX_AFFECTED_FINDINGS:
        raise ValueError('affected reliability findings require a nonempty bounded list')
    if any(type(item) is not str or not item.strip() or item != item.strip()
            or len(item) > MAX_FINDING_LENGTH for item in value):
        raise ValueError('affected reliability finding IDs require bounded exact nonblank strings')
    if len({item.casefold() for item in value}) != len(value):
        raise ValueError('affected reliability finding IDs must be unique')
    if any(item not in holds for item in value):
        raise ValueError('affected reliability findings must belong to the original evaluated hold set')
    return value


def _check_projection(result, receipt, expected, raw, evaluation):
    observation = receipt.source.evaluation
    actual = (result['context'], result['return_sha256'], result['evaluation_sha256'],
        result['policy_sha256'], result['dispatch_path'], result['dispatch_sha256'])
    wanted = (asdict(expected), observation.return_sha256, binding._sha(raw),
        binding._sha(observation.policy_bytes), receipt.source.dispatch_path,
        receipt.source.dispatch_sha256)
    if actual != wanted or result['evaluation'] != evaluation:
        raise ValueError('consumed reliability bindings differ from the retained original state')
    resolved, remaining = result['resolved_findings'], result['remaining_holds']
    if malformed_hold_reasons(resolved) or malformed_hold_reasons(remaining):
        raise ValueError('consumed reliability hold lists are malformed')
    holds = evaluation['hold_reasons']
    if not set(resolved) <= set(holds) or remaining != [hold for hold in holds if hold not in resolved]:
        raise ValueError('consumed reliability findings do not preserve the original hold set')


def _consume(receipt, expected, root, raw, evaluation):
    if type(expected) is not binding.ExpectedContext:
        raise ValueError('independent exact expected reliability context is required')
    if not isinstance(root, Path):
        raise ValueError('an independently selected dispatch root Path is required for reliability')
    if type(evaluation) is not dict or malformed_hold_reasons(evaluation.get('hold_reasons')):
        raise ValueError('the original evaluated reliability hold set is unreadable')
    result = source.consume_source(receipt, expected, root)
    _check_projection(result, receipt, expected, raw, evaluation)
    return result


def _original_vetoes(evaluation):
    values = (evaluation.get('verdict'), evaluation.get('disposition'))
    vetoes = []
    if any(value in ('reject', 'rejected', 'quarantine', 'quarantined') for value in values):
        vetoes.append('original-rejection-or-quarantine')
    if any(evaluation.get(name) == 'boundary-tainted'
            for name in ('boundary_taint_status', 'boundary_status', 'share_boundary_status')):
        vetoes.append('original-boundary-restriction')
    return tuple(vetoes)


def _global_eligible(evaluation):
    return (evaluation.get('verdict') in ('accept', 'accept-findings')
        and evaluation.get('accepted_for_use') is True
        and evaluation.get('implementation_blocked') is False and not _original_vetoes(evaluation))


def _use_errors(result, evaluation, affected, errors):
    issues = [*result['errors'], *errors, *_original_vetoes(evaluation)]
    if result.get('source_valid') is not True or result.get('inert_valid') is not True:
        issues.append('the consumed reliability adjudication source is invalid')
    if result.get('decision') not in ACCEPTING_DECISIONS or result['adjudication_restrictions']:
        issues.append('an accepting reliability decision without pending refusals is required')
    if not affected or not set(affected) <= set(result['resolved_findings']):
        issues.append('the same consumed reliability adjudication state must resolve every affected finding')
    return tuple(dict.fromkeys(issues))


def _finish(result, baseline, affected, errors):
    evaluation = baseline['evaluation'] or {}
    issues = _use_errors(result, evaluation, affected, errors)
    ready = not issues
    resolved = affected if ready else ()
    holds = baseline['remaining_holds']
    remaining = [hold for hold in holds if hold not in resolved]
    global_eligible = _global_eligible(evaluation)
    blockers = [*remaining, *issues]
    if not global_eligible:
        blockers.append('original-evaluation-does-not-permit-global-use')
    return {**result, 'consumer_scope': 'offline-affected-use-only',
        'evaluation': baseline['evaluation'], 'evaluation_sha256': baseline['evaluation_sha256'],
        'original_holds_known': baseline['original_holds_known'], 'original_hold_reasons': list(holds),
        'source_resolved_findings': list(result['resolved_findings']),
        'affected_findings': list(affected), 'resolved_findings': list(resolved),
        'remaining_holds': remaining, 'errors': list(issues), 'offline_affected_use_ready': ready,
        'all_original_holds_resolved': ready and not remaining,
        'full_local_hold_clearance': ready and not remaining and global_eligible,
        'local_implementation_blocked': not (ready and not remaining and global_eligible),
        'local_blockers': list(dict.fromkeys(blockers)),
        'production_ready': False, 'accepted_for_use': False, 'implementation_blocked': True,
        'trusted_host_authority': False, 'effect_authority': False}


def prepare(receipt, expected, root, *, affected_findings) -> PreparedAffectedUse:
    """Consume the actual reliability adjudication receipt for one independently selected affected use."""
    raw, evaluation = _retained_evaluation(receipt)
    baseline = _baseline(receipt, raw, evaluation)
    result, checked, selected, source_bytes = baseline, None, None, b''
    errors = []
    try:
        checked = _checked_receipt(receipt)
        result = _consume(checked, expected, root, raw, evaluation)
        source_bytes = binding._json(result)
        selected = root.absolute()
    except _REFUSALS as exc:
        result = baseline
        errors.append('offline reliability source refused: ' + str(exc))
    try:
        affected = _affected(affected_findings, baseline['remaining_holds'])
    except _REFUSALS as exc:
        affected = ()
        errors.append(str(exc))
    context = expected if type(expected) is binding.ExpectedContext else None
    projection = _finish(result, baseline, affected, errors)
    projection.update(expected_context=asdict(context) if context is not None else None,
        selected_root=str(selected) if selected is not None else None,
        source_binding_sha256=binding._sha(checked.binding_bytes) if checked is not None else None)
    return PreparedAffectedUse(checked, context, selected, affected, raw, source_bytes,
        binding._json(projection))


def synthesis_projection(prepared: PreparedAffectedUse) -> dict:
    """Render the common offline reliability state with all production restrictions."""
    if type(prepared) is not PreparedAffectedUse:
        raise TypeError('a prepared offline reliability state is required')
    return binding._parse(prepared.projection_bytes)


def status_projection(prepared: PreparedAffectedUse) -> dict:
    """Render exactly the same offline reliability state for status."""
    return synthesis_projection(prepared)


def _block(prepared, message):
    projection = synthesis_projection(prepared)
    projection.update(offline_affected_use_ready=False, all_original_holds_resolved=False,
        full_local_hold_clearance=False, local_implementation_blocked=True,
        resolved_findings=[], remaining_holds=list(projection['original_hold_reasons']),
        errors=list(dict.fromkeys((*projection['errors'], message))))
    projection['local_blockers'] = list(dict.fromkeys((
        *projection['local_blockers'], *projection['remaining_holds'], message)))
    return replace(prepared, projection_bytes=binding._json(projection))


def use_offline(receipt, expected, root, *, affected_findings,
                effect: Callable[[tuple[str, ...]], object]) -> PreparedAffectedUse:
    """Reconsume the original reliability receipt, then call only the supplied fake callback."""
    initial = prepare(receipt, expected, root, affected_findings=affected_findings)
    if not initial.affected_use_ready:
        return initial
    if not callable(effect):
        return _block(initial, 'a callable fake reliability effect is required')
    current = prepare(receipt, expected, root, affected_findings=list(initial.affected_findings))
    if current != initial:
        return _block(current, 'reliability bindings changed before fake affected use')
    if current.affected_use_ready:
        effect(current.affected_findings)
    return current
