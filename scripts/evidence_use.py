"""Consume issued adjudication in evaluation, synthesis and a useful evidence brief.

Rendering the accepted, scoped excerpt is the final evidence-use effect. This
module has no model, process, browser, Beads completion or filesystem-write API.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass

from cwo_core import adjudication_binding as binding
from cwo_core.errors import CWOError
from qualified_adjudication import QualifiedAdjudicationBroker
from cwo_core.synthesis import evaluate_synthesis_inputs
from cwo_core.synthesis_inputs import ACCEPTING_DECISIONS

_REFUSALS = (CWOError, ValueError, OSError, KeyError, TypeError, AttributeError, RecursionError)


@dataclass(frozen=True)
class EvidenceUseResult:
    state_bytes: bytes
    document: str

    def projection(self):
        return binding._parse(self.state_bytes)


def _incomplete(result, metadata):
    return (metadata['local_response_truncated'] or metadata['local_reasoning_malformed']
        or 'length' in [value.strip().lower() for value in metadata['local_finish_reasons']]
        or result['local_completion_status'] not in (None, 'completed')
        or result['local_usable_final_content'] is False)


def _vetoes(result, metadata):
    vetoes = []
    if result.get('verdict') in ('reject', 'quarantine') or result.get('hard_disqualifiers'):
        vetoes.append('original rejection/quarantine/disqualification remains in force')
    if any(result.get(key) == 'boundary-tainted' for key in ('boundary_taint_status', 'boundary_status')):
        vetoes.append('original boundary restriction remains in force')
    if result.get('peer_review_required') and result.get('peer_review_status') != 'passed':
        vetoes.append('independent peer review remains required')
    if _incomplete(result, metadata):
        vetoes.append('original incomplete dispatch remains in force')
    if result.get('recommended_synthesis_use') in ('reject', 'quarantine'):
        vetoes.append('original recommended refusal remains in force')
    return vetoes


def _use_scope(expected, affected, state):
    if type(expected) is not binding.ExpectedContext or expected != state.control.context:
        raise ValueError('exact independently selected current use context is required')
    if type(affected) is not list or not affected or any(type(x) is not str for x in affected):
        raise ValueError('use must select a nonempty exact list of affected finding IDs')
    if len(set(affected)) != len(affected) or set(affected) != set(state.findings):
        raise ValueError('use cannot widen or change the independently adjudicated scope')


def _use_evaluation(state, original, remaining, accepting, vetoes):
    # The use projection carries only status/identity data plus the approved
    # payload. Unrestricted sections and research/content fields stay historical.
    evaluation = {key: value for key, value in original.items() if key in {
        'dispatch_id', 'bead_id', 'packet_sha256', 'executor', 'provider_key', 'provider_family',
        'verdict', 'score', 'screening_eligible', 'evidence_quality_score', 'boundary_taint_status',
        'peer_review_required', 'peer_review_status', 'hold_classification'} or key.startswith('local_')}
    evaluation.update(hold_reasons=remaining, evidence_use_hold=bool(remaining),
        implementation_blocked=bool(remaining) or bool(vetoes),
        accepted_for_use=accepting and not remaining and not vetoes, execution_permitted=False)
    payload = {'text': state.excerpt, 'sha256': binding._sha(state.excerpt.encode()),
        'return_sha256': state.observation.return_sha256, 'finding_ids': list(state.findings),
        'context': asdict(state.control.context),
        'adjudication_id': binding._parse(state.record_bytes)['adjudication_id']}
    evaluation.update(sections={'adjudicated_excerpt': state.excerpt} if accepting and not vetoes else {},
        evidence_payload=payload if accepting and not vetoes else None)
    return evaluation


def _project(state):
    original = binding._parse(state.observation.result_bytes)
    remaining = [hold for hold in original['hold_reasons'] if hold not in state.findings]
    accepting = state.decision in ACCEPTING_DECISIONS
    vetoes = _vetoes(original, binding._parse(state.control.evaluation_metadata_bytes))
    resolved = list(state.findings) if state.decision == 'rejected' or accepting and not vetoes else []
    if not resolved:
        remaining = list(original['hold_reasons'])
    evaluation = _use_evaluation(state, original, remaining, accepting, vetoes)
    # Keep the original scored verdict and all diagnostics in original_evaluation.
    # A scoped accepting adjudication only supplies the matching use projection.
    entry = {**evaluation, 'lane': state.control.context.dispatch_id,
        'return_sha256': state.observation.return_sha256,
        'disposition': ('accepted' if accepting else state.decision),
        'recommended_synthesis_use': ('primary' if accepting else 'reject'),
        'synthesis_use': ('primary' if accepting else 'reject'),
        'reason': {'kind': 'adjudicated-excerpt', 'evidence_payload': evaluation['evidence_payload']}}
    if vetoes:
        entry.update(disposition=binding._evaluation_disposition(original),
            recommended_synthesis_use=original['recommended_synthesis_use'],
            synthesis_use=original['recommended_synthesis_use'])
    synthesis = evaluate_synthesis_inputs([entry],
        dispatch_records=[binding._parse(state.control.dispatch_bytes)],
        adjudications=[binding._parse(state.record_bytes)], candidate=state.control.context.candidate,
        scope=state.control.context.scope)
    return {'original_evaluation': original, 'evaluation': evaluation, 'synthesis': synthesis,
        'affected_findings': list(state.findings), 'resolved_findings': resolved,
        'remaining_holds': remaining, 'decision': state.decision,
        'affected_accepted_for_use': accepting and not vetoes,
        'errors': vetoes, 'execution_permitted': False, 'dispatch_permitted': False,
        'completion_permitted': False, 'live_activation': False}


def _render(state, projection):
    if not projection['affected_accepted_for_use']:
        return ''
    record = binding._parse(state.record_bytes)
    payload = projection['evaluation']['evidence_payload']
    context = payload['context']
    # The original advice outside this exact approved excerpt is never emitted.
    return (f'Evidence for {context["task"]} / {context["candidate"]} / {context["scope"]}\n'
        f'Dispatch: {context["dispatch_id"]}\nExecutor: {context["executor"]}\n'
        f'Packet SHA256: {context["packet_sha256"]}\n'
        f'Return SHA256: {payload["return_sha256"]}\nExcerpt SHA256: {payload["sha256"]}\n'
        f'Adjudication: {payload["adjudication_id"]} ({state.decision})\n'
        f'Affected findings: {", ".join(payload["finding_ids"])}\n'
        f'Rationale: {record["rationale"]}\n\n{payload["text"]}\n\n'
        'Supporting artifacts:\n' + '\n'.join(
            f'- {item["artifact"]} (sha256 {item["sha256"]})' for item in record['supporting_evidence'])
        + '\nRemaining whole-return holds: ' + (', '.join(projection['remaining_holds']) or 'none') + '\n')


def use_evidence(broker, permit, expected, *, affected_findings) -> EvidenceUseResult:
    """Spend one issued permit, then revalidate at actual downstream evidence use.

    Refusal is terminal even if a later read could recover. Partial facts and the
    original diagnostic survive; no downstream render is returned on failure.
    """
    state, projection = None, {'original_evaluation': None, 'evaluation': None,
        'resolved_findings': [], 'remaining_holds': ['qualified-source-unresolved'],
        'affected_accepted_for_use': False, 'execution_permitted': False,
        'dispatch_permitted': False, 'completion_permitted': False, 'live_activation': False}
    try:
        if type(broker) is not QualifiedAdjudicationBroker:
            raise ValueError('a host-registered qualified adjudication broker is required')
        state = broker._take(permit)
        original = binding._parse(state.observation.result_bytes)
        projection.update(original_evaluation=original, evaluation=original,
            remaining_holds=original['hold_reasons'])
        _use_scope(expected, affected_findings, state)
        broker._revalidate(state)
        projection = _project(state)
        if projection['affected_accepted_for_use']:
            selected = projection['synthesis']['input_summaries'][0]
            if selected['quarantine_in_force']:
                raise ValueError('selected synthesis input remains quarantined')
            if selected['synthesis_use'] == 'reject':
                raise ValueError('selected synthesis input remains rejected')
        document = _render(state, projection)
        broker._revalidate(state)
        return EvidenceUseResult(binding._json(projection), document)
    except _REFUSALS as exc:
        original = projection['original_evaluation']
        projection.update(evaluation=original, resolved_findings=[],
            remaining_holds=(original['hold_reasons'] if original else ['qualified-source-unresolved']),
            synthesis=None, affected_accepted_for_use=False, errors=[*projection.get('errors', []), str(exc)],
            diagnostic={'type': type(exc).__name__, 'message': str(exc)})
        return EvidenceUseResult(binding._json(projection), '')
