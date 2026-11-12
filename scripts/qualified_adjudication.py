"""Host-registered, one-use evidence adjudication; no activation or execution.

The embedding host pins a control adapter at bootstrap, outside the data API.
That adapter is trusted to observe the designated adjudicator, not to validate
the returned evidence. This broker performs those checks. An arbitrary adapter
registered by hostile host code is outside this in-process trust boundary.
There is deliberately no default adapter, JSON enrollment or serialized permit.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from cwo_core import adjudication_binding as binding
from cwo_core import return_tripwires
from cwo_core.adjudication import clearable_hold_reason
from cwo_core.returns import make_acceptance_decision
from cwo_core.peer_review import validate_peer_review_request
from cwo_core.synthesis_inputs import ACCEPTING_DECISIONS, RESTRICTIVE_DECISIONS, text

# A declaration template, never a grant. Every field must be independently
# declared by the control AND recorded on the selected dispatch.
METADATA_DEFAULTS = {
    'share_boundary': None, 'job_description_label': None, 'dispatch_mode': None,
    'local_profile': None, 'model_profile': None, 'expected_return_language': 'en',
    'peer_review_required': False, 'peer_review_status': 'not-run',
    'peer_review_reviewer': None, 'peer_review_record': None,
    'provider_conflict_domains': [], 'workspace_mutation': None, 'mutation_strategy': 'reject',
    'local_response_truncated': False, 'local_finish_reasons': [],
    'local_reasoning_malformed': False, 'local_completion_status': None,
    'local_usable_final_content': None, 'local_expected_response_contract': None,
    'local_response_contract': None, 'local_response_contract_status': None,
    'local_normalized_return_matches': None, 'local_v2_frame_valid': None,
    'local_v2_identity_consistent': None, 'local_response_model_status': None,
    'local_model_preflight_status': None, 'local_http_status': None,
}
_BOOL_METADATA = {'peer_review_required', 'local_response_truncated', 'local_reasoning_malformed'}
_OPTIONAL_BOOL_METADATA = {'local_usable_final_content', 'local_normalized_return_matches',
    'local_v2_frame_valid', 'local_v2_identity_consistent'}


def _metadata_value(name, value):
    if name in _BOOL_METADATA:
        return type(value) is bool
    if name in _OPTIONAL_BOOL_METADATA:
        return value is None or type(value) is bool
    if name in ('provider_conflict_domains', 'local_finish_reasons'):
        return type(value) is list and all(type(item) is str for item in value)
    if name in ('workspace_mutation', 'peer_review_record', 'peer_review_reviewer'):
        return value is None or type(value) is dict
    if name == 'local_http_status':
        return value is None or type(value) is int
    if name in ('peer_review_status', 'mutation_strategy'):
        return type(value) is str
    return value is None or type(value) is str


def _evaluation_metadata(raw):
    value = binding._parse(raw)
    if type(value) is not dict or set(value) != set(METADATA_DEFAULTS):
        raise ValueError('control must independently declare the complete evaluation metadata')
    if any(not _metadata_value(name, item) for name, item in value.items()):
        raise ValueError('independent evaluation metadata has a malformed value')
    validate_peer_review_request(value['peer_review_status'], value['peer_review_reviewer'],
                                value['peer_review_record'])
    if any(value[name] is not None and not value[name].strip()
            for name in ('local_expected_response_contract', 'local_response_contract')):
        raise ValueError('blank local contract marker in independent evaluation metadata')
    if value['mutation_strategy'] not in ('reject', 'warn'):
        raise ValueError('unsupported mutation strategy in independent evaluation metadata')
    if value['share_boundary'] is not None:
        binding._policy_call(binding.policy.boundary_config, value['share_boundary'])
    return value


def observe_boundary_policy(metadata_bytes):
    """Observe the existing boundary roster only when the evaluation uses it."""
    metadata = binding._parse(metadata_bytes)
    if type(metadata) is not dict:
        raise ValueError('independent evaluation metadata must be an object')
    if metadata.get('share_boundary') is None:
        return b''
    raw = (binding.policy.POLICY_DIR / 'share-boundaries.yaml').read_bytes()
    if binding._parse(raw) != binding._policy_call(binding.policy.load_policy, 'share-boundaries'):
        raise ValueError('share-boundary policy cache/bytes mismatch')
    return raw


@dataclass(frozen=True)
class ControlObservation:
    """Independent exact declaration obtained from the pinned control adapter.

    Constructing this value does not issue a permit. Support contains the actual
    artifacts observed by that control, not caller assertions about their hashes.
    """
    context: binding.ExpectedContext
    return_path: str
    dispatch_path: str
    raw_return: bytes
    dispatch_bytes: bytes
    evaluation_bytes: bytes
    policy_bytes: bytes
    record_bytes: bytes
    support: tuple[binding.SupportObservation, ...]
    evaluation_metadata_bytes: bytes
    boundary_policy_bytes: bytes = b''


class AdjudicationControl(Protocol):
    """Trusted host adapter; claim pins exclusive custody for this broker life.

    Completed controls also provide a no-callout require_active revocation veto.
    Historical claim/observe controls retain their existing observation contract.
    """

    def claim(self, owner: object) -> None: ...
    def observe(self, owner: object, control_id: str) -> ControlObservation: ...


def check_control_revocation(control):
    """Consult the pinned control's monotonic veto after validator callouts.

    This checks no acceptance predicate and enrolls no authority. Concrete
    completed controls only inspect their source/host revocation state here.
    """
    guard = getattr(control, 'require_active', None)
    if guard is not None:
        guard()


@dataclass(frozen=True, eq=False)
class EvidencePermit:
    """Opaque identity only; a constructor, copy or deserialization grants nothing."""


@dataclass(frozen=True)
class QualifiedState:
    control_id: str
    control: ControlObservation
    observation: binding.EvaluationObservation
    record_bytes: bytes
    findings: tuple[str, ...]
    decision: str
    excerpt: str


def evaluate_current(raw: bytes, context: binding.ExpectedContext, *,
                     metadata_bytes: bytes) -> binding.EvaluationObservation:
    """Run the production evaluator without overrides or rehearsal provenance."""
    before = binding._policies()
    boundary_before = observe_boundary_policy(metadata_bytes)
    # The scanner has a separate derived cache, not cleared by the policy loader.
    # Qualified observations must compile the same current policy checked above.
    return_tripwires._policy.cache_clear()
    result = make_acceptance_decision(raw.decode('utf-8'), bead_id=context.task,
        dispatch_id=context.dispatch_id, packet_sha256=context.packet_sha256,
        executor=context.executor, expected_return_language_source='registered-adjudication-control',
        **_evaluation_metadata(metadata_bytes))
    if before != binding._policies() or boundary_before != observe_boundary_policy(metadata_bytes):
        raise ValueError('policy changed during qualified evaluation')
    return binding.EvaluationObservation(context, raw, binding._json(result), before)


def _control_types(control):
    if type(control) is not ControlObservation or type(control.context) is not binding.ExpectedContext:
        raise ValueError('registered control must supply its exact independent observation')
    for name in ('raw_return', 'dispatch_bytes', 'evaluation_bytes', 'policy_bytes', 'record_bytes',
            'evaluation_metadata_bytes', 'boundary_policy_bytes'):
        if type(getattr(control, name)) is not bytes:
            raise ValueError('control observations require immutable bytes: ' + name)
    if type(control.support) is not tuple or len(control.support) > binding.MAX_SUPPORT_FILES:
        raise ValueError('control support observations are malformed or too numerous')
    for item in control.support:
        if type(item) is not binding.SupportObservation or type(item.raw) is not bytes:
            raise ValueError('actual immutable independently observed support is required')


def _observed_support(control, findings):
    observed = {}
    for support in control.support:
        path = binding.path_components(support.artifact)
        if path is None or path in observed or support.finding_id not in findings:
            raise ValueError('support paths/findings are invalid, duplicated or outside scope')
        observed[path] = support
    return observed


def _supports(control, record, root, findings):
    items = record.get('supporting_evidence')
    if type(items) is not list or len(items) != len(control.support):
        raise ValueError('record must name exactly the independently observed support')
    observed = _observed_support(control, findings)
    covered, selected = set(), set()
    for item in items:
        path = binding.path_components(item['artifact'])
        support = observed.get(path)
        if support is None or path in selected or item['finding_ids'] != [support.finding_id]:
            raise ValueError('support selection differs from the control observation')
        raw = binding.read_support(root, item['artifact'])
        if not raw or raw != support.raw or binding._sha(raw) != item['sha256']:
            raise ValueError('actual supporting evidence is missing, changed or unobserved')
        covered.add(support.finding_id)
        selected.add(path)
    if record['decision'] in ACCEPTING_DECISIONS and covered != set(findings):
        raise ValueError('accepting every affected finding requires observed supporting evidence')


def _resolution(control, observation, record, root):
    binding._binding_checks(observation, control.context, record)
    dispatch = binding.DispatchObservation(control.dispatch_path, control.dispatch_bytes,
        observation, binding._dispatch_provenance(control.dispatch_bytes,
            control.raw_return, control.context, observation.policy_bytes))
    config, item, bound, resolution = binding._normalized(observation, record,
        expected=control.context, root=root, observed_dispatch=dispatch)
    if not bound.bound or not bound.provenance_known or not resolution.applied:
        raise ValueError('qualified adjudication is unresolved: ' + repr(resolution.errors))
    findings = resolution.finding_ids
    if not findings or len(findings) > 32 or not set(findings) <= set(item.hold_reasons):
        raise ValueError('qualified findings must name a bounded exact subset of original holds')
    if any(not clearable_hold_reason(finding, config) for finding in findings):
        raise ValueError('independent review holds cannot be cleared by evidence adjudication')
    return findings, resolution.decision


def _excerpt(record, raw, decision):
    excerpt = record.get('accepted_excerpt', '')
    if decision in RESTRICTIVE_DECISIONS:
        if excerpt:
            raise ValueError('a refusal cannot carry accepted advice')
        return ''
    if type(excerpt) is not str or not excerpt.strip() or len(excerpt.encode()) > 65536:
        raise ValueError('acceptance needs a bounded explicitly adjudicated excerpt')
    if raw.decode('utf-8').count(excerpt) != 1:
        raise ValueError('accepted excerpt must select one exact occurrence in the actual return')
    return excerpt


def _recheck_bindings(control, root):
    current = (binding.read_support(root, control.return_path),
        binding.read_support(root, control.dispatch_path), binding._policies(),
        observe_boundary_policy(control.evaluation_metadata_bytes))
    if current != (control.raw_return, control.dispatch_bytes, control.policy_bytes, control.boundary_policy_bytes):
        raise ValueError('return/dispatch/policy changed during supporting-evidence validation')


def _observe(control_id, control, root):
    _control_types(control)
    raw = binding.read_support(root, control.return_path)
    dispatch = binding.read_support(root, control.dispatch_path)
    metadata = _evaluation_metadata(control.evaluation_metadata_bytes)
    if observe_boundary_policy(control.evaluation_metadata_bytes) != control.boundary_policy_bytes:
        raise ValueError('share-boundary policy differs from independent control declaration')
    if binding._parse(dispatch).get('evaluation_metadata') != metadata:
        raise ValueError('dispatch evaluation metadata differs from independent control declaration')
    observation = evaluate_current(raw, control.context, metadata_bytes=control.evaluation_metadata_bytes)
    actual = (raw, dispatch, observation.result_bytes, observation.policy_bytes)
    declared = (control.raw_return, control.dispatch_bytes, control.evaluation_bytes, control.policy_bytes)
    if actual != declared:
        raise ValueError('current return/dispatch/evaluation/policy differs from independent control')
    record = binding._parse(control.record_bytes)
    findings, decision = _resolution(control, observation, record, root)
    _supports(control, record, root, findings)
    excerpt = _excerpt(record, raw, decision)
    _recheck_bindings(control, root)
    return QualifiedState(control_id, control, observation, control.record_bytes, findings, decision, excerpt)


def _record_identity(control):
    """Read only the identity needed to make any later refusal terminal."""
    if type(control) is not ControlObservation or type(control.record_bytes) is not bytes:
        raise ValueError('registered control must expose immutable adjudication record bytes')
    record = binding._parse(control.record_bytes)
    if type(record) is not dict:
        raise ValueError('adjudication record must expose a readable identity')
    identity = text(record.get('adjudication_id'))
    if identity is None:
        raise ValueError('adjudication record must expose a readable identity')
    return identity


class QualifiedAdjudicationBroker:
    """Host bootstrap registry and issuer, with no live or default registration.

    The host owns this object and its adapter; request data never selects one.
    Registering a fake control exercises the SAME issuer/use path offline, but
    does not qualify that fake as a live authority. No keys or credentials exist.
    Receipts are valid only in this broker lifetime; restart requires host
    reenrollment, never import of old receipts. A refusal spends the attempt.
    """

    def __init__(self, root: Path, control: AdjudicationControl):
        if not isinstance(root, Path) or not callable(getattr(control, 'observe', None)):
            raise ValueError('host must pin a root and control adapter at bootstrap')
        self._root = root.absolute()
        self._control = control
        self._owner = object()
        self._attempts: set[str] = set()
        self._records: set[str] = set()
        self._issued: dict[EvidencePermit, QualifiedState] = {}
        control.claim(self._owner)

    def issue(self, control_id: str) -> EvidencePermit:
        if type(control_id) is not str or not control_id.strip() or control_id in self._attempts:
            raise ValueError('control observation is missing or already attempted')
        self._attempts.add(control_id)
        control = self._control.observe(self._owner, control_id)
        record_id = _record_identity(control)
        if record_id in self._records:
            raise ValueError('adjudication record was already issued by this broker')
        self._records.add(record_id)
        _control_types(control)
        state = _observe(control_id, control, self._root)
        check_control_revocation(self._control)
        permit = EvidencePermit()
        self._issued[permit] = state
        return permit

    def _take(self, permit):
        if type(permit) is not EvidencePermit:
            raise ValueError('only a live broker-issued permit can authorize evidence use')
        state = self._issued.pop(permit, None)
        if state is None:
            raise ValueError('permit is forged, foreign, stale or already consumed')
        return state

    def _revalidate(self, state):
        current = self._control.observe(self._owner, state.control_id)
        if current != state.control:
            raise ValueError('designated adjudicator observation changed before use')
        if _observe(state.control_id, current, self._root) != state:
            raise ValueError('qualified evidence changed before use')
        check_control_revocation(self._control)
