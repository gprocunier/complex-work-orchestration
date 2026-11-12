"""Experimental immutable adjudication binding preparation; NEVER production authority.

Expected context/support observations come from a controlled fixture source, not
from submitted JSON. No production-qualified source exists. These pure adapters
cannot clear a production hold, authorize an effect or complete production closure or local invocation qualification.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, replace
import hashlib
import json
import os
from pathlib import Path
import stat
from typing import Any

from . import policy
from .adjudication import bind_inputs, dispatch_provenance, hold_clearance, load_registries, resolve_adjudication
from .errors import CWOError
from .path_contract import path_components
from .returns import make_acceptance_decision
from .synthesis_inputs import call_view, consensus_policy_view, dispatch_record_view, synthesis_policy_view

MAX_SUPPORT_BYTES = 1024 * 1024
MAX_SUPPORT_FILES = 32
MAX_JSON_DEPTH = 64
POLICIES = ('contracting-controls', 'acceptance-policy', 'return-tripwires', 'synthesis-policy',
            'zero-trust-consensus-policy', 'provider-registry', 'executor-registry')
MISSING_PRODUCTION = ('no-qualified-production-adjudication-source', 'full-W06-37-unmet',
                      'full-W07-41-unmet', 'effect-restoration-held')


def _json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode('utf-8')


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate JSON key')
        result[key] = value
    return result


def _constant(value):
    raise ValueError('non-finite JSON constant: ' + value)


def _check_json_depth(raw: bytes):
    depth, quoted, escaped = 0, False, False
    for char in raw:
        if quoted:
            if escaped:
                escaped = False
            elif char == 92:
                escaped = True
            elif char == 34:
                quoted = False
        elif char == 34:
            quoted = True
        elif char in (123, 91):
            depth += 1
            if depth > MAX_JSON_DEPTH:
                raise ValueError(f"JSON nesting exceeds supported depth {MAX_JSON_DEPTH}")
        elif char in (125, 93):
            depth -= 1


def _parse(raw: bytes):
    _check_json_depth(raw)
    try:
        return json.loads(raw, object_pairs_hook=_unique, parse_constant=_constant)
    except RecursionError as exc:
        raise ValueError("JSON nesting exceeds supported parser resources") from exc


@dataclass(frozen=True)
class ExpectedContext:
    task: str
    scope: str
    candidate: str
    dispatch_id: str
    packet_sha256: str
    executor: str

    def __post_init__(self):
        if any(not isinstance(v, str) or not v.strip() for v in asdict(self).values()):
            raise ValueError('expected context needs exact nonblank strings')
        if len(self.packet_sha256) != 64 or any(c not in '0123456789abcdef' for c in self.packet_sha256):
            raise ValueError('packet digest invalid')


@dataclass(frozen=True)
class EvaluationObservation:
    context: ExpectedContext
    raw_return: bytes
    result_bytes: bytes
    policy_bytes: bytes

    @property
    def return_sha256(self):
        return _sha(self.raw_return)

    @property
    def evaluation_sha256(self):
        return _sha(self.result_bytes)


@dataclass(frozen=True)
class DispatchObservation:
    """Immutable dispatch reliability data validated independently by binding."""
    dispatch_path: str
    dispatch_bytes: bytes
    evaluation: EvaluationObservation
    provenance_bytes: bytes


@dataclass(frozen=True)
class SupportObservation:
    """Independently observed fixture support, NOT a serialized trust credential."""
    artifact: str
    finding_id: str
    raw: bytes


@dataclass(frozen=True)
class PreparedAdjudication:
    context: ExpectedContext
    errors: tuple[str, ...]
    resolved_findings: tuple[str, ...]
    remaining_holds: tuple[str, ...]
    support_bytes: tuple[bytes, ...]
    evaluation_bytes: bytes
    policy_bytes: bytes
    return_sha256: str
    decision: str | None = None
    adjudication_restrictions: tuple[str, ...] = ()

    @property
    def inert_valid(self):
        return not self.errors


def _policy_call(loader, *args):
    """Expected loader SystemExit refusals are validation failures, not process exits."""
    try:
        return loader(*args)
    except SystemExit as exc:
        raise ValueError(f"applicable policy refused: {exc}") from exc


def _policies() -> bytes:
    documents = {}
    for name in POLICIES:
        raw = (policy.POLICY_DIR / (name + '.yaml')).read_bytes()
        value = _parse(raw)
        if value != _policy_call(policy.load_policy, name):
            raise ValueError('policy cache/bytes mismatch: ' + name)
        documents[name] = {'raw_sha256': _sha(raw), 'value': value}
    return _json(documents)


def observe_evaluation(raw_return: bytes, context: ExpectedContext) -> EvaluationObservation:
    """Observe actual evaluated UTF-8 bytes through the existing real evaluator.

    Context describes an independently supplied fixture dispatch. This does not
    observe a production dispatch or authenticate whoever constructs this object.
    """
    if type(raw_return) is not bytes:
        raise ValueError('return must be immutable bytes')
    before = _policies()
    result = make_acceptance_decision(raw_return.decode('utf-8'), bead_id=context.task,
        dispatch_id=context.dispatch_id, packet_sha256=context.packet_sha256, executor=context.executor,
        expected_return_language='en', expected_return_language_source='fixture-observation')
    if before != _policies():
        raise ValueError('policy changed during evaluation')
    return EvaluationObservation(context, raw_return, _json(result), before)


def read_support(root: Path, name: str) -> bytes:
    """Bounded descriptor walk; no symlinks, devices, traversal or second read."""
    parts = path_components(name)
    if not parts:
        raise ValueError('support path is outside the relative path contract')
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        file_fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
        with os.fdopen(file_fd, 'rb') as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                raise ValueError('support must be a regular file')
            raw = stream.read(MAX_SUPPORT_BYTES + 1)
            if len(raw) > MAX_SUPPORT_BYTES:
                raise ValueError('support is too large')
            return raw
    finally:
        os.close(fd)


def _support_one(item, observed, observation, root):
    raw = read_support(root, item['artifact'])
    if raw != observed.raw or _sha(raw) != item['sha256']:
        raise ValueError('support differs from the independently observed fixture bytes')
    value = _parse(raw)
    expected = {'kind': 'cwo-inert-finding-observation-v1', 'context': asdict(observation.context),
        'return_sha256': observation.return_sha256, 'evaluation_sha256': observation.evaluation_sha256,
        'finding_id': observed.finding_id, 'resolution': 'not-applicable'}
    if value != expected or item['finding_ids'] != [observed.finding_id]:
        raise ValueError('support does not cover this exact observed finding/result/context')
    return raw


def _supports(record, observation, observed_support, root):
    items = record.get('supporting_evidence')
    if not isinstance(items, list) or not 1 <= len(items) <= MAX_SUPPORT_FILES:
        raise ValueError('support list absent/malformed/outside bound')
    expected = {}
    for observed in observed_support:
        key = path_components(observed.artifact)
        if key is None or key in expected:
            raise ValueError('invalid or duplicate observed support path after normalization')
        expected[key] = observed
    if len(expected) != len(items):
        raise ValueError('missing, duplicate or ambiguous fixture support observations')
    names = [path_components(item['artifact']) for item in items]
    if None in names or len(set(names)) != len(names) or set(names) != set(expected):
        raise ValueError('invalid, duplicate or mismatched support paths after normalization')
    return tuple(_support_one(item, expected[key], observation, root) for item, key in zip(items, names))


def _evaluation_disposition(result):
    if result['verdict'] == 'quarantine':
        return 'quarantined'
    if result['verdict'] == 'reject':
        return 'rejected'
    if result['implementation_blocked']:
        return 'needs-investigation'
    return 'accepted' if result['accepted_for_use'] else 'rejected'


def _dispatch_provenance(raw, raw_return, expected, policy_bytes):
    record = _parse(raw)
    _json(record)
    parsed = dispatch_record_view(record)
    if parsed.errors:
        raise ValueError('dispatch reliability record is malformed')
    for name, value in asdict(expected).items():
        if record.get(name) != value:
            raise ValueError('dispatch reliability context mismatch: ' + name)
    if record['return_sha256'] != _sha(raw_return):
        raise ValueError('dispatch reliability return digest mismatch')
    documents = _parse(policy_bytes)
    provenance = dispatch_provenance(record,
        executor_registry=documents['executor-registry']['value'],
        provider_registry=documents['provider-registry']['value'])
    if provenance['known'] is not True:
        raise ValueError('dispatch reliability provenance is unresolved')
    return _json(provenance)


def _normalization_dispatch(dispatch: DispatchObservation, observation: EvaluationObservation,
                            expected: ExpectedContext, root: Path) -> dict[str, Any]:
    """Validate immutable dispatch reliability data through binding-owned checks."""
    if type(dispatch) is not DispatchObservation or dispatch.evaluation is not observation:
        raise ValueError('normalization reliability dispatch is not the original observation')
    if (type(observation), type(observation.context), type(expected)) != (
            EvaluationObservation, ExpectedContext, ExpectedContext):
        raise ValueError('normalization reliability context or observation has the wrong type')
    raw = (dispatch.dispatch_bytes, dispatch.provenance_bytes, observation.raw_return,
           observation.result_bytes, observation.policy_bytes)
    if any(type(item) is not bytes for item in raw):
        raise ValueError('normalization reliability evidence must be immutable bytes')
    raw = read_support(root, dispatch.dispatch_path)
    if raw != dispatch.dispatch_bytes:
        raise ValueError('selected dispatch reliability bytes changed')
    provenance = _dispatch_provenance(raw, observation.raw_return, expected, observation.policy_bytes)
    if provenance != dispatch.provenance_bytes or _policies() != observation.policy_bytes:
        raise ValueError('normalization reliability provenance or policy changed')
    return _parse(raw)


def _normalized(observation, record, *, expected: ExpectedContext | None = None,
                root: Path | None = None,
                observed_dispatch: DispatchObservation | None = None):
    context = observation.context
    config = synthesis_policy_view(_policy_call(policy.load_policy, 'synthesis-policy'))
    result = _parse(observation.result_bytes)
    # Project the ACTUAL result conservatively, never an accepting held verdict.
    entry = {**result, 'lane': context.dispatch_id, 'dispatch_id': context.dispatch_id,
        'return_sha256': observation.return_sha256,
        'disposition': _evaluation_disposition(result)}
    dispatch = {'record_type': 'cwo-dispatch-record', 'version': 1, 'dispatch_id': context.dispatch_id,
        'return_sha256': observation.return_sha256, 'candidate': context.candidate, 'executor': context.executor}
    if observed_dispatch is not None:
        dispatch = _normalization_dispatch(observed_dispatch, observation, expected, root)
    call = call_view([entry], dispatch_records=[dispatch], adjudications=[record], candidate=context.candidate,
        scope=context.scope, zero_trust_required=False, policy=config,
        consensus_policy=consensus_policy_view(_policy_call(policy.load_policy, 'zero-trust-consensus-policy')))
    binding = bind_inputs(call, _policy_call(load_registries))[0]
    resolution = resolve_adjudication(call.inputs[0], binding, call,
                                      claimed_dispatch_ids=frozenset({context.dispatch_id}))
    return config, call.inputs[0], binding, resolution


def _binding_checks(observation, expected, record):
    if observation.context != expected or observation.policy_bytes != _policies():
        raise ValueError('expected context or applicable policy changed')
    if record.get('evaluation_sha256') != observation.evaluation_sha256:
        raise ValueError('adjudication does not bind the actual evaluation/hold set')
    if record.get('task') != expected.task or record.get('packet_sha256') != expected.packet_sha256:
        raise ValueError('adjudication task/packet mismatch')


def _restriction_state(binding, resolution):
    if not binding.bound or not binding.provenance_known:
        return None, ()
    restrictions = resolution.restrictive_decisions
    decision = None
    if resolution.applied and resolution.decision in ('rejected', 'quarantined'):
        decision = resolution.decision
        restrictions = tuple(dict.fromkeys((*restrictions, decision)))
    return decision, restrictions


def prepare_adjudication(observation: EvaluationObservation, expected: ExpectedContext, record: Any,
                         root: Path, *, observed_support: tuple[SupportObservation, ...] = (),
                         observed_dispatch: DispatchObservation | None = None) -> PreparedAdjudication:
    """One common immutable state for inert consumers; no production clearance.

    A fabricated record without independent fixture support cannot pass even
    inert preparation. Successful preparation still has no qualified production
    source. Record/observation objects are cooperative input, not authenticated.
    """
    holds = tuple(_parse(observation.result_bytes)['hold_reasons'])
    restrictive_decision, restrictions = None, ()
    try:
        # Snapshot submitted JSON before normalization or any support I/O.
        # Never re-read the caller's mutable record after checking it.
        record = _parse(_json(record))
        _binding_checks(observation, expected, record)
        config, item, binding, resolution = _normalized(observation, record,
            expected=expected, root=root, observed_dispatch=observed_dispatch)
        restrictive_decision, restrictions = _restriction_state(binding, resolution)
        if not binding.bound or not binding.provenance_known or not resolution.applied:
            raise ValueError('normalized binding/adjudication unresolved: ' + repr(resolution.errors))
        support = (() if restrictive_decision and record.get('supporting_evidence', []) == []
                   and not observed_support else _supports(record, observation, observed_support, root))
        resolved = tuple(reason for reason in holds
            if hold_clearance(replace(item, hold_reasons=(reason,)), resolution, config).authorized)
        return PreparedAdjudication(expected, (), resolved, tuple(x for x in holds if x not in resolved),
                                     support, observation.result_bytes, observation.policy_bytes, observation.return_sha256,
                                     resolution.decision, restrictions)
    except (CWOError, ValueError, OSError, KeyError, TypeError, AttributeError, RecursionError) as exc:
        return PreparedAdjudication(expected, (str(exc),), (), holds, (), observation.result_bytes,
            observation.policy_bytes, observation.return_sha256, restrictive_decision, restrictions)


def _consumption_errors(prepared: PreparedAdjudication, expected: ExpectedContext) -> tuple[str, ...]:
    try:
        if prepared.context != expected or prepared.policy_bytes != _policies():
            return (*prepared.errors, 'prepared context/policy is stale for this pure consumption')
    except (CWOError, ValueError, OSError, RecursionError) as exc:
        return (*prepared.errors, str(exc))
    return prepared.errors


def synthesis_preparation(prepared: PreparedAdjudication, expected: ExpectedContext) -> dict[str, Any]:
    errors = _consumption_errors(prepared, expected)
    remaining = (_parse(prepared.evaluation_bytes)['hold_reasons'] if errors else prepared.remaining_holds)
    return {'scope': 'inert-preparation-only', 'inert_valid': not errors,
        'context': asdict(prepared.context), 'return_sha256': prepared.return_sha256,
        'evaluation_sha256': _sha(prepared.evaluation_bytes), 'policy_sha256': _sha(prepared.policy_bytes),
        'support_sha256': [_sha(raw) for raw in prepared.support_bytes],
        'evaluation': _parse(prepared.evaluation_bytes),
        'decision': (prepared.decision if not errors or prepared.decision in ('rejected', 'quarantined') else None),
        'adjudication_restrictions': list(prepared.adjudication_restrictions),
        'resolved_findings': [] if errors else list(prepared.resolved_findings),
        'remaining_holds': list(remaining), 'errors': list(errors), 'production_ready': False,
        'accepted_for_use': False, 'implementation_blocked': True,
        'production_blockers': list(MISSING_PRODUCTION)}


def status_preparation(prepared: PreparedAdjudication, expected: ExpectedContext) -> dict[str, Any]:
    # Serialize the SAME state; a status adapter cannot silently drop restrictions.
    return synthesis_preparation(prepared, expected)
