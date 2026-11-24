"""Project one standing, admitted lead assignment through ordinary internal routing."""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
import re

import prepare_local_admission as admission
from prepare_native_worker import build_native_worker_packet, load_native_worker_policy
from cwo_core.native_authority import canonical_authority_sha256 as digest
from cwo_core.routing import classify_work
from cwo_core.util import packet_payload_hash


def _need(condition, message):
    if not condition:
        raise ValueError(message)


@dataclass(frozen=True, slots=True, init=False)
class StandingDelegation:
    """Protected host inputs for one signed operation and frozen delivery baseline.

    Capability observations come from the embedding controller. A caller's task
    supplies only the original admitted text and can never select these inputs.
    """

    baseline_sha256: str
    database_sha256: str
    capability_bytes: bytes
    cache_bytes: bytes

    def __init__(self, *, baseline_sha256, database_sha256, capability_evidence, cache_profile):
        _need(type(baseline_sha256) is str and re.fullmatch(r'sha256:[0-9a-f]{64}', baseline_sha256),
              'Standing delegation requires the frozen delivery baseline digest.')
        _need(type(database_sha256) is str and re.fullmatch(r'[0-9a-f]{64}', database_sha256),
              'Standing delegation requires the original Beads database identity.')
        _need(type(capability_evidence) is dict and type(cache_profile) is dict,
              'Standing delegation requires original host capability and cache evidence.')
        object.__setattr__(self, 'baseline_sha256', baseline_sha256)
        object.__setattr__(self, 'database_sha256', database_sha256)
        object.__setattr__(self, 'capability_bytes', admission.reconciliation._encode(capability_evidence))
        object.__setattr__(self, 'cache_bytes', admission.reconciliation._encode(cache_profile))

    def approval_scope(self, *, receipt, operation, publication):
        """Return the exact action for a protected operator standing directive."""
        node = json.loads(receipt.selected_node_bytes)
        return {'purpose': 'registered-delegation-for-hand-review',
                'native_operation_sha256': digest(operation), 'publication_operation_sha256': digest(publication),
                'admission_sha256': admission._receipt_sha256(receipt),
                'request_sha256': sha256(receipt.request_bytes).hexdigest(),
                'bead_id': node['unit_estimate']['bead_id'], 'database_sha256': self.database_sha256,
                'baseline_sha256': self.baseline_sha256,
                'capability_sha256': sha256(self.capability_bytes).hexdigest(),
                'cache_sha256': sha256(self.cache_bytes).hexdigest(),
                'provider': 'openai', 'disclosure': 'provider-only', 'workspace': operation['workspace'],
                'target': publication['workspace'], 'admission_expires_at': receipt.expires_at}


def original_assignment(workflow, task, database):
    receipt = workflow._receipt
    node = json.loads(receipt.selected_node_bytes)
    _need(database == workflow.config._standing_delegation.database_sha256,
          'Delegation must use the original Beads database.')
    _need(type(task) is str and task == node['prompt'], 'Delegation must match the original admitted task.')
    return node


def _assignment(workflow, task, operation, publication, database):
    config = workflow.config
    receipt = workflow._receipt
    node = original_assignment(workflow, task, database)
    estimate = node['unit_estimate']
    _need(estimate['bead_id'] == config.route['parent_id'], 'Delegation Bead differs from original admission.')
    _need(estimate['write_paths'] == operation['write_paths'] == publication['write_paths']
          and operation['workspace'] == str(config.host.worker)
          and publication['workspace'] == str(config.host.target),
          'Delegation workspace, target or write scope differs from signed approval.')
    amounts = json.loads(receipt.amounts_bytes)
    _need(all(amounts[name] <= operation['reservation'][name] for name in ('runtime_seconds', 'tool_calls')),
          'Original admitted allowance exceeds the signed finite operation budget.')
    admission._live(receipt, config.ledger)
    return node, amounts


def _authority(workflow, node, amounts, scope, operation):
    config = workflow.config
    standing = config._standing_delegation
    spec = config.native_bundle[0]['registered_n1']
    context = {'bead_id': scope['bead_id'], 'wave_id': None,
               'fresh_segment': True, 'work_lineage_id': config.route['run_id']}
    budget = {'tool_calls_hard': amounts['tool_calls'], 'runtime_seconds_hard': amounts['runtime_seconds'],
              'allocation_before': 0, 'allocation_ceiling': operation['reservation']['sessions'],
              'terminal_reserve': 0, 'budget_reset_allowed': False}
    cache_profile = json.loads(standing.cache_bytes)
    identity = {'tool_profile_sha256': digest(spec['configuration_pins']),
                'control_image_sha256': spec['implementation_sha256'],
                'host_provenance_sha256': digest(config.host._initial['worker_identity'])}
    return {'version': 1, 'attempt_state': 'ready', 'bound_model': operation['model'], 'escalation': None,
            'fit_inputs': {'work_estimate': node['unit_estimate'], 'cache_profile': cache_profile,
                           'capability_evidence': json.loads(standing.capability_bytes), 'context': context,
                           'aggregate_budget': budget},
            'identity': identity,
            'provenance': {'source_sha256': scope['request_sha256'], 'context_sha256': digest(cache_profile),
                           'scope_sha256': digest(scope), 'candidate_sha256': node['unit_sha256']},
            'attempt': {'attempt_id': operation['operation_id'], 'bead_id': context['bead_id'],
                        'work_lineage_id': context['work_lineage_id'], 'fresh_segment': True,
                        'ownership_sha256': identity['host_provenance_sha256']}}


def _route(node, authority):
    estimate = node['unit_estimate']
    segments = [node['prompt'], *(blob['text'] for group in ('wrappers', 'attachments', 'sources') for blob in node[group])]
    result = classify_work('\n'.join(segments), text_segments=segments, file_paths=estimate['write_paths'],
                           current_authority=authority)
    _need(result['recommended_executor'] == 'internal_worker' and result['route'] == 'internal-worker'
          and result['share_boundary'] == 'no-outside-sharing' and not result['hard_stops'],
          'The normal router did not select an internal worker for this assignment.')
    _need(not result['peer_review_required'], 'This assignment requires original pre-dispatch peer review.')
    return result


def _packet(node, route, scope, operation, authority):
    basis = load_native_worker_policy()['lane_budgets']['implementation']
    budget = authority['fit_inputs']['aggregate_budget']
    overrides = {key: budget[key] for key in ('tool_calls_hard', 'runtime_seconds_hard')}
    for source in ('tool_calls', 'runtime_seconds'):
        overrides[source + '_soft'] = min(basis[source + '_soft'], budget[source + '_hard'])
    try:
        packet = build_native_worker_packet(bead_id=scope['bead_id'], lane='implementation',
            workdir=scope['workspace'], allowed_paths=operation['write_paths'],
            acceptance_checks=node['unit_estimate']['acceptance_checks'], packet_id=operation['operation_id'],
            budget_overrides=overrides, requested_model=operation['model'], operative_routing=route,
            current_authority=authority)
    except SystemExit as exc:
        raise ValueError(f'Native delegation packet refused: {exc}') from exc
    _need(packet['scope']['allowed_paths'] == operation['write_paths'], 'Native packet write scope differs from approval.')
    return packet


def authorize(workflow, task, operation, publication, *, database):
    """Sign the exact route input under the current protected standing mission."""
    node, amounts = _assignment(workflow, task, operation, publication, database)
    _route(node, None)
    scope, parent = workflow.config._standing_approval()
    authority = _authority(workflow, node, amounts, scope, operation)
    action = {'scope': scope, 'current_authority_sha256': digest(authority)}
    directive = workflow._sign(action, 'everyday-delegation-current-route', parent)
    workflow._verify(action, directive, parent)
    result = _route(node, authority)
    route, execution = result['operative_route'], node['execution']
    _need(route['dispatch_authorized'], f"Current delegation route refused: {route['stop_reason']}.")
    _need((route['selected_executor'], route['selected_model'], route['reasoning_effort'])
          == (execution['executor'], execution['model'], execution['effort'])
          and result['selected_executor']['provider_family'] == execution['provider'],
          'Ordinary routing differs from the original registered admission.')
    packet = _packet(node, route, scope, operation, authority)
    delegation = {'approval': action, 'directive': directive, 'route_sha256': route['route_sha256'],
                  'dispatch': {'bead_id': scope['bead_id'], 'executor': route['selected_executor'],
                               'provider_key': result['selected_executor']['provider_key'],
                               'packet_sha256': packet_payload_hash(packet)}}
    return delegation, packet


def current(workflow, delegation):
    """Recheck the original approval and admission before continued use."""
    config = workflow.config
    action = delegation['approval']
    scope, parent = config._standing_approval()
    _need(action['scope'] == scope, 'Original standing delegation scope changed.')
    receipt = workflow._receipt
    if config.ledger.current_time() >= receipt.expires_at and workflow._completed_delegation_custody():
        _need(admission._read_policy_bytes() == receipt.policy_bytes,
              'Current planning policy bytes changed after offline admission.')
    else:
        admission._live(receipt, config.ledger)
    workflow._verify(action, delegation['directive'], parent)
    return delegation
