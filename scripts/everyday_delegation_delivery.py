"""Post a validated registered worker delivery for existing hand acceptance."""
from __future__ import annotations

import registered_n1_workflow as native
from cwo_core import candidate_identity, host_records, manual_delivery


def _need(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def _candidate(delivery, host, report):
    candidate = delivery.candidate
    candidate_identity.candidate_binding(candidate)
    errors = candidate_identity.baseline_binding_errors(candidate, delivery.chain)
    _need(not errors, 'The candidate must bind the original baseline: ' + '; '.join(errors))
    head = report['binding']['worker_identity']['head_commit']
    _need(delivery.root == host.worker and candidate['commit'] == candidate['base_commit'] == head,
          'The delivered candidate must use the original registered worker checkout and commit.')
    entries = {entry['path']: entry for entry in candidate['worktree_manifest']}
    outputs = {entry['path']: entry for entry in report['artifact']['files']}
    _need(entries.keys() == outputs.keys(), 'The candidate must contain exactly the original validated output paths.')
    scope = candidate['delivery_scope']['paths']
    for path, output in outputs.items():
        entry = entries[path]
        _need(entry['type'] == 'file' and entry['size'] == output['size'] and entry['sha256'] == output['sha256'],
              'The candidate bytes must match the original validated outputs.')
        _need(any(prefix == '.' or path == prefix or path.startswith(prefix + '/') for prefix in scope),
              'The candidate delivery scope must include each original validated output.')


def _original_delivery(workflow, delivery):
    _need(workflow._artifact is not None and workflow._publication_ready,
          'The original completed registered workflow is required for delivery.')
    workflow._require_execution()
    host, _token, report, _target, _policy = workflow._artifact
    _candidate(delivery, host, report)
    saved = workflow._load('custody.json')
    _need(saved['custody']['report'] == report and 'delivery_origin' in saved,
          'The original signed delegation custody is required for delivery.')
    attempt = saved['ledger']['attempt']
    _need(attempt['outcome'] == 'completed' and workflow.config.ledger.attempt(attempt['reservation_id']) == attempt,
          'The original completed native admission is required for delivery.')
    return saved['delivery_origin']


def verify_candidate(workflow, delivery: manual_delivery.Delivery, *, database: str) -> None:
    """Verify original completion and candidate fields before a lead posts its reference."""
    _need(type(workflow) is native.RegisteredN1Workflow, 'An original registered workflow is required for delivery.')
    with workflow._locked():
        origin = _original_delivery(workflow, delivery)
        manual_delivery.require_origin(host_records.configured_store(), delivery, origin, database=database)
        errors = candidate_identity.verify_candidate(delivery.candidate, delivery.root)
        _need(not errors, 'The original candidate changed before its reference was posted: ' + '; '.join(errors))


def record_delivery(workflow, args, summary: str) -> str:
    """Record the exact worker candidate for independent hand acceptance."""
    _need(type(workflow) is native.RegisteredN1Workflow, 'An original registered workflow is required for delivery.')
    delivery = manual_delivery.Delivery.from_args(args)
    with workflow._locked():
        return manual_delivery.post_delivery(delivery, summary, origin=_original_delivery(workflow, delivery))
