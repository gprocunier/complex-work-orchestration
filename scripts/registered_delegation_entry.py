"""Retain and reopen protected standing approvals for the installed lead."""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import asdict, fields
import json
import os
from pathlib import Path
import stat

import delegate_internal_work as delegation
import prepare_local_admission as admission
import registered_n1_workflow as native
from cwo_core import host_records, manual_delivery, workspace_capture


_RECONCILIATION = admission.reconciliation
_ADMISSION_FIELDS = tuple(item.name for item in fields(admission.PreparedAdmission) if item.init)
_APPROVAL_FIELDS = {'version', 'mission', 'mission_directive', 'actor_id', 'identity_source', 'factory_registry',
                    'native_bundle', 'publication_bundle', 'policy_specification', 'receipt', 'authority_state',
                    'controller_state', 'publication_state', 'standing_delegation', 'standing_directive'}
_KEY_DIRECTORY = 'standing-delegation-authority'
_RETIRED = 'retired-delegation'
_MAX_KEY_BYTES = 4096
_VERSION = 1


class StandingApprovalMissing(ValueError):
    """The protected store has no approval for the exact assignment."""


def _name(project, database, bead, task, baseline):
    selection = {'project': str(project), 'database_sha256': database, 'bead': bead,
                 'task': task, 'baseline_sha256': baseline}
    return 'standing-delegation-' + delegation.digest(selection) + '.json'


def _key_name(project, database):
    return delegation.digest({'project': str(project), 'database_sha256': database}) + '.key'


def _protected_store(*roots):
    store = host_records.configured_store()
    store.require_outside_worker_roots(roots)
    scripts = Path(__file__).resolve().parent
    native.boundary.require_private_roots((store.state_root,), visible_paths=(
        scripts, scripts.parent / 'policy', scripts.parent / 'schemas'))
    return store


@contextmanager
def _key_directory(store, *, create=False):
    with store._state(create=create) as parent:
        if create:
            try:
                os.mkdir(_KEY_DIRECTORY, 0o700, dir_fd=parent)
                os.fsync(parent)
            except FileExistsError:
                pass
        directory = os.open(_KEY_DIRECTORY, native.H._FLAGS, dir_fd=parent)
        try:
            host_records.HostRecordStore._check_record_directory(directory)
            yield directory
        finally:
            os.close(directory)


def _admission_data(receipt):
    data = asdict(receipt)
    return {name: (data[name].decode('utf-8') if name.endswith('_bytes') else data[name])
            for name in _ADMISSION_FIELDS}


def _coordinates(path):
    return [str(path), native.H._identity(path)]


def _approval_data(config):
    standing, verifier = config._standing_delegation, config.verifier
    project = {} if standing.project is None else {'project': standing.project}
    return {'version': _VERSION, 'mission': verifier._mission, 'mission_directive': json.loads(config._mission_directive),
            'actor_id': verifier._actor, 'identity_source': verifier._identity,
            'factory_registry': verifier._factories,
            'native_bundle': config.native_bundle, 'publication_bundle': config.publication_bundle,
            'policy_specification': config.policy.report, 'receipt': _admission_data(config.receipt),
            'authority_state': _coordinates(config.store.directory), 'controller_state': _coordinates(config.state),
            'publication_state': _coordinates(config.publication_state),
            'standing_delegation': {'baseline_sha256': standing.baseline_sha256,
                'database_sha256': standing.database_sha256, 'capability_evidence': json.loads(standing.capability_bytes),
                'cache_profile': json.loads(standing.cache_bytes), **project},
            'standing_directive': json.loads(config._standing_directive)}


def _sealed_approval(config):
    approval = _approval_data(config)
    verifier = config.verifier
    standing = approval['standing_directive']
    digest = delegation.digest(approval)
    custody = native.A.sign_controller_directive(verification_key=verifier._key, actor_id=verifier._actor,
        identity_source=verifier._identity, action_sha256=digest, directive_id='standing-delegation-custody',
        parent_receipt_sha256=delegation.digest(standing), issued_at=standing['issued_at'], nonce=digest)
    return _RECONCILIATION._encode({'approval': approval, 'custody_directive': custody})


def _write_once(directory, name, raw, limit, conflict):
    try:
        host_records._write_at(directory, name, raw, atomic_create=True)
    except FileExistsError:
        delegation._need(host_records._read_at(directory, name, limit) == raw, conflict)


def _write_approval(store, project, database, name, raw, key, *, replaces=None):
    delegation._need(len(raw) <= _RECONCILIATION.MAX_BYTES, 'Protected standing approval is too large.')
    delegation._need(0 < len(key) <= _MAX_KEY_BYTES, 'Protected controller key is outside its bound.')
    with _key_directory(store, create=True) as directory:
        _write_once(directory, _key_name(project, database), key, _MAX_KEY_BYTES,
                    'The project already has a different protected controller key.')
    if replaces is not None:
        _replace_approval(store, project, name, raw, key, replaces)
        return
    with store._state() as directory:
        _write_once(directory, name, raw, _RECONCILIATION.MAX_BYTES,
                    'Another original approval already matches this assignment.')


def retain_approved_assignment(workflow, *, replaces=None):
    """Publish the protected controller's already-signed assignment for the normal lead entry."""
    delegation._need(type(workflow) is native.RegisteredN1Workflow
                     and workflow.config._standing_delegation is not None,
                     'An original configured standing delegation is required.')
    config = workflow.config
    workflow._require_admission_inputs()
    delegation._need(workflow._production_selected(), 'An original registered production assignment is required.')
    workflow.verifier._current()
    admission._live(config.receipt, config.ledger)
    scope, _parent = config._standing_approval()
    project = config.project
    database, _run_bd = manual_delivery.project_beads(project)
    node = json.loads(config.receipt.selected_node_bytes)
    delegation.original_assignment(workflow, node['prompt'], database)
    name = _name(project, database, scope['bead_id'], node['prompt'], scope['baseline_sha256'])
    store = _protected_store(project, config.host.target, config.host.worker,
                             config.host.state / 'fake-server' / 'codex-home')
    _write_approval(store, project, database, name, _sealed_approval(config), workflow.verifier._key, replaces=replaces)


def _read_approval(store, name):
    try:
        with store._state() as directory:
            raw = host_records._read_at(directory, name, _RECONCILIATION.MAX_BYTES)
    except host_records.HostRecordError as exc:
        if isinstance(exc.__cause__, FileNotFoundError):
            raise StandingApprovalMissing('No protected standing approval matches this project, task and baseline.') from None
        raise
    return _RECONCILIATION._decode(raw)


def _read_key(store, project, database):
    try:
        with _key_directory(store) as directory:
            return host_records._read_at(directory, _key_name(project, database), _MAX_KEY_BYTES)
    except host_records.HostRecordError as exc:
        raise ValueError('The original protected project controller key is unavailable.') from exc


def _receipt(data):
    _RECONCILIATION._exact(data, set(_ADMISSION_FIELDS), 'Original admission receipt')
    receipt = admission.PreparedAdmission(**{name: (value.encode('utf-8') if name.endswith('_bytes') else value)
                                              for name, value in data.items()})
    return native.R.admitted._admission_snapshot(receipt)


def _original_path(coordinates):
    path, identity = coordinates
    path = native.H._path(path)
    delegation._need(native.H._identity(path) == identity, 'Original approval custody changed identity.')
    return path


def _verify_approval(envelope, key):
    _RECONCILIATION._exact(envelope, {'approval', 'custody_directive'}, 'Protected standing approval envelope')
    record = envelope['approval']
    _RECONCILIATION._exact(record, _APPROVAL_FIELDS, 'Original protected standing approval')
    delegation._need(type(record['version']) is int and record['version'] == _VERSION,
                     'Unsupported protected standing approval.')
    parent = delegation.digest(record['standing_directive'])
    try:
        native.A._directive(envelope['custody_directive'], key=key, actor=record['actor_id'],
            identity=record['identity_source'], action=delegation.digest(record), parent=parent)
    except native.A.MaintenanceAuthorityError as exc:
        raise ValueError('The retained approval does not match the protected project controller.') from exc
    return record


def _configuration(record, project, key):
    native_bundle = record['native_bundle']
    custody = native_bundle[0]['registered_n1']['custody']
    standing = delegation.StandingDelegation(**record['standing_delegation'])
    target = native.H._path(custody['target'])
    delegation._need((standing.project or str(target)) == str(project),
                     'Original approval belongs to another project checkout.')
    _protected_store(project, target, custody['worker'], Path(custody['state']) / 'fake-server' / 'codex-home')
    mission = record['mission']
    state_store = native.A.MaintenanceStateStore(_original_path(record['authority_state']),
        mission_id=mission['mission_id'], mission_sha256=native.A.mission_sha256(mission))
    receipt = _receipt(record['receipt'])
    host = native.H.OfflineN1Host(custody['state'], target, custody['worker'])
    return native.ControllerConfiguration(mission=mission, mission_directive=record['mission_directive'],
        verification_key=key, actor_id=record['actor_id'],
        identity_source=record['identity_source'], factory_registry=record['factory_registry'], state_store=state_store,
        native_bundle=native_bundle, publication_bundle=record['publication_bundle'],
        policy_specification=record['policy_specification'], receipt=receipt, route=json.loads(receipt.route_input_bytes),
        node_id=receipt.node_id, ledger=admission.ledger_api.InvocationLedger(custody['ledger']), host=host,
        controller_state=_original_path(record['controller_state']),
        publication_state=_original_path(record['publication_state']), evidence=None,
        standing_delegation=standing,
        standing_directive=record['standing_directive'])


def _original_workflow(envelope, project, key):
    try:
        return native.RegisteredN1Workflow(_configuration(_verify_approval(envelope, key), project, key))
    except (AttributeError, IndexError, KeyError, TypeError) as exc:
        raise ValueError('Protected standing approval is incomplete.') from exc


def _renewable(workflow, directory):
    config = workflow.config
    entries = os.listdir(directory)
    if entries:
        if entries != [_RETIRED]:
            return False
        marker = os.stat(_RETIRED, dir_fd=directory, follow_symlinks=False)
        if marker.st_mode != (stat.S_IFDIR | 0o700) or marker.st_uid != os.getuid():
            return False
    elif config.ledger.current_time() < config.receipt.expires_at:
        return False
    try:
        config.ledger.root.lstat()
    except FileNotFoundError:
        return not workflow.verifier._current()['operations']
    return False


def renewable(workflow):
    """Check whether an expired approval can be replaced without losing activity."""
    config = workflow.config
    if config.ledger.current_time() < config.receipt.expires_at and not (config.state / _RETIRED).is_dir():
        return False
    with workflow._locked(), workflow._state_directory() as directory:
        return _renewable(workflow, directory)


def _replace_approval(store, project, name, raw, key, replaces):
    original = _read_approval(store, name)
    changed = 'The original approval changed before renewal.'
    delegation._need(delegation.digest(original) == replaces, changed)
    workflow = _original_workflow(original, project, key)
    with workflow._locked(), workflow._state_directory() as custody:
        delegation._need(delegation.digest(_read_approval(store, name)) == replaces, changed)
        delegation._need(_renewable(workflow, custody), 'The original approval now requires reconciliation.')
        # Native dispatch requires an empty controller directory under this
        # same lock. Keep the fence even if publication fails or time rolls back.
        if _RETIRED not in os.listdir(custody):
            os.mkdir(_RETIRED, 0o700, dir_fd=custody)
        os.fsync(custody)
        with store._state() as directory:
            host_records._write_at(directory, name, raw, replace=True)


def _project_assignment(project, database, task, chain):
    store = _protected_store(project)
    name = _name(project, database, chain['bead_id'], task, chain['digest'])
    envelope = _read_approval(store, name)
    workflow = _original_workflow(envelope, project, _read_key(store, project, database))
    delegation.original_assignment(workflow, task, database)
    return workflow, envelope


def open_project_assignment(project, database, task, chain):
    """Reopen the original configured workflow in the selected project."""
    workflow, _envelope = _project_assignment(project, database, task, chain)
    return workflow


def open_foreground_assignment(project, database, task, chain):
    """Identify the sealed predecessor when the foreground can renew approval."""
    workflow, envelope = _project_assignment(project, database, task, chain)
    return workflow, delegation.digest(envelope) if renewable(workflow) else None


def open_assignment(task, chain):
    """Select by normal project identity and reopen the original configured workflow."""
    project = workspace_capture.worktree_top_level(Path.cwd())
    delegation._need(project is not None, 'Run delegate from the original project checkout.')
    project = Path(project)
    database, _run_bd = manual_delivery.project_beads(project)
    return open_project_assignment(project, database, task, chain)
