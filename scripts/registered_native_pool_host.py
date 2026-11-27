"""Read signed observations for an original registered serial pool."""
from __future__ import annotations

from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
import stat
import time

import registered_n1_workflow as W
from cwo_core import native_live_availability as live_availability
from cwo_core.host_records import configured_store

R, H = W.R, W.H
_need, _copy, _encode = W._need, W._copy, W._encode
_WORKFLOW = W.RegisteredN1Workflow
_CONFIGURATION = W.ControllerConfiguration
_METHODS = R.admitted._method_table(_WORKFLOW)
_CONFIG_METHODS = R.admitted._method_table(_CONFIGURATION)


def validate_structure(request):
    """Pure local parsing: zero imports selected by input, claims or model calls."""
    _need(type(request) is dict and set(request) == {'version', 'mode', 'pool_id', 'workers'},
          'Only structural pool client fields are supported; caller factories/imports are refused.')
    _need(type(request['version']) is int and request['version'] == 1
          and request['mode'] in ('validate-only', 'execute'), 'Unsupported pool client version or mode.')
    _need(R.admission.ledger_api._is_id(request['pool_id']), 'A bounded pool identity is required.')
    workers = request['workers']
    _need(type(workers) is list and 1 <= len(workers) <= 3
          and all(R.admission.ledger_api._is_id(item) for item in workers)
          and len(set(workers)) == len(workers), 'Exactly N=1..3 distinct worker identities are required.')
    return {'structurally_valid': True, 'authority_validated': False, 'model_calls': 0,
            'dispatch_authorized': False, **R._FALSE}


def _read_metadata(path, cap):
    # Git names use Git's grammar, not the narrower output artifact grammar.
    with H._directory(path.parent) as directory:
        kind, data, before = H.workspace_capture.read_at(directory, path.name, cap)
        _need(kind == 'file' and before is not None and before.st_nlink == 1,
              'A single regular Git metadata file is required.')
        after = os.stat(path.name, dir_fd=directory, follow_symlinks=False)
        _need(H._file_mark(before) == H._file_mark(after) and len(data) == after.st_size,
              'Git metadata changed during its bounded read.')
        return data


def _metadata_image(repository):
    """Bounded original-reader snapshot of metadata that workers cannot write."""
    H._metadata(repository)
    root = repository / '.git'
    image, remaining = {}, 16 * 1024 * 1024
    for path in sorted(root.rglob('*')):
        if path.is_file():
            data = _read_metadata(path, remaining)
            remaining -= len(data)
            _need(remaining >= 0, 'Pool Git metadata exceeds its byte bound.')
            image[str(path.relative_to(root))] = hashlib.sha256(data).hexdigest()
    return R.canonical_sha256(image)


def _worktree_ownership(root):
    """Reject writable inode aliases before any worker or publisher effect."""
    pending, seen = [root], set()
    deadline, remaining = time.monotonic() + 10, 20_000
    while pending:
        path = pending.pop()
        with H._directory(path) as directory:
            info = os.fstat(directory)
            seen.add((info.st_dev, info.st_ino))
            with os.scandir(directory) as entries:
                for entry in entries:
                    if path == root and entry.name == '.git':
                        continue
                    info = entry.stat(follow_symlinks=False)
                    seen.add((info.st_dev, info.st_ino))
                    if stat.S_ISDIR(info.st_mode):
                        pending.append(path / entry.name)
                    else:
                        _need(info.st_nlink == 1, 'Hard linked worktree files violate distinct write ownership.')
                    remaining -= 1
                    _need(remaining >= 0 and time.monotonic() <= deadline,
                          'Worktree ownership exceeds its inspection bound.')
    return seen


class PoolConfiguration:
    """Protected installed bootstrap, never deserialized from a client request.

    Each original controller owns its signed v8 native/publication operations,
    exact native-policy profile and isolated stores. The original finite ledger,
    enable flag and worker selections are retained in the signed record binding.
    """

    def __init__(self, *, pool_id, controllers, state_directory, ledger, limits, enabled=False,
                 controlled_failure_workers=()):
        self.pool_id, self.enabled = pool_id, enabled
        self.host_records = configured_store()
        _need(type(controllers) is dict, 'Protected named controllers are required.')
        self.workers, self.controllers = tuple(controllers), tuple(controllers.values())
        _need(type(controlled_failure_workers) in (tuple, list), 'Protected failure producer selection is required.')
        self.controlled_failure_workers = tuple(controlled_failure_workers)
        self.ledger, self.limits = ledger, _copy(limits)
        _need(not R.admission.ledger_api._limits_errors(self.limits, 'pool limits'), 'Finite aggregate resource limits required.')
        self._ledger_handles = R.admitted._ledger_handles(ledger)
        self.state = R._private(state_directory)
        self.identity = H._identity(self.state)
        self.workflows = tuple(_WORKFLOW(c) for c in self.controllers)
        validate_structure(self.request('validate-only'))
        _need(type(enabled) is bool, 'The protected enable switch must be Boolean.')
        self.check()
        self.binding = self.describe()

    def request(self, mode):
        return {'version': 1, 'mode': mode, 'pool_id': self.pool_id,
                'workers': list(self.workers)}

    def check(self):
        _need(1 <= len(self.controllers) <= 3, 'The finite cohort supports only N=1..3.')
        self.host_records.assert_worker_roots_excluded(tuple(
            root for controller in self.controllers for root in (
                controller.host.worker, controller.host.state / 'fake-server' / 'codex-home')))
        self._failure_selection()
        _need(H._identity(R._private(self.state)) == self.identity, 'Pool custody directory changed.')
        roots, metadata, ownership = [self.state, self.ledger.root], set(), set()
        R.admitted._original_methods(self.ledger, R.admission.ledger_api.InvocationLedger, R.admitted._LEDGER_METHODS)
        _need(R.admitted._ledger_handles(self.ledger) == self._ledger_handles, 'Aggregate ledger binding changed.')
        for c, workflow in zip(self.controllers, self.workflows):
            R.admitted._original_methods(c, _CONFIGURATION, _CONFIG_METHODS)
            R.admitted._original_methods(workflow, _WORKFLOW, _METHODS)
            _need(workflow.config is c, 'Original protected controller binding changed.')
            c._bootstrap()  # Actual approved v8 signature/registry/storage checks.
            receipt = R.admitted._admission_snapshot(c.receipt)
            R.admitted._require_primary(receipt)  # No implicit retry/fallback/input widening.
            fresh = R.admission.prepare(c.route, c.node_id, now=receipt.issued_at, expires_at=receipt.expires_at)
            _need(R.admission._same_admission(receipt, fresh), 'Original whole-route admission differs.')
            plan, _operation, _authority = W._operation(c.verifier, c.native_bundle)
            R._profile(plan['registered_n1'])
            R._configuration(plan['registered_n1'], c.host.worker)
            roots.extend((c.state, c.publication_state, c.host.state, c.host.worker,
                          c.host.target, c.store.directory, c.ledger.root))
            for repository in (c.host.worker, c.host.target):
                observed = H._metadata(repository)
                _need(not metadata.intersection(observed), 'Workers cannot share repository metadata.')
                metadata.update(observed)
                observed.update(_worktree_ownership(repository))
                _need(not ownership.intersection(observed), 'Worker and target write ownership overlaps.')
                ownership.update(observed)
        R._disjoint(roots)
        amounts = [json.loads(c.receipt.amounts_bytes) for c in self.controllers]
        _need(all(set(amount) == set(self.limits) for amount in amounts), 'Aggregate dimensions must cover each actual N1 allowance.')
        _need(all(sum(amount[key] for amount in amounts) <= limit for key, limit in self.limits.items()),
              'Whole cohort exceeds the protected finite aggregate allowance.')

    def _failure_selection(self):
        selected = self.controlled_failure_workers
        _need(type(selected) is tuple and all(type(worker) is str for worker in selected),
              'Protected failure producers require exact configured worker identities.')
        _need(len(set(selected)) == len(selected) and set(selected) <= set(self.workers),
              'Controlled failure producers must select distinct original members.')

    def describe(self):
        return {'pool_id': self.pool_id, 'enabled': self.enabled,
                'state': [str(self.state), self.identity],
                'source_image': R.implementation_sha256(),
                'workers': list(self.workers), 'limits': self.limits, 'ledger': str(self.ledger.root),
                'controlled_failure_workers': list(self.controlled_failure_workers),
                'members': [workflow._action() for workflow in self.workflows],
                'git_images': [[_metadata_image(c.host.worker), _metadata_image(c.host.target)] for c in self.controllers]}


class RegisteredNativePoolHost:
    """Validate the exact cohort and read its signed records."""

    def __init__(self, configuration):
        _need(type(configuration) is PoolConfiguration, 'Protected pool configuration is required.')
        self.config = configuration

    def _current(self):
        self.config.check()
        _need(self.config.describe() == self.config.binding, 'Protected pool source or configuration changed.')

    def _request(self, request):
        validate_structure(request)
        _need(request == self.config.request(request['mode']), 'Client must select the exact protected pool cohort.')

    def validate_authority(self, request):
        self._request(request)
        self._current()
        for workflow in self.config.workflows:
            self._validate_member_authority(workflow)
        return {**validate_structure(request), 'authority_validated': True}

    @staticmethod
    def _validate_member_authority(workflow):
        c = workflow.config
        R.admission._live(c.receipt, c.ledger)
        # The original verifier checks availability without claiming. Retire only
        # these fresh, unused process-local capabilities; expose none to clients.
        capabilities = []
        try:
            for bundle in (c.native_bundle, c.publication_bundle):
                capabilities.append(c.verifier.verify_operation(*bundle))
        finally:
            for capability in capabilities:
                c.verifier._capabilities.pop(capability._identity, None)

    def adopt_execution(self, *, adoption_id, disclosure_consents):
        raise ValueError("registered-serial-pool-execution-retired")

    @contextmanager
    def _locked(self):
        self._current()
        workflow = self.config.workflows[0]
        with workflow._descriptor(os.open(self.config.state, H._FLAGS)) as fd:
            self._require_directory(fd)
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self._require_directory(fd)
            primary = None
            try:
                yield fd
            except BaseException as failure:
                primary = failure
                raise
            finally:
                try:
                    fcntl.flock(fd, fcntl.LOCK_UN)
                except BaseException as secondary:
                    if primary is None:
                        raise
                    R.admission.ledger_api.add_failure_note(primary, 'Pool unlock failed: ' + type(secondary).__name__)

    def _require_directory(self, directory):
        info = os.fstat(directory)
        _need([info.st_dev, info.st_ino, info.st_mode] == self.config.identity,
              'Pool state descriptor changed.')
        _need(H._identity(R._private(self.config.state)) == self.config.identity,
              'Pool state directory changed.')

    def _load(self, name):
        workflow = self.config.workflows[0]
        record = json.loads(H._immutable_read(self.config.state, name, H.MAX_RECORD_BYTES))
        workflow._verify(record['body'], record['directive'], workflow.verifier._mission_hash)
        return record['body']

    def run(self, request):
        if type(request) is dict and request.get('mode') == 'execute':
            live_availability.require_pool_live()
            live_availability.require_n1_live()
            validate_structure(request)
            raise ValueError("registered-serial-pool-execution-retired")
        self._request(request)
        return self.validate_authority(request)

    def status(self):
        """Authenticate observations only; never dispatch, release or publish."""
        with self._locked():
            _need(self._load('intent.json') == self.config.binding, 'Original pool intent binding changed.')
            if not (self.config.state / 'terminal.json').exists():
                return {'pool_id': self.config.pool_id, 'reconciliation_required': True,
                        'redispatch_permitted': False, **R._FALSE}
            return self._load('terminal.json')
