"""Controller-owned authorization for the finite native worker qualification."""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import copy
import fcntl
import os
from pathlib import Path
import pwd
import re
import time

from cwo_core import host_records
from cwo_core import maintenance_authority as authority
from cwo_core.model_identities import MODEL_ROLES

CAMPAIGN = 'native-single-worker-host-qualification'
INITIAL_LIMIT = 10
RECHECK_LIMIT = 5
START_LIMIT = INITIAL_LIMIT + RECHECK_LIMIT
MODEL = 'gpt-6.2-sol'
EFFORT = 'xhigh'
TIER = 'default'
PROVIDER = 'openai'
APPROVAL_POLICY = 'never'
MODEL_SELECTION = 'qualification_model_selection'
_JOURNAL = 'starts.jsonl'
_HEADER = {'campaign': CAMPAIGN, 'version': 1}
_MAX_JOURNAL_BYTES = 8192
_DIGEST = re.compile(r'[0-9a-f]{64}')


class QualificationError(ValueError):
    """Qualification authorization, launch accounting or model binding refused."""


def _need(condition, message):
    if not condition:
        raise QualificationError(message)


def select_run_model(role):
    """Resolve one qualification role without changing normal model policy."""
    _need(role in MODEL_ROLES, 'Unknown qualification model role.')
    return {'model': MODEL, 'effort': EFFORT, 'service_tier': TIER, 'provider': PROVIDER}


def _model_selection():
    return {**select_run_model('sol'),
            'roles': {role: select_run_model(role)['model'] for role in MODEL_ROLES},
            'campaign': CAMPAIGN}


def bind_model_selection(spec):
    """Build the qualification spec before preparing admission and signing the operation."""
    selection = _model_selection()
    bound = copy.deepcopy(spec)
    bound.update({key: selection[key] for key in ('model', 'effort', 'provider')})
    bound[MODEL_SELECTION] = selection
    return bound


def require_model_selection(spec, plan, operation):
    selection = _model_selection()
    _need(spec.get(MODEL_SELECTION) == selection
          and all(spec.get(key) == selection[key] for key in ('model', 'effort', 'provider')),
          'Exact qualification model, provider, effort, tier and role routing are required.')
    _need(len(plan['children']) == plan['required_session_count'] == 1
          and operation['reservation']['sessions'] == operation['reservation']['max_concurrency'] == 1,
          'Qualification requires one registered worker and one reserved session.')


def thread_selectors():
    return {'modelProvider': PROVIDER, 'serviceTier': TIER}


FINITE_TOOL_NAMESPACE = 'cwo_finite'


def disabled_features():
    """Remove built-in shell and exec from the qualification thread configuration."""
    return dict.fromkeys(('shell_tool', 'unified_exec', 'unified_exec_tty',
                          'code_mode_only_strict_3p_tools'), False)


def configuration_features():
    return {**disabled_features(),
            'code_mode': {'enabled': True, 'direct_only_tool_namespaces': [FINITE_TOOL_NAMESPACE]}}


def require_executable_schema(executable, digest):
    """Check the original signed executable in the fixed offline schema namespace."""
    # The selected probe imports the registered pipe backend for its other
    # operations. Import it only after the factory module has initialized.
    import selected_native_containment as containment

    binary = Path(executable)
    try:
        identity = containment._observe_binary(binary)
        _need(identity[0] == digest, 'The qualification schema executable differs from the signed binary.')
        containment.check_codex_capabilities(binary, n1_qualification=True,
            launcher=lambda workspace: containment._schema_launcher(workspace, binary, identity))
    except (containment.CapabilityError, containment.SelectedProbeError) as exc:
        raise QualificationError(str(exc)) from exc


def check_thread_model(params, response):
    _need(all(params.get(key) == value for key, value in thread_selectors().items())
          and response.get('reasoningEffort') == EFFORT and response.get('serviceTier') == TIER,
          'Actual qualification reasoning effort or service tier differs.')
    _need(response.get('thread', {}).get('ephemeral') is False,
          'The qualification thread must use its private persistent rollout.')


def _digest(value):
    return type(value) is str and _DIGEST.fullmatch(value) is not None


@dataclass(frozen=True, slots=True)
class _StartRequest:
    operation_sha256: str
    expires_at: int
    repair_sha256: str | None

    def check(self):
        _need(_digest(self.operation_sha256)
              and (self.repair_sha256 is None or _digest(self.repair_sha256)),
              'Exact qualification operation and optional repair digests are required.')
        _need(type(self.expires_at) is int and 0 < self.expires_at < 253402300800,
              'Qualification expiry must be a UTC epoch second.')

    def require_current(self):
        self.check()
        _need(time.time() < self.expires_at, 'The qualification permit has expired.')

    def authorization(self):
        self.check()
        return {'authorization_type': 'registered-n1-qualification-permit', **_HEADER,
                'operation_sha256': self.operation_sha256, 'expires_at': self.expires_at,
                'repair_sha256': self.repair_sha256}


def sign_qualification_permit(*, operation_sha256, expires_at, verification_key, actor_id,
                              identity_source, mission_directive_sha256, repair_sha256=None):
    """Sign already-adopted qualification consent in the protected controller."""
    body = _StartRequest(operation_sha256, expires_at, repair_sha256).authorization()
    directive = authority.sign_controller_directive(
        verification_key=verification_key, actor_id=actor_id, identity_source=identity_source,
        action_sha256=authority.canonical_authority_sha256(body),
        directive_id=CAMPAIGN, parent_receipt_sha256=mission_directive_sha256)
    return {'authorization': body, 'directive': directive}


def verify_qualification_permit(value, capability, verifier):
    """Authenticate one explicit operation permit with the original operator verifier."""
    authority.require_maintenance_operation(capability, verifier=verifier)
    _need(type(value) is dict and set(value) == {'authorization', 'directive'}
          and type(value['authorization']) is dict, 'A signed qualification permit is required.')
    body = value['authorization']
    request = _StartRequest(capability.operation_sha256, body.get('expires_at'), body.get('repair_sha256'))
    _need(request.authorization() == body and type(body.get('version')) is int,
          'The qualification permit does not bind this campaign and operation.')
    authority._directive(value['directive'], key=verifier._key, actor=verifier._actor,
        identity=verifier._identity, action=authority.canonical_authority_sha256(body),
        parent=verifier._directive_hash)
    request.require_current()
    return request


def _campaign_directory():
    # An installed controller uses the same custody across source clones and
    # release updates. A worktree, environment or run input cannot select it.
    return Path(pwd.getpwuid(os.getuid()).pw_dir) / '.local' / 'state' / 'cwo' / CAMPAIGN


def campaign_directory():
    """Physical custody location for registered namespace exclusion."""
    return _campaign_directory()


def initialize_campaign():
    """One-time trusted controller enrollment. A partial enrollment fails closed."""
    directory = _campaign_directory()
    parent_fd = host_records._directory(directory.parent, create=True, private=True)
    try:
        os.mkdir(directory.name, mode=0o700, dir_fd=parent_fd)
        os.fsync(parent_fd)
    finally:
        os.close(parent_fd)
    directory_fd = host_records._directory(directory, private=True)
    try:
        host_records._write_at(directory_fd, _JOURNAL, host_records._json(_HEADER))
    finally:
        os.close(directory_fd)


@contextmanager
def _journal():
    flags = os.O_RDWR | os.O_APPEND | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
    try:
        directory = host_records._directory(_campaign_directory(), private=True)
        with authority._state_descriptor(directory):
            descriptor = os.open(_JOURNAL, flags, dir_fd=directory)
            with authority._state_descriptor(descriptor):
                authority.MaintenanceStateStore._private_file(descriptor)
                fcntl.flock(descriptor, fcntl.LOCK_EX)
                yield descriptor
    except (OSError, host_records.HostRecordError, authority.MaintenanceAuthorityError) as exc:
        raise QualificationError('Qualification campaign accounting is unavailable or unsafe.') from exc


def _check_row(row, expected_sequence, previous):
    _need(set(row) == {'sequence', 'operation_sha256', 'repair_sha256', 'started_at'}
          and type(row['sequence']) is int and row['sequence'] == expected_sequence
          and type(row['started_at']) is int and row['started_at'] > 0
          and _digest(row['operation_sha256']) and row['operation_sha256'] not in previous
          and (row['repair_sha256'] is None or _digest(row['repair_sha256'])),
          'Qualification campaign start record is malformed or duplicated.')


def _read_starts(descriptor):
    with os.fdopen(os.dup(descriptor), 'rb') as stream:
        raw = stream.read(_MAX_JOURNAL_BYTES + 1)
    lines = raw.splitlines(keepends=True)
    _need(0 < len(lines) <= START_LIMIT + 1 and len(raw) <= _MAX_JOURNAL_BYTES
          and lines[0] == host_records._json(_HEADER), 'Qualification campaign journal is malformed.')
    starts = {}
    for index, line in enumerate(lines[1:], 1):
        row = host_records._parse(line)
        _need(line == host_records._json(row), 'Qualification campaign record is incomplete.')
        _check_row(row, index, starts)
        starts[row['operation_sha256']] = row
    usage = _usage(starts)
    _need(usage['initial'] <= INITIAL_LIMIT and usage['rechecks'] <= RECHECK_LIMIT,
          'Qualification campaign accounting exceeds its bounds.')
    return starts


def _usage(starts):
    initial = sum(row['repair_sha256'] is None for row in starts.values())
    return {'initial': initial, 'rechecks': len(starts) - initial, 'total': len(starts)}


def campaign_usage():
    """Read durable started-run counts without using or extending a permit."""
    with _journal() as descriptor:
        return _usage(_read_starts(descriptor))


def _check_available(request, starts):
    _need(request.operation_sha256 not in starts, 'This qualification operation already started.')
    usage = _usage(starts)
    _need(usage['total'] < START_LIMIT, 'The qualification campaign start limit was reached.')
    if request.repair_sha256 is None:
        _need(usage['initial'] < INITIAL_LIMIT, 'The initial qualification start limit was reached.')
    else:
        _need(usage['initial'] > 0 and usage['rechecks'] < RECHECK_LIMIT,
              'The qualification recheck start limit or required initial run is unavailable.')


def require_available(request, started):
    with _journal() as descriptor:
        request.require_current()
        starts = _read_starts(descriptor)
        if started is None:
            _check_available(request, starts)
        else:
            _need(starts.get(request.operation_sha256) == started,
                  'The original qualification start record changed.')


def _campaign_start(request):
    """Fsync before command release. Unknown starts remain charged across restarts."""
    with _journal() as descriptor:
        starts = _read_starts(descriptor)
        _check_available(request, starts)
        request.require_current()
        row = {'sequence': len(starts) + 1, 'operation_sha256': request.operation_sha256,
               'repair_sha256': request.repair_sha256, 'started_at': int(time.time())}
        raw = host_records._json(row)
        _need(os.write(descriptor, raw) == len(raw), 'The qualification start record is incomplete.')
        os.fsync(descriptor)
        request.require_current()
        return row
