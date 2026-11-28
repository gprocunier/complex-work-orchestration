"""Controller-owned authorization for the finite native worker qualification."""

from __future__ import annotations

from collections.abc import Iterable
from contextlib import contextmanager
from dataclasses import dataclass
import copy
import fcntl
import os
from pathlib import Path
import pwd
import re
import shutil
import stat
import tempfile
import time
import uuid

from cwo_core import host_records
from cwo_core import maintenance_authority as authority
from cwo_core import native_session_boundary
from cwo_core.model_identities import MODEL_ROLES

CAMPAIGN = 'native-single-worker-host-qualification'
START_LIMIT = 20
_PERMIT_VERSION = 2
MODEL = 'gpt-6.2-sol'
EFFORT = 'xhigh'
TIER = 'default'
PROVIDER = 'openai'
APPROVAL_POLICY = 'never'
HISTORY_MODE = 'legacy'
MODEL_SELECTION = 'qualification_model_selection'
AUTHENTICATION = 'qualification_authentication'
MANAGED_LOGIN = 'codex-managed-file'
LOGIN_MOUNT = Path('/cwo/managed-login')
_JOURNAL = 'starts.jsonl'
_LOGIN_LEASE = 'managed-login.json'
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


def bind_model_selection(spec, *, managed_login=False):
    """Build the qualification spec before preparing admission and signing the operation."""
    selection = _model_selection()
    bound = copy.deepcopy(spec)
    bound.update({key: selection[key] for key in ('model', 'effort', 'provider')})
    bound[MODEL_SELECTION] = selection
    if managed_login:
        bound[AUTHENTICATION] = MANAGED_LOGIN
    return bound


def require_authentication_selection(spec):
    _need(AUTHENTICATION not in spec or spec[AUTHENTICATION] == MANAGED_LOGIN,
          'Unsupported qualification authentication mode.')


def _login_name(slot, first, suffix=''):
    _need(type(slot) is int and 1 <= slot <= 3, 'A dedicated qualification login slot is required.')
    return first + ('' if slot == 1 else '-' + str(slot)) + suffix


def _controller_home():
    return Path(pwd.getpwuid(os.getuid()).pw_dir)


def managed_login_home(slot=1):
    """The controller's dedicated login is independent of caller environment and spec paths."""
    return _controller_home() / _login_name(slot, '.cwo-qual-codex')


def worker_login_state():
    """Private interlocks for the installed controller, shared across checkouts."""
    return _controller_home() / '.local' / 'state' / 'cwo' / 'registered-worker-logins'


def _login_identity(path):
    try:
        info = path.stat()
    except FileNotFoundError:
        return None
    return info.st_dev, info.st_ino


def _login_overlap(left, right):
    if left.is_relative_to(right) or right.is_relative_to(left):
        return True
    left_id, right_id = _login_identity(left), _login_identity(right)
    return ((left_id is not None and left_id in map(_login_identity, right.parents))
            or (right_id is not None and right_id in map(_login_identity, (left, *left.parents))))


def _qualification_login_homes() -> tuple[Path, ...]:
    return tuple(managed_login_home(slot) for slot in (1, 2, 3))


def _require_login_location(home: Path, qualification_homes: Iterable[Path]) -> None:
    roots = [_controller_home() / '.codex', *qualification_homes]
    ambient = os.environ.get('CODEX_HOME')
    if ambient:
        roots.append(Path(ambient).expanduser())
    for root in roots:
        _need(not _login_overlap(home, root.absolute()) and not _login_overlap(home, root.resolve()),
              'The worker login must be separate from the primary Codex home and all qualification homes.')


def require_worker_login_location(home):
    _require_login_location(home, _qualification_login_homes())


def _file_identity(info):
    return info.st_ino, info.st_mode, info.st_uid, info.st_size, info.st_mtime_ns


_SESSION_STORES = ('sessions', 'archived_sessions')
_DIRECTORY_PROJECTIONS = ('.tmp', 'tmp', 'log', 'skills', 'shell_snapshots', 'thread-writer-locks')
_RUNTIME_PROJECTIONS = ('session_index.jsonl', 'installation_id', '.sandbox_migration')


class ManagedLoginMount:
    """Use the approved home as the overlay's writable layer, with operation-local state below it."""

    def __init__(self, home, *, work_root=None):
        self.home = home
        self._work_root = work_root
        self.identity = self._observe_home()[0]
        self.lower = self.work = None
        self.existing_runtime = ()
        self.rollout = None

    def _observe_home(self):
        try:
            directory = host_records._directory(self.home, private=True)
            with authority._state_descriptor(directory):
                info = os.fstat(directory)
                auth = self._observe_auth(directory)
                return (info.st_dev, info.st_ino), auth
        except (OSError, host_records.HostRecordError) as exc:
            raise QualificationError('The dedicated login requires an owned directory and private authentication file.') from exc

    @staticmethod
    def _observe_auth(directory):
        auth = os.stat('auth.json', dir_fd=directory, follow_symlinks=False)
        _need(stat.S_ISREG(auth.st_mode) and stat.S_IMODE(auth.st_mode) == 0o600
              and auth.st_uid == os.getuid() and auth.st_nlink == 1,
              'The dedicated login requires a private authentication file.')
        return _file_identity(auth)

    def _projections(self, home):
        runtime = home.parent / 'managed-runtime'
        return {**{name: home / name for name in ('config.toml', 'rules', *_SESSION_STORES)},
                **{name: runtime / name for name in (*_DIRECTORY_PROJECTIONS, *_RUNTIME_PROJECTIONS)}}

    def _existing_runtime(self):
        directory = host_records._directory(self.home, private=True)
        with authority._state_descriptor(directory):
            return tuple(name for name in _DIRECTORY_PROJECTIONS if self._directory_at(directory, name))

    @staticmethod
    def _directory_at(directory, name):
        try:
            observed = os.stat(name, dir_fd=directory, follow_symlinks=False)
        except FileNotFoundError:
            return False
        _need(stat.S_ISDIR(observed.st_mode) and observed.st_uid == os.getuid(),
              'A dedicated login runtime path is not an owned directory.')
        return True

    def prepare(self, home):
        self.existing_runtime = self._existing_runtime()
        self.lower = home.parent / 'managed-login-lower'
        self.lower.mkdir(mode=0o700)
        (home.parent / 'managed-runtime').mkdir(mode=0o700)
        for name, target in self._projections(home).items():
            if name in (*_SESSION_STORES, *_DIRECTORY_PROJECTIONS):
                target.mkdir(mode=0o700, exist_ok=True)
            (self.lower / name).symlink_to(target)
        work_root = campaign_directory() if self._work_root is None else self._work_root
        self.work = Path(tempfile.mkdtemp(prefix='managed-login-work-', dir=work_root))
        _need(self.work.stat().st_dev == self.identity[0],
              'The dedicated login and campaign state must share an overlay-capable filesystem.')

    def options(self, home):
        _need(self.lower is not None and self.work is not None, 'The original managed login projection is unavailable.')
        runtime = str(home.parent / 'managed-runtime')
        command = ['--bind', runtime, runtime, '--overlay-src', str(self.lower), '--overlay', str(self.home),
                   str(self.work), str(LOGIN_MOUNT), '--setenv', 'CODEX_SQLITE_HOME', runtime]
        for name in self.existing_runtime:
            command += ['--bind', str(Path(runtime) / name), str(LOGIN_MOUNT / name)]
        return command

    def confirm(self, root, home):
        identity, auth = self._observe_home()
        _need(identity == self.identity, 'The original dedicated login directory changed.')
        view = root / LOGIN_MOUNT.relative_to('/')
        _need(_file_identity((view / 'auth.json').lstat()) == auth,
              'The app server does not have the original private authentication file.')
        for name, target in self._projections(home).items():
            projected = view / name
            matched = (os.path.samestat(projected.lstat(), target.stat()) if name in self.existing_runtime
                       else projected.readlink() == target)
            _need(matched, 'The original operation login projection was shadowed.')

    def observe_rollout(self, home, thread):
        value = thread.get('path')
        if value is None:
            return
        path = self._project_rollout(home, value, thread['id'])
        if path.is_file():
            observed = native_session_boundary.locate_unique_session(home, thread['id'], reported_path=path)
            _need(observed.path == path, 'The reported qualification rollout differs from its operation spool.')
            _need(self.rollout is None or self.rollout == observed.source_identity_sha256,
                  'The original qualification rollout identity changed.')
            self.rollout = observed.source_identity_sha256

    @staticmethod
    def _project_rollout(home, raw, session_id):
        _need(type(raw) is str and 0 < len(raw) <= 4096 and '\0' not in raw,
              'A bounded qualification rollout path is required.')
        path = Path(raw)
        _need(path.is_absolute() and str(path) == raw and '..' not in path.parts
              and (path.is_relative_to(LOGIN_MOUNT) or path.is_relative_to(home)),
              'The qualification rollout path is outside its operation spool.')
        relative = path.relative_to(LOGIN_MOUNT if path.is_relative_to(LOGIN_MOUNT) else home)
        _need(len(relative.parts) >= 2 and relative.parts[0] in _SESSION_STORES
              and relative.name.endswith(f'{session_id}.jsonl'), 'The reported qualification rollout path differs.')
        return home / relative

    def confirm_archived(self, home, session_id):
        if self.rollout is not None:
            observed = native_session_boundary.locate_unique_session(home, session_id)
            _need(observed.store == 'archived_sessions' and observed.source_identity_sha256 == self.rollout,
                  'Qualification archive did not retain the original rollout in its operation spool.')

    def retire(self):
        if self.work is not None:
            overlay_work = self.work / 'work'
            if overlay_work.is_dir():
                overlay_work.chmod(0o700)
            shutil.rmtree(self.work)

    def claim(self):
        return claim_managed_login()

    def release(self, nonce):
        release_managed_login(nonce)

    def protected_roots(self):
        return (self.home,)


class WorkerLoginMount(ManagedLoginMount):
    """A production worker's overlay and durable interlock for its original login inode."""

    def __init__(self, home, state):
        self._require_location(home)
        super().__init__(home, work_root=state)
        self._lease_name = f'login-{self.identity[0]:x}-{self.identity[1]:x}.lock'

    def _require_location(self, home: Path) -> None:
        require_worker_login_location(home)

    @staticmethod
    def _observe_auth(directory):
        auth = ManagedLoginMount._observe_auth(directory)
        for name in ('auth.json.lock', 'auth.lock'):
            try:
                lock = os.stat(name, dir_fd=directory, follow_symlinks=False)
            except FileNotFoundError:
                continue
            _need(stat.S_ISREG(lock.st_mode) and stat.S_IMODE(lock.st_mode) == 0o600
                  and lock.st_uid == os.getuid() and lock.st_nlink == 1,
                  'The worker login requires a private authentication lock file.')
        return auth

    def _require_original_home(self):
        identity, _auth = self._observe_home()
        _need(identity == self.identity, 'The original worker login directory changed.')

    def claim(self):
        self._require_location(self.home)
        self._require_original_home()
        directory = host_records._directory(self._work_root, create=True, private=True)
        with authority._state_descriptor(directory):
            _need(os.fstat(directory).st_dev == self.identity[0],
                  'The worker login and interlock must share an overlay-capable filesystem.')
            return self._claim_lease(directory)

    def _claim_lease(self, directory: int) -> str:
        return _claim_login(directory, self._lease_name)

    def release(self, nonce):
        self._require_original_home()
        directory = host_records._directory(self._work_root, private=True)
        with authority._state_descriptor(directory):
            self._release_lease(directory, nonce)

    def _release_lease(self, directory: int, nonce: str) -> None:
        _release_login(directory, self._lease_name, nonce)

    def protected_roots(self):
        return self.home, self._work_root


class _PoolQualificationLoginMount(WorkerLoginMount):
    """An ordinary pool login that also holds its historical qualification slot."""

    def __init__(self, home: Path, state: Path, slot: int) -> None:
        self._slot = slot
        super().__init__(home, state)
        with _journal() as descriptor:
            _read_starts(descriptor)

    def _require_location(self, home: Path) -> None:
        homes = _qualification_login_homes()
        _need(home == homes[self._slot - 1], 'The original qualification login slot changed.')
        _require_login_location(home, (peer for peer in homes if peer != home))
        _need(not _login_overlap(home, campaign_directory()),
              'The qualification login and historical interlock must be separate.')

    def _claim_lease(self, directory: int) -> str:
        slot_lease = _login_lease_name(self._slot)
        with _journal(include_directory=True) as (_, campaign):
            nonce = _claim_login(campaign, slot_lease)
            try:
                return _claim_login(directory, self._lease_name, nonce=nonce)
            except QualificationError:
                # An existing inode lease blocked the claim before we could write to it.
                _release_login(campaign, slot_lease, nonce)
                raise

    def _release_lease(self, directory: int, nonce: str) -> None:
        slot_lease = _login_lease_name(self._slot)
        with _journal(include_directory=True) as (_, campaign):
            _require_login_nonce(campaign, slot_lease, nonce)
            super()._release_lease(directory, nonce)
            _release_login(campaign, slot_lease, nonce)

    def protected_roots(self) -> tuple[Path, ...]:
        return (*super().protected_roots(), campaign_directory())


def pool_worker_login_mount(home: Path, state: Path, homes: tuple[Path, ...]) -> WorkerLoginMount:
    """Use a qualification slot only for the exact ordered three-home pool roster."""
    slots = _qualification_login_homes()
    if homes == slots and home in slots:
        return _PoolQualificationLoginMount(home, state, slots.index(home) + 1)
    return WorkerLoginMount(home, state)


def require_model_selection(spec, plan, operation):
    selection = _model_selection()
    _need(spec.get(MODEL_SELECTION) == selection
          and all(spec.get(key) == selection[key] for key in ('model', 'effort', 'provider')),
          'Exact qualification model, provider, effort, tier and role routing are required.')
    _need(len(plan['children']) == plan['required_session_count'] == 1
          and operation['reservation']['sessions'] == operation['reservation']['max_concurrency'] == 1,
          'Qualification requires one registered worker and one reserved session.')


def thread_selectors():
    return {'modelProvider': PROVIDER, 'serviceTier': TIER, 'historyMode': HISTORY_MODE}


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


def check_thread_model(params, response, *, reasoning_effort=EFFORT):
    _need(all(params.get(key) == value for key, value in thread_selectors().items())
          and response.get('reasoningEffort') == reasoning_effort and response.get('serviceTier') == TIER,
          'Actual registered live reasoning effort or service tier differs.')
    thread = response.get('thread', {})
    _need(thread.get('ephemeral') is False,
          'The qualification thread must use its private persistent rollout.')
    _need(thread.get('historyMode') == HISTORY_MODE,
          'The qualification thread history mode readback differs.')


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
        return {'authorization_type': 'registered-n1-qualification-permit', 'campaign': CAMPAIGN,
                'version': _PERMIT_VERSION, 'start_limit': START_LIMIT,
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
    _need(type(body.get('version')) is int and type(body.get('start_limit')) is int
          and request.authorization() == body,
          'The qualification permit does not bind this campaign, operation and start limit.')
    authority._directive(value['directive'], key=verifier._key, actor=verifier._actor,
        identity=verifier._identity, action=authority.canonical_authority_sha256(body),
        parent=verifier._directive_hash)
    request.require_current()
    return request


def _campaign_directory():
    # An installed controller uses the same custody across source clones and
    # release updates. A worktree, environment or run input cannot select it.
    return _controller_home() / '.local' / 'state' / 'cwo' / CAMPAIGN


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
def _journal(*, include_directory=False):
    flags = os.O_RDWR | os.O_APPEND | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
    try:
        directory = host_records._directory(_campaign_directory(), private=True)
        with authority._state_descriptor(directory):
            descriptor = os.open(_JOURNAL, flags, dir_fd=directory)
            with authority._state_descriptor(descriptor):
                authority.MaintenanceStateStore._private_file(descriptor)
                fcntl.flock(descriptor, fcntl.LOCK_EX)
                yield (descriptor, directory) if include_directory else descriptor
    except (OSError, host_records.HostRecordError, authority.MaintenanceAuthorityError) as exc:
        raise QualificationError('Qualification campaign accounting is unavailable or unsafe.') from exc


def _login_lease_name(slot):
    stem, suffix = os.path.splitext(_LOGIN_LEASE)
    return _login_name(slot, stem, suffix)


def claim_managed_login(slot=1):
    """Leave a durable interlock across controller crashes and unresolved namespaces."""
    lease = _login_lease_name(slot)
    with _journal(include_directory=True) as (_, directory):
        return _claim_login(directory, lease)


def _claim_login(directory, lease, *, nonce: str | None = None):
    if nonce is None:
        nonce = uuid.uuid4().hex
    try:
        # O_EXCL also leaves a blocking entry after a partial write.
        host_records._write_at(directory, lease, nonce.encode())
    except FileExistsError as exc:
        raise QualificationError('A managed login launch remains unresolved.') from exc
    return nonce


def release_managed_login(nonce, slot=1):
    lease = _login_lease_name(slot)
    with _journal(include_directory=True) as (_, directory):
        _release_login(directory, lease, nonce)


def _require_login_nonce(directory: int, lease: str, nonce: str) -> None:
    observed = host_records._read_at(directory, lease, 32)
    _need(observed == nonce.encode(), 'The original managed login lease changed.')


def _release_login(directory, lease, nonce):
    _require_login_nonce(directory, lease, nonce)
    os.unlink(lease, dir_fd=directory)
    os.fsync(directory)


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
    return starts


def _usage(starts):
    initial = sum(row['repair_sha256'] is None for row in starts.values())
    return {'initial': initial, 'rechecks': len(starts) - initial, 'total': len(starts)}


def campaign_usage():
    """Read durable total and repair-provenance counts without consuming a start."""
    with _journal() as descriptor:
        return _usage(_read_starts(descriptor))


def _check_available(request, starts):
    _need(request.operation_sha256 not in starts, 'This qualification operation already started.')
    _need(len(starts) < START_LIMIT, 'The qualification campaign start limit was reached.')


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
