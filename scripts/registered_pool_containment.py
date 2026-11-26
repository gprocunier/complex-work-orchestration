"""One protected pool worker's original Linux namespaces and registered writer."""

from __future__ import annotations

from base64 import b64encode
from contextlib import ExitStack, contextmanager
from contextvars import ContextVar
from copy import deepcopy
from hashlib import sha256
import os
from pathlib import Path
import re
import stat
from threading import Lock, RLock, get_ident
from time import monotonic, monotonic_ns
from types import MappingProxyType, MethodType, SimpleNamespace

from cwo_core import native_live_availability as availability
from cwo_core.host_records import _directory, configured_store
from cwo_core.maintenance_authority import _state_descriptor
import registered_n1_factory as n1
import registered_n1_qualification as qualification
import registered_pool_configuration as config

native = n1.native
require = config.require
_ID = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,95}')
_FILE = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}')
_MAX_WRITE_BYTES = 2048
_CALIBRATION_CLOSE_PHASES = (
    'archive_us', 'monitor_exit_reap_us', 'namespace_exit_us', 'broker_close_us',
    'termination_receipt_us', 'lease_release_us', 'protocol_close_us',
)
_CALIBRATION_CLOSE_MAX_US = 3_600_000_000
_CALIBRATION_CLOSE_TIMES = ContextVar('calibration_close_times', default=None)
_WRITTEN = 'fixed qualification file written\n'
_WRITER = """import base64,os,sys
root=os.open('.',os.O_DIRECTORY|os.O_RDONLY|os.O_CLOEXEC)
try:
 fd=os.open(sys.argv[1],os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=root)
 try:
  content=base64.b64decode(sys.argv[2],validate=True)
  assert os.write(fd,content)==len(content)
  os.fsync(fd)
 finally:
  os.close(fd)
 os.fsync(root)
finally:
 os.close(root)
print('fixed qualification file written')
"""


@contextmanager
def _calibration_close_phase(phase):
    timings = _CALIBRATION_CLOSE_TIMES.get()
    if timings is None or phase is None:
        yield
        return
    started = monotonic_ns()
    try:
        yield
    finally:
        elapsed_us = max(0, (monotonic_ns() - started + 999) // 1000)
        timings[phase] = min(_CALIBRATION_CLOSE_MAX_US, (timings[phase] or 0) + elapsed_us)


def _route_available(production_live):
    if production_live:
        availability.require_registered_contained_pool_live()
    else:
        availability.require_pool_qualification()
    availability.require_registered_n1_live()


def _require_original_worker(effect, worker_id, worktree, spool, login_slot, containment=None):
    from registered_pool_qualification import _POOL_WORKER_EFFECT, _PoolWorker

    require(type(effect) is MethodType and effect.__func__ is _POOL_WORKER_EFFECT
            and type(effect.__self__) is _PoolWorker, 'Original retained pool worker required.')
    worker = effect.__self__
    require((worker.child_id, worker.worktree, worker.spool, worker.login_slot)
            == (worker_id, worktree, spool, login_slot) and worker.containment is containment,
            'Original retained pool worker required.')
    effect()
    return worker.production_login_home


def _require_original_writer(effect, authorize, call_id, deadline):
    from registered_pool_qualification import _PoolWriterAuthorization

    worker = effect.__self__
    require(type(authorize) is _PoolWriterAuthorization and authorize.worker is worker
            and worker._writer_authorization is authorize and authorize.pending.params['callId'] == call_id
            and worker.limits.deadline == deadline, 'Original retained pool writer required.')


def _directory_identity(path):
    identity = native._identity(path)
    info = path.stat(follow_symlinks=False)
    require(identity == [info.st_dev, info.st_ino, info.st_mode] and info.st_uid == os.getuid()
            and stat.S_IMODE(info.st_mode) & 0o022 == 0, 'A privately owned worker directory is required.')
    return tuple(identity)


def _confirm_view(root, source, *, readonly):
    view = root / source.relative_to('/')
    require(os.path.samestat(view.lstat(), source.lstat()), 'The contained mount is a different filesystem object.')
    observed = bool(os.statvfs(view).f_flag & os.ST_RDONLY)
    require(observed is readonly, 'The contained filesystem access differs from its required mode.')


def _dedicated_login(slot):
    home = native._path(qualification.managed_login_home(slot))
    identity = _directory_identity(home)[:2]
    alternatives = [qualification.managed_login_home(index) for index in (1, 2, 3) if index != slot]
    alternatives.append(home.parent / '.codex')
    for alternative in alternatives:
        try:
            observed = alternative.stat()
        except FileNotFoundError:
            continue
        require((observed.st_dev, observed.st_ino) != identity, 'The selected login aliases another Codex home.')
    return home


def _writer_bytes(path, text):
    require(type(path) is str and _FILE.fullmatch(path) is not None and type(text) is str,
            'The fixed writer requires one ordinary worktree file and exact text.')
    data = text.encode('utf-8')
    require(0 < len(data) <= _MAX_WRITE_BYTES, 'The fixed writer text exceeds its allowance.')
    return data


def _close_streams(process):
    if process is not None:
        for stream in (process.stdin, process.stdout, process.stderr):
            stream.close()


class _PoolLoginMount(qualification.ManagedLoginMount):
    """A direct pool-only login bind with leased, operation-local projections."""

    _SPOOL = Path('/cwo/pool-spool')
    _RUNTIME = Path('/cwo/pool-runtime')

    def __init__(self, home, configuration_files, record):
        super().__init__(home)
        self._config_files, self._record = configuration_files, record
        self._pins = ExitStack()
        self._directory_fd = self._planned = None
        self._existing, self._owned = {}, {}
        self._pending = None

    @staticmethod
    def _entry_identity(info):
        return info.st_dev, info.st_ino, info.st_mode, info.st_uid

    def _layout(self, spool, directory):
        existing = {}
        for name in self._projections(spool):
            try:
                info = os.stat(name, dir_fd=directory, follow_symlinks=False)
            except FileNotFoundError:
                continue
            if (name not in qualification._DIRECTORY_PROJECTIONS or not stat.S_ISDIR(info.st_mode)
                    or info.st_uid != os.getuid()):
                return None
            existing[name] = self._entry_identity(info)
        return existing

    def compatible(self, spool):
        with _state_descriptor(_directory(self.home, private=True)) as directory:
            self._planned = self._layout(spool, directory)
        return self._planned is not None

    def _alias(self, spool, source):
        if source.is_relative_to(spool):
            return self._SPOOL / source.relative_to(spool)
        return self._RUNTIME / source.relative_to(spool.parent / 'managed-runtime')

    def _pin(self, name):
        return self._pins.enter_context(_state_descriptor(os.open(
            name, os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=self._directory_fd)))

    def _check_home(self):
        with _state_descriptor(_directory(self.home, private=True)) as directory:
            info = os.fstat(directory)
            require((info.st_dev, info.st_ino) == self.identity
                    and os.path.samestat(info, os.fstat(self._directory_fd)),
                    'The original pool login directory changed.')

    def _mount_evidence(self):
        owned = {name: list(self._entry_identity(os.fstat(fd))) for name, (fd, _) in self._owned.items()}
        preserved = {name: list(self._entry_identity(os.fstat(fd))) for name, fd in self._existing.items()}
        return {'owned': owned, 'preserved': preserved}

    def prepare(self, spool):
        self._directory_fd = self._pins.enter_context(_state_descriptor(_directory(self.home, private=True)))
        self._check_home()
        require(self._layout(spool, self._directory_fd) == self._planned,
                'The original pool login projection layout changed.')
        (spool.parent / 'managed-runtime').mkdir(mode=0o700)
        for name, source in self._projections(spool).items():
            if name in (*qualification._SESSION_STORES, *qualification._DIRECTORY_PROJECTIONS):
                source.mkdir(mode=0o700, exist_ok=True)
            if name in self._planned:
                fd = self._pin(name)
                require(self._entry_identity(os.fstat(fd)) == self._planned[name],
                        'An original pool login directory projection changed.')
                self._existing[name] = fd
            else:
                self._create_link(name, self._alias(spool, source))
        os.fsync(self._directory_fd)
        self._record('login-projections-prepared', self._mount_evidence())

    def _create_link(self, name, target):
        self._pending = name
        try:
            os.symlink(target, name, dir_fd=self._directory_fd)
        except OSError:
            self._pending = None
            raise
        self._owned[name] = (self._pin(name), target)
        self._pending = None
        self._check_link(name)

    def _check_entry(self, name, fd):
        current = os.stat(name, dir_fd=self._directory_fd, follow_symlinks=False)
        require(self._entry_identity(current) == self._entry_identity(os.fstat(fd)),
                'An original pool login projection entry changed.')

    def _check_link(self, name):
        fd, target = self._owned[name]
        self._check_entry(name, fd)
        require(stat.S_ISLNK(os.fstat(fd).st_mode)
                and os.readlink(name, dir_fd=self._directory_fd) == str(target),
                'An original pool login projection target changed.')

    def options(self, spool):
        runtime = spool.parent / 'managed-runtime'
        login = qualification.LOGIN_MOUNT
        options = ['--bind', str(self.home), str(login), '--bind', str(spool), str(self._SPOOL),
                   '--bind', str(runtime), str(runtime), '--bind', str(runtime), str(self._RUNTIME),
                   '--setenv', 'CODEX_SQLITE_HOME', str(runtime)]
        for name in self._existing:
            options += ['--bind', str(runtime / name), str(login / name)]
        for name in self._config_files:
            options += ['--ro-bind', str(spool / name), str(self._SPOOL / name)]
        return options

    def confirm(self, root, spool):
        self._check_home()
        _, auth = self._observe_home()
        view = root / qualification.LOGIN_MOUNT.relative_to('/')
        require(os.path.samestat(view.stat(), os.fstat(self._directory_fd))
                and not os.statvfs(view).f_flag & os.ST_RDONLY
                and qualification._file_identity((view / 'auth.json').lstat()) == auth,
                'The app server does not have the original private pool login bind.')
        for name, source in self._projections(spool).items():
            projected = view / name
            if name in self._existing:
                self._check_entry(name, self._existing[name])
            else:
                self._check_link(name)
                target = self._alias(spool, source)
                require(projected.readlink() == target, 'The original pool login projection was shadowed.')
                projected = root / target.relative_to('/')
            if source.exists():
                require(os.path.samestat(projected.lstat(), source.lstat()),
                        'The original pool login projection source changed.')
            else:
                require(not os.path.lexists(projected), 'The original pool login projection was shadowed.')
        for name in self._config_files:
            alias = root / self._SPOOL.relative_to('/') / name
            require(os.path.samestat(alias.stat(), (spool / name).stat())
                    and bool(os.statvfs(alias).f_flag & os.ST_RDONLY),
                    'The original pool login configuration alias is not read-only.')

    def retire(self):
        with self._pins:
            require(self._pending is None, 'An original pool login projection was not retained.')
            if self._directory_fd is None:
                return
            self._check_home()
            for name, fd in self._existing.items():
                self._check_entry(name, fd)
            for name in self._owned:
                self._check_link(name)
            evidence = self._mount_evidence()
            for name in self._owned:
                self._check_link(name)
                os.unlink(name, dir_fd=self._directory_fd)
            os.fsync(self._directory_fd)
            self._record('login-projections-retired', evidence)


class _PoolLifetime(n1._Containment):
    """Use the original retained process, namespace gate and provider relay."""

    def __init__(self, worker, role, command):
        super().__init__(worker, role=role)
        self._selected_command = tuple(command)
        self.gate_released = False

    def _terminate_monitor(self):
        with _calibration_close_phase('monitor_exit_reap_us'):
            return super()._terminate_monitor()

    def _stop_namespace(self):
        with _calibration_close_phase('namespace_exit_us'):
            super()._stop_namespace()

    def _close_provider_network(self, primary=None):
        with _calibration_close_phase('broker_close_us'):
            super()._close_provider_network(primary)

    def _managed_mount(self):
        return self.factory._managed_login if self.role == 'appserver' else None

    def _provider_network_selected(self):
        return self.role == 'appserver'

    def _require_launch_command(self, command):
        self.factory.require_effect()
        require(tuple(command) == self._selected_command, 'The original contained command changed.')

    def _preflight_qualification_schema(self):
        if self.role == 'appserver':
            spec = self.factory.spec
            qualification.require_executable_schema(spec['executable'], spec['executable_sha256'])
            self.factory.require_effect()

    def _preflight_tool_launch(self, tool_call, deadline, tool_decision):
        if self.role == 'tool':
            self.factory.require_writer(tool_call, deadline)

    def _publish_pending_lifetime(self):
        # The worker retains the lifetime before spawning the original child.
        pass

    def _confirm_login_mount(self, root):
        super()._confirm_login_mount(root)
        worker = self.factory
        _confirm_view(root, worker.host.worker, readonly=self.role == 'appserver')
        _confirm_view(root, worker.host.worker / '.git', readonly=True)
        if self.role == 'appserver':
            _confirm_view(root, worker.home, readonly=False)
            for name in worker.spec['configuration_files']:
                _confirm_view(root, worker.home / name, readonly=True)
        else:
            n1._not_exposed(root, worker.home)

    def _release_command(self, descriptor, observation, tool_call, deadline):
        self._managed_mount_started = self._managed_mount() is not None
        os.write(descriptor, b'1')
        self._confirm_mounts()
        self.factory.require_effect()
        appserver = self.role == 'appserver'
        require((self.provider_network is not None) is appserver, 'The original provider relay selection differs.')
        facts = {
            **observation, 'filesystem_ready': True, 'worktree_readonly': appserver,
            'network': 'registered-provider-tunnel' if appserver else 'isolated',
            'managed_login_projection': appserver,
            'peer_worktrees_hidden': len(self.factory._peer_worktrees),
        }
        if appserver:
            facts['owner_identity_sha256'] = self.factory._owner_identity(observation, self._namespace_birth)
        self.factory.record(self.role + '-contained', facts)
        if appserver:
            self.factory.require_effect()
            self._open_gate()
        else:
            self._release_writer_gate(tool_call, deadline)

    def _open_gate(self):
        require(not self.gate_released, 'The original command gate was already released.')
        descriptor = self.process.stdin.fileno()
        os.set_blocking(descriptor, False)
        require(os.write(descriptor, b'1') == 1, 'The original command gate was not released.')
        self.gate_released = True

    def _release_writer_gate(self, call, deadline):
        owner = get_ident()
        pending = True

        def release():
            require(pending and owner == get_ident(), 'The original callback no longer owns its writer gate.')
            self.factory.require_writer(call, deadline)
            self._open_gate()

        try:
            call.authorize(release)
        finally:
            pending = False
        require(self.gate_released, 'The original registered callback did not release its writer.')


class _WriterCall:
    def __init__(self, call_id, authorize):
        self.call_id = call_id
        self.authorize = authorize


class PoolWorkerContainment:
    """One original worker. A protected parent supplies the effect and callback checks."""

    def __init__(self, *, worker_id, worktree, spool, login_slot, executable, executable_sha256,
                 launcher, launcher_sha256, validator, validator_sha256, protected_roots,
                 write_path, expected_utf8, require_effect, peer_worktrees=(), model_catalog=None):
        require(type(worker_id) is str and _ID.fullmatch(worker_id) is not None,
                'The original protected worker and effect check are required.')
        login_home = _require_original_worker(require_effect, worker_id, worktree, spool, login_slot)
        _route_available(login_home is not None)
        self._authorize_effect = require_effect
        self.operation_id = worker_id
        self.host = SimpleNamespace(worker=native._path(worktree))
        self.home = n1._private(spool)
        self._custody = n1._private(self.home.parent)
        self._peer_worktrees = tuple(native._path(path) for path in peer_worktrees)
        self._protected = (*tuple(native._path(path) for path in protected_roots), *self._peer_worktrees)
        self.host_records = configured_store()
        self._slot = login_slot
        self._worker_login = self._select_worker_login(login_home)
        self._login_home, self._lease_home = self._login_roots()
        self._login_identity = _directory_identity(self._login_home)
        self._paths = (self.host.worker, self.host.worker / '.git', self.home, self._custody)
        self._identities = tuple(_directory_identity(path) for path in self._paths)
        self._paths_disjoint()
        self._executables = self._pin_executables(((executable, executable_sha256),
                                                    (launcher, launcher_sha256), (validator, validator_sha256)))
        self._catalog = self._select_catalog(model_catalog)
        self._configure_spec()
        self._output_path = write_path
        self._output = _writer_bytes(write_path, expected_utf8)
        self.server = self._managed_login = self._managed_lease = self._managed_lifetime = None
        self._appserver = self._writer = self._call = None
        self._closed = self._failed = False
        self._lock, self._record_lock = RLock(), Lock()
        self._records = []
        self._receipt_root = self._custody / 'containment-receipts'
        self._receipt_identity = None
        self._configured = False

    @property
    def production_live(self):
        return self._worker_login is not None

    @staticmethod
    def _select_worker_login(home):
        if home is None:
            return None
        require(isinstance(home, Path), 'The original configured worker login is required.')
        state = native._path(qualification.worker_login_state())
        return qualification.WorkerLoginMount(native._path(home), state)

    def _login_roots(self):
        if self.production_live:
            return self._worker_login.protected_roots()
        return _dedicated_login(self._slot), native._path(qualification.campaign_directory())

    def _pin_executables(self, selections):
        pins = tuple(n1._file(path) for path, _ in selections)
        protected = (self.host.worker, self._custody, *self._protected_roots())
        for pin, (_, digest) in zip(pins, selections):
            self._require_private_executable(pin[0], protected)
            require(digest == pin[1], 'An original executable differs from its protected selection.')
        return pins

    @staticmethod
    def _require_private_executable(executable, roots):
        for root in set(roots):
            n1._disjoint((Path(executable), root))

    @staticmethod
    def _select_catalog(selection):
        if selection is None:
            return None
        require(type(selection) is tuple and len(selection) == 2, 'The optional model catalog needs bytes and a pin.')
        raw, digest = selection
        config.require_trimmed_model_catalog(raw, digest)
        return raw

    def _configure_spec(self):
        keys = ('executable', 'launcher', 'validator')
        spec = {key: pin[0] for key, pin in zip(keys, self._executables)}
        spec.update({key + '_sha256': pin[1] for key, pin in zip(keys, self._executables)})
        self._files = config.configuration_files(self.host.worker, self.home, catalog=self._catalog)
        config.require_named_deny_policy(self.host.worker, self._files['config.toml'])
        self.spec = MappingProxyType(dict(spec, configuration_files=tuple(self._files)))

    def _paths_disjoint(self):
        broad = (self.host.worker, self._custody)
        n1._disjoint(broad)
        for root in self._protected_roots():
            n1._disjoint((*broad, root))
            self._reject_aliased_root(root)
        n1.require_private_roots((*broad, *self._protected_roots()))
        if self.production_live:
            self._require_private_login_roots(broad)

    def _require_private_login_roots(self, worker_roots):
        peers = (*worker_roots, *self._protected, self.host_records.state_root)
        for home, others in ((self._login_home, (*peers, self._lease_home)), (self._lease_home, peers)):
            require(not any(qualification._login_overlap(home, root) for root in others),
                    'The worker login and its interlock must be separate from other protected roots.')

    def _reject_aliased_root(self, root):
        try:
            info = root.stat(follow_symlinks=False)
        except FileNotFoundError:
            return
        identity = (info.st_dev, info.st_ino)
        require(all(identity != pinned[:2] for pinned in self._identities),
                'The worker or spool aliases a protected filesystem object.')

    def _protected_roots(self):
        return (*self._protected, self._lease_home, self._login_home, self.host_records.state_root)

    def _require_login_home(self):
        if self.production_live:
            self._worker_login._require_original_home()
            return
        home = _dedicated_login(self._slot)
        require(home == self._login_home and _directory_identity(home) == self._login_identity,
                'The original dedicated login selection changed.')

    def require_effect(self):
        _route_available(self.production_live)
        require(not self._closed and not self._failed, 'The original worker is no longer open.')
        home = _require_original_worker(self._authorize_effect, self.operation_id, self.host.worker, self.home,
                                        self._slot, self)
        require(home == (self._login_home if self.production_live else None),
                'The original configured worker login changed.')
        require((self.host.worker, self.home) == (self._paths[0], self._paths[2])
                and tuple(_directory_identity(path) for path in self._paths) == self._identities,
                'An original contained directory changed.')
        self._require_login_home()
        self._paths_disjoint()
        require(tuple(n1._file(pin[0]) for pin in self._executables) == self._executables,
                'An original contained executable changed.')
        if self._configured:
            self._require_configuration()

    def _require_configuration(self):
        for name, expected in self._files.items():
            require(native._immutable_read(self.home, name, len(expected) + 1) == expected,
                    'The original contained configuration changed.')

    def _prepare_home(self):
        n1._cold_spool(self.home, False)
        self._receipt_root.mkdir(mode=0o700)
        self._receipt_identity = _directory_identity(self._receipt_root)
        native._sync(self._custody)
        if self.production_live:
            self._managed_lease = self._worker_login.claim()
        (self.home / 'rules').mkdir(mode=0o700)
        for name, value in self._files.items():
            path = self.home / name
            native._write_new(path, value, 0o400)
            native._sync(path.parent)
        if not self.production_live:
            self._managed_lease = qualification.claim_managed_login(self._slot)
        self._prepare_login_projection()
        self._configured = True

    def _prepare_login_projection(self):
        direct = _PoolLoginMount(self._login_home, self.spec['configuration_files'], self.record)
        if direct.compatible(self.home):
            self._managed_login = direct
        else:
            self._managed_login = self._worker_login or qualification.ManagedLoginMount(self._login_home)
        require(self._managed_login.identity == self._login_identity[:2], 'The original pool login directory changed.')
        self._managed_login.prepare(self.home)

    def _take_provider_access_token(self):
        return None

    def launch_appserver(self):
        """Return the private stdio pipes of the original contained app server."""
        with self._lock:
            self.require_effect()
            require(self._appserver is None, 'The original pool app server cannot be started twice.')
            try:
                self._prepare_home()
                command = [self.spec['executable'], 'app-server', '--stdio']
                self._appserver = _PoolLifetime(self, 'appserver', command)
                return self._appserver.launch(command, self.home)
            except BaseException as error:
                self._failed = True
                self._close_preserving(error)
                raise

    def thread_start_selectors(self):
        return config.thread_start_selectors(self.host.worker)

    def require_thread_start(self, params):
        require(type(params) is dict and n1._snapshot(self.thread_start_selectors()) == n1._snapshot(params),
                'The original contained thread selectors differ.')

    def require_thread_readback(self, response):
        self.require_effect()
        config.require_thread_readback(self.host.worker, response)
        self.record('named-profile-config', {'id': config.PROFILE, 'managed_login_access': 'deny'})

    @staticmethod
    def require_turn_selectors(params, *, thread_id):
        return config.require_turn_selectors(params, thread_id=thread_id)

    def _owner_identity(self, observation, birth):
        return n1.canonical_sha256({'worker_id': self.operation_id, 'worktree': str(self.host.worker),
            'worktree_identity': self._identities[0], 'spool_identity': self._identities[2],
            'executable_sha256': self.spec['executable_sha256'], 'namespace_birth': birth, **observation})

    @property
    def owner_identity_sha256(self):
        """Original retained app-server identity for the startup and tool joins."""
        with self._record_lock:
            started = next((row['observation'] for row in self._records if row['stage'] == 'appserver-contained'), None)
            require(started is not None and self._appserver.gate_released, 'Original app-server identity is unavailable.')
            return started['owner_identity_sha256']

    def rollout_path(self, path, *, thread_id):
        """Map the app server's private login path to the original host spool."""
        return qualification.ManagedLoginMount._project_rollout(self.home, path, thread_id)

    def require_writer(self, call, deadline):
        self.require_effect()
        self._remaining(deadline)
        require(self._call is call and self._appserver.gate_released and self._appserver.process.poll() is None,
                'The original writer callback or app-server lifetime changed.')

    @staticmethod
    def _remaining(deadline):
        remaining = deadline - monotonic()
        require(remaining > 0, 'The original writer callback deadline expired.')
        return min(remaining, 30)

    def run_writer(self, call_id, *, authorize, deadline):
        """Perform the sole fixed write after the parent authorizes the one-shot gate."""
        with self._lock:
            self.require_effect()
            _require_original_writer(self._authorize_effect, authorize, call_id, deadline)
            require(type(call_id) is str and _ID.fullmatch(call_id) is not None
                    and self._call is None and self._appserver is not None
                    and type(deadline) in (int, float), 'The original one-shot writer callback is required.')
            self._call = _WriterCall(call_id, authorize)
            try:
                return self._run_writer(deadline)
            except BaseException as error:
                self._failed = True
                self._close_preserving(error)
                raise

    def _run_writer(self, deadline):
        command = [self.spec['validator'], '-I', '-S', '-c', _WRITER,
                   self._output_path, b64encode(self._output).decode('ascii')]
        self._writer = _PoolLifetime(self, 'tool', command)
        process = self._writer.launch(command, self.home, tool_call=self._call, deadline=deadline)
        stdout, stderr = process.communicate('', self._remaining(deadline))
        require(process.poll() == 0 and stdout == _WRITTEN and stderr == '',
                'The fixed writer did not report successful completion.')
        self._settle(self._writer)
        require(native._read(self.host.worker, self._output_path, _MAX_WRITE_BYTES) == self._output,
                'The original worktree does not contain the fixed writer output.')
        self.record('writer-output', {'call_id': self._call.call_id, 'path': self._output_path,
                                     'content_sha256': sha256(self._output).hexdigest()})
        return stdout.encode()

    def record(self, stage, observation):
        phase = 'termination_receipt_us' if stage == 'appserver-terminated' else None
        with self._record_lock, _calibration_close_phase(phase):
            require(_directory_identity(self._receipt_root) == self._receipt_identity,
                    'The original containment receipt directory changed.')
            index = len(self._records)
            require(index < 256, 'The contained worker receipt bound was exceeded.')
            row = {'stage': stage, 'observation': deepcopy(observation)}
            native._write_new(self._receipt_root / f'{index:04d}.json', n1._snapshot(row), 0o400)
            native._sync(self._receipt_root)
            self._records.append(row)

    def _settle(self, lifetime):
        if lifetime is None:
            return
        try:
            if lifetime.receipt is not None and not lifetime.termination_recorded:
                lifetime.settle_termination()
        finally:
            _close_streams(lifetime.process)

    def _release_login(self):
        if self._managed_lease is None:
            return
        lifetime = self._managed_lifetime
        require(lifetime is None or not lifetime._managed_mount_started or lifetime.termination_recorded,
                'The original managed-login namespace cleanup is unresolved.')
        with _calibration_close_phase('lease_release_us'):
            if self.production_live:
                self._worker_login._require_original_home()
            if self._managed_login is not None:
                self._managed_login.retire()
            self._release_login_lease()
            self._managed_lease = None
            self.record('login-released', {'slot': self._slot})

    def _release_login_lease(self):
        if self.production_live:
            self._worker_login.release(self._managed_lease)
        else:
            qualification.release_managed_login(self._managed_lease, self._slot)

    def _close_preserving(self, primary):
        try:
            self.close()
        except BaseException as error:
            primary.add_note('Contained worker cleanup: ' + type(error).__name__)

    def close(self):
        """Settle every original lifetime before reporting or releasing login custody."""
        with self._lock:
            if self._closed:
                return self.receipt()
            self._closed = True
            failures = []
            for cleanup in (lambda: self._settle(self._writer), lambda: self._settle(self._appserver),
                            self._release_login):
                try:
                    cleanup()
                except BaseException as error:
                    failures.append(error)
            if failures:
                self._failed = True
                primary, *rest = failures
                for error in rest:
                    primary.add_note('Contained worker cleanup: ' + type(error).__name__)
                raise primary
            return self.receipt()

    def receipt(self):
        """Return current original mount, callback and cleanup observations."""
        with self._record_lock:
            return {'worker_id': self.operation_id, 'worktree': str(self.host.worker), 'spool': str(self.home),
                    'worktree_identity': list(self._identities[0]), 'spool_identity': list(self._identities[2]),
                    'login_slot': self._slot, 'config_sha256': sha256(self._files['config.toml']).hexdigest(),
                    'model_catalog_sha256': None if self._catalog is None else sha256(self._catalog).hexdigest(),
                    'closed': self._closed, 'failed': self._failed,
                    'cleanup_confirmed': self._cleanup_confirmed(), 'observations': deepcopy(self._records)}

    def _cleanup_confirmed(self):
        observed = {row['stage'] for row in self._records}
        required = {'appserver-terminated', 'login-released'}
        if self._writer is not None:
            required.add('tool-terminated')
        return self._closed and required <= observed
