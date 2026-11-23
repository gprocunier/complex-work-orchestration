"""Registered finite N=1 transport with parent custody and no route activation.

Only a claimed original maintenance capability can select this factory. Worker
code never runs in the controller. A signed qualification can select an
isolated dedicated Codex login or a one-shot provider credential attachment.
"""
from __future__ import annotations

import copy
import errno
import fcntl
import hashlib
import importlib
import json
import os
from pathlib import Path
import queue
import re
import select
import signal
import stat
import subprocess
import threading
import time
import tomllib
import weakref
from typing import NamedTuple

import linux_owned_children as owned
import offline_admitted_n1 as admitted
import offline_artifact_validation as validation
import registered_n1_qualification as qualification
import registered_provider_network as provider_network
from registered_server_requests import RegisteredServerRequests
from registered_finite_input import RegisteredFiniteInput
import registered_finite_tool_calls as finite_calls
from prepare_server_request_frames import _decode as decode_protocol_frame
from cwo_core.maintenance_authority import require_maintenance_operation
from cwo_core.maintenance_authority import MaintenanceStateStore
from cwo_core.native_control import build_control_turn_contract
from cwo_core.native_pool_contracts import canonical_sha256
from cwo_core import server_request_preparation as protocol
from cwo_core import native_live_availability as live_availability
from cwo_core.host_records import configured_store
from cwo_core.host_return_intake import record_received_return
from cwo_core.process_identity import parse_proc_stat
from cwo_core.supervision.transport.app_server import (
    AppServerError, _QUALIFICATION_RPC, _checked_native_frame, _prepare_native_frame, domain_sha256,
)
from cwo_core.supervision.turn_observations import provider_policy_blocker
from registered_app_server_transport import RegisteredAppServer
from registered_host_root_boundary import require_private_roots

native = admitted.native
admission = admitted.admission_api
_ADAPTERS = weakref.WeakKeyDictionary()
_LOCK = threading.RLock()
_FALSE = dict.fromkeys(admitted.FALSE_FIELDS, False)
# These are host packaging requirements, not a discovery search or worker input.
_RUNTIME = ("/usr", "/lib", "/lib64")
_READY = 'cwo-boundary-ready\n'
_BOOTSTRAP = ("import os,select,sys; os.write(1,b'cwo-boundary-ready\\n'); "
              "ready=select.select([0],[],[],10)[0]; "
              "(ready and os.read(0,1)==b'1') or sys.exit(73); "
              "os.execv(sys.argv[1],sys.argv[1:])")
_VALIDATOR = """import json,sys
sys.path.insert(0,'/cwo/scripts')
import offline_artifact_validation as v
r=json.loads(sys.stdin.buffer.read(8388609))
p=r['policy']; outputs=r['outputs']
assert len(p['outputs'])==len(outputs)
for entry,(name,data) in zip(p['outputs'],outputs):
 assert name==entry['path']
 assert v._compare(entry,bytes.fromhex(data))['passed'] is True
print('validated')
"""


def _need(condition, message):
    if not condition:
        raise native.OfflineHostError(message)


def _snapshot(value):
    return admitted.reconciliation._snapshot(value)[1]


def _model_task(receipt, spec, policy):
    selected = json.loads(receipt.selected_node_bytes)
    admission.planner._input_measurements(selected)
    _need(admission.planner.render_request(selected).encode('utf-8') == receipt.request_bytes
          and _snapshot(selected['execution']) == receipt.execution_bytes,
          'The model task requires the exact original admitted request and execution.')
    unit = selected['unit_estimate']
    task = {'version': 1,
            'task': {key: selected[key] for key in ('prompt', 'wrappers', 'attachments', 'sources')},
            'acceptance': {'allowed_command': spec['command'], 'completion_marker': spec['expected_token'],
                           'outputs': policy['outputs'], 'expected_artifacts': unit['expected_artifacts'],
                           'acceptance_checks': unit['acceptance_checks']}}
    data = _snapshot(task)
    _need(0 < len(data) <= min(len(receipt.request_bytes), native.MAX_TASK_BYTES),
          'The complete model task exceeds its original admitted byte allowance.')
    return data


def _observe_adapter_failure(adapter, failure):
    primary = getattr(adapter, '_first_action_failure', None)
    if primary is None:
        adapter._first_action_failure = primary = failure
    elif primary is not failure:
        admission.ledger_api.add_failure_note(primary, 'Later adapter action failed: ' + type(failure).__name__)
    try:
        adapter.server._fail_transport(failure)
    except BaseException as secondary:
        admission.ledger_api.add_failure_note(primary, 'Adapter failure cleanup also failed: ' + type(secondary).__name__)


def _require_summary_primary(adapter):
    primary = getattr(adapter, '_first_action_failure', None)
    if primary is None:
        primary = adapter.server.transport_failure
    if primary is not None:
        raise primary


def _argument_file():
    """One Linux ABI on both interpreters; unsupported kernels/libcs refuse."""
    library = owned.ctypes.CDLL(None, use_errno=True)
    create = getattr(library, 'memfd_create', None)
    _need(create is not None, "The registered Linux argument-file mechanism is unavailable.")
    create.argtypes = (owned.ctypes.c_char_p, owned.ctypes.c_uint)
    create.restype = owned.ctypes.c_int
    descriptor = create(b'cwo-n1-arguments', 3)  # Linux MFD_CLOEXEC | MFD_ALLOW_SEALING.
    if descriptor < 0:
        raise OSError(owned.ctypes.get_errno(), 'The registered argument-file mechanism failed.')
    return descriptor


def _launcher_argv(launcher, arguments, command):
    # Bubblewrap's argument file carries options; COMMAND must be real argv.
    return [launcher, '--args', str(arguments), '--', *command]


def _namespace_info_bytes(descriptor):
    """Read the one closed startup-info stream under one total budget."""
    deadline, raw = time.monotonic() + 5, bytearray()
    while True:
        remaining = deadline - time.monotonic()
        _need(remaining > 0 and select.select([descriptor], [], [], remaining)[0],
              "Namespace startup observation timed out.")
        chunk = os.read(descriptor, 4097 - len(raw))
        _need(time.monotonic() < deadline, "Namespace startup observation timed out.")
        if not chunk:
            _need(bool(raw), "Namespace startup report closed before a complete object.")
            return bytes(raw)
        raw.extend(chunk)
        _need(len(raw) <= 4096, "Namespace startup report exceeds its bound.")


def _namespace_info(descriptor):
    raw = _namespace_info_bytes(descriptor)
    try:
        info = decode_protocol_frame(raw)
    except (ValueError, RecursionError) as exc:
        raise native.OfflineHostError("Namespace startup report is not one complete bounded JSON object.") from exc
    _need(type(info) is dict, "Namespace startup report must be one JSON object.")
    return info


def implementation_sha256():
    """A parent signs this installed import image; the digest alone grants nothing."""
    root = Path(__file__).resolve().parent
    files = {}
    for path in sorted(root.rglob('*.py')):
        _need(not path.is_symlink() and path.is_file(), "Unsupported installed source entry.")
        with path.open('rb') as stream:
            files[str(path.relative_to(root))] = hashlib.file_digest(stream, 'sha256').hexdigest()
    return hashlib.sha256(_snapshot(files)).hexdigest()


def _file(path):
    path = native._path(path)
    info = path.stat(follow_symlinks=False)
    _need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, "A distinct regular executable is required.")
    _need(os.access(path, os.X_OK), "The registered executable is unavailable.")
    with path.open('rb') as stream:
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    after = path.stat(follow_symlinks=False)
    _need((after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
          == (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns), "Executable changed during observation.")
    return str(path), digest, (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns)


def _private(path):
    path = native._path(path)
    info = path.stat(follow_symlinks=False)
    _need(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid()
          and stat.S_IMODE(info.st_mode) == 0o700, "Controller storage requires an owned private directory.")
    return path


def _disjoint(paths):
    for index, left in enumerate(paths):
        for right in paths[index + 1:]:
            _need(not native._within(left, right) and not native._within(right, left),
                  "Worker, target and controller stores must be disjoint.")


def _not_exposed(root, source):
    try:
        observed = (root / source.relative_to('/')).stat()
    except FileNotFoundError:
        return
    original = source.stat()
    _need((observed.st_dev, observed.st_ino) != (original.st_dev, original.st_ino),
          "A controller store is visible inside the child namespace.")


def _cold_spool(home, configured):
    """Only empty spool directories and our explicitly staged config may enter."""
    pending, count = [(home, 0)], 0
    while pending:
        directory, depth = pending.pop()
        _need(depth <= 4, "The initial spool directory depth is unsupported.")
        with os.scandir(directory) as entries:
            for entry in entries:
                count += 1
                _need(count <= 64, "The initial spool entry bound was exceeded.")
                path = Path(entry.path)
                relative = path.relative_to(home).as_posix()
                info = entry.stat(follow_symlinks=False)
                if stat.S_ISDIR(info.st_mode):
                    _need(relative.split('/')[0] in {'sessions', 'archived_sessions'} | ({'rules'} if configured else set()),
                          "An unregistered initial spool directory is present.")
                    pending.append((path, depth + 1))
                else:
                    _need(configured and relative in {'config.toml', 'rules/default.rules'} and stat.S_ISREG(info.st_mode),
                          "An unregistered initial spool file is present; no parent data may be mounted.")


def _profile(spec):
    start, observed = spec['thread_start'], spec['profile_readback']
    is_qualification = qualification.MODEL_SELECTION in spec
    policy = qualification.APPROVAL_POLICY if is_qualification else 'untrusted'
    _need(set(start) == {'permissions', 'approvalPolicy', 'approvalsReviewer', 'ephemeral'},
          "Only the named permissions selector is supported; legacy/mixed selectors refuse.")
    _need(type(start['permissions']) is str and bool(start['permissions']), "A named profile is required.")
    _need(start['approvalPolicy'] == policy and start['approvalsReviewer'] == 'user'
          and start['ephemeral'] is (not is_qualification), "The finite no-grants approval profile is required.")
    expected = {'activePermissionProfile': {'id': start['permissions'], 'extends': None},
                'approvalPolicy': policy, 'approvalsReviewer': 'user'}
    _need(observed == expected, "Reported profile fallback or drift is refused.")
    facts = spec['pre_effect']
    _need(facts == {'profile': start['permissions'], 'policy_id': spec['configuration_pins']['w15'],
                   'rules': [], 'hooks': [], 'grants': [], 'network': False, 'input_capability': 'finite'},
          "Unknown pre-effect evidence, allows, hooks, network or unsupported input refuse.")


def _configuration(spec, worker):
    files = spec['configuration_files']
    _need(set(files) == {'config.toml', 'rules/default.rules'} and files['rules/default.rules'] == '',
          "Only registered configuration and an empty rules file are supported.")
    raw = files['config.toml']
    _need(type(raw) is str and len(raw.encode()) <= 32768, "Bounded registered configuration required.")
    config = tomllib.loads(raw)
    expected = {'default_permissions': spec['thread_start']['permissions'],
                'approval_policy': spec['thread_start']['approvalPolicy'],
                'approvals_reviewer': 'user', 'model': spec['model'],
                'model_reasoning_effort': spec['effort'], 'service_tier': 'default',
                'permissions': {spec['thread_start']['permissions']: {
                    'filesystem': {'/': 'deny', str(worker): 'write'}, 'network': {'enabled': False}}}}
    if qualification.MODEL_SELECTION in spec:
        expected['features'] = qualification.configuration_features()
        roots = expected['permissions'][spec['thread_start']['permissions']]['filesystem']
        roots[str(worker)] = 'read'
        _managed_login_config(spec, expected, roots)
    _need(config == expected, "Registered configuration selectors, roots, hooks or network differ.")


def _managed_login_config(spec, config, roots):
    if spec.get(qualification.AUTHENTICATION) == qualification.MANAGED_LOGIN:
        config['cli_auth_credentials_store'] = 'file'
        roots[str(qualification.LOGIN_MOUNT)] = 'deny'


class _DeadlineInput:
    """One bounded nonblocking protocol writer, including lock acquisition."""

    def __init__(self, stream, failure):
        self.stream, self.failure_callback = stream, failure
        self.descriptor = stream.fileno()
        self.failure = None
        self._lock = threading.Lock()
        self._poison = os.open(os.devnull, os.O_RDONLY | os.O_CLOEXEC)
        self._aborted = False
        self._closing = False
        os.set_blocking(self.descriptor, False)

    def write(self, value):
        deadline, acquired = time.monotonic() + 5, False
        try:
            _need(type(value) is str and len(value) <= 1048576, "A bounded protocol write is required.")
            data = value.encode('utf-8')
            _need(len(data) <= 1048576, "The protocol write byte bound was exceeded.")
            acquired = self._lock.acquire(timeout=max(0, deadline - time.monotonic()))
            if not acquired:
                raise TimeoutError('registered-protocol-write-lock-timeout')
            self.flush()
            self._write_all(memoryview(data), deadline)
            return len(value)
        except BaseException as failure:
            if self.failure is None:
                self.failure = failure
            self.failure_callback(self.failure)
            raise
        finally:
            if acquired:
                self._lock.release()
                if self._closing:
                    self.close()

    def _write_all(self, data, deadline):
        while data:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError('registered-protocol-write-timeout')
            try:
                if not select.select([], [self.descriptor], [], remaining)[1]:
                    continue
                self.flush()
                count = os.write(self.descriptor, data)
                _need(count > 0, "Protocol write made no progress.")
                data = data[count:]
            except (BlockingIOError, InterruptedError):
                continue

    def flush(self):
        if self.failure is not None or self.stream.closed or self._aborted or self._closing:
            raise AppServerError('registered-protocol-writer-unavailable') from self.failure
        # os.write has no Python-side pending buffer.

    def abort(self):
        """Fence a not-yet-entered write without waiting for its writer lock.

        The stable read-only descriptor prevents a paused writer from sending
        an old accepting frame after request authority has been revoked.
        """
        if not self._aborted and not self.stream.closed:
            os.dup2(self._poison, self.descriptor)
            self._aborted = True
        if self._poison is not None:
            os.close(self._poison)
            self._poison = None

    def close(self):
        self._closing = True
        if not self._lock.acquire(blocking=False):
            return
        try:
            if not self.stream.closed:
                self.stream.close()
            if self._poison is not None:
                os.close(self._poison)
                self._poison = None
        finally:
            self._lock.release()


class _PipeChild:
    """Protocol streams with status operations delegated to original custody."""

    def __init__(self, child, streams, argv):
        self._child = child
        self.stdin, self.stdout, self.stderr = streams
        self.args = argv

    def _get_pid(self):
        return self._child.pid

    def _set_pid(self, value):
        self._child.pid = value

    pid = property(_get_pid, _set_pid)

    def _get_returncode(self):
        return self._child.returncode

    def _set_returncode(self, value):
        self._child.returncode = value

    returncode = property(_get_returncode, _set_returncode)

    def poll(self):
        if self.returncode is not None:
            return self.returncode
        return self._handle_backend.status(self._handle_birth)

    def wait(self, timeout=None):
        _need(type(timeout) in (int, float) and 0 <= timeout <= 30, "A finite retained-handle wait is required.")
        if self.returncode is not None:
            return self.returncode
        if not self._handle_backend.wait_exit(self._handle_birth.descriptor, timeout):
            raise subprocess.TimeoutExpired(self.args, timeout)
        return self.poll()

    def communicate(self, data, timeout):
        return owned.atomic_spawn.communicate(self, data, timeout)


class _PipeBackend(owned._LinuxBackend):
    """Retain the exact direct-child handle, with private protocol pipes."""

    def __init__(self, pass_fds):
        super().__init__()
        self.pass_fds = pass_fds

    def _spawn_atomic(self, birth, argv, executable, workspace):
        def retain(child, streams):
            self._retain_atomic(birth, child)
            birth.child = _PipeChild(child, streams, argv)
            birth.child._handle_backend, birth.child._handle_birth = self, birth
        self._operation("Atomic protocol child creation", owned.atomic_spawn.spawn_piped,
                        executable, argv, workspace, tuple(self.pass_fds), retain)

    def spawn(self, birth, argv, executable, workspace):
        result = super().spawn(birth, argv, executable, workspace)
        birth.child._handle_backend, birth.child._handle_birth = self, birth
        return result

    def status(self, birth):
        with self._lifecycle_lock:
            if birth.child.returncode is not None:
                return birth.child.returncode
            if birth.active_operation is not None or birth.releasing or birth.closed:
                return None
            self._start_operation(birth.descriptor, 'wait')
            primary = None
            try:
                result = self._operation('Protocol child status', os.waitid, os.P_PIDFD,
                                         birth.descriptor, os.WEXITED | os.WNOHANG | os.WNOWAIT)
                return None if result is None else self._exit_code(birth, result)
            except BaseException as failure:
                primary = failure
                raise
            finally:
                self._finish_operation(birth, primary)


class CleanupObservation(NamedTuple):
    """One caller's immutable observation of the original cleanup owner."""

    kind: str
    physical_contained: bool
    termination_recorded: bool


class TerminationObservationError(native.OfflineHostError):
    """A bounded observer failed independently of the effect owner's result."""

    def __init__(self, kind, message):
        super().__init__(message)
        self.kind = kind


class _Containment:
    """One blocked namespace child, independently inspected before its gate opens."""

    def __init__(self, factory, *, validator=False, role=None):
        self.factory = factory
        self.role = role or ('validator' if validator else 'appserver')
        _need(self.role in {'appserver', 'tool', 'validator'}
              and not (validator and self.role != 'validator'), "A distinct trusted containment role is required.")
        self.validator = self.role == 'validator'
        self.controller = self.receipt = self.process = self.birth = self.command = None
        self.termination = None
        self.contained = False
        self.namespace_handle = None
        self._namespace_pid = self._namespace_birth = None
        self._lock = threading.Lock()
        self._ending = False
        self._termination_owner = None
        self._termination_finished = threading.Event()
        self._termination_error = None
        self.termination_recorded = False
        self._observation_local = threading.local()
        self._observation_pending = 0
        self._observation_results = []
        self._observation_failed = False
        self._observation_listener = None
        self._fds = []
        self.provider_network = None
        self._access_token_fd = -1
        self._managed_mount_started = False

    def _managed_mount(self):
        if self.role == 'appserver' and type(self.factory) is RegisteredN1Factory:
            return self.factory._managed_login
        return None

    def _appserver_mounts(self, home):
        mount = self._managed_mount()
        command = ['--bind', str(home), str(home), '--setenv', 'CODEX_HOME',
                   str(home if mount is None else qualification.LOGIN_MOUNT)]
        for name in self.factory.spec['configuration_files']:
            command += ['--ro-bind', str(home / name), str(home / name)]
        if mount is not None:
            _need(self.factory._managed_lease is not None, "The managed login requires its original lease.")
            self.factory._managed_lifetime = self
            command += mount.options(home)
        return command

    def _command(self, command, home, block, info):
        spec, host = self.factory.spec, self.factory.host
        worker_readonly = self.provider_network is not None
        actual_writable = () if self.validator or worker_readonly else (host.worker,)
        if self.role == 'appserver':
            actual_writable += (home,)
        self.factory.host_records.assert_worker_roots_excluded(actual_writable)
        argv = [spec['launcher'], '--unshare-all', '--die-with-parent', '--new-session',
                '--cap-drop', 'ALL', '--clearenv', '--block-fd', str(block), '--info-fd', str(info)]
        for directory in _RUNTIME:
            argv += ['--ro-bind', directory, directory]
        argv += ['--symlink', 'usr/bin', '/bin', '--proc', '/proc', '--dev', '/dev',
                 '--tmpfs', '/tmp', '--tmpfs', '/home', '--dir', '/etc',
                 '--setenv', 'HOME', '/home/worker', '--setenv', 'LC_ALL', 'C.UTF-8',
                 '--setenv', 'PATH', '/usr/bin:/bin']
        # The runtime supplies the finite shell. Bind other executables after overlays.
        if self.role != 'tool':
            argv += ['--ro-bind', command[0], command[0]]
        argv += ['--ro-bind', spec['validator'], spec['validator']]
        if self.validator:
            scripts = str(Path(__file__).resolve().parent)
            argv += ['--ro-bind', scripts, '/cwo/scripts', '--chdir', '/tmp']
            for name in ('policy', 'schemas'):
                argv += ['--ro-bind', str(Path(scripts).parent / name), '/cwo/' + name]
        else:
            worker = str(host.worker)
            argv += ['--ro-bind' if worker_readonly else '--bind', worker, worker,
                     '--ro-bind', worker + '/.git', worker + '/.git',
                     '--chdir', worker]
            if self.role == 'appserver':
                argv += self._appserver_mounts(home)
        argv += self._provider_network_mounts()
        argv += ['--remount-ro', '/']
        return argv

    def _provider_network_selected(self):
        return (self.role == 'appserver' and type(self.factory) is RegisteredN1Factory
                and self.factory.qualification is not None)

    def _provider_network_fds(self):
        if not self._provider_network_selected():
            return ()
        token = self.factory._take_provider_access_token()
        self.provider_network = provider_network.ProviderBroker(
            self._record_provider_denial, allow_personal_access_token=token is not None,
            allow_managed_login=self._managed_mount() is not None)
        control = self.provider_network.child_socket.fileno()
        if token is None:
            return (control,)
        self._stage_access_token(token)
        return (control, self._access_token_fd)

    def _pipe(self):
        descriptors = os.pipe()
        self._fds.extend(descriptors)
        return descriptors

    def _close_fd(self, descriptor):
        self._fds.remove(descriptor)
        os.close(descriptor)

    def _launch_pipes(self):
        gate = self._pipe()
        try:
            info = self._pipe()
        except BaseException as failure:
            for descriptor in gate:
                try:
                    self._close_fd(descriptor)
                except OSError as secondary:
                    admission.ledger_api.add_failure_note(
                        failure, 'Prelaunch pipe cleanup failed: ' + type(secondary).__name__)
            raise
        return (*gate, *info)

    def _stage_access_token(self, token):
        self._access_token_fd, writer = self._pipe()
        try:
            _need(os.write(writer, token) == len(token), "Provider credential handoff was incomplete.")
        finally:
            self._close_fd(writer)

    def _record_provider_denial(self, reason):
        self.factory.record('provider-network-denied', {'reason': reason})

    def _provider_network_mounts(self):
        if self.provider_network is None:
            return []
        return ['--ro-bind', str(provider_network.RELAY_SOURCE), provider_network.RELAY_MOUNT,
                '--ro-bind-try', '/etc/ssl/certs/ca-certificates.crt', '/etc/ssl/certs/ca-certificates.crt',
                '--ro-bind-try', '/etc/pki/tls/certs/ca-bundle.crt', '/etc/pki/tls/certs/ca-bundle.crt']

    def _release_gate(self, descriptor, tool_call, deadline):
        if self.role == 'tool':
            _need(self.factory.server is not None and self.factory.server.finite_tools is not None,
                  "Unselected tool containment has no gate authority.")
            self.factory.server.finite_tools._require_capture_current()
            self.factory.server.finite_input.dispatch_registered_gate(
                descriptor, tool_call, deadline)
        else:
            os.set_blocking(descriptor, False)
            os.write(descriptor, b'1')

    def _bootstrap_command(self, command):
        entry = [self.factory.spec['validator'], '-I', '-S']
        if self.provider_network is not None:
            return [*entry, provider_network.RELAY_MOUNT, str(self.provider_network.child_socket.fileno()),
                    str(self._access_token_fd), *command]
        return [*entry, '-c', _BOOTSTRAP, *command]

    def _confirm_mounts(self):
        _need(select.select([self.process.stdout], [], [], 5)[0], "Trusted namespace bootstrap readiness timed out.")
        _need(self.process.stdout.readline(64) == _READY, "Trusted namespace bootstrap readiness differs.")
        self.controller._engine._verified(self.controller._engine._lookup(self.receipt))
        _need(self._namespace_identity(self._namespace_pid) == self._namespace_birth,
              "Namespace birth changed after filesystem setup.")
        root = Path('/proc') / str(self._namespace_pid) / 'root'
        for source in self.factory._protected_roots():
            _not_exposed(root, source)
        self._confirm_login_mount(root)
        _need(not select.select([self.namespace_handle], [], [], 0)[0], "The inspected namespace has exited.")

    def _confirm_login_mount(self, root):
        mount = self._managed_mount()
        if mount is not None:
            mount.confirm(root, self.factory.home)
        else:
            _need(not (root / qualification.LOGIN_MOUNT.relative_to('/')).exists(),
                  "The managed login projection is visible outside its app-server namespace.")

    def _release_command(self, write_gate, observation, tool_call, deadline):
        # Bubblewrap's gate precedes filesystem setup. Only the fixed trusted
        # bootstrap runs after it, and the original command remains gated.
        self._managed_mount_started = self._managed_mount() is not None
        os.write(write_gate, b'1')
        self._confirm_mounts()
        observation['filesystem_ready'] = True
        self.factory.require_effect()
        self.factory.record(self.role + '-contained', observation)
        if self.role == 'tool':
            self.factory.server.finite_input.lifecycle.move('gate-closed', call=tool_call['callId'])
        self.factory.require_effect()
        _record_appserver_start(self.factory, self.role)
        self._release_gate(self.process.stdin.fileno(), tool_call, deadline)

    def _preflight_tool_launch(self, tool_call, deadline, tool_decision):
        if self.role != 'tool':
            return
        server = self.factory.server
        _need(self.factory.spec.get('finite_tool_mode') in finite_calls.CAPTURE_MODES
              and server is not None and server.finite_tools is not None,
              "The original selected finite producer is required before tool spawn.")
        server.finite_tools._require_capture_source()
        server.finite_tools._require_capture_current()
        server.finite_tools.require_launch(tool_call, deadline, tool_decision)

    def _preflight_qualification_schema(self):
        factory = self.factory
        if self.role == 'appserver' and type(factory) is RegisteredN1Factory and factory.qualification is not None:
            qualification.require_executable_schema(factory.spec['executable'], factory.spec['executable_sha256'])
            factory.require_effect()

    def launch(self, command, home, *, tool_call=None, deadline=None, tool_decision=None):
        _require_launch_selection(self.factory)
        self.factory.require_effect()
        _need((self.role == 'appserver' and command == [self.factory.spec['executable'], 'app-server', '--stdio'])
              or (self.role == 'tool' and command == ['/usr/bin/sh', '-c', self.factory.spec['command']])
              or (self.role == 'validator' and command == [self.factory.spec['validator'], '-I', '-S', '-c', _VALIDATOR]),
              "The trusted containment role has no other executable allowance.")
        self._preflight_tool_launch(tool_call, deadline, tool_decision)
        self._preflight_qualification_schema()
        self.command = tuple(command)
        read_gate, write_gate, read_info, write_info = self._launch_pipes()
        try:
            network_fds = self._provider_network_fds()
            argv = self._command(command, home, read_gate, write_info)
            arguments = _argument_file()
            self._fds.append(arguments)
            encoded = b'\0'.join(part.encode() for part in argv[1:]) + b'\0'
            _need(len(encoded) <= owned.MAX_ARGV_BYTES, "Registered launcher arguments exceed the original byte bound.")
            _need(os.write(arguments, encoded) == len(encoded), "The sealed launcher arguments were not completely written.")
            os.lseek(arguments, 0, os.SEEK_SET)
            # Linux UAPI: F_ADD_SEALS=1033, F_GET_SEALS=1034; all four seals=15.
            # Some supported Python builds omit these exported C constants.
            fcntl.fcntl(arguments, 1033, 15)
            _need(fcntl.fcntl(arguments, 1034) & 15 == 15, "Immutable argument-file seals were not observed.")
            backend = _PipeBackend((read_gate, write_info, arguments, *network_fds))
            self.controller = owned.LinuxOwnedChildController(self.factory.spec['launcher'])
            self.controller._backend = backend
            self.controller._engine = owned._LinuxEngine(backend, self.factory.spec['launcher'])
            result = self.controller.spawn_owned(
                self.factory.operation_id + {'appserver': '-transport', 'tool': '-tool',
                                             'validator': '-validation'}[self.role],
                _launcher_argv(argv[0], arguments, self._bootstrap_command(command)), str(self.factory.host.worker))
            self._retain(result)
            self._release_provider_descriptor()
            _need(result.get('outcome') == 'registered' and self.receipt is not None,
                  "Retained-child registration is required before startup.")
            birth = next(item for item in backend.births if item.receipt is self.receipt)
            self.birth = birth
            self.process = birth.child
            if self.role == 'tool':
                self.factory.server.finite_input.publish_pending_lifetime(self)
            for descriptor in (read_gate, write_info):
                self._close_fd(descriptor)
            observation = self._observe(read_info)
            self.controller._engine._verified(self.controller._engine._lookup(self.receipt))
            # This is the only gate release. A selected tool must still be the
            # current issued call when the one-byte, nonblocking gate opens.
            self._release_command(write_gate, observation, tool_call, deadline)
            return self.process
        except BaseException as failure:
            self._retain(getattr(failure, 'ownership_report', None))
            self._cleanup_launch_failure(failure)
            raise
        finally:
            for descriptor in self._fds:
                os.close(descriptor)
            self._fds = []

    def _cleanup_launch_failure(self, failure):
        # A published tool birth belongs to the gate even if launch fails
        # before the producer receives its lifetime. This path must publish
        # its own bounded observer result, including a timeout, at that gate.
        if self.role == 'tool' and self.factory.server is not None:
            gate = self.factory.server.finite_input
            with gate.lock:
                published = (gate.pending_lifetime is self or gate.lifetime is self
                             or gate.closed_lifetime is self)
            if published:
                gate.close(failure)
                return
        if self.receipt is None:
            self._close_provider_network(failure)
        self.cleanup_failure(failure)

    def _release_provider_descriptor(self):
        if self.provider_network is not None:
            self.provider_network.child_socket.close()
        if self._access_token_fd != -1:
            self._close_fd(self._access_token_fd)
            self._access_token_fd = -1

    def _close_provider_network(self, primary=None):
        if self.provider_network is None:
            return
        try:
            self.provider_network.close()
        except BaseException as secondary:
            if primary is None:
                raise
            admission.ledger_api.add_failure_note(primary,
                'Provider network cleanup failed: ' + type(secondary).__name__)

    def _retain(self, report):
        if type(report) is dict and report.get('receipt_available') is True:
            receipt = report.get('receipt')
            if type(receipt) is owned.OwnedChildReceipt:
                self.receipt = receipt

    def _observe(self, descriptor):
        info = _namespace_info(descriptor)
        pid = info.get('child-pid')
        _need(type(pid) is int and pid > 1, "No independent namespace child identity was observed.")
        facts = self._retain_namespace(pid)
        return {'child_pid': pid, 'namespaces': facts,
                'scope': 'credentialless-validator' if self.validator else 'worker-only-' + self.role}

    def _retain_namespace(self, pid):
        before = self._namespace_identity(pid)
        descriptor = os.pidfd_open(pid, 0)
        try:
            facts = self._check_namespace_handle(pid, descriptor, before)
        except BaseException:
            os.close(descriptor)
            raise
        # A cleanup handle is issued only after original-parent and birth checks.
        self.namespace_handle = descriptor
        self._namespace_pid, self._namespace_birth = pid, before
        return facts

    def _check_namespace_handle(self, pid, descriptor, before):
        fdinfo = Path('/proc/self/fdinfo') / str(descriptor)
        _need('Pid:\t' + str(pid) in fdinfo.read_text().splitlines(), "The namespace birth handle is not bound to the observed child.")
        _need(self._namespace_identity(pid) == before, "Namespace birth changed while retaining its handle.")
        child = Path('/proc') / str(pid)
        status = dict(line.split(':', 1) for line in (child / 'status').read_text().splitlines() if ':' in line)
        _need(status.get('NSpid', '').split()[-1:] == ['1'], "The retained namespace child is not its PID namespace init.")
        facts = {kind: os.readlink(child / 'ns' / kind) for kind in ('mnt', 'net', 'pid', 'user')}
        for kind, observed in facts.items():
            _need(observed != os.readlink(Path('/proc/self/ns') / kind), "Required namespace separation is absent.")
        _need('Pid:\t' + str(pid) in fdinfo.read_text().splitlines(), "Namespace lifetime changed during observation.")
        _need(not select.select([descriptor], [], [], 0)[0], "The blocked namespace has exited.")
        return facts

    def _namespace_identity(self, pid):
        registration = self.controller.owned_registration(self.receipt)
        _need(registration is not None, "The original namespace launcher is no longer retained.")
        value = parse_proc_stat((Path('/proc') / str(pid) / 'stat').read_text())
        _need(value.pid == pid and value.ppid == registration.pid,
              "The namespace is not the original retained launcher's child.")
        return value.pid, value.ppid, value.start_ticks

    def _stop_namespace(self):
        _need(self.namespace_handle is not None, "No retained original namespace handle is available.")
        if not select.select([self.namespace_handle], [], [], .1)[0]:
            self._signal_namespace()
        _need(select.select([self.namespace_handle], [], [], 5)[0],
              "The retained PID namespace init is not confirmed dead; capture is refused.")
        os.close(self.namespace_handle)
        self.namespace_handle = None

    def _signal_namespace(self):
        try:
            signal.pidfd_send_signal(self.namespace_handle, signal.SIGKILL)
        except ProcessLookupError:
            # Natural exit may win after the readiness check. Only the same
            # retained handle's subsequent exit observation can confirm it.
            pass

    def terminate(self):
        # This direct API cannot turn an uncertain prior attempt into a retry.
        self._revoke_before_ending()
        with self._lock:
            _need(not self._ending, "Termination already attempted; unknown termination cannot be retried.")
            self._ending = True
            self._termination_owner = threading.get_ident()
        return self._terminate_claimed()

    def settle_termination(self):
        self._revoke_before_ending()
        # Reserve the observation before waiting. Its result commits under the
        # same short lock before any caller can append a secondary failure note.
        with self._lock:
            self._observation_pending += 1
            claimed = not self._ending
            if claimed:
                self._ending = True
                self._termination_owner = threading.get_ident()
            owner = self._termination_owner
        if self.role == 'appserver' and self.factory.server is not None:
            self.factory.server.finite_input.lifecycle.original_cleanup_event('pending')
        failure = None
        try:
            if claimed:
                return self._terminate_claimed()
            if owner == threading.get_ident() and not self._termination_finished.is_set():
                raise TerminationObservationError(
                    'reentrant', "The termination owner cannot wait on its own completion.")
            if not self._termination_finished.wait(10):
                raise TerminationObservationError(
                    'timeout', "The original owned-child termination remains in flight.")
            if self._termination_error is not None:
                raise self._termination_error
            _need(self.contained and self.termination_recorded,
                  "The original owned-child containment or record remains unresolved.")
            return self.termination
        except BaseException as secondary:
            failure = secondary
            raise
        finally:
            self._record_observation(failure, reserved=True)

    def _revoke_before_ending(self):
        server = self.factory.server
        if self.provider_network is not None:
            self.provider_network.revoke()
        # A clean owned tool may still supply its final empty-poll output.
        # Transport ending is a connection-wide negative; tool reaping is not.
        if self.role == 'appserver' and server is not None:
            server.finite_input.lifecycle.authority_revoke('closed')

    def _terminate_monitor(self):
        _need(self.receipt is not None, "No original owned-child receipt is available.")
        try:
            self.termination = self.controller.terminate(self.receipt, 0.1, allow_kill=True)
        except BaseException as failure:
            self.termination = getattr(failure, 'ownership_report', None)
            raise
        report = self.termination
        controlled = report.get('outcome') in {'terminated', 'killed', 'already-exited', 'exited-before-signal'}
        _need((controlled or self._reaped_monitor_without_exe(report))
              and report.get('child_exit_confirmed') is True and report.get('child_reaped') is True,
              "Controlled termination and same-handle reaping are required before capture.")
        return report

    def _reaped_monitor_without_exe(self, report):
        """Use completed original custody when natural exit removed the proc link."""
        birth = self.birth
        if (report.get('outcome') != 'identity-unavailable' or report.get('signals') != []
                or birth is None or birth.receipt is not self.receipt):
            return False
        if (not birth.exit_confirmed or not birth.reaped or report.get('child_pid') != birth.pid
                or report.get('registration_committed') is not True or report.get('receipt_available') is not False):
            return False
        missing = FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT), f'/proc/{birth.pid}/exe')
        return report.get('reason') == str(missing)

    def _stop_namespace_preserving(self, primary):
        try:
            if self.namespace_handle is not None:
                self._stop_namespace()
        except BaseException as secondary:
            self._note_namespace_cleanup(primary, secondary)

    @staticmethod
    def _note_namespace_cleanup(primary, secondary):
        try:
            admission.ledger_api.add_failure_note(primary,
                'Independent retained namespace cleanup failed: ' + validation._exception_text(secondary))
        except BaseException:
            pass

    def _terminate_claimed(self):
        try:
            try:
                report = self._terminate_monitor()
            except BaseException as primary:
                self._stop_namespace_preserving(primary)
                raise
            self._stop_namespace()
            self.contained = True
            self._close_provider_network()
            self.factory.record(self.role + '-terminated',
                                {key: value for key, value in report.items() if key != 'receipt'})
            self.termination_recorded = True
            return report
        except BaseException as failure:
            self._termination_error = failure
            self._close_provider_network(failure)
            raise
        finally:
            self._termination_finished.set()

    def set_observation_listener(self, listener):
        with self._lock:
            _need(self._observation_listener is None,
                  "The original cleanup observation listener is already bound.")
            self._observation_listener = listener

    def _record_observation(self, failure=None, *, reserved=False, kind=None):
        with self._lock:
            if kind is None:
                if failure is None:
                    kind = 'completed'
                elif isinstance(failure, TerminationObservationError):
                    kind = failure.kind
                elif failure is self._termination_error:
                    kind = ('record-failed' if self.contained and not self.termination_recorded
                            else 'owner-failed')
                else:
                    kind = 'observer-failed'
            observation = CleanupObservation(kind, self.contained, self.termination_recorded)
            self._observation_results.append(observation)
            self._observation_failed |= (kind != 'completed' or not self.contained
                                         or not self.termination_recorded)
            if reserved:
                self._observation_pending -= 1
            listener = self._observation_listener
        self._observation_local.failure = failure
        self._observation_local.result = observation
        self._publish_original_cleanup(observation)
        if listener is not None:
            try:
                listener(self)
            except BaseException:
                # The result has already committed. A failed reducer callback
                # may not turn its observer or the original primary healthy.
                with self._lock:
                    self._observation_failed = True
            finally:
                # A same-thread listener may reenter and append another result.
                # Restore this call's immutable result for its own caller.
                self._observation_local.failure = failure
                self._observation_local.result = observation
        return observation

    def _publish_original_cleanup(self, observation):
        if self.role != 'appserver' or self.factory.server is None:
            return
        phase = ('contained' if observation.kind == 'completed'
                 and observation.physical_contained and observation.termination_recorded
                 else 'unknown')
        self.factory.server.finite_input.lifecycle.original_cleanup_event(phase)

    def observation_snapshot(self):
        with self._lock:
            return (tuple(self._observation_results), self._observation_pending,
                    self._observation_failed, self._termination_error is not None,
                    self.contained, self.termination_recorded, self._ending)

    def cleanup_observation(self, failure):
        # A patched or exceptional observer may fail before entering
        # settle_termination. Such a result still becomes authoritative.
        if (getattr(self._observation_local, 'failure', None) is failure
                and hasattr(self._observation_local, 'result')):
            return self._observation_local.result
        return self._record_observation(failure)

    def cleanup_failure(self, primary):
        if self.receipt is None and not self._ending:
            return self._record_observation(kind='unavailable')
        try:
            self.settle_termination()
        except BaseException as secondary:
            observation = self.cleanup_observation(secondary)
            try:
                admission.ledger_api.add_failure_note(
                    primary, 'Owned containment cleanup failed: ' + type(secondary).__name__)
            except BaseException:
                try:
                    primary.add_note('Owned containment cleanup note publication failed.')
                except BaseException:
                    pass
            return observation
        return self._observation_local.result


class _CoherentServerRequests(RegisteredServerRequests):
    """Publish original server request facts before releasing their common request lock.

    The original registry owns correlation, revocation and deadline decisions.
    Its lock is reentrant on this instance so the existing registry methods
    can execute inside the outer requests -> reducer publication fence.
    """

    def __init__(self, server):
        super().__init__(server)
        self.lock = threading.RLock()

    @staticmethod
    def _binding(entry):
        c = entry.correlation
        return None if c is None else (
            c.epoch, c.request_id, c.thread_id, c.turn_id, c.item_id, c.approval_id)

    def _latch_negative(self, kind, scope=None):
        self.server.finite_input.lifecycle.authority_revoke(kind, scope)

    def _commit_ingress(self, entry):
        lifecycle = self.server.finite_input.lifecycle
        return lifecycle.authority_dispatch('transport-ingress', self._binding(entry)) is not None

    def _commit_reply(self, entry):
        return self.server.finite_input.lifecycle.authority_dispatch(
            'reply-grant', self._binding(entry))

    def _reply_result(self, entry, dispatch, result):
        if dispatch is not None:
            self.server.finite_input.lifecycle.authority_result(dispatch, result)

    def _publish_progress(self):
        gate = getattr(self.server, 'finite_input', None)
        if gate is None:
            return
        lifecycle = gate.lifecycle
        if self.terminals or self.trusted_terminals or self.cancelled_turn is not None:
            lifecycle.original_transport_event('terminal')
        if self.server.transport_failure is not None:
            lifecycle.original_transport_event('fault')
        if self.closed:
            lifecycle.original_transport_event('closed')
        for key, entry in self.entries.items():
            binding = self._binding(entry)
            accepted = entry.state == 'sent' and entry.delivery == 'sent' and entry.accepting
            lifecycle.original_request_event(
                key, entry.state, binding=binding, deadline=entry.deadline,
                expired=entry.expired, accepted=accepted, delivery=entry.delivery)
        self.server._sync_finite_progress_locked()

    def _original_transition(self, action, *args, **kwargs):
        """Publish original facts and errors under one requests -> reducer fence.

        A later invalid projection cannot strand an earlier selected fact.
        Even a rejection before mutation faults before request-lock release, so
        a concurrent effect cannot use an otherwise live prior phase.
        """
        with self.lock:
            primary = publication = None
            try:
                return action(*args, **kwargs)
            except BaseException as failure:
                primary = failure
                # Publish the primary error before any reducer notification can
                # release a waiter to observe this exceptional transition.
                self.server._publish_transport_failure(failure)
                raise
            finally:
                try:
                    self._publish_progress()
                except BaseException as failure:
                    publication = failure
                    if primary is not None:
                        primary.add_note('Reducer publication also failed: '
                                         + type(failure).__name__)
                try:
                    if primary is not None or publication is not None:
                        cause = primary if primary is not None else publication
                        self.server._publish_transport_failure(cause)
                        if self.server.finite_tools is not None:
                            self.server.finite_input.lifecycle.finish('fault')
                finally:
                    self.wake.set()
                if publication is not None and primary is None:
                    raise publication

    def receive(self, message):
        return self._original_transition(super().receive, message)

    def _take(self):
        with self.lock:
            entry = super()._take()
            self._publish_progress()
            return entry

    def _ready(self, *args, **kwargs):
        return self._original_transition(super()._ready, *args, **kwargs)

    def observe(self, message):
        return self._original_transition(super().observe, message)

    def observe_response(self, message):
        return self._original_transition(super().observe_response, message)

    def observe_turn_response(self, thread_id, turn):
        return self._original_transition(super().observe_turn_response, thread_id, turn)

    def observe_trusted_terminal(self, thread_id, turn_id, boundary):
        return self._original_transition(
            super().observe_trusted_terminal, thread_id, turn_id, boundary)

    def cancel_turn(self, thread_id, turn_id):
        return self._original_transition(super().cancel_turn, thread_id, turn_id)

    def close(self):
        return self._original_transition(super().close)


class _RegisteredServer(RegisteredAppServer):
    """Original process/RPC client behind the registered namespace boundary."""

    def __init__(self, factory):
        self.factory = factory
        self.lifetime = _Containment(factory)
        self.archived = False
        self._approval_ids, self._request_ids, self._items = set(), set(), {}
        self._profile_response = None
        self.thread_id = None
        self.transport_failure = None
        self._response_ids = set()
        self._command_reply_committed = None
        self._wire_turn = None
        self.requests = _CoherentServerRequests(self)
        self.finite_input = RegisteredFiniteInput(factory, self)
        self.finite_tools = None
        self.qualified_tool_evidence = (finite_calls.QualifiedToolEvidence(self)
                                        if _qualification_operation_metadata(factory) is not None else None)
        self._tool_queue = None
        self._tool_cleanup_lock = threading.Lock()
        self._tool_cleanup_scheduled = False
        self._worker_lock = threading.Lock()
        self._workers = []
        self._workers_closed = False
        if factory.spec.get('finite_tool_mode') in finite_calls.CAPTURE_MODES:
            self.finite_tools = finite_calls.RegisteredFiniteToolCalls(self)
            self._tool_queue = queue.Queue(maxsize=8)
        super().__init__(requested_model=factory.spec['model'], reasoning_effort=factory.spec['effort'],
                         operation_metadata=_qualification_operation_metadata(factory))
        self._register_qualification_rpc()

    def _register_qualification_rpc(self):
        factory = self.factory
        if type(self) is _RegisteredServer and type(factory) is RegisteredN1Factory and factory.qualification is not None:
            self._qualification_rpcs = set()
            _QUALIFICATION_RPC.register(self, (
                lambda: RegisteredN1Factory.require_qualification_rpc(factory),
                lambda method, request: _RegisteredServer._check_qualification_wire(self, method, request),
                qualification.TIER,
            ))

    def _check_qualification_wire(self, method, request):
        _need(type(request.get('id')) is int and method not in self._qualification_rpcs,
              "Only one registered qualification thread and turn may start.")
        params = request['params']
        if method == 'thread/start':
            _need(params == self.factory._thread_start_parameters(), "Qualification thread selectors differ.")
        else:
            self._check_qualification_turn(request, params)
        self._qualification_rpcs.add(method)

    def _check_qualification_turn(self, request, params):
        record = self._turn_dispatch_records.get(self.thread_id, {})
        pins = {'threadId': self.thread_id, 'model': qualification.MODEL,
                'effort': qualification.EFFORT, 'serviceTier': qualification.TIER,
                'input': [{'type': 'text', 'text': self.factory.model_task_bytes().decode(), 'text_elements': []}]}
        _need(self._qualification_rpcs == {'thread/start'}
              and record.get('wire_request_sha256') == domain_sha256(request, domain='app-server-single-wire-request')
              and set(params) == set(pins) | {'clientUserMessageId', 'responsesapiClientMetadata'}
              and all(params.get(key) == value for key, value in pins.items()),
              "Qualification turn differs from the registered model, effort, tier or original task.")

    def _default_executable(self):
        return self.factory.spec['executable']

    def _requested_home(self):
        return self.factory.appserver_home()

    def _initialize_protocol(self, home, binding):
        super()._initialize_protocol(home, binding)
        # The wire readback verifies the child path. The controller uses the
        # original operation's physical spool for its own observations.
        self.codex_home = self.factory.home

    def _guard_thread_observation(self, thread_id, thread):
        super()._guard_thread_observation(thread_id, thread)
        self._observe_managed_rollout(thread)

    def _observe_managed_rollout(self, thread):
        if self.factory._managed_login is not None:
            self.factory._managed_login.observe_rollout(self.factory.home, thread)

    def _confirm_managed_archive(self, thread_id):
        if self.factory._managed_login is not None:
            self.factory._managed_login.confirm_archived(self.factory.home, thread_id)

    def _protocol_lines(self):
        try:
            for line in self._bounded_lines():
                message = decode_protocol_frame(line.encode('utf-8'))
                classified = protocol.classify_message(message)
                if type(classified) is protocol.Response:
                    self._observe_response(message)
                elif type(classified) is protocol.Notification:
                    self._check_finite_notification(message)
                    self.requests.observe(message)
                yield line
                if self.transport_failure is not None:
                    return
        except BaseException as failure:
            self._fail_transport(failure)

    def _check_finite_notification(self, message):
        if self.finite_tools is None:
            return
        method = message.get('method')
        params = message.get('params', {})
        item = params.get('item', {})
        if self.qualified_tool_evidence is not None:
            self._observe_qualified_tool_item(method, params, item)
            return
        if method == 'item/started':
            _need(item.get('type') not in {'commandExecution', 'fileChange'},
                  "Selected finite tools refuse uncontrolled builtin execution or writes.")
        if method == 'item/completed' and item.get('id') == self.finite_tools.command_call_id:
            identity = params.get('threadId'), params.get('turnId'), item.get('id')
            with self.requests.lock:
                _need(item.get('status') == 'completed'
                      and (self._command_reply_committed == identity
                           or self.finite_input.lifecycle.command_reply_dispatched(identity)),
                      "The original finite command completion must follow its dispatched reply.")

    def _observe_qualified_tool_item(self, method, params, item):
        if method == 'turn/completed':
            with self.requests.lock:
                self.qualified_tool_evidence.observe_turn_terminal(params)
            return
        if method == 'item/started':
            _need(item.get('type') not in {'commandExecution', 'fileChange'},
                  'Selected finite tools refuse uncontrolled builtin execution or writes.')
            if item.get('type') == 'dynamicToolCall':
                _need(item.get('namespace') == qualification.FINITE_TOOL_NAMESPACE
                      and item.get('tool') in ('finite_command', 'finite_poll')
                      and item.get('status') == 'inProgress'
                      and item.get('contentItems') is None and item.get('success') is None,
                      'Qualification requires an original direct finite tool item.')
        if method == 'item/completed':
            with self.requests.lock:
                identity = params.get('threadId'), params.get('turnId'), item.get('id')
                started = self._items.get(identity, {})
                if started.get('type') == 'dynamicToolCall' or item.get('type') == 'dynamicToolCall':
                    _need(item.get('type') == 'dynamicToolCall', 'Qualification completion must be typed.')
                    self.qualified_tool_evidence.complete(params, item)

    def _sync_finite_progress_locked(self):
        """Reconcile selected original facts under requests -> reducer.

        Called by every server request mutation route while the common request lock is
        held, including the registry's own refusal and close paths.
        """
        if self.finite_tools is None:
            return
        if self.qualified_tool_evidence is not None:
            self.qualified_tool_evidence.settlement.notify_all()
        lifecycle = self.finite_input.lifecycle
        with lifecycle.condition:
            if self.transport_failure is not None:
                lifecycle.finish('fault')
                return
            if self.requests.closed:
                lifecycle.finish('closed')
                return
            if self._wire_turn is not None:
                turn = self._wire_turn[:2]
                if (turn in self.requests.terminals
                        or turn in self.requests.trusted_terminals
                        or turn == self.requests.cancelled_turn):
                    lifecycle.finish('terminal', turn=turn)
                    return
                if self._sync_command_completion_locked(lifecycle, turn):
                    return
                if self._completed_unreplied_item_locked(lifecycle, turn):
                    lifecycle.finish('refused')
                    return
            if self.requests.refusal_only:
                lifecycle.finish('refused')

    def _sync_command_completion_locked(self, lifecycle, turn):
        command = self.finite_tools.command_call_id
        if command is None or (*turn, command) not in self.requests.completed_items:
            return False
        evidence = self.qualified_tool_evidence
        if evidence is not None and evidence.completion((*turn, command)) != 'committed':
            return False
        if lifecycle.phase == 'command-replied':
            lifecycle.complete(turn, command)
        elif lifecycle.phase == 'command-effect' and lifecycle.command_reply_dispatched(
                (*turn, command)):
            # Actual item intake may precede publication of a full physical
            # reply. A failed writer still faults; no completion is invented.
            return False
        elif lifecycle.phase in {'await-command', 'command-queued',
                'command-deciding', 'command-intent', 'pending-birth',
                'gate-closed', 'command-effect'}:
            lifecycle.finish('refused')
            return True
        return False

    def _completed_unreplied_item_locked(self, lifecycle, turn):
        command = self.finite_tools.command_call_id
        evidence = self.qualified_tool_evidence
        if evidence is not None:
            return any((*turn, entry[1]) in self.requests.completed_items
                       and evidence.completion((*turn, entry[1])) != 'pending'
                       for entry in lifecycle.pending.values())
        return any((*turn, entry[1]) in self.requests.completed_items
                   and not (entry[1] == command and lifecycle.phase == 'command-effect'
                            and lifecycle.command_reply_dispatched((*turn, command)))
                   for entry in lifecycle.pending.values())

    def await_finite_progress(self, *, host_deadline=None):
        """Wait for a bounded edge, then adjudicate expiry against the request registry."""
        if self.finite_tools is None:
            return
        lifecycle = self.finite_input.lifecycle
        while lifecycle.wait(host_deadline):
            with self.requests.lock:
                self._sync_finite_progress_locked()
                with lifecycle.condition:
                    deadline = lifecycle.progress_deadline()
                    expired = deadline is not None and deadline <= lifecycle.clock()
            if expired:
                raise AppServerError('registered-finite-progress-deadline')
        self._require_healthy()

    def _bounded_lines(self):
        total = 0
        for _index in range(512):
            line = self.process.stdout.readline(65537)
            if not line:
                _need(self.lifetime._ending, "The registered protocol ended before controlled termination.")
                return
            total += len(line.encode('utf-8'))
            _need(line.endswith('\n') and len(line.encode('utf-8')) <= 65536 and total <= 8388608,
                  "Transport frame/queue bound exceeded.")
            yield line
        raise native.OfflineHostError('Transport frame/queue bound exceeded.')

    def _drain_stderr(self):
        total = 0
        try:
            while True:
                chunk = self.process.stderr.buffer.read(4096)
                if not chunk:
                    return
                total += len(chunk)
                _need(total <= 65536, "The registered diagnostic byte budget was exceeded.")
                self._stderr_line_count += chunk.count(b'\n')
        except BaseException as failure:
            self._fail_transport(failure)
            with self._condition:
                self._condition.notify_all()

    def _read_stdout(self):
        try:
            super()._read_stdout()
        except BaseException as failure:
            self._fail_transport(failure)
        finally:
            if not self.lifetime._ending and self.transport_failure is None:
                self._fail_transport(AppServerError('registered-reader-ended-before-termination'))
            else:
                self.requests.close()
                if self.finite_tools is None:
                    self.finite_input.close(self.transport_failure)
                else:
                    self._schedule_tool_cleanup(self.transport_failure)

    def _latch_transport_failure(self, failure):
        with self.requests.lock:
            self._publish_transport_failure(failure)
            self._sync_finite_progress_locked()

    def _publish_transport_failure(self, failure):
        self.finite_input.lifecycle.authority_revoke('fault')
        if self.transport_failure is None:
            self.transport_failure = failure
            self.request_failure = failure
        try:
            self.requests._abort_inflight_reply()
        except BaseException as secondary:
            self.transport_failure.add_note('Reply descriptor fence failed: '
                                            + type(secondary).__name__)
        self.finite_input.lifecycle.original_transport_event('fault')
        self._reader_error = 'registered-transport-fault'

    def _fail_transport(self, failure):
        # Publish the fault under the request fence, then release it before
        # close and containment. A delayed close must not stall revocation or
        # the decision monitor's bounded reply.
        with self.requests.lock:
            self._publish_transport_failure(failure)
            self._sync_finite_progress_locked()
        self.requests.wake.set()
        self.requests.close()
        if self.finite_tools is None:
            self.finite_input.close(failure)
        else:
            self._schedule_tool_cleanup(failure)
        condition = getattr(self, '_condition', None)
        if condition is not None:
            with condition:
                condition.notify_all()

    def _schedule_tool_cleanup(self, failure):
        self.finite_input.revoke()
        with self._tool_cleanup_lock:
            if self._tool_cleanup_scheduled:
                return
            self._tool_cleanup_scheduled = True
        def cleanup():
            try:
                self.finite_input.close(failure)
            except BaseException as secondary:
                self._latch_transport_failure(secondary)
        self._start_worker(cleanup, 'cwo-registered-tool-cleanup', cleanup=True)

    def _start_worker(self, target, name, *, cleanup=False):
        worker = threading.Thread(target=target, name=name, daemon=True)
        started = threading.Event()
        with self._worker_lock:
            _need(cleanup or not self._workers_closed, 'Registered worker startup after close is refused.')
            self._workers.append((worker, started))
        try:
            worker.start()
        finally:
            started.set()

    def _begin_worker_shutdown(self):
        _QUALIFICATION_RPC.pop(self, None)
        with self._worker_lock:
            self._workers_closed = True

    def _worker_snapshot(self):
        with self._worker_lock:
            workers = list(self._workers)
        with self.requests.lock:
            workers.extend((worker, None) for worker in self.requests.threads)
        workers.extend((worker, None) for worker in self._reader_threads)
        return workers

    def _require_healthy(self):
        if self.transport_failure is not None:
            raise AppServerError('registered-transport-failed') from self.transport_failure
        transport_observation = self.lifetime.observation_snapshot()
        if transport_observation[2] or transport_observation[3]:
            raise AppServerError('registered-transport-cleanup-unresolved')
        if self.finite_tools is not None:
            gate = self.finite_input
            phase = gate.cleanup_phase()
            if phase == 'unknown' or (phase == 'cleanup-pending' and gate.state == 'revoked'):
                raise AppServerError('registered-tool-cleanup-unresolved')

    def request(self, *args, **kwargs):
        self._require_healthy()
        result = super().request(*args, **kwargs)
        self._require_healthy()
        return result

    def _observe_response(self, message):
        identity = message['id']
        _need(type(identity) is int and 0 < identity <= self._request_id and identity not in self._response_ids,
              "An unsolicited or repeated response identity was observed.")
        self._response_ids.add(identity)
        self.requests.observe_response(message)
        record = self._turn_dispatch_records.get(getattr(self, 'thread_id', None))
        if record is None or record['request_id'] != identity or 'error' in message:
            return
        result = message.get('result')
        turn = result.get('turn') if type(result) is dict else None
        turn_id = turn.get('id') if type(turn) is dict else None
        _need(record['status'] == 'dispatching' and record['connection_epoch_sha256'] == self.connection_epoch_sha256
              and type(turn_id) is str and 0 < len(turn_id) <= 256 and self._wire_turn is None,
              "The actual turn response is not bound to the original pending dispatch.")
        _need(turn.get('status') not in {'completed', 'failed', 'interrupted'},
              "The actual dispatched turn response is already terminal.")
        with self.requests.lock:
            self.requests.observe_turn_response(record['thread_id'], turn)
            self._wire_turn = (record['thread_id'], turn_id, identity)
            if self.finite_tools is not None:
                self.finite_input.lifecycle.select(
                    self.connection_epoch_sha256, self._wire_turn[:2], time.monotonic() + 15)

    def _launch_process(self, command, environment):
        _need(command == [self.factory.spec['executable'], 'app-server', '--stdio'], "Unexpected transport command.")
        process = self.lifetime.launch(command, self.factory.home)
        process.stdin = _DeadlineInput(process.stdin, self._fail_transport)
        # AppServer checks the initialize readback against this requested home.
        return process

    def _receive_method(self, message):
        try:
            self._route_method(message)
        except Exception as failure:
            self.request_failure = failure
            self._fail_transport(failure)

    def _route_method(self, message):
        if 'id' in message:
            self._reply(message)
            return
        super()._receive_method(message)

    def _reply(self, message):
        key = protocol._id_key(message['id'])
        _need(key not in self._request_ids and len(self._request_ids) < 64,
              "A repeated or unbounded inbound server request ID is refused across methods.")
        self._request_ids.add(key)
        if self.finite_tools is not None and message.get('method') == 'item/tool/call':
            try:
                deadline = time.monotonic() + 15
                tool = message.get('params', {}).get('tool')
                params = message.get('params', {})
                with self.finite_input.lifecycle.condition:
                    self._tool_queue.put_nowait((copy.deepcopy(message), deadline))
                    self.finite_input.lifecycle.queue(
                        key, tool, (params.get('threadId'), params.get('turnId')),
                        params.get('callId'), deadline)
            except queue.Full as failure:
                raise AppServerError('registered-tool-queue-bound') from failure
            return
        self.requests.receive(message)

    def _decision(self, method, params):
        self.factory.require_effect()
        if self.finite_tools is not None:
            return 'decline'
        approval = params.get('approvalId')
        if approval is not None:
            _need(approval not in self._approval_ids, "Repeated approval identity is refused.")
            self._approval_ids.add(approval)
        if method != protocol.COMMAND:
            return 'decline'
        blocked = ('additionalPermissions', 'environmentId', 'networkApprovalContext',
                   'proposedExecpolicyAmendment', 'proposedNetworkPolicyAmendments')
        if any(params.get(key) is not None for key in blocked):
            return 'decline'
        correlation = params.get('threadId'), params.get('turnId'), params.get('itemId')
        item = self._items.get(correlation)
        if item is None or self._wire_turn is None or correlation[:2] != self._wire_turn[:2]:
            return 'decline'
        if not self._command_item_matches(item, params):
            return 'decline'
        if type(params.get('startedAtMs')) is not int or not approval:
            return 'decline'
        return 'accept' if params.get('availableDecisions') == ['accept', 'decline'] else 'decline'

    def _command_item_matches(self, item, params):
        expected = {'kind': 'command', 'cwd': str(self.factory.host.worker), 'command': self.factory.spec['command']}
        return (all(params.get(key) == value for key, value in expected.items())
                and item.get('type') == 'commandExecution' and item.get('status') == 'inProgress'
                and item.get('command') == expected['command'] and item.get('cwd') == expected['cwd'])

    def start_registered_thread(self):
        self.factory.require_effect()
        params = self.factory._thread_start_parameters()
        response, _latency = self.request('thread/start', params, timeout=10)
        _check_response(self.factory, params, response)
        self._observe_managed_rollout(response['thread'])
        self.thread_id = response['thread']['id']
        if self.factory.qualification is None:
            self.factory.record_dispatch(self.thread_id)
        else:
            self.factory._record_qualification_dispatch(self.thread_id, response)
        self.started_threads[self.thread_id] = None
        self._known_thread_turn_ids[self.thread_id] = set()
        self._profile_response = copy.deepcopy(response)
        self._effective_thread_start_evidence = {self.thread_id: {'request': params, 'response': copy.deepcopy(response)}}
        if self.finite_tools is not None:
            self.finite_tools.register(params, response)
            self._start_worker(self._tool_loop, 'cwo-registered-tools')
        return response

    def _tool_loop(self):
        while self.transport_failure is None and not self.requests.closed:
            try:
                message, deadline = self._tool_queue.get(timeout=.05)
            except queue.Empty:
                continue
            try:
                response = self.finite_tools.receive(message, deadline=deadline)
                self._commit_tool_reply(message, response, deadline)
            except BaseException as failure:
                try:
                    self._commit_tool_reply(message, {'id': message['id'], 'error': {
                        'code': -32602, 'message': 'Registered finite tool refused.'}}, deadline, refusal=True)
                except BaseException as secondary:
                    admission.ledger_api.add_failure_note(failure, 'Tool reply failed: ' + type(secondary).__name__)
                self._fail_transport(failure)
                return

    def _capture_before_reply(self, refusal):
        if not refusal:
            self.finite_tools._require_capture_current()

    def _mark_command_reply(self, message, response, item):
        success = response.get('result', {}).get('success') is True
        tool = message.get('params', {}).get('tool')
        if success and tool == 'finite_command':
            self._command_reply_committed = item
        return self.finite_input.lifecycle.reply(
            protocol._id_key(message['id']), tool,
            message.get('params', {}).get('callId'), success)

    def _tool_reply_frame(self, message, response, deadline):
        if response.get('result', {}).get('success') is True:
            self.finite_tools.refresh_terminal_reply(message, response, deadline)
        frame = (json.dumps(response, separators=(',', ':')) + '\n').encode()
        _need(len(frame) <= 4096, "The finite tool reply exceeds the atomic pipe bound.")
        return frame

    def _commit_tool_reply(self, message, response, deadline, *, refusal=False):
        writer = self.process.stdin
        while time.monotonic() < deadline:
            frame = self._tool_reply_frame(message, response, deadline)
            observed = self.finite_input.issue_reply_observation(
                self.finite_tools, message, response, deadline, frame, refusal)
            if observed is None:
                continue
            if not writer._lock.acquire(timeout=.01):
                continue
            try:
                self._capture_before_reply(refusal)
                if self.finite_input.commit_reply_observation(
                        observed, self.finite_tools, message, response, deadline,
                        frame, writer, refusal):
                    return
            finally:
                writer._lock.release()
        raise TimeoutError('registered-finite-tool-reply-deadline')

    def interrupt_turn(self, thread_id, turn_id, *, timeout=15):
        if self.finite_tools is None:
            self.requests.cancel_turn(thread_id, turn_id)
        else:
            with self.finite_tools.lock:
                self.requests.cancel_turn(thread_id, turn_id)
        if self.finite_tools is None:
            self.finite_input.close()
        else:
            self.finite_tools.close()
        return super().interrupt_turn(thread_id, turn_id, timeout=timeout)

    def archive_thread(self, thread_id):
        self._begin_worker_shutdown()
        if self.finite_tools is None:
            if self._wire_turn is not None:
                self.requests.cancel_turn(*self._wire_turn[:2])
        else:
            with self.finite_tools.lock:
                if self._wire_turn is not None:
                    self.requests.cancel_turn(*self._wire_turn[:2])
                else:
                    self.requests.close()
        if self.finite_tools is None:
            self.finite_input.close()
        else:
            self.finite_tools.close()
        latency = super().archive_thread(thread_id)
        self._confirm_managed_archive(thread_id)
        self.requests.close()
        self.lifetime.settle_termination()
        self._join_readers()
        self._require_healthy()
        self.archived = True
        return latency

    def _join_readers(self, timeout=1):
        _need(type(timeout) in (int, float) and 0 <= timeout <= 12,
              'A bounded worker-drain timeout is required.')
        self._begin_worker_shutdown()
        deadline = time.monotonic() + timeout
        current = threading.current_thread()
        while True:
            for worker, started in self._worker_snapshot():
                self._join_worker(worker, started, current, deadline)
            pending, unchanged = self._pending_workers()
            if not pending and unchanged:
                return
            _need(time.monotonic() < deadline and current not in pending,
                  'Registered transport workers did not stop.')

    def _pending_workers(self):
        with self._worker_lock:
            registered = len(self._workers)
        pending = [worker for worker, started in self._worker_snapshot()
                   if self._worker_pending(worker, started)]
        # A creator may register cleanup after the snapshot and exit before
        # is_alive is read. Its dead status alone cannot retire that new owner.
        with self._worker_lock:
            unchanged = registered == len(self._workers)
        return pending, unchanged

    @staticmethod
    def _join_worker(worker, started, current, deadline):
        if worker is current:
            return
        if started is not None and not started.wait(max(0, deadline - time.monotonic())):
            return
        if worker.ident is not None:
            worker.join(max(0, deadline - time.monotonic()))

    @staticmethod
    def _worker_pending(worker, started):
        return worker.is_alive() or (started is not None and not started.is_set())

    def close(self):
        self._begin_worker_shutdown()
        primary = None
        try:
            self._close_transport()
        except BaseException as failure:
            primary = failure
            raise
        finally:
            try:
                self._join_readers()
            except BaseException as failure:
                target = failure if primary is None else primary
                self._record_worker_shutdown_failure(target, failure)
                if primary is None:
                    raise
                admission.ledger_api.add_failure_note(primary, 'Transport workers remain unresolved: '
                                                       + type(failure).__name__)
        if self.process is not None:
            for name in ('stdin', 'stdout', 'stderr'):
                getattr(self.process, name).close()
        self._require_healthy()
        return {'all_contained': True, 'resources_closed': True, 'errors': []}

    def _record_worker_shutdown_failure(self, target, failure):
        previous = target.__dict__.get('app_server_cleanup')
        report = (previous.copy() if type(previous) is dict else
                  {'all_contained': self.lifetime.contained, 'errors': []})
        report['resources_closed'] = False
        report['errors'] = [*report.get('errors', []), type(failure).__name__]
        target.app_server_cleanup = report

    def _close_transport(self):
        if self.finite_tools is None:
            self.requests.close()
        else:
            with self.finite_tools.lock:
                self.requests.close()
        if self.finite_tools is None or self.transport_failure is not None:
            self.finite_input.close(self.transport_failure)
        else:
            self.finite_tools.close()
        # Never use AppServer's PID-based Popen signals or a second reap.
        try:
            if self.lifetime.receipt is not None or self.lifetime._ending:
                self.lifetime.settle_termination()
            _need(self.lifetime.contained and self.lifetime.termination_recorded,
                  "The registered transport containment or record remains unresolved.")
        except BaseException as failure:
            failure.app_server_cleanup = {'all_contained': self.lifetime.contained,
                'resources_closed': False, 'errors': [type(failure).__name__]}
            raise


def _check_response(factory, params, response):
    spec = factory.spec
    for key, value in spec['profile_readback'].items():
        _need(response.get(key) == value, "Actual profile readback drift or fallback.")
    expected = {'model': spec['model'], 'modelProvider': spec['provider'],
                'cwd': str(factory.host.worker), 'runtimeWorkspaceRoots': [str(factory.host.worker)]}
    _need(all(response.get(key) == value for key, value in expected.items()), "Actual thread identity differs.")
    if factory.qualification is not None:
        qualification.check_thread_model(params, response)
    _need(set(params) == set(factory._thread_start_parameters()),
          "Mixed or unbound thread selectors.")
    mode = spec.get('finite_tool_mode')
    if mode in finite_calls.CAPTURE_MODES:
        tools = finite_calls.RegisteredFiniteToolCalls.thread_parameters(
            live_capture=mode == finite_calls.LIVE_CAPTURE_MODE)
        _need(params['dynamicTools'] == tools['dynamicTools'],
              "The selected finite tool definitions differ.")
    thread = response.get('thread', {})
    _need(type(thread.get('id')) is str and bool(thread['id']) and thread.get('turns') == [], "A fresh actual thread is required.")


class RegisteredAdapter(native.LiveThreadAdapter):
    """Original driver with a registered profile/custody validation boundary."""

    def _pending_thread_read_error(self, error):
        factory = _ADAPTERS.get(self)
        return super()._pending_thread_read_error(error) or (
            error.qualification_thread_unmaterialized is True
            and (error.method, error.code) == ('thread/read', -32600)
            and factory is not None and factory.server is self.server and factory.qualification is not None
            and self.thread_response['thread'].get('historyMode') == qualification.HISTORY_MODE
        )

    def _registered_tool_projector(self):
        factory = _ADAPTERS.get(self)
        _need(factory is not None and factory.server is self.server,
              'Only the original adapter may observe finite reply evidence.')
        evidence = self.server.qualified_tool_evidence
        if evidence is None:
            return None
        return lambda turn, records, receipts, terminal: evidence.project(
            self.thread_id, turn, records, receipts, terminal)

    def _observe_forbidden_tool_activity(self, boundary):
        if self.server.qualified_tool_evidence is not None:
            # The descriptor-bound projector has already validated every
            # finite activity row against the original qualification transport.
            boundary = dict(boundary, trusted_tool_activity=[
                row for row in boundary.get('trusted_tool_activity', [])
                if not (row.get('registered_finite') is True
                        and row.get('tool') in ('finite_command', 'finite_poll'))])
        return super()._observe_forbidden_tool_activity(boundary)

    def _timed(self, name, action):
        try:
            if name == 'check':
                original_action = action
                def observe_then_wait():
                    result = original_action()
                    if result.get('decision') in {'continue', 'warn'}:
                        deadline = (self._materialization_deadline_ns / 1_000_000_000
                                    if self._session_boundary_baseline is None
                                    and self._materialization_deadline_ns is not None else None)
                        self.server.await_finite_progress(host_deadline=deadline)
                    return result
                action = observe_then_wait
            return super()._timed(name, action)
        except BaseException as failure:
            # Revoke before NativeControlTurn records the original failure and
            # before finalization/scratch persistence can block its cleanup.
            _observe_adapter_failure(self, failure)
            raise

    def _current_effective_boundary(self):
        factory = _ADAPTERS.get(self)
        _need(factory is not None, 'Only the original registered factory can bind the model task.')
        boundary = super()._current_effective_boundary()
        boundary['adapter']['registered_task'] = factory.model_task_binding()
        return boundary

    def final_summary(self):
        _require_summary_primary(self)
        summary = super().final_summary()
        if summary['turn_status'] == 'failed':
            blocker = provider_policy_blocker(
                self.server.notifications(self.thread_id, 'turn/completed'),
                thread_id=self.thread_id, turn_id=self.turn_id,
            )
            if blocker:
                summary['terminal_blockers'] = blocker
        return summary

    def _validate_effective_boundary(self, boundary):
        factory = _ADAPTERS.get(self)
        _need(factory is not None, "Only the registered factory can issue an adapter.")
        factory.guard()
        expected = factory.boundary
        _need(expected is not None and _snapshot(boundary) == expected, "Registered task/session/policy boundary changed.")
        _check_response(factory, boundary['thread_start']['request'], boundary['thread_response'])
        binding = factory.model_task_binding()
        _need(self.prompt.encode() == factory.model_task_bytes() and self.worktree == factory.host.worker,
              "Task or workspace identity differs from the original admission.")
        _need(boundary['adapter']['registered_task'] == binding
              and boundary['control_contract']['task_sha256'] == binding['model_task_sha256'],
              'The original admission, actual model task and native control binding differ.')

    def _record_complete_boundary_locked(self, boundary):
        observed = super()._record_complete_boundary_locked(boundary)
        self.server.requests.observe_trusted_terminal(self.thread_id, self.turn_id, observed)
        return observed


def is_registered_adapter(adapter):
    return type(adapter) is RegisteredAdapter


def require_adapter(adapter):
    _need(type(adapter) is RegisteredAdapter and adapter in _ADAPTERS, "An original registered adapter is required.")
    for name, (original, static) in native._METHODS.items():
        expected = _registered_adapter_method(name, original)
        method = getattr(adapter, name)
        actual = method if static else getattr(method, '__func__', None)
        _need(actual is expected, "Registered adapter methods changed.")
    _need(adapter.server is _ADAPTERS[adapter].server, "Registered transport identity changed.")


def observe_execution_failure(adapter, failure):
    """Revoke a registered invocation before original host failure persistence."""
    if not is_registered_adapter(adapter):
        return
    factory = _ADAPTERS.get(adapter)
    if factory is not None:
        factory.server._fail_transport(failure)


def require_server_or_fixture(adapter):
    if is_registered_adapter(adapter):
        require_adapter(adapter)
        _need(type(adapter.server) is _RegisteredServer, "The production registered transport is required.")
        return
    fixtures = importlib.import_module('test_run_native_pool_live_canaries')
    _need(isinstance(adapter.server, fixtures.FakeLiveThreadServer), "Only an original fixture or registered transport is supported.")


_VALIDATE = RegisteredAdapter._validate_effective_boundary
_RECORD_BOUNDARY = RegisteredAdapter._record_complete_boundary_locked
_TIMED = RegisteredAdapter._timed
_CURRENT_BOUNDARY = RegisteredAdapter._current_effective_boundary
_FINAL_SUMMARY = RegisteredAdapter.final_summary
_TOOL_PROJECTOR = RegisteredAdapter._registered_tool_projector
_FORBIDDEN_TOOLS = RegisteredAdapter._observe_forbidden_tool_activity
_PENDING_THREAD_READ = RegisteredAdapter._pending_thread_read_error


def _registered_adapter_method(name, original):
    return {'_validate_effective_boundary': _VALIDATE,
            '_pending_thread_read_error': _PENDING_THREAD_READ,
            '_registered_tool_projector': _TOOL_PROJECTOR,
            '_observe_forbidden_tool_activity': _FORBIDDEN_TOOLS,
            '_record_complete_boundary_locked': _RECORD_BOUNDARY,
            '_timed': _TIMED, '_current_effective_boundary': _CURRENT_BOUNDARY,
            'final_summary': _FINAL_SUMMARY}.get(name, original)


class RegisteredN1Factory:
    """One parent-selected operation. Construction grants no effect authority."""

    def __init__(self, capability, verifier, *, receipt, route, node_id, ledger, host, policy,
                 review_target=None, qualification_permit=None):
        self.capability, self.verifier = capability, verifier
        require_maintenance_operation(capability, verifier=verifier)
        store = getattr(verifier._state_reader, '__self__', None)
        _need(type(store) is MaintenanceStateStore
              and getattr(verifier._claim, '__self__', None) is store,
              "The original verifier must bind one maintenance store.")
        self._store = store
        _need(capability.adapter_path == Path(__file__).resolve(), "The independently registered factory must select this source.")
        self.plan = capability.bound_plan()
        self.spec = json.loads(_snapshot(self.plan['registered_n1']))
        self.receipt = admitted._admission_snapshot(receipt)
        self.route, self.node_id, self.ledger, self.host = copy.deepcopy(route), node_id, ledger, host
        self.policy, self.policy_bytes = policy, _snapshot(policy.report)
        operation = capability.evidence()['operation']
        self.operation_id = operation['operation_id']
        self.dispatch_id = 'n1-' + hashlib.sha256(_snapshot({
            'operation_id': self.operation_id, 'state': str(host.state)})).hexdigest()
        self.host_records = configured_store()
        self.review_target = copy.deepcopy(review_target)
        self._review_target_bytes = _snapshot(review_target)
        self.dispatch_record_sha256 = self.return_record_sha256 = None
        self.boundary = self.server = self.adapter = None
        self.result = self.token = self.execution = None
        self._configured = False
        self._record_number = None
        self._started = False
        self._lock = threading.Lock()
        self._controlled_selected = False
        self._controlled_pending = None
        self._controlled_issued = None
        self._finite_approved_calls = set()
        self._host_bytes = admitted._host_snapshot(host)
        self._ledger_handles = admitted._ledger_handles(ledger)
        self._qualification_start = None
        self._provider_access_token = None
        self._qualification_permit = copy.deepcopy(qualification_permit)
        self._qualification = self._authorize_qualification(self._qualification_permit, operation)
        self._managed_lease = self._managed_lifetime = None
        self._managed_login = self._select_managed_login()
        self._validate()
        admitted._require_primary(self.receipt)
        self._model_task = _model_task(self.receipt, self.spec, self.policy.report)
        self.home = _private(host.state / 'fake-server' / 'codex-home')
        _cold_spool(self.home, False)
        self.records = _private(host.state / 'records')
        self._identities = tuple(native._identity(path) for path in (host.state, host.worker, host.target, self.home, self.records))
        self._executables = (_file(self.spec['launcher']), _file(self.spec['executable']), _file(self.spec['validator']))
        for key, observed in zip(('launcher', 'executable', 'validator'), self._executables):
            _need(observed[1] == self.spec[key + '_sha256'], "Executable differs from independently registered bytes.")
        self._source = capability.read_adapter_source()

    @property
    def qualification(self):
        return self._qualification

    def _authorize_qualification(self, permit, operation):
        if permit is None:
            if qualification.MODEL_SELECTION in self.spec:
                live_availability.require_n1_live()
                raise qualification.QualificationError('Qualification launch requires a signed permit.')
            return None
        _need(self.review_target is None, "Qualification cannot select a peer-review dispatch.")
        qualification.require_model_selection(self.spec, self.plan, operation)
        authority = qualification.verify_qualification_permit(permit, self.capability, self.verifier)
        _disjoint([qualification.campaign_directory(), self.host.worker, self.host.target,
                   self.host.state, self.ledger.root, self._store.directory, self.host_records.state_root])
        return authority

    def _select_managed_login(self):
        qualification.require_authentication_selection(self.spec)
        if qualification.AUTHENTICATION not in self.spec:
            return None
        _need(self.qualification is not None, "Managed login requires signed qualification.")
        home = native._path(qualification.managed_login_home())
        _disjoint([home, qualification.campaign_directory(), self.host.worker, self.host.target,
                   self.host.state, self.ledger.root, self._store.directory, self.host_records.state_root])
        return qualification.ManagedLoginMount(home)

    def appserver_home(self):
        return self.home if self._managed_login is None else qualification.LOGIN_MOUNT

    def _validate_spec_fields(self, spec, fields):
        if self.qualification is not None:
            _need(set(spec) - {qualification.AUTHENTICATION} == fields | {qualification.MODEL_SELECTION, 'finite_tool_mode'}
                  and spec['finite_tool_mode'] == 'captured-live-host-tools',
                  "Qualification requires the signed live finite tool mode.")
        else:
            _need(set(spec) == fields or (set(spec) == fields | {'finite_tool_mode'}
                  and spec['finite_tool_mode'] == 'captured-host-tools'), "Unsupported factory input fields.")

    def _validate(self):
        spec = self.spec
        _profile(spec)
        fields = {'launcher', 'executable', 'validator', 'model', 'provider', 'effort', 'thread_start',
                           'profile_readback', 'pre_effect', 'command', 'expected_token', 'configuration_pins',
                           'admission_sha256', 'validation_policy', 'max_steps', 'purpose', 'implementation_sha256',
                           'configuration_files', 'executable_sha256', 'launcher_sha256', 'validator_sha256', 'custody'}
        self._validate_spec_fields(spec, fields)
        _need(spec['custody'] == self._custody(), "Registered custody store, workspace or target binding differs.")
        _configuration(spec, self.host.worker)
        _need(spec['purpose'] == 'local-engineering', "External execution-purpose disclosure/adjudication is not wired.")
        _need(0 < len(self.receipt.request_bytes) <= native.MAX_TASK_BYTES, "The original task byte bound is required before startup.")
        _need(type(spec['max_steps']) is int and 0 < spec['max_steps'] <= native.MAX_STEPS, "The original finite step bound is required.")
        _need(spec['admission_sha256'] == admission._receipt_sha256(self.receipt), "Whole-route admission differs from registered authority.")
        _need(spec['validation_policy'] == self.policy.report, "Only independently registered validation is supported.")
        execution = json.loads(self.receipt.execution_bytes)
        _need(execution['model'] == spec['model'] and execution['provider'] == spec['provider']
              and execution['effort'] == spec['effort'], "Admitted execution identity differs.")
        _need(execution['options'] == {'registered_n1': {k: v for k, v in spec.items() if k != 'admission_sha256'}},
              "Whole-workflow options must bind the actual registered specification.")
        _need(type(self.host) is native.OfflineN1Host and self.host._observe() == self.host._initial, "Original current host required.")
        require_private_roots(self._protected_roots(), visible_paths=self._visible_mount_sources())
        self.host_records.assert_worker_roots_excluded(self._worker_writable_roots())
        self._check_review_target()
        _private(self.host.state)
        _disjoint([self.host.state, self.host.worker, self.host.target,
                   self.ledger.root, self._store.directory])
        _need(len(self.policy.report['outputs']) == 1, "The initial registered factory supports one declared output.")
        _need(type(spec['command']) is str and 0 < len(spec['command']) <= 4096, "Bounded exact command required.")
        native._pins(spec['configuration_pins'])

    def guard(self):
        require_private_roots(self._protected_roots(), visible_paths=self._visible_mount_sources())
        self.host_records.assert_worker_roots_excluded(self._worker_writable_roots())
        _need(_snapshot(self.review_target) == self._review_target_bytes,
              "The protected review dispatch target changed.")
        self._check_review_target()
        _need(admitted._host_snapshot(self.host) == self._host_bytes, "Original host binding changed.")
        admitted._check_ledger(self.ledger, self._ledger_handles, self.host)
        _need(self.host._observe() == self.host._initial, "Current repository state drifted before a registered effect.")
        require_maintenance_operation(self.capability, verifier=self.verifier, plan=self.plan,
            runtime_scope={'workspace': str(self.host.worker), 'model': self.spec['model'], 'role': 'product',
                           'write_paths': [entry['path'] for entry in self.policy.report['outputs']]})
        _need(self.spec == self.plan['registered_n1'] and _snapshot(self.policy.report) == self.policy_bytes,
              "Registered policy or input drift.")
        _need(self.capability.read_adapter_source() == self._source, "Registered factory source drift.")
        _need(implementation_sha256() == self.spec['implementation_sha256'], "Registered host import image drift.")
        _need(tuple(native._identity(path) for path in (self.host.state, self.host.worker, self.host.target, self.home, self.records))
              == self._identities, "Registered workspace or custody directory changed.")
        _need(tuple(_file(self.spec[key]) for key in ('launcher', 'executable', 'validator')) == self._executables,
              "Registered executable drift.")
        _need(admission._receipt_sha256(self.receipt) == self.spec['admission_sha256'], "Registered admission changed.")
        _need(self.spec['custody'] == self._custody() and self.node_id == self.receipt.node_id
              and _snapshot(self.route) == self.receipt.route_input_bytes, "Registered custody or route replay differs.")
        self._require_model_task()
        if self._configured:
            self._check_configuration()
        if self.server is None:
            _cold_spool(self.home, self._configured)

    def _require_model_task(self):
        _need(type(self._model_task) is bytes
              and self._model_task == _model_task(self.receipt, self.spec, self.policy.report),
              'The model task changed from its original admitted inputs.')

    def model_task_bytes(self):
        self._require_model_task()
        return self._model_task

    def model_task_binding(self):
        return {'projection_version': 1,
                'original_request_sha256': hashlib.sha256(self.receipt.request_bytes).hexdigest(),
                'model_task_sha256': hashlib.sha256(self.model_task_bytes()).hexdigest()}

    def _custody(self):
        return {'state': str(self.host.state), 'worker': str(self.host.worker), 'target': str(self.host.target),
                'ledger': str(self.ledger.root), 'initial': self.host._initial, 'state_identity': self.host._state_identity}

    def _protected_roots(self):
        roots = (self.host.target, self.host.state, self.ledger.root, self._store.directory,
                 self.host_records.root, self.host_records.audit_file)
        if self.qualification is not None:
            roots = (*roots, qualification.campaign_directory())
        if self._managed_login is not None:
            roots = (*roots, self._managed_login.home)
        return roots

    def _worker_writable_roots(self):
        return (self.host.worker, self.host.state / 'fake-server' / 'codex-home')

    def _check_review_target(self):
        target = self.review_target
        if target is None:
            return
        _need(type(target) is dict and set(target) == {'dispatch_id', 'return_sha256', 'evaluation_sha256'},
              "A review dispatch requires its exact return and evaluation target.")
        _need(type(target['evaluation_sha256']) is str
              and re.fullmatch('[0-9a-f]{64}', target['evaluation_sha256']) is not None,
              "A review dispatch requires an exact evaluation digest.")
        self.host_records.require_return(target['dispatch_id'], target['return_sha256'])
        _need(self.host_records.require_dispatch(target['dispatch_id'])['dispatch_role'] == 'executor',
              "A review dispatch must target an original executor return.")

    def record_dispatch(self, session_id):
        """Persist the checked actual thread identity before the first task turn."""
        from cwo_core.peer_review_identity import registered_review_model

        self.guard()
        _need(type(self) is not RegisteredN1Factory or self.qualification is None,
              "Qualification dispatch evidence stays in disposable worker custody.")
        registered = registered_review_model(self.spec['provider'], self.spec['model']) or {}
        self.dispatch_record_sha256 = self.host_records.write_dispatch(
            dispatch_id=self.dispatch_id,
            dispatch_role='peer-review' if self.review_target is not None else 'executor',
            provider=self.spec['provider'], model_family=registered.get('model_family'),
            model_id=self.spec['model'], reasoning_effort=self.spec['effort'], session_id=session_id,
            request_sha256=hashlib.sha256(self.receipt.request_bytes).hexdigest(),
            review_target=self.review_target,
            evaluation_metadata={'peer_review_required': True, 'dispatch_mode': 'registered-native-n1',
                                 'registered_task': self.model_task_binding()},
        )

    def _record_qualification_dispatch(self, session_id, response):
        self.guard()
        self.require_qualification_rpc()
        self.record('qualification-dispatch', {'session_id': session_id,
            'selection': self.spec[qualification.MODEL_SELECTION],
            'actual_readback': {key: response[key] for key in (
                'model', 'modelProvider', 'reasoningEffort', 'serviceTier')},
            'operation_sha256': self.capability.operation_sha256,
            'start': self._qualification_start})

    def _visible_mount_sources(self):
        scripts = Path(__file__).resolve().parent
        return (scripts, scripts.parent / 'policy', scripts.parent / 'schemas')

    def require_effect(self):
        self.require_launch_selection()
        attempt_id = admitted._intent(self.ledger, self.receipt)
        admission._graph_state(self.receipt, {}, self.ledger, attempt_id)
        self.guard()

    def require_launch_selection(self):
        if self.qualification is None:
            live_availability.require_n1_live()
            _need(qualification.MODEL_SELECTION not in self.spec, "Qualification requires its signed permit.")
        else:
            self._require_qualification_selection()

    def _require_qualification_selection(self):
        _need(qualification.MODEL_SELECTION in self.spec, "Qualification requires its signed model selection.")
        request = qualification.verify_qualification_permit(self._qualification_permit, self.capability, self.verifier)
        _need(request == self.qualification, "Qualification permit custody changed.")
        qualification.require_available(request, self._qualification_start)

    def require_qualification_rpc(self):
        _need(self.qualification is not None and self._qualification_start is not None,
              "The original qualification start receipt is required for model RPCs.")
        self.require_launch_selection()

    def record_qualification_start(self):
        if self.qualification is not None:
            _need(self._qualification_start is None, "Qualification already started this worker.")
            self._qualification_start = qualification._campaign_start(self.qualification)

    def _check_configuration(self):
        for name, expected in self.spec['configuration_files'].items():
            _need(native._read(self.home, name, 32768) == expected.encode(), "Registered configuration bytes changed.")

    def _provision_configuration(self):
        for name, data in self.spec['configuration_files'].items():
            path = self.home / name
            if path.parent != self.home:
                path.parent.mkdir(mode=0o700)
            native._write_new(path, data.encode(), 0o400)
            native._sync(path.parent)
        self._configured = True
        self._check_configuration()
        if self._managed_login is not None:
            self._managed_login.prepare(self.home)

    def record(self, stage, observation):
        directory = self.records / 'transport-observations'
        if not directory.exists():
            directory.mkdir(mode=0o700)
            native._sync(self.host.state)
        # Directory enumeration may wait on storage. It is only an initial
        # observation; the shared lock serializes the actual number claim.
        initial_count = len(list(directory.iterdir())) if self._record_number is None else None
        with _LOCK:
            if self._record_number is None:
                self._record_number = initial_count
            number = self._record_number
            _need(number < 256, "Transport observation bound exceeded.")
            self._record_number += 1
        # Reserve once, then persist outside the shared numbering lock. A
        # blocked approval observation must not hold retained-child termination records.
        native._write_new(directory / ('observation-%04d.json' % number),
                          _snapshot({'stage': stage, 'observation': observation}), 0o400)
        native._sync(directory)

    def _thread_start_parameters(self):
        params = dict(self.spec['thread_start'], model=self.spec['model'],
                      allowProviderModelFallback=False, cwd=str(self.host.worker),
                      runtimeWorkspaceRoots=[str(self.host.worker)])
        mode = self.spec.get('finite_tool_mode')
        if mode in finite_calls.CAPTURE_MODES:
            params.update(finite_calls.RegisteredFiniteToolCalls.thread_parameters(
                live_capture=mode == finite_calls.LIVE_CAPTURE_MODE))
        if self.qualification is not None:
            params.update(qualification.thread_selectors())
        return params

    def _preflight_qualification_thread(self):
        self.guard()
        method = 'thread/start'
        # The transport assigns the wire request ID and checks the resulting frame again.
        payload = {'id': 0, 'method': method, 'params': self._thread_start_parameters()}
        frame, binding = _prepare_native_frame(payload, method)
        _checked_native_frame(binding, frame, None, method)

    def _require_finite_capture(self, mode):
        self.guard()
        server = self.server
        _need(self.spec.get('finite_tool_mode') == mode
              and server is not None and server.finite_tools is not None
              and server.transport_failure is None and server.connection_epoch_sha256 is not None
              and server.lifetime.receipt is not None and server.lifetime.birth is not None
              and server.lifetime.process is server.process,
              "No protected original finite capture selection is active.")

    def require_finite_fake_capture(self):
        """Require the signed local fake-server catalog selection."""
        self._require_finite_capture(finite_calls.FAKE_CAPTURE_MODE)

    def require_finite_live_capture(self):
        """Require the signed live qualification and original app-server."""
        _need(self.qualification is not None and type(self.server) is _RegisteredServer,
              "Live finite capture requires the original qualification selection.")
        self.require_launch_selection()
        self._require_finite_capture(finite_calls.LIVE_CAPTURE_MODE)

    def decide_finite_tool(self, tool, params):
        """Fresh protected decision for each actual dynamic command or poll."""
        self.require_effect()
        server = self.server
        producer = None if server is None else server.finite_tools
        call = params.get('callId') if type(params) is dict else None
        if (self.spec.get('finite_tool_mode') not in finite_calls.CAPTURE_MODES
                or producer is None or producer.state not in {'registered', 'active'}
                or type(call) is not str or call in self._finite_approved_calls
                or len(self._finite_approved_calls) >= 256 or tool != params.get('tool')
                or not self._finite_tool_shape(params)):
            raise native.OfflineHostError('No fresh source-approved finite tool decision is available.')
        self.record('finite-tool-decision', {'operation': self.operation_id,
            'call': call, 'tool': tool,
            'decision': 'route-to-byte-gate' if tool == 'finite_poll' else 'accept',
            'epoch': server.connection_epoch_sha256})
        with server.requests.lock:
            if not producer._current(params):
                raise native.OfflineHostError('Finite tool decision expired before issuance.')
            self._finite_approved_calls.add(call)
        return finite_calls.issue_finite_tool_decision(self, tool, params)

    def _finite_tool_shape(self, params):
        tool, args = params.get('tool'), params.get('arguments')
        if tool == 'finite_command':
            return args == {'command': self.spec['command']}
        if tool == 'finite_poll':
            return (type(args) is dict and set(args) == {'commandCallId', 'chars'}
                    and type(args['chars']) is str and len(args['chars'].encode('utf-8')) <= 4096
                    and self.server.finite_tools.command_call_id == args['commandCallId'])
        return False

    def _make_adapter(self, response):
        output = self.policy.report['outputs'][0]['path']
        adapter = RegisteredAdapter(self.server, response, prompt=self.model_task_bytes().decode(),
            expected_token=self.spec['expected_token'], worktree=self.host.worker, mutable=True,
            expected_mutation=output, record_dir=self.records, campaign_live_route=False)
        self.adapter = adapter
        _ADAPTERS[adapter] = self
        control = build_control_turn_contract(state_file=str(self.records / 'worker-state.json'),
            agent_id=adapter.thread_id, control_turn_id=self.operation_id,
            task_sha256=hashlib.sha256(self.model_task_bytes()).hexdigest(), poll_interval_ms=500)
        # This boundary binds the original *actual* planner result and claimed
        # operation. No serialized success flag stands in for an admission.
        sources = {'planned_child': json.loads(self.receipt.selected_node_bytes),
                   'runtime_child': self.capability.evidence(), 'pool_contract': json.loads(self.receipt.plan_bytes),
                   'control_contract': control, 'predispatch_proof': json.loads(self.receipt.aggregate_context_bytes),
                   'writable_roots': [str(self.host.worker)]}
        adapter._effective_boundary_sources = sources
        self.boundary = _snapshot(adapter._current_effective_boundary())
        adapter._effective_boundary = json.loads(self.boundary)
        adapter._effective_boundary_sha256 = canonical_sha256(adapter._effective_boundary)
        require_adapter(adapter)
        return adapter, control

    def _effect(self, request, execution, allowance, _report):
        _need(request == self.receipt.request_bytes and execution == json.loads(self.receipt.execution_bytes)
              and allowance == json.loads(self.receipt.amounts_bytes), "Original admission invocation binding differs.")
        admitted._intent(self.ledger, self.receipt)
        self.guard()
        try:
            report = self.host.run_registered(self)
        except native.OfflineHostError as failure:
            self.execution = getattr(failure, 'native_report', None)
            raise
        self.execution = report
        _need(report['status'] == 'artifact-ready', report.get('error') or 'Native artifact unavailable.')
        self.record_native_return(report)
        try:
            self.token = validation.validate_artifact(self.host, report, self.host._initial['target'], self.policy)
        except validation.ValidationError as primary:
            if not self._controlled_selected or not self._known_output_rejection(report, primary):
                raise
            self._controlled_pending = (primary, _snapshot(report), self.server.lifetime.termination,
                                        admitted._intent(self.ledger, self.receipt))
            return admission.ledger_api.EffectResult('failed')
        self._isolated_validation(report)
        return admission.ledger_api.EffectResult('completed')

    def record_native_return(self, report):
        # The host's durable N1 report is the native return surface. Bind its
        # exact bytes before validation can produce any authorization.
        return_bytes = native._read(self.host.state, 'operation.json', native.MAX_RECORD_BYTES)
        _need(json.loads(return_bytes) == report, "The received native return differs from host custody.")
        if type(self) is RegisteredN1Factory and self.qualification is not None:
            self.record('qualification-return', {'return_sha256': hashlib.sha256(return_bytes).hexdigest()})
            return
        if self.review_target is None:
            self.return_record_sha256 = record_received_return(self.host_records, self.dispatch_id, return_bytes)
        else:
            entries = report['artifact']['files']
            _need(len(entries) == 1, "A peer-review native return must contain one exact structured decision.")
            entry = entries[0]
            peer_bytes = native._immutable_read(self.host.state / 'artifact', entry['blob'], native.MAX_FILE_BYTES)
            _need(len(peer_bytes) == entry['size'] and hashlib.sha256(peer_bytes).hexdigest() == entry['sha256'],
                  "The peer-review native decision bytes differ from the captured artifact.")
            self.return_record_sha256 = record_received_return(self.host_records, self.dispatch_id, peer_bytes)

    def select_controlled_failure(self):
        """Protected parent opt-in before invocation; no old failure is relabelled."""
        self.guard()
        with self._lock:
            _need(not self._started and not self._controlled_selected,
                  "Controlled failure selection requires a fresh original factory.")
            self._controlled_selected = True

    def _known_output_rejection(self, report, primary):
        """Fresh immutable comparisons, healthy archive and same-handle closure."""
        if not self._closed_ready_report(primary):
            return False
        observed = primary.report
        if (observed.get('offline_validation_complete') is not False
                or len(observed.get('host_checks', [])) < 2
                or len(observed.get('errors', [])) != 1
                or not any(entry.get('passed') is False for entry in observed.get('files', []))):
            return False
        try:
            binding = validation._inputs(self.host, report, self.host._initial['target'], self.policy)
            validation._check(self.host, binding)
            outputs = validation._blobs(self.host, report)
            policy = self.policy.report['outputs']
            comparisons = [validation._compare(entry, data) for entry, (_path, data) in zip(policy, outputs)]
            return (self.host._load() == report and len(comparisons) == len(policy)
                    and any(entry['passed'] is False for entry in comparisons)
                    and observed['files'] == comparisons)
        except (OSError, ValueError, TypeError, KeyError):
            return False

    def _closed_ready_report(self, primary):
        server = self.server
        if server is None or type(primary) is not validation.ValidationError:
            return False
        return (self._transport_archive_ready(server)
                and (server.finite_tools is None
                     or server.finite_input.cleanup_phase() in ('unselected', 'contained'))
                and self.token is None)

    @staticmethod
    def _transport_archive_ready(server):
        lifetime = server.lifetime
        termination = lifetime.termination
        observation = lifetime.observation_snapshot()
        return (server.archived and server.transport_failure is None
                and not observation[1] and not observation[2] and not observation[3]
                and server.requests.closed and lifetime.contained
                and lifetime.termination_recorded
                and lifetime.namespace_handle is None
                and type(termination) is dict and termination.get('child_exit_confirmed') is True
                and termination.get('child_reaped') is True)

    def _prepare_registered_adapter(self):
        self.require_effect()
        self.record('startup-intent', {'operation': self.operation_id, 'admission': admission._receipt_sha256(self.receipt),
            'execution': json.loads(self.receipt.execution_bytes), 'allowance': json.loads(self.receipt.amounts_bytes)})
        self._provision_configuration()
        # AppServer reads HOME from the process environment before constructing
        # its child. The requested home is supplied by our own initialize wrapper.
        self.server = _RegisteredServer(self)
        response = self.server.start_registered_thread()
        return self._make_adapter(response)

    def _cleanup_owned(self, primary):
        if self.server is not None:
            self.server.requests.close()
            self.server.finite_input.close(primary)
            self.server.lifetime.cleanup_failure(primary)

    def _isolated_validation(self, report):
        outputs = validation.consume_validated(self.host, self.token, report, self.host._initial['target'], self.policy)
        data = _snapshot({'policy': self.policy.report, 'outputs': [[name, value.hex()] for name, value in outputs]})
        lifetime = _Containment(self, validator=True)
        try:
            process = lifetime.launch([self.spec['validator'], '-I', '-S', '-c', _VALIDATOR], None)
            output, _errors = process.communicate(data.decode(), timeout=10)
            lifetime.terminate()
            _need(process.returncode == 0 and output == 'validated\n', "Fresh credentialless deterministic validation failed.")
        except BaseException as primary:
            lifetime.cleanup_failure(primary)
            raise
        self.record('validated', {'artifact': report['artifact']['sha256'], 'policy': self.policy.report})

    def _selected_access_token(self, provider_access_token):
        if provider_access_token is not None:
            _need(self.qualification is not None, "Provider credential attachment requires signed qualification.")
            _need(self._managed_login is None, "Only one authentication mode may apply to an original launch.")
            return provider_network.personal_access_token_bytes(provider_access_token)
        return None

    def _claim_run(self, provider_access_token):
        provider_access_token = self._selected_access_token(provider_access_token)
        self.require_launch_selection()
        with self._lock:
            if self._started:
                _need(provider_access_token is None, "Provider credentials apply to one original launch only.")
                _need(self.result is not None, "Unknown execution requires reconciliation, never redispatch.")
                self.guard()
                return False
            if self.qualification is not None:
                self._preflight_qualification_thread()
            if self._managed_login is not None:
                self._managed_lease = qualification.claim_managed_login()
            self._provider_access_token = provider_access_token
            self._started = True
            return True

    def _retire_managed_login(self, primary):
        if self._managed_lease is None:
            return
        lifetime = self._managed_lifetime
        try:
            _need(lifetime is None or not lifetime._managed_mount_started or lifetime.contained,
                  "The original managed login namespace remains unresolved.")
            self._managed_login.retire()
            qualification.release_managed_login(self._managed_lease)
            self._managed_lease = None
        except BaseException as failure:
            if primary is None:
                self.result = None
                raise
            admission.ledger_api.add_failure_note(primary, "Managed login retirement failed: " + type(failure).__name__)

    def _take_provider_access_token(self):
        token, self._provider_access_token = self._provider_access_token, None
        return token

    def run(self, *, provider_access_token=None):
        """Run once with an optional personal access token from the trusted embedder."""
        if not self._claim_run(provider_access_token):
            return self.result
        del provider_access_token
        primary = None
        try:
            self.guard()
            result = admission.invoke_offline(self.receipt, self.route, self.node_id,
                ledger=self.ledger, effect=self._effect, observer=self._observer)
            if self._controlled_pending is not None:
                primary, report_bytes, termination, attempt_id = self._controlled_pending
                attempt = result['attempt']
                _need(attempt['attempt_id'] == attempt_id and attempt['state'] == 'terminal'
                      and attempt['outcome'] == 'failed' and attempt['charge'] == attempt['amount']
                      and self.execution is not None and _snapshot(self.execution) == report_bytes
                      and self.server.lifetime.termination is termination
                      and self._known_output_rejection(self.execution, primary),
                      "Controlled failure settlement or immutable closure changed.")
                self._controlled_issued = (primary, attempt_id, attempt['reservation_id'], report_bytes,
                                           termination, self.capability, self.verifier, self.receipt)
                raise primary
            _need(self.token is not None and self.execution is not None, "An original issued validated artifact is required.")
            self.server.close()
            self.server.finite_input.lifecycle.original_output_event('published')
            _ADAPTERS.pop(self.adapter, None)
            self.result = result
            return result
        except BaseException as failure:
            primary = failure
            if self.server is not None:
                self.server.finite_input.lifecycle.original_output_event('revoked')
                self.server.requests.close()
                self.server.lifetime.cleanup_failure(primary)
                try:
                    self.server.close()
                except BaseException as secondary:
                    admission.ledger_api.add_failure_note(primary, 'Transport cleanup failed: ' + type(secondary).__name__)
            if self.adapter is not None:
                _ADAPTERS.pop(self.adapter, None)
            raise
        finally:
            self._provider_access_token = None
            self._retire_managed_login(primary)

    def _observer(self, report):
        # A real observer is persisted by InvocationLedger before the effect.
        _need(type(report) is dict, "The original invocation observation is required.")

    def issued_artifact(self):
        _need(self.qualification is None, "Qualification output stays in disposable worker custody.")
        _need(self.result is not None and self.token is not None, "No accepted output is available.")
        self.guard()
        validation.consume_validated(self.host, self.token, self.execution, self.host._initial['target'], self.policy)
        return self.host, self.token, self.execution, self.host._initial['target'], self.policy

    def controlled_failure(self, primary=None):
        """Observe this factory's issued failed terminal; a report grants nothing."""
        issued = self._controlled_issued
        _need(self._issued_failure_current(issued, primary),
              "No issued original controlled validation failure is available.")
        self.guard()
        attempt = self.ledger.attempt(issued[2])
        _need(attempt['attempt_id'] == issued[1] and attempt['state'] == 'terminal' and attempt['outcome'] == 'failed'
              and attempt['charge'] == attempt['amount']
              and attempt['admission_sha256'] == admission._receipt_sha256(self.receipt),
              "Original failed attempt or full charge changed.")
        return {'operation': self.operation_id, 'attempt_id': issued[1],
                'admission_sha256': admission._receipt_sha256(self.receipt),
                'execution_sha256': hashlib.sha256(issued[3]).hexdigest(),
                'outcome': 'failed', 'charge': copy.deepcopy(attempt['charge'])}

    def _issued_failure_current(self, issued, primary):
        if issued is None or (primary is not None and primary is not issued[0]):
            return False
        if (not self._controlled_selected or not self._started or self.result is not None
                or self.capability is not issued[5] or self.verifier is not issued[6]
                or self.receipt is not issued[7] or self.token is not None
                or self.execution is None or self.server is None):
            return False
        return (_snapshot(self.execution) == issued[3]
                and self.server.lifetime.termination is issued[4]
                and self._known_output_rejection(self.execution, issued[0]))


_FACTORY_METHODS = admitted._method_table(RegisteredN1Factory)


def _require_launch_selection(factory):
    if type(factory) is RegisteredN1Factory:
        RegisteredN1Factory.require_launch_selection(factory)
    else:
        live_availability.require_n1_live()


def _record_appserver_start(factory, role):
    if role == 'appserver' and type(factory) is RegisteredN1Factory:
        RegisteredN1Factory.record_qualification_start(factory)


def _qualification_operation_metadata(factory):
    if type(factory) is RegisteredN1Factory and factory.qualification is not None:
        return {'cwo_bead': qualification.CAMPAIGN, 'cwo_mission': qualification.CAMPAIGN,
                'cwo_control_turn': factory.operation_id}
    return None


def require_factory(factory, host):
    admitted._original_methods(factory, RegisteredN1Factory, _FACTORY_METHODS)
    _need(factory.host is host, "The original registered host identity is required.")
    factory.require_effect()
