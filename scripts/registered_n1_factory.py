"""Registered finite N=1 transport with parent custody and no route activation.

Only a claimed original maintenance capability can select this factory. Worker
code never runs in the controller, and the namespace launcher exposes neither
controller state nor credentials. OS qualification is separate from this code.
"""
from __future__ import annotations

import copy
import fcntl
import hashlib
import importlib
import json
import os
from pathlib import Path
import queue
import re
import select
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
from registered_server_requests import RegisteredServerRequests
from registered_finite_input import RegisteredFiniteInput
from prepare_server_request_frames import _decode as decode_protocol_frame
from cwo_core.maintenance_authority import require_maintenance_operation
from cwo_core.maintenance_authority import MaintenanceStateStore
from cwo_core.native_control import build_control_turn_contract
from cwo_core.native_pool_contracts import canonical_sha256
from cwo_core import server_request_preparation as protocol
from cwo_core import native_live_availability as live_availability
from cwo_core.host_records import configured_store
from cwo_core.host_return_intake import record_received_return
from cwo_core.policy import load_policy
from cwo_core.supervision.transport.app_server import AppServerError
from registered_app_server_transport import RegisteredAppServer
from registered_host_root_boundary import require_private_roots

native = admitted.native
admission = admitted.admission_api
_ADAPTERS = weakref.WeakKeyDictionary()
_LOCK = threading.RLock()
_FALSE = dict.fromkeys(admitted.FALSE_FIELDS, False)
# These are host packaging requirements, not a discovery search or worker input.
_RUNTIME = ("/usr", "/lib", "/lib64")
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
    _need(set(start) == {'permissions', 'approvalPolicy', 'approvalsReviewer', 'ephemeral'},
          "Only the named permissions selector is supported; legacy/mixed selectors refuse.")
    _need(type(start['permissions']) is str and bool(start['permissions']), "A named profile is required.")
    _need(start['approvalPolicy'] == 'untrusted' and start['approvalsReviewer'] == 'user'
          and start['ephemeral'] is True, "The finite no-grants approval profile is required.")
    expected = {'activePermissionProfile': {'id': start['permissions'], 'extends': None},
                'approvalPolicy': 'untrusted', 'approvalsReviewer': 'user'}
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
    expected = {'default_permissions': spec['thread_start']['permissions'], 'approval_policy': 'untrusted',
                'approvals_reviewer': 'user', 'model': spec['model'],
                'model_reasoning_effort': spec['effort'], 'service_tier': 'default',
                'permissions': {spec['thread_start']['permissions']: {
                    'filesystem': {'/': 'deny', str(worker): 'write'}, 'network': {'enabled': False}}}}
    _need(config == expected, "Registered configuration selectors, roots, hooks or network differ.")


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


class _PipeChild(owned._HandleChild):
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


class _PipeBackend(owned._LinuxBackend):
    """Retain the exact direct-child handle, with private protocol pipes."""

    def __init__(self, pass_fds):
        super().__init__()
        self.pass_fds = pass_fds

    def _popen(self, argv, executable, workspace):
        return _PipeChild(argv, executable=executable, cwd=workspace, env={},
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            close_fds=True, pass_fds=self.pass_fds, text=True, bufsize=1, umask=0o077)

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

    def _command(self, command, home, block, info):
        spec, host = self.factory.spec, self.factory.host
        actual_writable = () if self.validator else (host.worker,)
        if self.role == 'appserver':
            actual_writable += (home,)
        self.factory.host_records.assert_worker_roots_excluded(actual_writable)
        argv = [spec['launcher'], '--unshare-all', '--die-with-parent', '--new-session',
                '--cap-drop', 'ALL', '--clearenv', '--block-fd', str(block), '--info-fd', str(info)]
        for directory in _RUNTIME:
            argv += ['--ro-bind', directory, directory]
        argv += ['--ro-bind', command[0], command[0]]
        argv += ['--symlink', 'usr/bin', '/bin', '--proc', '/proc', '--dev', '/dev',
                 '--tmpfs', '/tmp', '--tmpfs', '/home', '--dir', '/etc',
                 '--setenv', 'HOME', '/home/worker', '--setenv', 'LC_ALL', 'C.UTF-8',
                 '--setenv', 'PATH', '/usr/bin:/bin']
        if self.validator:
            scripts = str(Path(__file__).resolve().parent)
            argv += ['--ro-bind', scripts, '/cwo/scripts', '--chdir', '/tmp']
            for name in ('policy', 'schemas'):
                argv += ['--ro-bind', str(Path(scripts).parent / name), '/cwo/' + name]
        else:
            worker = str(host.worker)
            argv += ['--bind', worker, worker, '--ro-bind', worker + '/.git', worker + '/.git',
                     '--chdir', worker]
            if self.role == 'appserver':
                argv += ['--bind', str(home), str(home), '--setenv', 'CODEX_HOME', str(home)]
                for name in self.factory.spec['configuration_files']:
                    argv += ['--ro-bind', str(home / name), str(home / name)]
        argv += ['--remount-ro', '/', '--', *command]
        return argv

    def _release_gate(self, descriptor, tool_call, deadline):
        if self.role == 'tool':
            _need(self.factory.server is not None and self.factory.server.finite_tools is not None,
                  "Unselected tool containment has no gate authority.")
            self.factory.server.finite_tools._require_capture_current()
            self.factory.server.finite_input.dispatch_registered_gate(
                descriptor, tool_call, deadline)
        else:
            os.write(descriptor, b'1')

    def _preflight_tool_launch(self, tool_call, deadline, tool_decision):
        if self.role != 'tool':
            return
        server = self.factory.server
        _need(self.factory.spec.get('finite_tool_mode') == 'captured-host-tools'
              and server is not None and server.finite_tools is not None,
              "The original selected finite producer is required before tool spawn.")
        self.factory.require_finite_fake_capture()
        server.finite_tools._require_capture_current()
        server.finite_tools.require_launch(tool_call, deadline, tool_decision)

    def launch(self, command, home, *, tool_call=None, deadline=None, tool_decision=None):
        live_availability.require_n1_live()
        self.factory.require_effect()
        _need((self.role == 'appserver' and command == [self.factory.spec['executable'], 'app-server', '--stdio'])
              or (self.role == 'tool' and command == ['/usr/bin/sh', '-c', self.factory.spec['command']])
              or (self.role == 'validator' and command == [self.factory.spec['validator'], '-I', '-S', '-c', _VALIDATOR]),
              "The trusted containment role has no other executable allowance.")
        self._preflight_tool_launch(tool_call, deadline, tool_decision)
        self.command = tuple(command)
        read_gate, write_gate = os.pipe()
        read_info, write_info = os.pipe()
        self._fds = [read_gate, write_gate, read_info, write_info]
        try:
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
            backend = _PipeBackend((read_gate, write_info, arguments))
            self.controller = owned.LinuxOwnedChildController(self.factory.spec['launcher'])
            self.controller._backend = backend
            self.controller._engine = owned._LinuxEngine(backend, self.factory.spec['launcher'])
            result = self.controller.spawn_owned(
                self.factory.operation_id + {'appserver': '-transport', 'tool': '-tool',
                                             'validator': '-validation'}[self.role],
                [argv[0], '--args', str(arguments)], str(self.factory.host.worker))
            self._retain(result)
            _need(result.get('outcome') == 'registered' and self.receipt is not None,
                  "Retained-child registration is required before startup.")
            birth = next(item for item in backend.births if item.receipt is self.receipt)
            self.birth = birth
            self.process = birth.child
            if self.role == 'tool':
                self.factory.server.finite_input.publish_pending_lifetime(self)
            for descriptor in (read_gate, write_info):
                os.close(descriptor)
                self._fds.remove(descriptor)
            observation = self._observe(read_info)
            self.controller._engine._verified(self.controller._engine._lookup(self.receipt))
            self.factory.require_effect()
            self.factory.record(self.role + '-contained', observation)
            if self.role == 'tool':
                self.factory.server.finite_input.lifecycle.move(
                    'gate-closed', call=tool_call['callId'])
            # This is the only gate release. A selected tool must still be the
            # current issued call when the one-byte, nonblocking gate opens.
            self._release_gate(write_gate, tool_call, deadline)
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
        self.cleanup_failure(failure)

    def _retain(self, report):
        if type(report) is dict and report.get('receipt_available') is True:
            receipt = report.get('receipt')
            if type(receipt) is owned.OwnedChildReceipt:
                self.receipt = receipt

    def _observe(self, descriptor):
        _need(select.select([descriptor], [], [], 5)[0], "Namespace startup observation timed out.")
        raw = os.read(descriptor, 4097)
        _need(len(raw) <= 4096, "Namespace startup report exceeds its bound.")
        info = json.loads(raw)
        pid = info.get('child-pid')
        _need(type(pid) is int and pid > 1, "No independent namespace child identity was observed.")
        self.namespace_handle = os.pidfd_open(pid, 0)
        fdinfo = Path('/proc/self/fdinfo') / str(self.namespace_handle)
        _need('Pid:\t' + str(pid) in fdinfo.read_text().splitlines(), "The namespace birth handle is not bound to the observed child.")
        child = Path('/proc') / str(pid)
        status = dict(line.split(':', 1) for line in (child / 'status').read_text().splitlines() if ':' in line)
        _need(status.get('NSpid', '').split()[-1:] == ['1'], "The retained namespace child is not its PID namespace init.")
        facts = {kind: os.readlink(child / 'ns' / kind) for kind in ('mnt', 'net', 'pid', 'user')}
        for kind, observed in facts.items():
            _need(observed != os.readlink(Path('/proc/self/ns') / kind), "Required namespace separation is absent.")
        # Read the child's actual mount namespace, never worker-returned evidence.
        root = child / 'root'
        for source in self.factory._protected_roots():
            _not_exposed(root, source)
        _need('Pid:\t' + str(pid) in fdinfo.read_text().splitlines(), "Namespace lifetime changed during observation.")
        return {'child_pid': pid, 'namespaces': facts,
                'scope': 'credentialless-validator' if self.validator else 'worker-only-' + self.role}

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
        # A clean owned tool may still supply its final empty-poll output.
        # Transport ending is a connection-wide negative; tool reaping is not.
        if self.role == 'appserver' and server is not None:
            server.finite_input.lifecycle.authority_revoke('closed')

    def _terminate_claimed(self):
        try:
            _need(self.receipt is not None, "No original owned-child receipt is available.")
            try:
                self.termination = self.controller.terminate(self.receipt, 0.1, allow_kill=True)
            except BaseException as failure:
                self.termination = getattr(failure, 'ownership_report', None)
                raise
            report = self.termination
            _need(report.get('outcome') in {'terminated', 'killed', 'already-exited', 'exited-before-signal'}
                  and report.get('child_exit_confirmed') is True and report.get('child_reaped') is True,
                  "Controlled termination and same-handle reaping are required before capture.")
            _need(self.namespace_handle is not None and select.select([self.namespace_handle], [], [], 5)[0],
                  "The retained PID namespace init is not confirmed dead; capture is refused.")
            os.close(self.namespace_handle)
            self.namespace_handle = None
            self.contained = True
            self.factory.record(self.role + '-terminated',
                                {key: value for key, value in report.items() if key != 'receipt'})
            self.termination_recorded = True
            return report
        except BaseException as failure:
            self._termination_error = failure
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
        self.transport_failure = None
        self._response_ids = set()
        self._command_reply_committed = None
        self._wire_turn = None
        self.requests = _CoherentServerRequests(self)
        self.finite_input = RegisteredFiniteInput(factory, self)
        self.finite_tools = None
        self._tool_queue = None
        self._tool_cleanup_lock = threading.Lock()
        self._tool_cleanup_scheduled = False
        if factory.spec.get('finite_tool_mode') == 'captured-host-tools':
            producer = importlib.import_module('registered_finite_tool_calls')
            self.finite_tools = producer.RegisteredFiniteToolCalls(self)
            self._tool_queue = queue.Queue(maxsize=8)
        super().__init__(requested_model=factory.spec['model'], reasoning_effort=factory.spec['effort'])

    def _default_executable(self):
        return self.factory.spec['executable']

    def _requested_home(self):
        return self.factory.home

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

    def _sync_finite_progress_locked(self):
        """Reconcile selected original facts under requests -> reducer.

        Called by every server request mutation route while the common request lock is
        held, including the registry's own refusal and close paths.
        """
        if self.finite_tools is None:
            return
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
                    deadlines = [entry[2] for entry in lifecycle.pending.values()]
                    if lifecycle.edge_deadline is not None:
                        deadlines.append(lifecycle.edge_deadline)
                    expired = (lifecycle.phase in lifecycle.WAITING and deadlines
                               and min(deadlines) <= lifecycle.clock())
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
        threading.Thread(target=cleanup, name='cwo-registered-tool-cleanup', daemon=True).start()

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
        params = dict(self.factory.spec['thread_start'], model=self.requested_model,
                      allowProviderModelFallback=False, cwd=str(self.factory.host.worker),
                      runtimeWorkspaceRoots=[str(self.factory.host.worker)])
        if self.finite_tools is not None:
            params.update(self.finite_tools.thread_parameters())
        response, _latency = self.request('thread/start', params, timeout=10)
        _check_response(self.factory, params, response)
        self.thread_id = response['thread']['id']
        self.factory.record_dispatch(self.thread_id)
        self.started_threads[self.thread_id] = None
        self._known_thread_turn_ids[self.thread_id] = set()
        self._profile_response = copy.deepcopy(response)
        self._effective_thread_start_evidence = {self.thread_id: {'request': params, 'response': copy.deepcopy(response)}}
        if self.finite_tools is not None:
            producer = importlib.import_module('registered_finite_tool_calls')
            self.finite_tools.register(params, response, producer.read_fake_server_capture(self))
            threading.Thread(target=self._tool_loop, name='cwo-registered-tools', daemon=True).start()
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
        self.finite_input.lifecycle.reply(
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
        self.requests.close()
        self.lifetime.settle_termination()
        self._join_readers()
        self._require_healthy()
        self.archived = True
        return latency

    def _join_readers(self):
        for reader in self._reader_threads:
            reader.join(timeout=1)
        _need(not any(reader.is_alive() for reader in self._reader_threads), "Transport reader did not stop.")

    def close(self):
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
            self._join_readers()
        except BaseException as failure:
            failure.app_server_cleanup = {'all_contained': self.lifetime.contained,
                'resources_closed': False, 'errors': [type(failure).__name__]}
            raise
        if self.process is not None:
            for name in ('stdin', 'stdout', 'stderr'):
                getattr(self.process, name).close()
        self._require_healthy()
        return {'all_contained': True, 'resources_closed': True, 'errors': []}


def _check_response(factory, params, response):
    spec = factory.spec
    for key, value in spec['profile_readback'].items():
        _need(response.get(key) == value, "Actual profile readback drift or fallback.")
    expected = {'model': spec['model'], 'modelProvider': spec['provider'],
                'cwd': str(factory.host.worker), 'runtimeWorkspaceRoots': [str(factory.host.worker)]}
    _need(all(response.get(key) == value for key, value in expected.items()), "Actual thread identity differs.")
    extra = {'dynamicTools'} if spec.get('finite_tool_mode') == 'captured-host-tools' else set()
    _need(set(params) == set(spec['thread_start']) | {'model', 'allowProviderModelFallback', 'cwd', 'runtimeWorkspaceRoots'} | extra,
          "Mixed or unbound thread selectors.")
    if extra:
        producer = importlib.import_module('registered_finite_tool_calls')
        _need(params['dynamicTools'] == producer.RegisteredFiniteToolCalls.thread_parameters()['dynamicTools'],
              "The selected finite tool definitions differ.")
    thread = response.get('thread', {})
    _need(type(thread.get('id')) is str and bool(thread['id']) and thread.get('turns') == [], "A fresh actual thread is required.")


class RegisteredAdapter(native.LiveThreadAdapter):
    """Original driver with a registered profile/custody validation boundary."""

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
        except Exception as failure:
            # Revoke before NativeControlTurn records the original failure and
            # before finalization/scratch persistence can block its cleanup.
            self.server._fail_transport(failure)
            raise

    def _validate_effective_boundary(self, boundary):
        factory = _ADAPTERS.get(self)
        _need(factory is not None, "Only the registered factory can issue an adapter.")
        factory.guard()
        expected = factory.boundary
        _need(expected is not None and _snapshot(boundary) == expected, "Registered task/session/policy boundary changed.")
        _check_response(factory, boundary['thread_start']['request'], boundary['thread_response'])
        _need(self.prompt.encode() == factory.receipt.request_bytes and self.worktree == factory.host.worker,
              "Task or workspace identity differs from the original admission.")

    def _record_complete_boundary_locked(self, boundary):
        observed = super()._record_complete_boundary_locked(boundary)
        self.server.requests.observe_trusted_terminal(self.thread_id, self.turn_id, observed)
        return observed


def is_registered_adapter(adapter):
    return type(adapter) is RegisteredAdapter


def require_adapter(adapter):
    _need(type(adapter) is RegisteredAdapter and adapter in _ADAPTERS, "An original registered adapter is required.")
    for name, (original, static) in native._METHODS.items():
        expected = _VALIDATE if name == '_validate_effective_boundary' else original
        if name == '_record_complete_boundary_locked':
            expected = _RECORD_BOUNDARY
        if name == '_timed':
            expected = _TIMED
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


class RegisteredN1Factory:
    """One parent-selected operation. Construction grants no effect authority."""

    def __init__(self, capability, verifier, *, receipt, route, node_id, ledger, host, policy,
                 review_target=None):
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
        self.operation_id = capability.evidence()['operation']['operation_id']
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
        self._validate()
        admitted._require_primary(self.receipt)
        self.home = _private(host.state / 'fake-server' / 'codex-home')
        _cold_spool(self.home, False)
        self.records = _private(host.state / 'records')
        self._identities = tuple(native._identity(path) for path in (host.state, host.worker, host.target, self.home, self.records))
        self._executables = (_file(self.spec['launcher']), _file(self.spec['executable']), _file(self.spec['validator']))
        for key, observed in zip(('launcher', 'executable', 'validator'), self._executables):
            _need(observed[1] == self.spec[key + '_sha256'], "Executable differs from independently registered bytes.")
        self._source = capability.read_adapter_source()

    def _validate(self):
        spec = self.spec
        _profile(spec)
        fields = {'launcher', 'executable', 'validator', 'model', 'provider', 'effort', 'thread_start',
                           'profile_readback', 'pre_effect', 'command', 'expected_token', 'configuration_pins',
                           'admission_sha256', 'validation_policy', 'max_steps', 'purpose', 'implementation_sha256',
                           'configuration_files', 'executable_sha256', 'launcher_sha256', 'validator_sha256', 'custody'}
        _need(set(spec) == fields or (set(spec) == fields | {'finite_tool_mode'}
              and spec['finite_tool_mode'] == 'captured-host-tools'), "Unsupported factory input fields.")
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
        if self._configured:
            self._check_configuration()
        if self.server is None:
            _cold_spool(self.home, self._configured)

    def _custody(self):
        return {'state': str(self.host.state), 'worker': str(self.host.worker), 'target': str(self.host.target),
                'ledger': str(self.ledger.root), 'initial': self.host._initial, 'state_identity': self.host._state_identity}

    def _protected_roots(self):
        return (self.host.target, self.host.state, self.ledger.root, self._store.directory,
                self.host_records.root, self.host_records.audit_file)

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
        self.guard()
        registered = load_policy('provider-registry').get('review_models', {}).get(
            self.spec['provider'], {}).get(self.spec['model'], {})
        self.dispatch_record_sha256 = self.host_records.write_dispatch(
            dispatch_id=self.dispatch_id,
            dispatch_role='peer-review' if self.review_target is not None else 'executor',
            provider=self.spec['provider'], model_family=registered.get('model_family'),
            model_id=self.spec['model'], reasoning_effort=self.spec['effort'], session_id=session_id,
            request_sha256=hashlib.sha256(self.receipt.request_bytes).hexdigest(),
            review_target=self.review_target,
            evaluation_metadata={'peer_review_required': True, 'dispatch_mode': 'registered-native-n1'},
        )

    def _visible_mount_sources(self):
        scripts = Path(__file__).resolve().parent
        return (scripts, scripts.parent / 'policy', scripts.parent / 'schemas')

    def require_effect(self):
        live_availability.require_n1_live()
        attempt_id = admitted._intent(self.ledger, self.receipt)
        admission._graph_state(self.receipt, {}, self.ledger, attempt_id)
        self.guard()

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

    def require_finite_fake_capture(self):
        """Only the signed local fake-server mode may read captured catalog evidence."""
        self.guard()
        server = self.server
        _need(self.spec.get('finite_tool_mode') == 'captured-host-tools'
              and server is not None and server.finite_tools is not None
              and server.transport_failure is None and server.connection_epoch_sha256 is not None
              and server.lifetime.receipt is not None and server.lifetime.birth is not None
              and server.lifetime.process is server.process,
              "No protected original finite capture selection is active.")

    def decide_finite_tool(self, tool, params):
        """Fresh protected decision for each actual dynamic command or poll."""
        self.require_effect()
        server = self.server
        producer = None if server is None else server.finite_tools
        call = params.get('callId') if type(params) is dict else None
        if (self.spec.get('finite_tool_mode') != 'captured-host-tools'
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
        return importlib.import_module('registered_finite_tool_calls').issue_finite_tool_decision(self, tool, params)

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
        adapter = RegisteredAdapter(self.server, response, prompt=self.receipt.request_bytes.decode(),
            expected_token=self.spec['expected_token'], worktree=self.host.worker, mutable=True,
            expected_mutation=output, record_dir=self.records, campaign_live_route=False)
        self.adapter = adapter
        _ADAPTERS[adapter] = self
        control = build_control_turn_contract(state_file=str(self.records / 'worker-state.json'),
            agent_id=adapter.thread_id, control_turn_id=self.operation_id,
            task_sha256=hashlib.sha256(self.receipt.request_bytes).hexdigest(), poll_interval_ms=500)
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

    def run(self):
        live_availability.require_n1_live()
        with self._lock:
            if self._started:
                _need(self.result is not None, "Unknown execution requires reconciliation, never redispatch.")
                self.guard()
                return self.result
            self._started = True
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
        except BaseException as primary:
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

    def _observer(self, report):
        # A real observer is persisted by InvocationLedger before the effect.
        _need(type(report) is dict, "The original invocation observation is required.")

    def issued_artifact(self):
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


def require_factory(factory, host):
    admitted._original_methods(factory, RegisteredN1Factory, _FACTORY_METHODS)
    _need(factory.host is host, "The original registered host identity is required.")
    factory.require_effect()
