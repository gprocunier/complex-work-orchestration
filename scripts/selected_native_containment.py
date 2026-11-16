"""Fixed no-model diagnostics for the selected native sandbox under a Linux owner.

This helper creates only disposable repositories. It never starts a model turn,
accepts worker artifacts, grants authority, or activates a held native route.
Native app-server tool execution is a separate, unperformed qualification case.
"""
from __future__ import annotations

import argparse
import array
import ctypes
import base64
import fcntl
import hashlib
import json
import os
from pathlib import Path
import select
import signal
import socket
import stat
import subprocess
import tempfile
import time

import linux_owned_children as owned
from registered_n1_factory import _PipeBackend, _argument_file
from cwo_core.qualification_target import selected_target
from cwo_core.process_identity import parse_proc_stat

PROBE_KINDS = frozenset({'useful', 'denials', 'waiting', 'appserver'})
CONFIG_METHODS = ('initialize', 'config/read', 'configRequirements/read')
_RUNTIME = ('/usr', '/lib', '/lib64')
_LIMIT = 131072
_WRITE_TIMEOUT = 5
_CONFIG = 'sandbox_mode = "workspace-write"\napproval_policy = "never"\n[sandbox_workspace_write]\nnetwork_access = false\n'
_USEFUL = r'''
import json, pathlib, subprocess
root=pathlib.Path.cwd()
r=subprocess.run(['/usr/bin/sh','-c','printf command-ok'],check=True,capture_output=True,text=True)
patch='diff --git a/result.txt b/result.txt\n--- a/result.txt\n+++ b/result.txt\n@@ -1 +1 @@\n-before\n+patched\n'
subprocess.run(['/usr/bin/git','apply','-'],input=patch,text=True,check=True)
common=subprocess.check_output(['/usr/bin/git','rev-parse','--git-common-dir'],text=True).strip()
print(json.dumps({'command':r.stdout,'patch':(root/'result.txt').read_text(),
 'independent_git':(root/common).resolve()==root/'.git'}),flush=True)
'''
_BOOTSTRAP = "import os,sys; print('boundary-ready',flush=True); gate=os.read(0,1); gate==b'1' or sys.exit(73); os.execv(sys.argv[1],sys.argv[1:])"
_DETACH = "if os.fork()==0:\n os.setsid()\n if os.fork(): os._exit(0)\n while True:\n  with open('heartbeat','a') as stream: stream.write('.')\n  time.sleep(.05)\n"
_WAITING = r'''
import os,time
assert os.read(0,1)==b''
print('poll-ok',flush=True)
time.sleep(25)
'''
_DENIALS = r'''
import ctypes, json, os, pathlib, signal, socket
r={}
def refused(name, action):
 try: action()
 except OSError: r[name]=True
 else: r[name]=False
for name,path in facts['readonly'].items():
 refused(name+'-write', lambda p=path: pathlib.Path(p).write_bytes(b'changed'))
for name,path in facts['protected'].items():
 refused(name+'-read', lambda p=path: pathlib.Path(p).read_bytes())
 refused(name+'-write', lambda p=path: pathlib.Path(p).write_bytes(b'changed'))
refused('git-metadata-write',lambda: pathlib.Path('.git/config').write_text('changed'))
refused('outside-workspace-write',lambda: pathlib.Path('/etc/changed').write_text('changed'))
refused('host-proc-read',lambda: pathlib.Path('/proc/'+str(facts['host_pid'])+'/mem').read_bytes())
refused('host-signal',lambda: os.kill(facts['host_pid'],signal.SIGCONT))
lib=ctypes.CDLL(None,use_errno=True)
r['host-debug-read']=lib.ptrace(2,facts['host_pid'],None,None)==-1
for name,address,family in [('network',('127.0.0.1',facts['port']),socket.AF_INET),
 ('host-control-socket',facts['socket'],socket.AF_UNIX)]:
 def connect(family=family,address=address):
  with socket.socket(family,socket.SOCK_STREAM) as s:
   s.settimeout(.3); s.connect(address)
 refused(name,connect)
r['credentials-cleared']='CWO_PROBE_CREDENTIAL' not in os.environ
r['inherited-descriptor-closed']=True
for entry in pathlib.Path('/proc/self/fd').iterdir():
 try: info=entry.stat()
 except OSError: continue
 if [info.st_dev,info.st_ino]==facts['descriptor_inode']:
  r['inherited-descriptor-closed']=False
print(json.dumps(r),flush=True)
'''


class SelectedProbeError(ValueError):
    """A fixed diagnostic refused or could not establish its physical boundary."""


def _need(condition, message):
    if not condition:
        raise SelectedProbeError(message)


def _stable_process_identity(observed):
    # Scheduler state may change between observations of the same lifetime.
    return observed.pid, observed.comm, observed.ppid, observed.start_ticks


def _pid_owning_user_namespace(pid):
    child = Path('/proc') / str(pid)
    descriptor = os.open(child / 'ns/pid', os.O_RDONLY | os.O_CLOEXEC)
    try:
        owner = fcntl.ioctl(descriptor, 0xb701)  # NS_GET_USERNS from linux/nsfs.h.
        try:
            observed, expected = os.fstat(owner), (child / 'ns/user').stat()
            identity = observed.st_dev, observed.st_ino
            _need(identity == (expected.st_dev, expected.st_ino),
                  'The private PID namespace belongs to another user namespace.')
            return identity
        finally:
            os.close(owner)
    finally:
        os.close(descriptor)


def _regular(path):
    _need(path.is_absolute() and path.resolve() == path and not path.is_symlink(), 'A direct absolute regular file is required.')
    info = path.stat(follow_symlinks=False)
    _need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, 'A distinct regular file is required.')
    with path.open('rb') as stream:
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    after = path.stat(follow_symlinks=False)
    fields = ('st_dev', 'st_ino', 'st_mode', 'st_nlink', 'st_uid', 'st_gid', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
    _need(all(getattr(info, name) == getattr(after, name) for name in fields),
          'The selected file changed during identity observation.')
    return digest


def _executable_object(path):
    canonical = Path(path).resolve(strict=True)
    info = canonical.stat(follow_symlinks=False)
    _need(stat.S_ISREG(info.st_mode) and os.access(canonical, os.X_OK),
          'The fixed helper must resolve to an executable regular object.')
    return str(canonical), (info.st_dev, info.st_ino)


def _package(package):
    package = Path(package)
    _need(package.is_absolute() and package.resolve() == package, 'Select a canonical absolute package directory.')
    target = selected_target()['selection']
    binary = package / target['package']['entrypoint']
    try:
        matched = (_regular(binary) == target['executable_sha256']
                   and _regular(package / target['package']['manifest']) == target['package']['sha256'])
    except OSError as exc:
        raise SelectedProbeError('The exact standalone package is unavailable.') from exc
    _need(matched, 'The executable or standalone package differs from the selected target.')
    return target, binary


def disposition(observations):
    """Keep required omissions visible; diagnostic observations grant no authority."""
    return {'profile_status': 'selected-unqualified', 'confidential': 'unsupported',
            'execution_authorized': False, 'accepted_output': False,
            'observations': observations,
            'unperformed': ['model-turn-builtin-tools', 'native-model-tool-stdin',
                           'native-ordinary-retry', 'native-approved-escalation',
                           'managed-runtime-grants', 'production-lifecycle-recovery'],
            'named_candidate': 'distinct-unselected-identity'}


def _note_child_stderr(process, primary):
    """Retain one bounded, nonblocking fixed-child observation before cleanup."""
    if process is None:
        return
    try:
        descriptor = process.stderr.fileno()
        os.set_blocking(descriptor, False)
        if select.select([descriptor], [], [], 0)[0]:
            detail = os.read(descriptor, 4096).decode('utf-8', errors='replace')
            if detail:
                owned._note(primary, 'Diagnostic child stderr: ' + detail)
    except BaseException as secondary:
        owned._note(primary, 'Diagnostic stderr observation: ' + repr(secondary))


class SelectedNativeProbe:
    """One disposable offline diagnostic epoch, with an original pidfd owner.

    Public operations select fixed probes or read fixed configuration RPCs.
    Empty polling has no input delivery operation. This is not a tool adapter.
    """

    def __init__(self, package):
        self.target, self.binary = _package(package)
        self._initialize()

    def _initialize(self):
        self.launcher = Path('/usr/bin/bwrap').resolve()
        try:
            _regular(self.launcher)
        except OSError as exc:
            raise SelectedProbeError('The fixed namespace launcher is unavailable.') from exc
        try:
            self._watchdog_object = _executable_object('/usr/bin/timeout')
        except OSError as exc:
            raise SelectedProbeError('The fixed watchdog executable is unavailable.') from exc
        supported, reason = owned.atomic_spawn.supported()
        _need(supported, reason)
        self._temporary = tempfile.TemporaryDirectory(prefix='cwo-native-probe-')
        self.root = Path(self._temporary.name)
        self.worker, self.private = self.root / 'worker', self.root / 'controller'
        self.worker.mkdir(mode=0o700)
        self.private.mkdir(mode=0o700)
        self.configuration = self.private / 'config.toml'
        self.configuration.write_text(_CONFIG, encoding='utf-8')
        self.rules = self.private / 'default.rules'
        self.rules.write_text('', encoding='utf-8')
        (self.worker / 'result.txt').write_text('before\n', encoding='utf-8')
        environment = {'PATH': '/usr/bin:/bin', 'HOME': str(self.private),
                       'GIT_CONFIG_GLOBAL': os.devnull, 'GIT_CONFIG_NOSYSTEM': '1'}
        subprocess.run(['/usr/bin/git', '-c', 'init.defaultBranch=probe', 'init', '--quiet', str(self.worker)],
                       env=environment, stdin=subprocess.DEVNULL, capture_output=True, timeout=5, check=True)
        self.controller = self.receipt = self.process = self.namespace_handle = None
        self.watchdog_handle = None
        self._closed = False
        self._cleanup = None
        self._fixtures = []
        self.observation = None
        self._rpc_buffer = bytearray()
        self._rpc_bytes = 0
        self._notifications = 0
        self._server_stderr = bytearray()
        self._issued_programs = set()
        self._credential_environment = None

    def _argv(self, command, block, info):
        argv = [str(self.launcher), '--unshare-all', '--die-with-parent', '--new-session',
                '--cap-drop', 'ALL', '--clearenv', '--hostname', 'cwo-offline-probe', '--block-fd', str(block), '--info-fd', str(info)]
        for directory in _RUNTIME:
            argv += ['--ro-bind', directory, directory]
        argv += ['--symlink', 'usr/bin', '/bin', '--proc', '/proc', '--dev', '/dev',
                 '--tmpfs', '/tmp', '--tmpfs', '/home', '--dir', '/etc',
                 '--dir', '/home/worker', '--dir', '/home/worker/.codex',
                 '--dir', '/home/worker/.codex/rules']
        # These mounts follow /home and /tmp overlays, including packages there.
        argv += ['--ro-bind', str(self.binary), str(self.binary),
                 '--ro-bind', str(self.configuration), '/home/worker/.codex/config.toml',
                 '--ro-bind', str(self.rules), '/home/worker/.codex/rules/default.rules',
                 '--bind', str(self.worker), str(self.worker),
                 '--ro-bind', str(self.worker / '.git'), str(self.worker / '.git'),
                 '--chdir', str(self.worker), '--setenv', 'HOME', '/home/worker',
                 '--setenv', 'CODEX_HOME', '/home/worker/.codex',
                 '--setenv', 'PATH', '/usr/bin:/bin', '--setenv', 'LC_ALL', 'C.UTF-8',
                 '--remount-ro', '/', '--', *command]
        return argv

    def _protected(self):
        return {'controller-record': self.private / 'receipt.json',
                'policy': Path(__file__).resolve().parent.parent / 'policy/qualification-target.yaml',
                'host-import': Path(__file__).resolve(),
                'adapter': Path(__file__).resolve().parent / 'registered_n1_factory.py',
                'configuration-source': self.configuration}

    def _observe(self, descriptor):
        deadline, raw = time.monotonic() + 5, bytearray()
        while time.monotonic() < deadline:
            _need(select.select([descriptor], [], [], max(0, deadline - time.monotonic()))[0],
                  'The blocked namespace report timed out.')
            chunk = os.read(descriptor, 4097 - len(raw))
            _need(bool(chunk), 'The blocked namespace report closed before admission.')
            raw.extend(chunk)
            _need(len(raw) <= 4096, 'The namespace report exceeded its bound.')
            try:
                info = json.loads(raw)
            except ValueError:
                continue
            return self._inspect(info)
        raise SelectedProbeError('The namespace report remained incomplete.')

    def _namespace_identity(self, pid):
        registration = self.controller.owned_registration(self.receipt)
        _need(registration is not None, 'The original launcher is no longer retained.')
        observed = parse_proc_stat((Path('/proc') / str(pid) / 'stat').read_text())
        _need(observed.pid == pid and observed.ppid == registration.pid,
              'The namespace is not a direct child of the retained launcher.')
        return observed

    def _inspect(self, info):
        pid = info.get('child-pid')
        _need(type(pid) is int and pid > 1, 'The blocked namespace init has no identity.')
        before = self._namespace_identity(pid)
        descriptor = os.pidfd_open(pid, 0)
        try:
            fdinfo = (Path('/proc/self/fdinfo') / str(descriptor)).read_text().splitlines()
            _need('Pid:\t' + str(pid) in fdinfo, 'The namespace handle has another identity.')
            _need(_stable_process_identity(self._namespace_identity(pid)) == _stable_process_identity(before), 'The namespace birth changed while opening its handle.')
            facts = self._namespace_facts(pid)
            _need(not select.select([descriptor], [], [], 0)[0], 'The blocked namespace already exited.')
            self.namespace_handle, self._namespace_pid = descriptor, pid
            self._namespace_start = before.start_ticks
            return {'namespace_init': pid, 'namespaces': facts}
        except BaseException:
            os.close(descriptor)
            raise

    def _namespace_facts(self, pid):
        child = Path('/proc') / str(pid)
        status = (child / 'status').read_text()
        _need(any(line.startswith('NSpid:') and line.split()[-1] == '1' for line in status.splitlines()),
              'The observed namespace child is not its PID namespace init.')
        facts = {kind: os.readlink(child / 'ns' / kind) for kind in ('mnt', 'net', 'pid', 'user')}
        for kind, value in facts.items():
            _need(value != os.readlink(Path('/proc/self/ns') / kind), 'Required namespace separation is absent.')
        return facts

    def _check_identity(self):
        _package(self.binary.parent.parent)

    def _native_command(self, kind, code):
        if kind == 'appserver':
            return [str(self.binary), 'app-server', '--listen', 'stdio://']
        _need(code is not None, 'The fixed sandbox probe is absent.')
        return [str(self.binary), '-c', 'sandbox_mode="workspace-write"',
                '-c', 'approval_policy="never"', '-c', 'sandbox_workspace_write.network_access=false',
                'sandbox', '--', '/usr/bin/python3', '-I', '-S', '-c', code]

    def _launch(self, kind, code=None):
        _need(kind in PROBE_KINDS and not self._closed and self.controller is None,
              'Only one fixed diagnostic is allowed per fresh epoch.')
        command = self._native_command(kind, code)
        self._check_identity()
        _need(_executable_object('/usr/bin/timeout') == self._watchdog_object,
              'The fixed watchdog executable object changed before launch.')
        _need(self.configuration.read_text() == _CONFIG and self.rules.read_bytes() == b'',
              'The staged configuration changed before launch.')
        command = ['/usr/bin/timeout', '--signal=KILL', '8',
                   '/usr/bin/python3', '-I', '-S', '-c', _BOOTSTRAP, *command]
        descriptors, primary = [], None
        try:
            read_gate, write_gate = os.pipe()
            descriptors.extend((read_gate, write_gate))
            read_info, write_info = os.pipe()
            descriptors.extend((read_info, write_info))
            argv = self._argv(command, read_gate, write_info)
            arguments = _argument_file()
            descriptors.append(arguments)
            delimiter = argv.index('--')
            encoded = b'\0'.join(part.encode() for part in argv[1:delimiter]) + b'\0'
            _need(len(encoded) <= owned.MAX_ARGV_BYTES, 'Fixed arguments exceed the retained owner bound.')
            _need(os.write(arguments, encoded) == len(encoded), 'Argument staging was incomplete.')
            os.lseek(arguments, 0, os.SEEK_SET)
            fcntl.fcntl(arguments, 1033, 15)
            _need(fcntl.fcntl(arguments, 1034) & 15 == 15, 'Argument-file seals were not observed.')
            self._spawn(arguments, read_gate, write_info, command)
            for descriptor in (read_gate, write_info):
                os.close(descriptor)
                descriptors.remove(descriptor)
            self.observation = self._observe(read_info)
            self.controller._engine._verified(self.controller._engine._lookup(self.receipt))
            os.write(write_gate, b'1')
            self._confirm_mounts()
            os.write(self.process.stdin.fileno(), b'1')
        except BaseException as failure:
            primary = failure
            self._close_after_failure(failure)
            raise
        finally:
            self._close_launch_descriptors(descriptors, primary)


    def _confirm_mounts(self):
        descriptor = self.process.stdout.fileno()
        _need(select.select([descriptor], [], [], 5)[0], 'The trusted bootstrap did not become ready.')
        _need(os.read(descriptor, 64) == b'boundary-ready\n', 'The trusted bootstrap readiness marker differs.')
        root = Path('/proc') / str(self._namespace_pid) / 'root'
        for path in self._protected().values():
            _need(not (root / str(path).lstrip('/')).exists(), 'Controller custody is child-visible after setup.')
        _need((root / 'home/worker/.codex/config.toml').read_text() == _CONFIG,
              'The mounted diagnostic configuration differs.')
        _need(not select.select([self.namespace_handle], [], [], 0)[0], 'The inspected namespace exited.')
        _need(self._namespace_identity(self._namespace_pid).start_ticks == self._namespace_start,
              'The namespace identity changed after filesystem setup.')
        self._retain_watchdog()
        self.observation['protected_paths_absent'] = True

    def _retain_watchdog(self):
        parent = Path('/proc') / str(self._namespace_pid)
        children = (parent / 'task' / str(self._namespace_pid) / 'children').read_text().split()
        _need(len(children) == 1, 'The fixed watchdog has an ambiguous birth.')
        pid = int(children[0])
        child = Path('/proc') / str(pid)
        before = parse_proc_stat((child / 'stat').read_text())
        observed_exe = os.readlink(child / 'exe')
        observed_info = (child / 'exe').stat()
        observed_object = (observed_exe, (observed_info.st_dev, observed_info.st_ino))
        detail = self._watchdog_details(before, observed_object)
        _need(before.ppid == self._namespace_pid and observed_object == self._watchdog_object,
              'The post-setup command is not the fixed watchdog: ' + detail)
        descriptor = os.pidfd_open(pid, 0)
        try:
            _need(_stable_process_identity(parse_proc_stat((child / 'stat').read_text())) == _stable_process_identity(before)
                  and 'Pid:\t' + str(pid) in (Path('/proc/self/fdinfo') / str(descriptor)).read_text().splitlines()
                  and not select.select([descriptor], [], [], 0)[0], 'The fixed watchdog birth changed: ' + detail)
            self.watchdog_handle = descriptor
        except BaseException:
            os.close(descriptor)
            raise

    def _watchdog_details(self, observed, executable):
        expected_exe, expected_inode = self._watchdog_object
        actual_exe, actual_inode = executable
        return json.dumps({'expected': {'exe': expected_exe[:256], 'inode': expected_inode,
                                        'ppid': self._namespace_pid},
                           'observed': {'exe': actual_exe[:256], 'inode': actual_inode,
                                        'ppid': observed.ppid, 'pid': observed.pid}}, sort_keys=True)

    def _spawn(self, arguments, read_gate, write_info, command):
        backend = _PipeBackend((read_gate, write_info, arguments))
        self.controller = owned.LinuxOwnedChildController(str(self.launcher))
        self.controller._backend = backend
        self.controller._engine = owned._LinuxEngine(backend, str(self.launcher))
        report = self.controller.spawn_owned('selected-offline-probe',
                    [str(self.launcher), '--args', str(arguments), '--', *command], str(self.worker))
        if backend.births and backend.births[0].child is not None:
            self.process = backend.births[0].child
        if report.get('receipt_available') is True:
            self.receipt = report.get('receipt')
        _need(report.get('outcome') == 'registered' and self.receipt is not None,
              'Original atomic child ownership could not be established: ' + str(report.get('reason', report['outcome'])))
        birth = next(item for item in backend.births if item.receipt is self.receipt)
        self.process = birth.child

    def _denial_program(self):
        (self.private / 'receipt.json').write_text('controller-only\n', encoding='utf-8')
        inherited = (self.private / 'credential').open('wb')
        inherited.write(b'disposable-probe-credential')
        inherited.flush()
        os.set_inheritable(inherited.fileno(), True)
        listener = socket.socket()
        listener.bind(('127.0.0.1', 0))
        listener.listen()
        unix = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        address = str(self.private / 'control.sock')
        unix.bind(address)
        unix.listen()
        self._fixtures += [inherited, listener, unix]
        info = os.fstat(inherited.fileno())
        facts = {'protected': {key: str(path) for key, path in self._protected().items()},
                 'host_pid': os.getpid(), 'descriptor_inode': [info.st_dev, info.st_ino],
                 'port': listener.getsockname()[1], 'socket': address}
        for endpoint in (listener.getsockname(), address):
            family = socket.AF_UNIX if type(endpoint) is str else socket.AF_INET
            with socket.socket(family, socket.SOCK_STREAM) as control:
                control.settimeout(1)
                control.connect(endpoint)
                connection, _ = (unix if family == socket.AF_UNIX else listener).accept()
                connection.close()
        facts['readonly'] = {'selected-executable': str(self.binary),
                             'mounted-configuration': '/home/worker/.codex/config.toml',
                             'mounted-rules': '/home/worker/.codex/rules/default.rules'}
        self._credential_environment = ('CWO_PROBE_CREDENTIAL' in os.environ, os.environ.get('CWO_PROBE_CREDENTIAL'))
        os.environ['CWO_PROBE_CREDENTIAL'] = 'disposable-synthetic-credential'
        return 'facts=' + repr(facts) + '\n' + _DENIALS

    def _read_until_exit(self, timeout=10):
        outputs = self._drain(timeout, until_exit=True)
        return self.process.wait(timeout=1), outputs

    def _drain(self, timeout, *, until_exit=False):
        deadline = time.monotonic() + timeout
        streams = {self.process.stdout.fileno(): bytearray(), self.process.stderr.fileno(): bytearray()}
        active = set(streams)
        while active and time.monotonic() < deadline:
            ready = select.select(list(active), [], [], max(0, deadline - time.monotonic()))[0]
            for descriptor in ready:
                block = os.read(descriptor, 4096)
                if not block:
                    active.remove(descriptor)
                else:
                    streams[descriptor].extend(block)
                    _need(sum(map(len, streams.values())) <= _LIMIT, 'Diagnostic output exceeded its bound.')
            if not until_exit and any(streams.values()):
                break
        _need(not until_exit or not active, 'The fixed diagnostic did not finish before its deadline.')
        return dict(zip(('stdout', 'stderr'), (bytes(value).decode('utf-8') for value in streams.values())))

    def run(self, kind):
        _need(kind in {'useful', 'denials'}, 'Only fixed command and denial probes can run to completion.')
        program = _USEFUL if kind == 'useful' else self._denial_program()
        if self.target is not None:
            return self._run_native_command(program)
        self._launch(kind, program)
        self.process.stdin.close()
        try:
            exit_code, output = self._read_until_exit()
            observed = json.loads(output['stdout']) if exit_code == 0 else {}
            return {'exit_code': exit_code, **output, 'observed': observed,
                    'boundary': self.observation, 'cleanup': self.close(), 'accepted_output': False,
                    'runner': 'outer-boundary-control' if self.target is None else 'selected-native-sandbox'}
        finally:
            self.close()

    def start_waiting(self, *, detached=False):
        _need(type(detached) is bool, 'Select the fixed detached control with a boolean.')
        program = _WAITING.replace("print('poll-ok',flush=True)", _DETACH + "print('poll-ok',flush=True)") if detached else _WAITING
        if self.target is not None:
            self._issued_programs.add(program)
            self._launch('appserver')
            self._configuration_responses()
            self._send({'id': 4, 'method': 'command/exec', 'params': {
                'command': ['/usr/bin/python3', '-I', '-S', '-c', program],
                'cwd': str(self.worker), 'processId': 'fixed-waiting', 'streamStdin': False,
                'streamStdoutStderr': True, 'timeoutMs': 25000, 'outputBytesCap': 32768}})
        else:
            self._launch('waiting', program)
            self.process.stdin.close()

    def poll(self, value):
        _need(type(value) is str and value == '', 'Nonempty input is denied before delivery.')
        _need(not self._closed and self.receipt is not None, 'The original epoch is closed.')
        _need(self.controller.owned_registration(self.receipt) is not None, 'Original process custody is unavailable.')
        try:
            output = self._poll_native() if self.target is not None else self._drain(3)
        except BaseException:
            self.close()
            raise
        return {**output, 'accepted_output': False, 'input_delivered': False}

    def _poll_native(self):
        for _ in range(18):
            frame = self._frame()
            if frame.get('method') != 'command/exec/outputDelta':
                self._notification(frame)
                continue
            params = frame['params']
            _need(params.get('processId') == 'fixed-waiting', 'The output belongs to another process.')
            _need(params.get('stream') in {'stdout', 'stderr'}, 'The output stream is unknown.')
            output = {'stdout': '', 'stderr': ''}
            output[params['stream']] = base64.b64decode(params['deltaBase64'], validate=True).decode('utf-8')
            return output
        raise SelectedProbeError('The fixed empty poll did not observe output.')

    def _validate_request(self, request):
        _need(type(request) is dict and request.get('method') in {*CONFIG_METHODS, 'command/exec'},
              'Unreviewed RPCs, model turns and tool-mediated input are forbidden.')
        if request['method'] != 'command/exec':
            return
        params = request['params']
        fields = {'command', 'cwd', 'timeoutMs', 'outputBytesCap', 'processId', 'streamStdin', 'streamStdoutStderr'}
        _need(set(params) <= fields and params.get('cwd') == str(self.worker),
              'Diagnostic command policy, environment or working-directory overrides are forbidden.')
        command = params.get('command', [])
        _need(len(command) == 5 and command[:4] == ['/usr/bin/python3', '-I', '-S', '-c']
              and command[4] in self._issued_programs, 'Only an issued fixed diagnostic program may run.')
        _need(params.get('timeoutMs') in {3000, 25000} and params.get('outputBytesCap') == 32768
              and params.get('streamStdin', False) is False, 'The fixed command limits or input boundary differ.')

    def _send(self, request):
        self._validate_request(request)
        pending = memoryview((json.dumps(request) + '\n').encode())
        _need(len(pending) <= owned.MAX_ARGV_BYTES, 'The fixed request exceeds its bound.')
        descriptor, deadline = self.process.stdin.fileno(), time.monotonic() + _WRITE_TIMEOUT
        os.set_blocking(descriptor, False)
        try:
            while pending:
                remaining = deadline - time.monotonic()
                _need(remaining > 0 and select.select([], [descriptor], [], remaining)[1],
                      'The fixed request writer timed out; the epoch cannot be replayed.')
                try:
                    count = os.write(descriptor, pending)
                    _need(count > 0, 'The fixed request writer made no progress.')
                    pending = pending[count:]
                except (BlockingIOError, InterruptedError):
                    continue
        except BaseException:
            self.close()
            raise

    def _frame(self):
        deadline = time.monotonic() + 5
        while b'\n' not in self._rpc_buffer:
            descriptor = self.process.stdout.fileno()
            stderr = self.process.stderr.fileno()
            ready = select.select([descriptor, stderr], [], [], max(0, deadline - time.monotonic()))[0]
            _need(bool(ready), 'The fixed response timed out.')
            if stderr in ready:
                self._server_stderr.extend(os.read(stderr, 4096))
                _need(not self._server_stderr, 'The native server emitted diagnostics during admission: '
                      + bytes(self._server_stderr[:1024]).decode('utf-8', errors='replace'))
            if descriptor not in ready:
                continue
            chunk = os.read(descriptor, 4096)
            _need(bool(chunk), 'The configuration server closed before its response.')
            self._rpc_bytes += len(chunk)
            _need(self._rpc_bytes <= _LIMIT, 'The diagnostic response stream exceeded its bound.')
            self._rpc_buffer.extend(chunk)
        line, _, remainder = self._rpc_buffer.partition(b'\n')
        self._rpc_buffer = bytearray(remainder)
        return json.loads(line)

    def _notification(self, frame):
        self._notifications += 1
        _need(self._notifications <= 16, 'The diagnostic notification bound was exceeded.')
        _need(frame.get('method') == 'remoteControl/status/changed'
              and frame.get('params', {}).get('status') == 'disabled' and 'id' not in frame,
              'Unexpected server request or notification during fixed diagnostics.')

    def _rpc(self, request):
        self._send(request)
        for _ in range(18):
            frame = self._frame()
            if 'method' in frame:
                self._notification(frame)
                continue
            _need(frame.get('id') == request['id'], 'The fixed response identity differs.')
            return frame
        raise SelectedProbeError('The fixed response remained incomplete.')

    def _configuration_responses(self):
        responses = {}
        parameters = ({'clientInfo': {'name': 'cwo-offline-containment', 'version': '1'}},
                      {'cwd': str(self.worker), 'includeLayers': True}, None)
        for number, (method, params) in enumerate(zip(CONFIG_METHODS, parameters), 1):
            responses[method] = self._rpc({'id': number, 'method': method, 'params': params})
        config = responses['config/read'].get('result', {}).get('config', {})
        _need(config.get('sandbox_mode') == 'workspace-write' and config.get('approval_policy') == 'never'
              and config.get('sandbox_workspace_write', {}).get('network_access') is False,
              'The actual app-server configuration differs from the selected legacy target.')
        layers = responses['config/read'].get('result', {}).get('layers', [])
        expected_layers = [('user', {'sandbox_mode': 'workspace-write', 'approval_policy': 'never',
                                     'sandbox_workspace_write': {'network_access': False}}), ('system', {})]
        _need([(layer['name']['type'], layer['config']) for layer in layers] == expected_layers
              and responses['configRequirements/read'].get('result', {}).get('requirements', 'missing') is None,
              'Unexpected effective configuration layers or managed requirements.')
        stderr = self.process.stderr.fileno()
        if select.select([stderr], [], [], 0)[0]:
            _need(not os.read(stderr, 4096), 'Native admission emitted server diagnostics.')
        return responses

    def _run_native_command(self, program):
        self._issued_programs.add(program)
        try:
            self._launch('appserver')
            configuration = self._configuration_responses()
            params = {'command': ['/usr/bin/python3', '-I', '-S', '-c', program],
                      'cwd': str(self.worker), 'timeoutMs': 3000, 'outputBytesCap': 32768}
            frame = self._rpc({'id': 4, 'method': 'command/exec', 'params': params})
            _need('error' not in frame, 'The fixed native command was refused: ' + repr(frame)[:1000])
            result = frame['result']
            code, stdout, stderr = result['exitCode'], result['stdout'], result['stderr']
            observed = json.loads(stdout) if code == 0 else {}
            return {'exit_code': code, 'stdout': stdout, 'stderr': stderr, 'observed': observed,
                    'configuration': configuration, 'boundary': self.observation,
                    'cleanup': self.close(), 'accepted_output': False, 'runner': 'selected-app-server-command-exec'}
        finally:
            self.close()

    def read_configuration(self):
        try:
            self._launch('appserver')
            responses = self._configuration_responses()
            return {'responses': responses, 'boundary': self.observation,
                    'accepted_output': False, 'cleanup': self.close()}
        finally:
            self.close()

    def _close_after_failure(self, primary):
        _note_child_stderr(self.__dict__.get('process'), primary)
        try:
            self.close()
        except BaseException as secondary:
            owned._note(primary, 'Diagnostic cleanup: ' + '; '.join(owned._details(secondary)))

    def _close_launch_descriptors(self, descriptors, primary):
        errors, interruption = owned._cleanup([lambda descriptor=descriptor: os.close(descriptor)
                                               for descriptor in descriptors])
        if primary is not None:
            for detail in errors:
                owned._note(primary, 'Launch descriptor cleanup: ' + detail)
            if interruption is not None:
                owned._note(primary, 'Launch descriptor cleanup: ' + repr(interruption))
            return
        failure = interruption or (SelectedProbeError('; '.join(errors)) if errors else None)
        if failure is not None:
            self._close_after_failure(failure)
            raise failure

    def _terminate_owner(self, report):
        if self.receipt is None:
            return
        try:
            observed = self.controller.terminate(self.receipt, .1, allow_kill=True)
        except BaseException as failure:
            observed = getattr(failure, 'ownership_report', None)
            if type(observed) is dict:
                report['owner'] = {key: value for key, value in observed.items() if key != 'receipt'}
            raise
        report['owner'] = {key: value for key, value in observed.items() if key != 'receipt'}

    def _stop_retained(self, name, descriptor, report):
        if descriptor is None:
            return
        if not select.select([descriptor], [], [], .1)[0]:
            try:
                signal.pidfd_send_signal(descriptor, signal.SIGKILL)
                report[name + '_kill'] = True
            except ProcessLookupError:
                # A raced exit is confirmed through this same retained handle.
                report[name + '_signal_exit_race'] = True
        report[name + '_exited'] = bool(select.select([descriptor], [], [], 5)[0])
        _need(report[name + '_exited'], 'The retained ' + name + ' exit remains unconfirmed.')

    def close(self):
        if self._closed:
            return self._cleanup
        self._closed = True
        report = {'namespace_exited': False, 'accepted_output': False}
        self._cleanup = report
        primary = None
        actions = [('owner', lambda: self._terminate_owner(report)),
                   ('namespace', lambda: self._stop_retained('namespace', self.namespace_handle, report)),
                   ('watchdog', lambda: self._stop_retained('watchdog', self.watchdog_handle, report)),
                   ('resources', self._release_resources)]
        for stage, action in actions:
            try:
                action()
            except BaseException as failure:
                details = [stage + ': ' + detail for detail in owned._details(failure)]
                report.setdefault('cleanup_errors', []).extend(details)
                if primary is None:
                    primary = failure
                else:
                    for detail in details:
                        owned._note(primary, detail)
        if primary is not None:
            raise primary
        return report

    def _resource_actions(self):
        actions = []
        for name in ('namespace_handle', 'watchdog_handle'):
            descriptor = getattr(self, name)
            setattr(self, name, None)
            if descriptor is not None:
                actions.append(lambda descriptor=descriptor: os.close(descriptor))
        if self.controller is not None:
            actions.append(self.controller.close)
        if self.process is not None:
            actions.extend(stream.close for stream in (self.process.stdin, self.process.stdout, self.process.stderr))
        actions.extend(resource.close for resource in self._fixtures)
        self._fixtures.clear()
        actions.extend((self._restore_credential_environment, self._temporary.cleanup))
        return actions

    def _release_resources(self):
        errors, interruption = owned._cleanup(self._resource_actions())
        if errors:
            self._cleanup.setdefault('cleanup_errors', []).extend(errors)
        if interruption is not None:
            for detail in errors:
                owned._note(interruption, detail)
            raise interruption
        if errors:
            raise SelectedProbeError('; '.join(errors))

    def _restore_credential_environment(self):
        if self._credential_environment is not None:
            present, value = self._credential_environment
            self._credential_environment = None
            if present:
                os.environ['CWO_PROBE_CREDENTIAL'] = value
            else:
                os.environ.pop('CWO_PROBE_CREDENTIAL', None)


class OuterBoundaryControl(SelectedNativeProbe):
    """Fixed OS controls without a Codex package; never selected-target evidence."""

    def __init__(self):
        self.target = None
        self.binary = Path('/usr/bin/python3').resolve()
        self._runtime_digest = _regular(self.binary)
        self._initialize()

    def _check_identity(self):
        _need(_regular(self.binary) == self._runtime_digest, 'The outer control interpreter changed.')

    def _native_command(self, kind, code):
        _need(kind in {'useful', 'denials', 'waiting'} and code is not None,
              'Only fixed Python outer-boundary controls are supported.')
        return [str(self.binary), '-I', '-S', '-c', code]


_EXEC_CONTEXT = r'''
import json,pathlib
status=dict(line.split(':',1) for line in pathlib.Path('/proc/self/status').read_text().splitlines() if ':' in line)
pathlib.Path('execution-context.json').write_text(json.dumps({'uid':os.getuid(),'gid':os.getgid(),
 'capabilities':{name:int(status[name],16) for name in ('CapEff','CapPrm','CapInh','CapAmb')}}))
'''
_PID_REUSE_SECONDS = 20
_PID_REUSE_CHILD = 'import os\n' + _EXEC_CONTEXT + r'''
import time
deadline=time.monotonic()+10
while time.monotonic()<deadline and not pathlib.Path('exit').exists():
 with pathlib.Path('heartbeat').open('a') as stream: stream.write('.')
 time.sleep(.01)
'''
_PID_REUSE_ENTRY = "import sys;sys.path.insert(0,sys.argv[1]);import selected_native_containment as s;s._pid_reuse_entry(sys.argv[2:])"
_PID_REUSE_LAUNCH = r'''
import ctypes,json,os,pathlib,signal,sys
expected=json.loads(sys.argv[1]); parent=os.getppid()
assert parent>1
entry=pathlib.Path('/proc')/str(parent)/'exe'; info=entry.stat()
assert [str(entry.resolve()),[info.st_dev,info.st_ino]]==expected
assert ctypes.CDLL(None,use_errno=True).prctl(1,signal.SIGKILL,0,0,0)==0
assert os.getppid()==parent
command=json.loads(sys.argv[2])
os.execve(command[0],command,{'PATH':'/usr/bin:/bin','LC_ALL':'C.UTF-8'})
'''


def _pid_namespace_facts():
    return {kind: os.readlink('/proc/self/ns/' + kind) for kind in ('pid', 'user', 'mnt', 'net')}


def _private_pid_scope(host_namespaces):
    _need(os.getpid() == 1 and os.readlink('/proc/self') == '1',
          'A private PID namespace with its own proc view is required.')
    facts = _pid_namespace_facts()
    _need(set(host_namespaces) == set(facts)
          and all(facts[kind] != host_namespaces[kind] for kind in facts),
          'Every private diagnostic namespace must differ from its host.')
    _need(parse_proc_stat(Path('/proc/1/stat').read_text()).pid == 1,
          'The private proc view does not expose its own namespace init.')
    return facts


def _write_private_pid_cursor(pid, host_namespaces):
    _need(type(pid) is int and 2 <= pid < 2**31, 'A bounded original child PID is required.')
    facts = _private_pid_scope(host_namespaces)
    descriptor = os.open('/proc/sys/kernel/ns_last_pid', os.O_WRONLY | os.O_NOFOLLOW)
    try:
        _need(_pid_namespace_facts() == facts, 'The private namespace changed before cursor write.')
        raw = str(pid - 1).encode('ascii')
        _need(os.write(descriptor, raw) == len(raw), 'The private PID cursor write was incomplete.')
    finally:
        os.close(descriptor)


class _ReuseCapHeader(ctypes.Structure):
    _fields_ = [('version', ctypes.c_uint32), ('pid', ctypes.c_int)]


class _ReuseCapData(ctypes.Structure):
    _fields_ = [('effective', ctypes.c_uint32), ('permitted', ctypes.c_uint32),
               ('inheritable', ctypes.c_uint32)]


def _drop_reuse_inheritance(host_namespaces):
    _private_pid_scope(host_namespaces)
    before = _pid_reuse_security_state()['capabilities']
    effective, permitted = int(before['CapEff'], 16), int(before['CapPrm'], 16)
    library = ctypes.CDLL(None, use_errno=True)
    header, values = _ReuseCapHeader(0x20080522, 0), (_ReuseCapData * 2)()
    library.capset.argtypes = [ctypes.POINTER(_ReuseCapHeader), ctypes.POINTER(_ReuseCapData)]
    library.capset.restype = ctypes.c_int
    # capget may report a policy-filtered view. Preserve exactly the capabilities
    # already held in kernel credentials; capset and every later use remain
    # subject to the unchanged host security policy.
    for index, value in enumerate(values):
        value.effective = (effective >> (index * 32)) & 0xffffffff
        value.permitted = (permitted >> (index * 32)) & 0xffffffff
    _need(library.capset(ctypes.byref(header), values) == 0, 'Private capability inheritance could not be cleared.')
    library.prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]
    library.prctl.restype = ctypes.c_int
    _need(library.prctl(47, 4, 0, 0, 0) == 0, 'Private ambient capability inheritance could not be cleared.')
    status = dict(line.split(':', 1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
    _need(int(status['CapInh'], 16) == 0 and int(status['CapAmb'], 16) == 0,
          'The private diagnostic would pass capabilities to its exec children.')
    _need(int(status['CapEff'], 16) == effective and int(status['CapPrm'], 16) == permitted,
          'Clearing private inheritance changed the driver capabilities.')


def _arm_private_parent_death(host_namespaces):
    _private_pid_scope(host_namespaces)
    library = ctypes.CDLL(None, use_errno=True)
    library.prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]
    library.prctl.restype = ctypes.c_int
    _need(library.prctl(1, signal.SIGKILL, 0, 0, 0) == 0, 'The private driver could not bind parent death.')
    _need(_pid_reuse_security_state()['parent_death_signal'] == signal.SIGKILL,
          'The private driver parent-death binding was not retained.')


def _reuse_wait(predicate, message, seconds=4):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(.01)
    raise SelectedProbeError(message)


def _reuse_heartbeat(path, descriptor):
    def size():
        return path.stat().st_size if path.exists() else 0
    _reuse_wait(lambda: size() > 0, 'The fixed child did not produce a heartbeat.')
    before = size()
    _reuse_wait(lambda: size() > before, 'The fixed child heartbeat did not advance.')
    _need(not select.select([descriptor], [], [], 0)[0], 'The fresh child exited during its heartbeat.')
    return True


def _reuse_exec_context(root):
    with (root / 'execution-context.json').open('rb') as stream:
        raw = stream.read(4097)
    _need(len(raw) <= 4096, 'The child execution-context record exceeded its bound.')
    context = json.loads(raw)
    _need(context['uid'] == os.getuid() and context['gid'] == os.getgid(),
          'The fixed child did not preserve the original UID/GID context.')
    _need(context['capabilities'] == dict.fromkeys(('CapEff', 'CapPrm', 'CapInh', 'CapAmb'), 0),
          'The fixed exec child inherited private driver capabilities.')
    return context


def _reuse_spawn(root):
    root.mkdir(mode=0o700)
    executable = str(Path('/usr/bin/python3').resolve())
    controller = owned.LinuxOwnedChildController(executable)
    try:
        report = controller.spawn_owned('fixed-pid-reuse-child',
            [executable, '-I', '-S', '-c', _PID_REUSE_CHILD], str(root))
        _need(report.get('outcome') == 'registered', 'The fixed child lacks its atomic birth: ' + str(report))
        receipt = report['receipt']
        birth = next(item for item in controller._backend.births if item.receipt is receipt)
        _reuse_heartbeat(root / 'heartbeat', birth.descriptor)
        return controller, receipt, birth
    except BaseException as failure:
        _finish_pid_reuse([controller.close], failure)
        raise


def _reuse_exit_original(root, birth):
    (root / 'original/exit').touch()
    _need(select.select([birth.descriptor], [], [], 5)[0], 'The original retained child did not exit.')
    result = os.waitid(os.P_PIDFD, birth.descriptor, os.WEXITED | os.WNOHANG)
    _need(result is not None and result.si_pid == birth.pid, 'The original external reap differs from its birth.')
    _need(owned.ProcAdapter().pidfd_pid(birth.descriptor) == -1,
          'The original pidfd still exposes a live PID after controlled reaping.')


def _reuse_sentinel(root, pid, host_namespaces):
    # Construct first: no child or background producer may allocate between the
    # namespaced cursor write and this one qualified atomic child creation.
    directory = root / 'sentinel'
    directory.mkdir(mode=0o700)
    executable = str(Path('/usr/bin/python3').resolve())
    controller = owned.LinuxOwnedChildController(executable)
    try:
        _write_private_pid_cursor(pid, host_namespaces)
        report = controller.spawn_owned('fixed-pid-reuse-sentinel',
            [executable, '-I', '-S', '-c', _PID_REUSE_CHILD], str(directory))
        _need(report.get('outcome') == 'registered', 'The fresh sentinel lacks its own atomic birth.')
        receipt = report['receipt']
        birth = next(item for item in controller._backend.births if item.receipt is receipt)
        _need(birth.pid == pid, 'The kernel did not reuse the required private PID.')
        return controller, receipt, birth
    except BaseException as failure:
        _finish_pid_reuse([controller.close], failure)
        raise


def _finish_pid_reuse(actions, primary):
    errors, interruption = owned._cleanup(actions)
    if primary is not None:
        for detail in errors:
            owned._note(primary, 'Private PID-reuse cleanup: ' + detail)
        if interruption is not None:
            owned._note(primary, interruption)
        return
    if interruption is not None:
        raise interruption
    _need(not errors, 'Private PID-reuse cleanup failed: ' + str(errors))


def _reuse_case(root, host_namespaces):
    original, receipt, birth = _reuse_spawn(root / 'original')
    fresh = primary = None
    try:
        _reuse_exit_original(root, birth)
        fresh, fresh_receipt, sentinel = _reuse_sentinel(root, birth.pid, host_namespaces)
        _need(sentinel.descriptor != birth.descriptor, 'Original and fresh handles must remain independently retained.')
        stale = original.terminate(receipt, 0, allow_kill=True)
        _need(stale['signals'] == [] and not sentinel.reaped,
              'The stale receipt affected the fresh sentinel lifetime.')
        grew = _reuse_heartbeat(root / 'sentinel/heartbeat', sentinel.descriptor)
        sentinel_context = _reuse_exec_context(root / 'sentinel')
        cleanup = fresh.terminate(fresh_receipt, .1, allow_kill=True)
        _need(cleanup.get('child_exit_confirmed') and cleanup.get('child_reaped'),
              'Fresh-handle cleanup did not confirm and reap its original sentinel.')
        result = {'original_pid': birth.pid, 'sentinel_pid': sentinel.pid,
                  'sentinel_heartbeat_grew': grew, 'sentinel_reaped_by_stale_owner': False,
                  'stale': stale, 'fresh_cleanup': cleanup,
                  'scope': 'primitive-controller-pid-reuse',
                  'sentinel_context': sentinel_context, 'profile_status': 'selected-unqualified',
                  'confidential': 'unsupported', 'model_calls': False, 'thread_or_turn_started': False,
                  'accepted_output': False, 'execution_authorized': False}
        return result
    except BaseException as failure:
        primary = failure
        raise
    finally:
        actions = [original.close]
        if fresh is not None:
            actions.append(fresh.close)
        _finish_pid_reuse(actions, primary)


def _pid_reuse_security_state():
    """Observe this process without changing capabilities or parent-death state."""
    with Path('/proc/self/status').open('rb') as stream:
        raw = stream.read(8192)
    status = dict(line.split(':', 1) for line in raw.decode('ascii').splitlines() if ':' in line)
    library = ctypes.CDLL(None, use_errno=True)
    library.prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]
    library.prctl.restype = ctypes.c_int
    death = ctypes.c_int()
    _need(library.prctl(2, ctypes.addressof(death), 0, 0, 0) == 0, 'Private parent-death observation failed.')
    securebits = library.prctl(27, 0, 0, 0, 0)
    _need(securebits >= 0, 'Private securebits observation failed.')
    return {'capabilities': {name: status[name].strip()[:32]
                             for name in ('CapEff', 'CapPrm', 'CapInh', 'CapAmb')},
            'securebits': securebits, 'parent_death_signal': death.value}


def _pid_reuse_failure_context():
    context = {'uid': os.getuid(), 'gid': os.getgid()}
    try:
        context.update(_pid_reuse_security_state())
    except BaseException as failure:
        context['capabilities_error'] = type(failure).__name__[:64]
    try:
        context['namespaces'] = {kind: value[:64] for kind, value in _pid_namespace_facts().items()}
        context['pid_owner_user_namespace'] = _pid_owning_user_namespace(os.getpid())
    except BaseException as failure:
        context['namespace_error'] = type(failure).__name__[:64]
    return context


def _pid_reuse_failure(failure):
    # Fixed failure context only: never inspect locals, source lines or environment.
    try:
        detail = str(failure) + '; '.join(failure.__dict__.get('__notes__', []))
    except BaseException:
        detail = 'Original failure message unavailable'
    name = type(failure).__name__.encode('utf-8')[:64].decode('utf-8', errors='ignore')
    error = name + ': ' + detail.encode('utf-8')[:400].decode('utf-8', errors='ignore')
    report = {'error': error}
    try:
        locations, trace = [], failure.__traceback__
        for _index in range(8):
            if trace is None:
                break
            code = trace.tb_frame.f_code
            locations.append({'file': Path(code.co_filename).name[:48],
                              'function': code.co_name[:64], 'line': trace.tb_lineno})
            trace = trace.tb_next
        report['locations'] = locations
        report['driver_context'] = _pid_reuse_failure_context()
    except BaseException as secondary:
        report['diagnostic_error'] = type(secondary).__name__[:64]
    try:
        if len(json.dumps(report).encode()) <= 4096:
            return report
    except BaseException:
        pass
    return {'error': error, 'diagnostic_error': 'Fixed diagnostic context exceeded its bound'}


def _pid_reuse_entry(arguments):
    descriptor, root, host_namespaces = arguments
    with socket.socket(fileno=int(descriptor)) as channel:
        try:
            facts = _private_pid_scope(json.loads(host_namespaces))
            # The independent parent verifies the original ancestry only after
            # this post-exec binding, before promoting or releasing the handoff.
            _arm_private_parent_death(json.loads(host_namespaces))
            own = os.pidfd_open(os.getpid(), 0)
            try:
                channel.sendmsg([json.dumps({'inner_pid': os.getpid(), 'namespaces': facts}).encode()],
                    [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', [own]))])
            finally:
                os.close(own)
            channel.settimeout(_PID_REUSE_SECONDS)
            _need(channel.recv(1) == b'1', 'The independent parent did not release the private diagnostic.')
            _drop_reuse_inheritance(json.loads(host_namespaces))
            report = _reuse_case(Path(root), json.loads(host_namespaces))
        except BaseException as failure:
            report = _pid_reuse_failure(failure)
        channel.sendall(json.dumps(report, default=str).encode())


class _PrivatePidReuseOwner:
    """One fixed, independently gated PID-namespace diagnostic; no native admission."""

    def __init__(self, package):
        _need(package is None, 'This private diagnostic supports only the primitive controller.')
        self.package = ''
        supported, reason = owned.atomic_spawn.supported()
        _need(supported, reason)
        self.timeout = _executable_object('/usr/bin/timeout')
        self.bwrap = _executable_object('/usr/bin/bwrap')
        self.python = _executable_object('/usr/bin/python3')
        self.host_namespaces = _pid_namespace_facts()
        self.temporary = tempfile.TemporaryDirectory(prefix='cwo-private-pid-reuse-')
        self.root = Path(self.temporary.name)
        self.scratch = self.root / 'temporary'
        self.scratch.mkdir(mode=0o700)
        self.controller = self.receipt = self.process = self.namespace_handle = None
        self._quarantined_handle = None
        self._parent_observation = None
        self.cleanup = {'namespace_exited': False, 'accepted_output': False}

    def _command(self, descriptor):
        entry = [self.python[0], '-I', '-S', '-c', _PID_REUSE_ENTRY,
                 str(Path(__file__).resolve().parent), str(descriptor), str(self.root),
                 json.dumps(self.host_namespaces)]
        # Use fixed device nodes without requesting devpts: the driver must stay
        # in the user namespace that owns its PID namespace and private cursor.
        command = [self.bwrap[0], '--unshare-user', '--uid', str(os.getuid()), '--gid', str(os.getgid()),
                   '--unshare-pid', '--unshare-net', '--unshare-ipc', '--unshare-uts', '--as-pid-1',
                   '--die-with-parent', '--new-session', '--clearenv', '--cap-add', 'ALL',
                   '--ro-bind', '/', '/', '--bind', str(self.root), str(self.root),
                   '--proc', '/proc', '--tmpfs', '/dev']
        for name in ('null', 'zero', 'full', 'random', 'urandom', 'tty'):
            command.extend(('--dev-bind', '/dev/' + name, '/dev/' + name))
        command.extend(('--symlink', '/proc/self/fd', '/dev/fd', '--setenv', 'TMPDIR', str(self.scratch),
                        '--setenv', 'PATH', '/usr/bin:/bin', '--setenv', 'LC_ALL', 'C.UTF-8', '--', *entry))
        return [self.timeout[0], '--signal=KILL', str(_PID_REUSE_SECONDS), self.python[0], '-I', '-S',
                '-c', _PID_REUSE_LAUNCH, json.dumps(self.timeout), json.dumps(command)]

    def _spawn(self, descriptor):
        backend = _PipeBackend((descriptor,))
        self.controller = owned.LinuxOwnedChildController(self.timeout[0])
        self.controller._backend = backend
        self.controller._engine = owned._LinuxEngine(backend, self.timeout[0])
        report = self.controller.spawn_owned('fixed-private-pid-reuse', self._command(descriptor), str(self.root))
        if backend.births:
            self.process = backend.births[0].child
        self.receipt = report.get('receipt')
        _need(report.get('outcome') == 'registered' and self.receipt is not None,
              'The private diagnostic watchdog has no original atomic owner.')

    def _verify_namespace(self, payload, descriptor):
        info = json.loads(payload)
        pid = owned.ProcAdapter().pidfd_pid(descriptor)
        _need(type(pid) is int and pid > 1, 'The handed-off namespace handle has no host-visible identity.')
        child = Path('/proc') / str(pid)
        before = parse_proc_stat((child / 'stat').read_text())
        parent = Path('/proc') / str(before.ppid)
        monitor = parse_proc_stat((parent / 'stat').read_text())
        registration = self.controller.owned_registration(self.receipt)
        _need(registration is not None and monitor.ppid == registration.pid,
              'The namespace is not below its original atomic watchdog.')
        _need(_executable_object(parent / 'exe') == self.bwrap
              and _executable_object(child / 'exe') == self.python, 'The fixed namespace helper ancestry differs.')
        facts = {kind: os.readlink(child / 'ns' / kind) for kind in self.host_namespaces}
        _need(info == {'inner_pid': 1, 'namespaces': facts}
              and all(facts[kind] != self.host_namespaces[kind] for kind in facts), 'Private namespace identities differ.')
        _need(parse_proc_stat((child / 'root/proc/1/stat').read_text()).pid == 1,
              'The namespace does not have its own PID1 proc view.')
        _need(os.readlink(child / 'root/proc/1/ns/pid') == facts['pid'],
              'The private proc mount belongs to another PID namespace.')
        owner_namespace = _pid_owning_user_namespace(pid)
        _need(_stable_process_identity(parse_proc_stat((child / 'stat').read_text())) == _stable_process_identity(before)
              and _stable_process_identity(parse_proc_stat((parent / 'stat').read_text())) == _stable_process_identity(monitor)
              and not select.select([descriptor], [], [], 0)[0], 'The namespace birth changed before release.')
        self._retain_parent_observation(monitor)
        self.controller._engine._verified(self.controller._engine._lookup(self.receipt))
        self.boundary = {'namespaces': facts, 'namespace_init': pid,
                         'watchdog_pid': registration.pid, 'private_proc': True,
                         'bwrap_pid': monitor.pid, 'bwrap_start_ticks': monitor.start_ticks,
                         'pid_owner_user_namespace': owner_namespace}

    def _retain_parent_observation(self, monitor):
        """Observe the verified original parent lifetime; never signal this fd."""
        identity = _stable_process_identity(monitor)
        original = self.__dict__.get('_parent_observation')
        if original is not None:
            _need(original[1] == identity, 'The original private parent lifetime changed.')
        descriptor = original[0] if original is not None else os.pidfd_open(monitor.pid, 0)
        try:
            current = parse_proc_stat((Path('/proc') / str(monitor.pid) / 'stat').read_text())
            _need(owned.ProcAdapter().pidfd_pid(descriptor) == monitor.pid
                  and _stable_process_identity(current) == identity
                  and not select.select([descriptor], [], [], 0)[0],
                  'The original private parent exited or changed before release.')
        except BaseException:
            if original is None:
                os.close(descriptor)
            raise
        self._parent_observation = descriptor, identity

    def _close_parent_observation(self):
        original = self.__dict__.get('_parent_observation')
        self._parent_observation = None
        if original is not None:
            os.close(original[0])

    def _receive_namespace(self, channel):
        payload, ancillary, flags, _address = channel.recvmsg(4096, socket.CMSG_SPACE(array.array('i').itemsize))
        descriptors = []
        try:
            for level, kind, raw in ancillary:
                if (level, kind) == (socket.SOL_SOCKET, socket.SCM_RIGHTS):
                    handles = array.array('i')
                    handles.frombytes(raw)
                    descriptors.extend(handles)
            _need(payload and not flags and len(ancillary) == 1 and len(descriptors) == 1,
                  'The private namespace handoff is incomplete or has unexpected handles.')
            self._quarantined_handle = descriptors.pop()
            return payload
        finally:
            for descriptor in descriptors:
                os.close(descriptor)

    def _verify_result(self, result):
        _need(type(result) is dict, 'The private diagnostic result must be an object.')
        _need('error' not in result, 'Private PID reuse refused: ' + json.dumps(result, sort_keys=True))
        _need(result.get('scope') == 'primitive-controller-pid-reuse', 'Primitive and selected PID-reuse evidence have different scopes.')
        _need(result.get('accepted_output') is False and result.get('execution_authorized') is False
              and result.get('profile_status') == 'selected-unqualified'
              and result.get('confidential') == 'unsupported', 'PID-reuse observations grant no authority or qualification.')

    def run(self):
        parent, child = socket.socketpair()
        deadline = time.monotonic() + _PID_REUSE_SECONDS
        primary = None
        try:
            self._spawn(child.fileno())
            child.close()
            parent.settimeout(max(.001, deadline - time.monotonic()))
            payload = self._receive_namespace(parent)
            self._verify_namespace(payload, self._quarantined_handle)
            # Receipt is not cleanup authority. Only the completed independent
            # verification promotes this exact handle to owned namespace cleanup.
            self.namespace_handle, self._quarantined_handle = self._quarantined_handle, None
            parent.sendall(b'1')
            parent.settimeout(max(.001, deadline - time.monotonic()))
            result = json.loads(parent.recv(32768))
            self._verify_result(result)
            _need(select.select([self.namespace_handle], [], [], max(0, deadline - time.monotonic()))[0],
                  'The private PID namespace did not exit within its original deadline.')
            return {**result, 'cleanup': self.cleanup, 'boundary': self.boundary, 'private_namespaces': True}
        except BaseException as failure:
            primary = failure
            _note_child_stderr(self.__dict__.get('process'), primary)
            raise
        finally:
            _finish_pid_reuse([parent.close, child.close, self.close], primary)

    def close(self):
        actions = [self._close_parent_observation]
        quarantined, self._quarantined_handle = self._quarantined_handle, None
        if quarantined is not None and quarantined != self.namespace_handle:
            # A refused handoff may refer to any lifetime. Close the received
            # reference without signaling it; the original watchdog remains owned.
            actions.append(lambda: os.close(quarantined))
        if self.namespace_handle is not None:
            descriptor, self.namespace_handle = self.namespace_handle, None
            actions.extend((lambda: SelectedNativeProbe._stop_retained(self, 'namespace', descriptor, self.cleanup),
                            lambda: os.close(descriptor)))
        if self.controller is not None:
            controller, self.controller = self.controller, None
            if self.receipt is not None:
                actions.append(lambda: controller.terminate(self.receipt, .1, allow_kill=True))
            actions.append(controller.close)
        if self.process is not None:
            process, self.process = self.process, None
            actions.extend(stream.close for stream in (process.stdin, process.stdout, process.stderr))
        actions.append(self.temporary.cleanup)
        errors, interruption = owned._cleanup(actions)
        _need(not errors and interruption is None, 'Private namespace cleanup failed: ' + str(errors))



def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--package', type=Path, required=True, help='Exact selected standalone package directory')
    args = parser.parse_args()
    observations = {}
    for kind in ('useful', 'denials', 'appserver'):
        probe = SelectedNativeProbe(args.package)
        try:
            observations[kind] = probe.read_configuration() if kind == 'appserver' else probe.run(kind)
        finally:
            probe.close()
    print(json.dumps(disposition(observations), sort_keys=True, indent=2))


if __name__ == '__main__':
    main()
