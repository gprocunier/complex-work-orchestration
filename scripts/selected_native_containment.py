"""Fixed no-model diagnostics for the selected native sandbox under a Linux owner.

This helper creates only disposable repositories. It never starts a model turn,
accepts worker artifacts, grants authority, or activates a held native route.
Native app-server tool execution is a separate, unperformed qualification case.
"""
from __future__ import annotations

import argparse
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
            _need(self._namespace_identity(pid) == before, 'The namespace birth changed while opening its handle.')
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
            _need(parse_proc_stat((child / 'stat').read_text()) == before
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
