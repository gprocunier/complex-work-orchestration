"""Offline selected-native probes; runtime coverage requires the exact package."""
from __future__ import annotations

import array
import json
import os
import select
import shutil
import signal
import socket
import subprocess
import tempfile
import time
import types
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))

import selected_native_containment as selected


class SelectedContainmentContractTests(unittest.TestCase):
    def test_package_identity_refuses_before_child_creation(self):
        with self.assertRaises(selected.SelectedProbeError):
            selected.SelectedNativeProbe(ROOT)

    def test_unsupported_atomic_backend_refuses_before_repository_or_child_effects(self):
        probe = object.__new__(selected.SelectedNativeProbe)
        with patch.object(selected, '_regular', return_value='launcher-identity'), \
                patch.object(selected.owned.atomic_spawn, 'supported', return_value=(False, 'unsupported atomic backend')), \
                patch.object(selected.tempfile, 'TemporaryDirectory') as temporary, \
                patch.object(selected.subprocess, 'run') as git, \
                patch.object(selected.owned.LinuxOwnedChildController, 'spawn_owned') as native:
            with self.assertRaisesRegex(selected.SelectedProbeError, 'unsupported atomic backend'):
                probe._initialize()
        temporary.assert_not_called()
        git.assert_not_called()
        native.assert_not_called()

    def test_missing_fixed_launcher_is_a_domain_refusal_before_effects(self):
        probe = object.__new__(selected.SelectedNativeProbe)
        with patch.object(selected, '_regular', side_effect=FileNotFoundError('missing fixed launcher')), \
                patch.object(selected.tempfile, 'TemporaryDirectory') as temporary, \
                patch.object(selected.subprocess, 'run') as git, \
                patch.object(selected.owned.LinuxOwnedChildController, 'spawn_owned') as native:
            with self.assertRaisesRegex(selected.SelectedProbeError, 'launcher'):
                probe._initialize()
        temporary.assert_not_called()
        git.assert_not_called()
        native.assert_not_called()

    def test_fixed_programs_cannot_select_a_model_or_turn(self):
        self.assertEqual(selected.PROBE_KINDS, frozenset({'useful', 'denials', 'waiting', 'appserver'}))
        self.assertNotIn('exec', selected.PROBE_KINDS)
        self.assertNotIn('turn/start', selected.CONFIG_METHODS)

    def test_unreviewed_rpc_refuses_before_touching_a_process(self):
        probe = object.__new__(selected.SelectedNativeProbe)
        for method in ('turn/start', 'thread/start', 'thread/shellCommand', 'config/value/write', 'command/exec/write'):
            with self.subTest(method=method), self.assertRaises(selected.SelectedProbeError):
                probe._send({'id': 1, 'method': method, 'params': {}})

    def test_full_protocol_pipe_refuses_without_replay_and_closes_epoch(self):
        read, write = os.pipe()
        stream = os.fdopen(write, 'w')
        self.addCleanup(stream.close)
        self.addCleanup(os.close, read)
        os.set_blocking(write, False)
        try:
            while True:
                os.write(write, b'x' * 4096)
        except BlockingIOError:
            pass
        probe = object.__new__(selected.SelectedNativeProbe)
        probe.process = types.SimpleNamespace(stdin=stream)
        started = time.monotonic()
        with patch.object(selected, '_WRITE_TIMEOUT', .02), patch.object(probe, 'close') as close:
            with self.assertRaises(selected.SelectedProbeError):
                probe._send({'id': 1, 'method': 'initialize', 'params': {}})
        self.assertLess(time.monotonic() - started, 2)
        close.assert_called_once_with()

    def test_startup_server_stderr_cannot_be_warning_free_admission(self):
        out_read, out_write = os.pipe()
        err_read, err_write = os.pipe()
        stdout, stderr = os.fdopen(out_read, 'r'), os.fdopen(err_read, 'r')
        for stream in (stdout, stderr):
            self.addCleanup(stream.close)
        for descriptor in (out_write, err_write):
            self.addCleanup(os.close, descriptor)
        probe = object.__new__(selected.SelectedNativeProbe)
        probe.process = types.SimpleNamespace(stdout=stdout, stderr=stderr)
        probe._rpc_buffer, probe._server_stderr, probe._rpc_bytes = bytearray(), bytearray(), 0
        os.write(err_write, b'warning: unsupported effective policy\n')
        with self.assertRaises(selected.SelectedProbeError):
            probe._frame()

    def test_diagnostic_result_never_claims_execution_authority(self):
        result = selected.disposition({})
        self.assertFalse(result['execution_authorized'])
        self.assertFalse(result['accepted_output'])
        self.assertEqual(result['profile_status'], 'selected-unqualified')
        self.assertEqual(result['confidential'], 'unsupported')
        self.assertIn('model-turn-builtin-tools', result['unperformed'])


class WatchdogObjectIdentityTests(unittest.TestCase):
    """Object-binding controls, without claiming native execution evidence."""

    def fixture(self):
        temporary = tempfile.TemporaryDirectory(prefix='cwo-watchdog-identity-')
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        executable, other, alias = root / 'runtime-object', root / 'other-object', root / 'timeout'
        executable.write_bytes(b'fixed watchdog object')
        executable.chmod(0o700)
        other.write_bytes(b'another object')
        alias.symlink_to(executable)
        info = executable.stat()
        probe = object.__new__(selected.SelectedNativeProbe)
        probe._namespace_pid, probe.watchdog_handle = 17001, None
        probe._watchdog_object = (str(alias.resolve()), (info.st_dev, info.st_ino))
        probe._watchdog_alias = alias
        return probe, executable, other

    def observe(self, probe, executable, *, parent=None, inode=None):
        pid, descriptor = 17002, 77
        parent = probe._namespace_pid if parent is None else parent
        def read(path, *args, **kwargs):
            if path.name == 'children':
                return str(pid)
            if path.name == 'stat':
                return f'{pid} (timeout) S {parent}' + ' 0' * 17 + ' 99'
            if path.parent == Path('/proc/self/fdinfo'):
                return f'Pid:\t{pid}\n'
            self.fail('Unexpected watchdog observation path: ' + str(path))
        with patch.object(Path, 'read_text', read), \
                patch.object(os, 'readlink', return_value=str(executable)), \
                patch.object(Path, 'stat', return_value=inode or executable.stat()), \
                patch.object(os, 'pidfd_open', return_value=descriptor) as opening, \
                patch.object(os, 'close') as closing, \
                patch.object(selected.select, 'select', return_value=([], [], [])):
            self.opening = opening
            probe._retain_watchdog()
        return opening, closing

    def test_canonical_fixed_alias_is_bound_to_the_same_executable_object(self):
        probe, executable, _other = self.fixture()
        self.assertEqual(selected._executable_object(probe._watchdog_alias), probe._watchdog_object)
        opening, closing = self.observe(probe, executable)
        self.assertEqual(probe.watchdog_handle, 77)
        opening.assert_called_once_with(17002, 0)
        closing.assert_not_called()

    def test_same_path_with_another_inode_refuses_before_retaining_a_handle(self):
        probe, executable, other = self.fixture()
        with self.assertRaises(selected.SelectedProbeError) as caught:
            self.observe(probe, executable, inode=other.stat())
        self.assertIsNone(probe.watchdog_handle)
        self.opening.assert_not_called()
        self.assertIn('expected', str(caught.exception))
        self.assertIn('observed', str(caught.exception))
        self.assertIn('17001', str(caught.exception))
        self.assertLess(len(str(caught.exception)), 2048)

    def test_canonical_object_with_another_parent_still_refuses(self):
        probe, executable, _other = self.fixture()
        with self.assertRaises(selected.SelectedProbeError) as caught:
            self.observe(probe, executable, parent=17009)
        self.assertIsNone(probe.watchdog_handle)
        self.opening.assert_not_called()
        self.assertIn('17009', str(caught.exception))
        self.assertIn(str(executable), str(caught.exception))


class DiagnosticCleanupContractTests(unittest.TestCase):
    def fixture(self):
        probe = object.__new__(selected.SelectedNativeProbe)
        probe._closed, probe._cleanup = False, None
        probe.receipt = object()
        probe._watchdog_object = ('EXAMPLE-fixed-helper', (0, 0))
        probe.controller = types.SimpleNamespace(terminate=Mock(return_value={
            'outcome': 'identity-unavailable', 'child_exit_confirmed': False}), close=Mock())
        probe.namespace_handle, probe.watchdog_handle = 101, 102
        probe.process, probe._fixtures, probe._credential_environment = None, [], None
        probe._temporary = types.SimpleNamespace(cleanup=Mock())
        return probe

    @staticmethod
    def exit_after_signal(reads, writes, errors, timeout):
        return (reads if timeout == 5 else [], [], [])

    def test_owner_failure_still_stops_retained_handles_and_preserves_primary_over_close_error(self):
        probe = self.fixture()
        primary = RuntimeError('original monitor failure')
        probe.controller.terminate.side_effect = primary
        def close_descriptor(descriptor):
            if descriptor == 101:
                raise OSError('secondary descriptor close failure')
        with patch.object(selected.select, 'select', side_effect=self.exit_after_signal), \
                patch.object(signal, 'pidfd_send_signal') as signaling, \
                patch.object(os, 'close', side_effect=close_descriptor):
            with self.assertRaises(RuntimeError) as caught:
                probe.close()
        self.assertIs(caught.exception, primary)
        self.assertEqual([call.args[0] for call in signaling.call_args_list], [101, 102])
        self.assertTrue(probe._cleanup['namespace_exited'])
        self.assertFalse(probe._cleanup['accepted_output'])
        self.assertIn('secondary descriptor close failure', str(probe._cleanup))
        probe.controller.close.assert_called_once_with()
        probe._temporary.cleanup.assert_called_once_with()

    def test_unknown_owner_status_is_retained_while_namespace_is_independently_stopped(self):
        probe = self.fixture()
        with patch.object(selected.select, 'select', side_effect=self.exit_after_signal), \
                patch.object(signal, 'pidfd_send_signal') as signaling, patch.object(os, 'close'):
            report = probe.close()
        self.assertEqual(report['owner']['outcome'], 'identity-unavailable')
        self.assertFalse(report['owner']['child_exit_confirmed'])
        self.assertTrue(report['namespace_exited'])
        self.assertFalse(report['accepted_output'])
        self.assertEqual([call.args[0] for call in signaling.call_args_list], [101, 102])

    def test_signal_exit_race_requires_and_accepts_retained_handle_exit(self):
        probe = self.fixture()
        with patch.object(selected.select, 'select', side_effect=self.exit_after_signal), \
                patch.object(signal, 'pidfd_send_signal', side_effect=ProcessLookupError('already exited')), \
                patch.object(os, 'close'):
            report = probe.close()
        self.assertTrue(report['namespace_exited'])
        self.assertFalse(report['accepted_output'])

    def test_signal_exit_race_without_exit_confirmation_remains_unknown(self):
        probe = self.fixture()
        with patch.object(selected.select, 'select', return_value=([], [], [])), \
                patch.object(signal, 'pidfd_send_signal', side_effect=ProcessLookupError('not observable')), \
                patch.object(os, 'close'):
            with self.assertRaises(selected.SelectedProbeError):
                probe.close()
        self.assertFalse(probe._cleanup['namespace_exited'])
        self.assertFalse(probe._cleanup['accepted_output'])
        probe._temporary.cleanup.assert_called_once_with()

    def test_owner_failure_without_retained_handles_never_opens_or_signals_a_pid(self):
        probe = self.fixture()
        probe.namespace_handle = probe.watchdog_handle = None
        primary = RuntimeError('original monitor failure')
        probe.controller.terminate.side_effect = primary
        with patch.object(os, 'pidfd_open') as opening, patch.object(signal, 'pidfd_send_signal') as signaling:
            with self.assertRaises(RuntimeError) as caught:
                probe.close()
        self.assertIs(caught.exception, primary)
        opening.assert_not_called()
        signaling.assert_not_called()
        self.assertFalse(probe._cleanup['namespace_exited'])

    def test_second_launch_pipe_failure_closes_the_first_pair(self):
        probe = self.fixture()
        probe.controller = None
        probe._native_command = Mock(return_value=['/usr/bin/true'])
        probe._check_identity = Mock()
        probe.configuration = types.SimpleNamespace(read_text=lambda: selected._CONFIG)
        probe.rules = types.SimpleNamespace(read_bytes=lambda: b'')
        probe.close = Mock()
        pair = os.pipe()
        primary = OSError('second launch pipe failed')
        try:
            with patch.object(os, 'pipe', side_effect=[pair, primary]), \
                    patch.object(selected, '_executable_object', return_value=probe._watchdog_object):
                with self.assertRaises(OSError) as caught:
                    probe._launch('waiting', 'fixed program')
            self.assertIs(caught.exception, primary)
            for descriptor in pair:
                with self.assertRaises(OSError):
                    os.fstat(descriptor)
        finally:
            for descriptor in pair:
                try:
                    os.close(descriptor)
                except OSError:
                    pass

    def test_launch_failure_survives_cleanup_failure(self):
        probe = self.fixture()
        probe.controller = None
        probe._native_command = Mock(return_value=['/usr/bin/true'])
        probe._check_identity = Mock()
        probe.configuration = types.SimpleNamespace(read_text=lambda: selected._CONFIG)
        probe.rules = types.SimpleNamespace(read_bytes=lambda: b'')
        probe._argv = Mock(return_value=['/usr/bin/bwrap', '--unshare-all', '--', '/usr/bin/true'])
        primary = RuntimeError('original launch failure')
        probe._spawn = Mock(side_effect=primary)
        probe.close = Mock(side_effect=OSError('secondary owner cleanup failure'))
        with patch.object(selected, '_executable_object', return_value=probe._watchdog_object), \
                self.assertRaises(RuntimeError) as caught:
            probe._launch('waiting', 'fixed program')
        self.assertIs(caught.exception, primary)
        self.assertIn('secondary owner cleanup failure', str(getattr(primary, '__notes__', ())))


def _require_os_prerequisites(test):
    if not Path('/usr/bin/bwrap').is_file():
        test.skipTest('The fixed /usr/bin/bwrap prerequisite is absent')
    supported, reason = selected.owned.atomic_spawn.supported()
    if not supported:
        test.skipTest(reason)


class ControllerDeathReadinessTests(unittest.TestCase):
    """Deterministic handoff ordering, without OS-enforcement credit."""

    def test_handoff_waits_for_live_heartbeat_growth_before_controller_death(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / 'probe'
            (root / 'worker').mkdir(parents=True)
            heartbeat = root / 'worker/heartbeat'
            read, write = os.pipe()
            self.addCleanup(os.close, read)
            state = {'alive': True, 'write': write, 'publications': 0, 'kill_sizes': []}
            process = Mock()
            process.poll.side_effect = lambda: None if state['alive'] else -9
            process.wait.return_value = -9

            def kill():
                state['kill_sizes'].append(heartbeat.stat().st_size if heartbeat.exists() else 0)
                state['alive'] = False
                if state['write'] is not None:
                    os.close(state['write'])
                    state['write'] = None

            process.kill.side_effect = kill

            def launch(*args, pass_fds, **kwargs):
                with socket.socket(fileno=os.dup(pass_fds[0])) as channel:
                    channel.sendmsg([json.dumps({'root': str(root)}).encode()],
                                    [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', [read]))])
                return process

            def publish_while_alive(_duration):
                if state['alive']:
                    with heartbeat.open('a') as stream:
                        stream.write('.')
                    state['publications'] += 1

            with patch.object(subprocess, 'Popen', side_effect=launch), \
                    patch.object(time, 'sleep', side_effect=publish_while_alive):
                try:
                    _controller_death(self, None)
                except FileNotFoundError:
                    self.fail('Controller died before the handed-off descendant produced a heartbeat')
            self.assertGreaterEqual(state['publications'], 2)
            self.assertGreaterEqual(state['kill_sizes'][0], 2)

    def test_absent_or_static_heartbeat_cannot_restart_the_startup_budget(self):
        with tempfile.TemporaryDirectory() as temporary:
            heartbeat = Path(temporary) / 'heartbeat'
            for contents in (None, '.'):
                with self.subTest(contents=contents):
                    if contents is not None:
                        heartbeat.write_text(contents)
                    process = Mock()
                    process.poll.return_value = None
                    with patch.object(time, 'monotonic', side_effect=(7.9, 7.9, 8)), \
                            patch.object(time, 'sleep') as sleeping, \
                            patch.object(select, 'select', return_value=([], [], [])):
                        with self.assertRaisesRegex(AssertionError, 'original startup budget'):
                            _await_live_heartbeat(self, process, 123, heartbeat, 8)
                    sleeping.assert_called_once_with(.01)
                    process.kill.assert_not_called()

    def test_early_controller_or_namespace_exit_cannot_supply_live_readiness(self):
        with tempfile.TemporaryDirectory() as temporary:
            heartbeat = Path(temporary) / 'heartbeat'
            heartbeat.write_text('..')
            for controller_status, ready in ((0, []), (None, [123])):
                with self.subTest(controller_status=controller_status, ready=ready):
                    process = Mock()
                    process.poll.return_value = controller_status
                    with patch.object(time, 'monotonic', return_value=7.9), \
                            patch.object(select, 'select', return_value=(ready, [], [])):
                        with self.assertRaisesRegex(AssertionError, 'exited before descendant readiness'):
                            _await_live_heartbeat(self, process, 123, heartbeat, 8)
                    process.kill.assert_not_called()


class OuterBoundaryOSControlTests(unittest.TestCase):
    """Actual outer OS mechanisms, explicitly without native-target credit."""

    def setUp(self):
        _require_os_prerequisites(self)

    def probe(self):
        probe = selected.OuterBoundaryControl()
        self.addCleanup(probe.close)
        return probe

    def test_outer_useful_command_patch_and_real_denials(self):
        for kind in ('useful', 'denials'):
            report = self.probe().run(kind)
            self.assertEqual(report['exit_code'], 0, report)
            self.assertEqual(report['runner'], 'outer-boundary-control')
            self.assertTrue(report['cleanup']['namespace_exited'])
            if kind == 'denials':
                self.assertTrue(all(report['observed'].values()), report)

    def test_foreign_pid_report_is_refused_before_open_or_signal(self):
        probe = self.probe()
        probe.start_waiting()
        with patch.object(os, 'pidfd_open') as opening, patch.object(signal, 'pidfd_send_signal') as signaling:
            with self.assertRaises(selected.SelectedProbeError):
                probe._inspect({'child-pid': os.getpid()})
        opening.assert_not_called()
        signaling.assert_not_called()
        self.assertIn('poll-ok', probe.poll('')['stdout'])

    def test_owner_failure_still_physically_stops_original_namespace(self):
        probe = self.probe()
        probe.start_waiting(detached=True)
        self.assertIn('poll-ok', probe.poll('')['stdout'])
        namespace = os.dup(probe.namespace_handle)
        self.addCleanup(os.close, namespace)
        primary = RuntimeError('injected original monitor failure')
        with patch.object(probe.controller, 'terminate', side_effect=primary):
            with self.assertRaises(RuntimeError) as caught:
                probe.close()
        self.assertIs(caught.exception, primary)
        self.assertTrue(select.select([namespace], [], [], .3)[0])
        self.assertTrue(probe._cleanup['namespace_exited'])
        self.assertFalse(probe._cleanup['accepted_output'])

    def test_configuration_drift_refuses_before_spawn(self):
        probe = self.probe()
        probe.configuration.write_text('sandbox_mode="danger-full-access"')
        with self.assertRaises(selected.SelectedProbeError), patch.object(probe, '_spawn') as spawn:
            probe.start_waiting()
        spawn.assert_not_called()

    def test_native_watchdog_ends_stalled_controller_and_detached_descendants(self):
        probe = self.probe()
        probe.start_waiting(detached=True)
        self.assertIn('poll-ok', probe.poll('')['stdout'])
        self.assertTrue(select.select([probe.namespace_handle], [], [], 10)[0])
        heartbeat = probe.worker / 'heartbeat'
        before = heartbeat.stat().st_size
        time.sleep(.1)
        self.assertEqual(heartbeat.stat().st_size, before)
        self.assertTrue(probe.close()['namespace_exited'])

    def test_watchdog_death_ends_the_namespace(self):
        probe = self.probe()
        probe.start_waiting(detached=True)
        self.assertIn('poll-ok', probe.poll('')['stdout'])
        signal.pidfd_send_signal(probe.watchdog_handle, signal.SIGKILL)
        self.assertTrue(select.select([probe.namespace_handle], [], [], 5)[0])
        self.assertTrue(probe.close()['namespace_exited'])

    def test_actual_controller_death_stops_detached_descendants(self):
        _controller_death(self, None)


def _controller_death(test, package):
    """Transfer the already-owned namespace pidfd before killing its controller."""
    parent, child = socket.socketpair()
    test.addCleanup(parent.close)
    test.addCleanup(child.close)
    code = r"""
import array,json,socket,sys,time
sys.path.insert(0,sys.argv[1])
import selected_native_containment as s
probe=s.SelectedNativeProbe(sys.argv[3]) if sys.argv[3] else s.OuterBoundaryControl()
probe.start_waiting(detached=True)
assert 'poll-ok' in probe.poll('')['stdout']
channel=socket.socket(fileno=int(sys.argv[2]))
channel.sendmsg([json.dumps({'root':str(probe.root)}).encode()],
 [(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array('i',[probe.namespace_handle]))])
while True: time.sleep(1)
"""
    startup_deadline = time.monotonic() + 8
    process = subprocess.Popen([sys.executable, '-I', '-S', '-c', code, str(ROOT / 'scripts'),
                                str(child.fileno()), str(package or '')], pass_fds=(child.fileno(),),
                               env={}, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    descriptor = None
    root = None
    try:
        child.close()
        remaining = startup_deadline - time.monotonic()
        test.assertGreater(remaining, 0, 'Controller exhausted the original startup budget')
        parent.settimeout(remaining)
        payload, ancillary, flags, address = parent.recvmsg(4096, socket.CMSG_SPACE(array.array('i').itemsize))
        test.assertTrue(payload, process.stderr.read().decode() if process.poll() is not None else 'No ready report')
        test.assertFalse(flags)
        handles = array.array('i')
        for level, kind, data in ancillary:
            test.assertEqual((level, kind), (socket.SOL_SOCKET, socket.SCM_RIGHTS))
            handles.frombytes(data)
        test.assertEqual(len(handles), 1)
        descriptor = handles[0]
        root = Path(json.loads(payload)['root'])
        heartbeat = root / 'worker/heartbeat'
        _await_live_heartbeat(test, process, descriptor, heartbeat, startup_deadline)
        process.kill()
        process.wait(timeout=5)
        test.assertTrue(select.select([descriptor], [], [], 5)[0], 'Owned namespace survived controller death')
        before = heartbeat.stat().st_size
        time.sleep(.1)
        test.assertEqual(heartbeat.stat().st_size, before)
    finally:
        if process.poll() is None:
            process.kill()
        process.wait(timeout=5)
        if descriptor is not None:
            if not select.select([descriptor], [], [], 0)[0]:
                signal.pidfd_send_signal(descriptor, signal.SIGKILL)
            os.close(descriptor)
        process.stdout.close()
        process.stderr.close()
        if root is not None:
            shutil.rmtree(root)


def _await_live_heartbeat(test, process, descriptor, heartbeat, deadline):
    """Observe descendant progress within the original controller startup budget."""
    first_size = None
    while time.monotonic() < deadline:
        test.assertIsNone(process.poll(), 'Controller exited before descendant readiness')
        test.assertFalse(select.select([descriptor], [], [], 0)[0], 'Namespace exited before descendant readiness')
        try:
            size = heartbeat.stat().st_size
        except FileNotFoundError:
            size = 0
        if size > 0:
            if first_size is None:
                first_size = size
            elif size > first_size:
                test.assertIsNone(process.poll(), 'Controller exited during descendant readiness')
                test.assertFalse(select.select([descriptor], [], [], 0)[0], 'Namespace exited during descendant readiness')
                return
        time.sleep(min(.01, max(0, deadline - time.monotonic())))
    test.fail('Detached descendant did not produce live heartbeat growth within the original startup budget')


@unittest.skipUnless(os.environ.get('CWO_QUALIFICATION_PACKAGE'), 'Exact standalone package not supplied')
class SelectedNativeOSProbeTests(unittest.TestCase):
    def setUp(self):
        _require_os_prerequisites(self)

    def probe(self):
        probe = selected.SelectedNativeProbe(Path(os.environ['CWO_QUALIFICATION_PACKAGE']))
        self.addCleanup(probe.close)
        return probe

    def test_useful_command_and_patch_use_selected_appserver_command_exec(self):
        probe = self.probe()
        report = probe.run('useful')
        self.assertEqual(report['exit_code'], 0, report)
        self.assertEqual(report['stderr'], '', report)
        self.assertEqual(report['observed']['command'], 'command-ok')
        self.assertEqual(report['observed']['patch'], 'patched\n')
        self.assertTrue(report['observed']['independent_git'])
        self.assertFalse(report['accepted_output'])
        self.assertTrue(report['cleanup']['namespace_exited'])

    def test_actual_native_denials_and_inherited_descriptor_control(self):
        probe = self.probe()
        report = probe.run('denials')
        self.assertEqual(report['exit_code'], 0, report)
        self.assertEqual(report['stderr'], '', report)
        self.assertTrue(report['observed'])
        self.assertTrue(all(report['observed'].values()), report)
        self.assertFalse(report['accepted_output'])

    def test_nonempty_input_denies_before_empty_poll_observes_output(self):
        probe = self.probe()
        probe.start_waiting()
        with self.assertRaises(selected.SelectedProbeError):
            probe.poll('injected input')
        result = probe.poll('')
        self.assertIn('poll-ok', result['stdout'])
        self.assertFalse(result['accepted_output'])
        self.assertTrue(probe.close()['namespace_exited'])

    def test_appserver_config_reads_without_a_thread_or_model_turn(self):
        report = self.probe().read_configuration()
        self.assertEqual(set(report['responses']), set(selected.CONFIG_METHODS))
        for frame in report['responses'].values():
            self.assertNotIn('error', frame, report)
        config = report['responses']['config/read']['result']['config']
        self.assertEqual(config['sandbox_mode'], 'workspace-write')
        self.assertEqual(config['approval_policy'], 'never')
        self.assertFalse(config['sandbox_workspace_write']['network_access'])
        self.assertFalse(report['accepted_output'])

    def test_actual_selected_controller_death_stops_detached_descendants(self):
        _controller_death(self, os.environ['CWO_QUALIFICATION_PACKAGE'])

    def test_actual_selected_watchdog_deadline_stops_stalled_controller(self):
        probe = self.probe()
        probe.start_waiting(detached=True)
        self.assertIn('poll-ok', probe.poll('')['stdout'])
        self.assertTrue(select.select([probe.namespace_handle], [], [], 10)[0])
        heartbeat = probe.worker / 'heartbeat'
        before = heartbeat.stat().st_size
        time.sleep(.1)
        self.assertEqual(heartbeat.stat().st_size, before)
        self.assertTrue(probe.close()['namespace_exited'])

    def test_actual_selected_watchdog_failure_stops_the_namespace(self):
        probe = self.probe()
        probe.start_waiting(detached=True)
        self.assertIn('poll-ok', probe.poll('')['stdout'])
        signal.pidfd_send_signal(probe.watchdog_handle, signal.SIGKILL)
        self.assertTrue(select.select([probe.namespace_handle], [], [], 5)[0])
        self.assertTrue(probe.close()['namespace_exited'])

    def test_stopped_epoch_refuses_poll_and_restart_uses_a_fresh_owner(self):
        probe = self.probe()
        probe.start_waiting()
        original = probe.receipt
        self.assertTrue(probe.close()['namespace_exited'])
        with self.assertRaises(selected.SelectedProbeError):
            probe.poll('')
        with self.assertRaises(selected.SelectedProbeError):
            probe.start_waiting()
        successor = self.probe()
        successor.start_waiting()
        self.assertIsNot(successor.receipt, original)
        refused = successor.controller.terminate(original, 0, allow_kill=True)
        self.assertNotIn(refused['outcome'], {'killed', 'terminated'})
        self.assertIn('poll-ok', successor.poll('')['stdout'])


if __name__ == '__main__':
    unittest.main()
