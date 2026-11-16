"""Offline selected-native probes; runtime coverage requires the exact package."""
from __future__ import annotations

import array
import contextlib
import dataclasses
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
from tests import test_private_pid_ci_applicability as cursor_applicability


_MASKED_CAPGET_ENTRY = r'''
import sys,types
from unittest.mock import patch
sys.path.insert(0,sys.argv[1])
import selected_native_containment as s
masked_original=s._drop_reuse_inheritance
real_cdll=s.ctypes.CDLL

def masked_clear(namespaces):
 lib=real_cdll(None,use_errno=True)
 lib.capget.argtypes=[s.ctypes.POINTER(s._ReuseCapHeader),s.ctypes.POINTER(s._ReuseCapData)]
 lib.capget.restype=s.ctypes.c_int
 real_get=lib.capget
 def capget(header,values):
  result=real_get(header,values)
  for value in values:
   value.effective=0
   value.permitted=0
  return result
 proxy=types.SimpleNamespace(capget=capget,capset=lib.capset,prctl=lib.prctl)
 with patch.object(s.ctypes,'CDLL',return_value=proxy):
  masked_original(namespaces)
s._drop_reuse_inheritance=masked_clear

'''
_CLEARED_DEATH_ENTRY = r'''import sys,json,ctypes
sys.path.insert(0,sys.argv[1])
import selected_native_containment as s
s._private_pid_scope(json.loads(sys.argv[4]))
assert ctypes.CDLL(None).prctl(1,0,0,0,0)==0
'''



class PrivatePidReuseContractTests(unittest.TestCase):
    def test_selected_package_scope_is_refused_before_primitive_driver_effects(self):
        with patch.object(selected, '_package') as package, \
                patch.object(selected.owned.atomic_spawn, 'supported') as supported, \
                patch.object(selected.tempfile, 'TemporaryDirectory') as temporary:
            with self.assertRaisesRegex(selected.SelectedProbeError, 'only the primitive controller'):
                selected._PrivatePidReuseOwner(Path('/EXAMPLE/selected-package'))
        package.assert_not_called()
        supported.assert_not_called()
        temporary.assert_not_called()

    def test_host_uid_map_boundary_requires_fixed_outer_bootstrap(self):
        """Inspect the sanctioned bootstrap contract; this is not OS-enforcement credit."""
        owner = object.__new__(selected._PrivatePidReuseOwner)
        owner.timeout = ('/EXAMPLE/timeout', (1, 1))
        owner.bwrap = ('/EXAMPLE/bwrap', (1, 2))
        owner.unshare = ('/EXAMPLE/unshare', (1, 3))
        owner.python = ('/EXAMPLE/python', (1, 4))
        owner.root, owner.package, owner.host_namespaces = Path('/EXAMPLE/owned'), '', {}
        owner.scratch = owner.root / 'temporary'
        command = owner._command(37)
        self.assertEqual(command[:3], [owner.timeout[0], '--signal=KILL', '20'])
        outer = json.loads(command[-1])
        self.assertEqual(outer[0], owner.bwrap[0], 'Direct uid mapping lacks the required outer bootstrap')
        for flag in ('--unshare-user', '--unshare-pid', '--unshare-net', '--as-pid-1',
                     '--die-with-parent', '--new-session', '--clearenv'):
            self.assertIn(flag, outer)
        self.assertEqual(outer[outer.index('--uid') + 1], str(os.getuid()))
        self.assertEqual(outer[outer.index('--gid') + 1], str(os.getgid()))
        self.assertEqual(outer[outer.index('--ro-bind') + 1:outer.index('--ro-bind') + 3], ['/', '/'])
        self.assertEqual(outer.count('--bind'), 1)
        self.assertEqual(outer[outer.index('--bind') + 1:outer.index('--bind') + 3], [str(owner.root)] * 2)
        temporary = outer.index('TMPDIR')
        self.assertEqual(outer[temporary - 1:temporary + 2], ['--setenv', 'TMPDIR', str(owner.scratch)])
        self.assertNotIn('--dev', outer, 'devpts creates a second user namespace without PID ownership')
        self.assertEqual(outer[outer.index('--tmpfs') + 1], '/dev')
        devices = [outer[index + 1:index + 3] for index, value in enumerate(outer) if value == '--dev-bind']
        self.assertEqual(devices, [[f'/dev/{name}'] * 2 for name in ('null', 'zero', 'full', 'random', 'urandom', 'tty')])
        inner = outer[outer.index('--') + 1:]
        self.assertEqual(inner[:3], [owner.python[0], '-I', '-S'])
        self.assertNotIn(owner.unshare[0], outer, 'The sanctioned boundary must not exec another unshare utility')
        self.assertNotIn('--unshare-user-try', outer)

    def _namespace_verification_case(self, direct=False, scope=None):
        """A fixed proc graph for ancestry refusals, without birth or cleanup authority."""
        enter = scope.enter_context if scope else self.enterContext
        owner = object.__new__(selected._PrivatePidReuseOwner)
        owner.timeout = ('/EXAMPLE/timeout', (1, 1))
        owner.bwrap = ('/EXAMPLE/bwrap', (1, 2))
        owner.unshare = ('/EXAMPLE/unshare', (1, 3))
        owner.python = ('/EXAMPLE/python', (1, 4))
        owner.receipt, owner.controller = object(), Mock()
        owner.controller.owned_registration.return_value = types.SimpleNamespace(pid=604)
        owner.host_namespaces = {kind: 'host-' + kind for kind in ('pid', 'user', 'mnt', 'net')}
        facts = {kind: 'private-' + kind for kind in owner.host_namespaces}
        records = {601: 602, 602: 603 if direct else 604, 603: 604, 604: 605}
        records = {f'/proc/{pid}/stat': selected.parse_proc_stat(f'{pid} (fixed-helper) S {parent}' + ' 0' * 17 + f' {pid}')
                   for pid, parent in records.items()}
        records['/proc/601/root/proc/1/stat'] = types.SimpleNamespace(pid=1)
        objects = {'/proc/601/exe': owner.python, '/proc/602/exe': owner.bwrap,
                   '/proc/603/exe': owner.unshare}
        enter(patch.object(Path, 'read_text', lambda path: str(path)))
        enter(patch.object(selected, 'parse_proc_stat', side_effect=lambda path: records[path]))
        enter(patch.object(selected.owned.ProcAdapter, 'pidfd_pid', side_effect=lambda fd: 602 if fd == 38 else 601))
        enter(patch.object(selected.os, 'pidfd_open', return_value=38))
        enter(patch.object(selected.os, 'close'))
        enter(patch.object(selected, '_executable_object', side_effect=lambda path: objects[str(path)]))
        enter(patch.object(selected.os, 'readlink', side_effect=lambda path: facts[str(path).split('/')[-1]]))
        enter(patch.object(selected.select, 'select', return_value=([], [], [])))
        enter(patch.object(selected, '_pid_owning_user_namespace', return_value=(7, 44), create=True))
        self.records = records
        return owner, json.dumps({'inner_pid': 1, 'namespaces': facts}), objects

    def test_parent_refuses_an_extra_unshare_layer_before_release(self):
        owner, payload, _objects = self._namespace_verification_case(direct=True)
        with self.assertRaisesRegex(selected.SelectedProbeError, 'original atomic watchdog'):
            owner._verify_namespace(payload, 37)
        owner.controller._engine._verified.assert_not_called()

    def test_private_driver_rearm_refuses_the_host_before_process_effects(self):
        with patch.object(selected.os, 'getpid', return_value=17), patch.object(selected.ctypes, 'CDLL') as library:
            with self.assertRaisesRegex(selected.SelectedProbeError, 'private PID namespace'):
                selected._arm_private_parent_death({})
        library.assert_not_called()

    def test_dead_original_parent_observation_refuses_before_promotion(self):
        owner, payload, _objects = self._namespace_verification_case()
        with patch.object(selected.select, 'select', side_effect=lambda handles, *_args:
                          ([38], [], []) if handles == [38] else ([], [], [])):
            with self.assertRaisesRegex(selected.SelectedProbeError, 'original private parent exited'):
                owner._verify_namespace(payload, 37)
        owner.controller._engine._verified.assert_not_called()
        selected.os.close.assert_called_once_with(38)
        self.assertNotIn('_parent_observation', owner.__dict__)

    def test_retained_parent_observation_never_refreshes_a_changed_birth(self):
        owner, payload, _objects = self._namespace_verification_case()
        owner._verify_namespace(payload, 37)
        prior = owner._parent_observation
        parent = self.records['/proc/602/stat']
        self.records['/proc/602/stat'] = dataclasses.replace(parent, start_ticks=parent.start_ticks + 1)
        with self.assertRaisesRegex(selected.SelectedProbeError, 'original private parent lifetime changed'):
            owner._verify_namespace(payload, 37)
        self.assertEqual(owner._parent_observation, prior)
        selected.os.pidfd_open.assert_called_once_with(602, 0)
        owner._close_parent_observation()
        selected.os.close.assert_called_once_with(38)

    def test_parent_binds_single_helper_birth_and_pid_owner_before_release(self):
        owner, payload, _objects = self._namespace_verification_case()
        owner._verify_namespace(payload, 37)
        self.assertEqual(owner.boundary['bwrap_pid'], 602)
        self.assertEqual(owner.boundary['pid_owner_user_namespace'], (7, 44))
        self.assertNotIn('unshare_pid', owner.boundary)
        selected._pid_owning_user_namespace.assert_called_once_with(601)
        owner.controller._engine._verified.assert_called_once()

    def test_parent_refuses_substituted_outer_helper_executable(self):
        owner, payload, objects = self._namespace_verification_case()
        objects['/proc/602/exe'] = ('/EXAMPLE/unrelated', (9, 9))
        with self.assertRaisesRegex(selected.SelectedProbeError, 'helper ancestry'):
            owner._verify_namespace(payload, 37)
        owner.controller._engine._verified.assert_not_called()

    def test_pid_owner_mismatch_refuses_before_release_or_signal(self):
        owner, payload, _objects = self._namespace_verification_case()
        parent, child = Mock(), Mock()
        owner._quarantined_handle, owner.process = 37, None
        owner._spawn, owner.close = Mock(), Mock()
        owner._receive_namespace = Mock(return_value=payload)
        selected._pid_owning_user_namespace.side_effect = selected.SelectedProbeError('PID namespace belongs to another user namespace')
        with patch.object(selected.socket, 'socketpair', return_value=(parent, child)), \
                patch.object(selected.signal, 'pidfd_send_signal') as signals:
            with self.assertRaisesRegex(selected.SelectedProbeError, 'another user namespace'):
                owner.run()
        parent.sendall.assert_not_called()
        signals.assert_not_called()
        owner.controller._engine._verified.assert_not_called()

    def test_private_helper_state_changes_preserve_only_stable_birth_fields(self):
        owner, payload, _objects = self._namespace_verification_case()
        reads = {}
        def transition(path):
            value = self.records[path]
            reads[path] = reads.get(path, 0) + 1
            if path.endswith('/stat') and path != '/proc/601/root/proc/1/stat':
                return dataclasses.replace(value, state='R' if reads[path] == 1 else 'S')
            return value
        selected.parse_proc_stat.side_effect = transition
        owner._verify_namespace(payload, 37)
        owner.controller._engine._verified.assert_called_once()

    def test_private_helper_stable_field_substitution_refuses(self):
        for pid in (601, 602):
            for name, value in (('pid', 700), ('comm', 'replacement'), ('ppid', 700), ('start_ticks', 700)):
                with self.subTest(pid=pid, field=name):
                    with contextlib.ExitStack() as scope:
                        owner, payload, _objects = self._namespace_verification_case(scope=scope)
                        counts = {}
                        def changed(path):
                            record = self.records[path]
                            counts[path] = counts.get(path, 0) + 1
                            return dataclasses.replace(record, **{name: value}) if path == f'/proc/{pid}/stat' and counts[path] > 1 else record
                        selected.parse_proc_stat.side_effect = changed
                        with self.assertRaisesRegex(selected.SelectedProbeError, 'birth changed'):
                            owner._verify_namespace(payload, 37)
                        owner.controller._engine._verified.assert_not_called()

    def test_unverified_handoff_cannot_signal_an_unrelated_owned_sentinel(self):
        supported, reason = selected.owned.atomic_spawn.supported()
        if not supported:
            self.skipTest(reason)
        with tempfile.TemporaryDirectory() as temporary:
            controller, receipt, birth = selected._reuse_spawn(Path(temporary) / 'sentinel')
            delivered = os.dup(birth.descriptor)
            parent, child = Mock(), Mock()
            parent.recvmsg.return_value = (b'{"inner_pid":1,"namespaces":{}}',
                [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', [delivered]).tobytes())], 0, None)
            owner = object.__new__(selected._PrivatePidReuseOwner)
            owner.controller, owner.receipt = Mock(), object()
            watchdog = owner.controller
            watchdog.owned_registration.return_value = types.SimpleNamespace(pid=-1)
            owner.process = owner.namespace_handle = owner._quarantined_handle = None
            owner.temporary = Mock()
            owner.cleanup = {'namespace_exited': False, 'accepted_output': False}
            try:
                with patch.object(selected.socket, 'socketpair', return_value=(parent, child)), \
                        patch.object(owner, '_spawn'), \
                        patch.object(selected.signal, 'pidfd_send_signal', wraps=signal.pidfd_send_signal) as sent:
                    with self.assertRaisesRegex(selected.SelectedProbeError, 'original atomic watchdog'):
                        owner.run()
                sent.assert_not_called()
                parent.sendall.assert_not_called()
                watchdog.terminate.assert_called_once_with(owner.receipt, .1, allow_kill=True)
                with self.assertRaises(OSError):
                    os.fstat(delivered)
                self.assertFalse(select.select([birth.descriptor], [], [], 0)[0])
                self.assertTrue(selected._reuse_heartbeat(Path(temporary) / 'sentinel/heartbeat', birth.descriptor))
                self.assertFalse(owner.cleanup['namespace_exited'])
            finally:
                controller.terminate(receipt, .1, allow_kill=True)
                controller.close()
                try:
                    os.close(delivered)
                except OSError:
                    pass

    def test_truncated_handoff_closes_every_delivered_descriptor(self):
        read, write = os.pipe()
        self.addCleanup(os.close, read)
        self.addCleanup(os.close, write)
        delivered = os.dup(read)
        parent, child = Mock(), Mock()
        parent.recvmsg.return_value = (b'{}', [(socket.SOL_SOCKET, socket.SCM_RIGHTS,
            array.array('i', [delivered]).tobytes())], socket.MSG_CTRUNC, None)
        owner = object.__new__(selected._PrivatePidReuseOwner)
        try:
            with patch.object(selected.socket, 'socketpair', return_value=(parent, child)), \
                    patch.object(owner, '_spawn'), patch.object(owner, 'close'):
                with self.assertRaises(selected.SelectedProbeError):
                    owner.run()
            with self.assertRaises(OSError):
                os.fstat(delivered)
        finally:
            try:
                os.close(delivered)
            except OSError:
                pass

    def test_capability_inheritance_change_refuses_the_host_process(self):
        with patch.object(selected.os, 'getpid', return_value=17), \
                patch('ctypes.CDLL') as library:
            with self.assertRaisesRegex(selected.SelectedProbeError, 'private PID namespace'):
                selected._drop_reuse_inheritance({})
        library.assert_not_called()


class PrivatePidReuseOSControlTests(unittest.TestCase):
    def _retain_boundary_observations(self, owner, descriptor):
        """Observation refs only: never signal/reap or derive cleanup authority from them."""
        birth = next(item for item in owner.controller._backend.births if item.receipt is owner.receipt)
        retained = [(os.dup(descriptor), 'driver', owner.boundary['namespace_init']),
                    (os.dup(birth.descriptor), 'watchdog', birth.pid)]
        for handle, _role, _pid in retained:
            self.addCleanup(os.close, handle)
        for role in ('bwrap',):
            pid = owner.boundary[role + '_pid']
            path = Path('/proc') / str(pid) / 'stat'
            before = selected.parse_proc_stat(path.read_text())
            self.assertEqual(before.start_ticks, owner.boundary[role + '_start_ticks'])
            handle = os.pidfd_open(pid, 0)
            self.addCleanup(os.close, handle)
            self.assertEqual(selected.owned.ProcAdapter().pidfd_pid(handle), pid)
            self.assertEqual(selected._stable_process_identity(selected.parse_proc_stat(path.read_text())),
                             selected._stable_process_identity(before))
            retained.append((handle, role, pid))
        return retained

    def _assert_boundary_exited(self, descriptors):
        deadline = time.monotonic() + 3
        for descriptor, role, pid in descriptors:
            ready = bool(select.select([descriptor], [], [], max(0, deadline - time.monotonic()))[0])
            self.assertTrue(ready, f'{role} original pid={pid} retained fd={descriptor} ready={ready}')

    def test_watchdog_death_stops_the_verified_private_namespace(self):
        _require_os_prerequisites(self)
        owner = selected._PrivatePidReuseOwner(None)
        original, observed = owner._verify_namespace, []
        def stop_watchdog(payload, descriptor):
            original(payload, descriptor)
            retained = self._retain_boundary_observations(owner, descriptor)
            birth = next(item for item in owner.controller._backend.births
                         if item.receipt is owner.receipt)
            signal.pidfd_send_signal(birth.descriptor, signal.SIGKILL)
            self._assert_boundary_exited(retained)
            observed.append(True)
        with patch.object(owner, '_verify_namespace', stop_watchdog):
            with self.assertRaises((OSError, ValueError)):
                cursor_applicability._run_measured_pid_owner(owner)
        self.assertEqual(observed, [True])
        self.assertTrue(owner.cleanup['namespace_exited'])

    def test_parent_refuses_an_aliased_host_proc_view_before_release(self):
        _require_os_prerequisites(self)
        owner = selected._PrivatePidReuseOwner(None)
        original, verify = os.readlink, owner._verify_namespace
        retained = []
        def aliased(path, *args, **kwargs):
            if str(path).endswith('/root/proc/1/ns/pid'):
                return owner.host_namespaces['pid']
            return original(path, *args, **kwargs)
        def refuse(payload, descriptor):
            # Independently retain the genuine namespace and watchdog before
            # injecting the refused observation. The refused received fd itself
            # must never become namespace signal authority.
            verify(payload, descriptor)
            retained.extend(self._retain_boundary_observations(owner, descriptor))
            with patch.object(selected.os, 'readlink', side_effect=aliased):
                verify(payload, descriptor)
        with patch.object(owner, '_verify_namespace', refuse):
            with self.assertRaisesRegex(selected.SelectedProbeError, 'private proc'):
                owner.run()
        self.assertEqual(len(retained), 3)
        self._assert_boundary_exited(retained)
        self.assertFalse(owner.cleanup['namespace_exited'])
        self.assertIsNone(owner.namespace_handle)
        self.assertIsNone(owner._quarantined_handle)

    def test_verified_inner_cleanup_survives_original_watchdog_owner_failure(self):
        _require_os_prerequisites(self)
        owner = selected._PrivatePidReuseOwner(None)
        parent, child = socket.socketpair()
        self.addCleanup(parent.close)
        self.addCleanup(child.close)
        primary = selected.SelectedProbeError('EXAMPLE parent release refused')
        proxy = types.SimpleNamespace(fileno=parent.fileno, settimeout=parent.settimeout,
            recvmsg=parent.recvmsg, recv=parent.recv, close=Mock(), sendall=Mock(side_effect=primary))
        verify, retained, targets, boundary = owner._verify_namespace, [], [], {}
        send = signal.pidfd_send_signal
        def observe_signal(descriptor, sig, *args):
            targets.append(selected.owned.ProcAdapter().pidfd_pid(descriptor))
            return send(descriptor, sig, *args)
        def verified(payload, descriptor):
            verify(payload, descriptor)
            boundary.update(owner.boundary)
            retained.extend(self._retain_boundary_observations(owner, descriptor))
            owner.controller.terminate = Mock(side_effect=RuntimeError('EXAMPLE original owner failure'))
        # Keep the real parent channel open until cleanup, so exit must be
        # obtained through the verified inner handle even when owner cleanup fails.
        with patch.object(selected.socket, 'socketpair', return_value=(proxy, child)), \
                patch.object(owner, '_verify_namespace', verified), \
                patch.object(selected.signal, 'pidfd_send_signal', side_effect=observe_signal):
            with self.assertRaises(selected.SelectedProbeError) as caught:
                owner.run()
        self.assertIs(caught.exception, primary)
        proxy.sendall.assert_called_once_with(b'1')
        self.assertIn(boundary['namespace_init'], targets)
        self.assertTrue(owner.cleanup['namespace_exited'])
        self.assertIn('original owner failure', str(primary.__notes__))
        self.assertEqual(len(retained), 3)
        self._assert_boundary_exited(retained)

    def test_substituted_outer_helper_refuses_without_unverified_namespace_signal(self):
        _require_os_prerequisites(self)
        owner = selected._PrivatePidReuseOwner(None)
        verify, executable = owner._verify_namespace, selected._executable_object
        retained, targets, boundary = [], [], {}
        send = signal.pidfd_send_signal
        def observe_signal(descriptor, sig, *args):
            targets.append(selected.owned.ProcAdapter().pidfd_pid(descriptor))
            return send(descriptor, sig, *args)
        def refuse(payload, descriptor):
            verify(payload, descriptor)
            boundary.update(owner.boundary)
            retained.extend(self._retain_boundary_observations(owner, descriptor))
            def substitute(path):
                if str(path) == f"/proc/{boundary['bwrap_pid']}/exe":
                    return ('/EXAMPLE/unrelated', (9, 9))
                return executable(path)
            with patch.object(selected, '_executable_object', side_effect=substitute):
                verify(payload, descriptor)
        with patch.object(owner, '_verify_namespace', refuse), \
                patch.object(selected.signal, 'pidfd_send_signal', side_effect=observe_signal):
            with self.assertRaisesRegex(selected.SelectedProbeError, 'helper ancestry'):
                owner.run()
        self.assertEqual(len(retained), 3)
        self._assert_boundary_exited(retained)
        self.assertNotIn(boundary['namespace_init'], targets)
        self.assertTrue(all(pid in (-1, boundary['watchdog_pid']) for pid in targets))
        self.assertFalse(owner.cleanup['namespace_exited'])
        self.assertIsNone(owner.namespace_handle)
        self.assertIsNone(owner._quarantined_handle)

    def test_policy_masked_capget_preserves_private_driver_capabilities(self):
        entry = _MASKED_CAPGET_ENTRY + cursor_applicability._MEASURED_PID_ENTRY
        with patch.object(cursor_applicability, '_MEASURED_PID_ENTRY', entry):
            self.test_actual_private_pid_reuse_preserves_the_fresh_lifetime()

    def test_exec_cleared_parent_death_is_rearmed_before_handoff(self):
        entry = _CLEARED_DEATH_ENTRY + cursor_applicability._MEASURED_PID_ENTRY
        with patch.object(cursor_applicability, '_MEASURED_PID_ENTRY', entry):
            self.test_watchdog_death_stops_the_verified_private_namespace()

    def test_parent_death_during_handoff_refuses_without_namespace_signal(self):
        _require_os_prerequisites(self)
        owner = selected._PrivatePidReuseOwner(None)
        retain, send = owner._retain_parent_observation, signal.pidfd_send_signal
        observations, targets = [], []
        def sent(descriptor, sig, *args):
            targets.append(selected.owned.ProcAdapter().pidfd_pid(descriptor))
            return send(descriptor, sig, *args)
        def parent_dies(monitor):
            driver = os.dup(owner._quarantined_handle)
            self.addCleanup(os.close, driver)
            observations.append(selected.owned.ProcAdapter().pidfd_pid(driver))
            birth = next(item for item in owner.controller._backend.births if item.receipt is owner.receipt)
            signal.pidfd_send_signal(birth.descriptor, signal.SIGKILL)
            deadline = time.monotonic() + 3
            for descriptor in (birth.descriptor, driver):
                self.assertTrue(select.select([descriptor], [], [], max(0, deadline - time.monotonic()))[0])
            return retain(monitor)
        with patch.object(owner, '_retain_parent_observation', parent_dies), \
                patch.object(selected.signal, 'pidfd_send_signal', sent):
            with self.assertRaises((selected.SelectedProbeError, OSError)):
                owner.run()
        self.assertEqual(len(observations), 1)
        self.assertNotIn(observations[0], targets)
        self.assertFalse(owner.cleanup['namespace_exited'])
        self.assertIsNone(owner.namespace_handle)
        self.assertIsNone(owner._quarantined_handle)
        self.assertIsNone(owner._parent_observation)

    def test_actual_private_pid_reuse_preserves_the_fresh_lifetime(self):
        _require_os_prerequisites(self)
        report = cursor_applicability._run_measured_pid_owner(selected._PrivatePidReuseOwner(None))
        self.assertEqual(report['scope'], 'primitive-controller-pid-reuse')
        self.assertEqual(report['original_pid'], report['sentinel_pid'])
        self.assertTrue(report['sentinel_heartbeat_grew'])
        self.assertEqual(report['stale']['signals'], [])
        self.assertFalse(report['sentinel_reaped_by_stale_owner'])
        self.assertTrue(report['fresh_cleanup']['child_exit_confirmed'])
        self.assertTrue(report['fresh_cleanup']['child_reaped'])
        self.assertTrue(report['cleanup']['namespace_exited'])
        self.assertFalse(report['execution_authorized'])
        self.assertFalse(report['accepted_output'])
        self.assertEqual(report['sentinel_context']['capabilities'],
                         {'CapEff': 0, 'CapPrm': 0, 'CapInh': 0, 'CapAmb': 0})


class PrivateWatchdogCleanupProofTests(unittest.TestCase):
    def owner(self, termination, closed):
        owner = object.__new__(selected._PrivatePidReuseOwner)
        owner._parent_observation = owner._quarantined_handle = owner.namespace_handle = owner.process = None
        owner.receipt = types.SimpleNamespace(registration=types.SimpleNamespace(pid=17001))
        owner.controller = types.SimpleNamespace(terminate=Mock(return_value=termination), close=Mock(return_value=closed))
        owner.temporary = types.SimpleNamespace(cleanup=Mock())
        owner.cleanup = {'namespace_exited': False, 'accepted_output': False}
        owner._deadline = time.monotonic() + selected._PID_REUSE_SECONDS
        return owner

    def test_missing_false_or_nonboolean_original_exit_proof_cannot_complete_cleanup(self):
        valid = {'outcome': 'already-exited', 'signals': [], 'child_pid': 17001,
                 'registration_committed': True, 'child_exit_confirmed': True,
                 'child_reaped': True, 'receipt_available': False}
        for stage in ('termination', 'close'):
            for field in ('registration_committed', 'child_exit_confirmed', 'child_reaped', 'receipt_available'):
                for value in ('missing', None, field == 'receipt_available', 1 if field != 'receipt_available' else 0):
                    with self.subTest(stage=stage, field=field, value=value):
                        reports = {'termination': dict(valid),
                                   'close': {**valid, 'outcome': 'closed', 'close_errors': []}}
                        if value == 'missing':
                            reports[stage].pop(field)
                        else:
                            reports[stage][field] = value
                        owner = self.owner(reports['termination'], reports['close'])
                        controller, temporary = owner.controller, owner.temporary
                        with self.assertRaisesRegex(selected.SelectedProbeError, 'watchdog.*unconfirmed'):
                            owner.close()
                        controller.terminate.assert_called_once()
                        controller.close.assert_called_once_with()
                        temporary.cleanup.assert_called_once_with()

    def test_changed_birth_mapping_refuses_before_original_exit_wait(self):
        owner = self.owner({}, {})
        owner.cleanup['namespace_exited'] = True
        backend = selected.owned._LinuxBackend()
        original = selected.owned._Birth(pid=17001, descriptor=37, child=object(),
                                        reap_authorized=True, receipt=owner.receipt)
        replacement = selected.owned._Birth(pid=17002, descriptor=37, child=object(),
                                           reap_authorized=True)
        backend.births = [original, replacement]
        backend._owned[37] = replacement
        owner.controller._backend = backend
        with patch.object(selected.owned.ProcAdapter, 'wait_exit') as waiting:
            with self.assertRaisesRegex(selected.owned._Refusal, 'original child handle'):
                owner._wait_original_watchdog(owner.controller)
        waiting.assert_not_called()
        self.assertIsNone(original.active_operation)
        self.assertIsNone(replacement.active_operation)

    def test_missing_close_errors_and_original_cleanup_errors_remain_failures(self):
        valid = {'outcome': 'already-exited', 'signals': [], 'child_pid': 17001,
                 'registration_committed': True, 'child_exit_confirmed': True,
                 'child_reaped': True, 'receipt_available': False}
        for field in ('close_errors', 'close_error', 'cleanup_errors', 'retained_cleanup_errors'):
            with self.subTest(field=field):
                closed = {**valid, 'outcome': 'closed', 'close_errors': []}
                if field == 'close_errors':
                    closed.pop(field)
                else:
                    closed[field] = ['EXAMPLE cleanup failure']
                owner = self.owner(dict(valid), closed)
                temporary = owner.temporary
                with self.assertRaisesRegex(selected.SelectedProbeError, 'watchdog.*cleanup errors'):
                    owner.close()
                temporary.cleanup.assert_called_once_with()


_EXITING_LEADER_CHILD = r'''
import ctypes,os,threading
release=threading.Event()
def sibling():
 release.wait()
 os.write(1,b'sibling-ready\n')
 os.read(0,1)
threading.Thread(target=sibling).start()
os.write(1,b'leader-ready\n')
assert os.read(0,1)==b'1'
release.set()
ctypes.CDLL(None).syscall(60,0)
raise AssertionError('The leader exit syscall returned.')
'''


class PrivateWatchdogCleanupOSControlTests(unittest.TestCase):
    """Real original-owner exit transitions, without private namespace credit."""

    def setUp(self):
        _require_os_prerequisites(self)

    def original_exiting_owner(self):
        temporary = tempfile.TemporaryDirectory(prefix='cwo-watchdog-exit-control-')
        self.addCleanup(temporary.cleanup)
        executable = str(Path('/usr/bin/python3').resolve())
        backend = selected._PipeBackend(())
        controller = selected.owned.LinuxOwnedChildController(executable)
        controller._backend = backend
        controller._engine = selected.owned._LinuxEngine(backend, executable)
        self.addCleanup(controller.close)
        deadline = time.monotonic() + selected._PID_REUSE_SECONDS
        report = controller.spawn_owned('fixed-watchdog-exit-control',
            [executable, '-I', '-S', '-c', _EXITING_LEADER_CHILD], temporary.name)
        self.assertEqual(report['outcome'], 'registered', report)
        receipt = report['receipt']
        birth = next(item for item in backend.births if item.receipt is receipt)
        observer = os.dup(birth.descriptor)
        child = birth.child
        self.addCleanup(self.release_original, controller, child, observer)
        self.marker(child, b'leader-ready\n', deadline)
        boundary_deadline = min(deadline, time.monotonic() + 3)
        os.write(child.stdin.fileno(), b'1')
        self.marker(child, b'sibling-ready\n', boundary_deadline)
        executable_link = Path('/proc') / str(birth.pid) / 'exe'
        while True:
            try:
                os.readlink(executable_link)
            except FileNotFoundError:
                break
            self.assertLess(time.monotonic(), boundary_deadline)
            time.sleep(.001)
        self.assertFalse(select.select([observer], [], [], 0)[0])
        self.assertIsNone(os.waitid(os.P_PIDFD, observer, os.WEXITED | os.WNOHANG | os.WNOWAIT))
        owner = object.__new__(selected._PrivatePidReuseOwner)
        owner._parent_observation = owner._quarantined_handle = owner.namespace_handle = None
        owner.controller, owner.receipt, owner.process = controller, receipt, child
        # Independent namespace enforcement is covered elsewhere. This fixture
        # starts at its completed-cleanup precondition to isolate the watchdog.
        owner.cleanup = {'namespace_exited': True, 'accepted_output': False}
        owner._deadline = deadline
        owner.temporary = temporary
        return owner, controller, backend, birth, child, observer, boundary_deadline

    def marker(self, child, expected, deadline):
        self.assertTrue(select.select([child.stdout], [], [], max(0, deadline - time.monotonic()))[0])
        self.assertEqual(os.read(child.stdout.fileno(), 64), expected)

    def release_original(self, controller, child, observer):
        # Fixture-only recovery never supplies proof to the failed owner call.
        try:
            if not child.stdin.closed:
                child.stdin.close()
            if not select.select([observer], [], [], 0)[0]:
                signal.pidfd_send_signal(observer, signal.SIGKILL)
            self.assertTrue(select.select([observer], [], [], 3)[0])
            try:
                os.waitid(os.P_PIDFD, observer, os.WEXITED | os.WNOHANG)
            except ChildProcessError:
                pass
        finally:
            os.close(observer)
            controller.close()
            for stream in (child.stdin, child.stdout, child.stderr):
                stream.close()

    def measured_reports(self, controller):
        records = []
        terminate, close = controller.terminate, controller.close
        def terminated(*args, **kwargs):
            report = terminate(*args, **kwargs)
            records.append(('termination', dict(report)))
            return report
        def closed():
            report = close()
            records.append(('close', dict(report)))
            return report
        self.enterContext(patch.object(controller, 'terminate', terminated))
        self.enterContext(patch.object(controller, 'close', closed))
        return records

    def test_private_close_waits_for_its_original_exiting_watchdog(self):
        owner, controller, backend, birth, child, observer, boundary_deadline = self.original_exiting_owner()
        records = self.measured_reports(controller)
        original_wait = selected.owned.ProcAdapter.wait_exit
        waiting, lifetime_deadline = [], owner._deadline
        remaining_before_close = max(0, lifetime_deadline - time.monotonic())
        def release_at_original_wait(observed_backend, descriptor, seconds):
            self.assertIs(observed_backend, backend)
            self.assertEqual(descriptor, birth.descriptor)
            self.assertFalse(birth.closed)
            self.assertIs(backend._owned[descriptor], birth)
            self.assertIsNotNone(controller.owned_registration(owner.receipt))
            waiting.append(seconds)
            self.assertGreater(seconds, 0)
            self.assertLessEqual(seconds, remaining_before_close)
            os.write(child.stdin.fileno(), b'2')
            return original_wait(backend, descriptor, seconds)
        with patch.object(selected.owned.ProcAdapter, 'wait_exit', release_at_original_wait), \
                patch.object(os, 'pidfd_open', side_effect=AssertionError('No late PID handle is allowed.')), \
                patch.object(signal, 'pidfd_send_signal', side_effect=AssertionError('No new signal is allowed.')):
            owner.close()
        self.assertEqual([stage for stage, _ in records], ['termination', 'close'])
        for _stage, report in records:
            self.assertTrue(report['child_exit_confirmed'])
            self.assertTrue(report['child_reaped'])
            self.assertFalse(report['receipt_available'])
            self.assertEqual(report['child_pid'], birth.pid)
            self.assertEqual(report['signals'], [])
        self.assertEqual(len(waiting), 1)
        self.assertTrue(select.select([observer], [], [], 0)[0])
        self.assertTrue(birth.reaped)
        self.assertEqual(owner._deadline, lifetime_deadline)
        self.assertLess(time.monotonic(), boundary_deadline)

    def test_expired_original_budget_cannot_be_restarted_or_claim_cleanup(self):
        owner, controller, backend, birth, _child, _observer, _boundary_deadline = self.original_exiting_owner()
        records = self.measured_reports(controller)
        owner._deadline = time.monotonic() - .001
        deadline = owner._deadline
        original_wait = selected.owned.ProcAdapter.wait_exit
        waits = []
        def held_original(observed_backend, descriptor, seconds):
            self.assertIs(observed_backend, backend)
            self.assertEqual(descriptor, birth.descriptor)
            self.assertEqual(seconds, 0)
            waits.append(seconds)
            return original_wait(backend, descriptor, seconds)
        with patch.object(selected.owned.ProcAdapter, 'wait_exit', held_original), \
                patch.object(os, 'pidfd_open', side_effect=AssertionError('No late PID handle is allowed.')), \
                patch.object(signal, 'pidfd_send_signal', side_effect=AssertionError('No refused-lifetime signal is allowed.')):
            with self.assertRaisesRegex(selected.SelectedProbeError, 'watchdog.*unconfirmed'):
                owner.close()
        self.assertEqual(waits, [0])
        self.assertEqual(owner._deadline, deadline)
        self.assertEqual([stage for stage, _ in records], ['termination', 'close'])
        for _stage, report in records:
            self.assertFalse(report['child_exit_confirmed'])
            self.assertFalse(report['child_reaped'])
            self.assertFalse(report['receipt_available'])
            self.assertEqual(report['signals'], [])
        self.assertFalse(birth.reaped)


class StableBirthContractTests(unittest.TestCase):
    def test_namespace_open_rejects_every_stable_identity_substitution(self):
        before = selected.parse_proc_stat('601 (driver) R 602' + ' 0' * 17 + ' 603')
        for name, value in (('pid', 700), ('comm', 'other'), ('ppid', 700), ('start_ticks', 700)):
            with self.subTest(field=name):
                probe = object.__new__(selected.SelectedNativeProbe)
                probe.namespace_handle = None
                probe._namespace_identity = Mock(side_effect=[before, dataclasses.replace(before, **{name: value})])
                probe._namespace_facts = Mock()
                with patch.object(selected.os, 'pidfd_open', return_value=37), \
                        patch.object(Path, 'read_text', return_value='Pid:\t601\n'), \
                        patch.object(selected.os, 'close') as close:
                    with self.assertRaisesRegex(selected.SelectedProbeError, 'birth changed'):
                        probe._inspect({'child-pid': 601})
                close.assert_called_once_with(37)
                probe._namespace_facts.assert_not_called()
                self.assertIsNone(probe.namespace_handle)


    def test_pid_owner_user_namespace_is_bound_and_observation_fds_close(self):
        for inode in (44, 45):
            with self.subTest(owner_inode=inode), \
                    patch.object(selected.os, 'open', return_value=37) as opening, \
                    patch.object(selected.fcntl, 'ioctl', return_value=38) as ioctl, \
                    patch.object(selected.os, 'fstat', return_value=types.SimpleNamespace(st_dev=7, st_ino=inode)), \
                    patch.object(Path, 'stat', return_value=types.SimpleNamespace(st_dev=7, st_ino=44)), \
                    patch.object(selected.os, 'close') as close:
                if inode == 44:
                    self.assertEqual(selected._pid_owning_user_namespace(601), (7, 44))
                else:
                    with self.assertRaisesRegex(selected.SelectedProbeError, 'another user namespace'):
                        selected._pid_owning_user_namespace(601)
                opening.assert_called_once_with(Path('/proc/601/ns/pid'), os.O_RDONLY | os.O_CLOEXEC)
                ioctl.assert_called_once_with(37, 0xb701)
                self.assertEqual(close.call_args_list, [unittest.mock.call(38), unittest.mock.call(37)])


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

    def observe(self, probe, executable, *, parent=None, inode=None, transition=None):
        pid, descriptor = 17002, 77
        parent = probe._namespace_pid if parent is None else parent
        observations = []
        def read(path, *args, **kwargs):
            if path.name == 'children':
                return str(pid)
            if path.name == 'stat':
                record = f'{pid} (timeout) S {parent}' + ' 0' * 17 + ' 99'
                observations.append(record)
                return transition(record, len(observations)) if transition else record
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

    def test_watchdog_scheduler_state_change_preserves_birth(self):
        probe, executable, _other = self.fixture()
        self.observe(probe, executable, transition=lambda raw, count: raw.replace(') S ', ') R ') if count == 1 else raw)
        self.assertEqual(probe.watchdog_handle, 77)

    def test_watchdog_stable_field_substitution_closes_unretained_handle(self):
        for original, replacement in (('(timeout)', '(other)'), ('17002 (', '17003 ('),
                                      (' S 17001 ', ' S 17009 '), (' 99', ' 100')):
            with self.subTest(replacement=replacement):
                probe, executable, _other = self.fixture()
                def transition(raw, count):
                    return raw.replace(original, replacement) if count > 1 else raw
                with self.assertRaisesRegex(selected.SelectedProbeError, 'birth changed'):
                    self.observe(probe, executable, transition=transition)
                self.assertIsNone(probe.watchdog_handle)

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

    def test_scheduler_state_change_during_namespace_handle_open_preserves_birth(self):
        probe = self.probe()
        original, observations = probe._namespace_identity, []
        def transition(pid):
            record = original(pid)
            record = dataclasses.replace(record, state='R' if not observations else 'S')
            observations.append(record)
            return record
        with patch.object(probe, '_namespace_identity', side_effect=transition):
            probe.start_waiting(detached=True)
        self.assertGreaterEqual(len(observations), 2)
        self.assertIn('poll-ok', probe.poll('')['stdout'])
        self.assertTrue(probe.close()['namespace_exited'])

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
