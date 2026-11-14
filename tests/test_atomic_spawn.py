"""Atomic creation uses only bounded children and descriptors owned by tests."""

from __future__ import annotations

import ctypes
import errno
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from cwo_core import atomic_spawn  # noqa: E402
from cwo_core.process_identity import ProcAdapter  # noqa: E402
import linux_owned_children as owned  # noqa: E402
import registered_n1_factory as factory  # noqa: E402


class AtomicSpawnTests(unittest.TestCase):
    def library(self, spawn):
        names = (
            "posix_spawn_file_actions_init", "posix_spawn_file_actions_destroy",
            "posix_spawnattr_init", "posix_spawnattr_destroy",
            "posix_spawn_file_actions_addchdir_np", "posix_spawn_file_actions_addopen",
            "posix_spawn_file_actions_addclosefrom_np", "posix_spawnattr_setsigdefault",
            "posix_spawnattr_setflags", "sigemptyset", "sigaddset",
        )
        return SimpleNamespace(**{name: mock.Mock(return_value=0) for name in names},
                               pidfd_spawn=mock.Mock(side_effect=spawn))

    def test_unsupported_platform_and_old_libc_refuse_before_creation(self):
        with mock.patch.object(atomic_spawn.sys, "platform", "unsupported"), \
                mock.patch.object(atomic_spawn.ctypes, "CDLL") as load:
            self.assertFalse(atomic_spawn.supported()[0])
            load.assert_not_called()
        libc = SimpleNamespace(gnu_get_libc_version=mock.Mock(return_value=b"2.39"))
        with mock.patch.object(atomic_spawn.ctypes, "CDLL", return_value=libc), \
                self.assertRaises(OSError) as failure:
            atomic_spawn.spawn("/EXAMPLE/executable", ("/EXAMPLE/executable",), "/EXAMPLE", mock.Mock())
        self.assertEqual(failure.exception.errno, errno.ENOSYS)

    def test_native_errno_is_used_and_all_initialized_resources_are_destroyed(self):
        for code in (errno.ENOSYS, errno.EPERM, errno.EAGAIN, errno.ENOENT):
            with self.subTest(errno=code):
                libc = self.library(lambda *_args: code)
                retain = mock.Mock()
                with mock.patch.object(atomic_spawn, "_library", return_value=libc), \
                        self.assertRaises(OSError) as failure:
                    ctypes.set_errno(errno.ENOTTY)
                    atomic_spawn.spawn("/EXAMPLE/executable", ("/EXAMPLE/executable",), "/EXAMPLE", retain)
                self.assertEqual(failure.exception.errno, code)
                retain.assert_not_called()
                libc.posix_spawn_file_actions_destroy.assert_called_once()
                libc.posix_spawnattr_destroy.assert_called_once()

    def test_c_return_interruption_transfers_the_original_handle_once(self):
        read, write = os.pipe()
        self.addCleanup(os.close, read)
        self.addCleanup(os.close, write)
        transferred, children = [], []
        descriptor = os.dup(read)
        self.addCleanup(lambda: os.close(transferred.pop()) if transferred else None)
        primary = KeyboardInterrupt("EXAMPLE C-return interruption")

        def interrupted(output, *_args):
            output._obj.value = descriptor
            raise primary

        def retain(child):
            children.append(child)
            transferred.append(child.transfer_handle())

        libc = self.library(interrupted)
        with mock.patch.object(atomic_spawn, "_library", return_value=libc), \
                self.assertRaises(KeyboardInterrupt) as failure:
            atomic_spawn.spawn("/EXAMPLE/executable", ("/EXAMPLE/executable",), "/EXAMPLE", retain)
        self.assertIs(failure.exception, primary)
        self.assertEqual(transferred, [descriptor])
        with self.assertRaises(ValueError):
            children[0].transfer_handle()
        os.fstat(descriptor)
        libc.posix_spawn_file_actions_destroy.assert_called_once()
        libc.posix_spawnattr_destroy.assert_called_once()

    def test_unclaimed_output_is_closed_once_without_masking_primary(self):
        read, write = os.pipe()
        self.addCleanup(os.close, read)
        self.addCleanup(os.close, write)
        descriptor = os.dup(read)
        primary = RuntimeError("EXAMPLE retain failure")

        def created(output, *_args):
            output._obj.value = descriptor
            return 0

        libc = self.library(created)
        close = os.close
        with mock.patch.object(atomic_spawn, "_library", return_value=libc), \
                mock.patch.object(atomic_spawn.os, "close", wraps=close) as release, \
                self.assertRaises(RuntimeError) as failure:
            atomic_spawn.spawn("/EXAMPLE/executable", ("/EXAMPLE/executable",), "/EXAMPLE",
                               mock.Mock(side_effect=primary))
        self.assertIs(failure.exception, primary)
        release.assert_called_once_with(descriptor)
        with self.assertRaises(OSError):
            os.fstat(descriptor)
        with self.assertRaises(TypeError):
            atomic_spawn.AtomicChild()

    def test_refused_atomic_adoption_closes_unclaimed_handle_once(self):
        # A substituted native result qualifies refusal cleanup, not actual
        # kernel descriptor reuse. The descriptor belongs only to this test.
        read, write = os.pipe()
        self.addCleanup(os.close, read)
        self.addCleanup(os.close, write)
        descriptor = os.dup(read)
        backend = owned._LinuxBackend()
        prior = owned._Birth(descriptor=descriptor)
        backend._owned[descriptor] = prior
        birth = owned._Birth()
        closed = []
        original_close = os.close

        def close(value):
            closed.append(value)
            original_close(value)

        def created(output, *_args):
            output._obj.value = descriptor
            return 0

        try:
            with mock.patch.object(atomic_spawn, "_library", return_value=self.library(created)), \
                    mock.patch.object(atomic_spawn.os, "close", side_effect=close), \
                    self.assertRaises(owned._Refusal):
                atomic_spawn.spawn("/EXAMPLE/executable", ("/EXAMPLE/executable",), "/EXAMPLE",
                                   lambda child: backend._retain_atomic(birth, child))
            self.assertEqual(closed, [descriptor])
            self.assertIs(backend._owned[descriptor], prior)
            self.assertEqual(backend.births, [])
            self.assertIsNone(birth.descriptor)
            with self.assertRaises(OSError):
                os.fstat(descriptor)
        finally:
            if descriptor not in closed:
                os.close(descriptor)

    def test_pipe_allocation_failure_closes_earlier_descriptors(self):
        before = set(os.listdir("/proc/self/fd"))
        original = os.pipe
        calls = []

        def failing_pipe():
            calls.append(True)
            if len(calls) == 2:
                raise OSError(errno.EMFILE, "EXAMPLE descriptor exhaustion")
            return original()

        with mock.patch.object(atomic_spawn.os, "pipe", side_effect=failing_pipe), \
                self.assertRaises(OSError) as failure:
            atomic_spawn.spawn_piped("/EXAMPLE/target", ("/EXAMPLE/target",), "/EXAMPLE", (), mock.Mock())
        self.assertEqual(failure.exception.errno, errno.EMFILE)
        self.assertEqual(set(os.listdir("/proc/self/fd")), before)

    def test_missing_malformed_and_expired_exec_handshakes_refuse(self):
        for data in (b"", b"not-ready", b"R\ntrailing", b"R\nEinvalid\n"):
            with self.subTest(data=data), self.assertRaises(OSError) as failure:
                atomic_spawn._exec_result(data)
            self.assertEqual(failure.exception.errno, errno.EIO)
        read, write = os.pipe()
        try:
            with self.assertRaises(OSError) as failure:
                atomic_spawn._await_exec(read, timeout=0)
            self.assertEqual(failure.exception.errno, errno.ETIMEDOUT)
        finally:
            os.close(read)
            os.close(write)


class RealAtomicPipeTests(unittest.TestCase):
    def setUp(self):
        supported, reason = owned._LinuxBackend().supported()
        if not supported:
            self.skipTest(reason)

    def reap(self, descriptor):
        try:
            if not ProcAdapter().wait_exit(descriptor, 5):
                signal.pidfd_send_signal(descriptor, signal.SIGKILL)
                self.assertTrue(ProcAdapter().wait_exit(descriptor, 5))
            os.waitid(os.P_PIDFD, descriptor, os.WEXITED)
        finally:
            os.close(descriptor)

    def test_standard_descriptor_cycles_preserve_distinct_sources(self):
        program = r'''
import json,os,socket,sys
sys.path.insert(0,sys.argv[1])
from cwo_core import atomic_spawn
from cwo_core.process_identity import ProcAdapter
left,first=socket.socketpair()
right,second=socket.socketpair()
os.dup2(left.fileno(),0)
os.dup2(right.fileno(),1)
descriptors=[]
atomic_spawn.spawn(sys.executable,(sys.executable,'-I','-S','-c',
    "import os; os.write(0,b'zero'); os.write(1,b'one')"),os.getcwd(),
    lambda child: descriptors.append(child.transfer_handle()),stdio=(1,0,2))
os.close(0)
os.close(1)
left.close()
right.close()
descriptor=descriptors[0]
if not ProcAdapter().wait_exit(descriptor,5):
    import signal
    signal.pidfd_send_signal(descriptor,signal.SIGKILL)
    assert ProcAdapter().wait_exit(descriptor,5)
os.waitid(os.P_PIDFD,descriptor,os.WEXITED)
os.close(descriptor)
first.settimeout(1)
second.settimeout(1)
result=[first.recv(16).decode(),second.recv(16).decode()]
os.write(2,json.dumps(result).encode())
'''
        result = subprocess.run([sys.executable, "-I", "-S", "-c", program, str(ROOT / "scripts")],
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stderr), ["one", "zero"])

    def test_closed_parent_standard_descriptors_preserve_pipe_handshake(self):
        program = r'''
import fcntl,json,os,sys,tempfile
from unittest import mock
sys.path.insert(0,sys.argv[1])
import linux_owned_children as owned
import registered_n1_factory as factory
report=fcntl.fcntl(1,fcntl.F_DUPFD_CLOEXEC,64)
read,write=os.pipe()
selected=fcntl.fcntl(read,fcntl.F_DUPFD_CLOEXEC,64)
os.close(read)
os.write(write,b'selected')
os.close(write)
executable=os.path.realpath(sys.executable)
with tempfile.TemporaryDirectory() as temporary:
    backend=factory._PipeBackend((selected,))
    with mock.patch.object(owned,'_LinuxBackend',return_value=backend):
        controller=owned.LinuxOwnedChildController(executable)
    for descriptor in (0,1,2):
        os.close(descriptor)
    result=controller.spawn_owned('EXAMPLE-closed-stdio',[executable,'-I','-S','-c',
        "import os,sys; print(sys.stdin.read()+os.read(int(sys.argv[1]),32).decode())",
        str(selected)],os.path.realpath(temporary))
    try:
        assert result['outcome']=='registered',result
        child=backend.births[0].child
        output,errors=child.communicate('input-',timeout=5)
        ended=controller.terminate(result['receipt'],1)
        assert ended['child_reaped'],ended
        os.write(report,json.dumps([output,errors]).encode())
    finally:
        if result.get('receipt'):
            controller.terminate(result['receipt'],0.1,allow_kill=True)
        controller.close()
os.close(selected)
os.close(report)
'''
        result = subprocess.run([sys.executable, "-I", "-S", "-c", program, str(ROOT / "scripts")],
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), ["input-selected\n", ""])

    def test_failed_exec_and_cwd_do_not_publish_a_target_or_leak_descriptors(self):
        executable = os.path.realpath(sys.executable)
        with tempfile.TemporaryDirectory() as temporary:
            for target, directory in ((str(Path(temporary) / "missing"), temporary),
                                      (executable, str(Path(temporary) / "missing-cwd"))):
                descriptors = []
                before = set(os.listdir("/proc/self/fd"))
                with self.subTest(target=target, cwd=directory), self.assertRaises(OSError) as failure:
                    atomic_spawn.spawn_piped(target, (target, "-c", "pass"), directory, (),
                        lambda child, _streams: descriptors.append(child.transfer_handle()))
                self.assertEqual(failure.exception.errno, errno.ENOENT)
                for descriptor in descriptors:
                    self.reap(descriptor)
                self.assertEqual(set(os.listdir("/proc/self/fd")), before)

    def test_interrupted_exec_handshake_retains_original_birth_and_closes_pipes(self):
        executable = os.path.realpath(sys.executable)
        descriptors, streams = [], []
        primary = KeyboardInterrupt("EXAMPLE interrupted handshake")
        before = set(os.listdir("/proc/self/fd"))

        def retain(child, selected):
            descriptors.append(child.transfer_handle())
            streams.extend(selected)

        with mock.patch.object(atomic_spawn, "_await_exec", side_effect=primary), \
                self.assertRaises(KeyboardInterrupt) as failure:
            atomic_spawn.spawn_piped(executable, (executable, "-I", "-S", "-c", "pass"),
                                     os.path.realpath(tempfile.gettempdir()), (), retain)
        self.assertIs(failure.exception, primary)
        self.assertEqual(len(descriptors), 1)
        self.assertTrue(all(stream.closed for stream in streams))
        self.reap(descriptors[0])
        self.assertEqual(set(os.listdir("/proc/self/fd")), before)

    def test_original_pipe_contract_preserves_stdio_pass_fds_and_child_only_umask(self):
        supported, reason = owned._LinuxBackend().supported()
        if not supported:
            self.skipTest(reason)
        executable = os.path.realpath(sys.executable)
        with tempfile.TemporaryDirectory() as temporary:
            read, write = os.pipe()
            self.addCleanup(os.close, read)
            os.write(write, b"selected descriptor")
            os.close(write)
            import fcntl
            excluded = fcntl.fcntl(read, fcntl.F_DUPFD_CLOEXEC, 64)
            self.addCleanup(os.close, excluded)
            os.set_inheritable(excluded, True)
            backend = factory._PipeBackend((read,))
            with mock.patch.object(owned, "_LinuxBackend", return_value=backend):
                controller = owned.LinuxOwnedChildController(executable)
            self.addCleanup(controller.close)
            program = (
                "import json,os,sys; "
                "data=sys.stdin.read(); selected=os.read(int(sys.argv[1]),64).decode(); "
                "mask=os.umask(0o077); fd=os.open('created',os.O_WRONLY|os.O_CREAT,0o666); os.close(fd); "
                "excluded=not os.path.exists('/proc/self/fd/'+sys.argv[2]); "
                "print(json.dumps({'data':data,'selected':selected,'mask':mask,'cwd':os.getcwd(),"
                "'excluded':excluded})); "
                "print('diagnostic',file=sys.stderr)"
            )
            parent_mask = next(line for line in Path("/proc/self/status").read_text().splitlines()
                               if line.startswith("Umask:"))
            report = controller.spawn_owned("EXAMPLE-pipe-birth",
                [executable, "-I", "-S", "-c", program, str(read), str(excluded)], os.path.realpath(temporary))
            self.assertIn(parent_mask, Path("/proc/self/status").read_text().splitlines())
            self.assertEqual(report["outcome"], "registered", report)
            child = backend.births[0].child
            self.addCleanup(child.stdin.close)
            self.addCleanup(child.stdout.close)
            self.addCleanup(child.stderr.close)
            stdout, stderr = child.communicate("request\n", timeout=5)
            self.assertEqual(json.loads(stdout), {"data": "request\n", "selected": "selected descriptor",
                "mask": 0o077, "cwd": os.path.realpath(temporary), "excluded": True})
            self.assertEqual(stderr, "diagnostic\n")
            self.assertEqual((Path(temporary) / "created").stat().st_mode & 0o777, 0o600)
            ended = controller.terminate(report["receipt"], 1)
            self.assertTrue(ended["child_exit_confirmed"])
            self.assertTrue(ended["child_reaped"])
            self.assertEqual(child.returncode, 0)

    def test_pipe_communication_drains_outputs_while_delivering_input(self):
        executable = os.path.realpath(sys.executable)
        backend = factory._PipeBackend(())
        with mock.patch.object(owned, "_LinuxBackend", return_value=backend):
            controller = owned.LinuxOwnedChildController(executable)
        self.addCleanup(controller.close)
        program = (
            "import sys; sys.stdout.write('o'*196608); sys.stdout.flush(); "
            "sys.stderr.write('e'*196608); sys.stderr.flush(); "
            "print(len(sys.stdin.read()))"
        )
        report = controller.spawn_owned("EXAMPLE-backpressure",
            [executable, "-I", "-S", "-c", program], os.path.realpath(tempfile.gettempdir()))
        self.assertEqual(report["outcome"], "registered", report)
        self.addCleanup(controller.terminate, report["receipt"], 0.1, allow_kill=True)
        child = backend.births[0].child
        for stream in (child.stdin, child.stdout, child.stderr):
            self.addCleanup(stream.close)
        stdout, stderr = child.communicate("i" * 196608, timeout=5)
        self.assertEqual(stdout, "o" * 196608 + "196608\n")
        self.assertEqual(stderr, "e" * 196608)
        ended = controller.terminate(report["receipt"], 1)
        self.assertTrue(ended["child_reaped"])
        self.assertEqual(child.returncode, 0)


if __name__ == "__main__":
    unittest.main()
