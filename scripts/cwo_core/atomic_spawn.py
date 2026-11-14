"""Qualified native child creation with an atomic, singly owned Linux pidfd.

The libc interface owns the child-side work; no Python callback runs there.
Unsupported runtimes refuse without a late PID open or a PID signal fallback.
"""

from __future__ import annotations

from contextlib import ExitStack, contextmanager
import ctypes
import errno
import json
import os
import select
import selectors
import signal
import subprocess
import sys
import time
from typing import Callable


class _Sigset(ctypes.Structure):
    _fields_ = [("words", ctypes.c_ulong * 16)]


class _Attributes(ctypes.Structure):
    _fields_ = [
        ("flags", ctypes.c_short), ("pgrp", ctypes.c_int),
        ("sigdefault", _Sigset), ("sigmask", _Sigset),
        ("priority", ctypes.c_int), ("policy", ctypes.c_int),
        ("cgroup", ctypes.c_int), ("padding", ctypes.c_int * 15),
    ]


class _Actions(ctypes.Structure):
    _fields_ = [
        ("allocated", ctypes.c_int), ("used", ctypes.c_int),
        ("actions", ctypes.c_void_p), ("padding", ctypes.c_int * 16),
    ]


class AtomicChild:
    """Native-created child status; its unclaimed handle has exactly one owner."""

    __slots__ = ("pid", "returncode", "_descriptor")

    def __new__(cls):
        raise TypeError("Atomic child results are created by native spawn only.")

    def transfer_handle(self) -> int:
        descriptor = self._descriptor
        if descriptor is None:
            raise ValueError("The atomic child handle was already transferred or closed.")
        self._descriptor = None
        return descriptor

    def close_unclaimed(self) -> None:
        descriptor = self._descriptor
        self._descriptor = None
        if descriptor is not None:
            os.close(descriptor)


def _native_child(descriptor: int) -> AtomicChild:
    child = object.__new__(AtomicChild)
    child.pid = None
    child.returncode = None
    child._descriptor = descriptor
    return child


def _platform() -> None:
    if sys.platform != "linux" or ctypes.sizeof(ctypes.c_void_p) != 8 or os.uname().machine != "x86_64":
        raise OSError(errno.ENOSYS, "The native spawn ABI is not qualified.")


def _version(libc) -> None:
    function = libc.gnu_get_libc_version
    function.argtypes, function.restype = [], ctypes.c_char_p
    parts = function().decode("ascii").split(".")
    # 2.40 fixed the pidfd-spawn descriptor leak on exec failure. The layouts
    # above are the stable x86-64 glibc spawn ABI, not a generic C-library ABI.
    if int(parts[0]) != 2 or int(parts[1]) < 40:
        raise OSError(errno.ENOSYS, "Atomic spawn requires qualified glibc 2.40 or later.")


def _library():
    _platform()
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        _version(libc)
        declarations = (
            ("posix_spawn_file_actions_init", [ctypes.POINTER(_Actions)]),
            ("posix_spawn_file_actions_destroy", [ctypes.POINTER(_Actions)]),
            ("posix_spawnattr_init", [ctypes.POINTER(_Attributes)]),
            ("posix_spawnattr_destroy", [ctypes.POINTER(_Attributes)]),
            ("posix_spawn_file_actions_addchdir_np", [ctypes.POINTER(_Actions), ctypes.c_char_p]),
            ("posix_spawn_file_actions_addopen", [ctypes.POINTER(_Actions), ctypes.c_int,
                                                ctypes.c_char_p, ctypes.c_int, ctypes.c_uint]),
            ("posix_spawn_file_actions_addclosefrom_np", [ctypes.POINTER(_Actions), ctypes.c_int]),
            ("posix_spawn_file_actions_adddup2", [ctypes.POINTER(_Actions), ctypes.c_int, ctypes.c_int]),
            ("posix_spawnattr_setsigdefault", [ctypes.POINTER(_Attributes), ctypes.POINTER(_Sigset)]),
            ("posix_spawnattr_setflags", [ctypes.POINTER(_Attributes), ctypes.c_short]),
            ("sigemptyset", [ctypes.POINTER(_Sigset)]),
            ("sigaddset", [ctypes.POINTER(_Sigset), ctypes.c_int]),
            ("pidfd_spawn", [ctypes.POINTER(ctypes.c_int), ctypes.c_char_p,
                             ctypes.POINTER(_Actions), ctypes.POINTER(_Attributes),
                             ctypes.POINTER(ctypes.c_char_p), ctypes.POINTER(ctypes.c_char_p)]),
        )
        for name, arguments in declarations:
            function = getattr(libc, name)
            function.argtypes, function.restype = arguments, ctypes.c_int
        return libc
    except (AttributeError, TypeError, ValueError, UnicodeError) as exc:
        raise OSError(errno.ENOSYS, "The atomic spawn interface is unavailable.") from exc


def supported() -> tuple[bool, str]:
    try:
        _library()
    except OSError as exc:
        return False, str(exc)
    return True, "Atomic pidfd spawn is available."


def _check(result: int) -> None:
    if result:
        code = ctypes.get_errno() if result < 0 else result
        raise OSError(code or errno.EINVAL, "Native spawn operation failed.")


@contextmanager
def _initialized(libc, prefix: str, value):
    _check(getattr(libc, prefix + "_init")(ctypes.byref(value)))
    try:
        yield value
    except BaseException as primary:
        try:
            _check(getattr(libc, prefix + "_destroy")(ctypes.byref(value)))
        except BaseException as secondary:
            primary.add_note("Native spawn resource release: " + repr(secondary))
        raise
    else:
        _check(getattr(libc, prefix + "_destroy")(ctypes.byref(value)))


def _cstring(value: str) -> bytes:
    if type(value) is not str or "\0" in value:
        raise ValueError("Native spawn arguments must be plain text without NUL.")
    return os.fsencode(value)


def _file_actions(libc, actions: _Actions, workspace: str, stdio, inherit) -> None:
    pointer = ctypes.byref(actions)
    _check(libc.posix_spawn_file_actions_addchdir_np(pointer, _cstring(workspace)))
    if stdio is None:
        for descriptor, flags in ((0, os.O_RDONLY), (1, os.O_WRONLY), (2, os.O_WRONLY)):
            _check(libc.posix_spawn_file_actions_addopen(pointer, descriptor, b"/dev/null", flags, 0))
    else:
        for descriptor, source in enumerate(stdio):
            _check(libc.posix_spawn_file_actions_adddup2(pointer, source, descriptor))
    for descriptor in inherit:
        _check(libc.posix_spawn_file_actions_adddup2(pointer, descriptor, descriptor))
    if not inherit:
        _check(libc.posix_spawn_file_actions_addclosefrom_np(pointer, 3))


def _attributes(libc, attributes: _Attributes) -> None:
    defaults = _Sigset()
    _check(libc.sigemptyset(ctypes.byref(defaults)))
    for name in ("SIGPIPE", "SIGXFZ", "SIGXFSZ"):
        signum = getattr(signal, name, None)
        if signum is not None:
            _check(libc.sigaddset(ctypes.byref(defaults), signum))
    _check(libc.posix_spawnattr_setsigdefault(ctypes.byref(attributes), ctypes.byref(defaults)))
    _check(libc.posix_spawnattr_setflags(ctypes.byref(attributes), 0x04))


def _stdio_sources(stdio, stack):
    if stdio is None:
        return None
    import fcntl
    sources = []
    # Native actions run in order. Retain distinct sources above 0/1/2 so a
    # redirect cannot overwrite a later source when standard fds were closed.
    for descriptor in stdio:
        duplicate = _Descriptor(fcntl.fcntl(descriptor, fcntl.F_DUPFD_CLOEXEC, 3))
        stack.callback(duplicate.close)
        sources.append(duplicate.value)
    return tuple(sources)


def _handoff(descriptor: int, retain: Callable[[AtomicChild], None]) -> None:
    child = _native_child(descriptor)
    try:
        retain(child)
    except BaseException as primary:
        try:
            child.close_unclaimed()
        except BaseException as secondary:
            primary.add_note("Unclaimed atomic handle release: " + repr(secondary))
        raise
    else:
        child.close_unclaimed()


def _invoke(libc, executable: str, argv: tuple[str, ...], actions, attributes, retain) -> None:
    arguments = (ctypes.c_char_p * (len(argv) + 1))(*map(_cstring, argv), None)
    environment = (ctypes.c_char_p * 1)(None)
    descriptor = ctypes.c_int(-1)
    result, primary = None, None
    try:
        result = libc.pidfd_spawn(ctypes.byref(descriptor), _cstring(executable),
            ctypes.byref(actions), ctypes.byref(attributes), arguments, environment)
    except BaseException as exc:
        primary = exc
    try:
        if descriptor.value >= 0 and (result == 0 or primary is not None):
            _handoff(descriptor.value, retain)
    except BaseException as secondary:
        if primary is None:
            primary = secondary
        else:
            primary.add_note("Atomic birth retention: " + repr(secondary))
    if primary is not None:
        raise primary
    _check(result)


def spawn(executable: str, argv: tuple[str, ...], workspace: str,
          retain: Callable[[AtomicChild], None], *, stdio=None, inherit=()) -> None:
    """Create once and transfer the native result even on a C-return interruption.

    ``retain`` runs in the parent and must transfer the handle into its original
    birth registry. A result it does not claim is closed exactly once here.
    """
    libc = _library()
    with _resources() as descriptors, \
            _initialized(libc, "posix_spawn_file_actions", _Actions()) as actions, \
            _initialized(libc, "posix_spawnattr", _Attributes()) as attributes:
        _file_actions(libc, actions, workspace, _stdio_sources(stdio, descriptors), inherit)
        _attributes(libc, attributes)
        _invoke(libc, executable, argv, actions, attributes, retain)


# A fresh isolated interpreter performs only fixed child-side descriptor and
# umask actions before replacing itself. It retains the atomically born PID.
# -B prevents bytecode writes before the child-only umask is installed.
_BOOTSTRAP = r"""
import os,sys
error=int(sys.argv[1])
os.set_inheritable(error,False)
try:
    os.umask(int(sys.argv[2]))
    import json
    request=json.loads(sys.argv[3])
    keep=set(request['pass_fds'])|{0,1,2,error}
    for entry in os.listdir('/proc/self/fd'):
        descriptor=int(entry)
        if descriptor not in keep:
            try: os.close(descriptor)
            except OSError: pass
    for descriptor in request['pass_fds']:
        os.set_inheritable(descriptor,True)
    os.write(error,b'R\n')
    os.execve(request['executable'],request['argv'],{})
except BaseException as failure:
    try: os.write(error,('E%d\n'%(getattr(failure,'errno',None) or 22)).encode('ascii'))
    except OSError: pass
    os._exit(127)
"""


@contextmanager
def _resources():
    stack = ExitStack()
    try:
        yield stack
    except BaseException as primary:
        try:
            stack.close()
        except BaseException as secondary:
            primary.add_note("Atomic pipe resource release: " + repr(secondary))
        raise
    else:
        stack.close()


class _Descriptor:
    def __init__(self, descriptor: int):
        self.value = descriptor

    def close(self) -> None:
        descriptor, self.value = self.value, None
        if descriptor is not None:
            os.close(descriptor)

    def stream(self, stack, mode: str):
        stream = os.fdopen(self.value, mode, encoding="utf-8", buffering=1 if mode == "w" else -1)
        self.value = None
        stack.callback(stream.close)
        return stream


def _pipe(stack):
    read, write = map(_Descriptor, os.pipe())
    stack.callback(read.close)
    stack.callback(write.close)
    return read, write


def _exec_result(data: bytes) -> None:
    if data == b"R\n":
        return
    message = data.removeprefix(b"R\n")
    if message.startswith(b"E") and message.endswith(b"\n") and message[1:-1].isdigit():
        raise OSError(int(message[1:-1]), "Atomic child target exec failed.")
    raise OSError(errno.EIO, "The atomic child exec handshake is incomplete.")


def _await_exec(descriptor: int, timeout: float = 5) -> None:
    os.set_blocking(descriptor, False)
    poller = select.poll()
    poller.register(descriptor, select.POLLIN | select.POLLHUP)
    deadline, data = time.monotonic() + timeout, bytearray()
    while time.monotonic() < deadline:
        if not poller.poll(max(1, int((deadline - time.monotonic()) * 1000))):
            continue
        chunk = os.read(descriptor, 65 - len(data))
        if not chunk:
            return _exec_result(bytes(data))
        data.extend(chunk)
        if len(data) > 64:
            raise OSError(errno.EIO, "The atomic child exec handshake exceeds its bound.")
    raise OSError(errno.ETIMEDOUT, "The atomic child exec handshake expired.")


def spawn_piped(executable: str, argv: tuple[str, ...], workspace: str, pass_fds: tuple[int, ...],
                retain: Callable[[AtomicChild, tuple], None]) -> None:
    """Retain native birth through a fixed child-only umask/pass-fd bootstrap."""
    with _resources() as descriptors, _resources() as parent_streams:
        stdin_read, stdin_write = _pipe(descriptors)
        stdout_read, stdout_write = _pipe(descriptors)
        stderr_read, stderr_write = _pipe(descriptors)
        error_read, error_write = _pipe(descriptors)
        streams = (stdin_write.stream(parent_streams, "w"), stdout_read.stream(parent_streams, "r"),
                   stderr_read.stream(parent_streams, "r"))
        request = json.dumps({"executable": executable, "argv": argv, "pass_fds": pass_fds})
        command = ("/proc/self/exe", "-I", "-S", "-B", "-c", _BOOTSTRAP,
                   str(error_write.value), str(0o077), request)
        with _resources() as child_ends:
            for descriptor in (stdin_read, stdout_write, stderr_write, error_write):
                child_ends.callback(descriptor.close)
            spawn("/proc/self/exe", command, workspace, lambda child: retain(child, streams),
                  stdio=(stdin_read.value, stdout_write.value, stderr_write.value),
                  inherit=(*pass_fds, error_write.value))
        _await_exec(error_read.value)
        parent_streams.pop_all()


def _remaining(child, deadline: float, timeout: float) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise subprocess.TimeoutExpired(child.args, timeout)
    return remaining


def _start_conversation(selector, child, pending) -> None:
    for name in ("stdin", "stdout", "stderr"):
        stream = getattr(child, name)
        if name == "stdin" and not pending:
            stream.close()
        else:
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_WRITE if name == "stdin" else selectors.EVENT_READ, name)


def _pipe_event(selector, key, pending, outputs):
    descriptor = key.fileobj.fileno()
    try:
        if key.data == "stdin":
            pending = pending[os.write(descriptor, pending):]
            data = pending
        else:
            data = os.read(descriptor, 65536)
            outputs[key.data].extend(data)
    except BlockingIOError:
        return pending
    except BrokenPipeError:
        data = b""
    if not data:
        selector.unregister(key.fileobj)
        key.fileobj.close()
    return pending


def communicate(child, data: str, timeout: float) -> tuple[str, str]:
    """Bound simultaneous pipe delivery/drain, then wait through child custody."""
    pending = memoryview(data.encode("utf-8"))
    deadline = time.monotonic() + timeout
    outputs = {"stdout": bytearray(), "stderr": bytearray()}
    with selectors.DefaultSelector() as selector:
        _start_conversation(selector, child, pending)
        while selector.get_map():
            events = selector.select(_remaining(child, deadline, timeout))
            for key, _mask in events:
                pending = _pipe_event(selector, key, pending, outputs)
    child.wait(timeout=_remaining(child, deadline, timeout))
    return bytes(outputs["stdout"]).decode("utf-8"), bytes(outputs["stderr"]).decode("utf-8")
