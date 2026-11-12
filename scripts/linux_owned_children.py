"""Experimental ownership for bounded Linux children created by this controller.

This cooperative library supplies no production authority or tree containment.
"""

from __future__ import annotations

import ctypes
import errno
import os
import re
import select
import signal
import stat
import subprocess
import sys
import threading
from dataclasses import dataclass, field
from typing import Any, Callable

from cwo_core.ownership_producer import (
    MAX_MIN_AGE_SECONDS,
    PID_LIMIT,
    ExpectedSpawn,
    _Refusal,
    _RetainedOwnershipProducer,
    _duration,
    _integer,
    _validate_spec,
)
from cwo_core.process_identity import (
    MAX_GRACE_SECONDS,
    ProcAdapter,
    TrustedRegistration,
    canonical_workspace,
    observe_identity,
)

MAX_CHILDREN = 64
MAX_ARGUMENTS = 64
MAX_TEXT_BYTES = 4096
MAX_ARGV_BYTES = 32768


@dataclass(frozen=True, eq=False)
class OwnedChildReceipt:
    """An object receipt; its fields do not grant process authority."""

    registration: TrustedRegistration


@dataclass
class _Birth:
    child: Any = None
    pid: int | None = None
    descriptor: int | None = None
    claimed: bool = False
    closed: bool = False
    releasing: bool = False
    release_pending: bool = False
    active_operation: str | None = None
    active_thread: int | None = None
    status_waiting: bool = False
    signal_count: int = 0
    release_errors: list[str] = field(default_factory=list)
    registered: bool = False
    finished: bool = False
    exit_confirmed: bool = False
    reaped: bool = False
    reaping: bool = False
    reap_authorized: bool = False
    receipt: OwnedChildReceipt | None = None


def _report(outcome: str, signals: list[str] | None = None, **detail: Any) -> dict[str, Any]:
    if "session" in detail:
        detail["receipt"] = detail.pop("session")
    return {
        "outcome": outcome, "signals": list(signals or []), **detail,
        "offline_only": False, "experimental": True, "cooperative": True,
        "production_authority": False, "default_cleanup_consumer": "none",
        "registration_persistence": "memory-only",
    }


def _note(primary: BaseException, detail: object) -> None:
    try:
        primary.add_note(f"Ownership cleanup: {detail}")
    except BaseException:
        pass


def _annotate(primary: BaseException, report: dict[str, Any]) -> None:
    try:
        primary.ownership_report = report
    except BaseException:
        pass


def _details(error: BaseException) -> list[str]:
    try:
        message = f"{type(error).__name__}: {error}"
    except BaseException:
        message = "Ownership cleanup failed; diagnostic text is unavailable."
    try:
        notes = [note for note in getattr(error, "__notes__", ()) if type(note) is str]
    except BaseException:
        notes = ["Ownership cleanup notes are unavailable."]
    return [message, *notes]


def _cleanup(actions: list[Callable[[], Any]]) -> tuple[list[str], BaseException | None]:
    errors = []
    interruption = None
    for action in actions:
        try:
            action()
        except Exception as exc:
            errors.extend(_details(exc))
        except BaseException as exc:
            if interruption is None:
                interruption = exc
            else:
                _note(interruption, exc)
    return errors, interruption


def _text(value: object, maximum: int = MAX_TEXT_BYTES) -> bool:
    if type(value) is not str or "\0" in value:
        return False
    try:
        return len(value.encode("utf-8")) <= maximum
    except UnicodeError:
        return False


def _path(value: object) -> bool:
    return _text(value) and canonical_workspace(value) and not value.startswith("//")


def _freeze(session_id: object, argv: object, workspace: object, executable: str) -> tuple:
    if type(session_id) is not str or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", session_id) is None:
        raise ValueError("The session ID must contain 1 to 128 plain ASCII identifier characters.")
    if type(argv) not in (list, tuple):
        raise ValueError("Arguments must be an exact plain list or tuple.")
    arguments = tuple(argv)
    if not 1 <= len(arguments) <= MAX_ARGUMENTS or not all(_text(arg) for arg in arguments):
        raise ValueError("Arguments must contain 1 to 64 bounded plain text values.")
    if sum(len(arg.encode("utf-8")) + 1 for arg in arguments) > MAX_ARGV_BYTES:
        raise ValueError("The complete argument list exceeds its byte limit.")
    if arguments[0] != executable or not _path(workspace):
        raise ValueError("Arguments must use the selected executable and an exact canonical workspace.")
    return session_id, arguments, workspace


class _Sigaction(ctypes.Structure):
    """Read only the qualified Linux C library signal layout."""

    _fields_ = [
        ("handler", ctypes.c_void_p),
        ("mask", ctypes.c_ulong * 16),
        ("flags", ctypes.c_int),
        ("restorer", ctypes.c_void_p),
    ]


def _sigchld_profile() -> tuple[bool, str]:
    """Refuse automatic status collection before a child can be bound."""
    if signal.getsignal(signal.SIGCHLD) != signal.SIG_DFL:
        return False, "The child signal disposition must retain child exit status."
    try:
        if (
            os.uname().machine != "x86_64"
            or ctypes.sizeof(ctypes.c_void_p) != 8
            or not os.confstr("CS_GNU_LIBC_VERSION").startswith("glibc ")
        ):
            return False, "The native child signal layout is not qualified."
        current = _Sigaction()
        query = ctypes.CDLL(None, use_errno=True).sigaction
        query.argtypes = [ctypes.c_int, ctypes.POINTER(_Sigaction), ctypes.POINTER(_Sigaction)]
        query.restype = ctypes.c_int
        if query(signal.SIGCHLD, None, ctypes.byref(current)) != 0:
            return False, f"The native child signal profile is unavailable: errno {ctypes.get_errno()}."
    except (AttributeError, OSError, TypeError, ValueError) as exc:
        return False, f"The native child signal profile is unavailable: {exc}"
    if current.handler is not None or current.flags & 2:
        return False, "The child profile has a handler or automatic status collection."
    return True, "The default child signal profile retains exit status."


class _HandleChild(subprocess.Popen):
    """Leave status collection to the retained handle, including on release."""

    def __del__(self) -> None:
        """Release Python state without a later PID wait or signal."""
        pass


class _LinuxBackend(ProcAdapter):
    """Create children directly and retain each newly opened birth handle."""

    def __init__(self) -> None:
        super().__init__()
        self._lifecycle_lock = threading.RLock()
        self.controller_pid = os.getpid()
        self._owner = None
        self._owned: dict[int, _Birth] = {}
        self.births: list[_Birth] = []
        self._unavailable: str | None = None

    def claim_writer(self, writer: object) -> bool:
        if self._owner is not None:
            return False
        self._owner = writer
        return True

    def supported(self) -> tuple[bool, str]:
        if self._unavailable is not None:
            return False, self._unavailable
        required = ((os, "pidfd_open"), (signal, "pidfd_send_signal"), (select, "poll"), (os, "waitid"))
        if sys.platform != "linux" or not all(callable(getattr(module, name, None)) for module, name in required):
            return False, "Required Linux child handle methods are unavailable."
        if not all(hasattr(os, name) for name in ("P_PIDFD", "WEXITED", "WNOHANG", "WNOWAIT", "CLD_EXITED", "CLD_KILLED", "CLD_DUMPED")):
            return False, "Required child handle wait constants are unavailable."
        if os.getpid() != self.controller_pid:
            return False, "The controller cannot be used after a process fork."
        try:
            if int(self.readlink("self")) != self.controller_pid:
                return False, "The proc view does not match the controller PID namespace."
        except (OSError, ValueError) as exc:
            return False, f"The controller proc view is unavailable: {exc}"
        return _sigchld_profile()

    def _require_lifecycle(self) -> None:
        supported, reason = self.supported()
        if supported is not True:
            self._unavailable = reason
            raise _Refusal("unavailable", reason)

    def _operation(self, label: str, action: Callable, *arguments: Any) -> Any:
        try:
            return action(*arguments)
        except OSError as exc:
            if exc.errno in (errno.ENOSYS, errno.EPERM, errno.EACCES, errno.EINVAL):
                self._unavailable = f"{label} is unavailable: {_details(exc)[0]}"
            raise

    def _mapped_birth(self, birth: _Birth) -> bool:
        return (
            self._owned.get(birth.descriptor) is birth
            and any(item is birth for item in self.births)
        )

    def _retained(self, birth: _Birth) -> bool:
        return (
            birth.descriptor is not None and not birth.closed
            and self._mapped_birth(birth)
        )

    def _reap_allowed(self, birth: _Birth) -> bool:
        return (
            self._retained(birth) and birth.reap_authorized
            and not birth.reaped and self._unavailable is None
        )

    def eligible(self, birth: _Birth) -> bool:
        return self._reap_allowed(birth) and not birth.releasing

    def _require_birth(self, descriptor: int) -> _Birth:
        birth = self._owned.get(descriptor)
        if birth is None or not self.eligible(birth):
            raise _Refusal("ownership-lost", "The original child handle no longer grants lifecycle authority.")
        return birth

    def _begin_operation(self, birth: _Birth, kind: str, *, releasing: bool = False) -> None:
        if not self._reap_allowed(birth) or (birth.releasing and not releasing):
            raise _Refusal("ownership-lost", "The original child handle no longer grants lifecycle authority.")
        if birth.active_operation is not None:
            raise _Refusal("producer-busy", "Another operation already retains this child handle.")
        birth.active_operation = kind
        birth.active_thread = threading.get_ident()
        birth.reaping = kind == "reap"

    def _start_operation(self, descriptor: int, kind: str) -> _Birth:
        with self._lifecycle_lock:
            birth = self._require_birth(descriptor)
            self._begin_operation(birth, kind)
            return birth

    def _check_operation(self, birth: _Birth, kind: str) -> None:
        with self._lifecycle_lock:
            if (
                not self._reap_allowed(birth) or birth.active_operation != kind
                or birth.active_thread != threading.get_ident()
            ):
                raise _Refusal("ownership-lost", "The original active child handle no longer grants lifecycle authority.")

    def send_signal(self, descriptor: int, signum: int) -> None:
        self._signal_operation(self._start_operation(descriptor, "signal"), signum)

    def _signal_operation(self, birth: _Birth, signum: int) -> None:
        primary = None
        try:
            self._require_lifecycle()
            self._check_operation(birth, "signal")
            self._operation("Child handle signalling", super().send_signal, birth.descriptor, signum)
            with self._lifecycle_lock:
                birth.signal_count += 1
        except BaseException as exc:
            primary = exc
            raise
        finally:
            self._finish_operation(birth, primary)

    def wait_exit(self, descriptor: int, timeout_seconds: float) -> bool:
        return self._exit_operation(self._start_operation(descriptor, "wait"), timeout_seconds)

    def _exit_operation(self, birth: _Birth, timeout_seconds: float) -> bool:
        primary = None
        try:
            self._require_lifecycle()
            self._check_operation(birth, "wait")
            exited = self._operation("Child handle exit wait", super().wait_exit, birth.descriptor, timeout_seconds)
            if exited is True:
                with self._lifecycle_lock:
                    birth.exit_confirmed = True
            return exited
        except BaseException as exc:
            primary = exc
            raise
        finally:
            self._finish_operation(birth, primary)

    def controller_uid(self) -> int:
        return os.getuid()

    def canonical(self, path: str, directory: bool) -> str:
        if os.path.realpath(path, strict=True) != path:
            raise ValueError("The selected path must already be absolute and canonical.")
        mode = os.stat(path).st_mode
        expected = stat.S_ISDIR if directory else stat.S_ISREG
        if not expected(mode):
            raise ValueError("The selected path has the wrong file type.")
        if not directory and not os.access(path, os.X_OK):
            raise PermissionError("The selected executable is not executable.")
        return path

    def _popen(self, argv: tuple[str, ...], executable: str, workspace: str) -> subprocess.Popen:
        return _HandleChild(
            argv, executable=executable, cwd=workspace, env={},
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            close_fds=True, shell=False,
        )

    def _open_pidfd(self, pid: int) -> int:
        return self._operation("Child handle opening", self.pidfd_open, pid)

    def spawn(self, birth: _Birth, argv: tuple[str, ...], executable: str, workspace: str) -> tuple[int, int]:
        self._require_lifecycle()
        birth.child = self._popen(argv, executable, workspace)
        self.births.append(birth)
        pid = birth.child.pid
        if not _integer(pid, 1, PID_LIMIT):
            raise _Refusal("invalid-spawn", "The created child has no bounded plain PID.")
        birth.pid = pid
        self._require_lifecycle()
        descriptor = self._open_pidfd(pid)
        if not _integer(descriptor, 0, 2**31 - 1) or descriptor in self._owned:
            raise _Refusal("invalid-spawn", "The created child has no distinct birth handle.")
        birth.descriptor = descriptor
        self._owned[descriptor] = birth
        birth.reap_authorized = True
        return pid, descriptor

    def claim_spawn(self, pid: int, descriptor: int, writer: object) -> bool:
        birth = self._owned.get(descriptor)
        if writer is not self._owner or birth is None or birth.pid != pid:
            return False
        if birth.claimed or birth.closed:
            return False
        birth.claimed = True
        return True

    def _close_fd(self, descriptor: int) -> None:
        super().close(descriptor)

    def _release_birth(self, birth: _Birth) -> None:
        with self._lifecycle_lock:
            if birth.active_operation is not None:
                birth.releasing = True
                birth.release_pending = True
                return
            descriptor = birth.descriptor
            retained = self._retained(birth)
            birth.closed = True
            birth.reap_authorized = False
            if retained:
                self._owned.pop(descriptor)
        if retained:
            self._close_fd(descriptor)

    def close(self, descriptor: int) -> None:
        with self._lifecycle_lock:
            birth = self._owned.get(descriptor)
        self._close_owned(birth)

    def _close_owned(self, birth: _Birth | None) -> None:
        with self._lifecycle_lock:
            if birth is None or not self._retained(birth) or birth.releasing:
                return
            birth.releasing = True
            if birth.active_operation is not None:
                birth.release_pending = True
                return
        self._release_owned(birth)

    def _release_owned(self, birth: _Birth, *, reap: bool = True) -> None:
        actions = []
        if reap:
            actions.append(lambda: self._reap(birth, releasing=True))
        actions.append(lambda: self._release_birth(birth))
        try:
            if not reap:
                self._release_birth(birth)
                return
            errors, interruption = _cleanup(actions)
            if interruption is not None:
                for error in errors:
                    _note(interruption, error)
                raise interruption
            if errors:
                raise RuntimeError("; ".join(errors))
        finally:
            with self._lifecycle_lock:
                birth.releasing = False

    def _wait_child(self, birth: _Birth, options: int) -> Any:
        self._begin_status_wait(birth)
        try:
            self._require_lifecycle()
            self._check_operation(birth, "reap")
            return self._status_result(birth, options)
        finally:
            with self._lifecycle_lock:
                birth.status_waiting = False

    def _begin_status_wait(self, birth: _Birth) -> None:
        with self._lifecycle_lock:
            self._check_operation(birth, "reap")
            if birth.status_waiting:
                raise _Refusal("producer-busy", "A child status callback is already active.")
            birth.status_waiting = True

    def _status_result(self, birth: _Birth, options: int) -> Any:
        try:
            return self._operation(
                "Child handle status wait", os.waitid, os.P_PIDFD, birth.descriptor, options,
            )
        except OSError as exc:
            if exc.errno == errno.ECHILD:
                with self._lifecycle_lock:
                    birth.reap_authorized = False
            raise

    @staticmethod
    def _exit_code(birth: _Birth, result: Any) -> int:
        if result.si_pid != birth.pid or result.si_code not in (os.CLD_EXITED, os.CLD_KILLED, os.CLD_DUMPED):
            raise ValueError("The retained child exit observation is inconsistent.")
        if not _integer(result.si_status, 0, 255):
            raise ValueError("The retained child exit status is invalid.")
        return result.si_status if result.si_code == os.CLD_EXITED else -result.si_status

    def _reap_once(self, birth: _Birth) -> None:
        result = self._wait_child(birth, os.WEXITED | os.WNOHANG | os.WNOWAIT)
        if result is None:
            return
        self._exit_code(birth, result)
        birth.exit_confirmed = True
        result = self._wait_child(birth, os.WEXITED | os.WNOHANG)
        birth.reap_authorized = False
        if result is None:
            raise ValueError("The retained child exit status was no longer available for collection.")
        birth.child.returncode = self._exit_code(birth, result)
        birth.reaped = True

    def _finish_operation(self, birth: _Birth, primary: BaseException | None) -> None:
        with self._lifecycle_lock:
            kind = birth.active_operation
            birth.active_operation = None
            birth.active_thread = None
            birth.reaping = False
            if not birth.release_pending:
                return
            birth.release_pending = False
        try:
            self._release_owned(birth, reap=kind != "reap")
        except BaseException as exc:
            details = _details(exc)
            with self._lifecycle_lock:
                birth.release_errors.extend(details)
            if primary is not None:
                if kind == "reap" and isinstance(primary, Exception) and not isinstance(exc, Exception):
                    _note(exc, primary)
                    raise
                _note(primary, exc)
                return
            if kind != "reap" and isinstance(exc, Exception):
                return
            raise

    def reap(self, birth: _Birth) -> None:
        self._reap(birth)

    def _reap(self, birth: _Birth, *, releasing: bool = False) -> None:
        with self._lifecycle_lock:
            if not self._reap_allowed(birth) or birth.child is None or birth.active_operation is not None:
                return
            if birth.releasing and not releasing:
                return
            self._begin_operation(birth, "reap", releasing=releasing)
        primary = None
        try:
            self._reap_once(birth)
        except BaseException as exc:
            primary = exc
            raise
        finally:
            self._finish_operation(birth, primary)

    def _close_unusable(self, birth: _Birth) -> None:
        if self._retained(birth) and (not birth.registered or not self.eligible(birth)):
            self._close_owned(birth)

    def cleanup(self, births: list[_Birth]) -> tuple[list[str], BaseException | None]:
        actions = []
        for birth in births:
            birth.finished = True
            actions.append(lambda item=birth: self.reap(item))
            actions.append(lambda item=birth: self._close_unusable(item))
        return _cleanup(actions)


    def take_release_errors(self, births: list[_Birth]) -> list[str]:
        """Snapshot retained birth diagnostics without consuming another report's evidence."""
        errors = []
        with self._lifecycle_lock:
            for birth in births:
                errors.extend(birth.release_errors)
        return errors


class _LinuxEngine(_RetainedOwnershipProducer):
    _session_type = OwnedChildReceipt
    _report = staticmethod(_report)
    _mode = "experimental"
    _kind = "observed"

    def __init__(self, backend: _LinuxBackend, executable: str) -> None:
        self._writer = object()
        if backend.claim_writer(self._writer) is not True:
            raise ValueError("The controller backend already has an ownership writer.")
        self._initialize(backend, backend.controller_pid, "linux-owned-child-experiment")
        self._executable = executable

    def _enter(self, state: str) -> None:
        with self._adapter._lifecycle_lock:
            super()._enter(state)

    def _leave(self) -> None:
        with self._adapter._lifecycle_lock:
            super()._leave()

    def _consume(
        self, session: OwnedChildReceipt, grace: float, minimum: float, kill: bool, signals: list[str],
    ) -> dict[str, Any]:
        self._enter("terminating")
        try:
            with self._adapter._lifecycle_lock:
                entry = self._lookup(session)
                self._live.pop(id(session))
                birth = next((item for item in self._adapter.births if item.receipt is session), None)
                if birth is None or self._adapter._owned.get(entry.descriptor) is not birth:
                    raise _Refusal("ownership-lost", "The receipt no longer retains its original child handle.")
            return self._using(
                entry.descriptor, lambda: self._act(entry, grace, minimum, kill, signals),
                signals, birth=birth,
            )
        finally:
            self._leave()

    def _signal(self, descriptor: int, signum: int, label: str, signals: list[str]) -> None:
        with self._adapter._lifecycle_lock:
            birth = self._adapter._owned.get(descriptor)
            count = birth.signal_count if birth is not None else 0
        try:
            super()._signal(descriptor, signum, label, signals)
        finally:
            if birth is not None and birth.signal_count != count and label not in signals:
                signals.append(label)

    def _wait(self, descriptor: int, grace: float, label: str) -> bool:
        self._ensure_open()
        try:
            exited = self._adapter.wait_exit(descriptor, grace)
            if type(exited) is not bool:
                raise ValueError("The retained child exit observation must be Boolean.")
            if exited:
                return True
            self._ensure_open()
            return False
        except (OSError, ValueError, OverflowError) as exc:
            raise _Refusal("wait-failed", str(exc), stage=label) from exc

    def spawn_owned(self, request: tuple, birth: _Birth) -> dict[str, Any]:
        return self._capture(lambda: self._reserve(request, birth), [])

    def _reserve(self, request: tuple, birth: _Birth) -> dict[str, Any]:
        session_id, argv, workspace = request
        self._ensure_open()
        self._check_session(session_id)
        self._enter("registering")
        self._pending_session = session_id
        try:
            if len(self._seen_sessions) >= MAX_CHILDREN:
                raise _Refusal("capacity-refused", "The controller epoch has reached its child attempt limit.")
            self._capability()
            executable = self._call(self._adapter.canonical, self._executable, False)
            workspace = self._call(self._adapter.canonical, workspace, True)
            context = self._context()
            expected = ExpectedSpawn(session_id, workspace, executable, context.uid, context.boot_id, context.pid_namespace)
            _validate_spec(expected)
            return self._spawn(expected, lambda spec: self._adapter.spawn(birth, argv, executable, workspace))
        finally:
            self._leave()

    def _context(self):
        observed = observe_identity(self._controller_pid, self._reads)
        if observed.uid != self._call(self._adapter.controller_uid):
            raise _Refusal("identity-mismatch", "The controller UID observation is inconsistent.")
        if observed.pid_namespace != self._call(self._adapter.own_pid_namespace):
            raise _Refusal("identity-mismatch", "The controller namespace observation is inconsistent.")
        return observed

    def _capability(self) -> None:
        supported, reason = self._call(self._adapter.supported)
        if supported is not True:
            raise _Refusal("unavailable", reason)

    def _adopt(self, pid: int, descriptor: int) -> None:
        if not _integer(pid, 1, PID_LIMIT) or not _integer(descriptor, 0, 2**31 - 1):
            raise _Refusal("invalid-spawn", "The controller birth result is malformed.")
        if self._adapter.claim_spawn(pid, descriptor, self._writer) is not True:
            raise _Refusal("invalid-spawn", "No unclaimed controller birth matches this handle.")

    def _observe(self, pid: int, descriptor: int):
        identity = super()._observe(pid, descriptor)
        self._bound(pid, descriptor)
        stat_value = self._stat(pid)
        self._bound(pid, descriptor)
        if stat_value.ppid != self._controller_pid or stat_value.start_ticks != identity.start_ticks:
            raise _Refusal("identity-mismatch", "The target is not the observed direct child of this controller.")
        return identity

    def _verified_birth(self, entry) -> None:
        birth = self._adapter._require_birth(entry.descriptor)
        if birth.receipt is not None and birth.receipt is not entry.session:
            raise _Refusal("ownership-lost", "The receipt does not retain this exact child birth.")

    def _verified(self, entry):
        self._verified_birth(entry)
        context = self._context()
        wanted = entry.expected
        if (context.boot_id, context.pid_namespace, context.uid) != (wanted.boot_id, wanted.pid_namespace, wanted.uid):
            raise _Refusal("identity-mismatch", "The independent controller context changed.")
        return super()._verified(entry)

    def _register(self, pid: int, descriptor: int, expected: ExpectedSpawn) -> dict[str, Any]:
        with self._adapter._lifecycle_lock:
            self._ensure_open()
            birth = self._adapter._require_birth(descriptor)
        report = super()._register(pid, descriptor, expected)
        return self._commit_birth(birth, report)

    def _commit_birth(self, birth: _Birth, report: dict[str, Any]) -> dict[str, Any]:
        with self._adapter._lifecycle_lock:
            try:
                self._ensure_open()
                if self._adapter._require_birth(birth.descriptor) is not birth:
                    raise _Refusal("ownership-lost", "Registration lost its exact retained child birth.")
            except BaseException:
                self._live.pop(id(report["receipt"]), None)
                raise
            birth.registered = True
            birth.receipt = report["receipt"]
            return report

    def _using_birth(self, descriptor: int, birth: _Birth | None) -> _Birth | None:
        return self._adapter._owned.get(descriptor) if birth is None else birth

    def _using(self, descriptor: int, action: Callable, signals: list[str], *, birth: _Birth | None = None) -> dict[str, Any]:
        birth = self._using_birth(descriptor, birth)
        try:
            report = self._capture(action, signals)
        except BaseException as primary:
            errors, interruption = _cleanup([lambda: self._adapter._close_owned(birth)])
            for error in errors:
                _note(primary, error)
            if interruption is not None:
                _note(primary, interruption)
            _annotate(primary, self._report("interrupted", signals))
            raise
        if report["outcome"] != "registered":
            errors, interruption = _cleanup([lambda: self._adapter._close_owned(birth)])
            if errors:
                report["close_error"] = errors[0]
            if interruption is not None:
                _annotate(interruption, report)
                raise interruption
        return report

    def close(self) -> dict[str, Any]:
        with self._adapter._lifecycle_lock:
            self._state = "closed"
            self._live.clear()
            births = list(self._adapter.births)
        errors, interruption = _cleanup([lambda item=birth: self._adapter._close_owned(item) for birth in births])
        report = self._report("closed", close_errors=errors)
        if interruption is not None:
            _annotate(interruption, report)
            for error in errors:
                _note(interruption, error)
            raise interruption
        return report


class LinuxOwnedChildController:
    """Own bounded direct children and issue one-use in-memory receipts."""

    def __init__(self, executable: str) -> None:
        if not _path(executable):
            raise ValueError("Select one absolute canonical executable path as plain bounded text.")
        self._executable = executable
        self._lock = threading.RLock()
        self._busy = False
        self._backend = _LinuxBackend()
        self._engine = _LinuxEngine(self._backend, executable)

    def _facts(self, birth: _Birth) -> dict[str, Any]:
        return {
            "child_creation": "popen-returned" if birth.child is not None else "not-observed",
            "child_pid": birth.pid,
            "registration_committed": birth.registered,
            "child_exit_confirmed": birth.exit_confirmed,
            "child_reaped": birth.reaped,
            "receipt_available": (
                birth.receipt is not None and id(birth.receipt) in self._engine._live
                and self._backend.eligible(birth)
            ),
        }

    def _retire_unusable(self, report: dict[str, Any]) -> None:
        for birth in self._backend.births:
            if birth.receipt is not None and not self._backend.eligible(birth):
                self._engine._live.pop(id(birth.receipt), None)
        receipt = report.get("receipt")
        if receipt is not None and id(receipt) not in self._engine._live:
            report.pop("receipt")
            if report["outcome"] == "registered":
                report["outcome"] = "unavailable" if self._backend._unavailable else "ownership-lost"
                report["reason"] = self._backend._unavailable or "The retained child lifecycle is no longer eligible."

    def _complete(self, action: Callable, births: list[_Birth]) -> dict[str, Any]:
        report = None
        primary = None
        try:
            report = action()
        except BaseException as exc:
            primary = exc
        errors, interruption = self._backend.cleanup(births)
        retained_errors = self._backend.take_release_errors(births)
        errors.extend(retained_errors)
        if report is None:
            report = getattr(primary, "ownership_report", _report("interrupted"))
        with self._backend._lifecycle_lock:
            self._retire_unusable(report)
            if len(births) == 1:
                report.update(self._facts(births[0]))
            elif births:
                report["children"] = [self._facts(birth) for birth in births]
        if errors:
            report["cleanup_errors"] = errors
        if retained_errors:
            report["retained_cleanup_errors"] = retained_errors
        if primary is None:
            primary = interruption
        elif interruption is not None:
            _note(primary, interruption)
        if primary is not None:
            for error in errors:
                _note(primary, error)
            _annotate(primary, report)
            raise primary
        return report

    def _run(self, action: Callable, births: list[_Birth]) -> dict[str, Any]:
        with self._lock:
            if self._busy:
                outcome = "producer-closed" if self._engine._state == "closed" else "producer-busy"
                return _report(outcome, reason="A controller operation is already active or closed.")
            self._busy = True
        try:
            return self._complete(action, births)
        finally:
            with self._lock:
                self._busy = False

    def spawn_owned(self, session_id: str, argv: list[str] | tuple[str, ...], workspace: str) -> dict[str, Any]:
        """Freeze the request, create a child directly and bind its birth handle."""
        try:
            request = _freeze(session_id, argv, workspace, self._executable)
        except ValueError as exc:
            return _report("invalid-request", reason=str(exc))
        birth = _Birth()
        return self._run(lambda: self._engine.spawn_owned(request, birth), [birth])

    def terminate(self, receipt: OwnedChildReceipt, grace_seconds: float, min_age_seconds: float = 0, allow_kill: bool = False) -> dict[str, Any]:
        """Consume one receipt and use only its original handle for signals."""
        limits = ((grace_seconds, MAX_GRACE_SECONDS), (min_age_seconds, MAX_MIN_AGE_SECONDS))
        if any(type(value) not in (int, float) or not _duration(value, maximum) for value, maximum in limits):
            return _report("invalid-request", reason="Durations must be plain finite numbers within their limits.")
        if type(allow_kill) is not bool:
            return _report("invalid-request", reason="allow_kill must be Boolean.")
        with self._lock:
            births = [birth for birth in self._backend.births if birth.receipt is receipt]
        return self._run(lambda: self._engine.terminate(
            receipt, grace_seconds=grace_seconds, min_age_seconds=min_age_seconds, allow_kill=allow_kill,
        ), births)

    def close(self) -> dict[str, Any]:
        """Reap only through retained handles, then release them without signals."""
        with self._lock:
            births = [birth for birth in self._backend.births if birth.registered or birth.finished]
        return self._complete(self._engine.close, births)
