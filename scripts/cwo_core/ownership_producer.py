"""Retained ownership logic and the public offline fake controller adapter.

No default cleanup path consumes these reports. This cooperative adapter does
not provide production authority, hostile writer protection or tree containment.
"""

from __future__ import annotations

import errno
import math
import signal
from dataclasses import dataclass
from typing import Any, Callable, Protocol

from .process_identity import (
    MAX_GRACE_SECONDS,
    ProcessIdentity,
    ProcStat,
    TrustedRegistration,
    canonical_workspace,
    identity_mismatches,
    observe_identity,
    parse_proc_stat,
)

MAX_MIN_AGE_SECONDS = 365 * 24 * 60 * 60
PID_LIMIT = 4194304
MAX_UPTIME_SECONDS = 10**12


class OfflineProcAdapter(Protocol):
    """Fake operations only; birth claims transfer one handle to one writer."""

    offline_only: bool

    def claim_writer(self, writer: object) -> bool: ...
    def claim_spawn(self, pid: int, descriptor: int, writer: object) -> bool: ...
    def offline_supported(self) -> tuple[bool, str]: ...
    def read_text(self, relative: str) -> str: ...
    def readlink(self, relative: str) -> str: ...
    def own_pid_namespace(self) -> str: ...
    def pidfd_pid(self, descriptor: int) -> int | None: ...
    def uptime_seconds(self) -> float: ...
    def clock_ticks(self) -> int: ...
    def send_signal(self, descriptor: int, signum: int) -> None: ...
    def wait_exit(self, descriptor: int, timeout_seconds: float) -> bool: ...
    def close(self, descriptor: int) -> None: ...


@dataclass(frozen=True)
class ExpectedSpawn:
    session_id: str
    workspace: str
    executable: str
    uid: int
    boot_id: str
    pid_namespace: str


@dataclass(frozen=True, eq=False)
class OfflineSession:
    """An in-memory receipt; registration fields alone cannot replay it."""

    registration: TrustedRegistration


@dataclass(frozen=True)
class _Live:
    session: Any
    registration: TrustedRegistration
    descriptor: int
    expected: ExpectedSpawn
    identity: ProcessIdentity


class _Refusal(Exception):
    def __init__(self, outcome: str, reason: str, **detail: Any) -> None:
        super().__init__(reason)
        self.outcome = outcome
        self.reason = reason
        self.detail = detail


def _report(outcome: str, signals: list[str] | None = None, **detail: Any) -> dict[str, Any]:
    return {
        "outcome": outcome, "signals": list(signals or []), **detail,
        "offline_only": True, "production_authority": False,
        "default_cleanup_consumer": "none",
    }


def _integer(value: object, low: int, high: int) -> bool:
    return type(value) is int and low <= value <= high


def _token(value: object) -> bool:
    if not isinstance(value, str) or not 0 < len(value) <= 256:
        return False
    return value.isascii() and not any(char.isspace() or char == "\0" for char in value)


def _path(value: object) -> bool:
    return isinstance(value, str) and canonical_workspace(value) and "\0" not in value


def _duration(value: object, maximum: float) -> bool:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    return 0 <= value <= maximum and (isinstance(value, int) or math.isfinite(value))


def _validate_spec(expected: ExpectedSpawn) -> None:
    if type(expected) is not ExpectedSpawn:
        raise ValueError("A controller ExpectedSpawn is required.")
    if not all(_token(value) for value in (expected.session_id, expected.boot_id, expected.pid_namespace)):
        raise ValueError("Controller session, boot and namespace values must be valid.")
    if not all(_path(value) for value in (expected.workspace, expected.executable)):
        raise ValueError("Controller paths must be absolute and normalized.")
    if not _integer(expected.uid, 0, 2**32 - 1):
        raise ValueError("Controller uid must be a bounded integer.")


def _registration(identity: ProcessIdentity, expected: ExpectedSpawn, name: str) -> TrustedRegistration:
    return TrustedRegistration(
        pid=identity.pid, boot_id=expected.boot_id, pid_namespace=expected.pid_namespace,
        start_ticks=identity.start_ticks, executable=expected.executable, uid=expected.uid,
        workspace=expected.workspace, session_id=expected.session_id, producer=name,
    )


def _same_registration(left: TrustedRegistration, right: TrustedRegistration) -> bool:
    if type(left) is not TrustedRegistration:
        return False
    return all(
        type(value) is type(getattr(left, name)) and value == getattr(left, name)
        for name, value in vars(right).items()
    )


class _IdentityReads:
    """Check producer closure around every fake identity read."""

    def __init__(self, adapter: OfflineProcAdapter, call: Callable) -> None:
        self._adapter = adapter
        self._call = call

    def read_text(self, relative: str) -> str:
        return self._call(self._adapter.read_text, relative)

    def readlink(self, relative: str) -> str:
        return self._call(self._adapter.readlink, relative)


class _RetainedOwnershipProducer:
    """Share retained handle checks without granting a public backend adapter."""

    _report = staticmethod(_report)
    _session_type = OfflineSession
    _mode = "offline"
    _kind = "fake"

    def __init__(self, adapter: OfflineProcAdapter, *, controller_pid: int, name: str) -> None:
        methods = (
            "claim_writer", "claim_spawn", "offline_supported", "read_text", "readlink",
            "own_pid_namespace", "pidfd_pid", "uptime_seconds", "clock_ticks",
            "send_signal", "wait_exit", "close",
        )
        if getattr(adapter, "offline_only", False) is not True:
            raise ValueError("An explicitly offline fake adapter is required.")
        if not all(callable(getattr(adapter, method, None)) for method in methods):
            raise ValueError("The offline adapter is missing a required operation.")
        if not _integer(controller_pid, 1, PID_LIMIT) or not _token(name):
            raise ValueError("A valid independent offline controller is required.")
        self._writer = object()
        if adapter.claim_writer(self._writer) is not True:
            raise ValueError("The offline process table already has an ownership writer.")
        self._initialize(adapter, controller_pid, name)

    def _initialize(self, adapter: Any, controller_pid: int, name: str) -> None:
        self._adapter = adapter
        self._controller_pid = controller_pid
        self._name = name
        self._live: dict[int, _Live] = {}
        self._seen_sessions: set[str] = set()
        self._claimed: set[int] = set()
        self._released: set[int] = set()
        self._state = "idle"
        self._pending_session: str | None = None
        self._reads = _IdentityReads(adapter, self._call)

    def register_from_spawn(
        self, expected: ExpectedSpawn, spawn: Callable[[ExpectedSpawn], tuple[int, int]],
    ) -> dict[str, Any]:
        """Call a fake spawn once; only a claimed birth handle enters the registry."""
        try:
            _validate_spec(expected)
            if not callable(spawn):
                raise ValueError("A fake spawn callback is required.")
        except ValueError as exc:
            return self._report("invalid-request", reason=str(exc))
        return self._capture(lambda: self._register_once(expected, spawn), [])

    def _register_once(self, expected: ExpectedSpawn, spawn: Callable) -> dict[str, Any]:
        self._ensure_open()
        self._check_session(expected.session_id)
        self._enter("registering")
        self._pending_session = expected.session_id
        try:
            return self._spawn(expected, spawn)
        finally:
            self._leave()

    def _ensure_open(self) -> None:
        if self._state == "closed":
            raise _Refusal("producer-closed", f"The {self._mode} producer is closed.")

    def _check_session(self, session_id: str) -> None:
        if session_id in self._seen_sessions or session_id == self._pending_session:
            raise _Refusal("duplicate-session", f"The {self._kind} session is already reserved or used.")

    def _enter(self, state: str) -> None:
        self._ensure_open()
        if self._state != "idle":
            raise _Refusal("producer-busy", f"Another {self._mode} operation is in progress.")
        self._state = state

    def _leave(self) -> None:
        self._pending_session = None
        if self._state != "closed":
            self._state = "idle"

    def _reserved(self, expected: ExpectedSpawn) -> None:
        self._ensure_open()
        if (self._state, self._pending_session) != ("registering", expected.session_id):
            raise _Refusal("invalid-session", f"The {self._kind} registration reservation is no longer active.")

    def _call(self, operation: Callable, *arguments: Any) -> Any:
        self._ensure_open()
        result = operation(*arguments)
        self._ensure_open()
        return result

    def _spawn(self, expected: ExpectedSpawn, spawn: Callable) -> dict[str, Any]:
        self._capability()
        self._ancestors()
        self._reserved(expected)
        self._seen_sessions.add(expected.session_id)
        result = spawn(expected)
        if type(result) is not tuple or len(result) != 2:
            raise _Refusal("invalid-spawn", f"The {self._kind} spawn must return a PID and its birth handle.")
        pid, descriptor = result
        self._adopt(pid, descriptor)
        return self._using(descriptor, lambda: self._register(pid, descriptor, expected), [])

    def _adopt(self, pid: int, descriptor: int) -> None:
        if not _integer(pid, 1, PID_LIMIT) or not _integer(descriptor, 0, 2**31 - 1):
            raise _Refusal("invalid-spawn", "The fake PID or handle is malformed.")
        if descriptor in self._claimed:
            raise _Refusal("invalid-spawn", "The lifetime handle was already claimed.")
        if self._adapter.claim_spawn(pid, descriptor, self._writer) is not True:
            raise _Refusal("invalid-spawn", "No unclaimed fake birth handle matches this spawn.")
        self._claimed.add(descriptor)

    def _register(self, pid: int, descriptor: int, expected: ExpectedSpawn) -> dict[str, Any]:
        self._reserved(expected)
        if any(entry.identity.pid == pid for entry in self._live.values()):
            raise _Refusal("duplicate-target", f"A live session already holds this {self._kind} PID.")
        identity = self._observe(pid, descriptor)
        registration = _registration(identity, expected, self._name)
        session = self._session_type(registration)
        entry = _Live(session, registration, descriptor, expected, identity)
        self._verified(entry)
        self._reserved(expected)
        self._live[id(session)] = entry
        return self._report("registered", session=session)

    def terminate(
        self, session: OfflineSession, *, grace_seconds: float,
        min_age_seconds: float = 0.0, allow_kill: bool = False,
    ) -> dict[str, Any]:
        """Consume one valid receipt; every signal and wait use its retained handle."""
        limits = (("grace_seconds", grace_seconds, MAX_GRACE_SECONDS),
                  ("min_age_seconds", min_age_seconds, MAX_MIN_AGE_SECONDS))
        for label, value, maximum in limits:
            if not _duration(value, maximum):
                return self._report("invalid-request", reason=f"{label} is outside its finite bounds.")
        if type(allow_kill) is not bool:
            return self._report("invalid-request", reason="allow_kill must be Boolean.")
        signals: list[str] = []
        return self._capture(
            lambda: self._consume(session, grace_seconds, min_age_seconds, allow_kill, signals), signals,
        )

    def _lookup(self, session: OfflineSession) -> _Live:
        entry = self._live.get(id(session))
        if type(session) is not self._session_type or entry is None:
            raise _Refusal("invalid-session", f"No live receipt from this {self._mode} producer matches.")
        if entry.session is not session or session.registration is not entry.registration:
            raise _Refusal("invalid-session", f"The {self._mode} receipt has been altered.")
        return entry

    def _consume(
        self, session: OfflineSession, grace: float, minimum: float, kill: bool, signals: list[str],
    ) -> dict[str, Any]:
        self._enter("terminating")
        try:
            entry = self._lookup(session)
            self._live.pop(id(session))
            return self._using(entry.descriptor, lambda: self._act(entry, grace, minimum, kill, signals), signals)
        finally:
            self._leave()

    def _capability(self) -> None:
        supported, reason = self._call(self._adapter.offline_supported)
        if supported is not True:
            raise _Refusal("unavailable", reason)

    def _bound(self, pid: int, descriptor: int) -> None:
        bound = self._call(self._adapter.pidfd_pid, descriptor)
        if type(bound) is int and bound == -1:
            raise _Refusal("already-exited", "The retained handle reports that its original process exited.")
        if not _integer(bound, 1, PID_LIMIT):
            raise _Refusal("identity-unavailable", "The retained handle has no valid visible PID.")
        if bound != pid:
            raise _Refusal("identity-mismatch", "The retained handle is bound to another PID.")

    def _stat(self, pid: int) -> ProcStat:
        stat = parse_proc_stat(self._reads.read_text(f"{pid}/stat"))
        if stat.pid != pid or not _integer(stat.ppid, 0, PID_LIMIT):
            raise ValueError(f"The {self._kind} stat PID or parent is invalid.")
        if not _integer(stat.start_ticks, 0, 2**63 - 1) or stat.state not in {"R", "S", "D", "T", "t", "W", "K", "P", "I"}:
            raise ValueError(f"The {self._kind} process has no valid live start identity.")
        return stat

    def _observe(self, pid: int, descriptor: int) -> ProcessIdentity:
        self._bound(pid, descriptor)
        observed = observe_identity(pid, self._reads)
        stat = self._stat(pid)
        self._bound(pid, descriptor)
        if stat.start_ticks != observed.start_ticks or not _integer(observed.uid, 0, 2**32 - 1):
            raise ValueError(f"The {self._kind} process fields are inconsistent.")
        if not all(_token(value) for value in (observed.boot_id, observed.pid_namespace)):
            raise ValueError(f"The {self._kind} boot or namespace identity is malformed.")
        if not all(_path(value) for value in (observed.cwd, observed.executable)):
            raise ValueError(f"The {self._kind} process paths are malformed.")
        return observed

    def _ancestors(self) -> set[int]:
        result: set[int] = set()
        current = self._controller_pid
        for _ in range(256):
            if current == 0:
                return result
            if current in result:
                raise ValueError(f"The {self._kind} controller ancestry is cyclic.")
            result.add(current)
            current = self._stat(current).ppid
        raise ValueError(f"The {self._kind} controller ancestry exceeds the {self._mode} limit.")

    def _verified(self, entry: _Live) -> ProcessIdentity:
        if not _same_registration(entry.registration, _registration(entry.identity, entry.expected, self._name)):
            raise _Refusal("invalid-session", "The stored registration no longer matches its spawn specification.")
        if self._call(self._adapter.own_pid_namespace) != entry.registration.pid_namespace:
            raise _Refusal("identity-mismatch", "The controller namespace does not match the registration.")
        observed = self._observe(entry.identity.pid, entry.descriptor)
        reasons = identity_mismatches(entry.registration, observed)
        if observed.cwd != entry.expected.workspace:
            reasons.append("exact-workspace-mismatch")
        if reasons:
            raise _Refusal("identity-mismatch", f"The {self._kind} identity differs from the controller specification.", reasons=reasons)
        if observed.pid in self._ancestors():
            raise _Refusal("protected", f"The target is the {self._kind} controller or one of its ancestors.")
        self._bound(observed.pid, entry.descriptor)
        return observed

    def _age(self, identity: ProcessIdentity) -> float:
        uptime = self._call(self._adapter.uptime_seconds)
        ticks = self._call(self._adapter.clock_ticks)
        if not _duration(uptime, MAX_UPTIME_SECONDS) or not _integer(ticks, 1, 10**9):
            raise ValueError(f"The {self._kind} process clock is invalid.")
        age = uptime - identity.start_ticks / ticks
        if age < 0:
            raise ValueError(f"The {self._kind} process start is later than uptime.")
        return age

    def _act(self, entry: _Live, grace: float, minimum: float, kill: bool, signals: list[str]) -> dict[str, Any]:
        self._capability()
        steps = [(signal.SIGTERM, "SIGTERM")]
        if kill:
            steps.append((signal.SIGKILL, "SIGKILL"))
        for signum, label in steps:
            identity = self._verified(entry)
            age = self._age(identity)
            if not signals and age < minimum:
                return self._report("not-stale", signals, age_seconds=age)
            self._verified(entry)
            self._signal(entry.descriptor, signum, label, signals)
            if self._wait(entry.descriptor, grace, label):
                return self._report("terminated" if label == "SIGTERM" else "killed", signals)
        return self._report("still-running", signals)

    def _signal(self, descriptor: int, signum: int, label: str, signals: list[str]) -> None:
        self._ensure_open()
        try:
            self._adapter.send_signal(descriptor, signum)
        except ProcessLookupError:
            raise _Refusal("terminated" if signals else "exited-before-signal", f"The original {self._kind} process exited.")
        except PermissionError as exc:
            raise _Refusal("permission-denied", str(exc), stage=label) from exc
        except OSError as exc:
            outcome = "unavailable" if exc.errno == errno.ENOSYS else "signal-failed"
            raise _Refusal(outcome, str(exc), stage=label, errno=exc.errno) from exc
        signals.append(label)
        self._ensure_open()

    def _wait(self, descriptor: int, grace: float, label: str) -> bool:
        try:
            exited = self._call(self._adapter.wait_exit, descriptor, grace)
            if type(exited) is not bool:
                raise ValueError(f"The {self._kind} exit observation must be Boolean.")
            return exited
        except (OSError, ValueError, OverflowError) as exc:
            raise _Refusal("wait-failed", str(exc), stage=label) from exc

    def _capture(self, action: Callable, signals: list[str]) -> dict[str, Any]:
        try:
            return action()
        except _Refusal as exc:
            outcome = "terminated" if signals and exc.outcome == "already-exited" else exc.outcome
            return self._report(outcome, signals, reason=exc.reason, **exc.detail)
        except PermissionError as exc:
            return self._report("permission-denied", signals, reason=str(exc))
        except (OSError, ValueError, TypeError, OverflowError, ZeroDivisionError) as exc:
            return self._report("identity-unavailable", signals, reason=str(exc))

    def _using(self, descriptor: int, action: Callable, signals: list[str]) -> dict[str, Any]:
        try:
            report = self._capture(action, signals)
        except BaseException:
            self._release(descriptor)
            raise
        if report["outcome"] != "registered":
            error = self._release(descriptor)
            if error is not None:
                report["close_error"] = error
        return report

    def _release(self, descriptor: int) -> str | None:
        if descriptor in self._released:
            return None
        self._released.add(descriptor)
        try:
            self._adapter.close(descriptor)
        except Exception as exc:
            return f"{type(exc).__name__}: {exc}"
        return None

    def _release_entries(self, entries: list[_Live]) -> list[dict[str, str]]:
        errors = []
        interruption: BaseException | None = None
        for entry in entries:
            try:
                error = self._release(entry.descriptor)
            except BaseException as exc:
                if interruption is None:
                    interruption = exc
                continue
            if error is not None:
                errors.append({"session_id": entry.registration.session_id, "error": error})
        if interruption is not None:
            raise interruption
        return errors

    def close(self) -> dict[str, Any]:
        """Release remaining handles once and report cleanup failures."""
        self._state = "closed"
        entries = list(self._live.values())
        self._live.clear()
        return self._report("closed", close_errors=self._release_entries(entries))


class OfflineOwnershipProducer(_RetainedOwnershipProducer):
    """Retain birth handles in one private registry for one fake controller."""
