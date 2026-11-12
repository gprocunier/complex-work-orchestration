"""Identity-bound process signalling with Linux pidfds.

A PID can be reused as soon as its process exits, so checking a PID and then
signalling it by number can hit a different process. A pidfd refers to one
process for its whole life: signals sent through it cannot reach a replacement.

``PidfdTerminator`` refuses unless /proc shows this process's own PID namespace
and the registration was made in that namespace. It opens the pidfd, confirms
through the handle's fdinfo that the handle holds the registered PID, reads the
identity from /proc, then confirms through fdinfo again that the same process
still holds that PID. Because a PID is not reused while its process lives, the
/proc reading therefore describes the process behind the handle. The identity
(boot, PID namespace, start time, executable, UID, canonical workspace) must
match the trusted registration, and the verified incarnation must be at least
the requested age. Every signal and the exit wait use that one handle. Nothing
here falls back to ``os.kill`` by PID.

The start time is exported in clock ticks, so the binding is exact only to one
tick: a replacement that reuses the PID within the same tick, with the same
executable, UID and cwd, cannot be told apart from /proc. A trusted producer
must therefore bind the process lifetime from spawn, for example by keeping
the pidfd it obtained at spawn or recording its pidfs inode, and the
terminator must then use or verify that binding.

Authority is separate from mechanism. A registration is trusted only when a
controller outside the lead's control wrote it; ``NoTrustedOwnershipSource`` is
the only source shipped today, so no production path reaches the terminator.
A pidfd binds one process, not its descendants.
"""

from __future__ import annotations

import errno
import math
import os
import select
import signal
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol


@dataclass(frozen=True)
class ProcStat:
    pid: int
    comm: str
    state: str
    ppid: int
    start_ticks: int


def parse_proc_stat(text: str) -> ProcStat:
    """Parse /proc/<pid>/stat. The command name may contain spaces and parentheses.

    The name is everything between the first ``(`` and the last ``)``; fields
    after it are space-separated, starting with field 3 (state). Start time is
    field 22.
    """
    open_index = text.find("(")
    close_index = text.rfind(")")
    if open_index <= 0 or close_index <= open_index:
        raise ValueError("malformed stat: no parenthesized command name")
    pid_text = text[:open_index].strip()
    fields = text[close_index + 1 :].split()
    if len(fields) < 20:
        raise ValueError("malformed stat: too few fields")
    try:
        return ProcStat(
            pid=int(pid_text),
            comm=text[open_index + 1 : close_index],
            state=fields[0],
            ppid=int(fields[1]),
            start_ticks=int(fields[19]),
        )
    except ValueError as exc:
        raise ValueError(f"malformed stat: {exc}") from exc


@dataclass(frozen=True)
class ProcessIdentity:
    pid: int
    boot_id: str
    pid_namespace: str
    start_ticks: int
    executable: str
    uid: int
    cwd: str


@dataclass(frozen=True)
class TrustedRegistration:
    """A process record written by a trusted controller when it spawned the process.

    ``workspace`` must be the absolute, normalized cwd in the controller's mount
    namespace. See the module docstring for the one-tick limit of the birth
    marker and the producer's lifetime-binding duty.
    """

    pid: int
    boot_id: str
    pid_namespace: str
    start_ticks: int
    executable: str
    uid: int
    workspace: str
    session_id: str
    producer: str


class ProcAdapter:
    """Real kernel and /proc access. Tests substitute a fake."""

    def __init__(self, proc_root: Path = Path("/proc")) -> None:
        self.proc_root = proc_root

    def read_text(self, relative: str) -> str:
        return (self.proc_root / relative).read_text(encoding="utf-8", errors="surrogateescape")

    def readlink(self, relative: str) -> str:
        return os.readlink(self.proc_root / relative)

    def supported(self) -> tuple[bool, str]:
        if not hasattr(os, "pidfd_open") or not hasattr(signal, "pidfd_send_signal"):
            return False, "pidfd-unsupported-by-python"
        try:
            if int(self.readlink("self")) != os.getpid():
                return False, "procfs-pid-namespace-mismatch"
        except (OSError, ValueError):
            return False, "procfs-unavailable"
        try:
            descriptor = self.pidfd_open(os.getpid())
        except OSError as exc:
            return False, f"pidfd-unavailable: {exc.strerror or exc}"
        try:
            bound = self.pidfd_pid(descriptor) == os.getpid()
        except (OSError, ValueError):
            bound = False
        try:
            self.close(descriptor)
        except OSError as exc:
            # Closed once; a failure is reported, never retried or raised.
            return False, f"pidfd-probe-close-failed: {exc.strerror or exc}"
        return (True, "pidfd-available") if bound else (False, "pidfd-fdinfo-unavailable")

    def own_pid_namespace(self) -> str:
        return self.readlink("self/ns/pid")

    def pidfd_pid(self, descriptor: int) -> int | None:
        """PID the handle refers to, from fdinfo, or None without a Pid line.

        The kernel reports -1 once the process has exited and 0 when it is not
        visible in this procfs's PID namespace.
        """
        for line in self.read_text(f"self/fdinfo/{descriptor}").splitlines():
            if line.startswith("Pid:"):
                parts = line.split()
                if len(parts) != 2:
                    raise ValueError("malformed fdinfo Pid line")
                return int(parts[1])
        return None

    def uptime_seconds(self) -> float:
        return float(self.read_text("uptime").split()[0])

    def clock_ticks(self) -> int:
        return int(os.sysconf("SC_CLK_TCK"))

    def pidfd_open(self, pid: int) -> int:
        return os.pidfd_open(pid)

    def send_signal(self, descriptor: int, signum: int) -> None:
        signal.pidfd_send_signal(descriptor, signum)

    def wait_exit(self, descriptor: int, timeout_seconds: float) -> bool:
        """Confirm exit only from one exact POLLIN event for this handle."""
        poller = select.poll()
        poller.register(descriptor, select.POLLIN)
        events = poller.poll(max(0, int(timeout_seconds * 1000)))
        if type(events) is not list:
            raise ValueError("The retained handle poll returned malformed events.")
        if not events:
            return False
        if len(events) != 1 or type(events[0]) is not tuple or len(events[0]) != 2:
            raise ValueError("The retained handle poll returned ambiguous events.")
        event_descriptor, mask = events[0]
        if type(event_descriptor) is not int or event_descriptor != descriptor:
            raise ValueError("The retained handle poll returned another descriptor.")
        if type(mask) is not int or mask != select.POLLIN:
            raise ValueError("The retained handle poll did not confirm an exact supported exit indication.")
        return True

    def close(self, descriptor: int) -> None:
        os.close(descriptor)


def observe_identity(pid: int, adapter: ProcAdapter) -> ProcessIdentity:
    """Read a process identity from /proc. Raises on any missing or malformed field."""
    stat = parse_proc_stat(adapter.read_text(f"{pid}/stat"))
    if stat.pid != pid:
        raise ValueError("stat pid does not match the requested pid")
    uid = None
    for line in adapter.read_text(f"{pid}/status").splitlines():
        if line.startswith("Uid:"):
            parts = line.split()
            if len(parts) >= 2:
                uid = int(parts[1])
            break
    if uid is None:
        raise ValueError("status has no Uid line")
    return ProcessIdentity(
        pid=pid,
        boot_id=adapter.read_text("sys/kernel/random/boot_id").strip(),
        pid_namespace=adapter.readlink(f"{pid}/ns/pid"),
        start_ticks=stat.start_ticks,
        executable=adapter.readlink(f"{pid}/exe"),
        uid=uid,
        cwd=adapter.readlink(f"{pid}/cwd"),
    )


def canonical_workspace(path: str) -> bool:
    """A trusted producer records workspaces as absolute, normalized paths."""
    return bool(path) and os.path.isabs(path) and os.path.normpath(path) == path


def identity_mismatches(registration: TrustedRegistration, observed: ProcessIdentity) -> list[str]:
    reasons: list[str] = []
    for field in ("pid", "boot_id", "pid_namespace", "start_ticks", "executable", "uid"):
        if getattr(registration, field) != getattr(observed, field):
            reasons.append(f"{field}-mismatch")
    workspace = registration.workspace
    if not canonical_workspace(workspace):
        reasons.append("workspace-not-canonical")
    else:
        prefix = workspace if workspace == "/" else workspace + "/"
        if not (observed.cwd == workspace or observed.cwd.startswith(prefix)):
            reasons.append("workspace-mismatch")
    return reasons


class OwnershipSource(Protocol):
    def trusted_registrations(self) -> list[TrustedRegistration] | None: ...


class NoTrustedOwnershipSource:
    """The only ownership source shipped today: there is no trusted producer."""

    reason = "no-trusted-ownership-producer"

    def trusted_registrations(self) -> list[TrustedRegistration] | None:
        return None


MAX_GRACE_SECONDS = 3600.0
EXITED = -1


def _valid_duration(value: object, maximum: float) -> bool:
    """Validate duration bounds without converting finite integers to floats."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    return 0 <= value <= maximum and (isinstance(value, int) or math.isfinite(value))


def _binding_failure(pid_value: int | None, *, observing: bool) -> dict[str, Any]:
    """Classify an fdinfo Pid that is not the registered PID.

    Only -1 proves that the handle's process exited; anything else means the
    binding could not be confirmed, so the target is kept.
    """
    if pid_value == EXITED:
        return {"outcome": "exited-during-observation" if observing else "already-exited", "signals": []}
    if pid_value is None:
        return {"outcome": "identity-unavailable", "reason": "pidfd-fdinfo-missing-pid", "signals": []}
    if pid_value == 0:
        return {"outcome": "identity-unavailable", "reason": "pidfd-target-not-in-procfs-namespace", "signals": []}
    return {"outcome": "identity-mismatch", "reasons": ["pidfd-pid-mismatch"], "signals": []}


class PidfdTerminator:
    def __init__(self, adapter: ProcAdapter | None = None) -> None:
        self.adapter = adapter or ProcAdapter()

    def supported(self) -> tuple[bool, str]:
        return self.adapter.supported()

    def terminate(
        self,
        registration: TrustedRegistration,
        *,
        grace_seconds: float,
        min_age_seconds: float = 0.0,
    ) -> dict[str, Any]:
        """Terminate the registered incarnation, or send nothing.

        The incarnation is identified to one start-time tick (see the module
        docstring). ``signals`` lists every signal actually sent, including
        when a later step fails. A failure to close the handle is attached as
        ``close_error`` without replacing the outcome.
        """
        for label, value in (("grace_seconds", grace_seconds), ("min_age_seconds", min_age_seconds)):
            if not _valid_duration(
                value, MAX_GRACE_SECONDS if label == "grace_seconds" else math.inf
            ):
                return {"outcome": "invalid-request", "reason": f"{label}-invalid", "signals": []}
        supported, support_reason = self.adapter.supported()
        if not supported:
            return {"outcome": "unavailable", "reason": support_reason, "signals": []}
        try:
            if self.adapter.own_pid_namespace() != registration.pid_namespace:
                return {"outcome": "identity-mismatch", "reasons": ["registration-namespace-mismatch"], "signals": []}
        except OSError as exc:
            return {"outcome": "unavailable", "reason": f"namespace-unreadable: {exc}", "signals": []}
        try:
            descriptor = self.adapter.pidfd_open(registration.pid)
        except ProcessLookupError:
            return {"outcome": "already-exited", "signals": []}
        except PermissionError:
            return {"outcome": "permission-denied", "stage": "open", "signals": []}
        except OSError as exc:
            return {"outcome": "unavailable", "reason": f"pidfd-open-failed: {exc.strerror or exc}", "signals": []}
        signals: list[str] = []
        try:
            outcome = self._act(descriptor, registration, grace_seconds, min_age_seconds, signals)
        except BaseException:
            self._close(descriptor)
            raise
        close_error = self._close(descriptor)
        if close_error is not None:
            outcome["close_error"] = close_error
        return outcome

    def _close(self, descriptor: int) -> str | None:
        """Close once; report a failure instead of raising or retrying."""
        try:
            self.adapter.close(descriptor)
        except OSError as exc:
            return f"{exc.errno}: {exc.strerror or exc}"
        return None

    def _act(
        self,
        descriptor: int,
        registration: TrustedRegistration,
        grace_seconds: float,
        min_age_seconds: float,
        signals: list[str],
    ) -> dict[str, Any]:
        try:
            bound = self.adapter.pidfd_pid(descriptor)
            if bound != registration.pid:
                return _binding_failure(bound, observing=False)
            observed = observe_identity(registration.pid, self.adapter)
            # The handle's process must still hold the PID after the read,
            # so the /proc entry read above belonged to it.
            bound = self.adapter.pidfd_pid(descriptor)
            if bound != registration.pid:
                return _binding_failure(bound, observing=True)
            age = self.adapter.uptime_seconds() - observed.start_ticks / self.adapter.clock_ticks()
        except (OSError, ValueError, ZeroDivisionError) as exc:
            return {"outcome": "identity-unavailable", "reason": str(exc), "signals": signals}
        mismatches = identity_mismatches(registration, observed)
        if mismatches:
            return {"outcome": "identity-mismatch", "reasons": mismatches, "signals": signals}
        if age < min_age_seconds:
            return {"outcome": "not-stale", "age_seconds": round(age, 3), "signals": signals}
        for signum, label in ((signal.SIGTERM, "SIGTERM"), (signal.SIGKILL, "SIGKILL")):
            try:
                self.adapter.send_signal(descriptor, signum)
            except ProcessLookupError:
                outcome = "terminated" if signals else "exited-before-signal"
                return {"outcome": outcome, "signals": signals}
            except PermissionError:
                return {"outcome": "permission-denied", "stage": label, "signals": signals}
            except OSError as exc:
                if exc.errno == errno.ENOSYS:
                    return {"outcome": "unavailable", "reason": "pidfd-send-signal-unavailable: ENOSYS",
                            "stage": label, "errno": exc.errno, "signals": signals}
                return {"outcome": "signal-failed", "stage": label, "errno": exc.errno, "signals": signals}
            signals.append(label)
            try:
                exited = self.adapter.wait_exit(descriptor, grace_seconds)
            except (OSError, ValueError, OverflowError) as exc:
                return {"outcome": "wait-failed", "stage": label, "reason": str(exc), "signals": signals}
            if exited:
                return {"outcome": "terminated" if label == "SIGTERM" else "killed", "signals": signals}
        return {"outcome": "still-running", "signals": signals}
