from __future__ import annotations

import contextlib
import errno
import io
import json
import os
import select
import signal
import subprocess
import sys
import tempfile
import unittest
import unittest.mock
from dataclasses import dataclass, field
from pathlib import Path
from typing import NamedTuple

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import cleanup_stale_agents  # noqa: E402
from cleanup_stale_agents import ProcessInfo  # noqa: E402
from cwo_core.process_identity import (  # noqa: E402
    PidfdTerminator,
    ProcAdapter,
    TrustedRegistration,
    observe_identity,
    parse_proc_stat,
)

NS = "pid:[4026531836]"
PID = 4242


def stat_line(pid: int, comm: str, start_ticks: int, ppid: int = 1) -> str:
    tail = ["S", str(ppid)] + ["0"] * 17 + [str(start_ticks)] + ["0"] * 10
    return f"{pid} ({comm}) " + " ".join(tail) + "\n"


@dataclass
class Incarnation:
    pid: int
    start_ticks: int
    exe: str = "/usr/bin/codex"
    cwd: str = "/work/repo"
    uid: int = 1003
    alive: bool = True
    exits_on: set[int] = field(default_factory=lambda: {signal.SIGTERM})
    signals: list[int] = field(default_factory=list)


class FakeKernel(ProcAdapter):
    """Process table whose handles are bound to incarnations, not PID numbers."""

    def __init__(self) -> None:
        super().__init__()
        self.procs = {PID: Incarnation(PID, start_ticks=100)}
        self.handles: dict[int, Incarnation] = {}
        self.next_fd = 70
        self.hooks: dict[str, object] = {}
        self.is_supported = True
        self.namespace = NS
        self.uptime = 10_000.0
        self.opened: list[int] = []
        self.send_errors: dict[int, BaseException] = {}
        self.open_error: BaseException | None = None
        self.wait_error: BaseException | None = None
        self.fdinfo_pid: object = None  # when set, fdinfo reports this instead of the true value

    def fire(self, name: str) -> None:
        hook = self.hooks.pop(name, None)
        if hook is not None:
            hook()

    def replace(self, pid: int = PID, *, same_tick: bool = False) -> Incarnation:
        old = self.procs[pid]
        old.alive = False
        fresh = Incarnation(pid, start_ticks=old.start_ticks + (0 if same_tick else 500))
        self.procs[pid] = fresh
        return fresh

    def supported(self) -> tuple[bool, str]:
        return (True, "pidfd-available") if self.is_supported else (False, "pidfd-unsupported-by-python")

    def own_pid_namespace(self) -> str:
        return self.namespace

    def pidfd_open(self, pid: int) -> int:
        self.opened.append(pid)
        if self.open_error is not None:
            raise self.open_error
        process = self.procs.get(pid)
        if process is None or not process.alive:
            raise ProcessLookupError(pid)
        self.next_fd += 1
        self.handles[self.next_fd] = process
        self.fire("after_open")
        return self.next_fd

    def pidfd_pid(self, descriptor: int) -> int | None:
        if self.fdinfo_pid is not None:
            return None if self.fdinfo_pid == "missing" else self.fdinfo_pid
        process = self.handles[descriptor]
        return process.pid if process.alive and self.procs.get(process.pid) is process else -1

    def read_text(self, relative: str) -> str:
        if relative == "uptime":
            return f"{self.uptime} 0\n"
        if relative == "sys/kernel/random/boot_id":
            return "boot-1\n"
        pid_text, _, leaf = relative.partition("/")
        process = self.procs[int(pid_text)]
        if leaf == "stat":
            self.fire("on_stat")
            process = self.procs[int(pid_text)]
            return stat_line(process.pid, "codex", process.start_ticks)
        if leaf == "status":
            return f"Name:\tcodex\nUid:\t{process.uid}\t{process.uid}\t{process.uid}\t{process.uid}\n"
        raise FileNotFoundError(relative)

    def readlink(self, relative: str) -> str:
        pid_text, _, leaf = relative.partition("/")
        process = self.procs[int(pid_text)]
        return {"ns/pid": self.namespace, "exe": process.exe, "cwd": process.cwd}[leaf]

    def clock_ticks(self) -> int:
        return 100

    def send_signal(self, descriptor: int, signum: int) -> None:
        self.fire(f"before_{signal.Signals(signum).name}")
        if signum in self.send_errors:
            raise self.send_errors[signum]
        process = self.handles[descriptor]
        if not process.alive:
            raise ProcessLookupError(process.pid)
        process.signals.append(signum)
        if signum in process.exits_on:
            process.alive = False

    def wait_exit(self, descriptor: int, timeout_seconds: float) -> bool:
        if self.wait_error is not None:
            raise self.wait_error
        return not self.handles[descriptor].alive

    def close(self, descriptor: int) -> None:
        self.handles.pop(descriptor, None)


def registration(**overrides: object) -> TrustedRegistration:
    values = dict(
        pid=PID, boot_id="boot-1", pid_namespace=NS, start_ticks=100, executable="/usr/bin/codex",
        uid=1003, workspace="/work/repo", session_id="s-1", producer="test-controller",
    )
    values.update(overrides)
    return TrustedRegistration(**values)


class FakeProbeAdapter(ProcAdapter):
    """Keep capability probes on fake process data and an invalid example handle."""

    EXAMPLE_DESCRIPTOR = -424242

    def readlink(self, relative: str) -> str:
        if relative != "self":
            raise AssertionError("EXAMPLE probe requested a real process link")
        return str(os.getpid())

    def read_text(self, relative: str) -> str:
        if relative != f"self/fdinfo/{self.EXAMPLE_DESCRIPTOR}":
            raise AssertionError("EXAMPLE probe requested a real process file")
        return f"Pid:\t{os.getpid()}\n"

    def pidfd_open(self, pid: int) -> int:
        if pid != os.getpid():
            raise AssertionError("EXAMPLE probe requested another process")
        return self.EXAMPLE_DESCRIPTOR

    def close(self, descriptor: int) -> None:
        if descriptor != self.EXAMPLE_DESCRIPTOR:
            raise AssertionError("EXAMPLE probe closed an unexpected handle")


@contextlib.contextmanager
def fake_probe_capabilities():
    """Expose API names only while fake probes run; reject syscall use."""
    with unittest.mock.patch.object(
        os, "pidfd_open", create=True,
        side_effect=AssertionError("EXAMPLE probe must use its fake open method"),
    ) as open_api, unittest.mock.patch.object(
        signal, "pidfd_send_signal", create=True,
        side_effect=AssertionError("EXAMPLE probe must never send a signal"),
    ) as signal_api:
        yield open_api, signal_api


class FakeProbeCapabilityTests(unittest.TestCase):
    def test_capabilities_are_restored_after_normal_exit(self) -> None:
        missing = object()
        original_open = getattr(os, "pidfd_open", missing)
        original_signal = getattr(signal, "pidfd_send_signal", missing)
        with fake_probe_capabilities() as (open_api, signal_api):
            self.assertEqual(FakeProbeAdapter().supported(), (True, "pidfd-available"))
        self.assertIs(getattr(os, "pidfd_open", missing), original_open)
        self.assertIs(getattr(signal, "pidfd_send_signal", missing), original_signal)
        open_api.assert_not_called()
        signal_api.assert_not_called()
        if original_open is missing or original_signal is missing:
            self.assertEqual(ProcAdapter().supported(), (False, "pidfd-unsupported-by-python"))

    def test_capabilities_are_restored_after_exception(self) -> None:
        missing = object()
        original_open = getattr(os, "pidfd_open", missing)
        original_signal = getattr(signal, "pidfd_send_signal", missing)
        with self.assertRaisesRegex(RuntimeError, "EXAMPLE probe failure"):
            with fake_probe_capabilities() as (open_api, signal_api):
                self.assertEqual(FakeProbeAdapter().supported(), (True, "pidfd-available"))
                raise RuntimeError("EXAMPLE probe failure")
        self.assertIs(getattr(os, "pidfd_open", missing), original_open)
        self.assertIs(getattr(signal, "pidfd_send_signal", missing), original_signal)
        open_api.assert_not_called()
        signal_api.assert_not_called()

    def test_missing_api_status_is_preserved_after_each_exit(self) -> None:
        for module, name in ((os, "pidfd_open"), (signal, "pidfd_send_signal")):
            for fail in (False, True):
                with self.subTest(api=name, fail=fail), unittest.mock.patch.object(
                    module, name, create=True
                ) as placeholder:
                    delattr(module, name)
                    try:
                        self.assertEqual(ProcAdapter().supported(), (False, "pidfd-unsupported-by-python"))
                        exit_check = (
                            self.assertRaisesRegex(RuntimeError, "EXAMPLE probe failure")
                            if fail else contextlib.nullcontext()
                        )
                        with exit_check, fake_probe_capabilities() as (open_api, signal_api):
                            self.assertEqual(FakeProbeAdapter().supported(), (True, "pidfd-available"))
                            if fail:
                                raise RuntimeError("EXAMPLE probe failure")
                        self.assertFalse(hasattr(module, name))
                        self.assertEqual(ProcAdapter().supported(), (False, "pidfd-unsupported-by-python"))
                        open_api.assert_not_called()
                        signal_api.assert_not_called()
                    finally:
                        setattr(module, name, placeholder)


class PollExitTests(unittest.TestCase):
    def test_exact_exit_and_empty_timeout_keep_the_original_poll_contract(self) -> None:
        for events, expected in (([(17, select.POLLIN)], True), ([], False)):
            with self.subTest(events=events):
                poller = unittest.mock.Mock()
                poller.poll.return_value = events
                with unittest.mock.patch.object(select, "poll", return_value=poller):
                    self.assertIs(ProcAdapter().wait_exit(17, 0.25), expected)
                poller.register.assert_called_once_with(17, select.POLLIN)
                poller.poll.assert_called_once_with(250)

    def test_errors_and_unsupported_masks_never_confirm_exit(self) -> None:
        for mask in (
            select.POLLNVAL, select.POLLERR, select.POLLHUP,
            select.POLLIN | select.POLLNVAL, select.POLLIN | select.POLLERR,
            select.POLLIN | select.POLLHUP, 0, 1 << 30, select.POLLIN | (1 << 30),
            True, False, float(select.POLLIN), None, "EXAMPLE-mask",
        ):
            with self.subTest(mask=mask):
                poller = unittest.mock.Mock()
                poller.poll.return_value = [(17, mask)]
                with unittest.mock.patch.object(select, "poll", return_value=poller):
                    with self.assertRaisesRegex(ValueError, "supported exit indication"):
                        ProcAdapter().wait_exit(17, 0)

    def test_wrong_descriptors_and_malformed_or_ambiguous_events_refuse(self) -> None:
        for events in (
            [(18, select.POLLIN)], [(True, select.POLLIN)], [("EXAMPLE-fd", select.POLLIN)],
            [(17, select.POLLIN), (17, select.POLLIN)], [[17, select.POLLIN]],
            [(17,)], [(17, select.POLLIN, 0)], [None], None, (), True,
        ):
            with self.subTest(events=events):
                poller = unittest.mock.Mock()
                poller.poll.return_value = events
                with unittest.mock.patch.object(select, "poll", return_value=poller):
                    with self.assertRaises(ValueError):
                        ProcAdapter().wait_exit(17, 0)

    def test_original_terminator_keeps_term_and_refuses_escalation_after_poll_error(self) -> None:
        for mask in (
            select.POLLNVAL, select.POLLERR,
            select.POLLIN | select.POLLNVAL, select.POLLIN | select.POLLERR,
        ):
            with self.subTest(mask=mask):
                kernel = FakeKernel()
                original = kernel.procs[PID]
                original.exits_on = set()
                kernel.wait_exit = lambda descriptor, timeout: ProcAdapter.wait_exit(kernel, descriptor, timeout)
                poller = unittest.mock.Mock()
                poller.poll.side_effect = lambda milliseconds: [(kernel.next_fd, mask)]
                with unittest.mock.patch.object(select, "poll", return_value=poller):
                    report = PidfdTerminator(kernel).terminate(registration(), grace_seconds=0)
                self.assertEqual(report["outcome"], "wait-failed")
                self.assertEqual(report["stage"], "SIGTERM")
                self.assertEqual(report["signals"], ["SIGTERM"])
                self.assertEqual(original.signals, [signal.SIGTERM])
                self.assertTrue(original.alive)
                self.assertEqual(kernel.handles, {})


class ParseProcStatTests(unittest.TestCase):
    def test_parses_names_with_spaces_and_parentheses(self) -> None:
        for comm in ("codex", "my agent", "a (b) c", "))(("):
            with self.subTest(comm=comm):
                parsed = parse_proc_stat(stat_line(99, comm, 12345, ppid=7))
                self.assertEqual((parsed.pid, parsed.comm, parsed.ppid, parsed.start_ticks), (99, comm, 7, 12345))

    def test_rejects_malformed_stat(self) -> None:
        for text in ("", "99 codex S 1", "99 (codex) S 1 2 3", "x (codex) " + " ".join(["0"] * 30), "99 (codex) S x" + " 0" * 25):
            with self.subTest(text=text[:20]), self.assertRaises(ValueError):
                parse_proc_stat(text)


class ReplacementRow(NamedTuple):
    original_id: str
    boundary: str
    outcome: str
    exits_on: tuple[int, ...] | None = None


class ReplacementTests(unittest.TestCase):
    """A replacement incarnation must never receive a signal, at any stage."""

    def test_replacement_and_escalation_boundary_family(self) -> None:
        rows = (
            ReplacementRow("tests.test_process_identity.ReplacementTests.test_replacement_before_open_is_refused", "before-open", "identity-mismatch"),
            ReplacementRow("tests.test_process_identity.ReplacementTests.test_replacement_during_observation_is_refused", "on_stat", "exited-during-observation"),
            ReplacementRow("tests.test_process_identity.ReplacementTests.test_replacement_before_term_receives_nothing", "before_SIGTERM", "exited-before-signal"),
            ReplacementRow("tests.test_process_identity.ReplacementTests.test_replacement_between_term_and_kill_receives_nothing", "before_SIGKILL", "terminated", ()),
            ReplacementRow("tests.test_process_identity.ReplacementTests.test_escalation_uses_one_handle", "no-replacement", "killed", (signal.SIGKILL,)),
        )
        for row in rows:
            with self.subTest(original_id=row.original_id):
                kernel = FakeKernel()
                original = kernel.procs[PID]
                if row.exits_on is not None:
                    original.exits_on = set(row.exits_on)
                if row.boundary == "before-open":
                    fresh = kernel.replace()
                elif row.boundary != "no-replacement":
                    kernel.hooks[row.boundary] = kernel.replace
                outcome = PidfdTerminator(kernel).terminate(registration(), grace_seconds=0)
                self.assertEqual(outcome["outcome"], row.outcome)
                if row.boundary == "before-open":
                    self.assertIn("start_ticks-mismatch", outcome["reasons"])
                    self.assertEqual(fresh.signals, [])
                elif row.boundary == "on_stat":
                    self.assertEqual((original.signals, kernel.procs[PID].signals), ([], []))
                elif row.boundary == "before_SIGTERM":
                    self.assertEqual(kernel.procs[PID].signals, [])
                elif row.boundary == "before_SIGKILL":
                    self.assertEqual(outcome["signals"], ["SIGTERM"])
                    self.assertEqual(original.signals, [signal.SIGTERM])
                    self.assertEqual(kernel.procs[PID].signals, [], "the replacement never receives SIGKILL")
                    self.assertEqual(kernel.opened, [PID], "the PID is opened once and never reopened")
                else:
                    self.assertEqual(original.signals, [signal.SIGTERM, signal.SIGKILL])
                    self.assertEqual(kernel.handles, {}, "the handle is closed")


class RefusalTests(unittest.TestCase):
    def test_identity_mismatches_send_nothing(self) -> None:
        cases = {
            "boot": registration(boot_id="boot-other"),
            "start (reuse)": registration(start_ticks=99),
            "executable": registration(executable="/usr/bin/sleep"),
            "uid": registration(uid=0),
            "sibling workspace": registration(workspace="/work/rep"),
            "non-canonical workspace": registration(workspace="/work/../work/repo"),
            "relative workspace": registration(workspace="work/repo"),
            "trailing slash": registration(workspace="/work/repo/"),
        }
        for label, expected in cases.items():
            with self.subTest(case=label):
                kernel = FakeKernel()
                outcome = PidfdTerminator(kernel).terminate(expected, grace_seconds=0)
                self.assertEqual(outcome["outcome"], "identity-mismatch")
                self.assertEqual(kernel.procs[PID].signals, [])

    def test_registration_from_another_namespace_is_refused_before_opening(self) -> None:
        kernel = FakeKernel()
        outcome = PidfdTerminator(kernel).terminate(registration(pid_namespace="pid:[1]"), grace_seconds=0)
        self.assertEqual(outcome["reasons"], ["registration-namespace-mismatch"])
        self.assertEqual(kernel.opened, [])

    def test_procfs_from_another_pid_namespace_is_unsupported(self) -> None:
        class ForeignProc(FakeProbeAdapter):
            def readlink(self, relative: str) -> str:
                return str(os.getpid() + 1) if relative == "self" else super().readlink(relative)

        with fake_probe_capabilities():
            self.assertEqual(ForeignProc().supported(), (False, "procfs-pid-namespace-mismatch"))

    def test_young_incarnation_is_not_stale(self) -> None:
        kernel = FakeKernel()
        kernel.uptime = 1.5  # started at 1.0 s (100 ticks at 100 Hz): 0.5 s old
        outcome = PidfdTerminator(kernel).terminate(registration(), grace_seconds=0, min_age_seconds=3600)
        self.assertEqual(outcome["outcome"], "not-stale")
        self.assertEqual(kernel.procs[PID].signals, [])

    def test_syscall_failures_are_structured(self) -> None:
        kernel = FakeKernel()
        kernel.send_errors[signal.SIGTERM] = OSError(errno.ENOSYS, "not implemented")
        outcome = PidfdTerminator(kernel).terminate(registration(), grace_seconds=0)
        self.assertEqual((outcome["outcome"], outcome["stage"], outcome["signals"]), ("unavailable", "SIGTERM", []))
        self.assertIn("ENOSYS", outcome["reason"])
        kernel = FakeKernel()
        kernel.send_errors[signal.SIGTERM] = OSError(errno.EINVAL, "invalid")
        outcome = PidfdTerminator(kernel).terminate(registration(), grace_seconds=0)
        self.assertEqual((outcome["outcome"], outcome["errno"], outcome["signals"]), ("signal-failed", errno.EINVAL, []))
        kernel = FakeKernel()
        kernel.procs[PID].exits_on = set()
        kernel.send_errors[signal.SIGKILL] = PermissionError()
        outcome = PidfdTerminator(kernel).terminate(registration(), grace_seconds=0)
        self.assertEqual((outcome["outcome"], outcome["stage"], outcome["signals"]), ("permission-denied", "SIGKILL", ["SIGTERM"]))
        self.assertEqual(kernel.handles, {})

    def test_unconfirmed_binding_is_not_an_exit(self) -> None:
        cases = {
            -1: ("already-exited", None),
            0: ("identity-unavailable", "pidfd-target-not-in-procfs-namespace"),
            "missing": ("identity-unavailable", "pidfd-fdinfo-missing-pid"),
            PID + 1000: ("identity-mismatch", None),  # caller numbers agree, target mapping differs
        }
        for reported, (expected, reason) in cases.items():
            with self.subTest(fdinfo=reported):
                kernel = FakeKernel()
                kernel.fdinfo_pid = reported
                outcome = PidfdTerminator(kernel).terminate(registration(), grace_seconds=0)
                self.assertEqual(outcome["outcome"], expected)
                if reason:
                    self.assertEqual(outcome["reason"], reason)
                self.assertEqual(kernel.procs[PID].signals, [])
                self.assertEqual(kernel.handles, {})

    def test_requests_are_validated_before_opening(self) -> None:
        for kwargs in ({"grace_seconds": float("inf")}, {"grace_seconds": -1}, {"grace_seconds": float("nan")},
                       {"grace_seconds": 0, "min_age_seconds": float("nan")}, {"grace_seconds": 1e9}):
            with self.subTest(kwargs=kwargs):
                kernel = FakeKernel()
                outcome = PidfdTerminator(kernel).terminate(registration(), **kwargs)
                self.assertEqual(outcome["outcome"], "invalid-request")
                self.assertEqual(kernel.opened, [])

    def test_wait_failure_keeps_the_signals_sent(self) -> None:
        kernel = FakeKernel()
        kernel.procs[PID].exits_on = set()
        kernel.wait_error = OSError(errno.EINVAL, "poll failed")
        outcome = PidfdTerminator(kernel).terminate(registration(), grace_seconds=1)
        self.assertEqual((outcome["outcome"], outcome["stage"], outcome["signals"]), ("wait-failed", "SIGTERM", ["SIGTERM"]))
        self.assertEqual(kernel.handles, {})

    def test_close_failure_keeps_the_outcome(self) -> None:
        kernel = FakeKernel()
        calls: list[int] = []
        real_close = kernel.close

        def failing_close(descriptor: int) -> None:
            calls.append(descriptor)
            real_close(descriptor)
            raise OSError(errno.EINTR, "Interrupted system call")

        kernel.close = failing_close  # type: ignore[method-assign]
        outcome = PidfdTerminator(kernel).terminate(registration(), grace_seconds=0)
        self.assertEqual((outcome["outcome"], outcome["signals"]), ("terminated", ["SIGTERM"]))
        self.assertTrue(outcome["close_error"].startswith(str(errno.EINTR)))
        self.assertEqual(len(calls), 1, "close is not retried")

    def test_malformed_fdinfo_is_contained(self) -> None:
        class Fdinfo(FakeProbeAdapter):
            def __init__(self, text: str) -> None:
                super().__init__()
                self.text = text

            def read_text(self, relative: str) -> str:
                return self.text if relative.startswith("self/fdinfo/") else super().read_text(relative)

        self.assertEqual(Fdinfo("pos:\t0\nPid:\t42\n").pidfd_pid(3), 42)
        self.assertIsNone(Fdinfo("pos:\t0\n").pidfd_pid(3))
        for text in ("Pid:\t\n", "Pid:\t1 2\n", "Pid:\tx\n"):
            with self.subTest(text=text):
                with self.assertRaises(ValueError):
                    Fdinfo(text).pidfd_pid(3)
                with fake_probe_capabilities():
                    self.assertEqual(Fdinfo(text).supported(), (False, "pidfd-fdinfo-unavailable"))
        kernel = FakeKernel()
        kernel.pidfd_pid = lambda descriptor: (_ for _ in ()).throw(ValueError("malformed fdinfo Pid line"))  # type: ignore[method-assign]
        outcome = PidfdTerminator(kernel).terminate(registration(), grace_seconds=0)
        self.assertEqual(outcome["outcome"], "identity-unavailable")
        self.assertEqual(kernel.procs[PID].signals, [])

    def test_probe_close_failure_is_contained(self) -> None:
        closes: list[int] = []

        class FailingClose(FakeProbeAdapter):
            def close(self, descriptor: int) -> None:
                closes.append(descriptor)
                super().close(descriptor)
                raise InterruptedError(errno.EINTR, "Interrupted system call")

        with fake_probe_capabilities():
            supported, reason = FailingClose().supported()
        self.assertFalse(supported)
        self.assertTrue(reason.startswith("pidfd-probe-close-failed"))
        self.assertEqual(len(closes), 1, "the probe descriptor is closed once")

    def test_same_tick_replacement_is_a_documented_limit(self) -> None:
        """Known limit: /proc start time has one-tick resolution.

        A replacement with the same PID, birth tick, executable, UID and cwd is
        indistinguishable from the registered process, so it is signalled. The
        a trusted producer must bind the lifetime from spawn; this test
        pins the limit so a change in behavior is noticed.
        """
        kernel = FakeKernel()
        kernel.replace(same_tick=True)
        outcome = PidfdTerminator(kernel).terminate(registration(), grace_seconds=0)
        self.assertEqual(outcome["outcome"], "terminated")

    def test_capability_probe_contains_fdinfo_failures(self) -> None:
        closed: list[int] = []

        class BrokenFdinfo(FakeProbeAdapter):
            def __init__(self, failure: BaseException | None, text: str = "") -> None:
                super().__init__()
                self.failure, self.text = failure, text

            def read_text(self, relative: str) -> str:
                if relative.startswith("self/fdinfo/"):
                    if self.failure is not None:
                        raise self.failure
                    return self.text
                return super().read_text(relative)

            def close(self, descriptor: int) -> None:
                closed.append(descriptor)
                super().close(descriptor)

        for adapter in (BrokenFdinfo(PermissionError("denied")), BrokenFdinfo(None, "Pid:\tnot-a-number\n")):
            with self.subTest(adapter=adapter.failure or adapter.text):
                closed.clear()
                with fake_probe_capabilities():
                    self.assertEqual(adapter.supported(), (False, "pidfd-fdinfo-unavailable"))
                self.assertEqual(len(closed), 1, "the probe descriptor is closed")

    def test_unsupported_mechanism_and_exit_before_open(self) -> None:
        kernel = FakeKernel()
        kernel.is_supported = False
        self.assertEqual(PidfdTerminator(kernel).terminate(registration(), grace_seconds=0)["outcome"], "unavailable")
        self.assertEqual(kernel.opened, [])
        kernel = FakeKernel()
        kernel.procs[PID].alive = False
        self.assertEqual(PidfdTerminator(kernel).terminate(registration(), grace_seconds=0)["outcome"], "already-exited")


class TrustedSource:
    def __init__(self, registrations: list[TrustedRegistration]) -> None:
        self.registrations = registrations

    def trusted_registrations(self) -> list[TrustedRegistration]:
        return self.registrations


class CleanupWithTrustedSourceTests(unittest.TestCase):
    def run_cleanup(self, records: list[dict], kernel: FakeKernel, **overrides: object) -> dict:
        with tempfile.TemporaryDirectory() as tmpdir:
            state_dir = Path(tmpdir) / "state"
            state_dir.mkdir()
            (state_dir / "sessions.jsonl").write_text("".join(json.dumps(r) + "\n" for r in records), encoding="utf-8")
            process = ProcessInfo(pid=PID, ppid=1, elapsed_seconds=7200, stat="S", command="codex", args="codex", cwd="/work/repo")
            options = dict(
                processes=[process], state_dir=state_dir, workspace_root=Path("/work/repo"), stale_after_seconds=3600,
                protected_pids=set(), terminate_owned=True, terminate_unowned_codex=False, prune_state=True,
                dry_run=False, grace_seconds=0, ownership_source=TrustedSource([registration()]),
                terminator=PidfdTerminator(kernel),
            )
            options.update(overrides)
            return cleanup_stale_agents.cleanup(**options)

    def test_eligible_registered_incarnation_is_terminated(self) -> None:
        kernel = FakeKernel()
        result = self.run_cleanup([{"pid": PID, "session_id": "s-1"}], kernel)
        self.assertEqual(result["actions"][0]["action"], "termination-terminated")
        self.assertEqual(result["termination"]["status"], "attempted")
        self.assertEqual(result["termination"]["outcomes"], {"terminated": 1})
        self.assertEqual(result["termination"]["signals_sent"], 1)

    def test_fresh_incarnation_behind_a_stale_snapshot_is_spared(self) -> None:
        kernel = FakeKernel()
        kernel.uptime = 1.5  # the verified process is young, whatever ps said
        result = self.run_cleanup([{"pid": PID, "session_id": "s-1"}], kernel)
        self.assertEqual(result["actions"][0]["action"], "termination-not-stale")
        self.assertEqual(kernel.procs[PID].signals, [])

    def test_session_mismatch_and_missing_registration_are_refused(self) -> None:
        for records, source, reason in (
            ([{"pid": PID, "session_id": "old-session"}], TrustedSource([registration()]), "session-mismatch"),
            ([{"pid": PID}], TrustedSource([registration()]), "session-mismatch"),
            ([{"pid": PID, "session_id": "s-1"}], TrustedSource([]), "not-in-trusted-registry"),
        ):
            with self.subTest(reason=reason, records=records):
                kernel = FakeKernel()
                result = self.run_cleanup(records, kernel, ownership_source=source)
                self.assertEqual(result["actions"][0]["reason"], reason)
                self.assertEqual(result["termination"]["refusals"], 1)
                self.assertEqual(kernel.opened, [])

    def test_duplicate_records_never_reopen_the_pid(self) -> None:
        kernel = FakeKernel()
        kernel.procs[PID].exits_on = set()  # survives both signals
        result = self.run_cleanup([{"pid": PID, "session_id": "s-1"}, {"pid": PID, "session_id": "s-1"}], kernel)
        self.assertEqual(kernel.opened, [PID])
        self.assertEqual([a["action"] for a in result["actions"]], ["termination-still-running", "termination-duplicate-record"])

    def test_dry_run_and_unsupported_mechanism_report_honestly(self) -> None:
        kernel = FakeKernel()
        dry = self.run_cleanup([{"pid": PID, "session_id": "s-1"}], kernel, dry_run=True)
        self.assertEqual((dry["termination"]["status"], kernel.opened), ("dry-run", []))
        kernel = FakeKernel()
        kernel.is_supported = False
        unsupported = self.run_cleanup([{"pid": PID, "session_id": "s-1"}], kernel)
        self.assertEqual(unsupported["termination"]["status"], "unavailable")
        self.assertFalse(unsupported["termination"]["available"])
        self.assertTrue(unsupported["termination"]["reasons"]["owned"].startswith("mechanism-unsupported"))
        self.assertEqual(kernel.opened, [])

    def test_runtime_unavailability_is_reported_in_both_modes(self) -> None:
        kernel = FakeKernel()
        kernel.open_error = OSError(errno.EMFILE, "Too many open files")
        result = self.run_cleanup([{"pid": PID, "session_id": "s-1"}], kernel)
        action = result["actions"][0]
        self.assertEqual(action["action"], "termination-unavailable")
        self.assertTrue(action["reason"].startswith("pidfd-open-failed"))
        termination = result["termination"]
        self.assertEqual((termination["status"], termination["available"], termination["refusals"]), ("attempted", False, 0))
        self.assertTrue(termination["reasons"]["owned"].startswith("mechanism-unavailable-at-runtime"))
        self.assertEqual(termination["outcomes"], {"unavailable": 1})
        self.assertEqual(len(kernel.opened), 1)
        for mode in (["--json"], []):
            with self.subTest(mode=mode):
                broken = FakeKernel()
                broken.open_error = OSError(errno.EMFILE, "Too many open files")
                code, output = self.run_main(broken, [{"pid": PID, "session_id": "s-1"}], mode)
                self.assertEqual(code, cleanup_stale_agents.TERMINATION_REFUSED_EXIT)
                if not mode:
                    self.assertIn("termination-unavailable (pidfd-open-failed", output)
                    self.assertIn("no process was signalled", output)

    def test_unavailable_signalling_syscall_is_reported_unavailable(self) -> None:
        kernel = FakeKernel()
        kernel.send_errors[signal.SIGTERM] = OSError(errno.ENOSYS, "not implemented")
        termination = self.run_cleanup([{"pid": PID, "session_id": "s-1"}], kernel)["termination"]
        self.assertFalse(termination["available"])
        self.assertIn("pidfd-send-signal-unavailable", termination["reasons"]["owned"])
        self.assertEqual((termination["outcomes"], termination["signals_sent"]), ({"unavailable": 1}, 0))

    def test_invalid_registry_pids_never_abort_the_run(self) -> None:
        kernel = FakeKernel()
        with tempfile.TemporaryDirectory() as tmpdir:
            state_dir = Path(tmpdir) / "state"
            state_dir.mkdir()
            lines = [json.dumps({"pid": PID, "session_id": "s-1"}), '{"pid": 1e999}']
            lines += [json.dumps({"pid": value}) for value in ("abc", True, -5, 0, 4194305, "12 ", 4242.0, None)]
            (state_dir / "sessions.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8")
            process = ProcessInfo(pid=PID, ppid=1, elapsed_seconds=7200, stat="S", command="codex", args="codex", cwd="/work/repo")
            result = cleanup_stale_agents.cleanup(
                processes=[process], state_dir=state_dir, workspace_root=Path("/work/repo"), stale_after_seconds=3600,
                protected_pids=set(), terminate_owned=True, terminate_unowned_codex=False, prune_state=True,
                dry_run=False, grace_seconds=0, ownership_source=TrustedSource([registration()]),
                terminator=PidfdTerminator(kernel),
            )
        reasons = [a.get("reason") for a in result["actions"] if a["action"] == "prune-record"]
        self.assertEqual(result["actions"][0]["action"], "termination-terminated")
        # 1e999 is not strict JSON, so that line is kept as an invalid record.
        self.assertEqual(result["actions"][1], {"action": "keep-invalid-record", "line_number": 2})
        self.assertEqual(reasons, ["invalid-pid"] * 7 + ["missing-pid"])
        self.assertEqual(result["termination"]["signals_sent"], 1)

    def test_hostile_registry_lines_keep_a_strict_json_report(self) -> None:
        nested = "[" * 1000 + "]" * 1000
        records = [
            {"pid": PID, "session_id": "s-1"},
            {"pid": "9" * 5000},
        ]
        extra_lines = ['{"pid": 1e999, "x": NaN}', '{"pid": ' + nested + "}", '{"pid": "4242", "session_id": "s-1"}']
        with tempfile.TemporaryDirectory() as tmpdir:
            state_dir = Path(tmpdir) / "state"
            state_dir.mkdir()
            text = "".join(json.dumps(r) + "\n" for r in records) + "\n".join(extra_lines) + "\n"
            (state_dir / "sessions.jsonl").write_text(text, encoding="utf-8")
            process = ProcessInfo(pid=PID, ppid=1, elapsed_seconds=7200, stat="S", command="codex", args="codex", cwd="/work/repo")
            original = cleanup_stale_agents.cleanup

            def patched(**kwargs: object) -> dict:
                kwargs.update(ownership_source=TrustedSource([registration()]), terminator=PidfdTerminator(FakeKernel()))
                return original(**kwargs)

            output = io.StringIO()
            with unittest.mock.patch.object(cleanup_stale_agents, "discover_processes", return_value=[process]), \
                    unittest.mock.patch.object(cleanup_stale_agents, "ancestor_pids", return_value=set()), \
                    unittest.mock.patch.object(cleanup_stale_agents, "cleanup", side_effect=patched), \
                    contextlib.redirect_stdout(output):
                code = cleanup_stale_agents.main(["--state-dir", str(state_dir), "--terminate-owned", "--json"])

        def strict(name: str) -> object:
            raise ValueError(name)

        report = json.loads(output.getvalue(), parse_constant=strict)
        actions = [(a["action"], a.get("reason"), a.get("line_number")) for a in report["actions"]]
        self.assertEqual(actions[0][0], "termination-terminated")
        self.assertIn(("prune-record", "invalid-pid", 2), actions)
        self.assertIn(("keep-invalid-record", None, 3), actions)
        self.assertIn(("keep-invalid-record", None, 4), actions)
        self.assertIn(("termination-duplicate-record", None, None), actions)
        self.assertEqual(report["termination"]["signals_sent"], 1)
        self.assertEqual(code, 0)

    def test_unresolvable_workspace_root_keeps_earlier_outcomes(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            loop = base / "loop"
            loop.symlink_to(loop)  # resolves forever: RuntimeError on 3.12, OSError later
            state_dir = base / "state"
            state_dir.mkdir()
            (state_dir / "sessions.jsonl").write_text(json.dumps({"pid": PID, "session_id": "s-1"}) + "\n", encoding="utf-8")
            owned = ProcessInfo(pid=PID, ppid=1, elapsed_seconds=7200, stat="S", command="codex", args="codex", cwd="/work/repo")
            unowned = ProcessInfo(pid=PID + 7, ppid=1, elapsed_seconds=7200, stat="S", command="codex", args="codex exec", cwd=str(loop))
            original = cleanup_stale_agents.cleanup

            def patched(**kwargs: object) -> dict:
                kwargs.update(ownership_source=TrustedSource([registration()]), terminator=PidfdTerminator(FakeKernel()))
                return original(**kwargs)

            output = io.StringIO()
            with unittest.mock.patch.object(cleanup_stale_agents, "discover_processes", return_value=[owned, unowned]), \
                    unittest.mock.patch.object(cleanup_stale_agents, "ancestor_pids", return_value=set()), \
                    unittest.mock.patch.object(cleanup_stale_agents, "cleanup", side_effect=patched), \
                    contextlib.redirect_stdout(output):
                code = cleanup_stale_agents.main(["--state-dir", str(state_dir), "--workspace-root", str(loop),
                                                  "--terminate-owned", "--terminate-unowned-codex", "--json"])
        report = json.loads(output.getvalue(), parse_constant=lambda name: (_ for _ in ()).throw(ValueError(name)))
        self.assertEqual(report["actions"][0]["action"], "termination-terminated")
        self.assertEqual(report["termination"]["signals_sent"], 1)
        self.assertEqual(code, cleanup_stale_agents.TERMINATION_UNAVAILABLE_EXIT)

    def test_non_object_registry_lines_are_kept_as_invalid(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            state_dir = Path(tmpdir)
            (state_dir / "sessions.jsonl").write_text('[1, 2]\n"text"\n7\n{"pid": 1}\n', encoding="utf-8")
            numbered = cleanup_stale_agents.load_record_lines(state_dir)
        self.assertEqual([number for number, record in numbered if record.get("invalid")], [1, 2, 3])
        self.assertEqual(numbered[3], (4, {"pid": 1}))

    def test_probe_close_failure_on_a_later_target_keeps_earlier_outcomes(self) -> None:
        class FlakyProbe(FakeKernel):
            def __init__(self) -> None:
                super().__init__()
                self.probes = 0

            def supported(self) -> tuple[bool, str]:
                self.probes += 1
                return (True, "pidfd-available") if self.probes <= 2 else (False, "pidfd-probe-close-failed: Interrupted system call")

        kernel = FlakyProbe()
        second = Incarnation(PID + 1, start_ticks=100)
        kernel.procs[PID + 1] = second
        with tempfile.TemporaryDirectory() as tmpdir:
            state_dir = Path(tmpdir) / "state"
            state_dir.mkdir()
            records = [{"pid": PID, "session_id": "s-1"}, {"pid": PID + 1, "session_id": "s-2"}]
            (state_dir / "sessions.jsonl").write_text("".join(json.dumps(r) + "\n" for r in records), encoding="utf-8")
            processes = [ProcessInfo(pid=pid, ppid=1, elapsed_seconds=7200, stat="S", command="codex", args="codex", cwd="/work/repo") for pid in (PID, PID + 1)]
            result = cleanup_stale_agents.cleanup(
                processes=processes, state_dir=state_dir, workspace_root=Path("/work/repo"), stale_after_seconds=3600,
                protected_pids=set(), terminate_owned=True, terminate_unowned_codex=False, prune_state=True,
                dry_run=False, grace_seconds=0,
                ownership_source=TrustedSource([registration(), registration(pid=PID + 1, session_id="s-2")]),
                terminator=PidfdTerminator(kernel),
            )
        self.assertEqual([a["action"] for a in result["actions"]], ["termination-terminated", "termination-unavailable"])
        self.assertEqual(result["termination"]["signals_sent"], 1)
        self.assertEqual(second.signals, [])

    def test_registry_write_failure_keeps_the_report(self) -> None:
        for failure in (PermissionError(errno.EACCES, "Permission denied"), OSError(errno.ENOSPC, "No space left on device")):
            with self.subTest(failure=failure):
                kernel = FakeKernel()
                with unittest.mock.patch.object(cleanup_stale_agents, "write_records", side_effect=failure):
                    result = self.run_cleanup([{"pid": PID, "session_id": "s-1"}], kernel)
                self.assertEqual(result["state_persistence"]["status"], "failed")
                self.assertEqual(result["actions"][0]["action"], "termination-terminated")
                self.assertEqual(result["termination"]["signals_sent"], 1)
                for mode in (["--json"], []):
                    with unittest.mock.patch.object(cleanup_stale_agents, "write_records", side_effect=failure):
                        code, output = self.run_main(FakeKernel(), [{"pid": PID, "session_id": "s-1"}], mode)
                    self.assertEqual(code, cleanup_stale_agents.STATE_WRITE_FAILED_EXIT)
                    if mode:
                        self.assertEqual(json.loads(output)["state_persistence"]["status"], "failed")
                    else:
                        self.assertIn("session registry was not rewritten", output)
                        self.assertIn("1 signal(s) sent", output)

    def test_unconfirmed_binding_keeps_the_record(self) -> None:
        kernel = FakeKernel()
        kernel.fdinfo_pid = 0
        with tempfile.TemporaryDirectory() as tmpdir:
            state_dir = Path(tmpdir) / "state"
            state_dir.mkdir()
            (state_dir / "sessions.jsonl").write_text(json.dumps({"pid": PID, "session_id": "s-1"}) + "\n", encoding="utf-8")
            process = ProcessInfo(pid=PID, ppid=1, elapsed_seconds=7200, stat="S", command="codex", args="codex", cwd="/work/repo")
            result = cleanup_stale_agents.cleanup(
                processes=[process], state_dir=state_dir, workspace_root=Path("/work/repo"), stale_after_seconds=3600,
                protected_pids=set(), terminate_owned=True, terminate_unowned_codex=False, prune_state=True,
                dry_run=False, grace_seconds=0, ownership_source=TrustedSource([registration()]),
                terminator=PidfdTerminator(kernel),
            )
            kept = (state_dir / "sessions.jsonl").read_text(encoding="utf-8")
        self.assertEqual(result["actions"][0]["action"], "termination-identity-unavailable")
        self.assertEqual(result["summary"]["records_after"], 1)
        self.assertIn('"session_id": "s-1"', kept)

    def test_poll_errors_keep_the_live_target_record(self) -> None:
        for mask in (
            select.POLLNVAL, select.POLLERR,
            select.POLLIN | select.POLLNVAL, select.POLLIN | select.POLLERR,
        ):
            with self.subTest(mask=mask):
                kernel = FakeKernel()
                kernel.procs[PID].exits_on = set()
                kernel.wait_exit = lambda descriptor, timeout: ProcAdapter.wait_exit(kernel, descriptor, timeout)
                poller = unittest.mock.Mock()
                poller.poll.side_effect = lambda milliseconds: [(kernel.next_fd, mask)]
                with unittest.mock.patch.object(select, "poll", return_value=poller):
                    result = self.run_cleanup([{"pid": PID, "session_id": "s-1"}], kernel)
                self.assertEqual(result["actions"][0]["action"], "termination-wait-failed")
                self.assertEqual(result["summary"]["records_after"], 1)
                self.assertEqual(result["termination"]["signals_sent"], 1)
                self.assertTrue(kernel.procs[PID].alive)
                self.assertEqual(kernel.procs[PID].signals, [signal.SIGTERM])

    def test_mixed_scopes_report_actual_signals(self) -> None:
        kernel = FakeKernel()
        result = self.run_cleanup([{"pid": PID, "session_id": "s-1"}], kernel, terminate_unowned_codex=True)
        termination = result["termination"]
        self.assertEqual(termination["status"], "partially-unavailable")
        self.assertEqual(termination["scopes"]["owned"]["status"], "attempted")
        self.assertEqual(termination["scopes"]["unowned"]["status"], "unavailable")
        self.assertEqual(termination["signals_sent"], 1)
        code, output = self.run_main(FakeKernel(), [{"pid": PID, "session_id": "s-1"}], ["--terminate-unowned-codex"])
        self.assertEqual(code, cleanup_stale_agents.TERMINATION_UNAVAILABLE_EXIT)
        self.assertIn("unowned: no-exact-target-authority", output)
        self.assertIn("1 signal(s) sent", output)
        self.assertNotIn("no process was signalled", output)

    def test_protected_process_never_reaches_the_terminator(self) -> None:
        kernel = FakeKernel()
        result = self.run_cleanup([{"pid": PID, "session_id": "s-1"}], kernel, protected_pids={PID})
        self.assertEqual(result["actions"][0]["action"], "protect")
        self.assertEqual(kernel.opened, [])
        self.assertEqual(result["termination"]["status"], "no-eligible-target")

    def run_main(self, kernel: FakeKernel, records: list[dict], extra: list[str]) -> tuple[int, str]:
        with tempfile.TemporaryDirectory() as tmpdir:
            state_dir = Path(tmpdir) / "state"
            state_dir.mkdir()
            (state_dir / "sessions.jsonl").write_text("".join(json.dumps(r) + "\n" for r in records), encoding="utf-8")
            process = ProcessInfo(pid=PID, ppid=1, elapsed_seconds=7200, stat="S", command="codex", args="codex", cwd="/work/repo")
            original = cleanup_stale_agents.cleanup

            def patched(**kwargs: object) -> dict:
                kwargs.update(ownership_source=TrustedSource([registration()]), terminator=PidfdTerminator(kernel))
                return original(**kwargs)

            output = io.StringIO()
            with unittest.mock.patch.object(cleanup_stale_agents, "discover_processes", return_value=[process]), \
                    unittest.mock.patch.object(cleanup_stale_agents, "ancestor_pids", return_value=set()), \
                    unittest.mock.patch.object(cleanup_stale_agents, "cleanup", side_effect=patched), \
                    contextlib.redirect_stdout(output):
                code = cleanup_stale_agents.main(["--state-dir", str(state_dir), "--terminate-owned", *extra])
            return code, output.getvalue()

    def test_exit_codes_reflect_outcomes(self) -> None:
        def main_with(kernel: FakeKernel, records: list[dict]) -> int:
            with tempfile.TemporaryDirectory() as tmpdir:
                state_dir = Path(tmpdir) / "state"
                state_dir.mkdir()
                (state_dir / "sessions.jsonl").write_text("".join(json.dumps(r) + "\n" for r in records), encoding="utf-8")
                process = ProcessInfo(pid=PID, ppid=1, elapsed_seconds=7200, stat="S", command="codex", args="codex", cwd="/work/repo")
                original = cleanup_stale_agents.cleanup

                def patched(**kwargs: object) -> dict:
                    kwargs.update(ownership_source=TrustedSource([registration()]), terminator=PidfdTerminator(kernel))
                    return original(**kwargs)

                with unittest.mock.patch.object(cleanup_stale_agents, "discover_processes", return_value=[process]), \
                        unittest.mock.patch.object(cleanup_stale_agents, "ancestor_pids", return_value=set()), \
                        unittest.mock.patch.object(cleanup_stale_agents, "cleanup", side_effect=patched), \
                        contextlib.redirect_stdout(io.StringIO()):
                    return cleanup_stale_agents.main(["--state-dir", str(state_dir), "--terminate-owned", "--json"])

        self.assertEqual(main_with(FakeKernel(), [{"pid": PID, "session_id": "s-1"}]), 0)
        self.assertEqual(main_with(FakeKernel(), [{"pid": PID, "session_id": "stale"}]), cleanup_stale_agents.TERMINATION_REFUSED_EXIT)
        unsupported = FakeKernel()
        unsupported.is_supported = False
        self.assertEqual(main_with(unsupported, [{"pid": PID, "session_id": "s-1"}]), cleanup_stale_agents.TERMINATION_UNAVAILABLE_EXIT)


@unittest.skipUnless(hasattr(os, "pidfd_open") and hasattr(signal, "pidfd_send_signal"), "pidfd unsupported")
class RealPidfdChildTests(unittest.TestCase):
    """Bounded test of the real mechanism against this test's own child process."""

    def spawn(self) -> subprocess.Popen:
        return subprocess.Popen(["sleep", "30"], cwd=os.path.realpath(tempfile.gettempdir()))

    def registration_for(self, child: subprocess.Popen, **overrides: object) -> TrustedRegistration:
        observed = observe_identity(child.pid, ProcAdapter())
        values = dict(
            pid=child.pid, boot_id=observed.boot_id, pid_namespace=observed.pid_namespace,
            start_ticks=observed.start_ticks, executable=observed.executable, uid=observed.uid,
            workspace=observed.cwd, session_id="real", producer="test",
        )
        values.update(overrides)
        return TrustedRegistration(**values)

    def test_real_adapter_is_supported_here(self) -> None:
        self.assertEqual(ProcAdapter().supported(), (True, "pidfd-available"))

    def test_matching_registration_terminates_exactly_the_child(self) -> None:
        child = self.spawn()
        try:
            outcome = PidfdTerminator().terminate(self.registration_for(child), grace_seconds=5)
            self.assertEqual(outcome["outcome"], "terminated")
            self.assertEqual(child.wait(timeout=5), -signal.SIGTERM)
        finally:
            if child.poll() is None:
                child.kill()
                child.wait(timeout=5)

    def test_wrong_start_time_and_young_age_leave_the_child_running(self) -> None:
        child = self.spawn()
        try:
            stale = self.registration_for(child)
            wrong = TrustedRegistration(**{**stale.__dict__, "start_ticks": stale.start_ticks - 1})
            self.assertEqual(PidfdTerminator().terminate(wrong, grace_seconds=1)["outcome"], "identity-mismatch")
            young = PidfdTerminator().terminate(stale, grace_seconds=1, min_age_seconds=3600)
            self.assertEqual(young["outcome"], "not-stale")
            self.assertIsNone(child.poll(), "the child must still be running")
        finally:
            child.kill()
            child.wait(timeout=5)


if __name__ == "__main__":
    unittest.main()
