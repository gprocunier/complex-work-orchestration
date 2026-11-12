from __future__ import annotations

import contextlib
import errno
import os
import signal
import sys
import unittest
from dataclasses import asdict, dataclass, field, replace
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import cleanup_stale_agents as cleanup_module  # noqa: E402
from cwo_core.ownership_producer import ExpectedSpawn, OfflineOwnershipProducer, OfflineSession  # noqa: E402
from cwo_core.process_identity import NoTrustedOwnershipSource, ProcAdapter  # noqa: E402

BOOT = "EXAMPLE-boot"
NS = "pid:[EXAMPLE-namespace]"
TARGET, CONTROLLER, PARENT = 424200, 424201, 424202
DEFAULT = object()


def expected(**changes):
    values = dict(
        session_id="EXAMPLE-session", workspace="/EXAMPLE/work", executable="/EXAMPLE/bin/worker",
        uid=43210, boot_id=BOOT, pid_namespace=NS,
    )
    values.update(changes)
    return ExpectedSpawn(**values)


def stat_line(process):
    fields = ["S", str(process.ppid)] + ["0"] * 17 + [str(process.start_ticks)]
    return f"{process.pid} ({process.comm}) " + " ".join(fields)


@dataclass
class FakeProcess:
    pid: int
    ppid: int = 0
    start_ticks: int = 100
    executable: str = "/EXAMPLE/bin/worker"
    cwd: str = "/EXAMPLE/work"
    uid: int = 43210
    namespace: str = NS
    comm: str = "EXAMPLE worker (fake)"
    argv: str = "EXAMPLE worker"
    alive: bool = True
    exits_on: set[int] = field(default_factory=lambda: {signal.SIGTERM})
    signals: list[int] = field(default_factory=list)


class FakeTable(ProcAdapter):
    """All operations use memory, including capability and birth claims."""

    offline_only = True

    def __init__(self):
        self.procs = {CONTROLLER: FakeProcess(CONTROLLER, PARENT), PARENT: FakeProcess(PARENT)}
        self.handles = {}
        self.births = {}
        self.writer = None
        self.next_fd = 80
        self.spawn_pid = TARGET
        self.spawn_calls = []
        self.closes = []
        self.waits = []
        self.opens = []
        self.probes = 0
        self.available = True
        self.boot = BOOT
        self.namespace = NS
        self.uptime = 10000.0
        self.hz = 100
        self.binding = DEFAULT
        self.binding_calls = 0
        self.stat_override = None
        self.status_override = None
        self.read_errors = {}
        self.signal_errors = {}
        self.wait_error = None
        self.close_error = None
        self.wait_result = DEFAULT
        self.hooks = {}
        self.send_signal = mock.Mock(wraps=self.send_signal)

    def fire(self, name):
        hook = self.hooks.pop(name, None)
        if hook is not None:
            hook()

    def claim_writer(self, writer):
        if self.writer is not None:
            return False
        self.writer = writer
        return True

    def claim_spawn(self, pid, descriptor, writer):
        birth = self.births.get(descriptor)
        if writer is not self.writer or birth is None or birth.pid != pid:
            return False
        self.births.pop(descriptor)
        self.fire("claimed")
        return True

    def offline_supported(self):
        self.fire("capability")
        return self.available, "EXAMPLE fake capability"

    def supported(self):
        self.probes += 1
        raise AssertionError("Offline code must not run a kernel capability probe.")

    def pidfd_open(self, pid):
        self.opens.append(pid)
        raise AssertionError("Offline code must not open a known PID.")

    def spawn(self, specification):
        self.spawn_calls.append(specification)
        old = self.procs.get(self.spawn_pid)
        if old is not None:
            old.alive = False
        process = FakeProcess(self.spawn_pid)
        self.procs[process.pid] = process
        self.next_fd += 1
        self.handles[self.next_fd] = process
        self.births[self.next_fd] = process
        self.fire("after_spawn")
        return process.pid, self.next_fd

    def reuse(self, same_tick=False):
        old = self.procs[TARGET]
        old.alive = False
        fresh = replace(old, start_ticks=old.start_ticks + (0 if same_tick else 500), alive=True, signals=[])
        self.procs[TARGET] = fresh
        return fresh

    def process(self, pid):
        process = self.procs.get(pid)
        if process is None or not process.alive:
            raise FileNotFoundError("EXAMPLE fake process is absent.")
        return process

    def read_text(self, relative):
        self.fire(relative)
        if relative in self.read_errors:
            raise self.read_errors[relative]
        if relative == "sys/kernel/random/boot_id":
            return self.boot
        pid_text, _, leaf = relative.partition("/")
        process = self.process(int(pid_text))
        if leaf == "stat":
            if process.pid == TARGET and self.stat_override is not None:
                return self.stat_override
            return stat_line(process)
        if leaf == "status":
            if process.pid == TARGET and self.status_override is not None:
                return self.status_override
            return f"Uid:\t{process.uid}\n"
        raise FileNotFoundError(relative)

    def readlink(self, relative):
        self.fire(relative)
        pid_text, _, leaf = relative.partition("/")
        process = self.process(int(pid_text))
        return {"ns/pid": process.namespace, "exe": process.executable, "cwd": process.cwd}[leaf]

    def own_pid_namespace(self):
        self.fire("namespace")
        return self.namespace

    def pidfd_pid(self, descriptor):
        self.binding_calls += 1
        self.fire(f"binding:{self.binding_calls}")
        if self.binding is not DEFAULT:
            return self.binding
        process = self.handles[descriptor]
        return process.pid if process.alive else -1

    def uptime_seconds(self):
        self.fire("uptime")
        return self.uptime

    def clock_ticks(self):
        self.fire("ticks")
        return self.hz

    def send_signal(self, descriptor, signum):
        self.fire(f"before_{signal.Signals(signum).name}")
        if signum in self.signal_errors:
            raise self.signal_errors[signum]
        process = self.handles[descriptor]
        if not process.alive:
            raise ProcessLookupError("EXAMPLE original process exited.")
        process.signals.append(signum)
        if signum in process.exits_on:
            process.alive = False

    def wait_exit(self, descriptor, timeout_seconds):
        self.waits.append((descriptor, timeout_seconds))
        self.fire("wait")
        if self.wait_error is not None:
            raise self.wait_error
        if self.wait_result is not DEFAULT:
            return self.wait_result
        return not self.handles[descriptor].alive

    def close(self, descriptor):
        self.closes.append(descriptor)
        self.fire("close")
        self.handles.pop(descriptor)
        if self.close_error is not None:
            raise self.close_error


class OwnershipProducerTests(unittest.TestCase):
    def setUp(self):
        self.stack = contextlib.ExitStack()
        self.real_spies = []
        self.tables = []
        for module, name in ((os, "kill"), (os, "killpg"), (os, "pidfd_open"), (signal, "pidfd_send_signal")):
            spy = self.stack.enter_context(mock.patch.object(
                module, name, create=True, side_effect=AssertionError("No real process operation is allowed."),
            ))
            self.real_spies.append(spy)

    def tearDown(self):
        try:
            for spy in self.real_spies:
                spy.assert_not_called()
            for table in self.tables:
                self.assertEqual(table.opens, [])
                self.assertEqual(table.probes, 0)
        finally:
            self.stack.close()

    def make(self):
        table = FakeTable()
        self.tables.append(table)
        producer = OfflineOwnershipProducer(table, controller_pid=CONTROLLER, name="EXAMPLE-controller")
        self.addCleanup(producer.close)
        return table, producer

    def registered(self):
        table, producer = self.make()
        report = producer.register_from_spawn(expected(), table.spawn)
        self.assert_report(report, "registered")
        return table, producer, report["session"]

    def assert_report(self, report, outcome):
        self.assertEqual(report["outcome"], outcome)
        self.assertIs(report["offline_only"], True)
        self.assertIs(report["production_authority"], False)
        self.assertEqual(report["default_cleanup_consumer"], "none")

    def test_positive_birth_registration_and_exact_same_handle_escalation(self):
        table, producer, session = self.registered()
        record = session.registration
        self.assertEqual(
            (record.pid, record.start_ticks, record.boot_id, record.pid_namespace, record.uid),
            (TARGET, 100, BOOT, NS, 43210),
        )
        self.assertEqual((record.workspace, record.executable), (expected().workspace, expected().executable))
        self.assertEqual((record.session_id, record.producer), ("EXAMPLE-session", "EXAMPLE-controller"))
        descriptor = table.next_fd
        original = table.handles[descriptor]
        original.exits_on = {signal.SIGKILL}
        report = producer.terminate(session, grace_seconds=0.25, allow_kill=True)
        self.assert_report(report, "killed")
        self.assertEqual(report["signals"], ["SIGTERM", "SIGKILL"])
        self.assertEqual(table.send_signal.call_args_list, [
            mock.call(descriptor, signal.SIGTERM), mock.call(descriptor, signal.SIGKILL),
        ])
        self.assertEqual(table.waits, [(descriptor, 0.25), (descriptor, 0.25)])
        self.assertEqual(original.signals, [signal.SIGTERM, signal.SIGKILL])
        self.assertEqual(table.closes, [descriptor])
        self.assert_report(producer.terminate(session, grace_seconds=0), "invalid-session")
        self.assert_report(producer.register_from_spawn(expected(), table.spawn), "duplicate-session")
        producer.close()
        self.assertEqual(table.closes, [descriptor])

    def test_term_only_and_explicit_close_are_one_use(self):
        table, producer, session = self.registered()
        table.procs[TARGET].exits_on = set()
        report = producer.terminate(session, grace_seconds=0)
        self.assert_report(report, "still-running")
        self.assertEqual(report["signals"], ["SIGTERM"])
        self.assertEqual(table.send_signal.call_count, 1)
        other_table, other, _ = self.registered()
        descriptor = other_table.next_fd
        self.assert_report(other.close(), "closed")
        other.close()
        self.assertEqual(other_table.closes, [descriptor])
        other_table.send_signal.assert_not_called()
        self.assert_report(other.register_from_spawn(expected(), other_table.spawn), "producer-closed")

    def test_every_expected_context_field_is_independent(self):
        cases = (
            {"boot_id": "EXAMPLE-other-boot"}, {"pid_namespace": "pid:[EXAMPLE-other]"},
            {"uid": 43211}, {"executable": "/EXAMPLE/bin/unrelated"},
            {"workspace": "/EXAMPLE/other"}, {"workspace": "/EXAMPLE"},
        )
        for changes in cases:
            with self.subTest(changes=changes):
                table, producer = self.make()
                report = producer.register_from_spawn(expected(**changes), table.spawn)
                self.assert_report(report, "identity-mismatch")
                table.send_signal.assert_not_called()
                self.assertEqual(table.closes, [table.next_fd])

    def test_invalid_specifications_do_not_spawn(self):
        cases = (
            None, {}, expected(session_id=""), expected(session_id=True), expected(boot_id=""),
            expected(pid_namespace=None), expected(uid=True), expected(uid=-1),
            expected(workspace="EXAMPLE/relative"), expected(workspace="/EXAMPLE/work/"),
            expected(executable=42), expected(executable="/EXAMPLE/bin/../worker"),
        )
        for specification in cases:
            with self.subTest(specification=specification):
                table, producer = self.make()
                self.assert_report(producer.register_from_spawn(specification, table.spawn), "invalid-request")
                self.assertEqual(table.spawn_calls, [])
                self.assertEqual(table.closes, [])
                table.send_signal.assert_not_called()

    def test_missing_malformed_and_foreign_receipts_send_nothing(self):
        table, producer, session = self.registered()
        foreign_table, foreign, foreign_session = self.registered()
        bogus = (None, {}, asdict(session), session.registration, OfflineSession(None),
                 OfflineSession(session.registration), foreign_session, table.next_fd)
        for receipt in bogus:
            self.assert_report(producer.terminate(receipt, grace_seconds=0), "invalid-session")
        table.send_signal.assert_not_called()
        foreign_table.send_signal.assert_not_called()
        self.assertEqual(table.closes, [])
        self.assert_report(foreign.terminate(foreign_session, grace_seconds=0), "terminated")
        self.assertEqual(foreign_table.send_signal.call_count, 1)

    def test_altered_registration_is_refused(self):
        table, producer, session = self.registered()
        object.__setattr__(session.registration, "uid", True)
        report = producer.terminate(session, grace_seconds=0)
        self.assert_report(report, "invalid-session")
        table.send_signal.assert_not_called()
        self.assertEqual(table.closes, [table.next_fd])

    def test_duplicate_sessions_handles_and_writers_are_refused(self):
        table, producer, session = self.registered()
        self.assert_report(producer.register_from_spawn(expected(), table.spawn), "duplicate-session")
        descriptor = table.next_fd
        report = producer.register_from_spawn(expected(session_id="EXAMPLE-second"), lambda spec: (TARGET, descriptor))
        self.assert_report(report, "invalid-spawn")
        self.assertEqual(len(table.spawn_calls), 1)
        self.assertEqual(table.closes, [])
        with self.assertRaises(ValueError):
            OfflineOwnershipProducer(table, controller_pid=CONTROLLER, name="EXAMPLE-second-controller")
        table.send_signal.assert_not_called()
        self.assert_report(producer.terminate(session, grace_seconds=0), "terminated")

    def test_duplicate_pid_and_unclaimed_serialized_handle_are_refused(self):
        table, producer, _ = self.registered()
        report = producer.register_from_spawn(expected(session_id="EXAMPLE-second"), table.spawn)
        self.assert_report(report, "duplicate-target")
        self.assertEqual(table.closes, [table.next_fd])
        report = producer.register_from_spawn(
            expected(session_id="EXAMPLE-import"), lambda spec: (TARGET, 987654),
        )
        self.assert_report(report, "invalid-spawn")
        table.send_signal.assert_not_called()

    def test_malformed_spawn_results_have_no_handle_transfer(self):
        for result in (None, {}, (TARGET,), (TARGET, True), (True, 81), (TARGET, -1)):
            table, producer = self.make()
            self.assert_report(producer.register_from_spawn(expected(), lambda spec: result), "invalid-spawn")
            self.assertEqual(table.closes, [])
            table.send_signal.assert_not_called()

    def test_protected_controller_ancestor_and_changed_tree(self):
        for pid in (CONTROLLER, PARENT):
            table, producer = self.make()
            table.spawn_pid = pid
            self.assert_report(producer.register_from_spawn(expected(), table.spawn), "protected")
            table.send_signal.assert_not_called()
        table, producer, session = self.registered()
        table.procs[CONTROLLER].ppid = TARGET
        self.assert_report(producer.terminate(session, grace_seconds=0), "protected")
        table.send_signal.assert_not_called()

    def test_inaccessible_or_ambiguous_controller_tree_is_refused(self):
        for mode in ("missing", "cycle", "malformed"):
            table, producer = self.make()
            if mode == "missing":
                table.procs.pop(PARENT)
            elif mode == "cycle":
                table.procs[PARENT].ppid = CONTROLLER
            else:
                table.procs[PARENT].ppid = -1
            self.assert_report(producer.register_from_spawn(expected(), table.spawn), "identity-unavailable")
            self.assertEqual(table.spawn_calls, [])
            table.send_signal.assert_not_called()

    def test_exit_and_same_tick_reuse_at_spawn_observation_and_first_signal(self):
        stages = ("after_spawn", "claimed", f"{TARGET}/stat", "binding:2", "before_SIGTERM")
        for stage in stages:
            for replacing in (False, True):
                table, producer = self.make()
                action = (lambda: table.reuse(same_tick=True)) if replacing else (lambda: setattr(table.procs[TARGET], "alive", False))
                if stage == "before_SIGTERM":
                    session = producer.register_from_spawn(expected(), table.spawn)["session"]
                    table.hooks[stage] = action
                    report = producer.terminate(session, grace_seconds=0, allow_kill=True)
                else:
                    table.hooks[stage] = action
                    report = producer.register_from_spawn(expected(), table.spawn)
                self.assertEqual(report["signals"], [])
                self.assertEqual(table.procs[TARGET].signals, [])
                self.assertEqual(table.closes, [table.next_fd])

    def test_exit_and_reuse_during_termination_observation_send_nothing(self):
        for reuse in (False, True):
            table, producer, session = self.registered()
            original = table.procs[TARGET]
            action = table.reuse if reuse else lambda: setattr(original, "alive", False)
            table.hooks[f"{TARGET}/stat"] = action
            report = producer.terminate(session, grace_seconds=0, allow_kill=True)
            self.assertEqual(report["signals"], [])
            table.send_signal.assert_not_called()
            self.assertEqual(original.signals, [])
            self.assertEqual(table.procs[TARGET].signals, [])

    def test_reuse_between_term_and_kill_never_signals_replacement(self):
        for stage in ("wait", "before_SIGKILL"):
            table, producer, session = self.registered()
            original = table.procs[TARGET]
            original.exits_on = set()
            table.wait_result = False
            table.hooks[stage] = lambda: table.reuse(same_tick=True)
            report = producer.terminate(session, grace_seconds=0, allow_kill=True)
            self.assert_report(report, "terminated")
            self.assertEqual(report["signals"], ["SIGTERM"])
            self.assertEqual(original.signals, [signal.SIGTERM])
            self.assertEqual(table.procs[TARGET].signals, [])

    def test_changed_identity_and_codex_argument_never_establish_ownership(self):
        cases = (
            ("start_ticks", 101), ("uid", 43211), ("namespace", "pid:[EXAMPLE-other]"),
            ("cwd", "/EXAMPLE/work/child"), ("executable", "/EXAMPLE/bin/unrelated"),
        )
        for field_name, value in cases:
            table, producer, session = self.registered()
            process = table.procs[TARGET]
            process.argv = "EXAMPLE unrelated.py codex"
            setattr(process, field_name, value)
            self.assert_report(producer.terminate(session, grace_seconds=0), "identity-mismatch")
            table.send_signal.assert_not_called()
        for attribute, value in (("boot", "EXAMPLE-new-boot"), ("namespace", "pid:[EXAMPLE-new]")):
            table, producer, session = self.registered()
            setattr(table, attribute, value)
            self.assert_report(producer.terminate(session, grace_seconds=0), "identity-mismatch")
            table.send_signal.assert_not_called()

    def test_unconfirmed_handle_binding_never_signals(self):
        for binding in (None, 0, True, -2, TARGET + 20, -1):
            table, producer, session = self.registered()
            table.binding = binding
            report = producer.terminate(session, grace_seconds=0)
            self.assertEqual(report["signals"], [])
            table.send_signal.assert_not_called()

    def test_stat_names_parse_and_malformed_proc_fields_refuse(self):
        for comm in ("EXAMPLE worker", "EXAMPLE (nested) worker", "))(("):
            table, producer = self.make()
            table.hooks["after_spawn"] = lambda: setattr(table.procs[TARGET], "comm", comm)
            session = producer.register_from_spawn(expected(), table.spawn)["session"]
            self.assert_report(producer.terminate(session, grace_seconds=0), "terminated")
        for text in ("", "424200 EXAMPLE S 1", "424200 (EXAMPLE) S 1", "x (EXAMPLE) " + "0 " * 22):
            table, producer = self.make()
            table.stat_override = text
            self.assert_report(producer.register_from_spawn(expected(), table.spawn), "identity-unavailable")
            table.send_signal.assert_not_called()
            self.assertEqual(table.closes, [table.next_fd])
        for status in ("Name:\tEXAMPLE", "Uid:\tEXAMPLE", "Uid:\t-1"):
            table, producer = self.make()
            table.status_override = status
            self.assert_report(producer.register_from_spawn(expected(), table.spawn), "identity-unavailable")
            table.send_signal.assert_not_called()

    def test_permissions_and_capability_absence_fail_closed(self):
        table, producer = self.make()
        table.available = False
        self.assert_report(producer.register_from_spawn(expected(), table.spawn), "unavailable")
        self.assertEqual(table.spawn_calls, [])
        table, producer, session = self.registered()
        table.available = False
        self.assert_report(producer.terminate(session, grace_seconds=0), "unavailable")
        table.send_signal.assert_not_called()
        table, producer = self.make()
        table.hooks["after_spawn"] = lambda: table.read_errors.update({
            f"{TARGET}/status": PermissionError(errno.EACCES, "EXAMPLE denied"),
        })
        self.assert_report(producer.register_from_spawn(expected(), table.spawn), "permission-denied")
        self.assertEqual(table.closes, [table.next_fd])
        table.send_signal.assert_not_called()
        incomplete = FakeTable()
        incomplete.send_signal = None
        with self.assertRaises(ValueError):
            OfflineOwnershipProducer(incomplete, controller_pid=CONTROLLER, name="EXAMPLE-controller")
        with self.assertRaises(ValueError):
            OfflineOwnershipProducer(ProcAdapter(), controller_pid=CONTROLLER, name="EXAMPLE-controller")

    def test_invalid_durations_leave_the_live_session_untouched(self):
        table, producer, session = self.registered()
        for label in ("grace_seconds", "min_age_seconds"):
            for value in (True, False, float("nan"), float("inf"), -1, 10**1000, "EXAMPLE"):
                arguments = {"grace_seconds": 0, label: value}
                self.assert_report(producer.terminate(session, **arguments), "invalid-request")
                self.assertEqual(table.closes, [])
                table.send_signal.assert_not_called()
        self.assert_report(producer.terminate(session, grace_seconds=3601), "invalid-request")
        self.assert_report(producer.terminate(session, grace_seconds=0, min_age_seconds=31536001), "invalid-request")
        self.assert_report(producer.terminate(session, grace_seconds=0, allow_kill=1), "invalid-request")
        self.assert_report(producer.terminate(session, grace_seconds=0), "terminated")
        self.assertEqual(table.send_signal.call_count, 1)

    def test_young_process_and_invalid_clocks_send_nothing(self):
        table, producer, session = self.registered()
        table.uptime = 1.5
        self.assert_report(producer.terminate(session, grace_seconds=0, min_age_seconds=1), "not-stale")
        table.send_signal.assert_not_called()
        for attribute, value in (("uptime", float("nan")), ("uptime", -1), ("uptime", 0),
                                 ("hz", 0), ("hz", True), ("hz", 10**1000)):
            table, producer, session = self.registered()
            setattr(table, attribute, value)
            self.assert_report(producer.terminate(session, grace_seconds=0), "identity-unavailable")
            table.send_signal.assert_not_called()

    def test_signal_failures_preserve_partial_signals(self):
        errors = (
            (PermissionError(errno.EACCES, "EXAMPLE denied"), "permission-denied"),
            (OSError(errno.ENOSYS, "EXAMPLE unavailable"), "unavailable"),
            (OSError(errno.EINVAL, "EXAMPLE signal failure"), "signal-failed"),
        )
        for stage in (signal.SIGTERM, signal.SIGKILL):
            for error, outcome in errors:
                table, producer, session = self.registered()
                table.procs[TARGET].exits_on = set()
                table.signal_errors[stage] = error
                report = producer.terminate(session, grace_seconds=0, allow_kill=True)
                self.assert_report(report, outcome)
                self.assertEqual(report["signals"], [] if stage == signal.SIGTERM else ["SIGTERM"])
                self.assertEqual(report["stage"], signal.Signals(stage).name)
                self.assertEqual(table.closes, [table.next_fd])

    def test_wait_and_close_errors_keep_the_primary_outcome(self):
        for error in (OSError(errno.EIO, "EXAMPLE wait failure"), ValueError("EXAMPLE invalid wait")):
            table, producer, session = self.registered()
            table.procs[TARGET].exits_on = set()
            table.wait_error = error
            table.close_error = OSError(errno.EINTR, "EXAMPLE close failure")
            report = producer.terminate(session, grace_seconds=0, allow_kill=True)
            self.assert_report(report, "wait-failed")
            self.assertEqual(report["signals"], ["SIGTERM"])
            self.assertIn("close_error", report)
            producer.close()
            self.assertEqual(table.closes, [table.next_fd])
        table, producer, session = self.registered()
        table.close_error = OSError(errno.EIO, "EXAMPLE close failure")
        report = producer.terminate(session, grace_seconds=0)
        self.assert_report(report, "terminated")
        self.assertEqual(report["signals"], ["SIGTERM"])
        self.assertIn("close_error", report)
        producer.close()
        self.assertEqual(table.closes, [table.next_fd])
        table, producer = self.make()
        table.close_error = OSError(errno.EIO, "EXAMPLE close failure")
        report = producer.register_from_spawn(expected(uid=43211), table.spawn)
        self.assert_report(report, "identity-mismatch")
        self.assertIn("close_error", report)
        table.send_signal.assert_not_called()
        producer.close()
        self.assertEqual(table.closes, [table.next_fd])

    def test_explicit_close_reports_failures_for_each_handle_once(self):
        table, producer, _ = self.registered()
        first = table.next_fd
        table.spawn_pid = TARGET + 10
        self.assertNotIn(table.spawn_pid, (CONTROLLER, PARENT))
        self.assert_report(producer.register_from_spawn(expected(session_id="EXAMPLE-next"), table.spawn), "registered")
        second = table.next_fd
        table.close_error = OSError(errno.EIO, "EXAMPLE close failure")
        report = producer.close()
        self.assert_report(report, "closed")
        self.assertEqual(len(report["close_errors"]), 2)
        self.assertEqual(table.closes, [first, second])
        self.assertEqual(producer.close()["close_errors"], [])
        table.send_signal.assert_not_called()

    def assert_released_once(self, table, descriptors):
        self.assertEqual(table.closes, descriptors)
        self.assertEqual(table.handles, {})
        self.assertEqual(table.births, {})

    def test_close_type_error_retains_success_and_signals(self):
        for error_type in (TypeError, RuntimeError):
            with self.subTest(error_type=error_type.__name__):
                table, producer, session = self.registered()
                table.close_error = error_type("EXAMPLE cleanup failure")
                report = producer.terminate(session, grace_seconds=0)
                self.assert_report(report, "terminated")
                self.assertEqual(report["signals"], ["SIGTERM"])
                self.assertEqual(report["close_error"], f"{error_type.__name__}: EXAMPLE cleanup failure")
                self.assertEqual(set(report), {
                    "outcome", "signals", "close_error", "offline_only", "production_authority", "default_cleanup_consumer",
                })
                self.assertEqual(table.send_signal.call_args_list, [mock.call(table.next_fd, signal.SIGTERM)])
                producer.close()
                self.assert_released_once(table, [table.next_fd])

    def test_close_type_error_continues_other_handles(self):
        for error_type in (TypeError, RuntimeError):
            table, producer, _ = self.registered()
            first = table.next_fd
            table.spawn_pid = TARGET + 10
            report = producer.register_from_spawn(expected(session_id="EXAMPLE-next"), table.spawn)
            self.assert_report(report, "registered")
            second = table.next_fd
            table.close_error = error_type("EXAMPLE cleanup failure")
            report = producer.close()
            self.assert_report(report, "closed")
            self.assertEqual(report["signals"], [])
            self.assertEqual(report["close_errors"], [
                {"session_id": "EXAMPLE-session", "error": f"{error_type.__name__}: EXAMPLE cleanup failure"},
                {"session_id": "EXAMPLE-next", "error": f"{error_type.__name__}: EXAMPLE cleanup failure"},
            ])
            self.assertEqual(len(table.spawn_calls), 2)
            self.assertEqual(producer.close()["close_errors"], [])
            self.assert_released_once(table, [first, second])
            table.send_signal.assert_not_called()

    def test_close_during_spawn_cannot_register_after_closed(self):
        table, producer = self.make()
        table.hooks["after_spawn"] = producer.close
        report = producer.register_from_spawn(expected(), table.spawn)
        self.assert_report(report, "producer-closed")
        self.assertEqual(report["signals"], [])
        self.assertNotIn("session", report)
        self.assertEqual(len(table.spawn_calls), 1)
        self.assert_report(producer.register_from_spawn(expected(), table.spawn), "producer-closed")
        self.assert_report(producer.terminate(OfflineSession(None), grace_seconds=0), "producer-closed")
        producer.close()
        self.assert_released_once(table, [table.next_fd])
        table.send_signal.assert_not_called()

    def test_same_session_capability_reentry_does_not_spawn_twice(self):
        table, producer = self.make()
        nested = []
        table.hooks["capability"] = lambda: nested.append(producer.register_from_spawn(expected(), table.spawn))
        report = producer.register_from_spawn(expected(), table.spawn)
        self.assert_report(report, "registered")
        self.assert_report(nested[0], "duplicate-session")
        self.assertEqual(nested[0]["signals"], [])
        self.assertEqual(len(table.spawn_calls), 1)
        self.assertEqual(table.closes, [])
        self.assert_report(producer.terminate(report["session"], grace_seconds=0), "terminated")
        producer.close()
        self.assert_released_once(table, [table.next_fd])
        self.assertEqual(table.send_signal.call_count, 1)

    def test_close_during_claim_and_identity_reads_releases_birth_once(self):
        stages = (
            "claimed", "binding:1", "binding:2", f"{TARGET}/stat", f"{TARGET}/status",
            "sys/kernel/random/boot_id", f"{TARGET}/ns/pid", f"{TARGET}/exe", f"{TARGET}/cwd", "namespace",
        )
        for stage in stages:
            with self.subTest(stage=stage):
                table, producer = self.make()
                table.hooks[stage] = producer.close
                report = producer.register_from_spawn(expected(), table.spawn)
                self.assert_report(report, "producer-closed")
                self.assertEqual(report["signals"], [])
                self.assertNotIn("session", report)
                self.assertEqual(len(table.spawn_calls), 1)
                producer.close()
                self.assert_released_once(table, [table.next_fd])
                table.send_signal.assert_not_called()

    def test_close_before_spawn_prevents_birth(self):
        for stage in ("capability", f"{CONTROLLER}/stat", f"{PARENT}/stat"):
            table, producer = self.make()
            table.hooks[stage] = producer.close
            report = producer.register_from_spawn(expected(), table.spawn)
            self.assert_report(report, "producer-closed")
            self.assertEqual(report["signals"], [])
            self.assertEqual(table.spawn_calls, [])
            self.assertEqual(table.closes, [])
            table.send_signal.assert_not_called()

    def test_same_session_ancestry_and_birth_callbacks_keep_reservation(self):
        stages = (f"{CONTROLLER}/stat", f"{PARENT}/stat", "after_spawn", "claimed", f"{TARGET}/stat", "namespace")
        for stage in stages:
            table, producer = self.make()
            nested = []
            table.hooks[stage] = lambda: nested.append(producer.register_from_spawn(expected(), table.spawn))
            report = producer.register_from_spawn(expected(), table.spawn)
            self.assert_report(report, "registered")
            self.assert_report(nested[0], "duplicate-session")
            self.assertEqual(nested[0]["signals"], [])
            self.assertEqual(len(table.spawn_calls), 1)
            self.assertEqual(table.closes, [])
            self.assert_report(producer.terminate(report["session"], grace_seconds=0), "terminated")
            producer.close()
            self.assert_released_once(table, [table.next_fd])
            self.assertEqual(table.send_signal.call_count, 1)

    def test_other_session_reentry_fails_without_using_its_session(self):
        table, producer = self.make()
        nested = []
        table.hooks["capability"] = lambda: nested.append(
            producer.register_from_spawn(expected(session_id="EXAMPLE-next"), table.spawn),
        )
        first = producer.register_from_spawn(expected(), table.spawn)
        self.assert_report(first, "registered")
        self.assert_report(nested[0], "producer-busy")
        self.assertEqual(len(table.spawn_calls), 1)
        table.spawn_pid = TARGET + 10
        second = producer.register_from_spawn(expected(session_id="EXAMPLE-next"), table.spawn)
        self.assert_report(second, "registered")
        self.assertEqual(len(table.spawn_calls), 2)
        producer.close()
        self.assert_released_once(table, [table.next_fd - 1, table.next_fd])
        table.send_signal.assert_not_called()

    def test_callback_reentry_cannot_consume_existing_receipt(self):
        for stage in ("capability", f"{CONTROLLER}/stat", "claimed"):
            table, producer, session = self.registered()
            first = table.next_fd
            table.spawn_pid = TARGET + 10
            nested = []
            table.hooks[stage] = lambda: nested.append(producer.terminate(session, grace_seconds=0))
            report = producer.register_from_spawn(expected(session_id="EXAMPLE-next"), table.spawn)
            self.assert_report(report, "registered")
            self.assert_report(nested[0], "producer-busy")
            self.assertEqual(nested[0]["signals"], [])
            self.assertEqual(table.closes, [])
            table.send_signal.assert_not_called()
            self.assert_report(producer.terminate(session, grace_seconds=0), "terminated")
            producer.close()
            self.assert_released_once(table, [first, table.next_fd])
            self.assertEqual(len(table.spawn_calls), 2)
            self.assertEqual(table.send_signal.call_args_list, [mock.call(first, signal.SIGTERM)])

    def test_close_during_termination_checks_sends_nothing(self):
        stages = ("capability", f"{TARGET}/stat", f"{TARGET}/status", f"{TARGET}/exe",
                  "namespace", f"{CONTROLLER}/stat", "uptime", "ticks", "binding")
        for stage in stages:
            table, producer, session = self.registered()
            key = f"binding:{table.binding_calls + 1}" if stage == "binding" else stage
            table.hooks[key] = producer.close
            report = producer.terminate(session, grace_seconds=0, allow_kill=True)
            self.assert_report(report, "producer-closed")
            self.assertEqual(report["signals"], [])
            self.assertEqual(table.waits, [])
            producer.close()
            self.assert_released_once(table, [table.next_fd])
            table.send_signal.assert_not_called()

    def test_close_during_wait_preserves_partial_signals_and_cleanup_errors(self):
        for error_type in (TypeError, RuntimeError):
            table, producer, session = self.registered()
            table.procs[TARGET].exits_on = set()
            table.close_error = error_type("EXAMPLE cleanup failure")
            table.hooks["wait"] = producer.close
            report = producer.terminate(session, grace_seconds=0, allow_kill=True)
            self.assert_report(report, "producer-closed")
            self.assertEqual(report["signals"], ["SIGTERM"])
            self.assertEqual(report["reason"], "The offline producer is closed.")
            self.assertEqual(report["close_error"], f"{error_type.__name__}: EXAMPLE cleanup failure")
            self.assertEqual(table.send_signal.call_args_list, [mock.call(table.next_fd, signal.SIGTERM)])
            self.assertEqual(table.waits, [(table.next_fd, 0)])
            producer.close()
            self.assert_released_once(table, [table.next_fd])

    def test_ordinary_close_errors_preserve_partial_failure_details(self):
        for error_type in (TypeError, RuntimeError):
            for stage, outcome in (("wait", "wait-failed"), ("SIGKILL", "permission-denied")):
                table, producer, session = self.registered()
                table.procs[TARGET].exits_on = set()
                failure = ValueError("EXAMPLE wait failure") if stage == "wait" else PermissionError("EXAMPLE signal failure")
                if stage == "wait":
                    table.wait_error = failure
                else:
                    table.signal_errors[signal.SIGKILL] = failure
                table.close_error = error_type("EXAMPLE cleanup failure")
                report = producer.terminate(session, grace_seconds=0, allow_kill=True)
                self.assert_report(report, outcome)
                self.assertEqual(report["signals"], ["SIGTERM"])
                self.assertEqual(report["stage"], "SIGTERM" if stage == "wait" else "SIGKILL")
                self.assertEqual(report["reason"], str(failure))
                self.assertEqual(report["close_error"], f"{error_type.__name__}: EXAMPLE cleanup failure")
                producer.close()
                self.assert_released_once(table, [table.next_fd])

    def test_ordinary_close_errors_preserve_registration_refusal(self):
        for error_type in (TypeError, RuntimeError):
            table, producer = self.make()
            table.close_error = error_type("EXAMPLE cleanup failure")
            report = producer.register_from_spawn(expected(uid=43211), table.spawn)
            self.assert_report(report, "identity-mismatch")
            self.assertEqual(report["signals"], [])
            self.assertEqual(report["reasons"], ["uid-mismatch"])
            self.assertEqual(report["reason"], "The fake identity differs from the controller specification.")
            self.assertEqual(report["close_error"], f"{error_type.__name__}: EXAMPLE cleanup failure")
            producer.close()
            self.assert_released_once(table, [table.next_fd])
            table.send_signal.assert_not_called()

    def test_close_callback_reentry_does_not_repeat_release(self):
        table, producer, session = self.registered()
        table.hooks["close"] = producer.close
        report = producer.close()
        self.assert_report(report, "closed")
        self.assertEqual(report["close_errors"], [])
        self.assert_report(producer.terminate(session, grace_seconds=0), "producer-closed")
        self.assert_released_once(table, [table.next_fd])
        table.send_signal.assert_not_called()

    def test_observation_interrupt_propagates_after_cleanup(self):
        table, producer = self.make()

        def interrupted():
            raise KeyboardInterrupt("EXAMPLE interrupted observation")

        table.hooks[f"{TARGET}/stat"] = interrupted
        table.close_error = TypeError("EXAMPLE cleanup failure")
        with self.assertRaisesRegex(KeyboardInterrupt, "EXAMPLE interrupted observation"):
            producer.register_from_spawn(expected(), table.spawn)
        producer.close()
        self.assert_released_once(table, [table.next_fd])
        table.send_signal.assert_not_called()

    def test_close_propagates_interrupt_after_attempting_other_handles(self):
        table, producer, _ = self.registered()
        first = table.next_fd
        table.spawn_pid = TARGET + 10
        self.assert_report(producer.register_from_spawn(expected(session_id="EXAMPLE-next"), table.spawn), "registered")
        second = table.next_fd
        table.close_error = KeyboardInterrupt("EXAMPLE interrupted cleanup")
        with self.assertRaisesRegex(KeyboardInterrupt, "EXAMPLE interrupted cleanup"):
            producer.close()
        self.assertEqual(producer.close()["close_errors"], [])
        self.assert_released_once(table, [first, second])
        table.send_signal.assert_not_called()

    def test_termination_cleanup_interrupt_propagates_without_retry(self):
        table, producer, session = self.registered()
        table.close_error = SystemExit("EXAMPLE interrupted cleanup")
        with self.assertRaisesRegex(SystemExit, "EXAMPLE interrupted cleanup"):
            producer.terminate(session, grace_seconds=0)
        producer.close()
        self.assert_released_once(table, [table.next_fd])
        self.assertEqual(table.send_signal.call_args_list, [mock.call(table.next_fd, signal.SIGTERM)])

    def test_pre_spawn_refusal_clears_pending_reservation(self):
        for stage in ("capability", "ancestry"):
            table, producer = self.make()
            if stage == "capability":
                table.available = False
            else:
                table.procs[PARENT].ppid = CONTROLLER
            report = producer.register_from_spawn(expected(), table.spawn)
            self.assert_report(report, "unavailable" if stage == "capability" else "identity-unavailable")
            self.assertEqual(report["signals"], [])
            self.assertEqual(table.spawn_calls, [])
            table.available = True
            table.procs[PARENT].ppid = 0
            report = producer.register_from_spawn(expected(), table.spawn)
            self.assert_report(report, "registered")
            producer.close()
            self.assert_released_once(table, [table.next_fd])
            table.send_signal.assert_not_called()

    def test_shipped_cleanup_and_unavailable_message_stay_detection_only(self):
        self.assertIsNone(NoTrustedOwnershipSource().trusted_registrations())
        self.assertEqual(NoTrustedOwnershipSource.reason, "no-trusted-ownership-producer")
        process = cleanup_module.ProcessInfo(TARGET, 0, 7200, "S", "python", "EXAMPLE unrelated.py codex", "/EXAMPLE/work")
        with mock.patch.object(cleanup_module, "load_record_lines", return_value=[
            (1, {"pid": TARGET, "session_id": "EXAMPLE-planted"}),
        ]):
            report = cleanup_module.cleanup(
                processes=[process], state_dir=Path("/EXAMPLE/state"), workspace_root=Path("/EXAMPLE/work"),
                stale_after_seconds=1, protected_pids=set(), terminate_owned=True,
                terminate_unowned_codex=False, prune_state=False, dry_run=False, grace_seconds=0,
            )
        self.assertEqual(report["termination"]["reasons"], {"owned": "no-trusted-ownership-producer"})
        self.assertEqual(report["termination"]["signals_sent"], 0)
        self.assertEqual(report["actions"][0]["action"], "termination-unavailable")


if __name__ == "__main__":
    unittest.main()
