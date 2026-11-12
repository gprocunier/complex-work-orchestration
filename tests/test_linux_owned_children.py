from __future__ import annotations

import copy
import errno
import os
import signal
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "tests"))

import linux_owned_children as linux  # noqa: E402
from cwo_core.ownership_producer import OfflineOwnershipProducer  # noqa: E402
from cwo_core.process_identity import NoTrustedOwnershipSource  # noqa: E402
from test_ownership_producer import CONTROLLER, PARENT, TARGET, FakeProcess, FakeTable  # noqa: E402

BACKEND = linux._LinuxBackend
ARGV = ("/EXAMPLE/bin/worker", "EXAMPLE-argument")


class FakeChild:
    def __init__(self, process):
        self.process = process
        self.pid = process.pid
        self.waits = []
        self.polls = 0
        self.returncode = None

    def wait(self, timeout):
        self.waits.append(timeout)
        raise AssertionError("Child status must be collected through its retained handle.")

    def poll(self):
        self.polls += 1
        raise AssertionError("Child status must be collected through its retained handle.")


class FakeLinux(FakeTable, BACKEND):
    _next_descriptor_base = 80

    def __init__(self):
        FakeTable.__init__(self)
        BACKEND.__init__(self)
        self.controller_pid = CONTROLLER
        self.children = []
        self.open_error = None
        FakeLinux._next_descriptor_base += 128
        self.next_fd = FakeLinux._next_descriptor_base
        self.waitid_error = None
        self.reap_error = None
        self.events = []

    claim_writer = BACKEND.claim_writer
    spawn = BACKEND.spawn
    close = BACKEND.close
    send_signal = BACKEND.send_signal
    wait_exit = BACKEND.wait_exit
    reap = BACKEND.reap

    def supported(self):
        self.fire("capability")
        if not self.available:
            return False, "EXAMPLE missing child capability."
        return BACKEND.supported(self)

    def controller_uid(self):
        return 43210

    def canonical(self, path, directory):
        self.fire("canonical")
        return path

    def readlink(self, relative):
        if relative == "self":
            return str(CONTROLLER)
        return FakeTable.readlink(self, relative)

    def _popen(self, argv, executable, workspace):
        self.spawn_calls.append((argv, executable, workspace))
        process = FakeProcess(self.spawn_pid, ppid=CONTROLLER)
        self.procs[process.pid] = process
        child = FakeChild(process)
        self.children.append(child)
        self.fire("after_spawn")
        return child

    def _open_pidfd(self, pid):
        self.opens.append(pid)
        self.fire("before_open")
        if self.open_error is not None:
            raise self.open_error
        self.next_fd += 1
        descriptor = self.next_fd
        self.handles[descriptor] = self.children[-1].process
        if self.children[-1].waits:
            raise AssertionError("The child was reaped before its birth handle.")
        self.fire("after_open")
        return descriptor

    def claim_spawn(self, pid, descriptor, writer):
        claimed = BACKEND.claim_spawn(self, pid, descriptor, writer)
        self.fire("claimed")
        return claimed

    def _close_fd(self, descriptor):
        self.events.append(("close", descriptor))
        FakeTable.close(self, descriptor)


class ControllerTests(unittest.TestCase):
    def setUp(self):
        self.spies = []
        self.tables = []
        self.profile_flags = 0
        self.profile_handler = None
        self.profile_errno = 0
        for module, name in ((os, "kill"), (os, "killpg"), (os, "pidfd_open"), (subprocess, "Popen")):
            self.spies.append(self.enterContext(mock.patch.object(
                module, name, create=True, side_effect=AssertionError("No real process operation is allowed."),
            )))
        self.enterContext(mock.patch.object(os, "getpid", return_value=CONTROLLER))
        self.enterContext(mock.patch.object(os, "uname", return_value=SimpleNamespace(machine="x86_64")))
        self.enterContext(mock.patch.object(os, "confstr", return_value="glibc EXAMPLE"))
        self.enterContext(mock.patch.object(signal, "getsignal", return_value=signal.SIG_DFL))
        self.enterContext(mock.patch.object(linux.sys, "platform", "linux"))
        query = mock.Mock(side_effect=self.sigaction)
        self.enterContext(mock.patch.object(linux.ctypes, "CDLL", return_value=SimpleNamespace(sigaction=query)))
        self.enterContext(mock.patch.object(os, "P_PIDFD", 3, create=True))
        self.waitid_api = self.enterContext(mock.patch.object(os, "waitid", create=True, side_effect=self.waitid))
        self.signal_api = self.enterContext(mock.patch.object(
            signal, "pidfd_send_signal", create=True, side_effect=self.send_signal,
        ))
        self.enterContext(mock.patch.object(linux.select, "poll", create=True, side_effect=self.poller))

    def sigaction(self, signum, replacement, current):
        self.assertEqual(signum, signal.SIGCHLD)
        self.assertIsNone(replacement)
        current._obj.handler = self.profile_handler
        current._obj.flags = self.profile_flags
        linux.ctypes.set_errno(self.profile_errno)
        return -1 if self.profile_errno else 0

    def table_for(self, descriptor):
        matches = [table for table in self.tables if descriptor in table._owned]
        self.assertEqual(len(matches), 1)
        return matches[0]

    def send_signal(self, descriptor, signum):
        table = self.table_for(descriptor)
        table.events.append(("signal", descriptor, signum))
        return FakeTable.send_signal(table, descriptor, signum)

    def poller(self):
        poller = mock.Mock()
        def poll(milliseconds):
            descriptor = poller.register.call_args.args[0]
            table = self.table_for(descriptor)
            table.events.append(("exit-wait", descriptor))
            exited = FakeTable.wait_exit(table, descriptor, milliseconds / 1000)
            return [(descriptor, linux.select.POLLIN)] if exited else []
        poller.poll.side_effect = poll
        return poller

    def waitid(self, kind, descriptor, options):
        self.assertEqual(kind, os.P_PIDFD)
        table = self.table_for(descriptor)
        table.events.append(("waitid", descriptor, options))
        collect = not bool(options & os.WNOWAIT)
        table.fire("waitid:reap" if collect else "waitid:observe")
        error = table.reap_error if collect else table.waitid_error
        if error is not None:
            raise error
        process = table.handles[descriptor]
        if getattr(process, "status_consumed", False):
            raise ChildProcessError(errno.ECHILD, "EXAMPLE child status belongs to an outside reaper.")
        if process.alive:
            return None
        if collect:
            process.status_consumed = True
        signum = process.signals[-1] if process.signals else 0
        return SimpleNamespace(
            si_pid=process.pid, si_code=os.CLD_KILLED if signum else os.CLD_EXITED,
            si_status=int(signum),
        )

    def tearDown(self):
        for spy in self.spies:
            spy.assert_not_called()

    def make(self):
        table = FakeLinux()
        self.tables.append(table)
        with mock.patch.object(linux, "_LinuxBackend", return_value=table):
            controller = linux.LinuxOwnedChildController(ARGV[0])
        self.addCleanup(controller.close)
        return table, controller

    def registered(self):
        table, controller = self.make()
        report = controller.spawn_owned("EXAMPLE-session", ARGV, "/EXAMPLE/work")
        self.assertEqual(report["outcome"], "registered")
        self.assertFalse(report["offline_only"])
        self.assertFalse(report["production_authority"])
        self.assertEqual(report["default_cleanup_consumer"], "none")
        return table, controller, report["receipt"]

    def reentrant_reap_case(self, stage):
        table, controller, receipt = self.registered()
        birth = table.births[0]
        descriptor = birth.descriptor
        original = table.handles[descriptor]
        original.alive = False
        self.assertTrue(table.wait_exit(descriptor, 0))
        replacement = FakeProcess(TARGET + 50, ppid=CONTROLLER, alive=False)
        foreign = linux._Birth(
            child=FakeChild(replacement), pid=replacement.pid,
            descriptor=descriptor, reap_authorized=True,
        )
        case = SimpleNamespace(
            table=table, controller=controller, receipt=receipt, birth=birth,
            original=original, replacement=replacement, foreign=foreign,
            primary=None, retained=[], after_release=[], wait_options=[],
            active_on_release=[], nested=[],
        )
        actual_close = table._close_fd
        def reenter():
            case.nested.extend((controller.close(), controller.close()))
            case.retained.append((
                table._retained(birth), table.handles.get(descriptor) is original,
                birth.reap_authorized, getattr(birth, "release_pending", False),
            ))
            if case.primary is not None:
                raise case.primary
        def waited(kind, fd, options):
            if birth.closed or table._owned.get(fd) is not birth:
                case.after_release.append((fd, options))
            case.wait_options.append(options)
            observing = bool(options & os.WNOWAIT)
            if observing and stage == "before-observe":
                reenter()
            result = self.waitid(kind, fd, options)
            if (observing and stage == "after-observe") or (not observing and stage == "after-collect"):
                reenter()
            return result
        def released(fd):
            case.active_on_release.append(birth.reaping)
            try:
                actual_close(fd)
            finally:
                table.procs[replacement.pid] = replacement
                table._owned[fd] = foreign
                table.handles[fd] = replacement
        if stage == "capability":
            table.hooks["capability"] = reenter
        table.hooks["close"] = controller.close
        case.wait_patch = mock.patch.object(os, "waitid", side_effect=waited)
        case.close_patch = mock.patch.object(table, "_close_fd", side_effect=released)
        return case

    def assert_reentrant_release(self, case, reaped):
        table, controller, birth = case.table, case.controller, case.birth
        descriptor = birth.descriptor
        self.assertEqual(case.retained, [(True, True, True, True)])
        self.assertEqual(case.after_release, [])
        self.assertEqual(case.active_on_release, [False])
        self.assertEqual([report["outcome"] for report in case.nested], ["closed", "closed"])
        self.assertEqual(table.closes, [descriptor])
        self.assertTrue(birth.closed)
        self.assertFalse(birth.reaping)
        self.assertFalse(birth.releasing)
        self.assertFalse(birth.release_pending)
        self.assertFalse(birth.reap_authorized)
        self.assertEqual(birth.reaped, reaped)
        self.assertEqual(getattr(case.original, "status_consumed", False), reaped)
        self.assertEqual(birth.child.returncode, 0 if reaped else None)
        calls = list(case.wait_options)
        report = controller.close()
        controller.close()
        table.reap(birth)
        table._release_birth(birth)
        with self.assertRaises(linux._Refusal):
            table._wait_child(birth, os.WEXITED | os.WNOHANG)
        self.assertEqual(controller.terminate(case.receipt, 0, allow_kill=True)["signals"], [])
        self.assertEqual(case.wait_options, calls)
        self.assertEqual(table.closes, [descriptor])
        self.assertIs(table._owned[descriptor], case.foreign)
        self.assertIs(table.handles[descriptor], case.replacement)
        self.assertFalse(getattr(case.replacement, "status_consumed", False))
        self.assertEqual(case.replacement.signals, [])
        self.assertEqual(birth.child.waits, [])
        self.assertEqual(birth.child.polls, 0)
        table.send_signal.assert_not_called()
        self.assertEqual(report["outcome"], "closed")
        self.assertEqual(report["child_creation"], "popen-returned")
        self.assertEqual(report["child_pid"], TARGET)
        self.assertTrue(report["registration_committed"])
        self.assertTrue(report["child_exit_confirmed"])
        self.assertEqual(report["child_reaped"], reaped)
        self.assertFalse(report["receipt_available"])

    def test_reaping_uses_the_retained_handle_before_final_close(self):
        table, controller, receipt = self.registered()
        descriptor = table.next_fd
        table.events.clear()
        self.waitid_api.reset_mock()
        report = controller.terminate(receipt, 0)
        self.assertTrue(report["child_exit_confirmed"])
        self.assertTrue(report["child_reaped"])
        self.assertEqual(self.waitid_api.call_args_list, [
            mock.call(os.P_PIDFD, descriptor, os.WEXITED | os.WNOHANG | os.WNOWAIT),
            mock.call(os.P_PIDFD, descriptor, os.WEXITED | os.WNOHANG),
        ])
        self.assertEqual([event[0] for event in table.events], [
            "signal", "exit-wait", "waitid", "waitid", "close",
        ])
        self.assertEqual(table.children[0].waits, [])
        calls = self.waitid_api.call_count
        controller.close()
        controller.close()
        table.reap(table.births[0])
        self.assertEqual(self.waitid_api.call_count, calls)
        self.assertEqual(table.closes, [descriptor])

    def test_reentrant_close_defers_release_until_status_operations_finish(self):
        for stage in ("capability", "before-observe", "after-observe", "after-collect"):
            with self.subTest(stage=stage):
                case = self.reentrant_reap_case(stage)
                with case.wait_patch, case.close_patch:
                    errors, interruption = linux._cleanup([lambda: case.table.reap(case.birth)])
                    self.assertFalse(getattr(case.replacement, "status_consumed", False))
                    self.assertEqual(case.after_release, [])
                    self.assertEqual(errors, [])
                    self.assertIsNone(interruption)
                    self.assertEqual(case.wait_options, [
                        os.WEXITED | os.WNOHANG | os.WNOWAIT,
                        os.WEXITED | os.WNOHANG,
                    ])
                    self.assert_reentrant_release(case, True)

    def test_reentrant_reaping_preserves_primary_and_secondary_interruptions(self):
        for stage in ("capability", "before-observe", "after-observe"):
            for primary_type in (KeyboardInterrupt, SystemExit):
                for secondary_type in (RuntimeError, KeyboardInterrupt, SystemExit):
                    with self.subTest(stage=stage, primary=primary_type, secondary=secondary_type):
                        case = self.reentrant_reap_case(stage)
                        primary = primary_type("EXAMPLE primary reaping interruption")
                        secondary = secondary_type("EXAMPLE secondary release failure")
                        case.primary = primary
                        case.table.close_error = secondary
                        with case.wait_patch, case.close_patch:
                            with self.assertRaises(primary_type) as caught:
                                case.table.reap(case.birth)
                            self.assertIs(caught.exception, primary)
                            self.assertTrue(any(str(secondary) in note for note in primary.__notes__))
                            self.assert_reentrant_release(case, False)

    def test_ordinary_reaping_failure_preserves_secondary_release_details(self):
        for secondary_type in (RuntimeError, KeyboardInterrupt, SystemExit):
            with self.subTest(secondary=secondary_type):
                case = self.reentrant_reap_case("after-observe")
                primary = OSError(errno.EIO, "EXAMPLE primary reaping failure")
                secondary = secondary_type("EXAMPLE secondary release failure")
                case.primary = primary
                case.table.close_error = secondary
                with case.wait_patch, case.close_patch:
                    errors, interruption = linux._cleanup([lambda: case.table.reap(case.birth)])
                    if isinstance(secondary, Exception):
                        self.assertIsNone(interruption)
                        self.assertTrue(any(str(primary) in error for error in errors))
                        self.assertTrue(any(str(secondary) in error for error in errors))
                    else:
                        self.assertIs(interruption, secondary)
                        self.assertTrue(any(str(primary) in note for note in secondary.__notes__))
                    self.assert_reentrant_release(case, False)

    def test_reentrant_release_failure_keeps_collected_facts_without_retry(self):
        for error_type in (RuntimeError, KeyboardInterrupt, SystemExit):
            with self.subTest(error=error_type):
                case = self.reentrant_reap_case("after-collect")
                failure = error_type("EXAMPLE release failure after collection")
                case.table.close_error = failure
                with case.wait_patch, case.close_patch:
                    with self.assertRaises(error_type) as caught:
                        case.table.reap(case.birth)
                    self.assertIs(caught.exception, failure)
                    self.assert_reentrant_release(case, True)

    def test_reentrant_reaping_keeps_required_operation_failure_latched(self):
        for code in (errno.ENOSYS, errno.EPERM, errno.EACCES, errno.EINVAL):
            with self.subTest(errno=code):
                case = self.reentrant_reap_case("capability")
                failure = OSError(code, "EXAMPLE required child wait unavailable")
                case.table.waitid_error = failure
                with case.wait_patch, case.close_patch:
                    with self.assertRaises(OSError) as caught:
                        case.table.reap(case.birth)
                    self.assertIs(caught.exception, failure)
                    self.assertFalse(case.table.supported()[0])
                    self.assert_reentrant_release(case, False)

    def test_every_status_wait_rechecks_birth_authority_after_capability(self):
        for phase in ("observe", "collect"):
            for loss in ("mapping", "closed", "authorization"):
                with self.subTest(phase=phase, loss=loss):
                    table, controller, _ = self.registered()
                    birth = table.births[0]
                    descriptor = birth.descriptor
                    original = table.handles[descriptor]
                    original.alive = False
                    replacement = FakeProcess(TARGET + 50, ppid=CONTROLLER, alive=False)
                    foreign = linux._Birth(
                        child=FakeChild(replacement), pid=replacement.pid,
                        descriptor=descriptor, reap_authorized=True,
                    )
                    def revoke():
                        if loss == "mapping":
                            table._owned[descriptor] = foreign
                            table.handles[descriptor] = replacement
                        elif loss == "closed":
                            birth.closed = True
                        else:
                            birth.reap_authorized = False
                    def waited(kind, fd, options):
                        result = self.waitid(kind, fd, options)
                        if options & os.WNOWAIT:
                            table.hooks["capability"] = revoke
                        return result
                    if phase == "observe":
                        table.hooks["capability"] = revoke
                    with mock.patch.object(os, "waitid", side_effect=waited) as status_wait:
                        with self.assertRaises(linux._Refusal) as caught:
                            table.reap(birth)
                        self.assertEqual(caught.exception.outcome, "ownership-lost")
                        controller._retire_unusable({})
                        controller.close()
                        self.assertEqual(status_wait.call_count, 0 if phase == "observe" else 1)
                    self.assertFalse(getattr(original, "status_consumed", False))
                    self.assertFalse(getattr(replacement, "status_consumed", False))
                    self.assertEqual(replacement.signals, [])
                    self.assertFalse(birth.reaped)
                    self.assertEqual(birth.exit_confirmed, phase == "collect")
                    self.assertFalse(birth.reaping)
                    self.assertEqual(birth.child.waits, [])
                    self.assertEqual(birth.child.polls, 0)
                    table.send_signal.assert_not_called()
                    self.assertEqual(table.closes, [descriptor] if loss == "authorization" else [])

    def pending_case(self, operation, stage, signum=signal.SIGTERM, integrated=False):
        table, controller, receipt = self.registered()
        birth = table.births[0]
        descriptor = birth.descriptor
        original = table.handles[descriptor]
        original.exits_on = {signum}
        if operation == "wait" and not integrated:
            original.alive = False
        replacement = FakeProcess(TARGET + 50, ppid=CONTROLLER)
        foreign = linux._Birth(
            child=FakeChild(replacement), pid=replacement.pid,
            descriptor=descriptor, reap_authorized=True,
        )
        case = SimpleNamespace(
            table=table, controller=controller, receipt=receipt, birth=birth,
            original=original, replacement=replacement, foreign=foreign,
            primary=None, retained=[], released=[], fired=False, close=controller.close,
        )
        actual_close = table._close_fd
        actual_supported = table.supported
        actual_poller = self.poller
        wanted_count = int(integrated and (operation == "wait" or signum == signal.SIGKILL))
        def reenter():
            if case.fired:
                return
            case.fired = True
            self.assertEqual(case.close()["outcome"], "closed")
            self.assertEqual(case.close()["outcome"], "closed")
            case.retained.append((
                table._retained(birth), table.handles.get(descriptor) is original,
                birth.active_operation, birth.release_pending,
            ))
            self.assertEqual(controller.terminate(receipt, 0, allow_kill=True)["signals"], [])
            self.assertEqual(controller.spawn_owned("EXAMPLE-nested", ARGV, "/EXAMPLE/work")["outcome"], "producer-closed")
            with self.assertRaises(linux._Refusal):
                table.send_signal(descriptor, signal.SIGKILL)
            with self.assertRaises(linux._Refusal):
                table.wait_exit(descriptor, 0)
            with self.assertRaises(linux._Refusal):
                table._wait_child(birth, os.WEXITED | os.WNOHANG)
            table.reap(birth)
            if case.primary is not None:
                raise case.primary
        def supported():
            result = actual_supported()
            if stage == "capability" and birth.active_operation == operation and birth.signal_count == wanted_count:
                reenter()
            return result
        def sent(fd, number):
            selected = operation == "signal" and number == signum
            if selected and stage == "before-effect":
                reenter()
            result = self.send_signal(fd, number)
            if selected and stage == "after-effect":
                reenter()
            return result
        def poller():
            result = actual_poller()
            actual_poll = result.poll.side_effect
            def polled(milliseconds):
                if operation == "wait" and stage == "before-effect":
                    reenter()
                events = actual_poll(milliseconds)
                if operation == "wait" and stage == "after-effect":
                    reenter()
                return events
            result.poll.side_effect = polled
            return result
        def released(fd):
            case.released.append(birth.active_operation)
            try:
                actual_close(fd)
            finally:
                table.procs[replacement.pid] = replacement
                table._owned[fd] = foreign
                table.handles[fd] = replacement
        case.capability_patch = mock.patch.object(table, "supported", side_effect=supported)
        case.signal_patch = mock.patch.object(signal, "pidfd_send_signal", side_effect=sent)
        case.poll_patch = mock.patch.object(linux.select, "poll", side_effect=poller)
        case.release_patch = mock.patch.object(table, "_close_fd", side_effect=released)
        if integrated:
            case.action = lambda: controller.terminate(receipt, 0, allow_kill=True)
        elif operation == "signal":
            case.action = lambda: table.send_signal(descriptor, signum)
        else:
            case.action = lambda: table.wait_exit(descriptor, 0)
        return case

    def test_missing_handle_wait_capabilities_refuse_before_creation(self):
        for module, name in ((os, "P_PIDFD"), (os, "waitid"), (linux.select, "poll")):
            with self.subTest(capability=name):
                table, controller = self.make()
                with mock.patch.object(module, name, create=True):
                    delattr(module, name)
                    report = controller.spawn_owned("EXAMPLE-missing", ARGV, "/EXAMPLE/work")
                self.assertEqual(report["outcome"], "unavailable")
                self.assertEqual(table.spawn_calls, [])
                table.send_signal.assert_not_called()

    def assert_pending_release(self, case, operation):
        birth, table = case.birth, case.table
        descriptor = birth.descriptor
        self.assertEqual(case.retained, [(True, True, operation, True)])
        self.assertEqual(case.released, [None])
        self.assertEqual(table.closes, [descriptor])
        self.assertTrue(birth.closed)
        self.assertIsNone(birth.active_operation)
        self.assertIsNone(birth.active_thread)
        self.assertFalse(birth.status_waiting)
        self.assertFalse(birth.reaping)
        self.assertFalse(birth.releasing)
        self.assertFalse(birth.release_pending)
        self.assertFalse(birth.reap_authorized)
        events = list(table.events)
        case.controller.close()
        case.controller.close()
        table.reap(birth)
        table._release_birth(birth)
        self.assertEqual(case.controller.terminate(case.receipt, 0, allow_kill=True)["signals"], [])
        self.assertEqual(table.events, events)
        self.assertIs(table._owned[descriptor], case.foreign)
        self.assertIs(table.handles[descriptor], case.replacement)
        self.assertEqual(case.replacement.signals, [])
        self.assertFalse(getattr(case.replacement, "status_consumed", False))
        self.assertEqual(birth.child.waits, [])
        self.assertEqual(birth.child.polls, 0)

    def test_pending_signal_and_poll_hold_the_original_handle_until_completion(self):
        for operation, signum in (("signal", signal.SIGTERM), ("signal", signal.SIGKILL), ("wait", signal.SIGTERM)):
            for stage in ("capability", "before-effect", "after-effect"):
                with self.subTest(operation=operation, signum=signum, stage=stage):
                    case = self.pending_case(operation, stage, signum)
                    with case.capability_patch, case.signal_patch, case.poll_patch, case.release_patch:
                        case.action()
                        self.assert_pending_release(case, operation)
                    self.assertTrue(case.birth.exit_confirmed)
                    self.assertTrue(case.birth.reaped)

    def test_exact_pending_signal_close_and_reuse_refuses_the_exited_original(self):
        for signum in (signal.SIGTERM, signal.SIGKILL):
            with self.subTest(signum=signum):
                case = self.pending_case("signal", "before-effect", signum)
                case.original.alive = False
                with case.capability_patch, case.signal_patch, case.poll_patch, case.release_patch:
                    with self.assertRaises(ProcessLookupError):
                        case.action()
                    self.assert_pending_release(case, "signal")
                self.assertEqual(case.original.signals, [])
                self.assertTrue(case.birth.reaped)

    def test_integrated_termination_preserves_completed_signals_and_successful_waits_after_close(self):
        for operation, signum in (("signal", signal.SIGTERM), ("signal", signal.SIGKILL), ("wait", signal.SIGTERM)):
            for stage in ("capability", "before-effect", "after-effect"):
                with self.subTest(operation=operation, signum=signum, stage=stage):
                    case = self.pending_case(operation, stage, signum, integrated=True)
                    with case.capability_patch, case.signal_patch, case.poll_patch, case.release_patch:
                        report = case.action()
                        self.assert_pending_release(case, operation)
                    expected = ["SIGTERM", "SIGKILL"] if signum == signal.SIGKILL else ["SIGTERM"]
                    self.assertEqual(report["signals"], expected)
                    self.assertEqual(report["outcome"], "terminated" if operation == "wait" else "producer-closed")
                    self.assertTrue(report["child_exit_confirmed"])
                    self.assertTrue(report["child_reaped"])
                    self.assertFalse(report["receipt_available"])
                    self.assertNotIn("receipt", report)

    def test_pending_operation_preserves_primary_exception_identity_through_release_failures(self):
        for operation in ("signal", "wait"):
            for primary_type in (OSError, KeyboardInterrupt, SystemExit):
                for secondary_type in (RuntimeError, KeyboardInterrupt, SystemExit):
                    with self.subTest(operation=operation, primary=primary_type, secondary=secondary_type):
                        case = self.pending_case(operation, "before-effect")
                        primary = primary_type("EXAMPLE primary operation failure")
                        secondary = secondary_type("EXAMPLE secondary release failure")
                        case.primary = primary
                        case.table.close_error = secondary
                        with case.capability_patch, case.signal_patch, case.poll_patch, case.release_patch:
                            with self.assertRaises(primary_type) as caught:
                                case.action()
                            self.assertIs(caught.exception, primary)
                            self.assertTrue(any(str(secondary) in note for note in primary.__notes__))
                            self.assert_pending_release(case, operation)

    def test_integrated_primary_failures_retain_secondary_release_diagnostics(self):
        for operation, signum in (("signal", signal.SIGTERM), ("signal", signal.SIGKILL), ("wait", signal.SIGTERM)):
            for primary_type in (OSError, KeyboardInterrupt, SystemExit):
                for secondary_type in (RuntimeError, KeyboardInterrupt, SystemExit):
                    with self.subTest(operation=operation, signum=signum, primary=primary_type, secondary=secondary_type):
                        case = self.pending_case(operation, "before-effect", signum, integrated=True)
                        primary = primary_type("EXAMPLE primary lifecycle failure")
                        secondary = secondary_type("EXAMPLE secondary release observation")
                        case.primary = primary
                        case.table.close_error = secondary
                        with case.capability_patch, case.signal_patch, case.poll_patch, case.release_patch:
                            if isinstance(primary, Exception):
                                report = case.action()
                                self.assertEqual(report["outcome"], "signal-failed" if operation == "signal" else "wait-failed")
                                self.assertEqual(report["reason"], str(primary))
                            else:
                                with self.assertRaises(primary_type) as caught:
                                    case.action()
                                self.assertIs(caught.exception, primary)
                                self.assertTrue(any(str(secondary) in note for note in primary.__notes__))
                                report = primary.ownership_report
                            self.assert_pending_release(case, operation)
                        self.assertEqual(report["signals"], ["SIGTERM"] if operation == "wait" or signum == signal.SIGKILL else [])
                        self.assertEqual(report["child_exit_confirmed"], operation == "wait")
                        self.assertEqual(report["child_reaped"], operation == "wait")
                        self.assertFalse(report["receipt_available"])
                        self.assertTrue(any(str(secondary) in text for text in report["cleanup_errors"]))
                        self.assertEqual(report["retained_cleanup_errors"], case.birth.release_errors)
                        self.assertEqual(case.controller.close()["retained_cleanup_errors"], report["retained_cleanup_errors"])
                        self.assertEqual(case.table.closes, [case.birth.descriptor])

    def test_deferred_release_failures_keep_integrated_partial_facts(self):
        for operation in ("signal", "wait"):
            for error_type in (RuntimeError, KeyboardInterrupt, SystemExit):
                with self.subTest(operation=operation, error=error_type):
                    case = self.pending_case(operation, "after-effect", integrated=True)
                    failure = error_type("EXAMPLE deferred release failure")
                    case.table.close_error = failure
                    with case.capability_patch, case.signal_patch, case.poll_patch, case.release_patch:
                        if isinstance(failure, Exception):
                            report = case.action()
                            self.assertTrue(any(str(failure) in error for error in report["cleanup_errors"]))
                        else:
                            with self.assertRaises(error_type) as caught:
                                case.action()
                            self.assertIs(caught.exception, failure)
                            report = failure.ownership_report
                        self.assert_pending_release(case, operation)
                    self.assertEqual(report["signals"], ["SIGTERM"])
                    self.assertTrue(report["child_exit_confirmed"])
                    self.assertTrue(report["child_reaped"])
                    self.assertFalse(report["receipt_available"])

    def test_failed_cleanup_diagnostics_cannot_replace_the_primary_operation_failure(self):
        class UnreadableFailure(RuntimeError):
            def __str__(self):
                raise KeyboardInterrupt("EXAMPLE unavailable diagnostic text")
        case = self.pending_case("signal", "before-effect")
        primary = KeyboardInterrupt("EXAMPLE primary operation interruption")
        case.primary = primary
        case.table.close_error = UnreadableFailure()
        with case.capability_patch, case.signal_patch, case.poll_patch, case.release_patch:
            with self.assertRaises(KeyboardInterrupt) as caught:
                case.action()
            self.assertIs(caught.exception, primary)
            self.assertTrue(any("diagnostic text is unavailable" in note for note in primary.__notes__))
            self.assert_pending_release(case, "signal")

    def test_callback_thread_can_close_without_waiting_for_the_active_controller(self):
        case = self.pending_case("signal", "before-effect", integrated=True)
        reports = []
        def close_in_thread():
            thread = threading.Thread(target=lambda: reports.append(case.controller.close()))
            thread.start()
            thread.join(timeout=2)
            self.assertFalse(thread.is_alive())
            return reports[-1]
        case.close = close_in_thread
        other_table, other_controller, other_receipt = self.registered()
        with case.capability_patch, case.signal_patch, case.poll_patch, case.release_patch:
            report = case.action()
            self.assert_pending_release(case, "signal")
        self.assertEqual(report["signals"], ["SIGTERM"])
        self.assertEqual(other_table.procs[TARGET].signals, [])
        self.assertEqual(other_controller.terminate(other_receipt, 0)["outcome"], "terminated")

    def test_concurrent_close_retains_the_originating_release_diagnostic(self):
        case = self.pending_case("signal", "after-effect", integrated=True)
        entered, published, started = threading.Event(), threading.Event(), threading.Event()
        reports, threads = [], []

        class PublicationList(list):
            def __iter__(self):
                snapshot = list(super().__iter__())
                if started.is_set() and not entered.is_set():
                    entered.set()
                    published.wait(timeout=1)
                return iter(snapshot)

            def extend(self, values):
                super().extend(values)
                published.set()

        case.birth.release_errors = PublicationList()
        case.table.close_error = RuntimeError("EXAMPLE deferred release diagnostic")
        original = linux._details

        def details(error):
            result = original(error)
            if case.birth.closed and not case.birth.releasing and not started.is_set():
                started.set()
                thread = threading.Thread(target=lambda: reports.append(case.controller.close()))
                threads.append(thread)
                thread.start()
                self.assertTrue(entered.wait(timeout=2))
            return result

        with case.capability_patch, case.signal_patch, case.poll_patch, case.release_patch, \
                mock.patch.object(linux, "_details", side_effect=details):
            report = case.action()
            for thread in threads:
                thread.join(timeout=2)
                self.assertFalse(thread.is_alive())
        self.assertTrue(started.is_set())
        self.assertTrue(published.is_set())
        self.assertEqual(report["signals"], ["SIGTERM"])
        self.assertTrue(report["child_exit_confirmed"])
        self.assertTrue(report["child_reaped"])
        self.assertTrue(any("EXAMPLE deferred release diagnostic" in text
                            for text in report["cleanup_errors"]))
        self.assertEqual(report["retained_cleanup_errors"], case.birth.release_errors)
        later = case.controller.close()
        self.assertEqual(later["retained_cleanup_errors"], report["retained_cleanup_errors"])
        self.assertEqual(case.table.closes, [case.birth.descriptor])

    def test_child_signal_profiles_are_checked_before_binding(self):
        for name, value in (
            ("profile_flags", 2), ("profile_handler", 1),
            ("profile_handler", 424242), ("profile_errno", errno.EPERM),
        ):
            with self.subTest(profile=name, value=value), mock.patch.object(self, name, value):
                table, controller = self.make()
                report = controller.spawn_owned("EXAMPLE-profile", ARGV, "/EXAMPLE/work")
                self.assertEqual(report["outcome"], "unavailable")
                self.assertEqual(table.spawn_calls, [])
        with mock.patch.object(os, "confstr", return_value="EXAMPLE unsupported C library"):
            table, controller = self.make()
            report = controller.spawn_owned("EXAMPLE-layout", ARGV, "/EXAMPLE/work")
            self.assertEqual(report["outcome"], "unavailable")
            self.assertEqual(table.spawn_calls, [])
        table, controller = self.make()
        table.hooks["after_spawn"] = lambda: setattr(self, "profile_flags", 2)
        report = controller.spawn_owned("EXAMPLE-changed-profile", ARGV, "/EXAMPLE/work")
        self.assertEqual(report["outcome"], "unavailable")
        self.assertEqual(report["child_creation"], "popen-returned")
        self.assertFalse(report["registration_committed"])
        self.assertEqual(table.opens, [])
        table.send_signal.assert_not_called()

    def test_known_reaping_failures_revoke_receipts_and_keep_birth_facts(self):
        for code in (errno.ENOSYS, errno.EPERM, errno.EACCES, errno.EINVAL):
            with self.subTest(errno=code):
                table, controller, old_receipt = self.registered()
                old_descriptor = table.next_fd
                table.spawn_pid = TARGET + 10
                table.waitid_error = OSError(code, "EXAMPLE required child wait unavailable")
                report = controller.spawn_owned("EXAMPLE-required-wait", ARGV, "/EXAMPLE/work")
                birth = table.births[-1]
                self.assertEqual(report["outcome"], "unavailable")
                self.assertEqual(report["child_creation"], "popen-returned")
                self.assertTrue(report["registration_committed"])
                self.assertFalse(report["receipt_available"])
                self.assertNotIn("receipt", report)
                self.assertFalse(report["child_reaped"])
                table.waitid_error = None
                self.assertFalse(table.supported()[0])
                self.assertEqual(controller.terminate(old_receipt, 0)["signals"], [])
                self.assertEqual(controller.terminate(birth.receipt, 0)["signals"], [])
                controller.close()
                self.assertEqual(table.closes, [birth.descriptor, old_descriptor])
                table.send_signal.assert_not_called()

    def test_signal_and_exit_wait_recheck_exact_birth_authority_after_capability(self):
        for operation in ("signal", "wait"):
            for loss in ("mapping", "closed", "authorization"):
                with self.subTest(operation=operation, loss=loss):
                    table, controller, _ = self.registered()
                    birth = table.births[0]
                    descriptor = birth.descriptor
                    original = table.handles[descriptor]
                    replacement = FakeProcess(TARGET + 50, ppid=CONTROLLER)
                    foreign = linux._Birth(
                        child=FakeChild(replacement), pid=replacement.pid,
                        descriptor=descriptor, reap_authorized=True,
                    )
                    actual_supported = table.supported
                    revoked = []
                    def supported():
                        result = actual_supported()
                        if birth.active_operation == operation and not revoked:
                            revoked.append(True)
                            if loss == "mapping":
                                table._owned[descriptor] = foreign
                                table.handles[descriptor] = replacement
                            elif loss == "closed":
                                birth.closed = True
                            else:
                                birth.reap_authorized = False
                        return result
                    self.signal_api.reset_mock()
                    with mock.patch.object(table, "supported", side_effect=supported), mock.patch.object(
                        linux.select, "poll", side_effect=AssertionError("No unauthorized exit poll is allowed."),
                    ):
                        with self.assertRaises(linux._Refusal) as caught:
                            if operation == "signal":
                                table.send_signal(descriptor, signal.SIGTERM)
                            else:
                                table.wait_exit(descriptor, 0)
                        self.assertEqual(caught.exception.outcome, "ownership-lost")
                        controller.close()
                    self.signal_api.assert_not_called()
                    self.assertEqual(original.signals, [])
                    self.assertEqual(replacement.signals, [])
                    self.assertFalse(getattr(replacement, "status_consumed", False))
                    self.assertFalse(birth.exit_confirmed)
                    self.assertFalse(birth.reaped)
                    self.assertIsNone(birth.active_operation)
                    self.assertEqual(table.closes, [descriptor] if loss == "authorization" else [])

    def test_poll_refusals_preserve_term_without_confirmed_exit_or_kill(self):
        for mask in (
            linux.select.POLLNVAL, linux.select.POLLERR,
            linux.select.POLLIN | linux.select.POLLNVAL,
            linux.select.POLLIN | linux.select.POLLERR, 1 << 30, True, "EXAMPLE-mask",
        ):
            with self.subTest(mask=mask):
                table, controller, receipt = self.registered()
                table.procs[TARGET].exits_on = set()
                poller = mock.Mock()
                poller.poll.return_value = [(table.next_fd, mask)]
                with mock.patch.object(linux.select, "poll", return_value=poller):
                    report = controller.terminate(receipt, 0, allow_kill=True)
                self.assertEqual(report["outcome"], "wait-failed")
                self.assertEqual(report["signals"], ["SIGTERM"])
                self.assertFalse(report["child_exit_confirmed"])
                self.assertFalse(report["child_reaped"])
                self.assertTrue(table.procs[TARGET].alive)
                self.assertEqual(table.procs[TARGET].signals, [signal.SIGTERM])
                self.assertEqual(table.closes, [table.next_fd])

    def test_known_exit_wait_failures_keep_term_and_prevent_later_signals(self):
        for code in (errno.ENOSYS, errno.EACCES):
            with self.subTest(errno=code):
                table, controller, receipt = self.registered()
                descriptor = table.next_fd
                table.procs[TARGET].exits_on = set()
                table.spawn_pid = TARGET + 10
                other = controller.spawn_owned("EXAMPLE-other-child", ARGV, "/EXAMPLE/work")
                table.wait_error = OSError(code, "EXAMPLE required exit wait unavailable")
                report = controller.terminate(receipt, 0, allow_kill=True)
                self.assertEqual(report["outcome"], "wait-failed")
                self.assertEqual(report["signals"], ["SIGTERM"])
                self.assertFalse(report["child_exit_confirmed"])
                later = controller.terminate(other["receipt"], 0)
                self.assertEqual(later["signals"], [])
                # The capability failure revokes every outstanding receipt.
                self.assertEqual(later["outcome"], "invalid-session")
                self.assertFalse(later["receipt_available"])
                self.assertFalse(table.supported()[0])
                table.send_signal.assert_called_once_with(descriptor, signal.SIGTERM)

    def test_confirmed_exit_survives_reaping_errors_and_interruptions(self):
        for stage in ("observe", "reap"):
            for error in (
                OSError(errno.EIO, "EXAMPLE child status failure"),
                KeyboardInterrupt("EXAMPLE child status interruption"),
                SystemExit("EXAMPLE child status exit"),
            ):
                with self.subTest(stage=stage, error=type(error).__name__):
                    table, controller, receipt = self.registered()
                    descriptor = table.next_fd
                    setattr(table, "waitid_error" if stage == "observe" else "reap_error", error)
                    if isinstance(error, Exception):
                        report = controller.terminate(receipt, 0)
                        self.assertIn("close_error", report)
                    else:
                        table.close_error = RuntimeError("EXAMPLE secondary close failure")
                        with self.assertRaises(type(error)) as caught:
                            controller.terminate(receipt, 0)
                        self.assertIs(caught.exception, error)
                        report = error.ownership_report
                        self.assertTrue(any("EXAMPLE secondary close failure" in note for note in error.__notes__))
                    self.assertEqual(report["outcome"], "terminated")
                    self.assertEqual(report["signals"], ["SIGTERM"])
                    self.assertTrue(report["child_exit_confirmed"])
                    self.assertFalse(report["child_reaped"])
                    self.assertTrue(report["registration_committed"])
                    self.assertFalse(report["receipt_available"])
                    self.assertEqual(table.closes, [descriptor])
                    calls = self.waitid_api.call_count
                    controller.close()
                    self.assertEqual(self.waitid_api.call_count, calls)

    def test_outside_reaping_and_pid_reuse_never_target_the_replacement(self):
        for stage in ("after-release", "before-observe", "before-reap"):
            with self.subTest(stage=stage):
                table, controller, receipt = self.registered()
                birth = table.births[0]
                original = table.procs[TARGET]
                def outside_reap():
                    original.alive = False
                    original.status_consumed = True
                    table.reuse(same_tick=True)
                if stage == "after-release":
                    controller.close()
                    outside_reap()
                elif stage == "before-observe":
                    outside_reap()
                    with self.assertRaises(ChildProcessError):
                        table.reap(birth)
                    report = controller.terminate(receipt, 0)
                    self.assertEqual(report["outcome"], "ownership-lost")
                    self.assertEqual(report["signals"], [])
                else:
                    table.hooks["waitid:reap"] = outside_reap
                    report = controller.terminate(receipt, 0)
                    self.assertEqual(report["signals"], ["SIGTERM"])
                    self.assertTrue(report["child_exit_confirmed"])
                replacement = table.procs[TARGET]
                self.assertIsNot(replacement, original)
                self.assertTrue(replacement.alive)
                self.assertEqual(replacement.signals, [])
                self.assertFalse(getattr(replacement, "status_consumed", False))
                self.assertFalse(birth.reaped)
                self.assertEqual(table.children[0].waits, [])
                calls = self.waitid_api.call_count
                controller.close()
                table.reap(birth)
                self.assertEqual(self.waitid_api.call_count, calls)
                self.assertEqual(table.closes, [birth.descriptor])

    def test_birth_binding_and_same_handle_term_kill(self):
        table, controller, receipt = self.registered()
        descriptor = table.next_fd
        original = table.procs[TARGET]
        original.exits_on = {signal.SIGKILL}
        report = controller.terminate(receipt, 0.25, allow_kill=True)
        self.assertEqual(report["outcome"], "killed")
        self.assertEqual(report["signals"], ["SIGTERM", "SIGKILL"])
        self.assertEqual((receipt.registration.pid, receipt.registration.start_ticks, original.ppid), (TARGET, 100, CONTROLLER))
        self.assertEqual(table.send_signal.call_args_list, [mock.call(descriptor, signal.SIGTERM), mock.call(descriptor, signal.SIGKILL)])
        self.assertEqual(table.waits, [(descriptor, 0.25), (descriptor, 0.25)])
        self.assertEqual(table.opens, [TARGET])
        self.assertEqual(table.closes, [descriptor])
        self.assertTrue(report["child_reaped"])
        self.assertEqual(controller.terminate(receipt, 0)["outcome"], "invalid-session")
        self.assertEqual(controller.spawn_owned("EXAMPLE-session", ARGV, "/EXAMPLE/work")["outcome"], "duplicate-session")

    def test_validation_freezes_inputs_and_keeps_a_valid_receipt(self):
        table, controller, receipt = self.registered()
        for value in (True, -1, float("nan"), float("inf"), 3601, 10**1000, "EXAMPLE"):
            self.assertEqual(controller.terminate(receipt, value)["outcome"], "invalid-request")
        self.assertEqual(controller.terminate(receipt, 0, allow_kill=1)["outcome"], "invalid-request")
        self.assertEqual(controller.terminate(receipt, 0, min_age_seconds=-1)["outcome"], "invalid-request")
        table.send_signal.assert_not_called()
        self.assertEqual(controller.terminate(receipt, 0)["signals"], ["SIGTERM"])
        table, controller = self.make()
        argv = list(ARGV)
        table.hooks["canonical"] = lambda: argv.append("EXAMPLE-late")
        report = controller.spawn_owned("EXAMPLE-frozen", argv, "/EXAMPLE/work")
        self.assertEqual(report["outcome"], "registered")
        self.assertEqual(table.spawn_calls[0][0], ARGV)
        for session_id in ("", "EXAMPLE session", "../EXAMPLE", True):
            self.assertEqual(controller.spawn_owned(session_id, ARGV, "/EXAMPLE/work")["outcome"], "invalid-request")
        for argv in (("/EXAMPLE/bin/other",), [ARGV[0], True], [ARGV[0]] * 65):
            self.assertEqual(controller.spawn_owned("EXAMPLE-invalid", argv, "/EXAMPLE/work")["outcome"], "invalid-request")

    def test_forged_copied_mutated_and_foreign_receipts(self):
        table, controller, receipt = self.registered()
        _, foreign, foreign_receipt = self.registered()
        for item in (None, {}, receipt.registration, copy.copy(receipt), foreign_receipt):
            self.assertEqual(controller.terminate(item, 0)["outcome"], "invalid-session")
        object.__setattr__(receipt.registration, "uid", True)
        self.assertEqual(controller.terminate(receipt, 0)["outcome"], "invalid-session")
        table.send_signal.assert_not_called()
        self.assertEqual(controller.close()["signals"], [])
        self.assertEqual(foreign.terminate(foreign_receipt, 0)["signals"], ["SIGTERM"])

    def test_exact_context_parent_and_ancestry_are_required(self):
        cases = (("ppid", PARENT), ("cwd", "/EXAMPLE/work/child"), ("executable", "/EXAMPLE/bin/other"), ("uid", 43211), ("start_ticks", 101))
        for name, value in cases:
            table, controller, receipt = self.registered()
            setattr(table.procs[TARGET], name, value)
            report = controller.terminate(receipt, 0)
            self.assertEqual(report["signals"], [])
            table.send_signal.assert_not_called()
        for field, value in (("boot", "EXAMPLE-other"), ("namespace", "pid:[EXAMPLE-other]")):
            table, controller, receipt = self.registered()
            setattr(table, field, value)
            self.assertEqual(controller.terminate(receipt, 0)["signals"], [])
        for pid in (CONTROLLER, PARENT):
            table, controller = self.make()
            table.spawn_pid = pid
            self.assertEqual(controller.spawn_owned("EXAMPLE-protected", ARGV, "/EXAMPLE/work")["signals"], [])

    def test_binding_refuses_wrong_birth_fields_before_receipt(self):
        for name, value in (("ppid", PARENT), ("cwd", "/EXAMPLE/other"), ("executable", "/EXAMPLE/bin/other"), ("uid", 43211)):
            table, controller = self.make()
            table.hooks["after_spawn"] = lambda n=name, v=value: setattr(table.procs[TARGET], n, v)
            report = controller.spawn_owned("EXAMPLE-refused", ARGV, "/EXAMPLE/work")
            self.assertEqual(report["outcome"], "identity-mismatch")
            self.assertNotIn("receipt", report)
            self.assertFalse(report["registration_committed"])
            self.assertEqual(table.closes, [table.next_fd])
            table.send_signal.assert_not_called()

    def test_exit_before_open_and_reuse_after_open_never_signal_replacement(self):
        for stage in ("before_open", "after_open", f"{TARGET}/stat", "before_SIGTERM"):
            table, controller = self.make()
            def exit_or_reuse():
                if stage == "before_open":
                    table.procs[TARGET].alive = False
                else:
                    table.reuse(same_tick=True)
            if stage == "before_SIGTERM":
                receipt = controller.spawn_owned("EXAMPLE-race", ARGV, "/EXAMPLE/work")["receipt"]
                table.hooks[stage] = exit_or_reuse
                report = controller.terminate(receipt, 0, allow_kill=True)
            else:
                table.hooks[stage] = exit_or_reuse
                report = controller.spawn_owned("EXAMPLE-race", ARGV, "/EXAMPLE/work")
            self.assertEqual(report["signals"], [])
            self.assertEqual(table.procs[TARGET].signals, [])
            self.assertEqual(table.closes, [table.next_fd])
        table, controller, receipt = self.registered()
        table.procs[TARGET].exits_on = set()
        table.wait_result = False
        table.hooks["wait"] = lambda: table.reuse(same_tick=True)
        report = controller.terminate(receipt, 0, allow_kill=True)
        self.assertEqual(report["signals"], ["SIGTERM"])
        self.assertEqual(table.procs[TARGET].signals, [])
        self.assertEqual(table.opens, [TARGET])

    def test_capability_permissions_wait_and_close_failures_keep_facts(self):
        table, controller = self.make()
        table.available = False
        self.assertEqual(controller.spawn_owned("EXAMPLE-unavailable", ARGV, "/EXAMPLE/work")["outcome"], "unavailable")
        self.assertEqual(table.spawn_calls, [])
        table, controller = self.make()
        table.open_error = PermissionError("EXAMPLE denied")
        report = controller.spawn_owned("EXAMPLE-open", ARGV, "/EXAMPLE/work")
        self.assertEqual(report["outcome"], "permission-denied")
        self.assertEqual(report["child_creation"], "popen-returned")
        self.assertFalse(report["registration_committed"])
        self.assertEqual(table.closes, [])
        table, controller, receipt = self.registered()
        table.procs[TARGET].exits_on = set()
        table.wait_error = ValueError("EXAMPLE wait failure")
        table.close_error = RuntimeError("EXAMPLE close failure")
        report = controller.terminate(receipt, 0, allow_kill=True)
        self.assertEqual(report["outcome"], "wait-failed")
        self.assertEqual(report["signals"], ["SIGTERM"])
        self.assertIn("EXAMPLE close failure", report["close_error"])
        self.assertEqual(table.closes, [table.next_fd])
        table, controller, receipt = self.registered()
        table.signal_errors[signal.SIGTERM] = OSError(errno.ENOSYS, "EXAMPLE missing syscall")
        self.assertEqual(controller.terminate(receipt, 0)["outcome"], "unavailable")
        self.assertEqual(table.procs[TARGET].signals, [])

    def test_closure_and_reentry_at_effect_boundaries(self):
        stages = ("capability", "canonical", "after_spawn", "after_open", "claimed", f"{TARGET}/stat", f"{TARGET}/exe", "namespace")
        for stage in stages:
            table, controller = self.make()
            table.hooks[stage] = controller.close
            report = controller.spawn_owned("EXAMPLE-closed", ARGV, "/EXAMPLE/work")
            self.assertEqual(report["outcome"], "producer-closed")
            self.assertEqual(report["signals"], [])
            self.assertNotIn("receipt", report)
            self.assertEqual(len(table.closes), len(set(table.closes)))
        table, controller, receipt = self.registered()
        table.procs[TARGET].exits_on = set()
        table.hooks["wait"] = controller.close
        report = controller.terminate(receipt, 0, allow_kill=True)
        self.assertEqual(report["signals"], ["SIGTERM"])
        self.assertEqual(report["outcome"], "producer-closed")
        self.assertEqual(table.closes, [table.next_fd])
        table, controller = self.make()
        nested = []
        table.hooks["claimed"] = lambda: nested.append(controller.spawn_owned("EXAMPLE-reentry", ARGV, "/EXAMPLE/work"))
        self.assertEqual(controller.spawn_owned("EXAMPLE-outer", ARGV, "/EXAMPLE/work")["outcome"], "registered")
        self.assertEqual(nested[0]["outcome"], "producer-busy")
        self.assertEqual(len(table.spawn_calls), 1)

    def test_interrupt_preserves_primary_signals_and_cleanup_failure(self):
        table, controller, receipt = self.registered()
        failure = KeyboardInterrupt("EXAMPLE primary interruption")
        def interrupted():
            raise failure
        table.hooks["wait"] = interrupted
        table.close_error = SystemExit("EXAMPLE cleanup interruption")
        with self.assertRaises(KeyboardInterrupt) as caught:
            controller.terminate(receipt, 0, allow_kill=True)
        self.assertIs(caught.exception, failure)
        self.assertEqual(failure.ownership_report["signals"], ["SIGTERM"])
        self.assertTrue(any("EXAMPLE cleanup interruption" in note for note in failure.__notes__))
        self.assertEqual(table.closes, [table.next_fd])

    def test_explicit_close_attempts_every_retained_handle_once(self):
        table, controller, _ = self.registered()
        first = table.next_fd
        table.spawn_pid = TARGET + 10
        self.assertEqual(controller.spawn_owned("EXAMPLE-next", ARGV, "/EXAMPLE/work")["outcome"], "registered")
        table.close_error = RuntimeError("EXAMPLE close failure")
        report = controller.close()
        self.assertEqual(len(report["close_errors"]), 2)
        self.assertEqual(table.closes, [first, table.next_fd])
        self.assertEqual(controller.close()["close_errors"], [])
        table.send_signal.assert_not_called()

    def test_concurrent_claims_consume_once(self):
        table, controller, receipt = self.registered()
        entered, release = threading.Event(), threading.Event()
        reports = []
        original = self.signal_api.side_effect
        def blocked_signal(descriptor, signum):
            entered.set()
            self.assertTrue(release.wait(timeout=2))
            return original(descriptor, signum)
        def consume():
            reports.append(controller.terminate(receipt, 0))
        thread = threading.Thread(target=consume)
        with mock.patch.object(self.signal_api, "side_effect", blocked_signal):
            thread.start()
            try:
                self.assertTrue(entered.wait(timeout=2))
                overlap = controller.terminate(receipt, 0)
                self.assertEqual(overlap["outcome"], "producer-busy")
                self.assertEqual(overlap["signals"], [])
                self.assertEqual(table.closes, [])
            finally:
                release.set()
                thread.join(timeout=2)
        self.assertFalse(thread.is_alive())
        self.assertEqual([report["outcome"] for report in reports], ["terminated"])
        completed = controller.terminate(receipt, 0)
        self.assertEqual(completed["outcome"], "invalid-session")
        self.assertEqual(completed["signals"], [])
        self.assertEqual(table.send_signal.call_count, 1)
        self.assertEqual(table.closes, [table.next_fd])

    def test_default_cleanup_and_public_fake_guard_stay_unchanged(self):
        self.assertIsNone(NoTrustedOwnershipSource().trusted_registrations())
        self.assertEqual(NoTrustedOwnershipSource.reason, "no-trusted-ownership-producer")
        with self.assertRaises(ValueError):
            OfflineOwnershipProducer(BACKEND(), controller_pid=CONTROLLER, name="EXAMPLE-controller")


class RealOwnedChildTests(unittest.TestCase):
    def test_owned_child_term_and_close_use_only_the_original_handle(self):
        supported, reason = BACKEND().supported()
        if not supported:
            self.skipTest(reason)
        executable = os.path.realpath(sys.executable)
        workspace = os.path.realpath(tempfile.gettempdir())
        for send_term in (True, False):
            with self.subTest(send_term=send_term):
                controller = linux.LinuxOwnedChildController(executable)
                backend = controller._backend
                backend.send_signal = mock.Mock(wraps=backend.send_signal)
                backend.wait_exit = mock.Mock(wraps=backend.wait_exit)
                backend.pidfd_open = mock.Mock(wraps=backend.pidfd_open)
                backend._close_fd = mock.Mock(wraps=backend._close_fd)
                child = None
                try:
                    report = controller.spawn_owned("EXAMPLE-disposable", [executable, "-I", "-S", "-c", "import time; time.sleep(3)"], workspace)
                    if backend.births:
                        child = backend.births[0].child
                    if report["outcome"] in ("unavailable", "permission-denied", "identity-unavailable"):
                        self.skipTest(report.get("reason", "Child capability is unavailable."))
                    self.assertEqual(report["outcome"], "registered")
                    descriptor = backend.births[0].descriptor
                    if send_term:
                        report = controller.terminate(report["receipt"], 1)
                        if report["outcome"] in ("unavailable", "permission-denied") and not report["signals"]:
                            self.skipTest(report.get("reason", "Child signalling capability is unavailable."))
                        self.assertEqual(report["outcome"], "terminated")
                        self.assertEqual(report["signals"], ["SIGTERM"])
                        self.assertTrue(report["child_exit_confirmed"])
                        self.assertTrue(report["child_reaped"])
                        self.assertEqual(child.returncode, -signal.SIGTERM)
                        backend.send_signal.assert_called_once_with(descriptor, signal.SIGTERM)
                        self.assertEqual(backend.wait_exit.call_args.args[0], descriptor)
                    else:
                        self.assertTrue(backend.wait_exit(descriptor, 5))
                        controller.close()
                        backend.send_signal.assert_not_called()
                        self.assertEqual(child.returncode, 0)
                    backend.pidfd_open.assert_called_once_with(child.pid)
                    backend._close_fd.assert_called_once_with(descriptor)
                finally:
                    for birth in backend.births:
                        if backend._retained(birth) and backend.eligible(birth):
                            backend.wait_exit(birth.descriptor, 5)
                    controller.close()


if __name__ == "__main__":
    unittest.main()
