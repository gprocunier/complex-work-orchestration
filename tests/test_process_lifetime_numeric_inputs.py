from __future__ import annotations

import signal
import sys
import unittest
from unittest import mock

from tests.test_process_identity import FakeKernel, PID, registration

from cwo_core.process_identity import MAX_GRACE_SECONDS, PidfdTerminator


class ProcessLifetimeNumericInputTests(unittest.TestCase):
    def assert_invalid_duration(self, field: str, value: object) -> None:
        kernel = FakeKernel()
        options = {"grace_seconds": 1, field: value}
        with (
            mock.patch.object(kernel, "supported", wraps=kernel.supported) as supported,
            mock.patch.object(kernel, "pidfd_open", wraps=kernel.pidfd_open) as opened,
            mock.patch.object(kernel, "send_signal", wraps=kernel.send_signal) as sent,
        ):
            outcome = PidfdTerminator(kernel).terminate(registration(), **options)
        self.assertEqual(
            outcome,
            {"outcome": "invalid-request", "reason": f"{field}-invalid", "signals": []},
        )
        supported.assert_not_called()
        opened.assert_not_called()
        sent.assert_not_called()
        self.assertEqual(kernel.opened, [])
        self.assertEqual(kernel.handles, {})
        self.assertEqual(kernel.procs[PID].signals, [])
        self.assertTrue(kernel.procs[PID].alive)

    def test_invalid_durations_are_refused_before_adapter_activity(self) -> None:
        invalid_values = (
            True, False, -(10**400), -1, -0.25,
            float("-inf"), float("inf"), float("nan"),
            "0", None, [], {}, (), set(),
        )
        for field in ("grace_seconds", "min_age_seconds"):
            for case, value in enumerate(invalid_values):
                with self.subTest(field=field, case=case):
                    self.assert_invalid_duration(field, value)

    def test_grace_upper_bound_refuses_large_integers_and_floats(self) -> None:
        invalid_values = (10**400, int(MAX_GRACE_SECONDS) + 1, MAX_GRACE_SECONDS + 0.25)
        for case, value in enumerate(invalid_values):
            with self.subTest(case=case):
                self.assert_invalid_duration("grace_seconds", value)

    def test_grace_values_preserve_one_signal_and_wait(self) -> None:
        values = (0, 0.0, -0.0, 1, 0.25, int(MAX_GRACE_SECONDS), MAX_GRACE_SECONDS)
        for case, value in enumerate(values):
            with self.subTest(case=case):
                kernel = FakeKernel()
                original = kernel.procs[PID]
                with mock.patch.object(kernel, "wait_exit", wraps=kernel.wait_exit) as waited:
                    outcome = PidfdTerminator(kernel).terminate(registration(), grace_seconds=value)
                self.assertEqual(outcome, {"outcome": "terminated", "signals": ["SIGTERM"]})
                waited.assert_called_once_with(kernel.next_fd, value)
                self.assertEqual(kernel.opened, [PID])
                self.assertEqual(kernel.handles, {})
                self.assertEqual(original.signals, [signal.SIGTERM])
                self.assertFalse(original.alive)

    def test_minimum_age_values_include_exact_age_boundary(self) -> None:
        values = (0, 0.0, -0.0, 1, 0.25, 9999, 9999.0)
        for case, value in enumerate(values):
            with self.subTest(case=case):
                kernel = FakeKernel()
                outcome = PidfdTerminator(kernel).terminate(
                    registration(), grace_seconds=1, min_age_seconds=value
                )
                self.assertEqual(outcome, {"outcome": "terminated", "signals": ["SIGTERM"]})
                self.assertEqual(kernel.procs[PID].signals, [signal.SIGTERM])
                self.assertEqual(kernel.opened, [PID])
                self.assertEqual(kernel.handles, {})

    def test_large_finite_minimum_ages_remain_not_stale(self) -> None:
        for case, value in enumerate((10**100, 10**400, sys.float_info.max)):
            with self.subTest(case=case):
                kernel = FakeKernel()
                outcome = PidfdTerminator(kernel).terminate(
                    registration(), grace_seconds=1, min_age_seconds=value
                )
                self.assertEqual(
                    outcome, {"outcome": "not-stale", "age_seconds": 9999.0, "signals": []}
                )
                self.assertEqual(kernel.procs[PID].signals, [])
                self.assertTrue(kernel.procs[PID].alive)
                self.assertEqual(kernel.opened, [PID])
                self.assertEqual(kernel.handles, {})

    def test_young_age_preserves_exact_not_stale_record(self) -> None:
        kernel = FakeKernel()
        kernel.uptime = 1.5
        outcome = PidfdTerminator(kernel).terminate(
            registration(), grace_seconds=0.25, min_age_seconds=0.75
        )
        self.assertEqual(
            outcome, {"outcome": "not-stale", "age_seconds": 0.5, "signals": []}
        )
        self.assertEqual(kernel.procs[PID].signals, [])
        self.assertTrue(kernel.procs[PID].alive)
        self.assertEqual(kernel.opened, [PID])
        self.assertEqual(kernel.handles, {})

    def test_unrelated_open_failure_stays_visible(self) -> None:
        kernel = FakeKernel()
        failure = RuntimeError("fake open failure")
        kernel.open_error = failure
        with self.assertRaises(RuntimeError) as raised:
            PidfdTerminator(kernel).terminate(registration(), grace_seconds=1)
        self.assertIs(raised.exception, failure)
        self.assertEqual(kernel.opened, [PID])
        self.assertEqual(kernel.handles, {})
        self.assertEqual(kernel.procs[PID].signals, [])


if __name__ == "__main__":
    unittest.main()
