from __future__ import annotations

import signal
import subprocess
import unittest
from unittest import mock

from tests import real_beads_fixture
from tests.real_beads_fixture import (
    REAL_BEADS_FIXTURE_TIMEOUT_SECONDS,
    initialize_real_beads,
    run_fixture_subprocess,
)


class RealBeadsFixtureTests(unittest.TestCase):
    def test_runner_starts_isolated_process_group(self) -> None:
        process = mock.Mock()
        process.communicate.return_value = ("output", "errors")
        process.returncode = 0

        with mock.patch.object(
            real_beads_fixture.subprocess,
            "Popen",
            return_value=process,
        ) as popen:
            completed = run_fixture_subprocess(
                ["bd", "show", "example"],
                cwd="/tmp",
                capture_output=True,
                text=True,
            )

        self.assertEqual(completed.stdout, "output")
        self.assertEqual(completed.stderr, "errors")
        popen.assert_called_once_with(
            ["bd", "show", "example"],
            cwd="/tmp",
            env=None,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
        process.communicate.assert_called_once_with(
            timeout=REAL_BEADS_FIXTURE_TIMEOUT_SECONDS
        )

    def test_timeout_kills_process_group_and_reaps_child(self) -> None:
        process = mock.Mock()
        process.pid = 12345
        process.communicate.side_effect = [
            subprocess.TimeoutExpired(["bd", "init"], 20),
            ("partial output", "partial errors"),
        ]

        with (
            mock.patch.object(
                real_beads_fixture.subprocess,
                "Popen",
                return_value=process,
            ),
            mock.patch.object(real_beads_fixture.os, "killpg") as killpg,
            self.assertRaises(subprocess.TimeoutExpired) as raised,
        ):
            run_fixture_subprocess(["bd", "init"], cwd="/tmp")

        killpg.assert_called_once_with(12345, signal.SIGKILL)
        self.assertEqual(
            process.communicate.call_args_list,
            [
                mock.call(timeout=REAL_BEADS_FIXTURE_TIMEOUT_SECONDS),
                mock.call(),
            ],
        )
        self.assertEqual(raised.exception.output, "partial output")
        self.assertEqual(raised.exception.stderr, "partial errors")

    def test_initialization_timeout_is_cached_as_optional_skip(self) -> None:
        timeout = subprocess.TimeoutExpired(["bd", "init"], 20)
        with (
            mock.patch.object(
                real_beads_fixture,
                "_real_beads_unavailable_reason",
                None,
            ),
            mock.patch.object(
                real_beads_fixture,
                "run_fixture_subprocess",
                side_effect=timeout,
            ) as runner,
        ):
            with self.assertRaisesRegex(
                unittest.SkipTest,
                "initialization timed out after 20s",
            ):
                initialize_real_beads(["bd", "init"], cwd="/tmp")
            with self.assertRaisesRegex(
                unittest.SkipTest,
                "initialization timed out after 20s",
            ):
                initialize_real_beads(["bd", "init"], cwd="/tmp")

        runner.assert_called_once()


if __name__ == "__main__":
    unittest.main()
