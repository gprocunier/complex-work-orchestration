from __future__ import annotations

import os
import signal
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from tests import real_beads_fixture
from tests.real_beads_fixture import (
    REAL_BEADS_FIXTURE_TIMEOUT_SECONDS,
    initialize_real_beads,
    run_fixture_subprocess,
)


class RealBeadsFixtureTests(unittest.TestCase):
    def test_git_fixture_commits_with_local_synthetic_identity(self) -> None:
        environment = {
            name: value for name, value in os.environ.items()
            if not name.startswith("GIT_") and name != "EMAIL"
        }
        environment.update(GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1")
        with tempfile.TemporaryDirectory() as root:
            for arguments in (
                ["init", "-q", "--template="],
                ["config", "--local", "user.useConfigOnly", "true"],
            ):
                run_fixture_subprocess(
                    ["git", *arguments], cwd=root, env=environment,
                    check=True, capture_output=True,
                )
            real_beads_fixture.configure_git_fixture(root, env=environment)
            run_fixture_subprocess(
                ["git", "commit", "--allow-empty", "-qm", "Neutral fixture"],
                cwd=root, env=dict(environment), check=True, capture_output=True,
            )
            recorded = run_fixture_subprocess(
                ["git", "log", "-1", "--format=%an%n%ae%n%cn%n%ce"],
                cwd=root, env=dict(environment), check=True, capture_output=True, text=True,
            )
        self.assertEqual(recorded.stdout.splitlines(), [
            "CWO test", "cwo-test@example.invalid",
            "CWO test", "cwo-test@example.invalid",
        ])

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
        for seconds in (REAL_BEADS_FIXTURE_TIMEOUT_SECONDS, 65):
            with self.subTest(timeout_seconds=seconds):
                process = mock.Mock()
                process.pid = 12345
                process.communicate.side_effect = [
                    subprocess.TimeoutExpired(["bd", "init"], seconds),
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
                    run_fixture_subprocess(
                        ["bd", "init"], cwd="/tmp", timeout_seconds=seconds
                    )

                killpg.assert_called_once_with(12345, signal.SIGKILL)
                self.assertEqual(
                    process.communicate.call_args_list,
                    [mock.call(timeout=seconds), mock.call()],
                )
                self.assertEqual(raised.exception.timeout, seconds)
                self.assertEqual(raised.exception.output, "partial output")
                self.assertEqual(raised.exception.stderr, "partial errors")

    def test_explicit_deadline_completes_or_reaps_real_child(self) -> None:
        original_popen = subprocess.Popen
        children = []

        def start(*args, **kwargs):
            process = original_popen(*args, **kwargs)
            children.append(process)
            return process

        with mock.patch.object(real_beads_fixture.subprocess, "Popen", side_effect=start):
            completed = run_fixture_subprocess(
                [sys.executable, "-c", "print('completed')"],
                cwd=tempfile.gettempdir(),
                capture_output=True,
                text=True,
                check=True,
                timeout_seconds=5,
            )
            with self.assertRaises(subprocess.TimeoutExpired) as raised:
                run_fixture_subprocess(
                    [sys.executable, "-c", "import time; time.sleep(60)"],
                    cwd=tempfile.gettempdir(),
                    capture_output=True,
                    timeout_seconds=0.1,
                )

        self.assertEqual(completed.stdout, "completed\n")
        self.assertEqual(raised.exception.timeout, 0.1)
        self.assertEqual([child.returncode for child in children], [0, -signal.SIGKILL])
        for child in children:
            with self.assertRaises(ChildProcessError):
                os.waitpid(child.pid, os.WNOHANG)

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
