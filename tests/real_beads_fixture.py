from __future__ import annotations

import os
import signal
import subprocess
import unittest
from collections.abc import Mapping, Sequence


REAL_BEADS_FIXTURE_TIMEOUT_SECONDS = 20

_real_beads_unavailable_reason: str | None = None


def run_fixture_subprocess(
    command: Sequence[str | os.PathLike[str]],
    *,
    cwd: str | os.PathLike[str],
    check: bool = False,
    capture_output: bool = False,
    text: bool = False,
    stdout: int | None = None,
    stderr: int | None = None,
    env: Mapping[str, str] | None = None,
) -> subprocess.CompletedProcess[str] | subprocess.CompletedProcess[bytes]:
    """Run one fixture command with a hard deadline and descendant cleanup."""

    if capture_output:
        if stdout is not None or stderr is not None:
            raise ValueError("stdout and stderr may not be used with capture_output")
        stdout = subprocess.PIPE
        stderr = subprocess.PIPE

    argv = list(command)
    process = subprocess.Popen(
        argv,
        cwd=cwd,
        env=env,
        stdout=stdout,
        stderr=stderr,
        text=text,
        start_new_session=True,
    )
    try:
        output, errors = process.communicate(timeout=REAL_BEADS_FIXTURE_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        except OSError:
            process.kill()
        output, errors = process.communicate()
        raise subprocess.TimeoutExpired(
            argv,
            REAL_BEADS_FIXTURE_TIMEOUT_SECONDS,
            output=output,
            stderr=errors,
        ) from None

    completed = subprocess.CompletedProcess(
        argv,
        process.returncode,
        stdout=output,
        stderr=errors,
    )
    if check:
        completed.check_returncode()
    return completed


def initialize_real_beads(
    command: Sequence[str | os.PathLike[str]],
    *,
    cwd: str | os.PathLike[str],
    check: bool = False,
    capture_output: bool = False,
    text: bool = False,
    stdout: int | None = None,
    stderr: int | None = None,
    env: Mapping[str, str] | None = None,
) -> subprocess.CompletedProcess[str] | subprocess.CompletedProcess[bytes]:
    """Initialize optional Beads fixtures once, caching only timeout failures."""

    global _real_beads_unavailable_reason

    if _real_beads_unavailable_reason is not None:
        raise unittest.SkipTest(_real_beads_unavailable_reason)

    try:
        return run_fixture_subprocess(
            command,
            cwd=cwd,
            check=check,
            capture_output=capture_output,
            text=text,
            stdout=stdout,
            stderr=stderr,
            env=env,
        )
    except subprocess.TimeoutExpired as exc:
        _real_beads_unavailable_reason = (
            "optional real-Beads fixture initialization timed out after "
            f"{REAL_BEADS_FIXTURE_TIMEOUT_SECONDS}s"
        )
        raise unittest.SkipTest(_real_beads_unavailable_reason) from exc
