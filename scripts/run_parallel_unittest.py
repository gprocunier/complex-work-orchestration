#!/usr/bin/env python3
"""Run unittest modules in eight isolated subprocess shards.

This is a temporary fixed-width runner.  The follow-up Bead
``complex-work-orchestration-p4vg.95`` replaces the constant with
topology-aware, duration-balanced scheduling.
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import TextIO


DEFAULT_WORKERS = 8
# These modules either observe or temporarily mutate the repository root, or
# rely on real Beads timestamp transitions.  Running them concurrently creates
# false containment drift or timing failures, so they remain one safety lane.
SERIAL_TEST_FILES = frozenset(
    {
        "test_continue_sprint.py",
        "test_native_pool_workspace.py",
        "test_native_precommit.py",
        "test_native_precommit_packet.py",
        "test_native_recovery.py",
        "test_native_release.py",
        "test_native_retry_supervision.py",
        "test_native_worker_planning.py",
        "test_supervise_native_worker.py",
    }
)
RESULT_PATTERN = re.compile(r"Ran\s+(\d+)\s+tests?\s+in\s+([0-9.]+)s")


@dataclass
class Shard:
    index: int
    paths: list[Path]
    estimated_bytes: int = 0


@dataclass
class RunningShard:
    shard: Shard
    process: subprocess.Popen[str]
    log_path: Path
    log_file: TextIO
    started: float
    temp_directory: tempfile.TemporaryDirectory[str]


@dataclass
class RunSummary:
    exit_code: int
    tests: int | None
    wall_seconds: float


def discover_test_files(start_directory: Path, pattern: str) -> list[Path]:
    """Return deterministic regular-file test paths beneath *start_directory*."""
    if not start_directory.is_dir():
        raise ValueError(f"start directory is not a directory: {start_directory}")
    return sorted(
        (path.resolve() for path in start_directory.rglob(pattern) if path.is_file()),
        key=lambda path: path.as_posix(),
    )


def build_shards(paths: list[Path], workers: int) -> list[Shard]:
    """Distribute files deterministically using file size as a temporary weight."""
    if workers < 1:
        raise ValueError("workers must be a positive integer")
    if not paths:
        return []
    shards = [Shard(index=index, paths=[]) for index in range(min(workers, len(paths)))]
    weighted = sorted(paths, key=lambda path: (-path.stat().st_size, path.as_posix()))
    for path in weighted:
        target = min(shards, key=lambda shard: (shard.estimated_bytes, shard.index))
        target.paths.append(path)
        target.estimated_bytes += path.stat().st_size
    for shard in shards:
        shard.paths.sort(key=lambda path: path.as_posix())
    return shards


def _result(log: str) -> tuple[int | None, float | None]:
    matches = list(RESULT_PATTERN.finditer(log))
    if not matches:
        return None, None
    match = matches[-1]
    return int(match.group(1)), float(match.group(2))


def _terminate(running: list[RunningShard]) -> None:
    for entry in running:
        if entry.process.poll() is None:
            entry.process.terminate()
    for entry in running:
        if entry.process.poll() is None:
            try:
                entry.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                entry.process.kill()
                entry.process.wait()
        entry.log_file.close()
        entry.temp_directory.cleanup()


def run_shards(
    shards: list[Shard],
    *,
    working_directory: Path,
    start_directory: Path,
    artifacts_directory: Path,
    verbose: bool,
    label: str = "parallel unittest",
    directory_prefix: str = "worker",
) -> RunSummary:
    """Run all shards concurrently and aggregate their deterministic results."""
    running: list[RunningShard] = []
    started = time.monotonic()
    try:
        for shard in shards:
            worker_root = artifacts_directory / f"{directory_prefix}-{shard.index + 1:02d}"
            worker_root.mkdir(parents=True, mode=0o700)
            temp_directory = tempfile.TemporaryDirectory(
                prefix=f"cwo-{directory_prefix}-{shard.index + 1:02d}-"
            )
            temp_root = Path(temp_directory.name)
            log_path = worker_root / "unittest.log"
            log_file = log_path.open("w", encoding="utf-8")
            command = [sys.executable, "-m", "unittest"]
            command.append("-v" if verbose else "-q")
            command.extend(str(path) for path in shard.paths)
            environment = os.environ.copy()
            python_path = [str(start_directory)]
            if environment.get("PYTHONPATH"):
                python_path.append(environment["PYTHONPATH"])
            environment.update(
                {
                    "TMPDIR": str(temp_root),
                    "TMP": str(temp_root),
                    "TEMP": str(temp_root),
                    "PYTHONDONTWRITEBYTECODE": "1",
                    "PYTHONPATH": os.pathsep.join(python_path),
                }
            )
            try:
                process = subprocess.Popen(
                    command,
                    cwd=working_directory,
                    env=environment,
                    stdout=log_file,
                    stderr=subprocess.STDOUT,
                    text=True,
                )
            except OSError:
                log_file.close()
                temp_directory.cleanup()
                raise
            running.append(
                RunningShard(
                    shard=shard,
                    process=process,
                    log_path=log_path,
                    log_file=log_file,
                    started=time.monotonic(),
                    temp_directory=temp_directory,
                )
            )
        for entry in running:
            entry.process.wait()
            entry.log_file.close()
    except (KeyboardInterrupt, OSError) as exc:
        _terminate(running)
        elapsed = time.monotonic() - started
        print(f"{label} aborted: {exc}", file=sys.stderr)
        return RunSummary(exit_code=2, tests=None, wall_seconds=elapsed)

    failures = 0
    total_tests = 0
    parse_complete = True
    for entry in running:
        log = entry.log_path.read_text(encoding="utf-8", errors="replace")
        tests, test_seconds = _result(log)
        parse_complete = parse_complete and tests is not None
        total_tests += tests or 0
        elapsed = time.monotonic() - entry.started
        status = "PASS" if entry.process.returncode == 0 else "FAIL"
        failures += int(entry.process.returncode != 0)
        detail = f"tests={tests}" if tests is not None else "tests=unknown"
        if test_seconds is not None:
            detail += f" test_seconds={test_seconds:.3f}"
        print(
            f"[shard {entry.shard.index + 1:02d}/{len(shards):02d}] {status} "
            f"files={len(entry.shard.paths)} {detail} wall_seconds={elapsed:.3f}"
        )
        if entry.process.returncode != 0:
            print(f"--- shard {entry.shard.index + 1:02d} log ---", file=sys.stderr)
            print(log, file=sys.stderr, end="" if log.endswith("\n") else "\n")
        entry.temp_directory.cleanup()

    wall_seconds = time.monotonic() - started
    status = "PASS" if failures == 0 else "FAIL"
    test_detail = str(total_tests) if parse_complete else "incomplete"
    print(
        f"{label}: {status} workers={len(shards)} tests={test_detail} "
        f"wall_seconds={wall_seconds:.3f}"
    )
    return RunSummary(
        exit_code=0 if failures == 0 else 1,
        tests=total_tests if parse_complete else None,
        wall_seconds=wall_seconds,
    )


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run unittest files in a temporary fixed-width process pool."
    )
    parser.add_argument("--workers", type=int, default=DEFAULT_WORKERS)
    parser.add_argument("--start-directory", default="tests")
    parser.add_argument("--pattern", default="test_*.py")
    parser.add_argument("--working-directory", default=".")
    parser.add_argument(
        "--artifacts-dir",
        help="Preserve per-worker logs here; default logs are removed after the run.",
    )
    parser.add_argument("--verbose", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if args.workers < 1:
        print("parallel unittest: --workers must be a positive integer", file=sys.stderr)
        return 2
    working_directory = Path(args.working_directory).expanduser().resolve()
    start_directory = Path(args.start_directory).expanduser()
    if not start_directory.is_absolute():
        start_directory = working_directory / start_directory
    try:
        paths = discover_test_files(start_directory, args.pattern)
        serial_paths = [path for path in paths if path.name in SERIAL_TEST_FILES]
        parallel_paths = [path for path in paths if path.name not in SERIAL_TEST_FILES]
        shards = build_shards(parallel_paths, args.workers)
    except (OSError, ValueError) as exc:
        print(f"parallel unittest: {exc}", file=sys.stderr)
        return 2
    if not shards and not serial_paths:
        print("parallel unittest: no test files matched", file=sys.stderr)
        return 2

    print(
        f"parallel unittest: files={len(paths)} parallel_files={len(parallel_paths)} "
        f"serial_files={len(serial_paths)} workers={len(shards)} "
        f"configured_workers={args.workers}"
    )
    overall_started = time.monotonic()

    def execute(artifacts_directory: Path) -> int:
        summaries: list[RunSummary] = []
        if shards:
            summaries.append(
                run_shards(
                    shards,
                    working_directory=working_directory,
                    start_directory=start_directory,
                    artifacts_directory=artifacts_directory,
                    verbose=args.verbose,
                )
            )
        if serial_paths:
            serial_shard = Shard(
                index=0,
                paths=serial_paths,
                estimated_bytes=sum(path.stat().st_size for path in serial_paths),
            )
            summaries.append(
                run_shards(
                    [serial_shard],
                    working_directory=working_directory,
                    start_directory=start_directory,
                    artifacts_directory=artifacts_directory,
                    verbose=args.verbose,
                    label="serial unittest",
                    directory_prefix="serial-worker",
                )
            )
        exit_code = 2 if any(item.exit_code == 2 for item in summaries) else int(
            any(item.exit_code for item in summaries)
        )
        tests = (
            sum(item.tests for item in summaries if item.tests is not None)
            if all(item.tests is not None for item in summaries)
            else None
        )
        status = "PASS" if exit_code == 0 else "FAIL"
        print(
            f"fixed-width unittest: {status} configured_workers={args.workers} "
            f"tests={tests if tests is not None else 'incomplete'} "
            f"wall_seconds={time.monotonic() - overall_started:.3f}"
        )
        return exit_code

    if args.artifacts_dir:
        artifacts_directory = Path(args.artifacts_dir).expanduser().resolve()
        artifacts_directory.mkdir(parents=True, exist_ok=True)
        return execute(artifacts_directory)
    with tempfile.TemporaryDirectory(prefix="cwo-parallel-unittest-") as temporary:
        return execute(Path(temporary))


if __name__ == "__main__":
    raise SystemExit(main())
