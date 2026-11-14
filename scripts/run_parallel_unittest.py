#!/usr/bin/env python3
"""Run ordinary unittest files or method groups in bounded subprocesses.

Cost hints pack selected slow modules toward 75 seconds; atomic methods and
repeated fixture costs can exceed that goal. Hints never select or skip tests.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import re
import subprocess
import sys
import tempfile
import time
import unittest
from dataclasses import dataclass
from pathlib import Path
from typing import TextIO


DEFAULT_WORKERS = 8
METHOD_SHARDED_TEST_FILES = frozenset({
    "test_registered_finite_tool_wiring.py", "test_registered_finite_input.py",
    "test_registered_native_pool_host.py", "test_native_artifact_delivery_closure.py",
    "test_registered_native_pool_profiles.py", "test_offline_native_adjudication.py",
    "test_offline_fake_artifact_promotion.py", "test_registered_n1_workflow.py",
    "test_outbound_screen.py", "test_qualified_closure.py",
    "test_registered_native_pool_retry.py", "test_registered_server_requests.py",
})
TARGET_WORKUNIT_SECONDS = 75.0
MAX_PACKED_SECONDS = 90.0
COST_FILE = Path(__file__).resolve().parents[1] / "policy" / "unittest-shard-costs.json"
DEDICATED_PARALLEL_TEST_FILES = frozenset({
    "test_registered_finite_tool_wiring.py",
    "test_outbound_screen.py",
    "test_registered_native_pool_host.py",
})
# These modules observe or temporarily mutate the repository root. Running
# them concurrently creates false containment drift, so they retain one lane.
# Continuation tests use separate temporary Beads databases and read-only source;
# their content-drift assertions do not require distinct wall-clock timestamps.
# Supervision tests also read source; receipts/state/registry live in private temp roots.
# Retry supervision uses the same private roots.
# Worker planning also confines receipts, registry and sequence specs to private roots.
SERIAL_TEST_FILES = frozenset(
    {
        "test_native_pool_workspace.py",
        "test_native_precommit.py",
        "test_native_precommit_packet.py",
        "test_native_recovery.py",
        "test_native_release.py",
    }
)
# Measured case seconds for costly, currently parallel families.
# Scores use byte-equivalent units so unmeasured files retain the existing
# byte-size floor. These hints affect packing only, never discovery or skips.
MEASURED_TEST_SECONDS = {
    'test_activation_closure_containment.py': 12.839,
    'test_argparse_screening.py': 11.871,
    'test_authoritative_artifact_requirement.py': 22.6,
    'test_beads_dash_id_safety.py': 104.854,
    'test_candidate_identity.py': 13.221,
    'test_code_health.py': 29.378,
    'test_codex_protocol_fact_metadata.py': 50.976,
    'test_combined_review_binding_preparation.py': 80.039,
    'test_comparative_evaluation.py': 10.354,
    'test_continue_sprint.py': 51.682,
    'test_executor_registry_schema.py': 10.096,
    'test_expert_registry_schema.py': 41.133,
    'test_final_review_binding_preparation.py': 11.407,
    'test_guarded_artifact_target.py': 70.259,
    'test_install_dependency_closure.py': 19.943,
    'test_install_projection.py': 97.04,
    'test_install_record_verification.py': 105.255,
    'test_install_script.py': 32.433,
    'test_installed_baseline_compatibility.py': 26.451,
    'test_installed_checked_consumers.py': 35.004,
    'test_installed_combined_review_consumers.py': 166.402,
    'test_installed_final_review_consumers.py': 173.619,
    'test_installed_graph_consumers.py': 41.905,
    'test_installed_in_thread_plan_consumers.py': 271.882,
    'test_installed_numeric_compatibility.py': 19.13,
    'test_installed_numeric_rollback.py': 22.426,
    'test_installed_route_ledger_consumers.py': 69.677,
    'test_installed_server_frame_consumers.py': 63.621,
    'test_local_admission_preparation.py': 21.009,
    'test_maintenance_native_runtime.py': 28.673,
    'test_maintenance_qualification.py': 22.945,
    'test_maintenance_route_fit.py': 10.165,
    'test_mixed_delivery_closure.py': 50.499,
    'test_native_activation_preview.py': 104.308,
    'test_native_artifact_delivery_closure.py': 257.253,
    'test_native_pool_admission.py': 13.116,
    'test_native_pool_phase1_certification.py': 86.785,
    'test_native_precommit_packet.py': 21.071,
    'test_native_retry_supervision.py': 35.218,
    'test_native_worker_execution_policy_schema.py': 121.018,
    'test_native_worker_planning.py': 30.731,
    'test_offline_admitted_n1.py': 111.912,
    'test_offline_artifact_validation.py': 19.865,
    'test_offline_closure_client.py': 62.051,
    'test_offline_delivery_closure.py': 49.099,
    'test_offline_fake_artifact_promotion.py': 214.638,
    'test_offline_host_crash_matrix.py': 12.077,
    'test_offline_native_adjudication.py': 214.085,
    'test_offline_profile_input.py': 44.988,
    'test_outbound_screen.py': 388.443,
    'test_policy_schema.py': 115.888,
    'test_post_move_campaign_gate.py': 10.08,
    'test_production_closure.py': 91.938,
    'test_prompt_coach.py': 11.644,
    'test_provider_registry_schema.py': 19.225,
    'test_qualified_closure.py': 156.843,
    'test_qualified_n1_host.py': 24.362,
    'test_qualified_review_dispatch.py': 29.233,
    'test_qualified_risk_use.py': 109.071,
    'test_registered_finite_input.py': 81.567,
    # Measured case sum; reserve this newly dominant family.
    'test_registered_finite_tool_wiring.py': 661.994,
    'test_registered_n1_factory.py': 57.237,
    'test_registered_n1_workflow.py': 303.58,
    'test_registered_native_pool_host.py': 419.709,
    'test_registered_native_pool_profiles.py': 292.797,
    'test_registered_native_pool_retry.py': 226.545,
    'test_registered_server_requests.py': 123.676,
    'test_retirement_delivery_closure.py': 15.236,
    'test_return_adjudication.py': 17.922,
    'test_routing_risk_features.py': 97.446,
    'test_run_admitted_native_pool_transaction.py': 89.886,
    'test_run_native_pool_live_canaries.py': 42.223,
    'test_source_hold_clearance.py': 14.571,
    'test_source_risk_narrowing.py': 42.798,
    'test_supervise_native_worker.py': 45.644,
    'test_supervision_transport.py': 13.37,
    'test_turn_observations.py': 13.996,
    'test_w08_useful_positive.py': 77.583,
    'test_w20_affected_contract_w13.py': 18.366,
    'test_workflow_adjudication.py': 176.171,
    'test_workspace_inert_inspection.py': 48.711,
}

RESULT_PATTERN = re.compile(r"Ran\s+(\d+)\s+tests?\s+in\s+([0-9.]+)s")
CASE_DURATION_PATTERN = re.compile(
    r"^\s*([0-9]+(?:\.[0-9]+)?)s\s+.*\(((?:tests\.)?test_[A-Za-z0-9_]+)\.[A-Za-z0-9_.]+\)\s*$"
)


@dataclass
class Shard:
    index: int
    paths: list[Path]
    estimated_bytes: int = 0
    selectors: list[str] | None = None


@dataclass
class RunningShard:
    shard: Shard
    process: subprocess.Popen[str]
    log_path: Path
    log_file: TextIO
    started: float
    temp_directory: tempfile.TemporaryDirectory[str]
    finished: float = 0.0


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


def _estimated_bytes(path: Path) -> int:
    """Return a comparable work score with the original byte-size floor."""
    measured = round(MEASURED_TEST_SECONDS.get(path.name, 0.0) * 10_000)
    return max(path.stat().st_size, measured)


def build_shards(paths: list[Path], workers: int) -> list[Shard]:
    """Reserve dedicated families, then balance measured work and size floors."""
    if workers < 1:
        raise ValueError("workers must be a positive integer")
    if not paths:
        return []
    shards = [Shard(index=index, paths=[]) for index in range(min(workers, len(paths)))]
    weighted = sorted(paths, key=lambda path: (-_estimated_bytes(path), path.as_posix()))
    dedicated = [path for path in weighted if path.name in DEDICATED_PARALLEL_TEST_FILES]
    reserved = dedicated[:max(0, len(shards) - 1)]
    for shard, path in zip(shards, reserved):
        shard.paths.append(path)
        shard.estimated_bytes = _estimated_bytes(path)
        weighted.remove(path)
    shared = shards[len(reserved):]
    for path in weighted:
        target = min(shared, key=lambda shard: (shard.estimated_bytes, shard.index))
        target.paths.append(path)
        target.estimated_bytes += _estimated_bytes(path)
    for shard in shards:
        shard.paths.sort(key=lambda path: path.as_posix())
    return shards


class _DiscoveryRunner:
    def run(self, suite: unittest.TestSuite) -> unittest.TestSuite:
        """Return stdlib's FILE-argument discovery without executing fixtures."""
        return suite


def _case_ids(suite: unittest.TestSuite) -> list[str]:
    result = []
    for test in suite:
        result.extend(_case_ids(test) if isinstance(test, unittest.TestSuite) else [test.id()])
    return result


def _write_discovery(paths: list[str], output: str) -> int:
    # A script child otherwise has scripts/ at sys.path[0], unlike -m unittest.
    sys.path[0] = os.getcwd()
    found = {}
    for path in paths:
        program = unittest.TestProgram(
            module=None, argv=["unittest", path], exit=False, testRunner=_DiscoveryRunner(),
        )
        if program.testLoader.errors:
            raise ValueError("unittest discovery failed: " + "\n".join(program.testLoader.errors))
        ids = _case_ids(program.result)
        if len(ids) != len(set(ids)):
            raise ValueError(f"duplicate unittest discovery IDs: {path}")
        found[path] = ids
    Path(output).write_text(json.dumps(found), encoding="utf-8")
    return 0


def _worker_environment(start_directory: Path, temp_root: Path) -> dict[str, str]:
    environment = os.environ.copy()
    python_path = [str(start_directory)]
    if environment.get("PYTHONPATH"):
        python_path.append(environment["PYTHONPATH"])
    environment.update({
        "TMPDIR": str(temp_root), "TMP": str(temp_root), "TEMP": str(temp_root),
        "PYTHONDONTWRITEBYTECODE": "1", "PYTHONPATH": os.pathsep.join(python_path),
        "PYTHONUNBUFFERED": "1",
    })
    return environment


def discover_methods(paths: list[Path], working_directory: Path,
                     start_directory: Path) -> dict[Path, list[str]]:
    """Discover in a fresh child with the same FILE conversion and worker env."""
    if not paths:
        return {}
    with tempfile.TemporaryDirectory(prefix="cwo-discovery-") as temporary:
        output = Path(temporary) / "methods.json"
        result = subprocess.run(
            [sys.executable, str(Path(__file__).resolve()), "--list-test-methods",
             *map(str, paths), "--discovery-output", str(output)],
            cwd=working_directory, env=_worker_environment(start_directory, Path(temporary)),
            text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False,
        )
        if result.returncode:
            raise ValueError(f"unittest method discovery failed:\n{result.stdout}")
        found = json.loads(output.read_text(encoding="utf-8"))
    return {path: found[str(path)] for path in paths}


def _cost_hints() -> dict[str, dict[str, float]]:
    hints = json.loads(COST_FILE.read_text(encoding="utf-8"))
    for values in (hints["case_seconds"], hints["fixture_seconds"]):
        if any(type(value) not in (int, float) or not math.isfinite(value) or value < 0
               for value in values.values()):
            raise ValueError("unittest cost hints must be finite nonnegative seconds")
    return hints


def _method_shards(path: Path, methods: list[str], hints: dict) -> list[Shard]:
    fallback = max(1.0, MEASURED_TEST_SECONDS.get(path.name, 0.0) / max(1, len(methods)))
    overhead = hints["fixture_seconds"].get(path.name, 5.0)
    shards, selected, seconds = [], [], overhead
    for method in methods:
        cost = hints["case_seconds"].get(method, fallback)
        if selected and seconds + cost > MAX_PACKED_SECONDS:
            shards.append(Shard(0, [path], round(seconds * 10_000), selected))
            selected, seconds = [], overhead
        selected.append(method)
        seconds += cost
        if seconds >= TARGET_WORKUNIT_SECONDS:
            shards.append(Shard(0, [path], round(seconds * 10_000), selected))
            selected, seconds = [], overhead
    if selected:
        shards.append(Shard(0, [path], round(seconds * 10_000), selected))
    return shards


def build_work_units(paths: list[Path], workers: int, methods: dict[Path, list[str]],
                     hints: dict) -> list[Shard]:
    """Pack every discovered method exactly once; other files retain file shards."""
    units = build_shards([path for path in paths if path not in methods], workers)
    for path in sorted(methods):
        units.extend(_method_shards(path, methods[path], hints))
    units.sort(key=lambda unit: (-unit.estimated_bytes, tuple(map(str, unit.paths)),
                                 tuple(unit.selectors or [])))
    for index, unit in enumerate(units):
        unit.index = index
    return units


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


def _print_case_timings(log: str, label: str) -> None:
    """Report case sums without fixture values or claims about setup overhead."""
    family_seconds: dict[str, float] = {}
    for line in log.splitlines():
        duration = CASE_DURATION_PATTERN.fullmatch(line)
        if duration is not None:
            family = duration.group(2)
            family_seconds[family] = family_seconds.get(family, 0.0) + float(duration.group(1))
    for family, seconds in sorted(family_seconds.items()):
        print(f"{label} family_case_seconds {family} {seconds:.3f}")


def _start_shard(shard: Shard, *, working_directory: Path, start_directory: Path,
                 artifacts_directory: Path, verbose: bool, directory_prefix: str) -> RunningShard:
    worker_root = artifacts_directory / f"{directory_prefix}-{shard.index + 1:02d}"
    worker_root.mkdir(parents=True, mode=0o700)
    temporary = tempfile.TemporaryDirectory(prefix=f"cwo-{directory_prefix}-{shard.index + 1:02d}-")
    log_path = worker_root / "unittest.log"
    log_file = log_path.open("w", encoding="utf-8")
    command = [sys.executable, "-m", "unittest", "-v" if verbose else "-q", "--durations", "0"]
    command.extend(shard.selectors if shard.selectors is not None else map(str, shard.paths))
    started = time.monotonic()
    try:
        process = subprocess.Popen(
            command, cwd=working_directory,
            env=_worker_environment(start_directory, Path(temporary.name)),
            stdout=log_file, stderr=subprocess.STDOUT, text=True,
        )
    except OSError:
        log_file.close()
        temporary.cleanup()
        raise
    return RunningShard(shard, process, log_path, log_file, started, temporary)


def _run_bounded(shards: list[Shard], workers: int, running: list[RunningShard], **options) -> None:
    """Wait only on owned children; more workunits never increase concurrency."""
    pending, active = iter(shards), []
    exhausted = False
    while active or not exhausted:
        while len(active) < workers and not exhausted:
            shard = next(pending, None)
            if shard is None:
                exhausted = True
            else:
                entry = _start_shard(shard, **options)
                running.append(entry)
                active.append(entry)
        completed = [entry for entry in active if entry.process.poll() is not None]
        for entry in completed:
            entry.finished = time.monotonic()
            entry.log_file.close()
            active.remove(entry)
        if active and not completed:
            time.sleep(0.01)


def run_shards(
    shards: list[Shard],
    *,
    working_directory: Path,
    start_directory: Path,
    artifacts_directory: Path,
    verbose: bool,
    workers: int | None = None,
    label: str = "parallel unittest",
    directory_prefix: str = "worker",
) -> RunSummary:
    """Run isolated workunits with at most the requested active subprocesses."""
    running: list[RunningShard] = []
    capacity = min(workers or len(shards), len(shards))
    started = time.monotonic()
    try:
        _run_bounded(
            shards, capacity, running, working_directory=working_directory,
            start_directory=start_directory, artifacts_directory=artifacts_directory,
            verbose=verbose, directory_prefix=directory_prefix,
        )
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
        _print_case_timings(log, label)
        parse_complete = parse_complete and tests is not None
        total_tests += tests or 0
        elapsed = entry.finished - entry.started
        failure = _workunit_failure(entry, tests)
        status = "FAIL" if failure else "PASS"
        failures += int(bool(failure))
        detail = f"tests={tests}" if tests is not None else "tests=unknown"
        if test_seconds is not None:
            detail += f" test_seconds={test_seconds:.3f}"
        print(
            f"[shard {entry.shard.index + 1:02d}/{len(shards):02d}] {status} "
            f"files={len(entry.shard.paths)} {detail} wall_seconds={elapsed:.3f} "
            f"estimated_seconds={entry.shard.estimated_bytes / 10_000:.3f}"
        )
        if failure:
            print(f"--- shard {entry.shard.index + 1:02d} log ---", file=sys.stderr)
            print(f"workunit failed: {failure}", file=sys.stderr)
            print(log, file=sys.stderr, end="" if log.endswith("\n") else "\n")
        entry.temp_directory.cleanup()

    wall_seconds = time.monotonic() - started
    status = "PASS" if failures == 0 else "FAIL"
    test_detail = str(total_tests) if parse_complete else "incomplete"
    print(
        f"{label}: {status} workers={capacity} tests={test_detail} "
        f"wall_seconds={wall_seconds:.3f}"
    )
    print(f"{label} workunits={len(shards)} capacity={capacity}")
    return RunSummary(
        exit_code=0 if failures == 0 else 1,
        tests=total_tests if parse_complete else None,
        wall_seconds=wall_seconds,
    )


def _workunit_failure(entry: RunningShard, tests: int | None) -> str:
    """Require a footer and exact method coverage as well as a successful exit."""
    if tests is None:
        return "missing unittest footer"
    selectors = entry.shard.selectors
    if selectors is not None and tests != len(selectors):
        return f"expected_tests={len(selectors)} reported_tests={tests}"
    return f"exit_code={entry.process.returncode}" if entry.process.returncode else ""


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
    parser.add_argument("--list-test-methods", nargs="+", help=argparse.SUPPRESS)
    parser.add_argument("--discovery-output", help=argparse.SUPPRESS)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if args.list_test_methods:
        return _write_discovery(args.list_test_methods, args.discovery_output)
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
        methods = discover_methods(
            [path for path in parallel_paths if path.name in METHOD_SHARDED_TEST_FILES],
            working_directory, start_directory,
        )
        shards = build_work_units(parallel_paths, args.workers, methods, _cost_hints())
    except (OSError, ValueError) as exc:
        print(f"parallel unittest: {exc}", file=sys.stderr)
        return 2
    if not shards and not serial_paths:
        print("parallel unittest: no test files matched", file=sys.stderr)
        return 2

    print(
        f"parallel unittest: files={len(paths)} parallel_files={len(parallel_paths)} "
        f"serial_files={len(serial_paths)} workers={min(args.workers, len(shards))} "
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
                    workers=args.workers,
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
