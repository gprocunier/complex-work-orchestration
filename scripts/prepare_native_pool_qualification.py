#!/usr/bin/env python3
"""Render the offline preparation for fixed N=2 and N=3 live qualification."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
from shutil import copytree
import stat
import sys
from tempfile import TemporaryDirectory

from cwo_core.invocation_ledger import MAX_UNITS
from cwo_core.model_identities import resolve_model
from cwo_core.native_pool_qualification_fixtures import (
    POOL_QUALIFICATION_SEED,
    fixed_pool_qualification_cohorts,
)
from cwo_core.paths import REPO_ROOT
from cwo_core.qualification_target import selected_target
from cwo_core.workspace_capture import trusted_git_private


LIMITS = ("sessions", "tool_calls", "runtime_seconds")


def _positive_units(raw: str) -> int:
    value = int(raw)
    if not 1 <= value <= MAX_UNITS:
        raise argparse.ArgumentTypeError(f"use an integer from 1 to {MAX_UNITS}")
    return value


def _prepare(runs_per_cohort: int, per_run: dict[str, int]) -> dict:
    cohorts = fixed_pool_qualification_cohorts()
    stage_ceiling = {key: len(cohorts) * runs_per_cohort * cap for key, cap in per_run.items()}
    if max(stage_ceiling.values()) > MAX_UNITS:
        raise ValueError(f"stage ceilings exceed {MAX_UNITS} units; reduce the run count or limits")
    if min(per_run["sessions"], per_run["tool_calls"]) < max(cohort["size"] for cohort in cohorts):
        raise ValueError("each run needs room for at least three sessions and three tool calls")

    selection = selected_target()["selection"]
    return {
        "mode": "prepare-only",
        "dispatch_authorized": False,
        "model_calls": 0,
        "target_profile": selection["profile"],
        "worker_role": "luna",
        "worker_model": resolve_model("luna"),
        "runs_per_cohort": runs_per_cohort,
        "per_run_limits": per_run,
        "stage_ceiling": stage_ceiling,
        "seed_files": dict(POOL_QUALIFICATION_SEED),
        "cohorts": cohorts,
        "qualification_record": {
            "cwo_version": (REPO_ROOT / "VERSION").read_text(encoding="utf-8").strip(),
            "minimum_codex_version": selection["minimum_version"],
            "date": datetime.now(timezone.utc).date().isoformat(),
            "outcome": "not-run",
            "limitations": ["Offline preparation only", "Synthetic disposable clones only",
                            "Confidential workloads unsupported"],
        },
    }


def _fixture_root(path: Path) -> Path:
    root = path.absolute()
    if ".." in root.parts or root == root.parent:
        raise ValueError("fixture root must name a new directory inside a protected parent")
    owner = os.geteuid()
    for directory in reversed(root.parents):
        info = directory.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid not in {0, owner}:
            raise ValueError("fixture root requires owned directories without symlinks")
        if info.st_mode & 0o022 and not info.st_mode & stat.S_ISVTX:
            raise ValueError("fixture root cannot use a shared writable ancestor")
    parent = root.parent.stat()
    if parent.st_uid != owner or parent.st_mode & 0o022:
        raise ValueError("fixture root requires an existing parent you own with no shared write access")
    root.mkdir(mode=0o700)
    return root


def _fixture_git(cwd: Path, *args: str) -> None:
    # A detached maintenance process can still write while the seed is copied.
    result = trusted_git_private(cwd, ["-c", "maintenance.auto=false", "-c", "gc.auto=0", *args])
    if result.returncode != 0:
        raise ValueError(f"fixture Git command failed: {result.stderr.strip()[:300]}")


def _protect_seed_directories(directory: Path) -> None:
    for child in directory.iterdir():
        mode = child.lstat().st_mode
        if stat.S_ISDIR(mode):
            if mode & 0o022:
                child.chmod(stat.S_IMODE(mode) & ~0o022)
            _protect_seed_directories(child)


def _populate_fixtures(layout: Path, plan: dict) -> None:
    seed = layout / "seed"
    seed.mkdir(mode=0o755)
    _fixture_git(seed, "init", "--quiet", "--template=", "--initial-branch=main")
    for path, contents in plan["seed_files"].items():
        (seed / path).write_bytes(contents.encode("utf-8"))
    _fixture_git(seed, "add", "--", *plan["seed_files"])
    _fixture_git(seed, "-c", "user.name=CWO Pool Qualification", "-c", "user.email=cwo@example.invalid",
                 "commit", "--quiet", "-m", "Synthetic pool qualification seed")
    # Git-created directories can inherit group write access from the umask.
    _protect_seed_directories(seed)

    for cohort in plan["cohorts"]:
        cohort_root = layout / f"n{cohort['size']}"
        cohort_root.mkdir(mode=0o755)
        slots = ["integration", *(task["worker_slot"] for task in cohort["tasks"])]
        for index in range(1, plan["runs_per_cohort"] + 1):
            run_root = cohort_root / f"run-{index}"
            run_root.mkdir(mode=0o755)
            for slot in slots:
                # Copy the generated repository, including its Git object store,
                # without requiring Git transport, shared metadata or remotes.
                copytree(seed, run_root / slot, symlinks=True)


def _materialize_fixtures(path: Path, plan: dict) -> None:
    root = _fixture_root(path)
    claimed = root.lstat()
    try:
        with TemporaryDirectory(prefix=".cwo-pool-", dir=root.parent) as scratch:
            layout = Path(scratch) / "fixture"
            layout.mkdir(mode=0o700)
            _populate_fixtures(layout, plan)
            if not os.path.samestat(root.lstat(), claimed):
                raise ValueError("fixture root changed during preparation")
            layout.replace(root)
    except BaseException as error:
        try:
            if os.path.samestat(root.lstat(), claimed):
                root.rmdir()
        except OSError as cleanup:
            error.add_note(f"fixture root cleanup failed: {cleanup}")
        raise


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--runs-per-cohort", required=True, type=_positive_units)
    for key in LIMITS:
        parser.add_argument("--max-" + key.replace("_", "-"), required=True,
                            dest=key, type=_positive_units, help=f"per-run cap on {key.replace('_', ' ')}")
    parser.add_argument("--fixture-root", type=Path, help="new directory for local synthetic Git fixtures")
    args = vars(parser.parse_args(argv))
    limits = {key: args[key] for key in LIMITS}
    try:
        plan = _prepare(args["runs_per_cohort"], limits)
        if args["fixture_root"] is not None:
            _materialize_fixtures(args["fixture_root"], plan)
    except (OSError, ValueError) as exc:
        print(f"prepare_native_pool_qualification: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(plan, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
