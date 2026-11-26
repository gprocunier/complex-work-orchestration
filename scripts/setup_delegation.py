#!/usr/bin/env python3
"""Set up the dedicated Codex sign-in and check isolated worker startup."""
from __future__ import annotations

import argparse
import fcntl
import os
from pathlib import Path
import shutil
import subprocess
import sys

from cwo_core import host_records
from cwo_core.paths import REPO_ROOT
import registered_n1_qualification as qualification
from registered_worker_login_config import read_worker_login_home, write_worker_login_home, write_pool_worker_login_homes
from selected_native_containment import SelectedNativeProbe


def _worker_home(home: Path, primary: Path) -> Path:
    home = home.expanduser().absolute()
    if home.resolve() != home:
        raise ValueError("The worker login requires a canonical path without symlinks.")
    if qualification._login_overlap(home, primary) or qualification._login_overlap(home, primary.resolve()):
        raise ValueError("Choose a worker login home separate from the main Codex home.")
    qualification.require_worker_login_location(home)
    protected = (REPO_ROOT, host_records.configured_store().state_root, qualification.worker_login_state())
    if any(qualification._login_overlap(home, path) for path in protected):
        raise ValueError("Choose a worker login home separate from the skill and its host state.")
    return home


def _codex_binary() -> Path:
    binary = shutil.which("codex")
    if binary is None:
        raise ValueError("Codex CLI is required to set up delegation.")
    return Path(binary).resolve(strict=True)


def _has_authentication(directory: int) -> bool:
    try:
        os.stat("auth.json", dir_fd=directory, follow_symlinks=False)
    except FileNotFoundError:
        return False
    return True


def _require_sign_in_home(directory: int) -> None:
    with os.scandir(directory) as entries:
        if any(entry.is_symlink() or entry.name == "config.toml" for entry in entries):
            raise ValueError("Choose a dedicated worker login home without configuration or symlinks.")


def _require_original_home(home: Path, identity: tuple[int, int]) -> None:
    descriptor = host_records._directory(home, private=True)
    try:
        current = os.fstat(descriptor)
        if (current.st_dev, current.st_ino) != identity:
            raise ValueError("The dedicated worker home changed during setup.")
    finally:
        os.close(descriptor)


def _sign_in(binary: Path, home: Path) -> None:
    env = {key: value for key, value in os.environ.items()
           if key not in {"CODEX_SQLITE_HOME", "CODEX_API_KEY", "OPENAI_API_KEY"}}
    env["CODEX_HOME"] = str(home)
    print("Sign in to the separate Codex worker home using the device instructions below.", flush=True)
    try:
        subprocess.run([str(binary), "-c", 'cli_auth_credentials_store="file"', "login", "--device-auth"],
                       env=env, check=True)
    except subprocess.CalledProcessError as exc:
        raise ValueError("The dedicated worker sign-in did not complete.") from exc


def _check_startup(binary: Path) -> None:
    probe = SelectedNativeProbe(codex=binary)
    result = probe.read_configuration()
    initialize = result.get("responses", {}).get("initialize", {})
    if (type(initialize.get("result")) is not dict or "error" in initialize
            or result.get("accepted_output") is not False or result.get("cleanup", {}).get("namespace_exited") is not True):
        raise ValueError("The isolated app server startup or cleanup could not be verified.")


def setup_delegation(home: Path, primary: Path) -> Path:
    home = _worker_home(home, primary)
    binary = _codex_binary()
    directory = host_records._directory(home, create=True, private=True)
    try:
        fcntl.flock(directory, fcntl.LOCK_EX | fcntl.LOCK_NB)
        opened = os.fstat(directory)
        identity = opened.st_dev, opened.st_ino
        worker_state = qualification.worker_login_state()
        mount = qualification.WorkerLoginMount(home, worker_state) if _has_authentication(directory) else None
        _check_startup(binary)
        if mount is None:
            _require_sign_in_home(directory)
            _require_original_home(home, identity)
            _sign_in(binary, home)
            mount = qualification.WorkerLoginMount(home, worker_state)
        if mount.identity != identity:
            raise ValueError("The dedicated worker home changed during setup.")
        lease = mount.claim()
        mount.release(lease)
        write_worker_login_home(home)
    finally:
        os.close(directory)
    return home


def setup_pool_delegation(homes: list[Path], primary: Path) -> None:
    if len(homes) not in (2, 3):
        raise ValueError("Provide two or three existing, separate pool worker login homes.")
    selected = tuple(_worker_home(home, primary) for home in homes)
    mounts = tuple(qualification.WorkerLoginMount(home, qualification.worker_login_state()) for home in selected)
    if len({mount.identity for mount in mounts}) != len(selected):
        raise ValueError("The pool worker login homes share a directory identity.")
    if any(qualification._login_overlap(home, peer)
           for index, home in enumerate(selected) for peer in selected[index + 1:]):
        raise ValueError("The configured pool worker login homes overlap.")
    write_pool_worker_login_homes(selected)


def main(argv: list[str] | None = None) -> int:
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--codex-home", type=Path, help="Main Codex home to leave untouched.")
    worker_choice = cli.add_mutually_exclusive_group()
    worker_choice.add_argument("--worker-home", type=Path, help="Dedicated sign-in home for the worker.")
    worker_choice.add_argument("--pool-worker-home", type=Path, action="append",
                               help="Existing dedicated pool sign-in home. Give this two or three times.")
    args = cli.parse_args(argv)
    account = qualification._controller_home()
    primary = args.codex_home or Path(os.environ.get("CODEX_HOME") or account / ".codex")
    try:
        if args.pool_worker_home is not None:
            setup_pool_delegation(args.pool_worker_home, primary.expanduser().absolute())
            print(f"Configured {len(args.pool_worker_home)} dedicated pool worker logins.")
            return 0
        home = args.worker_home or read_worker_login_home() or account / ".cwo-worker-codex"
        selection = setup_delegation(home, primary.expanduser().absolute())
    except (OSError, ValueError) as exc:
        print(f"Delegation setup failed. {exc}", file=sys.stderr)
        return 1
    print(f"Dedicated worker login configured at {selection}.")
    print("The isolated app server passed startup and cleanup checks. This check uses no model task.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
