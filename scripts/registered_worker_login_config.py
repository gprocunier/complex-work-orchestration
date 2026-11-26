"""Installation-local path setting for the registered worker login."""
from __future__ import annotations

import os
from pathlib import Path

from cwo_core import host_records

_FILE = "worker-login.json"
_POOL_FILE = "pool-worker-logins.json"
_MAX_BYTES = 4096


class WorkerLoginConfigurationError(ValueError):
    """The installation's worker login setting could not be read or saved."""


def _selection(directory: int) -> Path | None:
    try:
        raw = host_records._read_at(directory, _FILE, _MAX_BYTES)
    except FileNotFoundError:
        return None
    value = host_records._parse(raw)
    home = value.get("worker_login_home")
    if (set(value) != {"version", "worker_login_home"} or type(value["version"]) is not int
            or value["version"] != 1 or type(home) is not str or not Path(home).is_absolute()
            or ".." in Path(home).parts):
        raise WorkerLoginConfigurationError("The installed worker login setting is invalid.")
    return Path(home)


def read_worker_login_home() -> Path | None:
    """Read the existing bootstrap argument, if one was saved for this package."""
    try:
        directory = host_records._directory(host_records.configured_store().state_root, private=True)
    except FileNotFoundError:
        return None
    except (OSError, host_records.HostRecordError) as exc:
        raise WorkerLoginConfigurationError("The installed worker login setting is unavailable.") from exc
    try:
        return _selection(directory)
    except (OSError, host_records.HostRecordError) as exc:
        raise WorkerLoginConfigurationError("The installed worker login setting is unavailable.") from exc
    finally:
        os.close(directory)


def write_worker_login_home(home: Path) -> None:
    if not home.is_absolute() or home.resolve(strict=True) != home:
        raise WorkerLoginConfigurationError("The worker login home must be an existing canonical path.")
    raw = host_records._json({"version": 1, "worker_login_home": str(home)})
    if len(raw) > _MAX_BYTES:
        raise WorkerLoginConfigurationError("The worker login home path is too long.")
    try:
        with host_records.configured_store()._state(create=True) as directory:
            _selection(directory)
            host_records._write_at(directory, _FILE, raw, replace=True)
    except (OSError, host_records.HostRecordError) as exc:
        raise WorkerLoginConfigurationError("The installed worker login setting could not be saved.") from exc


def _pool_homes(value) -> tuple[Path, ...]:
    if (type(value) is not list or len(value) not in (2, 3)
            or any(type(item) is not str or not Path(item).is_absolute()
                   or ".." in Path(item).parts or str(Path(item)) != item for item in value)):
        raise WorkerLoginConfigurationError("Configure two or three distinct, canonical pool worker login homes.")
    homes = tuple(map(Path, value))
    if len(set(homes)) != len(homes):
        raise WorkerLoginConfigurationError("Pool worker login homes must be distinct.")
    return homes


def read_pool_worker_login_homes() -> tuple[Path, ...]:
    """Read the protected pool roster separately from the existing single-worker setting."""
    try:
        with host_records.configured_store()._state() as directory:
            value = host_records._parse(host_records._read_at(directory, _POOL_FILE, _MAX_BYTES))
    except (OSError, host_records.HostRecordError) as exc:
        raise WorkerLoginConfigurationError("Configure the installed pool worker login roster first.") from exc
    if set(value) != {"version", "worker_login_homes"} or type(value["version"]) is not int or value["version"] != 1:
        raise WorkerLoginConfigurationError("The installed pool worker login roster is invalid.")
    return _pool_homes(value["worker_login_homes"])


def write_pool_worker_login_homes(homes: tuple[Path, ...]) -> None:
    selected = _pool_homes([str(home) for home in homes])
    if any(home.resolve(strict=True) != home for home in selected):
        raise WorkerLoginConfigurationError("Pool worker homes must exist without symlink components.")
    raw = host_records._json({"version": 1, "worker_login_homes": list(map(str, selected))})
    if len(raw) > _MAX_BYTES:
        raise WorkerLoginConfigurationError("The pool worker login paths exceed the configuration bound.")
    with host_records.configured_store()._state(create=True) as directory:
        host_records._write_at(directory, _POOL_FILE, raw, replace=True)
