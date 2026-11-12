"""Owner-private file helpers used by the Codex app-server transport.

Moved unchanged from ``scripts/run_native_pool_live_canaries.py``, which still
re-exports these names.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import stat
from typing import Any

from cwo_core.native_live_campaign_contracts import JsonArtifactSnapshot
from cwo_core.supervision.transport.errors import AppServerError


def _load_owned_regular_bytes(
    path: Path,
    label: str,
    *,
    require_private: bool,
    expected_identity: tuple[int, int, int, int] | None = None,
) -> bytes:
    """Capture one owner-bound file exactly once through a stable descriptor."""

    supplied = Path(path)
    lexical = supplied.absolute()
    try:
        resolved = supplied.resolve(strict=True)
    except OSError as exc:
        raise AppServerError(f"{label}-file-invalid") from exc
    if lexical != resolved:
        raise AppServerError(f"{label}-path-invalid")
    try:
        descriptor = os.open(
            resolved,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
        )
    except OSError as exc:
        raise AppServerError(f"{label}-file-invalid") from exc
    try:
        before = os.fstat(descriptor)
        descriptor_identity = (
            before.st_dev,
            before.st_ino,
            before.st_uid,
            before.st_mode,
        )
        if (
            expected_identity is not None
            and descriptor_identity != tuple(expected_identity)
        ):
            raise AppServerError(f"{label}-source-identity-changed")
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.geteuid()
            or (
                before.st_mode & 0o077
                if require_private
                else before.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
            )
        ):
            raise AppServerError(f"{label}-permissions-invalid")
        chunks: list[bytes] = []
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        value = b"".join(chunks)
        after = os.fstat(descriptor)
    except OSError as exc:
        raise AppServerError(f"{label}-file-unreadable") from exc
    finally:
        os.close(descriptor)
    stable_fields = ("st_dev", "st_ino", "st_uid", "st_mode", "st_size", "st_mtime_ns", "st_ctime_ns")
    if any(getattr(before, field) != getattr(after, field) for field in stable_fields) or len(
        value
    ) != before.st_size:
        raise AppServerError(f"{label}-source-changed")
    if not value:
        raise AppServerError(f"{label}-file-empty")
    return value


def load_private_bytes(
    path: Path,
    label: str,
    *,
    expected_identity: tuple[int, int, int, int] | None = None,
) -> bytes:
    """Read one private regular file through a no-follow descriptor snapshot."""

    return _load_owned_regular_bytes(
        path,
        label,
        require_private=True,
        expected_identity=expected_identity,
    )


def load_private_json_snapshot(
    path: Path,
    label: str,
    *,
    expected_identity: tuple[int, int, int, int] | None = None,
) -> JsonArtifactSnapshot:
    raw = load_private_bytes(
        path,
        label,
        expected_identity=expected_identity,
    )
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AppServerError(f"{label}-file-unreadable") from exc
    if not isinstance(value, dict):
        raise AppServerError(f"{label}-not-object")
    return JsonArtifactSnapshot(raw=raw, value=value)


def load_private_json(path: Path, label: str) -> dict[str, Any]:
    return dict(load_private_json_snapshot(path, label).value)


def _private_control_directory(path: Path, label: str) -> Path:
    supplied = Path(path).absolute()
    try:
        if supplied.is_symlink():
            raise AppServerError(f"{label}-directory-permissions-invalid")
        missing: list[Path] = []
        cursor = supplied
        while not cursor.exists():
            if cursor.is_symlink():
                raise AppServerError(
                    f"{label}-directory-permissions-invalid"
                )
            missing.append(cursor)
            if cursor.parent == cursor:
                raise AppServerError(f"{label}-directory-unavailable")
            cursor = cursor.parent
        ancestor = cursor.lstat()
        if (
            stat.S_ISLNK(ancestor.st_mode)
            or not stat.S_ISDIR(ancestor.st_mode)
            or ancestor.st_uid != os.geteuid()
            or stat.S_IMODE(ancestor.st_mode) & 0o022
        ):
            raise AppServerError(f"{label}-directory-permissions-invalid")
        for directory in reversed(missing):
            directory.mkdir(mode=0o700)
            _fsync_private_control_directory(directory, label)
            _fsync_owned_control_directory(
                directory.parent,
                f"{label}-parent",
                require_private=False,
            )
        directory = supplied.resolve(strict=True)
    except OSError as exc:
        raise AppServerError(f"{label}-directory-unavailable") from exc
    if directory != supplied:
        raise AppServerError(f"{label}-directory-permissions-invalid")
    try:
        info = directory.lstat()
    except OSError as exc:
        raise AppServerError(f"{label}-directory-unavailable") from exc
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) != 0o700
    ):
        raise AppServerError(f"{label}-directory-permissions-invalid")
    _fsync_private_control_directory(directory, label)
    _fsync_owned_control_directory(
        directory.parent,
        f"{label}-parent",
        require_private=False,
    )
    return directory


def _open_private_control_lock(path: Path, label: str) -> int:
    """Open one owner-private regular lock file without following aliases."""

    descriptor: int | None = None
    try:
        descriptor = os.open(
            path,
            os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        info = os.fstat(descriptor)
    except OSError as exc:
        if descriptor is not None:
            os.close(descriptor)
        raise AppServerError(f"{label}-lock-invalid") from exc
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) != 0o600
    ):
        os.close(descriptor)
        raise AppServerError(f"{label}-lock-invalid")
    return descriptor


def _fsync_private_control_directory(path: Path, label: str) -> None:
    """Durably persist a newly created private control-plane directory entry."""

    _fsync_owned_control_directory(path, label, require_private=True)


def _fsync_owned_control_directory(
    path: Path,
    label: str,
    *,
    require_private: bool,
) -> None:
    """Fsync an owner-controlled directory without following an alias."""

    descriptor: int | None = None
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        info = os.fstat(descriptor)
        mode = stat.S_IMODE(info.st_mode)
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid != os.geteuid()
            or (mode != 0o700 if require_private else bool(mode & 0o022))
        ):
            raise AppServerError(f"{label}-directory-permissions-invalid")
        os.fsync(descriptor)
    except OSError as exc:
        raise AppServerError(f"{label}-directory-fsync-failed") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
