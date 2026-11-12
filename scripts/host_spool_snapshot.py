"""Inert, unwired descriptor-relative capture of opaque spool bytes.

Ownership and mode checks do not isolate a same-UID adversary. The caller
supplies protected directory custody; bytes and hashes confer no authority.
This helper captures bytes only; it does not admit work or authorize effects.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
import stat


_PLATFORM_OPEN = os.open
_MAXIMUM_BYTES = 1_048_576


class SpoolSnapshotError(ValueError):
    """A controlled refusal; diagnostics contain no supplied names or bytes."""


@dataclass(frozen=True, slots=True)
class SpoolSnapshot:
    """Opaque bytes, their digest, and opened-file identity; never a receipt.

    Identity order: dev, ino, uid, mode, nlink, size, mtime_ns, ctime_ns.
    """

    data: bytes
    sha256: str
    identity: tuple[int, int, int, int, int, int, int, int]


def _validate_name(name: str) -> None:
    if type(name) is not str:
        raise SpoolSnapshotError("spool basename is invalid")
    if name in ("", ".", "..") or any(c in name for c in ("/", "\\", "\0")):
        raise SpoolSnapshotError("spool basename is invalid")
    try:
        name.encode("utf-8")
    except UnicodeError:
        raise SpoolSnapshotError("spool basename is invalid") from None


def _validate_binding(expected_sha256: str, maximum_bytes: int) -> None:
    if type(expected_sha256) is not str:
        raise SpoolSnapshotError("spool expected hash is invalid")
    if len(expected_sha256) != 64 or any(
        c not in "0123456789abcdef" for c in expected_sha256
    ):
        raise SpoolSnapshotError("spool expected hash is invalid")
    if type(maximum_bytes) is not int:
        raise SpoolSnapshotError("spool byte bound is invalid")
    if not 1 <= maximum_bytes <= _MAXIMUM_BYTES:
        raise SpoolSnapshotError("spool byte bound is invalid")


def _required_flags() -> int:
    if os.name != "posix" or _PLATFORM_OPEN not in getattr(os, "supports_dir_fd", ()):
        raise SpoolSnapshotError("spool capture platform is unsupported")
    if not callable(getattr(os, "geteuid", None)):
        raise SpoolSnapshotError("spool capture platform is unsupported")
    flags = os.O_RDONLY
    for name in ("O_NOFOLLOW", "O_CLOEXEC", "O_NONBLOCK"):
        value = getattr(os, name, None)
        if type(value) is not int or value <= 0:
            raise SpoolSnapshotError("spool capture platform is unsupported")
        flags |= value
    return flags


def _check_root(info: os.stat_result, euid: int) -> None:
    if not stat.S_ISDIR(info.st_mode):
        raise SpoolSnapshotError("spool root must be a directory")
    if info.st_uid != euid or stat.S_IMODE(info.st_mode) & 0o077:
        raise SpoolSnapshotError("spool root must be owned and private")


def _check_file(info: os.stat_result, euid: int, maximum_bytes: int) -> None:
    if not stat.S_ISREG(info.st_mode):
        raise SpoolSnapshotError("spool input must be a regular file")
    if info.st_uid != euid or stat.S_IMODE(info.st_mode) & 0o077:
        raise SpoolSnapshotError("spool input must be owned and private")
    if info.st_nlink != 1:
        raise SpoolSnapshotError("spool input must have one link")
    if info.st_size < 0 or info.st_size > maximum_bytes:
        raise SpoolSnapshotError("spool input exceeds its byte bound")


def _identity(info: os.stat_result) -> tuple[int, int, int, int, int, int, int, int]:
    fields = (
        info.st_dev, info.st_ino, info.st_uid, info.st_mode,
        info.st_nlink, info.st_size,
        getattr(info, "st_mtime_ns", None), getattr(info, "st_ctime_ns", None),
    )
    if any(type(value) is not int for value in fields):
        raise SpoolSnapshotError("spool opened-file identity is unavailable")
    return fields


def _read_bounded(fd: int, maximum_bytes: int) -> bytes:
    chunks = []
    length = 0
    while length <= maximum_bytes:
        part = os.read(fd, min(65_536, maximum_bytes + 1 - length))
        if not part:
            break
        chunks.append(part)
        length += len(part)
    if length > maximum_bytes:
        raise SpoolSnapshotError("spool input exceeds its byte bound")
    return b"".join(chunks)


def _close_file(fd: int) -> None:
    try:
        os.close(fd)
    except OSError:
        raise SpoolSnapshotError("spool descriptor close failed") from None


def capture_spool_snapshot(
    root_fd: int,
    name: str,
    expected_sha256: str,
    *,
    maximum_bytes: int = 32_768,
) -> SpoolSnapshot:
    """Capture one private regular file once, relative to a caller-owned fd.

    The caller retains root_fd. This function closes only its own file fd.
    Hash equality binds content, not the identity or authority of its supplier.
    This does not execute validation code, wire a runtime, or confine execution.
    """
    if type(root_fd) is not int or root_fd < 0:
        raise SpoolSnapshotError("spool root descriptor is invalid")
    _validate_name(name)
    _validate_binding(expected_sha256, maximum_bytes)
    flags = _required_flags()
    fd = None
    try:
        euid = os.geteuid()
        _check_root(os.fstat(root_fd), euid)
        fd = os.open(name, flags, dir_fd=root_fd)
        before = os.fstat(fd)
        _check_file(before, euid, maximum_bytes)
        identity = _identity(before)
        data = _read_bounded(fd, maximum_bytes)
        after = os.fstat(fd)
        if _identity(after) != identity or len(data) != before.st_size:
            raise SpoolSnapshotError("spool file changed during capture")
        actual_sha256 = hashlib.sha256(data).hexdigest()
        if actual_sha256 != expected_sha256:
            raise SpoolSnapshotError("spool content hash mismatch")
        return SpoolSnapshot(data, actual_sha256, identity)
    except SpoolSnapshotError:
        raise
    except (OSError, ValueError, TypeError, OverflowError, NotImplementedError):
        raise SpoolSnapshotError("spool capture unavailable or refused") from None
    finally:
        if fd is not None:
            _close_file(fd)
