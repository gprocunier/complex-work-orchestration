"""Owner-only artifact files for review returns.

Every operation works through directory descriptors. The artifact directory is
opened one component at a time from ``/`` with ``O_NOFOLLOW``, so a symlinked
component anywhere in the path is refused and a component replaced after the
check cannot redirect a later step. A path with a ``..`` component is refused
rather than normalized, so every caller sees the same directory the walk opens.
Files are written with mode 0600 into an anonymous file (``O_TMPFILE``) inside
an owner-only 0700 directory and published with ``linkat`` only when complete,
so an existing artifact is never overwritten and no temporary name exists to
clean up. Publication is atomic or refused: where anonymous files cannot be
created and linked (no ``O_TMPFILE`` support, or no ``/proc``), writing fails
rather than exposing a partially written name. Nothing is ever removed by
name: when a later step fails, the error names the retained file instead,
because deleting by name could remove a file another writer has put there. Reads
open the file relative to the same kind of descriptor, non-blocking, and
refuse symlinks, special files, hard links, other owners, group or world
access and oversize content. Every operating-system failure is reported as
``PrivateArtifactError``.

This is local access hygiene. Any process running as the same Unix user can
still read these files; they are not confidential from a same-user lead or
worker.
"""

from __future__ import annotations

import errno
import hashlib
import os
import stat
from pathlib import Path

DEFAULT_MAX_BYTES = 16 * 1024 * 1024
_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_READ_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC


class PrivateArtifactError(ValueError):
    """Raised when an artifact cannot be written or read safely."""


# open(O_TMPFILE) failures that mean "not supported here" rather than an error.
_TMPFILE_UNSUPPORTED = {errno.EOPNOTSUPP, errno.EISDIR, errno.EINVAL, errno.ENOENT}


def _write_all(descriptor: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = os.write(descriptor, view)
        view = view[written:]


def _validate_name(name: str) -> str:
    if not name or name in {".", ".."} or "/" in name or "\x00" in name or name.startswith("."):
        raise PrivateArtifactError(f"unsafe artifact name: {name!r}")
    return name


def artifact_path(path: Path) -> Path:
    """Return ``path`` made absolute without normalizing it.

    A ``..`` component is refused: collapsing it lexically can drop a symlinked
    component that a resolving check would have followed, so two readings of
    the same argument could name different directories.
    """
    expanded = Path(path).expanduser()
    absolute = expanded if expanded.is_absolute() else Path.cwd() / expanded
    if ".." in absolute.parts:
        raise PrivateArtifactError(f"refusing a parent-directory component in artifact path: {path}")
    return absolute


def _open_directory(path: Path, *, create: bool) -> int:
    """Open ``path`` component by component without following symlinks."""
    absolute = artifact_path(path)
    current = os.open("/", _DIR_FLAGS)
    try:
        for index, part in enumerate(absolute.parts[1:], start=1):
            last = index == len(absolute.parts) - 1
            try:
                following = os.open(part, _DIR_FLAGS, dir_fd=current)
            except FileNotFoundError:
                if not create:
                    raise
                os.mkdir(part, 0o700, dir_fd=current)
                following = os.open(part, _DIR_FLAGS, dir_fd=current)
            except OSError as exc:
                prefix = Path(*absolute.parts[: index + 1])
                raise PrivateArtifactError(f"refusing symlinked or unusable path component: {prefix}") from exc
            os.close(current)
            current = following
            if last:
                break
        return current
    except BaseException:
        os.close(current)
        raise


class PrivateDirectory:
    """An owner-only artifact directory pinned by descriptor for every operation."""

    def __init__(self, path: Path, descriptor: int) -> None:
        self.path = path
        self.descriptor = descriptor
        # Successful writes remain known even if a file moves before the caller records the return.
        self.published_paths: list[str] = []

    @classmethod
    def open(cls, path: Path, *, create: bool = False) -> PrivateDirectory:
        try:
            descriptor = _open_directory(path, create=create)
        except PrivateArtifactError:
            raise
        except OSError as exc:
            raise PrivateArtifactError(f"cannot open artifact directory {path}: {exc.strerror or exc}") from exc
        try:
            info = os.fstat(descriptor)
            if info.st_uid != os.getuid():
                raise PrivateArtifactError(f"directory is owned by another user: {path}")
            if stat.S_IMODE(info.st_mode) != 0o700:
                if not create:
                    raise PrivateArtifactError(f"directory is not owner-only: {path}")
                os.fchmod(descriptor, 0o700)
        except OSError as exc:
            os.close(descriptor)
            raise PrivateArtifactError(f"cannot secure artifact directory {path}: {exc.strerror or exc}") from exc
        except BaseException:
            os.close(descriptor)
            raise
        return cls(artifact_path(path), descriptor)

    def close(self) -> None:
        # Closing this read-only directory descriptor cannot lose written
        # data (every write is synced explicitly), and Linux releases the
        # descriptor even when close reports an error, so a failure here is
        # not raised over results that are already durable.
        if self.descriptor >= 0:
            descriptor, self.descriptor = self.descriptor, -1
            try:
                os.close(descriptor)
            except OSError:
                pass

    def __enter__(self) -> PrivateDirectory:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def write(self, name: str, data: bytes) -> Path:
        """Publish ``data`` as ``name`` (0600) atomically. Never overwrites, and never removes a name.

        The data is written and synced in an anonymous file that is linked in
        as ``name`` only when complete, so a failure before publication leaves
        nothing. Where anonymous files are unavailable the write is refused.
        Once ``name`` exists it stays: any later failure or interruption
        reports the retained file, in the error or as an exception note, and
        as the exception's ``retained_artifact`` attribute. When an
        interruption leaves it unknown whether the link happened, the file is
        reported as possibly retained.
        """
        name = _validate_name(name)
        published: bool | None = False  # None: whether the link happened is unknown
        try:
            descriptor = self._anonymous_file()
            if descriptor is None:
                raise PrivateArtifactError(
                    "atomic artifact publication is unavailable here: it needs O_TMPFILE support and /proc/self/fd"
                )
            identity: tuple[int, int] | None = None
            active: BaseException | None = None
            try:
                info = os.fstat(descriptor)
                identity = (info.st_dev, info.st_ino)
                _write_all(descriptor, data)
                os.fsync(descriptor)
                try:
                    os.link(f"/proc/self/fd/{descriptor}", name, dst_dir_fd=self.descriptor)
                except FileExistsError as exc:
                    raise PrivateArtifactError(f"refusing to overwrite existing artifact: {self.path / name}") from exc
                published = True
            except BaseException as exc:
                active = exc
                if not published and identity is not None:
                    # Settled while the descriptor still pins the inode, so the
                    # identity cannot belong to a file created after this one.
                    published = self._holds(name, identity)
                raise
            finally:
                try:
                    os.close(descriptor)
                except OSError as close_error:
                    if active is None:
                        raise
                    # The earlier exception (perhaps a cancellation) stays the one raised.
                    active.add_note(f"closing the anonymous artifact file also failed: {close_error.strerror or close_error}")
            os.fsync(self.descriptor)
            self.published_paths.append(str(self.path / name))
        except BaseException as exc:
            retained = ""
            if published is True:
                retained = f"{self.path / name} was published and is retained"
            elif published is None:
                retained = f"{self.path / name} may have been published and retained"
            suffix = f"; {retained}" if retained else ""
            if isinstance(exc, PrivateArtifactError):
                error = PrivateArtifactError(f"{exc}{suffix}")
            elif isinstance(exc, OSError):
                error = PrivateArtifactError(f"cannot write artifact {self.path / name}: {exc.strerror or exc}{suffix}")
            else:
                if retained:
                    exc.add_note(retained)
                    exc.retained_artifact = self.path / name  # type: ignore[attr-defined]
                raise
            if retained:
                error.retained_artifact = self.path / name  # type: ignore[attr-defined]
            raise error from exc
        return self.path / name

    def _holds(self, name: str, identity: tuple[int, int]) -> bool | None:
        """Whether ``name`` is the inode ``identity``; None when that cannot be told."""
        try:
            current = os.stat(name, dir_fd=self.descriptor, follow_symlinks=False)
        except FileNotFoundError:
            return False
        except OSError:
            return None
        return (current.st_dev, current.st_ino) == identity

    def _anonymous_file(self) -> int | None:
        """An unnamed 0600 file in this directory that can be linked in later, or None."""
        if not hasattr(os, "O_TMPFILE") or not os.path.isdir("/proc/self/fd"):
            return None
        try:
            return os.open(".", os.O_WRONLY | os.O_TMPFILE | os.O_CLOEXEC, 0o600, dir_fd=self.descriptor)
        except OSError as exc:
            if exc.errno in _TMPFILE_UNSUPPORTED:
                return None
            raise

    def contains(self, name: str) -> bool | None:
        """Whether ``name`` exists in this directory (None when that cannot be told)."""
        try:
            os.stat(_validate_name(name), dir_fd=self.descriptor, follow_symlinks=False)
        except FileNotFoundError:
            return False
        except OSError:
            return None
        return True

    def read(self, name: str, *, max_bytes: int = DEFAULT_MAX_BYTES) -> bytes:
        """Read an owner-only regular file in this directory, refusing substitutions."""
        name = _validate_name(name)
        try:
            descriptor = os.open(name, _READ_FLAGS, dir_fd=self.descriptor)
        except OSError as exc:
            raise PrivateArtifactError(f"cannot open artifact safely: {self.path / name}: {exc.strerror}") from exc
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode):
                raise PrivateArtifactError(f"artifact is not a regular file: {self.path / name}")
            if info.st_uid != os.getuid():
                raise PrivateArtifactError(f"artifact is owned by another user: {self.path / name}")
            if stat.S_IMODE(info.st_mode) & 0o077:
                raise PrivateArtifactError(f"artifact is group or world accessible: {self.path / name}")
            if info.st_nlink != 1:
                raise PrivateArtifactError(f"artifact has unexpected hard links: {self.path / name}")
            if info.st_size > max_bytes:
                raise PrivateArtifactError(f"artifact exceeds {max_bytes} bytes: {self.path / name}")
            chunks: list[bytes] = []
            remaining = max_bytes + 1
            while remaining > 0:
                chunk = os.read(descriptor, min(remaining, 1024 * 1024))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
        except PrivateArtifactError:
            raise
        except OSError as exc:
            raise PrivateArtifactError(f"cannot read artifact {self.path / name}: {exc.strerror or exc}") from exc
        finally:
            os.close(descriptor)
        data = b"".join(chunks)
        if len(data) > max_bytes:
            raise PrivateArtifactError(f"artifact exceeds {max_bytes} bytes: {self.path / name}")
        return data


def ensure_private_directory(path: Path) -> Path:
    """Create or verify an owner-only directory with no symlinked components."""
    with PrivateDirectory.open(path, create=True) as directory:
        return directory.path


def note_present_artifacts(exc: BaseException, directory: PrivateDirectory, names: list[str]) -> list[str]:
    """Note on ``exc`` each named artifact that exists after a failure (or cannot be checked); return them.

    Used around a whole transaction, so an interruption at any point after a
    publication (including between instructions that record it) still says
    where the files are.
    """
    present = []
    for name in names:
        state = directory.contains(name)
        if state is not False:
            present.append(str(directory.path / name) + ("" if state else " (could not be checked)"))
    if present:
        note = "private artifacts present after the failure: " + ", ".join(present)
        if note not in getattr(exc, "__notes__", []):
            exc.add_note(note)
    return present


def note_retained_by_name(exc: BaseException, paths: list[Path], published: list[str] | tuple[str, ...] = ()) -> list[str]:
    """Note on ``exc`` each of ``paths`` that exists, checked by name, for use once the directory may be closed.

    ``published`` lists paths known to have been published. One that is no longer found at its path is still
    reported, because another process may have moved the file or replaced its directory: a failed lookup is uncertainty
    about the location, not evidence that nothing was published. A path an earlier note already names is not
    noted again. Returns the paths reported.
    """
    found = []
    for path in paths:
        try:
            os.lstat(path)
        except FileNotFoundError:
            if str(path) not in published:
                continue
            note = f"{path} was published, but is no longer at that path (the file or its directory may have been moved or replaced)"
        except ValueError:
            continue  # such a name (for example one with a NUL byte) cannot exist
        except OSError:
            note = f"{path} may have been published and retained (could not be checked)"
        else:
            note = f"{path} was published and is retained"
        found.append(str(path))
        if not any(str(path) in existing for existing in getattr(exc, "__notes__", [])):
            exc.add_note(note)
    return found


def write_private_artifact(directory: Path, name: str, data: bytes) -> Path:
    """Publish ``data`` as ``directory/name`` (0600). Never overwrites.

    Any exception after the file may have been published carries its path as a
    note, including one at the return, while closing the directory or on the
    way into that cleanup. After this returns, a caller that needs the same
    guarantee checks ``name`` itself; the name is known before the call.
    """
    handle = PrivateDirectory.open(directory, create=True)
    try:
        try:
            path = handle.write(name, data)
            # The return stays inside the try with the finally, so CPython keeps the
            # closing code it runs on the way out inside the outer handler.
            return path
        except BaseException as exc:
            note_present_artifacts(exc, handle, [name])
            raise
        finally:
            handle.close()
    except BaseException as exc:
        # The descriptor may be gone by now, so check by name, keeping what is known to be published.
        note_retained_by_name(exc, [handle.path / name], handle.published_paths)
        raise


def read_private_artifact(path: Path, *, max_bytes: int = DEFAULT_MAX_BYTES) -> bytes:
    """Read an owner-only regular file, refusing substitutions anywhere in its path."""
    absolute = artifact_path(path)
    with PrivateDirectory.open(absolute.parent) as directory:
        return directory.read(absolute.name, max_bytes=max_bytes)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
