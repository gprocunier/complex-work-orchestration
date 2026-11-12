"""Inert, bounded capture of a Git worktree for retrospective mutation checks.

Git runs through one executable chosen from fixed absolute paths, accepted only
when it and every parent directory are owned by root or the current user and
not writable by group or others, and re-checked by identity at the end of the
capture. Each command gets a controlled environment and flags that disable
system and global config, fsmonitor, hooks, the untracked cache, optional
locks, lazy fetches, replace objects and every transport; its output is read
under the shared byte budget and its timeout is the remaining deadline.

Git is never pointed at a file of the inspected workspace or its repository. A capture
copies, through the pinned reader below, the index and the ignore files into a
private scratch repository it creates and writes only through descriptors,
under a parent pinned and checked component by component, and runs exactly
two read-only commands there. A location checkpoint, climbing from the
scratch descriptor through ``..``, runs before every write, before and after
each Git command and before cleanup; a scratch directory found moved is
abandoned (never written to or removed again) and reported, and change marks
taken around each Git command are compared, a best-effort check for a
replacement made and restored while it ran. The commands are
``ls-files --stage`` for the index and
``ls-files --others --ignored --exclude-standard`` on a mirror of the
untracked names. Config, HEAD and references are parsed, and HEAD's tree is
read from loose and packed objects, without Git (``git_store``), each object
checked against its identifier. Nothing applies clean or smudge filters or
queries attributes.

The worktree itself is read without Git, through descriptors opened one
component at a time with ``O_NOFOLLOW``. Every entry is inventoried with its
exact type and mode: directories, regular files (hashed), symlinks (target
hashed, never followed), FIFOs, sockets and device nodes (never opened), and
gitlink roots (opaque). A regular file is first pinned with ``O_PATH``, which
has no effect on the file, and is opened for reading only after its type and
inode are confirmed.

All phases share one budget of hashed files, walked entries, bytes read and a
deadline; Git metadata has its own byte and entry budget under the same
deadline. That metadata byte budget is also charged for every path built from
untrusted names (worktree paths and directory prefixes, HEAD's tree paths,
metadata keys, excluded and mirrored directories, untracked status lines),
at its stored size and before it is built. Any failure, exhausted budget,
unobservable declared path, unsupported layout or change of the bound
identities (root, gitdir, common dir, Git executable) makes the capture
incomplete. Captures are retrospective observations, not a write boundary: a
change made and reverted between two captures is not seen.

Threat model. The capture inspects untrusted repository contents and metadata
inertly, with bounded resource use, the declared path contract and explicit
incomplete results. It assumes that the observer's code, its execution
configuration and the capture-owned scratch directory, including the
directories above it, are outside untrusted mutation authority during
capture. It is not confinement against an unrestricted process of the same
user that can modify that trusted state, and its observations do not prove
that no temporary change happened between them. The scratch checkpoints are
best-effort detection within that model: whatever one detects makes the
capture incomplete, and none of them is an atomicity guarantee. Hostile
concurrent workers need a separately qualified boundary.
"""

from __future__ import annotations

import bisect
import errno
import hashlib
import os
import re
import secrets
import select
import stat
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from . import git_store
from .path_contract import path_components, path_within

TRUSTED_GIT_PATHS = ("/usr/bin/git", "/usr/local/bin/git", "/bin/git")
CONTROLLED_PATH = "/usr/bin:/bin"
# Inert inspection is qualified release by release: the inspection suite was
# run against the latest patch of every Git minor release in this range,
# built from source. A version outside it is refused until it is qualified.
MINIMUM_GIT_VERSION = (2, 35)
MAXIMUM_GIT_VERSION = (2, 56)
NO_TRUSTED_GIT = "no trusted git executable in the qualified range 2.35 to 2.56"
INERT_GIT_CONFIG = (
    "-c", "core.fsmonitor=false",
    "-c", "core.hooksPath=/dev/null",
    "-c", "core.untrackedCache=false",
    "-c", "protocol.allow=never",
    "-c", "core.pager=cat",
)
INDEX_MODES = {
    "100644": "file",
    "100755": "executable",
    "120000": "symlink",
    "160000": "gitlink",
    "040000": "sparse-directory",
}
METADATA_FILE_CAP = 16 * 1024 * 1024
# Where a capture's scratch repository may go when the process's temporary
# directory lies inside the inspected workspace or its repository.
SCRATCH_PARENTS = ("/tmp", "/var/tmp")
# How many directories the scratch location checkpoint climbs before giving up.
MAX_SCRATCH_DEPTH = 1024
# Filesystem change times may come from a clock that advances once per kernel
# tick (10 ms at the lowest common rate). Before Git runs, the scratch
# directory is left unchanged by this capture this long, so its own writes do
# not share a tick with a later change. The change marks are best-effort
# detection, not proof that nothing changed: see _Snapshot.
CHANGE_TIME_GRAIN_NS = 12_000_000
# Scratch cleanup may run this long past the capture deadline; a cleanup still
# running then stops, and the capture reports the directory it left.
CLEANUP_GRACE_SECONDS = 5.0
INDEX_FILE_CAP = 128 * 1024 * 1024
OBJECT_SIZE_CAP = 64 * 1024 * 1024
# Repository format extensions this capture reads correctly; any other is refused.
# Git honors the first four even at repository format version 0.
V0_EXTENSIONS = {"noop", "preciousobjects", "partialclone", "worktreeconfig"}
SUPPORTED_EXTENSIONS = V0_EXTENSIONS | {"objectformat", "refstorage"}
METADATA_BYTES = 64 * 1024 * 1024
METADATA_ENTRIES = 20_000
GIT_OUTPUT_CAP = 256 * 1024 * 1024
_ROOT_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
_DIR_FLAGS = _ROOT_FLAGS | os.O_NOFOLLOW
_PATH_FLAGS = os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC
_UP_FLAGS = os.O_PATH | os.O_DIRECTORY | os.O_CLOEXEC
# Attributes and settings that can make Git's view of a file differ from its raw bytes.
CONVERSION_ATTRIBUTES = frozenset({"filter", "ident", "text", "eol", "crlf", "working-tree-encoding"})
CONVERSION_SETTINGS = ("core.autocrlf", "core.eol", "core.safecrlf")
# Settings Git reads with git_config_bool that the capture interprets, and the
# boolean repository-format extensions.
BOOLEAN_SETTINGS = ("core.bare", "core.ignorecase", "core.sparsecheckout", "core.sparsecheckoutcone", "index.sparse")
BOOLEAN_EXTENSIONS = ("extensions.preciousobjects", "extensions.worktreeconfig")
# Config that would make Git open files beyond the checked set. Matched on raw
# bytes, case-insensitively and anywhere (comments included), so no config
# syntax has to be interpreted to rule it out.
_UNSUPPORTED_CONFIG = re.compile(rb"(?i)\[\s*include|excludesfile|attributesfile|splitindex")
# A backstop at the capture and discovery boundaries: an exception of these
# kinds from reading repository data makes the result incomplete (or a
# discovery error) instead of escaping. The readers refuse every malformation
# they know of explicitly; this covers one they do not.
_MALFORMED_DATA = (ValueError, IndexError, OverflowError, RecursionError)
_TYPE_NAMES = {
    stat.S_IFIFO: "fifo",
    stat.S_IFSOCK: "socket",
    stat.S_IFCHR: "char-device",
    stat.S_IFBLK: "block-device",
}


class PathReplacedError(OSError):
    """A path changed type or inode between lstat and open."""


class BudgetExhausted(Exception):
    """The shared capture budget ran out."""


class WorkspaceDiscoveryError(RuntimeError):
    """Inspection failed; nothing is known about whether the path is a worktree."""


@dataclass
class Budget:
    """One budget for every phase of a capture."""

    max_files: int
    max_bytes: int
    max_entries: int
    deadline: float
    files: int = 0
    bytes: int = 0
    entries: int = 0

    @classmethod
    def start(cls, *, max_files: int, max_bytes: int, max_seconds: float, max_entries: int) -> Budget:
        return cls(max(0, int(max_files)), max(0, int(max_bytes)), max(0, int(max_entries)), time.monotonic() + max(0.0, float(max_seconds)))

    def remaining_bytes(self) -> int:
        return max(0, self.max_bytes - self.bytes)

    def remaining_seconds(self) -> float:
        return self.deadline - time.monotonic()

    def check_time(self) -> None:
        if time.monotonic() > self.deadline:
            raise BudgetExhausted("deadline")

    def take_entry(self, count: int = 1) -> None:
        self.check_time()
        self.entries += count
        if self.entries > self.max_entries:
            raise BudgetExhausted("entry cap")

    def take_file(self) -> None:
        self.files += 1
        if self.files > self.max_files:
            raise BudgetExhausted("file cap")

    def take_bytes(self, count: int) -> None:
        self.bytes += count
        if self.bytes > self.max_bytes:
            raise BudgetExhausted("byte cap")


def _read_pinned(
    dir_fd: int, name: str, info: os.stat_result, cap: int, *, follow: bool = False, deadline: float | None = None
) -> bytes:
    """Read a regular file whose type and inode are confirmed before any reading open.

    The name is first opened with ``O_PATH``, which neither reads nor wakes
    anything, and only that confirmed inode is reopened for reading.
    """
    if info.st_size > cap:
        raise BudgetExhausted("byte cap")
    pinned = os.open(name, _PATH_FLAGS if not follow else os.O_PATH | os.O_CLOEXEC, dir_fd=dir_fd)
    try:
        observed = os.fstat(pinned)
        if not stat.S_ISREG(observed.st_mode) or (observed.st_dev, observed.st_ino) != (info.st_dev, info.st_ino):
            raise PathReplacedError(errno.EAGAIN, "path replaced during read", name)
        descriptor = os.open(f"/proc/self/fd/{pinned}", os.O_RDONLY | os.O_CLOEXEC)
    finally:
        os.close(pinned)
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
            raise PathReplacedError(errno.EAGAIN, "path replaced during read", name)
        chunks: list[bytes] = []
        total = 0
        while True:
            if deadline is not None and time.monotonic() > deadline:
                raise BudgetExhausted("deadline")
            chunk = os.read(descriptor, min(1 << 20, cap + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > cap:
                raise BudgetExhausted("byte cap")
    finally:
        os.close(descriptor)
    return b"".join(chunks)


def entry_kind(info: os.stat_result) -> str:
    if stat.S_ISREG(info.st_mode):
        return "file"
    if stat.S_ISDIR(info.st_mode):
        return "directory"
    if stat.S_ISLNK(info.st_mode):
        return "symlink"
    return _TYPE_NAMES.get(stat.S_IFMT(info.st_mode), "special")


def read_at(dir_fd: int, name: str, cap: int, *, deadline: float | None = None) -> tuple[str, bytes | None, os.stat_result | None]:
    """Read one entry of an open directory without following it.

    Returns ``(kind, data, lstat)``: ``kind`` is file, symlink (data is the
    target), directory, fifo, socket, char-device, block-device or absent.
    Only regular files and symlink targets are read.
    """
    try:
        info = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
    except FileNotFoundError:
        return "absent", None, None
    kind = entry_kind(info)
    if kind == "symlink":
        target = os.fsencode(os.readlink(name, dir_fd=dir_fd))
        if len(target) > cap:
            raise BudgetExhausted("byte cap")
        return kind, target, info
    if kind == "file":
        return kind, _read_pinned(dir_fd, name, info, cap, deadline=deadline), info
    return kind, None, info


def read_beneath(
    root_fd: int, relative: str, cap: int, *, deadline: float | None = None
) -> tuple[str, bytes | None, os.stat_result | None]:
    """Read ``relative`` under an open root without following any symlink.

    A missing, non-directory or symlinked ancestor means the path is absent
    beneath the root; the read is never redirected elsewhere.
    """
    parts = path_components(relative)
    if parts is None:
        raise ValueError(f"invalid relative path: {relative!r}")
    current = os.dup(root_fd)
    try:
        for name in parts[:-1]:
            try:
                following = os.open(name, _DIR_FLAGS, dir_fd=current)
            except (FileNotFoundError, NotADirectoryError):
                return "absent", None, None
            except OSError as exc:
                if exc.errno == errno.ELOOP:
                    return "absent", None, None
                raise
            os.close(current)
            current = following
        return read_at(current, parts[-1], cap, deadline=deadline)
    finally:
        os.close(current)


def _blob_id(algorithm: str, data: bytes) -> str:
    digest = hashlib.new(algorithm)
    digest.update(b"blob %d\0" % len(data))
    digest.update(data)
    return digest.hexdigest()


def _decode(raw: bytes) -> str:
    return raw.decode("utf-8", errors="surrogateescape")


# Git executable -----------------------------------------------------------


@dataclass(frozen=True)
class GitExecutable:
    path: str
    identity: tuple[int, int, int, int]
    version: tuple[int, ...]

    def describe(self) -> dict[str, Any]:
        return {"path": self.path, "version": ".".join(str(part) for part in self.version)}


_GIT_CACHE: dict[str, GitExecutable] = {}


def _owned_and_not_shared(path: str) -> bool:
    try:
        info = os.stat(path)
    except OSError:
        return False
    return info.st_uid in {0, os.geteuid()} and not info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)


def _trustworthy(path: str) -> bool:
    if not os.path.isabs(path) or not os.path.isfile(path) or not os.access(path, os.X_OK):
        return False
    current = path
    while True:
        if not _owned_and_not_shared(current):
            return False
        parent = os.path.dirname(current)
        if parent == current:
            return True
        current = parent


def _identity(path: str) -> tuple[int, int, int, int] | None:
    try:
        info = os.stat(path)
    except OSError:
        return None
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns)


def _environment() -> dict[str, str]:
    return {
        "PATH": CONTROLLED_PATH,
        "HOME": "/nonexistent",
        "LC_ALL": "C",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_NO_LAZY_FETCH": "1",
        "GIT_ATTR_NOSYSTEM": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_PROTOCOL_FROM_USER": "0",
        # An allow list overrides every protocol.<name>.allow setting, including a
        # repository's own, so no transport (and no promisor fetch through one) can
        # start. The 2.35 to 2.38 releases in the qualified range ignore GIT_NO_LAZY_FETCH.
        "GIT_ALLOW_PROTOCOL": "",
    }


def _version(path: str, timeout: float = 10.0) -> tuple[int, ...] | None:
    try:
        result = subprocess.run([path, "--version"], env=_environment(), stdin=subprocess.DEVNULL,
                                capture_output=True, timeout=max(0.1, min(10.0, timeout)), check=False)
    except (OSError, subprocess.TimeoutExpired):
        return None
    words = result.stdout.decode("ascii", errors="replace").split()
    if result.returncode != 0 or len(words) < 3 or words[:2] != ["git", "version"]:
        return None
    numbers: list[int] = []
    for piece in words[2].split(".")[:3]:
        if not piece.isdigit():
            break
        numbers.append(int(piece))
    return tuple(numbers) or None


def trusted_git(candidates: tuple[str, ...] = TRUSTED_GIT_PATHS, *, timeout: float = 10.0) -> GitExecutable | None:
    """The first acceptable Git from fixed paths, or None. Never searches PATH.

    Qualifying an uncached executable runs ``git --version`` within ``timeout``.
    """
    for candidate in candidates:
        try:
            real = _real_path(candidate)
        except _CaptureFailure:
            continue
        if not _trustworthy(real):
            continue
        identity = _identity(real)
        cached = _GIT_CACHE.get(real)
        if cached is not None and cached.identity == identity:
            return cached
        version = _version(real, timeout)
        if identity is None or version is None or not MINIMUM_GIT_VERSION <= version[:2] <= MAXIMUM_GIT_VERSION:
            continue
        executable = GitExecutable(real, identity, version)
        _GIT_CACHE[real] = executable
        return executable
    return None


@dataclass
class GitResult:
    returncode: int
    stdout: bytes
    stderr: bytes


def run_git(
    git: GitExecutable,
    root: Path | str,
    args: list[str],
    *,
    timeout: float = 30.0,
    max_output: int = GIT_OUTPUT_CAP,
    budget: Budget | None = None,
    git_dir: str | None = None,
    work_tree: str | None = None,
    ceiling: str | None = None,
) -> GitResult:
    """Run read-only Git plumbing with the hardened configuration.

    Combined stdout and stderr beyond ``max_output`` bytes stops the command
    and raises BudgetExhausted, as does running past ``timeout``. With a
    ``budget``, its deadline applies and every byte read is charged to it as
    it arrives. With ``git_dir`` (and ``work_tree``), Git is bound to that
    repository and does no discovery of its own; with ``ceiling``, discovery
    stops below that directory.
    """
    deadline = budget.deadline if budget is not None else time.monotonic() + max(0.0, timeout)
    environment = _environment()
    if git_dir is not None:
        environment["GIT_DIR"] = git_dir
        environment["GIT_WORK_TREE"] = work_tree if work_tree is not None else str(root)
    if ceiling is not None:
        environment["GIT_CEILING_DIRECTORIES"] = ceiling
    process = subprocess.Popen(
        [git.path, "-C", str(root), *INERT_GIT_CONFIG, *args],
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    stdout_fd = process.stdout.fileno()  # type: ignore[union-attr]
    stderr_fd = process.stderr.fileno()  # type: ignore[union-attr]
    streams = {stdout_fd: bytearray(), stderr_fd: bytearray()}
    open_fds = set(streams)
    try:
        while open_fds:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise BudgetExhausted("deadline")
            ready, _, _ = select.select(list(open_fds), [], [], remaining)
            for fd in ready:
                chunk = os.read(fd, 1 << 16)
                if not chunk:
                    open_fds.discard(fd)
                    continue
                streams[fd] += chunk
                if budget is not None:
                    budget.take_bytes(len(chunk))
                if len(streams[stdout_fd]) + len(streams[stderr_fd]) > max_output:
                    raise BudgetExhausted("byte cap")
        returncode = process.wait(timeout=max(0.1, deadline - time.monotonic()))
    except BaseException:
        process.kill()
        process.wait()
        raise
    finally:
        process.stdout.close()  # type: ignore[union-attr]
        process.stderr.close()  # type: ignore[union-attr]
    return GitResult(returncode, bytes(streams[stdout_fd]), bytes(streams[stderr_fd]))


def _qualify_repository(root: Path | str) -> tuple[str, str]:
    """Check, without Git, the repository files Git would read for ``root``; return (top level, gitdir).

    The same preflight as a capture runs on the nearest directory holding a
    ``.git`` entry, and callers then bind Git to that worktree and gitdir
    (``GIT_DIR``, ``GIT_WORK_TREE``), so Git does no discovery of its own: a
    nested bare repository cannot take over. A directory with no ``.git``
    entry above it is refused, because Git could still discover a bare
    repository there whose files nothing has checked.
    """
    probe = _probe(root, "repository files are not safe for git to read")
    if probe is None:
        raise WorkspaceDiscoveryError(f"no .git entry at or above {root}; git is not run")
    return str(probe.root), probe.preflight_dirs[0]


def trusted_git_output(root: Path | str, args: list[str], *, timeout: float = 60.0) -> str:
    """stdout of read-only Git plumbing through the trusted executable, or raise.

    For inspection outside a capture: other modules use this instead of a bare
    ``git`` from PATH with an inherited environment.
    """
    git = trusted_git()
    if git is None:
        raise WorkspaceDiscoveryError(NO_TRUSTED_GIT)
    top, git_dir = _qualify_repository(root)
    try:
        result = run_git(git, root, args, timeout=timeout, git_dir=git_dir, work_tree=top)
    except (OSError, BudgetExhausted) as exc:
        raise WorkspaceDiscoveryError(f"git {args[0]} did not complete: {exc}") from exc
    if result.returncode != 0:
        raise WorkspaceDiscoveryError(f"git {args[0]} failed: {_decode(result.stderr).strip()[:200]}")
    # Only the line terminator: a path may end in a space Git kept, including a non-ASCII one.
    return _decode(result.stdout).rstrip("\n")


def trusted_git_succeeds(root: Path | str, args: list[str], *, timeout: float = 60.0) -> bool:
    """Exit status of a read-only predicate (for example ``merge-base --is-ancestor``).

    Exit 0 is True and exit 1 is False; any other outcome raises.
    """
    git = trusted_git()
    if git is None:
        raise WorkspaceDiscoveryError(NO_TRUSTED_GIT)
    top, git_dir = _qualify_repository(root)
    try:
        result = run_git(git, root, args, timeout=timeout, git_dir=git_dir, work_tree=top)
    except (OSError, BudgetExhausted) as exc:
        raise WorkspaceDiscoveryError(f"git {args[0]} did not complete: {exc}") from exc
    if result.returncode in {0, 1}:
        return result.returncode == 0
    raise WorkspaceDiscoveryError(f"git {args[0]} failed: {_decode(result.stderr).strip()[:200]}")


def trusted_git_completed(
    root: Path | str, args: list[str], *, timeout: float = 60.0, text: bool = False
) -> subprocess.CompletedProcess[Any]:
    """``subprocess.run``-shaped result of read-only Git through the trusted executable.

    The repository is qualified by the capture preflight first. When the
    trusted executable is missing, the repository is not safe for Git to read
    or the command cannot complete, the result has return code 128 and the
    reason in stderr, so callers that test the return code fail closed.
    """
    command = ["git", *args]
    git = trusted_git()
    if git is None:
        result = GitResult(128, b"", NO_TRUSTED_GIT.encode())
    else:
        try:
            top, git_dir = _qualify_repository(root)
            result = run_git(git, root, args, timeout=timeout, git_dir=git_dir, work_tree=top)
        except WorkspaceDiscoveryError as exc:
            result = GitResult(128, b"", str(exc).encode())
        except (OSError, BudgetExhausted) as exc:
            result = GitResult(128, b"", f"git did not complete: {exc}".encode())
    if text:
        return subprocess.CompletedProcess(command, result.returncode, _decode(result.stdout), _decode(result.stderr))
    return subprocess.CompletedProcess(command, result.returncode, result.stdout, result.stderr)


def trusted_git_private(root: Path | str, args: list[str], *, timeout: float = 60.0) -> subprocess.CompletedProcess[str]:
    """Git on a repository this process creates in its own private directory.

    For the scratch repositories that previews and canaries build (``init``,
    ``config``, ``add``, ``commit``, ``worktree add``); never for inspecting a
    workspace. The trusted executable and hardened configuration apply, and
    discovery stops at ``root`` itself (its parent is the ceiling), so an
    enclosing repository is never used. Failures have return code 128.
    """
    command = ["git", *args]
    git = trusted_git()
    if git is None:
        result = GitResult(128, b"", NO_TRUSTED_GIT.encode())
    else:
        try:
            real = _real_path(root)
            result = run_git(git, real, args, timeout=timeout, ceiling=os.path.dirname(real))
        except _CaptureFailure as exc:
            result = GitResult(128, b"", str(exc).encode())
        except (OSError, BudgetExhausted) as exc:
            result = GitResult(128, b"", f"git did not complete: {exc}".encode())
    return subprocess.CompletedProcess(command, result.returncode, _decode(result.stdout), _decode(result.stderr))


def trusted_git_ignored(root: Path | str, paths: list[str], *, timeout: float = 120.0) -> set[str]:
    """The subset of ``paths`` (relative to the worktree top level ``root``) that Git ignores; raise if unsure.

    ``check-ignore`` reads the ``.gitignore`` of the worktree root and of each
    directory leading to a path, besides the repository files the preflight
    checks. Before Git runs, each of those is found without following
    symlinks and must be a regular file or absent; a directory on the way that
    is a symlink is refused.
    """
    git = trusted_git()
    if git is None:
        raise WorkspaceDiscoveryError(NO_TRUSTED_GIT)
    top, git_dir = _qualify_repository(root)
    try:
        if _real_path(root) != top:
            raise WorkspaceDiscoveryError("ignore checks take paths from the worktree top level")
    except _CaptureFailure as exc:
        raise WorkspaceDiscoveryError(str(exc)) from exc
    split: list[tuple[str, ...]] = []
    for path in paths:
        parts = path_components(path)
        if parts is None:
            raise WorkspaceDiscoveryError("ignore checks need relative paths within the worktree")
        split.append(parts)
    try:
        _check_ignore_files(top, {parts[:index] for parts in split for index in range(len(parts))})
    except (OSError, *_MALFORMED_DATA) as exc:
        raise WorkspaceDiscoveryError(f"cannot inspect the ignore files of {top}: {exc}") from exc
    if not paths:
        return set()
    if any(character in path for path in paths for character in '"\\') or any(
            ord(character) < 0x20 or ord(character) == 0x7F for path in paths for character in path):
        # Git would quote such a name in its answer; refuse rather than unquote.
        raise WorkspaceDiscoveryError("ignore checks take paths without quotes, backslashes or control characters")
    try:
        result = run_git(git, top, ["-c", "core.quotePath=false", "check-ignore", "--", *paths], timeout=timeout,
                         git_dir=git_dir, work_tree=top)
    except (OSError, BudgetExhausted) as exc:
        raise WorkspaceDiscoveryError(f"git check-ignore did not complete: {exc}") from exc
    if result.returncode not in {0, 1}:
        raise WorkspaceDiscoveryError(f"git check-ignore failed: {_decode(result.stderr).strip()[:200]}")
    ignored = {line for line in _decode(result.stdout).split("\n") if line}
    if not ignored <= set(paths):
        raise WorkspaceDiscoveryError("git check-ignore answered with a path that was not asked about")
    return ignored


def _check_ignore_files(top: str, directories: set[tuple[str, ...]]) -> None:
    """Require the .gitignore of each directory (component tuples under ``top``) to be regular or absent."""
    for parts in sorted(directories):
        current = os.open(top, _ROOT_FLAGS)
        try:
            for name in parts:
                try:
                    following = os.open(name, _DIR_FLAGS, dir_fd=current)
                except OSError as exc:
                    try:
                        is_link = stat.S_ISLNK(os.stat(name, dir_fd=current, follow_symlinks=False).st_mode)
                    except FileNotFoundError:
                        break  # absent: nothing below is read
                    if is_link:
                        raise WorkspaceDiscoveryError(f"a directory on the way to an ignore check is a symlink: {'/'.join(parts)}") from exc
                    if isinstance(exc, NotADirectoryError):
                        break  # a file: nothing below is read
                    raise WorkspaceDiscoveryError(f"cannot inspect {'/'.join(parts)}: {exc.strerror}") from exc
                os.close(current)
                current = following
            else:
                try:
                    info = os.stat(".gitignore", dir_fd=current, follow_symlinks=False)
                except FileNotFoundError:
                    continue
                except OSError as exc:
                    raise WorkspaceDiscoveryError(f"cannot inspect {'/'.join((*parts, '.gitignore'))}: {exc.strerror}") from exc
                if not stat.S_ISREG(info.st_mode):
                    raise WorkspaceDiscoveryError(f"a .gitignore Git would read is not a regular file: {'/'.join((*parts, '.gitignore'))}")
        finally:
            os.close(current)


def _nearest_git_root(path: str) -> str | None:
    """The nearest of ``path`` and its ancestors holding a ``.git`` entry of any kind.

    Only genuine absence moves on to the parent; a permission or I/O error
    is a discovery failure, never "not a repository".
    """
    current = path
    while True:
        try:
            os.lstat(os.path.join(current, ".git"))
            return current
        except (FileNotFoundError, NotADirectoryError):
            pass
        except OSError as exc:
            raise WorkspaceDiscoveryError(f"cannot inspect {os.path.join(current, '.git')}: {exc.strerror or exc}") from exc
        parent = os.path.dirname(current)
        if parent == current:
            return None
        current = parent


def worktree_top_level(cwd: Path | str) -> str | None:
    """The worktree top level for ``cwd``; None only when no ``.git`` entry exists above it.

    Found without Git: the nearest directory holding a ``.git`` entry, whose
    repository files are checked as in a capture's preflight (indirection read
    as Git reads it, supported layouts only, no ``core.worktree``). Every
    failure (an unsafe or unsupported repository file, unreadable
    configuration, broken indirection) raises WorkspaceDiscoveryError.
    """
    probe = _probe(cwd, "repository files are not safe to read")
    return None if probe is None else str(probe.root)


def repository_dirs(path: Path | str) -> tuple[str, str, str]:
    """``(top level, gitdir, common directory)`` for the repository holding ``path``, found without Git."""
    probe = _probe(path, "repository files are not safe to read")
    if probe is None:
        raise WorkspaceDiscoveryError(f"no .git entry at or above {path}")
    return str(probe.root), probe.preflight_dirs[0], probe.preflight_dirs[1]


def _real_path(path: Path | str) -> str:
    """``os.path.realpath(path)``; a path that cannot be resolved raises _CaptureFailure.

    On Python 3.12 a long enough symlink chain makes ``realpath`` recurse past
    the interpreter's limit, and a path holding a NUL raises ValueError.
    """
    try:
        return os.path.realpath(path)
    except (OSError, *_MALFORMED_DATA) as exc:
        raise _CaptureFailure(f"cannot resolve {os.fsdecode(path)!r}: {type(exc).__name__}: {exc}") from exc


def _probe(path: Path | str, refusal: str) -> WorktreeCapture | None:
    """The preflighted repository holding ``path``; None only when no ``.git`` entry exists at or above it.

    Resolving ``path``, finding the ``.git`` entry and the preflight share one
    structured refusal: any failure is a WorkspaceDiscoveryError.
    """
    try:
        candidate = _nearest_git_root(_real_path(path))
        if candidate is None:
            return None
        probe = WorktreeCapture(candidate, budget=Budget.start(max_files=0, max_bytes=0, max_seconds=30, max_entries=0),
                                scope=CaptureScope())
        probe._preflight()
    except (_CaptureFailure, BudgetExhausted, PathReplacedError, OSError, *_MALFORMED_DATA) as exc:
        raise WorkspaceDiscoveryError(f"{refusal}: {exc}") from exc
    return probe


def _open_regular(path: str) -> int:
    """A read-only descriptor for the regular file at ``path``, opened only after its type is confirmed.

    Symlinks are followed, as Git follows them inside a repository directory.
    The name is pinned with ``O_PATH`` first, so a FIFO or device is never
    opened for reading; FileNotFoundError means the file is absent.
    """
    parent, name = os.path.split(path)
    parent_fd = os.open(parent or "/", _ROOT_FLAGS)
    try:
        info = os.stat(name, dir_fd=parent_fd)
        if not stat.S_ISREG(info.st_mode):
            raise _CaptureFailure(f"repository file is not a regular file: {path}")
        pinned = os.open(name, os.O_PATH | os.O_CLOEXEC, dir_fd=parent_fd)
        try:
            observed = os.fstat(pinned)
            if not stat.S_ISREG(observed.st_mode) or (observed.st_dev, observed.st_ino) != (info.st_dev, info.st_ino):
                raise PathReplacedError(errno.EAGAIN, "path replaced during read", path)
            return os.open(f"/proc/self/fd/{pinned}", os.O_RDONLY | os.O_CLOEXEC)
        finally:
            os.close(pinned)
    finally:
        os.close(parent_fd)


def _inside(path: str, directories: list[str]) -> bool:
    return any(path == directory or path.startswith(directory.rstrip(os.sep) + os.sep) for directory in directories)


def _scratch_candidates() -> list[str]:
    """Where a scratch directory may go, in order, found without touching the filesystem.

    ``tempfile.tempdir`` when a program has set it, then ``TMPDIR``, ``TEMP``
    and ``TMP`` as ``tempfile`` reads them, then ``SCRATCH_PARENTS``.
    ``tempfile.gettempdir()`` is never called: on first use it creates and
    deletes a probe file in each candidate, before anything here could check
    where that candidate is. A candidate that cannot be made absolute is left
    out.
    """
    candidates = [tempfile.tempdir] if isinstance(tempfile.tempdir, str) and tempfile.tempdir else []
    candidates += [value for value in (os.environ.get(name) for name in ("TMPDIR", "TEMP", "TMP")) if value]
    absolute: list[str] = []
    for candidate in (*candidates, *SCRATCH_PARENTS):
        # Made absolute without lexical normalization: a ".." after a symlink is left for the
        # filesystem to resolve (``_real_path``), as it would be when the path is used.
        try:
            absolute.append(candidate if os.path.isabs(candidate) else os.path.join(os.getcwd(), candidate))
        except (OSError, ValueError):
            continue
    return list(dict.fromkeys(absolute))


def _private_enough(info: os.stat_result) -> bool:
    """A directory owned by root or this user that nobody else can rename entries in.

    Group- or world-writable directories qualify only with the sticky bit
    (as ``/tmp`` has), which stops others from renaming or removing what
    this user creates there.
    """
    return (stat.S_ISDIR(info.st_mode) and info.st_uid in {0, os.geteuid()}
            and (not info.st_mode & (stat.S_IWGRP | stat.S_IWOTH) or bool(info.st_mode & stat.S_ISVTX)))


def _pin_directory(path: str) -> tuple[int, list[tuple[int, int]]] | None:
    """A descriptor for the absolute, resolved ``path``, opened one component at a time from ``/``.

    No component is followed if it is a symlink, and each directory on the
    way must be ``_private_enough``. Returns the descriptor and the device and
    inode of every directory on the way, in order from ``/`` to ``path``, or
    None when the path cannot be pinned like this.
    """
    descriptor = os.open("/", _ROOT_FLAGS)
    identities: list[tuple[int, int]] = []
    try:
        for name in ("", *(part for part in path.split("/") if part)):
            if name:
                following = os.open(name, _DIR_FLAGS, dir_fd=descriptor)
                os.close(descriptor)
                descriptor = following
            info = os.fstat(descriptor)
            if not _private_enough(info):
                os.close(descriptor)
                return None
            identities.append((info.st_dev, info.st_ino))
    except OSError:
        os.close(descriptor)
        return None
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor, identities


def _ancestry(fd: int) -> list[os.stat_result]:
    """The directory open at ``fd`` and every directory above it, up to ``/``, found by descriptor.

    Each step opens ``..`` of the directory reached (``O_PATH``, so nothing is
    read), never a path, so the chain is where the directory is now, whatever
    any path names. At most MAX_SCRATCH_DEPTH directories are climbed.
    """
    chain: list[os.stat_result] = []
    current = os.dup(fd)
    try:
        info = os.fstat(current)
        while True:
            chain.append(info)
            if len(chain) > MAX_SCRATCH_DEPTH:
                raise _ScratchRelocated("the scratch directory lies deeper than any pinned parent")
            parent = os.open("..", _UP_FLAGS, dir_fd=current)
            os.close(current)
            current = parent
            above = os.fstat(current)
            if (above.st_dev, above.st_ino) == (info.st_dev, info.st_ino):
                return chain  # "/" is its own parent
            info = above
    except OSError as exc:
        raise _ScratchRelocated(f"the scratch directory's location cannot be confirmed: {exc}") from exc
    finally:
        os.close(current)


def _check_location(fd: int, expected: list[tuple[int, int]], protected: set[tuple[int, int]]) -> list[os.stat_result]:
    """The location checkpoint: the chain above ``fd`` must be exactly ``expected`` (device and inode,
    from ``fd`` up to ``/``) and hold no ``protected`` directory. Raises _ScratchRelocated otherwise;
    returns the chain."""
    chain = _ancestry(fd)
    identities = [(info.st_dev, info.st_ino) for info in chain]
    if protected.intersection(identities):
        raise _ScratchRelocated("the scratch directory was relocated into the workspace or its repository")
    if identities != expected:
        raise _ScratchRelocated("the scratch directory was relocated from its pinned location")
    return chain


def _renamable(child: os.stat_result, parent: os.stat_result) -> bool:
    """Whether a process of this user could rename ``child`` out of ``parent``, and so replace and restore it."""
    euid = os.geteuid()
    if euid == 0 or parent.st_uid == euid:
        return True  # an owner can always make its directory writable
    if parent.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        return not parent.st_mode & stat.S_ISVTX or child.st_uid == euid
    return False


def _scratch_name() -> str:
    return "cwo-inspect-" + secrets.token_hex(8)


def _scratch_directory(
    protected: tuple[str, ...],
) -> tuple[int, int, str, str, tuple[int, int], list[tuple[int, int]], set[tuple[int, int]]]:
    """A new mode-0700 directory outside every ``protected`` directory, created through a pinned parent.

    Each candidate parent is resolved, then opened one component at a time
    without following symlinks (``_pin_directory``), and checked on those
    descriptors: every directory on the way must be owned by root or this
    user and not open to renames by others, and none may be a protected
    directory by device and inode (a bind mount of one). Immediately before
    the creation, the location checkpoint (``_check_location``) climbs from
    the parent's descriptor through ``..`` and confirms that the parent still
    sits on the pinned chain, with no protected directory above it; a parent
    moved since it was pinned fails the capture before anything is created.
    The new directory is created with ``mkdir`` relative to the parent's
    descriptor under a random name and opened without following symlinks.
    Returns ``(parent descriptor, scratch descriptor, scratch name, scratch
    path, scratch identity, pinned chain from / to the parent, protected
    identities)``.
    """
    real = [_real_path(path) for path in protected]
    identities: set[tuple[int, int]] = set()
    for path in real:
        info = os.stat(path)
        identities.add((info.st_dev, info.st_ino))
    for candidate in _scratch_candidates():
        try:
            parent = _real_path(candidate)
        except _CaptureFailure:
            continue
        if _inside(parent, real):
            continue
        pinned = _pin_directory(parent)
        if pinned is None:
            continue
        parent_fd, chain = pinned
        if identities.intersection(chain):
            os.close(parent_fd)
            continue
        try:
            upward = chain[::-1]
            _check_location(parent_fd, upward, identities)
            fd, name, identity = _create_private_directory(parent_fd, parent, upward, identities)
        except BaseException:
            os.close(parent_fd)
            raise
        return parent_fd, fd, name, os.path.join(parent, name), identity, chain, identities
    raise _CaptureFailure("no scratch directory outside the workspace and its repository")


def _observed_child(parent_fd: int, name: str, parent_path: str) -> str:
    """The absolute path of ``name`` in the directory open at ``parent_fd``, where that directory is now."""
    try:
        return os.path.join(os.readlink(f"/proc/self/fd/{parent_fd}"), name)
    except OSError:
        return os.path.join(parent_path, name)


def _remove_new_directory(
    parent_fd: int, name: str, parent_path: str, expected: list[tuple[int, int]], protected: set[tuple[int, int]],
    failure: str,
) -> None:
    """Remove a directory just created in ``parent_fd``, only while the parent is still where it was pinned.

    ``failure`` says why construction stopped. When the directory cannot be
    removed, because the parent has moved (it is then abandoned, not
    removed) or because the removal fails, the error raised carries the
    directory's absolute path as observed (``abandoned``), so the capture
    reports what it left behind: _ScratchRelocated for a moved parent,
    _CaptureFailure otherwise. Returns normally once the directory is gone.
    """
    try:
        _check_location(parent_fd, expected, protected)
    except _ScratchRelocated as exc:
        left = _observed_child(parent_fd, name, parent_path)
        raise _ScratchRelocated(f"{failure}; {exc}; the new scratch directory was abandoned, not removed: {left}",
                                abandoned=left) from exc
    try:
        os.rmdir(name, dir_fd=parent_fd)
    except OSError as exc:
        left = _observed_child(parent_fd, name, parent_path)
        raise _CaptureFailure(f"{failure}; the new scratch directory could not be removed ({exc}): {left}",
                              abandoned=left) from exc


def _create_private_directory(
    parent_fd: int, parent_path: str, expected: list[tuple[int, int]], protected: set[tuple[int, int]]
) -> tuple[int, str, tuple[int, int]]:
    """Create and open a new mode-0700 directory under a random name in the directory open at ``parent_fd``.

    Returns its descriptor, name and identity. If it cannot be opened or
    checked, or is not private, it is removed again only after the location
    checkpoint confirms the parent; every descriptor opened here is closed on
    failure, and a directory that could not be removed is reported with its
    path (``_remove_new_directory``).
    """
    for _ in range(16):
        name = _scratch_name()
        try:
            os.mkdir(name, 0o700, dir_fd=parent_fd)
        except FileExistsError:
            continue
        try:
            fd = os.open(name, _DIR_FLAGS, dir_fd=parent_fd)
        except BaseException as exc:
            _remove_new_directory(parent_fd, name, parent_path, expected, protected,
                                  f"the new scratch directory could not be opened: {exc}")
            raise
        try:
            info = os.fstat(fd)
            private = info.st_uid == os.geteuid() and not stat.S_IMODE(info.st_mode) & 0o077
        except BaseException as exc:
            os.close(fd)
            _remove_new_directory(parent_fd, name, parent_path, expected, protected,
                                  f"the new scratch directory could not be checked: {exc}")
            raise
        if not private:
            os.close(fd)
            _remove_new_directory(parent_fd, name, parent_path, expected, protected,
                                  "the new scratch directory is not private")
            raise _CaptureFailure("the new scratch directory is not private")
        return fd, name, (info.st_dev, info.st_ino)
    raise _CaptureFailure("no unused scratch directory name")


def _open_beneath(dir_fd: int, parts: list[bytes], *, create: bool) -> tuple[int, int]:
    """A descriptor for the directory ``parts`` below ``dir_fd``, never following a symlink; with
    ``create``, missing directories are made (mode 0700) on the way. Returns the descriptor and how
    many directories were made."""
    made = 0
    current = os.dup(dir_fd)
    try:
        for part in parts:
            if create:
                try:
                    os.mkdir(part, 0o700, dir_fd=current)
                    made += 1
                except FileExistsError:
                    pass
            following = os.open(part, _DIR_FLAGS, dir_fd=current)
            os.close(current)
            current = following
    except BaseException:
        os.close(current)
        raise
    return current, made


def _walk_down(
    top_fd: int,
    scan: Callable[[int, int], list[bytes]],
    leave: Callable[[int, bytes], None] | None = None,
    check_time: Callable[[], None] | None = None,
) -> None:
    """Visit each directory below the one open at ``top_fd`` exactly once, holding one descriptor at a time.

    ``scan(fd, depth)`` lists a directory once and returns the names of the
    subdirectories to enter, which are entered from the end of that list;
    ``leave(parent_fd, name)`` runs once everything below ``name`` has been
    visited. The traversal state is one list of pending names per level, so
    no directory is listed twice and depth costs neither descriptors nor
    recursion. Entering opens each name without following symlinks;
    climbing goes through ``..`` and checks the identity recorded on the way
    down, so a moved directory stops the walk (``EXDEV``) instead of reaching
    anything else. ``check_time`` runs at every step.
    """
    current = os.dup(top_fd)
    try:
        stack: list[tuple[bytes, tuple[int, int], list[bytes]]] = [(b"", (0, 0), scan(current, 0))]
        while True:
            if check_time is not None:
                check_time()
            name, parent_identity, pending = stack[-1]
            if pending:
                child = pending.pop()
                here = os.fstat(current)
                following = os.open(child, _DIR_FLAGS, dir_fd=current)
                os.close(current)
                current = following
                stack.append((child, (here.st_dev, here.st_ino), scan(current, len(stack))))
                continue
            stack.pop()
            if not stack:
                return
            parent = os.open("..", _DIR_FLAGS, dir_fd=current)
            try:
                info = os.fstat(parent)
            except BaseException:
                os.close(parent)
                raise
            if (info.st_dev, info.st_ino) != parent_identity:
                os.close(parent)
                raise OSError(errno.EXDEV, "scratch directory moved during the walk")
            os.close(current)
            current = parent
            if leave is not None:
                leave(current, name)
    finally:
        os.close(current)


def _empty_directory(top_fd: int, check_time: Callable[[], None] | None = None) -> None:
    """Remove everything below the directory open at ``top_fd``, through descriptors only.

    Each directory is listed exactly once (``_walk_down``), through a new open
    of it: a descriptor opened before entries were added may not list them
    (btrfs reads a directory up to its state at open). Its files and symlinks
    are unlinked, never followed, and it is removed once everything below it
    is. ``check_time`` runs at every step and every TIME_CHECK_INTERVAL
    entries; whatever stops the removal leaves the rest in place.
    """
    def scan(fd: int, _depth: int) -> list[bytes]:
        directories: list[bytes] = []
        others: list[bytes] = []
        listing = os.open(".", _DIR_FLAGS, dir_fd=fd)
        try:
            with os.scandir(listing) as entries:
                for count, entry in enumerate(entries, 1):
                    if check_time is not None and not count % git_store.TIME_CHECK_INTERVAL:
                        check_time()
                    (directories if entry.is_dir(follow_symlinks=False) else others).append(os.fsencode(entry.name))
        finally:
            os.close(listing)
        for count, name in enumerate(others, 1):
            if check_time is not None and not count % git_store.TIME_CHECK_INTERVAL:
                check_time()
            os.unlink(name, dir_fd=fd)
        return directories

    _walk_down(top_fd, scan, lambda parent_fd, name: os.rmdir(name, dir_fd=parent_fd), check_time)


class _Snapshot:
    """A private scratch repository holding copies of the files the capture's Git commands read.

    Created with mode 0700 through a pinned parent confirmed to lie outside
    the workspace, its gitdir and its common directory (``_scratch_directory``),
    written and removed only through descriptors. Git is bound to it by path
    (``GIT_DIR``, ``GIT_WORK_TREE``), as Git takes no descriptors.

    The location checkpoint (``checkpoint``) climbs from the scratch
    descriptor through ``..`` and requires the pinned chain, with no
    protected directory on it. It runs immediately before every write,
    before and after every Git command, and before cleanup. When it fails,
    the scratch directory is abandoned: nothing more is written to it and
    nothing in it is removed, since it may now lie inside the workspace, and
    its path is reported (``problems``, ``abandoned``). Around each Git
    command the path is also confirmed to name the pinned directory, and the
    change times of everything Git takes by path are compared (``marks``):
    every entry in the scratch directory, and each directory above it that
    this user could rename, together with that directory's parent. A
    replacement made and restored while Git ran fails the capture when it
    changes one of those marks.

    These checks are best-effort detection, not confinement or atomicity. The
    scratch directory, the directories above it and the descriptors opened
    in it are trusted capture state (see the module's threat model): a
    process of the same user that can modify them can act between two
    checkpoints, can move a child directory whose descriptor the capture
    holds, can substitute the layout before the first marks are taken, and
    can change something and undo it within one timestamp tick. Whatever a
    check does observe makes the capture incomplete.
    """

    def __init__(self, protected: tuple[str, ...]) -> None:
        self.fd = self.parent_fd = self.git_fd = self.mirror_fd = -1
        self.abandoned: str | None = None
        self.abandon_reason = ""
        self.problems: list[str] = []
        self.created = 0
        self.last_change = time.time_ns()
        self.check_time: Callable[[], None] | None = None
        self.parent_fd, self.fd, self.name, self.root, self.identity, chain, self.protected = _scratch_directory(protected)
        self.expected = [self.identity, *reversed(chain)]
        self.git_dir = os.path.join(self.root, "git")
        self.tree = os.path.join(self.root, "tree")
        self.mirror = os.path.join(self.root, "mirror")

    def setup(self, check_time: Callable[[], None] | None = None) -> None:
        """Create the scratch gitdir, work tree and mirror; failures are cleaned up by ``close``."""
        self.check_time = check_time
        self.checkpoint()
        for directory in ("git", "tree", "mirror"):
            self._mkdir(directory, self.fd)
        self.git_fd = os.open("git", _DIR_FLAGS, dir_fd=self.fd)
        self.mirror_fd = os.open("mirror", _DIR_FLAGS, dir_fd=self.fd)
        for directory in ("objects", "refs", "info"):
            self._mkdir(directory, self.git_fd)
        self.write("HEAD", b"ref: refs/heads/cwo-inspection\n")

    def _mkdir(self, name: str, dir_fd: int) -> None:
        os.mkdir(name, 0o700, dir_fd=dir_fd)
        self.created += 1
        self.last_change = time.time_ns()

    def _abandon(self, reason: str) -> None:
        if self.abandoned is not None:
            return
        try:
            observed = os.readlink(f"/proc/self/fd/{self.fd}")
        except OSError:
            observed = self.root
        self.abandoned = observed
        self.abandon_reason = reason
        self.problems.append(f"{reason}; the scratch directory was abandoned, not removed: {observed} (created as {self.root})")

    def checkpoint(self) -> list[os.stat_result]:
        """The location checkpoint; a failure abandons the scratch directory and raises _ScratchRelocated."""
        if self.abandoned is not None:
            raise _ScratchRelocated(self.abandon_reason)
        try:
            return _check_location(self.fd, self.expected, self.protected)
        except _ScratchRelocated as exc:
            self._abandon(str(exc))
            raise

    def verify(self) -> None:
        """Raise _CaptureFailure unless the scratch path, as Git resolves it, is still the pinned directory."""
        try:
            info = os.stat(self.root)
        except OSError as exc:
            raise _CaptureFailure(f"the scratch directory was replaced: {exc.strerror}") from exc
        if (info.st_dev, info.st_ino) != self.identity:
            raise _CaptureFailure("the scratch directory was replaced")

    def marks(self) -> tuple[list[tuple[int, int]], bytes]:
        """Change times of everything Git takes by path, after the location checkpoint.

        Every entry below the scratch directory (and the directory itself) goes
        into one digest, as each was created by this capture and nothing else
        changes it; there may be at most as many as were created. For each
        directory above it that this user could rename, the pair of its change
        time and its parent's is kept: a rename changes both, while either
        alone also changes when an unrelated entry is created in a busy
        temporary directory.

        ``check_time`` runs before anything is scanned, as each directory is
        entered, every TIME_CHECK_INTERVAL entries while a directory is listed
        and statted and while its entries are hashed, and around the sort, so
        no directory is processed whole past the deadline.
        """
        check_time = self.check_time if self.check_time is not None else (lambda: None)
        check_time()
        chain = self.checkpoint()
        pairs = [(child.st_ctime_ns, parent.st_ctime_ns) for child, parent in zip(chain[1:], chain[2:]) if _renamable(child, parent)]
        digest = hashlib.sha256()
        remaining = [self.created]

        def scan(fd: int, depth: int) -> list[bytes]:
            check_time()
            own = os.fstat(fd)
            digest.update(b"%d . %d %d %d\n" % (depth, own.st_ino, own.st_ctime_ns, own.st_mode))
            found: list[tuple[bytes, os.stat_result]] = []
            listing = os.open(".", _DIR_FLAGS, dir_fd=fd)
            try:
                with os.scandir(listing) as entries:
                    for count, entry in enumerate(entries, 1):
                        if not count % git_store.TIME_CHECK_INTERVAL:
                            check_time()
                        remaining[0] -= 1
                        if remaining[0] < 0:
                            raise _CaptureFailure("the scratch directory was replaced or changed: it holds entries this capture did not create")
                        found.append((os.fsencode(entry.name), entry.stat(follow_symlinks=False)))
            finally:
                os.close(listing)
            check_time()
            found.sort(key=lambda item: item[0])
            check_time()
            directories: list[bytes] = []
            for count, (name, info) in enumerate(found, 1):
                if not count % git_store.TIME_CHECK_INTERVAL:
                    check_time()
                digest.update(b"%d %s %d %d %d\n" % (depth, name, info.st_ino, info.st_ctime_ns, info.st_mode))
                if stat.S_ISDIR(info.st_mode):
                    directories.append(name)
            directories.reverse()
            return directories

        _walk_down(self.fd, scan, check_time=check_time)
        check_time()
        return pairs, digest.digest()

    def before_git(self) -> tuple[list[tuple[int, int]], bytes]:
        """Checks before a Git command; returns the marks ``after_git`` compares.

        The marks are taken only once this capture's own last change to the
        scratch directory is older than CHANGE_TIME_GRAIN_NS, so the capture's
        own writes cannot share a timestamp tick with a later change. This is
        best-effort detection, not a guarantee: it ages this capture's writes,
        not the marks observed, so a change made and undone within one
        filesystem timestamp tick, or a store through an already writable
        shared mapping, can leave every mark unchanged.
        """
        self.verify()
        wait = self.last_change + CHANGE_TIME_GRAIN_NS - time.time_ns()
        if wait > 0:
            if self.check_time is not None:
                self.check_time()
            time.sleep(wait / 1e9)
        return self.marks()

    def after_git(self, before: tuple[list[tuple[int, int]], bytes]) -> None:
        """Checks after a Git command: location, path, then whether the marks of what Git takes by path changed."""
        pairs, digest = self.marks()
        self.verify()
        moved = len(pairs) != len(before[0]) or any(
            now[0] != then[0] and now[1] != then[1] for now, then in zip(pairs, before[0]))
        if digest != before[1] or moved:
            raise _CaptureFailure("the scratch directory was replaced or changed while Git ran")

    def write(self, name: str, data: bytes) -> None:
        """Write ``data`` to ``name`` (slash-separated) inside the scratch gitdir, after the location checkpoint."""
        self.checkpoint()
        *parents, leaf = [os.fsencode(part) for part in name.split("/")]
        directory, _ = _open_beneath(self.git_fd, parents, create=False)
        try:
            self._create(directory, leaf, data)
        finally:
            os.close(directory)

    def _create(self, dir_fd: int, name: bytes, data: bytes) -> None:
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=dir_fd)
        self.created += 1
        try:
            view = memoryview(data)
            while view:
                view = view[os.write(fd, view):]
        finally:
            os.close(fd)
            self.last_change = time.time_ns()

    def mirror_entry(self, path: str, *, symlink: bool, data: bytes | None = None) -> None:
        """Create ``path`` under the mirror: an empty file, a dangling symlink, or ``data``.

        The location checkpoint runs first. Parent directories are created and
        entered one at a time through descriptors, in a loop rather than by
        recursion.
        """
        self.checkpoint()
        *parents, leaf = [os.fsencode(part) for part in path.split("/")]
        directory, made = _open_beneath(self.mirror_fd, parents, create=True)
        self.created += made
        try:
            if symlink:
                os.symlink(b"cwo-placeholder", leaf, dir_fd=directory)
                self.created += 1
                self.last_change = time.time_ns()
            else:
                self._create(directory, leaf, data or b"")
        finally:
            os.close(directory)

    def close(self, deadline: float | None = None) -> None:
        """Remove the scratch directory through its descriptors, after the location checkpoint.

        A failed checkpoint, a removal that fails or one still running at
        ``deadline`` (monotonic) leaves the directory in place, never touches
        anything else, and is recorded in ``problems`` with its path.
        """
        for attribute in ("git_fd", "mirror_fd"):
            descriptor = getattr(self, attribute)
            if descriptor >= 0:
                os.close(descriptor)
                setattr(self, attribute, -1)
        if self.fd >= 0:
            try:
                if self.abandoned is None:
                    try:
                        self.checkpoint()
                    except _ScratchRelocated:
                        pass  # abandoned, with the reason recorded
                if self.abandoned is None:
                    self._remove(deadline)
            finally:
                os.close(self.fd)
                self.fd = -1
        if self.parent_fd >= 0:
            os.close(self.parent_fd)
            self.parent_fd = -1

    def _remove(self, deadline: float | None) -> None:
        def check_time() -> None:
            if deadline is not None and time.monotonic() > deadline:
                raise BudgetExhausted("deadline")

        try:
            _empty_directory(self.fd, check_time)
            own = os.fstat(self.fd)
            info = os.stat(self.name, dir_fd=self.parent_fd, follow_symlinks=False)
            # Removed by name only while that name is still this directory.
            if (info.st_dev, info.st_ino) != (own.st_dev, own.st_ino):
                self._abandon("the scratch directory's name in its parent names something else")
                return
            os.rmdir(self.name, dir_fd=self.parent_fd)
        except BudgetExhausted:
            self._abandon("scratch cleanup stopped at its deadline")
        except OSError as exc:
            self._abandon(f"scratch cleanup failed: {exc}")


# Capture --------------------------------------------------------------------


@dataclass
class CaptureScope:
    """What the caller declares: write paths and parts excluded everywhere."""

    allowed_paths: tuple[str, ...] = ()
    excluded_parts: frozenset[str] = frozenset()


# A core.fsmonitor value that is not a boolean names a hook program, which Git
# runs from the worktree with its own arguments. Which files such a program
# (an interpreter reading a worktree file named by an argument, a path through
# a symlinked directory, a program found on PATH) depends on cannot be
# established without running it, so only booleans, read as Git reads them,
# are supported, and any other value makes the capture incomplete. Git parses
# booleans here only from 2.36 (fsmonitor-settings.c); 2.35 resolves every
# non-empty value, "true" included, as a program found through PATH, which may
# name a directory inside the repository. With a trusted Git older than
# FSMONITOR_BOOLEAN_VERSION, any non-empty value therefore makes the capture
# incomplete. The value is never run: every Git command the capture runs
# disables fsmonitor (INERT_GIT_CONFIG), and the scratch repository's config
# never mentions it.
FSMONITOR_PROGRAM_REASON = "fsmonitor program configured; dependency coverage cannot be established"
FSMONITOR_VERSION_REASON = ("fsmonitor value is resolved as a program by this Git version; "
                            "dependency coverage cannot be established")
FSMONITOR_BOOLEAN_VERSION = (2, 36)
# A ".." path component, which the filesystem resolves after any symlink before it.
_PARENT_COMPONENT = re.compile(r"(?:^|/)\.\.(?:/|$)")


@dataclass
class _State:
    reasons: list[str] = field(default_factory=list)

    def incomplete(self, reason: str) -> None:
        if reason not in self.reasons:
            self.reasons.append(reason)


class _CaptureFailure(Exception):
    """The capture cannot go on. ``abandoned`` is the absolute path of a scratch directory it left behind."""

    def __init__(self, message: str = "", *, abandoned: str | None = None) -> None:
        super().__init__(message)
        self.abandoned = abandoned


class _ScratchRelocated(_CaptureFailure):
    """The scratch directory is not where it was pinned; it is abandoned, never written to or removed."""


_ATTRIBUTE_TOKEN = re.compile(r"[^ \t\r\n]+")


def _records(data: bytes, separator: bytes) -> Any:
    """``(start, end)`` of each non-empty record of ``data``, found one at a time.

    Nothing is sliced or split in advance, so the caller can charge each
    record before building anything of it.
    """
    position = 0
    while position < len(data):
        end = data.find(separator, position)
        if end == -1:
            end = len(data)
        if end > position:
            yield position, end
        position = end + len(separator)


def _conversion_attributes(text: str, check_time: Any = None) -> list[str]:
    """Attribute names in a gitattributes file that can change stored or checked-out bytes.

    Lines end at a newline and tokens are separated by space, tab and carriage
    return only, as Git splits them; other Unicode spaces and line breaks
    belong to the token they appear in. Lines and tokens are found one at a
    time rather than split in advance, and ``check_time`` runs as they are:
    every line counts as a step, comments and blank lines included, and the
    deadline is checked once more before the answer is returned.
    """
    found: set[str] = set()
    position = 0
    steps = 0
    while position < len(text):
        # Counted before anything decides to skip the line.
        steps += 1
        if check_time is not None and not steps % git_store.TIME_CHECK_INTERVAL:
            check_time()
        end = text.find("\n", position)
        if end == -1:
            end = len(text)
        tokens = _ATTRIBUTE_TOKEN.finditer(text, position, end)
        position = end + 1
        first = next(tokens, None)
        if first is None or first.group().startswith("#"):
            continue
        for token in tokens:
            steps += 1
            if check_time is not None and not steps % git_store.TIME_CHECK_INTERVAL:
                check_time()
            name = token.group().lstrip("-!").split("=", 1)[0]
            if name in CONVERSION_ATTRIBUTES:
                found.add(name)
    if check_time is not None:
        check_time()
    return sorted(found)


class WorktreeCapture:
    def __init__(self, root: Path | str, *, budget: Budget, scope: CaptureScope) -> None:
        self.root = Path(root)
        self.budget = budget
        # Git metadata has its own fixed byte and entry budget, so a small
        # content budget is not spent on sample hooks; the deadline is shared.
        self.meta_budget = Budget(max_files=0, max_bytes=METADATA_BYTES, max_entries=METADATA_ENTRIES, deadline=budget.deadline)
        # Git's own output has a fixed budget too, charged as it streams.
        self.git_budget = Budget(max_files=0, max_bytes=GIT_OUTPUT_CAP, max_entries=0, deadline=budget.deadline)
        self.scope = scope
        self.state = _State()

    # Git queries ----------------------------------------------------------

    def _run(self, args: list[str], *, work_tree: str | None = None) -> GitResult:
        self.budget.check_time()
        tree = work_tree or self.snapshot.tree
        # Git is bound to the private snapshot: it never opens the workspace or its repository. It
        # takes the snapshot by path, so the location checkpoint, the path check and the change
        # marks run before and after it (best-effort detection; see _Snapshot).
        before = self.snapshot.before_git()
        # The marks may have taken a while: the deadline is checked again before Git starts.
        self.budget.check_time()
        result = run_git(self.git, tree, args, budget=self.git_budget, git_dir=self.snapshot.git_dir, work_tree=tree)
        self.snapshot.after_git(before)
        return result

    def _git(self, args: list[str], *, work_tree: str | None = None) -> bytes:
        result = self._run(args, work_tree=work_tree)
        if result.returncode != 0:
            raise _CaptureFailure(f"git {args[0]} failed: {_decode(result.stderr).strip()[:200]}")
        return result.stdout

    def _dirs(self) -> tuple[str, str, str]:
        """Re-resolve live indirection before use and at the final identity check."""
        git_dir, common_dir = self._resolve_dirs()
        return git_dir, common_dir, str(self.root)

    def _index(self) -> list[list[Any]]:
        index = self._regular_or_absent(os.path.join(self.dirs[0], "index"), cap=INDEX_FILE_CAP, budget=self.git_budget)
        if index is not None:
            self.snapshot.write("index", index)
        # Git decides from these patterns whether a sparse index stays sparse.
        patterns = self._regular_or_absent(os.path.join(self.dirs[0], "info", "sparse-checkout"))
        if patterns is not None:
            self.snapshot.write(os.path.join("info", "sparse-checkout"), patterns)
        self.snapshot.write("config", self._snapshot_config().encode("utf-8"))
        entries: list[list[Any]] = []
        output = self._git(["ls-files", "--stage", "-v", "--sparse", "--full-name", "-z"])
        for start, end in _records(output, b"\0"):
            # Charged before the record is sliced or decoded.
            self.budget.take_entry()
            meta, separator, raw_path = output[start:end].partition(b"\t")
            fields = meta.decode("ascii", errors="replace").split(" ")
            if not separator or not raw_path or len(fields) != 4 or fields[3] not in {"0", "1", "2", "3"}:
                raise _CaptureFailure("unparseable index record")
            tag, mode, object_id, stage = fields
            entries.append([mode, object_id, int(stage), _decode(raw_path), tag])
        return entries

    def _head(self) -> tuple[str, dict[str, tuple[str, str]]]:
        """HEAD's tree manifest, read without Git; "unborn" only when HEAD names a branch that does not exist yet."""
        git_dir, common_dir, _ = self.dirs
        try:
            reference, oid = git_store.resolve_head(self._read_repository_file, git_dir, common_dir, self.store.hash_length,
                                                    charge_entry=self.meta_budget.take_entry,
                                                    check_time=self.budget.check_time)
            if oid is None:
                return "unborn", {}
            self.head_commit = oid
            tree = self.store.peel_to_tree(oid)
            # Each expanded path is charged to the metadata byte budget before it is built.
            return tree, self.store.tree_manifest(tree, self.budget.take_entry, self.meta_budget.take_bytes)
        except git_store.MissingObject as exc:
            raise _CaptureFailure(f"HEAD names an object that is not present (nothing is fetched): {exc}") from exc
        except git_store.StoreError as exc:
            raise _CaptureFailure(f"HEAD cannot be read: {exc}") from exc

    def _read_repository_file(self, path: str) -> bytes | None:
        return self._regular_or_absent(path)

    def _list_names(self, path: str) -> list[str]:
        fd = os.open(path, _ROOT_FLAGS)
        try:
            names = []
            with os.scandir(fd) as entries:
                for entry in entries:
                    self.meta_budget.take_entry()
                    names.append(entry.name)
            return names
        finally:
            os.close(fd)

    def _check_unwalked_attributes(self) -> None:
        """Excluded directories are not inventoried, but a .gitattributes inside one still governs
        tracked files below it, so each is read for conversion attributes; one that cannot be read
        leaves cleanliness unknown. (Git no longer reads anything in the worktree, so their
        .gitignore files need no check.)"""
        # (directory, its label, the label's character width)
        stack: list[tuple[int, str, int]] = []
        # Root acquisition and traversal share one cleanup scope: a failure opening a later root
        # still closes every root already opened.
        try:
            for path in self.unwalked:
                parts = path_components(path)
                current = os.dup(self.root_fd)
                try:
                    for name in parts or ():
                        try:
                            following = os.open(name, _DIR_FLAGS, dir_fd=current)
                        except (NotADirectoryError, FileNotFoundError):
                            break
                        except OSError as exc:
                            if exc.errno == errno.ELOOP:
                                break  # a symlink is not traversed by Git either
                            raise _CaptureFailure(f"unreadable directory {path}: {exc.strerror}") from exc
                        os.close(current)
                        current = following
                    else:
                        stack.append((current, path, git_store.character_width(path)))
                        current = -1
                finally:
                    if current >= 0:
                        os.close(current)
            while stack:
                fd, label, label_width = stack.pop()
                try:
                    with os.scandir(fd) as entries:
                        for entry in entries:
                            self.budget.take_entry()
                            info = os.stat(entry.name, dir_fd=fd, follow_symlinks=False)
                            if entry.name == ".gitattributes":
                                self._charge_path(len(label) + len("/.gitattributes"), label_width)
                                self._read_unwalked_attributes(fd, f"{label}/.gitattributes", info)
                            if stat.S_ISDIR(info.st_mode):
                                # Each label below an excluded directory is charged before it is built.
                                width = max(label_width, git_store.character_width(entry.name))
                                self._charge_path(len(label) + 1 + len(entry.name), width)
                                stack.append((os.open(entry.name, _DIR_FLAGS, dir_fd=fd), f"{label}/{entry.name}", width))
                finally:
                    os.close(fd)
        finally:
            for fd, _, _ in stack:
                os.close(fd)

    def _read_unwalked_attributes(self, dir_fd: int, path: str, info: os.stat_result) -> None:
        if not stat.S_ISREG(info.st_mode):
            self.conversion_sources.add(f"{path} (not a regular file)")
            return
        try:
            data = _read_pinned(dir_fd, ".gitattributes", info, min(METADATA_FILE_CAP, self.meta_budget.remaining_bytes()),
                                deadline=self.budget.deadline)
        except (OSError, BudgetExhausted) as exc:
            self.conversion_sources.add(f"{path} (unreadable: {exc})")
            return
        self.meta_budget.take_bytes(len(data))
        self.attribute_texts[path] = data.decode("utf-8", errors="replace")

    def _ignored(self) -> tuple[set[str], tuple[str, ...]]:
        """Which untracked names Git ignores, asked of a mirror rather than the worktree.

        The mirror holds an empty placeholder for every untracked file or
        symlink the walk found, the directories leading to them, and copies of
        the ``.gitignore`` files read during the walk; the scratch gitdir holds
        the index and ``info/exclude``. Git's own matching then runs on files
        this capture wrote.
        """
        exclude = self._regular_or_absent(os.path.join(self.dirs[1], "info", "exclude"))
        if exclude is not None:
            self.snapshot.write(os.path.join("info", "exclude"), exclude)
        tracked = self.index_paths | self.unmerged_paths
        directories: set[str] = {""}
        for count, (path, value) in enumerate(self.inventory.items()):
            if not count % git_store.TIME_CHECK_INTERVAL:
                self.budget.check_time()
            if path in tracked or not value.startswith(("file:", "symlink:")):
                continue
            # Each entry is I/O in the scratch directory, so each checks the deadline.
            self.budget.check_time()
            self.snapshot.mirror_entry(path, symlink=value.startswith("symlink:"))
            # Each directory above the entry is built once, charged first, climbing only until a
            # directory already known (rather than every prefix of every path).
            width = git_store.character_width(path)
            cut = path.rfind("/")
            while cut > 0:
                self._charge_path(cut, width)
                parent = path[:cut]
                if parent in directories:
                    break
                directories.add(parent)
                cut = path.rfind("/", 0, cut)
        for path, data in self.ignore_texts.items():
            self.budget.check_time()
            cut = max(path.rfind("/"), 0)
            self._charge_path(cut, git_store.character_width(path))
            if path[:cut] in directories:
                self.snapshot.mirror_entry(path, symlink=False, data=data)
        files: set[str] = set()
        directories_ignored: list[str] = []
        output = self._git(["ls-files", "-z", "--others", "--ignored", "--exclude-standard", "--directory", "--full-name"],
                           work_tree=self.snapshot.mirror)
        for count, (start, end) in enumerate(_records(output, b"\0")):
            # Git answers only for names this capture mirrored, each charged when it was walked.
            if not count % git_store.TIME_CHECK_INTERVAL:
                self.budget.check_time()
            path = _decode(output[start:end])
            if path.endswith("/"):
                directories_ignored.append(path)
            else:
                files.add(path)
        return files, tuple(sorted(directories_ignored))

    def _object_format(self) -> str:
        return self.store.hash_name

    # Preflight --------------------------------------------------------------

    def _regular_or_absent(self, path: str, *, required: bool = False, cap: int = METADATA_FILE_CAP,
                           budget: Budget | None = None) -> bytes | None:
        """Read ``path`` (following symlinks, as Git does) only if it is a regular file."""
        budget = budget or self.meta_budget
        self.meta_budget.take_entry()
        parent, name = os.path.split(path)
        try:
            parent_fd = os.open(parent or "/", _ROOT_FLAGS)
        except FileNotFoundError:
            if required:
                raise _CaptureFailure(f"repository file is missing: {path}") from None
            return None
        try:
            try:
                info = os.stat(name, dir_fd=parent_fd)
            except FileNotFoundError:
                if required:
                    raise _CaptureFailure(f"repository file is missing: {path}") from None
                return None
            if not stat.S_ISREG(info.st_mode):
                raise _CaptureFailure(f"repository file is not a regular file: {path}")
            data = _read_pinned(parent_fd, name, info, min(cap, budget.remaining_bytes()),
                                follow=True, deadline=self.budget.deadline)
            budget.take_bytes(len(data))
            return data
        finally:
            os.close(parent_fd)

    def _check_tree(self, directory: str) -> None:
        """Every entry under ``directory`` must be a directory or a regular file."""
        try:
            base = os.open(directory, _ROOT_FLAGS)
        except FileNotFoundError:
            return
        except OSError as exc:
            raise _CaptureFailure(f"repository directory unreadable: {directory}: {exc.strerror}") from exc
        # (directory, its label, the label's character width)
        stack = [(base, directory, git_store.character_width(directory))]
        try:
            while stack:
                fd, label, label_width = stack.pop()
                try:
                    with os.scandir(fd) as entries:
                        for entry in entries:
                            # Charged as each entry is read, so a huge
                            # directory exhausts the budget instead of memory.
                            self.meta_budget.take_entry()
                            self.budget.check_time()
                            info = os.stat(entry.name, dir_fd=fd, follow_symlinks=False)
                            if stat.S_ISDIR(info.st_mode):
                                # The label holds the whole path; it is charged before it is built.
                                width = max(label_width, git_store.character_width(entry.name))
                                self._charge_path(len(label) + 1 + len(entry.name), width)
                                stack.append((os.open(entry.name, _DIR_FLAGS, dir_fd=fd), f"{label}/{entry.name}", width))
                            elif not stat.S_ISREG(info.st_mode):
                                raise _CaptureFailure(f"repository entry is not a regular file: {label}/{entry.name}")
                finally:
                    os.close(fd)
        finally:
            for fd, _, _ in stack:
                os.close(fd)

    def _config_qualified(self, path: str) -> None:
        """Check a repository config file and refuse settings that name more files for Git to open.

        Includes, ``core.excludesFile``, ``core.attributesFile`` and split
        indexes would make Git read files outside the checked set, interpreted
        by Git's own config syntax (quoting, escapes, continuations, ``~``
        expansion). Rather than reimplement that syntax, any mention of them
        anywhere in the raw bytes, comments included, makes the repository
        unsupported for inert capture.
        """
        data = self._regular_or_absent(path)
        if data is None:
            return
        if _UNSUPPORTED_CONFIG.search(data):
            raise _CaptureFailure(f"unsupported repository configuration (includes, excludes or attributes files, split index): {path}")
        try:
            # Each entry is charged before it is built, its name's size before the name, and the
            # deadline is checked as values are read.
            self.config_entries[path] = git_store.parse_config(data, charge_entry=self.meta_budget.take_entry,
                                                               check_time=self.meta_budget.check_time,
                                                               charge_bytes=self.meta_budget.take_bytes)
        except git_store.UnsupportedLayout as exc:
            raise _CaptureFailure(f"unsupported repository configuration syntax in {path}: {exc}") from exc

    def _direct_entries(self, directory: str) -> list[str]:
        """Names directly in ``directory``; each must be a regular file or a directory."""
        names: list[str] = []
        try:
            fd = os.open(directory, _ROOT_FLAGS)
        except OSError as exc:
            raise _CaptureFailure(f"repository directory unreadable: {directory}: {exc.strerror}") from exc
        try:
            with os.scandir(fd) as entries:
                for entry in entries:
                    self.meta_budget.take_entry()
                    self.budget.check_time()
                    info = os.stat(entry.name, dir_fd=fd, follow_symlinks=False)
                    if stat.S_ISLNK(info.st_mode):
                        # Git follows these; what it would reach must be safe to open.
                        try:
                            info = os.stat(entry.name, dir_fd=fd)
                        except FileNotFoundError:
                            names.append(entry.name)
                            continue
                    if not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)):
                        raise _CaptureFailure(f"repository entry is not a regular file or directory: {directory}/{entry.name}")
                    names.append(entry.name)
        finally:
            os.close(fd)
        return names

    @staticmethod
    def _indirection(data: bytes, prefix: bytes, what: str) -> str:
        """The path in a gitdir/commondir file, read as Git reads it: only trailing CR and LF are removed."""
        if not data.startswith(prefix):
            raise _CaptureFailure(f"the {what} file has an unsupported format")
        value = data[len(prefix):].rstrip(b"\r\n")
        if not value or b"\0" in value or b"\n" in value or b"\r" in value:
            raise _CaptureFailure(f"the {what} file names an unsupported path")
        return os.fsdecode(value)

    def _check_settings(self, common_config: str, worktree_config: str) -> None:
        """Merge the settings Git would use and refuse layouts this capture does not read correctly.

        Git checks each occurrence of these settings as it reads the files, and
        a later valid occurrence does not excuse an earlier invalid one, so every
        occurrence is checked in file order before the last one is taken.
        """
        common_entries = self.config_entries.get(common_config, [])
        for key, value in common_entries:
            self._check_occurrence(key, value, repository_format=True)
        common = dict(common_entries)
        # Absent means version 0; each occurrence is a number Git accepts, and the last must be 0 or 1.
        version = common.get("core.repositoryformatversion", "0")
        if version not in {"0", "1"}:
            raise _CaptureFailure(f"unsupported repository format version {version}")
        extensions = {name.split(".", 1)[1] for name in common if name.startswith("extensions.")}
        unsupported = extensions - (SUPPORTED_EXTENSIONS if version == "1" else V0_EXTENSIONS)
        if unsupported:
            raise _CaptureFailure("unsupported repository extension: " + ", ".join(sorted(unsupported)))
        object_format = common.get("extensions.objectformat", "sha1") if version == "1" else "sha1"
        if version == "1" and common.get("extensions.refstorage", "files") != "files":
            raise _CaptureFailure(f"reference storage {common['extensions.refstorage']} is not supported for inert capture")
        entries = list(common_entries)
        # An absent extension is off; only a present, true one makes Git read config.worktree.
        if "extensions.worktreeconfig" in common and git_store.config_bool(common["extensions.worktreeconfig"]):
            for key, value in self.config_entries.get(worktree_config, []):
                self._check_occurrence(key, value, repository_format=False)
                entries.append((key, value))
        else:
            self.config_entries.pop(worktree_config, None)  # Git ignores it without the extension
        settings = dict(entries)
        if "core.worktree" in settings:
            raise _CaptureFailure("core.worktree is not supported for inert capture")
        self.booleans = {key: git_store.config_bool(settings[key]) for key in BOOLEAN_SETTINGS if key in settings}
        if self.booleans.get("core.bare"):
            raise _CaptureFailure("a bare repository has no worktree to capture")
        self.object_format_name = object_format

    def _check_occurrence(self, key: str, value: str | None, *, repository_format: bool) -> None:
        """Refuse one occurrence of a setting that Git refuses as it reads it.

        The repository-format settings come only from the common config, as
        Git reads them from there alone. Git reads ``index.sparse`` only at its
        last occurrence, so checking each one is stricter than Git.
        """
        if key in BOOLEAN_SETTINGS or (repository_format and key in BOOLEAN_EXTENSIONS):
            self._boolean(key, value)
        if not repository_format:
            return
        if key == "core.repositoryformatversion" and git_store.config_int(value) is None:
            raise _CaptureFailure("core.repositoryformatversion is not a number Git accepts")
        if key in ("extensions.objectformat", "extensions.refstorage", "extensions.partialclone") and value is None:
            raise _CaptureFailure(f"{key} has no value")
        # Git matches these names exactly, case included.
        if key == "extensions.objectformat" and value not in {"sha1", "sha256"}:
            raise _CaptureFailure(f"unsupported object format {value}")
        if key == "extensions.refstorage" and value not in {"files", "reftable"}:
            raise _CaptureFailure(f"unknown reference storage {value}")

    @staticmethod
    def _boolean(key: str, value: str | None) -> bool:
        """A setting Git reads as a boolean; a value Git would refuse makes the repository unsupported."""
        try:
            return git_store.config_bool(value)
        except git_store.UnsupportedLayout as exc:
            raise _CaptureFailure(f"{key} has a value Git does not accept as a boolean") from exc

    def _snapshot_config(self) -> str:
        """The scratch repository's config: only the settings that change how Git reads the copied files."""
        lines = ["[core]", "\trepositoryformatversion = " + ("1" if self.object_format_name == "sha256" else "0"), "\tbare = false"]
        for key in ("core.ignorecase", "core.sparsecheckout", "core.sparsecheckoutcone"):
            if key in self.booleans:
                lines.append(f"\t{key.split('.', 1)[1]} = {str(self.booleans[key]).lower()}")
        if "index.sparse" in self.booleans:
            lines.extend(["[index]", f"\tsparse = {str(self.booleans['index.sparse']).lower()}"])
        if self.object_format_name == "sha256":
            lines.extend(["[extensions]", "\tobjectformat = sha256"])
        return "\n".join(lines) + "\n"

    def _resolve_dirs(self) -> tuple[str, str]:
        """Resolve current .git/commondir through bounded, type-checked reads."""
        dot_git = str(self.root / ".git")
        try:
            info = os.lstat(dot_git)
        except FileNotFoundError:
            raise _CaptureFailure("workspace root has no .git entry") from None
        if stat.S_ISDIR(info.st_mode):
            git_dir = os.path.realpath(dot_git)
        elif stat.S_ISREG(info.st_mode):
            target = self._indirection(self._regular_or_absent(dot_git, required=True) or b"", b"gitdir: ", ".git")
            git_dir = os.path.realpath(os.path.join(str(self.root), target))
        else:
            raise _CaptureFailure("the .git entry is neither a directory nor a gitdir file")
        if not os.path.isdir(git_dir):
            raise _CaptureFailure("the gitdir is not a directory")
        commondir = self._regular_or_absent(os.path.join(git_dir, "commondir"))
        common_dir = os.path.realpath(os.path.join(git_dir, self._indirection(commondir, b"", "commondir"))) if commondir is not None else git_dir
        if not os.path.isdir(common_dir):
            raise _CaptureFailure("the common git directory is not a directory")
        return git_dir, common_dir

    def _preflight(self) -> None:
        """Check, without Git, the repository files the inspection commands will read.

        Git opens configuration, the index, HEAD and the reference it names,
        packed and loose refs, info files and objects while running rev-parse,
        ls-files, ls-tree and show-ref. A FIFO, socket or device in any of
        those places could block Git or wake another process, so each must be
        a regular file (or a directory where one is expected) before the first
        Git command runs. Indirection is read as Git reads it, and the gitdir
        and common directory chosen here are re-resolved before capture and
        at its final identity check. Layouts that would make Git open more than this set (config
        includes, excludes or attributes files, split indexes, chained
        symbolic references, alternate object stores) are refused as
        unsupported. This is a check before Git runs, not confinement: a file
        replaced after it is still possible, and the capture deadline bounds
        what Git can then wait on.
        """
        git_dir, common_dir = self._resolve_dirs()
        self.preflight_dirs = (git_dir, common_dir)
        for directory in {git_dir, common_dir}:
            if any(name.startswith("sharedindex.") for name in self._direct_entries(directory)):
                raise _CaptureFailure("split indexes are not supported for inert capture")
        reference = git_store.symbolic_target(self._regular_or_absent(os.path.join(git_dir, "HEAD"), required=True) or b"")
        if reference is not None:
            if not git_store.valid_reference_name(reference):
                raise _CaptureFailure("HEAD names an invalid reference")
            for base in {git_dir, common_dir}:
                loose = self._regular_or_absent(os.path.join(base, reference))
                if loose is not None and git_store.symbolic_target(loose) is not None:
                    raise _CaptureFailure("chained symbolic references are not supported for inert capture")
        for path in (
            os.path.join(git_dir, "index"),
            os.path.join(git_dir, "gitdir"),
            os.path.join(common_dir, "packed-refs"),
            os.path.join(common_dir, "shallow"),
        ):
            self._regular_or_absent(path)
        for tree in {os.path.join(git_dir, "refs"), os.path.join(common_dir, "refs"), os.path.join(common_dir, "reftable"),
                     os.path.join(common_dir, "info"), os.path.join(git_dir, "info")}:
            self._check_tree(tree)
        self.config_entries: dict[str, list[tuple[str, str | None]]] = {}
        for config in (os.path.join(common_dir, "config"), os.path.join(git_dir, "config.worktree")):
            self._config_qualified(config)
        self._check_settings(os.path.join(common_dir, "config"), os.path.join(git_dir, "config.worktree"))
        objects = os.path.join(common_dir, "objects")
        for name in ("alternates", "http-alternates"):
            try:
                os.lstat(os.path.join(objects, "info", name))
            except FileNotFoundError:
                continue
            raise _CaptureFailure("alternate object stores are not supported for inert capture")
        self._check_tree(objects)

    # Worktree walk --------------------------------------------------------

    def _excluded(self, parts: tuple[str, ...]) -> bool:
        return any(part in self.scope.excluded_parts for part in parts)

    def _check_declared_paths(self) -> None:
        """A declared write path that overlaps content the capture cannot observe is incomplete.

        Gitlink contents are opaque, so a declared path equal to, inside or
        containing a gitlink is unobservable, as is anything under ``.git``.
        Excluded names (caches, CWO state) are observed when they lie on or
        under a declared path, so they need no refusal.
        """
        tick = self._ticker()
        for raw in self.scope.allowed_paths:
            self.budget.check_time()
            parts = path_components(raw)
            if parts is None:
                continue
            declared = "/".join(parts)
            if parts[0] == ".git":
                self.state.incomplete(f"declared path lies inside .git: {raw}")
            for gitlink in self.gitlinks:
                # Gitlinks are index entries: each comparison counts against the deadline.
                tick()
                if path_within(declared, [gitlink]) or path_within(gitlink, [declared]):
                    self.state.incomplete(f"declared path overlaps an opaque gitlink: {raw}")

    def _observed(self, path: str) -> bool:
        """Excluded names are skipped only off the declared paths."""
        return any(path_within(path, [allowed]) or path_within(str(allowed), [path]) for allowed in self.scope.allowed_paths)

    def _record(self, dir_fd: int, name: str, path: str, info: os.stat_result) -> None:
        mode = stat.S_IMODE(info.st_mode)
        kind = entry_kind(info)
        if kind == "symlink":
            target = os.fsencode(os.readlink(name, dir_fd=dir_fd))
            self.budget.take_bytes(len(target))
            self.inventory[path] = f"symlink:{mode:o}:{len(target)}:{hashlib.sha256(target).hexdigest()}"
            self.link_targets[path] = _decode(target)
            self.raw_blobs[path] = _blob_id(self.object_format, target)
            if path in self.index_paths:
                self.blobs[path] = ("symlink", self.raw_blobs[path])
        elif kind == "file":
            self.budget.take_file()
            data = _read_pinned(dir_fd, name, info, self.budget.remaining_bytes(), deadline=self.budget.deadline)
            self.budget.take_bytes(len(data))
            self.inventory[path] = f"file:{mode:o}:{len(data)}:{hashlib.sha256(data).hexdigest()}"
            self.raw_blobs[path] = _blob_id(self.object_format, data)
            if path in self.index_paths:
                self.blobs[path] = ("executable" if info.st_mode & stat.S_IXUSR else "file", self.raw_blobs[path])
            if name == ".gitattributes":
                self.attribute_texts[path] = data.decode("utf-8", errors="replace")
            elif name == ".gitignore":
                self.ignore_texts[path] = data  # copied into the mirror Git classifies
        else:
            self.inventory[path] = f"{kind}:{mode:o}:0:-"
            if path in self.index_paths:
                self.blobs[path] = (kind, None)

    def _charge_path(self, length: int, width: int) -> None:
        """Charge the metadata byte budget for a path of ``length`` characters of ``width`` bytes, before it is built.

        Every expanded path holds its whole directory prefix, so a deep tree of
        long names expands far beyond its entry count. Paths built from
        untrusted names (worktree paths and directory prefixes, metadata keys,
        excluded and mirrored directories, untracked status lines) are charged
        here, at the size Python stores them in, as HEAD's tree paths are.
        """
        self.meta_budget.take_bytes(length * width)

    def _walk(self) -> None:
        # (directory, its prefix, the prefix's character width)
        stack: list[tuple[int, str, int]] = [(os.dup(self.root_fd), "", 1)]
        try:
            while stack:
                dir_fd, prefix, prefix_width = stack.pop()
                try:
                    names: list[str] = []
                    try:
                        with os.scandir(dir_fd) as entries:
                            for entry in entries:
                                self.budget.take_entry()
                                names.append(entry.name)
                    except OSError as exc:
                        self.state.incomplete(f"unreadable directory {prefix or '.'}: {exc.strerror}")
                        continue
                    for name in sorted(names):
                        # Every name, whichever branch takes it, counts against the deadline.
                        self.budget.check_time()
                        if not prefix and name == ".git":
                            continue
                        width = max(prefix_width, git_store.character_width(name))
                        length = len(prefix) + len(name)
                        self._charge_path(length, width)
                        path = prefix + name
                        if name in self.scope.excluded_parts and not self._observed(path):
                            self.unwalked.append(path)
                            continue
                        try:
                            info = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
                        except FileNotFoundError:
                            self.state.incomplete(f"entry vanished during capture: {path}")
                            continue
                        if stat.S_ISDIR(info.st_mode):
                            mode = stat.S_IMODE(info.st_mode)
                            if path in self.gitlinks:
                                self.inventory[path] = f"gitlink:{mode:o}:0:-"  # submodule contents are opaque
                                continue
                            self.inventory[path] = f"directory:{mode:o}:0:-"
                            # The prefix its entries are built from, charged before it is built or opened.
                            self._charge_path(length + 1, width)
                            try:
                                child = os.open(name, _DIR_FLAGS, dir_fd=dir_fd)
                            except OSError as exc:
                                self.state.incomplete(f"unreadable directory {path}: {exc.strerror}")
                                continue
                            try:
                                opened = os.fstat(child)
                            except BaseException:
                                os.close(child)
                                raise
                            if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
                                os.close(child)
                                self.state.incomplete(f"directory replaced during capture: {path}")
                                continue
                            stack.append((child, path + "/", width))
                            continue
                        try:
                            self._record(dir_fd, name, path, info)
                        except PathReplacedError:
                            self.state.incomplete(f"file replaced during capture: {path}")
                        except FileNotFoundError:
                            self.state.incomplete(f"entry vanished during capture: {path}")
                        except PermissionError as exc:
                            self.state.incomplete(f"unreadable entry {path}: {exc.strerror}")
                finally:
                    os.close(dir_fd)
        finally:
            for dir_fd, _, _ in stack:
                os.close(dir_fd)

    def _read_excluded_tracked(self) -> None:
        """Tracked files under excluded directories are read only for status."""
        for count, path in enumerate(sorted(self.index_paths)):
            if not count % git_store.TIME_CHECK_INTERVAL:
                self.budget.check_time()
            parts = path_components(path)
            if parts is None or not self._excluded(parts[:-1]) or path in self.inventory:
                continue
            self.budget.take_entry()
            kind, data, info = read_beneath(self.root_fd, path, self.budget.remaining_bytes(), deadline=self.budget.deadline)
            if data is not None:
                self.budget.take_bytes(len(data))
            if kind == "file":
                self.budget.take_file()
            if kind == "file" and data is not None and info is not None:
                self.blobs[path] = ("executable" if info.st_mode & stat.S_IXUSR else "file", _blob_id(self.object_format, data))
            elif kind == "symlink" and data is not None:
                self.blobs[path] = ("symlink", _blob_id(self.object_format, data))
            elif kind != "absent":
                self.blobs[path] = (kind, None)

    # Status ---------------------------------------------------------------

    def _ticker(self) -> Callable[[], None]:
        """A step counter that checks the deadline every TIME_CHECK_INTERVAL calls."""
        steps = [0]

        def tick() -> None:
            steps[0] += 1
            if not steps[0] % git_store.TIME_CHECK_INTERVAL:
                self.budget.check_time()
        return tick

    def _status(self, entries: list[list[Any]], head: dict[str, tuple[str, str]]) -> list[str]:
        lines: list[str] = []
        stage0: dict[str, list[Any]] = {}
        unmerged: set[str] = set()
        tick = self._ticker()
        for entry in entries:
            tick()
            if entry[2] == 0:
                stage0[entry[3]] = entry
            else:
                unmerged.add(entry[3])
        for path in sorted(unmerged):
            tick()
            lines.append(f"UU {path}")
        for path in sorted(set(stage0) | (set(head) - unmerged)):
            tick()
            if path in unmerged:
                continue
            entry = stage0.get(path)
            head_entry = head.get(path)
            if entry is None:
                lines.append(f"D  {path}")
                continue
            mode, object_id, _, _, tag = entry
            expected = INDEX_MODES.get(mode, "unknown")
            if expected == "sparse-directory":
                continue
            if head_entry is None:
                x = "A"
            elif head_entry == (mode, object_id):
                x = " "
            elif INDEX_MODES.get(head_entry[0]) != expected and {INDEX_MODES.get(head_entry[0]), expected} != {"file", "executable"}:
                x = "T"
            else:
                x = "M"
            y = " "
            if expected != "gitlink":
                observed = self.blobs.get(path)
                if observed is None:
                    y = " " if tag == "S" else "D"
                else:
                    kind, blob = observed
                    if {expected, kind} <= {"file", "executable"}:
                        y = "M" if kind != expected or blob != object_id else " "
                    elif kind != expected:
                        y = "T"
                    elif blob != object_id:
                        y = "M"
            if x != " " or y != " ":
                lines.append(f"{x}{y} {path}")
        # Ignored directories without the ones inside another: a name lies under one of these only if
        # it lies under the last one not after it, so each name costs one search, not a scan of all.
        outermost: list[str] = []
        for directory in sorted(self.ignored_dirs):
            tick()
            if not outermost or not directory.startswith(outermost[-1]):
                outermost.append(directory)
        for path, value in sorted(self.inventory.items()):
            tick()
            if path in stage0 or path in unmerged or path in self.ignored_files:
                continue
            if not value.startswith(("file:", "symlink:")):
                continue  # like Git, untracked status names files and symlinks only
            position = bisect.bisect_right(outermost, path)
            if position and path.startswith(outermost[position - 1]):
                continue
            self._charge_path(3 + len(path), git_store.character_width(path))
            lines.append(f"?? {path}")
        return lines

    # Metadata -------------------------------------------------------------

    def _snapshot_entry(self, dir_fd: int, name: str, key: str, *, tree: bool) -> None:
        """Digest one metadata entry and, for a tree, every entry below it.

        A symlinked file or directory is followed once and bound. Directories
        are walked from an explicit stack, never by recursion, so depth is
        bounded only by the metadata budget. A directory that is already being
        walked above itself (reached again through a symlink or a bind mount)
        is a cycle: it is recorded as one, not entered, and the capture is
        incomplete.
        """
        pending = self._digest(dir_fd, name, key, tree=tree)
        if pending is None:
            return
        stack: list[tuple[Any, ...]] = [pending]
        walking: set[tuple[int, int]] = set()
        try:
            while stack:
                task = stack.pop()
                if task[0] == "leave":
                    _, fd, identity = task
                    walking.discard(identity)
                    os.close(fd)
                    continue
                _, parent_fd, child, child_key, identity, follow, record = task
                if identity in walking:
                    record["cycle"] = True
                    self.state.incomplete(f"metadata directory cycle at {child_key}")
                    continue
                try:
                    fd = os.open(child, _ROOT_FLAGS if follow else _DIR_FLAGS, dir_fd=parent_fd)
                except OSError as exc:
                    self.state.incomplete(f"unreadable metadata directory {child_key}: {exc.strerror}")
                    continue
                try:
                    opened = os.fstat(fd)
                except BaseException:
                    os.close(fd)
                    raise
                if (opened.st_dev, opened.st_ino) != identity:
                    os.close(fd)
                    self.state.incomplete(f"metadata directory replaced during capture: {child_key}")
                    continue
                walking.add(identity)
                stack.append(("leave", fd, identity))
                names: list[str] = []
                try:
                    with os.scandir(fd) as entries:
                        for entry in entries:
                            self.meta_budget.take_entry()
                            names.append(entry.name)
                except OSError as exc:
                    self.state.incomplete(f"unreadable metadata directory {child_key}: {exc.strerror}")
                    continue
                # Each key holds the whole path below the entry; it is charged before it is built.
                key_width = git_store.character_width(child_key)
                walks = []
                for entry_name in sorted(names):
                    self._charge_path(len(child_key) + 1 + len(entry_name),
                                      max(key_width, git_store.character_width(entry_name)))
                    walks.append(self._digest(fd, entry_name, f"{child_key}/{entry_name}", tree=True))
                stack.extend(walk for walk in reversed(walks) if walk is not None)
        finally:
            for task in stack:
                if task[0] == "leave":
                    os.close(task[1])

    def _digest(self, dir_fd: int, name: str, key: str, *, tree: bool) -> tuple[Any, ...] | None:
        """Record one metadata entry; return the task that walks it when it is a directory to walk."""
        self.meta_budget.take_entry()
        try:
            kind, data, info = read_at(dir_fd, name, min(METADATA_FILE_CAP, self.meta_budget.remaining_bytes()),
                                       deadline=self.budget.deadline)
        except (OSError, ValueError) as exc:
            self.metadata[key] = {"kind": "unreadable"}
            self.state.incomplete(f"unreadable metadata {key}: {exc}")
            return None
        if data is not None:
            self.meta_budget.take_bytes(len(data))
        record: dict[str, Any] = {"kind": kind}
        if info is not None:
            record["mode"] = stat.S_IMODE(info.st_mode)
        walk = None
        if kind == "file":
            record["sha256"] = hashlib.sha256(data or b"").hexdigest()
        elif kind == "symlink":
            record["sha256"] = hashlib.sha256(data or b"").hexdigest()
            record["referent"], walk = self._referent(dir_fd, name, key, tree=tree)
        elif kind == "directory" and tree and info is not None:
            walk = ("enter", dir_fd, name, key, (info.st_dev, info.st_ino), False, record)
        self.metadata[key] = record
        return walk

    def _referent(self, dir_fd: int, name: str, key: str, *, tree: bool) -> tuple[dict[str, Any], tuple[Any, ...] | None]:
        """Follow a metadata symlink once: digest a file, or bind a directory and return the task that walks it."""
        try:
            info = os.stat(name, dir_fd=dir_fd)
        except FileNotFoundError:
            return {"kind": "dangling"}, None
        except OSError as exc:
            self.state.incomplete(f"unreadable metadata referent {key}: {exc.strerror}")
            return {"kind": "unreadable"}, None
        kind = entry_kind(info)
        if kind == "file":
            try:
                data = _read_pinned(dir_fd, name, info, min(METADATA_FILE_CAP, self.meta_budget.remaining_bytes()), follow=True,
                                    deadline=self.budget.deadline)
            except PathReplacedError:
                self.state.incomplete(f"metadata referent replaced during capture: {key}")
                return {"kind": "unreadable"}, None
            except OSError as exc:
                self.state.incomplete(f"unreadable metadata referent {key}: {exc.strerror}")
                return {"kind": "unreadable"}, None
            self.meta_budget.take_bytes(len(data))
            return {"kind": "file", "mode": stat.S_IMODE(info.st_mode), "sha256": hashlib.sha256(data).hexdigest()}, None
        if kind == "directory":
            record = {"kind": "directory", "mode": stat.S_IMODE(info.st_mode), "identity": [info.st_dev, info.st_ino]}
            return record, ("enter", dir_fd, name, key, (info.st_dev, info.st_ino), True, record) if tree else None
        return {"kind": kind}, None

    def _snapshot_path(self, key: str, path: str, *, tree: bool) -> None:
        """Snapshot a file or tree named by absolute path; the base may be a symlink."""
        parent, name = os.path.split(path)
        try:
            base_fd = os.open(parent or "/", _ROOT_FLAGS)
        except FileNotFoundError:
            self.metadata[key] = {"kind": "absent"}
            return
        except OSError as exc:
            self.metadata[key] = {"kind": "unreadable"}
            self.state.incomplete(f"unreadable metadata {key}: {exc.strerror}")
            return
        try:
            self._snapshot_entry(base_fd, name, key, tree=tree)
        finally:
            os.close(base_fd)

    def _config(self) -> None:
        """Config files Git would read for this worktree, the files they name, and conversion settings, parsed without Git."""
        home = os.path.expanduser("~")
        for origin_path, entries in self.config_entries.items():
            origin_path = os.path.normpath(origin_path)
            self.config_files.add(origin_path)
            for key, value in entries:
                # Each entry was charged to the metadata budget as it was parsed.
                self.budget.check_time()
                if key in CONVERSION_SETTINGS and git_store.config_maybe_bool(value) is not False:
                    self.conversion_sources.add(key)
                if value is None:
                    continue
                if key in ("core.hookspath", "core.fsmonitor") and ("\t" in value or "\r" in value):
                    # Git 2.35 to 2.44 turn a tab or carriage return between words into a space;
                    # later releases keep it. Which file or command such a value names depends on
                    # the release, so its dependencies are unknown.
                    self.state.incomplete(f"{key} holds a tab or carriage return that Git releases read differently")
                    continue
                if key == "core.hookspath":
                    directory = self._hooks_directory(value, home)
                    if directory is not None:
                        self.dependencies[f"core.hookspath:{value}"] = (directory, True)
                elif key == "core.fsmonitor":
                    if git_store.config_maybe_bool(value) is None:
                        # Not a boolean, so a hook program Git would run from the worktree; never run here.
                        self.state.incomplete(FSMONITOR_PROGRAM_REASON)
                    elif value and self.git.version[:2] < FSMONITOR_BOOLEAN_VERSION:
                        # A boolean to later releases, a program found through PATH to this one. An empty
                        # value disables the monitor on every release; a valueless key (None, skipped
                        # above) is a config error to 2.35, which then runs nothing.
                        self.state.incomplete(FSMONITOR_VERSION_REASON)

    def _hooks_directory(self, value: str, home: str) -> str | None:
        """The directory a ``core.hooksPath`` value names, as the filesystem will resolve it; None makes the capture incomplete.

        Nothing is normalized lexically across a symlink: a ``..`` component is
        resolved by the filesystem after any symlink before it (``link/..`` is
        the parent of the link's target, not the directory holding the link),
        so a value holding one is refused, as are the ``~user`` and
        ``%(prefix)`` expansions this capture does not perform. What remains
        is normalized only for ``.`` components and repeated slashes, which the
        filesystem resolves the same way, and joined to the worktree root (or
        the home directory for ``~``) without normalizing that base; the
        snapshot then opens it by path, symlinks followed as Git follows them.
        """
        if _PARENT_COMPONENT.search(value):
            self.state.incomplete("core.hookspath holds a '..' component, which the filesystem resolves after any "
                                  "symlink before it, so the directory it names is not established")
            return None
        base = str(self.root)
        if value == "~" or value.startswith("~/"):
            base, value = home, value[2:]
        elif value.startswith(("~", "%(")):
            self.state.incomplete("core.hookspath uses a home or prefix expansion this capture does not resolve")
            return None
        value = os.path.normpath(value) if value else "."
        return value if os.path.isabs(value) else os.path.join(base, value)

    def _metadata(self) -> None:
        git_dir, common_dir, _ = self.dirs
        bases = {"worktree:": str(self.root), "gitdir:": git_dir, "common:": common_dir}
        files = {
            "worktree:": (".git",),
            "gitdir:": ("HEAD", "config.worktree", "commondir", "gitdir"),
            "common:": ("config", "packed-refs", "shallow", "objects/info/alternates"),
        }
        # A linked worktree's own gitdir has per-worktree refs and info (for
        # example info/sparse-checkout); both are snapshotted alongside the
        # common directory's.
        trees = {"worktree:": (), "gitdir:": ("refs", "info") if git_dir != common_dir else (), "common:": ("hooks", "info", "refs", "reftable")}
        for prefix, base in bases.items():
            try:
                base_fd = os.open(base, _ROOT_FLAGS)
            except OSError as exc:
                self.metadata[prefix] = {"kind": "unreadable"}
                self.state.incomplete(f"unreadable metadata base {prefix}: {exc.strerror}")
                continue
            try:
                for name in files[prefix]:
                    parent, _, leaf = name.rpartition("/")
                    if not parent:
                        self._snapshot_entry(base_fd, leaf, prefix + name, tree=False)
                        continue
                    try:
                        parent_fd = os.open(parent, _DIR_FLAGS, dir_fd=base_fd)
                    except FileNotFoundError:
                        self.metadata[prefix + name] = {"kind": "absent"}
                        continue
                    except OSError as exc:
                        self.metadata[prefix + name] = {"kind": "unreadable"}
                        self.state.incomplete(f"unreadable metadata {prefix}{name}: {exc.strerror}")
                        continue
                    try:
                        self._snapshot_entry(parent_fd, leaf, prefix + name, tree=False)
                    finally:
                        os.close(parent_fd)
                for name in trees[prefix]:
                    self._snapshot_entry(base_fd, name, prefix + name, tree=True)
            finally:
                os.close(base_fd)
        info_attributes = os.path.join(common_dir, "info", "attributes")
        self.attribute_files.append(info_attributes)
        known = {os.path.normpath(os.path.join(common_dir, "config")), os.path.normpath(os.path.join(git_dir, "config.worktree"))}
        for path in sorted(self.config_files - known):
            self._snapshot_path(f"config-file:{path}", path, tree=False)
        for key, (path, tree) in sorted(self.dependencies.items()):
            self._snapshot_path(f"dependency:{key}", path, tree=tree)

    def _conversions(self) -> list[str]:
        """Where conversion attributes or settings apply; raw equality then is not Git cleanliness."""
        sources = set(self.conversion_sources)
        for path, text in self.attribute_texts.items():
            if _conversion_attributes(text, self.budget.check_time):
                sources.add(path)
        for count, (path, value) in enumerate(self.inventory.items()):
            if not count % git_store.TIME_CHECK_INTERVAL:
                self.budget.check_time()
            if path.rsplit("/", 1)[-1] == ".gitattributes" and not value.startswith("file:"):
                # Not read as a file here (and a FIFO would block Git), tracked or not: what it says is unknown.
                sources.add(f"{path} (not a regular file)")
        for count, path in enumerate(sorted(self.index_paths)):
            if not count % git_store.TIME_CHECK_INTERVAL:
                self.budget.check_time()
            if path.rsplit("/", 1)[-1] == ".gitattributes" and not str(self.inventory.get(path, "")).startswith("file:"):
                # Git falls back to the indexed copy, which this capture does not read.
                sources.add(f"{path} (index only)")
        for path in self.attribute_files:
            parent, name = os.path.split(path)
            try:
                parent_fd = os.open(parent or "/", _ROOT_FLAGS)
            except FileNotFoundError:
                continue
            except OSError as exc:
                self.state.incomplete(f"unreadable attributes file {path}: {exc.strerror}")
                continue
            try:
                try:
                    info = os.stat(name, dir_fd=parent_fd)
                except FileNotFoundError:
                    continue
                if not stat.S_ISREG(info.st_mode):
                    self.state.incomplete(f"attributes file is not a regular file: {path}")
                    continue
                data = _read_pinned(parent_fd, name, info, min(METADATA_FILE_CAP, self.meta_budget.remaining_bytes()), follow=True,
                                    deadline=self.budget.deadline)
                self.meta_budget.take_bytes(len(data))
            except OSError as exc:
                self.state.incomplete(f"unreadable attributes file {path}: {exc}")
                continue
            finally:
                os.close(parent_fd)
            if _conversion_attributes(data.decode("utf-8", errors="replace"), self.budget.check_time):
                sources.add(path)
        # Conversion scanning runs near the end of a capture: its answer is evidence only within the deadline.
        self.budget.check_time()
        return sorted(sources)

    # Run ------------------------------------------------------------------

    def _bound_identity(self) -> dict[str, list[int]]:
        identities: dict[str, list[int]] = {}
        for name, path in (("root", str(self.root)), ("git_dir", self.dirs[0]), ("common_dir", self.dirs[1])):
            info = os.stat(path)
            identities[name] = [info.st_dev, info.st_ino, info.st_mode]
        return identities

    def run(self) -> dict[str, Any]:
        git = trusted_git(timeout=max(0.1, self.budget.remaining_seconds()))
        if git is None:
            return _failure(NO_TRUSTED_GIT, "git-unavailable")
        self.git = git
        self.inventory: dict[str, str] = {}
        self.blobs: dict[str, tuple[str, str | None]] = {}
        # Git blob IDs of the raw bytes of every walked file and symlink target, and every symlink's target, for
        # callers that compare the worktree with HEAD's tree without the index.
        self.raw_blobs: dict[str, str] = {}
        self.link_targets: dict[str, str] = {}
        self.head_commit: str | None = None
        self.metadata: dict[str, dict[str, Any]] = {}
        self.config_files: set[str] = set()
        self.dependencies: dict[str, tuple[str, bool]] = {}
        self.attribute_texts: dict[str, str] = {}
        self.attribute_files: list[str] = []
        self.conversion_sources: set[str] = set()
        self.unwalked: list[str] = []
        self.ignore_texts: dict[str, bytes] = {}
        try:
            self._preflight()
        except BudgetExhausted as exc:
            return _failure(f"capture budget exhausted: {exc}", "budget", partial=True)
        except (_CaptureFailure, OSError) as exc:
            return _failure(f"repository not safe to inspect: {exc}", "repository-unqualified")
        except _MALFORMED_DATA as exc:
            return _failure(f"repository not safe to inspect: malformed data ({type(exc).__name__}: {exc})", "repository-unqualified")
        self.root_fd = -1
        self.snapshot: _Snapshot | None = None
        self.store: git_store.ObjectStore | None = None
        try:
            result = self._run_bound(git)
        finally:
            # Every resource is released on every path out, whatever stopped the capture. Cleanup
            # runs under the capture deadline plus a fixed grace, so a capture that stopped at its
            # deadline still removes its scratch directory.
            if self.store is not None:
                self.store.close()
            if self.snapshot is not None:
                self.snapshot.close(deadline=max(self.budget.deadline, time.monotonic()) + CLEANUP_GRACE_SECONDS)
            if self.root_fd >= 0:
                os.close(self.root_fd)
        if self.snapshot is not None and self.snapshot.problems:
            result = _with_cleanup_problems(result, self.snapshot.problems, self.snapshot.abandoned)
        return result

    def _run_bound(self, git: GitExecutable) -> dict[str, Any]:
        """The capture after its preflight; resources are released by ``run``."""
        try:
            self.dirs = self._dirs()
        except BudgetExhausted as exc:
            return _failure(f"capture budget exhausted: {exc}", "budget", partial=True)
        except (_CaptureFailure, OSError) as exc:
            return _failure(f"not a git worktree: {exc}", "not-a-worktree")
        try:
            top_level = _real_path(self.root) == _real_path(self.dirs[2])
            same_dirs = (_real_path(self.dirs[0]), _real_path(self.dirs[1])) == self.preflight_dirs
        except _CaptureFailure as exc:
            return _failure(f"repository not safe to inspect: {exc}", "repository-unqualified")
        if not top_level:
            return _failure("workspace root is not the worktree top level", "not-top-level")
        if not same_dirs:
            return _failure("git reported a repository directory other than the one checked", "repository-unqualified")
        try:
            self.root_fd = os.open(self.root, _ROOT_FLAGS)
        except OSError as exc:
            return _failure(f"workspace root unreadable: {exc.strerror}", "root-unreadable")
        except _MALFORMED_DATA as exc:
            return _failure(f"workspace root unreadable: {type(exc).__name__}: {exc}", "root-unreadable")
        try:
            self.snapshot = _Snapshot((str(self.root), self.dirs[0], self.dirs[1]))
            self.snapshot.setup(self.budget.check_time)
        except _ScratchRelocated as exc:
            return _with_leftover(_failure(str(exc), "scratch-relocated"), exc)
        except (_CaptureFailure, OSError, *_MALFORMED_DATA) as exc:
            return _with_leftover(_failure(f"no private scratch repository: {type(exc).__name__}: {exc}",
                                           "scratch-unavailable"), exc)
        try:
            self.store = git_store.ObjectStore(
                os.path.join(self.dirs[1], "objects"),
                hash_name=self.object_format_name,
                open_regular=_open_regular,
                list_names=self._list_names,
                charge=self.meta_budget.take_bytes,
                check_time=self.budget.check_time,
                max_object_bytes=OBJECT_SIZE_CAP,
            )
        except git_store.StoreError as exc:
            return _failure(f"repository not safe to inspect: {exc}", "repository-unqualified")
        try:
            identity = self._bound_identity()
            root_info = os.fstat(self.root_fd)
            if [root_info.st_dev, root_info.st_ino, root_info.st_mode] != identity["root"]:
                return _failure("workspace root changed while opening", "identity-changed")
            self.object_format = self._object_format()
            entries = self._index()
            self.index_paths = {entry[3] for entry in entries if entry[2] == 0}
            self.unmerged_paths = {entry[3] for entry in entries if entry[2] != 0}
            self.gitlinks = {entry[3] for entry in entries if INDEX_MODES.get(entry[0]) == "gitlink"}
            sparse = sorted(entry[3] for entry in entries if INDEX_MODES.get(entry[0]) == "sparse-directory")
            if sparse:
                self.state.incomplete("sparse index directories are not expanded")
            self._check_declared_paths()
            head_tree, head = self._head()
            self._walk()
            tick = self._ticker()
            for path, value in self.inventory.items():
                tick()
                # Compared in place: no part of the path is copied.
                if (path == ".gitignore" or path.endswith("/.gitignore")) and not value.startswith("file:"):
                    # Its patterns cannot be copied, so what Git would ignore below it is unknown.
                    raise _CaptureFailure(f"a .gitignore entry is not a regular file: {path}")
            self._check_unwalked_attributes()
            self.ignored_files, self.ignored_dirs = self._ignored()
            self._read_excluded_tracked()
            status = self._status(entries, head)
            self._config()
            self._metadata()
            conversions = self._conversions()
            if self._dirs() != self.dirs or self._bound_identity() != identity or _identity(git.path) != git.identity:
                self.state.incomplete("capture identity changed during capture")
            # Nothing is returned as evidence once the deadline has passed.
            self.budget.check_time()
        except BudgetExhausted as exc:
            return _failure(f"capture budget exhausted: {exc}", "budget", partial=True)
        except _ScratchRelocated as exc:
            return _failure(str(exc), "scratch-relocated")
        except _CaptureFailure as exc:
            return _failure(str(exc), "git-failed")
        except OSError as exc:
            return _failure(f"capture failed: {exc}", "io-failed")
        except _MALFORMED_DATA as exc:
            return _failure(f"capture stopped on malformed data ({type(exc).__name__}: {exc})", "malformed-data")
        return {
            "error": None,
            "complete": not self.state.reasons,
            "incomplete_reasons": list(self.state.reasons),
            "git_executable": git.describe(),
            "dirs": self.dirs,
            "capture_identity": identity,
            "object_format": self.object_format,
            "head": head_tree,
            "head_commit": self.head_commit,
            "head_manifest_sha256": hashlib.sha256(repr(sorted(head.items())).encode()).hexdigest(),
            # HEAD's tree read from the object store, and the raw worktree as Git would hash it: independent of
            # the index, its flags and every conversion.
            "head_entries": dict(sorted(head.items())),
            "raw_blob_ids": dict(sorted(self.raw_blobs.items())),
            "symlink_targets": dict(sorted(self.link_targets.items())),
            "ignored_files": sorted(self.ignored_files),
            "index_entries": entries,
            "status_lines": status,
            "raw_inventory": dict(sorted(self.inventory.items())),
            "ignored_directories": list(self.ignored_dirs),
            "sparse_directories": sparse,
            "metadata": {"git_dir": self.dirs[0], "common_dir": self.dirs[1], "entries": dict(sorted(self.metadata.items())), "complete": not self.state.reasons},
            "normalization_sources": conversions,
            "git_cleanliness": "unknown-conversions" if conversions else "raw-equals-git",
        }


def _failure(message: str, kind: str, *, partial: bool = False) -> dict[str, Any]:
    return {"error": message, "error_kind": kind, "complete": False, "incomplete_reasons": [message], "budget_exhausted": partial}


def _with_leftover(result: dict[str, Any], exc: BaseException) -> dict[str, Any]:
    """``result`` naming the scratch directory a failed construction left behind, if any (its message
    already holds the path)."""
    abandoned = getattr(exc, "abandoned", None)
    return _with_cleanup_problems(result, [], abandoned) if abandoned is not None else result


def _with_cleanup_problems(result: dict[str, Any], problems: list[str], abandoned: str | None) -> dict[str, Any]:
    """``result`` made incomplete by what scratch cleanup reported, with any abandoned directory named."""
    result = dict(result)
    result["complete"] = False
    result["incomplete_reasons"] = [*result.get("incomplete_reasons", []), *problems]
    if isinstance(result.get("metadata"), dict):
        result["metadata"] = {**result["metadata"], "complete": False}
    result["scratch_abandoned"] = abandoned
    return result


def object_store(common_dir: str, object_format: str, budget: Budget) -> git_store.ObjectStore:
    """The object store of a repository a capture has qualified (``dirs[1]`` and ``object_format`` of its result).

    Objects are read without Git through the same pinned reader as a capture, each checked against its
    identifier, under ``budget``. A path that is not a regular file raises ``git_store.UnsupportedLayout``. The
    caller closes the store.
    """

    def open_regular(path: str) -> int:
        try:
            return _open_regular(path)
        except _CaptureFailure as exc:
            raise git_store.UnsupportedLayout(str(exc)) from exc

    def list_names(path: str) -> list[str]:
        fd = os.open(path, _ROOT_FLAGS)
        try:
            names = []
            with os.scandir(fd) as entries:
                for entry in entries:
                    budget.take_entry()
                    names.append(entry.name)
            return names
        finally:
            os.close(fd)

    return git_store.ObjectStore(os.path.join(common_dir, "objects"), hash_name=object_format,
                                 open_regular=open_regular, list_names=list_names, charge=budget.take_bytes,
                                 check_time=budget.check_time, max_object_bytes=OBJECT_SIZE_CAP)


def capture(
    root: Path | str,
    *,
    max_files: int,
    max_bytes: int,
    max_seconds: float,
    max_entries: int,
    allowed_paths: tuple[str, ...] = (),
    excluded_parts: frozenset[str] = frozenset(),
) -> dict[str, Any]:
    """Capture ``root`` under one shared budget. See the module docstring."""
    budget = Budget.start(max_files=max_files, max_bytes=max_bytes, max_seconds=max_seconds, max_entries=max_entries)
    return WorktreeCapture(root, budget=budget, scope=CaptureScope(tuple(allowed_paths), frozenset(excluded_parts))).run()


__all__ = [
    "Budget",
    "BudgetExhausted",
    "GitExecutable",
    "INDEX_MODES",
    "PathReplacedError",
    "WorkspaceDiscoveryError",
    "capture",
    "entry_kind",
    "object_store",
    "read_at",
    "read_beneath",
    "run_git",
    "trusted_git",
    "trusted_git_completed",
    "trusted_git_output",
    "trusted_git_succeeds",
    "worktree_top_level",
]
