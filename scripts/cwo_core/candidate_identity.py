"""Candidate identity (issue #37): the exact candidate a successful closure would claim.

A candidate identity record names, for one Bead:

- the requirement baseline version and digest the candidate is meant to satisfy;
- the repository, by its root commits, and the base commit the work started from, which must be an ancestor of
  the candidate commit;
- the candidate commit and its tree;
- a manifest of every path whose working content differs from the candidate commit's tree: its change, file
  type, mode, size and the SHA-256 of its bytes or link target. Untracked paths the record explicitly excludes
  (evidence files, which would otherwise be hashed into the candidate they describe) and ignored untracked files
  are left out; changed tracked files never are;
- the delivery scope: the repository paths the delivery claims, each of which must exist in the candidate, and the
  live resources whose observed state the delivery depends on;
- the SHA-256 of the full permission and special bits (read, write and execute for user, group and other, setuid,
  setgid and sticky) of every delivered file, symlink and directory and of the repository root, as lstat reports
  them (``delivered_modes``). The manifest's mode is Git's (100644, 100755 or 120000); this digest binds the rest,
  so a change such as 0644 to 0666, 0755 to 4755, or a directory made group-writable is a mismatch.

The manifest comes from inert workspace capture (``workspace_capture``): raw bytes, modes and types read from the
filesystem without following symlinks, compared with HEAD's tree entries read from the object store. The index,
its flags (assume-unchanged, skip-worktree), core.filemode and Git conversions (filters, end-of-line and encoding
attributes) have no part in it, and no Git command runs against the working tree or its repository: the capture
runs two read-only listing commands in a private scratch repository and reads everything else without Git. The
history (root commits, base ancestry) is read from the object store too.

Every delivered symlink must resolve, over the delivered content alone, to a delivered file or directory. A link
that resolves into excluded, ignored, absent or external content, into .git, or to the repository root is refused,
because delivered content would then depend on content the candidate does not bind. Ordinary code that opens or
imports ignored or excluded files by name is not detected: candidate identity binds content, it does not analyse
what delivered code loads.

A commit SHA alone does not identify dirty deliverables, so the manifest is part of the identity. A content
identity does not authenticate who approved the content either; the record has no approval or result fields, and
approvals bind to its digest elsewhere. The digest is the requirement baseline digest function applied to the
record. A Bead retains a candidate by a comment whose whole text is its reference line.

Verification re-identifies the working tree with the record's own base, scope and exclusions and refuses any
difference (drift), checks that the record claims the current baseline of the chain and that the Bead records both
that baseline and, as its most recent candidate, this one. Recording returns a record and writes nothing, to Beads
or to the repository. Successful closure stays unavailable (see scripts/close_bead_with_summary.py).

Independently observed live-resource state (a retired service, a deployed name) cannot be bound yet: that needs a
producer-bound observation record which does not exist. A delivery scope that names live resources is therefore
refused until it does.
"""
from __future__ import annotations

import bisect
import hashlib
import json
import re
import stat
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from . import git_store, workspace_capture
from .requirement_baseline import (
    RESULT_KEYS,
    RequirementBaselineError,
    bead_reference_errors,
    record_digest,
    reference_line,
    scan_reference_comments,
)

CANDIDATE_RECORD_TYPE = "cwo-candidate-identity"
RECORD_VERSION = 1
CANDIDATE_FIELDS = (
    "record_type",
    "version",
    "bead_id",
    "baseline",
    "repository",
    "base_commit",
    "commit",
    "tree",
    "delivery_scope",
    "excluded_paths",
    "worktree_manifest",
    "delivered_modes",
)
BASELINE_BINDING_FIELDS = ("version", "digest")
REPOSITORY_FIELDS = ("root_commits",)
SCOPE_FIELDS = ("paths", "live_resources")
MANIFEST_FIELDS = ("path", "change", "type", "mode", "size", "sha256")
CHANGES = ("added", "modified", "deleted")
FILE_TYPES = ("file", "symlink", "absent")
FILE_MODES = ("100644", "100755")
SYMLINK_MODE = "120000"
WHOLE_REPOSITORY = "."
# Keys that would make a content identity read as an approval.
APPROVAL_KEYS = frozenset({
    "approval", "approvals", "approved", "approved_by", "approver", "review", "reviewer", "signature", "signed_by",
})
MAX_PATH = 4096
MAX_PATHS = 1000
MAX_MANIFEST_ENTRIES = 10000
MAX_MANIFEST_BYTES = 256 * 1024 * 1024
CANDIDATE_REFERENCE_PREFIX = "cwo-candidate-identity"
_CANDIDATE_REFERENCE = re.compile(r"cwo-candidate-identity bead=(?P<bead>\S+) digest=(?P<digest>sha256:[0-9a-f]{64})")
_BEAD_ID = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9._-]{0,126}[A-Za-z0-9])?")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_OID = re.compile(r"[0-9a-f]{40}(?:[0-9a-f]{24})?")
_HEX = re.compile(r"[0-9a-f]{64}")
_CONTROL = re.compile("[\x00-\x1f\x7f-\x9f\u061c\u200e\u200f\u2028\u2029\u202a-\u202e\u2066-\u2069]")
LIVE_RESOURCE_REFUSAL = (
    "candidate identity cannot bind independently observed live-resource state yet: that needs a producer-bound "
    "observation record (evidence-bound adjudication) that does not exist, so a delivery scope that names live "
    "resources is refused until it does"
)


class CandidateIdentityError(ValueError):
    """A candidate that cannot be identified or verified, with every reason found."""

    def __init__(self, errors: Sequence[str]) -> None:
        self.errors = list(errors)
        super().__init__("; ".join(self.errors))


# Record shape


def _path_errors(value: Any, where: str, *, allow_whole: bool = False) -> list[str]:
    if allow_whole and value == WHOLE_REPOSITORY:
        return []
    if type(value) is not str or not value or len(value) > MAX_PATH:
        return [f"{where} must be a repository path of 1 to {MAX_PATH} characters"]
    if _CONTROL.search(value):
        return [f"{where} cannot contain control or text-direction characters"]
    parts = value.split("/")
    if value.startswith("/") or any(part in ("", ".", "..") for part in parts):
        return [f"{where} {value!r} must be a relative path with no empty, '.' or '..' component"]
    return []


def _within(path: str, prefix: str) -> bool:
    """Whether ``path`` is ``prefix`` or lies under it."""
    return prefix == WHOLE_REPOSITORY or path == prefix or path.startswith(prefix + "/")


def _sorted_unique(value: list[Any]) -> bool:
    return value == sorted(set(value))


def _closed(value: Mapping[str, Any], allowed: Sequence[str], where: str) -> list[str]:
    extra = sorted(set(value) - set(allowed))
    errors = []
    approvals = [key for key in extra if key in APPROVAL_KEYS]
    if approvals:
        errors.append(
            f"{where} carries approval field(s) {', '.join(approvals)}: a candidate identity is a content identity "
            "and does not authenticate who approved the candidate"
        )
    results = [key for key in extra if key in RESULT_KEYS and key not in APPROVAL_KEYS]
    if results:
        errors.append(
            f"{where} carries result field(s) {', '.join(results)}: a candidate identity records what is "
            "delivered, not whether it passed"
        )
    others = [key for key in extra if key not in RESULT_KEYS and key not in APPROVAL_KEYS]
    if others:
        errors.append(f"{where} has unsupported field(s) {', '.join(others)}")
    errors += [f"{where} is missing {field}" for field in allowed if field not in value]
    return errors


def _manifest_entry_errors(entry: Any, where: str) -> list[str]:
    if type(entry) is not dict:
        return [f"{where} must be an object"]
    errors = _closed(entry, MANIFEST_FIELDS, where)
    if errors:
        return errors
    errors = _path_errors(entry["path"], f"{where} path")
    change, kind, mode, size, digest = (entry[key] for key in ("change", "type", "mode", "size", "sha256"))
    if change not in CHANGES:
        errors.append(f"{where} change must be one of: {', '.join(CHANGES)}")
    if kind not in FILE_TYPES:
        errors.append(f"{where} type must be one of: {', '.join(FILE_TYPES)}")
    if kind == "absent" or change == "deleted":
        if (kind, change, mode, size, digest) != ("absent", "deleted", None, None, None):
            errors.append(f"{where}: a deleted path has type absent and no mode, size or sha256, and only a deleted "
                          "path is absent")
        return errors
    return errors + _present_entry_errors(kind, mode, size, digest, where)


def _present_entry_errors(kind: Any, mode: Any, size: Any, digest: Any, where: str) -> list[str]:
    errors = []
    if kind == "file" and mode not in FILE_MODES:
        errors.append(f"{where} mode must be one of {', '.join(FILE_MODES)} for a file")
    if kind == "symlink" and mode != SYMLINK_MODE:
        errors.append(f"{where} mode must be {SYMLINK_MODE} for a symlink")
    if type(size) is not int or size < 0:
        errors.append(f"{where} size must be a non-negative integer")
    if type(digest) is not str or not _HEX.fullmatch(digest):
        errors.append(f"{where} sha256 must be 64 lowercase hex digits")
    return errors


def _baseline_errors(baseline: Any) -> list[str]:
    if type(baseline) is not dict:
        return ["baseline must be an object with version and digest"]
    errors = _closed(baseline, BASELINE_BINDING_FIELDS, "baseline")
    if type(baseline.get("version")) is not int or baseline.get("version", 0) < 1:
        errors.append("baseline version must be an integer of at least 1")
    if type(baseline.get("digest")) is not str or not _DIGEST.fullmatch(baseline.get("digest")):
        errors.append("baseline digest must be sha256: and 64 lowercase hex digits")
    return errors


def _repository_errors(repository: Any) -> tuple[list[str], list[Any]]:
    """Errors in ``repository`` and its root commits, when they are well formed."""
    if type(repository) is not dict:
        return ["repository must be an object with root_commits"], []
    errors = _closed(repository, REPOSITORY_FIELDS, "repository")
    roots = repository.get("root_commits")
    if type(roots) is not list or not roots or not all(type(value) is str and _OID.fullmatch(value) for value in roots):
        errors.append("repository root_commits must be a non-empty list of full lowercase Git commit IDs")
    elif not _sorted_unique(roots):
        errors.append("repository root_commits must be sorted and distinct")
    else:
        return errors, roots
    return errors, []


def _object_id_errors(record: Mapping[str, Any], roots: list[Any]) -> list[str]:
    named = list(zip(("base_commit", "commit", "tree"), (record["base_commit"], record["commit"], record["tree"])))
    errors = [f"{name} must be a full lowercase Git object ID" for name, value in named
              if type(value) is not str or not _OID.fullmatch(value)]
    oids = [value for _, value in named] + roots
    if all(type(value) is str and _OID.fullmatch(value) for value in oids) and len({len(value) for value in oids}) != 1:
        errors.append("every object ID in the candidate must use the same hash")
    return errors


def _path_list_errors(paths: list[Any], where: str, *, allow_whole: bool = False) -> tuple[list[str], list[str]]:
    """Errors in a list of repository paths and the list itself when every item is a string."""
    errors = []
    for index, path in enumerate(paths):
        errors += _path_errors(path, f"{where}[{index}]", allow_whole=allow_whole)
    if not all(type(path) is str for path in paths):
        return errors, []
    if not _sorted_unique(paths):
        errors.append(f"{where} must be sorted and distinct")
    return errors, paths


def _scope_errors(scope: Any) -> tuple[list[str], list[str]]:
    if type(scope) is not dict:
        return ["delivery_scope must be an object with paths and live_resources"], []
    errors = _closed(scope, SCOPE_FIELDS, "delivery_scope")
    paths = scope.get("paths")
    scope_paths: list[str] = []
    if type(paths) is not list or not paths or len(paths) > MAX_PATHS:
        errors.append(f"delivery_scope paths must list 1 to {MAX_PATHS} repository paths the delivery claims")
    else:
        path_errors, scope_paths = _path_list_errors(paths, "delivery_scope paths", allow_whole=True)
        errors += path_errors
    live = scope.get("live_resources")
    if type(live) is not list:
        errors.append("delivery_scope live_resources must be a list")
    elif live:
        errors.append(LIVE_RESOURCE_REFUSAL)
    return errors, scope_paths


def _excluded_errors(excluded: Any, scope_paths: list[str]) -> tuple[list[str], list[str]]:
    if type(excluded) is not list or len(excluded) > MAX_PATHS:
        return [f"excluded_paths must be a list of at most {MAX_PATHS} repository paths"], []
    errors, excluded_paths = _path_list_errors(excluded, "excluded_paths")
    for path in excluded_paths:
        covered = [item for item in scope_paths if item != WHOLE_REPOSITORY and _within(item, path)]
        if covered:
            errors.append(f"excluded path {path} covers delivery scope path(s) {', '.join(covered)}: delivered "
                          "content cannot be left out of the candidate")
    return errors, excluded_paths


def _manifest_errors(manifest: Any, excluded_paths: list[str]) -> list[str]:
    if type(manifest) is not list or len(manifest) > MAX_MANIFEST_ENTRIES:
        return [f"worktree_manifest must be a list of at most {MAX_MANIFEST_ENTRIES} entries"]
    errors = []
    names = []
    for index, entry in enumerate(manifest):
        entry_errors = _manifest_entry_errors(entry, f"worktree_manifest[{index}]")
        errors += entry_errors
        if entry_errors:
            continue
        names.append(entry["path"])
        hidden = [path for path in excluded_paths if _within(entry["path"], path)]
        if entry["change"] == "added" and hidden:
            errors.append(f"worktree_manifest[{index}] {entry['path']} lies under excluded path {hidden[0]}")
    if len(names) == len(manifest) and not _sorted_unique(names):
        errors.append("worktree_manifest must be sorted by path with each path once")
    return errors


def candidate_errors(record: Any) -> list[str]:
    """Every reason ``record`` is not a usable version 1 candidate identity; empty when it is.

    This checks the record alone. ``verify_candidate`` compares it with a working tree and ``check_candidate``
    with the baseline chain and the Bead as well.
    """
    if type(record) is not dict:
        return ["a candidate identity must be a JSON object"]
    if record.get("record_type") != CANDIDATE_RECORD_TYPE:
        return [f"record_type must be {CANDIDATE_RECORD_TYPE}"]
    if type(record.get("version")) is not int or record.get("version") != RECORD_VERSION:
        return [f"unsupported candidate identity version {record.get('version')!r}; only {RECORD_VERSION} is supported"]
    errors = _closed(record, CANDIDATE_FIELDS, "the candidate")
    if errors:
        return errors
    bead = record["bead_id"]
    if type(bead) is not str or not _BEAD_ID.fullmatch(bead):
        errors.append("bead_id must be a Bead ID (letters, digits, '.', '_' and '-')")
    errors += _baseline_errors(record["baseline"])
    repository_errors, roots = _repository_errors(record["repository"])
    errors += repository_errors + _object_id_errors(record, roots)
    scope_errors, scope_paths = _scope_errors(record["delivery_scope"])
    excluded_errors, excluded_paths = _excluded_errors(record["excluded_paths"], scope_paths)
    errors += scope_errors + excluded_errors + _manifest_errors(record["worktree_manifest"], excluded_paths)
    return errors + _modes_errors(record["delivered_modes"])


def _modes_errors(value: Any) -> list[str]:
    if type(value) is not str or not _DIGEST.fullmatch(value):
        return ["delivered_modes must be sha256: and 64 lowercase hex digits"]
    return []


def candidate_digest(record: Mapping[str, Any]) -> str:
    """The digest that names a valid candidate: the same deterministic serialization as a requirement baseline."""
    return record_digest(record)


def candidate_reference_line(bead_id: str, digest: str) -> str:
    """The exact comment text by which a Bead retains one candidate."""
    return f"{CANDIDATE_REFERENCE_PREFIX} bead={bead_id} digest={digest}"


def candidate_binding(record: Any) -> str:
    """The value a later record binds as its candidate: evidence results and final approvals (restoration criteria
    3 and 4) and evidence-bound adjudication name a candidate by this digest. Refuses an invalid record."""
    errors = candidate_errors(record)
    if errors:
        raise CandidateIdentityError(errors)
    return candidate_digest(record)


# Reading the working tree: inert workspace capture (workspace_capture) and the object store (git_store). No Git
# command is run against the working tree or its repository, so no filter, hook or monitor configured there runs.


# Bounds of the capture, which reads every file in the working tree (ignored and excluded content too), and of the
# history walk. Only the manifest is bound by MAX_MANIFEST_ENTRIES and MAX_MANIFEST_BYTES.
CAPTURE_LIMITS = {"max_files": 100_000, "max_bytes": 1024 * 1024 * 1024, "max_seconds": 120.0, "max_entries": 500_000}
HISTORY_LIMITS = {"max_files": 0, "max_bytes": 512 * 1024 * 1024, "max_seconds": 60.0, "max_entries": 100_000}
MAX_LINK_HOPS = 40
GITLINK_MODE = "160000"
UNBOUND_TARGET = (
    "which is not bound content of the candidate (it is excluded, ignored, absent, under .git or outside the "
    "repository)"
)


def _refuse(*errors: str) -> CandidateIdentityError:
    return CandidateIdentityError(list(errors))


def _utf8(text: str) -> bool:
    try:
        text.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True


def _capture(root: Path) -> dict[str, Any]:
    """The complete inert capture of the working tree at ``root``, which must be its top level."""
    if not root.is_dir():
        raise _refuse(f"the repository {root} does not exist")
    try:
        top = workspace_capture.worktree_top_level(root)
    except workspace_capture.WorkspaceDiscoveryError as exc:
        raise _refuse(f"{root} is not a Git working tree that can be read inertly: {exc}") from exc
    if top is None:
        raise _refuse(f"{root} is not a Git working tree")
    if Path(top).resolve() != root.resolve():
        raise _refuse(f"{root} is not the top of its Git working tree")
    raw = workspace_capture.capture(root, **CAPTURE_LIMITS)
    if raw.get("error") or not raw.get("complete"):
        reasons = raw.get("incomplete_reasons") or [raw.get("error") or "incomplete"]
        raise _refuse(*(f"the working tree cannot be captured exactly: {reason}" for reason in reasons))
    if raw["head_commit"] is None:
        raise _refuse(f"HEAD in {root} names no commit yet")
    return raw


def _parents(store: git_store.ObjectStore, oid: str, what: str) -> list[str]:
    kind, content = store.read(oid)
    if kind != "commit":
        raise _refuse(f"{what} {oid} is not a commit")
    header = bytes(content).split(b"\n\n", 1)[0]
    return [line[7:].decode("ascii") for line in header.split(b"\n") if line.startswith(b"parent ")]


def _history(store: git_store.ObjectStore, commit: str) -> tuple[list[str], set[str]]:
    """The root commits of ``commit`` and every commit reachable from it, read from the object store."""
    seen = {commit}
    pending = [commit]
    roots = []
    while pending:
        oid = pending.pop()
        parents = _parents(store, oid, "the history object")
        if not parents:
            roots.append(oid)
        fresh = [parent for parent in parents if parent not in seen]
        seen.update(fresh)
        pending.extend(fresh)
    return sorted(roots), seen


def _base(store: git_store.ObjectStore, revision: Any, root: Path) -> str:
    if type(revision) is not str or not _OID.fullmatch(revision) or len(revision) != 2 * store.hash_length:
        raise _refuse("the base commit must name a commit by its full object ID")
    try:
        _parents(store, revision, "the base commit")
    except git_store.MissingObject:
        raise _refuse(f"the base commit {revision!r} is not a commit in {root}") from None
    except CandidateIdentityError:
        raise _refuse(f"the base commit {revision!r} is not a commit in {root}") from None
    return revision


def _commit_facts(raw: Mapping[str, Any], root: Path, base_commit: Any) -> tuple[list[str], str]:
    """The root commits and the checked base commit, read without Git."""
    budget = workspace_capture.Budget.start(**HISTORY_LIMITS)
    try:
        store = workspace_capture.object_store(raw["dirs"][1], raw["object_format"], budget)
    except git_store.StoreError as exc:
        raise _refuse(f"the object store of {root} cannot be read: {exc}") from exc
    try:
        base = _base(store, base_commit, root)
        roots, reachable = _history(store, raw["head_commit"])
    except (git_store.StoreError, workspace_capture.BudgetExhausted, OSError) as exc:
        raise _refuse(f"the history of {root} cannot be read completely: {exc}") from exc
    finally:
        store.close()
    if base not in reachable:
        raise _refuse(f"the base commit {base} is not an ancestor of the candidate commit {raw['head_commit']}")
    return roots, base


def _prefixes(path: str) -> list[str]:
    parts = path.split("/")
    return ["/".join(parts[:index]) for index in range(1, len(parts))]


def _under(path: str, prefixes: set[str]) -> bool:
    """Whether ``path`` is one of ``prefixes`` or lies under one."""
    return path in prefixes or any(prefix in prefixes for prefix in _prefixes(path))


class _Worktree:
    """The working tree as captured, compared with HEAD's tree by raw content, mode and type alone.

    The index, its flags (assume-unchanged, skip-worktree), core.filemode and every Git conversion play no part:
    a path is in the manifest exactly when its bytes, mode or type differ from HEAD's tree entry, or when it is a
    file or symlink outside HEAD's tree that is neither ignored nor excluded.
    """

    def __init__(self, raw: Mapping[str, Any], excluded: Sequence[str]) -> None:
        self.inventory: dict[str, str] = raw["raw_inventory"]
        self.blobs: dict[str, str] = raw["raw_blob_ids"]
        self.targets: dict[str, str] = raw["symlink_targets"]
        self.head: dict[str, tuple[str, str]] = raw["head_entries"]
        self.excluded = set(excluded)
        self.ignored_files = set(raw["ignored_files"])
        self.ignored_dirs = self._outermost(raw["ignored_directories"])

    @staticmethod
    def _outermost(directories: Sequence[str]) -> list[str]:
        outermost: list[str] = []
        for directory in sorted(directories):
            if not outermost or not directory.startswith(outermost[-1]):
                outermost.append(directory)
        return outermost

    def ignored(self, path: str) -> bool:
        if path in self.ignored_files:
            return True
        position = bisect.bisect_right(self.ignored_dirs, path)
        return bool(position) and path.startswith(self.ignored_dirs[position - 1])

    def kind(self, path: str) -> str | None:
        value = self.inventory.get(path)
        return None if value is None else value.split(":", 1)[0]

    def mode(self, path: str) -> str:
        if self.kind(path) == "symlink":
            return SYMLINK_MODE
        return "100755" if int(self.inventory[path].split(":", 2)[1], 8) & stat.S_IXUSR else "100644"

    def entry(self, path: str, change: str) -> dict[str, Any]:
        if change == "deleted":
            return {"path": path, "change": change, "type": "absent", "mode": None, "size": None, "sha256": None}
        kind, _, size, digest = self.inventory[path].split(":", 3)
        return {"path": path, "change": change, "type": kind, "mode": self.mode(path), "size": int(size),
                "sha256": digest}

    def tracked_change(self, path: str) -> str | None:
        """How the working tree differs from HEAD's entry for ``path``: None, modified or deleted."""
        mode, blob = self.head[path]
        if mode == GITLINK_MODE:
            raise _refuse(f"{path} is a submodule in the candidate commit; submodule content cannot be identified")
        kind = self.kind(path)
        if kind in (None, "directory"):
            return "deleted"
        if kind not in ("file", "symlink"):
            raise _refuse(f"{path} is neither a regular file nor a symlink (a {kind}), so its content cannot be "
                          "identified")
        return None if (self.mode(path), self.blobs[path]) == (mode, blob) else "modified"

    def untracked_refusal(self, path: str, kind: str) -> str | None:
        if path.rsplit("/", 1)[-1] == ".git":
            return f"{path} belongs to a nested repository, so its content cannot be identified"
        if kind not in ("file", "symlink", "directory"):
            return f"{path} is neither a regular file nor a symlink (a {kind}), so its content cannot be identified"
        return None

    def added(self) -> list[str]:
        """Files and symlinks outside HEAD's tree that the candidate binds; refuses content it cannot identify."""
        added = []
        for path, value in self.inventory.items():
            kind = value.split(":", 1)[0]
            if kind == "gitlink":
                # Before exclusions and ignore rules: an opaque directory is refused wherever it is.
                raise _refuse(f"{path} is a gitlink in the index; its content is opaque, so it cannot be identified")
            if path in self.head or _under(path, self.excluded) or self.ignored(path):
                continue
            refusal = self.untracked_refusal(path, kind)
            if refusal is not None:
                raise _refuse(refusal)
            if kind != "directory":
                added.append(path)
        return added

    def manifest(self) -> list[dict[str, Any]]:
        entries = {}
        for path in self.head:
            change = self.tracked_change(path)
            if change is not None:
                entries[path] = self.entry(path, change)
        for path in self.added():
            entries[path] = self.entry(path, "added")
        unreadable = [path for path in entries if not _utf8(path)]
        if unreadable:
            raise _refuse(f"{unreadable[0]!r} is not a UTF-8 path, so it cannot be recorded")
        total = sum(entry["size"] or 0 for entry in entries.values())
        if len(entries) > MAX_MANIFEST_ENTRIES or total > MAX_MANIFEST_BYTES:
            raise _refuse(
                f"the content that differs from the candidate commit exceeds {MAX_MANIFEST_ENTRIES} files or "
                f"{MAX_MANIFEST_BYTES} bytes; commit it or exclude untracked evidence paths before identifying the "
                "candidate"
            )
        return [entries[path] for path in sorted(entries)]


class _Delivered:
    """The content a candidate delivers: HEAD's tree with the manifest applied, and the directories holding it."""

    def __init__(self, worktree: _Worktree, manifest: Sequence[Mapping[str, Any]]) -> None:
        present = {path for path in worktree.head if worktree.kind(path) in ("file", "symlink")}
        present |= {entry["path"] for entry in manifest if entry["change"] == "added"}
        self.links = {path: worktree.targets[path] for path in present if worktree.kind(path) == "symlink"}
        self.files = present - set(self.links)
        self.directories = {prefix for path in present for prefix in _prefixes(path)}
        self.excluded = worktree.excluded
        self.inventory = worktree.inventory

    def modes_digest(self, root_mode: int) -> str:
        """SHA-256 of the full permission and special bits of the repository root and every delivered path.

        The bits are stat.S_IMODE of the no-follow workspace observation (lstat of each walked entry, the opened root's
        mode for the root): a JSON list of [path, type, octal mode], the root first as ".", then by path, with no
        whitespace and ASCII escapes. Ignored and excluded paths, and directories holding only them, are not
        delivered and not bound.
        """
        entries = [[WHOLE_REPOSITORY, "directory", f"{stat.S_IMODE(root_mode):o}"]]
        for path in sorted(self.files | set(self.links) | self.directories):
            kind, mode = self.inventory[path].split(":", 2)[:2]
            entries.append([path, kind, mode])
        payload = json.dumps(entries, separators=(",", ":"), ensure_ascii=True).encode("ascii")
        return "sha256:" + hashlib.sha256(payload).hexdigest()

    def holds(self, path: str) -> bool:
        return path == WHOLE_REPOSITORY or path in self.files or path in self.links or path in self.directories

    def scope_errors(self, scope_paths: Sequence[str]) -> list[str]:
        return [f"delivery scope path {path} is not in the candidate" for path in sorted(set(scope_paths))
                if not self.holds(path)]

    def link_errors(self) -> list[str]:
        errors = []
        for path in sorted(self.links):
            reason = _LinkResolution(self, path).reason()
            if reason is not None:
                errors.append(
                    f"delivered symlink {path} -> {self.links[path]} {reason}: delivered content would depend on "
                    "content the candidate does not bind; bind the target or remove the link"
                )
        return errors


class _LinkResolution:
    """Resolves one delivered symlink over the delivered content alone, following delivered symlinks."""

    def __init__(self, delivered: _Delivered, path: str) -> None:
        self.delivered = delivered
        self.parts = path.split("/")[:-1]
        self.pending = self._components(delivered.links[path])
        self.hops = 1  # the link itself counts, as it does for the kernel's limit of 40

    @staticmethod
    def _components(target: str) -> list[str] | None:
        """The target's components, keeping what requires a directory: an empty component (a trailing or doubled
        slash) becomes ".", and "." is kept, so a file followed by either is refused as the kernel refuses it."""
        if not target or target.startswith("/") or not _utf8(target):
            return None
        return [part or "." for part in target.split("/")]

    def reason(self) -> str | None:
        if self.pending is None:
            return "is empty, absolute or not UTF-8, so it does not resolve within the repository"
        while self.pending:
            reason = self._step(self.pending.pop(0))
            if reason is not None:
                return reason
        return self._final()

    def _step(self, part: str) -> str | None:
        # Between steps the resolved prefix is always a directory: a file with components still pending is refused
        # below, and a link is replaced by its target. So "." stays where it is.
        if part == ".":
            return None
        if part == "..":
            if not self.parts:
                return "resolves outside the repository"
            self.parts.pop()
            return None
        self.parts.append(part)
        here = "/".join(self.parts)
        if here in self.delivered.links:
            return self._follow(here)
        if here in self.delivered.files:
            return f"resolves through the file {here}" if self.pending else None
        if here not in self.delivered.directories:
            return f"resolves to {here}, {UNBOUND_TARGET}"
        return None

    def _follow(self, here: str) -> str | None:
        self.hops += 1
        components = self._components(self.delivered.links[here])
        if self.hops > MAX_LINK_HOPS:
            return "has too many levels of symlinks"
        if components is None:
            return f"resolves through {here}, which is empty, absolute or not UTF-8"
        self.parts.pop()
        self.pending = components + self.pending
        return None

    def _final(self) -> str | None:
        here = "/".join(self.parts)
        if not here:
            return "resolves to the repository root, which holds unbound content (.git, ignored and excluded paths)"
        if here in self.delivered.directories:
            inside = sorted(path for path in self.delivered.excluded if _within(path, here))
            if inside:
                return f"resolves to the directory {here}, which holds the excluded path {inside[0]}"
        return None


def _request_errors(scope_paths: Sequence[str], excluded_paths: Sequence[str], live_resources: Sequence[Any]) -> list[str]:
    errors = []
    for index, path in enumerate(scope_paths):
        errors += _path_errors(path, f"delivery scope path {index}", allow_whole=True)
    for index, path in enumerate(excluded_paths):
        errors += _path_errors(path, f"excluded path {index}")
    if not scope_paths:
        errors.append("name at least one delivery scope path")
    if live_resources:
        errors.append(LIVE_RESOURCE_REFUSAL)
    return errors


def _exclusion_errors(excluded: Sequence[str], head: Mapping[str, Any]) -> list[str]:
    errors = []
    for path in excluded:
        inside = sorted(item for item in head if _within(item, path))
        if inside:
            errors.append(f"excluded path {path} contains tracked file(s) such as {inside[0]}: only untracked "
                          "content can be excluded")
    return errors


def _identify(
    root: Path | str,
    *,
    bead_id: str,
    baseline: Mapping[str, Any],
    base_commit: str,
    scope_paths: Sequence[str],
    excluded_paths: Sequence[str],
    live_resources: Sequence[Any],
) -> dict[str, Any]:
    errors = _request_errors(scope_paths, excluded_paths, live_resources)
    if errors:
        raise CandidateIdentityError(errors)
    root = Path(root)
    raw = _capture(root)
    roots, base = _commit_facts(raw, root, base_commit)
    excluded = sorted(set(excluded_paths))
    errors = _exclusion_errors(excluded, raw["head_entries"])
    if errors:
        raise CandidateIdentityError(errors)
    worktree = _Worktree(raw, excluded)
    manifest = worktree.manifest()
    delivered = _Delivered(worktree, manifest)
    errors = delivered.scope_errors(scope_paths) + delivered.link_errors()
    record = {
        "record_type": CANDIDATE_RECORD_TYPE,
        "version": RECORD_VERSION,
        "bead_id": bead_id,
        "baseline": {"version": baseline.get("version"), "digest": baseline.get("digest")},
        "repository": {"root_commits": roots},
        "base_commit": base,
        "commit": raw["head_commit"],
        "tree": raw["head"],
        "delivery_scope": {"paths": sorted(set(scope_paths)), "live_resources": list(live_resources)},
        "excluded_paths": excluded,
        "worktree_manifest": manifest,
        "delivered_modes": delivered.modes_digest(raw["capture_identity"]["root"][2]),
    }
    errors += candidate_errors(record)
    if errors:
        raise CandidateIdentityError(errors)
    return record


def capture_candidate(
    root: Path | str,
    *,
    chain: Mapping[str, Any],
    base_commit: str,
    scope_paths: Sequence[str],
    excluded_paths: Sequence[str] = (),
    live_resources: Sequence[Any] = (),
) -> dict[str, Any]:
    """Identify the candidate in the working tree at ``root`` for the current baseline of ``chain``.

    Returns the candidate identity record without writing to Beads or the inspected
    repository. Capture may create and remove private temporary scratch files.
    Refuses (CandidateIdentityError) when the candidate cannot be identified exactly.
    """
    return _identify(
        root,
        bead_id=chain["bead_id"],
        baseline={"version": chain["version"], "digest": chain["digest"]},
        base_commit=base_commit,
        scope_paths=scope_paths,
        excluded_paths=excluded_paths,
        live_resources=live_resources,
    )


# Verification


def _manifest_differences(recorded: list[dict[str, Any]], current: list[dict[str, Any]]) -> list[str]:
    before = {entry["path"]: entry for entry in recorded}
    after = {entry["path"]: entry for entry in current}
    errors = []
    for path in sorted(set(after) - set(before)):
        errors.append(f"{path} is dirty or untracked now ({after[path]['change']}) but is not in the candidate")
    for path in sorted(set(before) - set(after)):
        errors.append(f"{path} was dirty or untracked in the candidate and is not now")
    for path in sorted(set(before) & set(after)):
        changed = [key for key in MANIFEST_FIELDS if before[path][key] != after[path][key]]
        if changed:
            errors.append(f"{path} changed since the candidate was recorded ({', '.join(changed)})")
    return errors


def verify_candidate(record: Any, root: Path | str) -> list[str]:
    """Every reason the working tree at ``root`` is not exactly the candidate ``record`` names; empty when it is.

    The tree is identified again with the record's own base commit, delivery scope and exclusions, and any
    difference is refused: another repository, commit or tree, a dirty or untracked file added, removed or changed,
    changed permission or special bits on delivered content, a base that is no longer an ancestor, or a scope path
    that is gone.
    """
    errors = candidate_errors(record)
    if errors:
        return errors
    try:
        current = _identify(
            root,
            bead_id=record["bead_id"],
            baseline=record["baseline"],
            base_commit=record["base_commit"],
            scope_paths=record["delivery_scope"]["paths"],
            excluded_paths=record["excluded_paths"],
            live_resources=record["delivery_scope"]["live_resources"],
        )
    except CandidateIdentityError as exc:
        return [f"the candidate cannot be identified again: {error}" for error in exc.errors]
    if candidate_digest(current) == candidate_digest(record):
        return []
    return _record_differences(record, current) or ["the working tree does not match the candidate record"]


def _record_differences(record: Mapping[str, Any], current: Mapping[str, Any]) -> list[str]:
    errors = []
    if current["repository"] != record["repository"]:
        errors.append(
            f"the working tree belongs to another repository (root commits {', '.join(current['repository']['root_commits'])}, "
            f"not {', '.join(record['repository']['root_commits'])})"
        )
    if current["commit"] != record["commit"]:
        errors.append(f"HEAD is {current['commit']}, not the candidate commit {record['commit']}")
    if current["tree"] != record["tree"]:
        errors.append(f"HEAD's tree is {current['tree']}, not the candidate tree {record['tree']}")
    errors += _manifest_differences(record["worktree_manifest"], current["worktree_manifest"])
    if current["delivered_modes"] != record["delivered_modes"]:
        errors.append(
            "the permission or special bits (read, write or execute for user, group or other, setuid, setgid or "
            "sticky) of a delivered file, symlink or directory, or of the repository root, changed since the "
            "candidate was recorded"
        )
    return errors


def baseline_binding_errors(record: Mapping[str, Any], chain: Mapping[str, Any]) -> list[str]:
    """Whether a valid candidate claims the current baseline of ``chain``, for the same Bead."""
    errors = []
    if record["bead_id"] != chain["bead_id"]:
        errors.append(f"the candidate is for Bead {record['bead_id']!r}, not {chain['bead_id']!r}")
    claimed = record["baseline"]
    if (claimed["version"], claimed["digest"]) != (chain["version"], chain["digest"]):
        known = {entry["version"]: entry["digest"] for entry in chain["baselines"]}
        if known.get(claimed["version"]) == claimed["digest"]:
            errors.append(
                f"the candidate was recorded against baseline version {claimed['version']}, but the baseline is now "
                f"version {chain['version']} ({chain['digest']}): it is stale; identify the candidate again against "
                "the current baseline"
            )
        else:
            errors.append(
                f"the candidate claims baseline version {claimed['version']} ({claimed['digest']}), which is not in "
                "this baseline chain"
            )
    return errors


def bead_candidate_errors(bead: Any, record: Mapping[str, Any]) -> list[str]:
    """Every reason the Bead projection ``bead`` does not retain the valid candidate ``record`` as its current one.

    The candidate's reference line must be on the Bead, after the comment recording the baseline version the
    candidate claims, and it must be the most recent candidate reference there: a later one means the claimed
    candidate was superseded. A candidate reference for another Bead, or a malformed or embedded one, is refused.
    This reads the projection only.
    """
    bead_id = record["bead_id"]
    if type(bead) is not dict:
        return ["the Bead projection must be an object"]
    if bead.get("id") != bead_id:
        return [f"the Bead projection is {bead.get('id')!r}, not {bead_id!r}"]
    comments = bead.get("comments")
    if type(comments) is not list:
        return [f"the Bead projection for {bead_id} has no comment list"]
    digest = candidate_digest(record)
    claimed = candidate_reference_line(bead_id, digest)
    found, errors = scan_reference_comments(comments, CANDIDATE_REFERENCE_PREFIX, _CANDIDATE_REFERENCE,
                                            "candidate reference")
    mine = []
    for index, match in found:
        if match["bead"] != bead_id:
            errors.append(f"comment {index} records a candidate for Bead {match['bead']} on {bead_id}")
        elif match.group(0) == claimed:
            mine.append(index)
    if not mine:
        errors.append(f"candidate {digest} is not recorded on {bead_id}")
        return errors
    latest = [(index, match) for index, match in found if match["bead"] == bead_id][-1]
    if latest[1].group(0) != claimed:
        errors.append(
            f"comment {latest[0]} records a later candidate {latest[1]['digest']} on {bead_id}: the claimed candidate "
            f"{digest} is not the current one"
        )
    return errors + _baseline_order_errors(comments, record, digest, max(mine))


def _baseline_order_errors(comments: list[Any], record: Mapping[str, Any], digest: str, latest: int) -> list[str]:
    """The candidate's latest reference must come after the comment recording the baseline version it claims."""
    bead_id = record["bead_id"]
    baseline_line = reference_line(bead_id, record["baseline"]["version"], record["baseline"]["digest"])
    recorded = [index for index, comment in enumerate(comments)
                if type(comment) is dict and type(comment.get("text")) is str and comment["text"].strip() == baseline_line]
    if not recorded:
        return [f"baseline version {record['baseline']['version']}, which the candidate claims, is not recorded "
                f"on {bead_id}"]
    if latest < recorded[0]:
        return [f"candidate {digest} was recorded on {bead_id} before baseline version {record['baseline']['version']} "
                "it claims to satisfy"]
    return []


def check_candidate(
    record: Any,
    *,
    root: Path | str,
    chain: Mapping[str, Any],
    bead: Any,
) -> dict[str, Any]:
    """The complete candidate identity check a closure will need, read-only.

    ``record`` is the candidate identity the closure claims, ``chain`` the resolved requirement baseline chain
    (``requirement_baseline.resolve_chain``) and ``bead`` the Bead projection with comments. Returns ``valid``,
    ``errors``, ``digest`` (the candidate binding, or None) and ``reference_line``. Absence, mismatch and drift are
    all refusals.
    """
    result: dict[str, Any] = {"valid": False, "errors": [], "digest": None, "reference_line": None}
    if record is None:
        result["errors"] = ["no candidate identity was supplied: a closure must name the exact candidate it claims"]
        return result
    errors = candidate_errors(record)
    if errors:
        result["errors"] = errors
        return result
    result["digest"] = candidate_digest(record)
    result["reference_line"] = candidate_reference_line(record["bead_id"], result["digest"])
    errors = baseline_binding_errors(record, chain)
    errors += verify_candidate(record, root)
    if bead is None:
        errors.append(f"no Bead projection was supplied: the candidate must be recorded on {record['bead_id']}")
    else:
        errors += bead_reference_errors(bead, chain)
        errors += bead_candidate_errors(bead, record)
    result["errors"] = errors
    result["valid"] = not errors
    return result


__all__ = [
    "CANDIDATE_RECORD_TYPE",
    "CandidateIdentityError",
    "RequirementBaselineError",
    "baseline_binding_errors",
    "bead_candidate_errors",
    "candidate_binding",
    "candidate_digest",
    "candidate_errors",
    "candidate_reference_line",
    "capture_candidate",
    "check_candidate",
    "verify_candidate",
]
