from __future__ import annotations

import fcntl
import hashlib
import json
import os
import subprocess
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any

from .paths import REPO_ROOT
from .util import artifact_hash


def status_path(line: str) -> str:
    path = line[3:] if len(line) > 3 else line
    if " -> " in path:
        path = path.split(" -> ", 1)[1]
    return path.strip().strip('"')


def tracked_status_map(lines: list[str]) -> dict[str, str]:
    return {status_path(line): line for line in lines if line.strip()}


def capture_tracked_workspace_state(cwd: Path | str = REPO_ROOT, *, include_untracked: bool = False) -> dict[str, Any]:
    root = Path(cwd)
    untracked_flag = "--untracked-files=all" if include_untracked else "--untracked-files=no"
    scope = "tracked-and-untracked" if include_untracked else "tracked"
    result = subprocess.run(
        ["git", "-C", str(root), "status", "--porcelain", untracked_flag],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        return {
            "workspace_state_type": "git-status",
            "version": 1,
            "cwd": str(root),
            "is_git_repo": False,
            "status_scope": scope,
            "include_untracked": bool(include_untracked),
            "error": result.stderr.strip() or result.stdout.strip(),
            "tracked_status": [],
            "tracked_status_sha256": artifact_hash(""),
        }
    lines = sorted(line for line in result.stdout.splitlines() if line.strip())
    fingerprint_lines = list(lines)
    tracked_files = subprocess.run(
        ["git", "-C", str(root), "ls-files", "-z"],
        check=False,
        capture_output=True,
    )
    if tracked_files.returncode == 0:
        fingerprint_lines.extend(
            f"?? {item}" for item in tracked_files.stdout.decode("utf-8", errors="replace").split("\0") if item
        )
    return {
        "workspace_state_type": "git-status",
        "version": 1,
        "cwd": str(root),
        "is_git_repo": True,
        "status_scope": scope,
        "include_untracked": bool(include_untracked),
        "tracked_status": lines,
        "tracked_status_sha256": artifact_hash("\n".join(lines)),
        "content_fingerprints": _content_fingerprints(root, fingerprint_lines, max_files=10000, max_bytes=50_000_000),
        "baseline_complete": True,
        "replay_allowed": False,
    }


def _status_path_value(line: str) -> str:
    return status_path(line)


def _path_matches_scope(path: str, root: Path, allowed_paths: list[str] | tuple[str, ...] | None) -> bool:
    if not allowed_paths:
        return False
    return path_allowed(path, allowed_paths)


def _fingerprint_candidates(
    root: Path,
    status_lines: list[str],
    allowed_paths: list[str] | tuple[str, ...] | None = None,
) -> list[str]:
    resolved_root = root.resolve()
    candidates = {_status_path_value(line) for line in status_lines if line.strip()}
    for raw in allowed_paths or []:
        base = (resolved_root / str(raw)).resolve() if not Path(str(raw)).is_absolute() else Path(str(raw)).resolve()
        try:
            base.relative_to(resolved_root)
        except ValueError:
            continue
        if base.is_file():
            candidates.add(base.relative_to(resolved_root).as_posix())
        elif base.is_dir():
            for path in sorted(base.rglob("*")):
                if path.is_file() and ".git" not in path.relative_to(resolved_root).parts:
                    candidates.add(path.relative_to(resolved_root).as_posix())
    return sorted(candidates)


def _content_fingerprints(
    root: Path,
    status_lines: list[str],
    *,
    allowed_paths: list[str] | tuple[str, ...] | None = None,
    max_files: int = 10000,
    max_bytes: int = 50_000_000,
    max_seconds: float = 5.0,
) -> dict[str, dict[str, Any]]:
    started = time.monotonic()
    candidates = _fingerprint_candidates(root, status_lines, allowed_paths)
    result: dict[str, dict[str, Any]] = {}
    total_bytes = 0
    for relative in sorted(candidates):
        if len(result) >= max_files or time.monotonic() - started > max_seconds:
            break
        path = root / relative
        try:
            resolved = path.resolve()
            resolved.relative_to(root.resolve())
            if not path.is_file() or path.is_symlink():
                continue
            size = path.stat().st_size
            if total_bytes + size > max_bytes:
                break
            digest = hashlib.sha256()
            with path.open("rb") as handle:
                for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                    digest.update(chunk)
            result[relative] = {"sha256": digest.hexdigest(), "size": size}
            total_bytes += size
        except (OSError, ValueError):
            result[relative] = {"sha256": None, "size": None, "error": "unreadable"}
    return result


def capture_workspace_baseline(
    cwd: Path | str = REPO_ROOT,
    *,
    allowed_paths: list[str] | tuple[str, ...] | None = None,
    include_untracked: bool = True,
    max_files: int = 10000,
    max_bytes: int = 50_000_000,
    max_seconds: float = 5.0,
) -> dict[str, Any]:
    """Capture status plus content evidence, retaining pre-existing dirt."""
    root = Path(cwd).resolve()
    state = capture_tracked_workspace_state(root, include_untracked=include_untracked)
    status_lines = list(state.get("tracked_status", []))
    fingerprints = _content_fingerprints(
        root,
        status_lines,
        allowed_paths=allowed_paths,
        max_files=max_files,
        max_bytes=max_bytes,
        max_seconds=max_seconds,
    )
    candidate_count = len(_fingerprint_candidates(root, status_lines, allowed_paths))
    fingerprint_error = any(item.get("error") for item in fingerprints.values())
    incomplete = len(fingerprints) < candidate_count or fingerprint_error
    dirty = sorted(_status_path_value(line) for line in status_lines if line[:2].strip())
    return {
        "workspace_evidence_type": "content-aware-baseline",
        "version": 2,
        "cwd": str(root),
        "allowed_paths": list(allowed_paths or []),
        "include_untracked": bool(include_untracked),
        "tracked_status": status_lines,
        "preexisting_dirty_paths": dirty,
        "content_fingerprints": fingerprints,
        "baseline_complete": not incomplete,
        "incomplete": incomplete,
        "replay_allowed": not incomplete and False,
        "caps": {"max_files": max_files, "max_bytes": max_bytes, "max_seconds": max_seconds},
    }


def _evidence_fingerprints(value: dict[str, Any]) -> dict[str, dict[str, Any]]:
    raw = value.get("content_fingerprints")
    return raw if isinstance(raw, dict) else {}


def compare_workspace_baseline(
    before: dict[str, Any],
    after: dict[str, Any],
    *,
    allowed_paths: list[str] | tuple[str, ...] | None = None,
) -> dict[str, Any]:
    """Compare content and status while separating baseline dirt from mutation."""
    before_status = tracked_status_map(list(before.get("tracked_status", [])))
    after_status = tracked_status_map(list(after.get("tracked_status", [])))
    before_fp = _evidence_fingerprints(before)
    after_fp = _evidence_fingerprints(after)
    paths = sorted(set(before_status) | set(after_status) | set(before_fp) | set(after_fp))
    mutations: list[dict[str, Any]] = []
    unchanged_dirty: list[str] = []
    for path in paths:
        status_changed = before_status.get(path) != after_status.get(path)
        content_changed = before_fp.get(path) != after_fp.get(path)
        baseline_dirty = path in set(before.get("preexisting_dirty_paths", [])) or bool(before_status.get(path, "")[:2].strip())
        if not status_changed and not content_changed:
            if baseline_dirty:
                unchanged_dirty.append(path)
            continue
        if path not in before_fp and path in after_fp:
            category = "untracked" if path not in before_status else "attribution-ambiguous"
        elif not _path_matches_scope(path, Path(str(before.get("cwd", "."))), allowed_paths or before.get("allowed_paths")):
            category = "out-of-scope"
        elif baseline_dirty and not content_changed:
            category = "unchanged-dirty"
        elif before.get("incomplete") or after.get("incomplete"):
            category = "attribution-ambiguous"
        else:
            category = "scoped"
        mutations.append({"path": path, "category": category, "before_status": before_status.get(path), "after_status": after_status.get(path), "content_changed": content_changed})
    categories = {name: sorted(item["path"] for item in mutations if item["category"] == name) for name in ("scoped", "out-of-scope", "untracked", "unchanged-dirty", "attribution-ambiguous")}
    categories["unchanged-dirty"] = sorted(unchanged_dirty)
    unexpected = [item for item in mutations if item["category"] in {"out-of-scope", "untracked", "attribution-ambiguous"}]
    return {
        "workspace_mutation_report_type": "content-aware-diff",
        "version": 2,
        "status_scope": "tracked-and-untracked" if before.get("include_untracked") or after.get("include_untracked") else "tracked",
        "before": before,
        "after": after,
        "allowed_paths": list(allowed_paths or before.get("allowed_paths", [])),
        "mutations": mutations,
        "mutation_categories": categories,
        "unchanged_dirty": unchanged_dirty,
        "mutation_detected": bool(mutations),
        "unexpected_mutation_detected": bool(unexpected),
        "attribution_ambiguous": bool(categories["attribution-ambiguous"]),
        "incomplete": bool(before.get("incomplete") or after.get("incomplete")),
        "replay_allowed": False,
        "changes": [{"path": item["path"], "before": item["before_status"], "after": item["after_status"]} for item in mutations],
        "allowed_mutations": [item for item in mutations if item["category"] == "scoped"],
        "unexpected_mutations": unexpected,
        "reverted": False,
    }


def path_allowed(path: str, allowed_paths: list[str] | tuple[str, ...] | None) -> bool:
    if not allowed_paths:
        return False
    normalized = path.strip().lstrip("./")
    for raw in allowed_paths:
        allowed = str(raw).strip().lstrip("./").rstrip("/")
        if not allowed:
            continue
        if normalized == allowed or normalized.startswith(f"{allowed}/"):
            return True
    return False


def diff_workspace_state(
    before: dict[str, Any],
    after: dict[str, Any],
    *,
    allowed_paths: list[str] | tuple[str, ...] | None = None,
    require_clean: bool = False,
) -> dict[str, Any]:
    if "content_fingerprints" in before or "content_fingerprints" in after:
        report = compare_workspace_baseline(before, after, allowed_paths=allowed_paths)
        if require_clean and before.get("tracked_status"):
            report["unexpected_mutations"] = list(report.get("unexpected_mutations", [])) + [
                {"path": status_path(line), "before": line, "after": line, "category": "unchanged-dirty"}
                for line in list(before.get("tracked_status", []))
            ]
            report["unexpected_mutation_detected"] = True
        return report
    before_map = tracked_status_map(list(before.get("tracked_status", [])))
    after_map = tracked_status_map(list(after.get("tracked_status", [])))
    changes: list[dict[str, str | None]] = []
    for path in sorted(set(before_map) | set(after_map)):
        before_status = before_map.get(path)
        after_status = after_map.get(path)
        if before_status == after_status:
            continue
        changes.append({"path": path, "before": before_status, "after": after_status})
    allowed: list[dict[str, str | None]] = []
    unexpected: list[dict[str, str | None]] = []
    for change in changes:
        target = str(change["path"])
        if path_allowed(target, allowed_paths):
            allowed.append(change)
        else:
            unexpected.append(change)
    if require_clean and before.get("tracked_status"):
        unexpected = [
            {"path": status_path(line), "before": line, "after": line}
            for line in list(before.get("tracked_status", []))
        ] + unexpected
    include_untracked = bool(before.get("include_untracked") or after.get("include_untracked"))
    return {
        "workspace_mutation_report_type": "git-status-diff",
        "version": 1,
        "status_scope": "tracked-and-untracked" if include_untracked else "tracked",
        "include_untracked": include_untracked,
        "before": before,
        "after": after,
        "allowed_paths": list(allowed_paths or []),
        "require_clean": bool(require_clean),
        "changes": changes,
        "allowed_mutations": allowed,
        "unexpected_mutations": unexpected,
        "mutation_detected": bool(changes),
        "unexpected_mutation_detected": bool(unexpected),
        "reverted": False,
    }


class WriteScopeLeaseCollision(RuntimeError):
    """Raised when a requested write scope overlaps an active lease."""


def _lease_registry_paths(workdir: Path) -> tuple[Path, Path]:
    digest = hashlib.sha256(str(workdir.resolve()).encode("utf-8")).hexdigest()
    directory = Path(tempfile.gettempdir()) / "cwo-write-scope-leases"
    return directory / f"{digest}.json", directory / f"{digest}.lock"


def _process_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _load_lease_registry(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise WriteScopeLeaseCollision("write-scope lease registry is unreadable") from exc
    if not isinstance(value, list):
        raise WriteScopeLeaseCollision("write-scope lease registry is malformed")
    entries: list[dict[str, Any]] = []
    for item in value:
        if not isinstance(item, dict):
            raise WriteScopeLeaseCollision("write-scope lease registry is malformed")
        owner = item.get("owner")
        pid = item.get("pid")
        paths = item.get("paths")
        if not isinstance(owner, str) or not isinstance(pid, int) or not isinstance(paths, list) or not all(isinstance(path, str) for path in paths):
            raise WriteScopeLeaseCollision("write-scope lease registry is malformed")
        if _process_alive(pid):
            entries.append({"owner": owner, "pid": pid, "paths": paths})
    return entries


def _write_lease_registry(path: Path, entries: list[dict[str, Any]]) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp")
    try:
        with temporary.open("x", encoding="utf-8") as handle:
            json.dump(entries, handle, sort_keys=True, separators=(",", ":"))
            handle.write("\n")
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


class WriteScopeLease:
    _active: dict[str, tuple[Path, str, tuple[str, ...]]] = {}
    _registries: set[Path] = set()

    def __init__(self, workdir: Path | str, allowed_paths: list[str] | tuple[str, ...], owner: str | None = None):
        self.workdir = Path(workdir).resolve()
        self.allowed_paths = tuple(sorted(_canonical_scope(self.workdir, allowed_paths)))
        self.owner = owner or uuid.uuid4().hex
        self.pid = os.getpid()
        self._acquired = False
        self._registry_path, self._lock_path = _lease_registry_paths(self.workdir)
        self._active_key = f"{self.workdir}:{self.pid}:{self.owner}"

    def acquire(self) -> "WriteScopeLease":
        if self._acquired:
            return self
        self._lock_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with self._lock_path.open("a+", encoding="utf-8") as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
            try:
                entries = _load_lease_registry(self._registry_path)
                for entry in entries:
                    if entry["pid"] == self.pid and entry["owner"] == self.owner:
                        continue
                    if _scopes_overlap(self.allowed_paths, tuple(entry["paths"])):
                        raise WriteScopeLeaseCollision("write-scope lease overlaps an active lease")
                if not any(entry["pid"] == self.pid and entry["owner"] == self.owner for entry in entries):
                    entries.append({"owner": self.owner, "pid": self.pid, "paths": list(self.allowed_paths)})
                _write_lease_registry(self._registry_path, entries)
            finally:
                fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
        self._active[self._active_key] = (self._registry_path, self.owner, self.allowed_paths)
        self._registries.add(self._registry_path)
        self._acquired = True
        return self

    def release(self) -> None:
        if not self._acquired:
            return
        with self._lock_path.open("a+", encoding="utf-8") as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
            try:
                entries = _load_lease_registry(self._registry_path)
                entries = [entry for entry in entries if not (entry["pid"] == self.pid and entry["owner"] == self.owner)]
                _write_lease_registry(self._registry_path, entries)
            finally:
                fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
        self._active.pop(self._active_key, None)
        self._acquired = False

    def __enter__(self) -> "WriteScopeLease":
        return self.acquire()

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        self.release()


def _canonical_scope(workdir: Path, allowed_paths: list[str] | tuple[str, ...]) -> list[str]:
    result: list[str] = []
    root = workdir.resolve()
    for raw in allowed_paths:
        candidate = Path(str(raw))
        resolved = (root / candidate).resolve() if not candidate.is_absolute() else candidate.resolve()
        try:
            relative = resolved.relative_to(root).as_posix()
        except ValueError as exc:
            raise ValueError("write scope is outside workdir") from exc
        result.append(relative or ".")
    return result


def _scopes_overlap(first: tuple[str, ...], second: tuple[str, ...]) -> bool:
    def overlaps(left: str, right: str) -> bool:
        return left == "." or right == "." or left == right or left.startswith(right + "/") or right.startswith(left + "/")
    return any(overlaps(left, right) for left in first for right in second)


def acquire_write_scope_lease(
    workdir: Path | str,
    allowed_paths: list[str] | tuple[str, ...],
    *,
    owner: str | None = None,
) -> WriteScopeLease:
    return WriteScopeLease(workdir, allowed_paths, owner).acquire()


def clear_write_scope_leases() -> None:
    """Remove only current-process lease records; retain other live processes."""
    pid = os.getpid()
    for registry_path in list(WriteScopeLease._registries):
        lock_path = registry_path.with_suffix(".lock")
        lock_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with lock_path.open("a+", encoding="utf-8") as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
            try:
                entries = _load_lease_registry(registry_path)
                _write_lease_registry(registry_path, [entry for entry in entries if entry["pid"] != pid])
            finally:
                fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
    WriteScopeLease._active.clear()
