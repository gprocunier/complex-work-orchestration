from __future__ import annotations

import bisect
import fcntl
import hashlib
import json
import os
import tempfile
import uuid
from pathlib import Path
from typing import Any

from .path_contract import path_components, path_within
from .paths import REPO_ROOT
from .util import artifact_hash
from .workspace_capture import INDEX_MODES, WorkspaceDiscoveryError, capture as _capture, worktree_top_level
from .workspace_transition import compare_git_metadata, mutation_is_allowed, unexpected_mutations
from .workspace_transition import metadata_category as metadata_category


FINGERPRINT_EXCLUDED_PARTS = frozenset(
    {
        ".git",
        ".beads",
        ".orchestration-audit",
        "__pycache__",
        ".ruff_cache",
        ".pytest_cache",
        ".mypy_cache",
    }
)
EVIDENCE_VERSION = 3
# Whole-worktree state checks use these caps; baselines take the caller's.
STATE_CAPS = {"max_files": 100_000, "max_bytes": 500_000_000, "max_seconds": 30.0, "max_entries": 500_000}


class WorkspaceInspectionError(RuntimeError):
    """Inert inspection could not produce complete evidence."""


def status_path(line: str) -> str:
    """Path from a version-3 status line: two status characters, a space, the exact name."""
    return line[3:] if len(line) > 3 else line


def legacy_status_path(line: str) -> str:
    """Path from a recorded version 1/2 ``git status --porcelain`` line."""
    path = line[3:] if len(line) > 3 else line
    if " -> " in path:
        path = path.split(" -> ", 1)[1]
    return path.strip().strip('"')


def tracked_status_map(lines: list[str], *, legacy: bool = False) -> dict[str, str]:
    parse = legacy_status_path if legacy else status_path
    return {parse(line): line for line in lines if line.strip()}


def _evidence_is_legacy(evidence: dict[str, Any]) -> bool:
    try:
        return int(evidence.get("evidence_version", 0) or 0) < EVIDENCE_VERSION
    except (TypeError, ValueError):
        return True


def _excluded(path: str) -> bool:
    parts = path_components(path)
    return parts is None or any(part in FINGERPRINT_EXCLUDED_PARTS for part in parts)


def _entries_cap(max_files: int) -> int:
    return max(200_000, 20 * int(max_files))


def _failed_evidence(root: Path, raw: dict[str, Any], **fields: Any) -> dict[str, Any]:
    """Evidence for a capture that failed: never complete, never clean."""
    return {
        **fields,
        "evidence_version": EVIDENCE_VERSION,
        "capture_method": "index-manifest-raw-inventory",
        "cwd": str(root),
        "is_git_repo": False,
        "error": raw.get("error"),
        "error_kind": raw.get("error_kind"),
        "incomplete_reasons": list(raw.get("incomplete_reasons", [])),
        "tracked_status": [],
        "tracked_status_sha256": artifact_hash(""),
        "content_fingerprints": {},
        "raw_inventory": {},
        "incomplete": True,
        "baseline_complete": False,
        "replay_allowed": False,
    }


def _tracked_scope_inventory(
    raw: dict[str, Any], allowed_paths: list[str] | tuple[str, ...] | None
) -> dict[str, str]:
    """The inventory kept without untracked status: tracked entries, every
    entry on or under a declared path, and the entries above both, so a mode
    change or removal of an ancestor is still observed.

    No ancestor path is built. An inventoried entry lies above a tracked or
    declared path exactly when, in the sorted list of those paths, the first
    one not before the entry's name and a slash begins with them, so each
    entry costs one search over references to paths the capture already
    charged, however deep the paths are.
    """
    tracked = {entry[3] for entry in raw["index_entries"]}
    below = sorted(
        {path for path in tracked if path_components(path) is not None}
        | {"/".join(parts) for declared in allowed_paths or () if (parts := path_components(declared)) is not None}
    )
    kept: dict[str, str] = {}
    for path, value in raw["raw_inventory"].items():
        if path in tracked or path_within(path, allowed_paths):
            kept[path] = value
            continue
        prefix = path + "/"
        position = bisect.bisect_left(below, prefix)
        if position < len(below) and below[position].startswith(prefix):
            kept[path] = value
    return kept


def _capture_fields(
    raw: dict[str, Any], include_untracked: bool = True, allowed_paths: list[str] | tuple[str, ...] | None = None
) -> dict[str, Any]:
    # With untracked status the whole inventory is kept, and nothing is selected.
    inventory = raw["raw_inventory"] if include_untracked else _tracked_scope_inventory(raw, allowed_paths)
    return {
        "capture_method": "index-manifest-raw-inventory",
        "git_executable": raw["git_executable"],
        "capture_identity": raw["capture_identity"],
        "object_format": raw["object_format"],
        "head": raw["head"],
        "head_manifest_sha256": raw["head_manifest_sha256"],
        "index_entries": raw["index_entries"],
        "index_manifest_sha256": artifact_hash(json.dumps(raw["index_entries"], sort_keys=True)),
        "raw_inventory": inventory,
        "ignored_directories": raw["ignored_directories"],
        "sparse_directories": raw["sparse_directories"],
        "normalization_sources": raw["normalization_sources"],
        "git_cleanliness": raw["git_cleanliness"],
        "git_metadata": raw["metadata"],
        "incomplete_reasons": list(raw["incomplete_reasons"]),
    }


def _status_lines(raw: dict[str, Any], include_untracked: bool) -> list[str]:
    return [line for line in raw["status_lines"] if include_untracked or not line.startswith("?? ")]


def capture_tracked_workspace_state(
    cwd: Path | str = REPO_ROOT,
    *,
    include_untracked: bool = False,
    include_content_fingerprints: bool = True,
) -> dict[str, Any]:
    """Inert capture of a whole worktree; see ``cwo_core.workspace_capture``."""
    root = Path(cwd)
    scope = "tracked-and-untracked" if include_untracked else "tracked"
    raw = _capture(root, **STATE_CAPS, excluded_parts=FINGERPRINT_EXCLUDED_PARTS)
    common = {"workspace_state_type": "git-status", "version": 1, "status_scope": scope, "include_untracked": bool(include_untracked)}
    if raw.get("error"):
        return _failed_evidence(root, raw, **common)
    lines = _status_lines(raw, include_untracked)
    fingerprints: dict[str, dict[str, Any]] = {}
    candidates: list[str] = []
    if include_content_fingerprints:
        # Skip-worktree entries are intentionally absent and gitlinks are
        # opaque; a materialized skip-worktree file appears in the inventory.
        indexed = {
            entry[3]
            for entry in raw["index_entries"]
            if entry[4] != "S" and INDEX_MODES.get(entry[0]) not in {"sparse-directory", "gitlink"}
        }
        candidates = sorted(path for path in indexed | {status_path(line) for line in lines} if not _excluded(path))
        fingerprints = _content_fingerprints(root, lines, candidates=candidates, capture=raw)
    incomplete = not raw["complete"] or len(fingerprints) < len(candidates) or any(item.get("error") for item in fingerprints.values())
    return {
        **common,
        "evidence_version": EVIDENCE_VERSION,
        "cwd": str(root),
        "is_git_repo": True,
        "tracked_status": lines,
        "tracked_status_sha256": artifact_hash("\n".join(lines)),
        **_capture_fields(raw, include_untracked),
        "content_fingerprints": fingerprints,
        "incomplete": incomplete,
        "baseline_complete": not incomplete,
        "replay_allowed": False,
    }


def workspace_is_clean(root: Path | str, *, include_untracked: bool) -> bool:
    """True only for a complete inert capture with no status lines and no unknown conversions.

    Raw equality with the index establishes Git cleanliness only when no
    filter, text, eol, ident or encoding attribute and no line-ending setting
    applies; otherwise Git may see a change raw bytes do not show.
    """
    state = capture_tracked_workspace_state(root, include_untracked=include_untracked, include_content_fingerprints=False)
    return (
        not state.get("error")
        and not state.get("incomplete")
        and not state.get("tracked_status")
        and state.get("git_cleanliness") == "raw-equals-git"
    )


def worktree_state_digest(cwd: Path | str) -> tuple[str, str | None]:
    """("available", digest) for the worktree containing ``cwd``, or ("unavailable-not-git", None).

    Raises WorkspaceInspectionError when the inspection itself fails.
    """
    try:
        top = worktree_top_level(cwd)
    except WorkspaceDiscoveryError as exc:
        raise WorkspaceInspectionError(str(exc)) from exc
    if top is None:
        return "unavailable-not-git", None
    state = capture_tracked_workspace_state(Path(top), include_untracked=True, include_content_fingerprints=False)
    if state.get("error") or state.get("incomplete"):
        raise WorkspaceInspectionError(state.get("error") or "; ".join(state.get("incomplete_reasons", [])))
    return "available", artifact_hash(json.dumps(
        {
            "status": state["tracked_status"],
            "inventory": state["raw_inventory"],
            "index": state["index_manifest_sha256"],
            "head": [state["head"], state["head_manifest_sha256"]],
            "identity": state["capture_identity"],
            "metadata": state["git_metadata"]["entries"],
        },
        sort_keys=True,
    ))


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
    *,
    capture: dict[str, Any] | None = None,
) -> list[str]:
    """Dirty paths, every inventoried entry inside the declared paths, and skip-worktree entries."""
    raw = capture if capture is not None else _capture(root, **STATE_CAPS, allowed_paths=tuple(allowed_paths or ()), excluded_parts=FINGERPRINT_EXCLUDED_PARTS)
    candidates = {status_path(line) for line in status_lines if line.strip()}
    candidates |= {
        path
        for path, value in raw.get("raw_inventory", {}).items()
        if path_within(path, allowed_paths) and not value.startswith(("directory:", "gitlink:"))
    }
    candidates |= {entry[3] for entry in raw.get("index_entries", []) if entry[4] == "S"}
    # Excluded names (caches, CWO state) are skipped only off the declared paths.
    return sorted(path for path in candidates if not _excluded(path) or path_within(path, allowed_paths))


def _tracked_file_paths(capture: dict[str, Any]) -> tuple[list[str], bool]:
    """Tracked paths from the captured index; incomplete when conflict stages exist."""
    entries = capture.get("index_entries", [])
    paths = sorted({entry[3] for entry in entries if not _excluded(entry[3])})
    unmerged = any(entry[2] != 0 for entry in entries)
    return paths, bool(capture.get("complete")) and not unmerged


def _content_fingerprints(
    root: Path,
    status_lines: list[str],
    *,
    allowed_paths: list[str] | tuple[str, ...] | None = None,
    candidates: list[str] | tuple[str, ...] | None = None,
    max_files: int = 10000,
    max_bytes: int = 50_000_000,
    max_seconds: float = 5.0,
    capture: dict[str, Any] | None = None,
) -> dict[str, dict[str, Any]]:
    """Fingerprints derived from the capture's inventory; nothing is read twice."""
    raw = capture if capture is not None else _capture(root, max_files=max_files, max_bytes=max_bytes, max_seconds=max_seconds, max_entries=_entries_cap(max_files), allowed_paths=tuple(allowed_paths or ()), excluded_parts=FINGERPRINT_EXCLUDED_PARTS)
    selected = list(candidates) if candidates is not None else _fingerprint_candidates(root, status_lines, allowed_paths, capture=raw)
    inventory = raw.get("raw_inventory", {})
    result: dict[str, dict[str, Any]] = {}
    for relative in sorted(selected):
        entry = inventory.get(relative)
        if entry is None:
            # Absence is evidence (a deletion, or an intentionally absent
            # skip-worktree entry), not a failed read.
            result[relative] = {"sha256": None, "size": None, "absent": True}
            continue
        kind, _, size, content = entry.split(":", 3)
        if kind == "symlink":
            result[relative] = {"kind": "symlink", "sha256": content, "size": int(size)}
        elif kind == "file":
            result[relative] = {"sha256": content, "size": int(size)}
        else:
            result[relative] = {"sha256": None, "size": None, "error": "unsupported-file-type"}
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
    """Capture status, inventory and content evidence, retaining pre-existing dirt.

    One budget (``max_files`` hashed files, ``max_bytes``, ``max_seconds``)
    covers the whole capture. Exhaustion or any failure is incomplete.
    """
    caps = {"max_files": max_files, "max_bytes": max_bytes, "max_seconds": max_seconds}
    common = {"workspace_evidence_type": "content-aware-baseline", "version": 2, "allowed_paths": list(allowed_paths or []),
              "include_untracked": bool(include_untracked), "caps": caps}
    try:
        root = Path(cwd).resolve()
    except (OSError, RuntimeError, ValueError) as exc:
        # RecursionError (a RuntimeError) for a long symlink chain on Python 3.12, ValueError for a NUL.
        message = f"workspace path cannot be resolved: {type(exc).__name__}: {exc}"
        failed = _failed_evidence(Path(cwd), {"error": message, "error_kind": "repository-unqualified",
                                              "incomplete_reasons": [message]}, **common)
        failed.update(tracked_paths=[], tracked_paths_complete=False, preexisting_dirty_paths=[])
        return failed
    raw = _capture(root, **caps, max_entries=_entries_cap(max_files), allowed_paths=tuple(allowed_paths or ()), excluded_parts=FINGERPRINT_EXCLUDED_PARTS)
    if raw.get("error"):
        failed = _failed_evidence(root, raw, **common)
        failed.update(tracked_paths=[], tracked_paths_complete=False, preexisting_dirty_paths=[])
        return failed
    status_lines = _status_lines(raw, include_untracked)
    candidates = _fingerprint_candidates(root, status_lines, allowed_paths, capture=raw)
    tracked_paths, tracked_paths_complete = _tracked_file_paths(raw)
    fingerprints = _content_fingerprints(
        root,
        status_lines,
        allowed_paths=allowed_paths,
        candidates=candidates,
        max_files=max_files,
        max_bytes=max_bytes,
        max_seconds=max_seconds,
        capture=raw,
    )
    incomplete = (
        not raw["complete"]
        or len(fingerprints) < len(candidates)
        or any(item.get("error") for item in fingerprints.values())
        or not tracked_paths_complete
    )
    dirty = sorted(_status_path_value(line) for line in status_lines if line[:2].strip())
    return {
        **common,
        "evidence_version": EVIDENCE_VERSION,
        "cwd": str(root),
        "is_git_repo": True,
        "tracked_status": status_lines,
        "tracked_paths": tracked_paths,
        "tracked_paths_complete": tracked_paths_complete,
        "preexisting_dirty_paths": dirty,
        "content_fingerprints": fingerprints,
        **_capture_fields(raw, include_untracked, allowed_paths),
        "baseline_complete": not incomplete,
        "incomplete": incomplete,
        "replay_allowed": False,
    }


def _evidence_fingerprints(value: dict[str, Any]) -> dict[str, dict[str, Any]]:
    raw = value.get("content_fingerprints")
    return raw if isinstance(raw, dict) else {}


def _index_map(evidence: dict[str, Any]) -> dict[tuple[str, int], tuple[Any, ...]]:
    """Index entries keyed by (path, stage), so conflict stages stay distinct."""
    result: dict[tuple[str, int], tuple[Any, ...]] = {}
    for entry in evidence.get("index_entries") or []:
        if isinstance(entry, list) and len(entry) == 5:
            mode, object_id, stage, path, tag = entry
            result[(path, stage)] = (mode, object_id, tag)
    return result


def _creates_scope_ancestor(
    path: str,
    before_inventory: dict[str, str] | None,
    after_inventory: dict[str, str] | None,
    allowed_paths: list[str] | tuple[str, ...] | None,
) -> bool:
    """A new directory on the way to a declared path is part of writing that path.

    Only creation counts; changing or removing an existing ancestor stays out
    of scope.
    """
    if before_inventory is None or after_inventory is None or path in before_inventory:
        return False
    if not str(after_inventory.get(path, "")).startswith("directory:"):
        return False
    return any(path_within(str(allowed), [path]) for allowed in allowed_paths or ())


def _evidence_incomplete(evidence: dict[str, Any]) -> bool:
    return bool(evidence.get("error") or evidence.get("incomplete") or not evidence.get("is_git_repo", True))


def compare_workspace_baseline(
    before: dict[str, Any],
    after: dict[str, Any],
    *,
    allowed_paths: list[str] | tuple[str, ...] | None = None,
    expected_git_transition: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Compare status, index, raw inventory, content and Git metadata.

    A failed or incomplete capture on either side makes the report incomplete
    and unexpected, whatever else it shows.
    """
    before_status = tracked_status_map(list(before.get("tracked_status", [])), legacy=_evidence_is_legacy(before))
    after_status = tracked_status_map(list(after.get("tracked_status", [])), legacy=_evidence_is_legacy(after))
    before_index = _index_map(before)
    after_index = _index_map(after)
    index_changed_paths = {
        key[0] for key in set(before_index) | set(after_index) if before_index.get(key) != after_index.get(key)
    } if before.get("index_entries") is not None and after.get("index_entries") is not None else set()
    before_inventory = before.get("raw_inventory") if isinstance(before.get("raw_inventory"), dict) else None
    after_inventory = after.get("raw_inventory") if isinstance(after.get("raw_inventory"), dict) else None
    inventory_changed_paths = {
        path for path in set(before_inventory) | set(after_inventory) if before_inventory.get(path) != after_inventory.get(path)
    } if before_inventory is not None and after_inventory is not None else set()
    before_fp = _evidence_fingerprints(before)
    after_fp = _evidence_fingerprints(after)
    before_tracked = set(before.get("tracked_paths", []))
    paths = sorted(set(before_status) | set(after_status) | set(before_fp) | set(after_fp) | index_changed_paths | inventory_changed_paths)
    # Built once, not once per path (which was quadratic in the number of paths).
    preexisting_dirty = set(before.get("preexisting_dirty_paths", []))
    mutations: list[dict[str, Any]] = []
    unchanged_dirty: list[str] = []
    for path in paths:
        status_changed = before_status.get(path) != after_status.get(path) or path in index_changed_paths
        content_changed = before_fp.get(path) != after_fp.get(path) or path in inventory_changed_paths
        baseline_dirty = path in preexisting_dirty or bool(before_status.get(path, "")[:2].strip())
        if not status_changed and not content_changed:
            if baseline_dirty:
                unchanged_dirty.append(path)
            continue
        scope = allowed_paths or before.get("allowed_paths")
        in_scope = _path_matches_scope(path, Path(str(before.get("cwd", "."))), scope)
        if not in_scope and _creates_scope_ancestor(path, before_inventory, after_inventory, scope):
            in_scope = True
        if path not in before_fp and path in after_fp:
            # A declared output may legitimately be absent from the baseline.
            # Classify ownership before treating a newly fingerprinted path as
            # an undeclared creation.  New paths outside the declared scope
            # remain fail-closed.
            if in_scope:
                category = "scoped"
            elif path in before_tracked:
                category = "out-of-scope"
            elif before.get("tracked_paths_complete") is True:
                category = "untracked"
            else:
                category = "attribution-ambiguous"
        elif not in_scope:
            category = "out-of-scope"
        elif baseline_dirty and not content_changed:
            category = "unchanged-dirty"
        elif before.get("incomplete") or after.get("incomplete"):
            category = "attribution-ambiguous"
        else:
            category = "scoped"
        mutations.append({"path": path, "category": category, "before_status": before_status.get(path), "after_status": after_status.get(path), "content_changed": content_changed})
    transition = compare_git_metadata(before, after, expected_git_transition)
    metadata_changes = transition["changes"]
    for change in metadata_changes:
        mutations.append({"path": change["path"], "category": change["category"], "authorization": change["authorization"], "metadata_kind": change["metadata_kind"], "metadata_scope": change["metadata_scope"], "before_status": change["before"], "after_status": change["after"], "content_changed": True})
    categories = {name: sorted(item["path"] for item in mutations if item["category"] == name) for name in ("scoped", "out-of-scope", "untracked", "unchanged-dirty", "attribution-ambiguous", "git-metadata", "git-refs")}
    categories["unchanged-dirty"] = sorted(unchanged_dirty)
    unexpected = unexpected_mutations(mutations, transition)
    incomplete = transition["incomplete"]
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
        "unexpected_mutation_detected": bool(unexpected) or incomplete,
        "attribution_ambiguous": bool(categories["attribution-ambiguous"]),
        "git_metadata_changes": metadata_changes,
        "expected_git_transition": transition["record"],
        "git_transition_classifications": transition["classifications"],
        "git_metadata_capture_complete": not transition["incomplete"],
        "incomplete": incomplete,
        "capture_failed": bool(before.get("error") or after.get("error")),
        "replay_allowed": False,
        "changes": [{"path": item["path"], "before": item["before_status"], "after": item["after_status"]} for item in mutations],
        "allowed_mutations": [item for item in mutations if mutation_is_allowed(item)],
        "unexpected_mutations": unexpected,
        "reverted": False,
    }


def path_allowed(path: str, allowed_paths: list[str] | tuple[str, ...] | None) -> bool:
    """Component-wise scope check; see ``cwo_core.path_contract``."""
    return path_within(path, allowed_paths)


_UNKNOWN_CLEANLINESS = {"path": ".", "before": None, "after": None, "category": "cleanliness-unknown"}


def cleanliness_established(evidence: dict[str, Any]) -> bool:
    """Version 3 evidence must say raw equality is Git cleanliness; older records came from git status."""
    if _evidence_is_legacy(evidence):
        return True
    return evidence.get("git_cleanliness") == "raw-equals-git"


_cleanliness_established = cleanliness_established


def diff_workspace_state(
    before: dict[str, Any],
    after: dict[str, Any],
    *,
    allowed_paths: list[str] | tuple[str, ...] | None = None,
    require_clean: bool = False,
    expected_git_transition: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if "content_fingerprints" in before or "content_fingerprints" in after:
        report = compare_workspace_baseline(before, after, allowed_paths=allowed_paths, expected_git_transition=expected_git_transition)
        if require_clean and before.get("tracked_status"):
            report["unexpected_mutations"] = list(report.get("unexpected_mutations", [])) + [
                {"path": status_path(line), "before": line, "after": line, "category": "unchanged-dirty"}
                for line in list(before.get("tracked_status", []))
            ]
            report["unexpected_mutation_detected"] = True
        if require_clean and not _cleanliness_established(before):
            report["unexpected_mutations"] = list(report.get("unexpected_mutations", [])) + [_UNKNOWN_CLEANLINESS]
            report["unexpected_mutation_detected"] = True
        return report
    before_map = tracked_status_map(list(before.get("tracked_status", [])), legacy=_evidence_is_legacy(before))
    after_map = tracked_status_map(list(after.get("tracked_status", [])), legacy=_evidence_is_legacy(after))
    changes: list[dict[str, Any]] = []
    for path in sorted(set(before_map) | set(after_map)):
        before_status = before_map.get(path)
        after_status = after_map.get(path)
        if before_status == after_status:
            continue
        changes.append({"path": path, "before": before_status, "after": after_status})
    allowed: list[dict[str, Any]] = []
    unexpected: list[dict[str, Any]] = []
    for change in changes:
        target = str(change["path"])
        if path_allowed(target, allowed_paths):
            allowed.append(change)
        else:
            unexpected.append(change)
    transition = compare_git_metadata(before, after, expected_git_transition)
    changes.extend(transition["changes"])
    allowed.extend(filter(mutation_is_allowed, transition["changes"]))
    unexpected.extend(unexpected_mutations(transition["changes"], transition))
    incomplete = transition["incomplete"]
    if incomplete:
        unexpected.append({"path": ".", "before": before.get("error"), "after": after.get("error"), "category": "capture-incomplete"})
    if require_clean and before.get("tracked_status"):
        unexpected = [
            {"path": status_path(line), "before": line, "after": line}
            for line in list(before.get("tracked_status", []))
        ] + unexpected
    if require_clean and not _cleanliness_established(before):
        unexpected.append(_UNKNOWN_CLEANLINESS)
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
        "incomplete": incomplete,
        "git_metadata_changes": transition["changes"],
        "expected_git_transition": transition["record"],
        "git_transition_classifications": transition["classifications"],
        "git_metadata_capture_complete": not transition["incomplete"],
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
