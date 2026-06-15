from __future__ import annotations

import subprocess
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
    return {
        "workspace_state_type": "git-status",
        "version": 1,
        "cwd": str(root),
        "is_git_repo": True,
        "status_scope": scope,
        "include_untracked": bool(include_untracked),
        "tracked_status": lines,
        "tracked_status_sha256": artifact_hash("\n".join(lines)),
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
