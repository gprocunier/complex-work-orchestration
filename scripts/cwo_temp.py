#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import shutil
import sys
import time
from pathlib import Path
from typing import Any

from cwo_core.paths import (
    CWO_EXCHANGE_DIR_NAME,
    cwo_session_id,
    cwo_temp_dir,
    cwo_temp_path,
    cwo_temp_root,
    cwo_user_name,
)


def parse_duration_seconds(value: str) -> int:
    text = value.strip().lower()
    if not text:
        raise argparse.ArgumentTypeError("duration must not be empty")
    multiplier = 1
    if text[-1] in {"s", "m", "h", "d"}:
        unit = text[-1]
        text = text[:-1]
        multiplier = {"s": 1, "m": 60, "h": 3600, "d": 86400}[unit]
    try:
        amount = float(text)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid duration: {value}") from exc
    seconds = int(amount * multiplier)
    if seconds < 0:
        raise argparse.ArgumentTypeError("duration must be non-negative")
    return seconds


def _entry_kind(path: Path) -> str:
    if path.is_symlink():
        return "symlink"
    if path.is_dir():
        return "directory"
    if path.is_file():
        return "file"
    return "other"


def _delete_path(path: Path) -> None:
    if path.is_symlink():
        raise SystemExit(f"refusing to delete symlinked CWO temp artifact: {path}")
    if path.is_dir():
        shutil.rmtree(path)
    else:
        path.unlink()


def _session_candidates(root: Path) -> list[Path]:
    if not root.exists():
        return []
    if root.is_symlink() or not root.is_dir():
        raise SystemExit(f"refusing unsafe CWO temp root: {root}")
    user_prefix = f"cwo-{cwo_user_name()}-"
    return [
        path
        for path in sorted(root.iterdir(), key=lambda candidate: candidate.name)
        if path.name.startswith(user_prefix) and path.name != CWO_EXCHANGE_DIR_NAME
    ]


def _exchange_candidates(root: Path) -> list[Path]:
    if not root.exists():
        return []
    if root.is_symlink() or not root.is_dir():
        raise SystemExit(f"refusing unsafe CWO exchange root: {root}")
    return [path for path in sorted(root.iterdir(), key=lambda candidate: candidate.name) if path.name.startswith("cwo-")]


def cleanup_cwo_temp(
    *,
    scope: str = "all",
    older_than_seconds: int = 48 * 3600,
    force: bool = False,
    include_current_session: bool = False,
    now: float | None = None,
) -> dict[str, Any]:
    timestamp = time.time() if now is None else now
    current_session_dir = cwo_temp_dir(scope="session", create=False)
    roots: dict[str, str] = {}
    actions: list[dict[str, Any]] = []

    def consider(path: Path, *, candidate_scope: str) -> None:
        kind = _entry_kind(path)
        if kind == "symlink":
            actions.append({"action": "skip-symlink", "scope": candidate_scope, "path": str(path), "kind": kind})
            return
        try:
            age_seconds = int(timestamp - path.stat().st_mtime)
        except FileNotFoundError:
            return
        if age_seconds < older_than_seconds:
            actions.append(
                {
                    "action": "keep",
                    "scope": candidate_scope,
                    "path": str(path),
                    "kind": kind,
                    "age_seconds": age_seconds,
                }
            )
            return
        if not include_current_session and candidate_scope == "session" and path.resolve() == current_session_dir.resolve():
            actions.append(
                {
                    "action": "protect-current-session",
                    "scope": candidate_scope,
                    "path": str(path),
                    "kind": kind,
                    "age_seconds": age_seconds,
                }
            )
            return
        action = "delete" if force else "would-delete"
        actions.append(
            action_record := {
                "action": action,
                "scope": candidate_scope,
                "path": str(path),
                "kind": kind,
                "age_seconds": age_seconds,
            }
        )
        if force:
            try:
                _delete_path(path)
            except (FileNotFoundError, PermissionError, OSError) as exc:
                action_record["action"] = "delete-failed"
                action_record["error"] = f"{exc.__class__.__name__}: {exc}"

    if scope in {"all", "session"}:
        session_root = cwo_temp_root(create=False)
        roots["session"] = str(session_root)
        for candidate in _session_candidates(session_root):
            consider(candidate, candidate_scope="session")
    if scope in {"all", "exchange"}:
        exchange_root = cwo_temp_dir(scope="exchange", create=False)
        roots["exchange"] = str(exchange_root)
        for candidate in _exchange_candidates(exchange_root):
            consider(candidate, candidate_scope="exchange")

    summary: dict[str, int] = {}
    for action in actions:
        key = str(action["action"]).replace("-", "_")
        summary[key] = summary.get(key, 0) + 1
    return {
        "cleanup_result_type": "cwo-temp-cleanup",
        "dry_run": not force,
        "force": force,
        "scope": scope,
        "older_than_seconds": older_than_seconds,
        "include_current_session": include_current_session,
        "current_session_id": cwo_session_id(),
        "roots": roots,
        "actions": actions,
        "summary": summary,
    }


def render_human_cleanup(result: dict[str, Any]) -> str:
    lines = [
        f"CWO temp cleanup ({'dry-run' if result['dry_run'] else 'force'})",
        f"scope={result['scope']} older_than_seconds={result['older_than_seconds']}",
    ]
    for action in result["actions"]:
        age = action.get("age_seconds")
        age_text = f" age={age}s" if age is not None else ""
        lines.append(f"- {action['action']} {action['scope']} {action['kind']} {action['path']}{age_text}")
    if not result["actions"]:
        lines.append("- no matching CWO temp artifacts")
    lines.append("summary=" + json.dumps(result["summary"], sort_keys=True))
    return "\n".join(lines)


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Create and clean CWO-owned ephemeral artifact paths.")
    subcommands = parser.add_subparsers(dest="command", required=True)

    dir_parser = subcommands.add_parser("dir", help="Print a CWO temp directory path.")
    dir_parser.add_argument("--scope", choices=["session", "exchange"], default="session")
    dir_parser.add_argument("--purpose")
    dir_parser.add_argument("--no-create", action="store_true", help="Print without creating the directory.")

    path_parser = subcommands.add_parser("path", help="Print a path under a CWO temp directory.")
    path_parser.add_argument("--name", required=True)
    path_parser.add_argument("--scope", choices=["session", "exchange"], default="session")
    path_parser.add_argument("--purpose")
    path_parser.add_argument("--no-create-parent", action="store_true")

    cleanup_parser = subcommands.add_parser("cleanup", help="List or delete stale CWO temp artifacts.")
    cleanup_parser.add_argument("--scope", choices=["all", "session", "exchange"], default="all")
    cleanup_parser.add_argument("--older-than", type=parse_duration_seconds, default=48 * 3600)
    cleanup_parser.add_argument("--force", action="store_true", help="Delete eligible artifacts. Default is dry-run.")
    cleanup_parser.add_argument("--include-current-session", action="store_true")
    cleanup_parser.add_argument("--json", action="store_true")

    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    if args.command == "dir":
        print(cwo_temp_dir(scope=args.scope, purpose=args.purpose, create=not args.no_create))
        return 0
    if args.command == "path":
        print(
            cwo_temp_path(
                args.name,
                scope=args.scope,
                purpose=args.purpose,
                create_parent=not args.no_create_parent,
            )
        )
        return 0
    if args.command == "cleanup":
        result = cleanup_cwo_temp(
            scope=args.scope,
            older_than_seconds=args.older_than,
            force=args.force,
            include_current_session=args.include_current_session,
        )
        if args.json:
            print(json.dumps(result, indent=2, sort_keys=True))
        else:
            print(render_human_cleanup(result))
        return 0
    raise AssertionError(args.command)


if __name__ == "__main__":
    raise SystemExit(main())
