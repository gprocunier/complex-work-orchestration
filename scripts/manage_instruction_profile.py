"""Install, verify, or remove CWO instruction profiles."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path
from shlex import quote

REPO_ROOT = Path(__file__).resolve().parents[1]
PROFILE_NAME = "cwo-architect"
PROMPT_FILENAME = "cwo-architect.md"
LAUNCHER_NAME = "cwo-codex"


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _managed_files(
    source_root: Path, codex_home: Path, launcher_dir: Path,
) -> dict[str, tuple[Path, bytes, bool]]:
    prompt_source = source_root / "prompts" / PROMPT_FILENAME
    launcher_source = source_root / "scripts" / LAUNCHER_NAME
    for source in (prompt_source, launcher_source, launcher_source.with_name("launch_architect.py")):
        if not source.is_file():
            raise ValueError(f"missing profile source: {source}")

    prompt = codex_home / "prompts" / PROMPT_FILENAME
    target = json.dumps(str(prompt.resolve()), ensure_ascii=False)
    profile = f"model_instructions_file = {target}\n"
    launcher = f'#!/usr/bin/env sh\nset -eu\n\nexec sh {quote(str(launcher_source))} "$@"\n'
    return {
        "prompt": (prompt, prompt_source.read_bytes(), False),
        "profile": (codex_home / f"{PROFILE_NAME}.config.toml", profile.encode(), False),
        "launcher": (launcher_dir / LAUNCHER_NAME, launcher.encode(), True),
    }


def _write_exact(path: Path, data: bytes, *, force: bool, executable: bool = False) -> str:
    if path.exists():
        current = path.read_bytes()
        mode_ok = not executable or bool(path.stat().st_mode & 0o111)
        if current == data and mode_ok:
            return "unchanged"
        if not force:
            raise ValueError(f"refusing to overwrite modified file: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    temporary.write_bytes(data)
    if executable:
        temporary.chmod(0o755)
    temporary.replace(path)
    return "installed"


def install(source_root: Path, codex_home: Path, launcher_dir: Path, *, force: bool) -> dict:
    managed = _managed_files(source_root, codex_home, launcher_dir)
    files = []
    for path, data, executable in managed.values():
        status = _write_exact(path, data, force=force, executable=executable)
        files.append({"path": str(path), "status": status, "sha256": _sha256(data)})
    return {"action": "install", "profiles": ["architect"], "files": files, "default_profile_changed": False}


def verify(source_root: Path, codex_home: Path, launcher_dir: Path) -> dict:
    managed = _managed_files(source_root, codex_home, launcher_dir)
    checks: list[dict[str, object]] = []
    for path, expected, must_be_executable in managed.values():
        actual = path.read_bytes() if path.is_file() else None
        check: dict[str, object] = {
            "path": str(path),
            "ok": actual == expected,
            "expected_sha256": _sha256(expected),
            "actual_sha256": _sha256(actual) if actual is not None else None,
        }
        if must_be_executable:
            executable = actual is not None and bool(path.stat().st_mode & 0o111)
            check["executable"] = executable
            check["ok"] = check["ok"] and executable
        checks.append(check)
    return {
        "action": "verify", "profiles": ["architect"], "ok": all(item["ok"] for item in checks),
        "checks": checks, "default_profile_changed": False,
    }


def _remove_exact(path: Path, expected: bytes, *, force: bool) -> str:
    if not path.exists():
        return "absent"
    if path.read_bytes() != expected and not force:
        raise ValueError(f"refusing to remove modified file: {path}")
    path.unlink()
    return "removed"


def remove(source_root: Path, codex_home: Path, launcher_dir: Path, *, force: bool) -> dict:
    managed = _managed_files(source_root, codex_home, launcher_dir)
    files = []
    for key in ("profile", "prompt", "launcher"):
        path, data, _ = managed[key]
        files.append({"path": str(path), "status": _remove_exact(path, data, force=force)})
    return {"action": "remove", "profiles": ["architect"], "files": files, "default_profile_changed": False}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("install", "verify", "remove"))
    parser.add_argument("--profile", choices=("architect", "all"), default="architect")
    parser.add_argument("--codex-home", type=Path, default=Path(os.environ.get("CODEX_HOME", Path.home() / ".codex")))
    parser.add_argument(
        "--launcher-dir",
        type=Path,
        default=Path.home() / ".local" / "bin",
        help="Launcher install directory (default: ~/.local/bin)",
    )
    parser.add_argument("--source-root", type=Path, default=REPO_ROOT)
    parser.add_argument("--force", action="store_true", help="Overwrite or remove a modified managed file")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    source_root = args.source_root.expanduser().resolve()
    codex_home = args.codex_home.expanduser().resolve()
    launcher_dir = args.launcher_dir.expanduser().resolve()
    try:
        if args.action == "install":
            result = install(source_root, codex_home, launcher_dir, force=args.force)
        elif args.action == "verify":
            result = verify(source_root, codex_home, launcher_dir)
        else:
            result = remove(source_root, codex_home, launcher_dir, force=args.force)
    except (OSError, ValueError) as exc:
        print(json.dumps({"status": "error", "error": str(exc)}, sort_keys=True), file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result.get("ok", True) else 2


if __name__ == "__main__":
    raise SystemExit(main())
