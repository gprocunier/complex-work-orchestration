"""Install, verify, or remove CWO instruction profiles."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
PROFILE_NAMES = {
    "overlay": "cwo-sol-overlay-experimental",
    "operator": "cwo-sol-operator-experimental",
    "operator-e": "cwo-sol-operator-e",
}
PROMPT_FILENAMES = {
    "operator": "cwo-sol-operator.md",
    "operator-e": "cwo-sol-operator-e.md",
}
LAUNCHER_NAME = "cwo-codex"
LAUNCHER_PROFILE = "operator-e"


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _source_paths(source_root: Path) -> dict[str, Path]:
    return {
        "overlay": source_root / "prompts" / "cwo-sol-overlay.md",
        "operator": source_root / "prompts" / "cwo-sol-operator.md",
        "operator-e": source_root / "prompts" / "cwo-sol-operator-e.md",
    }


def _selected(value: str) -> tuple[str, ...]:
    return tuple(PROFILE_NAMES) if value == "all" else (value,)


def _profile_path(codex_home: Path, key: str) -> Path:
    return codex_home / f"{PROFILE_NAMES[key]}.config.toml"


def _prompt_path(codex_home: Path, key: str) -> Path:
    return codex_home / "prompts" / PROMPT_FILENAMES[key]


def _launcher_source(source_root: Path) -> Path:
    return source_root / "scripts" / LAUNCHER_NAME


def _launcher_path(launcher_dir: Path) -> Path:
    return launcher_dir / LAUNCHER_NAME


def _expected(source_root: Path, codex_home: Path, key: str) -> bytes:
    sources = _source_paths(source_root)
    if key == "overlay":
        common = 'model = "gpt-5.6-sol"\nmodel_reasoning_effort = "max"\n'
        overlay = sources["overlay"].read_text(encoding="utf-8")
        return (common + f"developer_instructions = {json.dumps(overlay)}\n").encode()
    common = 'model = "gpt-5.6-sol"\n'
    if key == "operator":
        common += 'model_reasoning_effort = "max"\n'
    target = str(_prompt_path(codex_home, key).resolve())
    return (common + f"model_instructions_file = {json.dumps(target)}\n").encode()


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


def install(
    source_root: Path,
    codex_home: Path,
    launcher_dir: Path,
    keys: tuple[str, ...],
    *,
    force: bool,
) -> dict:
    sources = _source_paths(source_root)
    selected_sources = [sources[key] for key in keys]
    if LAUNCHER_PROFILE in keys:
        selected_sources.append(_launcher_source(source_root))
    for source in selected_sources:
        if not source.is_file():
            raise ValueError(f"missing profile source: {source}")
    files: list[dict[str, str]] = []
    for key in keys:
        if key not in PROMPT_FILENAMES:
            continue
        prompt = _prompt_path(codex_home, key)
        data = sources[key].read_bytes()
        files.append({"path": str(prompt), "status": _write_exact(prompt, data, force=force), "sha256": _sha256(data)})
    for key in keys:
        profile = _profile_path(codex_home, key)
        data = _expected(source_root, codex_home, key)
        files.append({"path": str(profile), "status": _write_exact(profile, data, force=force), "sha256": _sha256(data)})
    if LAUNCHER_PROFILE in keys:
        launcher = _launcher_path(launcher_dir)
        data = _launcher_source(source_root).read_bytes()
        files.append(
            {
                "path": str(launcher),
                "status": _write_exact(launcher, data, force=force, executable=True),
                "sha256": _sha256(data),
            }
        )
    return {"action": "install", "profiles": list(keys), "files": files, "default_profile_changed": False}


def verify(source_root: Path, codex_home: Path, launcher_dir: Path, keys: tuple[str, ...]) -> dict:
    checks: list[dict[str, object]] = []
    for key in keys:
        if key not in PROMPT_FILENAMES:
            continue
        prompt = _prompt_path(codex_home, key)
        expected = _source_paths(source_root)[key].read_bytes()
        actual = prompt.read_bytes() if prompt.is_file() else None
        checks.append({"path": str(prompt), "ok": actual == expected, "expected_sha256": _sha256(expected), "actual_sha256": _sha256(actual) if actual is not None else None})
    for key in keys:
        profile = _profile_path(codex_home, key)
        expected = _expected(source_root, codex_home, key)
        actual = profile.read_bytes() if profile.is_file() else None
        checks.append({"path": str(profile), "ok": actual == expected, "expected_sha256": _sha256(expected), "actual_sha256": _sha256(actual) if actual is not None else None})
    if LAUNCHER_PROFILE in keys:
        launcher = _launcher_path(launcher_dir)
        expected = _launcher_source(source_root).read_bytes()
        actual = launcher.read_bytes() if launcher.is_file() else None
        executable = bool(launcher.stat().st_mode & 0o111) if launcher.exists() else False
        checks.append(
            {
                "path": str(launcher),
                "ok": actual == expected and executable,
                "executable": executable,
                "expected_sha256": _sha256(expected),
                "actual_sha256": _sha256(actual) if actual is not None else None,
            }
        )
    return {"action": "verify", "profiles": list(keys), "ok": all(item["ok"] for item in checks), "checks": checks, "default_profile_changed": False}


def _remove_exact(path: Path, expected: bytes, *, force: bool) -> str:
    if not path.exists():
        return "absent"
    if path.read_bytes() != expected and not force:
        raise ValueError(f"refusing to remove modified file: {path}")
    path.unlink()
    return "removed"


def remove(
    source_root: Path,
    codex_home: Path,
    launcher_dir: Path,
    keys: tuple[str, ...],
    *,
    force: bool,
) -> dict:
    files: list[dict[str, str]] = []
    for key in keys:
        profile = _profile_path(codex_home, key)
        files.append({"path": str(profile), "status": _remove_exact(profile, _expected(source_root, codex_home, key), force=force)})
    for key in keys:
        if key not in PROMPT_FILENAMES:
            continue
        prompt = _prompt_path(codex_home, key)
        source = _source_paths(source_root)[key].read_bytes()
        files.append({"path": str(prompt), "status": _remove_exact(prompt, source, force=force)})
    if LAUNCHER_PROFILE in keys:
        launcher = _launcher_path(launcher_dir)
        source = _launcher_source(source_root).read_bytes()
        files.append({"path": str(launcher), "status": _remove_exact(launcher, source, force=force)})
    return {"action": "remove", "profiles": list(keys), "files": files, "default_profile_changed": False}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("install", "verify", "remove"))
    parser.add_argument("--profile", choices=("all", *PROFILE_NAMES), default="all")
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
    keys = _selected(args.profile)
    try:
        if args.action == "install":
            result = install(source_root, codex_home, launcher_dir, keys, force=args.force)
        elif args.action == "verify":
            result = verify(source_root, codex_home, launcher_dir, keys)
        else:
            result = remove(source_root, codex_home, launcher_dir, keys, force=args.force)
    except (OSError, ValueError) as exc:
        print(json.dumps({"status": "error", "error": str(exc)}, sort_keys=True), file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result.get("ok", True) else 2


if __name__ == "__main__":
    raise SystemExit(main())
