#!/usr/bin/env python3
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
from typing import Any


SKILL_NAME = "complex-work-orchestration"
INSTALL_MANIFEST_NAME = ".cwo-install-manifest.json"
INSTALL_ITEMS = (
    "README.md",
    "LICENSE",
    "SKILL.md",
    "AGENTS.md",
    "VERSION",
    "CHANGELOG.md",
    "agents",
    "policy",
    "templates",
    "experts",
    "references",
    "schemas",
    "examples",
    "docs",
    "scripts",
)
IGNORED_DIR_NAMES = {"__pycache__"}
IGNORED_SUFFIXES = {".pyc", ".pyo"}
IGNORED_FILE_NAMES = {INSTALL_MANIFEST_NAME, ".DS_Store"}
REPO_ROOT = Path(__file__).resolve().parents[1]


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_version(root: Path) -> str | None:
    version_path = root / "VERSION"
    if not version_path.is_file():
        return None
    value = version_path.read_text(encoding="utf-8").strip()
    return value or None


def ignored_path(path: Path) -> bool:
    if path.name in IGNORED_FILE_NAMES:
        return True
    if path.suffix in IGNORED_SUFFIXES:
        return True
    return any(part in IGNORED_DIR_NAMES for part in path.parts)


def iter_manifest_files(root: Path, items: tuple[str, ...] = INSTALL_ITEMS) -> list[tuple[str, Path]]:
    entries: list[tuple[str, Path]] = []
    for item in items:
        path = root / item
        if not path.exists():
            continue
        if path.is_file():
            if not ignored_path(Path(item)):
                entries.append((Path(item).as_posix(), path))
            continue
        for child in sorted(path.rglob("*")):
            if not child.is_file():
                continue
            relative = child.relative_to(root)
            if ignored_path(relative):
                continue
            entries.append((relative.as_posix(), child))
    return sorted(entries, key=lambda entry: entry[0])


def build_manifest(root: Path, items: tuple[str, ...] = INSTALL_ITEMS) -> dict[str, Any]:
    files = [
        {
            "path": relative,
            "sha256": file_sha256(path),
            "size": path.stat().st_size,
        }
        for relative, path in iter_manifest_files(root, items)
    ]
    payload = "\n".join(f"{item['path']}\0{item['sha256']}\0{item['size']}" for item in files)
    return {
        "manifest_type": "cwo-skill-content-manifest",
        "version": 1,
        "skill_name": SKILL_NAME,
        "skill_version": read_version(root),
        "content_sha256": sha256_bytes(payload.encode("utf-8")),
        "file_count": len(files),
        "files": files,
    }


def compare_manifests(source: dict[str, Any], installed: dict[str, Any]) -> dict[str, Any]:
    source_files = {item["path"]: item for item in source.get("files", [])}
    installed_files = {item["path"]: item for item in installed.get("files", [])}
    missing = sorted(set(source_files) - set(installed_files))
    extra = sorted(set(installed_files) - set(source_files))
    changed = sorted(
        path
        for path in set(source_files) & set(installed_files)
        if source_files[path].get("sha256") != installed_files[path].get("sha256")
        or source_files[path].get("size") != installed_files[path].get("size")
    )
    current = not missing and not extra and not changed and source.get("content_sha256") == installed.get("content_sha256")
    return {
        "status": "current" if current else "drift",
        "source_version": source.get("skill_version"),
        "installed_version": installed.get("skill_version"),
        "source_content_sha256": source.get("content_sha256"),
        "installed_content_sha256": installed.get("content_sha256"),
        "source_file_count": source.get("file_count"),
        "installed_file_count": installed.get("file_count"),
        "missing_files": missing,
        "extra_files": extra,
        "changed_files": changed,
    }


def default_codex_home() -> Path:
    return Path(os.environ.get("CODEX_HOME") or Path.home() / ".codex").expanduser()


def default_skills_dir() -> Path:
    if os.environ.get("CODEX_SKILLS_DIR"):
        return Path(os.environ["CODEX_SKILLS_DIR"]).expanduser()
    return default_codex_home() / "skills"


def resolve_target_dir(args: argparse.Namespace) -> Path:
    if args.installed_dir:
        return Path(args.installed_dir).expanduser().resolve()
    if args.skills_dir:
        return (Path(args.skills_dir).expanduser() / SKILL_NAME).resolve()
    if args.codex_home:
        return (Path(args.codex_home).expanduser() / "skills" / SKILL_NAME).resolve()
    return (default_skills_dir() / SKILL_NAME).resolve()


def installed_status(source_dir: Path, target_dir: Path) -> dict[str, Any]:
    source_manifest = build_manifest(source_dir)
    result: dict[str, Any] = {
        "skill_name": SKILL_NAME,
        "source_dir": str(source_dir),
        "installed_dir": str(target_dir),
    }
    if not target_dir.exists():
        result.update(
            {
                "status": "missing",
                "source_version": source_manifest.get("skill_version"),
                "installed_version": None,
                "source_content_sha256": source_manifest.get("content_sha256"),
                "installed_content_sha256": None,
                "source_file_count": source_manifest.get("file_count"),
                "installed_file_count": 0,
                "missing_files": [item["path"] for item in source_manifest.get("files", [])],
                "extra_files": [],
                "changed_files": [],
            }
        )
        return result
    installed_manifest = build_manifest(target_dir)
    result.update(compare_manifests(source_manifest, installed_manifest))
    return result


def write_install_manifest(target_dir: Path, status: dict[str, Any]) -> Path:
    manifest_path = target_dir / INSTALL_MANIFEST_NAME
    payload = {
        "manifest_type": "cwo-installed-skill-status",
        "version": 1,
        "generated_at": dt.datetime.now(dt.UTC).isoformat(),
        "skill_name": SKILL_NAME,
        "status": status["status"],
        "source_version": status.get("source_version"),
        "installed_version": status.get("installed_version"),
        "source_content_sha256": status.get("source_content_sha256"),
        "installed_content_sha256": status.get("installed_content_sha256"),
        "source_file_count": status.get("source_file_count"),
        "installed_file_count": status.get("installed_file_count"),
    }
    manifest_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return manifest_path


def render_text(status: dict[str, Any]) -> str:
    lines = [
        f"Skill install status: {status['status']}",
        f"  Source: {status['source_dir']}",
        f"  Installed: {status['installed_dir']}",
        f"  Source version: {status.get('source_version') or 'unknown'}",
        f"  Installed version: {status.get('installed_version') or 'unknown'}",
        f"  Source hash: {status.get('source_content_sha256') or 'missing'}",
        f"  Installed hash: {status.get('installed_content_sha256') or 'missing'}",
    ]
    for label, key in [
        ("Missing files", "missing_files"),
        ("Changed files", "changed_files"),
        ("Extra files", "extra_files"),
    ]:
        values = status.get(key) or []
        if values:
            lines.append(f"  {label}:")
            for value in values[:20]:
                lines.append(f"    - {value}")
            if len(values) > 20:
                lines.append(f"    - ... {len(values) - 20} more")
    if status["status"] != "current":
        lines.append("  Reload: ./scripts/install.sh --skills-dir <codex-skills-dir> --yes")
    return "\n".join(lines)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Check installed complex-work-orchestration skill drift.")
    parser.add_argument("--source-dir", default=str(REPO_ROOT), help="Source repository root. Defaults to this checkout.")
    parser.add_argument("--skills-dir", help="Codex skills directory containing the skill.")
    parser.add_argument("--codex-home", help="Codex home directory containing skills/.")
    parser.add_argument("--installed-dir", help="Direct path to an installed complex-work-orchestration skill.")
    parser.add_argument("--write-manifest", action="store_true", help=f"Write {INSTALL_MANIFEST_NAME} into the installed skill.")
    parser.add_argument("--check", action="store_true", help="Exit nonzero when the installed skill is missing or drifted.")
    parser.add_argument("--json", action="store_true", help="Print JSON instead of human-readable text.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    source_dir = Path(args.source_dir).expanduser().resolve()
    target_dir = resolve_target_dir(args)
    status = installed_status(source_dir, target_dir)
    if args.write_manifest and target_dir.exists():
        status["install_manifest_path"] = str(write_install_manifest(target_dir, status))
    if args.json:
        print(json.dumps(status, indent=2, sort_keys=True))
    else:
        print(render_text(status))
    if args.check and status["status"] != "current":
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
