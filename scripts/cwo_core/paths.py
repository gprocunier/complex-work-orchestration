from __future__ import annotations

from pathlib import Path


def _find_repo_root(start: Path) -> Path:
    for candidate in [start, *start.parents]:
        if (candidate / "policy").is_dir() and (candidate / "scripts").is_dir() and (candidate / "schemas").is_dir():
            return candidate
    raise RuntimeError(f"could not resolve repository root from {start}")


REPO_ROOT = _find_repo_root(Path(__file__).resolve())
POLICY_DIR = REPO_ROOT / "policy"
AUDIT_DIR = REPO_ROOT / ".orchestration-audit"
AUDIT_LOG = AUDIT_DIR / "audit.jsonl"
BLOCKED_PACKET_PATH_PARTS = {".git", ".beads", ".orchestration-audit"}
BLOCKED_PACKET_FILE_NAMES = {
    ".env",
    ".env.local",
    ".env.production",
    ".envrc",
    "id_rsa",
    "id_ed25519",
}
BLOCKED_PACKET_SUFFIXES = {".pem", ".key", ".p12", ".pfx"}


def repo_relative_path(path: Path) -> str:
    resolved = path.resolve()
    try:
        return resolved.relative_to(REPO_ROOT).as_posix()
    except ValueError as exc:
        raise SystemExit(f"refusing path outside repository: {path}") from exc


def assert_repo_safe_path(path: Path) -> Path:
    resolved = path.resolve()
    relative = Path(repo_relative_path(resolved))
    parts = set(relative.parts)
    blocked_parts = sorted(parts & BLOCKED_PACKET_PATH_PARTS)
    if blocked_parts:
        raise SystemExit(f"refusing forbidden packet path component: {', '.join(blocked_parts)}")
    lowered_parts = {part.lower() for part in relative.parts}
    name = resolved.name.lower()
    if name in BLOCKED_PACKET_FILE_NAMES:
        raise SystemExit(f"refusing likely secret file in packet: {relative.as_posix()}")
    if ".kube" in lowered_parts and name == "config":
        raise SystemExit(f"refusing kube config in packet: {relative.as_posix()}")
    if resolved.suffix.lower() in BLOCKED_PACKET_SUFFIXES:
        raise SystemExit(f"refusing private key or certificate bundle in packet: {relative.as_posix()}")
    if not resolved.is_file():
        raise SystemExit(f"packet artifact is not a regular file: {relative.as_posix()}")
    probe = resolved.read_bytes()[:4096]
    if b"\0" in probe:
        raise SystemExit(f"refusing binary packet artifact: {relative.as_posix()}")
    return resolved
