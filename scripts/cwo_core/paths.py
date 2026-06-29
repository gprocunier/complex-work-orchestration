from __future__ import annotations

from pathlib import Path
import tempfile


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
BLOCKED_OUTPUT_PATH_PARTS = BLOCKED_PACKET_PATH_PARTS | {".orchestration-agents"}
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


def _reject_secret_like_path(path: Path) -> None:
    name = path.name.lower()
    if name in BLOCKED_PACKET_FILE_NAMES:
        raise SystemExit(f"refusing likely secret output path: {path}")
    if path.suffix.lower() in BLOCKED_PACKET_SUFFIXES:
        raise SystemExit(f"refusing private key or certificate output path: {path}")


def _has_symlink_between(root: Path, path: Path) -> bool:
    try:
        relative = path.relative_to(root)
    except ValueError:
        return False
    current = root
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            return True
    return False


def assert_safe_output_path(path: Path) -> Path:
    """Validate an operator output path before creating or replacing it.

    Allowed output roots are the repository and the system temp directory. This
    keeps normal CWO work-packets and /tmp artifacts working while avoiding
    accidental writes to credentials, control directories, or symlink targets.
    """
    raw = Path(path).expanduser()
    if raw.exists():
        if raw.is_dir():
            raise SystemExit(f"refusing to overwrite directory output path: {raw}")
        if raw.is_symlink():
            raise SystemExit(f"refusing symlink output path: {raw}")
    parent = raw.parent if raw.parent != Path("") else Path.cwd()
    if not parent.exists():
        raise SystemExit(f"output parent does not exist: {parent}")
    if not parent.is_dir():
        raise SystemExit(f"output parent is not a directory: {parent}")
    for candidate in [parent, *parent.parents]:
        if candidate.exists() and candidate.is_symlink():
            raise SystemExit(f"refusing output path with symlink parent: {raw}")
    resolved_parent = parent.resolve()
    resolved = resolved_parent / raw.name
    _reject_secret_like_path(resolved)

    temp_root = Path(tempfile.gettempdir()).resolve()
    allowed_root: Path | None = None
    for root in [REPO_ROOT.resolve(), temp_root]:
        try:
            resolved.relative_to(root)
            allowed_root = root
            break
        except ValueError:
            continue
    if allowed_root is None:
        raise SystemExit(f"refusing output path outside repository or {temp_root}: {raw}")

    if _has_symlink_between(allowed_root, resolved_parent):
        raise SystemExit(f"refusing output path with symlink parent: {raw}")

    if allowed_root == REPO_ROOT.resolve():
        relative = resolved.relative_to(allowed_root)
        blocked_parts = sorted(set(relative.parts) & BLOCKED_OUTPUT_PATH_PARTS)
        if blocked_parts:
            raise SystemExit(f"refusing forbidden output path component: {', '.join(blocked_parts)}")

    return resolved
