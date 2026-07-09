from __future__ import annotations

import getpass
import os
from pathlib import Path
import re
import stat
import tempfile
import time


_SAFE_TEMP_COMPONENT_RE = re.compile(r"[^A-Za-z0-9_.-]+")
_DEFAULT_SESSION_ID: str | None = None


def _find_repo_root(start: Path) -> Path:
    for candidate in [start, *start.parents]:
        if (candidate / "policy").is_dir() and (candidate / "scripts").is_dir() and (candidate / "schemas").is_dir():
            return candidate
    raise RuntimeError(f"could not resolve repository root from {start}")


REPO_ROOT = _find_repo_root(Path(__file__).resolve())
POLICY_DIR = REPO_ROOT / "policy"
AUDIT_DIR = REPO_ROOT / ".orchestration-audit"
AUDIT_LOG = Path(os.environ.get("CWO_AUDIT_FILE", AUDIT_DIR / "audit.jsonl")).expanduser()
CWO_TEMP_DIR_PREFIX = "cwo-"
CWO_EXCHANGE_DIR_NAME = "cwo-exchange"
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


def _sanitize_temp_component(value: str | None, default: str) -> str:
    raw = (value or "").strip()
    safe = _SAFE_TEMP_COMPONENT_RE.sub("-", raw).strip(".-")
    return safe[:96] or default


def _absolute_configured_dir(env_name: str, default: Path) -> Path:
    configured = os.environ.get(env_name)
    raw = Path(configured).expanduser() if configured else default
    if not raw.is_absolute():
        raise SystemExit(f"{env_name} must be an absolute path: {raw}")
    return raw


def _reject_symlinked_existing_parts(path: Path) -> None:
    absolute = path.expanduser()
    if not absolute.is_absolute():
        absolute = absolute.resolve()
    current = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current = current / part
        if current.is_symlink():
            raise SystemExit(f"refusing CWO temp path with symlink component: {path}")


def _ensure_temp_dir(path: Path, *, mode: int, require_owner: bool) -> Path:
    _reject_symlinked_existing_parts(path)
    path.mkdir(parents=True, exist_ok=True, mode=mode)
    if path.is_symlink():
        raise SystemExit(f"refusing symlink CWO temp directory: {path}")
    if not path.is_dir():
        raise SystemExit(f"CWO temp path is not a directory: {path}")
    stat_result = path.stat()
    if require_owner and stat_result.st_uid != os.getuid():
        raise SystemExit(f"refusing CWO private temp directory owned by another user: {path}")
    try:
        current_mode = stat.S_IMODE(stat_result.st_mode)
        if current_mode != mode:
            path.chmod(mode)
            current_mode = stat.S_IMODE(path.stat().st_mode)
        if require_owner and current_mode != mode:
            raise SystemExit(f"could not enforce private CWO temp directory mode: {path}")
    except PermissionError:
        if require_owner:
            raise SystemExit(f"could not enforce private CWO temp directory mode: {path}") from None
        # Shared exchange directories may be owned by an operator-managed group.
        # Keep running when the directory is usable but chmod is not allowed.
    return path.resolve()


def cwo_temp_root(*, create: bool = True) -> Path:
    """Return the root used for CWO-owned ephemeral artifacts."""
    configured = os.environ.get("CWO_TEMP_ROOT")
    root = _absolute_configured_dir("CWO_TEMP_ROOT", Path(tempfile.gettempdir()))
    if create:
        if configured:
            _reject_symlinked_existing_parts(root)
            root.mkdir(parents=True, exist_ok=True, mode=0o770)
            if root.is_symlink():
                raise SystemExit(f"refusing symlink CWO temp root: {root}")
            if not root.is_dir():
                raise SystemExit(f"CWO temp root is not a directory: {root}")
            return root.resolve()
        _reject_symlinked_existing_parts(root)
        if not root.exists() or not root.is_dir():
            raise SystemExit(f"system temp root is not a directory: {root}")
        return root.resolve()
    return root


def cwo_session_id() -> str:
    """Return the stable session id for this process or CWO_SESSION_ID override."""
    configured = os.environ.get("CWO_SESSION_ID")
    if configured:
        return _sanitize_temp_component(configured, "session")
    global _DEFAULT_SESSION_ID
    if _DEFAULT_SESSION_ID is None:
        _DEFAULT_SESSION_ID = f"{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}-{os.getpid()}"
    return _DEFAULT_SESSION_ID


def cwo_user_name() -> str:
    """Return a sanitized user component for CWO temp directory names."""
    return _sanitize_temp_component(os.environ.get("USER") or getpass.getuser(), "user")


def cwo_temp_dir(
    *,
    scope: str = "session",
    purpose: str | None = None,
    create: bool = True,
) -> Path:
    """Return a CWO-owned temp directory for private session or exchange use.

    Session scope is owner-private and defaults to ``/tmp/cwo-<user>-<session>``.
    Exchange scope is for operator-approved cross-user handoff and defaults to
    ``/tmp/cwo-exchange`` with best-effort group-readable permissions.
    """
    if scope == "session":
        base = cwo_temp_root(create=create) / f"{CWO_TEMP_DIR_PREFIX}{cwo_user_name()}-{cwo_session_id()}"
        mode = 0o700
    elif scope == "exchange":
        default_exchange = cwo_temp_root(create=create) / CWO_EXCHANGE_DIR_NAME
        base = _absolute_configured_dir("CWO_EXCHANGE_ROOT", default_exchange)
        mode = 0o1770
    else:
        raise SystemExit("scope must be 'session' or 'exchange'")
    if purpose:
        base = base / _sanitize_temp_component(purpose, "artifact")
    if create:
        return _ensure_temp_dir(base, mode=mode, require_owner=scope == "session")
    return base


def cwo_temp_path(
    name: str,
    *,
    scope: str = "session",
    purpose: str | None = None,
    create_parent: bool = True,
) -> Path:
    """Return a path under a CWO-owned temp directory without creating the file."""
    safe_name = _sanitize_temp_component(name, "artifact")
    return cwo_temp_dir(scope=scope, purpose=purpose, create=create_parent) / safe_name


def is_cwo_temp_path(path: Path) -> bool:
    """Return whether a path is inside the configured CWO temp or exchange roots."""
    resolved = path.expanduser().resolve()
    exchange_root = cwo_temp_dir(scope="exchange", create=False).expanduser().resolve()
    try:
        resolved.relative_to(exchange_root)
        return True
    except ValueError:
        pass
    temp_root = cwo_temp_root(create=False).expanduser().resolve()
    try:
        relative = resolved.relative_to(temp_root)
    except ValueError:
        return False
    return bool(relative.parts) and relative.parts[0].startswith(CWO_TEMP_DIR_PREFIX)
    return False


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
    parent = raw.parent
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
