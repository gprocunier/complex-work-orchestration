"""Operator grant for contractor disclosure within one checkout, assignment and destination."""

from pathlib import Path
import re
from typing import Any

from .lead_authority import AuthorityError, configured_approval
from .workspace_capture import WorkspaceDiscoveryError, worktree_top_level

OUTBOUND_APPROVAL = "outbound-approval"
_SCOPE = ("project", "bead_id", "epic_id", "executor", "provider_key")
_BOUNDARY_RANK = {"redacted-packet": 1, "repo-readonly": 2, "patch-branch": 3}


def _scope_id(value: object) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", value) is not None


def outbound_approval_payload(grant: dict[str, Any]) -> dict[str, Any]:
    """Validate the grant held by the protected outbound-approval handler."""
    if not isinstance(grant, dict) or set(grant) != {*_SCOPE, "maximum_share_boundary"}:
        raise AuthorityError("invalid protected outbound approval fields")
    project = grant["project"]
    if not isinstance(project, str) or not Path(project).is_absolute() or ".." in Path(project).parts or str(Path(project)) != project:
        raise AuthorityError("protected outbound approval requires a canonical project root")
    if not all(_scope_id(grant[key]) for key in ("bead_id", "executor", "provider_key")):
        raise AuthorityError("protected outbound approval requires exact scope identifiers")
    if grant["epic_id"] is not None and not _scope_id(grant["epic_id"]):
        raise AuthorityError("protected outbound approval requires an exact epic identifier or null")
    if str(grant["maximum_share_boundary"]) not in _BOUNDARY_RANK:
        raise AuthorityError("protected outbound approval requires a supported maximum share boundary")
    return grant


def require_outbound_project() -> Path:
    """Identify the invoking target checkout independently of the installed skill and packet."""
    refusal = "run production contractor disclosure from the assigned project checkout"
    try:
        project = worktree_top_level(Path.cwd())
    except (OSError, WorkspaceDiscoveryError) as exc:
        raise SystemExit(refusal) from exc
    if project is None:
        raise SystemExit(refusal)
    return Path(project)


def require_outbound_approval(reference: object, scope: dict[str, Any], *, project: Path | None = None) -> None:
    """Resolve current host approval and compare it with the managed action's scope."""
    if not isinstance(reference, str) or not re.fullmatch(r"[0-9a-f]{64}", reference):
        raise SystemExit("production contractor disclosure requires a protected --opt-in-record reference")
    try:
        grant = outbound_approval_payload(configured_approval(OUTBOUND_APPROVAL, reference))
    except AuthorityError as exc:
        raise SystemExit("protected outbound approval is unavailable or invalid") from exc
    actual = {**scope, "project": str(project if project is not None else require_outbound_project())}
    if any(grant[key] != actual.get(key) for key in _SCOPE):
        raise SystemExit("protected outbound approval does not match this project, assignment or destination")
    rank = _BOUNDARY_RANK.get(str(actual.get("share_boundary")), 0)
    if not 0 < rank <= _BOUNDARY_RANK[grant["maximum_share_boundary"]]:
        raise SystemExit("protected outbound approval does not permit this share boundary")
