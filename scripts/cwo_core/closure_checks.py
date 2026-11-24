"""Read current Beads prerequisites for the manual and verified close paths."""
from __future__ import annotations

from collections.abc import Callable
from typing import Any

from .requirement_baseline import load_record

MAX_PROJECTION = 4 * 1024 * 1024


class PrerequisiteError(ValueError):
    """A blocker or child is open, or its recorded relationship is unclear."""


def projection(raw: str, key: str) -> Any:
    if len(raw.encode()) > MAX_PROJECTION:
        raise ValueError(f"{key} projection exceeds the control bound")
    return load_record('{"value":' + raw + '}')["value"]


def require_closed_prerequisites(
    run_bd: Callable[[list[str]], str], bead_id: str, *,
    decode: Callable[[str, str], Any] = projection,
) -> None:
    """Read blocking dependencies and reverse parent-child edges separately."""
    for kind, direction in (("blocks", "down"), ("parent-child", "up")):
        rows = decode(run_bd(["dep", "list", "--json", "--type", kind,
                              "--direction", direction, "--", bead_id]), "prerequisite")
        if type(rows) is not list:
            raise PrerequisiteError("authoritative prerequisite list is required")
        for row in rows:
            if (type(row) is not dict or type(row.get("id")) is not str
                    or not row["id"] or row.get("dependency_type") != kind):
                raise PrerequisiteError("authoritative prerequisite identity/type is required")
            if row.get("status") != "closed":
                raise PrerequisiteError(f"nonclosed blocker or child prevents closure ({row['id']})")
