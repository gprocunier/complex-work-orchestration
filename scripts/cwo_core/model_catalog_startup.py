"""Read Codex's public model list as selection input."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any


class ModelCatalogError(ValueError):
    pass


def _model_rows(page: object) -> list[Any]:
    if not isinstance(page, Mapping) or not isinstance(page.get("data"), list):
        raise ModelCatalogError("Codex model/list response has no data array")
    return page["data"]


def _public_models(rows: list[Any]) -> list[dict[str, Any]]:
    by_id: dict[str, Mapping[str, Any]] = {}
    for row in rows:
        if (not isinstance(row, Mapping) or type(row.get("id")) is not str
                or type(row.get("model")) is not str or type(row.get("hidden")) is not bool):
            raise ModelCatalogError("Codex model/list response has an invalid entry")
        if row["id"] in by_id:
            raise ModelCatalogError("Codex model/list response has a duplicate model ID")
        by_id[row["id"]] = row
    return [
        dict(item)
        for item in by_id.values()
        if item["hidden"] is False and item["id"] == item["model"]
    ]


def public_model_catalog(
    request: Callable[[str, dict[str, Any]], tuple[Mapping[str, Any], float]],
) -> dict[str, Any]:
    """Collect public exact identities using an initialized Codex app server."""
    models = []
    params: dict[str, Any] = {"includeHidden": False}
    seen_cursors: set[str] = set()
    for _ in range(20):
        page, _latency = request("model/list", params)
        models.extend(_model_rows(page))
        cursor = page.get("nextCursor")
        if cursor is None:
            return {"data": _public_models(models), "nextCursor": None}
        if not isinstance(cursor, str) or not cursor or cursor in seen_cursors:
            raise ModelCatalogError("Codex model/list response has an invalid pagination cursor")
        seen_cursors.add(cursor)
        params = {"includeHidden": False, "cursor": cursor}
    raise ModelCatalogError("Codex public model list exceeded the pagination limit")
