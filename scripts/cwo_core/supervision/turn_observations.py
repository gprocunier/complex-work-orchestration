"""Pure turn observations with no dispatch or acceptance authority."""

from __future__ import annotations

from typing import Any, Mapping


def turn_from_thread(thread: Mapping[str, Any], turn_id: str | None) -> Mapping[str, Any] | None:
    turns = thread.get("turns")
    if not isinstance(turns, list):
        return None
    for item in turns:
        if isinstance(item, Mapping) and item.get("id") == turn_id:
            return item
    return None


def turn_items(thread: Mapping[str, Any], turn_id: str | None) -> list[Mapping[str, Any]]:
    turn = turn_from_thread(thread, turn_id)
    items = turn.get("items") if isinstance(turn, Mapping) else None
    return [item for item in items if isinstance(item, Mapping)] if isinstance(items, list) else []
