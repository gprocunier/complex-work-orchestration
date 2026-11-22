"""Pure turn observations with no dispatch or acceptance authority."""

from __future__ import annotations

from typing import Any, Mapping, Sequence


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


def provider_policy_blocker(
    notifications: Sequence[Mapping[str, Any]], *, thread_id: str, turn_id: str | None
) -> dict[str, str]:
    """Project the explicit policy category from one bound failed completion."""
    if not turn_id:
        return {}
    matches = []
    for message in notifications:
        if message.get("method") != "turn/completed":
            continue
        params = message.get("params")
        if not isinstance(params, Mapping) or params.get("threadId") != thread_id:
            continue
        turn = params.get("turn")
        if isinstance(turn, Mapping) and turn.get("id") == turn_id:
            matches.append((params, turn))
    if len(matches) != 1:
        return {}
    params, turn = matches[0]
    if (params.get("turnId", turn_id) != turn_id or turn.get("status") != "failed"
            or not isinstance(turn.get("items"), list)):
        return {}
    error = turn.get("error")
    if not isinstance(error, Mapping) or not isinstance(error.get("message"), str):
        return {}
    category = error.get("codexErrorInfo")
    if category in ("cyberPolicy", "misalignmentPolicyViolation"):
        return {"provider-safety-policy-refusal": category}
    return {}
