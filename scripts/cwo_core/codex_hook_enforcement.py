"""Codex hook enforcement disposition and advisory hook allowlist.

Hook-based enforcement is unsupported and ineligible on the pinned Codex versions
(0.163.0 and 0.162.0). Advisory Beads lifecycle hooks are permitted only as an
exact positive allowlist: the qualified events, the allowed hook type, and the
exact commands that ``scripts/configure_codex_beads_hooks.py`` writes. Anything
else, including malformed structure, is refused.

``validate_advisory_hook_configuration`` is the single validation path. The hooks
writer, the hooks CLI and the access profile registry all call it.
"""
from __future__ import annotations

from typing import Any

from .codex_protocol_pin import load_pins
from .errors import CWOValidationError


ENFORCEMENT_HOOK_EVENTS = frozenset({
    "PreToolUse",
    "PermissionRequest",
})

# Exactly what scripts/configure_codex_beads_hooks.py writes, per event: the group
# matcher (None means the group carries no matcher) and the exact commands.
ADVISORY_HOOK_ALLOWLIST: dict[str, dict[str, Any]] = {
    "SessionStart": {
        "matcher": "startup|resume|clear",
        "commands": frozenset({
            "bd codex-hook SessionStart",
            "bd prime --memories-only --hook-json",
        }),
    },
    "UserPromptSubmit": {
        "matcher": None,
        "commands": frozenset({"bd codex-hook UserPromptSubmit"}),
    },
    "PreCompact": {
        "matcher": "manual|auto",
        "commands": frozenset({"bd codex-hook PreCompact"}),
    },
    "PostCompact": {
        "matcher": "manual|auto",
        "commands": frozenset({"bd codex-hook PostCompact"}),
    },
}

ADVISORY_HOOK_EVENTS = frozenset(ADVISORY_HOOK_ALLOWLIST)
ADVISORY_HOOK_TYPES = frozenset({"command"})
ADVISORY_VISIBILITY_HINTS = frozenset({"quiet", "verbose"})
ADVISORY_ROOT_KEYS = frozenset({"hooks"})
ADVISORY_GROUP_KEYS = frozenset({"hooks", "matcher"})
ADVISORY_HOOK_KEYS = frozenset({"type", "command", "statusMessage", "visibilityHint"})

# Named so the refusal says why; any key outside ADVISORY_HOOK_KEYS is refused anyway.
PERMISSION_GRANTING_HOOK_FIELDS = frozenset({
    "grant_permission",
    "grantPermission",
    "allow",
    "approve",
    "bypass_review",
    "bypassReview",
    "skip_approval",
    "skipApproval",
})

_ENFORCEMENT_EVENT_FOLDED = frozenset(event.casefold() for event in ENFORCEMENT_HOOK_EVENTS)


def _type_name(value: Any) -> str:
    return type(value).__name__


def _keys(values: Any) -> list[str]:
    return sorted(str(value) for value in values)


def check_pinned_versions_ineligible(*, context: str | None = None, events: list[str] | None = None) -> None:
    """Refuse hook-based enforcement on the pinned Codex versions. Always raises."""
    try:
        pins = load_pins()
    except Exception as exc:
        raise CWOValidationError(
            f"codex protocol pins not loaded; cannot verify enforcement eligibility: {exc}"
        ) from exc

    pinned_versions = [pin["version"] for pin in pins]
    if not pinned_versions:
        raise CWOValidationError(
            "no pinned codex versions found; cannot verify enforcement eligibility"
        )

    prefix = f"{context}: hook event(s) {events} refused: " if context else ""
    raise CWOValidationError(
        f"{prefix}hook-based enforcement is unsupported on pinned Codex versions {pinned_versions}; "
        f"PreToolUse leaves should_block=false on execution/JSON failures, "
        f"stdin skips PreToolUse, and PermissionRequest fallthrough is not equivalent to PreToolUse; "
        f"enforcement mode refused"
    )


def validate_advisory_hook_configuration(payload: Any, *, context: str = "hook configuration") -> None:
    """Accept only the exact advisory Beads hook allowlist; refuse anything else.

    ``payload`` is a hooks.json document: an object whose only key is ``hooks``,
    mapping event names to lists of hook groups. Prohibited enforcement events are
    refused by name before their contents are inspected.
    """
    if not isinstance(payload, dict):
        raise CWOValidationError(
            f"{context}: hook configuration must be a JSON object, not {_type_name(payload)}; refused"
        )
    unknown = [key for key in payload if key not in ADVISORY_ROOT_KEYS]
    if unknown:
        raise CWOValidationError(
            f"{context}: unsupported top-level key(s) {_keys(unknown)}; only 'hooks' is allowed; refused"
        )
    events = payload.get("hooks", {})
    if not isinstance(events, dict):
        raise CWOValidationError(
            f"{context}: 'hooks' must be an object mapping event names to hook groups, "
            f"not {_type_name(events)}; refused"
        )
    for name in events:
        if not isinstance(name, str):
            raise CWOValidationError(
                f"{context}: hook event names must be strings, not {_type_name(name)}; refused"
            )
    prohibited = sorted(name for name in events if name.casefold() in _ENFORCEMENT_EVENT_FOLDED)
    if prohibited:
        check_pinned_versions_ineligible(context=context, events=prohibited)
    for name in events:
        if name not in ADVISORY_HOOK_ALLOWLIST:
            raise CWOValidationError(
                f"{context}: hook event {name!r} is not an allowlisted advisory event "
                f"{sorted(ADVISORY_HOOK_ALLOWLIST)}; refused"
            )
    for name, groups in events.items():
        if not isinstance(groups, list):
            raise CWOValidationError(
                f"{context} event {name!r}: hook groups must be a list, not {_type_name(groups)}; refused"
            )
        for index, group in enumerate(groups):
            _validate_group(name, group, context=f"{context} event {name!r} group {index}")


def _validate_group(event: str, group: Any, *, context: str) -> None:
    if not isinstance(group, dict):
        raise CWOValidationError(f"{context}: hook group must be an object, not {_type_name(group)}; refused")
    unknown = [key for key in group if key not in ADVISORY_GROUP_KEYS]
    if unknown:
        raise CWOValidationError(
            f"{context}: unsupported key(s) {_keys(unknown)}; allowed keys are "
            f"{sorted(ADVISORY_GROUP_KEYS)}; refused"
        )
    expected = ADVISORY_HOOK_ALLOWLIST[event]["matcher"]
    if expected is None:
        matcher_ok = "matcher" not in group
    else:
        matcher_ok = "matcher" in group and group["matcher"] == expected
    if not matcher_ok:
        actual = repr(group["matcher"]) if "matcher" in group else "(absent)"
        wanted = repr(expected) if expected is not None else "(absent)"
        raise CWOValidationError(
            f"{context}: matcher {actual} does not match the allowlisted matcher {wanted}; refused"
        )
    hooks = group.get("hooks")
    if not isinstance(hooks, list) or not hooks:
        raise CWOValidationError(f"{context}: 'hooks' must be a non-empty list of hook entries; refused")
    for index, hook in enumerate(hooks):
        _validate_entry(event, hook, context=f"{context} hook {index}")


def _validate_entry(event: str, hook: Any, *, context: str) -> None:
    if not isinstance(hook, dict):
        raise CWOValidationError(f"{context}: hook entry must be an object, not {_type_name(hook)}; refused")
    granting = [key for key in hook if key in PERMISSION_GRANTING_HOOK_FIELDS]
    if granting:
        raise CWOValidationError(
            f"{context}: hook contains permission-granting field(s) {_keys(granting)}; "
            f"advisory hooks cannot issue authority; refused"
        )
    unknown = [key for key in hook if key not in ADVISORY_HOOK_KEYS]
    if unknown:
        raise CWOValidationError(
            f"{context}: unsupported key(s) {_keys(unknown)}; allowed keys are "
            f"{sorted(ADVISORY_HOOK_KEYS)}; refused"
        )
    hook_type = hook.get("type")
    if not isinstance(hook_type, str) or hook_type not in ADVISORY_HOOK_TYPES:
        raise CWOValidationError(
            f"{context}: hook type {hook_type!r} is not an allowlisted advisory hook type "
            f"{sorted(ADVISORY_HOOK_TYPES)}; refused"
        )
    commands = ADVISORY_HOOK_ALLOWLIST[event]["commands"]
    command = hook.get("command")
    if not isinstance(command, str) or command not in commands:
        raise CWOValidationError(
            f"{context}: command {command!r} is not an allowlisted advisory command for {event}; "
            f"allowed: {sorted(commands)}; refused"
        )
    if "statusMessage" in hook and not isinstance(hook["statusMessage"], str):
        raise CWOValidationError(f"{context}: statusMessage must be a string; refused")
    if "visibilityHint" in hook:
        hint = hook["visibilityHint"]
        if not isinstance(hint, str) or hint not in ADVISORY_VISIBILITY_HINTS:
            raise CWOValidationError(
                f"{context}: visibilityHint {hint!r} is not one of {sorted(ADVISORY_VISIBILITY_HINTS)}; refused"
            )


def validate_profile_hooks(profile: Any, *, profile_name: str = "profile") -> None:
    """Refuse enforcement hooks in an access profile and route any profile hooks
    through ``validate_advisory_hook_configuration``."""
    if not isinstance(profile, dict):
        raise CWOValidationError(f"access profile '{profile_name}' must be an object; refused")
    if "enforcement_hooks" in profile:
        raise CWOValidationError(
            f"access profile '{profile_name}' declares enforcement_hooks; "
            f"hook-based enforcement is unsupported on pinned Codex versions"
        )
    if "hooks" in profile:
        validate_advisory_hook_configuration(
            {"hooks": profile["hooks"]},
            context=f"access profile '{profile_name}' hooks",
        )
