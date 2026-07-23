"""Strict prompt and tool-isolation contracts for native workers.

The helpers in this module are deliberately transport agnostic.  A launcher
must supply a truthful description of the server surface; these contracts do
not treat prompt instructions as an enforcement mechanism.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Mapping


TOOL_POLICY_VERSION = 1
TOOL_POLICY_FIELDS = {
    "version",
    "permitted_tools",
    "forbidden_tools",
    "enforcement_mode",
    "workload_class",
    "override_provenance",
}
TOOL_ENFORCEMENT_MODES = frozenset(
    {"server-allowlist-required", "trusted-detect-and-contain"}
)
TOOL_WORKLOAD_CLASSES = frozenset({"operative", "safety-canary"})
TOOL_SURFACE_FIELDS = {
    "surface_type",
    "version",
    "source",
    "server_allowlist_supported",
    "allowlist_parameter",
    "requested_allowlist",
    "effective_allowlist",
    "override_provenance",
    "surface_sha256",
}
TOOL_SURFACE_TYPE = "cwo-native-tool-surface-snapshot"
PROMPT_PREFLIGHT_TYPE = "cwo-native-worker-prompt-preflight"

DEFAULT_FORBIDDEN_TOOLS = (
    "followup_task",
    "request_user_input",
    "send_message",
    "spawn_agent",
    "web_search",
)
UNPROVEN_PERMITTED_TOOLS = frozenset(
    {"apply_patch", "exec_command", "write_stdin"}
)
KNOWN_TOOL_NAMES = frozenset(
    {
        "apply_patch",
        "exec_command",
        "followup_task",
        "image_generation",
        "request_user_input",
        "send_message",
        "spawn_agent",
        "view_image",
        "web_search",
        "write_stdin",
    }
)
_TOOL_NAME = re.compile(r"^[a-z][a-z0-9_.:-]{0,127}$")
_EXPLICIT_SKILL_TRIGGER = re.compile(
    r"(?:(?<![a-z0-9_-])(?:\$|/)complex-work-orchestration\b|"
    r"(?<![/a-z0-9_-])complex-work-orchestration(?![/a-z0-9_-]))",
    re.IGNORECASE,
)
_SKILL_ROUTER_DIRECTIVE = re.compile(
    r"\b(?:use|invoke|load|activate|route\s+through)\s+(?:the\s+)?"
    r"(?:(?:complex-work-orchestration|cwo)\s+(?:skill|router|workflow)|"
    r"(?:skill|router|workflow)\s+(?:complex-work-orchestration|cwo))\b",
    re.IGNORECASE,
)
_SUBAGENT_DIRECTIVE = re.compile(
    r"\b(?:spawn|use|invoke|delegate\s+to|hand\s+off\s+to)\s+(?:an?\s+)?"
    r"(?:sub-?agents?|worker\s+agents?|agents?)\b",
    re.IGNORECASE,
)
_TOOL_DIRECTIVE = re.compile(
    r"\b(?:use|invoke|call|run)\s+(?:the\s+)?(?P<tool>[a-z][a-z0-9_.:-]{0,127})"
    r"(?:\s+tool)?\b",
    re.IGNORECASE,
)
_NEGATION_SUFFIX = re.compile(
    r"(?:do\s+not|don't|never|must\s+not)\s+$",
    re.IGNORECASE,
)


class NativeToolIsolationError(ValueError):
    """Raised when a required native tool boundary cannot be established."""


def canonical_sha256(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _strict_fields(
    value: Any,
    expected: set[str],
    prefix: str,
    errors: list[str],
) -> Mapping[str, Any] | None:
    if not isinstance(value, Mapping):
        errors.append(f"{prefix}-must-be-object")
        return None
    missing = sorted(expected - set(value))
    unknown = sorted(set(value) - expected)
    if missing:
        errors.append(f"{prefix}-missing-fields:" + ",".join(missing))
    if unknown:
        errors.append(f"{prefix}-unknown-fields:" + ",".join(unknown))
    return value


def _validate_tool_names(value: Any, prefix: str, errors: list[str]) -> list[str]:
    if not isinstance(value, list):
        errors.append(f"{prefix}-must-be-array")
        return []
    normalized: list[str] = []
    for item in value:
        if not isinstance(item, str) or not _TOOL_NAME.fullmatch(item):
            errors.append(f"{prefix}-contains-invalid-tool")
            continue
        normalized.append(item)
    if normalized != sorted(normalized):
        errors.append(f"{prefix}-must-be-sorted")
    if len(normalized) != len(set(normalized)):
        errors.append(f"{prefix}-contains-duplicate-tool")
    return normalized


def default_tool_policy(
    *,
    mutable: bool,
    workload_class: str = "operative",
    permitted_tools: list[str] | tuple[str, ...] | None = None,
    forbidden_tools: list[str] | tuple[str, ...] | None = None,
) -> dict[str, Any]:
    """Build the narrow default for an operative worker or safety canary."""

    permitted = (
        list(permitted_tools)
        if permitted_tools is not None
        else ["apply_patch", "exec_command", "write_stdin"]
        if mutable
        else ["exec_command", "write_stdin"]
    )
    forbidden_candidates: list[Any] = [
        *DEFAULT_FORBIDDEN_TOOLS,
        *(list(forbidden_tools) if forbidden_tools is not None else []),
    ]
    forbidden = (
        sorted(set(forbidden_candidates))
        if all(isinstance(item, str) for item in forbidden_candidates)
        else forbidden_candidates
    )
    normalized_permitted = (
        sorted(permitted)
        if all(isinstance(item, str) for item in permitted)
        else permitted
    )
    value = {
        "version": TOOL_POLICY_VERSION,
        "permitted_tools": normalized_permitted,
        "forbidden_tools": forbidden,
        "enforcement_mode": (
            "trusted-detect-and-contain"
            if workload_class == "safety-canary"
            else "server-allowlist-required"
        ),
        "workload_class": workload_class,
        # Authority-bearing overrides are introduced by the provenance repair.
        # Until then, the only accepted value is an explicit null.
        "override_provenance": None,
    }
    errors = validate_tool_policy(value)
    if errors:
        raise NativeToolIsolationError("tool-policy-invalid:" + ";".join(errors))
    return value


def validate_tool_policy(
    value: Any,
    *,
    prefix: str = "tool-policy",
) -> list[str]:
    errors: list[str] = []
    policy = _strict_fields(value, TOOL_POLICY_FIELDS, prefix, errors)
    if policy is None:
        return errors
    if policy.get("version") != TOOL_POLICY_VERSION:
        errors.append(f"{prefix}-version-invalid")
    permitted = _validate_tool_names(
        policy.get("permitted_tools"), f"{prefix}-permitted-tools", errors
    )
    forbidden = _validate_tool_names(
        policy.get("forbidden_tools"), f"{prefix}-forbidden-tools", errors
    )
    if not permitted:
        errors.append(f"{prefix}-permitted-tools-must-not-be-empty")
    unproven_permitted = sorted(set(permitted) - UNPROVEN_PERMITTED_TOOLS)
    if unproven_permitted:
        errors.append(
            f"{prefix}-unproven-permitted-tool-expansion:"
            + ",".join(unproven_permitted)
        )
    missing_forbidden = sorted(set(DEFAULT_FORBIDDEN_TOOLS) - set(forbidden))
    if missing_forbidden:
        errors.append(
            f"{prefix}-required-forbidden-tools-missing:"
            + ",".join(missing_forbidden)
        )
    if set(permitted) & set(forbidden):
        errors.append(f"{prefix}-permitted-forbidden-overlap")
    mode = policy.get("enforcement_mode")
    workload = policy.get("workload_class")
    if mode not in TOOL_ENFORCEMENT_MODES:
        errors.append(f"{prefix}-enforcement-mode-invalid")
    if workload not in TOOL_WORKLOAD_CLASSES:
        errors.append(f"{prefix}-workload-class-invalid")
    if workload == "operative" and mode != "server-allowlist-required":
        errors.append(f"{prefix}-operative-requires-server-allowlist")
    if policy.get("override_provenance") is not None:
        errors.append(f"{prefix}-override-provenance-not-yet-authorized")
    return sorted(set(errors))


def normalize_tool_policy(value: Any) -> dict[str, Any]:
    errors = validate_tool_policy(value)
    if errors:
        raise NativeToolIsolationError("tool-policy-invalid:" + ";".join(errors))
    assert isinstance(value, Mapping)
    return {
        "version": TOOL_POLICY_VERSION,
        "permitted_tools": list(value["permitted_tools"]),
        "forbidden_tools": list(value["forbidden_tools"]),
        "enforcement_mode": str(value["enforcement_mode"]),
        "workload_class": str(value["workload_class"]),
        "override_provenance": None,
    }


def _negated_prefix(line: str, start: int) -> bool:
    return _NEGATION_SUFFIX.search(line[max(0, start - 24) : start]) is not None


def prompt_preflight(prompt: str, tool_policy: Mapping[str, Any]) -> dict[str, Any]:
    """Scan an exact rendered prompt and return location-bound findings."""

    if not isinstance(prompt, str) or not prompt.strip():
        raise NativeToolIsolationError("prompt-preflight-input-invalid")
    policy = normalize_tool_policy(tool_policy)
    findings: list[dict[str, Any]] = []
    permitted = set(policy["permitted_tools"])
    forbidden = set(policy["forbidden_tools"])
    rules = (
        ("explicit-skill-trigger", _EXPLICIT_SKILL_TRIGGER, False),
        ("skill-router-directive", _SKILL_ROUTER_DIRECTIVE, False),
        ("subagent-routing-directive", _SUBAGENT_DIRECTIVE, True),
    )
    for line_number, line in enumerate(prompt.splitlines(), start=1):
        for rule_id, pattern, honor_negation in rules:
            for match in pattern.finditer(line):
                if honor_negation and _negated_prefix(line, match.start()):
                    continue
                findings.append(
                    {
                        "rule_id": rule_id,
                        "line": line_number,
                        "column": match.start() + 1,
                        "matched_sha256": hashlib.sha256(
                            match.group(0).encode("utf-8")
                        ).hexdigest(),
                    }
                )
        for match in _TOOL_DIRECTIVE.finditer(line):
            if _negated_prefix(line, match.start()):
                continue
            tool = match.group("tool").lower()
            if tool in permitted and tool not in forbidden:
                continue
            if tool not in forbidden and tool not in KNOWN_TOOL_NAMES:
                continue
            findings.append(
                {
                    "rule_id": "out-of-contract-tool-directive",
                    "line": line_number,
                    "column": match.start("tool") + 1,
                    "matched_sha256": hashlib.sha256(tool.encode("utf-8")).hexdigest(),
                }
            )
    findings.sort(key=lambda item: (item["line"], item["column"], item["rule_id"]))
    result = {
        "preflight_type": PROMPT_PREFLIGHT_TYPE,
        "version": 1,
        "prompt_sha256": hashlib.sha256(prompt.encode("utf-8")).hexdigest(),
        "tool_policy_sha256": canonical_sha256(policy),
        "findings": findings,
        "accepted": not findings,
    }
    result["preflight_sha256"] = canonical_sha256(result)
    return result


def require_prompt_preflight(
    prompt: str,
    tool_policy: Mapping[str, Any],
) -> dict[str, Any]:
    result = prompt_preflight(prompt, tool_policy)
    if not result["accepted"]:
        locations = ",".join(
            f"{item['rule_id']}@{item['line']}:{item['column']}"
            for item in result["findings"]
        )
        raise NativeToolIsolationError("prompt-trigger-conflict:" + locations)
    return result


def build_tool_surface_snapshot(
    tool_policy: Mapping[str, Any],
    *,
    source: str,
    server_allowlist_supported: bool,
    allowlist_parameter: str | None,
    effective_allowlist: list[str] | None,
) -> dict[str, Any]:
    """Bind the requested policy to a truthful server capability snapshot."""

    policy = normalize_tool_policy(tool_policy)
    if not isinstance(source, str) or not source.strip():
        raise NativeToolIsolationError("tool-surface-source-invalid")
    if not isinstance(server_allowlist_supported, bool):
        raise NativeToolIsolationError("tool-surface-support-invalid")
    if server_allowlist_supported:
        if not isinstance(allowlist_parameter, str) or not allowlist_parameter.strip():
            raise NativeToolIsolationError("tool-surface-allowlist-parameter-invalid")
        tool_errors: list[str] = []
        effective = _validate_tool_names(
            effective_allowlist, "tool-surface-effective-allowlist", tool_errors
        )
        if tool_errors:
            raise NativeToolIsolationError(";".join(tool_errors))
        requested = policy["permitted_tools"]
        extra = sorted(set(effective) - set(requested))
        if extra:
            raise NativeToolIsolationError(
                "tool-surface-expanded:" + ",".join(extra)
            )
        if effective != requested:
            raise NativeToolIsolationError("tool-surface-allowlist-mismatch")
    else:
        if allowlist_parameter is not None or effective_allowlist is not None:
            raise NativeToolIsolationError("tool-surface-unsupported-claims-effective")
        effective = None
        if policy["enforcement_mode"] == "server-allowlist-required":
            raise NativeToolIsolationError(
                "operative-tool-restriction-unsupported"
            )
    value = {
        "surface_type": TOOL_SURFACE_TYPE,
        "version": 1,
        "source": source.strip(),
        "server_allowlist_supported": server_allowlist_supported,
        "allowlist_parameter": allowlist_parameter,
        "requested_allowlist": list(policy["permitted_tools"]),
        "effective_allowlist": effective,
        "override_provenance": policy["override_provenance"],
    }
    value["surface_sha256"] = canonical_sha256(value)
    return value


def validate_tool_surface_snapshot(
    value: Any,
    tool_policy: Mapping[str, Any],
) -> list[str]:
    errors: list[str] = []
    surface = _strict_fields(value, TOOL_SURFACE_FIELDS, "tool-surface", errors)
    if surface is None:
        return errors
    try:
        expected = build_tool_surface_snapshot(
            tool_policy,
            source=surface.get("source"),
            server_allowlist_supported=surface.get("server_allowlist_supported"),
            allowlist_parameter=surface.get("allowlist_parameter"),
            effective_allowlist=surface.get("effective_allowlist"),
        )
    except NativeToolIsolationError as exc:
        errors.append(str(exc))
    else:
        if dict(surface) != expected:
            errors.append("tool-surface-snapshot-mismatch")
    return sorted(set(errors))


def require_unchanged_tool_surface(
    before: Mapping[str, Any],
    after: Mapping[str, Any],
) -> None:
    if dict(before) != dict(after):
        raise NativeToolIsolationError("tool-surface-changed-before-dispatch")


def forbidden_tool_activity(
    trusted_activity: Any,
    tool_policy: Mapping[str, Any],
) -> list[dict[str, str]]:
    """Return only hash-bound violations from trusted exact-turn activity."""

    policy = normalize_tool_policy(tool_policy)
    permitted = set(policy["permitted_tools"])
    forbidden = set(policy["forbidden_tools"])
    if not isinstance(trusted_activity, list):
        raise NativeToolIsolationError("trusted-tool-activity-must-be-array")
    violations: list[dict[str, str]] = []
    for item in trusted_activity:
        if not isinstance(item, Mapping):
            raise NativeToolIsolationError("trusted-tool-activity-item-invalid")
        tool = item.get("tool")
        evidence_sha256 = item.get("evidence_sha256")
        if (
            not isinstance(tool, str)
            or not _TOOL_NAME.fullmatch(tool)
            or not isinstance(evidence_sha256, str)
            or not re.fullmatch(r"[0-9a-f]{64}", evidence_sha256)
        ):
            raise NativeToolIsolationError("trusted-tool-activity-item-invalid")
        if tool not in permitted or tool in forbidden:
            violations.append(
                {"tool": tool, "evidence_sha256": evidence_sha256}
            )
    return sorted(
        violations, key=lambda item: (item["tool"], item["evidence_sha256"])
    )
