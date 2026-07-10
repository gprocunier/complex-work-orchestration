from __future__ import annotations

import datetime as dt
import fnmatch
import hashlib
import json
import re
from pathlib import Path
from typing import Any

from .errors import CWOPolicyError
from .paths import REPO_ROOT, assert_repo_safe_path, repo_relative_path
from .policy import (
    boundary_config,
    executor_key_allowed,
    load_contracting_controls,
    load_policy,
    provider_profile,
)
from .util import artifact_hash, packet_payload_hash, parse_iso_datetime
from .return_language import default_expected_return_language, validate_expected_return_language


MANDATORY_EXCLUDED_ARTIFACTS = {"full_bead_json", "secrets", "production_access"}
MANDATORY_SECRET_FIELD_ALIASES = (
    "token",
    "password",
    "passwd",
    "secret",
    "credential",
    "private_key",
    "client_secret",
    "connection_string",
    "authorization",
    "auth_token",
    "session_token",
    "cookie",
    "api_key",
    "access_key",
    "secret_access_key",
    "aws_access_key_id",
    "aws_secret_access_key",
)


MANDATORY_SECRET_FIELD_ALIAS_SET = tuple(sorted(set(MANDATORY_SECRET_FIELD_ALIASES)))
_SECRET_FIELD_PATTERN_STATES: dict[
    tuple[str, ...], tuple[str, re.Pattern[str], re.Pattern[str], re.Pattern[str]]
] = {}


def _compile_secret_field_regex(aliases: list[str] | None = None) -> str:
    aliases = list(MANDATORY_SECRET_FIELD_ALIAS_SET) if aliases is None else aliases
    parts: list[str] = []
    for alias in aliases:
        words = [piece for piece in re.split(r"[\s._-]+", alias) if piece]
        if not words:
            continue
        core = r"[._-]+".join(map(re.escape, words))
        parts.append(core)
        if len(words) > 1:
            parts.append("".join(map(re.escape, words)))
    if not parts:
        return r"token"
    core_pattern = "|".join(sorted(set(parts), key=len, reverse=True))
    return rf"(?:[a-z0-9]+[._-]+)*(?:{core_pattern})"


def _build_secret_field_pattern_state(
    aliases: tuple[str, ...] | None = None,
) -> tuple[str, re.Pattern[str], re.Pattern[str], re.Pattern[str]]:
    aliases_tuple = MANDATORY_SECRET_FIELD_ALIAS_SET if aliases is None else aliases
    cached = _SECRET_FIELD_PATTERN_STATES.get(aliases_tuple)
    if cached is not None:
        return cached
    pattern = _compile_secret_field_regex(list(aliases_tuple))
    secret_like = re.compile(rf"(?i)({pattern})")
    field_assignment = re.compile(
        rf"(?i)(?<![\w-])(?P<quote>[\"']?)(?P<key>_?(?:{pattern}))"
        rf"(?P=quote)(?![\w-])(?P<before>[ \t]*)(?P<operator>[:=])(?P<after>[ \t]*)"
    )
    leading_field = re.compile(
        rf"(?i)(?P<quote>[\"']?)(?P<key>_?(?:{pattern}))"
        rf"(?P=quote)(?![\w-])(?P<separator>[ \t]+)"
    )
    state = (pattern, secret_like, field_assignment, leading_field)
    _SECRET_FIELD_PATTERN_STATES[aliases_tuple] = state
    return state


def _effective_secret_field_pattern_state(
    *, require_policy_patterns: bool = False
) -> tuple[str, re.Pattern[str], re.Pattern[str], re.Pattern[str]]:
    if not require_policy_patterns:
        return _build_secret_field_pattern_state()
    aliases = tuple(_load_secret_field_aliases())
    return _build_secret_field_pattern_state(aliases)


def _load_secret_field_aliases() -> list[str]:
    try:
        policy = load_policy("share-boundaries").get("secret_field_policy", {})
    except SystemExit as exc:
        raise CWOPolicyError(f"unable to load secret-field policy: {exc}") from exc
    policy_aliases: list[str] = []
    categories = policy.get("categories")
    if categories is None:
        categories = {}
    if not isinstance(categories, dict):
        raise CWOPolicyError(
            "secret_field_policy.categories must be an object mapping category names to string lists"
        )
    for category, values in categories.items():
        if not isinstance(values, list):
            raise CWOPolicyError(
                f"secret_field_policy.categories.{category!r} must be a list of aliases"
            )
        for alias in values:
            if not isinstance(alias, str):
                raise CWOPolicyError(
                    f"secret_field_policy.categories.{category!r} contains non-string alias {alias!r}"
                )
            normalized = alias.strip().lower()
            if normalized:
                policy_aliases.append(normalized)

    seen: set[str] = set()
    deduped_policy_aliases: list[str] = []
    for alias in policy_aliases:
        if alias in seen:
            continue
        seen.add(alias)
        deduped_policy_aliases.append(alias)
    mandatory_aliases = sorted(set(MANDATORY_SECRET_FIELD_ALIASES))
    policy_aliases = [alias for alias in deduped_policy_aliases if alias not in set(mandatory_aliases)]
    # Preserve deterministic ordering while keeping an immutable mandatory floor.
    merged_aliases: list[str] = mandatory_aliases + policy_aliases
    # Keep deterministic, user-visible ordering and return the merged floor.
    seen = set()
    deduped_merged: list[str] = []
    for alias in merged_aliases:
        if alias in seen:
            continue
        seen.add(alias)
        deduped_merged.append(alias)
    return deduped_merged


_BASE_SECRET_FIELD_PATTERN_STATE = _build_secret_field_pattern_state()
SECRET_FIELD_PATTERN = _BASE_SECRET_FIELD_PATTERN_STATE[0]
SECRET_LIKE_FIELD_RE, FIELD_ASSIGNMENT_RE, LEADING_FIELD_RE = (
    _BASE_SECRET_FIELD_PATTERN_STATE[1],
    _BASE_SECRET_FIELD_PATTERN_STATE[2],
    _BASE_SECRET_FIELD_PATTERN_STATE[3],
)
REDACTION_SENTINEL = "[REDACTED]"
INLINE_CONTAINER_SPAN_REASON = "inline-container-value"
_REASON_CONTAINER_REDACTION = {INLINE_CONTAINER_SPAN_REASON}
COMMENT_FIELD_ASSIGNMENT_RE = re.compile(r"^[ \t]*#(?!#)[ \t]*")
FIELD_PREFIX_RE = re.compile(
    r"^[ \t]*(?:>[ \t]*)*(?:(?:[-+*]|\d+[.)])[ \t]+)?"
)
AUTHORIZATION_BEARER_RE = re.compile(
    r"(?i)\bauthorization\b\s*:\s*bearer\s+(?P<value>[A-Za-z0-9._~+/=-]+)"
)
BARE_BEARER_RE = re.compile(r"(?i)\bbearer\s+(?P<value>[A-Za-z0-9._~+/=-]{8,})")
PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN [A-Z ]+ PRIVATE KEY-----[\s\S]*?-----END [A-Z ]+ PRIVATE KEY-----"
)
KNOWN_CREDENTIAL_PREFIX_RE = re.compile(
    r"(?i)^(?:sk[-_]|ghp_|github_pat_|xox[baprs]-|AKIA|ASIA|eyJ)[A-Za-z0-9._~+/=-]+$"
)
JWT_RE = re.compile(r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$")
# Compatibility exports for callers that imported the former module-level
# pattern collections. Context-sensitive field handling now lives in
# _secret_spans(), so these contain only the unconditional patterns.
DEFAULT_REDACTION_PATTERNS = [
    r"(?i)(\bauthorization\b\s*:\s*bearer\s+)[A-Za-z0-9._~+/=-]+",
    r"(?i)(\bbearer\s+)[A-Za-z0-9._~+/=-]{8,}",
    PRIVATE_KEY_RE.pattern,
]
RESIDUAL_SECRET_PATTERNS = [
    re.compile(r"(?i)\bauthorization\b\s*:\s*bearer\s+(?!\[REDACTED\]\b)[A-Za-z0-9._~+/=-]{8,}"),
    re.compile(r"(?i)\bbearer\s+(?!\[REDACTED\]\b)[A-Za-z0-9._~+/=-]{20,}"),
    PRIVATE_KEY_RE,
]


CONTRACTOR_PACKET_REQUIRED_FIELDS = [
    "dispatch_id",
    "generated_at",
    "bead_id",
    "executor",
    "provider_key",
    "provider_trust_tier",
    "share_boundary",
    "disclosure_stage",
    "disclosure_escalation_approved",
    "job_description_label",
    "expert_profile_included",
    "degraded_context_justification",
    "external_opt_in",
    "opt_in_basis",
    "boundary_description",
    "bead_summary",
    "selected_snippets",
    "included_artifacts",
    "excluded_artifacts",
    "required_return_sections",
    "acceptance_rule",
    "quota_checked",
    "packet_sha256",
]


LOCAL_DISPATCH_REQUIRED_FIELDS = [
    "envelope_type",
    "version",
    "dispatch_id",
    "executor_key",
    "provider_key",
    "transport_kind",
    "messages",
    "constraints",
    "execution_enabled",
]


def _matching_bracket_pairs(value: str) -> list[tuple[int, int]]:
    pairs: list[tuple[int, int]] = []
    stack: list[tuple[str, int]] = []
    quote: str | None = None
    escaped = False
    matching = {"}": "{", "]": "["}
    for index, character in enumerate(value):
        if quote:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == quote:
                quote = None
            continue
        if character in "\"'":
            quote = character
        elif character in "{[":
            stack.append((character, index))
        elif character in matching and stack and stack[-1][0] == matching[character]:
            _, start = stack.pop()
            pairs.append((start, index))
    return pairs


def _find_balanced_inline_container(
    value: str, start: int, context_indent: int | None = None
) -> tuple[int, int] | None:
    if start >= len(value) or value[start] not in "{[":
        return None
    open_bracket = value[start]
    close_bracket = {"{": "}", "[": "]"}[open_bracket]
    openers: list[str] = [open_bracket]
    line_start = value.rfind("\n", 0, start) + 1
    if context_indent is None:
        line_prefix = value[line_start:start]
        context_indent = len(line_prefix) - len(line_prefix.lstrip(" \t"))
    quote: str | None = None
    escaped = False
    closing = {"}": "{", "]": "["}
    for index in range(start + 1, len(value)):
        character = value[index]
        if quote:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == quote:
                quote = None
            continue
        if character in "\"'":
            quote = character
            continue
        if character in "{[":
            openers.append(character)
            continue
        if character in closing:
            if not openers:
                return None
            if openers[-1] != closing[character]:
                return None
            openers.pop()
            if not openers:
                return (start, index + 1)
        if character == "\n":
            next_line_start = index + 1
            if next_line_start < len(value) and value[next_line_start] == "\r":
                next_line_start += 1
            if next_line_start >= len(value):
                return None
            next_line_end = value.find("\n", next_line_start)
            if next_line_end == -1:
                next_line_end = len(value)
            next_line = value[next_line_start:next_line_end].rstrip("\r")
            next_line = next_line.rstrip("\n")
            next_line_stripped = next_line.strip()
            if next_line_stripped and not next_line_stripped.startswith("#"):
                next_indent = len(next_line) - len(next_line.lstrip(" \t"))
                if next_indent < context_indent:
                    return None
                if next_indent == context_indent and not next_line_stripped.startswith(close_bracket):
                    return None
    return None


def _containing_inline_structure(value: str, index: int) -> tuple[int, int] | None:
    containing = [pair for pair in _matching_bracket_pairs(value) if pair[0] < index < pair[1]]
    return max(containing, key=lambda pair: pair[0]) if containing else None


def _inside_unclosed_inline_structure(value: str, index: int) -> bool:
    stack: list[str] = []
    quote: str | None = None
    escaped = False
    matching = {"}": "{", "]": "["}
    for character in value[:index]:
        if quote:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == quote:
                quote = None
            continue
        if character in "\"'":
            quote = character
        elif character in "{[":
            stack.append(character)
        elif character in matching and stack and stack[-1] == matching[character]:
            stack.pop()
    return bool(stack)


def _field_position_start(value: str) -> int:
    match = FIELD_PREFIX_RE.match(value)
    return match.end() if match else 0


def _inline_value_end(value: str, start: int, close: int) -> int:
    stack: list[str] = []
    quote: str | None = None
    escaped = False
    matching = {"}": "{", "]": "["}
    for index in range(start, close):
        character = value[index]
        if quote:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == quote:
                quote = None
            continue
        if character in "\"'":
            quote = character
        elif character in "{[":
            stack.append(character)
        elif character in matching and stack and stack[-1] == matching[character]:
            stack.pop()
        elif character == "," and not stack:
            return index
    return close


def _line_value_end(value: str, start: int) -> int:
    quote: str | None = None
    escaped = False
    for index in range(start, len(value)):
        character = value[index]
        if quote:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == quote:
                quote = None
            continue
        if character in "\"'":
            quote = character
        elif character == "#" and index > start and value[index - 1] in " \t":
            return index - 1
    return len(value)


def _quoted_value_end(value: str, start: int, limit: int) -> int | None:
    quote = value[start]
    escaped = False
    for index in range(start + 1, limit):
        character = value[index]
        if escaped:
            escaped = False
        elif character == "\\":
            escaped = True
        elif character == quote:
            return index
    return None


def _structural_value_span(value: str, start: int, limit: int) -> tuple[int, int] | None:
    while start < limit and value[start] in " \t":
        start += 1
    if start >= limit:
        return None
    end = limit
    if value[start] in "\"'":
        quote_end = _quoted_value_end(value, start, limit)
        if quote_end is not None:
            trailing = value[quote_end + 1 : limit].strip()
            if not trailing or trailing.startswith("#") or trailing[0] in ",}]":
                inner_start, inner_end = start + 1, quote_end
                if value[inner_start:inner_end].strip() == REDACTION_SENTINEL:
                    return None
                return (inner_start, inner_end) if inner_start < inner_end else None
        return None
    while end > start and value[end - 1] in " \t":
        end -= 1
    if start >= end or value[start:end].strip() == REDACTION_SENTINEL:
        return None
    return start, end


def _prose_candidate_span(value: str, start: int, limit: int) -> tuple[int, int] | None:
    while start < limit and value[start] in " \t":
        start += 1
    if start >= limit:
        return None
    if value[start] in "\"'":
        quote_end = _quoted_value_end(value, start, limit)
        if quote_end is None:
            return None
        return start + 1, quote_end
    end = start
    while end < limit and not value[end].isspace() and value[end] not in ",;)}]":
        end += 1
    while end > start and value[end - 1] in ".!?":
        end -= 1
    return (start, end) if start < end else None


def _looks_like_credential(candidate: str) -> bool:
    if not candidate or candidate == REDACTION_SENTINEL:
        return False
    if KNOWN_CREDENTIAL_PREFIX_RE.fullmatch(candidate):
        return True
    if len(candidate) >= 20 and JWT_RE.fullmatch(candidate):
        return True
    if "://" in candidate:
        return True
    if len(candidate) >= 6 and candidate.isdigit():
        return True
    if len(candidate) >= 16 and re.fullmatch(r"[A-Fa-f0-9]+", candidate):
        return True
    if (
        len(candidate) >= 6
        and re.fullmatch(r"[A-Za-z0-9_-]+", candidate)
        and any(character.isalpha() for character in candidate)
        and any(character.isdigit() for character in candidate)
    ):
        return True
    if (
        len(candidate) >= 20
        and re.fullmatch(r"[A-Za-z0-9+/=_-]+", candidate)
        and (any(character.isupper() for character in candidate) or any(character in "+/=" for character in candidate))
    ):
        return True
    punctuation = [character for character in candidate if character in "._~+/=-"]
    return (
        len(candidate) >= 8
        and bool(re.fullmatch(r"[A-Za-z0-9._~+/=-]+", candidate))
        and bool(re.search(r"[A-Za-z0-9]", candidate))
        and (any(character in "._~+/=" for character in punctuation) or len(punctuation) >= 2)
    )


def _looks_like_secret_value(candidate: str) -> bool:
    if not candidate or candidate == REDACTION_SENTINEL:
        return False
    if _looks_like_credential(candidate):
        return True
    return bool(re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{11,}", candidate))


def _is_markdown_heading_line(value: str) -> bool:
    return bool(re.match(r"^[ \t]*(?:>[ \t]*)*#{1,6}\s", value))


def _is_comment_only_line(value: str) -> bool:
    stripped = value.strip()
    return bool(stripped) and stripped.lstrip(" \t").startswith("#")


def _line_scalar_tail_span(line: str, start: int, line_offset: int) -> tuple[int, int] | None:
    while start < len(line) and line[start] in " \t":
        start += 1
    if start >= len(line):
        return None
    if _is_comment_only_line(line[start:]):
        return None

    if line[start] in "\"'":
        quote_end = _quoted_value_end(line, start, len(line))
        if quote_end is None:
            return None
        trailing = line[quote_end + 1 :].strip()
        if trailing and not (trailing.startswith("#") or trailing[0] in ",}]"):
            return None
        inner_start, inner_end = start + 1, quote_end
        if line[inner_start:inner_end].strip() == REDACTION_SENTINEL:
            return None
        return line_offset + inner_start, line_offset + inner_end

    if line[start] in "{[":
        return None

    span = _prose_candidate_span(line, start, len(line))
    if not span:
        return None
    candidate_start, candidate_end = span
    candidate = line[candidate_start:candidate_end].strip()
    if (
        not candidate
        or candidate == REDACTION_SENTINEL
        or candidate[0] in "{["
        or (":" in candidate and not _looks_like_credential(candidate))
    ):
        return None
    return line_offset + candidate_start, line_offset + candidate_end


def _assignment_spans(
    value: str,
    base: int,
    *,
    field_assignment_re: re.Pattern[str],
    leading_field_re: re.Pattern[str],
) -> list[tuple[int, int, str]]:
    is_comment_form = False
    comment_prefix_match = COMMENT_FIELD_ASSIGNMENT_RE.match(value)
    if comment_prefix_match and field_assignment_re.match(value, comment_prefix_match.end()):
        base += comment_prefix_match.end()
        value = value[comment_prefix_match.end() :]
        is_comment_form = True

    spans: list[tuple[int, int, str]] = []
    field_start = _field_position_start(value)
    is_heading_line = not is_comment_form and _is_markdown_heading_line(value)
    base_indent = len(value) - len(value.lstrip(" \t"))
    for match in field_assignment_re.finditer(value):
        structure = _containing_inline_structure(value, match.start())
        structural = (
            match.group("operator") == "="
            or match.start() == field_start
            or structure is not None
            or _inside_unclosed_inline_structure(value, match.start())
        )
        if is_heading_line and not structural:
            continue
        value_start = match.end()
        while value_start < len(value) and value[value_start] in " \t":
            value_start += 1
        if (
            value_start < len(value)
            and value[value_start] in "{["
            and _find_balanced_inline_container(
                value, value_start, context_indent=base_indent
            )
            is None
        ):
            continue
        limit = _inline_value_end(value, match.end(), structure[1]) if structure else _line_value_end(value, match.end())
        span = (
            _structural_value_span(value, value_start, limit)
            if structural
            else _prose_candidate_span(value, match.end(), limit)
        )
        if span and (structural or _looks_like_secret_value(value[span[0] : span[1]])):
            spans.append((base + span[0], base + span[1], "secret-field-assignment"))

    leading = leading_field_re.match(value, field_start)
    if leading:
        limit = _line_value_end(value, leading.end())
        candidate = _structural_value_span(value, leading.end(), limit)
        raw_value = value[leading.end() : limit].strip()
        quoted_value = bool(raw_value) and raw_value[0] in "\"'"
        single_value = (
            bool(raw_value)
            and not any(character.isspace() for character in raw_value)
            and leading.group("key") == leading.group("key").lower()
            and raw_value[-1] not in ".!?"
        )
        unambiguous = (
            bool(leading.group("quote"))
            or leading.group("key").startswith("_")
            or quoted_value
            or _looks_like_secret_value(raw_value)
        )
        if candidate and unambiguous:
            span = candidate
            spans.append((base + span[0], base + span[1], "secret-field-whitespace-assignment"))
    return spans


def _multiline_structural_spans(
    value: str,
    *,
    field_assignment_re: re.Pattern[str],
) -> list[tuple[int, int, str]]:
    spans: list[tuple[int, int, str]] = []
    lines = value.splitlines(keepends=True)
    offsets: list[int] = []
    offset = 0
    for line in lines:
        offsets.append(offset)
        offset += len(line)

    for line_index, line_with_ending in enumerate(lines):
        line = line_with_ending.rstrip("\r\n")
        field_start = _field_position_start(line)
        for match in field_assignment_re.finditer(line):
            structure = _containing_inline_structure(line, match.start())
            structural = (
                match.group("operator") == "="
                or match.start() == field_start
                or structure is not None
                or _inside_unclosed_inline_structure(line, match.start())
            )
            if not structural:
                continue
            local_start = match.end()
            base_indent = len(line) - len(line.lstrip(" \t"))
            while local_start < len(line) and line[local_start] in " \t":
                local_start += 1

            if local_start >= len(line):
                continuation_start: int | None = None
                for next_index in range(line_index + 1, len(lines)):
                    next_line = lines[next_index].rstrip("\r\n")
                    if not next_line.strip():
                        continue
                    next_indent = len(next_line) - len(next_line.lstrip(" \t"))
                    if next_indent <= base_indent:
                        break
                    if _is_comment_only_line(next_line):
                        continue
                    continuation_start = next_index
                    break
                if continuation_start is None:
                    continue

                next_line = lines[continuation_start].rstrip("\r\n")
                continuation_indent = len(next_line) - len(next_line.lstrip(" \t"))
                continuation = next_line[continuation_indent:]
                if continuation.startswith("- "):
                    for list_index in range(continuation_start, len(lines)):
                        list_line = lines[list_index].rstrip("\r\n")
                        if not list_line.strip():
                            continue
                        list_indent = len(list_line) - len(list_line.lstrip(" \t"))
                        if list_indent < continuation_indent:
                            break
                        list_content = list_line[list_indent:]
                        if _is_comment_only_line(list_content):
                            continue
                        if not list_content.startswith("- "):
                            if list_indent <= continuation_indent:
                                break
                            continue
                        list_value_start = list_indent + 2
                        span = _line_scalar_tail_span(list_line, list_value_start, offsets[list_index])
                        if span is not None:
                            spans.append((span[0], span[1], "multiline-list-scalar"))
                    continue

                span = _line_scalar_tail_span(next_line, continuation_indent, offsets[continuation_start])
                if span is not None:
                    spans.append((span[0], span[1], "multiline-plain-value"))
                continue

            global_start = offsets[line_index] + local_start
            if line[local_start] in "{[":
                container_span = _find_balanced_inline_container(
                    value, global_start, context_indent=base_indent
                )
                if container_span is not None:
                    spans.append((container_span[0], container_span[1], INLINE_CONTAINER_SPAN_REASON))
                else:
                    spans.append((global_start, offsets[line_index] + len(line), "unbalanced-inline-container"))
                continue
            if line[local_start] in "\"'" and _quoted_value_end(line, local_start, len(line)) is None:
                global_quote_end = _quoted_value_end(value, global_start, len(value))
                if global_quote_end is None:
                    spans.append((global_start, len(value), "unclosed-structural-value"))
                elif value[global_start + 1 : global_quote_end].strip() != REDACTION_SENTINEL:
                    spans.append((global_start + 1, global_quote_end, "multiline-quoted-value"))
                continue

            value_without_comment = line[local_start : _line_value_end(line, local_start)].strip()
            if not re.fullmatch(r"[|>](?:[1-9]?[+-]?|[+-]?[1-9]?)", value_without_comment):
                continue
            base_indent = len(line) - len(line.lstrip(" \t"))
            block_end = offsets[line_index] + len(line)
            block_indent: int | None = None
            for next_index in range(line_index + 1, len(lines)):
                next_line = lines[next_index].rstrip("\r\n")
                if next_line.strip():
                    next_indent = len(next_line) - len(next_line.lstrip(" \t"))
                    if block_indent is None:
                        if next_indent <= base_indent:
                            break
                        block_indent = next_indent
                    elif next_indent < block_indent:
                        break
                block_end = offsets[next_index] + len(next_line)
            while block_end > global_start and value[block_end - 1] in "\r\n":
                block_end -= 1
            spans.append((global_start, block_end, "yaml-block-scalar"))
    return spans


def _configured_pattern_spans(value: str) -> list[tuple[int, int, str]]:
    spans: list[tuple[int, int, str]] = []
    for pattern in load_policy("share-boundaries").get("redaction_patterns", []):
        for match in re.finditer(pattern, value):
            start, end = match.span()
            if match.groups() and match.group(1) is not None:
                start = match.end(1)
            if start < end and value[start:end].strip() != REDACTION_SENTINEL:
                spans.append((start, end, "configured-redaction-pattern"))
    return spans


def _secret_spans(
    value: str, *, require_policy_patterns: bool = False
) -> list[tuple[int, int, str]]:
    _, _, field_assignment_re, leading_field_re = _effective_secret_field_pattern_state(
        require_policy_patterns=require_policy_patterns
    )
    spans: list[tuple[int, int, str]] = []
    for match in PRIVATE_KEY_RE.finditer(value):
        spans.append((*match.span(), "private-key"))
    for pattern in [AUTHORIZATION_BEARER_RE, BARE_BEARER_RE]:
        for match in pattern.finditer(value):
            spans.append((*match.span("value"), "bearer-credential"))
    spans.extend(
        _multiline_structural_spans(
            value,
            field_assignment_re=field_assignment_re,
        )
    )
    offset = 0
    for line_with_ending in value.splitlines(keepends=True):
        line = line_with_ending.rstrip("\r\n")
        spans.extend(
            _assignment_spans(
                line,
                offset,
                field_assignment_re=field_assignment_re,
                leading_field_re=leading_field_re,
            )
        )
        offset += len(line_with_ending)
    if offset < len(value):
        spans.extend(
            _assignment_spans(
                value[offset:],
                offset,
                field_assignment_re=field_assignment_re,
                leading_field_re=leading_field_re,
            )
        )
    spans.extend(_configured_pattern_spans(value))
    return sorted(set(spans), key=lambda span: (span[0], span[1], span[2]))


def _coalesced_secret_spans(
    value: str, *, include_risky_spans: bool = False, require_policy_patterns: bool = False
) -> list[tuple[int, int, str]]:
    merged: list[list[object]] = []
    for start, end, reason in _secret_spans(value, require_policy_patterns=require_policy_patterns):
        if start >= end or value[start:end].strip() == REDACTION_SENTINEL:
            continue
        if reason == "unbalanced-inline-container" and not include_risky_spans:
            continue
        if merged and start <= merged[-1][1]:
            merged_end = max(merged[-1][1], end)
            merged_reason = (
                merged[-1][2]
                if merged[-1][2] in _REASON_CONTAINER_REDACTION
                else reason if reason in _REASON_CONTAINER_REDACTION else merged[-1][2]
            )
            merged[-1][1] = merged_end
            merged[-1][2] = merged_reason
        else:
            merged.append([start, end, reason])
    return [(start, end, reason) for start, end, reason in merged]


def _redaction_for_reason(reason: str) -> str:
    if reason in _REASON_CONTAINER_REDACTION:
        return json.dumps(REDACTION_SENTINEL)
    return REDACTION_SENTINEL


def redact_text(value: str, *, require_policy_patterns: bool = False) -> str:
    redacted = value
    for start, end, reason in reversed(
        _coalesced_secret_spans(value, require_policy_patterns=require_policy_patterns)
    ):
        redacted = redacted[:start] + _redaction_for_reason(reason) + redacted[end:]
    return redacted


def redact_value(value: Any, *, require_policy_patterns: bool = False) -> Any:
    if isinstance(value, str):
        return redact_text(value, require_policy_patterns=require_policy_patterns)
    if isinstance(value, list):
        return [redact_value(item, require_policy_patterns=require_policy_patterns) for item in value]
    if isinstance(value, dict):
        return {
            key: redact_value(item, require_policy_patterns=require_policy_patterns)
            for key, item in value.items()
        }
    return value


def sanitize_boundary_value(value: Any, forbidden: set[str]) -> Any:
    return sanitize_boundary_value_with_patterns(value, forbidden, secret_like_field_re=SECRET_LIKE_FIELD_RE)


def sanitize_boundary_value_with_patterns(
    value: Any,
    forbidden: set[str],
    *,
    secret_like_field_re: re.Pattern[str],
) -> Any:
    if isinstance(value, dict):
        sanitized: dict[str, Any] = {}
        for key, item in value.items():
            key_text = str(key)
            if key_text in forbidden:
                continue
            if secret_like_field_re.search(key_text):
                sanitized[key_text] = "[REDACTED]"
                continue
            sanitized[key_text] = sanitize_boundary_value_with_patterns(
                item,
                forbidden,
                secret_like_field_re=secret_like_field_re,
            )
        return sanitized
    if isinstance(value, list):
        return [
            sanitize_boundary_value_with_patterns(
                item,
                forbidden,
                secret_like_field_re=secret_like_field_re,
            )
            for item in value
        ]
    return redact_value(value, require_policy_patterns=False)


def sanitize_bead(
    bead_json: Any, share_boundary: str, *, require_policy_patterns: bool = False
) -> dict[str, Any]:
    boundary = boundary_config(share_boundary)
    whitelist = set(boundary.get("field_whitelist", []))
    forbidden = set(boundary.get("forbidden_fields", []))
    _, secret_like_field_re, _, _ = _effective_secret_field_pattern_state(
        require_policy_patterns=require_policy_patterns
    )
    if isinstance(bead_json, list) and len(bead_json) == 1 and isinstance(bead_json[0], dict):
        bead_json = bead_json[0]
    elif isinstance(bead_json, list):
        return {
            "raw_type": "list",
            "item_count": len(bead_json),
            "reason": "multi-item bead list requires explicit selection before sharing",
        }
    if not isinstance(bead_json, dict):
        return {"raw_type": type(bead_json).__name__}
    source = bead_json.get("issue") if isinstance(bead_json.get("issue"), dict) else bead_json
    sanitized: dict[str, Any] = {}
    for key, value in source.items():
        if key in forbidden:
            continue
        if whitelist and key not in whitelist:
            continue
        if secret_like_field_re.search(str(key)):
            sanitized[key] = "[REDACTED]"
        else:
            sanitized[key] = sanitize_boundary_value_with_patterns(
                value,
                forbidden,
                secret_like_field_re=secret_like_field_re,
            )
    return sanitized


def _value_is_redacted(value: Any) -> bool:
    return isinstance(value, str) and value.strip() == REDACTION_SENTINEL


def find_residual_private_context(
    value: Any, prefix: str = "", *, require_policy_patterns: bool = False
) -> list[str]:
    hits: list[str] = []
    _, secret_like_field_re, _, _ = _effective_secret_field_pattern_state(
        require_policy_patterns=require_policy_patterns
    )
    if isinstance(value, dict):
        for key, item in value.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            if secret_like_field_re.search(str(key)) and not _value_is_redacted(item):
                hits.append(path)
            hits.extend(
                find_residual_private_context(
                    item, path, require_policy_patterns=require_policy_patterns
                )
            )
    elif isinstance(value, list):
        for index, item in enumerate(value):
            path = f"{prefix}[{index}]" if prefix else f"[{index}]"
            hits.extend(
                find_residual_private_context(
                    item, path, require_policy_patterns=require_policy_patterns
                )
            )
    elif isinstance(value, str):
        if _coalesced_secret_spans(
            value, include_risky_spans=True, require_policy_patterns=require_policy_patterns
        ):
            hits.append(prefix or "<root>")
    return sorted(set(hits))


def artifact_whitelist_for_boundary(share_boundary: str) -> set[str]:
    return set(boundary_config(share_boundary).get("artifact_whitelist", []))


def validate_opt_in_record(
    path: str | Path,
    *,
    executor: str,
    share_boundary: str,
    bead_id: str | None = None,
    epic_id: str | None = None,
) -> dict[str, Any]:
    record_path = Path(path)
    if not record_path.is_file():
        raise SystemExit(f"opt-in record does not exist: {record_path}")
    try:
        record = json.loads(record_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise SystemExit(f"opt-in record is not valid JSON: {record_path}: {exc}") from exc
    if not isinstance(record, dict):
        raise SystemExit("opt-in record must contain a top-level object")

    auth_fields = {
        key: record[key]
        for key in ["allowed", "external_contracting_allowed"]
        if key in record
    }
    if len(auth_fields) == 2 and auth_fields["allowed"] != auth_fields["external_contracting_allowed"]:
        raise SystemExit("opt-in record has conflicting allowed and external_contracting_allowed values")
    if not auth_fields or not all(value is True for value in auth_fields.values()):
        raise SystemExit("opt-in record must set allowed=true or external_contracting_allowed=true")

    boundaries = record.get("share_boundaries", record.get("share_boundary"))
    if isinstance(boundaries, str):
        boundary_allowed = boundaries in [share_boundary, "*"]
    elif isinstance(boundaries, list):
        boundary_allowed = share_boundary in boundaries or "*" in boundaries
    else:
        boundary_allowed = False
    if not boundary_allowed:
        raise SystemExit(f"opt-in record does not allow share boundary {share_boundary!r}")

    executors = record.get(
        "allowed_external_executors",
        record.get("allowed_executors", record.get("executors", record.get("executor"))),
    )
    if not executor_key_allowed(executor, executors):
        raise SystemExit(f"opt-in record does not allow executor {executor!r}")
    allowed_providers = record.get("allowed_providers")
    if allowed_providers is not None:
        executor_info = load_policy("executor-registry").get("executors", {}).get(executor, {})
        provider_key = executor_info.get("provider_key")
        if isinstance(allowed_providers, str):
            provider_allowed = allowed_providers in [provider_key, "*"]
        elif isinstance(allowed_providers, list):
            provider_allowed = provider_key in allowed_providers or "*" in allowed_providers
        else:
            provider_allowed = False
        if not provider_allowed:
            raise SystemExit(f"opt-in record does not allow provider {provider_key!r}")

    if not record.get("decision_source"):
        raise SystemExit("opt-in record must include decision_source")
    if not record.get("recorded_at"):
        raise SystemExit("opt-in record must include recorded_at")
    parse_iso_datetime(str(record["recorded_at"]), "recorded_at")
    expires_at = record.get("expires_at")
    if expires_at:
        expiry = parse_iso_datetime(str(expires_at), "expires_at")
        if expiry <= dt.datetime.now(dt.timezone.utc):
            raise SystemExit("opt-in record has expired")
    if not record.get("scope"):
        raise SystemExit("opt-in record must include scope")
    record_bead = record.get("bead_id")
    if record_bead and bead_id and record_bead != bead_id:
        raise SystemExit(f"opt-in record bead_id {record_bead!r} does not match assigned bead {bead_id!r}")
    record_epic = record.get("epic_id")
    if record_epic and epic_id and record_epic != epic_id:
        raise SystemExit(f"opt-in record epic_id {record_epic!r} does not match assigned epic {epic_id!r}")
    return record


def find_forbidden_fields(value: Any, forbidden_fields: set[str], prefix: str = "") -> list[str]:
    hits: list[str] = []
    if isinstance(value, dict):
        for key, item in value.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            if key in forbidden_fields:
                hits.append(path)
            hits.extend(find_forbidden_fields(item, forbidden_fields, path))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            path = f"{prefix}[{index}]" if prefix else f"[{index}]"
            hits.extend(find_forbidden_fields(item, forbidden_fields, path))
    return hits


def validate_contractor_packet(packet: dict[str, Any], *, allow_degraded_packet: bool = False) -> list[str]:
    errors: list[str] = []
    if not isinstance(packet, dict):
        return ["packet must contain a top-level object"]

    try:
        _load_secret_field_aliases()
    except (CWOPolicyError, SystemExit) as exc:
        errors.append(f"invalid secret-field policy configuration: {exc}")

    for field in CONTRACTOR_PACKET_REQUIRED_FIELDS:
        if field not in packet:
            errors.append(f"packet is missing required field {field!r}")
    if errors:
        return errors

    executor_key = str(packet.get("executor", ""))
    executors = load_policy("executor-registry").get("executors", {})
    executor = executors.get(executor_key)
    if not isinstance(executor, dict):
        errors.append(f"packet executor {executor_key!r} is unknown")
    elif not executor.get("external"):
        errors.append(f"packet executor {executor_key!r} is not an outside contractor executor")
    elif packet.get("provider_key") != executor.get("provider_key"):
        errors.append(f"packet provider_key {packet.get('provider_key')!r} does not match executor provider")
    elif packet.get("provider_trust_tier") != provider_profile(executor.get("provider_key")).get("trust_tier"):
        errors.append(f"packet provider_trust_tier {packet.get('provider_trust_tier')!r} does not match provider registry")

    controls = load_contracting_controls()
    allowed_external = controls.get("allowed_external_executors", [])
    if allowed_external and not executor_key_allowed(executor_key, allowed_external):
        errors.append(f"packet executor {executor_key!r} is not allowed by contracting controls")

    raw_packet_version = packet.get("packet_version")
    packet_version = 1 if raw_packet_version is None else raw_packet_version
    if not isinstance(packet_version, int) or isinstance(packet_version, bool) or packet_version < 1:
        errors.append("packet_version must be a positive integer when present")
    expected_language = packet.get("expected_return_language")
    if isinstance(packet_version, int) and packet_version >= 2 and expected_language in {None, ""}:
        errors.append("version-2 contractor packet is missing expected_return_language")
    if expected_language not in {None, ""}:
        try:
            validate_expected_return_language(str(expected_language))
        except CWOPolicyError as exc:
            errors.append(str(exc))

    share_boundary = str(packet.get("share_boundary", ""))
    try:
        boundary = boundary_config(share_boundary)
    except SystemExit as exc:
        errors.append(str(exc))
        boundary = {}
    if boundary and not boundary.get("allows_external"):
        errors.append(f"packet share boundary {share_boundary!r} does not allow external contracting")
    if boundary:
        expected_stage = str(boundary.get("disclosure_stage", share_boundary))
        if packet.get("disclosure_stage") != expected_stage:
            errors.append(
                f"packet disclosure_stage {packet.get('disclosure_stage')!r} does not match boundary stage {expected_stage!r}"
            )
        if boundary.get("requires_disclosure_escalation") and packet.get("disclosure_escalation_approved") is not True:
            errors.append(f"packet share boundary {share_boundary!r} requires disclosure escalation approval")

    if packet.get("external_opt_in") is not True:
        errors.append("packet external_opt_in must be true")
    if packet.get("opt_in_basis") in [None, "", "not-recorded"]:
        errors.append("packet opt_in_basis must record explicit user opt-in")
    job_label = str(packet.get("job_description_label", ""))
    if not job_label.startswith("contract-jd-"):
        errors.append("packet job_description_label must be a contract-jd label")
    registry_job_labels = {
        str(profile.get("job_description_label"))
        for profile in load_policy("expert-registry").get("experts", {}).values()
        if isinstance(profile, dict) and profile.get("job_description_label")
    }
    if registry_job_labels and job_label not in registry_job_labels:
        errors.append(f"packet job_description_label {job_label!r} is not registered")
    bead_labels = packet.get("bead_summary", {}).get("labels", []) if isinstance(packet.get("bead_summary"), dict) else []
    if isinstance(bead_labels, list):
        label_set = {str(label) for label in bead_labels}
        missing_guard_labels = sorted({"contractor-only", "no-codex-exec"} - label_set)
        if missing_guard_labels:
            errors.append("packet bead_summary is missing contractor guard labels: " + ", ".join(missing_guard_labels))
        job_labels = [str(label) for label in bead_labels if str(label).startswith("contract-jd-")]
        if len(job_labels) != 1:
            errors.append(
                "packet bead_summary must contain exactly one primary job-description label"
                + (": " + ", ".join(job_labels) if job_labels else "")
            )
        elif job_label not in job_labels:
            errors.append("packet job_description_label does not match bead_summary job-description label")
    else:
        errors.append("packet bead_summary labels must be a list")
    if packet.get("expert_profile_included") is not True and not allow_degraded_packet:
        errors.append("packet is missing the expert profile; pass --allow-degraded-packet to dispatch anyway")
    if packet.get("expert_profile_included") is not True and not str(packet.get("degraded_context_justification", "")).strip():
        errors.append("degraded packet is missing degraded_context_justification")

    expected_hash = packet_payload_hash(packet)
    if packet.get("packet_sha256") != expected_hash:
        errors.append("packet_sha256 does not match packet payload")

    forbidden_fields = set(boundary.get("forbidden_fields", [])) if boundary else set()
    forbidden_hits = find_forbidden_fields(packet, forbidden_fields)
    if forbidden_hits:
        errors.append("packet contains forbidden boundary fields: " + ", ".join(sorted(forbidden_hits)))
    residual_hits = find_residual_private_context(
        {
            "bead_summary": packet.get("bead_summary"),
            "selected_snippets": packet.get("selected_snippets"),
        },
        require_policy_patterns=True,
    )
    if residual_hits:
        errors.append("packet contains residual private or secret-like context at: " + ", ".join(residual_hits))

    excluded_types = {
        artifact.get("type")
        for artifact in packet.get("excluded_artifacts", [])
        if isinstance(artifact, dict)
    }
    missing_exclusions = sorted(MANDATORY_EXCLUDED_ARTIFACTS - excluded_types)
    if missing_exclusions:
        errors.append("excluded_artifacts is missing mandatory exclusions: " + ", ".join(missing_exclusions))

    whitelist = set(boundary.get("artifact_whitelist", [])) if boundary else set()
    included_artifacts = [item for item in packet.get("included_artifacts", []) if isinstance(item, dict)]
    selected_snippets = [item for item in packet.get("selected_snippets", []) if isinstance(item, dict)]
    snippet_limit = int(boundary.get("snippet_line_limit", 0)) if boundary else 0
    for artifact in packet.get("included_artifacts", []):
        artifact_type = artifact.get("type") if isinstance(artifact, dict) else None
        if not artifact_type:
            errors.append("included_artifacts contains an artifact without a type")
        elif artifact_type not in whitelist:
            errors.append(f"artifact type {artifact_type!r} is not allowed by share boundary {share_boundary!r}")

    for snippet in packet.get("selected_snippets", []):
        if not isinstance(snippet, dict):
            errors.append("selected_snippets contains a non-object entry")
            continue
        required_snippet_fields = {"type", "path", "line_count", "truncated", "sha256", "content"}
        missing = sorted(required_snippet_fields - set(snippet))
        if missing:
            errors.append(f"selected snippet {snippet.get('path', '<unknown>')} is missing fields: {', '.join(missing)}")
        snippet_type = snippet.get("type") if isinstance(snippet, dict) else None
        if snippet_type and snippet_type not in whitelist:
            errors.append(f"snippet artifact type {snippet_type!r} is not allowed by share boundary {share_boundary!r}")
        line_count = snippet.get("line_count")
        if not isinstance(line_count, int):
            errors.append(f"selected snippet {snippet.get('path', '<unknown>')} has non-integer line_count")
        elif snippet_limit and line_count > snippet_limit:
            errors.append(
                f"selected snippet {snippet.get('path', '<unknown>')} exceeds boundary line limit {snippet_limit}"
            )
        content = snippet.get("content")
        sha256 = snippet.get("sha256")
        if isinstance(content, str) and isinstance(sha256, str) and artifact_hash(content) != sha256:
            errors.append(f"selected snippet {snippet.get('path', '<unknown>')} sha256 does not match content")

    assignment = next((item for item in included_artifacts if item.get("type") == "assignment_summary"), None)
    if not assignment:
        errors.append("included_artifacts is missing assignment_summary")
    elif assignment.get("sha256") != artifact_hash(json.dumps(packet.get("bead_summary", {}), sort_keys=True)):
        errors.append("assignment_summary sha256 does not match bead_summary")

    if packet.get("expert_profile_included"):
        profile = packet.get("expert_profile") or {}
        profile_artifact = next((item for item in included_artifacts if item.get("type") == "expert_profile"), None)
        if not profile_artifact:
            errors.append("included_artifacts is missing expert_profile")
        elif isinstance(profile, dict):
            if profile_artifact.get("path") != profile.get("path") or profile_artifact.get("sha256") != profile.get("sha256"):
                errors.append("expert_profile artifact does not match expert_profile payload")
            content = profile.get("content")
            if not isinstance(content, str) or not content.strip():
                errors.append("expert_profile.content is required when expert_profile_included is true")
            elif artifact_hash(content) != profile.get("sha256"):
                errors.append("expert_profile sha256 does not match content")
        else:
            errors.append("expert_profile must be an object when expert_profile_included is true")

    for artifact in included_artifacts:
        artifact_type = artifact.get("type")
        if artifact_type in {"selected_file_snippet", "inline_snippet"}:
            match = next(
                (
                    snippet
                    for snippet in selected_snippets
                    if snippet.get("type") == artifact_type
                    and snippet.get("path") == artifact.get("path")
                    and snippet.get("sha256") == artifact.get("sha256")
                ),
                None,
            )
            if not match:
                errors.append(f"included artifact {artifact_type}:{artifact.get('path')} has no matching selected snippet")

    if not packet.get("required_return_sections"):
        errors.append("packet required_return_sections must not be empty")
    return errors


def contractor_packet_language_metadata(packet: dict[str, Any]) -> tuple[str, str]:
    raw_version = packet.get("packet_version")
    packet_version = 1 if raw_version is None else raw_version
    if not isinstance(packet_version, int) or isinstance(packet_version, bool) or packet_version < 1:
        raise CWOPolicyError("packet_version must be a positive integer when present")
    raw = packet.get("expected_return_language")
    if raw not in {None, ""}:
        resolved = validate_expected_return_language(str(raw))
        if resolved is None:
            raise CWOPolicyError("contractor packet expected_return_language is empty")
        source = "packet-v2" if packet_version >= 2 else "packet"
        return resolved, source
    if packet_version >= 2:
        raise CWOPolicyError("version-2 contractor packet is missing expected_return_language")
    return default_expected_return_language(), "legacy-policy-default"


def local_dispatch_language_metadata(envelope: dict[str, Any]) -> tuple[str, str]:
    raw_version = envelope.get("version")
    version = 1 if raw_version is None else raw_version
    if not isinstance(version, int) or isinstance(version, bool) or version < 1:
        raise CWOPolicyError("local dispatch envelope version must be a positive integer")
    raw = envelope.get("expected_return_language")
    if raw not in {None, ""}:
        resolved = validate_expected_return_language(str(raw))
        if resolved is None:
            raise CWOPolicyError("local dispatch envelope expected_return_language is empty")
        source = "local-envelope-v2" if version >= 2 else "local-envelope"
        return resolved, source
    if version >= 2:
        raise CWOPolicyError("version-2 local dispatch envelope is missing expected_return_language")
    return default_expected_return_language(), "legacy-policy-default"


def contractor_packet_evaluation_metadata(packet: dict[str, Any]) -> dict[str, Any]:
    expected_language, expected_language_source = contractor_packet_language_metadata(packet)
    return {
        "bead": packet.get("bead_id"),
        "bead_id": packet.get("bead_id"),
        "dispatch_id": packet.get("dispatch_id"),
        "packet_sha256": packet.get("packet_sha256"),
        "share_boundary": packet.get("share_boundary"),
        "job_description": packet.get("job_description_label"),
        "executor": packet.get("executor"),
        "provider_key": packet.get("provider_key"),
        "provider_trust_tier": packet.get("provider_trust_tier"),
        "expected_return_language": expected_language,
        "expected_return_language_source": expected_language_source,
    }


def require_valid_contractor_packet(packet: dict[str, Any], *, allow_degraded_packet: bool = False) -> None:
    errors = validate_contractor_packet(packet, allow_degraded_packet=allow_degraded_packet)
    if errors:
        raise SystemExit("invalid contractor packet:\n- " + "\n- ".join(errors))


def load_expert_profile(persona_file: str | None, *, require_policy_patterns: bool = False) -> dict[str, str]:
    if not persona_file:
        return {}
    safe_path = assert_repo_safe_path(REPO_ROOT / persona_file)
    relative = Path(repo_relative_path(safe_path))
    if not relative.parts or relative.parts[0] != "experts" or safe_path.suffix != ".md":
        raise SystemExit("expert profile must be a Markdown file under experts/")
    content = redact_text(
        safe_path.read_text(encoding="utf-8"),
        require_policy_patterns=require_policy_patterns,
    )
    line_count = len(content.splitlines())
    if line_count > 220:
        raise SystemExit(f"expert profile exceeds line limit 220: {relative.as_posix()}")
    return {
        "path": relative.as_posix(),
        "sha256": artifact_hash(content),
        "content": content,
    }


def file_snippet(path: Path, *, max_lines: int, require_policy_patterns: bool = False) -> dict[str, Any]:
    repo_path = assert_repo_safe_path(path)
    relative = repo_relative_path(repo_path)
    lines = repo_path.read_text(encoding="utf-8", errors="replace").splitlines()
    selected = "\n".join(lines[:max_lines])
    redacted = redact_text(selected, require_policy_patterns=require_policy_patterns)
    return {
        "type": "selected_file_snippet",
        "path": relative,
        "line_count": min(len(lines), max_lines),
        "truncated": len(lines) > max_lines,
        "sha256": artifact_hash(redacted),
        "content": redacted,
    }


def attestation_payload_hash(attestation: dict[str, Any]) -> str:
    payload = dict(attestation)
    payload.pop("attestation_sha256", None)
    return artifact_hash(json.dumps(payload, sort_keys=True))


def make_attestation(
    *,
    subject_type: str,
    subject_sha256: str,
    subject_id: str | None = None,
    issuer: str = "complex-work-orchestration",
    predicate: dict[str, Any] | None = None,
) -> dict[str, Any]:
    attestation: dict[str, Any] = {
        "attestation_type": "sha256-subject-attestation",
        "version": 1,
        "issued_at": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "issuer": issuer,
        "subject_type": subject_type,
        "subject_id": subject_id,
        "subject_sha256": subject_sha256,
        "predicate": predicate or {},
    }
    attestation["attestation_sha256"] = attestation_payload_hash(attestation)
    return attestation


def verify_attestation(
    subject: str | bytes,
    attestation: dict[str, Any],
    *,
    expected_subject_type: str | None = None,
    expected_subject_id: str | None = None,
    expected_predicate: dict[str, Any] | None = None,
) -> dict[str, Any]:
    subject_bytes = subject if isinstance(subject, bytes) else subject.encode("utf-8")
    actual_subject_hash = hashlib.sha256(subject_bytes).hexdigest()
    errors: list[str] = []
    if not isinstance(attestation, dict):
        errors.append("attestation must be an object")
        return {
            "valid": False,
            "errors": errors,
            "subject_sha256": actual_subject_hash,
            "attestation_sha256": None,
        }
    expected_attestation_hash = attestation_payload_hash(attestation)
    if attestation.get("attestation_type") != "sha256-subject-attestation":
        errors.append("attestation_type must be sha256-subject-attestation")
    if attestation.get("version") != 1:
        errors.append("attestation version must be 1")
    if not isinstance(attestation.get("predicate"), dict):
        errors.append("attestation predicate must be an object")
    if expected_subject_type and attestation.get("subject_type") != expected_subject_type:
        errors.append("subject_type does not match expected context")
    if expected_subject_id and attestation.get("subject_id") != expected_subject_id:
        errors.append("subject_id does not match expected context")
    if expected_predicate:
        predicate = attestation.get("predicate") if isinstance(attestation.get("predicate"), dict) else {}
        for key, expected in expected_predicate.items():
            if predicate.get(key) != expected:
                errors.append(f"predicate {key!r} does not match expected context")
    if attestation.get("subject_sha256") != actual_subject_hash:
        errors.append("subject_sha256 does not match subject bytes")
    if not re.fullmatch(r"[0-9a-f]{64}", str(attestation.get("subject_sha256", ""))):
        errors.append("subject_sha256 is not a lowercase SHA-256 hex digest")
    if attestation.get("attestation_sha256") != expected_attestation_hash:
        errors.append("attestation_sha256 does not match attestation payload")
    return {
        "valid": not errors,
        "errors": errors,
        "subject_sha256": actual_subject_hash,
        "attestation_sha256": expected_attestation_hash,
    }


def fenced_block(content: Any, info: str = "text") -> str:
    text = str(content if content is not None else "")
    longest = max((len(match.group(0)) for match in re.finditer(r"`+", text)), default=0)
    fence = "`" * max(3, longest + 1)
    suffix = info.strip()
    opener = f"{fence}{suffix}" if suffix else fence
    return f"{opener}\n{text}\n{fence}"


def markdown_table_cell(value: Any) -> str:
    text = str(value if value is not None else "")
    return text.replace("\\", "\\\\").replace("|", "\\|").replace("\n", "<br>").replace("`", "\\`")
