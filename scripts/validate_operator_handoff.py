#!/usr/bin/env python3
"""Validate a CWO operator handoff packet."""

from __future__ import annotations

import argparse
import json
import re
import sys
import tempfile
from pathlib import Path
from typing import Any


FIELD_ALIASES = {
    "Next executable Bead": ["next executable bead", "next executable issue"],
    "Why it is next": ["why it is next", "why next"],
    "Exact command/resume": ["exact command resume", "exact command", "resume command"],
    "Execution prompt": ["execution prompt"],
    "What must NOT run yet": ["what must not run yet", "must not run yet"],
    "Commit/push status": ["commit push status", "commit status", "push status"],
    "Validation status": ["validation status"],
    "Escalation rule": ["escalation rule", "escalation rules"],
}

SCOPED_FIELD_ALIASES = {
    "Stopped operation": ["stopped operation"],
    "Stop scope": ["stop scope"],
    "Continuation disposition": ["continuation disposition"],
    "Already-authorized next action": ["already authorized next action"],
    "Authority delta required": ["authority delta required"],
}
STOP_SCOPES = {"child", "cohort", "execution-path", "complete-task", "publication"}
CONTINUATION_DISPOSITIONS = {"continue-authorized", "material-decision", "complete"}
CONTINUATION_STATE_FIELDS = {
    "version", "stopped_operation", "stop_scope",
    "authorized_next_action", "authority_delta_required",
}

PLACEHOLDER_VALUES = {
    "",
    "unknown",
    "tbd",
    "todo",
    "n/a",
    "na",
    "none",
    "none recorded",
}

LABEL_RE = re.compile(r"^\s*(?:[-*]\s*)?(?:\*\*)?([^:*`]+?)(?:\*\*)?\s*:\s*(.*?)\s*$")
HEADING_RE = re.compile(r"^\s*#{1,6}\s+(.+?)\s*$")
ANGLE_PLACEHOLDER_RE = re.compile(r"<[^>\n]+>")


def normalize(text: str) -> str:
    text = text.lower().replace("`", "").replace("*", "")
    text = re.sub(r"[^a-z0-9]+", " ", text)
    return re.sub(r"\s+", " ", text).strip()


def unstyle_value(text: str) -> str:
    stripped = text.strip()
    changed = True
    while changed:
        changed = False
        for left, right in [("`", "`"), ("**", "**"), ("*", "*")]:
            if stripped.startswith(left) and stripped.endswith(right) and len(stripped) >= len(left) + len(right):
                stripped = stripped[len(left) : len(stripped) - len(right)].strip()
                changed = True
    return stripped


def meaningful(value: str | None) -> bool:
    if value is None:
        return False
    stripped = unstyle_value(value)
    if not stripped:
        return False
    if ANGLE_PLACEHOLDER_RE.search(stripped):
        return False
    normalized = normalize(stripped)
    if normalized in PLACEHOLDER_VALUES:
        return False
    return True


def matching_field(label: str) -> str | None:
    normalized = normalize(label)
    for canonical, aliases in {**FIELD_ALIASES, **SCOPED_FIELD_ALIASES}.items():
        if any(normalized == alias for alias in aliases):
            return canonical
    return None


def parse_fields(text: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    lines = text.splitlines()
    for index, line in enumerate(lines):
        label_match = LABEL_RE.match(line)
        if label_match:
            field = matching_field(label_match.group(1))
            if field:
                fields[field] = label_match.group(2).strip()
            continue

        heading_match = HEADING_RE.match(line)
        if not heading_match:
            continue
        field = matching_field(heading_match.group(1))
        if not field:
            continue
        value = ""
        for later in lines[index + 1 :]:
            if HEADING_RE.match(later):
                break
            stripped = later.strip()
            if stripped:
                value = stripped.lstrip("-* ").strip()
                break
        fields[field] = value
    return fields


def validate_continuation_state(value: Any) -> list[str]:
    """Validate a caller-supplied consistency input, never dispatch authority."""

    if not isinstance(value, dict) or set(value) != CONTINUATION_STATE_FIELDS:
        return ["continuation state fields invalid"]
    errors: list[str] = []
    if type(value["version"]) is not int or value["version"] != 1:
        errors.append("continuation state version invalid")
    if type(value["stopped_operation"]) is not str or not meaningful(value["stopped_operation"]):
        errors.append("continuation state stopped operation invalid")
    if type(value["stop_scope"]) is not str or value["stop_scope"] not in STOP_SCOPES:
        errors.append("continuation state stop scope invalid")
    for field in ("authorized_next_action", "authority_delta_required"):
        item = value[field]
        if item is not None and (type(item) is not str or not meaningful(item)):
            errors.append(f"continuation state {field} invalid")
    return errors


def validate_text(
    text: str,
    *,
    require_scoped_continuation: bool = False,
    continuation_state: Any = None,
) -> list[str]:
    fields = parse_fields(text)
    errors: list[str] = []
    for field in FIELD_ALIASES:
        if field not in fields:
            errors.append(f"missing field: {field}")
        elif not meaningful(fields[field]):
            errors.append(f"field has no meaningful value: {field}")
    if continuation_state is not None:
        errors.extend(validate_continuation_state(continuation_state))
        require_scoped_continuation = True
    if not require_scoped_continuation:
        return errors

    for field in SCOPED_FIELD_ALIASES:
        if field not in fields:
            errors.append(f"missing field: {field}")
    if any(field not in fields for field in SCOPED_FIELD_ALIASES):
        return errors

    if not meaningful(fields["Stopped operation"]):
        errors.append("field has no meaningful value: Stopped operation")
    scope = unstyle_value(fields["Stop scope"]).lower()
    if scope not in STOP_SCOPES:
        errors.append("invalid stop scope")
    disposition = unstyle_value(fields["Continuation disposition"]).lower()
    if disposition not in CONTINUATION_DISPOSITIONS:
        errors.append("invalid continuation disposition")
        return errors

    next_action = unstyle_value(fields["Already-authorized next action"])
    authority_delta = unstyle_value(fields["Authority delta required"])
    next_is_none = normalize(next_action) == "none"
    delta_is_none = normalize(authority_delta) == "none"
    if disposition == "continue-authorized":
        if not meaningful(next_action):
            errors.append("continue-authorized requires an exact next action")
        command = normalize(fields.get("Exact command/resume", ""))
        if command.startswith(("ask ", "await ", "request ")):
            errors.append("continue-authorized cannot hand off a generic approval request")
    elif disposition == "material-decision":
        if not next_is_none:
            errors.append("material-decision requires no already-authorized next action")
        if not meaningful(authority_delta) or normalize(authority_delta) in {
            "approval", "approval needed", "permission", "permission needed", "proceed"
        }:
            errors.append("material-decision requires a precise authority delta")
    else:
        if not next_is_none or not delta_is_none:
            errors.append("complete requires no next action or authority delta")
        if scope not in {"complete-task", "publication"}:
            errors.append("child or path stop cannot complete the parent")
    if continuation_state is not None and not validate_continuation_state(continuation_state):
        if fields["Stopped operation"].strip() != continuation_state["stopped_operation"]:
            errors.append("handoff stopped operation disagrees with continuation state")
        if scope != continuation_state["stop_scope"]:
            errors.append("handoff stop scope disagrees with continuation state")
        authorized = continuation_state["authorized_next_action"]
        delta = continuation_state["authority_delta_required"]
        if authorized is not None:
            if disposition != "continue-authorized" or next_action != authorized:
                errors.append("handoff omitted an already-authorized next action")
        elif delta is not None:
            if disposition != "material-decision" or authority_delta != delta:
                errors.append("handoff authority delta disagrees with continuation state")
        elif disposition != "complete":
            errors.append("handoff disposition disagrees with completed continuation state")
    return errors


def self_test() -> int:
    good = """# Operator Handoff Packet

- Next executable Bead: cwo-123
- Why it is next: it is the highest priority ready issue and unblocks validation
- Exact command/resume: python3 scripts/cwo.py continue --epic cwo-epic
- Execution prompt: Continue cwo-123 only and stop before any blocked lane.
- What must NOT run yet: no contractor-only or no-codex-exec lanes
- Commit/push status: committed and pushed, remote HEAD verified
- Validation status: repository validation and unit tests passed
- Escalation rule: stop if validation cannot run or the ready issue is blocked
"""
    missing = """# Done

- Commit/push status: pushed
"""
    placeholder = """# Operator Handoff Packet

- Next executable Bead: `<bead-id>`
- Why it is next: `<why>`
- Exact command/resume: `<copy-paste command>`
- Execution prompt: `<prompt>`
- What must NOT run yet: `<blocked>`
- Commit/push status: `<status>`
- Validation status: `<status>`
- Escalation rule: `<rule>`
"""
    with tempfile.TemporaryDirectory() as tmp:
        good_path = Path(tmp) / "good.md"
        missing_path = Path(tmp) / "missing.md"
        placeholder_path = Path(tmp) / "placeholder.md"
        good_path.write_text(good, encoding="utf-8")
        missing_path.write_text(missing, encoding="utf-8")
        placeholder_path.write_text(placeholder, encoding="utf-8")
        good_errors = validate_text(good_path.read_text(encoding="utf-8"))
        missing_errors = validate_text(missing_path.read_text(encoding="utf-8"))
        placeholder_errors = validate_text(placeholder_path.read_text(encoding="utf-8"))
    if good_errors:
        print("good fixture failed:", good_errors, file=sys.stderr)
        return 1
    if not missing_errors:
        print("missing fixture unexpectedly passed", file=sys.stderr)
        return 1
    if not placeholder_errors:
        print("placeholder fixture unexpectedly passed", file=sys.stderr)
        return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="*", type=Path)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--require-scoped-continuation", action="store_true")
    parser.add_argument(
        "--continuation-state",
        type=Path,
        help="Caller-supplied state for consistency checking; never grants authority",
    )
    args = parser.parse_args(argv)

    if args.self_test:
        return self_test()
    if not args.paths:
        parser.error("provide at least one handoff packet path")

    state = None
    if args.continuation_state is not None:
        try:
            state = json.loads(args.continuation_state.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            print(f"continuation state unreadable: {exc}", file=sys.stderr)
            return 1
        state_errors = validate_continuation_state(state)
        if state_errors:
            for error in state_errors:
                print(error, file=sys.stderr)
            return 1

    failed = False
    for path in args.paths:
        errors = validate_text(
            path.read_text(encoding="utf-8"),
            require_scoped_continuation=args.require_scoped_continuation,
            continuation_state=state,
        )
        if errors:
            failed = True
            print(f"{path}: invalid", file=sys.stderr)
            for error in errors:
                print(f"  - {error}", file=sys.stderr)
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
