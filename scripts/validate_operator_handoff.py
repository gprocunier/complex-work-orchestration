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

SCOPED_FIELDS = {"Next action": "next_action", "Waiting on": "waiting_on"}
CONTINUATION_STATE_FIELDS = {"version", *SCOPED_FIELDS.values()}
GENERIC_APPROVAL_REQUESTS = {"approval", "approval needed", "permission", "permission needed", "proceed"}
READABLE_FIELDS = {
    "Outcome": "an outcome in words",
    "Goal": "a project goal",
    "Completed and verified": "a task title",
    "What stands in the way": "a named blocker",
    "Next step": "a task title",
    "What it enables": "a named result",
    "Reader action": "an explicit reader action or no-decision statement",
}
STATUS_LINE = re.compile(r"^#{1,6}[ \t]+Status Summary[ \t]*$", re.IGNORECASE | re.MULTILINE)
EXECUTION_LINE = re.compile(r"^#{1,6}[ \t]+Execution Details[ \t]*$", re.IGNORECASE | re.MULTILINE)
TASK_ID = re.compile(r"\b[\w./:-]+[-_.:/]\d[\w./:-]*\b")
TASK_REFERENCE = re.compile(r"(?:\s+\([\w./:-]+\))+")
TITLE_PREFIX = re.compile(
    r"^(?:The work graph lists these closed tasks:\s*|(?:The project team can continue|Continue|"
    r".*?check what must change before)\s+)", re.IGNORECASE,
)
GENERIC_WORDS = frozenset("""
    a an and as action approval approved be blocker blockers can clear clears closed complete completed continue current
    decide decision depends do done enable enables finishing for from goal has in is it lets needed next no on only pending
    permission please proceed project ready recorded removes resolving right now sprint status step task tasks team
    that the these this to unblock unblocks unlock unlocks validate verified was were what whether which who work you your
""".split())
READABLE_ABSENCES = {
    "Completed and verified": {"no work is recorded as closed verification was not checked"},
    "What stands in the way": {"no blockers are recorded"},
    "Next step": {"no next step is needed"},
    "What it enables": {"no further work depends on a next step in this scope"},
    "Reader action": {"no decision is needed from you right now", "no decision is recorded for you"},
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
    for canonical in (*SCOPED_FIELDS, *READABLE_FIELDS):
        if normalized == canonical.lower():
            return canonical
    for canonical, aliases in FIELD_ALIASES.items():
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


def concrete_continuation_detail(value: str) -> bool:
    return meaningful(value) and normalize(value) not in GENERIC_APPROVAL_REQUESTS


def validate_continuation_state(value: Any) -> list[str]:
    """Validate a caller-supplied observation for handoff consistency."""

    if not isinstance(value, dict) or set(value) != CONTINUATION_STATE_FIELDS:
        return ["continuation state fields invalid"]
    errors: list[str] = []
    if type(value["version"]) is not int or value["version"] != 2:
        errors.append("continuation state version invalid")
    for field in SCOPED_FIELDS.values():
        item = value[field]
        if item is not None and (type(item) is not str or not concrete_continuation_detail(item)):
            errors.append(f"continuation state {field} invalid")
    return errors


def validate_scoped_fields(fields: dict[str, str], state: Any) -> list[str]:
    errors = []
    observed: dict[str, str | None] = {}
    for field, key in SCOPED_FIELDS.items():
        if field not in fields:
            errors.append(f"missing field: {field}")
            continue
        value = unstyle_value(fields[field])
        if value.lower() == "none":
            observed[key] = None
        elif concrete_continuation_detail(value):
            observed[key] = value
        else:
            errors.append(f"field has no meaningful value: {field}")
    if observed.get("next_action") is not None:
        command_start = normalize(fields.get("Exact command/resume", "")).partition(" ")[0]
        if command_start in {"ask", "await", "request"}:
            errors.append("Exact command/resume must carry out the Next action")
    if state is not None:
        state_errors = validate_continuation_state(state)
        errors.extend(state_errors)
        if not state_errors:
            for field, key in SCOPED_FIELDS.items():
                if key in observed and observed[key] != state[key]:
                    errors.append(f"handoff {field} disagrees with continuation state")
    elif len(observed) == len(SCOPED_FIELDS) and all(value is None for value in observed.values()):
        errors.append("a scoped handoff with no Next action or Waiting on requires continuation state")
    return errors


def readable_words(value: str) -> set[str]:
    # Drop tracker and sprint references before checking for meaningful prose.
    value = re.sub(r"\([\w./:-]+\)", " ", value)
    words = set(re.findall(r"[^\W\d_]+", TASK_ID.sub(" ", value).lower()))
    return words - GENERIC_WORDS


def has_titled_reference(value: str) -> bool:
    references = list(TASK_REFERENCE.finditer(value))
    if not references:
        return False
    start = 0
    for reference in references:
        issue_id = reference.group().rsplit("(", 1)[1][:-1]
        title = TITLE_PREFIX.sub("", value[start:reference.start()].strip())
        title = re.sub(r"^\[(?:done|closed|completed|resolved)\][, ]*", "", title)
        title = re.sub(rf"(?<!\w){re.escape(issue_id)}(?!\w)", " ", title)
        if not re.search(r"[^\W\d_]", TASK_ID.sub(" ", title)):
            return False
        start = reference.end()
    return True


def validate_readable_value(field: str, value: str) -> bool:
    value = unstyle_value(value)
    normalized = normalize(value)
    if normalized in READABLE_ABSENCES.get(field, set()):
        return True
    if not value or ANGLE_PLACEHOLDER_RE.search(value) or normalized in (PLACEHOLDER_VALUES - {""}) | GENERIC_APPROVAL_REQUESTS:
        return False
    if "untitled work item" in normalized or normalized == "project goal is missing from the work graph":
        return False
    if field == "Goal" and normalized.startswith("continue sprint "):
        return False
    if field in {"Completed and verified", "Next step"}:
        # Keep each tracker reference beside a title. Strip common evidence
        # qualifiers so they cannot stand in for a missing title.
        value = re.split(r"\.\s+Verification\b", value, maxsplit=1)[0]
        return has_titled_reference(value)
    if field == "Reader action" and not normalized.startswith(("please ", "you ", "your ")):
        return False
    return bool(readable_words(value)) or (field in {"Outcome", "What it enables"} and has_titled_reference(value))


def validate_readable_summary(text: str) -> list[str]:
    start = STATUS_LINE.search(text)
    end = EXECUTION_LINE.search(text)
    if not start or not end or start.end() >= end.start():
        return ["missing readable Status Summary before Execution Details"]
    fields = parse_fields(text[start.end():end.start()])
    return [
        f"readable summary needs {need}: {field}"
        for field, need in READABLE_FIELDS.items()
        if not validate_readable_value(field, fields.get(field, ""))
    ]


def validate_text(
    text: str,
    *,
    require_scoped_continuation: bool = False,
    require_readable_summary: bool = False,
    continuation_state: Any = None,
) -> list[str]:
    execution = EXECUTION_LINE.search(text)
    fields = parse_fields(text[execution.end():] if execution else text)
    errors: list[str] = []
    for field in FIELD_ALIASES:
        if field not in fields:
            errors.append(f"missing field: {field}")
        elif not meaningful(fields[field]):
            errors.append(f"field has no meaningful value: {field}")
    scoped = require_scoped_continuation or continuation_state is not None
    if scoped:
        errors.extend(validate_scoped_fields(fields, continuation_state))
    if scoped or require_readable_summary or SCOPED_FIELDS.keys() & fields.keys() or STATUS_LINE.search(text):
        errors.extend(validate_readable_summary(text))
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
    parser.add_argument("--require-readable-summary", action="store_true", help="Require the current status-first handoff format.")
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
            require_readable_summary=args.require_readable_summary,
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
