#!/usr/bin/env python3
"""Validate a CWO operator handoff packet."""

from __future__ import annotations

import argparse
import re
import sys
import tempfile
from pathlib import Path


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


def validate_text(text: str) -> list[str]:
    fields = parse_fields(text)
    errors: list[str] = []
    for field in FIELD_ALIASES:
        if field not in fields:
            errors.append(f"missing field: {field}")
        elif not meaningful(fields[field]):
            errors.append(f"field has no meaningful value: {field}")
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
    args = parser.parse_args(argv)

    if args.self_test:
        return self_test()
    if not args.paths:
        parser.error("provide at least one handoff packet path")

    failed = False
    for path in args.paths:
        errors = validate_text(path.read_text(encoding="utf-8"))
        if errors:
            failed = True
            print(f"{path}: invalid", file=sys.stderr)
            for error in errors:
                print(f"  - {error}", file=sys.stderr)
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
