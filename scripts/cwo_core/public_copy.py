from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path


def _text(*parts: str) -> str:
    return "".join(parts)


@dataclass(frozen=True)
class PublicCopyIssue:
    kind: str
    match: str
    section: str = "document"
    line: int | None = None

    def render(self) -> str:
        location = f"line {self.line}, " if self.line is not None else ""
        return f'{self.kind} "{self.match}" in public narrative ({location}section={self.section})'


INTERNAL_LABEL_PATTERN = re.compile(r"\bcontract-jd-[A-Za-z0-9-]+\b")

PUBLIC_COPY_FORBIDDEN_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("internal editorial wording", re.compile(r"\bEditor gate:", re.IGNORECASE)),
    ("internal editorial wording", re.compile(r"\bAI-slop wording\b", re.IGNORECASE)),
    ("internal editorial wording", re.compile(r"\bdocs/pages flow\b", re.IGNORECASE)),
    ("internal editorial wording", re.compile(r"\bsite-flow\b", re.IGNORECASE)),
    ("internal editorial wording", re.compile(r"\bRed Hat UX reference\b", re.IGNORECASE)),
    ("internal editorial wording", re.compile(r"\bRed Hat UX design corpus\b", re.IGNORECASE)),
    ("internal editorial wording", re.compile(r"\bdesign corpus\b", re.IGNORECASE)),
    (
        "internal editorial wording",
        re.compile(r"\b" + re.escape(_text("Publication", " gate")) + r"\b", re.IGNORECASE),
    ),
    (
        "internal editorial wording",
        re.compile(r"\b" + re.escape(_text("first-reader", " walkthrough")) + r"\b", re.IGNORECASE),
    ),
    (
        "internal editorial wording",
        re.compile(r"\b" + re.escape(_text("rendered", " first-reader")) + r"\b", re.IGNORECASE),
    ),
    (
        "internal editorial wording",
        re.compile(r"\b" + re.escape(_text("README", " alignment")) + r"\b", re.IGNORECASE),
    ),
    (
        "internal editorial wording",
        re.compile(r"\b" + re.escape(_text("canonical", " Reference home")) + r"\b", re.IGNORECASE),
    ),
    (
        "internal editorial wording",
        re.compile(
            r"\b" + re.escape(_text("before publishing", " public docs")) + r"\b",
            re.IGNORECASE,
        ),
    ),
    (
        "internal editorial wording",
        re.compile(
            r"\b" + re.escape(_text("inventory the existing", " page URLs")) + r"\b",
            re.IGNORECASE,
        ),
    ),
    (
        "internal editorial wording",
        re.compile(r"\b" + re.escape(_text("authority-boundary", " wording")) + r"\b", re.IGNORECASE),
    ),
    (
        "internal editorial wording",
        re.compile(r"\b" + re.escape(_text("execution-profile", " limits")) + r"\b", re.IGNORECASE),
    ),
    (
        "internal editorial wording",
        re.compile(r"\b" + re.escape(_text("maintainer", " checklist")) + r"\b", re.IGNORECASE),
    ),
    (
        "internal editorial wording",
        re.compile(
            r"\b(?:contractors?|outside models?)\s+(?:can|may|will|should)\s+"
            r"(?:approve|merge|publish|implement)\b",
            re.IGNORECASE,
        ),
    ),
    ("internal editorial wording", re.compile(r"\bCWO\s+requires\s+Codex(?:\s+CLI)?\b", re.IGNORECASE)),
    ("internal editorial wording", re.compile(r"\bsend\s+raw\s+Beads\s+comments\b", re.IGNORECASE)),
    ("internal editorial wording", re.compile(r"\bGemini\b.{0,80}\baccepted\s+authority\b", re.IGNORECASE)),
    (
        "circular public-copy wording",
        re.compile(r"\b(?:start|begin|go|move)\s+(?:somewhere|elsewhere|on another page)\b", re.IGNORECASE),
    ),
    (
        "circular public-copy wording",
        re.compile(r"\b(?:this|that)\s+page\s+(?:only\s+)?(?:tells|points|sends)\s+(?:the\s+)?reader\s+(?:to|elsewhere)\b", re.IGNORECASE),
    ),
)

VAGUE_MARKETING_PATTERN = re.compile(
    r"\b(seamlessly|robust|streamlined|powerful|comprehensive)\b",
    re.IGNORECASE,
)
VAGUE_EXAMPLE_CONTEXT = re.compile(
    r"\b(?:avoid|forbid|reject|do not use|phrases like|generic evidence)\b",
    re.IGNORECASE,
)

MARKDOWN_ALLOW_START = re.compile(r"<!--\s*cwo-public-copy:\s*allow-start\s+reason=\"[^\"]+\"\s*-->")
MARKDOWN_ALLOW_END = re.compile(r"<!--\s*cwo-public-copy:\s*allow-end\s*-->")
MARKDOWN_ALLOW_START_MISSING_REASON = re.compile(r"<!--\s*cwo-public-copy:\s*allow-start\b(?![^>]*reason=\")", re.IGNORECASE)
FENCE_START = re.compile(r"^\s*(`{3,}|~{3,})")


def find_public_copy_issues(
    fragment: str,
    *,
    allow_internal_labels: bool = False,
    check_editorial_patterns: bool = True,
    section: str = "document",
    line: int | None = None,
) -> list[PublicCopyIssue]:
    issues: list[PublicCopyIssue] = []
    if not fragment.strip():
        return issues
    if not allow_internal_labels:
        for match in INTERNAL_LABEL_PATTERN.finditer(fragment):
            issues.append(PublicCopyIssue("internal label", match.group(0), section, line))
    if not check_editorial_patterns:
        return issues
    for kind, pattern in PUBLIC_COPY_FORBIDDEN_PATTERNS:
        match = pattern.search(fragment)
        if match:
            issues.append(PublicCopyIssue(kind, match.group(0), section, line))
    vague = VAGUE_MARKETING_PATTERN.search(fragment)
    if vague and not VAGUE_EXAMPLE_CONTEXT.search(fragment):
        issues.append(PublicCopyIssue("vague AI-style wording", vague.group(0), section, line))
    return issues


def strip_inline_code(line: str) -> str:
    return re.sub(r"`[^`]*`", "", line)


def strip_html_comments(line: str, *, in_comment: bool) -> tuple[str, bool]:
    output = line
    comment_open = in_comment
    while True:
        if comment_open:
            end = output.find("-->")
            if end == -1:
                return "", True
            output = output[end + 3 :]
            comment_open = False
            continue
        start = output.find("<!--")
        if start == -1:
            return output, False
        end = output.find("-->", start + 4)
        if end == -1:
            output = output[:start]
            return output, True
        output = output[:start] + output[end + 3 :]


def validate_markdown_public_copy(
    path: Path,
    *,
    source_name: str | None = None,
    allow_internal_labels: bool = False,
) -> list[str]:
    source = source_name or path.as_posix()
    errors: list[str] = []
    in_fence: str | None = None
    in_comment = False
    in_allow_block = False
    for line_number, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        line = raw_line.rstrip("\n")
        stripped = line.strip()
        if MARKDOWN_ALLOW_START_MISSING_REASON.search(line):
            errors.append(f"{source}: public-copy allow-start on line {line_number} is missing reason")
        if MARKDOWN_ALLOW_START.search(line):
            if in_allow_block:
                errors.append(f"{source}: nested public-copy allow block starts on line {line_number}")
            in_allow_block = True
            continue
        if MARKDOWN_ALLOW_END.search(line):
            if not in_allow_block:
                errors.append(f"{source}: public-copy allow-end without allow-start on line {line_number}")
            in_allow_block = False
            continue
        if in_allow_block:
            continue
        fence = FENCE_START.match(stripped)
        if fence and in_fence is None:
            in_fence = fence.group(1)[0]
            continue
        if in_fence is not None:
            if stripped.startswith(in_fence * 3):
                in_fence = None
            continue
        visible, in_comment = strip_html_comments(line, in_comment=in_comment)
        visible = strip_inline_code(visible)
        for issue in find_public_copy_issues(
            visible,
            allow_internal_labels=allow_internal_labels,
            section="markdown",
            line=line_number,
        ):
            errors.append(f"{source}: {issue.render()}")
    if in_allow_block:
        errors.append(f"{source}: public-copy allow block was not closed")
    if in_fence is not None:
        errors.append(f"{source}: markdown fence was not closed")
    if in_comment:
        errors.append(f"{source}: HTML comment was not closed")
    return errors


def validate_required_doc_terms(relative_path: str, terms: list[str]) -> list[str]:
    errors: list[str] = []
    for term in terms:
        for issue in find_public_copy_issues(
            term,
            allow_internal_labels=True,
            section="required-doc-term",
        ):
            errors.append(f"{relative_path} required term {term!r} violates public-copy guard: {issue.render()}")
    return errors
