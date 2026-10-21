#!/usr/bin/env python3
from __future__ import annotations

from html.parser import HTMLParser
import re
import sys

from cwo_core.paths import REPO_ROOT
from cwo_core.public_copy import validate_markdown_public_copy
from validate_repository import (
    iter_public_copy_markdown_docs,
    public_copy_allows_internal_labels,
)
from validate_site import validate_html


class _VisibleText(HTMLParser):
    def __init__(self, source: str):
        super().__init__()
        self.parts: list[str] = []
        self.feed(source)

    def handle_data(self, data: str) -> None:
        self.parts.append(data)


RETIRED_BROWSER_GUIDANCE = re.compile(
    r"\b(?:ChatGPT\s+Pro\s+5\.5|GPT[-\s]?5\.5\s+Pro|Extended\s+Reasoning)\b"
    r"|\b(?:chatgpt_browser_review\.py|launch_chatgpt_cdp_chrome\.sh|"
    r"chatgpt_pro_browser_master_reviewer)\b"
    r"|\b(?:set|export|configure)\s+CWO_CHATGPT_BROWSER_CONFIG\b",
    re.IGNORECASE,
)


def retired_browser_guidance_errors(source: str, *, source_name: str) -> list[str]:
    """Reject withdrawn setup in maintained copy, including highlighted code.

    Legacy runtime policy, tests and historical records are not altered by this
    documentation rule. A version-neutral deferral notice is allowed.
    """
    visible = " ".join("".join(_VisibleText(source).parts).split())
    return [f"{source_name}: withdrawn browser guidance: {m.group(0)}"
            for m in RETIRED_BROWSER_GUIDANCE.finditer(visible)]


def main() -> int:
    errors: list[str] = []
    for path in iter_public_copy_markdown_docs(REPO_ROOT):
        relative = path.relative_to(REPO_ROOT).as_posix()
        errors.extend(
            validate_markdown_public_copy(
                path,
                source_name=relative,
                allow_internal_labels=public_copy_allows_internal_labels(relative),
            )
        )
    for path in sorted((REPO_ROOT / "docs").glob("*.html")):
        errors.extend(validate_html(path))
    maintained = [*iter_public_copy_markdown_docs(REPO_ROOT),
                  *sorted((REPO_ROOT / "experts").glob("*.md")),
                  *sorted((REPO_ROOT / "docs").glob("*.html"))]
    for path in maintained:
        errors.extend(retired_browser_guidance_errors(
            path.read_text(encoding="utf-8"),
            source_name=path.relative_to(REPO_ROOT).as_posix(),
        ))
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print("Public-copy validation passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
