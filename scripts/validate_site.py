#!/usr/bin/env python3
from __future__ import annotations

import re
import sys
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"
REPO_URL = "https://github.com/gprocunier/complex-work-orchestration"
REQUIRED_PAGES = [
    "index.html",
    "get-started.html",
    "prompt-coach.html",
    "workflows.html",
    "external-contracting.html",
    "local-workers.html",
    "reference.html",
]
SOURCE_LINK_PATTERNS = [
    REPO_URL,
    f"{REPO_URL}/blob/main/LICENSE",
    "https://github.com/steveyegge/beads",
    "https://ux.redhat.com/",
    "https://diataxis.fr/",
]
PRIMARY_NAV_HREFS = [
    "./index.html",
    "./get-started.html",
    "./prompt-coach.html",
    "./workflows.html",
    "./reference.html",
    REPO_URL,
]
FOOTER_HREFS = [
    "./index.html",
    "./get-started.html",
    "./prompt-coach.html",
    "./workflows.html",
    "./external-contracting.html",
    "./local-workers.html",
    "./reference.html",
    REPO_URL,
    f"{REPO_URL}/blob/main/LICENSE",
]

PRIVATE_PATTERNS = [
    re.compile(r"/home/[A-Za-z0-9_.-]+"),
    re.compile(r"codex@local"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"(?i)\b(password|api[_ -]?key|token)\s*[:=]\s*[^\\s<]+"),
]


class SiteParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.ids: set[str] = set()
        self.hrefs: list[str] = []
        self.headings: list[tuple[str, str]] = []
        self.landmarks: set[str] = set()
        self.title = ""
        self._in_title = False
        self._current_heading: str | None = None
        self._heading_text: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attrs_dict = {key: value or "" for key, value in attrs}
        if "id" in attrs_dict:
            self.ids.add(attrs_dict["id"])
        if tag == "a" and attrs_dict.get("href"):
            self.hrefs.append(attrs_dict["href"])
        if tag in {"main", "nav", "header", "footer"}:
            self.landmarks.add(tag)
        if tag == "title":
            self._in_title = True
        if tag in {"h1", "h2", "h3"}:
            self._current_heading = tag
            self._heading_text = []

    def handle_endtag(self, tag: str) -> None:
        if tag == "title":
            self._in_title = False
        if self._current_heading == tag:
            self.headings.append((tag, " ".join(self._heading_text).strip()))
            self._current_heading = None
            self._heading_text = []

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self.title += data
        if self._current_heading:
            self._heading_text.append(data)


def validate_html(path: Path) -> list[str]:
    errors: list[str] = []
    text = path.read_text(encoding="utf-8")
    parser = SiteParser()
    parser.feed(text)

    if not parser.title.strip():
        errors.append(f"{path.relative_to(ROOT)} missing <title>")
    if not any(tag == "h1" for tag, _ in parser.headings):
        errors.append(f"{path.relative_to(ROOT)} missing h1")
    if '<aside class="page-nav"' in text:
        errors.append(f"{path.relative_to(ROOT)} uses aside for page navigation instead of nav")
    if '<div class="nav-links">' in text:
        for href in PRIMARY_NAV_HREFS:
            if f'href="{href}"' not in text:
                errors.append(f"{path.relative_to(ROOT)} missing primary navigation link: {href}")
    if '<footer class="site-footer">' in text:
        for href in FOOTER_HREFS:
            if f'href="{href}"' not in text:
                errors.append(f"{path.relative_to(ROOT)} missing footer navigation link: {href}")
    if path.name == "prompt-coach.html":
        for term in ["External Contract", "Local Worker"]:
            if term not in text:
                errors.append(f"{path.relative_to(ROOT)} missing prompt-coach output level: {term}")
    if path.name in {"external-contracting.html", "local-workers.html"} and "Publish-gate handoff" not in text:
        errors.append(f"{path.relative_to(ROOT)} missing publish-gate handoff note")
    for landmark in ["main", "nav", "header", "footer"]:
        if landmark not in parser.landmarks:
            errors.append(f"{path.relative_to(ROOT)} missing {landmark} landmark")
    for href in parser.hrefs:
        parsed = urlparse(href)
        if parsed.scheme in {"http", "https", "mailto"}:
            if parsed.scheme in {"http", "https"} and not any(
                href == pattern or href.startswith(pattern + "#") for pattern in SOURCE_LINK_PATTERNS
            ):
                errors.append(f"{path.relative_to(ROOT)} links to non-source external URL: {href}")
            if "github.com" in parsed.netloc and "/blob/main/" in parsed.path and not parsed.path.endswith("/LICENSE"):
                errors.append(f"{path.relative_to(ROOT)} links to GitHub markdown/source blob instead of local docs: {href}")
            if "github.com" in parsed.netloc and "/tree/main/" in parsed.path:
                errors.append(f"{path.relative_to(ROOT)} links to GitHub tree instead of local docs: {href}")
            continue
        if href.startswith("#"):
            anchor = href[1:]
            if anchor and anchor not in parser.ids:
                errors.append(f"{path.relative_to(ROOT)} links to missing anchor #{anchor}")
            continue
        target = (path.parent / parsed.path).resolve()
        try:
            target.relative_to(ROOT)
        except ValueError:
            errors.append(f"{path.relative_to(ROOT)} links outside repo: {href}")
            continue
        if parsed.path and not target.exists():
            errors.append(f"{path.relative_to(ROOT)} links to missing file: {href}")

    for pattern in PRIVATE_PATTERNS:
        if pattern.search(text):
            errors.append(f"{path.relative_to(ROOT)} contains private or secret-looking content: {pattern.pattern}")
    return errors


def main() -> int:
    errors: list[str] = []
    required = [DOCS / page for page in REQUIRED_PAGES] + [DOCS / "styles.css", DOCS / ".nojekyll"]
    for path in required:
        if not path.exists():
            errors.append(f"missing required site file: {path.relative_to(ROOT)}")
    for path in sorted(DOCS.glob("*.html")):
        errors.extend(validate_html(path))
    if (DOCS / "styles.css").exists():
        css = (DOCS / "styles.css").read_text(encoding="utf-8")
        if "@media" not in css:
            errors.append("docs/styles.css missing responsive media query")
        if ":focus-visible" not in css:
            errors.append("docs/styles.css missing focus-visible styling")
        for required_term in ["doc-layout", "page-nav", "callout", "tile-grid"]:
            if required_term not in css:
                errors.append(f"docs/styles.css missing docs component: {required_term}")
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print("Site validation passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
