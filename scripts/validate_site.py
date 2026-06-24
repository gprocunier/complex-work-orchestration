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
INCIDENT_PLAYBOOK_URL = f"{REPO_URL}/blob/main/references/incident-response-playbook.md"
REQUIRED_PAGES = [
    "index.html",
    "get-started.html",
    "explanation.html",
    "prompt-coach.html",
    "workflows.html",
    "use-cases.html",
    "external-contracting.html",
    "local-workers.html",
    "contractor-demo.html",
    "beads-memory.html",
    "model-synthesis.html",
    "malpractice-sabotage.html",
    "reference.html",
]
SOURCE_LINK_PATTERNS = [
    REPO_URL,
    f"{REPO_URL}/blob/main/LICENSE",
    INCIDENT_PLAYBOOK_URL,
    "https://github.com/gprocunier/hello-world-contractor-demo",
    "https://gprocunier.github.io/hello-world-contractor-demo/",
    "https://github.com/steveyegge/beads",
    "https://diataxis.fr/",
    "https://www.anthropic.com/news/claude-fable-5-mythos-5",
    "https://www.anthropic.com/system-cards",
    "https://www-cdn.anthropic.com/2f9323abbcc4abe219577539efe19a623c9ca2bd/Claude%20Fable%205%20%26%20Claude%20Mythos%205%20System%20Card.pdf",
]
PRIMARY_NAV_HREFS = [
    "./index.html",
    "./get-started.html",
    "./workflows.html",
    "./use-cases.html",
    "./reference.html",
    REPO_URL,
]
FOOTER_HREFS = [
    "./index.html",
    "./get-started.html",
    "./prompt-coach.html",
    "./workflows.html",
    "./use-cases.html",
    "./external-contracting.html",
    "./local-workers.html",
    "./contractor-demo.html",
    "./reference.html",
    REPO_URL,
    f"{REPO_URL}/blob/main/LICENSE",
]

PRIVATE_PATTERNS = [
    re.compile(r"/home/[A-Za-z0-9_.-]+"),
    re.compile(r"file:///"),
    re.compile(r"codex@local"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"(?i)\b(password|api[_ -]?key|token)\s*[:=]\s*[^\\s<]+"),
]
INTERNAL_LABEL_PATTERN = re.compile(r"\bcontract-jd-[A-Za-z0-9-]+\b")
PUBLIC_COPY_FORBIDDEN_PATTERNS = [
    re.compile(r"\bEditor gate:", re.IGNORECASE),
    re.compile(r"\bAI-slop wording\b", re.IGNORECASE),
    re.compile(r"\bdocs/pages flow\b", re.IGNORECASE),
    re.compile(r"\bsite-flow\b", re.IGNORECASE),
    re.compile(r"\bRed Hat UX reference\b", re.IGNORECASE),
    re.compile(r"\bRed Hat UX design corpus\b", re.IGNORECASE),
    re.compile(r"\bdesign corpus\b", re.IGNORECASE),
    re.compile(r"\b(?:contractors?|outside models?)\s+(?:can|may|will|should)\s+(?:approve|merge|publish|implement)\b", re.IGNORECASE),
    re.compile(r"\bCWO\s+requires\s+Codex(?:\s+CLI)?\b", re.IGNORECASE),
    re.compile(r"\bsend\s+raw\s+Beads\s+comments\b", re.IGNORECASE),
    re.compile(r"\bGemini\b.{0,80}\baccepted\s+authority\b", re.IGNORECASE),
]
INTERNAL_LABEL_REFERENCE_PAGES = {"reference.html"}
INDEX_FIRST_SCREEN_FORBIDDEN_TERMS = [
    "Beads",
    "contractor",
    "synthesis",
    "sabotage",
    "malpractice",
    "quarantine",
    "adjudication",
    "RHOAI",
    "model profile",
    "execution environment",
    "evidence lane",
    "PM",
    "architect",
    "workerbee",
    "Dolt",
    "OpenCode",
    "airgapped",
]
INDEX_EXPERT_ROUTE_HREFS = [
    "./workflows.html",
    "./beads-memory.html",
    "./model-synthesis.html",
    "./malpractice-sabotage.html",
    "./reference.html",
    "./contractor-demo.html",
    REPO_URL,
]


class SiteParser(HTMLParser):
    def __init__(self, *, allow_internal_labels: bool = False) -> None:
        super().__init__()
        self.allow_internal_labels = allow_internal_labels
        self.ids: set[str] = set()
        self.hrefs: list[str] = []
        self.headings: list[tuple[str, str]] = []
        self.landmarks: set[str] = set()
        self.internal_copy_errors: list[str] = []
        self.title = ""
        self._in_title = False
        self._pre_depth = 0
        self._code_depth = 0
        self._section_stack: list[str] = []
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
        if tag == "pre":
            self._pre_depth += 1
        if tag == "code":
            self._code_depth += 1
        if tag == "section":
            self._section_stack.append(attrs_dict.get("id", ""))
        if tag in {"h1", "h2", "h3"}:
            self._current_heading = tag
            self._heading_text = []

    def handle_endtag(self, tag: str) -> None:
        if tag == "title":
            self._in_title = False
        if tag == "pre" and self._pre_depth:
            self._pre_depth -= 1
        if tag == "code" and self._code_depth:
            self._code_depth -= 1
        if tag == "section" and self._section_stack:
            self._section_stack.pop()
        if self._current_heading == tag:
            self.headings.append((tag, " ".join(self._heading_text).strip()))
            self._current_heading = None
            self._heading_text = []

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self.title += data
        if self._current_heading:
            self._heading_text.append(data)
        self._record_internal_copy_errors(data)

    def _record_internal_copy_errors(self, data: str) -> None:
        if self._pre_depth:
            return
        section = self._section_stack[-1] if self._section_stack else "document"
        if not self.allow_internal_labels:
            for match in INTERNAL_LABEL_PATTERN.finditer(data):
                context = "inline-code" if self._code_depth else "text"
                self.internal_copy_errors.append(
                    f'internal label "{match.group(0)}" in public narrative (section={section}, context={context})'
                )
        if self._code_depth:
            return
        for pattern in PUBLIC_COPY_FORBIDDEN_PATTERNS:
            match = pattern.search(data)
            if match:
                self.internal_copy_errors.append(
                    f'internal editorial wording "{match.group(0)}" in public narrative (section={section})'
                )


def validate_html(path: Path) -> list[str]:
    errors: list[str] = []
    text = path.read_text(encoding="utf-8")
    parser = SiteParser(allow_internal_labels=path.name in INTERNAL_LABEL_REFERENCE_PAGES)
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
    if path.name == "index.html":
        first_screen = text.split('<section id="walk"', 1)[0]
        first_screen_plain = re.sub(r"<[^>]+>", " ", first_screen)
        for term in INDEX_FIRST_SCREEN_FORBIDDEN_TERMS:
            if re.search(rf"\b{re.escape(term)}\b", first_screen_plain, re.IGNORECASE):
                errors.append(
                    f"{path.relative_to(ROOT)} introduces advanced term before novice ramp: {term}"
                )
        for href in INDEX_EXPERT_ROUTE_HREFS:
            if f'href="{href}"' not in text:
                errors.append(f"{path.relative_to(ROOT)} missing expert route link: {href}")
    if path.name in {"external-contracting.html", "local-workers.html"} and "Publication handoff" not in text:
        errors.append(f"{path.relative_to(ROOT)} missing publication handoff note")
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
            if (
                "github.com" in parsed.netloc
                and "/blob/main/" in parsed.path
                and href != INCIDENT_PLAYBOOK_URL
                and not parsed.path.endswith("/LICENSE")
            ):
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
    for error in parser.internal_copy_errors:
        errors.append(f"{path.relative_to(ROOT)} contains {error}")
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
