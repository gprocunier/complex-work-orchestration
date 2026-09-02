#!/usr/bin/env python3
from __future__ import annotations

import re
import sys
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlparse

from cwo_core.public_copy import find_public_copy_issues

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"
REPO_URL = "https://github.com/gprocunier/complex-work-orchestration"
INCIDENT_PLAYBOOK_URL = f"{REPO_URL}/blob/main/references/incident-response-playbook.md"
NATIVE_SUPERVISION_POOL_REFERENCE_URL = (
    f"{REPO_URL}/blob/main/references/native-supervision-pools.md"
)
NATIVE_SUPERVISION_REFERENCE_URL = (
    f"{REPO_URL}/blob/main/references/native-supervision.md"
)
SOURCE_BLOB_LINK_ALLOWLIST = {
    INCIDENT_PLAYBOOK_URL,
    NATIVE_SUPERVISION_REFERENCE_URL,
    NATIVE_SUPERVISION_POOL_REFERENCE_URL,
    f"{REPO_URL}/blob/main/LICENSE",
}
REQUIRED_PAGES = [
    "index.html",
    "get-started.html",
    "explanation.html",
    "prompt-coach.html",
    "workflows.html",
    "native-supervision.html",
    "use-cases.html",
    "external-contracting.html",
    "local-workers.html",
    "contractor-demo.html",
    "beads-memory.html",
    "model-synthesis.html",
    "zero-trust-consensus.html",
    "malpractice-sabotage.html",
    "codex-beads-hooks.html",
    "reference.html",
]
SOURCE_LINK_PATTERNS = [
    REPO_URL,
    f"{REPO_URL}/blob/main/LICENSE",
    INCIDENT_PLAYBOOK_URL,
    NATIVE_SUPERVISION_REFERENCE_URL,
    NATIVE_SUPERVISION_POOL_REFERENCE_URL,
    "https://github.com/gprocunier/hello-world-contractor-demo",
    "https://gprocunier.github.io/hello-world-contractor-demo/",
    "https://github.com/gastownhall/beads",
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
    "./native-supervision.html",
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
    "./native-supervision.html",
    "./beads-memory.html",
    "./model-synthesis.html",
    "./zero-trust-consensus.html",
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
        self.duplicate_ids: set[str] = set()
        self.hrefs: list[str] = []
        self.headings: list[tuple[str, str]] = []
        self.landmarks: set[str] = set()
        self.internal_copy_errors: list[str] = []
        self.title = ""
        self._in_title = False
        self._pre_depth = 0
        self._code_depth = 0
        self._public_copy_allow = False
        self._section_stack: list[str] = []
        self._current_heading: str | None = None
        self._heading_text: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attrs_dict = {key: value or "" for key, value in attrs}
        if "id" in attrs_dict:
            element_id = attrs_dict["id"]
            if element_id in self.ids:
                self.duplicate_ids.add(element_id)
            self.ids.add(element_id)
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

    def handle_comment(self, data: str) -> None:
        normalized = data.strip().lower()
        if normalized.startswith("cwo-public-copy: allow-start"):
            if 'reason="' not in data:
                self.internal_copy_errors.append(
                    "public-copy allow-start is missing reason (section=document)"
                )
            self._public_copy_allow = True
        elif normalized.startswith("cwo-public-copy: allow-end"):
            self._public_copy_allow = False

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self.title += data
        if self._current_heading:
            self._heading_text.append(data)
        self._record_internal_copy_errors(data)

    def _record_internal_copy_errors(self, data: str) -> None:
        if self._pre_depth or self._public_copy_allow:
            return
        section = self._section_stack[-1] if self._section_stack else "document"
        for issue in find_public_copy_issues(
            data,
            allow_internal_labels=self.allow_internal_labels,
            check_editorial_patterns=not self._code_depth,
            section=section,
        ):
            self.internal_copy_errors.append(issue.render())


def validate_html(path: Path) -> list[str]:
    errors: list[str] = []
    text = path.read_text(encoding="utf-8")
    parser = SiteParser(allow_internal_labels=path.name in INTERNAL_LABEL_REFERENCE_PAGES)
    parser.feed(text)

    if not parser.title.strip():
        errors.append(f"{path.relative_to(ROOT)} missing <title>")
    h1_count = sum(tag == "h1" for tag, _ in parser.headings)
    if h1_count != 1:
        errors.append(f"{path.relative_to(ROOT)} must contain exactly one h1; found {h1_count}")
    for element_id in sorted(parser.duplicate_ids):
        errors.append(f"{path.relative_to(ROOT)} contains duplicate id: {element_id}")
    if '<aside class="page-nav"' in text:
        errors.append(f"{path.relative_to(ROOT)} uses aside for page navigation instead of nav")
    if '<div class="nav-links">' in text:
        for href in PRIMARY_NAV_HREFS:
            if f'href="{href}"' not in text:
                errors.append(f"{path.relative_to(ROOT)} missing primary navigation link: {href}")
        primary_pages = {
            "index.html",
            "get-started.html",
            "workflows.html",
            "use-cases.html",
            "reference.html",
        }
        if path.name in primary_pages:
            expected = f'href="./{path.name}" aria-current="page"'
            if expected not in text:
                errors.append(f"{path.relative_to(ROOT)} missing current-page navigation state")
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
    if path.name == "get-started.html":
        ordered_terms = [
            "manage_instruction_profile.py install --profile operator-e",
            "manage_instruction_profile.py verify --profile operator-e",
            'cwo-codex -C "$PWD"',
            "/plan Use $complex-work-orchestration prompt coach:",
        ]
        positions = [text.find(term) for term in ordered_terms]
        if any(position < 0 for position in positions) or positions != sorted(positions):
            errors.append(
                f"{path.relative_to(ROOT)} must present Candidate E install, verify, fresh launch, then coach in order"
            )
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
                and href not in SOURCE_BLOB_LINK_ALLOWLIST
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
        elif parsed.fragment and target.suffix == ".html":
            target_text = target.read_text(encoding="utf-8")
            fragment = re.escape(parsed.fragment)
            if not re.search(rf'\bid=["\']{fragment}["\']', target_text):
                errors.append(
                    f"{path.relative_to(ROOT)} links to missing fragment: {href}"
                )

    for pattern in PRIVATE_PATTERNS:
        if pattern.search(text):
            errors.append(f"{path.relative_to(ROOT)} contains private or secret-looking content: {pattern.pattern}")
    for error in parser.internal_copy_errors:
        errors.append(f"{path.relative_to(ROOT)} contains {error}")
    if parser._public_copy_allow:
        errors.append(f"{path.relative_to(ROOT)} contains unclosed public-copy allow block")
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
