#!/usr/bin/env python3
from __future__ import annotations

import re
import sys
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlparse

from cwo_core.public_copy import find_public_copy_issues
from generate_site import PAGES, PRIMARY_NAV, FOOTER_NAV
from site_code import without_token_spans

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
SOURCE_BLOB_LINK_ALLOWLIST.update(
    f"{REPO_URL}/blob/main/{name}" for name in (
        "CONTRIBUTING.md", "SKILL.md", "SECURITY.md", "CHANGELOG.md",
        "references/cwo-system-prompt.md",
        "references/execution-environments.md", "references/native-pool-capacity-migration.md",
        "references/run-readiness.md", "references/security-threat-model.md",
        "references/frozen-protocol-lock.md", "references/pre-dispatch-readiness.md",
        "policy/native-worker-execution.yaml", "policy/executor-registry.yaml",
        "policy/access-profiles.yaml", "policy/execution-environments.yaml",
        "scripts/manage_instruction_profile.py", "scripts/check_installed_skill.py",
        "scripts/close_bead_with_summary.py", "references/external-contracting.md",
        "examples/first-project/README.md",
        "examples/first-project/VALIDATION.md", "examples/release-readiness/RECORD.md", "examples/release-readiness/HANDOFF.md",
    )
)
SOURCE_BLOB_LINK_ALLOWLIST.add(
    f"{REPO_URL}/blob/8e05b6cce4c4cf89325112f019fdd8c69a28ecff/examples/release-readiness/RECORD.md"
)
# Immutable implementation evidence for the positioning/reference slice.
SOURCE_BLOB_LINK_ALLOWLIST.update(
    f"{REPO_URL}/blob/8e05b6cce4c4cf89325112f019fdd8c69a28ecff/{name}"
    for name in (
        "scripts/cwo_core/frozen_protocol.py", "scripts/cwo_core/synthesis.py",
        "scripts/cwo_core/native_pool_transaction.py", "tests/test_frozen_protocol.py",
        "tests/test_zero_trust_consensus.py", "tests/test_local_dispatch.py",
        "tests/test_model_synthesis.py",
    )
)
SOURCE_LINK_PATTERNS = [
    REPO_URL,
    f"{REPO_URL}/blob/main/LICENSE",
    INCIDENT_PLAYBOOK_URL,
    NATIVE_SUPERVISION_REFERENCE_URL,
    NATIVE_SUPERVISION_POOL_REFERENCE_URL,
    "https://github.com/gprocunier/hello-world-contractor-demo",
    "https://gprocunier.github.io/hello-world-contractor-demo/",
    "https://github.com/gastownhall/beads",
    "https://beads.gascity.com/",
    "https://diataxis.fr/",
    "https://www.anthropic.com/news/claude-fable-5-mythos-5",
    "https://www.anthropic.com/system-cards",
    "https://www-cdn.anthropic.com/2f9323abbcc4abe219577539efe19a623c9ca2bd/Claude%20Fable%205%20%26%20Claude%20Mythos%205%20System%20Card.pdf",
]
SOURCE_LINK_PATTERNS.extend(sorted(SOURCE_BLOB_LINK_ALLOWLIST))
SOURCE_LINK_PATTERNS.extend([
    "https://learn.chatgpt.com/docs/codex/cli",
    "https://learn.chatgpt.com/docs/models",
    "https://learn.chatgpt.com/docs/agent-configuration/subagents",
    "https://learn.chatgpt.com/docs/config-file/config-reference",
])
# Exact primary sources for the dated ecosystem comparison; fragments are allowed.
SOURCE_LINK_PATTERNS.extend([
    'https://code.claude.com/docs/en/sub-agents',
    'https://code.claude.com/docs/en/agent-teams',
    'https://docs.opencode.ai/docs/providers/',
    'https://docs.opencode.ai/docs/permissions/',
    'https://docs.langchain.com/oss/python/langgraph/persistence',
    'https://docs.langchain.com/oss/python/langgraph/interrupts',
    'https://docs.crewai.com/en/concepts/flows',
    'https://openai.github.io/openai-agents-python/models/',
    'https://openai.github.io/openai-agents-python/guardrails/',
    'https://microsoft.github.io/autogen/stable/user-guide/agentchat-user-guide/tutorial/teams.html',
])
# Shell/navigation inventory has one producer. Content safety stays independent.
REQUIRED_PAGES = list(PAGES)
PRIMARY_NAV_HREFS = [href for href, _ in PRIMARY_NAV]
FOOTER_HREFS = [href for href, _ in FOOTER_NAV]

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
    "./use-cases.html",
    "./explanation.html",
    "./reference.html",
    REPO_URL,
]

ONBOARDING_STEPS = [
    "manage_instruction_profile.py install --profile operator-e",
    "manage_instruction_profile.py verify --profile operator-e",
    "scripts/create_first_project.py",
    'cwo-codex -C "$HOME/cwo-first-project"',
    "Fix only errors(config)",
]


ONBOARDING_PAGE_STEPS = {"install.html": ONBOARDING_STEPS[:2], "first-project.html": ONBOARDING_STEPS[2:]}
SEMANTIC_ROUTES = {
    "beads-graph": ("./beads-memory.html#example", "bd show TASK_ID --json"),
    "validate-handoff": ("./beads-memory.html", "cat HANDOFF.md"),
    "optional-lanes": ("./external-contracting.html#collaboration", None),
}


def validate_onboarding(contents: dict[str, str]) -> list[str]:
    from html import unescape
    errors = []
    for page, steps in ONBOARDING_PAGE_STEPS.items():
        plain = unescape(without_token_spans(contents.get(page, "")))
        positions = [plain.find(step) for step in steps]
        if any(p < 0 for p in positions) or positions != sorted(positions):
            errors.append(f"docs/{page} must preserve canonical onboarding steps in order")
    entry = contents.get("get-started.html", "")
    stages = [entry.find(f'href="./{page}"') for page in ("install.html", "first-project.html", "continue-project.html")]
    if any(p < 0 for p in stages) or stages != sorted(stages):
        errors.append("docs/get-started.html must link the install, first task and continuation stages in order")
    return errors


class FragmentContent(HTMLParser):
    """Collect one real section, so a stray alias elsewhere cannot satisfy it."""
    def __init__(self, target):
        super().__init__()
        self.target = target
        self.depth = 0
        self.found = False
        self.hrefs = []
        self.text = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "section":
            if self.depth:
                self.depth += 1
            elif attrs.get("id") == self.target:
                self.depth = 1
                self.found = True
        if self.depth and tag == "a":
            self.hrefs.append(attrs.get("href"))

    def handle_endtag(self, tag):
        if tag == "section" and self.depth:
            self.depth -= 1

    def handle_data(self, data):
        if self.depth:
            self.text.append(data)


def validate_semantic_routes(source: str) -> list[str]:
    errors = []
    for anchor, (href, command) in SEMANTIC_ROUTES.items():
        section = FragmentContent(anchor)
        section.feed(source)
        if not section.found or href not in section.hrefs or (command and command not in "".join(section.text)):
            errors.append(f"docs/workflows.html#{anchor} must provide its promised task and exact continuation link")
    return errors


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


def first_screen_term_text(first_screen: str, term: str) -> str:
    """Allow a definition-first Beads introduction only in its memory section.

    The owner requested a named explanation of durable memory. This is not a
    blanket exemption for unexplained brand/internal terms on the landing page.
    """
    if term == "Beads":
        section = re.search(r'<section id="durable-memory"[^>]*>.*?</section>', first_screen, re.DOTALL)
        if section:
            plain = re.sub(r"<[^>]+>", " ", section.group(0))
            plain = " ".join(plain.split())
            first_beads = re.search(r"\bBeads\b", plain, re.IGNORECASE)
            if first_beads and plain[first_beads.start():].startswith("Beads is the task database CWO uses for durable project memory."):
                first_screen = first_screen[:section.start()] + first_screen[section.end():]
    return re.sub(r"<[^>]+>", " ", first_screen)


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
            "explanation.html",
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
        for term in INDEX_FIRST_SCREEN_FORBIDDEN_TERMS:
            first_screen_plain = first_screen_term_text(first_screen, term)
            if re.search(rf"\b{re.escape(term)}\b", first_screen_plain, re.IGNORECASE):
                errors.append(
                    f"{path.relative_to(ROOT)} introduces advanced term before novice ramp: {term}"
                )
        for href in INDEX_EXPERT_ROUTE_HREFS:
            if f'href="{href}"' not in text:
                errors.append(f"{path.relative_to(ROOT)} missing expert route link: {href}")
    if path.name == "workflows.html":
        errors.extend(validate_semantic_routes(text))
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
        if parsed.path.startswith("../"):
            errors.append(f"{path.relative_to(ROOT)} link leaves published docs directory: {href}")
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
    errors.extend(validate_onboarding({page: (DOCS / page).read_text() for page in ["get-started.html", *ONBOARDING_PAGE_STEPS] if (DOCS / page).is_file()}))
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
