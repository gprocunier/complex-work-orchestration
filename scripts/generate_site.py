#!/usr/bin/env python3
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

from cwo_core.util import atomic_write_text

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"
REPO_URL = "https://github.com/gprocunier/complex-work-orchestration"
FAVICON = (
    "data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Crect "
    "width='32' height='32' rx='4' fill='%23151515'/%3E%3Ccircle cx='16' cy='16' r='9' "
    "fill='%23e00'/%3E%3Cpath d='M7 16h18' stroke='white' stroke-width='4'/%3E%3C/svg%3E"
)

PAGES = [
    "index.html",
    "get-started.html",
    "install.html",
    "first-project.html",
    "continue-project.html",
    "tutorial-recovery.html",
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
PRIMARY_NAV = [
    ("./index.html", "Home"),
    ("./get-started.html", "Start Here"),
    ("./use-cases.html", "Examples"),
    ("./workflows.html", "Guides"),
    ("./explanation.html", "Concepts"),
    ("./reference.html", "Reference"),
    (REPO_URL, "GitHub"),
]
FOOTER_NAV = [
    ("./index.html", "Home"),
    ("./get-started.html", "Start Here"),
    ("./prompt-coach.html", "Prompt Coach"),
    ("./workflows.html", "Guides"),
    ("./native-supervision.html", "Native Supervision"),
    ("./use-cases.html", "Examples"),
    ("./external-contracting.html", "Contractors"),
    ("./local-workers.html", "Local Workers"),
    ("./contractor-demo.html", "Historical Demo"),
    ("./reference.html", "Reference"),
    (REPO_URL, "Source"),
    (f"{REPO_URL}/blob/main/LICENSE", "GPL-3.0"),
]

# Pages using the article shell and progressive local-contents navigation.
REFERENCE_SLICE = {"index.html", "get-started.html", "install.html", "first-project.html", "continue-project.html", "tutorial-recovery.html", "workflows.html", "beads-memory.html"}
PAGE_PARENTS = {**{p: "get-started.html" for p in ("install.html", "first-project.html", "continue-project.html", "tutorial-recovery.html")}, "beads-memory.html": "workflows.html"}

TITLE_RE = re.compile(r"<title>(?P<title>.*?)</title>", re.DOTALL)
DESCRIPTION_RE = re.compile(r'<meta\s+name="description"\s+content="(?P<description>.*?)"\s*>', re.DOTALL)
MAIN_RE = re.compile(r'\n    <main id="main"(?: tabindex="-1")?>.*?\n    </main>\n', re.DOTALL)


def extract_required(pattern: re.Pattern[str], text: str, path: Path, name: str) -> str:
    match = pattern.search(text)
    if not match:
        raise ValueError(f"{path.relative_to(ROOT)} missing {name}")
    return match.group(name).strip()


def render_link(href: str, label: str, current_page: str) -> str:
    current_attr = (' aria-current="page"' if href == f"./{current_page}" else
                    ' aria-current="true"' if href == f"./{PAGE_PARENTS.get(current_page)}" else "")
    return f'          <a href="{href}"{current_attr}>{label}</a>'


def render_page(path: Path) -> str:
    text = path.read_text(encoding="utf-8")
    title = extract_required(TITLE_RE, text, path, "title")
    description = extract_required(DESCRIPTION_RE, text, path, "description")
    main_match = MAIN_RE.search(text)
    if not main_match:
        raise ValueError(f"{path.relative_to(ROOT)} missing <main id=\"main\"> shell boundary")
    main = main_match.group(0).strip("\n").replace(
        '<main id="main">', '<main id="main" tabindex="-1">', 1
    )
    primary_nav = "\n".join(render_link(href, label, path.name) for href, label in PRIMARY_NAV)
    footer_nav = "\n".join(f'        <a href="{href}">{label}</a>' for href, label in FOOTER_NAV)
    enhancement = '<script src="./site.js" defer></script>' if path.name in REFERENCE_SLICE else ""
    if path.name in REFERENCE_SLICE:
        groups = [("Learn", FOOTER_NAV[:4]), ("Operate", FOOTER_NAV[4:10]), ("Project", FOOTER_NAV[10:])]
        footer = '<div class="page-shell footer-grid"><div><strong>Complex Work Orchestration</strong><p>Dependent tasks, saved decisions, checked results.</p></div>'
        for label, links in groups:
            footer += f'<nav class="footer-group" aria-label="Footer {label}"><strong>{label}</strong>' + ''.join(f'<a href="{href}">{name}</a>' for href, name in links) + '</nav>'
        footer += '</div>'
    else:
        footer = f'<div>\n        <strong>Complex Work Orchestration</strong>\n        <p>Keep decisions, progress, and evidence across agent sessions.</p>\n      </div>\n      <nav aria-label="Footer">\n{footer_nav}\n      </nav>'
    rendered = f"""<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta
      name="description"
      content="{description}"
    >
    <title>{title}</title>
    <link rel="icon" href="{FAVICON}">
    <link rel="stylesheet" href="./styles.css">
    {enhancement}
  </head>
  <body>
    <a class="skip-link" href="#main">Skip to content</a>
    <header class="site-header">
      <nav class="top-nav" aria-label="Primary">
        <a class="brand" href="./index.html" aria-label="Complex Work Orchestration home">
          <span class="brand-mark" aria-hidden="true"></span>
          <span>Complex Work Orchestration</span>
        </a>
        <div class="nav-links">
{primary_nav}
        </div>
      </nav>
    </header>

{main}

    <footer class="site-footer">
      {footer}
    </footer>
  </body>
</html>
"""
    return rendered.replace("\n    \n  </head>", "\n  </head>")



def check_pages(*, write: bool, pages: list[str] | None = None) -> list[Path]:
    changed: list[Path] = []
    for page in pages or PAGES:
        path = DOCS / page
        rendered = render_page(path)
        current = path.read_text(encoding="utf-8")
        if current == rendered:
            continue
        changed.append(path)
        if write:
            atomic_write_text(path, rendered)
    return changed


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate the shared docs HTML shell while preserving page bodies.")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true", help="Fail if generated site shell output is not current.")
    mode.add_argument("--write", action="store_true", help="Rewrite docs pages with the generated site shell.")
    parser.add_argument("--pages", nargs="+", choices=PAGES, help="Restrict shell generation to explicit pages")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    write = bool(args.write)
    changed = check_pages(write=write, pages=args.pages)
    if changed and not write:
        print("Generated site shell is out of date:")
        for path in changed:
            print(f"  {path.relative_to(ROOT)}")
        print("Run: python scripts/generate_site.py --write")
        return 1
    if changed:
        print("Updated generated site shell:")
        for path in changed:
            print(f"  {path.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
