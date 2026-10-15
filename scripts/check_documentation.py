#!/usr/bin/env python3
"""Check maintained Markdown targets and retained Pages routes/fragments."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[1]


def markdown_ids(text):
    identifiers = set(re.findall(r'\bid=["\']([^"\']+)', text))
    counts = {}
    for title in re.findall(r"^#{1,6}\s+(.+?)\s*#*\s*$", re.sub(r"```.*?```", "", text, flags=re.S), re.M):
        slug = re.sub(r"[^\w\s-]", "", re.sub(r"<[^>]+>", "", title).lower()).replace(" ", "-")
        count = counts.get(slug, 0)
        counts[slug] = count + 1
        identifiers.add(slug + (f"-{count}" if count else ""))
    return identifiers


def check(root=ROOT):
    errors = []
    paths = [root / "README.md", root / "CONTRIBUTING.md", *sorted((root / "references").glob("*.md")),
             *sorted((root / "examples/first-project").rglob("*.md")),
             *sorted((root / "examples/worked-evidence").rglob("*.md"))]
    for path in paths:
        if not path.is_file():
            errors.append(f"missing maintained document: {path.relative_to(root)}")
            continue
        text = re.sub(r"```.*?```", "", path.read_text(), flags=re.S)
        for href in re.findall(r"\]\(([^\s)]+)(?:\s+[^)]*)?\)", text):
            parsed = urlsplit(href)
            if parsed.scheme or not parsed.path:
                continue
            target = (path.parent / unquote(parsed.path)).resolve()
            if not target.is_relative_to(root.resolve()) or not target.exists():
                errors.append(f"{path.relative_to(root)}: missing/outside target {href}")
            elif parsed.fragment and target.suffix in {".md", ".html"}:
                content = target.read_text()
                identifiers = (markdown_ids(content) if target.suffix == ".md" else
                               set(re.findall(r'\bid=["\']([^"\']+)', content)))
                if unquote(parsed.fragment) not in identifiers:
                    errors.append(f"{path.relative_to(root)}: missing fragment {href}")
    manifest = json.loads((root / "tests/fixtures/site-legacy-routes.json").read_text())
    for name, anchors in manifest.items():
        path = root / "docs" / name
        if not path.is_file():
            errors.append(f"retired route without alias: {name}")
            continue
        ids = set(re.findall(r'\bid=["\']([^"\']+)', path.read_text()))
        for anchor in anchors:
            if anchor not in ids:
                errors.append(f"missing legacy route: {name}#{anchor}")
    return errors


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--json", action="store_true", help="Emit a versioned machine-readable report instead of human text")
    args = parser.parse_args(argv)
    errors = check()
    if args.json:
        print(json.dumps({"version": 1, "ok": not errors, "errors": errors}))
    else:
        for error in errors:
            print("ERROR:", error)
        if not errors:
            print("Maintained Markdown links and legacy Pages routes passed.")
    return bool(errors)


if __name__ == "__main__":
    raise SystemExit(main())
