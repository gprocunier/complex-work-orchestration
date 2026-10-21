#!/usr/bin/env python3
"""Generate palette-only theme CSS for the two authored SVG illustrations."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re

from site_diagram_theme import svg_theme_style

ROOT = Path(__file__).resolve().parents[1]
THEME_STYLE = re.compile(r'<style id="diagram-theme">.*?</style>', re.S)


def outputs(root=ROOT):
    assets = root / 'docs/illustrations'
    manifest_path = assets / 'sources.json'
    manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
    expected = {}
    for name in manifest['illustrations']:
        path = assets / name
        original = THEME_STYLE.sub('', path.read_text(encoding='utf-8'))
        if hashlib.sha256(original.encode()).hexdigest() != manifest['original_illustrations'][name]:
            raise ValueError(f'{name}: approved source changed beyond its theme style')
        if original.count('<defs>') != 1:
            raise ValueError(f'{name}: expected exactly one defs boundary')
        themed = original.replace('<defs>', svg_theme_style('illustration') + '<defs>', 1)
        expected[path] = themed
        manifest['illustrations'][name] = hashlib.sha256(themed.encode()).hexdigest()
    expected[manifest_path] = json.dumps(manifest, indent=2) + '\n'
    return expected


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument('--write', action='store_true')
    modes.add_argument('--check', action='store_true')
    args = parser.parse_args(argv)
    changed = []
    for path, content in outputs().items():
        if path.read_text(encoding='utf-8') != content:
            changed.append(path.name)
            if args.write:
                path.write_text(content, encoding='utf-8')
    if changed:
        print(('Updated' if args.write else 'Stale') + ' illustration themes: ' + ', '.join(changed))
    return int(bool(changed) and not args.write)


if __name__ == '__main__':
    raise SystemExit(main())
