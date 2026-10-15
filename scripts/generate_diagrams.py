#!/usr/bin/env python3
"""Generate local SVG flowcharts and their responsive, text-equivalent figures."""
from __future__ import annotations

import argparse
from html import escape
import json
from pathlib import Path
import re
import sys
import textwrap

ROOT = Path(__file__).resolve().parents[1]


def text_lines(title, detail, x, y, *, limit=25):
    lines = [(line, True) for line in textwrap.wrap(title, limit)]
    lines += [(line, False) for line in textwrap.wrap(detail, limit)]
    top = y - (len(lines) - 1) * 12
    return ''.join(f'<text x="{x}" y="{top + i * 24}" text-anchor="middle" dominant-baseline="central" font-size="{20 if bold else 18}" font-weight="{600 if bold else 400}">{escape(line)}</text>'
                   for i, (line, bold) in enumerate(lines))


def node(key, title, detail, x, y, *, shape='process', w=260, h=112):
    attrs = f'data-node="{key}" data-x="{x}" data-y="{y}" data-width="{w}" data-height="{h}"'
    if shape == 'decision':
        geometry = f'<polygon points="{x},{y-h/2} {x+w/2},{y} {x},{y+h/2} {x-w/2},{y}" fill="#fff4e5" stroke="#8f5200" stroke-width="2"/>'
    else:
        geometry = f'<rect x="{x-w/2}" y="{y-h/2}" width="{w}" height="{h}" rx="{32 if shape == "terminal" else 6}" fill="#fff" stroke="#6a6e73" stroke-width="2"/>'
    return f'<g {attrs}>{geometry}{text_lines(title, detail, x, y, limit=16 if shape == "decision" else 25)}</g>'


def edge(source, target, path, label=None, label_at=None):
    result = f'<path data-from="{source}" data-to="{target}" d="{path}" fill="none" stroke="#a60000" stroke-width="2.5" stroke-linejoin="round" marker-end="url(#arrow)"/>'
    if label:
        x, y = label_at
        result += f'<text x="{x}" y="{y}" text-anchor="middle" font-size="18" font-weight="600" fill="#760000" stroke="#fff" stroke-width="5" paint-order="stroke">{escape(label)}</text>'
    return result


def sequence(diagram, narrow):
    width = 320 if narrow else 680
    positions = []
    for i in range(len(diagram['nodes'])):
        row, col = (i, 0) if narrow else divmod(i, 2)
        x = 160 if narrow else (160 if (col == 0) == (row % 2 == 0) else 520)
        positions.append((x, 80 + row * 180))
    paths = []
    for i, ((x1, y1), (x2, y2)) in enumerate(zip(positions, positions[1:])):
        if y1 == y2:
            direction = 1 if x2 > x1 else -1
            path = f'M {x1 + direction * 130},{y1} H {x2 - direction * 136}'
        else:
            path = f'M {x1},{y1+56} V {y2-62}'
        paths.append(edge(str(i), str(i + 1), path))
    nodes = [node(str(i), n['title'], n['detail'], x, y,
                  shape='terminal' if i in (0, len(positions)-1) else 'process')
             for i, (n, (x, y)) in enumerate(zip(diagram['nodes'], positions))]
    return width, positions[-1][1] + 80, ''.join(paths + nodes)


def hook_decision(narrow):
    # Both layouts encode exactly the same graph; only positions/routes change.
    x = 160 if narrow else 340
    geometry = [('symptom', 'Visible context', 'SessionStart output', x, 80, 'terminal'),
                ('inspect', 'Inspect support', 'installed Codex build', x, 260, 'process'),
                ('support', 'Display hint', 'supported?', x, 460, 'decision')]
    paths = [edge('symptom', 'inspect', f'M {x},136 V 198'),
             edge('inspect', 'support', f'M {x},316 V 384')]
    if narrow:
        geometry += [('quiet', 'Quiet display', 'presentation hint only', 160, 680, 'process'),
                     ('full', 'Full-context display', 'unsupported quiet fails closed', 160, 860, 'process'),
                     ('preserve', 'Preserve memory', 'Beads additionalContext', 160, 1060, 'terminal')]
        paths += [edge('support', 'quiet', 'M 160,530 V 618', 'Yes', (185, 575)),
                  edge('support', 'full', 'M 280,460 H 307 V 860 H 296', 'No', (294, 570)),
                  edge('quiet', 'preserve', 'M 30,680 H 13 V 1060 H 24'),
                  edge('full', 'preserve', 'M 160,916 V 998')]
        width, height = 320, 1140
    else:
        geometry += [('quiet', 'Quiet display', 'presentation hint only', 160, 680, 'process'),
                     ('full', 'Full-context display', 'unsupported quiet fails closed', 520, 680, 'process'),
                     ('preserve', 'Preserve memory', 'Beads additionalContext', 340, 900, 'terminal')]
        paths += [edge('support', 'quiet', 'M 220,460 H 160 V 618', 'Yes', (154, 550)),
                  edge('support', 'full', 'M 460,460 H 520 V 618', 'No', (545, 550)),
                  edge('quiet', 'preserve', 'M 160,736 V 790 H 340 V 838'),
                  edge('full', 'preserve', 'M 520,736 V 790 H 340 V 838')]
        width, height = 680, 980
    nodes = [node(key, title, detail, px, py, shape=shape,
                  w=240 if shape == 'decision' else 260,
                  h=140 if shape == 'decision' else 112)
             for key, title, detail, px, py, shape in geometry]
    return width, height, ''.join(paths + nodes)


def durable_memory(narrow):
    width = 320 if narrow else 680
    x, left, right = (160, 80, 240) if narrow else (340, 170, 510)
    paths = [edge('session-a', 'files', f'M {x},100 V 130 H {left} V 159'),
             edge('session-a', 'tasks', f'M {x},100 V 130 H {right} V 159'),
             edge('files', 'session-b', f'M {left},275 V 310 H {x} V 344'),
             edge('tasks', 'session-b', f'M {right},275 V 310 H {x} V 344')]
    nodes = [node('session-a', 'Session A', 'save checked work', x, 60, w=240, h=80, shape='terminal'),
             node('files', 'Files', 'and tests', left, 220, w=136 if narrow else 260, h=110),
             node('tasks', 'Tasks', 'decisions', right, 220, w=136 if narrow else 260, h=110),
             node('session-b', 'Session B', 'verify, then continue', x, 390, w=240, h=80, shape='terminal')]
    return width, 450, ''.join(paths + nodes)


def render(diagram, narrow=False):
    width, height, body = (hook_decision(narrow) if diagram['kind'] == 'hook-decision' else
                           durable_memory(narrow) if diagram['kind'] == 'durable-memory' else sequence(diagram, narrow))
    svg = f'''<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}" role="img" aria-labelledby="title desc" font-family="system-ui, sans-serif" fill="#151515">
  <title id="title">{escape(diagram['title'])}</title>
  <desc id="desc">{escape(diagram['description'])}</desc>
  <defs><marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M 0 0 L 10 5 L 0 10 z" fill="#a60000"/></marker></defs>
  {body}
</svg>
'''
    return svg, width, height


def figure(slug, diagram):
    _, wide_w, wide_h = render(diagram)
    _, narrow_w, narrow_h = render(diagram, True)
    return f'''<!-- diagram:{slug} -->
            <figure class="flowchart">
              <picture>
                <source media="(max-width: 40rem)" srcset="./diagrams/{slug}-narrow.svg" width="{narrow_w}" height="{narrow_h}">
                <img src="./diagrams/{slug}.svg" width="{wide_w}" height="{wide_h}" alt="{escape(diagram['title'], quote=True)} flowchart. Text equivalent follows." loading="lazy" decoding="async">
              </picture>
              <figcaption>{escape(diagram['description'])}</figcaption>
            </figure>
            <!-- /diagram:{slug} -->'''


def outputs(root=ROOT):
    diagrams = json.loads((root / 'docs/diagrams/flows.json').read_text(encoding='utf-8'))
    expected = {}
    for slug, diagram in diagrams.items():
        if not re.fullmatch(r'[a-z][a-z0-9-]*', slug):
            raise ValueError(f'Invalid diagram name: {slug}')
        for narrow in (False, True):
            path = root / 'docs/diagrams' / f'{slug}{"-narrow" if narrow else ""}.svg'
            expected[path] = render(diagram, narrow)[0]
        page = root / 'docs' / diagram['page']
        source = expected.get(page, page.read_text(encoding='utf-8'))
        pattern = rf'<!-- diagram:{slug} -->.*?<!-- /diagram:{slug} -->'
        source, count = re.subn(pattern, lambda _: figure(slug, diagram), source, flags=re.S)
        if count != 1:
            raise ValueError(f'{page.name}: expected exactly one diagram marker for {slug}; found {count}')
        expected[page] = source
    return expected


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument('--write', action='store_true')
    modes.add_argument('--check', action='store_true')
    args = parser.parse_args(argv)
    changed = []
    for path, source in outputs().items():
        if not path.exists() or path.read_text(encoding='utf-8') != source:
            changed.append(path.relative_to(ROOT))
            if args.write:
                path.write_text(source, encoding='utf-8')
    if changed:
        print(('Updated' if args.write else 'Stale') + ' diagram outputs: ' + ', '.join(map(str, changed)))
    else:
        print('SVG diagrams and responsive figures are current.')
    return int(bool(changed) and not args.write)


if __name__ == '__main__':
    sys.exit(main())
