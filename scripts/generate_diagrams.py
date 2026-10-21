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

from site_diagram_theme import svg_theme_style
from example_diagrams import EXAMPLE_KINDS, render_example
from guide_diagrams import GUIDE_KINDS, render_guide

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
        geometry += [('quiet', 'Quiet display', 'hide terminal display', 160, 680, 'process'),
                     ('full', 'Full-context display', 'quiet not supported', 160, 860, 'process'),
                     ('preserve', 'Keep model context', 'Beads additionalContext', 160, 1060, 'terminal')]
        paths += [edge('support', 'quiet', 'M 160,530 V 618', 'Yes', (185, 575)),
                  edge('support', 'full', 'M 280,460 H 307 V 860 H 296', 'No', (294, 570)),
                  edge('quiet', 'preserve', 'M 30,680 H 13 V 1060 H 24'),
                  edge('full', 'preserve', 'M 160,916 V 998')]
        width, height = 320, 1140
    else:
        geometry += [('quiet', 'Quiet display', 'hide terminal display', 160, 680, 'process'),
                     ('full', 'Full-context display', 'quiet not supported', 520, 680, 'process'),
                     ('preserve', 'Keep model context', 'Beads additionalContext', 340, 900, 'terminal')]
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


def purpose_preserving(narrow):
    """Compact fork/decision flow; the narrow variant keeps readable type."""
    width = 320 if narrow else 480
    center, left, right = width / 2, (84 if narrow else 120), (236 if narrow else 360)
    peer_width = 136 if narrow else 192
    def compact(key, title, detail, x, y, w, h, decision=False):
        attributes = f'data-node="{key}" data-x="{x}" data-y="{y}" data-width="{w}" data-height="{h}"'
        shape = (f'<polygon points="{x},{y-h/2} {x+w/2},{y} {x},{y+h/2} {x-w/2},{y}" fill="#fff4e5" stroke="#8f5200" stroke-width="2"/>' if decision else
                 f'<rect x="{x-w/2}" y="{y-h/2}" width="{w}" height="{h}" rx="6" fill="#fff" stroke="#6a6e73" stroke-width="2"/>')
        text = (f'<text x="{x}" y="{y-8}" text-anchor="middle" dominant-baseline="central" font-size="17" font-weight="600">{escape(title)}</text>'
                f'<text x="{x}" y="{y+16}" text-anchor="middle" dominant-baseline="central" font-size="16">{escape(detail)}</text>')
        return f'<g {attributes}>{shape}{text}</g>'
    nodes = [compact('outcome', 'Agreed result', 'requirements + permissions', center, 50, width-32, 64),
             compact('build', 'Build', 'agreed task', left, 160, peer_width, 72),
             compact('review', 'Review', 'check result', right, 160, peer_width, 72),
             compact('evaluate', 'Check findings', 'inspect the evidence', center, 256, width-32, 64),
             compact('decision', 'Lead decides', 'accept?', center, 368, 248, 96, True),
             compact('accepted', 'Accepted', 'checks pass', left, 498, peer_width, 72),
             compact('held', 'Still open', 'questions', right, 498, peer_width, 72)]
    paths = [edge('outcome', 'build', f'M {center},82 V 102 H {left} V 118'),
             edge('outcome', 'review', f'M {center},82 V 102 H {right} V 118'),
             edge('build', 'evaluate', f'M {left},196 V 218'),
             edge('review', 'evaluate', f'M {right},196 V 218'),
             edge('evaluate', 'decision', f'M {center},288 V 314'),
             edge('decision', 'accepted', f'M {center},416 V 438 H {left} V 456'),
             edge('decision', 'held', f'M {center},416 V 438 H {right} V 456')]
    return width, 550, ''.join(paths + nodes)


def durable_recovery(narrow):
    """Save outside the conversation, then recover and verify current state."""
    width, height = (360, 1380) if narrow else (1120, 780)
    labels = {
        'work': ('Working session', ('Save decisions and evidence', 'as the task progresses')),
        'beads': ('Beads task database', ('Tasks and dependencies', 'Decisions + next task', 'Open work + evidence links')),
        'files': ('Files and evidence', ('Code + tests + reports', 'Handoff + source revision')),
        'recover': ('Recover context', ('After compaction / restart', 'Read saved tasks and links')),
        'verify': ('Verify current state', ('Inspect files; rerun checks', 'Confirm scope and limits')),
        'continue': ('Continue the work', ('Only if still permitted', 'Or record what blocks it')),
    }
    positions = ({'work': (180, 90), 'beads': (180, 320), 'files': (180, 550),
                  'recover': (180, 820), 'verify': (180, 1050), 'continue': (180, 1280)} if narrow else
                 {'work': (170, 210), 'beads': (560, 115), 'files': (560, 325),
                  'recover': (950, 210), 'verify': (950, 475), 'continue': (950, 695)})
    routes = ([('work', 'beads', 'M 180,160 V 244'),
               ('work', 'files', 'M 180,160 V 210 H 344 V 550 H 326'),
               ('beads', 'recover', 'M 40,320 H 16 V 820 H 34'),
               ('files', 'recover', 'M 180,620 V 744'),
               ('recover', 'verify', 'M 180,890 V 974'),
               ('verify', 'continue', 'M 180,1120 V 1204')] if narrow else
              [('work', 'beads', 'M 320,210 H 360 V 115 H 404'),
               ('work', 'files', 'M 320,210 H 360 V 325 H 404'),
               ('beads', 'recover', 'M 710,115 H 760 V 180 H 794'),
               ('files', 'recover', 'M 710,325 H 760 V 240 H 794'),
               ('recover', 'verify', 'M 950,280 V 399'),
               ('verify', 'continue', 'M 950,545 V 619')])
    parts = [edge(source, target, path) for source, target, path in routes]
    for key, (title, detail) in labels.items():
        x, y = positions[key]
        w, h = (280 if narrow else 300), 140
        attrs = f'data-node="{key}" data-x="{x}" data-y="{y}" data-width="{w}" data-height="{h}"'
        parts.append(f'<g {attrs}><rect x="{x-w/2}" y="{y-h/2}" width="{w}" height="{h}" rx="12" fill="#fff" stroke="#6a6e73" stroke-width="2"/>')
        lines = [title, *detail]
        top = y - (len(lines)-1)*13.5
        for i, line in enumerate(lines):
            parts.append(f'<text x="{x}" y="{top+i*27}" text-anchor="middle" dominant-baseline="central" font-size="{22 if i == 0 else 18}" font-weight="{600 if i == 0 else 400}">{escape(line)}</text>')
        parts.append('</g>')
    if not narrow:
        parts.append('<rect x="20" y="450" width="690" height="260" rx="12" fill="#fff4e5" stroke="#8f5200" stroke-width="2"/>')
        for i, line in enumerate(('What compaction changes', 'The conversation may be summarized.',
                                  'Saved task records and project files stay outside it.',
                                  'Recovery uses those records—not assumed recall.',
                                  'Missing or stale records still need investigation.')):
            parts.append(f'<text x="46" y="{495+i*42}" font-size="{24 if i == 0 else 20}" font-weight="{600 if i == 0 else 400}">{escape(line)}</text>')
    return width, height, ''.join(parts)


def render(diagram, narrow=False):
    width, height, body = (render_guide(diagram['kind'], narrow) if diagram['kind'] in GUIDE_KINDS else
                           render_example(diagram['kind'], narrow) if diagram['kind'] in EXAMPLE_KINDS else
                           durable_recovery(narrow) if diagram['kind'] == 'durable-recovery' else
                           purpose_preserving(narrow) if diagram['kind'] == 'purpose-preserving' else
                           hook_decision(narrow) if diagram['kind'] == 'hook-decision' else
                           durable_memory(narrow) if diagram['kind'] == 'durable-memory' else sequence(diagram, narrow))
    marker = ('<marker id="arrow" markerUnits="userSpaceOnUse" viewBox="0 0 8 8" refX="8" refY="4" markerWidth="8" markerHeight="8" orient="auto-start-reverse"><path d="M 0 0 L 8 4 L 0 8 z" fill="#a60000"/></marker>' if diagram['kind'] in {'purpose-preserving', 'durable-recovery'} | EXAMPLE_KINDS | GUIDE_KINDS else
              '<marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M 0 0 L 10 5 L 0 10 z" fill="#a60000"/></marker>')
    font_family = 'DejaVu Sans, sans-serif' if diagram['kind'] in {'durable-recovery'} | EXAMPLE_KINDS | GUIDE_KINDS else 'system-ui, sans-serif'
    svg = f'''<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}" role="img" aria-labelledby="title desc" font-family="{font_family}" fill="#151515">
  <title id="title">{escape(diagram['title'])}</title>
  <desc id="desc">{escape(diagram['description'])}</desc>
  {svg_theme_style("flow")}
  <defs>{marker}</defs>
  {body}
</svg>
'''
    return svg, width, height


def figure(slug, diagram):
    _, wide_w, wide_h = render(diagram)
    _, narrow_w, narrow_h = render(diagram, True)
    anchor = f' id="{escape(slug, quote=True)}"' if diagram['kind'] in EXAMPLE_KINDS | GUIDE_KINDS else ''
    equivalent = ''
    if diagram['kind'] in GUIDE_KINDS:
        steps = diagram.get('text_equivalent')
        if not isinstance(steps, list) or not steps or not all(isinstance(s, str) and s.strip() for s in steps):
            raise ValueError(f'{slug}: guide diagrams require a detailed text equivalent')
        equivalent = ('\n            <details class="diagram-text"><summary>Read the diagram as text</summary><ul>' +
                      ''.join(f'<li>{escape(step)}</li>' for step in steps) + '</ul></details>')
    return f'''<!-- diagram:{slug} -->
            <figure{anchor} class="{escape(diagram.get('figure_class', 'flowchart'), quote=True)}">
              <picture>
                <source media="{escape(diagram.get('narrow_media', '(max-width: 40rem)'), quote=True)}" srcset="./diagrams/{slug}-narrow.svg" width="{narrow_w}" height="{narrow_h}">
                <img src="./diagrams/{slug}.svg" width="{wide_w}" height="{wide_h}" alt="{escape(diagram['title'], quote=True)} flowchart. Text equivalent follows." loading="lazy" decoding="async">
              </picture>
              <figcaption>{escape(diagram['description'])}</figcaption>
            </figure>{equivalent}
            <!-- /diagram:{slug} -->'''


def figure_pages(diagram):
    additional = diagram.get('additional_pages', [])
    if not isinstance(additional, list) or not all(isinstance(p, str) for p in additional):
        raise ValueError('additional_pages must be a list of page names')
    pages = [diagram['page'], *additional]
    if len(pages) != len(set(pages)) or not all(re.fullmatch(r'[a-z][a-z0-9-]*\.html', p) for p in pages):
        raise ValueError('figure pages must be unique local HTML page names')
    return pages


def outputs(root=ROOT):
    diagrams = json.loads((root / 'docs/diagrams/flows.json').read_text(encoding='utf-8'))
    expected = {}
    for slug, diagram in diagrams.items():
        if not re.fullmatch(r'[a-z][a-z0-9-]*', slug):
            raise ValueError(f'Invalid diagram name: {slug}')
        for narrow in (False, True):
            path = root / 'docs/diagrams' / f'{slug}{"-narrow" if narrow else ""}.svg'
            expected[path] = render(diagram, narrow)[0]
        for page_name in figure_pages(diagram):
            page = root / 'docs' / page_name
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
