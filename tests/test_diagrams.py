from __future__ import annotations

import importlib.util
import json
import re
import sys
from pathlib import Path
import tempfile
import unittest
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
SPEC = importlib.util.spec_from_file_location('generate_diagrams', ROOT / 'scripts/generate_diagrams.py')
DIAGRAMS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DIAGRAMS)
NS = {'s': 'http://www.w3.org/2000/svg'}


class DiagramTests(unittest.TestCase):
    def setUp(self):
        self.flows = json.loads((ROOT / 'docs/diagrams/flows.json').read_text())

    def test_all_nineteen_figures_and_thirty_eight_assets_are_current(self):
        self.assertEqual(len(self.flows), 19)
        expected = DIAGRAMS.outputs()
        self.assertEqual({p for p in expected if p.suffix == '.svg'},
                         set((ROOT / 'docs/diagrams').glob('*.svg')))
        for path, source in expected.items():
            with self.subTest(path=path):
                self.assertEqual(path.read_text(), source)

    def test_wide_and_narrow_variants_preserve_nodes_and_directed_edges(self):
        for name, diagram in self.flows.items():
            graphs = []
            for narrow in (False, True):
                tree = ET.fromstring(DIAGRAMS.render(diagram, narrow)[0])
                nodes = {n.attrib['data-node']: ''.join(n.itertext())
                         for n in tree.findall('s:g', NS)}
                edges = {(p.attrib['data-from'], p.attrib['data-to'])
                         for p in tree.findall('s:path', NS)}
                self.assertTrue(edges, name)
                for source, target in edges:
                    self.assertIn(source, nodes)
                    self.assertIn(target, nodes)
                graphs.append((nodes, edges))
            self.assertEqual(graphs[0], graphs[1], name)

    def test_shapes_stay_inside_canvas_with_positive_gutters(self):
        for diagram in self.flows.values():
            for narrow in (False, True):
                svg, w, h = DIAGRAMS.render(diagram, narrow)
                boxes = []
                for n in ET.fromstring(svg).findall('s:g', NS):
                    a = n.attrib
                    x, y, bw, bh = (float(a[f'data-{key}']) for key in ('x', 'y', 'width', 'height'))
                    box = (x-bw/2, y-bh/2, x+bw/2, y+bh/2)
                    self.assertGreaterEqual(box[0], 12)
                    self.assertGreaterEqual(box[1], 12)
                    self.assertLessEqual(box[2], w-12)
                    self.assertLessEqual(box[3], h-12)
                    for left, top, right, bottom in boxes:
                        self.assertTrue(box[2] + 12 <= left or box[0] >= right + 12 or
                                        box[3] + 12 <= top or box[1] >= bottom + 12)
                    boxes.append(box)

    def test_every_semantic_connector_has_an_arrowhead(self):
        for diagram in self.flows.values():
            for narrow in (False, True):
                tree = ET.fromstring(DIAGRAMS.render(diagram, narrow)[0])
                for path in tree.findall('s:path', NS):
                    self.assertEqual(path.attrib.get('marker-end'), 'url(#arrow)')

    def test_purpose_arrows_have_fixed_size_clear_targets_and_visible_shafts(self):
        for narrow in (False, True):
            tree = ET.fromstring(DIAGRAMS.render(self.flows['purpose-preserving'], narrow)[0])
            marker = tree.find('s:defs/s:marker', NS)
            self.assertEqual(marker.attrib['markerUnits'], 'userSpaceOnUse')
            self.assertEqual(marker.attrib['viewBox'], '0 0 8 8')
            self.assertEqual(float(marker.attrib['markerWidth']), 8)
            self.assertEqual(float(marker.attrib['markerHeight']), 8)
            self.assertEqual(float(marker.attrib['refX']), 8)  # Tip at endpoint, not beyond it.
            nodes = {n.attrib['data-node']: n.attrib for n in tree.findall('s:g', NS)}
            for path in tree.findall('s:path', NS):
                d = path.attrib['d']
                start = re.match(r'M ([0-9.]+),([0-9.]+)', d)
                x, y = map(float, start.groups())
                for direction, number in re.findall(r'([HV]) ([0-9.]+)', d):
                    old_x, old_y = x, y
                    if direction == 'H': x = float(number)
                    else: y = float(number)
                self.assertEqual(direction, 'V', d)
                self.assertEqual(x, old_x, d)
                self.assertGreaterEqual(y-old_y, 14, d)  # Eight-pixel head plus visible shaft.
                target = nodes[path.attrib['data-to']]
                target_top = float(target['data-y'])-float(target['data-height'])/2
                self.assertEqual(target_top-y, 6, d)
            # Each evaluator input has its own clean port, not a duplicated central head.
            inputs = [p.attrib['d'] for p in tree.findall('s:path', NS)
                      if p.attrib['data-to'] == 'evaluate']
            self.assertEqual(len(inputs), 2)
            self.assertNotEqual(inputs[0], inputs[1])
            self.assertTrue(all(' H ' not in d for d in inputs))

    def test_svg_has_text_equivalent_and_no_active_or_external_content(self):
        for name, diagram in self.flows.items():
            for narrow in (False, True):
                tree = ET.fromstring(DIAGRAMS.render(diagram, narrow)[0])
                self.assertEqual(tree.attrib['role'], 'img')
                self.assertEqual(tree.attrib['aria-labelledby'], 'title desc')
                self.assertEqual(tree.find('s:title', NS).text, diagram['title'])
                self.assertEqual(tree.find('s:desc', NS).text, diagram['description'])
                for item in tree.iter():
                    self.assertNotIn(item.tag.rsplit('}', 1)[-1], ('script', 'foreignObject', 'image', 'a'))
                    self.assertFalse(any(k.lower().startswith('on') or 'href' in k for k in item.attrib), name)

    def test_hook_support_is_a_real_labeled_fork_not_a_linear_quiet_default(self):
        for narrow in (False, True):
            tree = ET.fromstring(DIAGRAMS.render(self.flows['codex-beads-hooks'], narrow)[0])
            self.assertIsNotNone(tree.find("s:g[@data-node='support']/s:polygon", NS))
            edges = {(p.attrib['data-from'], p.attrib['data-to']) for p in tree.findall('s:path', NS)}
            self.assertIn(('support', 'quiet'), edges)
            self.assertIn(('support', 'full'), edges)
            self.assertNotIn(('quiet', 'full'), edges)
            self.assertIn(('quiet', 'delivery'), edges)
            self.assertIn(('delivery', 'adopt'), edges)
            self.assertIn(('delivery', 'fallback'), edges)
            self.assertNotIn(('quiet', 'adopt'), edges)
            self.assertFalse(any(a == 'full' for a, b in edges))
        self.assertIn('Unsupported quiet mode is rejected', self.flows['codex-beads-hooks']['description'])

    def test_responsive_figures_have_visible_captions_and_no_legacy_text_diagrams(self):
        for name, diagram in self.flows.items():
            source = DIAGRAMS.figure(name, diagram)
            self.assertIn(f'srcset="./diagrams/{name}-narrow.svg"', source)
            self.assertIn(f'src="./diagrams/{name}.svg"', source)
            self.assertIn('<figcaption>', source)
            page = (ROOT / 'docs' / diagram['page']).read_text()
            self.assertNotIn('workflow-diagram', page)
            self.assertNotIn('class="flow-card"', page)
            self.assertNotIn('<pre aria-label="Task acceptance sequence">', page)

    def test_labels_are_xml_escaped(self):
        diagram = {'kind': 'sequence', 'title': 'A & B', 'description': '<not markup>',
                   'nodes': [{'title': '<script>', 'detail': 'A & B'}]}
        tree = ET.fromstring(DIAGRAMS.render(diagram)[0])
        self.assertEqual(tree.find('s:desc', NS).text, '<not markup>')
        self.assertIsNone(tree.find('.//s:script', NS))
        self.assertIn('<script>', ''.join(tree.itertext()))

    def test_missing_or_duplicate_page_markers_fail_closed(self):
        for marker in ('', '<!-- diagram:sample --><!-- /diagram:sample -->' * 2):
            with self.subTest(marker=marker), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                (root / 'docs/diagrams').mkdir(parents=True)
                (root / 'docs/diagrams/flows.json').write_text(json.dumps({'sample': {
                    'page': 'sample.html', 'title': 'Sample', 'description': 'Example',
                    'kind': 'sequence', 'nodes': [{'title': 'Start', 'detail': 'Here'}]}}))
                (root / 'docs/sample.html').write_text(marker)
                with self.assertRaisesRegex(ValueError, 'exactly one diagram marker'):
                    DIAGRAMS.outputs(root)

    def test_check_detects_stale_asset_without_rewriting_it(self):
        # Main uses the projected files, but check mode never mutates stale output.
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'sample.svg'
            path.write_text('stale')
            with patch.object(DIAGRAMS, 'ROOT', Path(tmp)), patch.object(DIAGRAMS, 'outputs', return_value={path: 'current'}):
                self.assertEqual(DIAGRAMS.main(['--check']), 1)
                self.assertEqual(path.read_text(), 'stale')
                self.assertEqual(DIAGRAMS.main(['--write']), 0)
                self.assertEqual(path.read_text(), 'current')


if __name__ == '__main__':
    unittest.main()
