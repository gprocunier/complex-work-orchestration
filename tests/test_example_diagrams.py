"""Semantic and geometric contracts for the five explanatory example figures."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import re
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import generate_diagrams as diagrams
from example_diagrams import EXAMPLE_KINDS

NS = {'s': 'http://www.w3.org/2000/svg'}
SECTIONS = {'example-retry':'conflicting-review', 'example-recovery':'multi-session',
            'example-migration':'migration-evaluation', 'example-encoding':'cli-review',
            'example-restore':'lab-operations'}


def load_fixture():
    spec = importlib.util.spec_from_file_location('worked_example_diagram_fixture', ROOT / 'examples/worked-evidence/run_examples.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def points(d):
    start = re.match(r'M ([0-9.]+),([0-9.]+)', d)
    if not start:
        raise AssertionError(d)
    x,y = map(float,start.groups())
    result=[(x,y)]
    for direction,number in re.findall(r'([HV]) ([0-9.]+)',d):
        if direction=='H': x=float(number)
        else: y=float(number)
        result.append((x,y))
    return result


class ExampleDiagramTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.flows=json.loads((ROOT/'docs/diagrams/flows.json').read_text())
        cls.page=(ROOT/'docs/use-cases.html').read_text()

    def trees(self,slug):
        return [ET.fromstring(diagrams.render(self.flows[slug],narrow)[0]) for narrow in (False,True)]

    def node_text(self,tree,key):
        return ''.join(tree.find(f"s:g[@data-node='{key}']",NS).itertext())

    def test_exactly_five_canonical_figures_with_qualified_retry_reuse(self):
        self.assertEqual({k for k,v in self.flows.items() if v['kind'] in EXAMPLE_KINDS},set(SECTIONS))
        for slug,section in SECTIONS.items():
            block=re.search(r'<section id="'+section+r'".*?</section>',self.page,re.S)[0]
            self.assertEqual(block.count('<!-- diagram:'+slug+' -->'),1)
            self.assertEqual(self.flows[slug]['section'],section)
            self.assertIn('media="(max-width: 75rem)"',block)
            self.assertIn('<figcaption>',block)
            self.assertIn(f'<figure id="{slug}"',block)
        retry=re.search(r'<section id="retry-decision".*?</section>',self.page,re.S)[0]
        self.assertNotIn('<figure',retry)
        self.assertIn('href="#conflicting-review"',retry)
        self.assertIn('does not simulate a lost reply',retry)
        planning=re.search(r'<section id="planning-example".*?</section>',self.page,re.S)[0]
        self.assertNotIn('<figure',planning)
        self.assertIn('href="#docs-workflow"',self.page)
        css=(ROOT/'docs/styles.css').read_text()
        self.assertRegex(css,r'@media \(max-width: 75rem\) \{\s*\.example-flow picture, \.example-flow img \{ max-width: 22.5rem; \}')
        self.assertTrue(all(self.flows[slug]['figure_class']=='memory-flow example-flow' for slug in SECTIONS))

    def test_retry_trace_counts_match_executable_fixture(self):
        fixture=load_fixture()
        cases=[('post-replay','POST',True),('post-stop','POST',False),('get','GET',False)]
        for tree in self.trees('example-retry'):
            for key,method,replay in cases:
                observed=fixture.retry_observation(method,replay)
                result=self.node_text(tree,key+'-result')
                self.assertRegex(result,rf'{observed["attempts"]} attempts?')
                self.assertRegex(result,rf'{observed["effects"]} (?:write )?effects?')
            self.assertIn('ambiguous',self.node_text(tree,'post-stop-result'))
        description=self.flows['example-retry']['description']
        self.assertIn('before the stop decision',description)
        self.assertIn('no live service or reviewer calls',description)

    def test_recovery_has_two_stores_and_acceptance_before_dependent_cli(self):
        for tree in self.trees('example-recovery'):
            self.assertIn('Booleans are not ports',self.node_text(tree,'session-one'))
            self.assertIn('list-of-errors',self.node_text(tree,'session-one'))
            edges={(p.attrib['data-from'],p.attrib['data-to']) for p in tree.findall('s:path',NS)}
            self.assertTrue({('session-one','beads'),('session-one','files'),('beads','session-two'),
                             ('files','session-two'),('session-two','acceptance'),
                             ('acceptance','cli'),('acceptance','investigate')}<=edges)
            self.assertNotIn(('session-two','cli'),edges)
            self.assertIn('Do not start the CLI',self.node_text(tree,'investigate'))
        desc=self.flows['example-recovery']['description']
        self.assertIn('Recorded earlier two-session',desc)
        self.assertIn('has not had a new equivalent',desc)
        self.assertIn('no automatic memory transfer',desc)

    def test_migration_checks_unchanged_baseline_and_allows_no_winner(self):
        for tree in self.trees('example-migration'):
            self.assertIn('Invoke the check',self.node_text(tree,'check'))
            self.assertIn('Keep the saved baseline',self.node_text(tree,'repair'))
            edges={(p.attrib['data-from'],p.attrib['data-to']) for p in tree.findall('s:path',NS)}
            self.assertTrue({('baseline','check'),('repair','check'),('check','converter-a'),
                             ('check','converter-b'),('check','separate')}<=edges)
            self.assertFalse(any(a=='separate' for a,b in edges))
            self.assertIn('Neither may qualify',self.node_text(tree,'report'))
            self.assertIn('Keep its original evidence',self.node_text(tree,'separate'))
        self.assertIn('not executed',self.flows['example-migration']['description'])
        self.assertIn('Existing component regressions are not',self.flows['example-migration']['description'])

    def test_encoding_contrasts_stream_with_process_and_retains_filename(self):
        for tree in self.trees('example-encoding'):
            self.assertIn('No ASCII encoder tested',self.node_text(tree,'memory'))
            self.assertIn('UnicodeEncodeError',self.node_text(tree,'process'))
            self.assertIn(r'\u00e9',self.node_text(tree,'escape'))
            self.assertIn('café.md preserved',self.node_text(tree,'consumer'))
            self.assertIn('Force ASCII stdout',self.node_text(tree,'test'))
            edges={(p.attrib['data-from'],p.attrib['data-to']) for p in tree.findall('s:path',NS)}
            self.assertIn(('test','consumer'),edges)
            self.assertNotIn(('memory','process'),edges)
        self.assertIn('historical finding',self.flows['example-encoding']['description'])

    def test_restoration_matches_fixture_values_without_claiming_durable_backup(self):
        with tempfile.TemporaryDirectory() as tmp:
            observed=load_fixture().lab_example(Path(tmp))
            self.assertEqual(json.loads((Path(tmp)/'active.json').read_text())['port'],observed['restored_port'])
        for tree in self.trees('example-restore'):
            self.assertIn(str(observed['staged_port']),self.node_text(tree,'stage'))
            self.assertIn(str(observed['restored_port']),self.node_text(tree,'verify'))
            self.assertIn('Not a backup file',self.node_text(tree,'previous'))
            self.assertIn('Parsed JSON equals',self.node_text(tree,'verify'))
            self.assertIn('sets False',self.node_text(tree,'health'))
        self.assertIn('does not establish byte-exact recovery',self.flows['example-restore']['description'])
        self.assertIn('does not assert byte-for-byte restoration',self.page)

    def test_connector_clearance_fixed_heads_and_no_unrelated_card_crossings(self):
        for slug in SECTIONS:
            for tree in self.trees(slug):
                marker=tree.find('s:defs/s:marker',NS)
                self.assertEqual(marker.attrib['markerUnits'],'userSpaceOnUse')
                self.assertEqual(marker.attrib['markerWidth'],'8')
                boxes={}
                for g in tree.findall('s:g',NS):
                    x,y,w,h=(float(g.attrib['data-'+k]) for k in ('x','y','width','height'))
                    boxes[g.attrib['data-node']]=(x-w/2,y-h/2,x+w/2,y+h/2)
                for edge in tree.findall('s:path',NS):
                    pts=points(edge.attrib['d'])
                    self.assertGreaterEqual(abs(pts[-1][0]-pts[-2][0])+abs(pts[-1][1]-pts[-2][1]),14,(slug,edge.attrib))
                    for a,b in zip(pts,pts[1:]):
                        for key,(l,t,r,bt) in boxes.items():
                            if key in {edge.attrib['data-from'],edge.attrib['data-to']}: continue
                            crosses=(a[0]==b[0] and l<=a[0]<=r and max(min(a[1],b[1]),t)<=min(max(a[1],b[1]),bt)) or (a[1]==b[1] and t<=a[1]<=bt and max(min(a[0],b[0]),l)<=min(max(a[0],b[0]),r))
                            self.assertFalse(crosses,(slug,key,edge.attrib['d']))


if __name__=='__main__':
    unittest.main()
