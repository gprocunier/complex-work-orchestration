from __future__ import annotations

import json
from pathlib import Path
import re
import sys
import unittest
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'scripts'))
import generate_diagrams as diagrams

NS = {'s': 'http://www.w3.org/2000/svg'}


class DurableMemoryDocumentationTests(unittest.TestCase):
    def test_memory_is_the_third_layer_with_plain_why_how_and_limits(self):
        home = (ROOT/'docs/index.html').read_text()
        ids = [home.index(f'id="{name}"') for name in ('ecosystem','supervised-execution','durable-memory','multi-model')]
        self.assertEqual(ids, sorted(ids))
        memory = re.search(r'<section id="durable-memory".*?</section>', home, re.S)[0]
        visible_memory = ' '.join(re.sub(r'<[^>]+>', ' ', memory).split())
        beads_link = '<a href="https://beads.gascity.com/">Beads</a>'
        self.assertIn(beads_link, memory)
        self.assertNotIn('Beads', memory.split(beads_link, 1)[0])
        for phrase in ('compaction', 'summarizes earlier messages',
                       'Beads is the task database CWO uses for durable project memory.',
                       'tasks and dependencies', 'Code, tests and saved reports',
                       'checks the current files and remaining limits',
                       'not perfect model recall', 'Missing or stale records'):
            self.assertIn(phrase, visible_memory)
        self.assertIn('href="./beads-memory.html#compaction"', memory)
        readme = (ROOT/'README.md').read_text()
        self.assertLess(readme.index('supervised-delegation.svg'),readme.index('durable-recovery.svg'))
        self.assertIn('Beads is the task database CWO uses for durable project memory.',readme)
        self.assertIn('Local records are not remote backup',readme)
        self.assertNotIn('never forget', memory.lower())

    def test_guide_distinguishes_recording_recovery_verification_and_hook_support(self):
        guide = (ROOT/'docs/beads-memory.html').read_text()
        for fragment in ('compaction', 'what-to-save', 'hooks'):
            self.assertIn(f'href="#{fragment}"',guide)
            self.assertIn(f'id="{fragment}"',guide)
        for phrase in ('Record as work proceeds', 'Read the relevant project record',
                       'Compare the record with the current project', 'A stopped attempt remains stopped',
                       'remaining budget and attempt limits',
                       'cannot reconstruct decisions that were never recorded',
                       'not a new observed compaction trial',
                       'When configured and supported', 'not proof that every host',
                       'Hooks do not manufacture missing decisions',
                       'not remote backup', 'See the compact two-session view'):
            self.assertIn(phrase,guide)
        hooks = (ROOT/'scripts/configure_codex_beads_hooks.py').read_text()
        for event in ('SessionStart','UserPromptSubmit','PreCompact','PostCompact'):
            self.assertIn(f'"{event}"',hooks)
        prompt = (ROOT/'prompts/cwo-sol-operator-e.md').read_text()
        self.assertIn('After interruption or compaction,',prompt)
        self.assertIn('reconcile the checkout, tracker, accepted evidence, remaining scope, and budget',prompt)

    def test_recovery_graph_keeps_both_stores_and_requires_verification_before_continuation(self):
        config = json.loads((ROOT/'docs/diagrams/flows.json').read_text())['durable-recovery']
        expected = {('work','beads'),('work','files'),('beads','recover'),('files','recover'),
                    ('recover','verify'),('verify','continue')}
        for narrow in (False,True):
            tree = ET.fromstring(diagrams.render(config,narrow)[0])
            self.assertEqual(tree.attrib['font-family'], 'DejaVu Sans, sans-serif')
            nodes = {n.attrib['data-node']: ''.join(n.itertext()) for n in tree.findall('s:g',NS)}
            edges = {(p.attrib['data-from'],p.attrib['data-to']) for p in tree.findall('s:path',NS)}
            self.assertEqual(edges, expected)
            self.assertIn('Beads task database',nodes['beads'])
            self.assertIn('Code + tests + reports',nodes['files'])
            self.assertIn('After compaction / restart',nodes['recover'])
            self.assertIn('rerun checks',nodes['verify'])
            self.assertIn('Or record what blocks it',nodes['continue'])
            marker=tree.find('s:defs/s:marker',NS)
            self.assertEqual(marker.attrib['markerUnits'],'userSpaceOnUse')
            self.assertEqual(marker.attrib['markerWidth'],'8')

    def test_arrowheads_have_clearance_visible_shafts_and_separate_recovery_ports(self):
        config=json.loads((ROOT/'docs/diagrams/flows.json').read_text())['durable-recovery']
        for narrow in (False,True):
            tree=ET.fromstring(diagrams.render(config,narrow)[0])
            boxes={}
            for n in tree.findall('s:g',NS):
                a=n.attrib;x,y,w,h=[float(a['data-'+k]) for k in ('x','y','width','height')]
                boxes[a['data-node']]=(x-w/2,y-h/2,x+w/2,y+h/2)
            ports=[]
            for path in tree.findall('s:path',NS):
                a=path.attrib;d=a['d'];x,y=map(float,re.match(r'M ([0-9.]+),([0-9.]+)',d).groups());segments=[]
                for axis,number in re.findall(r'([HV]) ([0-9.]+)',d):
                    old=(x,y)
                    if axis=='H':x=float(number)
                    else:y=float(number)
                    segments.append((old,(x,y)))
                (px,py),_=segments[-1]
                self.assertGreaterEqual(abs(x-px)+abs(y-py),14,d)
                l,t,r,b=boxes[a['data-to']]
                self.assertTrue((l-6==x or r+6==x) and t<=y<=b or (t-6==y or b+6==y) and l<=x<=r,d)
                if a['data-to']=='recover':ports.append((x,y))
                for key,(l,t,r,b) in boxes.items():
                    if key in (a['data-from'],a['data-to']):continue
                    for (sx,sy),(ex,ey) in segments:
                        intersects=(sx==ex and l-6<sx<r+6 and max(sy,ey)>t-6 and min(sy,ey)<b+6 or
                                    sy==ey and t-6<sy<b+6 and max(sx,ex)>l-6 and min(sx,ex)<r+6)
                        self.assertFalse(intersects,(d,key))
            self.assertEqual(len(set(ports)),2)

    def test_both_pages_use_the_same_generated_responsive_figure(self):
        config=json.loads((ROOT/'docs/diagrams/flows.json').read_text())['durable-recovery']
        self.assertEqual(diagrams.figure_pages(config),['index.html','beads-memory.html'])
        expected=diagrams.figure('durable-recovery',config)
        for page in diagrams.figure_pages(config):
            source=(ROOT/'docs'/page).read_text()
            self.assertEqual(source.count('<!-- diagram:durable-recovery -->'),1)
            self.assertIn(expected,source)
        for additional in ('beads-memory.html',[None],['index.html'],['../private.html']):
            with self.subTest(additional=additional),self.assertRaises(ValueError):
                diagrams.figure_pages({**config,'additional_pages':additional})


if __name__ == '__main__':
    unittest.main()
