"""Contracts for the eight guide illustrations and their accessible placement."""
from __future__ import annotations

from html import unescape
import json
from pathlib import Path
import re
import sys
import unittest
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import generate_diagrams as diagrams
from guide_diagrams import GUIDE_KINDS

NS = {'s':'http://www.w3.org/2000/svg'}
CANONICAL = {
    'sharing-boundaries':('explanation.html','privacy'),
    'scoped-work-graph':('native-supervision.html','recovery'),
    'source-count-groups':('zero-trust-consensus.html','domains'),
    'local-workers':('local-workers.html','invoke-codex'),
    'malpractice-sabotage':('malpractice-sabotage.html','gate'),
    'model-synthesis':('model-synthesis.html','pipeline'),
    'codex-beads-hooks':('codex-beads-hooks.html','helper'),
    'contractor-demo':('contractor-demo.html','flow'),
}
REUSE = [('workflows.html','beads-graph','native-supervision.html','recovery'),
         ('workflows.html','failure','native-supervision.html','recovery'),
         ('workflows.html','sharing','explanation.html','privacy'),
         ('explanation.html','diversity','zero-trust-consensus.html','domains'),
         ('native-supervision.html','supervision','index.html','supervised-execution'),
         ('external-contracting.html','multi-expert-review','model-synthesis.html','pipeline')]


def section(page, key):
    return re.search(r'<section id="'+key+r'"[^>]*>.*?</section>', page, re.S)[0]


def points(path):
    first = re.match(r'M ([0-9.]+),([0-9.]+)', path)
    if not first:
        raise AssertionError(path)
    x,y = map(float,first.groups()); result=[(x,y)]
    for direction,value in re.findall(r'([HV]) ([0-9.]+)',path):
        if direction=='H': x=float(value)
        else: y=float(value)
        result.append((x,y))
    return result


class GuideDiagramTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.flows=json.loads((ROOT/'docs/diagrams/flows.json').read_text())

    def trees(self, slug):
        return [ET.fromstring(diagrams.render(self.flows[slug],n)[0]) for n in (False,True)]

    def edges(self, tree):
        return {(e.attrib['data-from'],e.attrib['data-to']) for e in tree.findall('s:path',NS)}

    def words(self, tree, key):
        return ' '.join(tree.find(f"s:g[@data-node='{key}']",NS).itertext())

    def test_exact_scope_canonical_placement_and_selectable_equivalents(self):
        self.assertEqual({s for s,d in self.flows.items() if d['kind'] in GUIDE_KINDS},set(CANONICAL))
        for slug,(page,key) in CANONICAL.items():
            d=self.flows[slug]; block=section((ROOT/'docs'/page).read_text(),key)
            self.assertEqual((d['page'],d['section']),(page,key))
            self.assertEqual(block.count(f'<!-- diagram:{slug} -->'),1)
            self.assertIn('class="memory-flow guide-flow"',block)
            self.assertIn('media="(max-width: 75rem)"',block)
            self.assertIn('<summary>Read the diagram as text</summary>',block)
            self.assertNotIn('<ol class="sr-only">',block)
            for step in d['text_equivalent']:
                self.assertIn(step,unescape(block))
            self.assertIn(d['description'],unescape(block))
        css=(ROOT/'docs/styles.css').read_text()
        self.assertRegex(css,r'@media \(max-width: 75rem\) \{\s*\.guide-flow picture, \.guide-flow img \{ max-width: 22.5rem; \}')

    def test_six_descriptive_reuse_links_resolve_without_duplicate_diagrams(self):
        for page,key,target,anchor in REUSE:
            block=section((ROOT/'docs'/page).read_text(),key)
            self.assertIn(f'href="./{target}#{anchor}"',block)
            self.assertNotIn('<figure',block)
            self.assertIn(f'id="{anchor}"',(ROOT/'docs'/target).read_text())

    def test_routes_have_fixed_heads_clear_targets_and_no_unrelated_card_crossings(self):
        for slug in CANONICAL:
            for tree in self.trees(slug):
                marker=tree.find('s:defs/s:marker',NS)
                self.assertEqual(marker.attrib['markerUnits'],'userSpaceOnUse')
                self.assertEqual(marker.attrib['markerWidth'],'8')
                boxes={}
                for node in tree.findall('s:g',NS):
                    x,y,w,h=(float(node.attrib['data-'+k]) for k in ('x','y','width','height'))
                    boxes[node.attrib['data-node']]=(x-w/2,y-h/2,x+w/2,y+h/2)
                    labels=node.findall('s:text',NS)
                    for label in labels:
                        # Numeric vertical padding, not merely a character-count fit.
                        self.assertGreaterEqual(float(label.attrib['y'])-float(label.attrib['font-size'])/2,y-h/2+16,(slug,label.text))
                        self.assertLessEqual(float(label.attrib['y'])+float(label.attrib['font-size'])/2,y+h/2-16,(slug,label.text))
                for edge in tree.findall('s:path',NS):
                    pts=points(edge.attrib['d']); end=pts[-1]
                    self.assertGreaterEqual(abs(end[0]-pts[-2][0])+abs(end[1]-pts[-2][1]),14,(slug,edge.attrib))
                    l,t,r,b=boxes[edge.attrib['data-to']]
                    gap=max(l-end[0],0,end[0]-r)+max(t-end[1],0,end[1]-b)
                    self.assertEqual(gap,6,(slug,edge.attrib))
                    for a,b in zip(pts,pts[1:]):
                        for key,(l,t,r,bt) in boxes.items():
                            if key in {edge.attrib['data-from'],edge.attrib['data-to']}:continue
                            crosses=(a[0]==b[0] and l-4<=a[0]<=r+4 and max(min(a[1],b[1]),t-4)<=min(max(a[1],b[1]),bt+4)) or (a[1]==b[1] and t-4<=a[1]<=bt+4 and max(min(a[0],b[0]),l-4)<=min(max(a[0],b[0]),r+4))
                            self.assertFalse(crosses,(slug,key,edge.attrib['d']))

    def test_unrelated_connectors_do_not_form_false_junctions(self):
        for slug in CANONICAL:
            for tree in self.trees(slug):
                edges=tree.findall('s:path',NS)
                for i,first in enumerate(edges):
                    for second in edges[i+1:]:
                        # A deliberate fork or shared target may share a rail.
                        if first.attrib['data-from']==second.attrib['data-from'] or first.attrib['data-to']==second.attrib['data-to']:
                            continue
                        fp,sp=points(first.attrib['d']),points(second.attrib['d'])
                        for a,b in zip(fp,fp[1:]):
                            for c,d in zip(sp,sp[1:]):
                                if a[0]==b[0] and c[1]==d[1]:
                                    cross=min(a[1],b[1])<=c[1]<=max(a[1],b[1]) and min(c[0],d[0])<=a[0]<=max(c[0],d[0])
                                elif a[1]==b[1] and c[0]==d[0]:
                                    cross=min(c[1],d[1])<=a[1]<=max(c[1],d[1]) and min(a[0],b[0])<=c[0]<=max(a[0],b[0])
                                else:
                                    cross=False
                                self.assertFalse(cross,(slug,first.attrib,second.attrib))

    def test_local_call_precedes_its_records_and_keeps_original_evaluator_inputs(self):
        for tree in self.trees('local-workers'):
            edges=self.edges(tree)
            self.assertTrue({('prepare','checks'),('checks','call'),('call','answer'),('answer','mutation'),('mutation','normalize'),('normalize','evaluate'),('evaluate','lead')}<=edges)
            self.assertEqual({a for a,b in edges if b=='stop'},{'checks','answer','mutation'})
            self.assertIn('No model call',self.words(tree,'prepare'))
            self.assertIn('Raw answer + dispatch JSON',self.words(tree,'evaluate'))
            self.assertIn('Matching mutation report',self.words(tree,'evaluate'))
        self.assertIn('normalized bundle is not a substitute',' '.join(self.flows['local-workers']['text_equivalent']))

    def test_evidence_disposition_and_procedural_hold_are_orthogonal(self):
        for tree in self.trees('malpractice-sabotage'):
            edges=self.edges(tree)
            self.assertTrue({('return','evidence'),('return','review'),('evidence','both'),('review','both'),('evidence','isolated')}<=edges)
            self.assertNotIn(('evidence','review'),edges)
            self.assertIn('Usable does not mean ready',self.words(tree,'both'))
            outgoing=[e for e in tree.findall('s:path',NS) if e.attrib['data-from']=='both']
            self.assertEqual(points(outgoing[0].attrib['d'])[0][0],float(tree.find("s:g[@data-node='both']",NS).attrib['data-x']))
        self.assertIn('Honest disclosure',self.flows['malpractice-sabotage']['description'])

    def test_separate_reviewer_assignments_and_evaluations_merge_only_at_comparison(self):
        for tree in self.trees('model-synthesis'):
            edges=self.edges(tree)
            self.assertTrue({('plan','review-a'),('plan','review-b'),('review-a','evaluated-a'),('review-b','evaluated-b'),('evaluated-a','compare'),('evaluated-b','compare'),('compare','decision')}<=edges)
            self.assertNotIn(('review-a','review-b'),edges)
            self.assertIn('Keep excluded inputs apart',self.words(tree,'compare'))
        page=(ROOT/'docs/model-synthesis.html').read_text()
        self.assertNotIn('authored lost-reply exercise',page)
        self.assertIn('scripted retry-and-effect-count exercise',page)

    def test_scoped_failure_keeps_independent_work_separate_and_replacement_fresh(self):
        for tree in self.trees('scoped-work-graph'):
            edges=self.edges(tree)
            independent={'independent','checks','continue'}
            self.assertFalse(any((a in independent)!=(b in independent) for a,b in edges))
            self.assertIn(('accepted','dependent'),edges)
            self.assertFalse(any(b=='ended' for a,b in edges))
            self.assertIn('fresh allowance',self.words(tree,'replacement'))
            self.assertIn('UNKNOWN',self.words(tree,'inspect'))
        self.assertIn('not an observed incident',self.flows['scoped-work-graph']['description'])

    def test_sharing_recipients_are_siblings_not_provider_subcomponents(self):
        for tree in self.trees('sharing-boundaries'):
            edges=self.edges(tree)
            self.assertTrue({('client','provider'),('client','outside'),('client','local')}<=edges)
            self.assertFalse(any(a=='provider' for a,b in edges))
            self.assertIn('Extra opt-in required',self.words(tree,'outside'))
            self.assertIn('Only approved material',self.words(tree,'outside'))
            self.assertIn('Not an offline guarantee',self.words(tree,'local'))
        self.assertIn('not proof that the cloud session is offline',self.flows['sharing-boundaries']['description'])

    def test_source_counting_excludes_ineligible_records_before_explicit_comparison(self):
        for tree in self.trees('source-count-groups'):
            edges=self.edges(tree)
            self.assertTrue({('cloud','count'),('local','count'),('count','compare'),('input','excluded')}<=edges)
            self.assertFalse(any(a=='excluded' for a,b in edges))
            self.assertIn('one group',self.words(tree,'cloud'))
            self.assertIn('one group',self.words(tree,'local'))
            self.assertIn('Default minimum: two',self.words(tree,'count'))
        self.assertIn('hypothetical eligible records',' '.join(self.flows['source-count-groups']['text_equivalent']))

    def test_hooks_require_observed_delivery_not_just_supported_configuration(self):
        for tree in self.trees('codex-beads-hooks'):
            edges=self.edges(tree)
            self.assertTrue({('support','quiet'),('support','full'),('quiet','delivery'),('delivery','adopt'),('delivery','fallback')}<=edges)
            self.assertNotIn(('quiet','adopt'),edges)
            self.assertIn('Character count is not proof',self.words(tree,'delivery'))
            self.assertIn('If proof is missing or fails',self.words(tree,'fallback'))
        self.assertIn('Full-context configuration alone',' '.join(self.flows['codex-beads-hooks']['text_equivalent']))

    def test_historical_ownership_has_two_named_branches_and_codex_validation(self):
        for tree in self.trees('contractor-demo'):
            edges=self.edges(tree)
            self.assertTrue({('prepare','antigravity'),('prepare','claude'),('antigravity','integrate'),('claude','integrate'),('integrate','validate'),('validate','publication')}<=edges)
            self.assertIn('documentation',self.words(tree,'antigravity'))
            self.assertIn('Pages',self.words(tree,'claude'))
            self.assertNotIn('merges',self.words(tree,'integrate'))
            self.assertIn('Merge + publication',self.words(tree,'publication'))
            self.assertIn('No new permission implied',self.words(tree,'publication'))
        self.assertIn('not evidence of concurrent execution',self.flows['contractor-demo']['description'])


if __name__=='__main__':
    unittest.main()
