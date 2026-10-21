from __future__ import annotations
from html.parser import HTMLParser
from pathlib import Path
import sys
import unittest
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from validate_site import SOURCE_BLOB_LINK_ALLOWLIST, SOURCE_LINK_PATTERNS

class Sections(HTMLParser):
    def __init__(self):
        super().__init__(); self.sections = {}; self.current = None; self.hrefs = {}
    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == 'section':
            self.current = attrs.get('id'); self.sections[self.current] = ''; self.hrefs[self.current] = []
        if tag == 'a' and self.current: self.hrefs[self.current].append(attrs.get('href'))
    def handle_endtag(self, tag):
        if tag == 'section': self.current = None
    def handle_data(self, data):
        if self.current: self.sections[self.current] += data

def page(name):
    parsed = Sections(); parsed.feed((ROOT/'docs'/name).read_text()); return parsed

class PositioningSliceTests(unittest.TestCase):
    def test_two_problem_specs_precede_observed_evidence_and_keep_truth_labels(self):
        p = page('use-cases.html'); ids = list(p.sections)
        self.assertLess(ids.index('migration-evaluation'), ids.index('cli-review'))
        self.assertLess(ids.index('retry-decision'), ids.index('cli-review'))
        for section in ('migration-evaluation', 'retry-decision'):
            self.assertIn('Proposed demonstration · not executed', p.sections[section])
            self.assertTrue(any('/blob/8e05' in h for h in p.hrefs[section]))
        self.assertIn('No converter implementation, integrated fixture or agent-led migration result', p.sections['migration-evaluation'])
        self.assertIn('No integrated simulator/client demonstration or live multi-provider review', p.sections['retry-decision'])
        self.assertIn('Observed local work', p.sections['cli-review'])
        self.assertIn('authored proposals', p.sections['conflicting-review'])
    def test_home_proposition_routes_and_source_limits_are_connected(self):
        p = page('index.html'); readme = (ROOT/'README.md').read_text()
        self.assertIn('Delegate the work.', p.sections['start'])
        self.assertIn('Keep the definition of done.', p.sections['start'])
        self.assertIn('Delegate the work. Keep the definition of done.', readme)
        self.assertIn('./workflows.html#operator', p.hrefs['start'])
        self.assertIn('./install.html', p.hrefs['start'])
        self.assertIn('./get-started.html', p.hrefs['start'])
        self.assertIn('when invoked', p.sections['keeps'])
        self.assertIn('not detect every change in intent', p.sections['keeps'])
        self.assertIn('earlier tutorial run', p.sections['continuity'])
    def test_expert_route_delivers_each_promised_workflow(self):
        p = page('workflows.html')
        for href in ('#contract', '#optional-lanes', '#validate-handoff', '#failure',
                     './use-cases.html#migration-evaluation', './use-cases.html#retry-decision'):
            self.assertIn(href, p.hrefs['operator'])
        for target in ('contract', 'optional-lanes', 'validate-handoff', 'failure'):
            self.assertTrue(p.sections[target].strip())
    def test_evaluation_action_preserves_contract_and_invokes_check_before_work(self):
        text=page('workflows.html').sections['contract']
        for phrase in ('fixed case set', 'scoring and selection rule', 'before candidate work',
                       'A blocked check stops candidate work', 'actually invoked'):
            self.assertIn(phrase, text)
        self.assertIn('references/frozen-protocol-lock.md', ' '.join(page('workflows.html').hrefs['contract']))
    def test_working_launcher_and_public_maintainer_example_keep_correct_scope(self):
        text=page('continue-project.html').sections['continue']
        self.assertIn('same working launch command as the first session', text)
        self.assertIn('explicit named-profile alternative', text)
        self.assertNotIn('remains subject to owner review', page('use-cases.html').sections['docs-workflow'])

    def test_home_separates_component_recorded_and_unexecuted_evidence(self):
        home = page('index.html'); ids = list(home.sections)
        self.assertLess(ids.index('multi-model'), ids.index('continuity'))
        self.assertLess(ids.index('continuity'), ids.index('walk'))
        component = home.sections['multi-model']
        for phrase in ('Component tests', 'deliberately written responses', 'deliberately written claims',
                       'not a single live endpoint run', 'explicitly invoked Python API',
                       'adding models does not guarantee better answers'):
            self.assertIn(phrase, component)
        designs = home.sections['walk']
        self.assertIn('configuration converters against unchanged requirements', designs)
        self.assertIn('retries that do not create duplicate jobs', designs)
        self.assertIn('Neither has been run end to end', designs)
        for href in ('./use-cases.html#migration-evaluation', './use-cases.html#retry-decision'):
            self.assertIn(href, home.hrefs['walk'])
        for href in ('./use-cases.html#cli-review', './use-cases.html#multi-session'):
            self.assertIn(href, home.hrefs['continuity'])
        self.assertNotIn('A green check', designs)
        self.assertNotIn('lost-acknowledgement counterexample', designs)

    def test_new_source_allowlist_is_exact_not_repo_wide(self):
        base='https://github.com/gprocunier/complex-work-orchestration/blob/8e05b6cce4c4cf89325112f019fdd8c69a28ecff/'
        self.assertIn(base+'scripts/cwo_core/frozen_protocol.py', SOURCE_BLOB_LINK_ALLOWLIST)
        unapproved=base+'not-reviewed/private.md'
        self.assertFalse(any(unapproved == p or unapproved.startswith(p+'#') for p in SOURCE_LINK_PATTERNS))
    def test_purpose_flow_has_separate_accepted_and_held_branches(self):
        ns={'s':'http://www.w3.org/2000/svg'}
        for suffix in ('', '-narrow'):
            tree = ET.fromstring((ROOT/f'docs/diagrams/purpose-preserving{suffix}.svg').read_text())
            edges={(p.attrib['data-from'],p.attrib['data-to']) for p in tree.findall('s:path',ns)}
            self.assertIn(('decision','accepted'), edges)
            self.assertIn(('decision','held'), edges)
            self.assertNotIn(('held','accepted'), edges)
            self.assertIn('not an observed concurrent execution trace', tree.find('s:desc',ns).text)

if __name__ == '__main__': unittest.main()
