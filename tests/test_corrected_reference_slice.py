from __future__ import annotations
import json
import re
from html import unescape
from html.parser import HTMLParser
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import generate_site
from validate_site import FragmentContent
from site_code import without_token_spans

class Page(HTMLParser):
    def __init__(self):
        super().__init__(); self.in_prompt = False; self.prompts = []; self.ids = []; self.pre_attrs = []
    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if attrs.get('id'): self.ids.append(attrs['id'])
        if tag == 'pre': self.pre_attrs.append(attrs)
        if tag == 'pre' and 'prompt' in attrs.get('class', '').split():
            self.in_prompt = True; self.prompts.append('')
    def handle_data(self, data):
        if self.in_prompt: self.prompts[-1] += data
    def handle_endtag(self, tag):
        if tag == 'pre': self.in_prompt = False

class CorrectedReferenceSliceTests(unittest.TestCase):
    def source(self, file): return without_token_spans((ROOT / 'docs' / file).read_text())
    def test_case_is_canonical_in_examples_not_a_homepage_success_blob(self):
        home = self.source('index.html')
        case = self.source('use-cases.html')
        guides = self.source('workflows.html')
        self.assertNotIn('&quot;errors&quot;: []', home)
        self.assertIn('./use-cases.html#cli-review', home)
        self.assertIn('id="cli-review"', case)
        self.assertIn('café.md', case)
        self.assertIn('fresh-agent continuation of this case has not yet been observed', case)
        self.assertIn('id="case-record"', guides)
        self.assertIn('./use-cases.html#cli-review', guides)
        self.assertLess(guides.index('Start with the task you need'), guides.index('id="case-record"'))
    def test_tutorial_specifications_keep_fresh_session_and_acceptance_boundaries(self):
        p = Page(); p.feed(self.source('first-project.html'))
        prompt = '\n'.join(p.prompts)
        for text in ['Fix only errors(config)', 'Reject boolean ports', 'Leave the CLI unimplemented',
                     'CLI task blocked by it', 'only after its checks pass', 'record both IDs',
                     'No delegation', 'tool-initiated external network requests', 'Stop after this phase']:
            self.assertIn(text, prompt)
        first = self.source('first-project.html')
        self.assertIn('bd show VALIDATOR_TASK_ID --json', first)
        self.assertIn('bd show CLI_TASK_ID --json', first)
        continuation = self.source('continue-project.html')
        self.assertIn('preserve the accepted validator task and its dependency', continuation)
        self.assertNotIn('Same boundary as session one', continuation)
        self.assertIn('Restoring files does not reset task history', self.source('tutorial-recovery.html'))
    def test_advanced_pilot_and_examples_have_one_article_grammar(self):
        for file in ['native-supervision.html', 'use-cases.html']:
            source = self.source(file)
            self.assertIn('class="reading-layout"', source)
            self.assertLess(source.index('class="page-intro"'), source.index('<details class="contents" open>'))
            self.assertIn('aria-labelledby="page-title"', source)
            self.assertIn('footer-grid', source)
        self.assertEqual(generate_site.PAGE_PARENTS['native-supervision.html'], 'workflows.html')
    def test_reference_aliases_deliver_their_promised_details(self):
        for anchor, required in [('durable-memory', 'close_bead_with_summary.py'), ('experts', 'policy/executor-registry.yaml')]:
            p = FragmentContent(anchor); p.feed(self.source('reference.html'))
            self.assertTrue(p.found)
            self.assertTrue(any(required in href for href in p.hrefs))
        self.assertIn('./use-cases.html#conflicting-review', self.source('external-contracting.html'))
    def test_slice_menu_progresses_without_hiding_or_losing_destinations(self):
        for file in generate_site.PAGES:
            source = self.source(file)
            self.assertIn('<details class="site-menu" open>', source)
            for href, _ in generate_site.PRIMARY_NAV:
                self.assertIn('href="' + href + '"', source)
            self.assertIn('<script src="./site.js" defer>', source)
            parsed = Page(); parsed.feed(source)
            for attrs in parsed.pre_attrs:
                self.assertEqual(attrs.get('tabindex'), '0', file)
                self.assertEqual(attrs.get('role'), 'region', file)
                self.assertTrue(attrs.get('aria-label'), file)
    def test_reviewed_task_order_terminal_transition_and_return_link(self):
        source = self.source('workflows.html')
        positions = [source.index('<section id="' + item + '"') for item in
                     ['operator', 'contract', 'optional-lanes', 'beads-graph', 'validate-handoff', 'failure', 'cost', 'case-record']]
        self.assertEqual(positions, sorted(positions))
        continuation = self.source('continue-project.html')
        end = continuation.index('</code></pre>', continuation.index('<pre class="prompt '))
        terminal = continuation.index('<p class="input-label">Terminal</p>', end)
        self.assertIn('second terminal', continuation[end:terminal])
        self.assertIn('href="./workflows.html#operator">Return to operating tasks', self.source('beads-memory.html'))
        native = self.source('native-supervision.html')
        for text in ['The lead prepares', 'fit check without tool access', 'scoped assignment', 'register monitoring before sending']:
            self.assertIn(text, native)

    def test_ids_are_unique_after_case_relocation(self):
        for file in generate_site.PAGES:
            p = Page(); p.feed(self.source(file))
            self.assertEqual(len(p.ids), len(set(p.ids)), file)

if __name__ == '__main__': unittest.main()
