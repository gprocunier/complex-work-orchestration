"""Known reader regressions: orphaned coaching and obsolete browser setup.

These checks preserve concrete explanations; they do not score writing quality
or claim that the illustrative reviewers actually ran.
"""
from html.parser import HTMLParser
from pathlib import Path
import json
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from site_code import CodeBlocks
from validate_public_copy import retired_browser_guidance_errors


class MainText(HTMLParser):
    def __init__(self, source):
        super().__init__()
        self.inside = False
        self.parts, self.links = [], []
        self.feed(source)

    def handle_starttag(self, tag, attrs):
        if tag == 'main':
            self.inside = True
        if self.inside and tag == 'a':
            self.links.append(dict(attrs).get('href'))

    def handle_endtag(self, tag):
        if tag == 'main':
            self.inside = False

    def handle_data(self, data):
        if self.inside:
            self.parts.append(data)

    @property
    def text(self):
        return ' '.join(''.join(self.parts).split())


def source(name):
    return (ROOT / 'docs' / name).read_text()


class PlanningNarrativeTests(unittest.TestCase):
    def planning_prompt(self):
        code = CodeBlocks()
        code.feed(source('prompt-coach.html'))
        return next(text for attrs, text in code.blocks
                    if attrs.get('aria-label') == 'Example planning request')

    def test_coach_and_example_follow_both_diagrams_and_remain_in_main_story(self):
        for name in ('index.html', 'workflows.html', 'get-started.html', 'explanation.html'):
            with self.subTest(page=name):
                main = MainText(source(name))
                self.assertIn('./prompt-coach.html', main.links)
                self.assertIn('./model-synthesis.html#planning-example', main.links)
        home = source('index.html')
        sections = ['ecosystem', 'supervised-execution', 'planning', 'durable-memory']
        positions = [home.index(f'<section id="{section}"') for section in sections]
        self.assertEqual(positions, sorted(positions))
        hero = home[home.index('<section id="start"'):positions[0]]
        self.assertNotIn('href="./prompt-coach.html"', hero)
        readme = (ROOT / 'README.md').read_text()
        sequence = ['docs/illustrations/connected-ecosystem.svg',
                    'docs/illustrations/supervised-delegation.svg',
                    'Start with [Prompt Coach]',
                    '## Keep project memory beyond the conversation']
        positions = [readme.index(marker) for marker in sequence]
        self.assertEqual(positions, sorted(positions))

    def test_coach_connects_sizing_draft_second_opinions_synthesis_and_execution(self):
        page = MainText(source('prompt-coach.html')).text
        steps = ['Define and size.', 'Draft the plan.', 'Get second opinions when useful.',
                 'Synthesize and revise.', 'Execute only when permitted.']
        self.assertEqual(sorted(page.index(s) for s in steps), [page.index(s) for s in steps])
        self.assertIn('does not call reviewers or authorize implementation', page)
        self.assertIn('The practice example already provides a small workflow', page)

    def test_copy_ready_request_binds_scope_cost_reviewers_and_stop_point(self):
        prompt = self.planning_prompt()
        for phrase in ('One user request must not create duplicate jobs',
                       'Planning only: do not modify files or deploy',
                       'two second opinions, synthesis and validation',
                       'estimate implementation and handoff', 'Agree the review allowance',
                       'Claude Opus', 'configured local vLLM', 'same brief',
                       'report a missing route rather than substitute a model',
                       'Ask each reviewer independently', 'evaluate their evidence',
                       'Stop after the reviewed plan'):
            self.assertIn(phrase, prompt)

    def test_request_routes_synthesis_without_reviving_the_retired_browser_gate(self):
        result = subprocess.run(
            [sys.executable, 'scripts/coach_prompt.py', '--json', '--external-ok',
             '--local-ok', '--share-boundary', 'redacted-packet', '--model-synthesis',
             self.planning_prompt()], cwd=ROOT, capture_output=True, text=True, timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        output = json.loads(result.stdout)
        self.assertTrue(output['model_synthesis']['active'])
        self.assertFalse(output['route']['blocking_review_required'])
        self.assertEqual(output['route']['share_boundary'], 'redacted-packet')
        # Metadata is not a dispatch grant; current runtime readiness can block.

    def test_example_names_the_assumption_findings_checks_and_revised_tasks(self):
        text = MainText(source('model-synthesis.html')).text
        for phrase in ('authored findings, not live model responses',
                       'retry the submission up to twice', 'no reply means no job',
                       'Cloud second opinion: challenge the design',
                       'Local vLLM second opinion: challenge recovery',
                       'not a verified service fact', 'not a vote',
                       'Count created jobs', 'proposed new test',
                       'Check the server contract first', 'save the identifier before the first send',
                       'do not automatically resubmit', 'blocks the dependent retry implementation',
                       'More models do not guarantee better answers'):
            self.assertIn(phrase, text)
        examples = MainText(source('use-cases.html'))
        self.assertIn('./model-synthesis.html#planning-example', examples.links)
        self.assertIn('not returns from real reviewers', examples.text)

    def test_withdrawn_copy_detector_rejects_plain_split_and_highlighted_old_setup(self):
        cases = ['Use ChatGPT Pro 5.5 Extended Reasoning',
                 'Use GPT-5.5 Pro for the final plan',
                 'ChatGPT\nPro\n5.5',
                 '<pre><code><span>ChatGPT</span><span> Pro 5.5</span></code></pre>',
                 'python scripts/chatgpt_browser_review.py --confirm-only',
                 'scripts/launch_chatgpt_cdp_chrome.sh --write-config',
                 'Set CWO_CHATGPT_BROWSER_CONFIG',
                 'executor chatgpt_pro_browser_master_reviewer']
        for text in cases:
            with self.subTest(text=text):
                self.assertTrue(retired_browser_guidance_errors(text, source_name='fixture'))

    def test_withdrawn_copy_detector_allows_deferred_plugin_and_generic_review_rules(self):
        for text in ['ChatGPT Pro web through the browser plugin is deferred.',
                     'Confirm the named model and effort before review.',
                     'Registry names CWO_CHATGPT_BROWSER_CONFIG without printing values.',
                     'Use a configured local vLLM reviewer and compare evidence.',
                     '<p>Review the revised plan.</p>']:
            with self.subTest(text=text):
                self.assertEqual(retired_browser_guidance_errors(text, source_name='fixture'), [])

    def test_browser_retirement_keeps_mandatory_review_and_no_substitution(self):
        page = MainText(source('external-contracting.html')).text
        for phrase in ('Required reviewer gate', 'remains blocking',
                       'Only an explicit operator decision', 'do not silently substitute',
                       'Browser-plugin instructions are deferred'):
            self.assertIn(phrase, page)
        self.assertIn('id="master-review"', source('external-contracting.html'))
        retired = (ROOT / 'references/chatgpt-pro-browser.md').read_text()
        self.assertIn('documentation withdrawn', retired)
        self.assertIn('deferred', retired)
        self.assertIn('Do not skip a', retired)
        self.assertNotIn('```', retired)


if __name__ == '__main__':
    unittest.main()
