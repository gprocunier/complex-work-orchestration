"""Protect concrete reader explanations and the distinctions they must preserve.

These checks guard known regressions, not a claim to automate editorial judgment.
"""
from html.parser import HTMLParser
from pathlib import Path
import re
import json
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]

class Text(HTMLParser):
    def __init__(self):
        super().__init__(); self.parts = []
    def handle_data(self, data):
        self.parts.append(data)

def text(name):
    parser = Text(); parser.feed((ROOT / 'docs' / name).read_text())
    return ' '.join(' '.join(parser.parts).split())

class EditorialClarityTests(unittest.TestCase):
    def section_text(self, name, key):
        source = (ROOT / 'docs' / name).read_text()
        block = re.search(r'<section id="' + key + r'"[^>]*>.*?</section>', source, re.S)[0]
        parser = Text(); parser.feed(block)
        return ' '.join(' '.join(parser.parts).split())

    def test_zero_trust_premise_is_visible_on_home_not_only_in_the_hover_note(self):
        hero = self.section_text('index.html', 'start')
        for phrase in ('No model gets implicit trust.',
                       'public-cloud and open-weight models as untrusted contributors',
                       'The lead is not exempt.',
                       'Using a model without guardrails is a choice to trust it implicitly.',
                       'Limit its access, check its work',
                       'do not make the model trustworthy'):
            self.assertIn(phrase, hero)
        self.assertIn('Some safeguards are instructions, not enforced restrictions.', hero)

    def test_concepts_distinguish_guardrails_from_optional_coordination(self):
        limits = self.section_text('explanation.html', 'limits')
        for phrase in ('Every model needs guardrails',
                       'The lead is not exempt: its plans and acceptance decisions also need checks.',
                       'Using a model without guardrails is a choice to trust it implicitly.',
                       'limiting what the agent can access and do',
                       'checking its work against agreed requirements',
                       'agent client and host must enforce them',
                       'A small edit may need one lead and focused validation',
                       'does not remove the need for access limits and evidence checks',
                       'do not make a model trustworthy or guarantee safety'):
            self.assertIn(phrase, limits)
        self.assertNotIn('When the extra structure is worth it', text('explanation.html'))
        self.assertIn('href="#limits">Every model needs guardrails</a>',
                      (ROOT / 'docs/explanation.html').read_text())

    def test_short_task_guidance_does_not_grant_implicit_trust_to_the_lead(self):
        readme = ' '.join((ROOT / 'README.md').read_text().split())
        for phrase in ('No model gets implicit trust.',
                       'Using a model without guardrails is a choice to trust it implicitly.',
                       'Every model remains untrusted, including the lead.',
                       'Neither replaces the host\'s tool permissions or sandbox.'):
            self.assertIn(phrase, readme)
        cost = self.section_text('workflows.html', 'cost')
        self.assertIn('only one thread, but it still needs access limits and evidence checks', cost)
        self.assertIn('not a reason to trust the model implicitly', cost)
        self.assertIn('Every native worker CWO delegates to must be supervised', text('native-supervision.html'))

    def test_examples_explain_the_failure_before_naming_idempotency(self):
        page = text('use-cases.html')
        self.assertLess(page.index('The server creates it, but the reply'), page.index('idempotency'))
        for phrase in ('Neither has been run end to end', 'not returns from real reviewers',
                       'No converter implementation', 'No integrated simulator/client demonstration'):
            self.assertIn(phrase, page)

    def test_reviews_define_the_exact_decision_terms_and_do_not_use_a_docs_self_example(self):
        page = text('model-synthesis.html')
        for phrase in ('This is model synthesis', 'that decision is adjudication',
                       'server may have created the job', 'not proof of statistical independence'):
            self.assertIn(phrase, page)
        self.assertNotIn('Keep three pages', page)
        self.assertNotIn('top-nav restraint', page)

    def test_risk_guide_explains_the_task_substitution_without_spy_or_locksmith_analogy(self):
        page = text('malpractice-sabotage.html')
        self.assertIn('asked to implement and test an evaluator returns only a research note', page)
        self.assertIn('pending review is a process hold', page.lower())
        self.assertNotIn('hiring a locksmith', page)
        self.assertNotIn('In intelligence work', page)
        self.assertIn('not the model’s intent', page)

    def test_delegation_names_whole_route_and_monitoring_order(self):
        page = text('native-supervision.html')
        self.assertIn('Estimate preparation, execution, review, integration and validation', page)
        self.assertIn('register monitoring before sending', page)
        self.assertIn('fit check alone does not approve execution', page)
        self.assertIn('CONTAINED state label does not prove cleanup finished', page)

    def local_capture_block(self):
        sys.path.insert(0, str(ROOT / 'scripts'))
        from site_code import CodeBlocks
        parser = CodeBlocks(); parser.feed((ROOT / 'docs/local-workers.html').read_text())
        return next(code for _, code in parser.blocks if 'No usable final answer;' in code)

    def test_local_capture_shell_is_valid_and_records_before_execution(self):
        block = self.local_capture_block()
        result = subprocess.run(['bash', '-n'], input=block, text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertLess(block.index('--snapshot'), block.index('--execute-local'))
        self.assertLess(block.index('--execute-local'), block.index('--compare'))
        self.assertIn('--json', block)
        self.assertIn('test ! -e', block)

    def test_local_capture_prefers_normalized_answer_and_rejects_unusable_content(self):
        code = re.search(r"python3 - <<'PY'\n(.*?)\nPY", self.local_capture_block(), re.S).group(1)
        for response, expected in [
            ({'usable_final_content': True, 'normalized_return': 'normalized answer', 'final_content': 'raw answer'}, 'normalized answer'),
            ({'usable_final_content': True, 'final_content': 'final answer'}, 'final answer'),
            ({'usable_final_content': False, 'final_content': 'must not escape'}, None),
            ({'usable_final_content': True, 'final_content': ''}, None),
        ]:
            with self.subTest(response=response), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                (root / 'local-dispatch-result.json').write_text(json.dumps({'local_response': response}))
                result = subprocess.run([sys.executable, '-c', code], cwd=root, capture_output=True, text=True)
                self.assertEqual(result.returncode == 0, expected is not None)
                output = root / 'local-return.md'
                if expected is None:
                    self.assertFalse(output.exists())
                else:
                    self.assertEqual(output.read_text(), expected)

    def test_local_execution_and_human_decisions_have_explicit_boundaries(self):
        source = (ROOT / 'docs/local-workers.html').read_text()
        prep = source.split('<section id="dispatch-envelope">')[1].split('</section>')[0]
        self.assertNotIn('--execute-local</span>', prep)
        for page in ('model-synthesis.html', 'external-contracting.html', 'zero-trust-consensus.html'):
            self.assertIn('Decisions reserved to you', text(page))
            self.assertIn('stay with a human', text(page))
        hooks = text('codex-beads-hooks.html')
        self.assertIn('not proof that two values are equal', hooks)
        self.assertIn('do not establish live delivery into Codex', hooks)

    def test_inline_identifiers_wrap_without_changing_preformatted_commands(self):
        css = (ROOT / 'docs/styles.css').read_text()
        self.assertIn('.doc-content :not(pre) > code { overflow-wrap: anywhere; }', css)
        self.assertIn('.reference-slice pre { max-width: 100%; overflow-x: auto; white-space: pre;', css)

    def test_maintainer_review_requires_sections_and_preserves_exact_contracts(self):
        guide = (ROOT / 'CONTRIBUTING.md').read_text()
        self.assertIn('Review every affected section', guide)
        self.assertIn('Passing tests, word counts and readability scores do not establish comprehension', guide)
        self.assertIn('Do not rewrite', guide)

if __name__ == '__main__':
    unittest.main()
