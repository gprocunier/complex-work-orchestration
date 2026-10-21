"""Guard concrete onboarding explanations, not an automated readability score."""
from html.parser import HTMLParser
from pathlib import Path
import re
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from site_code import CodeBlocks


class Reader(HTMLParser):
    def __init__(self):
        super().__init__()
        self.in_main = False
        self.in_pre = False
        self.first_code_seen = False
        self.introduction = []
        self.prose = []
        self.headings = []
        self.heading = None
        self.heading_parts = []

    def handle_starttag(self, tag, attrs):
        if tag == 'main':
            self.in_main = True
        if not self.in_main:
            return
        if tag == 'pre':
            self.in_pre = True
            self.first_code_seen = True
        if tag in {'h1', 'h2', 'h3'}:
            self.heading = tag
            self.heading_parts = []

    def handle_endtag(self, tag):
        if tag == self.heading:
            self.headings.append(''.join(self.heading_parts))
            self.heading = None
        if tag == 'pre':
            self.in_pre = False
        if tag == 'main':
            self.in_main = False

    def handle_data(self, data):
        if self.in_main and not self.in_pre:
            self.prose.append(data)
            if not self.first_code_seen:
                self.introduction.append(data)
            if self.heading:
                self.heading_parts.append(data)


def read(name):
    parsed = Reader()
    parsed.feed((ROOT / 'docs' / name).read_text())
    return parsed


def joined(parts):
    return ' '.join(' '.join(parts).split())


class ReaderOnboardingTests(unittest.TestCase):
    def test_practice_example_is_explicit_before_any_setup_command(self):
        page = read('first-project.html')
        self.assertTrue(page.headings[0].startswith('Practice example:'))
        intro = joined(page.introduction)
        for phrase in ('simple, optional practice exercise', 'supplied sample files',
                       'not work on your own project', 'Disposable folder',
                       'inspecting the changes and tests', 'saving a handoff'):
            self.assertIn(phrase, intro)
        self.assertLess(intro.index('not work on your own project'),
                        intro.index('Copy the starter'))
        source = (ROOT / 'docs/first-project.html').read_text()
        self.assertIn('href="./workflows.html#operator">Use CWO on your own project', source)

    def test_every_walkthrough_step_uses_the_practice_label(self):
        for name in ('get-started.html', 'install.html', 'first-project.html',
                     'continue-project.html'):
            source = (ROOT / 'docs' / name).read_text()
            nav = re.search(r'<nav class="tutorial-progress".*?</nav>', source, re.S)[0]
            with self.subTest(page=name):
                self.assertIn('3. Practice example', nav)
                self.assertIn('4. Continue the example', nav)
                self.assertNotIn('First task', nav)
                self.assertIn('aria-label="Practice walkthrough stages"', nav)
        for name in ('get-started.html', 'first-project.html', 'continue-project.html'):
            self.assertIn('practice example', read(name).headings[0].lower())
        intro = joined(read('continue-project.html').introduction)
        self.assertIn('disposable sample project from the practice example', intro)

    def test_entry_links_name_the_example_instead_of_promising_real_project_work(self):
        for name in ('index.html', 'reference.html', 'explanation.html', 'prompt-coach.html'):
            with self.subTest(page=name):
                self.assertIn('practice example', joined(read(name).prose))
        self.assertIn('guided practice example', (ROOT / 'README.md').read_text())
        self.assertIn('Next: try the practice example', (ROOT / 'docs/install.html').read_text())
        self.assertIn('use your own project directory', joined(read('workflows.html').prose))

    def test_first_task_identifies_program_input_and_learning_goal_before_commands(self):
        intro = joined(read('first-project.html').introduction)
        for phrase in ('deliberately broken Python program', 'server name and port number',
                       'fresh agent session', 'save the results', '"host": "localhost"', '"port": 8080',
                       'should pass', 'must never connect to the server'):
            self.assertIn(phrase, intro)
        self.assertLess(intro.index('deliberately broken'), intro.index('Copy the starter'))

    def test_start_here_explains_practice_project_and_continuation_before_setup(self):
        intro = joined(read('get-started.html').introduction)
        for phrase in ('checks service configuration', 'fresh agent session',
                       'saved task records', 'Beads, the task database CWO uses'):
            self.assertIn(phrase, intro)

    def test_requirement_is_not_presented_as_an_unspecified_decision(self):
        first = read('first-project.html')
        prose = joined(first.prose)
        self.assertIn('validation requirements', prose)
        self.assertIn('Boolean values', prose)
        self.assertIn('they are not port numbers', prose)
        for heading in first.headings:
            self.assertNotIn('save the decision', heading.lower())
            self.assertNotIn('repair a checker', heading.lower())
        continuation = joined(read('continue-project.html').introduction)
        self.assertIn('python3 checker.py service.json', continuation)
        self.assertIn('saved requirements, tests and task records before editing', continuation)

    def test_example_headings_name_actions_instead_of_unexplained_artifacts(self):
        headings = read('use-cases.html').headings
        for concrete in ('documentation-checking command', 'duplicate jobs',
                         'failed health check', 'supported facts'):
            self.assertTrue(any(concrete in h for h in headings), concrete)
        self.assertFalse(any(re.search(r'\b(authored|source-to-memo)\b', h, re.I) for h in headings))
        prose = joined(read('use-cases.html').prose)
        self.assertIn('N3 , the deliberately unsupported speed claim', prose)
        self.assertIn('not returns from real reviewers', prose)
        self.assertIn('Neither has been run end to end', prose)

    def test_standalone_guides_define_their_essential_terms(self):
        definitions = {
            'native-supervision.html': ('A native worker is another Codex agent', 'not a Git commit'),
            'local-workers.html': ('server that receives your model requests', 'vLLM is one way to serve that model'),
            'prompt-coach.html': ('a work graph', 'a saved set of tasks and dependencies'),
            'codex-beads-hooks.html': ('Hooks are commands', 'When configured and supported'),
            'model-synthesis.html': ('A return is a reviewer’s answer and supporting evidence', 'that decision is adjudication'),
            'zero-trust-consensus.html': ('trust domain', 'a provider or deployment group'),
        }
        for page, phrases in definitions.items():
            with self.subTest(page=page):
                prose = joined(read(page).prose)
                for phrase in phrases:
                    self.assertIn(phrase, prose)

    def test_continuation_prompt_keeps_the_validation_and_permission_contract(self):
        parser = CodeBlocks()
        parser.feed((ROOT / 'docs/continue-project.html').read_text())
        prompt = next(code for attrs, code in parser.blocks if attrs.get('class', '').startswith('prompt '))
        for phrase in ('Identify the saved validation requirements', 'Verify the accepted validator tests before editing',
                       'Preserve the validation contract', 'valid input (exit 0)', 'invalid configuration (exit 1)',
                       'usage errors (exit 2)', 'preserve the accepted validator task and its dependency',
                       'No delegation, service-host contact', 'commits, pushes, publication'):
            self.assertIn(phrase, prompt)

    def test_maintenance_guide_requires_a_direct_entry_reader_pass(self):
        guide = (ROOT / 'CONTRIBUTING.md').read_text()
        self.assertIn('before the first setup command', guide)
        self.assertIn('Distinguish an existing requirement from a decision', guide)
        self.assertIn('Read each page as a direct entry point', guide)
        self.assertIn('Passing tests, word counts and readability scores do not establish comprehension', guide)


if __name__ == '__main__':
    unittest.main()
