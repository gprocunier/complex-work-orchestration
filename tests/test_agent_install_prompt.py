"""Agent-assisted setup is discoverable without requiring an installed CWO.

The command test uses an isolated disposable HOME, not the live installation.
It does not run a model, install OS packages, or initialize a real Beads backend.
"""
from html.parser import HTMLParser
from pathlib import Path
import json
import os
import shlex
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from site_code import CodeBlocks

TITLE = 'If you want your agent to install this skill, give it this'
COMMANDS = [
    './scripts/install.sh --yes --dry-run',
    './scripts/install.sh --yes',
    'python3 scripts/check_installed_skill.py --check',
    'python3 scripts/manage_instruction_profile.py install --profile operator-e',
    'python3 scripts/manage_instruction_profile.py verify --profile operator-e',
]


class InstallStructure(HTMLParser):
    def __init__(self, source):
        super().__init__()
        self.sections, self.details, self.prompt_parents = [], [], []
        self.stack = []
        self.feed(source)

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == 'section':
            self.sections.append(attrs.get('id'))
        if tag == 'details':
            self.details.append(attrs)
            self.stack.append(attrs)
        if tag == 'pre' and attrs.get('aria-label') == 'Agent installation prompt':
            self.prompt_parents = self.stack.copy()

    def handle_endtag(self, tag):
        if tag == 'details':
            self.stack.pop()


class AgentInstallPromptTests(unittest.TestCase):
    def prompt(self):
        parser = CodeBlocks()
        parser.feed((ROOT / 'docs/install.html').read_text())
        matches = [(attrs, text) for attrs, text in parser.blocks
                   if attrs.get('aria-label') == 'Agent installation prompt']
        self.assertEqual(len(matches), 1)
        return matches[0]

    def test_first_section_has_exact_title_and_default_closed_native_prompt(self):
        source = (ROOT / 'docs/install.html').read_text()
        tree = InstallStructure(source)
        self.assertEqual(tree.sections[:2], ['agent-install', 'install'])
        self.assertIn(f'<h2 id="agent-install-title">{TITLE}</h2>', source)
        self.assertIn('href="#agent-install"', source)
        self.assertEqual(len(tree.prompt_parents), 1)
        self.assertIn('install-prompt', tree.prompt_parents[0]['class'].split())
        self.assertNotIn('open', tree.prompt_parents[0])
        self.assertIn('<summary>Show the installation prompt</summary>', source)
        attrs, prompt = self.prompt()
        self.assertIn('prompt', attrs['class'].split())  # Existing full-copy enhancement.
        self.assertIn('shiki', attrs['class'].split())
        self.assertEqual(attrs['data-language'], 'text')
        self.assertEqual(attrs['data-theme'], 'github-dark-default')
        self.assertIn('this existing conversation has not acquired the new instruction profile.', prompt)

    def test_prompt_bootstraps_prerequisites_storage_and_safe_boundaries(self):
        _, prompt = self.prompt()
        for required in (
            'CWO is not installed yet', 'ordinary tools',
            'https://github.com/gprocunier/complex-work-orchestration',
            'https://learn.chatgpt.com/docs/cli',
            'https://beads.gascity.com/getting-started/installation',
            'Bash, Git, Python 3, Codex CLI and Beads',
            'Let me complete any sign-in myself', 'request approval',
            'Do not bypass the sandbox', 'only if that version needs it',
            'new disposable scratch project', 'bd ready --json',
            'Isolate its database', 'stop only temporary services you started',
            'do not replace or\nmigrate an existing working backend',
            'Do not configure a\nremote', 'Never delete,\nreset or overwrite',
            'CODEX_HOME', 'CODEX_SKILLS_DIR', 'do not unset overrides',
            'preserve its local changes and backup', 'Do not use --force',
            'Leave my default Codex settings unchanged',
            'do not label a partial install ready', 'fresh CWO session',
            'Do not start project work or launch additional models',
        ):
            with self.subTest(required=required):
                self.assertIn(required, prompt)

    def test_documented_commands_are_ordered_and_have_real_helper_producers(self):
        _, prompt = self.prompt()
        commands = [line for line in prompt.splitlines()
                    if line.startswith(('./scripts/', 'python3 scripts/'))]
        self.assertEqual(commands, COMMANDS)
        for command in commands:
            argv = shlex.split(command)
            helper = argv[1] if argv[0] == 'python3' else argv[0]
            self.assertTrue((ROOT / helper).is_file(), command)

    def test_prompt_command_sequence_works_in_an_isolated_custom_home(self):
        _, prompt = self.prompt()
        commands = [shlex.split(line) for line in prompt.splitlines()
                    if line.startswith(('./scripts/', 'python3 scripts/'))]
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / 'user home'
            codex = home / 'custom codex'
            skills = home / 'separate skills'
            bin_dir = home / 'bin'
            codex.mkdir(parents=True)
            bin_dir.mkdir()
            config = codex / 'config.toml'
            config.write_text('# existing user settings must be retained\n')
            original = config.read_bytes()
            bd = bin_dir / 'bd'
            bd.write_text('#!/bin/sh\n[ "$1" = version ] || exit 64\nprintf "fixture Beads CLI\\n"\n')
            bd.chmod(0o755)
            env = {**os.environ, 'HOME': str(home), 'CODEX_HOME': str(codex),
                   'CODEX_SKILLS_DIR': str(skills),
                   'PATH': str(bin_dir) + os.pathsep + os.environ['PATH'],
                   'SKILL_VALIDATOR': str(home / 'no-live-validator.py')}
            results = []
            for index, argv in enumerate(commands):
                result = subprocess.run(argv, cwd=ROOT, env=env, text=True,
                                        capture_output=True, timeout=40)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                results.append(result)
                if index == 0:
                    self.assertFalse(skills.exists(), 'Dry run must not install')
            self.assertIn('current', results[2].stdout.lower())
            self.assertTrue(json.loads(results[-1].stdout)['ok'])
            self.assertEqual(config.read_bytes(), original)
            target = skills / 'complex-work-orchestration'
            self.assertEqual((target / 'SKILL.md').read_bytes(), (ROOT / 'SKILL.md').read_bytes())
            self.assertTrue((home / '.local/bin/cwo-codex').is_file())
            self.assertFalse((home / '.codex').exists())
            self.assertFalse((home / '.beads').exists())


if __name__ == '__main__':
    unittest.main()
