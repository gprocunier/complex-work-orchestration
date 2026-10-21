from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from site_code import CodeBlocks, without_token_spans
from validate_site import validate_onboarding, ONBOARDING_PAGE_STEPS


class SiteHighlightingTests(unittest.TestCase):
    def test_every_code_box_is_statically_highlighted_with_explicit_language(self):
        total = 0
        css = (ROOT / 'docs/shiki.css').read_text()
        self.assertIn('background-color:#0d1117;color:#e6edf3', css)
        for path in sorted((ROOT / 'docs').glob('*.html')):
            self.assertIn('href="./shiki.css"', path.read_text())
            parser = CodeBlocks()
            parser.feed(path.read_text())
            for attrs, text in parser.blocks:
                total += 1
                self.assertIn('shiki', attrs.get('class', '').split(), path.name)
                self.assertEqual(attrs.get('data-theme'), 'github-dark-default', path.name)
                self.assertNotIn('github-light', attrs.get('class', '').split(), path.name)
                self.assertNotIn('style', attrs, path.name)
                generated = [c for c in attrs.get('class', '').split() if c.startswith('shiki-style-')]
                self.assertEqual(len(generated), 1, path.name)
                self.assertIn('.shiki.' + generated[0], css)
                self.assertIn(attrs.get('data-language'), {'bash', 'json', 'text'}, path.name)
                if 'prompt' in attrs.get('class', '').split():
                    self.assertEqual(attrs.get('data-language'), 'text', path.name)
        self.assertGreater(total, 0)

    def test_token_removal_preserves_command_adjacency_and_other_html(self):
        html = '<span id="keep"></span><pre><code><span class="line"><span>bd</span><span> show TASK_ID --json</span></span></code></pre>'
        self.assertEqual(without_token_spans(html), '<span id="keep"></span><pre><code>bd show TASK_ID --json</code></pre>')

    def test_onboarding_validation_reads_visible_commands_but_still_rejects_omission(self):
        pages = {p.name: p.read_text() for p in (ROOT / 'docs').glob('*.html')}
        self.assertEqual(validate_onboarding(pages), [])
        pages['install.html'] = without_token_spans(pages['install.html']).replace(ONBOARDING_PAGE_STEPS['install.html'][0], 'missing command')
        self.assertTrue(validate_onboarding(pages))


if __name__ == '__main__':
    unittest.main()
