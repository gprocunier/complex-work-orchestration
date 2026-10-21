from __future__ import annotations
import importlib.util
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import generate_site
from validate_site import validate_onboarding, validate_semantic_routes
from site_code import without_token_spans

class ReferenceSliceTests(unittest.TestCase):
    def test_canonical_stages_and_semantic_destinations_are_complete(self):
        pages={p.name:p.read_text() for p in (ROOT/'docs').glob('*.html')}
        self.assertEqual(validate_onboarding(pages), [])
        self.assertEqual(validate_semantic_routes(pages['workflows.html']), [])

    def test_shared_article_scope_and_parent_navigation_are_explicit(self):
        self.assertEqual(generate_site.ARTICLE_PAGES, set(generate_site.PAGES) - {'index.html'})
        self.assertIn('use-cases.html', generate_site.ARTICLE_PAGES)
        self.assertIn('native-supervision.html', generate_site.ARTICLE_PAGES)
        self.assertIn('first-project.html', generate_site.PAGES)
        self.assertIn('aria-current="true"', generate_site.render_link('./get-started.html', 'Start Here', 'first-project.html'))
        self.assertNotIn('aria-current', generate_site.render_link('./reference.html', 'Reference', 'first-project.html'))
        self.assertIn('aria-current="page"', generate_site.render_link('./workflows.html', 'Guides', 'workflows.html'))

    def test_legacy_get_started_urls_are_visible_specific_migration_notices(self):
        source=(ROOT/'docs/get-started.html').read_text()
        from html.parser import HTMLParser
        class Arrivals(HTMLParser):
            def __init__(self):super().__init__();self.anchors={};self.current=None
            def handle_starttag(self,tag,attrs):
                attrs=dict(attrs)
                if tag=='p' and 'id' in attrs:self.current=attrs['id'];self.anchors[self.current]=[]
                if tag=='a' and self.current:self.anchors[self.current].append(attrs.get('href'))
            def handle_endtag(self,tag):
                if tag=='p':self.current=None
        parser=Arrivals();parser.feed(source)
        for anchor,target in {'install':'./install.html#install','first-task':'./first-project.html#first-task','continue':'./continue-project.html#continue','recover':'./tutorial-recovery.html#recover'}.items():
            self.assertIn(target,parser.anchors[anchor])

    def test_local_contents_enhancement_is_shared_and_progressive(self):
        root=ROOT/'docs'
        new=generate_site.render_page(root/'first-project.html')
        old=generate_site.render_page(root/'local-workers.html')
        self.assertIn('<script src="./site.js" defer>',new)
        self.assertIn('<script src="./site.js" defer>',old)
        self.assertIn('<details class="contents" open>',new)
        self.assertIn('<summary>On this page</summary>',new)

    def test_handoff_hashes_bind_the_actual_case_code_and_tests(self):
        import hashlib
        source=(ROOT/'examples/release-readiness/HANDOFF.md').read_text()
        for file in ['scripts/check_documentation.py','tests/test_documentation_cli.py']:
            self.assertIn(hashlib.sha256((ROOT/file).read_bytes()).hexdigest(),source)

    def test_reviewed_startup_recovery_has_an_explicit_main_override(self):
        import html
        source=html.unescape(without_token_spans((ROOT/'docs/tutorial-recovery.html').read_text()))
        self.assertIn('--model YOUR_AVAILABLE_MAIN_MODEL',source)
        self.assertIn('--profile cwo-sol-operator-e',source)
        self.assertIn('/model',source)
        self.assertIn('/status',source)
        self.assertIn('exact working launch command',source)
        self.assertIn('HANDOFF.md',source)

    def test_reviewed_continuation_checks_saved_completion_not_only_code(self):
        source=without_token_spans((ROOT/'docs/continue-project.html').read_text())
        section=source.split('<section id="finish-check">',1)[1].split('</section>',1)[0]
        for command in ['cat HANDOFF.md','bd show VALIDATOR_TASK_ID --json','bd show CLI_TASK_ID --json','git diff cwo-tutorial-start']:
            self.assertIn(command,section)
        self.assertIn('both tasks are accepted and closed',section)
        self.assertIn('preserve the accepted validator task and its dependency',source)

    def test_case_snapshot_and_actual_encoding_reproduction(self):
        import hashlib,json,subprocess
        record=json.loads((ROOT/'examples/release-readiness/SOURCE-SNAPSHOT.json').read_text())
        for file,digest in record['files'].items():
            self.assertEqual(hashlib.sha256((ROOT/file).read_bytes()).hexdigest(),digest)
        run=subprocess.run([sys.executable,'examples/release-readiness/reproduce_encoding_case.py'],cwd=ROOT,capture_output=True,text=True)
        self.assertEqual(run.returncode,0,run.stderr)
        result=json.loads(run.stdout)
        self.assertEqual(result['exit_code'],1)
        self.assertIs(result['report']['ok'],False)

if __name__ == '__main__':unittest.main()
