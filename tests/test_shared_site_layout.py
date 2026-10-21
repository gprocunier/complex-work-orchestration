"""The public site has one width/container and one article navigation grammar."""
from html.parser import HTMLParser
from pathlib import Path
import re
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import generate_site

VOID = {'area','base','br','col','embed','hr','img','input','link','meta','param','source','track','wbr'}


class Element:
    def __init__(self, tag, attrs, parent):
        self.tag, self.attrs, self.parent = tag, dict(attrs), parent
        self.children = []

    def has(self, name):
        return name in self.attrs.get('class', '').split()


class Layout(HTMLParser):
    def __init__(self, source):
        super().__init__()
        self.nodes, self.stack = [], []
        self.feed(source)

    def handle_starttag(self, tag, attrs):
        node = Element(tag, attrs, self.stack[-1] if self.stack else None)
        self.nodes.append(node)
        if node.parent:
            node.parent.children.append(node)
        if tag not in VOID:
            self.stack.append(node)

    def handle_endtag(self, tag):
        if tag not in VOID and any(n.tag == tag for n in self.stack):
            while self.stack.pop().tag != tag:
                pass

    def one(self, predicate):
        matches = [n for n in self.nodes if predicate(n)]
        if len(matches) != 1:
            raise AssertionError(f'Expected one element, found {len(matches)}')
        return matches[0]


def article_errors(source):
    layout = Layout(source)
    errors = []
    try:
        main = layout.one(lambda n: n.tag == 'main')
        frame = layout.one(lambda n: n.has('page-shell') and n.parent is main)
        reading = layout.one(lambda n: n.has('reading-layout'))
        if reading.parent is not frame:
            errors.append('reading frame')
        expected = [('header', 'page-intro'), ('details', 'contents'), ('article', 'doc-content')]
        if len(reading.children) != len(expected) or any(
            n.tag != tag or not n.has(cls)
            for n, (tag, cls) in zip(reading.children, expected)
        ):
            errors.append('intro/contents/article order')
        contents = layout.one(lambda n: n.has('contents'))
        if 'open' not in contents.attrs:
            errors.append('no-JS contents visibility')
        nav = layout.one(lambda n: n.tag == 'nav' and n.parent is contents)
        if nav.attrs.get('aria-label') != 'On this page':
            errors.append('contents label')
        title = layout.one(lambda n: n.tag == 'h1')
        if not title.parent.has('page-intro') or title.attrs.get('id') != 'page-title':
            errors.append('title before navigation')
        article = layout.one(lambda n: n.tag == 'article' and n.parent is reading)
        if article.attrs.get('aria-labelledby') != 'page-title':
            errors.append('article title association')
    except AssertionError as exc:
        errors.append(str(exc))
    if any(n.has(c) for n in layout.nodes for c in ('doc-layout', 'reader-layout', 'doc-body')):
        errors.append('retired layout')
    return errors


class SharedSiteLayoutTests(unittest.TestCase):
    # Independent positive fixture, not generated from the checked-in pages.
    ARTICLE = '''<main><div class="page-shell"><div class="reading-layout">
<header class="page-intro"><h1 id="page-title">Example guide</h1></header>
<details class="contents" open><summary>On this page</summary><nav aria-label="On this page"><a href="#task">Task</a></nav></details>
<article class="doc-content" aria-labelledby="page-title"><section id="task"><h2>Task</h2></section></article>
</div></div></main>'''

    def test_all_pages_use_the_same_main_frame_and_shared_shell(self):
        for page in generate_site.PAGES:
            with self.subTest(page=page):
                source = (ROOT / 'docs' / page).read_text()
                layout = Layout(source)
                main = layout.one(lambda n: n.tag == 'main')
                layout.one(lambda n: n.has('page-shell') and n.parent is main)
                self.assertEqual(source.count('src="./site.js"'), 1)
                self.assertIn('<details class="site-menu" open>', source)
                self.assertIn('class="page-shell footer-grid"', source)
                self.assertEqual(generate_site.render_page(ROOT / 'docs' / page), source)

    def test_every_article_places_contents_after_its_title_in_the_shared_grid(self):
        self.assertEqual(generate_site.ARTICLE_PAGES, set(generate_site.PAGES) - {'index.html'})
        for page in generate_site.ARTICLE_PAGES:
            with self.subTest(page=page):
                self.assertEqual(article_errors((ROOT / 'docs' / page).read_text()), [])

    def test_landing_page_keeps_its_own_body_without_article_navigation(self):
        layout = Layout((ROOT / 'docs/index.html').read_text())
        self.assertFalse(any(n.has('reading-layout') or n.has('contents') for n in layout.nodes))
        layout.one(lambda n: n.has('page--landing'))

    def test_reader_css_does_not_reintroduce_a_narrower_page_or_article_cap(self):
        css = (ROOT / 'docs/styles.css').read_text()
        self.assertRegex(css, r'\.page-shell\s*\{[^}]*max-width:\s*var\(--max\)')
        for selector in (r'\.doc-content', r'\.page-intro'):
            block = re.search(selector + r'\s*\{([^}]+)\}', css).group(1)
            self.assertIn('max-width: none;', block)
        self.assertNotIn('.doc-layout.reader-layout', css)
        self.assertIn('.reading-layout > .contents { grid-column: 1; grid-row: 2;', css)

    def test_independent_article_fixture_and_negative_navigation_cases(self):
        self.assertEqual(article_errors(self.ARTICLE), [])
        header = '<header class="page-intro"><h1 id="page-title">Example guide</h1></header>'
        variants = {
            'closed fallback': self.ARTICLE.replace('class="contents" open', 'class="contents"'),
            'missing frame': self.ARTICLE.replace('class="page-shell"', 'class="reader-layout"'),
            'title below contents': self.ARTICLE.replace(header, '').replace('<article ', header + '<article '),
            'title inside body': self.ARTICLE.replace(header, '').replace('<section ', header + '<section '),
            'unlabelled article': self.ARTICLE.replace(' aria-labelledby="page-title"', ''),
        }
        for label, source in variants.items():
            with self.subTest(label=label):
                self.assertTrue(article_errors(source), label)


if __name__ == '__main__':
    unittest.main()
