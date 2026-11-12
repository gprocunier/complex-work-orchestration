from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

from typing import Iterator, NamedTuple
from tests.structural_assertions import Check, assert_checks

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from validate_site import validate_html, ONBOARDING_STEPS, ONBOARDING_PAGE_STEPS, validate_onboarding, validate_semantic_routes, SEMANTIC_ROUTES  # noqa: E402


def internal_copy_errors(errors: list[str]) -> list[str]:
    return [error for error in errors if "internal label" in error or "internal editorial wording" in error]


class SiteSnippetCase(NamedTuple):
    original: str
    page: str
    markup: str
    options: dict
    checks: tuple[Check, ...]


def _site_snippet_rows() -> Iterator[SiteSnippetCase]:
    yield SiteSnippetCase('test_rejects_contract_label_in_public_narrative', "workflows.html", "<section id='flow'><p>Use <code>contract-jd-editorial-reasoning</code> before publish.</p></section>", {}, (
        Check(lambda result: any(('contract-jd-editorial-reasoning' in error for error in internal_copy_errors(result))), None, 'true'),
    ))

    yield SiteSnippetCase('test_rejects_editor_gate_monologue_in_public_narrative', "workflows.html", "<section id='flow'><p><strong>Editor gate:</strong> check AI-slop wording.</p></section>", {}, (
        Check(lambda result: '\n'.join(internal_copy_errors(result)), 'Editor gate:', 'contains'),
        Check(lambda result: '\n'.join(internal_copy_errors(result)), 'AI-slop wording', 'contains'),
    ))

    phrase = "Publication" + " gate"
    yield SiteSnippetCase('test_rejects_publication_gate_monologue_in_public_narrative', "workflows.html", f"<section id='flow'><p><strong>{phrase}:</strong> run the first-reader walkthrough.</p></section>", {}, (
        Check(lambda result: '\n'.join(internal_copy_errors(result)), phrase, 'contains'),
    ))

    phrase = "documentation" + " commit"
    yield SiteSnippetCase('test_rejects_publication_rollback_monologue_in_public_narrative', "workflows.html", f"<section id='flow'><p><strong>Rollback:</strong> <code>git revert</code> the {phrase}, then start a fresh Pages deployment to restore the prior published copy.</p></section>", {}, (
        Check(lambda result: '\n'.join(result), phrase, 'contains'),
        Check(lambda result: '\n'.join(result), 'fresh Pages deployment', 'contains'),
        Check(lambda result: '\n'.join(result), 'prior published copy', 'contains'),
    ))

    yield SiteSnippetCase('test_allows_specific_operational_rollback_guidance', "workflows.html", "<section id='flow'><p>Revert the documentation commit if its generated links fail validation. Start a fresh Pages deployment after the corrected source passes.</p></section>", {}, (
        Check(lambda result: internal_copy_errors(result), []),
    ))

    yield SiteSnippetCase('test_rejects_design_source_as_public_reference_copy', "index.html", "<section id='reference'><p><a href='https://ux.redhat.com/'>Red Hat UX reference for the public docs site</a></p></section>", {}, (
        Check(lambda result: '\n'.join(result), 'Red Hat UX reference', 'contains'),
        Check(lambda result: '\n'.join(result), 'non-source external URL', 'contains'),
    ))

    url = (
        "https://github.com/gprocunier/complex-work-orchestration/"
        "blob/main/references/native-supervision-pools.md"
    )
    yield SiteSnippetCase('test_allows_native_supervision_operator_source_link', "workflows.html", f"<section id='preview'><p><a href='{url}'>Operator reference</a></p></section>", {}, (
        Check(lambda result: any(('non-source external URL' in error for error in result)), None, 'false', message=lambda result: result),
        Check(lambda result: any(('GitHub markdown/source blob' in error for error in result)), None, 'false', message=lambda result: result),
    ))

    url = (
        "https://github.com/gprocunier/complex-work-orchestration/"
        "blob/main/references/native-supervision.md"
    )
    yield SiteSnippetCase('test_allows_single_worker_supervision_operator_source_link', "native-supervision.html", f"<section id='reference'><p><a href='{url}'>Operator reference</a></p></section>", {}, (
        Check(lambda result: any(('non-source external URL' in error for error in result)), None, 'false', message=lambda result: result),
        Check(lambda result: any(('GitHub markdown/source blob' in error for error in result)), None, 'false', message=lambda result: result),
    ))

    yield SiteSnippetCase('test_rejects_duplicate_h1_and_ids', "workflows.html", "<section id='repeat'><h1>Second</h1></section><section id='repeat'></section>", {}, (
        Check(lambda result: '\n'.join(result), 'must contain exactly one h1; found 2', 'contains'),
        Check(lambda result: '\n'.join(result), 'contains duplicate id: repeat', 'contains'),
    ))

    yield SiteSnippetCase('test_rejects_repository_file_outside_pages_publication_root', "workflows.html", '<a href="../SECURITY.md">Security</a>', {}, (
        Check(lambda result: any(('leaves published docs directory' in e for e in result)), None, 'true', message=lambda result: result),
    ))

    url = (
        "https://github.com/gprocunier/complex-work-orchestration/"
        "blob/main/references/unapproved.md"
    )
    yield SiteSnippetCase('test_rejects_unapproved_operator_source_blob', "workflows.html", f"<section id='preview'><p><a href='{url}'>Unapproved source</a></p></section>", {}, (
        Check(lambda result: '\n'.join(result), 'non-source external URL', 'contains'),
        Check(lambda result: '\n'.join(result), 'GitHub markdown/source blob', 'contains'),
    ))

    yield SiteSnippetCase('test_rejects_contractor_authority_public_copy', "use-cases.html", "<section id='fit'><p>Outside models can approve implementation when they agree.</p></section>", {}, (
        Check(lambda result: '\n'.join(internal_copy_errors(result)), 'Outside models can approve', 'contains'),
    ))

    yield SiteSnippetCase('test_rejects_codex_required_public_copy', "workflows.html", "<section id='fit'><p>CWO requires Codex CLI for every execution path.</p></section>", {}, (
        Check(lambda result: '\n'.join(internal_copy_errors(result)), 'CWO requires Codex CLI', 'contains'),
    ))

    yield SiteSnippetCase('test_rejects_raw_beads_comment_disclosure_copy', "external-contracting.html", "<section id='boundary'><p>Operators may send raw Beads comments to reviewers.</p></section>", {}, (
        Check(lambda result: '\n'.join(internal_copy_errors(result)), 'send raw Beads comments', 'contains'),
    ))

    yield SiteSnippetCase('test_allows_contract_label_in_pre_code_block', "workflows.html", "<section id='flow'><pre><code>contract-jd-editorial-reasoning</code></pre></section>", {}, (
        Check(lambda result: internal_copy_errors(result), []),
    ))

    yield SiteSnippetCase('test_allows_contract_label_on_reference_page', "reference.html", "<section id='experts'><p><code>contract-jd-editorial-reasoning</code> is an operator label.</p></section>", {}, (
        Check(lambda result: internal_copy_errors(result), []),
    ))

    yield SiteSnippetCase('test_rejects_advanced_terms_before_index_novice_ramp', "index.html", """
<section id="top"><p>Beads, model synthesis, sabotage, malpractice, quarantine, and adjudication make this powerful.</p></section>
<section id="walk"><p>Now explain the ramp.</p></section>
<a href="./workflows.html">Workflows</a>
<a href="./use-cases.html">Examples</a>
<a href="./explanation.html">Concepts</a>
<a href="./native-supervision.html">Native Supervision</a>
<a href="./beads-memory.html">Beads Memory</a>
<a href="./model-synthesis.html">Model Synthesis</a>
<a href="./zero-trust-consensus.html">Zero-Trust Consensus</a>
<a href="./malpractice-sabotage.html">Guardrails</a>
<a href="./reference.html">Reference</a>
<a href="./contractor-demo.html">Demo</a>
<a href="https://github.com/gprocunier/complex-work-orchestration">GitHub</a>
""", {}, (
        Check(lambda result: '\n'.join(result), 'advanced term before novice ramp: Beads', 'contains'),
        Check(lambda result: '\n'.join(result), 'advanced term before novice ramp: synthesis', 'contains'),
        Check(lambda result: '\n'.join(result), 'advanced term before novice ramp: sabotage', 'contains'),
        Check(lambda result: '\n'.join(result), 'advanced term before novice ramp: malpractice', 'contains'),
        Check(lambda result: '\n'.join(result), 'advanced term before novice ramp: quarantine', 'contains'),
        Check(lambda result: '\n'.join(result), 'advanced term before novice ramp: adjudication', 'contains'),
    ))

    yield SiteSnippetCase('test_index_requires_expert_routes', "index.html", """
<section id="top"><p>Shell work should be recoverable.</p></section>
<section id="walk"><p>Now explain the ramp.</p></section>
""", {}, (
        Check(lambda result: '\n'.join(result), 'missing expert route link: ./workflows.html', 'contains'),
        Check(lambda result: '\n'.join(result), 'missing expert route link: ./use-cases.html', 'contains'),
        Check(lambda result: '\n'.join(result), 'missing expert route link: ./explanation.html', 'contains'),
        Check(lambda result: '\n'.join(result), 'missing expert route link: ./reference.html', 'contains'),
    ))

    yield SiteSnippetCase('test_allows_plain_index_opening_before_walk', "index.html", """
<section id="top"><p>Turn AI coding sessions into work you can resume, review, test, and trust.</p></section>
<section id="crawl"><p>A web chat answers questions. A coding shell works in the project.</p></section>
<section id="walk"><p>Now introduce the workflow.</p></section>
<a href="./workflows.html">Workflows</a>
<a href="./use-cases.html">Examples</a>
<a href="./explanation.html">Concepts</a>
<a href="./native-supervision.html">Native Supervision</a>
<a href="./beads-memory.html">Beads Memory</a>
<a href="./model-synthesis.html">Model Synthesis</a>
<a href="./zero-trust-consensus.html">Zero-Trust Consensus</a>
<a href="./malpractice-sabotage.html">Guardrails</a>
<a href="./reference.html">Reference</a>
<a href="./contractor-demo.html">Demo</a>
<a href="https://github.com/gprocunier/complex-work-orchestration">GitHub</a>
""", {}, (
        Check(lambda result: any(('advanced term before novice ramp' in error for error in result)), None, 'false'),
        Check(lambda result: any(('missing expert route link' in error for error in result)), None, 'false'),
    ))


class ValidateSiteTests(unittest.TestCase):
    def validate_snippet(self, name: str, body: str) -> list[str]:
        with tempfile.TemporaryDirectory(dir=ROOT) as tmpdir:
            path = Path(tmpdir) / name
            path.write_text(
                f"""<!doctype html>
<html lang="en">
<head><title>Test</title></head>
<body>
<header></header>
<nav></nav>
<main>
<h1>Test</h1>
{body}
</main>
<footer></footer>
</body>
</html>
""",
                encoding="utf-8",
            )
            return validate_html(path)

    def test_site_snippet_validation_rows(self) -> None:
        for row in _site_snippet_rows():
            with self.subTest(original=row.original):
                result = self.validate_snippet(row.page, row.markup, **row.options)
                assert_checks(self, result, row.checks)


    def test_rejects_missing_cross_page_fragment(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT) as tmpdir:
            directory = Path(tmpdir)
            target = directory / "target.html"
            target.write_text("<section id='present'></section>", encoding="utf-8")
            source = directory / "workflows.html"
            source.write_text(
                """<!doctype html><html lang="en"><head><title>Test</title></head>
<body><header></header><nav></nav><main><h1>Test</h1>
<a href="./target.html#missing">Broken fragment</a></main><footer></footer></body></html>""",
                encoding="utf-8",
            )
            errors = validate_html(source)
        self.assertTrue(any("links to missing fragment" in error for error in errors), errors)

    def test_split_tutorial_preserves_each_operational_step_in_order(self):
        contents = {page: "\n".join(f"<p>{step}</p>" for step in steps) for page, steps in ONBOARDING_PAGE_STEPS.items()}
        contents["get-started.html"] = ''.join(f'<a href="./{p}">Next</a>' for p in ("install.html", "first-project.html", "continue-project.html"))
        self.assertEqual(validate_onboarding(contents), [])
        for page, steps in ONBOARDING_PAGE_STEPS.items():
            for step in steps:
                missing = {**contents, page: contents[page].replace(step, "")}
                self.assertTrue(validate_onboarding(missing), (page, step))
            reversed_steps = {**contents, page: "\n".join(reversed(contents[page].splitlines()))}
            self.assertTrue(validate_onboarding(reversed_steps), page)
        self.assertTrue(validate_onboarding({**contents, "get-started.html": ""}))

    def test_semantic_routes_require_real_task_sections_not_empty_aliases(self):
        good = ''.join(f'<section id="{anchor}"><h2>Task</h2><pre>{command or ""}</pre><a href="{href}">Continue</a></section>' for anchor, (href, command) in SEMANTIC_ROUTES.items())
        self.assertEqual(validate_semantic_routes(good), [])
        for anchor in SEMANTIC_ROUTES:
            self.assertTrue(validate_semantic_routes(good.replace(f'<section id="{anchor}">', f'<section><span id="{anchor}"></span>')))
        self.assertTrue(validate_semantic_routes(good.replace('cat HANDOFF.md', 'A handoff exists')))
        self.assertTrue(validate_semantic_routes(good.replace('./external-contracting.html#collaboration', './index.html')))

    def test_allows_exact_official_prerequisite_source_not_lookalike(self) -> None:
        for url, allowed in [("https://learn.chatgpt.com/docs/codex/cli", True),
                             ("https://learn.chatgpt.com.evil.invalid/docs/codex/cli", False),
                             ("https://learn.chatgpt.com/docs/models", True),
                             ("https://learn.chatgpt.com/docs/models-pretend", False)]:
            errors = self.validate_snippet("workflows.html", f'<a href="{url}">Prerequisites</a>')
            self.assertEqual(any("non-source external URL" in e for e in errors), not allowed, errors)


    def test_beads_definition_is_allowed_only_in_the_named_memory_section(self) -> None:
        definition = "<strong>Beads is the task database CWO uses for durable project memory.</strong>"
        allowed = f'<section id="durable-memory"><h2>Saved project state</h2><p>{definition} Beads stores tasks.</p></section>'
        cases = [
            (allowed, False),
            (allowed.replace('Beads is', '<a href="https://beads.gascity.com/">Beads</a> is'), False),
            ('<section id="durable-memory"><p>Beads stores tasks.</p></section>', True),
            (f'<section id="durable-memory"><p>Beads is powerful.</p><p>{definition}</p></section>', True),
            (allowed + '<p>Beads outside the explanation.</p>', True),
            ('<p>Beads before the explanation.</p>' + allowed, True),
            (allowed.replace('durable-memory', 'another-section'), True),
            (allowed.replace('task database', 'magic memory'), True),
            (allowed.replace('Beads stores tasks.', 'Beads offers synthesis.'), False),
        ]
        for source, forbidden in cases:
            with self.subTest(source=source):
                errors = self.validate_snippet('index.html', source + '<section id="walk"><p>Examples</p></section>')
                self.assertEqual(any('advanced term before novice ramp: Beads' in e for e in errors), forbidden)
        errors = self.validate_snippet('index.html', allowed.replace('Beads stores tasks.', 'Beads offers synthesis.'))
        self.assertTrue(any('advanced term before novice ramp: synthesis' in e for e in errors))

    def test_beads_upstream_link_allowlist_is_exact(self) -> None:
        for url, allowed in (
            ('https://beads.gascity.com/', True),
            ('https://beads.gascity.com/#introduction', True),
            ('https://beads.gascity.com/unapproved', False),
            ('https://beads.gascity.com.evil.invalid/', False),
        ):
            with self.subTest(url=url):
                errors = self.validate_snippet('reference.html', f'<a href="{url}">Beads</a>')
                self.assertEqual(any('non-source external URL' in e for e in errors), not allowed, errors)


if __name__ == "__main__":
    unittest.main()
