from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from validate_site import validate_html, ONBOARDING_STEPS, ONBOARDING_PAGE_STEPS, validate_onboarding, validate_semantic_routes, SEMANTIC_ROUTES  # noqa: E402


def internal_copy_errors(errors: list[str]) -> list[str]:
    return [error for error in errors if "internal label" in error or "internal editorial wording" in error]


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

    def test_rejects_contract_label_in_public_narrative(self) -> None:
        errors = self.validate_snippet(
            "workflows.html",
            "<section id='flow'><p>Use <code>contract-jd-editorial-reasoning</code> before publish.</p></section>",
        )
        self.assertTrue(any("contract-jd-editorial-reasoning" in error for error in internal_copy_errors(errors)))

    def test_rejects_editor_gate_monologue_in_public_narrative(self) -> None:
        errors = self.validate_snippet(
            "workflows.html",
            "<section id='flow'><p><strong>Editor gate:</strong> check AI-slop wording.</p></section>",
        )
        rendered = "\n".join(internal_copy_errors(errors))
        self.assertIn("Editor gate:", rendered)
        self.assertIn("AI-slop wording", rendered)

    def test_rejects_publication_gate_monologue_in_public_narrative(self) -> None:
        phrase = "Publication" + " gate"
        errors = self.validate_snippet(
            "workflows.html",
            f"<section id='flow'><p><strong>{phrase}:</strong> run the first-reader walkthrough.</p></section>",
        )
        rendered = "\n".join(internal_copy_errors(errors))
        self.assertIn(phrase, rendered)

    def test_rejects_publication_rollback_monologue_in_public_narrative(self) -> None:
        phrase = "documentation" + " commit"
        errors = self.validate_snippet(
            "workflows.html",
            f"<section id='flow'><p><strong>Rollback:</strong> <code>git revert</code> the {phrase}, then start a fresh Pages deployment to restore the prior published copy.</p></section>",
        )
        rendered = "\n".join(errors)
        self.assertIn(phrase, rendered)
        self.assertIn("fresh Pages deployment", rendered)
        self.assertIn("prior published copy", rendered)

    def test_allows_specific_operational_rollback_guidance(self) -> None:
        errors = self.validate_snippet(
            "workflows.html",
            "<section id='flow'><p>Revert the documentation commit if its generated links fail validation. Start a fresh Pages deployment after the corrected source passes.</p></section>",
        )
        self.assertEqual(internal_copy_errors(errors), [])

    def test_rejects_design_source_as_public_reference_copy(self) -> None:
        errors = self.validate_snippet(
            "index.html",
            "<section id='reference'><p><a href='https://ux.redhat.com/'>Red Hat UX reference for the public docs site</a></p></section>",
        )
        rendered = "\n".join(errors)
        self.assertIn("Red Hat UX reference", rendered)
        self.assertIn("non-source external URL", rendered)

    def test_allows_native_supervision_operator_source_link(self) -> None:
        url = (
            "https://github.com/gprocunier/complex-work-orchestration/"
            "blob/main/references/native-supervision-pools.md"
        )
        errors = self.validate_snippet(
            "workflows.html",
            f"<section id='preview'><p><a href='{url}'>Operator reference</a></p></section>",
        )
        self.assertFalse(any("non-source external URL" in error for error in errors), errors)
        self.assertFalse(any("GitHub markdown/source blob" in error for error in errors), errors)

    def test_allows_single_worker_supervision_operator_source_link(self) -> None:
        url = (
            "https://github.com/gprocunier/complex-work-orchestration/"
            "blob/main/references/native-supervision.md"
        )
        errors = self.validate_snippet(
            "native-supervision.html",
            f"<section id='reference'><p><a href='{url}'>Operator reference</a></p></section>",
        )
        self.assertFalse(any("non-source external URL" in error for error in errors), errors)
        self.assertFalse(any("GitHub markdown/source blob" in error for error in errors), errors)

    def test_rejects_duplicate_h1_and_ids(self) -> None:
        errors = self.validate_snippet(
            "workflows.html",
            "<section id='repeat'><h1>Second</h1></section><section id='repeat'></section>",
        )
        rendered = "\n".join(errors)
        self.assertIn("must contain exactly one h1; found 2", rendered)
        self.assertIn("contains duplicate id: repeat", rendered)

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

    def test_rejects_repository_file_outside_pages_publication_root(self) -> None:
        errors = self.validate_snippet("workflows.html", '<a href="../SECURITY.md">Security</a>')
        self.assertTrue(any("leaves published docs directory" in e for e in errors), errors)

    def test_rejects_unapproved_operator_source_blob(self) -> None:
        url = (
            "https://github.com/gprocunier/complex-work-orchestration/"
            "blob/main/references/unapproved.md"
        )
        errors = self.validate_snippet(
            "workflows.html",
            f"<section id='preview'><p><a href='{url}'>Unapproved source</a></p></section>",
        )
        rendered = "\n".join(errors)
        self.assertIn("non-source external URL", rendered)
        self.assertIn("GitHub markdown/source blob", rendered)

    def test_rejects_contractor_authority_public_copy(self) -> None:
        errors = self.validate_snippet(
            "use-cases.html",
            "<section id='fit'><p>Outside models can approve implementation when they agree.</p></section>",
        )
        rendered = "\n".join(internal_copy_errors(errors))
        self.assertIn("Outside models can approve", rendered)

    def test_rejects_codex_required_public_copy(self) -> None:
        errors = self.validate_snippet(
            "workflows.html",
            "<section id='fit'><p>CWO requires Codex CLI for every execution path.</p></section>",
        )
        rendered = "\n".join(internal_copy_errors(errors))
        self.assertIn("CWO requires Codex CLI", rendered)

    def test_rejects_raw_beads_comment_disclosure_copy(self) -> None:
        errors = self.validate_snippet(
            "external-contracting.html",
            "<section id='boundary'><p>Operators may send raw Beads comments to reviewers.</p></section>",
        )
        rendered = "\n".join(internal_copy_errors(errors))
        self.assertIn("send raw Beads comments", rendered)

    def test_allows_contract_label_in_pre_code_block(self) -> None:
        errors = self.validate_snippet(
            "workflows.html",
            "<section id='flow'><pre><code>contract-jd-editorial-reasoning</code></pre></section>",
        )
        self.assertEqual(internal_copy_errors(errors), [])

    def test_allows_contract_label_on_reference_page(self) -> None:
        errors = self.validate_snippet(
            "reference.html",
            "<section id='experts'><p><code>contract-jd-editorial-reasoning</code> is an operator label.</p></section>",
        )
        self.assertEqual(internal_copy_errors(errors), [])

    def test_rejects_advanced_terms_before_index_novice_ramp(self) -> None:
        errors = self.validate_snippet(
            "index.html",
            """
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
""",
        )
        rendered = "\n".join(errors)
        self.assertIn("advanced term before novice ramp: Beads", rendered)
        self.assertIn("advanced term before novice ramp: synthesis", rendered)
        self.assertIn("advanced term before novice ramp: sabotage", rendered)
        self.assertIn("advanced term before novice ramp: malpractice", rendered)
        self.assertIn("advanced term before novice ramp: quarantine", rendered)
        self.assertIn("advanced term before novice ramp: adjudication", rendered)

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

    def test_index_requires_expert_routes(self) -> None:
        errors = self.validate_snippet(
            "index.html",
            """
<section id="top"><p>Shell work should be recoverable.</p></section>
<section id="walk"><p>Now explain the ramp.</p></section>
""",
        )
        rendered = "\n".join(errors)
        self.assertIn("missing expert route link: ./workflows.html", rendered)
        self.assertIn("missing expert route link: ./use-cases.html", rendered)
        self.assertIn("missing expert route link: ./explanation.html", rendered)
        self.assertIn("missing expert route link: ./reference.html", rendered)

    def test_allows_plain_index_opening_before_walk(self) -> None:
        errors = self.validate_snippet(
            "index.html",
            """
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
""",
        )
        self.assertFalse(any("advanced term before novice ramp" in error for error in errors))
        self.assertFalse(any("missing expert route link" in error for error in errors))


if __name__ == "__main__":
    unittest.main()
