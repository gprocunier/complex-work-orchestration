from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

from typing import Iterator, NamedTuple
from tests.structural_assertions import Check, assert_checks

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from cwo_core.public_copy import (  # noqa: E402
    validate_markdown_public_copy,
    validate_required_doc_terms,
)


class PublicCopyCase(NamedTuple):
    original: str
    text: str
    options: dict
    checks: tuple[Check, ...]


def _markdown_public_copy_rows() -> Iterator[PublicCopyCase]:
    phrase = "Publication" + " gate"
    yield PublicCopyCase('test_rejects_maintainer_checklist_language_in_markdown', f"{phrase}: run the first-reader walkthrough before publishing.\n", {}, (
        Check(lambda result: '\n'.join(result), phrase, 'contains'),
    ))

    phrase = "documentation" + " commit"
    yield PublicCopyCase('test_rejects_publication_rollback_monologue_in_markdown', f"Rollback the {phrase}, then start a fresh Pages deployment to restore the prior published copy.\n", {}, (
        Check(lambda result: '\n'.join(result), phrase, 'contains'),
        Check(lambda result: '\n'.join(result), 'fresh Pages deployment', 'contains'),
        Check(lambda result: '\n'.join(result), 'prior published copy', 'contains'),
    ))

    yield PublicCopyCase('test_allows_specific_operational_rollback_guidance_in_markdown', "Revert the documentation commit if its generated links fail validation.\n"
        "Start a fresh Pages deployment after the corrected source passes.\n", {}, (
        Check(lambda result: result, []),
    ))

    yield PublicCopyCase('test_allows_component_words_without_internal_process_phrase', "Use the canonical URL in the API walkthrough after setup.\n", {}, (
        Check(lambda result: result, []),
    ))

    yield PublicCopyCase('test_rejects_vague_ai_style_wording', "This gives operators a powerful workflow.\n", {}, (
        Check(lambda result: '\n'.join(result), 'powerful', 'contains'),
        Check(lambda result: '\n'.join(result), 'vague AI-style wording', 'contains'),
    ))

    phrase = "Publication" + " gate"
    yield PublicCopyCase('test_allows_forbidden_language_inside_fenced_code', f"```text\n{phrase}\n```\n", {}, (
        Check(lambda result: result, []),
    ))

    phrase = "Publication" + " gate"
    yield PublicCopyCase('test_allows_reasoned_operator_reference_block', '<!-- cwo-public-copy: allow-start reason="operator checklist example" -->\n'
        f"{phrase}\n"
        "<!-- cwo-public-copy: allow-end -->\n", {}, (
        Check(lambda result: result, []),
    ))

    yield PublicCopyCase('test_allow_block_requires_reason_and_closure', "<!-- cwo-public-copy: allow-start -->\n", {}, (
        Check(lambda result: '\n'.join(result), 'missing reason', 'contains'),
        Check(lambda result: '\n'.join(result), 'was not closed', 'not-contains'),
    ))

    yield PublicCopyCase('test_operator_docs_can_allow_contract_labels', "Use `contract-jd-editorial-reasoning` for the editor profile.\n", {'allow_internal_labels': True}, (
        Check(lambda result: result, []),
    ))


class PublicCopyTests(unittest.TestCase):
    def validate_markdown(self, text: str, *, allow_internal_labels: bool = False) -> list[str]:
        with tempfile.TemporaryDirectory(dir=ROOT) as tmpdir:
            path = Path(tmpdir) / "doc.md"
            path.write_text(text, encoding="utf-8")
            return validate_markdown_public_copy(
                path,
                source_name="doc.md",
                allow_internal_labels=allow_internal_labels,
            )

    def test_markdown_public_copy_rows(self) -> None:
        for row in _markdown_public_copy_rows():
            with self.subTest(original=row.original):
                result = self.validate_markdown(row.text, **row.options)
                assert_checks(self, result, row.checks)


    def test_public_required_doc_terms_cannot_require_forbidden_copy(self) -> None:
        term = "first-reader" + " walkthrough"
        errors = validate_required_doc_terms("docs/workflows.html", [term])
        rendered = "\n".join(errors)
        self.assertIn("required term", rendered)
        self.assertIn(term, rendered)


if __name__ == "__main__":
    unittest.main()
