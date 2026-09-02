from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from cwo_core.public_copy import (  # noqa: E402
    validate_markdown_public_copy,
    validate_required_doc_terms,
)


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

    def test_rejects_maintainer_checklist_language_in_markdown(self) -> None:
        phrase = "Publication" + " gate"
        errors = self.validate_markdown(f"{phrase}: run the first-reader walkthrough before publishing.\n")
        rendered = "\n".join(errors)
        self.assertIn(phrase, rendered)

    def test_rejects_publication_rollback_monologue_in_markdown(self) -> None:
        phrase = "documentation" + " commit"
        errors = self.validate_markdown(
            f"Rollback the {phrase}, then start a fresh Pages deployment to restore the prior published copy.\n"
        )
        rendered = "\n".join(errors)
        self.assertIn(phrase, rendered)
        self.assertIn("fresh Pages deployment", rendered)
        self.assertIn("prior published copy", rendered)

    def test_allows_specific_operational_rollback_guidance_in_markdown(self) -> None:
        errors = self.validate_markdown(
            "Revert the documentation commit if its generated links fail validation.\n"
            "Start a fresh Pages deployment after the corrected source passes.\n"
        )
        self.assertEqual(errors, [])

    def test_allows_component_words_without_internal_process_phrase(self) -> None:
        errors = self.validate_markdown(
            "Use the canonical URL in the API walkthrough after setup.\n"
        )
        self.assertEqual(errors, [])

    def test_rejects_vague_ai_style_wording(self) -> None:
        errors = self.validate_markdown("This gives operators a powerful workflow.\n")
        rendered = "\n".join(errors)
        self.assertIn("powerful", rendered)
        self.assertIn("vague AI-style wording", rendered)

    def test_allows_forbidden_language_inside_fenced_code(self) -> None:
        phrase = "Publication" + " gate"
        errors = self.validate_markdown(f"```text\n{phrase}\n```\n")
        self.assertEqual(errors, [])

    def test_allows_reasoned_operator_reference_block(self) -> None:
        phrase = "Publication" + " gate"
        errors = self.validate_markdown(
            '<!-- cwo-public-copy: allow-start reason="operator checklist example" -->\n'
            f"{phrase}\n"
            "<!-- cwo-public-copy: allow-end -->\n"
        )
        self.assertEqual(errors, [])

    def test_allow_block_requires_reason_and_closure(self) -> None:
        errors = self.validate_markdown("<!-- cwo-public-copy: allow-start -->\n")
        rendered = "\n".join(errors)
        self.assertIn("missing reason", rendered)
        self.assertNotIn("was not closed", rendered)

    def test_public_required_doc_terms_cannot_require_forbidden_copy(self) -> None:
        term = "first-reader" + " walkthrough"
        errors = validate_required_doc_terms("docs/workflows.html", [term])
        rendered = "\n".join(errors)
        self.assertIn("required term", rendered)
        self.assertIn(term, rendered)

    def test_operator_docs_can_allow_contract_labels(self) -> None:
        errors = self.validate_markdown(
            "Use `contract-jd-editorial-reasoning` for the editor profile.\n",
            allow_internal_labels=True,
        )
        self.assertEqual(errors, [])


if __name__ == "__main__":
    unittest.main()
