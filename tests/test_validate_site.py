from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from validate_site import validate_html  # noqa: E402


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

    def test_rejects_design_source_as_public_reference_copy(self) -> None:
        errors = self.validate_snippet(
            "index.html",
            "<section id='reference'><p><a href='https://ux.redhat.com/'>Red Hat UX reference for the public docs site</a></p></section>",
        )
        rendered = "\n".join(errors)
        self.assertIn("Red Hat UX reference", rendered)
        self.assertIn("non-source external URL", rendered)

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


if __name__ == "__main__":
    unittest.main()
