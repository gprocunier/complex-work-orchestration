from __future__ import annotations

import importlib
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))


class ReturnsFacadeTests(unittest.TestCase):
    def test_returns_all_names_resolve(self) -> None:
        import cwo_core.returns as returns  # noqa: E402

        missing = [name for name in returns.__all__ if not hasattr(returns, name)]
        self.assertEqual(missing, [])

    def test_returns_facade_points_to_extracted_modules(self) -> None:
        import cwo_core.return_boundary as return_boundary  # noqa: E402
        import cwo_core.return_evidence as return_evidence  # noqa: E402
        import cwo_core.return_sections as return_sections  # noqa: E402
        import cwo_core.returns as returns  # noqa: E402

        self.assertIs(returns.SectionReader, return_sections.SectionReader)
        self.assertIs(returns.parse_return_sections, return_sections.parse_return_sections)
        self.assertIs(returns.redacted_boundary_taint_findings, return_boundary.redacted_boundary_taint_findings)
        self.assertIs(returns.score_evidence_quality, return_evidence.score_evidence_quality)

    def test_extracted_modules_import_in_isolation(self) -> None:
        for module in [
            "cwo_core.return_common",
            "cwo_core.return_sections",
            "cwo_core.return_boundary",
            "cwo_core.return_evidence",
            "cwo_core.types",
            "cwo_core.errors",
        ]:
            with self.subTest(module=module):
                importlib.import_module(module)

    def test_return_sections_preserve_parser_behavior(self) -> None:
        from cwo_core.return_sections import SectionReader, parse_return_sections  # noqa: E402

        text = """### Status
complete

**Contractor job description:** contract-jd-security-reasoning
### Summary
Parser smoke.
```text
### Evidence
not a section
```
### Evidence
- policy excerpt
"""
        sections = parse_return_sections(text)
        reader = SectionReader(sections)

        self.assertEqual(reader.value("Status"), "complete")
        self.assertEqual(reader.value("Contractor job description"), "contract-jd-security-reasoning")
        self.assertIn("not a section", reader.value("Summary"))
        self.assertEqual(reader.value("Evidence"), "- policy excerpt")

    def test_boundary_helpers_preserve_redacted_packet_taint(self) -> None:
        from cwo_core.return_boundary import redacted_boundary_taint_findings  # noqa: E402

        sections = {
            "Commands run": "python scripts/validate_repository.py",
            "Validation result": "tests passed",
        }

        findings = redacted_boundary_taint_findings(
            "I inspected the repository.",
            sections,
            share_boundary="redacted-packet",
        )

        self.assertIn("redacted packet return claims command or test execution", findings)
        self.assertIn("redacted packet return claims unsupported validation", findings)
        self.assertIn("redacted packet return claims direct repository or workspace inspection", findings)

    def test_type_and_error_contracts_import(self) -> None:
        from cwo_core.errors import CWOError, CWOValidationError  # noqa: E402
        from cwo_core.types import AcceptanceDecision, ContractorReturnBundle  # noqa: E402

        self.assertTrue(issubclass(CWOValidationError, CWOError))
        self.assertEqual(AcceptanceDecision.__name__, "AcceptanceDecision")
        self.assertEqual(ContractorReturnBundle.__name__, "ContractorReturnBundle")


if __name__ == "__main__":
    unittest.main()
