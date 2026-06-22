from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from validate_repository import (  # noqa: E402
    CI_REQUIRED_COMMANDS,
    validate_ci_workflow,
    validate_local_inference_peer_review_guidance,
    validate_public_docs_do_not_expose_hardware_categories,
    validate_repository,
)


class ValidateRepositoryTests(unittest.TestCase):
    def test_repository_control_plane_is_consistent(self) -> None:
        self.assertEqual(validate_repository(), [])

    def test_missing_ci_workflow_is_allowed_for_installed_skill_layout(self) -> None:
        errors: list[str] = []
        with tempfile.TemporaryDirectory() as tmpdir:
            validate_ci_workflow(errors, Path(tmpdir) / "missing.yml")
        self.assertEqual(errors, [])

    def test_present_ci_workflow_still_enforces_required_commands(self) -> None:
        errors: list[str] = []
        with tempfile.TemporaryDirectory() as tmpdir:
            ci_path = Path(tmpdir) / "ci.yml"
            ci_path.write_text(CI_REQUIRED_COMMANDS[0], encoding="utf-8")
            validate_ci_workflow(errors, ci_path)
        self.assertIn(f"CI workflow is missing required command: {CI_REQUIRED_COMMANDS[1]}", errors)
        self.assertIn(f"CI workflow is missing required command: {CI_REQUIRED_COMMANDS[2]}", errors)

    def test_local_inference_evaluator_peer_review_guidance_is_route_derived(self) -> None:
        errors: list[str] = []
        validate_local_inference_peer_review_guidance(
            errors,
            content=(
                "python3 scripts/evaluate_return.py --file local-return.md\n"
                "--executor openshift_ai_vllm_worker\n"
                "provider_trust_tier\n"
                "provenance_class\n"
                "Add `--peer-review-required` only when route_work.py or evaluator policy requires it.\n"
            ),
        )
        self.assertEqual(errors, [])

    def test_local_inference_rejects_unconditional_peer_review_flag(self) -> None:
        errors: list[str] = []
        validate_local_inference_peer_review_guidance(
            errors,
            content="python3 scripts/evaluate_return.py --file local-return.md --peer-review-required\n",
        )
        self.assertTrue(any("unconditional --peer-review-required" in error for error in errors))

    def test_public_docs_reject_hardware_specific_category_terms(self) -> None:
        errors: list[str] = []
        with tempfile.TemporaryDirectory() as tmpdir:
            public_doc = Path(tmpdir) / "page.html"
            public_doc.write_text("Use H200/CerIO Enterprise Candidates.", encoding="utf-8")
            validate_public_docs_do_not_expose_hardware_categories(errors, [public_doc])
        self.assertTrue(any("hardware-specific public category terms" in error for error in errors))

    def test_public_docs_allow_generic_enterprise_targets(self) -> None:
        errors: list[str] = []
        with tempfile.TemporaryDirectory() as tmpdir:
            public_doc = Path(tmpdir) / "page.html"
            public_doc.write_text("Use Enterprise evaluation targets after a benchmark gate.", encoding="utf-8")
            validate_public_docs_do_not_expose_hardware_categories(errors, [public_doc])
        self.assertEqual(errors, [])


if __name__ == "__main__":
    unittest.main()
