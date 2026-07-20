from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from cwo_core.policy import native_authorized_worker_models, native_spark_model  # noqa: E402
import validate_repository  # noqa: E402


class NativeModelPolicyTests(unittest.TestCase):
    def test_native_spark_model_matches_execution_policy(self) -> None:
        self.assertEqual(native_spark_model(), "gpt-5.3-codex-spark")

    def test_authorized_models_include_preferred(self) -> None:
        self.assertIn(native_spark_model(), native_authorized_worker_models())

    def test_repository_pins_are_consistent(self) -> None:
        errors: list[str] = []
        validate_repository.validate_native_model_consistency(errors)
        self.assertEqual(errors, [])

    def test_scanner_matches_worker_model_family_tokens(self) -> None:
        token = "gpt-9.9-codex-spark"
        self.assertEqual(
            validate_repository.NATIVE_MODEL_TOKEN_RE.findall(f"model: {token}"),
            [token],
        )
        self.assertEqual(
            validate_repository.NATIVE_MODEL_TOKEN_RE.findall("gpt-5 and gpt 5.5 pro"),
            [],
        )


if __name__ == "__main__":
    unittest.main()
