from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from cwo_core.policy import load_policy  # noqa: E402
from cwo_core.return_risk import sabotage_thresholds  # noqa: E402
import validate_repository  # noqa: E402


class SabotageThresholdSingleSourceTests(unittest.TestCase):
    def test_effective_thresholds_come_from_contracting_controls(self) -> None:
        self.assertEqual(
            sabotage_thresholds(),
            {"review": 20, "architect_escalation": 35, "quarantine": 50},
        )

    def test_explicit_overrides_still_apply(self) -> None:
        result = sabotage_thresholds(review_threshold=5, quarantine_threshold=99)
        self.assertEqual(result["review"], 5)
        self.assertEqual(result["quarantine"], 99)
        self.assertEqual(result["architect_escalation"], 35)

    def test_shadow_threshold_blocks_are_absent(self) -> None:
        self.assertIsNone(load_policy("acceptance-policy").get("sabotage", {}).get("thresholds"))
        self.assertIsNone(load_policy("peer-review-policy").get("sabotage_thresholds"))

    def test_contracting_controls_declares_threshold_authority(self) -> None:
        sabotage_policy = load_policy("contracting-controls").get("sabotage_policy", {})
        self.assertIn("single-source", str(sabotage_policy.get("threshold_authority", "")))

    def test_validator_flags_shadow_threshold_blocks(self) -> None:
        errors: list[str] = []
        validate_repository.validate_sabotage_threshold_single_source(
            errors,
            acceptance_policy={"sabotage": {"thresholds": {"review": 30}}},
            peer_review={"sabotage_thresholds": {"review": 30}},
            controls={"sabotage_policy": {"thresholds": {"peer_review": 20, "architect_escalation": 35, "quarantine": 50}}},
        )
        self.assertEqual(len(errors), 2, errors)

    def test_validator_requires_integer_thresholds(self) -> None:
        errors: list[str] = []
        validate_repository.validate_sabotage_threshold_single_source(
            errors,
            acceptance_policy={},
            peer_review={},
            controls={"sabotage_policy": {"thresholds": {"peer_review": "20"}}},
        )
        self.assertTrue(any("must be an integer" in error for error in errors), errors)


if __name__ == "__main__":
    unittest.main()
