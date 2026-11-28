"""Replay the historical Generation 11 validator contract witness."""

from __future__ import annotations

from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from tests.historical_campaign_launcher import REVIEWED_CAMPAIGN_SOURCE, run_archived_cases  # noqa: E402


class Generation11PreallocationContractTests(unittest.TestCase):
    def test_validator_contract_v5_adds_v10_v7_without_changing_v4(self) -> None:
        run_archived_cases(
            self, REVIEWED_CAMPAIGN_SOURCE,
            "tests.test_native_live_campaign_generation11.Generation11PreallocationContractTests."
            "test_validator_contract_v5_adds_v10_v7_without_changing_v4",
        )
