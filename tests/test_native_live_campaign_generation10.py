"""Replay the historical Generation 10 validator contract witness."""

from __future__ import annotations

from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from tests.historical_campaign_launcher import REVIEWED_CAMPAIGN_SOURCE, run_archived_cases  # noqa: E402


class Generation10ProtectedFaultContractTests(unittest.TestCase):
    def test_validator_contract_v4_adds_v9_v6_without_changing_v1_v2_v3(self) -> None:
        run_archived_cases(
            self, REVIEWED_CAMPAIGN_SOURCE,
            "tests.test_native_live_campaign_generation10.Generation10ProtectedFaultContractTests."
            "test_validator_contract_v4_adds_v9_v6_without_changing_v1_v2_v3",
        )
