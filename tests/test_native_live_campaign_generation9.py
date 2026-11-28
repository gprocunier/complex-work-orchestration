"""Replay the historical Generation 9 validator contract witness."""

from __future__ import annotations

from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from tests.historical_campaign_launcher import REVIEWED_CAMPAIGN_SOURCE, run_archived_cases  # noqa: E402


class Generation9QuarantineContractTests(unittest.TestCase):
    def test_validator_contract_v3_adds_schema_blobs_without_changing_v1_v2(self) -> None:
        run_archived_cases(
            self, REVIEWED_CAMPAIGN_SOURCE,
            "tests.test_native_live_campaign_generation9.Generation9QuarantineContractTests."
            "test_validator_contract_v3_adds_schema_blobs_without_changing_v1_v2",
        )
