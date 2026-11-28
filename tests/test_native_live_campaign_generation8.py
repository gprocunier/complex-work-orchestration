"""Replay the historical Generation 8 validator contract witness."""

from __future__ import annotations

from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from tests.historical_campaign_launcher import REVIEWED_CAMPAIGN_SOURCE, run_archived_cases  # noqa: E402


class Generation8FiniteDagContractTests(unittest.TestCase):
    def test_v1_digest_is_frozen_and_v2_requires_the_new_schema_blobs(self) -> None:
        run_archived_cases(
            self, REVIEWED_CAMPAIGN_SOURCE,
            "tests.test_native_live_campaign_generation8.Generation8FiniteDagContractTests."
            "test_v1_digest_is_frozen_and_v2_requires_the_new_schema_blobs",
        )
