"""Archived campaign validation with the matching release source and fixtures."""

from __future__ import annotations

from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from tests.historical_campaign_launcher import RETIRED_CAMPAIGN, run_archived_cases  # noqa: E402


class ArchivedCampaignContractTests(unittest.TestCase):
    def test_generation_contracts_and_launcher_bindings(self) -> None:
        run_archived_cases(
            self, RETIRED_CAMPAIGN,
            *(f"tests.test_native_live_campaign_generation{generation}" for generation in range(8, 13)),
            *(f"tests.test_generation{generation}_live_launcher" for generation in range(8, 13)),
            "tests.test_post_move_campaign_gate.ValidatorContractV6TreeTests."
            "test_the_gate_stays_while_the_operative_tuple_selects_v6",
        )

    def test_manifest_renderer_and_release_patch(self) -> None:
        run_archived_cases(
            self, RETIRED_CAMPAIGN,
            "tests.test_native_pool_config.NativePoolConfigTests.test_historical_manifest_versions_are_not_live_renderable",
            "tests.test_native_pool_config.NativePoolConfigTests.test_v8_manifest_requires_exact_full_binding_receipt",
            "tests.test_run_native_pool_live_canaries.FullAutoAuthorizationLauncherTests."
            "test_release_patch_is_bound_to_candidate_and_prospective_tree",
        )


if __name__ == "__main__":
    unittest.main()
