from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from cwo_core.routing import classify_work  # noqa: E402
from cwo_core.synthesis import recommend_model_synthesis, synthesis_lane_enabled  # noqa: E402


class ModelSynthesisTests(unittest.TestCase):
    def test_route_result_carries_inactive_recommendation(self) -> None:
        route = classify_work(
            "Refactor the orchestration control plane across routing, schema validation, docs, and CI.",
            requested_roles=["architecture"],
        )
        synthesis = route["model_synthesis"]

        self.assertEqual(synthesis["recommended_mode"], "recommended")
        self.assertEqual(synthesis["activation_state"], "recommended")
        self.assertFalse(synthesis["active"])
        self.assertTrue(synthesis["requires_user_acceptance"])
        self.assertFalse(synthesis_lane_enabled(synthesis))
        self.assertIn("accepted", synthesis["active_modes"])

    def test_explicit_synthesis_request_is_active(self) -> None:
        route = classify_work(
            "Use model synthesis to combine Claude Opus, Gemini, and ChatGPT Pro findings.",
            external_ok=True,
            share_boundary="redacted-packet",
            requested_roles=["architecture"],
        )
        synthesis = route["model_synthesis"]

        self.assertEqual(synthesis["recommended_mode"], "requested")
        self.assertTrue(synthesis["active"])
        self.assertTrue(synthesis_lane_enabled(synthesis))
        self.assertIn("input evaluator dispositions", synthesis["artifact_contract"])
        self.assertIn("partial or missing lane summary", synthesis["artifact_contract"])

    def test_accepted_synthesis_opt_in_is_active(self) -> None:
        text = "Refactor a high-risk architecture policy route."
        route = classify_work(text, requested_roles=["architecture"])
        synthesis = recommend_model_synthesis(text, route, force_accepted=True)

        self.assertEqual(synthesis["recommended_mode"], "accepted")
        self.assertEqual(synthesis["activation_state"], "accepted")
        self.assertTrue(synthesis["active"])
        self.assertFalse(synthesis["prompt_user_in_plan_mode"])
        self.assertTrue(synthesis_lane_enabled(synthesis))

    def test_provider_conflict_and_partial_disposition_contracts_are_carried(self) -> None:
        route = classify_work(
            "Review a Claude Mythos eval harness for a frontier model provider competitor.",
            external_ok=True,
            share_boundary="redacted-packet",
            requested_roles=["general-reasoning"],
        )
        synthesis = route["model_synthesis"]

        self.assertEqual(synthesis["recommended_mode"], "recommended")
        self.assertFalse(synthesis["active"])
        self.assertTrue(synthesis["provider_conflict_flags"])
        self.assertEqual(synthesis["provider_conflict_flags"][0]["kind"], "route-provider-conflict")
        self.assertIn("frontier-ai-development", synthesis["provider_conflict_flags"][0]["domains"])
        self.assertIn("quarantined", synthesis["input_disposition_policy"]["quarantine"])
        self.assertIn("timed-out", synthesis["input_disposition_policy"]["partial_only"])
        self.assertTrue(synthesis["partial_synthesis_policy"]["allow_partial"])


if __name__ == "__main__":
    unittest.main()
