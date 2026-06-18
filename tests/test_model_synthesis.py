from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from cwo_core.routing import classify_work  # noqa: E402
from cwo_core.synthesis import (  # noqa: E402
    evaluate_synthesis_inputs,
    recommend_model_synthesis,
    synthesis_lane_enabled,
)


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

    def test_two_accepted_synthesis_inputs_are_ready(self) -> None:
        result = evaluate_synthesis_inputs(
            [
                {"lane": "chatgpt", "provider_camp": "openai", "disposition": "accepted"},
                {
                    "lane": "opus",
                    "provider_camp": "anthropic",
                    "disposition": "accepted-with-modification",
                },
            ]
        )

        self.assertEqual(result["status"], "ready")
        self.assertFalse(result["blocked"])
        self.assertEqual(result["usable_input_count"], 2)
        self.assertEqual([item["synthesis_use"] for item in result["input_summaries"]], ["primary", "primary"])

    def test_gemini_accepted_input_defaults_to_salvage_only(self) -> None:
        result = evaluate_synthesis_inputs(
            [
                {"lane": "gemini", "provider_camp": "google", "disposition": "accepted"},
                {"lane": "opus", "provider_camp": "anthropic", "disposition": "accepted"},
            ]
        )

        self.assertEqual(result["status"], "blocked")
        self.assertEqual(result["usable_input_count"], 1)
        self.assertEqual(result["salvage_input_count"], 1)
        self.assertEqual(result["input_summaries"][0]["synthesis_use"], "salvage-only")
        self.assertIn("salvage-only inputs do not satisfy minimum_usable_inputs", result["blocked_reasons"])

    def test_gemini_salvage_does_not_block_when_two_primary_inputs_remain(self) -> None:
        result = evaluate_synthesis_inputs(
            [
                {"lane": "gemini", "provider_camp": "google", "disposition": "accepted"},
                {"lane": "opus", "provider_camp": "anthropic", "disposition": "accepted"},
                {"lane": "chatgpt", "provider_camp": "openai", "disposition": "accepted-with-modification"},
            ]
        )

        self.assertEqual(result["status"], "ready")
        self.assertFalse(result["blocked"])
        self.assertEqual(result["usable_input_count"], 2)
        self.assertEqual(result["salvage_input_count"], 1)

    def test_explicit_primary_override_can_upgrade_gemini_after_adjudication(self) -> None:
        result = evaluate_synthesis_inputs(
            [
                {
                    "lane": "gemini",
                    "provider_camp": "google",
                    "disposition": "accepted",
                    "synthesis_use": "primary",
                    "reason": "architect upgraded one evaluated finding",
                },
                {"lane": "opus", "provider_camp": "anthropic", "disposition": "accepted"},
            ]
        )

        self.assertEqual(result["status"], "ready")
        self.assertEqual(result["usable_input_count"], 2)
        self.assertEqual(result["salvage_input_count"], 0)
        self.assertEqual(result["input_summaries"][0]["synthesis_use"], "primary")

    def test_invalid_synthesis_use_cannot_upgrade_gemini(self) -> None:
        result = evaluate_synthesis_inputs(
            [
                {
                    "lane": "gemini",
                    "provider_camp": "google",
                    "disposition": "accepted",
                    "synthesis_use": "definitely-primary",
                },
                {"lane": "opus", "provider_camp": "anthropic", "disposition": "accepted"},
            ]
        )

        self.assertEqual(result["status"], "blocked")
        self.assertEqual(result["usable_input_count"], 1)
        self.assertEqual(result["salvage_input_count"], 1)
        self.assertEqual(result["input_summaries"][0]["synthesis_use"], "salvage-only")

    def test_all_salvage_only_inputs_do_not_make_synthesis_ready(self) -> None:
        result = evaluate_synthesis_inputs(
            [
                {"lane": "gemini", "provider_camp": "google", "disposition": "accepted"},
                {"lane": "manual", "provider_camp": "openai", "disposition": "accepted", "synthesis_use": "salvage-only"},
            ]
        )

        self.assertEqual(result["status"], "blocked")
        self.assertEqual(result["usable_input_count"], 0)
        self.assertEqual(result["salvage_input_count"], 2)
        self.assertIn("salvage-only inputs do not satisfy minimum_usable_inputs", result["blocked_reasons"])

    def test_open_risk_differs_from_salvage_only(self) -> None:
        result = evaluate_synthesis_inputs(
            [
                {"lane": "chatgpt", "provider_camp": "openai", "disposition": "accepted"},
                {"lane": "opus", "provider_camp": "anthropic", "disposition": "accepted"},
                {"lane": "risk", "provider_camp": "local", "disposition": "needs-investigation"},
            ]
        )

        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["usable_input_count"], 2)
        self.assertEqual(result["open_risk_input_count"], 1)
        self.assertEqual(result["salvage_input_count"], 0)

    def test_recommended_synthesis_use_salvage_only_is_honored(self) -> None:
        result = evaluate_synthesis_inputs(
            [
                {
                    "lane": "outside-critic",
                    "provider_camp": "anthropic",
                    "disposition": "accepted",
                    "recommended_synthesis_use": "salvage-only",
                },
                {"lane": "chatgpt", "provider_camp": "openai", "disposition": "accepted"},
            ]
        )

        self.assertEqual(result["status"], "blocked")
        self.assertEqual(result["usable_input_count"], 1)
        self.assertEqual(result["salvage_input_count"], 1)

    def test_missing_empty_and_timeout_inputs_do_not_satisfy_minimum(self) -> None:
        result = evaluate_synthesis_inputs(
            [
                {"lane": "gemini", "disposition": "accepted"},
                {"lane": "opus", "disposition": "timed-out"},
                {"lane": "chatgpt", "disposition": "missing"},
                {"lane": "local", "disposition": "empty"},
            ]
        )

        self.assertEqual(result["status"], "blocked")
        self.assertTrue(result["blocked"])
        self.assertEqual(result["usable_input_count"], 1)
        self.assertEqual(result["partial_input_count"], 3)
        self.assertIn(
            "fewer than minimum_usable_inputs accepted or accepted-with-modification inputs",
            result["blocked_reasons"],
        )

    def test_partial_synthesis_is_ready_when_minimum_primary_inputs_remain(self) -> None:
        result = evaluate_synthesis_inputs(
            [
                {"lane": "gemini", "disposition": "accepted"},
                {"lane": "opus", "disposition": "accepted-with-modification"},
                {"lane": "chatgpt", "disposition": "timed-out"},
                {"lane": "local", "disposition": "needs-investigation"},
            ]
        )

        self.assertEqual(result["status"], "partial")
        self.assertFalse(result["blocked"])
        self.assertEqual(result["usable_input_count"], 2)
        self.assertEqual(result["partial_input_count"], 1)
        self.assertEqual(result["open_risk_input_count"], 1)

    def test_quarantined_and_boundary_tainted_external_inputs_block_synthesis(self) -> None:
        result = evaluate_synthesis_inputs(
            [
                {"lane": "gemini", "disposition": "quarantined", "external": True},
                {"lane": "opus", "disposition": "accepted", "boundary_taint_status": "boundary-tainted"},
            ]
        )

        self.assertEqual(result["status"], "blocked")
        self.assertEqual(result["usable_input_count"], 0)
        self.assertEqual(result["quarantined_input_count"], 2)
        self.assertEqual(result["input_summaries"][1]["effective_disposition"], "boundary-tainted")
        self.assertIn("all external inputs are quarantined or boundary-tainted", result["blocked_reasons"])

    def test_rejected_and_failed_inputs_are_excluded_from_minimum(self) -> None:
        result = evaluate_synthesis_inputs(
            [
                {"lane": "gemini", "disposition": "accepted"},
                {"lane": "opus", "disposition": "rejected"},
                {"lane": "chatgpt", "disposition": "failed-evaluation"},
            ]
        )

        self.assertEqual(result["status"], "blocked")
        self.assertEqual(result["usable_input_count"], 1)
        self.assertEqual(result["rejected_input_count"], 2)
        self.assertIn(
            "fewer than minimum_usable_inputs accepted or accepted-with-modification inputs",
            result["blocked_reasons"],
        )

    def test_empty_synthesis_input_set_is_blocked(self) -> None:
        result = evaluate_synthesis_inputs([])

        self.assertEqual(result["status"], "blocked")
        self.assertEqual(result["input_count"], 0)
        self.assertIn(
            "fewer than minimum_usable_inputs accepted or accepted-with-modification inputs",
            result["blocked_reasons"],
        )


if __name__ == "__main__":
    unittest.main()
