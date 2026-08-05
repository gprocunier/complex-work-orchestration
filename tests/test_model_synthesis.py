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

    def test_default_codex_synthesis_owner_uses_sol_label(self) -> None:
        route = classify_work(
            "Use model synthesis with Codex 5.6 Sol, Claude Opus, and Gemini.",
            external_ok=True,
            share_boundary="redacted-packet",
            requested_roles=["architecture"],
        )
        panel = {item["executor"]: item for item in route["model_synthesis"]["recommended_panel"]}

        self.assertEqual(panel["frontier_architect"]["role"], "synthesis-owner")
        self.assertEqual(panel["frontier_architect"]["effort"], "codex-5.6-sol")

    def test_explicit_critic_contracts_constrain_synthesis_panel(self) -> None:
        route = classify_work(
            "Use Claude Opus and GLM as architecture critics. "
            "The critic panel is closed to those two providers. "
            "Do not add Gemini or ChatGPT Pro.",
            external_ok=True,
            local_ok=True,
            share_boundary="redacted-packet",
            requested_roles=["architecture"],
            model_synthesis=True,
        )
        synthesis = route["model_synthesis"]

        self.assertEqual(
            [item["executor"] for item in synthesis["recommended_panel"]],
            [
                "frontier_architect",
                "claude_architecture_critic",
                "rhoai_glm_hardened_architecture_critic",
            ],
        )
        self.assertEqual(synthesis["mentioned_provider_camps"], ["anthropic", "local"])
        self.assertTrue(synthesis["active"])

    def test_explicit_provider_exclusion_filters_generic_synthesis_panel(self) -> None:
        route = classify_work(
            "Use model synthesis without Gemini.",
            requested_roles=["architecture"],
        )

        self.assertEqual(route["model_synthesis"]["recommended_mode"], "requested")
        self.assertTrue(route["model_synthesis"]["active"])
        executors = [
            item["executor"] for item in route["model_synthesis"]["recommended_panel"]
        ]
        self.assertNotIn("gemini_architecture_critic", executors)
        self.assertNotIn("google", route["model_synthesis"]["mentioned_provider_camps"])

    def test_natural_language_synthesis_prohibitions_disable_the_lane(self) -> None:
        prompts = [
            "No model synthesis.",
            "Proceed without model synthesis.",
            "Do not use model synthesis; direct adjudication.",
        ]
        for text in prompts:
            with self.subTest(text=text):
                route = classify_work(text, requested_roles=["architecture"])
                synthesis = route["model_synthesis"]

                self.assertEqual(synthesis["recommended_mode"], "disabled")
                self.assertEqual(synthesis["activation_state"], "disabled")
                self.assertFalse(synthesis["active"])
                self.assertFalse(synthesis_lane_enabled(synthesis))
                self.assertFalse(synthesis["requires_user_acceptance"])
                self.assertFalse(synthesis["prompt_user_in_plan_mode"])
                self.assertEqual(synthesis["recommended_panel"], [])
                self.assertEqual(synthesis["mentioned_provider_camps"], [])
                self.assertEqual(synthesis["artifact_contract"], [])
                self.assertEqual(route["hard_stops"], [])

    def test_conflicting_natural_language_synthesis_intent_disables_and_stops(self) -> None:
        route = classify_work(
            "Use model synthesis. Do not use model synthesis.",
            requested_roles=["architecture"],
        )

        self.assertEqual(route["model_synthesis"]["recommended_mode"], "disabled")
        self.assertFalse(route["model_synthesis"]["active"])
        self.assertIn(
            "conflicting model synthesis intent: synthesis is both requested and prohibited",
            route["hard_stops"],
        )

    def test_accepted_synthesis_opt_in_is_active(self) -> None:
        text = "Refactor a high-risk architecture policy route."
        route = classify_work(text, requested_roles=["architecture"])
        synthesis = recommend_model_synthesis(text, route, force_accepted=True)

        self.assertEqual(synthesis["recommended_mode"], "accepted")
        self.assertEqual(synthesis["activation_state"], "accepted")
        self.assertTrue(synthesis["active"])
        self.assertFalse(synthesis["prompt_user_in_plan_mode"])
        self.assertTrue(synthesis_lane_enabled(synthesis))

    def test_disabled_synthesis_takes_precedence_over_accepted_opt_in(self) -> None:
        text = "Use model synthesis for a high-risk architecture policy route."
        route = classify_work(text, requested_roles=["architecture"])
        synthesis = recommend_model_synthesis(text, route, force_accepted=True, disabled=True)

        self.assertEqual(synthesis["recommended_mode"], "disabled")
        self.assertFalse(synthesis["active"])
        self.assertFalse(synthesis_lane_enabled(synthesis))
        self.assertEqual(synthesis["trigger_reasons"], [])

    def test_high_risk_architecture_work_recommends_synthesis_without_explicit_request(self) -> None:
        synthesis = recommend_model_synthesis(
            "Redesign the architecture boundary for a high-risk release workflow.",
            {
                "risk_level": "high",
                "task_class": "architecture-review",
                "share_boundary": "redacted-packet",
            },
        )

        self.assertEqual(synthesis["recommended_mode"], "recommended")
        self.assertTrue(synthesis["requires_user_acceptance"])
        self.assertFalse(synthesis["active"])
        self.assertIn("high-risk architecture work", synthesis["trigger_reasons"])

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

    def test_glm_local_input_is_primary_eligible_while_gemini_remains_salvage(self) -> None:
        result = evaluate_synthesis_inputs(
            [
                {"lane": "glm", "provider_camp": "local", "disposition": "accepted"},
                {"lane": "opus", "provider_camp": "anthropic", "disposition": "accepted"},
                {"lane": "gemini", "provider_camp": "google", "disposition": "accepted"},
            ]
        )

        self.assertEqual(result["status"], "ready")
        self.assertEqual(result["usable_input_count"], 2)
        self.assertEqual(result["salvage_input_count"], 1)
        self.assertEqual(result["input_summaries"][0]["synthesis_use"], "primary")
        self.assertEqual(result["input_summaries"][2]["synthesis_use"], "salvage-only")

    def test_explicit_primary_override_can_upgrade_gemini_after_adjudication(self) -> None:
        result = evaluate_synthesis_inputs(
            [
                {
                    "lane": "gemini",
                    "provider_camp": "google",
                    "disposition": "accepted",
                    "synthesis_use": "primary",
                    "synthesis_use_authority": "architect",
                    "reason": "architect upgraded one evaluated finding",
                },
                {"lane": "opus", "provider_camp": "anthropic", "disposition": "accepted"},
            ]
        )

        self.assertEqual(result["status"], "ready")
        self.assertEqual(result["usable_input_count"], 2)
        self.assertEqual(result["salvage_input_count"], 0)
        self.assertEqual(result["input_summaries"][0]["synthesis_use"], "primary")

    def test_primary_override_without_architect_authority_cannot_upgrade_gemini(self) -> None:
        result = evaluate_synthesis_inputs(
            [
                {
                    "lane": "gemini",
                    "provider_camp": "google",
                    "disposition": "accepted",
                    "synthesis_use": "primary",
                },
                {"lane": "opus", "provider_camp": "anthropic", "disposition": "accepted"},
            ]
        )

        self.assertEqual(result["status"], "blocked")
        self.assertEqual(result["input_summaries"][0]["synthesis_use"], "salvage-only")

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
        self.assertIsNone(result["input_summaries"][0]["requested_synthesis_use"])

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

    def test_partial_synthesis_disabled_blocks_otherwise_ready_partial_result(self) -> None:
        policy = {
            "input_disposition_policy": {
                "use_as_synthesis_input": ["accepted", "accepted-with-modification"],
                "partial_only": ["timed-out"],
                "summarize_as_open_risk": ["needs-investigation"],
                "quarantine": ["quarantined", "boundary-tainted"],
                "exclude_as_rejected": ["rejected", "failed-evaluation"],
            },
            "partial_synthesis_policy": {
                "allow_partial": False,
                "minimum_usable_inputs": 2,
                "partial_status": "partial",
            },
            "salvage_only_provider_camps": [],
        }

        result = evaluate_synthesis_inputs(
            [
                {"lane": "opus", "disposition": "accepted"},
                {"lane": "chatgpt", "disposition": "accepted-with-modification"},
                {"lane": "risk", "disposition": "needs-investigation"},
            ],
            policy=policy,
        )

        self.assertEqual(result["status"], "blocked")
        self.assertTrue(result["blocked"])
        self.assertFalse(result["allow_partial"])
        self.assertIn("partial synthesis is disabled by policy", result["blocked_reasons"])

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

    def test_boundary_taint_overrides_requested_primary_synthesis_use(self) -> None:
        result = evaluate_synthesis_inputs(
            [
                {
                    "lane": "opus",
                    "provider_camp": "anthropic",
                    "disposition": "accepted",
                    "boundary_taint_status": "boundary-tainted",
                    "synthesis_use": "primary",
                },
                {"lane": "chatgpt", "provider_camp": "openai", "disposition": "accepted"},
            ]
        )

        self.assertEqual(result["status"], "blocked")
        self.assertEqual(result["usable_input_count"], 1)
        self.assertEqual(result["quarantined_input_count"], 1)
        self.assertEqual(result["input_summaries"][0]["synthesis_use"], "quarantine")
        self.assertEqual(result["input_summaries"][0]["requested_synthesis_use"], "primary")

    def test_process_hold_blocks_primary_synthesis_without_architect_override(self) -> None:
        result = evaluate_synthesis_inputs(
            [
                {
                    "lane": "opus",
                    "provider_camp": "anthropic",
                    "disposition": "accepted",
                    "recommended_synthesis_use": "primary",
                    "implementation_blocked": True,
                    "hold_classification": "provider-conflict-pending",
                    "hold_reasons": ["provider-conflict-peer-review-pending"],
                },
                {"lane": "chatgpt", "provider_camp": "openai", "disposition": "accepted"},
            ]
        )

        self.assertEqual(result["status"], "blocked")
        self.assertEqual(result["usable_input_count"], 1)
        self.assertEqual(result["open_risk_input_count"], 1)
        self.assertEqual(result["held_input_count"], 1)
        self.assertEqual(result["input_summaries"][0]["synthesis_use"], "open-risk")
        self.assertTrue(result["input_summaries"][0]["implementation_blocked"])
        self.assertEqual(result["input_summaries"][0]["hold_classification"], "provider-conflict-pending")

    def test_architect_override_can_promote_process_held_input(self) -> None:
        result = evaluate_synthesis_inputs(
            [
                {
                    "lane": "opus",
                    "provider_camp": "anthropic",
                    "disposition": "accepted",
                    "recommended_synthesis_use": "primary",
                    "implementation_blocked": True,
                    "hold_reasons": ["peer-review-pending"],
                    "architect_adjudication_authorized": True,
                },
                {"lane": "chatgpt", "provider_camp": "openai", "disposition": "accepted"},
            ]
        )

        self.assertEqual(result["status"], "ready")
        self.assertEqual(result["usable_input_count"], 2)
        self.assertEqual(result["held_input_count"], 1)
        self.assertEqual(result["input_summaries"][0]["synthesis_use"], "primary")

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
