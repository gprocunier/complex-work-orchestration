from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from cwo_core.routing import classify_work  # noqa: E402
from cwo_core.policy import (  # noqa: E402
    load_policy,
    validate_peer_review_controls,
)


class ProviderPolicyTests(unittest.TestCase):
    def test_frontier_provider_conflict_forces_peer_review(self) -> None:
        route = classify_work(
            "Review a Claude Mythos eval harness for a frontier model provider competitor.",
            external_ok=True,
            share_boundary="redacted-packet",
            requested_roles=["general-reasoning"],
        )
        self.assertTrue(route["provider_conflict_detected"])
        self.assertIn("frontier-ai-development", route["provider_conflict_domains"])
        self.assertTrue(route["peer_review_required"])
        self.assertGreaterEqual(route["peer_review_count"], 1)
        self.assertIn("provider_key", route["selected_executor"])

    def test_peer_review_controls_enforce_count_and_provider_diversity(self) -> None:
        result = validate_peer_review_controls(
            primary_provider_family="openai",
            peer_reviews=[{"status": "passed", "provider_family": "openai"}],
            minimum_peer_reviews=1,
            provider_diversity_required=True,
        )
        self.assertFalse(result["valid"])
        self.assertIn("provider diversity not satisfied", result["errors"])

        result = validate_peer_review_controls(
            primary_provider_family="openai",
            peer_reviews=[{"status": "passed", "provider_family": "anthropic"}],
            minimum_peer_reviews=1,
            provider_diversity_required=True,
        )
        self.assertTrue(result["valid"])

    def test_peer_review_controls_require_minimum_passed_reviews(self) -> None:
        result = validate_peer_review_controls(
            primary_provider_family="openai",
            peer_reviews=[{"status": "pending", "provider_family": "anthropic"}],
            minimum_peer_reviews=1,
            provider_diversity_required=False,
        )
        self.assertFalse(result["valid"])
        self.assertIn("minimum peer reviews not satisfied: required=1 passed=0", result["errors"])

    def test_local_secure_reviewer_is_repo_read_only_and_not_codex_pickup(self) -> None:
        executor = load_policy("executor-registry")["executors"]["local_secure_review_worker"]
        self.assertEqual(executor["dispatch_mode"], "local_secure_review")
        self.assertEqual(executor["codex_pickup"], "forbidden")
        self.assertTrue(executor["supports_repo_read"])
        self.assertFalse(executor["supports_repo_write"])
        self.assertFalse(executor["supports_shell"])
        self.assertFalse(executor["supports_web"])
        self.assertEqual(executor["provider_key"], "local_inference")

    def test_local_secure_reviewer_can_handle_high_risk_local_security_review(self) -> None:
        route = classify_work(
            "Security review local repo auth handling without outside sharing.",
            local_ok=True,
            prefer_local=True,
            share_boundary="no-outside-sharing",
            requested_roles=["security"],
        )
        self.assertEqual(route["route"], "local-worker")
        self.assertEqual(route["recommended_executor"], "local_secure_review_worker")
        self.assertEqual(route["selected_executor"]["dispatch_mode"], "local_secure_review")

    def test_gemini_manual_executor_is_registered_as_external_contractor(self) -> None:
        providers = load_policy("provider-registry")["providers"]
        executors = load_policy("executor-registry")["executors"]
        controls = load_policy("contracting-controls")

        provider = providers["google_gemini_manual"]
        executor = executors["gemini_3_1_pro_manual"]
        self.assertTrue(provider["external"])
        self.assertEqual(provider["family"], "google")
        self.assertEqual(executor["provider_key"], "google_gemini_manual")
        self.assertTrue(executor["external"])
        self.assertEqual(executor["codex_pickup"], "forbidden")
        self.assertTrue(executor["supports_repo_read"])
        self.assertFalse(executor["supports_repo_write"])
        self.assertIn("gemini_3_1_pro_manual", controls["allowed_external_executors"])

    def test_gemini_agy_architecture_critic_is_registered_as_external_contractor(self) -> None:
        providers = load_policy("provider-registry")["providers"]
        executors = load_policy("executor-registry")["executors"]
        controls = load_policy("contracting-controls")

        provider = providers["google_gemini_manual"]
        executor = executors["gemini_3_1_pro_preview_agy"]
        self.assertTrue(provider["external"])
        self.assertEqual(executor["provider_key"], "google_gemini_manual")
        self.assertTrue(executor["external"])
        self.assertEqual(executor["codex_pickup"], "forbidden")
        self.assertEqual(executor["critique_mode"], "architect-design-second-opinion")
        self.assertTrue(executor["supports_repo_read"])
        self.assertFalse(executor["supports_repo_write"])
        self.assertIn("architecture-review", executor["allowed_task_classes"])
        self.assertIn("gemini_3_1_pro_preview_agy", controls["allowed_external_executors"])

    def test_claude_opus_architecture_critic_is_registered_as_external_contractor(self) -> None:
        providers = load_policy("provider-registry")["providers"]
        executors = load_policy("executor-registry")["executors"]
        controls = load_policy("contracting-controls")

        provider = providers["anthropic_manual"]
        executor = executors["claude_opus_4_6_architecture_critic"]
        self.assertTrue(provider["external"])
        self.assertEqual(provider["family"], "anthropic")
        self.assertEqual(executor["provider_key"], "anthropic_manual")
        self.assertTrue(executor["external"])
        self.assertEqual(executor["codex_pickup"], "forbidden")
        self.assertEqual(executor["critique_mode"], "architect-design-second-opinion")
        self.assertTrue(executor["supports_repo_read"])
        self.assertFalse(executor["supports_repo_write"])
        self.assertIn("architecture-review", executor["allowed_task_classes"])
        self.assertEqual(executor["transport"]["model"], "claude-opus-4-6")
        self.assertEqual(executor["transport"]["minimum_effort"], "high")
        self.assertIn("--effort high", executor["transport"]["default_command"])
        self.assertIn("claude_opus_4_6_architecture_critic", controls["allowed_external_executors"])

    def test_chatgpt_pro_browser_reviewer_is_registered_as_external_contractor(self) -> None:
        providers = load_policy("provider-registry")["providers"]
        executors = load_policy("executor-registry")["executors"]
        controls = load_policy("contracting-controls")

        provider = providers["openai_manual"]
        executor = executors["chatgpt_pro_5_5_extended_reasoning_browser"]
        self.assertTrue(provider["external"])
        self.assertEqual(provider["family"], "openai")
        self.assertEqual(executor["provider_key"], "openai_manual")
        self.assertTrue(executor["external"])
        self.assertEqual(executor["dispatch_mode"], "browser_automation")
        self.assertEqual(executor["codex_pickup"], "forbidden")
        self.assertEqual(executor["critique_mode"], "master-plan-review")
        self.assertFalse(executor["supports_repo_read"])
        self.assertFalse(executor["supports_repo_write"])
        self.assertIn("master-plan-review", executor["allowed_task_classes"])
        self.assertIn("chatgpt_pro_5_5_extended_reasoning_browser", controls["allowed_external_executors"])


if __name__ == "__main__":
    unittest.main()
