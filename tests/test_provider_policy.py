from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from cwo_core.routing import classify_work  # noqa: E402
from cwo_core.policy import (  # noqa: E402
    executor_config,
    executor_key_allowed,
    load_policy,
    resolve_executor_key,
    validate_peer_review_controls,
)
from cwo_core.returns import executor_default_synthesis_use, return_provenance  # noqa: E402


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

    def test_provider_policy_intervention_terms_force_peer_review(self) -> None:
        route = classify_work(
            "Review a model policy hidden filter that may use prompt modification or a safety layer.",
            external_ok=True,
            share_boundary="redacted-packet",
            requested_roles=["general-reasoning"],
        )

        self.assertTrue(route["provider_conflict_detected"])
        self.assertIn("provider-policy-intervention", route["provider_conflict_domains"])
        self.assertTrue(route["peer_review_required"])
        self.assertGreaterEqual(route["peer_review_count"], 1)

    def test_external_frontier_providers_carry_policy_intervention_risk_domain(self) -> None:
        providers = load_policy("provider-registry")["providers"]
        for provider_key in ["openai_manual", "anthropic_manual", "google_gemini_manual"]:
            with self.subTest(provider_key=provider_key):
                self.assertIn(
                    "provider-policy-intervention",
                    providers[provider_key]["conflict_risk_domains"],
                )

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
        executor = executors["gemini_manual_reviewer"]
        self.assertTrue(provider["external"])
        self.assertEqual(provider["family"], "google")
        self.assertEqual(executor["provider_key"], "google_gemini_manual")
        self.assertTrue(executor["external"])
        self.assertEqual(executor["codex_pickup"], "forbidden")
        self.assertTrue(executor["supports_repo_read"])
        self.assertFalse(executor["supports_repo_write"])
        self.assertIn("gemini_manual_reviewer", controls["allowed_external_executors"])

    def test_gemini_agy_architecture_critic_is_registered_as_external_contractor(self) -> None:
        providers = load_policy("provider-registry")["providers"]
        executors = load_policy("executor-registry")["executors"]
        controls = load_policy("contracting-controls")

        provider = providers["google_gemini_manual"]
        executor = executors["gemini_architecture_critic"]
        self.assertTrue(provider["external"])
        self.assertEqual(executor["provider_key"], "google_gemini_manual")
        self.assertTrue(executor["external"])
        self.assertEqual(executor["codex_pickup"], "forbidden")
        self.assertEqual(executor["critique_mode"], "architect-design-second-opinion")
        self.assertTrue(executor["supports_repo_read"])
        self.assertFalse(executor["supports_repo_write"])
        self.assertIn("architecture-review", executor["allowed_task_classes"])
        self.assertIn("gemini_architecture_critic", controls["allowed_external_executors"])

    def test_claude_opus_architecture_critic_is_registered_as_external_contractor(self) -> None:
        providers = load_policy("provider-registry")["providers"]
        executors = load_policy("executor-registry")["executors"]
        controls = load_policy("contracting-controls")

        provider = providers["anthropic_manual"]
        executor = executors["claude_architecture_critic"]
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
        self.assertIn("claude_architecture_critic", controls["allowed_external_executors"])

    def test_chatgpt_pro_browser_reviewer_is_registered_as_external_contractor(self) -> None:
        providers = load_policy("provider-registry")["providers"]
        executors = load_policy("executor-registry")["executors"]
        controls = load_policy("contracting-controls")

        provider = providers["openai_manual"]
        executor = executors["chatgpt_pro_browser_master_reviewer"]
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
        self.assertIn("chatgpt_pro_browser_master_reviewer", controls["allowed_external_executors"])

    def test_executor_aliases_resolve_historical_keys_to_role_keys(self) -> None:
        registry = load_policy("executor-registry")

        self.assertEqual(
            resolve_executor_key("chatgpt_pro_5_5_extended_reasoning_browser", registry),
            "chatgpt_pro_browser_master_reviewer",
        )
        executor = executor_config("chatgpt_pro_5_5_extended_reasoning_browser", registry)
        self.assertEqual(executor["canonical_key"], "chatgpt_pro_browser_master_reviewer")
        self.assertEqual(executor["requested_key"], "chatgpt_pro_5_5_extended_reasoning_browser")
        self.assertEqual(executor["dispatch_mode"], "browser_automation")

    def test_executor_alias_matching_accepts_alias_or_canonical_key(self) -> None:
        registry = load_policy("executor-registry")

        self.assertTrue(
            executor_key_allowed(
                "chatgpt_pro_5_5_extended_reasoning_browser",
                ["chatgpt_pro_browser_master_reviewer"],
                registry,
            )
        )
        self.assertTrue(
            executor_key_allowed(
                "chatgpt_pro_browser_master_reviewer",
                ["chatgpt_pro_5_5_extended_reasoning_browser"],
                registry,
            )
        )

    def test_return_provenance_resolves_historical_executor_alias(self) -> None:
        provenance = return_provenance(executor="chatgpt_pro_5_5_extended_reasoning_browser")

        self.assertEqual(provenance["provider_key"], "openai_manual")
        self.assertEqual(provenance["dispatch_mode"], "browser_automation")
        self.assertEqual(provenance["provenance_class"], "external-contractor")
        self.assertEqual(provenance["provenance_warnings"], [])

    def test_default_synthesis_use_resolves_historical_executor_alias(self) -> None:
        self.assertEqual(
            executor_default_synthesis_use("gemini_3_1_pro_preview_agy"),
            "salvage-only",
        )

    def test_glm_bf16_architecture_critic_is_registered_as_local_reviewer(self) -> None:
        executors = load_policy("executor-registry")["executors"]
        executor = executors["rhoai_glm_architecture_critic"]

        self.assertFalse(executor["external"])
        self.assertEqual(executor["provider_key"], "openshift_ai_vllm")
        self.assertEqual(executor["dispatch_mode"], "local_secure_review")
        self.assertEqual(executor["codex_pickup"], "forbidden")
        self.assertEqual(executor["critique_mode"], "architect-design-second-opinion")
        self.assertTrue(executor["supports_repo_read"])
        self.assertFalse(executor["supports_repo_write"])
        self.assertFalse(executor["supports_shell"])
        self.assertFalse(executor["supports_web"])
        self.assertIn("architecture-review", executor["allowed_task_classes"])
        self.assertEqual(executor["model_profile"], "rhoai-architect-glm-5-2-bf16-thinking")
        self.assertEqual(executor["transport"]["default_model"], "glm-5.2-bf16-128k")
        self.assertEqual(executor["transport"]["request_options"], {"chat_template_kwargs": {"enable_thinking": True}})
        self.assertEqual(executor["transport"]["thinking_parser"], "glm-think-tags")

    def test_glm_bf16_primary_architect_is_read_only_local_architect(self) -> None:
        executors = load_policy("executor-registry")["executors"]
        executor = executors["rhoai_glm_primary_architect"]

        self.assertFalse(executor["external"])
        self.assertEqual(executor["provider_key"], "openshift_ai_vllm")
        self.assertEqual(executor["dispatch_mode"], "local_secure_review")
        self.assertEqual(executor["role"], "local-primary-architect")
        self.assertEqual(executor["codex_pickup"], "forbidden")
        self.assertEqual(executor["critique_mode"], "primary-architect")
        self.assertTrue(executor["supports_repo_read"])
        self.assertFalse(executor["supports_repo_write"])
        self.assertFalse(executor["supports_shell"])
        self.assertFalse(executor["supports_web"])
        self.assertEqual(executor["model_profile"], "rhoai-architect-glm-5-2-bf16-thinking")
        self.assertEqual(executor["transport"]["request_options"], {"chat_template_kwargs": {"enable_thinking": True}})

    def test_codex_xhigh_counter_review_is_internal_read_only_review_lane(self) -> None:
        executors = load_policy("executor-registry")["executors"]
        executor = executors["codex_architecture_critic"]

        self.assertFalse(executor["external"])
        self.assertEqual(executor["provider_key"], "internal_codex")
        self.assertEqual(executor["dispatch_mode"], "main_thread_review")
        self.assertEqual(executor["role"], "architecture-critic")
        self.assertEqual(executor["codex_pickup"], "forbidden")
        self.assertEqual(executor["critique_mode"], "architect-design-second-opinion")
        self.assertTrue(executor["supports_repo_read"])
        self.assertFalse(executor["supports_repo_write"])
        self.assertFalse(executor["supports_shell"])
        self.assertFalse(executor["supports_web"])

    def test_explicit_glm_architecture_critic_routes_to_local_executor(self) -> None:
        route = classify_work(
            "Use GLM-5.2 BF16 thinking as an independent architecture critic second opinion.",
            local_ok=True,
            local_profile="openshift-ai-vllm",
            requested_roles=["architecture"],
        )

        self.assertEqual(route["route"], "local-worker")
        self.assertEqual(route["recommended_executor"], "rhoai_glm_architecture_critic")
        self.assertEqual(route["selected_executor"]["model_profile"], "rhoai-architect-glm-5-2-bf16-thinking")
        self.assertIn(
            "rhoai_glm_architecture_critic",
            route["requested_architecture_critic_executors"],
        )


if __name__ == "__main__":
    unittest.main()
