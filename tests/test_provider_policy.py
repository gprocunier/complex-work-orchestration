from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from orchestration_lib import classify_work, load_policy  # noqa: E402


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


if __name__ == "__main__":
    unittest.main()
