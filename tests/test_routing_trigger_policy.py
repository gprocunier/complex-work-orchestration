from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from cwo_core.policy import load_policy  # noqa: E402
from cwo_core.routing_signals import (  # noqa: E402
    explicit_claude_architect_critique_requested,
    explicit_gemini_architect_critique_requested,
    explicit_glm_architect_critique_requested,
    requested_architecture_critic_executor_keys,
)
import validate_repository  # noqa: E402


class RoutingCriticTriggerTests(unittest.TestCase):
    def test_policy_defines_trigger_registry(self) -> None:
        triggers = load_policy("routing-policy").get("architecture_critic_triggers")
        self.assertIsInstance(triggers, dict)
        self.assertIn("claude_architecture_critic", triggers.get("executors", {}))

    def test_claude_critic_trigger(self) -> None:
        self.assertTrue(
            explicit_claude_architect_critique_requested(
                "ask claude for an architecture second opinion"
            )
        )
        self.assertFalse(
            explicit_claude_architect_critique_requested("ask claude to implement the fix")
        )

    def test_gemini_critic_trigger(self) -> None:
        self.assertTrue(
            explicit_gemini_architect_critique_requested("get a gemini design critique")
        )
        self.assertFalse(
            explicit_gemini_architect_critique_requested("get a claude design critique")
        )

    def test_glm_critic_accepts_synthesis_phrasing(self) -> None:
        self.assertTrue(
            explicit_glm_architect_critique_requested("run glm architecture synthesis")
        )

    def test_executor_keys_order_is_stable(self) -> None:
        text = "claude and gemini and glm architecture review second opinion synthesis"
        self.assertEqual(
            requested_architecture_critic_executor_keys(text),
            [
                "claude_architecture_critic",
                "gemini_architecture_critic",
                "rhoai_glm_hardened_architecture_critic",
            ],
        )

    def test_validator_accepts_shipped_policy(self) -> None:
        errors: list[str] = []
        validate_repository.validate_routing_critic_triggers(
            errors,
            load_policy("routing-policy"),
            load_policy("executor-registry").get("executors", {}),
        )
        self.assertEqual(errors, [])

    def test_validator_flags_unknown_executor_and_empty_terms(self) -> None:
        errors: list[str] = []
        synthetic = {
            "architecture_critic_triggers": {
                "shared_critique_terms": ["critique"],
                "executors": {
                    "missing_executor": {"provider_terms": [], "context_terms": ["design"]}
                },
            }
        }
        validate_repository.validate_routing_critic_triggers(errors, synthetic, {})
        self.assertTrue(any("unknown executor" in error for error in errors), errors)
        self.assertTrue(any("provider_terms" in error for error in errors), errors)


if __name__ == "__main__":
    unittest.main()
