from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from cwo_core.policy import load_policy  # noqa: E402
from cwo_core.routing import classify_work  # noqa: E402
from cwo_core.synthesis import evaluate_synthesis_inputs  # noqa: E402


def claim(category: str, key: str, value: str, *, claim_id: str | None = None) -> dict[str, str]:
    return {
        "claim_id": claim_id or f"{category}:{key}",
        "category": category,
        "key": key,
        "value": value,
        "claim_type": "security_assertion",
        "evidence": "synthetic test claim",
    }


class ZeroTrustConsensusTests(unittest.TestCase):
    def test_same_provider_family_does_not_satisfy_independence(self) -> None:
        result = evaluate_synthesis_inputs(
            [
                {
                    "lane": "chatgpt",
                    "provider_family": "openai",
                    "disposition": "accepted",
                    "zero_trust_claims": [claim("auth", "jwt_algorithms", "RS256 only")],
                },
                {
                    "lane": "codex",
                    "provider_family": "openai",
                    "disposition": "accepted",
                    "zero_trust_claims": [claim("auth", "jwt_algorithms", "RS256 only")],
                },
            ],
            zero_trust_required=True,
        )

        zero = result["zero_trust_consensus"]
        self.assertEqual(zero["independent_trust_domain_count"], 1)
        self.assertEqual(zero["consensus_status"], "blocked")
        self.assertTrue(result["blocked"])
        self.assertIn("Agreement across model returns is not verification", zero["trust_domain_independence_disclaimer"])

    def test_boundary_tainted_input_is_excluded_from_domain_count(self) -> None:
        result = evaluate_synthesis_inputs(
            [
                {
                    "lane": "opus",
                    "provider_family": "anthropic",
                    "disposition": "accepted",
                    "zero_trust_claims": [claim("network", "tls_verify", "enabled")],
                },
                {
                    "lane": "gemini",
                    "provider_family": "google",
                    "disposition": "accepted",
                    "boundary_status": "boundary-tainted",
                    "zero_trust_claims": [claim("network", "tls_verify", "disabled")],
                },
            ],
            zero_trust_required=True,
        )

        zero = result["zero_trust_consensus"]
        self.assertEqual(zero["independent_trust_domain_count"], 1)
        self.assertEqual(zero["excluded_input_count"], 1)
        self.assertEqual(zero["consensus_status"], "blocked")
        self.assertFalse(zero["divergence_report"])

    def test_cross_domain_divergence_requires_architect_resolution(self) -> None:
        result = evaluate_synthesis_inputs(
            [
                {
                    "lane": "opus",
                    "provider_family": "anthropic",
                    "disposition": "accepted",
                    "zero_trust_claims": [claim("crypto", "cipher_mode", "AES-256-GCM")],
                },
                {
                    "lane": "chatgpt",
                    "provider_family": "openai",
                    "disposition": "accepted",
                    "zero_trust_claims": [claim("crypto", "cipher_mode", "AES-128-CBC")],
                },
            ],
            zero_trust_required=True,
        )

        zero = result["zero_trust_consensus"]
        self.assertEqual(zero["consensus_status"], "divergent")
        self.assertEqual(zero["recommended_action"], "escalate")
        self.assertEqual(zero["divergence_report"][0]["resolution_authority"], "architect")
        self.assertTrue(result["blocked"])

    def test_matching_claims_do_not_create_positive_validation_status(self) -> None:
        result = evaluate_synthesis_inputs(
            [
                {
                    "lane": "opus",
                    "provider_family": "anthropic",
                    "disposition": "accepted",
                    "zero_trust_claims": [claim("auth", "jwt_algorithms", "RS256 only")],
                },
                {
                    "lane": "chatgpt",
                    "provider_family": "openai",
                    "disposition": "accepted",
                    "zero_trust_claims": [claim("auth", "jwt_algorithms", "RS256 only")],
                },
            ],
            zero_trust_required=True,
        )

        zero = result["zero_trust_consensus"]
        self.assertEqual(zero["consensus_status"], "informational")
        self.assertEqual(zero["recommended_action"], "none")
        self.assertTrue(zero["agreement_is_not_validation"])
        self.assertNotIn(zero["consensus_status"], {"confirmed", "validated", "trusted", "passed"})

    def test_formatting_only_technical_claim_difference_is_not_divergence(self) -> None:
        result = evaluate_synthesis_inputs(
            [
                {
                    "lane": "opus",
                    "provider_family": "anthropic",
                    "disposition": "accepted",
                    "zero_trust_claims": [claim("crypto", "cipher_mode", "AES-256-GCM")],
                },
                {
                    "lane": "chatgpt",
                    "provider_family": "openai",
                    "disposition": "accepted",
                    "zero_trust_claims": [claim("crypto", "cipher_mode", "aes256gcm")],
                },
            ],
            zero_trust_required=True,
        )

        zero = result["zero_trust_consensus"]
        self.assertEqual(zero["consensus_status"], "informational")
        self.assertFalse(zero["divergence_report"])

    def test_semantic_technical_claim_difference_still_diverges(self) -> None:
        result = evaluate_synthesis_inputs(
            [
                {
                    "lane": "opus",
                    "provider_family": "anthropic",
                    "disposition": "accepted",
                    "zero_trust_claims": [claim("crypto", "cipher_mode", "AES-256-CBC")],
                },
                {
                    "lane": "chatgpt",
                    "provider_family": "openai",
                    "disposition": "accepted",
                    "zero_trust_claims": [claim("crypto", "cipher_mode", "AES-256-GCM")],
                },
            ],
            zero_trust_required=True,
        )

        zero = result["zero_trust_consensus"]
        self.assertEqual(zero["consensus_status"], "divergent")
        self.assertTrue(zero["divergence_report"])

    def test_version_punctuation_is_not_collapsed(self) -> None:
        result = evaluate_synthesis_inputs(
            [
                {
                    "lane": "opus",
                    "provider_family": "anthropic",
                    "disposition": "accepted",
                    "zero_trust_claims": [claim("network", "tls_version", "TLS-1.2")],
                },
                {
                    "lane": "chatgpt",
                    "provider_family": "openai",
                    "disposition": "accepted",
                    "zero_trust_claims": [claim("network", "tls_version", "TLS-1.3")],
                },
            ],
            zero_trust_required=True,
        )

        zero = result["zero_trust_consensus"]
        self.assertEqual(zero["consensus_status"], "divergent")
        self.assertTrue(zero["divergence_report"])

    def test_domain_aliases_resolve_before_independence_count(self) -> None:
        result = evaluate_synthesis_inputs(
            [
                {
                    "lane": "codex",
                    "trust_domain": "codex",
                    "disposition": "accepted",
                    "zero_trust_claims": [claim("auth", "jwt_algorithms", "RS256 only")],
                },
                {
                    "lane": "chatgpt",
                    "provider_family": "openai",
                    "disposition": "accepted",
                    "zero_trust_claims": [claim("auth", "jwt_algorithms", "RS-256 only")],
                },
                {
                    "lane": "local",
                    "provider_family": "local-openai-compatible",
                    "disposition": "accepted",
                    "zero_trust_claims": [claim("auth", "jwt_algorithms", "RS256 only")],
                },
            ],
            zero_trust_required=True,
        )

        zero = result["zero_trust_consensus"]
        self.assertEqual(zero["independent_trust_domains"], ["local", "openai"])
        self.assertEqual(zero["independent_trust_domain_count"], 2)
        self.assertEqual(zero["consensus_status"], "informational")

    def test_partial_four_domain_divergence_can_quarantine(self) -> None:
        result = evaluate_synthesis_inputs(
            [
                {
                    "lane": "opus",
                    "provider_family": "anthropic",
                    "disposition": "accepted",
                    "zero_trust_claims": [claim("crypto", "cipher_mode", "AES-256-GCM")],
                },
                {
                    "lane": "chatgpt",
                    "provider_family": "openai",
                    "disposition": "accepted",
                    "zero_trust_claims": [claim("crypto", "cipher_mode", "AES-256-GCM")],
                },
                {
                    "lane": "gemini",
                    "provider_family": "google",
                    "disposition": "accepted",
                    "zero_trust_claims": [claim("crypto", "cipher_mode", "AES-128-CBC")],
                },
                {
                    "lane": "local",
                    "provider_family": "local-openai-compatible",
                    "disposition": "accepted",
                    "zero_trust_claims": [claim("crypto", "cipher_mode", "AES-256-GCM")],
                },
            ],
            zero_trust_required=True,
        )

        zero = result["zero_trust_consensus"]
        self.assertEqual(zero["independent_trust_domain_count"], 4)
        self.assertEqual(zero["consensus_status"], "divergent")
        self.assertEqual(zero["recommended_action"], "quarantine")
        self.assertTrue(result["blocked"])

    def test_optional_zero_trust_without_claims_is_informational(self) -> None:
        result = evaluate_synthesis_inputs(
            [
                {
                    "lane": "opus",
                    "provider_family": "anthropic",
                    "disposition": "accepted",
                },
                {
                    "lane": "chatgpt",
                    "provider_family": "openai",
                    "disposition": "accepted",
                },
            ],
            zero_trust_required=False,
        )

        zero = result["zero_trust_consensus"]
        self.assertEqual(zero["consensus_status"], "informational")
        self.assertEqual(zero["recommended_action"], "none")
        self.assertFalse(result["blocked"])
        self.assertFalse(zero["blocked_reasons"])

    def test_required_zero_trust_blocks_without_explicit_claims(self) -> None:
        result = evaluate_synthesis_inputs(
            [
                {
                    "lane": "opus",
                    "provider_family": "anthropic",
                    "disposition": "accepted",
                },
                {
                    "lane": "chatgpt",
                    "provider_family": "openai",
                    "disposition": "accepted",
                },
            ],
            zero_trust_required=True,
        )

        zero = result["zero_trust_consensus"]
        self.assertEqual(zero["consensus_status"], "blocked")
        self.assertTrue(result["blocked"])
        self.assertIn("explicit zero_trust_claims", " ".join(zero["blocked_reasons"]))

    def test_required_zero_trust_blocks_without_comparable_claims(self) -> None:
        result = evaluate_synthesis_inputs(
            [
                {
                    "lane": "opus",
                    "provider_family": "anthropic",
                    "disposition": "accepted",
                    "zero_trust_claims": [claim("auth", "jwt_algorithms", "RS256 only")],
                },
                {
                    "lane": "chatgpt",
                    "provider_family": "openai",
                    "disposition": "accepted",
                    "zero_trust_claims": [claim("network", "tls_verify", "enabled")],
                },
            ],
            zero_trust_required=True,
        )

        zero = result["zero_trust_consensus"]
        self.assertEqual(zero["consensus_status"], "blocked")
        self.assertTrue(result["blocked"])
        self.assertIn("comparable claims", " ".join(zero["blocked_reasons"]))

    def test_weakness_patterns_are_informational_only(self) -> None:
        result = evaluate_synthesis_inputs(
            [
                {
                    "lane": "opus",
                    "provider_family": "anthropic",
                    "disposition": "accepted",
                    "zero_trust_claims": [claim("network", "tls_verify", "verify=False")],
                },
                {
                    "lane": "chatgpt",
                    "provider_family": "openai",
                    "disposition": "accepted",
                    "zero_trust_claims": [claim("network", "tls_verify", "verify=False")],
                },
            ],
            zero_trust_required=True,
        )

        zero = result["zero_trust_consensus"]
        self.assertEqual(zero["consensus_status"], "informational")
        self.assertEqual(zero["weakness_pattern_findings"][0]["effect"], "informational-only")
        self.assertFalse(result["blocked"])

    def test_route_zero_trust_trigger_terms_surface_requirement(self) -> None:
        result = classify_work(
            "Use zero-trust consensus to review auth flow and TLS implementation choices.",
            requested_roles=["architecture"],
        )

        self.assertTrue(result["zero_trust_consensus_required"])
        self.assertGreaterEqual(result["zero_trust_minimum_independent_domains"], 2)
        self.assertTrue(result["zero_trust_consensus_trigger_reasons"])

    def test_route_incidental_security_term_does_not_trigger_without_context(self) -> None:
        result = classify_work("Rename the dependency heading in public documentation.")

        self.assertFalse(result["zero_trust_consensus_required"])

    def test_policy_has_safe_status_vocabulary(self) -> None:
        policy = load_policy("zero-trust-consensus-policy")

        self.assertEqual(set(policy["status_values"]), {"informational", "blocked", "divergent"})
        self.assertNotIn("confirmed", policy["status_values"])
        self.assertNotIn("validated", policy["status_values"])
        self.assertEqual(policy["resolution_authority"], "architect")


if __name__ == "__main__":
    unittest.main()
