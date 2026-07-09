from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from cwo_core.errors import CWOPolicyError, CWOValidationError  # noqa: E402
from cwo_core.routing import (  # noqa: E402
    classify_work,
    normalize_beads_context_depth,
    normalize_data_sensitivity,
    resolve_execution_environment,
)
from cwo_core.routing_signals import explicit_openai_deep_research_requested  # noqa: E402


class RoutingTests(unittest.TestCase):
    def test_invalid_data_sensitivity_raises_typed_validation_error(self) -> None:
        with self.assertRaisesRegex(CWOValidationError, "data_sensitivity must be one of"):
            normalize_data_sensitivity("customer-secret")

    def test_invalid_beads_context_depth_raises_typed_validation_error(self) -> None:
        with self.assertRaisesRegex(CWOValidationError, "beads_context_depth must be one of"):
            normalize_beads_context_depth("deepest")

    def test_unknown_execution_environment_raises_typed_policy_error(self) -> None:
        with self.assertRaisesRegex(CWOPolicyError, "unknown execution environment: missing-env"):
            resolve_execution_environment("missing-env")

    def test_classify_work_propagates_typed_execution_environment_error(self) -> None:
        with self.assertRaisesRegex(CWOPolicyError, "unknown execution environment: missing-env"):
            classify_work("Review the architecture plan.", execution_environment="missing-env")

    def test_ranks_security_and_architecture_experts(self) -> None:
        result = classify_work(
            "Security and architecture review for token handling, redaction boundary, and API compatibility.",
            external_ok=True,
            share_boundary="redacted-packet",
            requested_roles=["security"],
            file_paths=["scripts/build_contractor_packet.py", "policy/routing-policy.yaml"],
        )
        expert_names = [expert["name"] for expert in result["ranked_experts"]]
        self.assertIn("security", expert_names[:3])
        self.assertIn("architecture", expert_names[:5])
        self.assertTrue(result["ranked_executors"])
        self.assertIn(result["route"], {"external-contract", "architect-review", "internal-worker"})

    def test_external_without_opt_in_has_hard_stop_or_non_external_route(self) -> None:
        result = classify_work(
            "Claude security review for auth token handling.",
            external_ok=False,
            share_boundary="redacted-packet",
            requested_roles=["security"],
        )
        if result["route"] == "external-contract":
            self.assertTrue(result["hard_stops"])
        else:
            self.assertNotEqual(result["route"], "external-contract")

    def test_local_worker_requires_explicit_opt_in(self) -> None:
        result = classify_work(
            "Documentation review for internal example notes.",
            requested_roles=["documentation"],
            share_boundary="no-outside-sharing",
            prefer_local=True,
        )
        self.assertNotEqual(result["route"], "local-worker")
        local_candidate = next(item for item in result["ranked_executors"] if item["key"] == "local_openai_compatible_worker")
        self.assertIn("local worker dispatch requires --local-ok", local_candidate["policy_violations"])

    def test_prefer_local_selects_low_risk_local_worker_when_allowed(self) -> None:
        result = classify_work(
            "Documentation review for internal example notes.",
            requested_roles=["documentation"],
            share_boundary="no-outside-sharing",
            local_ok=True,
            prefer_local=True,
        )
        self.assertEqual(result["route"], "local-worker")
        self.assertEqual(result["recommended_executor"], "local_openai_compatible_worker")
        self.assertTrue(result["has_local_worker_contracts"])
        self.assertIn("local-worker-only", result["guard_labels"])
        self.assertIn("no-codex-exec", result["guard_labels"])
        self.assertTrue(result["evaluator_required"])

    def test_openai_deep_research_requires_provider_co_signal(self) -> None:
        self.assertFalse(explicit_openai_deep_research_requested("Do a deep research pass on this design."))
        self.assertTrue(explicit_openai_deep_research_requested("Use ChatGPT Deep Research for this design."))
        self.assertTrue(explicit_openai_deep_research_requested("Use OpenAI deep research for this design."))

    def test_operator_calibrated_execution_can_be_requested_explicitly(self) -> None:
        result = classify_work(
            "Review whether this sprint result is a true clean-negative or a safety-deferred not-run.",
            requested_roles=["operator-calibrated"],
        )

        primary = result["ranked_experts"][0]
        self.assertEqual(primary["name"], "operator_calibrated_execution")
        self.assertEqual(primary["job_description_label"], "contract-jd-operator-calibrated-execution")
        self.assertIn("closure disposition", primary["output_contract"])


if __name__ == "__main__":
    unittest.main()
