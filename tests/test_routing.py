from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from orchestration_lib import classify_work  # noqa: E402


class RoutingTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
