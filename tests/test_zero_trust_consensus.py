from __future__ import annotations

import hashlib
import sys
import unittest
from pathlib import Path

from typing import Iterator, NamedTuple
from tests.structural_assertions import Check, assert_checks

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


CANDIDATE = "commit:" + "a" * 40 + " tree:" + "b" * 40
SCOPE = "bead:cwo-zero-trust-fixture"
# The executor that served each lane. Trust domains come from these fake
# dispatch records through the registries, never from the input labels.
LANE_EXECUTORS = {
    "opus": "claude_architecture_critic",
    "chatgpt": "chatgpt_pro_browser_master_reviewer",
    "codex": "codex_architecture_critic",
    "gemini": "gemini_architecture_critic",
    "local": "openshift_ai_vllm_worker",
}


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def evaluate_dispatched(inputs: list[dict], *, accepted: tuple[str, ...] = (), **kwargs: object) -> dict:
    """Bind each lane with a known executor to a fake dispatch record, then evaluate."""

    records: list[dict] = []
    adjudications: list[dict] = []
    bound: list[dict] = []
    for raw in inputs:
        entry = dict(raw)
        executor = LANE_EXECUTORS.get(entry["lane"])
        if executor:
            dispatch_id = "dispatch-" + entry["lane"]
            entry.update(dispatch_id=dispatch_id, return_sha256=_sha(dispatch_id))
            records.append({
                "record_type": "cwo-dispatch-record", "version": 1, "dispatch_id": dispatch_id,
                "executor": executor, "return_sha256": _sha(dispatch_id), "candidate": CANDIDATE,
            })
            if entry["lane"] in accepted:
                adjudications.append({
                    "record_type": "cwo-return-adjudication", "version": 1,
                    "adjudication_id": "adj-" + entry["lane"], "dispatch_id": dispatch_id,
                    "return_sha256": _sha(dispatch_id), "candidate": CANDIDATE, "scope": SCOPE,
                    "finding_ids": ["finding:claims"], "decision": "accepted",
                    "rationale": "claims checked against the candidate",
                    "supporting_evidence": [{
                        "artifact": "validation.txt", "artifact_type": "validation-log",
                        "sha256": _sha("evidence"), "finding_ids": ["finding:claims"],
                    }],
                    "authority": {"rule": "synthesis-input-adjudication"},
                    "adjudicator": "lead",
                })
        bound.append(entry)
    return evaluate_synthesis_inputs(
        bound, dispatch_records=records, adjudications=adjudications, candidate=CANDIDATE, scope=SCOPE, **kwargs
    )


class ConsensusInputCase(NamedTuple):
    original: str
    inputs: list[dict]
    options: dict
    checks: tuple[Check, ...]


def _consensus_input_rows() -> Iterator[ConsensusInputCase]:
    yield ConsensusInputCase('test_same_provider_family_does_not_satisfy_independence', [
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
        ], {'zero_trust_required': True}, (
        Check(lambda result: result['zero_trust_consensus']['independent_trust_domain_count'], 1),
        Check(lambda result: result['zero_trust_consensus']['consensus_status'], 'blocked'),
        Check(lambda result: result['blocked'], None, 'true'),
        Check(lambda result: result['zero_trust_consensus']['trust_domain_independence_disclaimer'], 'Agreement across model returns is not verification', 'contains'),
    ))

    yield ConsensusInputCase('test_boundary_tainted_input_is_excluded_from_domain_count', [
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
        ], {'zero_trust_required': True}, (
        Check(lambda result: result['zero_trust_consensus']['independent_trust_domain_count'], 1),
        Check(lambda result: result['zero_trust_consensus']['excluded_input_count'], 1),
        Check(lambda result: result['zero_trust_consensus']['consensus_status'], 'blocked'),
        Check(lambda result: result['zero_trust_consensus']['divergence_report'], None, 'false'),
    ))

    yield ConsensusInputCase('test_cross_domain_divergence_requires_architect_resolution', [
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
        ], {'zero_trust_required': True}, (
        Check(lambda result: result['zero_trust_consensus']['consensus_status'], 'divergent'),
        Check(lambda result: result['zero_trust_consensus']['recommended_action'], 'escalate'),
        Check(lambda result: result['zero_trust_consensus']['divergence_report'][0]['resolution_authority'], 'architect'),
        Check(lambda result: result['blocked'], None, 'true'),
    ))

    yield ConsensusInputCase('test_matching_claims_do_not_create_positive_validation_status', [
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
        ], {'zero_trust_required': True}, (
        Check(lambda result: result['zero_trust_consensus']['consensus_status'], 'informational'),
        Check(lambda result: result['zero_trust_consensus']['recommended_action'], 'none'),
        Check(lambda result: result['zero_trust_consensus']['agreement_is_not_validation'], None, 'true'),
        Check(lambda result: result['zero_trust_consensus']['consensus_status'], {'confirmed', 'validated', 'trusted', 'passed'}, 'not-in'),
    ))

    yield ConsensusInputCase('test_formatting_only_technical_claim_difference_is_not_divergence', [
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
        ], {'zero_trust_required': True}, (
        Check(lambda result: result['zero_trust_consensus']['consensus_status'], 'informational'),
        Check(lambda result: result['zero_trust_consensus']['divergence_report'], None, 'false'),
    ))

    yield ConsensusInputCase('test_semantic_technical_claim_difference_still_diverges', [
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
        ], {'zero_trust_required': True}, (
        Check(lambda result: result['zero_trust_consensus']['consensus_status'], 'divergent'),
        Check(lambda result: result['zero_trust_consensus']['divergence_report'], None, 'true'),
    ))

    yield ConsensusInputCase('test_version_punctuation_is_not_collapsed', [
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
        ], {'zero_trust_required': True}, (
        Check(lambda result: result['zero_trust_consensus']['consensus_status'], 'divergent'),
        Check(lambda result: result['zero_trust_consensus']['divergence_report'], None, 'true'),
    ))

    yield ConsensusInputCase('test_domain_aliases_resolve_before_independence_count', [
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
        ], {'zero_trust_required': True}, (
        Check(lambda result: result['zero_trust_consensus']['independent_trust_domains'], ['local', 'openai']),
        Check(lambda result: result['zero_trust_consensus']['independent_trust_domain_count'], 2),
        Check(lambda result: result['zero_trust_consensus']['consensus_status'], 'informational'),
    ))

    yield ConsensusInputCase('test_self_declared_trust_domain_without_provider_metadata_is_excluded', [
            {
                "lane": "spoofed",
                "trust_domain": "anthropic",
                "disposition": "accepted",
                "zero_trust_claims": [claim("auth", "jwt_algorithms", "RS256 only")],
            },
            {
                "lane": "chatgpt",
                "provider_family": "openai",
                "disposition": "accepted",
                "zero_trust_claims": [claim("auth", "jwt_algorithms", "RS256 only")],
            },
        ], {'zero_trust_required': True}, (
        Check(lambda result: result['zero_trust_consensus']['independent_trust_domain_count'], 1),
        Check(lambda result: result['zero_trust_consensus']['consensus_status'], 'blocked'),
    ))

    yield ConsensusInputCase('test_partial_four_domain_divergence_can_quarantine', [
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
                "synthesis_use": "primary",
                "zero_trust_claims": [claim("crypto", "cipher_mode", "AES-128-CBC")],
            },
            {
                "lane": "local",
                "provider_family": "local-openai-compatible",
                "disposition": "accepted",
                "zero_trust_claims": [claim("crypto", "cipher_mode", "AES-256-GCM")],
            },
        ], {'zero_trust_required': True, 'accepted': ("gemini",)}, (
        Check(lambda result: result['zero_trust_consensus']['independent_trust_domain_count'], 4),
        Check(lambda result: result['zero_trust_consensus']['consensus_status'], 'divergent'),
        Check(lambda result: result['zero_trust_consensus']['recommended_action'], 'quarantine'),
        Check(lambda result: result['blocked'], None, 'true'),
    ))

    yield ConsensusInputCase('test_optional_zero_trust_without_claims_is_informational', [
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
        ], {'zero_trust_required': False}, (
        Check(lambda result: result['zero_trust_consensus']['consensus_status'], 'informational'),
        Check(lambda result: result['zero_trust_consensus']['recommended_action'], 'none'),
        Check(lambda result: result['blocked'], None, 'false'),
        Check(lambda result: result['zero_trust_consensus']['blocked_reasons'], None, 'false'),
    ))

    yield ConsensusInputCase('test_required_zero_trust_blocks_without_explicit_claims', [
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
        ], {'zero_trust_required': True}, (
        Check(lambda result: result['zero_trust_consensus']['consensus_status'], 'blocked'),
        Check(lambda result: result['blocked'], None, 'true'),
        Check(lambda result: ' '.join(result['zero_trust_consensus']['blocked_reasons']), 'explicit zero_trust_claims', 'contains'),
    ))

    yield ConsensusInputCase('test_required_zero_trust_blocks_without_comparable_claims', [
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
        ], {'zero_trust_required': True}, (
        Check(lambda result: result['zero_trust_consensus']['consensus_status'], 'blocked'),
        Check(lambda result: result['blocked'], None, 'true'),
        Check(lambda result: ' '.join(result['zero_trust_consensus']['blocked_reasons']), 'comparable claims', 'contains'),
    ))

    yield ConsensusInputCase('test_weakness_patterns_are_informational_only', [
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
        ], {'zero_trust_required': True}, (
        Check(lambda result: result['zero_trust_consensus']['consensus_status'], 'informational'),
        Check(lambda result: result['zero_trust_consensus']['weakness_pattern_findings'][0]['effect'], 'informational-only'),
        Check(lambda result: result['blocked'], None, 'false'),
    ))


class ZeroTrustConsensusTests(unittest.TestCase):
    def test_zero_trust_consensus_input_rows(self) -> None:
        for row in _consensus_input_rows():
            with self.subTest(original=row.original):
                result = evaluate_dispatched(row.inputs, **row.options)
                assert_checks(self, result, row.checks)

        identifiers = [
            {"lane": "opus", "disposition": "accepted",
             "zero_trust_claims": [claim("crypto", "cipher_mode", "AES-256-GCM")]},
            {"lane": "chatgpt", "disposition": "accepted",
             "zero_trust_claims": [claim("crypto", "cipher_mode", "aes_256_gcm")]},
        ]
        normalized = evaluate_dispatched(identifiers, zero_trust_required=True)["zero_trust_consensus"]
        self.assertEqual(normalized["consensus_status"], "informational")
        self.assertEqual(normalized["recommended_action"], "none")
        for reported, expected in ((" ", None), ("readable-claim", "readable-claim")):
            with self.subTest(unresolved_reported_claim=reported):
                invalid = claim("crypto", "cipher_mode", "AES-256-GCM", claim_id=reported)
                invalid["category"] = None
                inputs = [identifiers[0], {"lane": "chatgpt", "disposition": "accepted",
                                           "zero_trust_claims": [invalid]}]
                consensus = evaluate_dispatched(inputs, zero_trust_required=True)["zero_trust_consensus"]
                unresolved = next(row for row in consensus["unresolved_claims"]
                                  if row["lane"] == "chatgpt" and row["claim"] == 1)
                self.assertEqual(unresolved["claim_id"], expected)
                self.assertIn(consensus["recommended_action"], ("block", "quarantine", "escalate"))


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
