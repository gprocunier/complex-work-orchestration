from __future__ import annotations

import json
import hashlib
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Callable, Iterator, Literal, NamedTuple

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from cwo_core.returns import (  # noqa: E402
    SectionReader,
    classify_patch_authorization,
    evidence_items_from_sections,
    is_merge_readiness_go_claim,
    is_packet_only_declared,
    make_acceptance_decision,
    normalize_contractor_return,
    parse_return_sections,
    score_evidence_quality,
    score_malpractice_signals,
    score_research_evidence,
    score_sabotage_signals,
    section_value,
)


from unittest.mock import patch
from tests.f3_peer_review_fixtures import review_binding

class ReturnOutcome(NamedTuple):
    value: Callable[[dict], object]
    expected: object
    operation: Literal["equal", "not-equal", "less", "greater", "true", "false", "contains", "not-contains", "in", "not-in"] = "equal"


class ReturnCase(NamedTuple):
    original: str
    text: str
    options: dict
    checks: tuple[ReturnOutcome, ...]


def _return_outcome_rows(sample: str) -> Iterator[ReturnCase]:
    yield ReturnCase('test_direct_v2_truncation_overrides_claimed_valid_frame', sample, {'executor': "rhoai_glm_compact_architecture_critic", 'local_completion_status': "completed", 'local_usable_final_content': True, 'local_expected_response_contract': "cwo-glm-critic-v2", 'local_response_contract': "cwo-glm-critic-v2", 'local_response_contract_status': "valid", 'local_normalized_return_matches': True, 'local_v2_frame_valid': True, 'local_v2_identity_consistent': True, 'local_response_model_status': "matched", 'local_model_preflight_status': "passed", 'local_http_status': 200, 'local_response_truncated': True}, (
        ReturnOutcome(lambda result: result['verdict'], 'quarantine'),
        ReturnOutcome(lambda result: result['recommended_synthesis_use'], 'quarantine'),
        ReturnOutcome(lambda result: result['local_v2_frame_valid'], None, 'false'),
    ))


    text = sample
    text = text.replace("Escalation needed: no", "Escalation needed: yes")
    yield ReturnCase('test_escalation_flag_routes_to_architect_adjudication', text, {}, (
        ReturnOutcome(lambda result: result['verdict'], 'escalate'),
        ReturnOutcome(lambda result: result['recommended_disposition'], 'architect-adjudication'),
        ReturnOutcome(lambda result: result['human_adjudication_required'], None, 'true'),
        ReturnOutcome(lambda result: result['escalation_flagged'], None, 'true'),
    ))


    text = sample
    yield ReturnCase('test_patch_branch_requires_files_and_commands', text, {'share_boundary': "patch-branch"}, (
        ReturnOutcome(lambda result: result['verdict'], 'reject'),
        ReturnOutcome(lambda result: result['hard_disqualifiers'], 'patch branch return missing patch proposal or direct-change evidence', 'contains'),
    ))

    text = """Status: complete
Contractor job description: contract-jd-security-reasoning
Summary: Reviewed the packet.
Validation result: Reviewed supplied evidence.
Evidence: policy excerpt and packet summary.
Evidence provenance: packet.
Attestation/repro note: reproducible from the packet.
Share boundary conformance: stayed inside redacted packet.
Peer review disposition: not required for this sample.
Alternatives considered: none.
Confidence: medium
Risks or gaps: no repo access.
Recommended next bead: No follow-up implementation bead needed.
Escalation needed: no
"""
    yield ReturnCase('test_aliases_satisfy_required_sections', text, {'job_description_label': "contract-jd-security-reasoning"}, (
        ReturnOutcome(lambda result: result['missing_sections'], []),
    ))

    text = """Status: complete
Contractor job description: contract-jd-docs-reasoning
Summary: Mentions contract-jd-security-reasoning elsewhere but wrong structured field.
Validation result: Reviewed packet.
Evidence: packet excerpt.
Evidence provenance: packet.
Attestation or reproducibility note: packet.
Share boundary conformance: stayed inside packet.
Peer-review disposition: not required.
Alternatives considered: none.
Confidence: medium
Risks or gaps: none.
Recommended next bead: none.
Escalation needed: no
"""
    yield ReturnCase('test_job_description_alignment_requires_structured_field', text, {'job_description_label': "contract-jd-security-reasoning"}, (
        ReturnOutcome(lambda result: result['hard_disqualifiers'], 'missing assigned job-description alignment', 'contains'),
    ))

    text = sample + "\n_evaluator_api_key = plain-secret\n"
    yield ReturnCase('test_underscore_prefixed_secret_assignment_is_detected', text, {}, (
        ReturnOutcome(lambda result: result['hard_disqualifiers'], 'suspected secret or personal-data spill', 'contains'),
    ))

    text = sample
    text = text.replace(
        "Summary: The redacted packet design blocks full Bead JSON and only includes selected snippets.",
        "Summary: Plan is ready for merge and safe to ship in readiness review.",
    ) + "\nReview surface: packet-only\nSource inspection: packet-only"
    yield ReturnCase('test_master_review_declared_review_surface_and_source_inspection', text, {'executor': "chatgpt_pro_browser_master_reviewer"}, (
        ReturnOutcome(lambda result: result['review_surface'], 'packet-only'),
        ReturnOutcome(lambda result: result['source_inspection'], 'packet-only'),
        ReturnOutcome(lambda result: result['review_surface_packet_only'], None, 'true'),
        ReturnOutcome(lambda result: result['source_inspection_packet_only'], None, 'true'),
        ReturnOutcome(lambda result: result['go_for_pr_merge_readiness_claimed'], None, 'true'),
        ReturnOutcome(lambda result: result['review_surface_mismatch'], None, 'true'),
        ReturnOutcome(lambda result: result['review_surface_required_evidence_missing'], None, 'true'),
        ReturnOutcome(lambda result: result['review_surface_mismatch_reasons'], 'packet-only master review cannot provide unconditional PR/merge/readiness GO', 'contains'),
        ReturnOutcome(lambda result: result['master_review_packet_only_go_hold'], None, 'true'),
        ReturnOutcome(lambda result: result['implementation_blocked'], None, 'true'),
        ReturnOutcome(lambda result: result['hold_reasons'], 'reviewer packet-only GO claim for merge/readiness requires architect adjudication', 'contains'),
        ReturnOutcome(lambda result: result['recommended_disposition'], 'architect-adjudication'),
    ))

    text = sample
    text = text.replace(
        "Summary: The redacted packet design blocks full Bead JSON and only includes selected snippets.",
        "Summary: The PR is ready for merge after source review confirms behavior.",
    ) + "\nReview surface: repo-readonly\nSource inspection: repo-readonly"
    yield ReturnCase('test_master_review_non_packet_scope_go_claim_is_not_packet_only_held', text, {'executor': "chatgpt_pro_browser_master_reviewer"}, (
        ReturnOutcome(lambda result: result['master_review_packet_only_go_hold'], None, 'false'),
        ReturnOutcome(lambda result: result['review_surface_mismatch'], None, 'false'),
        ReturnOutcome(lambda result: result['implementation_blocked'], None, 'false'),
        ReturnOutcome(lambda result: result['hold_reasons'], 'reviewer packet-only GO claim for merge/readiness requires architect adjudication', 'not-contains'),
    ))

    text = sample.replace(
        "Summary: The redacted packet design blocks full Bead JSON and only includes selected snippets.",
        "Summary: GO for PR merge readiness.",
    ) + "\nReview surface: packet-only\nSource inspection: PR was not inspected"
    yield ReturnCase('test_source_first_uninspected_phrase_blocks_packet_go_claim', text, {'executor': "chatgpt_pro_browser_master_reviewer"}, (
        ReturnOutcome(lambda result: result['review_surface_required_evidence_missing'], None, 'true'),
        ReturnOutcome(lambda result: result['review_surface_mismatch_reasons'], 'return says required PR/diff/repo/source evidence was not inspected', 'contains'),
    ))

    text = sample
    text = text.replace(
        "Patch authorization: no patch access requested or used",
        "Patch authorization: patch proposal only; no direct workspace mutation authorized",
    ).replace(
        "Evidence:\n",
        "Evidence:\n- Proposed patch artifact: docs-refresh.diff.\n",
    )
    yield ReturnCase('test_patch_branch_proposal_does_not_require_direct_mutation', text, {'share_boundary': "patch-branch"}, (
        ReturnOutcome(lambda result: result['hard_disqualifiers'], 'patch branch return missing patch proposal or direct-change evidence', 'not-contains'),
    ))

    text = sample
    text = text.replace("Files changed: none", "Files changed: scripts/example.py")
    text = text.replace(
        "Evidence:\n",
        "Evidence:\n- Proposed patch artifact: example.diff.\n",
    )
    yield ReturnCase('test_redacted_packet_changed_file_claim_requires_direct_authorization', text, {'share_boundary': "redacted-packet"}, (
        ReturnOutcome(lambda result: result['hard_disqualifiers'], 'unapproved patch or repo access', 'contains'),
    ))

    text = sample
    text = text.replace(
        "Commands run: none",
        "Commands run:\n- python scripts/validate_repository.py\n- python -m unittest discover -s tests -v",
    ).replace(
        "Validation result: Reviewed provided packet manifest and selected snippets; no runtime command was executed.",
        "Validation result: passed (repository validation verified and all unit tests passed)",
    )
    yield ReturnCase('test_redacted_packet_command_execution_claim_rejects_even_with_boundary_compliance', text, {'share_boundary': "redacted-packet"}, (
        ReturnOutcome(lambda result: result['verdict'], 'reject'),
        ReturnOutcome(lambda result: result['boundary_taint_status'], 'boundary-tainted'),
        ReturnOutcome(lambda result: result['hard_disqualifiers'], 'redacted packet return claims command or test execution', 'contains'),
        ReturnOutcome(lambda result: result['hard_disqualifiers'], 'redacted packet return claims unsupported validation', 'contains'),
    ))

    text = sample
    text = "I am analyzing the repository directory structure before returning.\n" + text
    yield ReturnCase('test_redacted_packet_repo_inspection_preamble_rejects', text, {'share_boundary': "redacted-packet"}, (
        ReturnOutcome(lambda result: result['verdict'], 'reject'),
        ReturnOutcome(lambda result: result['boundary_taint_findings'], 'redacted packet return claims direct repository or workspace inspection', 'contains'),
    ))

    text = sample
    text = text.replace(
        "Validation result: Reviewed provided packet manifest and selected snippets; no runtime command was executed.",
        "Validation result: passed based on packet validation evidence: repository validator, site validator, and 248 unit tests.",
    )
    yield ReturnCase('test_redacted_packet_packet_reported_validation_is_allowed', text, {'share_boundary': "redacted-packet"}, (
        ReturnOutcome(lambda result: result['hard_disqualifiers'], 'redacted packet return claims unsupported validation', 'not-contains'),
        ReturnOutcome(lambda result: result['boundary_taint_status'], 'clear'),
    ))


    text = sample
    yield ReturnCase('test_peer_review_required_cannot_be_dismissed', text, {'peer_review_required': True, 'provider_conflict_domains': ["frontier-ai-development"]}, (
        ReturnOutcome(lambda result: result['hard_disqualifiers'], 'peer review incorrectly dismissed', 'contains'),
        ReturnOutcome(lambda result: result['recommended_disposition'], 'reject'),
    ))

    text = sample
    text = text.replace(
        "Peer-review disposition: not required for this sample return.",
        "Peer-review disposition: Required peer review is pending.",
    )
    yield ReturnCase('test_pending_peer_review_blocks_implementation_until_review_runs', text, {'peer_review_required': True}, (
        ReturnOutcome(lambda result: result['verdict'], 'escalate'),
        ReturnOutcome(lambda result: result['accepted_for_use'], None, 'false'),
        ReturnOutcome(lambda result: result['evidence_use_hold'], None, 'true'),
        ReturnOutcome(lambda result: result['implementation_blocked'], None, 'true'),
        ReturnOutcome(lambda result: result['hold_classification'], 'peer-review-pending'),
        ReturnOutcome(lambda result: result['hold_reasons'], 'peer-review-pending', 'contains'),
        ReturnOutcome(lambda result: result['hard_disqualifiers'], 'peer review required before implementation use', 'not-contains'),
        ReturnOutcome(lambda result: result['recommended_disposition'], 'run-peer-review'),
        ReturnOutcome(lambda result: result['recommended_synthesis_use'], 'open-risk'),
    ))

    text = sample
    yield ReturnCase('test_local_worker_acceptance_decision_carries_provider_provenance', text, {'executor': "openshift_ai_vllm_worker", 'model_profile': "rhoai-secure-review-qwen3-6-35b-a3b-nvfp4"}, (
        ReturnOutcome(lambda result: result['executor'], 'openshift_ai_vllm_worker'),
        ReturnOutcome(lambda result: result['provider_key'], 'openshift_ai_vllm'),
        ReturnOutcome(lambda result: result['provider_trust_tier'], 'local-platform'),
        ReturnOutcome(lambda result: result['dispatch_mode'], 'local_openai_compatible'),
        ReturnOutcome(lambda result: result['local_profile'], 'openshift-ai-vllm'),
        ReturnOutcome(lambda result: result['model_profile'], 'rhoai-secure-review-qwen3-6-35b-a3b-nvfp4'),
        ReturnOutcome(lambda result: result['provenance_class'], 'local-worker'),
        ReturnOutcome(lambda result: result['provider_external'], None, 'false'),
    ))

    text = sample
    yield ReturnCase('test_glm_bf16_high_quality_return_is_primary_eligible', text, {'executor': "rhoai_glm_architecture_critic"}, (
        ReturnOutcome(lambda result: result['verdict'], 'accept'),
        ReturnOutcome(lambda result: result['provider_key'], 'openshift_ai_vllm'),
        ReturnOutcome(lambda result: result['model_profile'], 'rhoai-architect-glm-5-2-bf16-thinking'),
        ReturnOutcome(lambda result: result['recommended_synthesis_use'], 'primary'),
    ))

    text = sample
    yield ReturnCase('test_hardened_glm_completed_final_content_is_primary_eligible', text, {'executor': "rhoai_glm_hardened_architecture_critic", 'local_completion_status': "completed", 'local_usable_final_content': True}, (
        ReturnOutcome(lambda result: result['verdict'], 'accept'),
        ReturnOutcome(lambda result: result['model_profile'], 'rhoai-architect-glm-5-2-bf16-256k-thinking'),
        ReturnOutcome(lambda result: result['recommended_synthesis_use'], 'primary'),
        ReturnOutcome(lambda result: result['local_completion_status'], 'completed'),
        ReturnOutcome(lambda result: result['local_usable_final_content'], None, 'true'),
    ))

    text = sample
    yield ReturnCase('test_hardened_glm_reasoning_only_result_is_salvage_only', text, {'executor': "rhoai_glm_hardened_architecture_critic", 'local_completion_status': "empty-final-content", 'local_usable_final_content': False}, (
        ReturnOutcome(lambda result: result['verdict'], 'accept'),
        ReturnOutcome(lambda result: result['recommended_synthesis_use'], 'salvage-only'),
        ReturnOutcome(lambda result: result['human_adjudication_required'], None, 'true'),
        ReturnOutcome(lambda result: result['recommended_disposition'], ['request-clarification', 'architect-adjudication'], 'in'),
        ReturnOutcome(lambda result: any(('usable final content' in reason for reason in result['penalty_reasons'])), None, 'true'),
    ))

    text = sample
    yield ReturnCase('test_local_truncation_metadata_forces_salvage_and_clarification', text, {'executor': "rhoai_glm_architecture_critic", 'local_response_truncated': True, 'local_finish_reasons': ["length", "max_tokens"]}, (
        ReturnOutcome(lambda result: result['verdict'], 'accept'),
        ReturnOutcome(lambda result: result['recommended_disposition'], ['request-clarification', 'architect-adjudication'], 'in'),
        ReturnOutcome(lambda result: result['recommended_synthesis_use'], 'salvage-only'),
        ReturnOutcome(lambda result: result['human_adjudication_required'], None, 'true'),
        ReturnOutcome(lambda result: any(('truncation' in str(reason).lower() for reason in result['penalty_reasons'])), None, 'true'),
    ))

    text = sample
    yield ReturnCase('test_local_reasoning_malformed_metadata_reduces_synthesis_use', text, {'executor': "rhoai_glm_architecture_critic", 'local_reasoning_malformed': True}, (
        ReturnOutcome(lambda result: result['recommended_disposition'], ['request-clarification', 'architect-adjudication'], 'in'),
        ReturnOutcome(lambda result: result['recommended_synthesis_use'], 'salvage-only'),
        ReturnOutcome(lambda result: result['human_adjudication_required'], None, 'true'),
        ReturnOutcome(lambda result: any(('reasoning content malformed' in str(reason).lower() for reason in result['penalty_reasons'])), None, 'true'),
    ))

    text = sample
    text = text.replace(
        "- Included artifacts list contains assignment summary and selected snippets only.\n"
        "- Excluded artifacts list explicitly names full Bead JSON and secrets.",
        "- Looks good and appears reasonable.\n- No issues found.",
    ).replace(
        "Evidence provenance: packet manifest and selected snippets supplied in the contractor packet.",
        "Evidence provenance: reviewer judgment.",
    )
    yield ReturnCase('test_structurally_complete_generic_return_is_not_accepted', text, {'executor': "gemini_architecture_critic"}, (
        ReturnOutcome(lambda result: result['verdict'], 'accept', 'not-equal'),
        ReturnOutcome(lambda result: result['evidence_quality_score'], 85, 'less'),
        ReturnOutcome(lambda result: result['evidence_quality_signal_categories'], 'claim_only_evidence', 'contains'),
        ReturnOutcome(lambda result: result['evidence_quality_signal_categories'], 'vague_evidence', 'contains'),
        ReturnOutcome(lambda result: result['recommended_synthesis_use'], 'primary', 'not-equal'),
    ))

    text = sample
    yield ReturnCase('test_gemini_high_quality_return_defaults_to_salvage_only', text, {'executor': "gemini_architecture_critic"}, (
        ReturnOutcome(lambda result: result['verdict'], 'accept'),
        ReturnOutcome(lambda result: result['evidence_quality_score'], 100),
        ReturnOutcome(lambda result: result['recommended_synthesis_use'], 'salvage-only'),
    ))

    text = sample
    yield ReturnCase('test_file_and_packet_evidence_remains_primary_quality', text, {'executor': "claude_architecture_critic"}, (
        ReturnOutcome(lambda result: result['evidence_quality_score'], 100),
        ReturnOutcome(lambda result: result['evidence_quality_signal_categories'], []),
        ReturnOutcome(lambda result: result['recommended_synthesis_use'], 'primary'),
    ))

    text = sample + """

Research evidence:
```json
{
  "research_evidence_items": [
    {
      "claim_id": "claim-1",
      "claim": "Structured research evidence should be evaluated before synthesis.",
      "source_id": "src-1",
      "source_type": "official-doc",
      "source_locator": "policy/acceptance-policy.yaml",
      "citation_span": "evidence_quality.thresholds",
      "quoted_excerpt": "primary: 85",
      "source_reliability_score": 95,
      "relevance_score": 95,
      "support_type": "supports",
      "access_status": "full",
      "notes": "Repo policy evidence."
    }
  ]
}
```
Research contradictions:
```json
[]
```
Research reflection:
```json
{"coverage": 90, "factual_support": 95, "depth": 85, "consistency": 90, "gaps": [], "followup_queries": [], "replan_recommended": false}
```
"""
    yield ReturnCase('test_well_grounded_research_evidence_scores_primary', text, {}, (
        ReturnOutcome(lambda result: result['research_evidence_present'], None, 'true'),
        ReturnOutcome(lambda result: result['research_evidence_score'], 100),
        ReturnOutcome(lambda result: result['evidence_quality_score'], 100),
        ReturnOutcome(lambda result: result['research_evidence_signal_categories'], []),
    ))

    text = sample + """

Research evidence:
```json
{"research_evidence_items": [{"claim_id": "claim-1", "claim": "This seems likely."}]}
```
Research reflection:
```json
{"coverage": 40, "factual_support": 20, "depth": 20, "consistency": 50, "gaps": [], "followup_queries": [], "replan_recommended": false}
```
"""
    yield ReturnCase('test_claim_only_research_evidence_is_downgraded', text, {}, (
        ReturnOutcome(lambda result: result['evidence_quality_score'], 85, 'less'),
        ReturnOutcome(lambda result: result['evidence_quality_signal_categories'], 'missing_research_source_locator', 'contains'),
        ReturnOutcome(lambda result: result['evidence_quality_signal_categories'], 'missing_research_grounding', 'contains'),
        ReturnOutcome(lambda result: result['recommended_synthesis_use'], 'primary', 'not-equal'),
    ))

    text = sample + """

Research evidence:
```json
{
  "research_evidence_items": [
    {
      "claim_id": "claim-1",
      "claim": "Research returns should use explicit source grounding.",
      "source_id": "src-1",
      "source_type": "official-doc",
      "source_locator": "references/external-contracting.md",
      "citation_span": "Return Review",
      "quoted_excerpt": "normalized, evaluated, and adjudicated",
      "source_reliability_score": 90,
      "relevance_score": 90,
      "support_type": "supports",
      "access_status": "full"
    }
  ],
  "research_contradictions": [
    {"claim_id": "claim-1", "source_ids": ["src-1", "src-2"], "summary": "conflicting guidance", "resolution_status": "unresolved"}
  ],
  "research_reflection": {"coverage": 80, "factual_support": 80, "depth": 75, "consistency": 50, "gaps": [], "followup_queries": [], "replan_recommended": false}
}
```
"""
    yield ReturnCase('test_unresolved_research_contradictions_lower_score', text, {}, (
        ReturnOutcome(lambda result: result['research_unresolved_contradiction_count'], 1),
        ReturnOutcome(lambda result: result['research_evidence_signal_categories'], 'unresolved_research_contradiction', 'contains'),
    ))

    yield ReturnCase('test_legacy_return_has_no_research_evidence_fields_active', sample, {}, (
        ReturnOutcome(lambda result: result['research_evidence_present'], None, 'false'),
        ReturnOutcome(lambda result: result['research_evidence_items'], []),
        ReturnOutcome(lambda result: result['research_evidence_score'], 100),
    ))


class EvaluateReturnTests(unittest.TestCase):
    def sample_return(self) -> str:
        return (ROOT / "examples" / "sample-contractor-return.md").read_text(encoding="utf-8")

    def _v2_dispatch_artifact(self, text: str) -> dict:
        """Independent synthetic oracle: no model output or live dispatch."""
        return {
            "dispatch_id": "synthetic-v2-dispatch",
            "bead_id": "synthetic-review",
            "dispatch_mode": "local_secure_review",
            "route": {
                "share_boundary": "redacted-packet",
                "recommended_executor": "rhoai_glm_compact_architecture_critic",
                "selected_executor": {
                    "key": "rhoai_glm_compact_architecture_critic",
                    "provider_key": "openshift_ai_vllm",
                    "provider_trust_tier": "local-platform",
                    "dispatch_mode": "local_secure_review",
                    "local_profile": "openshift-ai-glm-5-3-direct",
                    "model_profile": "rhoai-architect-glm-5-3-bf16-compact-critic",
                },
            },
            "local_envelope": {
                "response_contract": "cwo-glm-critic-v2",
                "dispatch_id": "synthetic-v2-dispatch",
                "bead_id": "synthetic-review",
                "executor_key": "rhoai_glm_compact_architecture_critic",
                "provider_key": "openshift_ai_vllm",
                "provider_trust_tier": "local-platform",
                "local_profile": "openshift-ai-glm-5-3-direct",
                "model_profile": "rhoai-architect-glm-5-3-bf16-compact-critic",
                "share_boundary": "redacted-packet",
                "model": "glm-5.3-bf16",
                "execution_enabled": True,
            },
            "local_response": {
                "status_code": 200,
                "completion_status": "completed",
                "usable_final_content": True,
                "response_contract": "cwo-glm-critic-v2",
                "response_contract_status": "valid",
                "response_model_status": "matched",
                "model_preflight": {"status": "passed", "required_model": "glm-5.3-bf16", "status_code": 200},
                "finish_reasons": ["stop"],
                "response_truncated": False,
                "reasoning_malformed": False,
                "response_contract_errors": [],
                "content_security_status": "passed",
                "final_content_chars": 100,
                "normalized_return": text,
                "normalized_return_sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
                "normalized_return_chars": len(text),
            },
        }

    def _evaluate_v2_cli(
        self, artifact: dict, text: str, *extra: str, return_bytes: bytes | None = None
    ) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory() as workdir:
            artifact_path = Path(workdir) / "dispatch.json"
            return_path = Path(workdir) / "return.md"
            artifact_path.write_text(json.dumps(artifact), encoding="utf-8")
            if return_bytes is None:
                return_path.write_text(text, encoding="utf-8")
            else:
                return_path.write_bytes(return_bytes)
            return subprocess.run(
                [sys.executable, "-B", str(ROOT / "scripts" / "evaluate_return.py"),
                 "--file", str(return_path), "--local-dispatch-result", str(artifact_path),
                 "--advisory", "--no-audit", "--waiver-reason", "synthetic v2 eligibility regression",
                 "--json", *extra],
                cwd=ROOT, capture_output=True, text=True, check=False,
            )

    def test_v2_cli_rejects_unusable_or_unbound_dispatch_evidence(self) -> None:
        sample = self.sample_return()
        valid = self._v2_dispatch_artifact(sample)
        cases = {
            "contract-invalid": lambda d: d["local_response"].update(completion_status="contract-invalid", usable_final_content=False, normalized_return=None),
            "missing-response": lambda d: d.pop("local_response"),
            "string-usability": lambda d: d["local_response"].update(usable_final_content="false"),
            "invalid-contract-status": lambda d: d["local_response"].update(response_contract_status="invalid"),
            "wrong-response-contract": lambda d: d["local_response"].update(response_contract="cwo-glm-critic-v1"),
            "wrong-digest": lambda d: d["local_response"].update(normalized_return_sha256="0" * 64),
            "missing-digest": lambda d: d["local_response"].pop("normalized_return_sha256"),
            "wrong-model": lambda d: d["local_response"].update(response_model_status="mismatch"),
            "unknown-status": lambda d: d["local_response"].update(completion_status="not-a-status"),
            "contradictory-truncation": lambda d: d["local_response"].update(response_truncated=True),
            "contradictory-contract-errors": lambda d: d["local_response"].update(response_contract_errors=["error"]),
            "overlong-final-frame": lambda d: d["local_response"].update(final_content_chars=6001),
            "v1-response-unknown-envelope": lambda d: (
                d["local_envelope"].update(response_contract="unknown-contract"),
                d["local_response"].update(response_contract="cwo-glm-critic-v1", completion_status="contract-invalid", usable_final_content=False, normalized_return=None),
            ),
            "missing-outer-dispatch": lambda d: d.pop("dispatch_id"),
            "envelope-dispatch-mismatch": lambda d: d["local_envelope"].update(dispatch_id="other-dispatch"),
            "envelope-executor-mismatch": lambda d: d["local_envelope"].update(executor_key="rhoai_glm_hardened_architecture_critic"),
            "preflight-model-mismatch": lambda d: d["local_response"]["model_preflight"].update(required_model="not-glm-5.3"),
            "one-sided-bead": lambda d: d.update(bead_id=None),
            "mismatched-bead": lambda d: d["local_envelope"].update(bead_id="other-bead"),
            "empty-bead-pair": lambda d: (d.update(bead_id=""), d["local_envelope"].update(bead_id="")),
        }
        for name, mutate in cases.items():
            with self.subTest(name=name):
                artifact = self._v2_dispatch_artifact(sample)
                mutate(artifact)
                completed = self._evaluate_v2_cli(artifact, sample)
                self.assertEqual(completed.returncode, 0, completed.stderr)
                result = json.loads(completed.stdout)
                self.assertIn(result["verdict"], {"reject", "quarantine"})
                self.assertIn(result["recommended_synthesis_use"], {"reject", "quarantine"})
                self.assertEqual(result["sections"], {})
                if name == "unknown-status":
                    self.assertNotIn("not-a-status", completed.stdout)

        stale = self._evaluate_v2_cli(valid, sample + "\nSTALE")
        self.assertEqual(stale.returncode, 0, stale.stderr)
        stale_result = json.loads(stale.stdout)
        self.assertIn(stale_result["recommended_synthesis_use"], {"reject", "quarantine"})
        self.assertEqual(stale_result["sections"], {})
        crlf = self._evaluate_v2_cli(
            valid, sample, return_bytes=sample.replace("\n", "\r\n").encode("utf-8")
        )
        self.assertEqual(crlf.returncode, 0, crlf.stderr)
        self.assertIn(json.loads(crlf.stdout)["recommended_synthesis_use"], {"reject", "quarantine"})

    def test_return_evaluation_input_outcome_rows(self) -> None:
        for row in _return_outcome_rows(self.sample_return()):
            with self.subTest(original=row.original):
                result = make_acceptance_decision(row.text, **row.options)
                for check in row.checks:
                    self._assert_return_outcome(result, check)

    def _assert_return_outcome(self, result: dict, check: ReturnOutcome) -> None:
        value = check.value(result)
        if check.operation == "true":
            self.assertTrue(value)
        elif check.operation == "false":
            self.assertFalse(value)
        elif check.operation == "not-equal":
            self.assertNotEqual(value, check.expected)
        elif check.operation == "less":
            self.assertLess(value, check.expected)
        elif check.operation == "greater":
            self.assertGreater(value, check.expected)
        elif check.operation == "contains":
            self.assertIn(check.expected, value)
        elif check.operation == "not-contains":
            self.assertNotIn(check.expected, value)
        elif check.operation == "in":
            self.assertIn(value, check.expected)
        elif check.operation == "not-in":
            self.assertNotIn(value, check.expected)
        else:
            self.assertEqual(value, check.expected)

    def test_v2_cli_inspects_matching_return_and_rejects_identity_override(self) -> None:
        sample = self.sample_return()
        artifact = self._v2_dispatch_artifact(sample)
        valid = self._evaluate_v2_cli(artifact, sample)
        self.assertEqual(valid.returncode, 0, valid.stderr)
        self.assertEqual(json.loads(valid.stdout)["recommended_synthesis_use"], "open-risk")
        self.assertEqual(json.loads(valid.stdout)["result_class"], "advisory-nonproduction")
        self.assertTrue(json.loads(valid.stdout)["implementation_blocked"])
        no_bead = self._v2_dispatch_artifact(sample)
        no_bead["bead_id"] = None
        no_bead["local_envelope"]["bead_id"] = None
        valid_without_bead = self._evaluate_v2_cli(no_bead, sample)
        self.assertEqual(valid_without_bead.returncode, 0, valid_without_bead.stderr)
        self.assertEqual(json.loads(valid_without_bead.stdout)["recommended_synthesis_use"], "open-risk")
        self.assertTrue(json.loads(valid_without_bead.stdout)["implementation_blocked"])
        overridden = self._evaluate_v2_cli(artifact, sample, "--executor", "rhoai_glm_hardened_architecture_critic")
        self.assertNotEqual(overridden.returncode, 0)
        wrong_dispatch = self._evaluate_v2_cli(artifact, sample, "--dispatch-id", "another-dispatch")
        self.assertNotEqual(wrong_dispatch.returncode, 0)

    def test_documented_glm_handoff_does_not_evaluate_stale_file_after_dispatch_failure(self) -> None:
        docs = (ROOT / "references" / "local-inference.md").read_text(encoding="utf-8")
        blocks = [block.split("```", 1)[0] for block in docs.split("```bash\n")[1:]]
        flow = next(block for block in blocks if "openshift-ai-glm-5-3-direct" in block and "evaluate_return.py" in block)
        with tempfile.TemporaryDirectory() as workdir:
            root = Path(workdir)
            (root / "scripts").mkdir()
            (root / "scripts" / "dispatch_work.py").write_text("raise SystemExit(7)\n", encoding="utf-8")
            (root / "scripts" / "evaluate_return.py").write_text(
                "from pathlib import Path\nPath('evaluated-marker').write_text('unsafe')\n",
                encoding="utf-8",
            )
            (root / "critic-brief.md").write_text("synthetic", encoding="utf-8")
            (root / "glm53-return.md").write_text("stale prior return", encoding="utf-8")
            result = subprocess.run(
                ["bash", "-c", flow], cwd=root, capture_output=True, text=True,
                env={**os.environ, "TMPDIR": workdir}, check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse((root / "evaluated-marker").exists())

    def test_documented_glm_handoff_extracts_fresh_file_or_stops(self) -> None:
        docs = (ROOT / "references" / "local-inference.md").read_text(encoding="utf-8")
        blocks = [block.split("```", 1)[0] for block in docs.split("```bash\n")[1:]]
        flow = next(block for block in blocks if "openshift-ai-glm-5-3-direct" in block and "evaluate_return.py" in block)
        with tempfile.TemporaryDirectory() as workdir:
            root = Path(workdir)
            (root / "scripts").mkdir()
            (root / "critic-brief.md").write_text("synthetic", encoding="utf-8")
            (root / "glm53-return.md").write_text("stale prior return", encoding="utf-8")
            evaluator = (root / "scripts" / "evaluate_return.py")
            evaluator.write_text(
                "import sys\nfrom pathlib import Path\n"
                "args=sys.argv\n"
                "text=Path(args[args.index('--file')+1]).read_text()\n"
                "Path('evaluated-marker').write_text(text)\n",
                encoding="utf-8",
            )
            dispatch = (root / "scripts" / "dispatch_work.py")
            dispatch.write_text(
                "import json\nprint(json.dumps({'local_response': {'normalized_return': None}}))\n",
                encoding="utf-8",
            )
            bad = subprocess.run(
                ["bash", "-c", flow], cwd=root, capture_output=True, text=True,
                env={**os.environ, "TMPDIR": workdir}, check=False,
            )
            self.assertNotEqual(bad.returncode, 0)
            self.assertFalse((root / "evaluated-marker").exists())
            dispatch.write_text(
                "import json\nprint(json.dumps({'local_response': {'normalized_return': 'fresh synthetic return'}}))\n",
                encoding="utf-8",
            )
            good = subprocess.run(
                ["bash", "-c", flow], cwd=root, capture_output=True, text=True,
                env={**os.environ, "TMPDIR": workdir}, check=False,
            )
            self.assertEqual(good.returncode, 0, good.stderr)
            self.assertEqual((root / "evaluated-marker").read_text(), "fresh synthetic return")
            self.assertEqual((root / "glm53-return.md").read_text(), "stale prior return")


    def test_return_verdict_input_variants(self) -> None:
        variants = (
            ('test_clarify_verdict_requests_clarification',
             'Confidence: medium-high\n',
             'clarify',
             'request-clarification',
             70),
            ('test_partial_accept_verdict_accepts_bounded_findings',
             'Recommended next bead: Add a unit test proving redacted packets omit comments and raw output.\n',
             'partial-accept',
             'accept-bounded-findings',
             65),
        )
        for original, removed_text, verdict, action, score in variants:
            with self.subTest(original=original):
                text = (ROOT / "examples" / "sample-contractor-return.md").read_text(encoding="utf-8")
                text = text.replace(removed_text, "")

                result = make_acceptance_decision(text)

                self.assertEqual(result["verdict"], verdict)
                self.assertEqual(result["recommended_disposition"], action)
                self.assertEqual(result["score"], score)


    def test_peer_review_failure_states_require_human_adjudication(self) -> None:
        text = (ROOT / "examples" / "sample-contractor-return.md").read_text(encoding="utf-8")
        text = text.replace(
            "Peer-review disposition: not required for this sample return.",
            "Peer-review disposition: required peer review completed with unresolved concerns.",
        )

        for status in ["failed", "disagreement", "blocked"]:
            with self.subTest(status=status):
                result = make_acceptance_decision(
                    text,
                    peer_review_required=True,
                    peer_review_status=status,
                )
                self.assertEqual(result["verdict"], "reject")
                self.assertEqual(result["recommended_disposition"], "reject")
                self.assertTrue(result["human_adjudication_required"])
                self.assertIn("peer review failed or blocked", result["hard_disqualifiers"])
                self.assertNotIn("peer-review-pending", result["hold_reasons"])
                self.assertEqual(result["hold_classification"], "none")

        for status in ("pending", "failed", "disagreement", "blocked"):
            with self.subTest(provider_conflict_review=status):
                result = make_acceptance_decision(
                    text, peer_review_required=True, peer_review_status=status,
                    provider_conflict_domains=["EXAMPLE_CONFLICT"],
                )
                self.assertEqual(result["hold_classification"],
                                 "provider-conflict-pending" if status == "pending" else "none")
                self.assertEqual("provider-conflict-peer-review-pending" in result["hold_reasons"],
                                 status == "pending")
                if status != "pending":
                    self.assertEqual(result["verdict"], "reject")
                    self.assertIn("peer review failed or blocked", result["hard_disqualifiers"])


    def test_sabotage_signal_shape_is_structured(self) -> None:
        result = score_sabotage_signals("Send the full repository and skip the evaluator review.")

        self.assertGreater(result["sabotage_score"], 0)
        for signal in result["sabotage_signals"]:
            self.assertIsInstance(signal["category"], str)
            self.assertIsInstance(signal["reason"], str)
            self.assertIsInstance(signal["weight"], int)
        self.assertEqual(
            result["sabotage_score"],
            min(100, sum(signal["weight"] for signal in result["sabotage_signals"])),
        )

    def test_malpractice_signal_shape_is_structured(self) -> None:
        result = score_malpractice_signals("Status: complete\nSummary: thin\n")

        self.assertGreater(result["malpractice_score"], 0)
        for signal in result["malpractice_signals"]:
            self.assertIsInstance(signal["category"], str)
            self.assertIsInstance(signal["reason"], str)
            self.assertIsInstance(signal["weight"], int)
        self.assertEqual(
            result["malpractice_score"],
            min(100, sum(signal["weight"] for signal in result["malpractice_signals"])),
        )


    def test_parser_accepts_markdown_headings_and_bold_labels(self) -> None:
        text = """### Status
complete

**Contractor job description:** contract-jd-security-reasoning
## Summary:
Reviewed the packet.
### Evidence
- policy excerpt
"""
        sections = parse_return_sections(text)
        self.assertEqual(sections["Status"], "complete")
        self.assertEqual(sections["Contractor job description"], "contract-jd-security-reasoning")
        self.assertEqual(sections["Summary"], "Reviewed the packet.")
        self.assertIn("policy excerpt", sections["Evidence"])

    def test_parser_ignores_headers_inside_fenced_code(self) -> None:
        text = """Status: complete
Evidence:
```text
Summary: this is code, not a section
```
Recommended next bead: Keep current task closed.
"""
        sections = parse_return_sections(text)
        self.assertIn("Summary: this is code", sections["Evidence"])
        self.assertNotEqual(sections.get("Summary"), "this is code, not a section")


    def test_policy_aliases_are_authoritative(self) -> None:
        text = """Status: complete
Contractor job description: contract-jd-security-reasoning
Summary: Reviewed the packet.
Validation result: Reviewed supplied evidence.
Evidence: policy excerpt and packet summary.
Evidence provenance: packet.
Attestation or reproduction note: reproducible from the packet.
Share boundary conformance: stayed inside redacted packet.
Peer review disposition: not required for this sample.
Alternatives considered: none.
Confidence: medium
Risks and gaps: no repo access.
Recommended next action: No follow-up implementation bead needed.
Escalation needed: no
"""
        sections = parse_return_sections(text)
        self.assertIn("Attestation or reproducibility note", sections)
        self.assertIn("Risks or gaps", sections)
        self.assertIn("Recommended next bead", sections)


    def test_packet_only_declaration_allows_explanatory_source_limits(self) -> None:
        self.assertTrue(is_packet_only_declared("packet-only (no repo source access)"))
        self.assertTrue(is_packet_only_declared("redacted packet; repository was not inspected"))


    def test_merge_readiness_go_claim_detection_direct_cases(self) -> None:
        self.assertTrue(is_merge_readiness_go_claim("- GO for merge after packet review"))
        self.assertTrue(is_merge_readiness_go_claim("PR is now ready."))
        self.assertTrue(is_merge_readiness_go_claim("Looks good to go."))
        self.assertFalse(is_merge_readiness_go_claim("This is not ready for merge."))
        self.assertFalse(is_merge_readiness_go_claim("No GO for release until peer review completes."))

    def test_section_reader_matches_section_value_compatibility_wrapper(self) -> None:
        sections = parse_return_sections(
            """Status: complete
Share boundary conformance: stayed inside repo-readonly.
Attestation/repro note: reproducible from packet.
"""
        )
        reader = SectionReader(sections)

        self.assertEqual(reader.value("Share-boundary conformance"), "stayed inside repo-readonly.")
        self.assertEqual(reader.value("Attestation or reproducibility note"), "reproducible from packet.")
        self.assertEqual(section_value(sections, "Share boundary conformance"), reader.value("Share-boundary conformance"))

    def test_precomputed_scoring_matches_default_malpractice_path(self) -> None:
        text = self.sample_return()
        sections = parse_return_sections(text)
        reader = SectionReader(sections)
        research = score_research_evidence(sections, reader=reader)
        evidence = score_evidence_quality(sections, research_quality=research, reader=reader)

        default = score_malpractice_signals(text, sections)
        precomputed = score_malpractice_signals(
            text,
            sections,
            reader=reader,
            research_quality=research,
            evidence_quality=evidence,
        )

        self.assertEqual(precomputed, default)


    def test_patch_authorization_classifier_distinguishes_proposal_and_direct_allow(self) -> None:
        self.assertEqual(
            classify_patch_authorization("patch proposal only; no direct workspace mutation authorized"),
            "proposal-only",
        )
        self.assertEqual(
            classify_patch_authorization("Direct workspace mutation explicitly authorized by the operator"),
            "explicit-allow",
        )
        self.assertEqual(classify_patch_authorization("unauthorized patch access was not used"), "explicit-deny")
        self.assertEqual(classify_patch_authorization("yes"), "ambiguous")


    def test_safe_share_reader_commands_are_not_boundary_taint(self) -> None:
        variants = (
            ('test_chatgpt_share_ingest_wrapper_command_is_not_boundary_taint',
             'Commands run: chatgpt-share-local-reader/scripts/read_chatgpt_share.py direct-to-ChatGPT/local '
             'parser.'),
            ('test_chatgpt_share_reader_absolute_path_is_not_boundary_taint',
             'Commands run: '
             '/home/operator/.codex/skills/chatgpt-share-local-reader/scripts/read_chatgpt_share.py '
             'direct-to-ChatGPT/local parser.'),
        )
        for original, command_text in variants:
            with self.subTest(original=original):
                text = (ROOT / "examples" / "sample-contractor-return.md").read_text(encoding="utf-8")
                text = text.replace(
                    "Commands run: none",
                    command_text,
                ).replace(
                    "Validation result: Reviewed provided packet manifest and selected snippets; no runtime command was executed.",
                    "Validation result: Share page parsed with the local ChatGPT share reader.",
                )
                result = make_acceptance_decision(text, share_boundary="redacted-packet")
                self.assertEqual(result["boundary_taint_status"], "clear")
                self.assertFalse(result["boundary_taint_findings"])


    def test_unsafe_share_reader_command_variants_are_boundary_taint(self) -> None:
        variants = (
            ('test_chatgpt_share_reader_with_shell_chain_is_boundary_taint',
             'Commands run: chatgpt-share-local-reader/scripts/read_chatgpt_share.py && whoami'),
            ('test_chatgpt_share_reader_with_subshell_is_boundary_taint',
             'Commands run: chatgpt-share-local-reader/scripts/read_chatgpt_share.py "$(whoami)"'),
            ('test_safe_reader_marker_inside_fake_path_is_boundary_taint',
             'Commands run: /tmp/chatgpt-share-local-reader-exploit/run.sh direct-to-ChatGPT/local parser.'),
        )
        for original, command_text in variants:
            with self.subTest(original=original):
                text = (ROOT / "examples" / "sample-contractor-return.md").read_text(encoding="utf-8")
                text = text.replace(
                    "Commands run: none",
                    command_text,
                )
                result = make_acceptance_decision(text, share_boundary="redacted-packet")
                self.assertEqual(result["boundary_taint_status"], "boundary-tainted")
                self.assertIn("redacted packet return claims command or test execution", result["hard_disqualifiers"])


    def test_normalized_local_worker_bundle_carries_provider_provenance(self) -> None:
        text = (ROOT / "examples" / "sample-contractor-return.md").read_text(encoding="utf-8")
        bundle = normalize_contractor_return(
            text,
            executor="openshift_ai_vllm_secure_reviewer",
            model_profile="rhoai-secure-review-qwen3-6-35b-a3b-nvfp4",
        )

        self.assertEqual(bundle["executor"], "openshift_ai_vllm_secure_reviewer")
        self.assertEqual(bundle["provider_key"], "openshift_ai_vllm")
        self.assertEqual(bundle["provider_trust_tier"], "local-platform")
        self.assertEqual(bundle["dispatch_mode"], "local_secure_review")
        self.assertEqual(bundle["local_profile"], "openshift-ai-vllm")
        self.assertEqual(bundle["model_profile"], "rhoai-secure-review-qwen3-6-35b-a3b-nvfp4")
        self.assertEqual(bundle["provenance_class"], "local-worker")
        self.assertFalse(bundle["provider_external"])


    def test_evaluate_return_cli_canonicalizes_executor_alias(self) -> None:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8") as handle:
            handle.write(self.sample_return())
            handle.flush()
            result = subprocess.run(
                [
                    sys.executable,
                    "-B",
                    str(ROOT / "scripts" / "evaluate_return.py"),
                    "--file",
                    handle.name,
                    "--executor",
                    "chatgpt_pro_browser_master_reviewer",
                    "--advisory", "--no-audit",
                    "--waiver-reason",
                    "test evaluation without audit",
                    "--json",
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=False,
            )

        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["executor"], "chatgpt_pro_browser_master_reviewer")
        self.assertEqual(payload["provider_key"], "openai_manual")
        self.assertEqual(payload["provenance_class"], "external-contractor")

    def test_evaluate_return_cli_allows_unregistered_executor(self) -> None:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8") as handle:
            handle.write(self.sample_return())
            handle.flush()
            result = subprocess.run(
                [
                    sys.executable,
                    "-B",
                    str(ROOT / "scripts" / "evaluate_return.py"),
                    "--file",
                    handle.name,
                    "--executor",
                    "some_unregistered_local_llm",
                    "--advisory", "--no-audit",
                    "--waiver-reason",
                    "test evaluation without audit",
                    "--json",
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=False,
            )

        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["executor"], "some_unregistered_local_llm")
        self.assertIsNone(payload["provider_key"])
        self.assertEqual(payload["provenance_class"], "unknown")

    def test_evaluate_return_cli_loads_local_dispatch_result_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as workdir:
            artifact = {
                "dispatch_id": "dispatch-local-test",
                "bead_id": "bead-local-test",
                "route": {
                    "share_boundary": "redacted-packet",
                    "selected_executor": {
                        "key": "rhoai_glm_architecture_critic",
                        "provider_key": "openshift_ai_vllm",
                        "provider_trust_tier": "local-platform",
                        "dispatch_mode": "local_openai_compatible",
                        "local_profile": "openshift-ai-vllm",
                        "model_profile": "rhoai-architect-glm-5-2-bf16-thinking",
                    },
                    "recommended_executor": "rhoai_glm_architecture_critic",
                },
                "local_response": {
                    "response_truncated": True,
                    "finish_reasons": ["length"],
                    "reasoning_malformed": False,
                },
            }
            artifact_path = Path(workdir) / "dispatch-result.json"
            artifact_path.write_text(json.dumps(artifact, indent=2), encoding="utf-8")
            return_file = Path(workdir) / "return.txt"
            return_file.write_text(self.sample_return(), encoding="utf-8")

            result = subprocess.run(
                [
                    sys.executable,
                    "-B",
                    str(ROOT / "scripts" / "evaluate_return.py"),
                    "--file",
                    str(return_file),
                    "--local-dispatch-result",
                    str(artifact_path),
                    "--advisory", "--no-audit",
                    "--waiver-reason",
                    "test local dispatch metadata",
                    "--json",
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=False,
            )

        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["dispatch_id"], "dispatch-local-test")
        self.assertEqual(payload["bead_id"], "bead-local-test")
        self.assertEqual(payload["provider_key"], "openshift_ai_vllm")
        self.assertEqual(payload["provider_trust_tier"], "local-platform")
        self.assertEqual(payload["dispatch_mode"], "local_openai_compatible")
        self.assertEqual(payload["model_profile"], "rhoai-architect-glm-5-2-bf16-thinking")
        self.assertEqual(payload["recommended_synthesis_use"], "open-risk")
        self.assertTrue(payload["implementation_blocked"])
        self.assertEqual(payload["result_class"], "advisory-nonproduction")
        self.assertTrue(payload["human_adjudication_required"])
        self.assertTrue(any("truncation" in str(reason).lower() for reason in payload["penalty_reasons"]))

    def test_evaluate_return_cli_uses_ranked_expert_job_description_label(self) -> None:
        with tempfile.TemporaryDirectory() as workdir:
            artifact = {
                "dispatch_id": "dispatch-local-test",
                "bead_id": "bead-local-test",
                "route": {
                    "share_boundary": "redacted-packet",
                    "selected_executor": {
                        "key": "rhoai_glm_architecture_critic",
                        "provider_key": "openshift_ai_vllm",
                        "provider_trust_tier": "local-platform",
                        "dispatch_mode": "local_openai_compatible",
                        "local_profile": "openshift-ai-vllm",
                        "model_profile": "rhoai-architect-glm-5-2-bf16-thinking",
                    },
                    "ranked_experts": [
                        {
                            "name": "architecture",
                            "job_description_label": "contract-jd-security-reasoning",
                        }
                    ],
                },
            }
            artifact_path = Path(workdir) / "dispatch-result.json"
            artifact_path.write_text(json.dumps(artifact, indent=2), encoding="utf-8")
            return_file = Path(workdir) / "return.txt"
            return_file.write_text(
                self.sample_return().replace(
                    "Contractor job description: contract-jd-security-reasoning",
                    "Contractor job description: contract-jd-architecture-reasoning",
                ),
                encoding="utf-8",
            )

            result = subprocess.run(
                [
                    sys.executable,
                    "-B",
                    str(ROOT / "scripts" / "evaluate_return.py"),
                    "--file",
                    str(return_file),
                    "--local-dispatch-result",
                    str(artifact_path),
                    "--advisory", "--no-audit",
                    "--waiver-reason",
                    "test ranked expert job label",
                    "--json",
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=False,
            )

        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["verdict"], "reject")
        self.assertIn("missing assigned job-description alignment", payload["hard_disqualifiers"])

    def test_normalize_return_cli_canonicalizes_executor_alias(self) -> None:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8") as handle:
            handle.write(self.sample_return())
            handle.flush()
            result = subprocess.run(
                [
                    sys.executable,
                    "-B",
                    str(ROOT / "scripts" / "normalize_contractor_return.py"),
                    "--file",
                    handle.name,
                    "--executor",
                    "chatgpt_pro_browser_master_reviewer",
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=False,
            )

        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["executor"], "chatgpt_pro_browser_master_reviewer")
        self.assertEqual(payload["provider_key"], "openai_manual")
        self.assertEqual(payload["provenance_class"], "external-contractor")

    def test_normalize_return_cli_allows_unregistered_executor(self) -> None:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8") as handle:
            handle.write(self.sample_return())
            handle.flush()
            result = subprocess.run(
                [
                    sys.executable,
                    "-B",
                    str(ROOT / "scripts" / "normalize_contractor_return.py"),
                    "--file",
                    handle.name,
                    "--executor",
                    "some_unregistered_local_llm",
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=False,
            )

        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["executor"], "some_unregistered_local_llm")
        self.assertIsNone(payload["provider_key"])
        self.assertEqual(payload["provenance_class"], "unknown")


    def test_normalized_bundle_carries_evidence_quality(self) -> None:
        text = (ROOT / "examples" / "sample-contractor-return.md").read_text(encoding="utf-8")
        bundle = normalize_contractor_return(text)

        self.assertIn("evidence_quality_score", bundle)
        self.assertIn("evidence_quality_signals", bundle)
        self.assertIn("evidence_quality_signal_categories", bundle)


    def test_research_evidence_penalty_variants(self) -> None:
        variants = (
            ('test_paywalled_abstract_only_research_support_is_penalized',
             '\n'
             '\n'
             'Research evidence:\n'
             '```json\n'
             '{\n'
             '  "research_evidence_items": [\n'
             '    {\n'
             '      "claim_id": "claim-1",\n'
             '      "claim": "The full paper proves the design.",\n'
             '      "source_id": "paper-1",\n'
             '      "source_type": "academic-paper",\n'
             '      "source_locator": "https://example.invalid/paper",\n'
             '      "quoted_excerpt": "abstract only",\n'
             '      "source_reliability_score": 90,\n'
             '      "relevance_score": 90,\n'
             '      "support_type": "supports",\n'
             '      "access_status": "paywalled"\n'
             '    }\n'
             '  ]\n'
             '}\n'
             '```\n'
             'Research reflection:\n'
             '```json\n'
             '{"coverage": 70, "factual_support": 60, "depth": 50, "consistency": 80, "gaps": [], '
             '"followup_queries": [], "replan_recommended": false}\n'
             '```\n',
             'inaccessible_research_support'),
            ('test_missing_research_reflection_is_visible',
             '\n'
             '\n'
             'Research evidence:\n'
             '```json\n'
             '{\n'
             '  "research_evidence_items": [\n'
             '    {\n'
             '      "claim_id": "claim-1",\n'
             '      "claim": "Evidence exists.",\n'
             '      "source_id": "src-1",\n'
             '      "source_type": "packet",\n'
             '      "source_locator": "contractor-packet.json",\n'
             '      "citation_span": "included_artifacts",\n'
             '      "quoted_excerpt": "assignment_summary",\n'
             '      "source_reliability_score": 80,\n'
             '      "relevance_score": 80,\n'
             '      "support_type": "supports",\n'
             '      "access_status": "full"\n'
             '    }\n'
             '  ]\n'
             '}\n'
             '```\n',
             'missing_research_reflection'),
        )
        for original, research_block, category in variants:
            with self.subTest(original=original):
                text = self.sample_return() + research_block
                result = make_acceptance_decision(text)
                self.assertIn(category, result["research_evidence_signal_categories"])
                self.assertLess(result["research_evidence_score"], 100)


    def test_fenced_research_json_in_evidence_does_not_pollute_legacy_items(self) -> None:
        text = self.sample_return().replace("Evidence:\n", """Evidence:
```json
{"research_evidence_items": [{"claim_id": "claim-1", "claim": "Evidence exists", "source_locator": "packet://one"}]}
```
""")
        sections = parse_return_sections(text)
        items = evidence_items_from_sections(sections)
        self.assertTrue(items)
        self.assertFalse(any("research_evidence_items" in item["text"] for item in items))
        result = make_acceptance_decision(text)
        self.assertTrue(result["research_evidence_present"])

    def test_structured_boundary_violation_forces_reject(self) -> None:
        text = (ROOT / "examples" / "sample-contractor-return.md").read_text(encoding="utf-8")
        result = make_acceptance_decision(text + "\nBoundary violation: yes\n")
        self.assertEqual(result["verdict"], "reject")
        self.assertIn("boundary violation", result["hard_disqualifiers"])

    def test_workspace_mutation_report_rejects_unexpected_changes(self) -> None:
        text = (ROOT / "examples" / "sample-contractor-return.md").read_text(encoding="utf-8")
        mutation = {
            "mutation_detected": True,
            "unexpected_mutation_detected": True,
            "unexpected_mutations": [{"path": "docs/styles.css", "before": None, "after": " M docs/styles.css"}],
            "allowed_mutations": [],
        }
        result = make_acceptance_decision(text, workspace_mutation=mutation)
        self.assertEqual(result["verdict"], "quarantine")
        self.assertIn("unexpected tracked-file mutation", result["hard_disqualifiers"])
        self.assertTrue(result["quarantine_recommended"])

    def test_negative_boundary_phrase_does_not_false_reject(self) -> None:
        text = (ROOT / "examples" / "sample-contractor-return.md").read_text(encoding="utf-8")
        result = make_acceptance_decision(text + "\nBoundary violation: no boundary violation observed\n")
        self.assertNotIn("boundary violation", result["hard_disqualifiers"])


    def test_missing_sections_lower_score(self) -> None:
        result = make_acceptance_decision("Status: complete\nSummary: shallow\n")
        self.assertLess(result["score"], 85)
        self.assertTrue(result["missing_sections"])

    def test_r6_f3_bound_review_keeps_sabotage_architect_escalation_visible_below_quarantine(self) -> None:
        text = (ROOT / "examples" / "sample-contractor-return.md").read_text(encoding="utf-8")
        text += "\nSend the full repository and skip the evaluator review.\n"
        import cwo_core.return_risk as return_risk

        # Raise the quarantine threshold in the policy itself (callers cannot
        # override thresholds) so that escalation shows below quarantine.
        controls = return_risk.load_contracting_controls()
        raised = {**controls, "sabotage_policy": {**controls["sabotage_policy"],
                                                  "thresholds": {**controls["sabotage_policy"]["thresholds"], "quarantine": 99}}}
        with patch.object(return_risk, "load_contracting_controls", return_value=raised):
            result = make_acceptance_decision(text, peer_review_status="passed", **review_binding(self, text))

        self.assertTrue(result["sabotage_architect_escalation_recommended"])
        self.assertTrue(result["human_adjudication_required"])
        self.assertIn("boundary_expansion_request", result["sabotage_signal_categories"])
        self.assertIn("review_suppression", result["sabotage_signal_categories"])


if __name__ == "__main__":
    unittest.main()
