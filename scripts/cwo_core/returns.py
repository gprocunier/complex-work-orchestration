from __future__ import annotations

import json
import re
from typing import Any

from .policy import executor_config, load_policy, provider_profile
from .return_boundary import (
    is_merge_readiness_go_claim,
    is_packet_only_declared,
    negates_direct_access_claim,
    normalize_review_surface,
    parse_master_review_surface_controls,
    redacted_boundary_taint_findings,
    redacted_packet_command_allowed,
    redacted_packet_direct_access_findings,
    redacted_packet_validation_claim_unsupported,
)
from .return_common import (
    add_signal,
    affirmative_field,
    malpractice_signal_weights,
    negative_field,
    nonempty_work_field,
    strip_fenced_blocks,
)
from .return_evidence import (
    RESEARCH_ACCESS_STATUSES,
    RESEARCH_SOURCE_TYPES,
    RESEARCH_SUPPORT_TYPES,
    as_research_list,
    as_research_reflection,
    booleanish,
    evidence_items_from_sections,
    research_evidence_from_sections,
    research_score_value,
    research_sections_present,
    score_evidence_quality,
    score_research_evidence,
    structured_json_values,
)
from .return_language import default_expected_return_language, validate_expected_return_language
from .return_sections import (
    RETURN_CONTROL_SECTIONS,
    RETURN_SECTION_ALIASES,
    SectionReader,
    canonical_return_section,
    parse_return_header,
    parse_return_sections,
    return_section_aliases,
    section_lookup_key,
    section_value,
)
from .return_risk import (
    SECRET_ASSIGNMENT_RE,
    classify_patch_authorization,
    critical_deferral_present,
    direct_mutation_authorized,
    explicit_assigned_delivery_language,
    fabricated_evidence_admission_present,
    internal_narration_present,
    malpractice_thresholds,
    non_implementation_review_job,
    opaque_provider_policy_intervention_present,
    patch_proposal_evidence,
    procedural_hold_metadata,
    provider_conflict_disposition_inadequate,
    provider_policy_misrepresentation_present,
    sabotage_signal_weights,
    sabotage_thresholds,
    score_malpractice_signals,
    score_sabotage_signals,
    typed_deferral_allowed_for_work,
    typed_follow_up_deferral_present,
    work_rerouting_or_subversion_reasons,
    workspace_unexpected_mutations,
)
from .types import (
    AcceptanceDecision,
    ContractorReturnBundle,
    MalpracticeSignalResult,
    ProceduralHoldMetadata,
    ReturnSignal,
    ReturnProvenance,
    SabotageSignalResult,
)
from .util import artifact_hash


CHATGPT_MASTER_REVIEW_EXECUTOR = "chatgpt_pro_browser_master_reviewer"
CHATGPT_MASTER_REVIEW_JOB_LABEL = "contract-jd-master-plan-review"


__all__ = [
    "AcceptanceDecision",
    "CHATGPT_MASTER_REVIEW_EXECUTOR",
    "CHATGPT_MASTER_REVIEW_JOB_LABEL",
    "ContractorReturnBundle",
    "MalpracticeSignalResult",
    "ProceduralHoldMetadata",
    "RESEARCH_ACCESS_STATUSES",
    "RESEARCH_SOURCE_TYPES",
    "RESEARCH_SUPPORT_TYPES",
    "RETURN_CONTROL_SECTIONS",
    "RETURN_SECTION_ALIASES",
    "ReturnSignal",
    "ReturnProvenance",
    "SECRET_ASSIGNMENT_RE",
    "SectionReader",
    "SabotageSignalResult",
    "add_signal",
    "affirmative_field",
    "as_research_list",
    "as_research_reflection",
    "booleanish",
    "boundary_taint_status",
    "canonical_return_section",
    "classify_patch_authorization",
    "critical_deferral_present",
    "direct_mutation_authorized",
    "evidence_items_from_sections",
    "evidence_quality_thresholds",
    "executor_default_synthesis_use",
    "explicit_assigned_delivery_language",
    "fabricated_evidence_admission_present",
    "internal_narration_present",
    "is_merge_readiness_go_claim",
    "is_packet_only_declared",
    "job_description_matches",
    "make_acceptance_decision",
    "malpractice_signal_weights",
    "malpractice_thresholds",
    "negates_direct_access_claim",
    "negative_field",
    "non_implementation_review_job",
    "nonempty_work_field",
    "normalize_contractor_return",
    "normalize_review_surface",
    "opaque_provider_policy_intervention_present",
    "parse_master_review_surface_controls",
    "parse_return_header",
    "parse_return_sections",
    "patch_proposal_evidence",
    "procedural_hold_metadata",
    "provider_conflict_disposition_inadequate",
    "provider_policy_misrepresentation_present",
    "recommend_synthesis_use",
    "redacted_boundary_taint_findings",
    "redacted_packet_command_allowed",
    "redacted_packet_direct_access_findings",
    "redacted_packet_validation_claim_unsupported",
    "research_evidence_from_sections",
    "research_score_value",
    "research_sections_present",
    "return_provenance",
    "return_section_aliases",
    "sabotage_signal_weights",
    "sabotage_thresholds",
    "score_evidence_quality",
    "score_malpractice_signals",
    "score_research_evidence",
    "score_sabotage_signals",
    "section_lookup_key",
    "section_value",
    "strip_fenced_blocks",
    "structured_json_values",
    "typed_deferral_allowed_for_work",
    "typed_follow_up_deferral_present",
    "work_rerouting_or_subversion_reasons",
    "workspace_unexpected_mutations",
]


def resolve_return_language_context(
    expected_return_language: str | None,
    expected_return_language_source: str | None,
    *,
    provenance: ReturnProvenance,
    share_boundary: str | None,
) -> tuple[str | None, str]:
    explicit = validate_expected_return_language(expected_return_language)
    if explicit is not None:
        return explicit, expected_return_language_source or "explicit"
    evidence_lane = provenance.get("provenance_class") in {"external-contractor", "local-worker"}
    if share_boundary in {"redacted-packet", "repo-readonly", "patch-branch"}:
        evidence_lane = True
    if evidence_lane:
        return default_expected_return_language(), expected_return_language_source or "policy-default"
    return None, expected_return_language_source or "not-enforced"


def evidence_quality_thresholds() -> dict[str, int]:
    configured = load_policy("acceptance-policy").get("evidence_quality", {}).get("thresholds", {})
    return {
        "primary": int(configured.get("primary", 85)),
        "salvage": int(configured.get("salvage", 60)),
        "reject_below": int(configured.get("reject_below", 40)),
    }




def boundary_taint_status(findings: list[str], *, share_boundary: str | None) -> str:
    if findings:
        return "boundary-tainted"
    if share_boundary == "redacted-packet":
        return "clear"
    return "not-applicable"


def return_provenance(
    *,
    executor: str | None = None,
    provider_key: str | None = None,
    provider_trust_tier: str | None = None,
    dispatch_mode: str | None = None,
    local_profile: str | None = None,
    model_profile: str | None = None,
) -> ReturnProvenance:
    executor_info = {}
    if executor:
        try:
            executor_info = executor_config(executor)
        except SystemExit:
            executor_info = {}

    resolved_provider_key = provider_key or executor_info.get("provider_key")
    provider = provider_profile(str(resolved_provider_key) if resolved_provider_key else None)
    registry_trust_tier = provider.get("trust_tier")
    resolved_trust_tier = provider_trust_tier or registry_trust_tier
    resolved_dispatch_mode = dispatch_mode or executor_info.get("dispatch_mode")
    resolved_local_profile = local_profile or executor_info.get("local_profile")
    resolved_model_profile = model_profile or executor_info.get("model_profile")
    provider_external = provider.get("external")
    warnings: list[str] = []
    if provider_key and registry_trust_tier and provider_trust_tier and provider_trust_tier != registry_trust_tier:
        warnings.append("provider_trust_tier does not match provider registry")
    if executor and not executor_info:
        warnings.append("executor not found in executor registry")
    if resolved_provider_key and not provider:
        warnings.append("provider_key not found in provider registry")

    local_provider_keys = {"local_inference", "openshift_ai_vllm"}
    local_dispatch_modes = {"local_openai_compatible", "local_secure_review"}
    if resolved_dispatch_mode in local_dispatch_modes or resolved_provider_key in local_provider_keys:
        provenance_class = "local-worker"
    elif provider_external is True:
        provenance_class = "external-contractor"
    elif resolved_provider_key:
        provenance_class = "internal"
    else:
        provenance_class = "unknown"

    return {
        "executor": executor,
        "provider_key": resolved_provider_key,
        "provider_trust_tier": resolved_trust_tier,
        "provider_family": provider.get("family"),
        "provider_retention_class": provider.get("retention_class"),
        "provider_external": provider_external,
        "dispatch_mode": resolved_dispatch_mode,
        "local_profile": resolved_local_profile,
        "model_profile": resolved_model_profile,
        "provenance_class": provenance_class,
        "provenance_warnings": warnings,
    }


def executor_default_synthesis_use(executor: str | None) -> str | None:
    if not executor:
        return None
    try:
        config = executor_config(executor)
    except SystemExit:
        return None
    value = str(config.get("default_synthesis_use") or "").strip().lower().replace("_", "-")
    return value or None


def recommend_synthesis_use(
    *,
    verdict: str,
    recommended_disposition: str,
    evidence_quality_score: int,
    boundary_status: str,
    executor: str | None,
    provider_family: str | None,
    hard_disqualifiers: list[str],
    local_dispatch_incomplete: bool = False,
) -> str:
    thresholds = evidence_quality_thresholds()
    default_use = executor_default_synthesis_use(executor)
    if boundary_status == "boundary-tainted" or verdict == "quarantine":
        return "quarantine"
    if hard_disqualifiers or verdict == "reject" or recommended_disposition == "reject":
        return "reject"
    if local_dispatch_incomplete and verdict in {"accept", "clarify", "partial-accept"}:
        return "salvage-only"
    if default_use in {"salvage-only", "open-risk", "partial-only"}:
        return default_use
    if provider_family == "google" and verdict in {"accept", "partial-accept"}:
        return "salvage-only"
    if evidence_quality_score < thresholds["reject_below"]:
        return "reject"
    if evidence_quality_score < thresholds["salvage"]:
        return "salvage-only"
    if evidence_quality_score < thresholds["primary"]:
        return "salvage-only"
    if verdict == "accept":
        return "primary"
    if verdict == "partial-accept":
        return "salvage-only"
    if verdict == "clarify":
        return "open-risk"
    return "reject"


def job_description_matches(sections: dict[str, str], expected_label: str | None) -> bool:
    if not expected_label:
        return True
    value = section_value(sections, "Contractor job description")
    if not value:
        return False
    labels = set(re.findall(r"\bcontract-jd-[a-z0-9-]+\b", value.lower()))
    return expected_label.lower() in labels


def normalize_contractor_return(
    text: str,
    *,
    bead_id: str | None = None,
    dispatch_id: str | None = None,
    share_boundary: str | None = None,
    job_description_label: str | None = None,
    packet_sha256: str | None = None,
    executor: str | None = None,
    provider_key: str | None = None,
    provider_trust_tier: str | None = None,
    dispatch_mode: str | None = None,
    local_profile: str | None = None,
    model_profile: str | None = None,
    expected_return_language: str | None = None,
    expected_return_language_source: str | None = None,
    workspace_mutation: dict[str, Any] | None = None,
) -> ContractorReturnBundle:
    sections = parse_return_sections(text)
    reader = SectionReader(sections)
    required = load_policy("acceptance-policy").get("contractor_return_required_sections", [])
    missing = [section for section in required if not sections.get(section)]
    research_evidence = score_research_evidence(sections, reader=reader)
    evidence_quality = score_evidence_quality(sections, research_quality=research_evidence, reader=reader)
    provenance = return_provenance(
        executor=executor,
        provider_key=provider_key,
        provider_trust_tier=provider_trust_tier,
        dispatch_mode=dispatch_mode,
        local_profile=local_profile,
        model_profile=model_profile,
    )
    resolved_language, language_source = resolve_return_language_context(
        expected_return_language,
        expected_return_language_source,
        provenance=provenance,
        share_boundary=share_boundary,
    )
    sabotage = score_sabotage_signals(
        text,
        sections,
        reader=reader,
        expected_return_language=resolved_language,
        expected_return_language_source=language_source,
    )
    malpractice = score_malpractice_signals(
        text,
        sections,
        reader=reader,
        research_quality=research_evidence,
        evidence_quality=evidence_quality,
    )
    master_review_controls = parse_master_review_surface_controls(
        sections,
        reader=reader,
        share_boundary=share_boundary,
    )
    boundary_taint_findings = redacted_boundary_taint_findings(text, sections, share_boundary=share_boundary)
    bundle: dict[str, Any] = {
        "bundle_type": "contractor-return-bundle",
        "version": 2,
        "bead_id": bead_id,
        "dispatch_id": dispatch_id,
        "share_boundary": share_boundary,
        "job_description_label": job_description_label,
        "packet_sha256": packet_sha256,
        **provenance,
        "sections": sections,
        "boundary_taint_status": boundary_taint_status(boundary_taint_findings, share_boundary=share_boundary),
        "boundary_taint_findings": boundary_taint_findings,
        "required_sections_missing": missing,
        "required_sections_present": [section for section in required if section in sections and section not in missing],
        "evidence_items": evidence_items_from_sections(sections, reader=reader),
        **master_review_controls,
        **evidence_quality,
        **research_evidence,
        "workspace_mutation": workspace_mutation,
        "implementation_blocked": False,
        "hold_reasons": [],
        "hold_classification": "none",
        **sabotage,
        **malpractice,
    }
    bundle["bundle_sha256"] = artifact_hash(json.dumps(bundle, sort_keys=True))
    return bundle



def make_acceptance_decision(
    text: str,
    *,
    bead_id: str | None = None,
    dispatch_id: str | None = None,
    packet_sha256: str | None = None,
    share_boundary: str | None = None,
    job_description_label: str | None = None,
    executor: str | None = None,
    provider_key: str | None = None,
    provider_trust_tier: str | None = None,
    dispatch_mode: str | None = None,
    local_profile: str | None = None,
    model_profile: str | None = None,
    expected_return_language: str | None = None,
    expected_return_language_source: str | None = None,
    peer_review_required: bool = False,
    peer_review_status: str = "not-run",
    provider_conflict_domains: list[str] | None = None,
    sabotage_review_threshold: int | None = None,
    sabotage_quarantine_threshold: int | None = None,
    malpractice_review_threshold: int | None = None,
    malpractice_reject_threshold: int | None = None,
    workspace_mutation: dict[str, Any] | None = None,
    mutation_strategy: str = "reject",
    local_response_truncated: bool = False,
    local_finish_reasons: list[str] | None = None,
    local_reasoning_malformed: bool = False,
    local_completion_status: str | None = None,
    local_usable_final_content: bool | None = None,
) -> AcceptanceDecision:
    policy = load_policy("acceptance-policy")
    provenance = return_provenance(
        executor=executor,
        provider_key=provider_key,
        provider_trust_tier=provider_trust_tier,
        dispatch_mode=dispatch_mode,
        local_profile=local_profile,
        model_profile=model_profile,
    )
    resolved_language, language_source = resolve_return_language_context(
        expected_return_language,
        expected_return_language_source,
        provenance=provenance,
        share_boundary=share_boundary,
    )
    sections = parse_return_sections(text)
    reader = SectionReader(sections)
    required = policy.get("contractor_return_required_sections", [])
    missing = [section for section in required if not sections.get(section)]
    penalties = policy.get("score", {}).get("penalties", {})
    score = int(policy.get("score", {}).get("start", 100))
    penalty_reasons: list[str] = []
    hard_disqualifiers: list[str] = []
    research_evidence = score_research_evidence(sections, reader=reader)
    master_review_controls = parse_master_review_surface_controls(
        sections,
        reader=reader,
        share_boundary=share_boundary,
    )
    master_review_packet_only_go_hold = bool(
        (
            executor == CHATGPT_MASTER_REVIEW_EXECUTOR
            or (job_description_label or "").strip().lower() == CHATGPT_MASTER_REVIEW_JOB_LABEL
        )
        and master_review_controls["packet_only_go_hold"]
    )
    evidence_quality = score_evidence_quality(sections, research_quality=research_evidence, reader=reader)
    evidence_thresholds = evidence_quality_thresholds()

    local_finish_reasons = [
        str(reason)
        for reason in (local_finish_reasons or [])
        if isinstance(reason, str) and reason.strip()
    ]
    local_completion_reason_lengths = {
        reason.strip().lower() for reason in local_finish_reasons
    }
    local_reasoning_malformed = bool(local_reasoning_malformed)
    local_completion_status = str(local_completion_status or "").strip().lower() or None
    local_response_truncated_by_length = bool(
        local_response_truncated
        or "length" in local_completion_reason_lengths
    )
    local_completion_incomplete = bool(
        local_response_truncated_by_length
        or local_reasoning_malformed
        or (local_completion_status is not None and local_completion_status != "completed")
        or local_usable_final_content is False
    )

    if local_response_truncated_by_length:
        penalty_reasons.append("local response truncation detected; requires confirmation of completeness")
    if local_reasoning_malformed:
        penalty_reasons.append("local reasoning content malformed; extracted reasoning should be manually reviewed")
    if local_completion_status is not None and local_completion_status != "completed":
        penalty_reasons.append(
            f"local completion status {local_completion_status!r} is incomplete and cannot support a verdict"
        )
    if local_usable_final_content is False:
        penalty_reasons.append("local dispatch did not produce usable final content")

    if missing:
        score -= penalties.get("missing_required_section", 20) * len(missing)
        penalty_reasons.append("missing sections: " + ", ".join(missing))
    evidence = sections.get("Evidence", "")
    if not evidence or len(evidence.split()) < 4:
        score -= penalties.get("no_concrete_evidence", 20)
        penalty_reasons.append("evidence is missing or too thin")
    validation = sections.get("Validation result", "")
    if not validation or re.search(r"\b(none|not run|n/a)\b", validation, re.I):
        score -= penalties.get("non_reproducible_validation", 15)
        penalty_reasons.append("validation is missing or non-reproducible")
    recommendation = sections.get("Recommended next bead", "")
    if not recommendation or len(recommendation.split()) < 4:
        score -= penalties.get("vague_recommendation", 15)
        penalty_reasons.append("recommended next bead is vague")
    if not sections.get("Confidence"):
        score -= penalties.get("missing_confidence", 10)
        penalty_reasons.append("confidence missing")
    if not sections.get("Risks or gaps"):
        score -= penalties.get("missing_residual_risk", 10)
        penalty_reasons.append("risks or gaps missing")
    if evidence_quality["evidence_quality_score"] < evidence_thresholds["primary"]:
        score -= penalties.get("weak_evidence_quality", 20)
        penalty_reasons.append(
            f"evidence quality below primary threshold: {evidence_quality['evidence_quality_score']}"
        )

    boundary_violation = reader.value("Boundary violation")
    if affirmative_field(boundary_violation):
        hard_disqualifiers.append("boundary violation")

    patch_authorization = reader.value("Patch authorization")
    patch_authorization_state = classify_patch_authorization(patch_authorization)
    files_changed = reader.value("Files changed")
    commands_run = reader.value("Commands run")
    if share_boundary == "patch-branch":
        if not patch_proposal_evidence(sections) and not (nonempty_work_field(files_changed) and nonempty_work_field(commands_run)):
            hard_disqualifiers.append("patch branch return missing patch proposal or direct-change evidence")
        elif nonempty_work_field(files_changed) and not patch_proposal_evidence(sections) and patch_authorization_state != "explicit-allow":
            hard_disqualifiers.append("patch branch direct mutation missing explicit authorization")
    elif nonempty_work_field(files_changed) and patch_authorization_state != "explicit-allow":
        hard_disqualifiers.append("unapproved patch or repo access")
    if patch_authorization_state == "explicit-deny" and affirmative_field(patch_authorization):
        hard_disqualifiers.append("unapproved patch or repo access")
    boundary_taint_findings = redacted_boundary_taint_findings(text, sections, share_boundary=share_boundary)
    hard_disqualifiers.extend(boundary_taint_findings)
    unexpected_mutations = workspace_unexpected_mutations(workspace_mutation)
    workspace_quarantine = bool(unexpected_mutations and mutation_strategy == "reject")
    if unexpected_mutations:
        if mutation_strategy == "reject":
            hard_disqualifiers.append("unexpected tracked-file mutation")
        else:
            score -= 20
            penalty_reasons.append("unexpected tracked-file mutation observed")

    if job_description_label and not job_description_matches(sections, job_description_label):
        hard_disqualifiers.append("missing assigned job-description alignment")
    secret_spill = reader.value("Secret or personal-data spill", "Secret spill", "Personal-data spill")
    if affirmative_field(secret_spill):
        hard_disqualifiers.append("suspected secret or personal-data spill")
    if SECRET_ASSIGNMENT_RE.search(text):
        hard_disqualifiers.append("suspected secret or personal-data spill")
    scope_compliance = reader.value("Scope compliance")
    scope_lower = scope_compliance.strip().lower()
    scope_noncompliant = bool(
        re.match(r"^(no|false)\b", scope_lower)
        and not re.search(r"\b(no scope creep|no deviation|no out-of-scope work)\b", scope_lower)
    ) or bool(
        scope_compliance
        and re.search(r"\b(outside assigned scope|broadened scope|scope creep)\b", scope_compliance, re.I)
        and not re.search(r"\b(no|not observed|not present)\s+(scope creep|out-of-scope|deviation)\b", scope_compliance, re.I)
    )
    if scope_compliance and not affirmative_field(scope_compliance) and not scope_noncompliant:
        penalty_reasons.append("scope compliance field is unclear")
    if scope_noncompliant:
        hard_disqualifiers.append("scope creep beyond assigned bead")
        score -= penalties.get("scope_creep", 10)

    sabotage = score_sabotage_signals(
        text,
        sections,
        provider_conflict_domains=provider_conflict_domains,
        review_threshold=sabotage_review_threshold,
        quarantine_threshold=sabotage_quarantine_threshold,
        reader=reader,
        expected_return_language=resolved_language,
        expected_return_language_source=language_source,
    )
    malpractice = score_malpractice_signals(
        text,
        sections,
        provider_conflict_domains=provider_conflict_domains,
        review_threshold=malpractice_review_threshold,
        reject_threshold=malpractice_reject_threshold,
        reader=reader,
        research_quality=research_evidence,
        evidence_quality=evidence_quality,
    )
    if sabotage["quarantine_recommended"]:
        hard_disqualifiers.append("suspected sabotage or malpractice")
    elif sabotage["sabotage_review_recommended"]:
        score -= penalties.get("sabotage_review", 20)
        penalty_reasons.append("sabotage or malpractice signals require review")
    if malpractice["malpractice_reject_recommended"]:
        hard_disqualifiers.append("suspected sabotage or malpractice")
    elif malpractice["malpractice_review_recommended"]:
        score -= penalties.get("malpractice_review", 10)
        penalty_reasons.append("malpractice signals require review")

    peer_required = bool(
        peer_review_required
        or sabotage["sabotage_review_recommended"]
        or malpractice["malpractice_review_recommended"]
        or provider_conflict_domains
    )
    hold = procedural_hold_metadata(
        peer_required=peer_required,
        peer_review_status=peer_review_status,
        provider_conflict_domains=provider_conflict_domains,
        sabotage_review_recommended=bool(sabotage["sabotage_review_recommended"]),
        malpractice_review_recommended=bool(malpractice["malpractice_review_recommended"]),
    )
    if master_review_packet_only_go_hold:
        hold["implementation_blocked"] = True
        reason = "reviewer packet-only GO claim for merge/readiness requires architect adjudication"
        if reason not in hold["hold_reasons"]:
            hold["hold_reasons"].append(reason)
    implementation_blocked = bool(hold["implementation_blocked"])
    peer_disposition = reader.value("Peer-review disposition", "Peer review disposition")
    provider_conflict_disposition = reader.value("Provider conflict disposition")
    if peer_required and re.search(r"\b(not required|not needed|unnecessary|no peer review required|no peer review needed)\b", peer_disposition, re.I):
        hard_disqualifiers.append("peer review incorrectly dismissed")
    if provider_conflict_domains and provider_conflict_disposition_inadequate(provider_conflict_disposition):
        hard_disqualifiers.append("provider conflict disposition incorrectly dismissed")
    if peer_required and peer_review_status in {"failed", "disagreement", "blocked"}:
        hard_disqualifiers.append("peer review failed or blocked")

    score = max(0, min(100, score))
    escalation = re.search(r"^\s*Escalation needed\s*:\s*(yes|true|required)", text, re.I | re.M)
    thresholds = policy.get("score", {}).get("thresholds", {})
    if sabotage["quarantine_recommended"] or workspace_quarantine:
        verdict = "quarantine"
    elif hard_disqualifiers:
        verdict = "reject"
    elif escalation:
        verdict = "escalate"
    elif score >= thresholds.get("accept", 85):
        verdict = "accept"
    elif score >= thresholds.get("clarify", 70):
        verdict = "clarify"
    elif score >= thresholds.get("partial_accept", 50):
        verdict = "partial-accept"
    else:
        verdict = "reject"

    human_adjudication_required = bool(
        hard_disqualifiers
        or escalation
        or verdict in {"escalate", "quarantine"}
        or sabotage["sabotage_architect_escalation_recommended"]
        or implementation_blocked
        or peer_review_status in {"failed", "disagreement", "blocked"}
        or workspace_quarantine
        or local_completion_incomplete
    )
    if verdict == "quarantine":
        recommended_disposition = "quarantine-and-adjudicate"
    elif implementation_blocked and not hard_disqualifiers:
        if master_review_packet_only_go_hold:
            recommended_disposition = "architect-adjudication"
        else:
            recommended_disposition = "run-peer-review"
    elif hard_disqualifiers:
        recommended_disposition = "reject"
    elif human_adjudication_required:
        recommended_disposition = "architect-adjudication"
    elif verdict == "accept":
        recommended_disposition = "accept-findings"
    elif verdict == "clarify":
        recommended_disposition = "request-clarification"
    elif verdict == "partial-accept":
        recommended_disposition = "accept-bounded-findings"
    else:
        recommended_disposition = "reject"

    signal_categories = sorted(
        set(sabotage.get("sabotage_signal_categories", []))
        | set(malpractice.get("malpractice_signal_categories", []))
    )
    resolved_boundary_status = boundary_taint_status(boundary_taint_findings, share_boundary=share_boundary)
    if local_completion_incomplete and recommended_disposition not in {"reject", "quarantine", "architect-adjudication"}:
        recommended_disposition = "request-clarification"
    recommended_synthesis_use = recommend_synthesis_use(
        verdict=verdict,
        recommended_disposition=recommended_disposition,
        evidence_quality_score=int(evidence_quality["evidence_quality_score"]),
        boundary_status=resolved_boundary_status,
        executor=executor,
        provider_family=provenance.get("provider_family"),
        hard_disqualifiers=hard_disqualifiers,
        local_dispatch_incomplete=local_completion_incomplete,
    )
    if implementation_blocked and recommended_synthesis_use == "primary":
        recommended_synthesis_use = "open-risk"

    return {
        "dispatch_id": dispatch_id,
        "bead_id": bead_id,
        "packet_sha256": packet_sha256,
        "share_boundary": share_boundary,
        **provenance,
        "verdict": verdict,
        "score": score,
        "missing_sections": missing,
        "penalty_reasons": penalty_reasons,
        "hard_disqualifiers": hard_disqualifiers,
        "sabotage_score": sabotage["sabotage_score"],
        "sabotage_signals": sabotage["sabotage_signals"],
        "sabotage_signal_categories": sabotage["sabotage_signal_categories"],
        "sabotage_review_recommended": sabotage["sabotage_review_recommended"],
        "sabotage_architect_escalation_recommended": sabotage["sabotage_architect_escalation_recommended"],
        "expected_return_language": sabotage["expected_return_language"],
        "expected_return_language_source": sabotage["expected_return_language_source"],
        "return_language_status": sabotage["return_language_status"],
        "return_language_findings": sabotage["return_language_findings"],
        "detected_letter_scripts": sabotage["detected_letter_scripts"],
        "unexpected_script_ratio": sabotage["unexpected_script_ratio"],
        "unicode_normalization_changed": sabotage["unicode_normalization_changed"],
        "evidence_quality_score": evidence_quality["evidence_quality_score"],
        "evidence_quality_signals": evidence_quality["evidence_quality_signals"],
        "evidence_quality_signal_categories": evidence_quality["evidence_quality_signal_categories"],
        "research_evidence_present": research_evidence["research_evidence_present"],
        "research_evidence_items": research_evidence["research_evidence_items"],
        "research_contradictions": research_evidence["research_contradictions"],
        "research_reflection": research_evidence["research_reflection"],
        "research_evidence_score": research_evidence["research_evidence_score"],
        "research_evidence_signals": research_evidence["research_evidence_signals"],
        "research_evidence_signal_categories": research_evidence["research_evidence_signal_categories"],
        "research_unresolved_contradiction_count": research_evidence["research_unresolved_contradiction_count"],
        "research_replan_recommended": research_evidence["research_replan_recommended"],
        "malpractice_score": malpractice["malpractice_score"],
        "malpractice_signals": malpractice["malpractice_signals"],
        "malpractice_signal_categories": malpractice["malpractice_signal_categories"],
        "malpractice_review_recommended": malpractice["malpractice_review_recommended"],
        "malpractice_reject_recommended": malpractice["malpractice_reject_recommended"],
        "signal_categories": signal_categories,
        "peer_review_required": peer_required,
        "peer_review_status": peer_review_status,
        **{
            key: master_review_controls[key]
            for key in [
                "review_surface",
                "source_inspection",
                "sources_inspected",
                "sources_not_inspected",
                "independent_verification",
                "packet_reported_claims",
            ]
        },
        "review_surface_packet_only": bool(master_review_controls["review_surface_packet_only"]),
        "source_inspection_packet_only": bool(master_review_controls["source_inspection_packet_only"]),
        "go_for_pr_merge_readiness_claimed": bool(master_review_controls["go_for_pr_merge_readiness_claimed"]),
        "review_surface_mismatch": bool(master_review_controls["review_surface_mismatch"]),
        "review_surface_required_evidence_missing": bool(master_review_controls["review_surface_required_evidence_missing"]),
        "review_surface_mismatch_reasons": list(master_review_controls["review_surface_mismatch_reasons"]),
        "master_review_packet_only_go_hold": bool(master_review_controls["packet_only_go_hold"]),
        "implementation_blocked": implementation_blocked,
        "hold_reasons": hold["hold_reasons"],
        "hold_classification": hold["hold_classification"],
        "patch_authorization_state": patch_authorization_state,
        "provider_conflict_domains": provider_conflict_domains or [],
        "boundary_taint_status": resolved_boundary_status,
        "boundary_taint_findings": boundary_taint_findings,
        "workspace_mutation": workspace_mutation,
        "human_adjudication_required": human_adjudication_required,
        "recommended_disposition": recommended_disposition,
        "recommended_synthesis_use": recommended_synthesis_use,
        "local_completion_status": local_completion_status,
        "local_usable_final_content": local_usable_final_content,
        "quarantine_recommended": bool(sabotage["quarantine_recommended"] or workspace_quarantine),
        "escalation_flagged": bool(escalation),
        "architect_review_required": True,
        "sections": sections,
    }
