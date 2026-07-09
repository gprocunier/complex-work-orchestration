from __future__ import annotations

from typing import Any, Literal, TypedDict


RiskLevel = Literal["low", "medium", "high", "critical"]
SensitivityLevel = Literal["public", "redacted", "internal", "restricted"]
AcceptanceVerdict = Literal["accept", "clarify", "partial-accept", "reject", "escalate", "quarantine"]
SynthesisUse = Literal["primary", "salvage-only", "open-risk", "partial-only", "reject", "quarantine"]


class ResearchEvidenceQuality(TypedDict, total=False):
    research_evidence_present: bool
    research_evidence_items: list[dict[str, Any]]
    research_contradictions: list[dict[str, Any]]
    research_reflection: dict[str, Any]
    research_unresolved_contradiction_count: int
    research_replan_recommended: bool
    research_evidence_score: int
    research_evidence_signals: list[dict[str, Any]]
    research_evidence_signal_categories: list[str]


class EvidenceQuality(TypedDict, total=False):
    evidence_quality_score: int
    evidence_quality_signals: list[dict[str, Any]]
    evidence_quality_signal_categories: list[str]


class ContractorReturnBundle(TypedDict, total=False):
    bundle_type: str
    version: int
    bead_id: str | None
    dispatch_id: str | None
    share_boundary: str | None
    job_description_label: str | None
    packet_sha256: str | None
    sections: dict[str, str]
    bundle_sha256: str


class AcceptanceDecision(TypedDict, total=False):
    verdict: AcceptanceVerdict
    score: int
    recommended_disposition: str
    recommended_synthesis_use: SynthesisUse
    missing_sections: list[str]
    hard_disqualifiers: list[str]
    human_adjudication_required: bool
    quarantine_recommended: bool


class SynthesisInputSummary(TypedDict, total=False):
    lane: str
    provider_camp: str
    disposition: str
    boundary_status: str
    recommended_synthesis_use: SynthesisUse


class SynthesisEvaluation(TypedDict, total=False):
    consensus_points: list[str]
    material_disagreements: list[str]
    unsupported_claims: list[str]
    risk_deltas: list[str]
    input_dispositions: list[SynthesisInputSummary]
