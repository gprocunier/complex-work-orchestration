from __future__ import annotations

from typing import Any, Literal, TypedDict


RiskLevel = Literal["low", "medium", "high", "critical"]
SensitivityLevel = Literal["public", "redacted", "internal", "restricted"]
AcceptanceVerdict = Literal["accept", "clarify", "partial-accept", "reject", "escalate", "quarantine"]
SynthesisUse = Literal["primary", "salvage-only", "open-risk", "partial-only", "reject", "quarantine"]
RouteName = Literal["external-contract", "local-worker", "architect-review", "internal-worker"]
BeadsContextDepth = Literal["none", "summary", "focused", "heavy", "audit"]
BeadsContextDepthSource = Literal["explicit", "autosized"]
OrchestrationLevel = Literal[
    "in-thread",
    "lightweight-beads",
    "full-harness",
    "external-contract",
    "local-worker",
    "publish-release",
]


class ReturnSignal(TypedDict):
    category: str
    reason: str
    weight: int


class ReturnLanguageResult(TypedDict, total=False):
    expected_return_language: str | None
    expected_return_language_source: str
    return_language_status: str
    return_language_findings: list[ReturnSignal]
    detected_letter_scripts: list[str]
    unexpected_script_ratio: float
    unicode_normalization_changed: bool


class SabotageSignalResult(TypedDict, total=False):
    sabotage_score: int
    sabotage_signals: list[ReturnSignal]
    sabotage_signal_categories: list[str]
    sabotage_review_recommended: bool
    sabotage_architect_escalation_recommended: bool
    quarantine_recommended: bool
    expected_return_language: str | None
    expected_return_language_source: str
    return_language_status: str
    return_language_findings: list[ReturnSignal]
    detected_letter_scripts: list[str]
    unexpected_script_ratio: float
    unicode_normalization_changed: bool


class MalpracticeSignalResult(TypedDict, total=False):
    malpractice_score: int
    malpractice_signals: list[ReturnSignal]
    malpractice_signal_categories: list[str]
    malpractice_review_recommended: bool
    malpractice_reject_recommended: bool


class ProceduralHoldMetadata(TypedDict, total=False):
    implementation_blocked: bool
    hold_reasons: list[str]
    hold_classification: str


class ReturnProvenance(TypedDict, total=False):
    executor: str | None
    provider_key: str | None
    provider_trust_tier: str | None
    provider_family: str | None
    provider_retention_class: str | None
    provider_external: bool | None
    dispatch_mode: str | None
    local_profile: str | None
    model_profile: str | None
    provenance_class: str
    provenance_warnings: list[str]


class ExecutorCandidate(TypedDict, total=False):
    key: str
    display_name: str
    role: str | None
    venue: str | None
    dispatch_mode: str | None
    external: bool
    provider_key: str | None
    provider_family: str | None
    provider_trust_tier: str | None
    provider_retention_class: str | None
    local_profile: str | None
    model_profile: str | None
    access_profile: str | None
    access_profile_details: dict[str, Any] | None
    transport: dict[str, Any] | None
    supports_repo_read: bool
    supports_repo_write: bool
    supports_shell: bool
    supports_web: bool
    score: int
    policy_violations: list[str]
    reasons: list[str]
    codex_pickup: str
    acceptance_required: bool
    architect_review_required: bool
    critique_mode: str | None


class ExpertResult(TypedDict, total=False):
    name: str
    display_name: str
    discipline: str
    score: int
    task_class: str
    default_risk: RiskLevel
    job_description_label: str
    review_stage: str
    output_contract: list[str]
    acceptance_checks: list[str]
    recommended_executor: str
    selected_executor: ExecutorCandidate
    executor_policy_violations: list[str]
    executor_candidates: list[ExecutorCandidate]


class BeadsContextDepthProvenance(TypedDict, total=False):
    source: BeadsContextDepthSource
    requested_depth: BeadsContextDepth | None
    computed_depth: BeadsContextDepth
    effective_depth: BeadsContextDepth
    actor_context: str
    rationale: list[str]


class BeadsContextDepthSignal(TypedDict, total=False):
    beads_context_depth: BeadsContextDepth
    beads_context_depth_source: BeadsContextDepthSource
    beads_context_depth_rationale: list[str]
    beads_context_depth_provenance: BeadsContextDepthProvenance


class ScaffoldSizingSignal(TypedDict, total=False):
    recommended_size: Literal["full", "tight"]
    source: str
    rationale: list[str]


class WorkerbeeParallelismSignal(TypedDict, total=False):
    recommended: bool
    prompt_user_in_plan_mode: bool
    workerbee_count: int
    rationale: list[str]
    trigger_reasons: list[str]


class WorkerbeePlannedDelegation(TypedDict, total=False):
    enabled: bool
    workerbee_count: int
    lanes: list[dict[str, Any]]
    source: str


class CoachQuestionOption(TypedDict, total=False):
    label: str
    value: str
    description: str


class CoachQuestion(TypedDict, total=False):
    id: str
    question: str
    default: str
    options: list[CoachQuestionOption]


class RouteResult(TypedDict, total=False):
    route: RouteName
    task_class: str
    risk_level: RiskLevel
    data_sensitivity: SensitivityLevel
    data_sensitivity_source: str
    data_sensitivity_heuristic: SensitivityLevel
    data_sensitivity_disclaimer: str
    data_sensitivity_provenance: dict[str, Any]
    dispatch_sensitivity: SensitivityLevel
    share_boundary: str
    execution_environment: str
    execution_environment_profile: dict[str, Any]
    project_manager_executor: str | None
    primary_architect_executor: str | None
    architecture_counter_review_executor: str | None
    architecture_authority: str
    native_operative_dispatch: dict[str, Any]
    external_opt_in: bool
    disclosure_escalation_approved: bool
    external_contract_allowed: bool
    local_worker_allowed: bool
    local_worker_opt_in_source: str | None
    prefer_local_worker: bool
    local_profile: str | None
    has_external_expert_contracts: bool
    has_local_worker_contracts: bool
    external_experts: list[str]
    local_worker_experts: list[str]
    internal_experts: list[str]
    acceptance_required_experts: list[str]
    recommended_executor: str
    selected_executor: ExecutorCandidate
    access_profile: str | None
    blocking_review_required: bool
    blocking_review_active: bool
    blocking_review_gate: str | None
    blocking_review_executor: str | None
    blocking_review_job_description_label: str | None
    blocking_review_waiver_required: bool
    blocking_review_failure_behavior: str | None
    blocking_review_required_evidence: list[str]
    architecture_review_complexity: str
    claude_architecture_effort: str
    requested_architecture_critic_executors: list[str]
    architecture_critic_contracts: list[dict[str, Any]]
    provider_conflict_detected: bool
    provider_conflict_domains: list[str]
    provider_diversity_required: bool
    peer_review_required: bool
    sabotage_review_required: bool
    peer_review_count: int
    peer_review_labels: list[str]
    quarantine_on_fail: bool
    local_secure_review_executor: str | None
    required_experts: list[ExpertResult]
    ranked_experts: list[ExpertResult]
    ranked_executors: list[ExecutorCandidate]
    editor_gate_required: bool
    editor_gate_added_experts: list[str]
    editor_gate_experts: list[str]
    guard_labels: list[str]
    evaluator_required: bool
    architect_adjudication_required: bool
    architect_review_required: bool
    beads_required_for_full_handoff: bool
    hard_stops: list[str]
    reasons: list[str]
    model_synthesis: dict[str, Any]
    beads_context_depth: BeadsContextDepth
    beads_context_depth_source: BeadsContextDepthSource
    beads_context_depth_rationale: list[str]
    beads_context_depth_provenance: BeadsContextDepthProvenance


class CoachResult(TypedDict, total=False):
    coach_result_type: Literal["complex-work-orchestration-prompt-coach"]
    version: int
    beads_tracking_required: bool
    recommended_orchestration_level: OrchestrationLevel
    scaffold_sizing: ScaffoldSizingSignal
    beads_context_depth: BeadsContextDepth
    beads_context_depth_provenance: BeadsContextDepthProvenance
    rationale: list[str]
    missing_questions: list[CoachQuestion]
    interactive_questions: list[CoachQuestion]
    requires_user_selection_before_plan: bool
    selection_before_plan_reason: str
    selection_before_plan_question_ids: list[str]
    enabled_levers: list[str]
    disabled_levers: list[str]
    workerbee_parallelism: WorkerbeeParallelismSignal
    workerbee_planned_delegation: WorkerbeePlannedDelegation
    model_synthesis: dict[str, Any]
    operator_calibration: dict[str, Any]
    route: RouteResult
    paste_ready_prompt: str
    warnings: list[str]


class ResearchEvidenceQuality(TypedDict, total=False):
    research_evidence_present: bool
    research_evidence_items: list[dict[str, Any]]
    research_contradictions: list[dict[str, Any]]
    research_reflection: dict[str, Any]
    research_unresolved_contradiction_count: int
    research_replan_recommended: bool
    research_evidence_score: int
    research_evidence_signals: list[ReturnSignal]
    research_evidence_signal_categories: list[str]


class EvidenceQuality(TypedDict, total=False):
    evidence_quality_score: int
    evidence_quality_signals: list[ReturnSignal]
    evidence_quality_signal_categories: list[str]


class ContractorReturnBundle(TypedDict, total=False):
    bundle_type: str
    version: int
    bead_id: str | None
    dispatch_id: str | None
    share_boundary: str | None
    job_description_label: str | None
    packet_sha256: str | None
    expected_return_language: str | None
    expected_return_language_source: str
    return_language_status: str
    return_language_findings: list[ReturnSignal]
    detected_letter_scripts: list[str]
    unexpected_script_ratio: float
    unicode_normalization_changed: bool
    sections: dict[str, str]
    executor: str | None
    provider_key: str | None
    provider_trust_tier: str | None
    provider_family: str | None
    provider_retention_class: str | None
    provider_external: bool | None
    dispatch_mode: str | None
    local_profile: str | None
    model_profile: str | None
    provenance_class: str
    provenance_warnings: list[str]
    boundary_taint_status: str
    boundary_taint_findings: list[str]
    required_sections_missing: list[str]
    required_sections_present: list[str]
    evidence_items: list[dict[str, str]]
    workspace_mutation: dict[str, Any] | None
    implementation_blocked: bool
    hold_reasons: list[str]
    hold_classification: str
    review_surface: str
    source_inspection: str
    sources_inspected: str
    sources_not_inspected: str
    independent_verification: str
    packet_reported_claims: str
    bundle_sha256: str


class AcceptanceDecision(TypedDict, total=False):
    dispatch_id: str | None
    bead_id: str | None
    share_boundary: str | None
    packet_sha256: str | None
    expected_return_language: str | None
    expected_return_language_source: str
    return_language_status: str
    return_language_findings: list[ReturnSignal]
    detected_letter_scripts: list[str]
    unexpected_script_ratio: float
    unicode_normalization_changed: bool
    executor: str | None
    provider_key: str | None
    provider_trust_tier: str | None
    provider_family: str | None
    provider_retention_class: str | None
    provider_external: bool | None
    dispatch_mode: str | None
    local_profile: str | None
    model_profile: str | None
    provenance_class: str
    provenance_warnings: list[str]
    verdict: AcceptanceVerdict
    score: int
    recommended_disposition: str
    recommended_synthesis_use: SynthesisUse
    missing_sections: list[str]
    penalty_reasons: list[str]
    hard_disqualifiers: list[str]
    sabotage_score: int
    sabotage_signals: list[ReturnSignal]
    sabotage_signal_categories: list[str]
    sabotage_review_recommended: bool
    sabotage_architect_escalation_recommended: bool
    malpractice_score: int
    malpractice_signals: list[ReturnSignal]
    malpractice_signal_categories: list[str]
    malpractice_review_recommended: bool
    malpractice_reject_recommended: bool
    evidence_quality_score: int
    evidence_quality_signals: list[ReturnSignal]
    evidence_quality_signal_categories: list[str]
    signal_categories: list[str]
    peer_review_required: bool
    peer_review_status: str
    review_surface: str
    source_inspection: str
    sources_inspected: str
    sources_not_inspected: str
    independent_verification: str
    packet_reported_claims: str
    review_surface_packet_only: bool
    source_inspection_packet_only: bool
    go_for_pr_merge_readiness_claimed: bool
    review_surface_mismatch: bool
    review_surface_required_evidence_missing: bool
    review_surface_mismatch_reasons: list[str]
    master_review_packet_only_go_hold: bool
    implementation_blocked: bool
    hold_reasons: list[str]
    hold_classification: str
    patch_authorization_state: str
    provider_conflict_domains: list[str]
    boundary_taint_status: str
    boundary_taint_findings: list[str]
    workspace_mutation: dict[str, Any] | None
    human_adjudication_required: bool
    quarantine_recommended: bool
    escalation_flagged: bool
    architect_review_required: bool
    sections: dict[str, str]


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
