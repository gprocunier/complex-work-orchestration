"""Centralized contract field contracts for native worker packet/return parsing."""

from .native_disposition import DISPOSITION_FIELDS

ALLOWED_PACKET_FIELDS = {
    "packet_type",
    "version",
    "packet_id",
    "bead_id",
    "lane",
    "requested_model",
    "session_policy",
    "scope",
    "acceptance_checks",
    "budget",
    "budget_provenance",
    "supervision",
    "validation_lineage",
    "escalation_triggers",
    "return_contract",
}
ALLOWED_SESSION_POLICY_FIELDS = {
    "fresh_session_required",
    "resume_forbidden",
    "attestation",
    "source",
}
ALLOWED_ATTESTATION_FIELDS = {
    "required",
    "tool_mode",
    "model_authority",
    "self_report_authority",
    "required_actual_model",
}
ALLOWED_SCOPE_FIELDS = {
    "workdir",
    "allowed_paths",
    "allowed_actions",
    "prohibited_actions",
}
ALLOWED_BUDGET_FIELDS = {
    "tool_calls_soft",
    "tool_calls_hard",
    "runtime_seconds_soft",
    "runtime_seconds_hard",
    "max_compactions",
    "max_full_suite_runs",
}
ALLOWED_BUDGET_PROVENANCE_FIELDS = {
    "profile",
    "policy_source",
    "overrides_applied",
    "overridden_fields",
}
ALLOWED_SUPERVISION_FIELDS = {
    "required",
    "mode",
    "poll_interval_ms",
    "poll_lag_tolerance_ms",
    "arm_to_dispatch_max_ms",
    "control_turn_required",
    "segment_start_grace_seconds",
    "control_adapter",
    "required_capabilities",
    "interrupt_thresholds",
}
ALLOWED_INTERRUPT_THRESHOLD_FIELDS = {"tool_calls", "runtime_seconds"}
ALLOWED_VALIDATION_LINEAGE_FIELDS = {
    "root_packet_id",
    "parent_packet_id",
    "attempt",
}
ALLOWED_ESCALATION_TRIGGER_FIELDS = {
    "scope_ambiguity",
    "architecture_ambiguity",
    "security_ambiguity",
    "policy_ambiguity",
    "soft_limit",
    "hard_limit",
    "compaction",
}
ALLOWED_RETURN_CONTRACT_FIELDS = {
    "allowed_statuses",
    "required_fields",
    "realignment_required_fields",
}
ALLOWED_RETURN_FIELDS = {
    "return_type",
    "version",
    "packet_id",
    "bead_id",
    "session_id",
    "segment_id",
    "status",
    "requested_model",
    "actual_model",
    "attestation_source",
    "attestation_status",
    "completed_evidence",
    "files_touched",
    "mutation_state",
    "commands_run",
    "validation",
    "decision_required",
    "bounded_options",
    "recommendation",
    "remaining_scope",
    "usage",
    "residual_risks",
    *DISPOSITION_FIELDS,
}
ALLOWED_RETURN_USAGE_FIELDS = {
    "tool_calls",
    "elapsed_seconds",
    "context_compactions",
    "full_suite_runs",
    "input_tokens",
    "output_tokens",
    "total_tokens",
    "cached_input_tokens",
    "reasoning_tokens",
}
ALLOWED_MUTATION_STATES = {"clean", "modified", "committed", "unknown"}
ALLOWED_ATTESTATION_STATUSES = {
    "trusted",
    "missing",
    "mismatch",
    "untrusted",
    "denied",
}
ALLOWED_ESCALATION_SOFT_LIMIT_FIELDS = {"distinct_soft_limits_required"}
ALLOWED_ESCALATION_HARD_LIMIT_FIELDS = {"any_hard_limit", "status"}
ALLOWED_ESCALATION_COMPACTION_FIELDS = {"any_compaction", "status"}
