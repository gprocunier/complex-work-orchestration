#!/usr/bin/env python3
from __future__ import annotations

import ast
import json
import os
import re
import stat
import sys
from pathlib import Path
from typing import Any, Iterator

import scaffold_workgraph
from site_code import without_token_spans
from cwo_core import epic_convergence, qualification_target, release_effect_routes
from cwo_core.packets import (
    CONTRACTOR_PACKET_REQUIRED_FIELDS,
    LOCAL_DISPATCH_REQUIRED_FIELDS,
)
from cwo_core.paths import (
    POLICY_DIR,
    REPO_ROOT,
)
from cwo_core.native_pool_capacity import (
    NativePoolCapacityPolicyError,
    capacity_schema_errors,
    load_pool_capacity,
)
from cwo_core.native_pool_schedulability import (
    PoolSchedulabilityError,
    scheduling_budget_proof,
    validate_slack_warning_fraction,
)
from cwo_core.coach import PROMPT_COACH_RESULT_REQUIRED_FIELDS
from cwo_core.harness import (
    HARNESS_DISPATCH_REQUIRED_FIELDS,
    MODEL_PROFILE_REQUIRED_FIELDS,
    validate_execution_environment_registry,
)
from cwo_core.model_identity_scope import lint_model_identities
from cwo_core.policy import load_json_compatible_yaml, load_policy
from cwo_core.policy_schema import POLICY_SCHEMAS, POLICY_VALIDATION_BOUNDARIES, policy_document_errors
from cwo_core.workspace_capture import WorkspaceDiscoveryError, trusted_git_completed, trusted_git_ignored
from cwo_core.public_copy import (
    validate_markdown_public_copy,
    validate_required_doc_terms,
)
from validate_run_readiness_plan import validate_plan as validate_run_readiness_plan

# Keep the maintained Python under scripts/ from growing back after consolidation.
PYTHON_LINE_CEILING = 171_500

EMITTED_PACKET_ARTIFACT_TYPES = {
    "assignment_summary",
    "selected_file_snippet",
    "inline_snippet",
    "expert_profile",
}
CI_UNIT_TEST_COMMAND = (
    'python scripts/run_parallel_unittest.py --workers 4 --verbose '
    '--shard-index "${CWO_TEST_SHARD_INDEX:-0}" --shard-count "${CWO_TEST_SHARD_COUNT:-1}"'
)
CI_CODEX_CONTRACT_COMMAND = "python scripts/check_codex_protocol_capabilities.py"
CI_REQUIRED_COMMANDS = [
    "timeout --kill-after=10 300 python -B scripts/check_release_filesystem.py",
    "python -m compileall -j 8 -x '(^|/)(\\.git|\\.beads|\\.orchestration-audit|__pycache__|\\.ruff_cache)(/|$)' .",
    "python scripts/validate_repository.py",
    "python scripts/validate_public_copy.py",
    "python scripts/check_code_health.py",
    "python scripts/validate_site.py",
    "python scripts/generate_site.py --check",
    CI_UNIT_TEST_COMMAND,
    CI_CODEX_CONTRACT_COMMAND,
    "bash examples/sample-prompt-coach-command.sh",
    "python scripts/validate_run_readiness_plan.py examples/sample-run-readiness-plan.json",
    "python scripts/render_run_projection.py examples/sample-run-readiness-plan.json --projection run-sheet",
    "python scripts/render_run_projection.py examples/sample-run-readiness-plan.json --projection wrap-up-status",
    "python scripts/render_run_projection.py examples/sample-run-readiness-plan.json --projection next-version",
    "python scripts/close_bead_with_summary.py --bead example-1 --disposition superseded --why \"replaced by a follow-up Bead\" --follow-up none --dry-run --json",
    "python scripts/cleanup_stale_agents.py --dry-run --json",
]
APPROVED_ACTION_PINS = {
    "actions/checkout": ("d23441a48e516b6c34aea4fa41551a30e30af803", "v6"),
    "actions/configure-pages": ("45bfe0192ca1faeb007ade9deae92b16b8254a0d", "v6"),
    "actions/deploy-pages": ("368f82528645a54fb793d4d04e342629a3f51346", "v5"),
    "actions/setup-python": ("ece7cb06caefa5fff74198d8649806c4678c61a1", "v6"),
    "actions/upload-pages-artifact": ("fc324d3547104276b827a68afc52ff2a11cc49c9", "v5"),
    "github/codeql-action": ("cdf488f595d80d6e07e03d4674febd5ab45fa938", "v4"),
    "ludeeus/action-shellcheck": ("00cae500b08a931fb5698e11e79bfbd38e612a38", "2.0.0"),
}
CWO_CORE_ALLOWED_IMPORTS = {
    "qualification_target": {"policy", "policy_schema"},
    "release_effect_routes": set(),
    "atomic_spawn": set(),
    "ownership_producer": {"process_identity"},
    "server_request_preparation": set(),
    "access_profiles": {"codex_hook_enforcement", "errors", "policy"},
    "codex_hook_enforcement": {"errors"},
    "paths": set(),
    "util": set(),
    "chatgpt_urls": set(),
    "path_contract": set(),
    "private_artifact": set(),
    "browser_provenance": {
        "audit", "candidate_identity", "chatgpt_urls", "outbound_screen",
        "packet_provenance", "private_artifact",
    },
    "process_identity": set(),
    "invocation_ledger": {"paths", "process_identity"},
    "local_invocation": {"invocation_ledger", "policy", "prepared_outbound"},
    "policy": {"errors", "model_identities", "paths", "policy_schema", "util"},
    "policy_schema": {"paths"},
    "model_identity_scope": {"model_identities", "policy", "policy_schema"},
    "routing": {"access_profiles", "errors", "harness", "native_containment", "operative_routing", "policy", "reasoning_effort", "risk_features", "routing_signals", "synthesis", "types", "util"},
    "reasoning_effort": {"policy", "return_advisory", "risk_features", "routing_signals", "util"},
    "routing_signals": {"util"},
    "adjudication": {"policy", "synthesis_inputs"},
    "adjudication_binding": {"adjudication", "errors", "path_contract", "policy", "returns", "synthesis_inputs"},
    "adjudication_source": {"adjudication", "adjudication_binding", "errors", "synthesis_inputs"},
    "synthesis": {"adjudication", "model_identities", "policy", "synthesis_inputs", "util"},
    "synthesis_inputs": {"policy"},
    "coach": {"model_identities", "operative_routing", "routing", "synthesis", "types", "util"},
    "frozen_protocol": set(),
    "packets": {"errors", "paths", "policy", "return_language", "review_inputs", "util"},
    "review_inputs": {"beads", "policy"},
    "packet_provenance": {"audit", "outbound_approval", "packets"},
    "outbound_approval": {"lead_authority", "workspace_capture"},
    "lead_authority": {"errors", "policy_schema", "private_artifact"},
    "model_identities": {"policy"},
    "model_catalog_startup": set(),
    "cyber_fallback": {"invocation_ledger", "model_identities"},
    "outbound_screen": {"policy"},
    "prepared_outbound": {"outbound_screen"},
    "return_common": {"errors", "policy"},
    "return_language": {"errors", "policy", "return_common", "types"},
    "return_sections": {"errors", "policy"},
    "return_boundary": {"return_common", "return_sections"},
    "return_evidence": {"return_common", "return_sections", "types"},
    "return_risk": {"errors", "peer_review", "policy", "return_common", "return_evidence", "return_language", "return_sections", "types"},
    "peer_review": {"errors", "peer_review_identity"},
    "peer_review_identity": {"adjudication", "errors", "host_records", "model_identities", "peer_review", "policy"},
    "host_records": {"audit", "audit_segments", "errors", "host_record_inventory", "host_record_quarantine", "paths"},
    "host_record_inventory": {"host_records"},
    "host_record_quarantine": {"audit", "audit_segments", "host_record_inventory", "host_records"},
    "host_acceptance": {"browser_provenance", "errors", "host_records", "peer_review", "peer_review_identity",
                        "policy", "policy_schema", "return_advisory", "returns"},
    "audit_segments": {"audit", "host_records"},
    "host_return_intake": {"errors", "peer_review", "policy_schema"},
    "dispatch_workload": {"paths", "policy_schema", "route_feasibility"},
    "route_feasibility": {"native_authority", "work_sizing"},
    "codex_critic_capture": {"dispatch_workload", "errors", "host_acceptance", "host_return_intake", "model_identities",
                             "native_session_boundary", "peer_review", "peer_review_identity", "policy",
                             "outbound_screen", "policy_schema", "reasoning_effort", "return_advisory", "returns"},
    "manual_gemini_critic": {"errors", "host_records", "host_return_intake", "peer_review_identity", "policy", "policy_schema"},
    "return_advisory": {"host_records", "packets", "policy_schema"},
    "return_structure": {"return_sections"},
    "return_tripwires": {"policy", "return_language", "return_structure"},
    "risk_features": {"errors", "policy"},
    "returns": {"peer_review", "policy", "return_boundary", "return_common", "return_evidence", "return_language", "return_risk", "return_sections", "return_tripwires", "types", "util"},
    "workspace": {"path_contract", "paths", "util", "workspace_capture", "workspace_transition"},
    "workspace_capture": {"git_store", "path_contract"},
    "workspace_transition": set(),
    "git_store": set(),
    "workgraph_markdown": set(),
    "telemetry": {"epic_convergence", "peer_review", "peer_review_identity", "util"},
    "audit": {"audit_segments", "host_record_quarantine", "host_records", "paths", "policy", "telemetry", "util"},
    "waivers": set(),
    "beads": {"paths", "util"},
    "beads_ready_set": {
        "model_identities",
        "native_authority",
        "native_capability",
        "native_pool_capacity",
        "native_pool_schedulability",
        "native_tool_isolation",
        "policy",
        "work_sizing",
    },
    "harness": {"access_profiles", "model_identities", "operative_routing", "policy", "util"},
    "native_disposition": set(),
    "execution_status_report": {"audit", "epic_convergence", "execution_enhancement_metrics", "model_identities", "paths"},
    "execution_enhancement_metrics": set(),
    "native_session": {"native_disposition"},
    "native_session_boundary": {"native_session", "policy_schema"},
    "native_live_availability": set(),
    "native_worker_contracts": {"native_disposition"},
    "native_authority": set(),
    "native_activation_ledger": set(),
    "native_activation_preview": {
        "beads",
        "beads_ready_set",
        "model_identities",
        "native_activation_ledger",
        "native_authority",
        "native_capability",
        "native_pool_admission",
        "native_pool_contracts",
        "native_pool_preflight",
        "native_pool_proportionality",
        "native_pool_workspace",
        "native_tool_activation",
        "native_tool_isolation",
        "policy",
        "work_sizing",
        "workspace",
        "workspace_capture",
    },
    "native_capability": {"native_authority"},
    "native_canary_contracts": set(),
    "native_live_campaign_contracts": set(),
    "native_live_allocation_ledger": {
        "audit",
        "native_canary_contracts",
        "native_turn_dispatch",
    },
    "native_turn_dispatch": set(),
    "native_containment": {"native_release", "policy"},
    "native_precommit": {"maintenance_authority", "audit", "model_identities", "native_session", "native_session_boundary", "operative_routing", "paths", "policy", "util", "workspace"},
    "native_release": {
        "maintenance_release", "model_identities", "work_sizing", "native_precommit", "operative_routing", "paths", "policy", "util"},
    "operative_routing": {"model_identities", "policy", "reasoning_effort", "work_sizing"},
    "proportional_execution": {"native_capability", "native_containment"},
    "native_recovery": set(),
    "native_recovery_authority": {
        "native_live_allocation_ledger",
        "native_recovery_policy",
        "native_retry",
    },
    "native_recovery_policy": set(),
    "native_retry": {"native_authority"},
    "native_control": set(),
    "native_tool_isolation": set(),
    "native_tool_activation": {
        "native_authority",
        "native_pool_admission",
        "native_recovery_authority",
        "native_tool_isolation",
    },
    "native_stop_scope": {"native_authority"},
    "native_pool_admission": {
        "beads",
        "beads_ready_set",
        "native_pool_capacity",
        "native_pool_proportionality",
        "native_recovery_authority",
        "policy",
        "work_sizing",
    },
    "native_pool_capacity": {"paths", "policy"},
    "native_pool_capacity_compat": set(),
    "native_pool_schedulability": set(),
    "native_pool_contracts": {
        "native_authority",
        "native_control",
        "native_pool_admission",
        "native_pool_capacity",
        "native_pool_capacity_compat",
        "native_recovery_authority",
        "native_pool_schedulability",
        "native_stop_scope",
        "native_tool_isolation",
    },
    "native_pool_scheduler": {"native_pool_contracts"},
    "maintenance_native_runtime": {'native_live_availability', 'maintenance_qualification', 'maintenance_image', 'native_precommit', 'native_pool_config', 'native_pool_contracts', 'native_pool_preflight', 'workspace', 'native_control', 'native_tool_isolation', 'native_pool_transaction', 'maintenance_runtime_support', 'native_pool_leases', 'paths', 'policy', 'native_pool_workspace', 'native_pool_admission', 'native_stop_scope', 'supervision.transport.app_server', 'supervision.transport.errors', 'supervision.turn_observations', 'supervision.callback_timing', 'supervision.containment', 'supervision.live_thread', 'supervision.session_evidence'},
    "maintenance_runtime_support": {'maintenance_authority', 'native_pool_admission', 'native_pool_contracts'},
    "maintenance_authority": {"native_authority", "native_pool_contracts"},
    "maintenance_image": {"native_pool_contracts", "paths"},
    "maintenance_readiness": {"model_identities", "maintenance_authority", "native_pool_contracts", "native_pool_transaction", "native_precommit", "work_sizing"},
    'maintenance_qualification': {'native_live_availability', 'maintenance_image', 'native_tool_isolation', 'native_pool_contracts', 'maintenance_runtime_support', 'maintenance_authority', 'native_authority', 'native_canary_contracts', 'checked_command', 'native_turn_dispatch', 'codex_tool_surface', 'supervision.transport.app_server', 'supervision.transport.errors', 'supervision.containment'},
    'maintenance_release': {'native_precommit', 'native_pool_contracts', 'maintenance_authority', 'maintenance_qualification', 'operative_routing', 'work_sizing'},
    'private_authority_input': {'native_precommit', 'operative_routing'},

    "requirement_baseline": set(),
    "typed_artifact_requirement": {"requirement_baseline"},
    "candidate_identity": {"git_store", "requirement_baseline", "workspace_capture"},
    "closure_checks": {"requirement_baseline"},
    "manual_delivery": {"audit", "beads", "candidate_identity", "closure_checks", "host_records",
                        "process_identity", "requirement_baseline", "util"},
    "stage_evidence": set(),
    "stage_completion": {"stage_evidence", "checked_command", "native_pool_transaction"},
    "native_pool_deferred_context": {"native_pool_contracts", "native_tool_isolation"},
    "native_pool_deferred_attestation": {"native_pool_deferred_context", "native_pool_transaction", "worker_patch"},
    "worker_patch": {"path_contract"},
    "native_pool_qualification_evidence": {
        "native_pool_deferred_context", "native_session_boundary",
    },
    "native_pool_qualification_stage": {
        "invocation_ledger",
        "native_live_availability",
        "native_pool_contracts",
        "native_pool_deferred_context",
        "native_pool_leases",
        "native_pool_transaction",
        "native_tool_isolation",
        "policy_schema",
        "workspace_capture",
    },
    "native_pool_transaction": {
        "maintenance_authority",
        "native_live_availability",
        "native_pool_admitted",
        "native_pool_contracts",
        "native_pool_deferred_context",
        "policy_schema",
        "util",
    },
    "native_pool_leases": {"native_pool_contracts", "policy_schema"},
    "native_pool_workspace": {"native_pool_contracts", "workspace", "workspace_capture"},
    "native_pool": {
        "native_authority",
        "native_control",
        "native_pool_admission",
        "native_pool_capacity",
        "native_pool_contracts",
        "native_pool_leases",
        "native_recovery_authority",
        "native_pool_scheduler",
        "native_pool_schedulability",
        "native_stop_scope",
        "policy_schema",
    },
    "native_pool_admitted": {
        "native_pool",
        "native_pool_admission",
        "native_pool_capacity",
        "native_pool_contracts",
        "native_pool_deferred_context",
        "native_pool_leases",
        "native_pool_preflight",
        "native_tool_activation",
        "native_tool_isolation",
    },
    "native_pool_config": {
        "native_control",
        "native_pool_capacity",
        "native_pool_admission",
        "native_pool_contracts",
        "native_pool_schedulability",
        "native_pool_leases",
        "native_pool_workspace",
        "native_tool_isolation",
        "policy",
    },
    "native_pool_preflight": {
        "native_authority",
        "native_pool_admission",
        "native_pool_capacity",
        "native_pool_contracts",
        "native_pool_schedulability",
        "native_tool_activation",
        "native_tool_isolation",
    },
    "native_pool_proportionality": {
        "native_authority",
        "native_pool_capacity",
        "native_pool_schedulability",
        "policy",
        "work_sizing",
    },
    "native_pool_reporting": {"audit", "native_pool_contracts"},
    "native_replanning": {"native_authority", "policy"},
    "native_progress": {"native_authority", "native_stop_scope", "policy"},
    "checked_command": {"path_contract"},
    "checked_command_sequence": {"checked_command"},
    "codex_protocol_capabilities": set(),
    "codex_protocol_pin": {"policy"},
    "codex_tool_surface": {"native_tool_isolation"},
    "supervision": set(),
    "supervision.callback_timing": {
        "native_canary_contracts",
        "native_pool_capacity",
        "native_pool_contracts",
        "native_pool_schedulability",
        "supervision.transport.app_server",
        "supervision.transport.errors",
    },
    "supervision.containment": {
        "native_turn_dispatch",
        "supervision.transport.app_server",
        "supervision.transport.errors",
    },
    "supervision.live_thread": {
        "codex_tool_surface",
        "native_live_availability",
        "native_pool_contracts",
        "native_session_boundary",
        "native_tool_isolation",
        "native_worker_contracts",
        "supervision.callback_timing",
        "supervision.containment",
        "supervision.session_evidence",
        "supervision.transport.app_server",
        "supervision.transport.errors",
        "workspace",
    },
    "supervision.session_evidence": {
        "codex_tool_surface",
        "native_canary_contracts",
        "native_pool_contracts",
        "native_session",
        "native_session_boundary",
        "native_tool_isolation",
        "native_worker_contracts",
        "supervision.transport.app_server",
        "supervision.transport.errors",
    },
    "supervision.turn_observations": set(),
    "supervision.transport": set(),
    "supervision.transport.errors": {"native_turn_dispatch"},
    "supervision.transport.private_io": {"native_live_campaign_contracts", "supervision.transport.errors"},
    "supervision.transport.app_server": {
        "native_live_availability",
        "codex_protocol_capabilities",
        "codex_tool_surface",
        "native_canary_contracts",
        "native_live_allocation_ledger",
        "native_pool_contracts",
        "native_turn_dispatch",
        "outbound_screen",
        "prepared_outbound",
        "supervision.transport.errors",
        "supervision.transport.private_io",
    },
    "work_sizing": {"model_identities", "checked_command", "native_authority", "native_containment", "native_precommit", "policy"},
    "epic_convergence": set(),
    "public_copy": set(),
    "errors": set(),
    "types": set(),
}
PUBLIC_DOC_FORBIDDEN_HARDWARE_TERMS = ["H200", "CerIO", "airgapped-rhoai-h200"]
PUBLIC_COPY_DOC_PATHS = [
    "README.md",
    "SKILL.md",
    "AGENTS.md",
]
PUBLIC_COPY_DOC_GLOBS = [
    "references/*.md",
    "templates/*.md",
    "examples/*.md",
]
PUBLIC_COPY_INTERNAL_LABEL_ALLOWED_PREFIXES = (
    "references/",
    "templates/",
    "examples/",
)
PUBLIC_COPY_INTERNAL_LABEL_ALLOWED_FILES = {
    "SKILL.md",
    "AGENTS.md",
}
WAIVER_CONVENTION_SCRIPTS = {
    "scripts/authorize_sol_breakfix.py": {
        "flags": ["--allow-sol-breakfix"],
        "audit_fields": True,
    },
    "scripts/build_contractor_packet.py": {
        "flags": ["--allow-disclosure-escalation", "--no-audit"],
        "audit_fields": True,
    },
    "scripts/chatgpt_browser_review.py": {
        "flags": ["--allow-degraded-packet", "--allow-unlinked-packet", "--no-audit"],
        "audit_fields": True,
    },
    "scripts/dispatch_work.py": {
        "flags": [
            "--allow-degraded-packet",
            "--allow-unlinked-packet",
            "--allow-raw-manual-prompt",
            "--allow-disclosure-escalation",
            "--local-allow-private-dns",
            "--local-insecure-tls",
            "--allow-offline-access-profile",
            "--no-audit",
        ],
        "audit_fields": True,
    },
    "scripts/evaluate_return.py": {
        "flags": ["--no-audit"],
        "audit_fields": True,
    },
    "scripts/render_harness_dispatch.py": {
        "flags": ["--no-audit"],
        "audit_fields": True,
    },
    "scripts/import_execution_telemetry.py": {
        "flags": ["--allow-unmatched"],
        "audit_terms": ["waiver_required", "waiver_flags", "waiver_reason"],
    },
    "scripts/generate_manual_dispatch_prompt.py": {
        "flags": [
            "--allow-degraded-packet",
            "--allow-raw-manual-prompt",
            "--allow-disclosure-escalation",
        ],
    },
    "scripts/configure_codex_beads_hooks.py": {
        "flags": ["--force-visibility-hint", "--allow-degraded-context"],
    },
    "scripts/coach_prompt.py": {
        "flags": ["--allow-disclosure-escalation"],
    },
    "scripts/route_work.py": {
        "flags": ["--allow-disclosure-escalation"],
    },
    "scripts/scaffold_workgraph.py": {
        "flags": ["--allow-disclosure-escalation"],
    },
}
WAIVER_FLAG_DISCOVERY_EXCEPTIONS = {
    "scripts/workspace_mutation_guard.py": {"--allow-path"},
}
RETIRED_BEADS_CONTEXT_ALIAS_PATTERNS = [
    "beads_" + "briefing_depth",
    "beads-" + "briefing-depth",
]


def load_json(path: Path) -> Any:
    """Load JSON-compatible policy/schema files, including .yaml policy files.

    CWO policy files intentionally use a JSON-compatible YAML subset so all
    validators run with the Python standard library and no PyYAML dependency.
    """
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"{path.relative_to(REPO_ROOT)} is not valid JSON: {exc}") from exc


def validate_retired_beads_context_aliases(
    errors: list[str],
    *,
    repo_root: Path = REPO_ROOT,
) -> None:
    allowed_names = {"CHANGELOG.md"}
    skipped_dirs = {".git", "__pycache__"}
    candidates: list[tuple[Path, Path]] = []
    for path in sorted(repo_root.rglob("*")):
        if not path.is_file() or path.name in allowed_names:
            continue
        try:
            relative = path.relative_to(repo_root)
        except ValueError:
            continue
        if any(part in skipped_dirs for part in relative.parts):
            continue
        if path.suffix not in {".py", ".json", ".md", ".html", ".sh", ".yaml", ".yml"}:
            continue
        candidates.append((path, relative))
    ignored: set[str] = set()
    if (repo_root / ".git").is_dir():
        # One check through the trusted executable, after every ignore file it
        # reads has been checked; any failure counts as "nothing ignored", so
        # every file is still validated.
        try:
            ignored = trusted_git_ignored(repo_root, [relative.as_posix() for _, relative in candidates])
        except WorkspaceDiscoveryError:
            ignored = set()
    for path, relative in candidates:
        if relative.as_posix() in ignored:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for pattern in RETIRED_BEADS_CONTEXT_ALIAS_PATTERNS:
            if pattern in text:
                errors.append(f"{relative} uses retired Beads context alias {pattern!r}")


def validate_closure_pressure_contract(errors: list[str]) -> None:
    def _report_error(prefix: str, message: str) -> None:
        errors.append(f"closure-pressure contract regression ({prefix}): {message}")

    def _check_graph_fields(graph: list[dict[str, Any]], disposition: str) -> None:
        if not graph:
            _report_error("graph", "planned_graph returned empty graph")
            return
        for idx, item in enumerate(graph):
            metadata = item.get("metadata")
            if not isinstance(metadata, dict):
                _report_error("graph", f"graph item {idx} is missing metadata")
                continue
            for field in ("closure_pressure_active", "routine_repair_child_forbidden"):
                if metadata.get(field) is not True:
                    _report_error("graph", f"graph item {idx} has {field}={metadata.get(field)!r} expected True")
            closure_pressure = metadata.get("closure_pressure")
            if not isinstance(closure_pressure, dict):
                _report_error(
                    "graph",
                    f"graph item {idx} has invalid closure_pressure metadata",
                )
                continue
            if closure_pressure.get("active") is not True:
                _report_error(
                    "graph",
                    f"graph item {idx} has closure_pressure.active={closure_pressure.get('active')!r} expected True",
                )
            if closure_pressure.get("disposition") != disposition:
                _report_error(
                    "graph",
                    f"graph item {idx} has closure_pressure.disposition={closure_pressure.get('disposition')!r} expected {disposition!r}",
                )
            if closure_pressure.get("allowed") is not True:
                _report_error(
                    "graph",
                    f"graph item {idx} has closure_pressure.allowed={closure_pressure.get('allowed')!r} expected True",
                )

    current_action = "continue-current-work-unit"
    repair_action = "create-routine-repair-child"
    allowed_dispositions = list(epic_convergence.CLOSURE_DISPOSITIONS)

    def _decision_cases() -> Iterator[tuple[bool, str | None, tuple[tuple[str, bool, str], ...]]]:
        yield False, None, ((current_action, True, "closure-pressure-inactive"),)
        yield True, None, ((current_action, False, "explicit-closure-disposition-required"),)
        for disposition in epic_convergence.CLOSURE_DISPOSITIONS:
            yield True, disposition, (
                (current_action, True, "closure-disposition-recorded"),
                (repair_action, False, "routine-repair-child-rejected"),
            )

    for active, disposition, checks in _decision_cases():
        expected = [
            {"active": active, "action": action, "disposition": disposition, "allowed": allowed,
             "reason": reason, "allowed_dispositions": allowed_dispositions}
            for action, allowed, reason in checks
        ]
        try:
            decisions = [
                epic_convergence.evaluate_closure_pressure(active, action, disposition)
                for action, _, _ in checks
            ]
        except Exception as exc:
            case = f"active={active}" if len(checks) == 1 else f"disposition={disposition!r}"
            _report_error("evaluator", f"decision failed for {case}: {exc}")
            continue
        if len(checks) == 1:
            if decisions[0] != expected[0]:
                _report_error("evaluator", f"decision mismatch for active={active}: {decisions[0]} != {expected[0]}")
            continue

        allowed, denied = decisions
        expected_allowed, expected_denied = expected
        if allowed != expected_allowed:
            _report_error(
                "evaluator",
                f"current-work decision invalid for disposition={disposition!r}: {allowed}",
            )
        if denied != expected_denied:
            _report_error(
                "evaluator",
                f"routine-child decision invalid for disposition={disposition!r}: {denied}",
            )

        try:
            continue_route = {
                "closure_pressure": {
                    "active": True,
                    "action": current_action,
                    "disposition": disposition,
                }
            }
            continue_graph = scaffold_workgraph.planned_graph("closure-pressure-continue", continue_route)
        except Exception as exc:
            _report_error(
                "graph",
                f"planned_graph failed for disposition={disposition!r} continue path: {exc}",
            )
            continue
        _check_graph_fields(continue_graph, disposition)
        try:
            scaffold_workgraph.planned_graph(
                "closure-pressure-routine-child",
                {
                    "closure_pressure": {
                        "active": True,
                        "action": "create-routine-repair-child",
                        "disposition": disposition,
                    }
                },
            )
        except ValueError as exc:
            if "routine-repair-child-rejected" not in str(exc):
                _report_error(
                    "evaluator",
                    f"create-routine-repair-child was blocked for wrong reason: {exc}",
                )
        except Exception as exc:
            _report_error(
                "graph",
                f"create-routine-repair-child decision failed for disposition={disposition!r}: {exc}",
            )
        else:
            _report_error(
                "graph",
                f"create-routine-repair-child was unexpectedly allowed for disposition={disposition!r}",
            )


_CAPACITY_SOURCE_GLOBS = (
    "scripts/cwo_core/native_pool*.py",
    "scripts/cwo_core/native_activation_preview.py",
    "scripts/run_native_pool_activation_preview.py",
    "scripts/run_native_pool_live_canaries.py",
    "scripts/cwo_core/supervision/*.py",
    "scripts/cwo_core/supervision/transport/*.py",
    "scripts/supervise_native_pool.py",
)
_CAPACITY_COMPATIBILITY_SOURCES = {
    "scripts/cwo_core/native_pool_capacity_compat.py",
}
_SCHEDULABILITY_PROOF_SOURCE = "scripts/cwo_core/native_pool_schedulability.py"
_DEPRECATED_CAPACITY_PATTERNS = (
    ("MAX_ACTIVE_WORKERS", re.compile(r"\bMAX_ACTIVE_WORKERS\b")),
    ("cap_two field", re.compile(r"\bcap_two_[a-z0-9_]*\b")),
    ("cap-two diagnostic", re.compile(r"cap-two")),
    (
        "capacity-two scheduler model",
        re.compile(r"nonpreemptive-edf-cap2|max_lifecycle\+2\*check"),
    ),
    (
        "literal capacity-two branch",
        re.compile(
            r"(?:max_active_workers|requested_cap)[^\n]{0,120}(?:==|!=)\s*2"
        ),
    ),
)


def validate_native_pool_capacity_invariants(
    errors: list[str],
    *,
    repo_root: Path = REPO_ROOT,
    policy_document: dict[str, Any] | None = None,
) -> None:
    """Keep runtime, schemas, and active naming bound to one policy source."""

    document = policy_document
    if document is None:
        policy_path = repo_root / "policy/native-worker-execution.yaml"
        try:
            loaded = json.loads(policy_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            errors.append(
                "pool-capacity-policy-unreadable:"
                f"{type(error).__name__}"
            )
            return
        if not isinstance(loaded, dict):
            errors.append("pool-capacity-policy-not-object")
            return
        document = loaded
    try:
        limits = load_pool_capacity(document)
    except NativePoolCapacityPolicyError as error:
        errors.append(str(error))
        return

    pool = document.get("native_supervision_pool")
    certification = (
        pool.get("callback_certification")
        if isinstance(pool, dict)
        else None
    )
    scheduler = pool.get("scheduler") if isinstance(pool, dict) else None
    if not isinstance(certification, dict) or not isinstance(scheduler, dict):
        errors.append("pool-schedulability-policy-missing")
    else:
        try:
            warning_fraction = validate_slack_warning_fraction(
                certification.get("slack_warning_fraction")
            )
            proof = scheduling_budget_proof(
                requested_workers=limits.hard_max_active_workers,
                certified_callback_max_ms=certification.get(
                    "certified_callback_max_ms"
                ),
                certified_scheduler_overhead_ms=certification.get(
                    "certified_scheduler_overhead_ms"
                ),
                poll_interval_ms=scheduler.get("poll_interval_ms"),
            )
        except PoolSchedulabilityError as error:
            errors.append(f"pool-schedulability-policy-invalid:{error}")
        else:
            if scheduler.get("slack_warning_fraction") != warning_fraction:
                errors.append("pool-slack-warning-fraction-mismatch")
            if not proof.accepted:
                errors.append(
                    "pool-hard-cap-unschedulable:"
                    f"demand={proof.total_demand_ms}:slack={proof.slack_ms}"
                )
    try:
        errors.extend(
            capacity_schema_errors(
                repo_root=repo_root,
                limits=limits,
            )
        )
    except NativePoolCapacityPolicyError as error:
        errors.append(str(error))

    source_paths: set[Path] = set()
    for pattern in _CAPACITY_SOURCE_GLOBS:
        source_paths.update(path for path in repo_root.glob(pattern) if path.is_file())
    for path in sorted(source_paths):
        relative = path.relative_to(repo_root).as_posix()
        if relative in _CAPACITY_COMPATIBILITY_SOURCES:
            continue
        content = path.read_text(encoding="utf-8")
        for label, pattern in _DEPRECATED_CAPACITY_PATTERNS:
            if pattern.search(content):
                errors.append(
                    f"active native-pool source uses deprecated {label}: {relative}"
                )
        if relative != _SCHEDULABILITY_PROOF_SOURCE:
            compact = re.sub(r"\s+", "", content)
            if re.search(
                r"lifecycle_max(?:_ms)?\+[^+]{0,120}\*"
                r"(?:float\()?check(?:_max|_ms)?",
                compact,
            ):
                errors.append(
                    "active native-pool source duplicates schedulability "
                    f"arithmetic: {relative}"
                )


def validate_release_effect_inventory(errors: list[str]) -> None:
    """Validate current repository coverage without generating review evidence."""
    try:
        release_effect_routes.trace(REPO_ROOT)
    except (release_effect_routes.Refused, OSError) as exc:
        errors.append(f"release effect inventory refused: {exc}")


_MAJOR_ONE_VERSION = re.compile(
    r"1\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    r"(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
)
_CHANGELOG_RELEASE_HEADING = re.compile(r"^ {0,3}#{1,6}[ \t]+\[?[vV]?(?P<major>[0-9]+)\.[0-9]+")
_PUBLISHED_ZERO_MAJOR_HEADINGS = (
    "## 0.8.0 - 2026-11-15",
    "## 0.7.0 - 2026-11-15",
    "## 0.6.0 - 2026-11-14",
    "## 0.5.0 - 2026-11-14",
    "## 0.4.0 - 2026-11-14",
    "## 0.3.1 - 2026-11-14",
    "## 0.3.0 - 2026-11-14",
    "## 0.2.1 - 2026-11-14",
    "## 0.2.0 - 2026-11-11",
)


def validate_release_version(errors: list[str], repo_root: Path) -> None:
    try:
        version = (repo_root / "VERSION").read_text(encoding="utf-8").strip()
        changelog = (repo_root / "CHANGELOG.md").read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        errors.append(f"Could not read release metadata ({exc})")
        return
    if _MAJOR_ONE_VERSION.fullmatch(version) is None:
        errors.append(f"VERSION must contain a 1.x version, found {version!r}")

    # Each published heading can appear once at its original version and date.
    remaining_history = set(_PUBLISHED_ZERO_MAJOR_HEADINGS)
    for number, heading in enumerate(changelog.splitlines(), 1):
        if heading in remaining_history:
            remaining_history.remove(heading)
            continue
        release = _CHANGELOG_RELEASE_HEADING.match(heading)
        if release is not None and release["major"] != "1":
            errors.append(f"CHANGELOG.md:{number} release heading {heading.strip()!r} must use major version 1")


def _script_python_paths(repo_root: Path) -> list[Path]:
    git_dir = repo_root / ".git"
    if not (git_dir.exists() or git_dir.is_symlink()):
        # A source archive has no index. Its exported files define the scope.
        return sorted((repo_root / "scripts").rglob("*.py"))
    result = trusted_git_completed(repo_root, ["ls-files", "-z", "--deduplicate", "--", "scripts/"], timeout=30)
    if result.returncode:
        raise WorkspaceDiscoveryError(f"git ls-files failed: {os.fsdecode(result.stderr).strip()}")
    tracked = result.stdout
    return [repo_root / os.fsdecode(path) for path in tracked.split(b"\0") if path.endswith(b".py")]


def _script_python_lines(path: Path, repo_root: Path) -> int:
    if not path.parent.resolve().is_relative_to(repo_root):
        raise OSError(f"Python path has a parent outside the repository: {path}")
    try:
        mode = path.lstat().st_mode
    except FileNotFoundError:
        return 0  # The tracked path was removed from the working tree.
    if stat.S_ISLNK(mode):
        return len(os.readlink(os.fsencode(path)).splitlines())
    if stat.S_ISREG(mode):
        return len(path.read_bytes().splitlines())
    return 0


def validate_python_line_ceiling(errors: list[str], repo_root: Path) -> None:
    repo_root = repo_root.resolve()
    try:
        total = sum(_script_python_lines(path, repo_root) for path in _script_python_paths(repo_root))
    except (OSError, WorkspaceDiscoveryError) as exc:
        errors.append(f"Could not count physical Python lines under scripts/: {exc}")
        return
    if total > PYTHON_LINE_CEILING:
        errors.append(
            f"Python line ceiling exceeded under scripts/: {total:,} physical lines "
            f"(limit {PYTHON_LINE_CEILING:,})."
        )


def validate_repository() -> list[str]:
    errors: list[str] = []
    validate_python_line_ceiling(errors, REPO_ROOT)
    validate_release_version(errors, REPO_ROOT)
    validate_qualification_target(errors)
    validate_release_effect_inventory(errors)
    validate_cwo_core_contract(errors)
    validate_native_pool_capacity_invariants(errors)
    validate_retired_beads_context_aliases(errors)
    validate_public_copy_docs(errors)
    validate_native_supervision_tech_preview_copy(errors)
    _validate_documentation_group(errors, "native")
    validate_closure_pressure_contract(errors)

    validate_policy_validation_boundaries(errors)
    errors.extend(lint_model_identities(REPO_ROOT))

    normalized_schemas: dict[str, str] = {}
    for path in sorted((REPO_ROOT / "schemas").glob("*.json")):
        try:
            schema = load_json(path)
        except ValueError as exc:
            errors.append(str(exc))
            continue
        if path.name.endswith(".schema.json") and isinstance(schema, dict):
            normalized = dict(schema)
            normalized.pop("title", None)
            fingerprint = json.dumps(normalized, sort_keys=True, separators=(",", ":"))
            previous = normalized_schemas.get(fingerprint)
            if previous:
                errors.append(
                    f"schemas {previous!r} and {path.name!r} are duplicates except for title"
                )
            else:
                normalized_schemas[fingerprint] = path.name

    try:
        executors = load_policy("executor-registry").get("executors", {})
        executor_aliases = load_policy("executor-registry").get("aliases", {})
        experts = load_policy("expert-registry").get("experts", {})
        controls = load_policy("contracting-controls")
        boundaries = load_policy("share-boundaries").get("boundaries", {})
        providers = load_policy("provider-registry").get("providers", {})
        peer_review = load_policy("peer-review-policy")
        zero_trust = load_policy("zero-trust-consensus-policy")
        acceptance = load_policy("acceptance-policy")
        native = load_policy("native-worker-execution")
        model_roles = load_policy("model-roles")
    except SystemExit as exc:
        return [str(exc)]

    errors.extend(validate_execution_environment_registry())
    validate_preferred_native_model(errors, native, model_roles)
    validate_sabotage_threshold_mirrors(errors, controls, acceptance, peer_review)

    if executor_aliases and not isinstance(executor_aliases, dict):
        errors.append("executor-registry aliases must be an object")
        executor_aliases = {}
    for alias, target in executor_aliases.items():
        if alias in executors:
            errors.append(f"executor alias {alias!r} must not shadow an executor key")
        if target not in executors:
            errors.append(f"executor alias {alias!r} targets unknown executor {target!r}")

    # GPT-5.5's protocol-prescribed stable executor key is the sole intentional
    # exception to the role-like-key rule; arbitrary versioned executor keys
    # remain rejected.
    versioned_executor_key_exceptions = {"internal_worker_gpt55"}
    for key, executor in executors.items():
        if any(char.isdigit() for char in key) and key not in versioned_executor_key_exceptions:
            errors.append(f"executor key {key!r} must be role-like and must not contain version digits")
        alias_for = executor.get("alias_for")
        if alias_for and alias_for not in executors:
            errors.append(f"executor {key!r} aliases unknown executor {alias_for!r}")
        if executor.get("external") and executor.get("codex_pickup") != "forbidden":
            errors.append(f"external executor {key!r} must set codex_pickup=forbidden")
        if executor.get("dispatch_mode") in {"local_openai_compatible", "local_secure_review"} and executor.get("codex_pickup") != "forbidden":
            errors.append(f"local worker executor {key!r} must set codex_pickup=forbidden")
        provider_key = executor.get("provider_key")
        if not provider_key or provider_key not in providers:
            errors.append(f"executor {key!r} references unknown provider_key {provider_key!r}")
        elif bool(executor.get("external")) != bool(providers[provider_key].get("external")):
            errors.append(f"executor {key!r} external flag does not match provider {provider_key!r}")
        if executor.get("dispatch_mode") in {"local_openai_compatible", "local_secure_review"}:
            if not executor.get("local_profile"):
                errors.append(f"local executor {key!r} is missing local_profile")
            transport = executor.get("transport") or {}
            for field in [
                "kind",
                "base_url_env",
                "api_key_env",
                "model_env",
                "endpoint_path",
                "timeout_seconds",
                "max_input_chars",
            ]:
                if field not in transport:
                    errors.append(f"local executor {key!r} transport is missing {field!r}")
            if executor.get("supports_web") or executor.get("supports_shell") or executor.get("supports_repo_write"):
                errors.append(f"local executor {key!r} must not support web, shell, or repo write")
        if executor.get("dispatch_mode") == "local_secure_review":
            for permission in ("web", "shell", "repo_write"):
                if executor.get(f"supports_{permission}"):
                    errors.append(f"local secure reviewer {key!r} must not support {permission.replace('_', ' ')}")
            if not executor.get("supports_repo_read"):
                errors.append(f"local secure reviewer {key!r} must support repo read")

    labels: dict[str, str] = {}
    for name, expert in experts.items():
        persona = expert.get("persona_file")
        if not persona or not (REPO_ROOT / persona).is_file():
            errors.append(f"expert {name!r} references missing persona_file {persona!r}")
        label = expert.get("job_description_label")
        if not label or not str(label).startswith("contract-jd-"):
            errors.append(f"expert {name!r} has invalid job_description_label {label!r}")
        elif label in labels:
            errors.append(f"experts {labels[label]!r} and {name!r} share duplicate job label {label!r}")
        else:
            labels[label] = name
        for preferred in expert.get("preferred_executors", []):
            if preferred not in executors:
                errors.append(f"expert {name!r} prefers unknown executor {preferred!r}")

    allowed_external = set(controls.get("allowed_external_executors", []))
    for executor in allowed_external:
        if executor not in executors:
            errors.append(f"contracting controls allow unknown executor {executor!r}")
        elif not executors[executor].get("external"):
            errors.append(f"contracting controls allow non-external executor {executor!r}")
    for key, executor in executors.items():
        if executor.get("external") and key not in allowed_external:
            errors.append(f"external executor {key!r} is not listed in contracting controls")

    for name, boundary in boundaries.items():
        whitelist = set(boundary.get("artifact_whitelist", []))
        if "selected_file_snippets" in whitelist:
            errors.append(f"boundary {name!r} uses legacy plural artifact selected_file_snippets")
        if boundary.get("allows_external"):
            missing = sorted(EMITTED_PACKET_ARTIFACT_TYPES - whitelist)
            if missing:
                errors.append(f"boundary {name!r} does not whitelist emitted artifacts: {', '.join(missing)}")
        if boundary.get("allows_repo_access") and not boundary.get("requires_disclosure_escalation"):
            errors.append(f"boundary {name!r} allows repo access without disclosure escalation")
        if not boundary.get("disclosure_stage"):
            errors.append(f"boundary {name!r} is missing disclosure_stage")

    local_secure = peer_review.get("defaults", {}).get("local_secure_review_executor")
    if local_secure and local_secure not in executors:
        errors.append(f"peer-review policy references unknown local secure reviewer {local_secure!r}")
    elif local_secure and executors[local_secure].get("dispatch_mode") != "local_secure_review":
        errors.append(f"peer-review local secure reviewer {local_secure!r} must use local_secure_review dispatch mode")

    control_peer_executors = controls.get("peer_review_policy", {}).get("allowed_peer_executors", [])
    for executor in control_peer_executors:
        if executor not in executors:
            errors.append(f"contracting controls peer review allows unknown executor {executor!r}")
    for policy in ("sabotage_policy", "malpractice_policy"):
        if not controls.get(policy, {}).get("signal_weights"):
            errors.append(f"contracting controls must define {policy}.signal_weights")
    acceptance_sabotage_signals = acceptance.get("sabotage", {}).get("signals", [])
    for required_signal in [
        "provider_policy_opaque_intervention",
        "provider_conflict_disposition_missing",
        "provider_conflict_disposition_inadequate",
        "work_rerouting_or_subversion",
    ]:
        if required_signal not in controls.get("sabotage_policy", {}).get("signal_weights", {}):
            errors.append(f"contracting controls sabotage_policy.signal_weights missing {required_signal!r}")
    if "work_rerouting_or_subversion" not in acceptance_sabotage_signals:
        errors.append("acceptance-policy sabotage.signals missing 'work_rerouting_or_subversion'")
    work_rerouting_note = acceptance.get("sabotage", {}).get("signal_notes", {}).get("work_rerouting_or_subversion", {})
    if work_rerouting_note.get("authority") != "evidence-quality gate and architect-escalation trigger":
        errors.append("acceptance-policy work_rerouting_or_subversion must remain an evidence-quality architect-escalation gate")
    if work_rerouting_note.get("intent_finding") != "not required and not asserted":
        errors.append("acceptance-policy work_rerouting_or_subversion must not assert intent or misconduct")
    for required_signal in [
        "provider_policy_misrepresentation",
        "provider_conflict_disposition_noncompliant",
    ]:
        if required_signal not in controls.get("malpractice_policy", {}).get("signal_weights", {}):
            errors.append(f"contracting controls malpractice_policy.signal_weights missing {required_signal!r}")
    conflict_terms = load_policy("provider-registry").get("conflict_risk_terms", {})
    for required_term in ["distributed training infrastructure", "accelerator design", "pretraining pipeline"]:
        if required_term not in conflict_terms.get("frontier-ai-development", []):
            errors.append(f"provider-registry frontier-ai-development terms missing {required_term!r}")
    if "provider-policy-intervention" not in conflict_terms:
        errors.append("provider-registry conflict_risk_terms missing 'provider-policy-intervention'")
    for provider_key in ["openai_manual", "anthropic_manual", "google_gemini_manual"]:
        domains = providers.get(provider_key, {}).get("conflict_risk_domains", [])
        if "provider-policy-intervention" not in domains:
            errors.append(f"provider {provider_key!r} conflict_risk_domains missing 'provider-policy-intervention'")
    for required_expert in ["peer_review", "sabotage_review", "editor"]:
        if required_expert not in experts:
            errors.append(f"expert registry is missing required {required_expert!r} gate")
    sabotage_triggers = experts.get("sabotage_review", {}).get("trigger_terms", [])
    for required_term in ["work_rerouting_or_subversion", "objective dilution", "critical path deferral"]:
        if required_term not in sabotage_triggers:
            errors.append(f"sabotage_review trigger_terms missing {required_term!r}")
    if set(zero_trust.get("status_values", [])) != {"informational", "blocked", "divergent"}:
        errors.append("zero-trust-consensus-policy status_values must be informational, blocked, and divergent only")
    if {"confirmed", "validated", "trusted", "passed"} & set(zero_trust.get("status_values", [])):
        errors.append("zero-trust-consensus-policy must not use positive-confidence status names")
    if zero_trust.get("resolution_authority") != "architect":
        errors.append("zero-trust-consensus-policy resolution_authority must be architect")
    if int(zero_trust.get("defaults", {}).get("minimum_independent_domains", 0)) < 2:
        errors.append("zero-trust-consensus-policy minimum_independent_domains must be at least 2")
    if not zero_trust.get("trust_domain_independence_disclaimer"):
        errors.append("zero-trust-consensus-policy must define trust_domain_independence_disclaimer")
    if not zero_trust.get("claim_categories"):
        errors.append("zero-trust-consensus-policy must define claim_categories")
    for category, details in zero_trust.get("claim_categories", {}).items():
        weight = details.get("weight", 0) if isinstance(details, dict) else details
        if int(weight) <= 0:
            errors.append(f"zero-trust claim category {category!r} must have a positive weight")
    thresholds = zero_trust.get("thresholds", {})
    if not all(name in thresholds for name in ["review", "escalation", "quarantine"]):
        errors.append("zero-trust-consensus-policy thresholds must include review, escalation, and quarantine")

    _validate_contractor_schemas(errors)
    _validate_routing_schemas(errors)
    _validate_activation_schemas(errors)
    _validate_readiness_schemas(errors)
    for error in validate_run_readiness_plan(load_json(REPO_ROOT / "examples" / "sample-run-readiness-plan.json")):
        errors.append(f"sample-run-readiness-plan.json: {error}")

    _validate_documentation_group(errors, "public")
    _validate_skill_size(errors)
    _validate_documentation_group(errors, "references")
    validate_local_inference_peer_review_guidance(errors)
    validate_public_docs_do_not_expose_hardware_categories(errors)
    validate_waiver_conventions(errors)

    validate_ci_workflow(errors)

    return errors


def _validate_contractor_schemas(errors: list[str]) -> None:
    _require_runtime_schema_fields(
        errors, "contractor packet", load_json(REPO_ROOT / "schemas" / "contractor-packet.schema.json"),
        CONTRACTOR_PACKET_REQUIRED_FIELDS,
    )
    evidence_properties = [
        "evidence_quality_score",
        "evidence_quality_signals",
        "evidence_quality_signal_categories",
        "research_evidence_score",
        "research_evidence_signals",
        "research_evidence_signal_categories",
        "research_evidence_items",
        "research_contradictions",
        "research_reflection",
    ]
    language_properties = [
        "expected_return_language",
        "expected_return_language_source",
        "return_language_status",
        "return_language_findings",
        "detected_letter_scripts",
        "unexpected_script_ratio",
        "unicode_normalization_changed",
    ]
    _require_schema_file_properties(errors, {
        "opt-in-record.schema.json": ["allowed_providers"],
        "acceptance-decision.schema.json": [
            "malpractice_score",
            "malpractice_signals",
            *evidence_properties,
            "signal_categories",
            "peer_review_required",
            "peer_review_status",
            "boundary_taint_status",
            "boundary_taint_findings",
            "provider_key",
            "provider_trust_tier",
            "provider_external",
            "model_profile",
            "provenance_class",
            "human_adjudication_required",
            "recommended_disposition",
            "recommended_synthesis_use",
            *language_properties,
        ],
        "contractor-return-bundle.schema.json": [
            "provider_key",
            "provider_trust_tier",
            "provider_external",
            "dispatch_mode",
            "local_profile",
            "model_profile",
            "provenance_class",
            *evidence_properties,
            *language_properties,
        ],
    })


def _validate_routing_schemas(errors: list[str]) -> None:
    local_envelope_schema = load_json(REPO_ROOT / "schemas" / "local-dispatch-envelope.schema.json")
    _require_runtime_schema_fields(errors, "local dispatch envelope", local_envelope_schema, LOCAL_DISPATCH_REQUIRED_FIELDS)
    require_schema_properties(
        errors, schema_name="local-dispatch-envelope.schema.json", schema=local_envelope_schema,
        properties=[
            "access_profile",
            "access_profile_details",
            "access_profile_readiness",
            "model_profile",
            "allow_private_dns",
            "tls_verify",
            "tls_ca_bundle_env",
            "request_options",
            "thinking_parser",
            "response_sanitization",
        ],
    )
    prompt_coach_schema = load_json(REPO_ROOT / "schemas" / "prompt-coach-result.schema.json")
    _require_runtime_schema_fields(errors, "prompt coach result", prompt_coach_schema, PROMPT_COACH_RESULT_REQUIRED_FIELDS)
    require_schema_properties(
        errors, schema_name="prompt-coach-result.schema.json", schema=prompt_coach_schema,
        properties=[
            "scaffold_sizing",
            "requires_user_selection_before_plan",
            "selection_before_plan_reason",
            "selection_before_plan_question_ids",
        ],
    )
    _require_schema_file_properties(errors, {
        "route-result.schema.json": [
            "access_profile",
            "model_synthesis",
            "data_sensitivity_source",
            "data_sensitivity_heuristic",
            "data_sensitivity_provenance",
            "data_sensitivity_disclaimer",
            "beads_context_depth",
            "zero_trust_consensus_required",
            "zero_trust_consensus_trigger_reasons",
            "zero_trust_minimum_independent_domains",
            "zero_trust_policy_version",
        ],
    })
    harness_dispatch_schema = load_json(REPO_ROOT / "schemas" / "harness-dispatch-envelope.schema.json")
    _require_runtime_schema_fields(errors, "harness dispatch envelope", harness_dispatch_schema, HARNESS_DISPATCH_REQUIRED_FIELDS)
    require_schema_properties(
        errors, schema_name="harness-dispatch-envelope.schema.json", schema=harness_dispatch_schema,
        properties=[
            "model_profile",
            "model_profile_details",
            "access_profile",
            "access_profile_details",
            "access_profile_readiness",
        ],
    )
    _require_schema_file_properties(errors, {"access-profile.schema.json": ["profiles"]})
    model_profile_schema = load_json(REPO_ROOT / "schemas" / "model-profile.schema.json")
    profile_properties = (
        model_profile_schema.get("properties", {})
        .get("profiles", {})
        .get("additionalProperties", {})
        .get("properties", {})
    )
    for field in MODEL_PROFILE_REQUIRED_FIELDS:
        if field not in profile_properties:
            errors.append(f"model-profile.schema.json profile is missing property {field!r}")
    for field in ["precision", "thinking_enabled", "reasoning_mode", "request_options", "required_vllm_flags"]:
        if field not in profile_properties:
            errors.append(f"model-profile.schema.json profile is missing property {field!r}")
    _require_schema_file_properties(errors, {"execution-environment.schema.json": ["profiles"]})


def _validate_activation_schemas(errors: list[str]) -> None:
    _require_schema_file_properties(errors, {
        "native-tool-activation-result-v2.schema.json": [
            "tool_trace_sha256",
            "bead_closure_sha256",
            "result_sha256",
        ],
        "native-tool-activation-trace.schema.json": [
            "children",
            "all_satisfied",
            "tool_trace_sha256",
        ],
        "native-tool-activation-bead-closure.schema.json": [
            "expected_bead_ids",
            "attempted_bead_ids",
            "unattempted_bead_ids",
            "close_receipts",
            "errors",
            "parent_close_attempted",
            "publication_close_attempted",
            "all_closed",
            "bead_closure_sha256",
        ],
    }, check_required=True)
    activation_result_schemas = (
        (1, load_json(REPO_ROOT / "schemas" / "native-tool-activation-result.schema.json")),
        (2, load_json(REPO_ROOT / "schemas" / "native-tool-activation-result-v2.schema.json")),
    )
    if any(
        schema.get("properties", {}).get("version", {}).get("const") != version
        for version, schema in activation_result_schemas
    ):
        errors.append(
            "native tool activation result schemas must preserve "
            "historical v1 and current v2"
        )


def _validate_readiness_schemas(errors: list[str]) -> None:
    _require_schema_file_properties(errors, {
        "run-readiness-plan.schema.json": [
            "workstreams",
            "rubric",
            "criterion_evidence_matrix",
            "provider_provenance",
            "quarantine_rules",
            "boundary_negative_tests",
            "next_version_rail",
            "patrol_stopping_rule",
            "handoff_evidence_requirements",
            "adjudication_record",
        ],
        "sprint-continuation.schema.json": [
            "recommended_next_issue",
            "why_next",
            "ready_issues",
            "blocked_issues",
            "definition_of_ready",
            "definition_of_done",
            "resume_commands",
            "operator_handoff_packet",
            "modeling_note",
            "ranked_ready_issues",
            "recommended_ready_set",
            "excluded_ready_issues",
            "beads_readiness_snapshot",
            "beads_readiness_snapshot_sha256",
            "fanout_decision",
            "fanout_reasons",
            "candidate_capacity_evidence",
            "ready_set_authority",
            "dispatch_authorized",
        ],
    })
    sprint_continuation_schema = load_json(REPO_ROOT / "schemas" / "sprint-continuation.schema.json")
    operator_packet_schema = sprint_continuation_schema.get("properties", {}).get("operator_handoff_packet", {})
    for field in [
        "next_executable_bead",
        "why_it_is_next",
        "exact_command_resume",
        "execution_prompt",
        "what_must_not_run_yet",
        "commit_push_status",
        "validation_status",
        "escalation_rule",
    ]:
        if field not in operator_packet_schema.get("required", []):
            errors.append(f"sprint-continuation.schema.json operator_handoff_packet is missing required field {field!r}")
        if field not in operator_packet_schema.get("properties", {}):
            errors.append(f"sprint-continuation.schema.json operator_handoff_packet is missing property {field!r}")


def validate_qualification_target(errors: list[str]) -> None:
    """Resolve the selected target through the same boundary used by consumers."""
    try:
        qualification_target.selected_target()
    except qualification_target.TargetError as exc:
        errors.append(f"qualification-target: {exc}")


def validate_policy_validation_boundaries(errors: list[str], policy_dir: Path = POLICY_DIR) -> None:
    """Every policy parses, matches its registered schema, and has a recorded validation boundary."""
    present = {path.name for path in policy_dir.glob("*.yaml")}
    for name in sorted(present):
        try:
            value = load_json_compatible_yaml(policy_dir / name)
        except SystemExit as exc:
            errors.append(str(exc))
            continue
        try:
            schema_errors = policy_document_errors(name, value)
        except SystemExit as exc:
            errors.append(str(exc))
            continue
        errors.extend(f"policy/{name} does not match schemas/{POLICY_SCHEMAS[name]}: {error}" for error in schema_errors)
        if name not in POLICY_VALIDATION_BOUNDARIES:
            errors.append(f"policy/{name} has no recorded validation boundary in cwo_core.policy_schema")
    for name, (kind, _detail) in sorted(POLICY_VALIDATION_BOUNDARIES.items()):
        if name not in present:
            errors.append(f"validation boundary recorded for missing policy/{name}")
        if (kind == "schema") != (name in POLICY_SCHEMAS):
            errors.append(f"policy/{name} validation boundary {kind!r} disagrees with the registered schemas")
    for name in sorted(set(POLICY_SCHEMAS) - present):
        errors.append(f"schema registered for missing policy/{name}")


def validate_preferred_native_model(
    errors: list[str], native: dict[str, Any], model_roles: dict[str, Any],
) -> None:
    worker = native.get("governance", {}).get("native_operative_worker", {})
    expected = model_roles["roles"]["luna"]["current"]
    if worker.get("preferred_model") != expected:
        errors.append("native-worker-execution governance.native_operative_worker.preferred_model must match "
                      f"model-roles roles.luna.current ({expected!r})")


def validate_sabotage_threshold_mirrors(
    errors: list[str], controls: dict[str, Any], acceptance: dict[str, Any], peer_review: dict[str, Any],
) -> None:
    production = controls["sabotage_policy"]["thresholds"]
    mirrors = (
        ("acceptance-policy sabotage.thresholds", acceptance.get("sabotage", {}).get("thresholds", {}),
         {"review": "peer_review", "architect_escalation": "architect_escalation", "quarantine": "quarantine"}),
        ("peer-review-policy sabotage_thresholds", peer_review["sabotage_thresholds"],
         {"review": "peer_review", "quarantine": "quarantine"}),
    )
    for name, thresholds, fields in mirrors:
        for mirror_field, production_field in fields.items():
            expected = production[production_field]
            if thresholds.get(mirror_field) != expected:
                errors.append(f"{name}.{mirror_field} must match contracting-controls "
                              f"sabotage_policy.thresholds.{production_field} ({expected})")


def validate_cwo_core_contract(errors: list[str]) -> None:
    core_dir = REPO_ROOT / "scripts" / "cwo_core"
    legacy_name = "orchestration" + "_lib"
    old_module = REPO_ROOT / "scripts" / f"{legacy_name}.py"
    if old_module.exists():
        errors.append("legacy monolith file remains under scripts/")

    for directory in [REPO_ROOT / "scripts", REPO_ROOT / "tests"]:
        for path in sorted(directory.rglob("*.py")):
            text = path.read_text(encoding="utf-8")
            if legacy_name in text:
                errors.append(f"legacy monolith reference remains in {path.relative_to(REPO_ROOT)}")

    for module_name in CWO_CORE_ALLOWED_IMPORTS:
        module_path = cwo_core_module_path(core_dir, module_name)
        if not module_path.is_file():
            errors.append(f"missing cwo_core module: {module_path.relative_to(REPO_ROOT)}")

    # Subpackages are covered too: a module under scripts/cwo_core/<package>/ is
    # named by its dotted path and needs its own allowlist entry.
    for path in sorted(core_dir.rglob("*.py")):
        if path == core_dir / "__init__.py":
            continue
        module_name = cwo_core_module_name(core_dir, path)
        allowed = CWO_CORE_ALLOWED_IMPORTS.get(module_name)
        if allowed is None:
            errors.append(f"unexpected cwo_core module: {path.relative_to(REPO_ROOT)}")
            continue
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except SyntaxError as exc:
            errors.append(f"{path.relative_to(REPO_ROOT)} has invalid Python syntax: {exc}")
            continue
        for node in ast.walk(tree):
            for imported in cwo_core_import_targets(
                node,
                module_name,
                is_package=path.name == "__init__.py",
                known=CWO_CORE_ALLOWED_IMPORTS,
            ):
                if imported != module_name and imported not in allowed:
                    errors.append(f"cwo_core dependency violation: {module_name} imports {imported}")


def cwo_core_module_name(core_dir: Path, path: Path) -> str:
    """Dotted name below ``cwo_core`` (``routing``, ``supervision.transport``)."""

    parts = path.relative_to(core_dir).with_suffix("").parts
    if parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts)


def cwo_core_module_path(core_dir: Path, module_name: str) -> Path:
    module_path = core_dir.joinpath(*module_name.split("."))
    if module_path.is_dir():
        return module_path / "__init__.py"
    return module_path.with_name(module_path.name + ".py")


def _import_from_core_base(node: ast.ImportFrom, module_name: str, is_package: bool) -> list[str] | None:
    module_parts = node.module.split(".") if node.module else []
    if node.level == 0:
        return module_parts[1:] if module_parts and module_parts[0] == "cwo_core" else None
    package = module_name.split(".") if is_package else module_name.split(".")[:-1]
    if node.level - 1 > len(package):
        return ["<outside cwo_core>"]
    return package[:len(package) - (node.level - 1)] + module_parts


def cwo_core_import_targets(
    node: ast.AST,
    module_name: str,
    *,
    is_package: bool,
    known: dict[str, set[str]],
) -> set[str]:
    """Return the cwo_core modules one import statement depends on.

    A target is named by its longest dotted prefix that is a known module, so
    ``cwo_core.routing.classify_work`` is ``routing`` and
    ``cwo_core.supervision.transport.app_server`` is itself; an unknown target
    is named by its first component. Relative imports
    resolve from the importing module's package; one that climbs above
    ``cwo_core`` is reported as ``<outside cwo_core>``.
    """

    candidates: list[list[str]] = []
    if isinstance(node, ast.Import):
        for alias in node.names:
            parts = alias.name.split(".")
            if parts[0] == "cwo_core" and len(parts) > 1:
                candidates.append(parts[1:])
    elif isinstance(node, ast.ImportFrom):
        base = _import_from_core_base(node, module_name, is_package)
        if base is None:
            return set()
        if base:
            candidates.append(base)
        for alias in node.names:
            if alias.name != "*":
                candidates.append(base + [alias.name])
    targets: set[str] = set()
    for parts in candidates:
        prefixes = [".".join(parts[:end]) for end in range(len(parts), 0, -1)]
        targets.add(next((prefix for prefix in prefixes if prefix in known), parts[0]))
    return targets


def _ci_job_block(ci: str, job: str) -> str:
    blocks = re.findall(r"^  " + re.escape(job) + r":\n(.*?)(?=^  [\w-]+:|\Z)", ci,
                        flags=re.MULTILINE | re.DOTALL)
    return blocks[0] if len(blocks) == 1 else ""


def _ci_required_lines(block: str, lines: tuple[str, ...]) -> bool:
    return all(len(re.findall("^" + re.escape(line) + "$", block, re.MULTILINE)) == 1
               for line in lines)


def _ci_exact_job_section(block: str, name: str, expected: str) -> bool:
    """Compare the entire section up to the next job key, not just its prefix."""
    sections = re.findall(r"^    " + re.escape(name) + r":\n.*?(?=^    \S|\Z)", block,
                          flags=re.MULTILINE | re.DOTALL)
    return sections == [expected]


def _ci_step(job: str, label: str) -> list[str]:
    return re.findall(r"^      - " + label + r"\n(.*?)(?=^      - |\Z)", job,
                      flags=re.MULTILINE | re.DOTALL)


def _validate_ci_unit_shards(errors: list[str], ci: str) -> None:
    job = _ci_job_block(ci, "test")
    strategy = ("    strategy:\n      fail-fast: false\n"
                "      matrix:\n        python-version: ['3.12', '3.14']\n"
                "        shard: [0, 1, 2, 3]\n")
    required = (
        "    name: unit-tests (Python ${{ matrix.python-version }}, ${{ matrix.shard }}/4)",
        "    env:\n      CWO_TEST_SHARD_INDEX: ${{ matrix.shard }}\n      CWO_TEST_SHARD_COUNT: 4",
    )
    units = _ci_step(job, "name: Unit tests")
    setup = _ci_step(job, r"uses: actions/setup-python@[^\n]+")
    checkout_count = len(re.findall(r"^      - uses: actions/checkout@", job, re.MULTILINE))
    if (not _ci_required_lines(job, required) or not _ci_exact_job_section(job, "strategy", strategy)
            or setup != ["        with:\n          python-version: ${{ matrix.python-version }}\n"]
            or [step.strip("\n") for step in units] != ["        run: " + CI_UNIT_TEST_COMMAND]
            or checkout_count != 1
            or re.search(r"^    (?:if|continue-on-error):", job, re.MULTILINE)):
        errors.append("CI unit shards must cover 0..3/4 on Python 3.12 and 3.14 with unconditional steps")


def _validate_ci_test_aggregate(errors: list[str], ci: str) -> None:
    job = _ci_job_block(ci, "test-result")
    required = (
        "    name: test", "    needs: [test, quality, codex-protocol-contract]", "    if: ${{ always() }}",
        "    env:\n      UNIT_TEST_RESULT: ${{ needs.test.result }}\n"
        "      QUALITY_RESULT: ${{ needs.quality.result }}\n"
        "      CODEX_PROTOCOL_RESULT: ${{ needs.codex-protocol-contract.result }}",
    )
    steps = ('    steps:\n      - name: Require all unit test shards, quality checks and Codex protocol contracts\n'
             '        run: test "$UNIT_TEST_RESULT" = success && test "$QUALITY_RESULT" = success'
             ' && test "$CODEX_PROTOCOL_RESULT" = success')
    if (not _ci_required_lines(job, required) or not job.rstrip().endswith(steps)
            or re.search(r"^    continue-on-error:", job, re.MULTILINE)):
        errors.append("CI test aggregate must always require success from unit shards, quality and Codex contracts")


def _ci_top_level_section(workflow: str, name: str) -> list[str]:
    pattern = rf"^{re.escape(name)}:\n(.*?)(?=^\S|\Z)"
    return [section.strip() for section in re.findall(pattern, workflow, re.MULTILINE | re.DOTALL)]


def _ci_codex_contract_steps(job: str, package: str) -> bool:
    install = rf"^(?: {{6}}- run: | {{10}})npm install\b[^\n]* {re.escape(package)}(?: +\#.*)?$"
    return (_ci_required_lines(job, (f"        run: {CI_CODEX_CONTRACT_COMMAND}",))
            and re.search(install, job, re.MULTILINE) is not None
            and not re.search(r"^ +(?:if|continue-on-error|permissions):", job, re.MULTILINE))


def _validate_ci_codex_contracts(errors: list[str], ci: str) -> None:
    job = _ci_job_block(ci, "codex-protocol-contract")
    strategy = ("    strategy:\n      fail-fast: false\n      matrix:\n"
                "        codex-version: ['0.163.0', '0.171.0']\n")
    env = "    env:\n      CODEX_VERSION: ${{ matrix.codex-version }}\n"
    if (not re.search(r"^  pull_request:\s*$", ci, re.MULTILINE)
            or _ci_top_level_section(ci, "permissions") != ["contents: read"]
            or not _ci_exact_job_section(job, "strategy", strategy)
            or not _ci_exact_job_section(job, "env", env)
            or not _ci_codex_contract_steps(job, '"@openai/codex@$CODEX_VERSION"')):
        errors.append("CI Codex protocol contract must run for released 0.163.0 and 0.171.0")


def _validate_weekly_codex_contract(errors: list[str]) -> None:
    path = REPO_ROOT / ".github" / "workflows" / "codex-protocol-latest.yml"
    if not path.is_file():
        errors.append("Weekly Codex protocol contract workflow is missing")
        return
    workflow = path.read_text(encoding="utf-8")
    events = _ci_top_level_section(workflow, "on")
    week = r"schedule:\n    - cron: '[0-5]?\d (?:[01]?\d|2[0-3]) \* \* [0-6]'"
    job = _ci_job_block(workflow, "codex-protocol-contract")
    if (len(events) != 1 or re.fullmatch(week, events[0]) is None
            or _ci_top_level_section(workflow, "permissions") != ["contents: read"]
            or not _ci_required_lines(job, ("          persist-credentials: false",))
            or not _ci_codex_contract_steps(job, "@openai/codex@latest")):
        errors.append("Weekly Codex protocol contract must use the scheduled, read-only latest release check")


def validate_ci_workflow(errors: list[str], ci_path: Path | None = None) -> None:
    path = ci_path or REPO_ROOT / ".github" / "workflows" / "ci.yml"
    if not path.is_file():
        return
    ci = path.read_text(encoding="utf-8")
    _validate_ci_unit_shards(errors, ci)
    _validate_ci_test_aggregate(errors, ci)
    _validate_ci_codex_contracts(errors, ci)
    _validate_weekly_codex_contract(errors)
    for term in CI_REQUIRED_COMMANDS:
        if term not in ci:
            errors.append(f"CI workflow is missing required command: {term}")
    for workflow_path in sorted((REPO_ROOT / ".github" / "workflows").glob("*.yml")):
        content = workflow_path.read_text(encoding="utf-8")
        for match in re.finditer(r"uses:\s*([\w.-]+/[\w.-]+)(?:/[^@\s]+)?@([^\s]+)(?:\s+#\s*(\S+))?", content):
            action, reference, comment = match.groups()
            base = action if action in APPROVED_ACTION_PINS else action.split("/", 2)[0] + "/" + action.split("/", 2)[1]
            expected = APPROVED_ACTION_PINS.get(base)
            if expected is None:
                errors.append(f"workflow uses unknown action: {action}")
            elif reference != expected[0] or comment != expected[1] or len(reference) != 40:
                errors.append(f"workflow action pin is invalid: {action}@{reference}")
    if "contents: read" not in ci or "cancel-in-progress: true" not in ci:
        errors.append("CI workflow is missing least privilege or cancellable concurrency")
    if "timeout-minutes:" not in ci or "codeql:" not in ci or "shellcheck:" not in ci:
        errors.append("CI workflow is missing timeout, CodeQL, or ShellCheck controls")


def require_schema_properties(
    errors: list[str],
    *,
    schema_name: str,
    schema: dict[str, Any],
    properties: list[str],
) -> None:
    available = set(schema.get("properties", {}))
    missing = sorted(set(properties) - available)
    if missing:
        errors.append(f"schema {schema_name} is missing properties: {', '.join(missing)}")


def _require_schema_file_properties(
    errors: list[str], requirements: dict[str, list[str]], *, check_required: bool = False
) -> None:
    for schema_name, properties in requirements.items():
        schema = load_json(REPO_ROOT / "schemas" / schema_name)
        require_schema_properties(errors, schema_name=schema_name, schema=schema, properties=properties)
        if check_required:
            missing_required = sorted(set(properties) - set(schema.get("required", [])))
            if missing_required:
                errors.append(f"schema {schema_name} does not require properties: {', '.join(missing_required)}")


def _require_runtime_schema_fields(
    errors: list[str], label: str, schema: dict[str, Any], fields: list[str],
) -> None:
    required = set(schema.get("required", []))
    missing = sorted(set(fields) - required)
    if missing:
        errors.append(f"{label} schema is missing runtime required fields: {', '.join(missing)}")


def _validate_documentation_group(errors: list[str], group: str) -> None:
    path = REPO_ROOT / "tools" / "ci" / "required-documentation.json"
    try:
        groups = load_json(path)
    except (OSError, ValueError) as exc:
        errors.append(f"Could not read documentation requirements: {exc}")
        return
    rules = groups.get(group) if isinstance(groups, dict) else None
    if not isinstance(rules, list) or not rules:
        errors.append(f"Missing documentation requirements for {group!r}")
        return
    for rule in rules:
        if not isinstance(rule, dict) or not all(
            isinstance(values := rule.get(key), list)
            and values
            and all(isinstance(value, str) and value for value in values)
            for key in ("files", "terms")
        ):
            errors.append(f"Invalid documentation requirements for {group!r}")
            continue
        for relative_path in rule["files"]:
            require_doc_terms(errors, relative_path, rule["terms"])


def _validate_skill_size(errors: list[str]) -> None:
    skill_path = REPO_ROOT / "SKILL.md"
    if skill_path.is_file():
        skill_content = skill_path.read_text(encoding="utf-8")
        line_count, word_count = len(skill_content.splitlines()), len(skill_content.split())
        for count, unit, limit in ((line_count, "lines", 220), (word_count, "words", 1600)):
            if count > limit:
                errors.append(f"SKILL.md should stay router-sized: {count} {unit} > {limit}")


def require_doc_terms(errors: list[str], relative_path: str, terms: list[str]) -> None:
    if public_copy_validated_path(relative_path):
        errors.extend(validate_required_doc_terms(relative_path, terms))
    path = REPO_ROOT / relative_path
    if not path.is_file():
        errors.append(f"required documentation file is missing: {relative_path}")
        return
    content = path.read_text(encoding="utf-8")
    if path.suffix == ".html":
        content = without_token_spans(content)
    normalized_content = " ".join(content.split())
    missing = [
        term
        for term in terms
        if term not in content and " ".join(term.split()) not in normalized_content
    ]
    if missing:
        errors.append(f"{relative_path} is missing required terms: {', '.join(missing)}")


def validate_native_supervision_tech_preview_copy(
    errors: list[str],
    content: str | None = None,
    relative_path: str = "docs/native-supervision.html",
) -> None:
    if content is None:
        path = REPO_ROOT / relative_path
        if not path.is_file():
            errors.append(f"required documentation file is missing: {relative_path}")
            return
        content = path.read_text(encoding="utf-8")

    normalized = " ".join(content.split())
    required_fragments = [
        ('default section anchor', 'id="default-path"'),
        ('single-worker navigation', 'href="#single-worker"'),
        ('control-turn section anchor', 'id="control-turn"'),
        ('workspace section anchor', 'id="workspace-authority"'),
        ('failure section anchor', 'id="failure-recovery"'),
        ('concurrency section anchor', 'id="concurrency-preview"'),
        ('mandatory supervision', 'no unsupervised opt-out'),
        ('configured Luna role', 'configured Luna model'),
        ('Sol escalation role', 'Sol handles recorded coding escalation'),
        ('Terra assignment', 'Terra handles explicitly classified interface, visual and computer-use work'),
        ('no model substitution', 'Do not silently substitute an available model'),
        ('persistence before triggering', 'Save the control state and register monitoring before sending the assignment'),
        ('enforced effect boundary', 'enforced filesystem/network boundaries'),
        ('finite operation reservation', 'finite time/usage allowance'),
        ('final attribution', 'which files actually changed'),
        ('owned cleanup', 'Confirm owned processes and resources are closed'),
        ('fixed cohort ceiling', 'two or three independent approved assignments'),
        ('same-host callback measurement', 'measures its callbacks on the same host'),
        ('registered contained route', 'Registered contained pools'),
        ('stateful operation ordering', 'Beads updates, integration and publication in their normal order'),
        ('terminal attempts', 'A stopped attempt cannot be resumed; another attempt needs its own fresh allowance'),
        ('single-worker operator link', 'https://github.com/gprocunier/complex-work-orchestration/blob/main/references/native-supervision.md'),
        ('pool operator link', 'https://github.com/gprocunier/complex-work-orchestration/blob/main/references/native-supervision-pools.md'),
    ]
    missing = [label for label, fragment in required_fragments if fragment not in normalized]
    if missing:
        errors.append(
            f"{relative_path} is missing the layered native-supervision contract: "
            + ", ".join(missing)
        )


def public_copy_validated_path(relative_path: str) -> bool:
    if relative_path in PUBLIC_COPY_DOC_PATHS:
        return True
    return any(Path(relative_path).match(pattern) for pattern in PUBLIC_COPY_DOC_GLOBS)


def public_copy_allows_internal_labels(relative_path: str) -> bool:
    return (
        relative_path in PUBLIC_COPY_INTERNAL_LABEL_ALLOWED_FILES
        or relative_path.startswith(PUBLIC_COPY_INTERNAL_LABEL_ALLOWED_PREFIXES)
    )


def iter_public_copy_markdown_docs(repo_root: Path = REPO_ROOT) -> list[Path]:
    paths: list[Path] = []
    for relative_path in PUBLIC_COPY_DOC_PATHS:
        path = repo_root / relative_path
        if path.is_file():
            paths.append(path)
    for pattern in PUBLIC_COPY_DOC_GLOBS:
        paths.extend(path for path in sorted(repo_root.glob(pattern)) if path.is_file())
    return sorted(set(paths))


def validate_public_copy_docs(errors: list[str], repo_root: Path = REPO_ROOT) -> None:
    for path in iter_public_copy_markdown_docs(repo_root):
        try:
            relative = path.relative_to(repo_root).as_posix()
        except ValueError:
            relative = path.as_posix()
        errors.extend(
            validate_markdown_public_copy(
                path,
                source_name=relative,
                allow_internal_labels=public_copy_allows_internal_labels(relative),
            )
        )


def validate_public_docs_do_not_expose_hardware_categories(
    errors: list[str], public_docs: list[Path] | None = None
) -> None:
    if public_docs is None:
        public_docs = [REPO_ROOT / "README.md", *sorted((REPO_ROOT / "docs").glob("*.html"))]
    for path in public_docs:
        if not path.is_file():
            continue
        content = path.read_text(encoding="utf-8")
        lowered = content.lower()
        forbidden = [
            term
            for term in PUBLIC_DOC_FORBIDDEN_HARDWARE_TERMS
            if term.lower() in lowered
        ]
        if forbidden:
            try:
                relative = path.relative_to(REPO_ROOT)
            except ValueError:
                relative = path
            errors.append(
                f"{relative} exposes hardware-specific public category terms: {', '.join(forbidden)}"
            )


def validate_local_inference_peer_review_guidance(
    errors: list[str], content: str | None = None, relative_path: str = "references/local-inference.md"
) -> None:
    if content is None:
        path = REPO_ROOT / relative_path
        if not path.is_file():
            return
        content = path.read_text(encoding="utf-8")
    unconditional_command = "python3 scripts/evaluate_return.py --file local-return.md --peer-review-required"
    baseline_section = content.split("Add `--peer-review-required` only when", 1)[0]
    if unconditional_command in baseline_section:
        errors.append(
            f"{relative_path} must show local-worker evaluation without unconditional --peer-review-required"
        )
    required_terms = [
        "python3 scripts/evaluate_return.py --file local-return.md",
        "--executor openshift_ai_vllm_worker",
        "provider_trust_tier",
        "provenance_class",
        "Add `--peer-review-required` only when",
        "route_work.py",
        "evaluator policy",
    ]
    missing = [term for term in required_terms if term not in content]
    if missing:
        errors.append(f"{relative_path} is missing route-derived peer-review guidance: {', '.join(missing)}")


def waiver_flag_dest(flag: str) -> str:
    if flag == "--no-audit":
        return "audit"
    return flag.removeprefix("--").replace("-", "_")


def literal_string_list(node: ast.AST) -> set[str]:
    if not isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return set()
    values: set[str] = set()
    for item in node.elts:
        if isinstance(item, ast.Constant) and isinstance(item.value, str):
            values.add(item.value)
    return values


def literal_call_flags(node: ast.Call) -> set[str]:
    flags: set[str] = set()
    for arg in node.args:
        if isinstance(arg, ast.Constant) and isinstance(arg.value, str) and arg.value.startswith("--"):
            flags.add(arg.value)
    return flags


def called_function_name(node: ast.Call) -> str | None:
    if isinstance(node.func, ast.Name):
        return node.func.id
    if isinstance(node.func, ast.Attribute):
        return node.func.attr
    return None


def extract_flag_destinations(tree: ast.AST, function_name: str) -> set[str]:
    destinations: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or called_function_name(node) != function_name:
            continue
        if len(node.args) >= 2:
            destinations.update(literal_string_list(node.args[1]))
        for keyword in node.keywords:
            if keyword.arg == "flag_dests":
                destinations.update(literal_string_list(keyword.value))
    return destinations


def extract_argparse_flags(tree: ast.AST) -> set[str]:
    flags: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and called_function_name(node) == "add_argument":
            flags.update(literal_call_flags(node))
    return flags


def is_waiver_shaped_flag(flag: str) -> bool:
    return flag == "--no-audit" or flag.startswith("--allow-") or "-allow-" in flag


def validate_no_uncovered_waiver_flags(
    errors: list[str],
    *,
    parsed_scripts: dict[str, ast.AST],
    scripts: dict[str, dict[str, Any]],
) -> None:
    covered_by_path = {
        relative_path: set(spec.get("flags", []))
        for relative_path, spec in scripts.items()
    }
    for relative_path, tree in parsed_scripts.items():
        discovered = {
            flag
            for flag in extract_argparse_flags(tree)
            if is_waiver_shaped_flag(flag)
        }
        exceptions = WAIVER_FLAG_DISCOVERY_EXCEPTIONS.get(relative_path, set())
        uncovered = sorted(discovered - covered_by_path.get(relative_path, set()) - exceptions)
        if uncovered:
            errors.append(
                f"{relative_path} defines bypass-shaped flags not covered by WAIVER_CONVENTION_SCRIPTS: "
                + ", ".join(uncovered)
            )


def validate_waiver_conventions(
    errors: list[str],
    scripts: dict[str, dict[str, Any]] | None = None,
    repo_root: Path = REPO_ROOT,
) -> None:
    script_specs = scripts or WAIVER_CONVENTION_SCRIPTS
    parsed_scripts: dict[str, ast.AST] = {}
    for relative_path, spec in script_specs.items():
        path = repo_root / relative_path
        if not path.is_file():
            errors.append(f"waiver convention script is missing: {relative_path}")
            continue
        content = path.read_text(encoding="utf-8")
        try:
            tree = ast.parse(content)
        except SyntaxError as exc:
            errors.append(f"{relative_path} has invalid Python syntax: {exc}")
            continue
        parsed_scripts[relative_path] = tree
        flags = list(spec.get("flags", []))
        missing_flags = [flag for flag in flags if flag not in content]
        if missing_flags:
            errors.append(f"{relative_path} is missing controlled waiver flags: {', '.join(missing_flags)}")
            continue
        required_destinations = {waiver_flag_dest(flag) for flag in flags}
        reason_destinations = extract_flag_destinations(tree, "require_waiver_reason")
        missing_reason = sorted(required_destinations - reason_destinations)
        if "add_waiver_reason_argument" not in content:
            errors.append(f"{relative_path} must define --waiver-reason with add_waiver_reason_argument")
        if missing_reason:
            errors.append(
                f"{relative_path} must require --waiver-reason for: {', '.join(missing_reason)}"
            )
        if spec.get("audit_fields"):
            audit_destinations = extract_flag_destinations(tree, "waiver_audit_fields")
            missing_audit = sorted(required_destinations - audit_destinations)
            if missing_audit:
                errors.append(
                    f"{relative_path} must add waiver audit fields for: {', '.join(missing_audit)}"
                )
        for term in spec.get("audit_terms", []):
            if term not in content:
                errors.append(f"{relative_path} is missing waiver audit term: {term}")
    if scripts is None:
        for path in sorted((repo_root / "scripts").glob("*.py")):
            relative_path = str(path.relative_to(repo_root))
            if relative_path in parsed_scripts:
                continue
            try:
                tree = ast.parse(path.read_text(encoding="utf-8"))
            except SyntaxError as exc:
                errors.append(f"{relative_path} has invalid Python syntax: {exc}")
                continue
            parsed_scripts[relative_path] = tree
    validate_no_uncovered_waiver_flags(errors, parsed_scripts=parsed_scripts, scripts=script_specs)


def main() -> None:
    errors = validate_repository()
    if errors:
        print("Repository validation failed:", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        raise SystemExit(1)
    print("Repository validation passed.")


if __name__ == "__main__":
    main()
