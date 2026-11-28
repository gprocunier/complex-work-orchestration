#!/usr/bin/env python3
"""Compatibility exports for native supervision and the retired campaign CLI."""

from __future__ import annotations

import copy as copy
import hashlib as hashlib
import json
import math as math
import os as os
import re as re
import shlex as shlex
from pathlib import Path
import stat as stat
import sys
import threading as threading
import time as time
from typing import Any, Callable, Iterable, Mapping, NoReturn
import uuid as uuid


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))


from cwo_core import native_live_availability as live_availability  # noqa: E402
from cwo_core.codex_tool_surface import (  # noqa: E402
    CodexToolSurfaceError as CodexToolSurfaceError,
    DIRECT_TOOL_TRANSPORT as DIRECT_TOOL_TRANSPORT,
    NAMESPACED_EXEC_TOOL_TRANSPORT as NAMESPACED_EXEC_TOOL_TRANSPORT,
    ALLOWLIST_PARAMETER as _CONFIG_TOOL_ALLOWLIST_PARAMETER,
    discover_codex_binary,
    prepare_capture_binding as prepare_capture_binding,
    require_capture_binding as require_capture_binding,
    require_surface_proof as require_surface_proof,
    require_zero_endpoint_inventory as require_zero_endpoint_inventory,
    thread_start_enforcement_params as thread_start_enforcement_params,
    tool_profile_is_mutable as tool_profile_is_mutable,
    tool_transport_instructions as tool_transport_instructions,
)
from cwo_core.native_canary_contracts import (  # noqa: E402
    CONTROL_OBSERVATION_MAX as CONTROL_OBSERVATION_MAX,
    MATERIALIZATION_EVIDENCE_SCHEMA as MATERIALIZATION_EVIDENCE_SCHEMA,
    MATERIALIZATION_EVIDENCE_TYPE as MATERIALIZATION_EVIDENCE_TYPE,
    NativeCanaryContractError as NativeCanaryContractError,
    materialization_execution_correlation as materialization_execution_correlation,
    materialization_liveness_correlation as materialization_liveness_correlation,
    seal_materialization_evidence as seal_materialization_evidence,
    validate_capability_rendered_command as validate_capability_rendered_command,
    validate_materialization_evidence as validate_materialization_evidence,
)
from cwo_core.native_live_allocation_ledger import (  # noqa: E402
    IdentityCapabilityRegistry,
    TurnNegativeResponseObserverBinding,
)
from cwo_core.native_pool import LegacyNativePoolExecutionRetired as LegacyNativePoolExecutionRetired  # noqa: E402
from cwo_core.native_pool_capacity import load_pool_capacity as load_pool_capacity  # noqa: E402
from cwo_core.native_pool_capacity_compat import LEGACY_CONCURRENT_CAPACITY as LEGACY_CONCURRENT_CAPACITY  # noqa: E402
from cwo_core.native_pool_contracts import (  # noqa: E402
    CAPABILITY_CERTIFICATION_ENVELOPE as CAPABILITY_CERTIFICATION_ENVELOPE,
    CAPABILITY_CERTIFICATION_VERSION as CAPABILITY_CERTIFICATION_VERSION,
    CAPABILITY_OBSERVATION_AUTHORITY as CAPABILITY_OBSERVATION_AUTHORITY,
    CAPABILITY_RECEIPT_SCHEMA as CAPABILITY_RECEIPT_SCHEMA,
    CAPABILITY_RECEIPT_TYPE as CAPABILITY_RECEIPT_TYPE,
    CAPABILITY_RESPONSE_TIME_EQUATION as CAPABILITY_RESPONSE_TIME_EQUATION,
    CAPABILITY_SCHEDULER_MODEL as CAPABILITY_SCHEDULER_MODEL,
    CAPABILITY_SLACK_WARNING_FRACTION as CAPABILITY_SLACK_WARNING_FRACTION,
    CERTIFIED_CALLBACK_MAX_MS as CERTIFIED_CALLBACK_MAX_MS,
    CERTIFIED_SCHEDULER_OVERHEAD_MS as CERTIFIED_SCHEDULER_OVERHEAD_MS,
    POOL_POLL_INTERVAL_MS as POOL_POLL_INTERVAL_MS,
    POOL_POLL_LAG_TOLERANCE_MS as POOL_POLL_LAG_TOLERANCE_MS,
    callback_certification_policy_sha256 as callback_certification_policy_sha256,
    canonical_sha256 as canonical_sha256,
    default_completion_evidence_policy as default_completion_evidence_policy,
    seal_artifact as seal_artifact,
    validate_capability_receipt as validate_capability_receipt,
    validate_completion_evidence_policy as validate_completion_evidence_policy,
    write_private_artifact as write_private_artifact,
    zero_token_usage as zero_token_usage,
)
from cwo_core.native_pool_schedulability import (  # noqa: E402
    PoolSchedulabilityError as PoolSchedulabilityError,
    scheduling_budget_proof as scheduling_budget_proof,
)
from cwo_core.native_pool_scheduler import select_earliest_deadline as select_earliest_deadline  # noqa: E402
from cwo_core.native_session import session_record_token_snapshot  # noqa: E402
from cwo_core.native_session_boundary import (  # noqa: E402
    LocatedSession as LocatedSession,
    NativeSessionBoundaryError as NativeSessionBoundaryError,
    capture_boundary as capture_boundary,
    capture_unique_boundary as capture_unique_boundary,
    locate_unique_session as locate_unique_session,
    session_source_identity as session_source_identity,
    telemetry_markers as telemetry_markers,
    trusted_terminal_event as trusted_terminal_event,
    trusted_turn_context as trusted_turn_context,
)
from cwo_core.native_tool_isolation import (  # noqa: E402
    NativeToolIsolationError as NativeToolIsolationError,
    build_tool_surface_snapshot as build_tool_surface_snapshot,
    default_tool_policy as default_tool_policy,
    forbidden_tool_activity as forbidden_tool_activity,
    normalize_tool_policy as normalize_tool_policy,
    require_prompt_preflight as require_prompt_preflight,
    require_unchanged_tool_surface as require_unchanged_tool_surface,
    validate_tool_surface_snapshot as validate_tool_surface_snapshot,
)
from cwo_core.native_turn_dispatch import (  # noqa: E402
    TURN_ABSENCE_PROOF_ARTIFACT_TYPE as TURN_ABSENCE_PROOF_ARTIFACT_TYPE,
    TurnDispatchReservation as TurnDispatchReservation,
    evolve_turn_dispatch_record as evolve_turn_dispatch_record,
    seal_turn_absence_proof as seal_turn_absence_proof,
    validate_turn_dispatch_record as validate_turn_dispatch_record,
)
from cwo_core.native_worker_contracts import (  # noqa: E402
    tool_argument_value,
    session_event_items,
    tool_output_text,
    paired_namespaced_exec_result,
    canonical_argument_hash as canonical_argument_hash,
    decode_namespaced_exec_source as decode_namespaced_exec_source,
    is_tool_call_item as is_tool_call_item,
    is_tool_output_item as is_tool_output_item,
    normalize_action_receipts as normalize_action_receipts,
    trusted_tool_name as trusted_tool_name,
)
from cwo_core.supervision.callback_timing import (  # noqa: E402
    ADAPTER_IMPLEMENTATION_PATHS as ADAPTER_IMPLEMENTATION_PATHS,
    PROVISIONAL_TERMINAL_GRACE_SECONDS as PROVISIONAL_TERMINAL_GRACE_SECONDS,
    measure_action_ms,
    adapter_implementation_sha256 as adapter_implementation_sha256,
    callback_certification_policy as callback_certification_policy,
    capability_certification as capability_certification,
    guarded_measure as guarded_measure,
    iso as iso,
    percentile as percentile,
    pool_sleep as pool_sleep,
    stats as stats,
    utc_now as utc_now,
)
from cwo_core.supervision.containment import (  # noqa: E402
    STAGED_ARCHIVE_CLOSE_SETTLE_SECONDS as STAGED_ARCHIVE_CLOSE_SETTLE_SECONDS,
    STAGED_ARCHIVE_TERMINAL_POLL_SECONDS as STAGED_ARCHIVE_TERMINAL_POLL_SECONDS,
    STAGED_ARCHIVE_TERMINAL_TIMEOUT_SECONDS as STAGED_ARCHIVE_TERMINAL_TIMEOUT_SECONDS,
    StagedThreadArchive as StagedThreadArchive,
    contain_started_threads as contain_started_threads,
)
from cwo_core.supervision.live_thread import (  # noqa: E402
    LivePoolProtectedFault as LivePoolProtectedFault,
    LiveThreadAdapter as LiveThreadAdapter,
    OPERATIVE_ITEM_TYPES as OPERATIVE_ITEM_TYPES,
    POST_SUBMISSION_MATERIALIZATION_GRACE_MS as POST_SUBMISSION_MATERIALIZATION_GRACE_MS,
)
from cwo_core.supervision.session_evidence import (  # noqa: E402
    CALIBRATION_READ_RECOVERY_POLICY as CALIBRATION_READ_RECOVERY_POLICY,
    CALIBRATION_READ_RECOVERY_TELEMETRY_FIELDS as CALIBRATION_READ_RECOVERY_TELEMETRY_FIELDS,
    CALIBRATION_READ_RECOVERY_TELEMETRY_TYPE as CALIBRATION_READ_RECOVERY_TELEMETRY_TYPE,
    DESCRIPTOR_CAPTURE_ATTEMPT_MAX as DESCRIPTOR_CAPTURE_ATTEMPT_MAX,
    DESCRIPTOR_CAPTURE_RETRY_GAP_SECONDS as DESCRIPTOR_CAPTURE_RETRY_GAP_SECONDS,
    EXACT_TOOL_TRACE_STEP_FIELDS as EXACT_TOOL_TRACE_STEP_FIELDS,
    PENDING_EXEC_SESSION as PENDING_EXEC_SESSION,
    PreAttestationSessionBoundaryTracker as PreAttestationSessionBoundaryTracker,
    READ_ONLY_COMMAND_AUTHORITY_STEP_FIELDS as READ_ONLY_COMMAND_AUTHORITY_STEP_FIELDS,
    STARTUP_SCAFFOLD_RECORD_TYPES as STARTUP_SCAFFOLD_RECORD_TYPES,
    STARTUP_SCAFFOLD_SESSION_META_FIELDS as STARTUP_SCAFFOLD_SESSION_META_FIELDS,
    STARTUP_SCAFFOLD_TASK_STARTED_FIELDS as STARTUP_SCAFFOLD_TASK_STARTED_FIELDS,
    STARTUP_SCAFFOLD_TOP_LEVEL_FIELDS as STARTUP_SCAFFOLD_TOP_LEVEL_FIELDS,
    DIRECT_PENDING_EXEC_RESULT_PATTERN,
    READ_ONLY_SHELL_META,
    bind_tool_receipt_workdirs,
    direct_pending_operation_session_id,
    exec_workdir_binding,
    is_nonexistent_canonical_nonsymlink_path,
    normalize_expected_tool_trace,
    normalize_read_only_command_authority,
    parse_read_only_command_tokens,
    require_positive_read_only_command,
    strict_session_json_object_pairs,
    parse_strict_session_json_record,
    project_tool_receipt,
    require_trusted_session_workdir,
    trusted_tool_authority_receipts,
    capture_server_tool_surface as capture_server_tool_surface,
    captured_session_boundary_summary as captured_session_boundary_summary,
    domain_sha256 as domain_sha256,
    final_message_hash_and_match as final_message_hash_and_match,
    privacy_safe_notification_shape as privacy_safe_notification_shape,
    seal_calibration_read_recovery_telemetry as seal_calibration_read_recovery_telemetry,
    session_boundary_summary as session_boundary_summary,
    trusted_tool_evidence_summary as trusted_tool_evidence_summary,
    turn_from_thread as turn_from_thread,
    turn_items as turn_items,
    turn_status as turn_status,
    validate_calibration_read_recovery_telemetry as validate_calibration_read_recovery_telemetry,
    validate_startup_scaffold_records as validate_startup_scaffold_records,
)
from cwo_core.supervision.transport.app_server import (  # noqa: E402
    AMBIGUOUS_TURN_DISCOVERY_POLL_SECONDS as AMBIGUOUS_TURN_DISCOVERY_POLL_SECONDS,
    AMBIGUOUS_TURN_DISCOVERY_TIMEOUT_SECONDS as AMBIGUOUS_TURN_DISCOVERY_TIMEOUT_SECONDS,
    AppServer as AppServer,
    CONTROL_TURN_ID as CONTROL_TURN_ID,
    EXACT_MODEL as EXACT_MODEL,
    THREAD_PHASE_LIVE_CANARY as THREAD_PHASE_LIVE_CANARY,
    THREAD_PHASE_PRECOMMIT_FIT as THREAD_PHASE_PRECOMMIT_FIT,
    THREAD_READ_TIMEOUT_SECONDS as THREAD_READ_TIMEOUT_SECONDS,
    THREAD_START_PHASES as THREAD_START_PHASES,
    canonical_controller_workdir,
    _seal_same_process_proof as _seal_same_process_proof,
    _validated_same_process_proof as _validated_same_process_proof,
    sha256_bytes as sha256_bytes,
    sha256_text as sha256_text,
)
from cwo_core.supervision.transport.errors import (  # noqa: E402
    AmbiguousTurnStartError as AmbiguousTurnStartError,
    AppServerError as AppServerError,
    AppServerRpcError as AppServerRpcError,
)
from cwo_core.supervision.transport.private_io import (  # noqa: E402
    fsync_owned_control_directory,
    fsync_private_control_directory,
    load_owned_regular_bytes,
    open_private_control_lock,
    ensure_private_control_directory,
    load_private_bytes as load_private_bytes,
    load_private_json as load_private_json,
    load_private_json_snapshot as load_private_json_snapshot,
)
from cwo_core.workspace import (  # noqa: E402
    WorkspaceInspectionError as WorkspaceInspectionError,
    capture_tracked_workspace_state as capture_tracked_workspace_state,
    capture_workspace_baseline as capture_workspace_baseline,
    cleanliness_established as cleanliness_established,
    compare_workspace_baseline as compare_workspace_baseline,
    status_path as status_path,
    worktree_state_digest as worktree_state_digest,
)


CONFIG_TOOL_ALLOWLIST_PARAMETER = _CONFIG_TOOL_ALLOWLIST_PARAMETER



def _refuse_retired_campaign() -> NoReturn:
    live_availability.require_campaign_live()
    live_availability.require_pool_live()
    live_availability.require_n1_live()
    raise LegacyNativePoolExecutionRetired()


def build_pool_inputs(
    server: AppServer,
    capability_receipt: Mapping[str, Any],
    campaign_manifest: Mapping[str, Any],
    *,
    root: Path,
    integration: Path,
    pool_name: str,
    worktrees: list[Path],
    mutable: bool,
    prompts: list[str],
    expected_tokens: list[str],
    completion_evidence_policies: list[Mapping[str, Any]] | None = None,
    tool_policies: list[Mapping[str, Any]] | None = None,
    read_only_command_authorities: list[list[Mapping[str, Any]] | None] | None = None,
    pre_thread_start_check: Callable[[], Mapping[str, Any] | None],
    pre_allocation_check: Callable[[], None] | None = None,
    expected_bound_manifest_validation: Mapping[str, Any] | None = None,
    interrupt_after: list[int | None] | None = None,
) -> NoReturn:
    """Refuse retired campaign pool preparation."""
    _refuse_retired_campaign()


def run_pool_canary(
    server: AppServer,
    capability_receipt: Mapping[str, Any],
    campaign_manifest: Mapping[str, Any],
    *,
    root: Path,
    integration: Path,
    pool_name: str,
    worktrees: list[Path],
    mutable: bool,
    prompts: list[str],
    expected_tokens: list[str],
    completion_evidence_policies: list[Mapping[str, Any]] | None = None,
    tool_policies: list[Mapping[str, Any]] | None = None,
    read_only_command_authorities: list[list[Mapping[str, Any]] | None] | None = None,
    pre_thread_start_check: Callable[[], Mapping[str, Any] | None],
    pre_allocation_check: Callable[[], None] | None = None,
    expected_bound_manifest_validation: Mapping[str, Any] | None = None,
    interrupt_after: list[int | None] | None = None,
) -> dict[str, Any]:
    """Refuse the retired v1 pool canary before preparing a worker."""
    _refuse_retired_campaign()


def acquire_global_campaign_claim(
    inputs: Any,
    *,
    launch_claim_sha256: str,
    output: Path,
    authorization_state: Path,
    steering_registry: Path,
    allocation_ledger: Path,
    claim_root: Path | None = None,
    registry_root: Path | None = None,
) -> NoReturn:
    """Refuse retired machine-global campaign claims."""
    _refuse_retired_campaign()


def validate_and_acquire_global_campaign_claim(
    inputs: Any,
    *,
    campaign_nonce: str,
    authorization_id: str,
    authorization_sha256: str,
    repo_head: str,
    guarded_primary: Path,
    output: Path,
    authorization_state: Path,
    steering_registry: Path,
    allocation_ledger: Path,
    pre_mutation_verified_operator_authorities: Iterable[Any] | None = None,
    pre_live_verified_operator_authorities: Iterable[Any] | None = None,
) -> NoReturn:
    """Refuse retired campaign validation and claims."""
    _refuse_retired_campaign()


def _start_campaign_server() -> AppServer:
    """Refuse retired campaign server construction."""
    _refuse_retired_campaign()


def main() -> int:
    """Return a sealed refusal independently of the historical arguments."""
    started_at = utc_now()
    try:
        _refuse_retired_campaign()
    except Exception as exc:
        raw_failure = str(exc)
        failure_class = type(exc).__name__
        safe_failure_code = (
            raw_failure
            if raw_failure
            and len(raw_failure) <= 240
            and all(character.isalnum() or character in "-_:;." for character in raw_failure)
            else failure_class
        )
        failure = seal_artifact(
            {
                "result_type": "cwo-native-supervision-pool-live-canary-failure",
                "version": 1,
                "bead_id": None,
                "work_unit_id": None,
                "control_turn_id": CONTROL_TURN_ID,
                "exact_model": EXACT_MODEL,
                "started_at": iso(started_at),
                "failed_at": iso(),
                "failure_class": failure_class,
                "failure_code": safe_failure_code,
                "failure_message_sha256": sha256_text(raw_failure),
                "validation_outcome": "rejected",
                "release_gate_passed": False,
                "no_resume_or_salvage": True,
                "containment": {
                    "allocated_count": 0,
                    "identified_thread_count": 0,
                    "interrupted_count": 0,
                    "archived_count": 0,
                    "already_contained_count": 0,
                    "unresolved_allocation_intent_count": 0,
                    "unresolved_turn_intent_count": 0,
                    "ambiguous_count": 0,
                    "all_contained": True,
                    "ledger_consistent": True,
                    "ledger_error_sha256": [],
                },
                "authorization_state_sha256": None,
                "steering_consumptions": {},
                "campaign_bindings": {},
                "first_protected_fault": getattr(exc, "first_protected_fault", None),
                "allocation_ledger": None,
                "glm_5_2_used": False,
                "model_synthesis_used": False,
            },
            "evidence_sha256",
        )
        print(
            json.dumps(
                {
                    "release_gate_passed": False,
                    "failure_class": failure_class,
                    "failure_code": safe_failure_code,
                    "failure_message_sha256": failure["failure_message_sha256"],
                    "evidence_sha256": failure["evidence_sha256"],
                    "failure_evidence_persisted": False,
                },
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 1


# Preserve the retired canary module's compatibility exports.
_record_token_snapshot = session_record_token_snapshot
_argument_value = tool_argument_value
_event_items = session_event_items
_output_text = tool_output_text
_paired_namespaced_exec_result = paired_namespaced_exec_result
_measure_action_ms = measure_action_ms
_DIRECT_PENDING_EXEC_RESULT = DIRECT_PENDING_EXEC_RESULT_PATTERN
_READ_ONLY_SHELL_META = READ_ONLY_SHELL_META
_bind_receipt_workdirs = bind_tool_receipt_workdirs
_direct_pending_operation_session_id = direct_pending_operation_session_id
_exec_workdir_binding = exec_workdir_binding
_nonexistent_canonical_nonsymlink_path = is_nonexistent_canonical_nonsymlink_path
_normalize_expected_tool_trace = normalize_expected_tool_trace
_normalize_read_only_command_authority = normalize_read_only_command_authority
_read_only_command_tokens = parse_read_only_command_tokens
_require_positive_read_only_command = require_positive_read_only_command
_strict_json_object_pairs = strict_session_json_object_pairs
_strict_session_json_record = parse_strict_session_json_record
_tool_receipt_projection = project_tool_receipt
_trusted_session_workdir_binding = require_trusted_session_workdir
_trusted_tool_authority_receipts = trusted_tool_authority_receipts
_codex_binary = discover_codex_binary
_IdentityCapabilityRegistry = IdentityCapabilityRegistry
_TurnNegativeResponseObserverBinding = TurnNegativeResponseObserverBinding
_canonical_controller_workdir = canonical_controller_workdir
_fsync_owned_control_directory = fsync_owned_control_directory
_fsync_private_control_directory = fsync_private_control_directory
_load_owned_regular_bytes = load_owned_regular_bytes
_open_private_control_lock = open_private_control_lock
_private_control_directory = ensure_private_control_directory


if __name__ == "__main__":
    raise SystemExit(main())
