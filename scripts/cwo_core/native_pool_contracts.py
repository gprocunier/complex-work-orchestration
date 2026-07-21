"""Strict, stdlib-only contracts for bounded native-supervision pools."""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import tempfile
from typing import Any, Iterable, Mapping

from .native_control import validate_control_turn_receipt
from .native_authority import validate_authority_provenance
from .native_pool_capacity import PoolCapacityLimits, load_pool_capacity
from .native_pool_capacity_compat import (
    LEGACY_CONCURRENT_CAPACITY,
    LEGACY_CERTIFICATION_VERSION,
    LEGACY_RESPONSE_TIME_EQUATION,
    LEGACY_SCHEDULER_MODEL,
    is_legacy_capability_certification,
)
from .native_pool_schedulability import (
    PoolSchedulabilityError,
    scheduling_budget_proof,
    validate_slack_warning_fraction,
)
from .native_tool_isolation import validate_tool_policy
from .native_stop_scope import STOP_METADATA_FIELDS, validate_stop_metadata


VERSION = 1
ADMITTED_POOL_VERSION = 2
POOL_CONTRACT_TYPE = "cwo-native-supervision-pool-contract"
POOL_STATE_TYPE = "cwo-native-supervision-pool-state"
POOL_DECISION_TYPE = "cwo-native-supervision-pool-decision"
POOL_CONTROL_REQUEST_TYPE = "cwo-native-supervision-pool-control-request"
CAPABILITY_RECEIPT_TYPE = "cwo-native-supervision-adapter-capability-receipt"
LEASE_TYPE = "cwo-native-supervision-lease"
POOL_RECEIPT_TYPE = "cwo-native-supervision-pool-receipt"

POOL_CONTRACT_SCHEMA = "schemas/native-supervision-pool-contract.schema.json"
ADMITTED_POOL_CONTRACT_SCHEMA = (
    "schemas/native-supervision-pool-contract-v2.schema.json"
)
POOL_STATE_SCHEMA = "schemas/native-supervision-pool-state.schema.json"
POOL_DECISION_SCHEMA = "schemas/native-supervision-pool-decision.schema.json"
POOL_CONTROL_REQUEST_SCHEMA = (
    "schemas/native-supervision-pool-control-request.schema.json"
)
CAPABILITY_RECEIPT_SCHEMA = (
    "schemas/native-supervision-adapter-capability-receipt.schema.json"
)
LEASE_SCHEMA = "schemas/native-supervision-lease.schema.json"
POOL_RECEIPT_SCHEMA = "schemas/native-supervision-pool-receipt.schema.json"
ADMITTED_POOL_RECEIPT_SCHEMA = (
    "schemas/native-supervision-pool-receipt-v2.schema.json"
)

POOL_STATUSES = (
    "created",
    "capability-validated",
    "admitting",
    "running",
    "draining",
    "interrupt-pending",
    "completed",
    "closed",
    "control-failed",
)
POOL_DECISIONS = ("continue", "warn", "complete", "interrupt", "control-lost")
CHILD_STATUSES = (
    "created",
    "armed",
    "running",
    "interrupt-pending",
    "interrupt-confirmed",
    "completed",
    "closed",
    "control-failed",
)
POOL_ALLOWED_ACTIONS = (
    "admit",
    "step",
    "interrupt",
    "close",
    "finalize",
    "release-leases",
)
REQUIRED_CAPABILITY_CALLBACKS = (
    "arm",
    "send_input",
    "mark_dispatched",
    "check",
    "interrupt",
    "close",
    "finalize",
)
MAX_CAPABILITY_TTL_SECONDS = 3600
CAPABILITY_CERTIFICATION_VERSION = "live-thread-adapter-callback-certification:v2"
CAPABILITY_CERTIFICATION_ENVELOPE = "live-thread-adapter-callback-v1"
CAPABILITY_SCHEDULER_MODEL = "nonpreemptive-edf-generalized-v2"
CAPABILITY_RESPONSE_TIME_EQUATION = "max_lifecycle+N*check+scheduler<=poll_interval"
CAPABILITY_OBSERVATION_AUTHORITY = "telemetry-only-non-authoritative"
CERTIFIED_CALLBACK_MAX_MS = {
    "arm": 100,
    "send_input": 250,
    "mark_dispatched": 100,
    "check": 200,
    "interrupt": 250,
    "close": 250,
    "finalize": 100,
}
CERTIFIED_SCHEDULER_OVERHEAD_MS = 100
CAPABILITY_SLACK_WARNING_FRACTION = 0.8
MAX_CERTIFIED_CHECK_MS = CERTIFIED_CALLBACK_MAX_MS["check"]
POOL_POLL_INTERVAL_MS = 1000
POOL_POLL_LAG_TOLERANCE_MS = 1500
COMPLETION_EVIDENCE_POLICY_FIELDS = {
    "minimum_tool_calls",
    "required_evidence",
    "allow_zero_tool_completion",
    "expected_mutation_mode",
}
REQUIRED_COMPLETION_EVIDENCE_FIELDS = {"predicates", "sha256"}
COMPLETION_EVIDENCE_PREDICATES = frozenset(
    {
        "expected-workspace-mutation",
        "read-only-workspace-clean",
        "trusted-terminal-boundary",
        "trusted-tool-call",
    }
)
COMPLETION_MUTATION_MODES = frozenset({"read-only", "mutable-isolated"})

HASH_FIELDS = {
    POOL_CONTRACT_TYPE: "contract_sha256",
    POOL_STATE_TYPE: "state_sha256",
    POOL_DECISION_TYPE: "decision_sha256",
    POOL_CONTROL_REQUEST_TYPE: "request_sha256",
    CAPABILITY_RECEIPT_TYPE: "receipt_sha256",
    LEASE_TYPE: "lease_sha256",
    POOL_RECEIPT_TYPE: "receipt_sha256",
}

OWNER_FIELDS = {"pid", "start_ticks", "boot_id_sha256"}
IDENTITY_FIELDS = {
    "canonical_path_sha256",
    "git_common_dir_sha256",
    "device",
    "inode",
    "baseline_sha256",
}
TOKEN_FIELDS = {
    "availability",
    "input",
    "cached_input",
    "output",
    "reasoning",
    "total",
    "unavailable_reason",
}
FIRST_PROTECTED_FAULT_FIELDS = {
    "code",
    "operation",
    "observed_callback_latency_ms",
    "certified_callback_max_ms",
    "latched_state_sequence",
}
CERTIFICATION_FIELDS = {
    "version",
    "envelope",
    "scheduler_model",
    "response_time_equation",
    "observation_authority",
    "policy_sha256",
    "adapter_implementation_sha256",
    "certified_callback_max_ms",
    "certified_scheduler_overhead_ms",
    "slack_warning_fraction",
}
LEGACY_CERTIFICATION_FIELDS = CERTIFICATION_FIELDS - {"slack_warning_fraction"}
USAGE_FIELDS = {
    "tool_calls",
    "runtime_seconds",
    "compactions",
    "full_suite_runs",
    "mutations",
    "tokens",
}
CHILD_CONTRACT_FIELDS_V1 = {
    "ordinal",
    "child_id",
    "packet_id",
    "attempt_nonce",
    "session_id",
    "agent_id",
    "control_turn_id",
    "packet_sha256",
    "control_contract_sha256",
    "state_file",
    "worktree_identity",
    "isolation_class",
    "completion_evidence_policy",
    "tool_policy",
    "declared_write_paths",
    "integration_target_paths",
    "lease_id",
}
ADMISSION_TOP_BINDING_FIELDS = {
    "admission_reservation_sha256",
    "readiness_snapshot_sha256",
    "readiness_evidence_sha256",
    "work_estimate_set_sha256",
    "native_worker_policy_sha256",
    "proportionality_policy_sha256",
    "proportionality_assessment_sha256",
    "selected_cohort_sha256",
    "fixed_cohort_sha256",
    "child_bindings_sha256",
    "claim_set_sha256",
}
ADMISSION_CHILD_IDENTITY_FIELDS = {
    "bead_id",
    "work_unit_id",
    "candidate_sha256",
    "claim_sha256",
    "work_estimate_sha256",
    "worker_commitment_sha256",
    "lease_scope_sha256",
    "worktree_identity_sha256",
    "admitted_child_sha256",
}
ADMISSION_CHILD_RENDER_FIELDS = {
    "hard_budget",
    "requested_model",
    "packet_binding_sha256",
    "lease_binding_sha256",
    "path_binding_sha256",
    "budget_binding_sha256",
    "tool_binding_sha256",
    "model_binding_sha256",
    "session_binding_sha256",
}
CHILD_CONTRACT_FIELDS_V2 = (
    CHILD_CONTRACT_FIELDS_V1
    | ADMISSION_CHILD_IDENTITY_FIELDS
    | ADMISSION_CHILD_RENDER_FIELDS
)
POOL_CONTRACT_FIELDS_V1 = {
    "contract_type",
    "version",
    "schema",
    "pool_id",
    "pool_epoch",
    "control_turn_id",
    "created_at",
    "owner",
    "children",
    "max_active_workers",
    "scheduler",
    "aggregate_hard_budget",
    "topology",
    "allowed_actions",
    "capability_receipt_sha256",
    "contract_sha256",
}
POOL_CONTRACT_FIELDS_V2 = POOL_CONTRACT_FIELDS_V1 | ADMISSION_TOP_BINDING_FIELDS

# Compatibility aliases retain the v1 public constants used by historical
# readers and tests. Productive admission selects the explicit v2 sets.
CHILD_CONTRACT_FIELDS = CHILD_CONTRACT_FIELDS_V1
POOL_CONTRACT_FIELDS = POOL_CONTRACT_FIELDS_V1


def admission_child_render_hashes(child: Mapping[str, Any]) -> dict[str, str]:
    """Bind every v2 admission identity rendered into one pool child."""

    bead_id = child.get("bead_id")
    return {
        "packet_binding_sha256": canonical_sha256(
            {
                "bead_id": bead_id,
                "child_id": child.get("child_id"),
                "packet_id": child.get("packet_id"),
                "packet_sha256": child.get("packet_sha256"),
                "candidate_sha256": child.get("candidate_sha256"),
                "work_estimate_sha256": child.get("work_estimate_sha256"),
                "worker_commitment_sha256": child.get("worker_commitment_sha256"),
                "admitted_child_sha256": child.get("admitted_child_sha256"),
            }
        ),
        "lease_binding_sha256": canonical_sha256(
            {
                "bead_id": bead_id,
                "lease_id": child.get("lease_id"),
                "lease_scope_sha256": child.get("lease_scope_sha256"),
                "worktree_identity_sha256": child.get("worktree_identity_sha256"),
            }
        ),
        "path_binding_sha256": canonical_sha256(
            {
                "bead_id": bead_id,
                "isolation_class": child.get("isolation_class"),
                "declared_write_paths": child.get("declared_write_paths"),
                "integration_target_paths": child.get("integration_target_paths"),
            }
        ),
        # The render boundary binds all five operative pool-budget dimensions.
        # The earlier work-estimate receipt intentionally carries only the
        # dimensions available during candidate selection.
        "budget_binding_sha256": canonical_sha256(
            {"bead_id": bead_id, "hard_budget": child.get("hard_budget")}
        ),
        "tool_binding_sha256": canonical_sha256(
            {"bead_id": bead_id, "tool_policy": child.get("tool_policy")}
        ),
        "model_binding_sha256": canonical_sha256(
            {"bead_id": bead_id, "requested_model": child.get("requested_model")}
        ),
        "session_binding_sha256": canonical_sha256(
            {
                "bead_id": bead_id,
                "attempt_nonce": child.get("attempt_nonce"),
                "session_id": child.get("session_id"),
                "agent_id": child.get("agent_id"),
                "control_turn_id": child.get("control_turn_id"),
            }
        ),
    }


CHILD_STATE_FIELDS = {
    "ordinal",
    "child_id",
    "status",
    "last_deadline_ns",
    "next_deadline_ns",
    "child_state_sha256",
    "child_receipt_sha256",
    "last_cumulative_usage",
    "lease_id",
}
POOL_STATE_FIELDS = {
    "state_type",
    "version",
    "schema",
    "pool_id",
    "pool_epoch",
    "contract_sha256",
    "state_sequence",
    "status",
    "owner",
    "coordinator_epoch",
    "scheduler_cursor",
    "active_children",
    "terminal_children",
    "children",
    "aggregate_usage",
    "pool_started_monotonic_ns",
    "pool_wall_seconds",
    "worker_seconds",
    "poll_overhead_seconds",
    "lease_bindings",
    "reasons",
    "reason_records",
    "first_protected_fault",
    "control_loss_scope",
    *STOP_METADATA_FIELDS,
    "state_sha256",
}
POOL_DECISION_FIELDS = {
    "decision_type",
    "version",
    "schema",
    "pool_id",
    "pool_epoch",
    "contract_sha256",
    "state_sha256",
    "decision_sequence",
    "decision",
    "selected_child_id",
    "deadlines",
    "observed_callback_latency_ms",
    "aggregate_usage",
    "reasons",
    "reason_records",
    "required_control_actions",
    *STOP_METADATA_FIELDS,
    "decision_sha256",
}
POOL_CONTROL_REQUEST_FIELDS = {
    "request_type",
    "version",
    "schema",
    "request_id",
    "pool_id",
    "pool_epoch",
    "contract_sha256",
    "observed_state_sequence",
    "observed_state_sha256",
    "action",
    "reason",
    "created_at",
    "request_sha256",
}
CAPABILITY_FIELDS = {
    "receipt_type",
    "version",
    "schema",
    "adapter_id",
    "adapter_version",
    "execution_surface",
    "host_identity",
    "control_turn_id",
    "measured_at",
    "expires_at",
    "sample_count",
    "requested_cap",
    "clock",
    "callbacks",
    "scheduler_overhead",
    "certification",
    "capabilities",
    "attestation_source",
    "validation_outcome",
    "receipt_sha256",
}
LEASE_FIELDS = {
    "lease_type",
    "version",
    "schema",
    "lease_id",
    "pool_id",
    "child_id",
    "pool_epoch",
    "integration_root_identity",
    "worktree_identity",
    "target_paths",
    "owner",
    "lifecycle_state",
    "acquired_at",
    "updated_at",
    "terminal_evidence_sha256",
    "release_reason",
    "lease_sha256",
}
POOL_RECEIPT_FIELDS_V1 = {
    "receipt_type",
    "version",
    "schema",
    "pool_id",
    "pool_epoch",
    "contract_sha256",
    "terminal_state_sha256",
    "capability_receipt_sha256",
    "admission_order",
    "poll_order",
    "terminal_order",
    "timing",
    "child_terminal_receipts",
    "final_aggregate_usage",
    "pool_wall_seconds",
    "worker_seconds",
    "lease_evidence",
    "mutation_evidence",
    "reasons",
    "reason_records",
    "first_protected_fault",
    "child_dispositions",
    "pool_disposition",
    "accepting",
    *STOP_METADATA_FIELDS,
    "receipt_sha256",
}
POOL_RECEIPT_FIELDS_V2 = POOL_RECEIPT_FIELDS_V1 | {
    "reservation_sha256",
    "dispatch_sha256",
}
POOL_RECEIPT_FIELDS = POOL_RECEIPT_FIELDS_V1
POOL_CHILD_RECEIPT_FIELDS_V1 = {"child_id", "receipt_sha256"}
POOL_CHILD_RECEIPT_FIELDS_V2 = POOL_CHILD_RECEIPT_FIELDS_V1 | {
    "bead_id",
    "work_unit_id",
    "packet_sha256",
    "admitted_child_sha256",
    "control_receipt",
}
POOL_CHILD_DISPOSITION_FIELDS_V1 = {
    "child_id",
    "session_disposition",
    "artifact_disposition",
}
POOL_CHILD_DISPOSITION_FIELDS_V2 = POOL_CHILD_DISPOSITION_FIELDS_V1 | {
    "bead_id",
    "work_unit_id",
    "packet_sha256",
    "admitted_child_sha256",
    "implementation_bead_close_authorized",
    "parent_close_authorized",
    "publication_close_authorized",
}
POOL_RECEIPT_LEGACY_TIMING_FIELDS = {
    "max_callback_latency_ms",
    "max_poll_gap_ms",
    "poll_interval_ms",
    "poll_lag_tolerance_ms",
}
POOL_RECEIPT_EXCLUSIVE_TIMING_FIELDS = POOL_RECEIPT_LEGACY_TIMING_FIELDS | {
    "accounting_version",
    "callback_ns",
    "noncallback_invoke_ns",
    "coordinator_ns",
    "wait_ns",
}


def canonical_sha256(value: Any) -> str:
    payload = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def artifact_sha256(value: Mapping[str, Any], hash_field: str) -> str:
    return canonical_sha256(
        {key: item for key, item in value.items() if key != hash_field}
    )


def seal_artifact(value: Mapping[str, Any], hash_field: str) -> dict[str, Any]:
    sealed = dict(value)
    sealed.pop(hash_field, None)
    sealed[hash_field] = canonical_sha256(sealed)
    return sealed


def write_private_artifact(path: Path, value: Mapping[str, Any]) -> None:
    """Atomically persist canonical JSON with CWO-owned mode 0600."""
    target = Path(path)
    if target.exists() and target.is_symlink():
        raise ValueError("artifact-path-is-symlink")
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    target.parent.chmod(0o700)
    temporary_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            dir=target.parent,
            prefix=f".{target.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temporary_name = handle.name
            os.fchmod(handle.fileno(), 0o600)
            handle.write(json.dumps(value, indent=2, sort_keys=True) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, target)
        temporary_name = None
        target.chmod(0o600)
    finally:
        if temporary_name:
            try:
                Path(temporary_name).unlink()
            except FileNotFoundError:
                pass


def _strict(
    value: Any, fields: set[str], prefix: str, errors: list[str]
) -> Mapping[str, Any] | None:
    if not isinstance(value, Mapping):
        errors.append(f"{prefix}-must-be-object")
        return None
    keys = set(value)
    missing = sorted(fields - keys)
    unknown = sorted(keys - fields)
    if missing:
        errors.append(f"{prefix}-missing-fields:" + ",".join(missing))
    if unknown:
        errors.append(f"{prefix}-unknown-fields:" + ",".join(unknown))
    return value


def _nonempty(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _is_int(value: Any, minimum: int = 0) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= minimum


def _is_number(value: Any, minimum: float = 0.0) -> bool:
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(float(value))
        and value >= minimum
    )


def _is_sha256(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def default_completion_evidence_policy(
    isolation_class: str,
    *,
    minimum_tool_calls: int = 1,
) -> dict[str, Any]:
    """Return the fail-closed observable-work policy for a pool child."""

    if isolation_class == "read-only-shared":
        expected_mutation_mode = "read-only"
        predicates = [
            "read-only-workspace-clean",
            "trusted-terminal-boundary",
            "trusted-tool-call",
        ]
    elif isolation_class == "mutable-isolated":
        expected_mutation_mode = "mutable-isolated"
        predicates = [
            "expected-workspace-mutation",
            "trusted-terminal-boundary",
            "trusted-tool-call",
        ]
    else:
        raise ValueError("completion-evidence-isolation-class-invalid")
    if not _is_int(minimum_tool_calls, 1):
        raise ValueError("completion-evidence-minimum-tool-calls-invalid")
    return {
        "minimum_tool_calls": minimum_tool_calls,
        "required_evidence": {"predicates": predicates, "sha256": []},
        "allow_zero_tool_completion": False,
        "expected_mutation_mode": expected_mutation_mode,
    }


def validate_completion_evidence_policy(
    value: Any,
    *,
    isolation_class: str | None = None,
    prefix: str = "completion-evidence-policy",
) -> list[str]:
    """Validate one worker's trusted completion-evidence requirements."""

    errors: list[str] = []
    policy = _strict(value, COMPLETION_EVIDENCE_POLICY_FIELDS, prefix, errors)
    if policy is None:
        return errors
    minimum = policy.get("minimum_tool_calls")
    if not _is_int(minimum):
        errors.append(f"{prefix}-minimum-tool-calls-invalid")
    allow_zero = policy.get("allow_zero_tool_completion")
    if not isinstance(allow_zero, bool):
        errors.append(f"{prefix}-allow-zero-tool-completion-invalid")
    mutation_mode = policy.get("expected_mutation_mode")
    if mutation_mode not in COMPLETION_MUTATION_MODES:
        errors.append(f"{prefix}-expected-mutation-mode-invalid")
    expected_mode = {
        "read-only-shared": "read-only",
        "mutable-isolated": "mutable-isolated",
    }.get(isolation_class)
    if expected_mode is not None and mutation_mode != expected_mode:
        errors.append(f"{prefix}-isolation-mutation-mode-mismatch")

    required = _strict(
        policy.get("required_evidence"),
        REQUIRED_COMPLETION_EVIDENCE_FIELDS,
        f"{prefix}-required-evidence",
        errors,
    )
    predicates: list[Any] = []
    hashes: list[Any] = []
    if required is not None:
        raw_predicates = required.get("predicates")
        raw_hashes = required.get("sha256")
        if not isinstance(raw_predicates, list):
            errors.append(f"{prefix}-required-evidence-predicates-invalid")
        else:
            predicates = raw_predicates
            if len(predicates) != len(set(str(item) for item in predicates)):
                errors.append(f"{prefix}-required-evidence-predicates-duplicate")
            unknown = sorted(
                str(item)
                for item in predicates
                if not isinstance(item, str)
                or item not in COMPLETION_EVIDENCE_PREDICATES
            )
            if unknown:
                errors.append(
                    f"{prefix}-required-evidence-predicates-unknown:"
                    + ",".join(unknown)
                )
        if not isinstance(raw_hashes, list):
            errors.append(f"{prefix}-required-evidence-sha256-invalid")
        else:
            hashes = raw_hashes
            if any(not _is_sha256(item) for item in hashes):
                errors.append(f"{prefix}-required-evidence-sha256-invalid")
            if len(hashes) != len(set(str(item) for item in hashes)):
                errors.append(f"{prefix}-required-evidence-sha256-duplicate")

    predicate_set = {item for item in predicates if isinstance(item, str)}
    if "trusted-terminal-boundary" not in predicate_set:
        errors.append(f"{prefix}-trusted-terminal-boundary-required")
    if (
        mutation_mode == "read-only"
        and "read-only-workspace-clean" not in predicate_set
    ):
        errors.append(f"{prefix}-read-only-clean-evidence-required")
    if mutation_mode == "read-only" and "expected-workspace-mutation" in predicate_set:
        errors.append(f"{prefix}-read-only-mutation-evidence-forbidden")
    if (
        mutation_mode == "mutable-isolated"
        and "expected-workspace-mutation" not in predicate_set
    ):
        errors.append(f"{prefix}-mutable-mutation-evidence-required")
    if minimum and "trusted-tool-call" not in predicate_set:
        errors.append(f"{prefix}-minimum-tool-calls-require-tool-predicate")

    if allow_zero is True:
        if minimum != 0:
            errors.append(f"{prefix}-zero-tool-policy-requires-zero-minimum")
        if mutation_mode != "read-only":
            errors.append(f"{prefix}-zero-tool-policy-must-be-read-only")
        if predicate_set - {
            "read-only-workspace-clean",
            "trusted-terminal-boundary",
        }:
            errors.append(f"{prefix}-zero-tool-policy-observable-action-conflict")
    elif (
        minimum == 0
        and "expected-workspace-mutation" not in predicate_set
        and not hashes
    ):
        errors.append(f"{prefix}-observable-work-requirement-missing")
    return errors


def _datetime(value: Any) -> dt.datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else None


def _validate_header(
    value: Mapping[str, Any],
    *,
    type_field: str,
    expected_type: str,
    expected_schema: str,
    errors: list[str],
    expected_version: int = VERSION,
) -> None:
    if value.get(type_field) != expected_type:
        errors.append("invalid-artifact-type")
    version = value.get("version")
    if not _is_int(version) or version != expected_version:
        errors.append("invalid-version")
    if value.get("schema") != expected_schema:
        errors.append("invalid-schema")


def _validate_hash(
    value: Mapping[str, Any], hash_field: str, errors: list[str]
) -> None:
    actual = value.get(hash_field)
    if not _is_sha256(actual):
        errors.append(f"invalid-{hash_field.replace('_', '-')}")
    elif actual != artifact_sha256(value, hash_field):
        errors.append(f"{hash_field.replace('_', '-')}-mismatch")


def _validate_reason_records(
    value: Any,
    reasons: Any,
    authority_provenance: Any,
    errors: list[str],
) -> None:
    if not isinstance(reasons, list) or not all(
        isinstance(reason, str) and reason for reason in reasons
    ):
        return
    if not isinstance(value, list) or len(value) != len(reasons):
        errors.append("reason-records-lineage-mismatch")
        return
    if validate_authority_provenance(authority_provenance):
        errors.append("reason-records-authority-invalid")
        return
    for index, (record, reason) in enumerate(zip(value, reasons)):
        if not isinstance(record, Mapping) or set(record) != {
            "reason",
            "authority_provenance",
            "detected_by",
        }:
            errors.append(f"reason-record[{index}]-fields-invalid")
            continue
        if record.get("reason") != reason:
            errors.append(f"reason-record[{index}]-reason-mismatch")
        if record.get("authority_provenance") != authority_provenance:
            errors.append(f"reason-record[{index}]-authority-mismatch")
        if not isinstance(record.get("detected_by"), str) or not record["detected_by"]:
            errors.append(f"reason-record[{index}]-detector-invalid")


def _validate_replay(
    value: Mapping[str, Any],
    hash_field: str,
    seen_hashes: Iterable[str] | None,
    errors: list[str],
) -> None:
    if seen_hashes is not None and value.get(hash_field) in set(seen_hashes):
        errors.append("replay-detected")


def _validate_owner(value: Any, prefix: str, errors: list[str]) -> None:
    owner = _strict(value, OWNER_FIELDS, prefix, errors)
    if owner is None:
        return
    if not _is_int(owner.get("pid"), 1):
        errors.append(f"invalid-{prefix}-pid")
    if not _is_int(owner.get("start_ticks"), 1):
        errors.append(f"invalid-{prefix}-start-ticks")
    if not _is_sha256(owner.get("boot_id_sha256")):
        errors.append(f"invalid-{prefix}-boot-id-sha256")


def _validate_identity(value: Any, prefix: str, errors: list[str]) -> None:
    identity = _strict(value, IDENTITY_FIELDS, prefix, errors)
    if identity is None:
        return
    for field in ("canonical_path_sha256", "git_common_dir_sha256", "baseline_sha256"):
        if not _is_sha256(identity.get(field)):
            errors.append(f"invalid-{prefix}-{field.replace('_', '-')}")
    for field in ("device", "inode"):
        if not _is_int(identity.get(field)):
            errors.append(f"invalid-{prefix}-{field}")


def _validate_token_usage(value: Any, prefix: str, errors: list[str]) -> None:
    tokens = _strict(value, TOKEN_FIELDS, prefix, errors)
    if tokens is None:
        return
    availability = tokens.get("availability")
    counters = ("input", "cached_input", "output", "reasoning", "total")
    if availability == "available":
        if any(not _is_int(tokens.get(field)) for field in counters):
            errors.append(f"invalid-{prefix}-available-counters")
        if tokens.get("unavailable_reason") is not None:
            errors.append(f"invalid-{prefix}-available-reason")
        if all(_is_int(tokens.get(field)) for field in counters):
            if (
                tokens["total"]
                != tokens["input"]
                + tokens["cached_input"]
                + tokens["output"]
                + tokens["reasoning"]
            ):
                errors.append(f"invalid-{prefix}-total")
    elif availability == "unavailable":
        if any(tokens.get(field) is not None for field in counters):
            errors.append(f"invalid-{prefix}-unavailable-counters")
        if not _nonempty(tokens.get("unavailable_reason")):
            errors.append(f"invalid-{prefix}-unavailable-reason")
    else:
        errors.append(f"invalid-{prefix}-availability")


def _validate_usage(value: Any, prefix: str, errors: list[str]) -> None:
    usage = _strict(value, USAGE_FIELDS, prefix, errors)
    if usage is None:
        return
    for field in (
        "tool_calls",
        "runtime_seconds",
        "compactions",
        "full_suite_runs",
        "mutations",
    ):
        if not _is_int(usage.get(field)):
            errors.append(f"invalid-{prefix}-{field.replace('_', '-')}")
    _validate_token_usage(usage.get("tokens"), f"{prefix}-tokens", errors)


def zero_token_usage(
    reason: str = "trusted-token-telemetry-unavailable",
) -> dict[str, Any]:
    return {
        "availability": "unavailable",
        "input": None,
        "cached_input": None,
        "output": None,
        "reasoning": None,
        "total": None,
        "unavailable_reason": reason,
    }


def zero_usage() -> dict[str, Any]:
    return {
        "tool_calls": 0,
        "runtime_seconds": 0,
        "compactions": 0,
        "full_suite_runs": 0,
        "mutations": 0,
        "tokens": zero_token_usage(),
    }


def _validate_relative_paths(
    value: Any, prefix: str, *, allow_empty: bool, errors: list[str]
) -> list[str]:
    if not isinstance(value, list):
        errors.append(f"{prefix}-must-be-array")
        return []
    if not allow_empty and not value:
        errors.append(f"{prefix}-must-not-be-empty")
    paths: list[str] = []
    for index, item in enumerate(value):
        if not _nonempty(item):
            errors.append(f"invalid-{prefix}[{index}]")
            continue
        path = PurePosixPath(item)
        if (
            path.is_absolute()
            or item in {".", ".."}
            or any(part in {"", ".", ".."} for part in path.parts)
        ):
            errors.append(f"unsafe-{prefix}[{index}]")
            continue
        normalized = path.as_posix()
        if normalized != item:
            errors.append(f"noncanonical-{prefix}[{index}]")
            continue
        paths.append(normalized)
    if len(paths) != len(set(paths)):
        errors.append(f"duplicate-{prefix}")
    for index, left in enumerate(paths):
        left_parts = PurePosixPath(left).parts
        for right in paths[index + 1 :]:
            right_parts = PurePosixPath(right).parts
            if (
                left_parts == right_parts[: len(left_parts)]
                or right_parts == left_parts[: len(right_parts)]
            ):
                errors.append(f"overlapping-{prefix}:{left}:{right}")
    return paths


def _validate_stats(
    value: Any, prefix: str, errors: list[str]
) -> Mapping[str, Any] | None:
    stats = _strict(value, {"p50_ms", "p90_ms", "p99_ms", "max_ms"}, prefix, errors)
    if stats is None:
        return None
    values = [stats.get(field) for field in ("p50_ms", "p90_ms", "p99_ms", "max_ms")]
    if any(not _is_number(item) for item in values):
        errors.append(f"invalid-{prefix}-values")
    elif values != sorted(values):
        errors.append(f"nonmonotonic-{prefix}-values")
    return stats


def callback_certification_policy_sha256(value: Mapping[str, Any]) -> str:
    """Hash the exact callback-certification policy without file-path authority."""

    return canonical_sha256(dict(value))


def _validate_certification(
    value: Any,
    errors: list[str],
    *,
    allow_legacy: bool = False,
) -> Mapping[str, Any] | None:
    legacy = allow_legacy and is_legacy_capability_certification(value)
    certification = _strict(
        value,
        LEGACY_CERTIFICATION_FIELDS if legacy else CERTIFICATION_FIELDS,
        "certification",
        errors,
    )
    if certification is None:
        return None
    expected_scalars = {
        "version": (
            LEGACY_CERTIFICATION_VERSION if legacy else CAPABILITY_CERTIFICATION_VERSION
        ),
        "envelope": CAPABILITY_CERTIFICATION_ENVELOPE,
        "scheduler_model": (
            LEGACY_SCHEDULER_MODEL if legacy else CAPABILITY_SCHEDULER_MODEL
        ),
        "response_time_equation": (
            LEGACY_RESPONSE_TIME_EQUATION
            if legacy
            else CAPABILITY_RESPONSE_TIME_EQUATION
        ),
        "observation_authority": CAPABILITY_OBSERVATION_AUTHORITY,
        "certified_scheduler_overhead_ms": CERTIFIED_SCHEDULER_OVERHEAD_MS,
    }
    for field, expected in expected_scalars.items():
        if certification.get(field) != expected:
            errors.append(f"certification-{field.replace('_', '-')}-mismatch")
    if not legacy:
        try:
            warning_fraction = validate_slack_warning_fraction(
                certification.get("slack_warning_fraction")
            )
        except PoolSchedulabilityError:
            errors.append("certification-slack-warning-fraction-invalid")
        else:
            if warning_fraction != CAPABILITY_SLACK_WARNING_FRACTION:
                errors.append("certification-slack-warning-fraction-mismatch")
    for field in ("policy_sha256", "adapter_implementation_sha256"):
        if not _is_sha256(certification.get(field)):
            errors.append(f"certification-{field.replace('_', '-')}-invalid")
    ceilings = certification.get("certified_callback_max_ms")
    if not isinstance(ceilings, Mapping):
        errors.append("certification-callback-ceilings-must-be-object")
    else:
        missing = sorted(set(REQUIRED_CAPABILITY_CALLBACKS) - set(ceilings))
        unknown = sorted(set(ceilings) - set(REQUIRED_CAPABILITY_CALLBACKS))
        if missing:
            errors.append(
                "certification-callback-ceilings-missing:" + ",".join(missing)
            )
        if unknown:
            errors.append(
                "certification-callback-ceilings-unknown:" + ",".join(unknown)
            )
        for name, expected in CERTIFIED_CALLBACK_MAX_MS.items():
            if ceilings.get(name) != expected:
                errors.append(f"certification-callback-ceiling-mismatch:{name}")
    return certification


def _validate_first_protected_fault(
    value: Any,
    *,
    state_sequence: Any,
    prefix: str,
    errors: list[str],
) -> Mapping[str, Any] | None:
    if value is None:
        return None
    fault = _strict(value, FIRST_PROTECTED_FAULT_FIELDS, prefix, errors)
    if fault is None:
        return None
    if not _nonempty(fault.get("code")):
        errors.append(f"invalid-{prefix}-code")
    operation = fault.get("operation")
    if operation is not None and operation not in REQUIRED_CAPABILITY_CALLBACKS:
        errors.append(f"invalid-{prefix}-operation")
    observed = fault.get("observed_callback_latency_ms")
    certified = fault.get("certified_callback_max_ms")
    if observed is not None and not _is_number(observed):
        errors.append(f"invalid-{prefix}-observed-callback-latency-ms")
    if certified is not None and not _is_number(certified):
        errors.append(f"invalid-{prefix}-certified-callback-max-ms")
    if (observed is None) != (certified is None):
        errors.append(f"invalid-{prefix}-callback-pair")
    if operation is None and (observed is not None or certified is not None):
        errors.append(f"invalid-{prefix}-callback-operation")
    latched = fault.get("latched_state_sequence")
    if not _is_int(latched):
        errors.append(f"invalid-{prefix}-latched-state-sequence")
    elif _is_int(state_sequence) and latched > state_sequence:
        errors.append(f"invalid-{prefix}-future-state-sequence")
    return fault


def _identity_key(value: Any) -> str:
    if not isinstance(value, Mapping):
        return ""
    return canonical_sha256(
        {
            field: value.get(field)
            for field in (
                "canonical_path_sha256",
                "git_common_dir_sha256",
                "device",
                "inode",
            )
        }
    )


def _admission_binding_projection(child: Mapping[str, Any]) -> dict[str, Any]:
    hard_budget = child.get("hard_budget")
    admission_budget = (
        {
            "tool_calls": hard_budget.get("tool_calls"),
            "runtime_seconds": hard_budget.get("runtime_seconds"),
            "compactions": hard_budget.get("compactions"),
        }
        if isinstance(hard_budget, Mapping)
        else None
    )
    return {
        "bead_id": child.get("bead_id"),
        "work_unit_id": child.get("work_unit_id"),
        "child_id": child.get("child_id"),
        "packet_id": child.get("packet_id"),
        "packet_sha256": child.get("packet_sha256"),
        "candidate_sha256": child.get("candidate_sha256"),
        "work_estimate_sha256": child.get("work_estimate_sha256"),
        "worker_commitment_sha256": child.get("worker_commitment_sha256"),
        "lease_scope_sha256": child.get("lease_scope_sha256"),
        "worktree_identity_sha256": child.get("worktree_identity_sha256"),
        "hard_budget": admission_budget,
        "requested_model": child.get("requested_model"),
        "admitted_child_sha256": child.get("admitted_child_sha256"),
    }


def _validate_v2_admission_binding(
    contract: Mapping[str, Any],
    children: list[Mapping[str, Any]],
    admission_reservation: Mapping[str, Any] | None,
    errors: list[str],
) -> None:
    for field in ADMISSION_TOP_BINDING_FIELDS:
        if not _is_sha256(contract.get(field)):
            errors.append(f"invalid-{field.replace('_', '-')}")

    observed_bindings = [_admission_binding_projection(child) for child in children]
    if contract.get("child_bindings_sha256") != canonical_sha256(observed_bindings):
        errors.append("admission-child-bindings-sha256-mismatch")

    if admission_reservation is None:
        return
    from .native_pool_admission import validate_reservation_receipt

    reservation_errors = validate_reservation_receipt(admission_reservation)
    if reservation_errors:
        errors.extend(f"admission-reservation:{item}" for item in reservation_errors)
        return
    if admission_reservation.get("status") != "admitted" or admission_reservation.get(
        "candidate_mode"
    ) not in {"single", "released-capacity"}:
        errors.append("admission-reservation-not-productively-admitted")
    expected_top = {
        "admission_reservation_sha256": admission_reservation.get("reservation_sha256"),
        "readiness_snapshot_sha256": admission_reservation.get(
            "readiness_snapshot_sha256"
        ),
        "readiness_evidence_sha256": admission_reservation.get(
            "readiness_evidence_sha256"
        ),
        "work_estimate_set_sha256": admission_reservation.get(
            "work_estimate_set_sha256"
        ),
        "native_worker_policy_sha256": admission_reservation.get(
            "native_worker_policy_sha256"
        ),
        "proportionality_policy_sha256": admission_reservation.get(
            "proportionality_policy_sha256"
        ),
        "proportionality_assessment_sha256": admission_reservation.get(
            "proportionality_assessment_sha256"
        ),
        "selected_cohort_sha256": admission_reservation.get("selected_cohort_sha256"),
        "fixed_cohort_sha256": admission_reservation.get("fixed_cohort_sha256"),
        "child_bindings_sha256": admission_reservation.get("child_bindings_sha256"),
        "claim_set_sha256": admission_reservation.get("claim_set_sha256"),
    }
    for field, expected in expected_top.items():
        if contract.get(field) != expected:
            errors.append(f"admission-{field.replace('_', '-')}-mismatch")

    reservation_bindings = admission_reservation.get("child_bindings")
    claims = admission_reservation.get("claims")
    if not isinstance(reservation_bindings, list) or not isinstance(claims, list):
        return
    bindings_by_bead = {
        item.get("bead_id"): item
        for item in reservation_bindings
        if isinstance(item, Mapping)
    }
    claims_by_bead = {
        item.get("bead_id"): item
        for item in claims
        if isinstance(item, Mapping) and item.get("owned") is True
    }
    if [child.get("bead_id") for child in children] != admission_reservation.get(
        "issue_ids"
    ):
        errors.append("admission-child-order-mismatch")
    for index, child in enumerate(children):
        bead_id = child.get("bead_id")
        if _admission_binding_projection(child) != bindings_by_bead.get(bead_id):
            errors.append(f"admission-child[{index}]-binding-mismatch")
        claim = claims_by_bead.get(bead_id)
        if not isinstance(claim, Mapping) or child.get("claim_sha256") != claim.get(
            "claim_sha256"
        ):
            errors.append(f"admission-child[{index}]-claim-mismatch")


def validate_pool_contract(
    value: Any,
    *,
    seen_hashes: Iterable[str] | None = None,
    capacity_limits: PoolCapacityLimits | None = None,
    admission_reservation: Mapping[str, Any] | None = None,
) -> list[str]:
    errors: list[str] = []
    limits = capacity_limits or load_pool_capacity()
    admitted_v2 = (
        isinstance(value, Mapping) and value.get("version") == ADMITTED_POOL_VERSION
    )
    contract_fields = (
        POOL_CONTRACT_FIELDS_V2 if admitted_v2 else POOL_CONTRACT_FIELDS_V1
    )
    child_fields = CHILD_CONTRACT_FIELDS_V2 if admitted_v2 else CHILD_CONTRACT_FIELDS_V1
    contract = _strict(value, contract_fields, "pool-contract", errors)
    if contract is None:
        return errors
    _validate_header(
        contract,
        type_field="contract_type",
        expected_type=POOL_CONTRACT_TYPE,
        expected_schema=(
            ADMITTED_POOL_CONTRACT_SCHEMA if admitted_v2 else POOL_CONTRACT_SCHEMA
        ),
        errors=errors,
        expected_version=ADMITTED_POOL_VERSION if admitted_v2 else VERSION,
    )
    for field in ("pool_id", "pool_epoch", "control_turn_id"):
        if not _nonempty(contract.get(field)):
            errors.append(f"invalid-{field.replace('_', '-')}")
    if _datetime(contract.get("created_at")) is None:
        errors.append("invalid-created-at")
    _validate_owner(contract.get("owner"), "owner", errors)

    children = contract.get("children")
    normalized_children: list[Mapping[str, Any]] = []
    if not isinstance(children, list) or not 1 <= len(children) <= (
        limits.released_max_active_workers
        if admitted_v2
        else limits.hard_max_active_workers
    ):
        errors.append("invalid-children")
    else:
        for index, item in enumerate(children):
            child = _strict(item, child_fields, f"child[{index}]", errors)
            if child is None:
                continue
            normalized_children.append(child)
            if child.get("ordinal") != index:
                errors.append(f"invalid-child[{index}]-ordinal")
            for field in (
                "child_id",
                "packet_id",
                "attempt_nonce",
                "session_id",
                "agent_id",
                "control_turn_id",
                "lease_id",
            ):
                if not _nonempty(child.get(field)):
                    errors.append(f"invalid-child[{index}]-{field.replace('_', '-')}")
            for field in ("packet_sha256", "control_contract_sha256"):
                if not _is_sha256(child.get(field)):
                    errors.append(f"invalid-child[{index}]-{field.replace('_', '-')}")
            if admitted_v2:
                for field in ADMISSION_CHILD_IDENTITY_FIELDS:
                    if field in {"bead_id", "work_unit_id"}:
                        if not _nonempty(child.get(field)):
                            errors.append(
                                f"invalid-child[{index}]-{field.replace('_', '-')}"
                            )
                    elif not _is_sha256(child.get(field)):
                        errors.append(
                            f"invalid-child[{index}]-{field.replace('_', '-')}"
                        )
                if not _nonempty(child.get("requested_model")):
                    errors.append(f"invalid-child[{index}]-requested-model")
                child_budget = _strict(
                    child.get("hard_budget"),
                    {
                        "tool_calls",
                        "runtime_seconds",
                        "compactions",
                        "full_suite_runs",
                        "mutations",
                    },
                    f"child[{index}]-hard-budget",
                    errors,
                )
                if child_budget is not None:
                    for field in ("tool_calls", "runtime_seconds"):
                        if not _is_int(child_budget.get(field), 1):
                            errors.append(
                                f"invalid-child[{index}]-hard-budget-{field.replace('_', '-')}"
                            )
                    for field in ("compactions", "full_suite_runs", "mutations"):
                        if not _is_int(child_budget.get(field)):
                            errors.append(
                                f"invalid-child[{index}]-hard-budget-{field.replace('_', '-')}"
                            )
                for field, expected in admission_child_render_hashes(child).items():
                    if child.get(field) != expected:
                        errors.append(
                            f"child[{index}]-{field.replace('_', '-')}-mismatch"
                        )
            state_file = child.get("state_file")
            if not _nonempty(state_file) or not Path(str(state_file)).is_absolute():
                errors.append(f"invalid-child[{index}]-state-file")
            _validate_identity(
                child.get("worktree_identity"), f"child[{index}]-worktree", errors
            )
            isolation = child.get("isolation_class")
            if isolation not in {"read-only-shared", "mutable-isolated"}:
                errors.append(f"invalid-child[{index}]-isolation-class")
            errors.extend(
                validate_completion_evidence_policy(
                    child.get("completion_evidence_policy"),
                    isolation_class=str(isolation),
                    prefix=f"child[{index}]-completion-evidence-policy",
                )
            )
            errors.extend(
                validate_tool_policy(
                    child.get("tool_policy"),
                    prefix=f"child[{index}]-tool-policy",
                )
            )
            child_tool_policy = child.get("tool_policy")
            if (
                isolation == "read-only-shared"
                and isinstance(child_tool_policy, Mapping)
                and "apply_patch" in child_tool_policy.get("permitted_tools", [])
            ):
                errors.append(
                    f"read-only-child[{index}]-tool-policy-permits-apply-patch"
                )
            write_paths = _validate_relative_paths(
                child.get("declared_write_paths"),
                f"child[{index}]-declared-write-paths",
                allow_empty=isolation == "read-only-shared",
                errors=errors,
            )
            target_paths = _validate_relative_paths(
                child.get("integration_target_paths"),
                f"child[{index}]-integration-target-paths",
                allow_empty=isolation == "read-only-shared",
                errors=errors,
            )
            if isolation == "read-only-shared" and (write_paths or target_paths):
                errors.append(f"read-only-child[{index}]-paths-must-be-empty")
            if isolation == "mutable-isolated":
                for write_path in write_paths:
                    write_parts = PurePosixPath(write_path).parts
                    if not any(
                        PurePosixPath(target).parts
                        == write_parts[: len(PurePosixPath(target).parts)]
                        for target in target_paths
                    ):
                        errors.append(
                            f"child[{index}]-declared-write-outside-integration-target:{write_path}"
                        )

        for field in (
            "child_id",
            "packet_id",
            "attempt_nonce",
            "session_id",
            "agent_id",
            "control_turn_id",
            "lease_id",
        ):
            values = [child.get(field) for child in normalized_children]
            if len(values) != len(set(values)):
                errors.append(f"duplicate-child-{field.replace('_', '-')}")
        if admitted_v2:
            for field in ("bead_id", "work_unit_id", "admitted_child_sha256"):
                values = [child.get(field) for child in normalized_children]
                if len(values) != len(set(values)):
                    errors.append(f"duplicate-child-{field.replace('_', '-')}")

        mutable = [
            child
            for child in normalized_children
            if child.get("isolation_class") == "mutable-isolated"
        ]
        mutable_worktrees = [
            _identity_key(child.get("worktree_identity")) for child in mutable
        ]
        if len(mutable_worktrees) != len(set(mutable_worktrees)):
            errors.append("duplicate-mutable-worktree-identity")
        targets: list[tuple[str, str]] = []
        for child in mutable:
            for path in child.get("integration_target_paths", []):
                targets.append((str(child.get("child_id")), path))
        for index, (left_child, left) in enumerate(targets):
            left_parts = PurePosixPath(left).parts
            for right_child, right in targets[index + 1 :]:
                if left_child == right_child:
                    continue
                right_parts = PurePosixPath(right).parts
                if (
                    left_parts == right_parts[: len(left_parts)]
                    or right_parts == left_parts[: len(right_parts)]
                ):
                    errors.append(
                        f"cross-child-target-overlap:{left_child}:{left}:{right_child}:{right}"
                    )

    cap = contract.get("max_active_workers")
    if not limits.validates_requested_capacity(cap):
        errors.append("invalid-max-active-workers")
    elif isinstance(children, list) and cap != len(children):
        errors.append("max-active-workers-must-equal-fixed-cohort")

    scheduler = _strict(
        contract.get("scheduler"),
        {
            "kind",
            "poll_interval_ms",
            "poll_lag_tolerance_ms",
            "certified_max_check_ms",
            "certified_max_scheduler_overhead_ms",
        },
        "scheduler",
        errors,
    )
    if scheduler is not None:
        if scheduler.get("kind") != "earliest-deadline-rotating-v1":
            errors.append("invalid-scheduler-kind")
        if scheduler.get("poll_interval_ms") != POOL_POLL_INTERVAL_MS:
            errors.append("invalid-scheduler-poll-interval-ms")
        if scheduler.get("poll_lag_tolerance_ms") != POOL_POLL_LAG_TOLERANCE_MS:
            errors.append("invalid-scheduler-poll-lag-tolerance-ms")
        for field in ("certified_max_check_ms", "certified_max_scheduler_overhead_ms"):
            item = scheduler.get(field)
            if item is not None and not _is_number(item):
                errors.append(f"invalid-scheduler-{field.replace('_', '-')}")
        check_ms = scheduler.get("certified_max_check_ms")
        overhead_ms = scheduler.get("certified_max_scheduler_overhead_ms")
        if cap == 1 and (check_ms is not None or overhead_ms is not None):
            errors.append("single-worker-scheduler-certification-must-be-null")
        if limits.requires_capability_receipt(cap):
            if check_ms != CERTIFIED_CALLBACK_MAX_MS["check"]:
                errors.append("concurrent-check-certification-invalid")
            if overhead_ms != CERTIFIED_SCHEDULER_OVERHEAD_MS:
                errors.append("concurrent-overhead-certification-invalid")
            if (
                _is_number(check_ms)
                and _is_number(overhead_ms)
                and _is_int(scheduler.get("poll_interval_ms"), 1)
            ):
                try:
                    proof = scheduling_budget_proof(
                        requested_workers=cap,
                        certified_callback_max_ms=CERTIFIED_CALLBACK_MAX_MS,
                        certified_scheduler_overhead_ms=overhead_ms,
                        poll_interval_ms=scheduler["poll_interval_ms"],
                    )
                except PoolSchedulabilityError:
                    errors.append("concurrent-schedulability-input-invalid")
                else:
                    if not proof.accepted:
                        errors.append("concurrent-response-time-bound-failed")

    budget = _strict(
        contract.get("aggregate_hard_budget"),
        {
            "tool_calls",
            "runtime_seconds",
            "compactions",
            "full_suite_runs",
            "mutations",
        },
        "aggregate-hard-budget",
        errors,
    )
    if budget is not None:
        for field in ("tool_calls", "runtime_seconds"):
            if not _is_int(budget.get(field), 1):
                errors.append(
                    f"invalid-aggregate-hard-budget-{field.replace('_', '-')}"
                )
        for field in ("compactions", "full_suite_runs", "mutations"):
            if not _is_int(budget.get(field)):
                errors.append(
                    f"invalid-aggregate-hard-budget-{field.replace('_', '-')}"
                )
        required_tool_calls = sum(
            int(
                child.get("completion_evidence_policy", {}).get("minimum_tool_calls", 0)
            )
            for child in normalized_children
            if isinstance(child.get("completion_evidence_policy"), Mapping)
            and _is_int(
                child.get("completion_evidence_policy", {}).get("minimum_tool_calls")
            )
        )
        if (
            _is_int(budget.get("tool_calls"), 1)
            and required_tool_calls > budget["tool_calls"]
        ):
            errors.append(
                "completion-evidence-minimum-tool-calls-exceed-aggregate-budget"
            )
        if admitted_v2 and normalized_children:
            for field in (
                "tool_calls",
                "runtime_seconds",
                "compactions",
                "full_suite_runs",
                "mutations",
            ):
                child_values = [
                    child.get("hard_budget", {}).get(field)
                    for child in normalized_children
                    if isinstance(child.get("hard_budget"), Mapping)
                ]
                if (
                    len(child_values) != len(normalized_children)
                    or any(not _is_int(item) for item in child_values)
                    or sum(child_values) != budget.get(field)
                ):
                    errors.append(
                        f"admission-child-budget-{field.replace('_', '-')}-aggregate-mismatch"
                    )

    topology = _strict(
        contract.get("topology"),
        {"integration_root_identity", "shared_read_only_worktree"},
        "topology",
        errors,
    )
    if topology is not None:
        _validate_identity(
            topology.get("integration_root_identity"), "integration-root", errors
        )
        if not isinstance(topology.get("shared_read_only_worktree"), bool):
            errors.append("invalid-shared-read-only-worktree")
        integration_key = _identity_key(topology.get("integration_root_identity"))
        for index, child in enumerate(normalized_children):
            if (
                integration_key
                and _identity_key(child.get("worktree_identity")) == integration_key
            ):
                errors.append(f"child[{index}]-worktree-aliases-integration-root")
        shared = topology.get("shared_read_only_worktree")
        child_worktree_keys = [
            _identity_key(child.get("worktree_identity"))
            for child in normalized_children
        ]
        if shared is True:
            if any(
                child.get("isolation_class") != "read-only-shared"
                for child in normalized_children
            ):
                errors.append("shared-read-only-worktree-has-mutable-child")
            if child_worktree_keys and len(set(child_worktree_keys)) != 1:
                errors.append("shared-read-only-worktree-identity-mismatch")
        elif len(child_worktree_keys) != len(set(child_worktree_keys)):
            errors.append("shared-worktree-requires-read-only-topology")
    if contract.get("allowed_actions") != list(POOL_ALLOWED_ACTIONS):
        errors.append("invalid-allowed-actions")
    capability_hash = contract.get("capability_receipt_sha256")
    if cap == 1 and capability_hash is not None:
        errors.append("single-worker-capability-receipt-must-be-null")
    if limits.requires_capability_receipt(cap) and not _is_sha256(capability_hash):
        errors.append("concurrent-capability-receipt-required")
    if admitted_v2:
        if not limits.is_released(cap):
            errors.append("admitted-capacity-not-released")
        _validate_v2_admission_binding(
            contract,
            normalized_children,
            admission_reservation,
            errors,
        )
    _validate_hash(contract, "contract_sha256", errors)
    _validate_replay(contract, "contract_sha256", seen_hashes, errors)
    return errors


def validate_capability_receipt(
    value: Any,
    *,
    expected_contract: Mapping[str, Any] | None = None,
    now: dt.datetime | None = None,
    seen_hashes: Iterable[str] | None = None,
    capacity_limits: PoolCapacityLimits | None = None,
) -> list[str]:
    errors: list[str] = []
    limits = capacity_limits or load_pool_capacity()
    receipt = _strict(value, CAPABILITY_FIELDS, "capability-receipt", errors)
    if receipt is None:
        return errors
    _validate_header(
        receipt,
        type_field="receipt_type",
        expected_type=CAPABILITY_RECEIPT_TYPE,
        expected_schema=CAPABILITY_RECEIPT_SCHEMA,
        errors=errors,
    )
    for field in (
        "adapter_id",
        "adapter_version",
        "execution_surface",
        "control_turn_id",
    ):
        if not _nonempty(receipt.get(field)):
            errors.append(f"invalid-{field.replace('_', '-')}")
    _validate_owner(receipt.get("host_identity"), "host-identity", errors)
    measured = _datetime(receipt.get("measured_at"))
    expires = _datetime(receipt.get("expires_at"))
    if measured is None:
        errors.append("invalid-measured-at")
    if expires is None:
        errors.append("invalid-expires-at")
    if measured is not None and expires is not None:
        if expires <= measured:
            errors.append("invalid-capability-lifetime")
        elif (expires - measured).total_seconds() > MAX_CAPABILITY_TTL_SECONDS:
            errors.append("capability-ttl-exceeded")
        effective_now = now or dt.datetime.now(dt.timezone.utc)
        if expires <= effective_now:
            errors.append("capability-receipt-stale")
    if not _is_int(receipt.get("sample_count"), 1):
        errors.append("invalid-sample-count")
    requested_cap = receipt.get("requested_cap")
    if not limits.validates_requested_capacity(
        requested_cap
    ) or not limits.requires_capability_receipt(requested_cap):
        errors.append("invalid-requested-cap")
    if receipt.get("clock") != "monotonic_ns":
        errors.append("invalid-clock")
    callbacks = receipt.get("callbacks")
    if not isinstance(callbacks, Mapping):
        errors.append("callbacks-must-be-object")
    else:
        missing = sorted(set(REQUIRED_CAPABILITY_CALLBACKS) - set(callbacks))
        unknown = sorted(set(callbacks) - set(REQUIRED_CAPABILITY_CALLBACKS))
        if missing:
            errors.append("callbacks-missing-fields:" + ",".join(missing))
        if unknown:
            errors.append("callbacks-unknown-fields:" + ",".join(unknown))
        for name in REQUIRED_CAPABILITY_CALLBACKS:
            if name in callbacks:
                _validate_stats(callbacks[name], f"callback-{name}", errors)
    scheduler_stats = _validate_stats(
        receipt.get("scheduler_overhead"), "scheduler-overhead", errors
    )
    certification = _validate_certification(
        receipt.get("certification"),
        errors,
        allow_legacy=(
            expected_contract is None and requested_cap == LEGACY_CONCURRENT_CAPACITY
        ),
    )
    capabilities = _strict(
        receipt.get("capabilities"),
        {"interrupt", "close", "wait", "trusted_telemetry"},
        "capabilities",
        errors,
    )
    if capabilities is not None and any(
        capabilities.get(name) is not True for name in capabilities
    ):
        errors.append("required-capability-missing")
    if receipt.get("attestation_source") != "trusted-control-plane-session-metadata":
        errors.append("untrusted-attestation-source")
    if receipt.get("validation_outcome") != "accepted":
        errors.append("capability-not-accepted")
    if isinstance(callbacks, Mapping) and isinstance(certification, Mapping):
        ceilings = certification.get("certified_callback_max_ms")
        if isinstance(ceilings, Mapping):
            for name in REQUIRED_CAPABILITY_CALLBACKS:
                observed = callbacks.get(name)
                if isinstance(observed, Mapping):
                    observed_max = observed.get("max_ms")
                    ceiling = ceilings.get(name)
                    if (
                        _is_number(observed_max)
                        and _is_number(ceiling)
                        and observed_max > ceiling
                    ):
                        errors.append(f"callback-observed-above-certified:{name}")
            overhead_max = certification.get("certified_scheduler_overhead_ms")
            scheduler = (
                expected_contract.get("scheduler", {})
                if expected_contract is not None
                else {}
            )
            interval = (
                scheduler.get("poll_interval_ms")
                if isinstance(scheduler, Mapping)
                else POOL_POLL_INTERVAL_MS
            )
            if not _is_number(interval, 1):
                interval = POOL_POLL_INTERVAL_MS
            response_time_workers = (
                expected_contract.get("max_active_workers")
                if expected_contract is not None
                else requested_cap
            )
            try:
                proof = scheduling_budget_proof(
                    requested_workers=response_time_workers,
                    certified_callback_max_ms=ceilings,
                    certified_scheduler_overhead_ms=overhead_max,
                    poll_interval_ms=interval,
                )
            except PoolSchedulabilityError:
                errors.append("capability-schedulability-input-invalid")
            else:
                if not proof.accepted:
                    errors.append("capability-response-time-bound-failed")
            if expected_contract is not None and isinstance(scheduler, Mapping):
                if scheduler.get("certified_max_check_ms") != ceilings.get("check"):
                    errors.append("capability-contract-check-ceiling-mismatch")
                if scheduler.get("certified_max_scheduler_overhead_ms") != overhead_max:
                    errors.append("capability-contract-scheduler-ceiling-mismatch")
    if isinstance(scheduler_stats, Mapping) and isinstance(certification, Mapping):
        observed_overhead = scheduler_stats.get("max_ms")
        certified_overhead = certification.get("certified_scheduler_overhead_ms")
        if (
            _is_number(observed_overhead)
            and _is_number(certified_overhead)
            and observed_overhead > certified_overhead
        ):
            errors.append("scheduler-observed-above-certified")
    if expected_contract is not None:
        if receipt.get("control_turn_id") != expected_contract.get("control_turn_id"):
            errors.append("capability-control-turn-mismatch")
        if receipt.get("host_identity") != expected_contract.get("owner"):
            errors.append("capability-owner-mismatch")
        if receipt.get("requested_cap") != expected_contract.get("max_active_workers"):
            errors.append("capability-cap-mismatch")
        if receipt.get("receipt_sha256") != expected_contract.get(
            "capability_receipt_sha256"
        ):
            errors.append("capability-contract-hash-mismatch")
    _validate_hash(receipt, "receipt_sha256", errors)
    _validate_replay(receipt, "receipt_sha256", seen_hashes, errors)
    return errors


def _usage_sum(children: list[Mapping[str, Any]]) -> dict[str, Any] | None:
    usages = [child.get("last_cumulative_usage") for child in children]
    if not all(isinstance(usage, Mapping) for usage in usages):
        return None
    result = zero_usage()
    for field in (
        "tool_calls",
        "runtime_seconds",
        "compactions",
        "full_suite_runs",
        "mutations",
    ):
        values = [usage.get(field) for usage in usages]
        if not all(_is_int(item) for item in values):
            return None
        result[field] = sum(values)
    token_values = [usage.get("tokens") for usage in usages]
    if all(
        isinstance(tokens, Mapping) and tokens.get("availability") == "available"
        for tokens in token_values
    ):
        result["tokens"] = {
            "availability": "available",
            "input": sum(tokens["input"] for tokens in token_values),
            "cached_input": sum(tokens["cached_input"] for tokens in token_values),
            "output": sum(tokens["output"] for tokens in token_values),
            "reasoning": sum(tokens["reasoning"] for tokens in token_values),
            "total": sum(tokens["total"] for tokens in token_values),
            "unavailable_reason": None,
        }
    return result


def validate_pool_state(
    value: Any,
    *,
    contract: Mapping[str, Any] | None = None,
    seen_hashes: Iterable[str] | None = None,
) -> list[str]:
    errors: list[str] = []
    state = _strict(value, POOL_STATE_FIELDS, "pool-state", errors)
    if state is None:
        return errors
    _validate_header(
        state,
        type_field="state_type",
        expected_type=POOL_STATE_TYPE,
        expected_schema=POOL_STATE_SCHEMA,
        errors=errors,
    )
    for field in ("pool_id", "pool_epoch"):
        if not _nonempty(state.get(field)):
            errors.append(f"invalid-{field.replace('_', '-')}")
    if not _is_sha256(state.get("contract_sha256")):
        errors.append("invalid-contract-sha256")
    if not _is_int(state.get("state_sequence")):
        errors.append("invalid-state-sequence")
    if state.get("status") not in POOL_STATUSES:
        errors.append("invalid-pool-status")
    _validate_owner(state.get("owner"), "owner", errors)
    if not _is_int(state.get("coordinator_epoch")):
        errors.append("invalid-coordinator-epoch")
    if not _is_int(state.get("scheduler_cursor")):
        errors.append("invalid-scheduler-cursor")
    active = state.get("active_children")
    terminal = state.get("terminal_children")
    if not isinstance(active, list) or any(not _nonempty(item) for item in active):
        errors.append("invalid-active-children")
        active = []
    if not isinstance(terminal, list) or any(not _nonempty(item) for item in terminal):
        errors.append("invalid-terminal-children")
        terminal = []
    if len(active) != len(set(active)):
        errors.append("duplicate-active-children")
    if len(terminal) != len(set(terminal)):
        errors.append("duplicate-terminal-children")
    if set(active) & set(terminal):
        errors.append("active-terminal-overlap")

    children_value = state.get("children")
    children: list[Mapping[str, Any]] = []
    hard_capacity = load_pool_capacity().hard_max_active_workers
    if (
        not isinstance(children_value, list)
        or not 1 <= len(children_value) <= hard_capacity
    ):
        errors.append("invalid-children")
    else:
        for index, item in enumerate(children_value):
            child = _strict(item, CHILD_STATE_FIELDS, f"child[{index}]", errors)
            if child is None:
                continue
            children.append(child)
            if child.get("ordinal") != index:
                errors.append(f"invalid-child[{index}]-ordinal")
            if not _nonempty(child.get("child_id")):
                errors.append(f"invalid-child[{index}]-id")
            if child.get("status") not in CHILD_STATUSES:
                errors.append(f"invalid-child[{index}]-status")
            for field in ("last_deadline_ns", "next_deadline_ns"):
                if child.get(field) is not None and not _is_int(child.get(field)):
                    errors.append(f"invalid-child[{index}]-{field.replace('_', '-')}")
            for field in ("child_state_sha256", "child_receipt_sha256"):
                if child.get(field) is not None and not _is_sha256(child.get(field)):
                    errors.append(f"invalid-child[{index}]-{field.replace('_', '-')}")
            _validate_usage(
                child.get("last_cumulative_usage"), f"child[{index}]-usage", errors
            )
            if not _nonempty(child.get("lease_id")):
                errors.append(f"invalid-child[{index}]-lease-id")
    child_ids = [child.get("child_id") for child in children]
    if len(child_ids) != len(set(child_ids)):
        errors.append("duplicate-child-id")
    if not set(active).issubset(set(child_ids)) or not set(terminal).issubset(
        set(child_ids)
    ):
        errors.append("active-or-terminal-child-unknown")
    expected_active = [
        child.get("child_id")
        for child in children
        if child.get("status")
        in {"armed", "running", "interrupt-pending", "interrupt-confirmed", "completed"}
    ]
    expected_terminal = [
        child.get("child_id")
        for child in children
        if child.get("status") in {"closed", "control-failed"}
    ]
    if active != expected_active:
        errors.append("active-child-status-mismatch")
    if terminal != expected_terminal:
        errors.append("terminal-child-status-mismatch")
    _validate_usage(state.get("aggregate_usage"), "aggregate-usage", errors)
    expected_usage = _usage_sum(children)
    if expected_usage is not None and state.get("aggregate_usage") != expected_usage:
        errors.append("aggregate-usage-mismatch")
    for field in (
        "pool_started_monotonic_ns",
        "pool_wall_seconds",
        "worker_seconds",
        "poll_overhead_seconds",
    ):
        if not _is_number(state.get(field)):
            errors.append(f"invalid-{field.replace('_', '-')}")
    if (
        expected_usage is not None
        and state.get("worker_seconds") != expected_usage["runtime_seconds"]
    ):
        errors.append("worker-seconds-mismatch")
    lease_bindings = state.get("lease_bindings")
    if not isinstance(lease_bindings, list) or any(
        not _is_sha256(item) for item in lease_bindings
    ):
        errors.append("invalid-lease-bindings")
    elif len(lease_bindings) != len(set(lease_bindings)):
        errors.append("duplicate-lease-binding")
    reasons = state.get("reasons")
    if not isinstance(reasons, list) or any(not _nonempty(item) for item in reasons):
        errors.append("invalid-reasons")
    first_fault = _validate_first_protected_fault(
        state.get("first_protected_fault"),
        state_sequence=state.get("state_sequence"),
        prefix="first-protected-fault",
        errors=errors,
    )
    if first_fault is None and reasons:
        errors.append("reasons-require-first-protected-fault")
    if first_fault is not None and not reasons:
        errors.append("first-protected-fault-requires-reason")
    if first_fault is not None and reasons and first_fault.get("code") not in reasons:
        errors.append("first-protected-fault-reason-mismatch")
    if state.get("control_loss_scope") not in {None, "child", "pool"}:
        errors.append("invalid-control-loss-scope")
    state_stop_metadata = {field: state.get(field) for field in STOP_METADATA_FIELDS}
    errors.extend(validate_stop_metadata(state_stop_metadata))
    _validate_reason_records(
        state.get("reason_records"),
        reasons,
        state.get("scope_authority"),
        errors,
    )
    if state.get("status") == "control-failed" and not reasons:
        errors.append("control-failed-requires-reason")
    if state.get("status") == "completed" and set(terminal) != set(child_ids):
        errors.append("completed-requires-terminal-cohort")
    if state.get("status") == "closed" and set(terminal) != set(child_ids):
        errors.append("closed-requires-terminal-cohort")
    if state.get("status") == "control-failed" and set(terminal) != set(child_ids):
        errors.append("control-failed-requires-terminal-cohort")
    if contract is not None:
        if state.get("pool_id") != contract.get("pool_id"):
            errors.append("state-pool-id-mismatch")
        if state.get("pool_epoch") != contract.get("pool_epoch"):
            errors.append("state-pool-epoch-mismatch")
        if state.get("contract_sha256") != contract.get("contract_sha256"):
            errors.append("state-contract-sha256-mismatch")
        if state.get("owner") != contract.get("owner"):
            errors.append("state-owner-mismatch")
        contract_children = contract.get("children", [])
        expected_ids = [
            child.get("child_id")
            for child in contract_children
            if isinstance(child, Mapping)
        ]
        if child_ids != expected_ids:
            errors.append("state-child-order-mismatch")
        if (
            _is_int(state.get("scheduler_cursor"))
            and expected_ids
            and state["scheduler_cursor"] >= len(expected_ids)
        ):
            errors.append("scheduler-cursor-out-of-range")
    _validate_hash(state, "state_sha256", errors)
    _validate_replay(state, "state_sha256", seen_hashes, errors)
    return errors


def validate_pool_decision(
    value: Any,
    *,
    contract: Mapping[str, Any] | None = None,
    state: Mapping[str, Any] | None = None,
    seen_hashes: Iterable[str] | None = None,
) -> list[str]:
    errors: list[str] = []
    decision = _strict(value, POOL_DECISION_FIELDS, "pool-decision", errors)
    if decision is None:
        return errors
    _validate_header(
        decision,
        type_field="decision_type",
        expected_type=POOL_DECISION_TYPE,
        expected_schema=POOL_DECISION_SCHEMA,
        errors=errors,
    )
    for field in ("pool_id", "pool_epoch"):
        if not _nonempty(decision.get(field)):
            errors.append(f"invalid-{field.replace('_', '-')}")
    for field in ("contract_sha256", "state_sha256"):
        if not _is_sha256(decision.get(field)):
            errors.append(f"invalid-{field.replace('_', '-')}")
    if not _is_int(decision.get("decision_sequence")):
        errors.append("invalid-decision-sequence")
    if decision.get("decision") not in POOL_DECISIONS:
        errors.append("invalid-decision")
    selected = decision.get("selected_child_id")
    if selected is not None and not _nonempty(selected):
        errors.append("invalid-selected-child-id")
    deadlines = decision.get("deadlines")
    if not isinstance(deadlines, list):
        errors.append("deadlines-must-be-array")
    else:
        deadline_ids: list[str] = []
        for index, item in enumerate(deadlines):
            entry = _strict(
                item, {"child_id", "next_deadline_ns"}, f"deadline[{index}]", errors
            )
            if entry is None:
                continue
            if not _nonempty(entry.get("child_id")):
                errors.append(f"invalid-deadline[{index}]-child-id")
            else:
                deadline_ids.append(str(entry["child_id"]))
            if entry.get("next_deadline_ns") is not None and not _is_int(
                entry.get("next_deadline_ns")
            ):
                errors.append(f"invalid-deadline[{index}]-next-deadline-ns")
        if len(deadline_ids) != len(set(deadline_ids)):
            errors.append("duplicate-deadline-child")
    latency = decision.get("observed_callback_latency_ms")
    if latency is not None and not _is_number(latency):
        errors.append("invalid-observed-callback-latency-ms")
    _validate_usage(decision.get("aggregate_usage"), "aggregate-usage", errors)
    reasons = decision.get("reasons")
    if not isinstance(reasons, list) or any(not _nonempty(item) for item in reasons):
        errors.append("invalid-reasons")
    actions = decision.get("required_control_actions")
    if not isinstance(actions, list) or any(
        item not in POOL_ALLOWED_ACTIONS for item in actions
    ):
        errors.append("invalid-required-control-actions")
    elif len(actions) != len(set(actions)):
        errors.append("duplicate-required-control-action")
    decision_stop_metadata = {
        field: decision.get(field) for field in STOP_METADATA_FIELDS
    }
    errors.extend(validate_stop_metadata(decision_stop_metadata))
    _validate_reason_records(
        decision.get("reason_records"),
        reasons,
        decision.get("scope_authority"),
        errors,
    )
    if contract is not None:
        for field in ("pool_id", "pool_epoch", "contract_sha256"):
            if decision.get(field) != contract.get(field):
                errors.append(f"decision-{field.replace('_', '-')}-mismatch")
        child_ids = [
            child.get("child_id")
            for child in contract.get("children", [])
            if isinstance(child, Mapping)
        ]
        if selected is not None and selected not in child_ids:
            errors.append("selected-child-unknown")
        if isinstance(deadlines, list):
            deadline_ids = [
                item.get("child_id") for item in deadlines if isinstance(item, Mapping)
            ]
            if deadline_ids != child_ids:
                errors.append("deadline-child-order-mismatch")
    if state is not None:
        if decision.get("state_sha256") != state.get("state_sha256"):
            errors.append("decision-state-sha256-mismatch")
        if decision.get("decision_sequence") != state.get("state_sequence"):
            errors.append("decision-sequence-mismatch")
        if decision.get("aggregate_usage") != state.get("aggregate_usage"):
            errors.append("decision-aggregate-usage-mismatch")
        if any(
            decision.get(field) != state.get(field) for field in STOP_METADATA_FIELDS
        ):
            errors.append("decision-stop-metadata-mismatch")
        if decision.get("reason_records") != state.get("reason_records"):
            errors.append("decision-reason-records-mismatch")
    _validate_hash(decision, "decision_sha256", errors)
    _validate_replay(decision, "decision_sha256", seen_hashes, errors)
    return errors


def validate_pool_control_request(
    value: Any,
    *,
    contract: Mapping[str, Any] | None = None,
    state: Mapping[str, Any] | None = None,
    seen_hashes: Iterable[str] | None = None,
) -> list[str]:
    errors: list[str] = []
    request = _strict(
        value, POOL_CONTROL_REQUEST_FIELDS, "pool-control-request", errors
    )
    if request is None:
        return errors
    _validate_header(
        request,
        type_field="request_type",
        expected_type=POOL_CONTROL_REQUEST_TYPE,
        expected_schema=POOL_CONTROL_REQUEST_SCHEMA,
        errors=errors,
    )
    for field in ("request_id", "pool_id", "pool_epoch", "reason"):
        if not _nonempty(request.get(field)):
            errors.append(f"invalid-{field.replace('_', '-')}")
    request_id = request.get("request_id")
    if (
        isinstance(request_id, str)
        and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", request_id) is None
    ):
        errors.append("invalid-request-id-format")
    if isinstance(request.get("reason"), str) and len(request["reason"]) > 256:
        errors.append("control-request-reason-too-long")
    if request.get("action") != "interrupt":
        errors.append("invalid-control-request-action")
    if not _is_sha256(request.get("contract_sha256")):
        errors.append("invalid-contract-sha256")
    if not _is_int(request.get("observed_state_sequence")):
        errors.append("invalid-observed-state-sequence")
    if not _is_sha256(request.get("observed_state_sha256")):
        errors.append("invalid-observed-state-sha256")
    if _datetime(request.get("created_at")) is None:
        errors.append("invalid-created-at")
    if contract is not None:
        for field in ("pool_id", "pool_epoch", "contract_sha256"):
            if request.get(field) != contract.get(field):
                errors.append(f"control-request-{field.replace('_', '-')}-mismatch")
    if state is not None:
        for field in ("pool_id", "pool_epoch", "contract_sha256"):
            if request.get(field) != state.get(field):
                errors.append(
                    f"control-request-state-{field.replace('_', '-')}-mismatch"
                )
        observed_sequence = request.get("observed_state_sequence")
        current_sequence = state.get("state_sequence")
        if _is_int(observed_sequence) and _is_int(current_sequence):
            if observed_sequence > current_sequence:
                errors.append("control-request-state-sequence-from-future")
            elif observed_sequence == current_sequence and request.get(
                "observed_state_sha256"
            ) != state.get("state_sha256"):
                errors.append("control-request-state-sha256-mismatch")
    _validate_hash(request, "request_sha256", errors)
    _validate_replay(request, "request_sha256", seen_hashes, errors)
    return errors


def validate_lease(
    value: Any,
    *,
    contract: Mapping[str, Any] | None = None,
    seen_hashes: Iterable[str] | None = None,
) -> list[str]:
    errors: list[str] = []
    lease = _strict(value, LEASE_FIELDS, "lease", errors)
    if lease is None:
        return errors
    _validate_header(
        lease,
        type_field="lease_type",
        expected_type=LEASE_TYPE,
        expected_schema=LEASE_SCHEMA,
        errors=errors,
    )
    for field in ("lease_id", "pool_id", "child_id", "pool_epoch"):
        if not _nonempty(lease.get(field)):
            errors.append(f"invalid-{field.replace('_', '-')}")
    _validate_identity(
        lease.get("integration_root_identity"), "integration-root", errors
    )
    _validate_identity(lease.get("worktree_identity"), "worktree", errors)
    # Read-only shared children hold lifecycle leases without claiming mutable
    # integration targets. Contract cross-binding still requires mutable
    # children to carry their non-empty target list.
    _validate_relative_paths(
        lease.get("target_paths"), "target-paths", allow_empty=True, errors=errors
    )
    _validate_owner(lease.get("owner"), "owner", errors)
    lifecycle = lease.get("lifecycle_state")
    if lifecycle not in {
        "acquired",
        "held",
        "release-pending",
        "released",
        "orphaned-active",
    }:
        errors.append("invalid-lifecycle-state")
    acquired = _datetime(lease.get("acquired_at"))
    updated = _datetime(lease.get("updated_at"))
    if acquired is None:
        errors.append("invalid-acquired-at")
    if updated is None:
        errors.append("invalid-updated-at")
    if acquired is not None and updated is not None and updated < acquired:
        errors.append("lease-time-regression")
    terminal_hash = lease.get("terminal_evidence_sha256")
    reason = lease.get("release_reason")
    if lifecycle in {"released", "release-pending"}:
        if not _is_sha256(terminal_hash):
            errors.append(f"{lifecycle}-lease-terminal-evidence-required")
        if not _nonempty(reason):
            errors.append(f"{lifecycle}-lease-reason-required")
    else:
        if terminal_hash is not None:
            errors.append("nonterminal-lease-terminal-evidence-forbidden")
        if reason is not None:
            errors.append("nonterminal-lease-release-reason-forbidden")
    if contract is not None:
        for field in ("pool_id", "pool_epoch"):
            if lease.get(field) != contract.get(field):
                errors.append(f"lease-{field.replace('_', '-')}-mismatch")
        child = next(
            (
                item
                for item in contract.get("children", [])
                if isinstance(item, Mapping)
                and item.get("child_id") == lease.get("child_id")
            ),
            None,
        )
        if child is None:
            errors.append("lease-child-unknown")
        else:
            if lease.get("lease_id") != child.get("lease_id"):
                errors.append("lease-id-mismatch")
            if lease.get("worktree_identity") != child.get("worktree_identity"):
                errors.append("lease-worktree-identity-mismatch")
            if lease.get("target_paths") != child.get("integration_target_paths"):
                errors.append("lease-target-paths-mismatch")
            if lease.get("integration_root_identity") != contract.get(
                "topology", {}
            ).get("integration_root_identity"):
                errors.append("lease-integration-root-identity-mismatch")
            if lease.get("owner") != contract.get("owner"):
                errors.append("lease-owner-mismatch")
    _validate_hash(lease, "lease_sha256", errors)
    _validate_replay(lease, "lease_sha256", seen_hashes, errors)
    return errors


def validate_pool_receipt(
    value: Any,
    *,
    contract: Mapping[str, Any] | None = None,
    terminal_state: Mapping[str, Any] | None = None,
    admission_reservation: Mapping[str, Any] | None = None,
    dispatch_receipt: Mapping[str, Any] | None = None,
    seen_hashes: Iterable[str] | None = None,
) -> list[str]:
    errors: list[str] = []
    admitted_v2 = isinstance(value, Mapping) and value.get("version") == 2
    receipt = _strict(
        value,
        POOL_RECEIPT_FIELDS_V2 if admitted_v2 else POOL_RECEIPT_FIELDS_V1,
        "pool-receipt",
        errors,
    )
    if receipt is None:
        return errors
    _validate_header(
        receipt,
        type_field="receipt_type",
        expected_type=POOL_RECEIPT_TYPE,
        expected_schema=(
            ADMITTED_POOL_RECEIPT_SCHEMA if admitted_v2 else POOL_RECEIPT_SCHEMA
        ),
        errors=errors,
        expected_version=ADMITTED_POOL_VERSION if admitted_v2 else VERSION,
    )
    for field in ("pool_id", "pool_epoch"):
        if not _nonempty(receipt.get(field)):
            errors.append(f"invalid-{field.replace('_', '-')}")
    identity_hash_fields = ["contract_sha256", "terminal_state_sha256"]
    if admitted_v2:
        identity_hash_fields.extend(["reservation_sha256", "dispatch_sha256"])
    for field in identity_hash_fields:
        if not _is_sha256(receipt.get(field)):
            errors.append(f"invalid-{field.replace('_', '-')}")
    if receipt.get("capability_receipt_sha256") is not None and not _is_sha256(
        receipt.get("capability_receipt_sha256")
    ):
        errors.append("invalid-capability-receipt-sha256")
    for field in ("admission_order", "terminal_order"):
        order = receipt.get(field)
        if not isinstance(order, list) or any(not _nonempty(item) for item in order):
            errors.append(f"invalid-{field.replace('_', '-')}")
        elif len(order) != len(set(order)):
            errors.append(f"duplicate-{field.replace('_', '-')}")
    poll_order = receipt.get("poll_order")
    if not isinstance(poll_order, list) or any(
        not _nonempty(item) for item in poll_order
    ):
        errors.append("invalid-poll-order")
    timing_value = receipt.get("timing")
    timing_fields = (
        POOL_RECEIPT_EXCLUSIVE_TIMING_FIELDS
        if isinstance(timing_value, Mapping) and "accounting_version" in timing_value
        else POOL_RECEIPT_LEGACY_TIMING_FIELDS
    )
    timing = _strict(timing_value, timing_fields, "timing", errors)
    if timing is not None:
        for field in POOL_RECEIPT_LEGACY_TIMING_FIELDS:
            if not _is_number(timing.get(field)):
                errors.append(f"invalid-timing-{field.replace('_', '-')}")
        if "accounting_version" in timing:
            if timing.get("accounting_version") != "exclusive-v1":
                errors.append("invalid-timing-accounting-version")
            for field in (
                "callback_ns",
                "noncallback_invoke_ns",
                "coordinator_ns",
                "wait_ns",
            ):
                if not _is_int(timing.get(field)):
                    errors.append(f"invalid-timing-{field.replace('_', '-')}")
    child_receipts = receipt.get("child_terminal_receipts")
    child_receipt_ids: list[str] = []
    if not isinstance(child_receipts, list):
        errors.append("child-terminal-receipts-must-be-array")
    else:
        for index, item in enumerate(child_receipts):
            entry = _strict(
                item,
                (
                    POOL_CHILD_RECEIPT_FIELDS_V2
                    if admitted_v2
                    else POOL_CHILD_RECEIPT_FIELDS_V1
                ),
                f"child-receipt[{index}]",
                errors,
            )
            if entry is None:
                continue
            if not _nonempty(entry.get("child_id")):
                errors.append(f"invalid-child-receipt[{index}]-id")
            else:
                child_receipt_ids.append(str(entry["child_id"]))
            if not _is_sha256(entry.get("receipt_sha256")):
                errors.append(f"invalid-child-receipt[{index}]-sha256")
            if admitted_v2:
                for field in ("bead_id", "work_unit_id"):
                    if not _nonempty(entry.get(field)):
                        errors.append(
                            f"invalid-child-receipt[{index}]-{field.replace('_', '-')}"
                        )
                for field in ("packet_sha256", "admitted_child_sha256"):
                    if not _is_sha256(entry.get(field)):
                        errors.append(
                            f"invalid-child-receipt[{index}]-{field.replace('_', '-')}"
                        )
                control_receipt = entry.get("control_receipt")
                if control_receipt is not None:
                    control_errors = validate_control_turn_receipt(control_receipt)
                    errors.extend(
                        f"child-receipt[{index}]-control:" + item
                        for item in control_errors
                    )
                    if canonical_sha256(control_receipt) != entry.get(
                        "receipt_sha256"
                    ):
                        errors.append(
                            f"child-receipt[{index}]-control-receipt-sha256-mismatch"
                        )
    if len(child_receipt_ids) != len(set(child_receipt_ids)):
        errors.append("duplicate-child-terminal-receipt")
    _validate_usage(
        receipt.get("final_aggregate_usage"), "final-aggregate-usage", errors
    )
    for field in ("pool_wall_seconds", "worker_seconds"):
        if not _is_number(receipt.get(field)):
            errors.append(f"invalid-{field.replace('_', '-')}")
    if (
        timing is not None
        and timing.get("accounting_version") == "exclusive-v1"
        and _is_number(receipt.get("pool_wall_seconds"))
        and all(
            _is_int(timing.get(field))
            for field in (
                "callback_ns",
                "noncallback_invoke_ns",
                "coordinator_ns",
                "wait_ns",
            )
        )
    ):
        accounted_ns = sum(
            timing[field]
            for field in (
                "callback_ns",
                "noncallback_invoke_ns",
                "coordinator_ns",
                "wait_ns",
            )
        )
        wall_ns = round(float(receipt["pool_wall_seconds"]) * 1_000_000_000)
        if abs(accounted_ns - wall_ns) > 1:
            errors.append("timing-buckets-do-not-reconcile-with-pool-wall")
    lease_evidence = receipt.get("lease_evidence")
    lease_ids: list[str] = []
    if not isinstance(lease_evidence, list):
        errors.append("lease-evidence-must-be-array")
    else:
        for index, item in enumerate(lease_evidence):
            entry = _strict(
                item,
                {"lease_id", "lease_sha256", "lifecycle_state"},
                f"lease-evidence[{index}]",
                errors,
            )
            if entry is None:
                continue
            if not _nonempty(entry.get("lease_id")):
                errors.append(f"invalid-lease-evidence[{index}]-id")
            else:
                lease_ids.append(str(entry["lease_id"]))
            if not _is_sha256(entry.get("lease_sha256")):
                errors.append(f"invalid-lease-evidence[{index}]-sha256")
            if entry.get("lifecycle_state") not in {
                "acquired",
                "held",
                "release-pending",
                "released",
                "orphaned-active",
            }:
                errors.append(f"invalid-lease-evidence[{index}]-state")
    if len(lease_ids) != len(set(lease_ids)):
        errors.append("duplicate-lease-evidence")
    mutation = _strict(
        receipt.get("mutation_evidence"),
        {
            "integration_root_clean",
            "shared_read_only_clean",
            "child_worktrees_clean",
            "evidence_sha256",
        },
        "mutation-evidence",
        errors,
    )
    if mutation is not None:
        for field in (
            "integration_root_clean",
            "shared_read_only_clean",
            "child_worktrees_clean",
        ):
            if not isinstance(mutation.get(field), bool):
                errors.append(f"invalid-mutation-{field.replace('_', '-')}")
        if not _is_sha256(mutation.get("evidence_sha256")):
            errors.append("invalid-mutation-evidence-sha256")
        else:
            expected_mutation_hash = canonical_sha256(
                {
                    field: mutation.get(field)
                    for field in (
                        "integration_root_clean",
                        "shared_read_only_clean",
                        "child_worktrees_clean",
                    )
                }
            )
            if mutation.get("evidence_sha256") != expected_mutation_hash:
                errors.append("mutation-evidence-sha256-mismatch")
    reasons = receipt.get("reasons")
    if not isinstance(reasons, list) or any(not _nonempty(item) for item in reasons):
        errors.append("invalid-reasons")
    first_fault = _validate_first_protected_fault(
        receipt.get("first_protected_fault"),
        state_sequence=(terminal_state or {}).get("state_sequence")
        if terminal_state
        else None,
        prefix="first-protected-fault",
        errors=errors,
    )
    if first_fault is None and reasons:
        errors.append("reasons-require-first-protected-fault")
    if first_fault is not None and not reasons:
        errors.append("first-protected-fault-requires-reason")
    if first_fault is not None and reasons and first_fault.get("code") not in reasons:
        errors.append("first-protected-fault-reason-mismatch")
    receipt_stop_metadata = {
        field: receipt.get(field) for field in STOP_METADATA_FIELDS
    }
    errors.extend(validate_stop_metadata(receipt_stop_metadata))
    _validate_reason_records(
        receipt.get("reason_records"),
        reasons,
        receipt.get("scope_authority"),
        errors,
    )
    dispositions = receipt.get("child_dispositions")
    disposition_ids: list[str] = []
    if not isinstance(dispositions, list):
        errors.append("child-dispositions-must-be-array")
    else:
        for index, item in enumerate(dispositions):
            entry = _strict(
                item,
                (
                    POOL_CHILD_DISPOSITION_FIELDS_V2
                    if admitted_v2
                    else POOL_CHILD_DISPOSITION_FIELDS_V1
                ),
                f"child-disposition[{index}]",
                errors,
            )
            if entry is None:
                continue
            if not _nonempty(entry.get("child_id")):
                errors.append(f"invalid-child-disposition[{index}]-id")
            else:
                disposition_ids.append(str(entry["child_id"]))
            if entry.get("session_disposition") not in {
                "accepted",
                "accepted-with-warning",
                "quarantined",
            }:
                errors.append(f"invalid-child-disposition[{index}]-session")
            if entry.get("artifact_disposition") not in {
                "accepted",
                "independent-validation-required",
                "architect-adjudication-required",
                "rejected",
            }:
                errors.append(f"invalid-child-disposition[{index}]-artifact")
            if admitted_v2:
                for field in ("bead_id", "work_unit_id"):
                    if not _nonempty(entry.get(field)):
                        errors.append(
                            f"invalid-child-disposition[{index}]-{field.replace('_', '-')}"
                        )
                for field in ("packet_sha256", "admitted_child_sha256"):
                    if not _is_sha256(entry.get(field)):
                        errors.append(
                            f"invalid-child-disposition[{index}]-{field.replace('_', '-')}"
                        )
                expected_close = (
                    entry.get("session_disposition")
                    in {"accepted", "accepted-with-warning"}
                    and entry.get("artifact_disposition") == "accepted"
                )
                if entry.get("implementation_bead_close_authorized") is not expected_close:
                    errors.append(
                        f"child-disposition[{index}]-implementation-close-mismatch"
                    )
                for field in (
                    "parent_close_authorized",
                    "publication_close_authorized",
                ):
                    if entry.get(field) is not False:
                        errors.append(
                            f"child-disposition[{index}]-{field.replace('_', '-')}-must-be-false"
                        )
    if len(disposition_ids) != len(set(disposition_ids)):
        errors.append("duplicate-child-disposition")
    if receipt.get("pool_disposition") not in {
        "accepted",
        "partial",
        "quarantined",
        "rejected",
    }:
        errors.append("invalid-pool-disposition")
    if not isinstance(receipt.get("accepting"), bool):
        errors.append("invalid-accepting")
    if contract is not None:
        for field in (
            "pool_id",
            "pool_epoch",
            "contract_sha256",
            "capability_receipt_sha256",
        ):
            if receipt.get(field) != contract.get(field):
                errors.append(f"receipt-{field.replace('_', '-')}-mismatch")
        child_ids = [
            child.get("child_id")
            for child in contract.get("children", [])
            if isinstance(child, Mapping)
        ]
        admission_ids = receipt.get("admission_order", [])
        if not isinstance(admission_ids, list) or any(
            child_id not in child_ids for child_id in admission_ids
        ):
            errors.append("admission-order-child-unknown")
        elif admission_ids != [
            child_id for child_id in child_ids if child_id in admission_ids
        ]:
            errors.append("admission-order-mismatch")
        if isinstance(poll_order, list) and any(
            child_id not in child_ids for child_id in poll_order
        ):
            errors.append("poll-order-child-unknown")
        if set(receipt.get("terminal_order", [])) != set(child_ids):
            errors.append("terminal-order-mismatch")
        if child_receipt_ids != child_ids:
            errors.append("child-terminal-receipt-order-mismatch")
        if disposition_ids != child_ids:
            errors.append("child-disposition-order-mismatch")
        expected_leases = [
            child.get("lease_id")
            for child in contract.get("children", [])
            if isinstance(child, Mapping)
        ]
        if any(lease_id not in expected_leases for lease_id in lease_ids):
            errors.append("lease-evidence-id-unknown")
        elif lease_ids != [
            lease_id for lease_id in expected_leases if lease_id in lease_ids
        ]:
            errors.append("lease-evidence-order-mismatch")
        if timing is not None:
            scheduler = contract.get("scheduler", {})
            if timing.get("poll_interval_ms") != scheduler.get("poll_interval_ms"):
                errors.append("receipt-poll-interval-mismatch")
            if timing.get("poll_lag_tolerance_ms") != scheduler.get(
                "poll_lag_tolerance_ms"
            ):
                errors.append("receipt-poll-lag-tolerance-mismatch")
        if admitted_v2:
            if contract.get("version") != ADMITTED_POOL_VERSION:
                errors.append("receipt-v2-requires-v2-contract")
            if admission_reservation is None:
                errors.append("receipt-v2-admission-reservation-required")
            else:
                contract_errors = validate_pool_contract(
                    contract,
                    admission_reservation=admission_reservation,
                )
                errors.extend(
                    "receipt-v2-contract:" + item for item in contract_errors
                )
                if receipt.get("reservation_sha256") != admission_reservation.get(
                    "reservation_sha256"
                ):
                    errors.append("receipt-reservation-sha256-mismatch")
            if dispatch_receipt is None:
                errors.append("receipt-v2-dispatch-receipt-required")
            else:
                from .native_pool_admission import validate_dispatch_receipt

                dispatch_errors = validate_dispatch_receipt(
                    dispatch_receipt,
                    reservation_receipt=admission_reservation,
                )
                errors.extend(
                    "receipt-v2-dispatch:" + item for item in dispatch_errors
                )
                if receipt.get("dispatch_sha256") != dispatch_receipt.get(
                    "dispatch_sha256"
                ):
                    errors.append("receipt-dispatch-sha256-mismatch")
                if dispatch_receipt.get("pool_contract_sha256") != contract.get(
                    "contract_sha256"
                ):
                    errors.append("receipt-dispatch-contract-mismatch")
            if isinstance(child_receipts, list):
                for index, child in enumerate(contract.get("children", [])):
                    if index >= len(child_receipts) or not isinstance(
                        child_receipts[index], Mapping
                    ):
                        continue
                    entry = child_receipts[index]
                    for field in (
                        "child_id",
                        "bead_id",
                        "work_unit_id",
                        "packet_sha256",
                        "admitted_child_sha256",
                    ):
                        if entry.get(field) != child.get(field):
                            errors.append(
                                f"child-receipt[{index}]-{field.replace('_', '-')}-mismatch"
                            )
                    control_receipt = entry.get("control_receipt")
                    if isinstance(control_receipt, Mapping) and control_receipt.get(
                        "contract_sha256"
                    ) != child.get("control_contract_sha256"):
                        errors.append(
                            f"child-receipt[{index}]-control-contract-sha256-mismatch"
                        )
            if isinstance(dispositions, list):
                for index, child in enumerate(contract.get("children", [])):
                    if index >= len(dispositions) or not isinstance(
                        dispositions[index], Mapping
                    ):
                        continue
                    entry = dispositions[index]
                    for field in (
                        "child_id",
                        "bead_id",
                        "work_unit_id",
                        "packet_sha256",
                        "admitted_child_sha256",
                    ):
                        if entry.get(field) != child.get(field):
                            errors.append(
                                f"child-disposition[{index}]-{field.replace('_', '-')}-mismatch"
                            )
                    child_receipt = (
                        child_receipts[index]
                        if isinstance(child_receipts, list)
                        and index < len(child_receipts)
                        and isinstance(child_receipts[index], Mapping)
                        else {}
                    )
                    control_receipt = child_receipt.get("control_receipt")
                    implementation_close = entry.get(
                        "implementation_bead_close_authorized"
                    )
                    if implementation_close is True and (
                        not isinstance(control_receipt, Mapping)
                        or control_receipt.get("terminal_state") != "completed"
                        or control_receipt.get("errors") != []
                    ):
                        errors.append(
                            f"child-disposition[{index}]-implementation-close-requires-successful-control-receipt"
                        )
                    if (
                        isinstance(control_receipt, Mapping)
                        and control_receipt.get("terminal_state") == "control-failed"
                        and implementation_close is not False
                    ):
                        errors.append(
                            f"child-disposition[{index}]-control-failed-close-forbidden"
                        )
    if terminal_state is not None:
        if receipt.get("terminal_state_sha256") != terminal_state.get("state_sha256"):
            errors.append("receipt-terminal-state-sha256-mismatch")
        if receipt.get("final_aggregate_usage") != terminal_state.get(
            "aggregate_usage"
        ):
            errors.append("receipt-aggregate-usage-mismatch")
        if receipt.get("pool_wall_seconds") != terminal_state.get("pool_wall_seconds"):
            errors.append("receipt-pool-wall-seconds-mismatch")
        if receipt.get("worker_seconds") != terminal_state.get("worker_seconds"):
            errors.append("receipt-worker-seconds-mismatch")
        if (
            timing is not None
            and timing.get("accounting_version") == "exclusive-v1"
            and _is_int(timing.get("noncallback_invoke_ns"))
            and _is_int(timing.get("coordinator_ns"))
            and _is_number(terminal_state.get("poll_overhead_seconds"))
        ):
            expected_poll_overhead = (
                timing["noncallback_invoke_ns"] + timing["coordinator_ns"]
            ) / 1_000_000_000
            if not math.isclose(
                float(terminal_state["poll_overhead_seconds"]),
                expected_poll_overhead,
                rel_tol=0.0,
                abs_tol=1e-9,
            ):
                errors.append("receipt-poll-overhead-seconds-mismatch")
        if receipt.get("first_protected_fault") != terminal_state.get(
            "first_protected_fault"
        ):
            errors.append("receipt-first-protected-fault-mismatch")
        if any(
            receipt.get(field) != terminal_state.get(field)
            for field in STOP_METADATA_FIELDS
        ):
            errors.append("receipt-stop-metadata-mismatch")
    if receipt.get("accepting") is True:
        if receipt.get("pool_disposition") != "accepted":
            errors.append("accepting-requires-accepted-disposition")
        if reasons:
            errors.append("accepting-requires-empty-reasons")
        if first_fault is not None:
            errors.append("accepting-forbids-first-protected-fault")
        if terminal_state is None or terminal_state.get("status") != "closed":
            errors.append("accepting-requires-closed-state")
        if contract is not None:
            child_ids = [
                child.get("child_id")
                for child in contract.get("children", [])
                if isinstance(child, Mapping)
            ]
            expected_leases = [
                child.get("lease_id")
                for child in contract.get("children", [])
                if isinstance(child, Mapping)
            ]
            if receipt.get("admission_order") != child_ids:
                errors.append("accepting-requires-complete-admission")
            if not isinstance(poll_order, list) or any(
                child_id not in poll_order for child_id in child_ids
            ):
                errors.append("accepting-requires-complete-poll-evidence")
            if lease_ids != expected_leases:
                errors.append("accepting-requires-complete-lease-evidence")
            if timing is not None:
                maximum_gap = contract.get("scheduler", {}).get(
                    "poll_interval_ms", 0
                ) + contract.get("scheduler", {}).get("poll_lag_tolerance_ms", 0)
                if (
                    _is_number(timing.get("max_poll_gap_ms"))
                    and timing["max_poll_gap_ms"] > maximum_gap
                ):
                    errors.append("accepting-receipt-poll-gap-exceeded")
        if isinstance(mutation, Mapping) and any(
            mutation.get(field) is not True
            for field in (
                "integration_root_clean",
                "shared_read_only_clean",
                "child_worktrees_clean",
            )
        ):
            errors.append("accepting-requires-clean-mutation-evidence")
        if isinstance(lease_evidence, list) and any(
            not isinstance(item, Mapping) or item.get("lifecycle_state") != "released"
            for item in lease_evidence
        ):
            errors.append("accepting-requires-released-leases")
        if isinstance(dispositions, list) and any(
            not isinstance(item, Mapping)
            or item.get("session_disposition")
            not in {"accepted", "accepted-with-warning"}
            or item.get("artifact_disposition") != "accepted"
            for item in dispositions
        ):
            errors.append("accepting-requires-accepted-children")
    elif receipt.get("pool_disposition") == "accepted":
        errors.append("accepted-disposition-requires-accepting-receipt")
    _validate_hash(receipt, "receipt_sha256", errors)
    _validate_replay(receipt, "receipt_sha256", seen_hashes, errors)
    return errors


def validate_pool_artifact(value: Any, **kwargs: Any) -> list[str]:
    if not isinstance(value, Mapping):
        return ["artifact-must-be-object"]
    artifact_type = (
        value.get("contract_type")
        or value.get("state_type")
        or value.get("decision_type")
        or value.get("request_type")
        or value.get("lease_type")
        or value.get("receipt_type")
        or value.get("reservation_type")
        or value.get("dispatch_type")
    )
    from .native_pool_admission import (
        DISPATCH_TYPE,
        RESERVATION_TYPE,
        validate_dispatch_receipt,
        validate_reservation_receipt,
    )

    if artifact_type == RESERVATION_TYPE:
        return validate_reservation_receipt(value)
    if artifact_type == DISPATCH_TYPE:
        return validate_dispatch_receipt(
            value,
            reservation_receipt=kwargs.get("admission_reservation"),
        )
    if artifact_type == POOL_CONTRACT_TYPE:
        return validate_pool_contract(
            value,
            seen_hashes=kwargs.get("seen_hashes"),
            admission_reservation=kwargs.get("admission_reservation"),
        )
    if artifact_type == POOL_STATE_TYPE:
        return validate_pool_state(
            value,
            contract=kwargs.get("contract"),
            seen_hashes=kwargs.get("seen_hashes"),
        )
    if artifact_type == POOL_DECISION_TYPE:
        return validate_pool_decision(
            value,
            contract=kwargs.get("contract"),
            state=kwargs.get("state"),
            seen_hashes=kwargs.get("seen_hashes"),
        )
    if artifact_type == POOL_CONTROL_REQUEST_TYPE:
        return validate_pool_control_request(
            value,
            contract=kwargs.get("contract"),
            state=kwargs.get("state"),
            seen_hashes=kwargs.get("seen_hashes"),
        )
    if artifact_type == CAPABILITY_RECEIPT_TYPE:
        return validate_capability_receipt(
            value,
            expected_contract=kwargs.get("contract"),
            now=kwargs.get("now"),
            seen_hashes=kwargs.get("seen_hashes"),
        )
    if artifact_type == LEASE_TYPE:
        return validate_lease(
            value,
            contract=kwargs.get("contract"),
            seen_hashes=kwargs.get("seen_hashes"),
        )
    if artifact_type == POOL_RECEIPT_TYPE:
        return validate_pool_receipt(
            value,
            contract=kwargs.get("contract"),
            terminal_state=kwargs.get("state"),
            seen_hashes=kwargs.get("seen_hashes"),
        )
    return ["unknown-artifact-type"]
