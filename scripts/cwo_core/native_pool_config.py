"""Strict configuration and contract rendering for native supervision pools."""

from __future__ import annotations

import datetime as dt
import json
import os
from pathlib import Path, PurePosixPath
from typing import Any, Mapping

from .native_live_campaign_contracts import (
    MANIFEST_VERSION,
    MANIFEST_VERSION_V3,
    validate_campaign_manifest,
)
from .native_control import validate_control_turn_contract
from .native_pool_contracts import (
    CAPABILITY_CERTIFICATION_ENVELOPE,
    CAPABILITY_CERTIFICATION_VERSION,
    CAPABILITY_OBSERVATION_AUTHORITY,
    CAPABILITY_RESPONSE_TIME_EQUATION,
    CAPABILITY_SCHEDULER_MODEL,
    CERTIFIED_CALLBACK_MAX_MS,
    CERTIFIED_SCHEDULER_OVERHEAD_MS,
    MAX_ACTIVE_WORKERS,
    POOL_ALLOWED_ACTIONS,
    POOL_CONTRACT_SCHEMA,
    POOL_CONTRACT_TYPE,
    POOL_POLL_INTERVAL_MS,
    POOL_POLL_LAG_TOLERANCE_MS,
    VERSION,
    canonical_sha256,
    callback_certification_policy_sha256,
    seal_artifact,
    validate_capability_receipt,
    validate_pool_contract,
)
from .native_pool_leases import capture_owner_identity, owner_identity_is_live
from .native_pool_workspace import PoolWorkspaceMonitor, capture_workspace_snapshot
from .policy import load_policy


RENDER_REQUEST_TYPE = "cwo-native-supervision-pool-render-request"
RENDER_REQUEST_SCHEMA = "schemas/native-supervision-pool-render-request.schema.json"
RENDER_REQUEST_FIELDS = {
    "request_type",
    "version",
    "schema",
    "pool_id",
    "pool_epoch",
    "control_turn_id",
    "created_at",
    "max_active_workers",
    "aggregate_hard_budget",
    "integration_root",
    "children",
}
RENDER_CHILD_FIELDS = {
    "child_id",
    "packet_id",
    "attempt_nonce",
    "session_id",
    "agent_id",
    "control_turn_id",
    "packet_sha256",
    "control_contract_file",
    "state_file",
    "worktree",
    "isolation_class",
    "declared_write_paths",
    "integration_target_paths",
    "lease_id",
}
_BUDGET_FIELDS = {
    "tool_calls",
    "runtime_seconds",
    "compactions",
    "full_suite_runs",
    "mutations",
}
_STATE_BINDING_FIELDS = {
    "result_type",
    "version",
    "schema",
    "packet_id",
    "packet_sha256",
    "agent_id",
    "session_id",
    "status",
    "control_turn_id",
    "poll_interval_ms",
    "control_adapter",
    "required_capabilities",
}
BOUND_MANIFEST_VALIDATION_TYPE = "cwo-bound-campaign-manifest-validation"
BOUND_MANIFEST_VALIDATION_VERSION = 1
BOUND_MANIFEST_VALIDATION_FIELDS = {
    "validation_type",
    "version",
    "manifest_id",
    "manifest_sha256",
    "authorization_id",
    "control_turn_id",
    "candidate_commit",
    "candidate_tree",
    "launch_claim_sha256",
    "artifact_bindings_sha256",
    "validation_sha256",
}


class NativePoolConfigError(ValueError):
    """Raised when a pool cannot be rendered from complete trusted inputs."""


def _nonempty(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _integer(value: Any, minimum: int = 0) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= minimum


def _sha256(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _aware_datetime(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return parsed.tzinfo is not None


def seal_bound_manifest_validation(
    campaign_manifest: Mapping[str, Any],
    artifact_bindings: Mapping[str, Any],
) -> dict[str, Any]:
    """Seal the result of the launcher's complete v3 binding validation.

    This record is evidence from the trusted launch callback, not a replacement
    for that callback.  The shared pool renderer consumes it so a v3 manifest is
    never revalidated without the authorization and predecessor proof inputs.
    """

    candidate = campaign_manifest.get("candidate")
    if (
        campaign_manifest.get("version") != MANIFEST_VERSION_V3
        or not isinstance(candidate, Mapping)
    ):
        raise NativePoolConfigError("bound-manifest-validation-source-invalid")
    launch_claim_sha256 = artifact_bindings.get("launch_claim_sha256")
    if not _sha256(launch_claim_sha256):
        raise NativePoolConfigError("bound-manifest-validation-launch-claim-invalid")
    receipt = {
        "validation_type": BOUND_MANIFEST_VALIDATION_TYPE,
        "version": BOUND_MANIFEST_VALIDATION_VERSION,
        "manifest_id": campaign_manifest.get("manifest_id"),
        "manifest_sha256": campaign_manifest.get("manifest_sha256"),
        "authorization_id": campaign_manifest.get("authorization_id"),
        "control_turn_id": campaign_manifest.get("control_turn_id"),
        "candidate_commit": candidate.get("commit"),
        "candidate_tree": candidate.get("tree"),
        "launch_claim_sha256": launch_claim_sha256,
        "artifact_bindings_sha256": canonical_sha256(dict(artifact_bindings)),
    }
    receipt["validation_sha256"] = canonical_sha256(receipt)
    errors = validate_bound_manifest_validation(receipt, campaign_manifest)
    if errors:
        raise NativePoolConfigError(
            "bound-manifest-validation-invalid:" + ";".join(errors)
        )
    return receipt


def validate_bound_manifest_validation(
    value: Any,
    campaign_manifest: Mapping[str, Any],
) -> list[str]:
    """Validate an exact full-binding receipt against the current v3 manifest."""

    errors: list[str] = []
    receipt = _strict_fields(
        value,
        BOUND_MANIFEST_VALIDATION_FIELDS,
        "bound-manifest-validation",
        errors,
    )
    if receipt is None:
        return errors
    if (
        receipt.get("validation_type") != BOUND_MANIFEST_VALIDATION_TYPE
        or receipt.get("version") != BOUND_MANIFEST_VALIDATION_VERSION
    ):
        errors.append("bound-manifest-validation-header-invalid")
    candidate = campaign_manifest.get("candidate")
    expected = {
        "manifest_id": campaign_manifest.get("manifest_id"),
        "manifest_sha256": campaign_manifest.get("manifest_sha256"),
        "authorization_id": campaign_manifest.get("authorization_id"),
        "control_turn_id": campaign_manifest.get("control_turn_id"),
        "candidate_commit": (
            candidate.get("commit") if isinstance(candidate, Mapping) else None
        ),
        "candidate_tree": (
            candidate.get("tree") if isinstance(candidate, Mapping) else None
        ),
    }
    if any(receipt.get(field) != expected_value for field, expected_value in expected.items()):
        errors.append("bound-manifest-validation-binding-mismatch")
    for field in (
        "manifest_sha256",
        "launch_claim_sha256",
        "artifact_bindings_sha256",
        "validation_sha256",
    ):
        if not _sha256(receipt.get(field)):
            errors.append(f"bound-manifest-validation-{field.replace('_', '-')}-invalid")
    unsigned = dict(receipt)
    unsigned.pop("validation_sha256", None)
    if receipt.get("validation_sha256") != canonical_sha256(unsigned):
        errors.append("bound-manifest-validation-sha256-mismatch")
    return sorted(set(errors))


def validate_live_canary_manifest_gate(
    campaign_manifest: Mapping[str, Any],
    bound_manifest_validation: Mapping[str, Any] | None,
    expected_bound_manifest_validation: Mapping[str, Any] | None,
) -> list[str]:
    """Validate the manifest gate that must run before any live allocation."""

    manifest_version = campaign_manifest.get("version")
    if manifest_version == MANIFEST_VERSION_V3:
        errors: list[str] = []
        for label, receipt in (
            ("observed", bound_manifest_validation),
            ("expected", expected_bound_manifest_validation),
        ):
            errors.extend(
                f"{label}:{item}"
                for item in validate_bound_manifest_validation(
                    receipt,
                    campaign_manifest,
                )
            )
        if (
            isinstance(bound_manifest_validation, Mapping)
            and isinstance(expected_bound_manifest_validation, Mapping)
            and dict(bound_manifest_validation)
            != dict(expected_bound_manifest_validation)
        ):
            errors.append("observed-expected-receipt-mismatch")
        return sorted(set(errors))
    if manifest_version == MANIFEST_VERSION:
        if (
            bound_manifest_validation is not None
            or expected_bound_manifest_validation is not None
        ):
            return ["campaign-manifest-v2-bound-validation-forbidden"]
        return validate_campaign_manifest(campaign_manifest)
    return ["campaign-manifest-version-invalid"]


def _strict_fields(value: Any, expected: set[str], prefix: str, errors: list[str]) -> Mapping[str, Any] | None:
    if not isinstance(value, Mapping):
        errors.append(f"{prefix}-must-be-object")
        return None
    missing = sorted(expected - set(value))
    unknown = sorted(set(value) - expected)
    if missing:
        errors.append(f"{prefix}-missing-fields:" + ",".join(missing))
    if unknown:
        errors.append(f"{prefix}-unknown-fields:" + ",".join(unknown))
    return value


def _validate_paths(value: Any, prefix: str, *, allow_empty: bool, errors: list[str]) -> None:
    if not isinstance(value, list):
        errors.append(f"{prefix}-must-be-array")
        return
    if not value and not allow_empty:
        errors.append(f"{prefix}-must-not-be-empty")
    normalized: list[str] = []
    for item in value:
        if not _nonempty(item):
            errors.append(f"{prefix}-contains-invalid-path")
            continue
        path = PurePosixPath(item)
        if path.is_absolute() or item in {".", ".."} or any(part in {"", ".", ".."} for part in path.parts):
            errors.append(f"{prefix}-contains-unsafe-path")
            continue
        if path.as_posix() != item:
            errors.append(f"{prefix}-contains-noncanonical-path")
            continue
        normalized.append(item)
    if len(normalized) != len(set(normalized)):
        errors.append(f"{prefix}-contains-duplicate-path")


def validate_pool_render_request(value: Any) -> list[str]:
    """Validate the local path-bearing request used to render a pool contract."""
    errors: list[str] = []
    request = _strict_fields(value, RENDER_REQUEST_FIELDS, "render-request", errors)
    if request is None:
        return errors
    if request.get("request_type") != RENDER_REQUEST_TYPE:
        errors.append("invalid-request-type")
    if request.get("version") != VERSION:
        errors.append("invalid-version")
    if request.get("schema") != RENDER_REQUEST_SCHEMA:
        errors.append("invalid-schema")
    for field in ("pool_id", "pool_epoch", "control_turn_id"):
        if not _nonempty(request.get(field)):
            errors.append(f"invalid-{field.replace('_', '-')}")
    if not _aware_datetime(request.get("created_at")):
        errors.append("invalid-created-at")
    cap = request.get("max_active_workers")
    if not _integer(cap, 1) or cap > MAX_ACTIVE_WORKERS:
        errors.append("invalid-max-active-workers")
    integration_root = request.get("integration_root")
    if not _nonempty(integration_root) or not Path(str(integration_root)).is_absolute():
        errors.append("invalid-integration-root")
    budget = _strict_fields(request.get("aggregate_hard_budget"), _BUDGET_FIELDS, "aggregate-hard-budget", errors)
    if budget is not None:
        for field in ("tool_calls", "runtime_seconds"):
            if not _integer(budget.get(field), 1):
                errors.append(f"invalid-budget-{field.replace('_', '-')}")
        for field in ("compactions", "full_suite_runs", "mutations"):
            if not _integer(budget.get(field)):
                errors.append(f"invalid-budget-{field.replace('_', '-')}")
    children = request.get("children")
    if not isinstance(children, list) or not 1 <= len(children) <= MAX_ACTIVE_WORKERS:
        errors.append("invalid-children")
        return errors
    if _integer(cap, 1) and len(children) != cap:
        errors.append("fixed-cohort-size-mismatch")
    identities: dict[str, list[Any]] = {
        field: []
        for field in ("child_id", "packet_id", "attempt_nonce", "session_id", "agent_id", "control_turn_id", "lease_id")
    }
    for index, raw in enumerate(children):
        child = _strict_fields(raw, RENDER_CHILD_FIELDS, f"child[{index}]", errors)
        if child is None:
            continue
        for field in identities:
            value_for_field = child.get(field)
            identities[field].append(value_for_field)
            if not _nonempty(value_for_field):
                errors.append(f"invalid-child[{index}]-{field.replace('_', '-')}")
        if not _sha256(child.get("packet_sha256")):
            errors.append(f"invalid-child[{index}]-packet-sha256")
        for field in ("control_contract_file", "state_file", "worktree"):
            candidate = child.get(field)
            if not _nonempty(candidate) or not Path(str(candidate)).is_absolute():
                errors.append(f"invalid-child[{index}]-{field.replace('_', '-')}")
        isolation = child.get("isolation_class")
        if isolation not in {"read-only-shared", "mutable-isolated"}:
            errors.append(f"invalid-child[{index}]-isolation-class")
        read_only = isolation == "read-only-shared"
        _validate_paths(child.get("declared_write_paths"), f"child[{index}]-declared-write-paths", allow_empty=read_only, errors=errors)
        _validate_paths(child.get("integration_target_paths"), f"child[{index}]-integration-target-paths", allow_empty=read_only, errors=errors)
        if read_only and (child.get("declared_write_paths") or child.get("integration_target_paths")):
            errors.append(f"read-only-child[{index}]-paths-must-be-empty")
    for field, values in identities.items():
        if len(values) != len(set(values)):
            errors.append(f"duplicate-child-{field.replace('_', '-')}")
    return errors


def _load_private_object(path_value: str, label: str) -> dict[str, Any]:
    path = Path(path_value).absolute()
    if path.is_symlink():
        raise NativePoolConfigError(f"{label}-is-symlink")
    try:
        stat = path.stat()
        if stat.st_uid != os.geteuid() or stat.st_mode & 0o077:
            raise NativePoolConfigError(f"{label}-permissions-invalid")
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise NativePoolConfigError(f"{label}-unreadable") from exc
    if not isinstance(value, dict):
        raise NativePoolConfigError(f"{label}-must-be-object")
    return value


def _validate_worker_state_binding(state: Mapping[str, Any], child: Mapping[str, Any]) -> list[str]:
    errors: list[str] = []
    missing = sorted(_STATE_BINDING_FIELDS - set(state))
    if missing:
        errors.append("worker-state-missing-fields:" + ",".join(missing))
        return errors
    if state.get("result_type") != "cwo-native-supervision-state" or state.get("version") != 1:
        errors.append("worker-state-header-invalid")
    if state.get("schema") != "schemas/native-supervision-state.schema.json":
        errors.append("worker-state-schema-invalid")
    for field in ("packet_id", "packet_sha256", "agent_id", "session_id"):
        if state.get(field) != child.get(field):
            errors.append(f"worker-state-{field.replace('_', '-')}-mismatch")
    if state.get("status") != "created":
        errors.append("worker-state-not-newly-created")
    if state.get("control_turn_id") is not None:
        errors.append("worker-state-already-control-bound")
    if state.get("poll_interval_ms") != POOL_POLL_INTERVAL_MS:
        errors.append("worker-state-poll-interval-mismatch")
    if state.get("control_adapter") != "native-multi-agent-v1":
        errors.append("worker-state-control-adapter-mismatch")
    if state.get("required_capabilities") != ["interrupt", "close", "wait"]:
        errors.append("worker-state-capabilities-mismatch")
    return errors


def _pool_policy(policy_document: Mapping[str, Any] | None) -> Mapping[str, Any]:
    document = dict(policy_document) if policy_document is not None else load_policy("native-worker-execution")
    policy = document.get("native_supervision_pool")
    if not isinstance(policy, Mapping):
        raise NativePoolConfigError("native-supervision-pool-policy-missing")
    required = {
        "version": 1,
        "enabled": True,
        "default_max_active_workers": 1,
        "hard_max_active_workers": 2,
        "cap_two_requires_explicit_opt_in": True,
        "cap_two_requires_fresh_capability": True,
        "required_control_adapter": "native-multi-agent-v1",
        "max_capability_ttl_seconds": 3600,
        "max_certified_check_ms": CERTIFIED_CALLBACK_MAX_MS["check"],
    }
    for field, expected in required.items():
        if policy.get(field) != expected:
            raise NativePoolConfigError(f"native-supervision-pool-policy-invalid:{field}")
    if policy.get("status") not in {"canary-gated", "operative-authorized"}:
        raise NativePoolConfigError("native-supervision-pool-policy-invalid:status")
    if not isinstance(policy.get("cap_two_operative_release"), bool):
        raise NativePoolConfigError("native-supervision-pool-policy-invalid:cap_two_operative_release")
    if (
        policy.get("status") == "canary-gated"
        and policy.get("cap_two_operative_release") is not False
    ) or (
        policy.get("status") == "operative-authorized"
        and policy.get("cap_two_operative_release") is not True
    ):
        raise NativePoolConfigError("native-supervision-pool-policy-release-inconsistent")
    if not _nonempty(policy.get("release_requires")):
        raise NativePoolConfigError("native-supervision-pool-policy-invalid:release_requires")
    surfaces = policy.get("allowed_execution_surfaces")
    if not isinstance(surfaces, list) or not surfaces or any(not _nonempty(item) for item in surfaces):
        raise NativePoolConfigError("native-supervision-pool-policy-invalid:allowed_execution_surfaces")
    single_flight = policy.get("single_flight_surfaces")
    required_single_flight = {
        "precommit-supervision",
        "candidate-packet-construction",
        "operative-prompt-render",
        "native-retry",
        "native-resume",
        "native-replay-dispatch",
        "outside-critic-review",
        "integration",
        "publication",
    }
    if not isinstance(single_flight, list) or not required_single_flight.issubset(set(single_flight)):
        raise NativePoolConfigError("native-supervision-pool-policy-invalid:single_flight_surfaces")
    scheduler = policy.get("scheduler")
    if (
        not isinstance(scheduler, Mapping)
        or scheduler.get("kind") != "earliest-deadline-rotating-v1"
        or scheduler.get("poll_interval_ms") != POOL_POLL_INTERVAL_MS
        or scheduler.get("poll_lag_tolerance_ms") != POOL_POLL_LAG_TOLERANCE_MS
        or scheduler.get("hot_admission_allowed") is not False
        or scheduler.get("threads_allowed") is not False
    ):
        raise NativePoolConfigError("native-supervision-pool-policy-invalid:scheduler")
    certification = policy.get("callback_certification")
    expected_certification = {
        "version": CAPABILITY_CERTIFICATION_VERSION,
        "envelope": CAPABILITY_CERTIFICATION_ENVELOPE,
        "scheduler_model": CAPABILITY_SCHEDULER_MODEL,
        "response_time_equation": CAPABILITY_RESPONSE_TIME_EQUATION,
        "observation_authority": CAPABILITY_OBSERVATION_AUTHORITY,
        "certified_callback_max_ms": CERTIFIED_CALLBACK_MAX_MS,
        "certified_scheduler_overhead_ms": CERTIFIED_SCHEDULER_OVERHEAD_MS,
    }
    if not isinstance(certification, Mapping) or dict(certification) != expected_certification:
        raise NativePoolConfigError(
            "native-supervision-pool-policy-invalid:callback_certification"
        )
    return policy


def _build_pool_contract(
    request: Mapping[str, Any],
    *,
    capability_receipt: Mapping[str, Any] | None = None,
    enable_concurrency: bool = False,
    owner_pid: int | None = None,
    now: dt.datetime | None = None,
    policy_document: Mapping[str, Any] | None = None,
    canary_manifest: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Render a strict pool contract without carrying task or repository content."""
    request_errors = validate_pool_render_request(request)
    if request_errors:
        raise NativePoolConfigError("pool-render-request-invalid:" + ";".join(request_errors))
    policy = _pool_policy(policy_document)
    cap = int(request["max_active_workers"])
    if cap == 2 and not enable_concurrency:
        raise NativePoolConfigError("cap-two-requires-explicit-enable-concurrency")
    if cap == 2 and policy.get("cap_two_requires_fresh_capability") is not True:
        raise NativePoolConfigError("cap-two-policy-does-not-require-fresh-capability")
    if cap == 2:
        operative_released = (
            policy.get("status") == "operative-authorized"
            and policy.get("cap_two_operative_release") is True
        )
        if not operative_released and canary_manifest is None:
            raise NativePoolConfigError("cap-two-operative-release-required")
        if not operative_released and {
            "status": policy.get("status"),
            "cap_two_operative_release": policy.get("cap_two_operative_release"),
        } != canary_manifest.get("release", {}).get("policy_before"):
            raise NativePoolConfigError("live-canary-policy-binding-mismatch")

    effective_now = now or dt.datetime.now(dt.timezone.utc)
    if cap == 2:
        if capability_receipt is None:
            raise NativePoolConfigError("cap-two-capability-receipt-required")
        capability_errors = validate_capability_receipt(capability_receipt, now=effective_now)
        if capability_errors:
            raise NativePoolConfigError("capability-receipt-invalid:" + ";".join(capability_errors))
        if capability_receipt.get("adapter_id") != policy.get("required_control_adapter"):
            raise NativePoolConfigError("capability-adapter-policy-mismatch")
        if capability_receipt.get("execution_surface") not in policy.get("allowed_execution_surfaces", []):
            raise NativePoolConfigError("capability-execution-surface-not-allowed")
        certification = capability_receipt.get("certification")
        expected_policy_sha256 = callback_certification_policy_sha256(
            policy["callback_certification"]
        )
        if (
            not isinstance(certification, Mapping)
            or certification.get("policy_sha256") != expected_policy_sha256
        ):
            raise NativePoolConfigError("capability-certification-policy-mismatch")
        owner = dict(capability_receipt["host_identity"])
        if owner_pid is not None and owner.get("pid") != owner_pid:
            raise NativePoolConfigError("owner-pid-capability-mismatch")
    else:
        owner = capture_owner_identity(owner_pid)
    if not owner_identity_is_live(owner):
        raise NativePoolConfigError("pool-owner-not-live")

    integration = capture_workspace_snapshot(str(request["integration_root"]))
    rendered_children: list[dict[str, Any]] = []
    child_roots: list[str] = []
    child_worktrees: dict[str, str] = {}
    for ordinal, raw_child in enumerate(request["children"]):
        child = dict(raw_child)
        control = _load_private_object(child["control_contract_file"], f"child[{ordinal}]-control-contract")
        control_errors = validate_control_turn_contract(control)
        if control_errors:
            raise NativePoolConfigError(f"child[{ordinal}]-control-contract-invalid:" + ";".join(control_errors))
        for request_field, contract_field in (
            ("state_file", "state_file"),
            ("agent_id", "agent_id"),
            ("control_turn_id", "control_turn_id"),
        ):
            if child[request_field] != control[contract_field]:
                raise NativePoolConfigError(f"child[{ordinal}]-control-{request_field.replace('_', '-')}-mismatch")
        if control.get("poll_interval_ms") != POOL_POLL_INTERVAL_MS:
            raise NativePoolConfigError(f"child[{ordinal}]-control-poll-interval-mismatch")
        worker_state = _load_private_object(child["state_file"], f"child[{ordinal}]-worker-state")
        state_errors = _validate_worker_state_binding(worker_state, child)
        if state_errors:
            raise NativePoolConfigError(f"child[{ordinal}]-worker-state-invalid:" + ";".join(state_errors))
        snapshot = capture_workspace_snapshot(
            child["worktree"],
            allowed_paths=child["declared_write_paths"],
        )
        child_roots.append(snapshot["root"])
        child_worktrees[child["child_id"]] = snapshot["root"]
        rendered_children.append(
            {
                "ordinal": ordinal,
                "child_id": child["child_id"],
                "packet_id": child["packet_id"],
                "attempt_nonce": child["attempt_nonce"],
                "session_id": child["session_id"],
                "agent_id": child["agent_id"],
                "control_turn_id": child["control_turn_id"],
                "packet_sha256": child["packet_sha256"],
                "control_contract_sha256": control["contract_sha256"],
                "state_file": child["state_file"],
                "worktree_identity": snapshot["identity"],
                "isolation_class": child["isolation_class"],
                "declared_write_paths": list(child["declared_write_paths"]),
                "integration_target_paths": list(child["integration_target_paths"]),
                "lease_id": child["lease_id"],
            }
        )

    read_only = all(child["isolation_class"] == "read-only-shared" for child in rendered_children)
    shared_read_only = read_only and len(set(child_roots)) == 1
    check_max = (
        capability_receipt["certification"]["certified_callback_max_ms"]["check"]
        if cap == 2
        else None
    )
    overhead_max = (
        capability_receipt["certification"]["certified_scheduler_overhead_ms"]
        if cap == 2
        else None
    )
    contract = seal_artifact(
        {
            "contract_type": POOL_CONTRACT_TYPE,
            "version": VERSION,
            "schema": POOL_CONTRACT_SCHEMA,
            "pool_id": request["pool_id"],
            "pool_epoch": request["pool_epoch"],
            "control_turn_id": request["control_turn_id"],
            "created_at": request["created_at"],
            "owner": owner,
            "children": rendered_children,
            "max_active_workers": cap,
            "scheduler": {
                "kind": "earliest-deadline-rotating-v1",
                "poll_interval_ms": POOL_POLL_INTERVAL_MS,
                "poll_lag_tolerance_ms": POOL_POLL_LAG_TOLERANCE_MS,
                "certified_max_check_ms": check_max,
                "certified_max_scheduler_overhead_ms": overhead_max,
            },
            "aggregate_hard_budget": dict(request["aggregate_hard_budget"]),
            "topology": {
                "integration_root_identity": integration["identity"],
                "shared_read_only_worktree": shared_read_only,
            },
            "allowed_actions": list(POOL_ALLOWED_ACTIONS),
            "capability_receipt_sha256": capability_receipt["receipt_sha256"] if cap == 2 else None,
        },
        "contract_sha256",
    )
    contract_errors = validate_pool_contract(contract)
    if contract_errors:
        raise NativePoolConfigError("rendered-pool-contract-invalid:" + ";".join(contract_errors))
    if cap == 2:
        capability_errors = validate_capability_receipt(
            capability_receipt,
            expected_contract=contract,
            now=effective_now,
        )
        if capability_errors:
            raise NativePoolConfigError("capability-contract-binding-invalid:" + ";".join(capability_errors))
    PoolWorkspaceMonitor(
        contract,
        integration_root=integration["root"],
        child_worktrees=child_worktrees,
    )
    return contract


def build_pool_contract(
    request: Mapping[str, Any],
    *,
    capability_receipt: Mapping[str, Any] | None = None,
    enable_concurrency: bool = False,
    owner_pid: int | None = None,
    now: dt.datetime | None = None,
    policy_document: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Render an ordinary pool contract under the operative release policy."""
    return _build_pool_contract(
        request,
        capability_receipt=capability_receipt,
        enable_concurrency=enable_concurrency,
        owner_pid=owner_pid,
        now=now,
        policy_document=policy_document,
    )


def build_live_canary_pool_contract(
    request: Mapping[str, Any],
    *,
    campaign_manifest: Mapping[str, Any],
    capability_receipt: Mapping[str, Any],
    bound_manifest_validation: Mapping[str, Any] | None = None,
    expected_bound_manifest_validation: Mapping[str, Any] | None = None,
    owner_pid: int | None = None,
    now: dt.datetime | None = None,
    policy_document: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Render the one manifest-bound cap-two canary before operative release."""
    manifest_errors = validate_live_canary_manifest_gate(
        campaign_manifest,
        bound_manifest_validation,
        expected_bound_manifest_validation,
    )
    if manifest_errors:
        error_prefix = (
            "campaign-manifest-bound-validation-invalid"
            if campaign_manifest.get("version") == MANIFEST_VERSION_V3
            else "campaign-manifest-invalid"
        )
        raise NativePoolConfigError(
            error_prefix + ":" + ";".join(manifest_errors)
        )
    if request.get("max_active_workers") != 2:
        raise NativePoolConfigError("live-canary-requires-cap-two")
    if request.get("control_turn_id") != campaign_manifest.get("control_turn_id"):
        raise NativePoolConfigError("live-canary-control-turn-mismatch")
    return _build_pool_contract(
        request,
        capability_receipt=capability_receipt,
        enable_concurrency=True,
        owner_pid=owner_pid,
        now=now,
        policy_document=policy_document,
        canary_manifest=campaign_manifest,
    )
