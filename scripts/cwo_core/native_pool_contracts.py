"""Strict, stdlib-only contracts for bounded native-supervision pools."""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import tempfile
from typing import Any, Iterable, Mapping


VERSION = 1
POOL_CONTRACT_TYPE = "cwo-native-supervision-pool-contract"
POOL_STATE_TYPE = "cwo-native-supervision-pool-state"
POOL_DECISION_TYPE = "cwo-native-supervision-pool-decision"
CAPABILITY_RECEIPT_TYPE = "cwo-native-supervision-adapter-capability-receipt"
LEASE_TYPE = "cwo-native-supervision-lease"
POOL_RECEIPT_TYPE = "cwo-native-supervision-pool-receipt"

POOL_CONTRACT_SCHEMA = "schemas/native-supervision-pool-contract.schema.json"
POOL_STATE_SCHEMA = "schemas/native-supervision-pool-state.schema.json"
POOL_DECISION_SCHEMA = "schemas/native-supervision-pool-decision.schema.json"
CAPABILITY_RECEIPT_SCHEMA = "schemas/native-supervision-adapter-capability-receipt.schema.json"
LEASE_SCHEMA = "schemas/native-supervision-lease.schema.json"
POOL_RECEIPT_SCHEMA = "schemas/native-supervision-pool-receipt.schema.json"

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
MAX_ACTIVE_WORKERS = 2
MAX_CAPABILITY_TTL_SECONDS = 3600
MAX_CERTIFIED_CHECK_MS = 400

HASH_FIELDS = {
    POOL_CONTRACT_TYPE: "contract_sha256",
    POOL_STATE_TYPE: "state_sha256",
    POOL_DECISION_TYPE: "decision_sha256",
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
USAGE_FIELDS = {
    "tool_calls",
    "runtime_seconds",
    "compactions",
    "full_suite_runs",
    "mutations",
    "tokens",
}
CHILD_CONTRACT_FIELDS = {
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
    "declared_write_paths",
    "integration_target_paths",
    "lease_id",
}
POOL_CONTRACT_FIELDS = {
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
    "control_loss_scope",
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
    "required_control_actions",
    "decision_sha256",
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
POOL_RECEIPT_FIELDS = {
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
    "child_dispositions",
    "pool_disposition",
    "accepting",
    "receipt_sha256",
}


def canonical_sha256(value: Any) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def artifact_sha256(value: Mapping[str, Any], hash_field: str) -> str:
    return canonical_sha256({key: item for key, item in value.items() if key != hash_field})


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


def _strict(value: Any, fields: set[str], prefix: str, errors: list[str]) -> Mapping[str, Any] | None:
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
    return isinstance(value, (int, float)) and not isinstance(value, bool) and value >= minimum


def _is_sha256(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


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
) -> None:
    if value.get(type_field) != expected_type:
        errors.append("invalid-artifact-type")
    version = value.get("version")
    if not _is_int(version) or version != VERSION:
        errors.append("invalid-version")
    if value.get("schema") != expected_schema:
        errors.append("invalid-schema")


def _validate_hash(value: Mapping[str, Any], hash_field: str, errors: list[str]) -> None:
    actual = value.get(hash_field)
    if not _is_sha256(actual):
        errors.append(f"invalid-{hash_field.replace('_', '-')}")
    elif actual != artifact_sha256(value, hash_field):
        errors.append(f"{hash_field.replace('_', '-')}-mismatch")


def _validate_replay(
    value: Mapping[str, Any], hash_field: str, seen_hashes: Iterable[str] | None, errors: list[str]
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
            if tokens["total"] != tokens["input"] + tokens["cached_input"] + tokens["output"] + tokens["reasoning"]:
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
    for field in ("tool_calls", "runtime_seconds", "compactions", "full_suite_runs", "mutations"):
        if not _is_int(usage.get(field)):
            errors.append(f"invalid-{prefix}-{field.replace('_', '-')}")
    _validate_token_usage(usage.get("tokens"), f"{prefix}-tokens", errors)


def zero_token_usage(reason: str = "trusted-token-telemetry-unavailable") -> dict[str, Any]:
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


def _validate_relative_paths(value: Any, prefix: str, *, allow_empty: bool, errors: list[str]) -> list[str]:
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
        if path.is_absolute() or item in {".", ".."} or any(part in {"", ".", ".."} for part in path.parts):
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
            if left_parts == right_parts[: len(left_parts)] or right_parts == left_parts[: len(right_parts)]:
                errors.append(f"overlapping-{prefix}:{left}:{right}")
    return paths


def _validate_stats(value: Any, prefix: str, errors: list[str]) -> Mapping[str, Any] | None:
    stats = _strict(value, {"p50_ms", "p90_ms", "p99_ms", "max_ms"}, prefix, errors)
    if stats is None:
        return None
    values = [stats.get(field) for field in ("p50_ms", "p90_ms", "p99_ms", "max_ms")]
    if any(not _is_number(item) for item in values):
        errors.append(f"invalid-{prefix}-values")
    elif values != sorted(values):
        errors.append(f"nonmonotonic-{prefix}-values")
    return stats


def _identity_key(value: Any) -> str:
    return canonical_sha256(value) if isinstance(value, Mapping) else ""


def validate_pool_contract(
    value: Any, *, seen_hashes: Iterable[str] | None = None
) -> list[str]:
    errors: list[str] = []
    contract = _strict(value, POOL_CONTRACT_FIELDS, "pool-contract", errors)
    if contract is None:
        return errors
    _validate_header(
        contract,
        type_field="contract_type",
        expected_type=POOL_CONTRACT_TYPE,
        expected_schema=POOL_CONTRACT_SCHEMA,
        errors=errors,
    )
    for field in ("pool_id", "pool_epoch", "control_turn_id"):
        if not _nonempty(contract.get(field)):
            errors.append(f"invalid-{field.replace('_', '-')}")
    if _datetime(contract.get("created_at")) is None:
        errors.append("invalid-created-at")
    _validate_owner(contract.get("owner"), "owner", errors)

    children = contract.get("children")
    normalized_children: list[Mapping[str, Any]] = []
    if not isinstance(children, list) or not 1 <= len(children) <= MAX_ACTIVE_WORKERS:
        errors.append("invalid-children")
    else:
        for index, item in enumerate(children):
            child = _strict(item, CHILD_CONTRACT_FIELDS, f"child[{index}]", errors)
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
            state_file = child.get("state_file")
            if not _nonempty(state_file) or not Path(str(state_file)).is_absolute():
                errors.append(f"invalid-child[{index}]-state-file")
            _validate_identity(child.get("worktree_identity"), f"child[{index}]-worktree", errors)
            isolation = child.get("isolation_class")
            if isolation not in {"read-only-shared", "mutable-isolated"}:
                errors.append(f"invalid-child[{index}]-isolation-class")
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

        for field in ("child_id", "packet_id", "attempt_nonce", "session_id", "agent_id", "control_turn_id", "lease_id"):
            values = [child.get(field) for child in normalized_children]
            if len(values) != len(set(values)):
                errors.append(f"duplicate-child-{field.replace('_', '-')}")

        mutable = [child for child in normalized_children if child.get("isolation_class") == "mutable-isolated"]
        mutable_worktrees = [_identity_key(child.get("worktree_identity")) for child in mutable]
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
                if left_parts == right_parts[: len(left_parts)] or right_parts == left_parts[: len(right_parts)]:
                    errors.append(f"cross-child-target-overlap:{left_child}:{left}:{right_child}:{right}")

    cap = contract.get("max_active_workers")
    if not _is_int(cap, 1) or cap > MAX_ACTIVE_WORKERS:
        errors.append("invalid-max-active-workers")
    elif isinstance(children, list) and cap > len(children):
        errors.append("max-active-workers-exceeds-cohort")

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
        if not _is_int(scheduler.get("poll_interval_ms"), 1):
            errors.append("invalid-scheduler-poll-interval-ms")
        if not _is_int(scheduler.get("poll_lag_tolerance_ms")):
            errors.append("invalid-scheduler-poll-lag-tolerance-ms")
        for field in ("certified_max_check_ms", "certified_max_scheduler_overhead_ms"):
            item = scheduler.get(field)
            if item is not None and not _is_number(item):
                errors.append(f"invalid-scheduler-{field.replace('_', '-')}")
        check_ms = scheduler.get("certified_max_check_ms")
        overhead_ms = scheduler.get("certified_max_scheduler_overhead_ms")
        if cap == 2:
            if not _is_number(check_ms) or check_ms > MAX_CERTIFIED_CHECK_MS:
                errors.append("cap-two-check-certification-invalid")
            if not _is_number(overhead_ms):
                errors.append("cap-two-overhead-certification-invalid")
            if _is_number(check_ms) and _is_number(overhead_ms) and _is_int(scheduler.get("poll_interval_ms"), 1):
                if cap * check_ms + overhead_ms > scheduler["poll_interval_ms"]:
                    errors.append("cap-two-scheduler-inequality-failed")

    budget = _strict(
        contract.get("aggregate_hard_budget"),
        {"tool_calls", "runtime_seconds", "compactions", "full_suite_runs", "mutations"},
        "aggregate-hard-budget",
        errors,
    )
    if budget is not None:
        for field in ("tool_calls", "runtime_seconds"):
            if not _is_int(budget.get(field), 1):
                errors.append(f"invalid-aggregate-hard-budget-{field.replace('_', '-')}")
        for field in ("compactions", "full_suite_runs", "mutations"):
            if not _is_int(budget.get(field)):
                errors.append(f"invalid-aggregate-hard-budget-{field.replace('_', '-')}")

    topology = _strict(
        contract.get("topology"),
        {"integration_root_identity", "shared_read_only_worktree"},
        "topology",
        errors,
    )
    if topology is not None:
        _validate_identity(topology.get("integration_root_identity"), "integration-root", errors)
        if not isinstance(topology.get("shared_read_only_worktree"), bool):
            errors.append("invalid-shared-read-only-worktree")
    if contract.get("allowed_actions") != list(POOL_ALLOWED_ACTIONS):
        errors.append("invalid-allowed-actions")
    capability_hash = contract.get("capability_receipt_sha256")
    if cap == 1 and capability_hash is not None:
        errors.append("cap-one-capability-receipt-must-be-null")
    if cap == 2 and not _is_sha256(capability_hash):
        errors.append("cap-two-capability-receipt-required")
    _validate_hash(contract, "contract_sha256", errors)
    _validate_replay(contract, "contract_sha256", seen_hashes, errors)
    return errors


def validate_capability_receipt(
    value: Any,
    *,
    expected_contract: Mapping[str, Any] | None = None,
    now: dt.datetime | None = None,
    seen_hashes: Iterable[str] | None = None,
) -> list[str]:
    errors: list[str] = []
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
    for field in ("adapter_id", "adapter_version", "execution_surface", "control_turn_id"):
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
    if receipt.get("requested_cap") != 2:
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
    scheduler_stats = _validate_stats(receipt.get("scheduler_overhead"), "scheduler-overhead", errors)
    capabilities = _strict(
        receipt.get("capabilities"),
        {"interrupt", "close", "wait", "trusted_telemetry"},
        "capabilities",
        errors,
    )
    if capabilities is not None and any(capabilities.get(name) is not True for name in capabilities):
        errors.append("required-capability-missing")
    if receipt.get("attestation_source") != "trusted-control-plane-session-metadata":
        errors.append("untrusted-attestation-source")
    if receipt.get("validation_outcome") != "accepted":
        errors.append("capability-not-accepted")
    if isinstance(callbacks, Mapping) and isinstance(callbacks.get("check"), Mapping):
        check_max = callbacks["check"].get("max_ms")
        if not _is_number(check_max) or check_max > MAX_CERTIFIED_CHECK_MS:
            errors.append("certified-check-ceiling-exceeded")
        if expected_contract is not None and scheduler_stats is not None:
            scheduler = expected_contract.get("scheduler", {})
            cap = expected_contract.get("max_active_workers")
            interval = scheduler.get("poll_interval_ms") if isinstance(scheduler, Mapping) else None
            overhead_max = scheduler_stats.get("max_ms")
            if _is_int(cap, 1) and _is_number(check_max) and _is_number(overhead_max) and _is_int(interval, 1):
                if cap * check_max + overhead_max > interval:
                    errors.append("capability-scheduler-inequality-failed")
    if expected_contract is not None:
        if receipt.get("control_turn_id") != expected_contract.get("control_turn_id"):
            errors.append("capability-control-turn-mismatch")
        if receipt.get("host_identity") != expected_contract.get("owner"):
            errors.append("capability-owner-mismatch")
        if receipt.get("requested_cap") != expected_contract.get("max_active_workers"):
            errors.append("capability-cap-mismatch")
        if receipt.get("receipt_sha256") != expected_contract.get("capability_receipt_sha256"):
            errors.append("capability-contract-hash-mismatch")
    _validate_hash(receipt, "receipt_sha256", errors)
    _validate_replay(receipt, "receipt_sha256", seen_hashes, errors)
    return errors


def _usage_sum(children: list[Mapping[str, Any]]) -> dict[str, Any] | None:
    usages = [child.get("last_cumulative_usage") for child in children]
    if not all(isinstance(usage, Mapping) for usage in usages):
        return None
    result = zero_usage()
    for field in ("tool_calls", "runtime_seconds", "compactions", "full_suite_runs", "mutations"):
        values = [usage.get(field) for usage in usages]
        if not all(_is_int(item) for item in values):
            return None
        result[field] = sum(values)
    token_values = [usage.get("tokens") for usage in usages]
    if all(isinstance(tokens, Mapping) and tokens.get("availability") == "available" for tokens in token_values):
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
    if not isinstance(children_value, list) or not 1 <= len(children_value) <= MAX_ACTIVE_WORKERS:
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
            _validate_usage(child.get("last_cumulative_usage"), f"child[{index}]-usage", errors)
            if not _nonempty(child.get("lease_id")):
                errors.append(f"invalid-child[{index}]-lease-id")
    child_ids = [child.get("child_id") for child in children]
    if len(child_ids) != len(set(child_ids)):
        errors.append("duplicate-child-id")
    if not set(active).issubset(set(child_ids)) or not set(terminal).issubset(set(child_ids)):
        errors.append("active-or-terminal-child-unknown")
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
    if expected_usage is not None and state.get("worker_seconds") != expected_usage["runtime_seconds"]:
        errors.append("worker-seconds-mismatch")
    lease_bindings = state.get("lease_bindings")
    if not isinstance(lease_bindings, list) or any(not _is_sha256(item) for item in lease_bindings):
        errors.append("invalid-lease-bindings")
    elif len(lease_bindings) != len(set(lease_bindings)):
        errors.append("duplicate-lease-binding")
    reasons = state.get("reasons")
    if not isinstance(reasons, list) or any(not _nonempty(item) for item in reasons):
        errors.append("invalid-reasons")
    if state.get("control_loss_scope") not in {None, "child", "pool"}:
        errors.append("invalid-control-loss-scope")
    if state.get("status") == "control-failed" and not reasons:
        errors.append("control-failed-requires-reason")
    if state.get("status") == "completed" and set(terminal) != set(child_ids):
        errors.append("completed-requires-terminal-cohort")
    if state.get("status") == "closed" and set(terminal) != set(child_ids):
        errors.append("closed-requires-terminal-cohort")
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
        expected_ids = [child.get("child_id") for child in contract_children if isinstance(child, Mapping)]
        if child_ids != expected_ids:
            errors.append("state-child-order-mismatch")
        if _is_int(state.get("scheduler_cursor")) and expected_ids and state["scheduler_cursor"] >= len(expected_ids):
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
            entry = _strict(item, {"child_id", "next_deadline_ns"}, f"deadline[{index}]", errors)
            if entry is None:
                continue
            if not _nonempty(entry.get("child_id")):
                errors.append(f"invalid-deadline[{index}]-child-id")
            else:
                deadline_ids.append(str(entry["child_id"]))
            if entry.get("next_deadline_ns") is not None and not _is_int(entry.get("next_deadline_ns")):
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
    if not isinstance(actions, list) or any(item not in POOL_ALLOWED_ACTIONS for item in actions):
        errors.append("invalid-required-control-actions")
    if contract is not None:
        for field in ("pool_id", "pool_epoch", "contract_sha256"):
            if decision.get(field) != contract.get(field):
                errors.append(f"decision-{field.replace('_', '-')}-mismatch")
        child_ids = [child.get("child_id") for child in contract.get("children", []) if isinstance(child, Mapping)]
        if selected is not None and selected not in child_ids:
            errors.append("selected-child-unknown")
        if isinstance(deadlines, list):
            deadline_ids = [item.get("child_id") for item in deadlines if isinstance(item, Mapping)]
            if deadline_ids != child_ids:
                errors.append("deadline-child-order-mismatch")
    if state is not None:
        if decision.get("state_sha256") != state.get("state_sha256"):
            errors.append("decision-state-sha256-mismatch")
        if decision.get("decision_sequence") != state.get("state_sequence"):
            errors.append("decision-sequence-mismatch")
        if decision.get("aggregate_usage") != state.get("aggregate_usage"):
            errors.append("decision-aggregate-usage-mismatch")
    _validate_hash(decision, "decision_sha256", errors)
    _validate_replay(decision, "decision_sha256", seen_hashes, errors)
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
    _validate_identity(lease.get("integration_root_identity"), "integration-root", errors)
    _validate_identity(lease.get("worktree_identity"), "worktree", errors)
    _validate_relative_paths(lease.get("target_paths"), "target-paths", allow_empty=False, errors=errors)
    _validate_owner(lease.get("owner"), "owner", errors)
    lifecycle = lease.get("lifecycle_state")
    if lifecycle not in {"acquired", "held", "release-pending", "released", "orphaned-active"}:
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
    if lifecycle == "released":
        if not _is_sha256(terminal_hash):
            errors.append("released-lease-terminal-evidence-required")
        if not _nonempty(reason):
            errors.append("released-lease-reason-required")
    elif terminal_hash is not None and not _is_sha256(terminal_hash):
        errors.append("invalid-terminal-evidence-sha256")
    if reason is not None and not _nonempty(reason):
        errors.append("invalid-release-reason")
    if contract is not None:
        for field in ("pool_id", "pool_epoch"):
            if lease.get(field) != contract.get(field):
                errors.append(f"lease-{field.replace('_', '-')}-mismatch")
        child = next(
            (
                item
                for item in contract.get("children", [])
                if isinstance(item, Mapping) and item.get("child_id") == lease.get("child_id")
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
            if lease.get("integration_root_identity") != contract.get("topology", {}).get("integration_root_identity"):
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
    seen_hashes: Iterable[str] | None = None,
) -> list[str]:
    errors: list[str] = []
    receipt = _strict(value, POOL_RECEIPT_FIELDS, "pool-receipt", errors)
    if receipt is None:
        return errors
    _validate_header(
        receipt,
        type_field="receipt_type",
        expected_type=POOL_RECEIPT_TYPE,
        expected_schema=POOL_RECEIPT_SCHEMA,
        errors=errors,
    )
    for field in ("pool_id", "pool_epoch"):
        if not _nonempty(receipt.get(field)):
            errors.append(f"invalid-{field.replace('_', '-')}")
    for field in ("contract_sha256", "terminal_state_sha256"):
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
    if not isinstance(poll_order, list) or any(not _nonempty(item) for item in poll_order):
        errors.append("invalid-poll-order")
    timing = _strict(
        receipt.get("timing"),
        {"max_callback_latency_ms", "max_poll_gap_ms", "poll_interval_ms", "poll_lag_tolerance_ms"},
        "timing",
        errors,
    )
    if timing is not None:
        for field in timing:
            if not _is_number(timing.get(field)):
                errors.append(f"invalid-timing-{field.replace('_', '-')}")
    child_receipts = receipt.get("child_terminal_receipts")
    child_receipt_ids: list[str] = []
    if not isinstance(child_receipts, list):
        errors.append("child-terminal-receipts-must-be-array")
    else:
        for index, item in enumerate(child_receipts):
            entry = _strict(item, {"child_id", "receipt_sha256"}, f"child-receipt[{index}]", errors)
            if entry is None:
                continue
            if not _nonempty(entry.get("child_id")):
                errors.append(f"invalid-child-receipt[{index}]-id")
            else:
                child_receipt_ids.append(str(entry["child_id"]))
            if not _is_sha256(entry.get("receipt_sha256")):
                errors.append(f"invalid-child-receipt[{index}]-sha256")
    if len(child_receipt_ids) != len(set(child_receipt_ids)):
        errors.append("duplicate-child-terminal-receipt")
    _validate_usage(receipt.get("final_aggregate_usage"), "final-aggregate-usage", errors)
    for field in ("pool_wall_seconds", "worker_seconds"):
        if not _is_number(receipt.get(field)):
            errors.append(f"invalid-{field.replace('_', '-')}")
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
            if entry.get("lifecycle_state") not in {"released", "release-pending", "orphaned-active"}:
                errors.append(f"invalid-lease-evidence[{index}]-state")
    if len(lease_ids) != len(set(lease_ids)):
        errors.append("duplicate-lease-evidence")
    mutation = _strict(
        receipt.get("mutation_evidence"),
        {"integration_root_clean", "shared_read_only_clean", "child_worktrees_clean", "evidence_sha256"},
        "mutation-evidence",
        errors,
    )
    if mutation is not None:
        for field in ("integration_root_clean", "shared_read_only_clean", "child_worktrees_clean"):
            if not isinstance(mutation.get(field), bool):
                errors.append(f"invalid-mutation-{field.replace('_', '-')}")
        if not _is_sha256(mutation.get("evidence_sha256")):
            errors.append("invalid-mutation-evidence-sha256")
    reasons = receipt.get("reasons")
    if not isinstance(reasons, list) or any(not _nonempty(item) for item in reasons):
        errors.append("invalid-reasons")
    dispositions = receipt.get("child_dispositions")
    disposition_ids: list[str] = []
    if not isinstance(dispositions, list):
        errors.append("child-dispositions-must-be-array")
    else:
        for index, item in enumerate(dispositions):
            entry = _strict(
                item,
                {"child_id", "session_disposition", "artifact_disposition"},
                f"child-disposition[{index}]",
                errors,
            )
            if entry is None:
                continue
            if not _nonempty(entry.get("child_id")):
                errors.append(f"invalid-child-disposition[{index}]-id")
            else:
                disposition_ids.append(str(entry["child_id"]))
            if entry.get("session_disposition") not in {"accepted", "accepted-with-warning", "quarantined"}:
                errors.append(f"invalid-child-disposition[{index}]-session")
            if entry.get("artifact_disposition") not in {
                "accepted",
                "independent-validation-required",
                "architect-adjudication-required",
                "rejected",
            }:
                errors.append(f"invalid-child-disposition[{index}]-artifact")
    if len(disposition_ids) != len(set(disposition_ids)):
        errors.append("duplicate-child-disposition")
    if receipt.get("pool_disposition") not in {"accepted", "partial", "quarantined", "rejected"}:
        errors.append("invalid-pool-disposition")
    if not isinstance(receipt.get("accepting"), bool):
        errors.append("invalid-accepting")
    if contract is not None:
        for field in ("pool_id", "pool_epoch", "contract_sha256", "capability_receipt_sha256"):
            if receipt.get(field) != contract.get(field):
                errors.append(f"receipt-{field.replace('_', '-')}-mismatch")
        child_ids = [child.get("child_id") for child in contract.get("children", []) if isinstance(child, Mapping)]
        if receipt.get("admission_order") != child_ids:
            errors.append("admission-order-mismatch")
        if set(receipt.get("terminal_order", [])) != set(child_ids):
            errors.append("terminal-order-mismatch")
        if child_receipt_ids != child_ids:
            errors.append("child-terminal-receipt-order-mismatch")
        if disposition_ids != child_ids:
            errors.append("child-disposition-order-mismatch")
        expected_leases = [child.get("lease_id") for child in contract.get("children", []) if isinstance(child, Mapping)]
        if lease_ids != expected_leases:
            errors.append("lease-evidence-order-mismatch")
    if terminal_state is not None:
        if receipt.get("terminal_state_sha256") != terminal_state.get("state_sha256"):
            errors.append("receipt-terminal-state-sha256-mismatch")
        if receipt.get("final_aggregate_usage") != terminal_state.get("aggregate_usage"):
            errors.append("receipt-aggregate-usage-mismatch")
        if receipt.get("pool_wall_seconds") != terminal_state.get("pool_wall_seconds"):
            errors.append("receipt-pool-wall-seconds-mismatch")
        if receipt.get("worker_seconds") != terminal_state.get("worker_seconds"):
            errors.append("receipt-worker-seconds-mismatch")
    if receipt.get("accepting") is True:
        if receipt.get("pool_disposition") != "accepted":
            errors.append("accepting-requires-accepted-disposition")
        if reasons:
            errors.append("accepting-requires-empty-reasons")
        if terminal_state is None or terminal_state.get("status") != "closed":
            errors.append("accepting-requires-closed-state")
        if isinstance(mutation, Mapping) and any(
            mutation.get(field) is not True
            for field in ("integration_root_clean", "shared_read_only_clean", "child_worktrees_clean")
        ):
            errors.append("accepting-requires-clean-mutation-evidence")
        if isinstance(lease_evidence, list) and any(
            not isinstance(item, Mapping) or item.get("lifecycle_state") != "released"
            for item in lease_evidence
        ):
            errors.append("accepting-requires-released-leases")
        if isinstance(dispositions, list) and any(
            not isinstance(item, Mapping)
            or item.get("session_disposition") not in {"accepted", "accepted-with-warning"}
            or item.get("artifact_disposition") != "accepted"
            for item in dispositions
        ):
            errors.append("accepting-requires-accepted-children")
    _validate_hash(receipt, "receipt_sha256", errors)
    _validate_replay(receipt, "receipt_sha256", seen_hashes, errors)
    return errors


def validate_pool_artifact(value: Any, **kwargs: Any) -> list[str]:
    if not isinstance(value, Mapping):
        return ["artifact-must-be-object"]
    artifact_type = value.get("contract_type") or value.get("state_type") or value.get("decision_type") or value.get("lease_type") or value.get("receipt_type")
    if artifact_type == POOL_CONTRACT_TYPE:
        return validate_pool_contract(value, seen_hashes=kwargs.get("seen_hashes"))
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
