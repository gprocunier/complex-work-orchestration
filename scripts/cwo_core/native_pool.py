"""Cooperative coordinator for a fixed native-worker supervision pool."""

from __future__ import annotations

import copy
import datetime as dt
import fcntl
import json
import os
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from .native_control import NativeControlTurn, validate_control_turn_contract
from .native_pool_capacity import load_pool_capacity
from .native_pool_contracts import (
    POOL_DECISION_SCHEMA,
    POOL_DECISION_TYPE,
    POOL_RECEIPT_SCHEMA,
    POOL_RECEIPT_TYPE,
    POOL_STATE_SCHEMA,
    POOL_STATE_TYPE,
    VERSION,
    canonical_sha256,
    seal_artifact,
    validate_capability_receipt,
    validate_pool_contract,
    validate_pool_control_request,
    validate_pool_decision,
    validate_pool_receipt,
    validate_pool_state,
    write_private_artifact,
    zero_usage,
)
from .native_pool_leases import PoolLeaseError, PoolLeaseRegistry, owner_identity_is_live
from .native_pool_scheduler import (
    AggregateUsageLedger,
    PoolAccountingError,
    PoolSchedulingError,
    exhausted_budget,
    mutation_evidence_sha256,
    normalize_usage,
    peer_deadline_guard,
    select_earliest_deadline,
    wait_seconds,
)
from .native_pool_schedulability import (
    PoolSchedulabilityError,
    SchedulingBudgetProof,
    latency_consumes_slack_fraction,
    scheduling_budget_proof,
)
from .native_authority import build_reason_records
from .native_stop_scope import (
    STOP_SCOPE_RANK,
    STOP_SCOPES,
    VerifiedScopeAuthority,
    build_stop_metadata,
    continuation_path,
    merge_stop_metadata,
    policy_scope_authority,
)


POOL_CALLBACKS = {
    "monotonic_ns",
    "sleep",
    "now_utc",
    "read_child_evidence",
    "compare_workspaces",
}
CHILD_EVIDENCE_FIELDS = {
    "state_sha256",
    "usage",
    "protected_fault",
    "control_loss",
    "reasons",
    "session_disposition",
    "artifact_disposition",
}
SESSION_DISPOSITIONS = {"accepted", "accepted-with-warning", "quarantined"}
ARTIFACT_DISPOSITIONS = {
    "accepted",
    "independent-validation-required",
    "architect-adjudication-required",
    "rejected",
}


def _read_only_fast_path_child_ids(
    children: Sequence[Mapping[str, Any]],
) -> frozenset[str]:
    """Return the immutable admission-validated read-only fast-path cohort."""

    return frozenset(
        str(child["child_id"])
        for child in children
        if child.get("isolation_class") == "read-only-shared"
        and isinstance(child.get("completion_evidence_policy"), Mapping)
        and child["completion_evidence_policy"].get("expected_mutation_mode")
        == "read-only"
        and child.get("declared_write_paths") == []
        and child.get("integration_target_paths") == []
    )


FAULT_SCOPE_POLICY_CAPS = {
    "child-fault": "child",
    "cohort-budget": "cohort",
    "cohort-control": "cohort",
    "execution-integrity": "execution-path",
}
POOL_LEASE_ERROR_CODES = {
    "boot-identity-empty",
    "boot-identity-unavailable",
    "integration-target-lease-collision",
    "invalid-lease-time",
    "lease-child-unknown",
    "lease-id-already-active",
    "lease-identity-invalid",
    "lease-invalid",
    "lease-not-found",
    "lease-registry-artifact-invalid",
    "lease-registry-duplicate-lease-id",
    "lease-registry-fields-invalid",
    "lease-registry-header-invalid",
    "lease-registry-leases-invalid",
    "lease-registry-lock-is-symlink",
    "lease-registry-path-is-symlink",
    "lease-registry-sha256-mismatch",
    "lease-registry-unreadable",
    "lease-release-requires-completed-or-closed-pool",
    "lease-time-must-be-timezone-aware",
    "lease-transition-not-allowed",
    "lease-transition-invalid",
    "owner-pid-invalid",
    "pool-contract-invalid",
    "process-identity-incomplete",
    "process-identity-malformed",
    "process-identity-unavailable",
    "process-start-ticks-invalid",
    "released-lease-cannot-transition",
    "stale-lease-transition-invalid",
    "terminal-pool-state-invalid",
    "worktree-lease-collision",
}


class NativePoolError(ValueError):
    """Raised when pool construction or trusted evidence fails closed."""


def _is_sha256(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _callback_name(phase: str) -> str | None:
    return {
        "start": "arm",
        "arm": "arm",
        "send-input": "send_input",
        "mark-dispatched": "mark_dispatched",
        "check": "check",
        "waiting": "check",
        "finalize-complete": "finalize",
        "close-complete": "close",
        "interrupt": "interrupt",
        "finalize-interrupt": "finalize",
        "close-interrupt": "close",
        "finalize-close": "finalize",
        "finalize-control-failed": "finalize",
    }.get(phase)


def _normalize_now(value: Any) -> dt.datetime:
    if isinstance(value, str):
        try:
            parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise NativePoolError("now-utc-invalid") from exc
    elif isinstance(value, dt.datetime):
        parsed = value
    else:
        raise NativePoolError("now-utc-invalid")
    if parsed.tzinfo is None:
        raise NativePoolError("now-utc-must-be-timezone-aware")
    return parsed.astimezone(dt.timezone.utc)


def _normalize_child_evidence(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != CHILD_EVIDENCE_FIELDS:
        raise NativePoolError("child-evidence-fields-invalid")
    if not _is_sha256(value.get("state_sha256")):
        raise NativePoolError("child-evidence-state-sha256-invalid")
    usage = normalize_usage(value.get("usage"))
    if not isinstance(value.get("protected_fault"), bool):
        raise NativePoolError("child-evidence-protected-fault-invalid")
    if not isinstance(value.get("control_loss"), bool):
        raise NativePoolError("child-evidence-control-loss-invalid")
    reasons = value.get("reasons")
    if not isinstance(reasons, list) or any(not isinstance(reason, str) or not reason for reason in reasons):
        raise NativePoolError("child-evidence-reasons-invalid")
    if value.get("session_disposition") not in SESSION_DISPOSITIONS:
        raise NativePoolError("child-evidence-session-disposition-invalid")
    if value.get("artifact_disposition") not in ARTIFACT_DISPOSITIONS:
        raise NativePoolError("child-evidence-artifact-disposition-invalid")
    return {**dict(value), "usage": usage, "reasons": list(reasons)}


def _sanitize_exception_message(error: BaseException) -> str:
    """Return bounded, single-line exception evidence safe for JSON artifacts."""
    try:
        message = " ".join(str(error).split())
    except BaseException:
        return "message-unavailable"
    message = "".join(character for character in message if character.isprintable())
    return message[:256] or "message-unavailable"


def _evidence_identifier(value: Any) -> str:
    text = str(value)
    if 1 <= len(text) <= 128 and all(
        character.isascii() and (character.isalnum() or character in "._-")
        for character in text
    ):
        return text
    return "sha256-" + canonical_sha256({"identifier": text})


def _pool_lease_error_evidence(error: PoolLeaseError) -> tuple[str, str]:
    message = _sanitize_exception_message(error)
    candidate = message.partition(":")[0]
    code = candidate if candidate in POOL_LEASE_ERROR_CODES else "unclassified"
    digest = canonical_sha256(
        {
            "error_type": type(error).__name__,
            "message": message,
        }
    )
    return code, digest


class NativePoolCoordinator:
    """Drive a bounded cohort with one native adapter callback per step."""

    def __init__(
        self,
        contract: Mapping[str, Any],
        child_contracts: Mapping[str, Mapping[str, Any]],
        task_inputs: Mapping[str, str],
        child_callbacks: Mapping[str, Mapping[str, Callable[..., Any]]],
        *,
        pool_callbacks: Mapping[str, Callable[..., Any]],
        lease_registry: PoolLeaseRegistry,
        capability_receipt: Mapping[str, Any] | None = None,
        state_file: Path | str | None = None,
        decision_file: Path | str | None = None,
        control_file: Path | str | None = None,
        policy_document: Mapping[str, Any] | None = None,
    ) -> None:
        self.capacity_limits = load_pool_capacity(policy_document)
        contract_errors = validate_pool_contract(
            contract,
            capacity_limits=self.capacity_limits,
        )
        if contract_errors:
            raise NativePoolError("pool-contract-invalid:" + ";".join(contract_errors))
        if not self.capacity_limits.is_released(
            contract.get("max_active_workers")
        ):
            raise NativePoolError("requested-capacity-not-released")
        # Keep the validated admission artifact isolated from caller mutation.
        # The fast-path cohort below must never widen after admission.
        self.contract = copy.deepcopy(dict(contract))
        self.children = [dict(child) for child in self.contract["children"]]
        self.child_ids = [str(child["child_id"]) for child in self.children]
        self._read_only_fast_path_children = _read_only_fast_path_child_ids(
            self.children
        )
        self._invalidated_read_only_fast_path_children: frozenset[str] = (
            frozenset()
        )
        self._deferred_read_only_workspace_check = False
        if set(child_contracts) != set(self.child_ids):
            raise NativePoolError("child-control-contract-set-mismatch")
        if set(task_inputs) != set(self.child_ids) or any(not isinstance(value, str) for value in task_inputs.values()):
            raise NativePoolError("task-input-set-mismatch")
        if set(child_callbacks) != set(self.child_ids):
            raise NativePoolError("child-callback-set-mismatch")
        if not isinstance(pool_callbacks, Mapping) or set(pool_callbacks) != POOL_CALLBACKS:
            raise NativePoolError("pool-callback-set-mismatch")
        if any(not callable(pool_callbacks[name]) for name in POOL_CALLBACKS):
            raise NativePoolError("pool-callback-noncallable")
        if not owner_identity_is_live(self.contract["owner"]):
            raise NativePoolError("pool-owner-identity-not-live")
        self.pool_callbacks = dict(pool_callbacks)
        self.lease_registry = lease_registry
        self.capability_receipt = dict(capability_receipt) if capability_receipt is not None else None
        self.state_file = Path(state_file).absolute() if state_file is not None else None
        self.decision_file = Path(decision_file).absolute() if decision_file is not None else None
        self.control_file = Path(control_file).absolute() if control_file is not None else None
        self._state_lock_handle: Any = None
        self._consumed_control_request_ids: set[str] = set()
        self._control_request_seen = False
        self._task_inputs = dict(task_inputs)
        self._callback_count = 0
        self._last_callback_name: str | None = None
        self._last_callback_latency_ms: float | None = None
        self._max_callback_latency_ms = 0.0
        self._callback_fault: str | None = None
        self._callback_fault_detail: dict[str, Any] | None = None
        self._poll_order: list[str] = []
        self._admission_order: list[str] = []
        self._terminal_order: list[str] = []
        self._last_poll_ns: dict[str, int | None] = {child_id: None for child_id in self.child_ids}
        self._max_poll_gap_ms = 0.0
        self._leases: dict[str, dict[str, Any]] = {}
        self._progress: dict[str, dict[str, Any]] = {
            child_id: {
                "status": "pending",
                "phase": "start",
                "wait_required": False,
                "wait_seconds": None,
                "receipt": None,
            }
            for child_id in self.child_ids
        }
        self._first_poll = {child_id: False for child_id in self.child_ids}
        self._dispositions = {
            child_id: {
                "session_disposition": "quarantined",
                "artifact_disposition": "rejected",
            }
            for child_id in self.child_ids
        }
        self._turns: dict[str, NativeControlTurn] = {}
        self._reasons: list[str] = []
        self._first_protected_fault: dict[str, Any] | None = None
        self._protected_fault = False
        self._control_failed = False
        self._ledger = AggregateUsageLedger(self.child_ids)
        self._started_ns = self._monotonic_ns()
        self._pool_wall_ns = 0
        self._callback_ns = 0
        self._noncallback_invoke_ns = 0
        self._coordinator_ns = 0
        self._wait_ns = 0
        self._wait_started_ns: int | None = None
        self._timing_frozen = False
        self._last_mutation_evidence = self._compare_workspaces("create")
        self._initial_mutation_fault = not all(
            self._last_mutation_evidence[field]
            for field in (
                "integration_root_clean",
                "shared_read_only_clean",
                "child_worktrees_clean",
            )
        )
        self._poll_overhead_seconds = 0.0
        self._terminal_comparison_complete = False
        self._receipt: dict[str, Any] | None = None
        self._decision: dict[str, Any] | None = None
        self._crash_cleanup_started = False
        self._crash_cleanup_complete = False
        self._stop_metadata = build_stop_metadata(
            "child",
            authority=policy_scope_authority(
                "native-pool-baseline-v1",
                authorized_scope="child",
            ),
        )

        self._certified_callback_max_ms: Mapping[str, Any] = {}
        self._certified_scheduler_overhead_ms = 0.0
        self._schedulability_proof: SchedulingBudgetProof | None = None
        self._slack_warning_fraction = 1.0
        self._slack_warning_active = False
        configured_capacity = self.contract["max_active_workers"]
        if self.capacity_limits.requires_capability_receipt(configured_capacity):
            if self.capability_receipt is None:
                raise NativePoolError("concurrent-capability-receipt-required")
            capability_errors = validate_capability_receipt(
                self.capability_receipt,
                expected_contract=self.contract,
                now=_normalize_now(self.pool_callbacks["now_utc"]()),
                capacity_limits=self.capacity_limits,
            )
            if capability_errors:
                raise NativePoolError("capability-receipt-invalid:" + ";".join(capability_errors))
            certification = self.capability_receipt["certification"]
            self._certified_callback_max_ms = certification["certified_callback_max_ms"]
            self._certified_scheduler_overhead_ms = float(
                certification["certified_scheduler_overhead_ms"]
            )
            self._slack_warning_fraction = float(
                certification["slack_warning_fraction"]
            )
            try:
                self._schedulability_proof = scheduling_budget_proof(
                    requested_workers=configured_capacity,
                    certified_callback_max_ms=(
                        self._certified_callback_max_ms
                    ),
                    certified_scheduler_overhead_ms=(
                        self._certified_scheduler_overhead_ms
                    ),
                    poll_interval_ms=self.contract["scheduler"][
                        "poll_interval_ms"
                    ],
                )
            except PoolSchedulabilityError as error:
                raise NativePoolError(
                    f"pool-schedulability-input-invalid:{error}"
                ) from error
            if not self._schedulability_proof.accepted:
                raise NativePoolError("pool-schedulability-proof-rejected")
        elif self.capability_receipt is not None:
            raise NativePoolError("single-worker-capability-receipt-forbidden")

        for child in self.children:
            child_id = child["child_id"]
            control_contract = dict(child_contracts[child_id])
            control_errors = validate_control_turn_contract(control_contract)
            if control_errors:
                raise NativePoolError(
                    f"child-control-contract-invalid:{child_id}:" + ";".join(control_errors)
                )
            bindings = {
                "state_file": child["state_file"],
                "agent_id": child["agent_id"],
                "control_turn_id": child["control_turn_id"],
                "control_contract_sha256": control_contract["contract_sha256"],
            }
            if any(control_contract[key] != value for key, value in bindings.items() if key != "control_contract_sha256"):
                raise NativePoolError(f"child-control-contract-binding-mismatch:{child_id}")
            if child["control_contract_sha256"] != control_contract["contract_sha256"]:
                raise NativePoolError(f"child-control-contract-sha256-mismatch:{child_id}")
            if control_contract["poll_interval_ms"] != self.contract["scheduler"]["poll_interval_ms"]:
                raise NativePoolError(f"child-poll-interval-mismatch:{child_id}")
            callbacks = self._wrap_callbacks(child_id, child_callbacks[child_id])
            self._turns[child_id] = NativeControlTurn(control_contract, callbacks)

        self._state = self._new_state()
        self._acquire_state_lock()
        try:
            self._persist_state()
        except Exception:
            self._release_state_lock()
            raise

    def _acquire_state_lock(self) -> None:
        if self.state_file is None:
            return
        lock_path = self.state_file.with_suffix(self.state_file.suffix + ".lock")
        if self.state_file.exists() and self.state_file.is_symlink():
            raise NativePoolError("pool-state-file-is-symlink")
        if lock_path.exists() and lock_path.is_symlink():
            raise NativePoolError("pool-state-lock-is-symlink")
        lock_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        lock_path.parent.chmod(0o700)
        handle = lock_path.open("a+", encoding="utf-8")
        os.fchmod(handle.fileno(), 0o600)
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            handle.close()
            raise NativePoolError("pool-state-lock-unavailable") from exc
        self._state_lock_handle = handle

    def _release_state_lock(self) -> None:
        handle = self._state_lock_handle
        if handle is None:
            return
        self._state_lock_handle = None
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        finally:
            try:
                handle.close()
            finally:
                if not handle.closed:
                    self._state_lock_handle = handle

    def _verify_state_watermark(self) -> None:
        if self.state_file is None:
            return
        try:
            current = json.loads(self.state_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise NativePoolError("pool-state-watermark-unreadable") from exc
        if current != self._state:
            raise NativePoolError("pool-state-watermark-mismatch")

    def _consume_control_request(self) -> bool:
        if self.control_file is None or self._control_request_seen or not self.control_file.exists():
            return False
        self._control_request_seen = True
        try:
            if self.control_file.is_symlink():
                raise NativePoolError("pool-control-file-is-symlink")
            stat = self.control_file.stat()
            if stat.st_uid != os.geteuid() or stat.st_mode & 0o077:
                raise NativePoolError("pool-control-file-permissions-invalid")
            request = json.loads(self.control_file.read_text(encoding="utf-8"))
            errors = validate_pool_control_request(
                request,
                contract=self.contract,
                state=self._state,
            )
            if errors:
                raise NativePoolError("pool-control-request-invalid:" + ";".join(errors))
            request_id = str(request["request_id"])
            if request_id in self._consumed_control_request_ids:
                return False
            self._consumed_control_request_ids.add(request_id)
            reason_hash = canonical_sha256({"reason": request["reason"]})
            self._enter_fault(
                f"external-control-request:{request_id}:{reason_hash}",
                control_failed=False,
                requested_stop_scope="cohort",
                scope_policy_rule="cohort-control",
            )
            return True
        except NativePoolError as exc:
            self._enter_fault(
                f"pool-control-request-failed:{type(exc).__name__}:{exc}",
                control_failed=False,
                requested_stop_scope="cohort",
                scope_policy_rule="cohort-control",
            )
            return True
        except (OSError, json.JSONDecodeError, TypeError) as exc:
            self._enter_fault(
                f"pool-control-request-failed:{type(exc).__name__}",
                control_failed=False,
                requested_stop_scope="cohort",
                scope_policy_rule="cohort-control",
            )
            return True

    def _monotonic_ns(self) -> int:
        value = self.pool_callbacks["monotonic_ns"]()
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise NativePoolError("monotonic-clock-invalid")
        return value

    def _capture_timing(self, now_ns: int, *, freeze: bool = False) -> None:
        """Reconcile mutually exclusive timing buckets against pool wall time."""
        if self._timing_frozen:
            return
        self._pool_wall_ns = max(0, now_ns - self._started_ns)
        attributed_ns = (
            self._callback_ns + self._noncallback_invoke_ns + self._wait_ns
        )
        self._coordinator_ns = max(0, self._pool_wall_ns - attributed_ns)
        self._poll_overhead_seconds = (
            self._noncallback_invoke_ns + self._coordinator_ns
        ) / 1_000_000_000
        if freeze:
            self._timing_frozen = True

    def _complete_wait(self) -> None:
        if self._wait_started_ns is None:
            return
        ended_ns = self._monotonic_ns()
        if not self._timing_frozen:
            self._wait_ns += max(0, ended_ns - self._wait_started_ns)
        self._wait_started_ns = None

    def _timing_receipt(self) -> dict[str, int | float | str]:
        return {
            "max_callback_latency_ms": self._max_callback_latency_ms,
            "max_poll_gap_ms": self._max_poll_gap_ms,
            "poll_interval_ms": self.contract["scheduler"]["poll_interval_ms"],
            "poll_lag_tolerance_ms": self.contract["scheduler"][
                "poll_lag_tolerance_ms"
            ],
            "accounting_version": "exclusive-v1",
            "callback_ns": self._callback_ns,
            "noncallback_invoke_ns": self._noncallback_invoke_ns,
            "coordinator_ns": self._coordinator_ns,
            "wait_ns": self._wait_ns,
        }

    def _compare_workspaces(self, phase: str) -> dict[str, Any]:
        try:
            value = self.pool_callbacks["compare_workspaces"](contract=self.contract, phase=phase)
            mutation_evidence_sha256(value)
        except (TypeError, ValueError, PoolSchedulingError) as exc:
            raise NativePoolError(f"workspace-comparison-failed:{exc}") from exc
        return dict(value)

    def _invalidate_read_only_fast_path(self) -> None:
        """Contain the optimized cohort and revoke its fast path for this run."""

        optimized_children = self._read_only_fast_path_children
        self._invalidated_read_only_fast_path_children = (
            self._invalidated_read_only_fast_path_children | optimized_children
        )
        for child_id in optimized_children:
            self._dispositions[child_id] = {
                "session_disposition": "quarantined",
                "artifact_disposition": "rejected",
            }
        self._read_only_fast_path_children = frozenset()
        self._deferred_read_only_workspace_check = False

    def _compare_deferred_workspace_on_control_failure(self) -> None:
        """Close the skipped-check interval before an abnormal terminal receipt."""

        if (
            not self._deferred_read_only_workspace_check
            or self._terminal_comparison_complete
        ):
            return
        try:
            self._last_mutation_evidence = self._compare_workspaces("close")
            if not all(
                self._last_mutation_evidence[field]
                for field in (
                    "integration_root_clean",
                    "shared_read_only_clean",
                    "child_worktrees_clean",
                )
            ):
                self._invalidate_read_only_fast_path()
                self._enter_fault(
                    "terminal-workspace-comparison-failed",
                    control_failed=True,
                    requested_stop_scope="execution-path",
                    scope_policy_rule="execution-integrity",
                )
            self._terminal_comparison_complete = True
        except NativePoolError as exc:
            self._invalidate_read_only_fast_path()
            self._enter_fault(
                str(exc),
                control_failed=True,
                requested_stop_scope="execution-path",
                scope_policy_rule="execution-integrity",
            )

    def _wrap_callbacks(
        self,
        child_id: str,
        callbacks: Mapping[str, Callable[..., Any]],
    ) -> dict[str, Callable[..., Any]]:
        if not isinstance(callbacks, Mapping):
            raise NativePoolError(f"child-callbacks-invalid:{child_id}")
        wrapped: dict[str, Callable[..., Any]] = {}
        for name, callback in callbacks.items():
            if not callable(callback):
                raise NativePoolError(f"child-callback-noncallable:{child_id}:{name}")

            def timed(*args: Any, _name: str = name, _callback: Callable[..., Any] = callback, **kwargs: Any) -> Any:
                started = self._monotonic_ns()
                self._callback_count += 1
                self._last_callback_name = _name
                try:
                    return _callback(*args, **kwargs)
                finally:
                    ended = self._monotonic_ns()
                    latency_ns = ended - started
                    latency_ms = latency_ns / 1_000_000
                    if latency_ms < 0:
                        self._callback_fault = "nonmonotonic-callback-clock"
                    if not self._timing_frozen:
                        self._callback_ns += max(0, latency_ns)
                    self._last_callback_latency_ms = max(0.0, latency_ms)
                    self._max_callback_latency_ms = max(
                        self._max_callback_latency_ms, self._last_callback_latency_ms
                    )
                    maximum = self._certified_callback_max_ms.get(_name)
                    if isinstance(maximum, (int, float)) and not isinstance(maximum, bool):
                        if self._last_callback_latency_ms > maximum:
                            self._callback_fault = f"callback-overrun:{_name}"
                            self._callback_fault_detail = {
                                "operation": _name,
                                "observed_callback_latency_ms": self._last_callback_latency_ms,
                                "certified_callback_max_ms": float(maximum),
                            }

            wrapped[name] = timed
        return wrapped

    def _new_state(self) -> dict[str, Any]:
        state = {
            "state_type": POOL_STATE_TYPE,
            "version": VERSION,
            "schema": POOL_STATE_SCHEMA,
            "pool_id": self.contract["pool_id"],
            "pool_epoch": self.contract["pool_epoch"],
            "contract_sha256": self.contract["contract_sha256"],
            "state_sequence": 0,
            "status": "created",
            "owner": self.contract["owner"],
            "coordinator_epoch": 0,
            "scheduler_cursor": 0,
            "active_children": [],
            "terminal_children": [],
            "children": [
                {
                    "ordinal": child["ordinal"],
                    "child_id": child["child_id"],
                    "status": "created",
                    "last_deadline_ns": None,
                    "next_deadline_ns": None,
                    "child_state_sha256": None,
                    "child_receipt_sha256": None,
                    "last_cumulative_usage": zero_usage(),
                    "lease_id": child["lease_id"],
                }
                for child in self.children
            ],
            "aggregate_usage": zero_usage(),
            "pool_started_monotonic_ns": self._started_ns,
            "pool_wall_seconds": 0.0,
            "worker_seconds": 0,
            "poll_overhead_seconds": 0.0,
            "lease_bindings": [],
            "reasons": [],
            "reason_records": [],
            "first_protected_fault": None,
            "control_loss_scope": None,
            **self._stop_metadata,
        }
        return seal_artifact(state, "state_sha256")

    def _child_state(self, child_id: str) -> dict[str, Any]:
        return next(child for child in self._state["children"] if child["child_id"] == child_id)

    def _add_reason(self, reason: str) -> None:
        if reason and reason not in self._reasons:
            self._reasons.append(reason)

    def _persist_state(self) -> None:
        errors = validate_pool_state(self._state, contract=self.contract)
        if errors:
            raise NativePoolError("pool-state-invalid:" + ";".join(errors))
        if self.state_file is not None:
            write_private_artifact(self.state_file, self._state)

    def _refresh_state(
        self,
        status: str,
        *,
        increment: bool = True,
        freeze_timing: bool = False,
    ) -> None:
        now = self._monotonic_ns()
        self._capture_timing(now, freeze=freeze_timing)
        active = [
            child_id
            for child_id in self.child_ids
            if self._progress[child_id]["status"] not in {"pending", "terminal"}
        ]
        terminal = [child_id for child_id in self.child_ids if self._progress[child_id]["status"] == "terminal"]
        self._state.update(
            {
                "state_sequence": self._state["state_sequence"] + (1 if increment else 0),
                "status": status,
                "active_children": active,
                "terminal_children": terminal,
                "aggregate_usage": self._ledger.aggregate,
                "pool_wall_seconds": self._pool_wall_ns / 1_000_000_000,
                "worker_seconds": self._ledger.aggregate["runtime_seconds"],
                "poll_overhead_seconds": self._poll_overhead_seconds,
                "lease_bindings": [
                    self._leases[child_id]["lease_sha256"]
                    for child_id in self.child_ids
                    if child_id in self._leases
                ],
                "reasons": list(self._reasons),
                "reason_records": build_reason_records(
                    self._reasons,
                    self._stop_metadata["scope_authority"],
                    detected_by="native-pool-supervision",
                ),
                "first_protected_fault": (
                    dict(self._first_protected_fault)
                    if self._first_protected_fault is not None
                    else None
                ),
                "control_loss_scope": "pool" if self._control_failed else None,
                **self._stop_metadata,
            }
        )
        self._state = seal_artifact(self._state, "state_sha256")
        self._persist_state()

    def _decision_for(
        self,
        *,
        decision: str,
        selected_child_id: str | None,
        actions: Sequence[str],
    ) -> dict[str, Any]:
        value = seal_artifact(
            {
                "decision_type": POOL_DECISION_TYPE,
                "version": VERSION,
                "schema": POOL_DECISION_SCHEMA,
                "pool_id": self.contract["pool_id"],
                "pool_epoch": self.contract["pool_epoch"],
                "contract_sha256": self.contract["contract_sha256"],
                "state_sha256": self._state["state_sha256"],
                "decision_sequence": self._state["state_sequence"],
                "decision": decision,
                "selected_child_id": selected_child_id,
                "deadlines": [
                    {
                        "child_id": child["child_id"],
                        "next_deadline_ns": child["next_deadline_ns"],
                    }
                    for child in self._state["children"]
                ],
                "observed_callback_latency_ms": self._last_callback_latency_ms,
                "aggregate_usage": self._state["aggregate_usage"],
                "reasons": list(self._reasons),
                "reason_records": build_reason_records(
                    self._reasons,
                    self._stop_metadata["scope_authority"],
                    detected_by="native-pool-supervision",
                ),
                "required_control_actions": list(actions),
                **self._stop_metadata,
            },
            "decision_sha256",
        )
        errors = validate_pool_decision(value, contract=self.contract, state=self._state)
        if errors:
            raise NativePoolError("pool-decision-invalid:" + ";".join(errors))
        if self.decision_file is not None:
            write_private_artifact(self.decision_file, value)
        self._decision = value
        return value

    def _enter_fault(
        self,
        reason: str,
        *,
        control_failed: bool,
        operation: str | None = None,
        observed_callback_latency_ms: float | None = None,
        certified_callback_max_ms: float | None = None,
        requested_stop_scope: str = "child",
        scope_authority: VerifiedScopeAuthority | None = None,
        authorized_continuation_paths: Sequence[Mapping[str, Any]] | None = None,
        affected_child_id: str | None = None,
        scope_policy_rule: str = "child-fault",
    ) -> None:
        if requested_stop_scope not in STOP_SCOPE_RANK:
            raise NativePoolError("fault-stop-scope-invalid")
        if scope_authority is not None and not isinstance(
            scope_authority, VerifiedScopeAuthority
        ):
            raise NativePoolError("verified-scope-authority-required")
        if scope_authority is None:
            policy_cap = FAULT_SCOPE_POLICY_CAPS.get(scope_policy_rule)
            if policy_cap is None:
                raise NativePoolError("fault-scope-policy-rule-invalid")
            scope_authority = policy_scope_authority(
                f"native-pool-fault-policy:{scope_policy_rule}",
                authorized_scope=policy_cap,
                source_sha256=canonical_sha256(
                    {
                        "reason": reason,
                        "requested_stop_scope": requested_stop_scope,
                        "scope_policy_rule": scope_policy_rule,
                        "operation": operation,
                        "affected_child_id": affected_child_id,
                    }
                ),
            )
        continuation_scope = STOP_SCOPES[
            min(
                STOP_SCOPE_RANK[requested_stop_scope],
                STOP_SCOPE_RANK[scope_authority.authorized_scope],
            )
        ]
        if authorized_continuation_paths is None:
            if continuation_scope == "child":
                authorized_continuation_paths = [
                    continuation_path(
                        "replace-child",
                        target_id=affected_child_id,
                        conditions=["fault-contained", "fresh-attempt"],
                    ),
                    continuation_path(
                        "continue-cohort",
                        conditions=["healthy-peer-evidence-preserved"],
                    ),
                ]
            elif continuation_scope == "cohort":
                authorized_continuation_paths = [
                    continuation_path(
                        "retry-cohort",
                        conditions=["fault-remediated", "new-pool-epoch"],
                    )
                ]
            elif continuation_scope == "execution-path":
                authorized_continuation_paths = [
                    continuation_path(
                        "alternate-execution-path",
                        conditions=["independent-validation"],
                    )
                ]
            elif continuation_scope == "complete-task":
                authorized_continuation_paths = [
                    continuation_path(
                        "task-remediation",
                        conditions=["architect-approved-remediation"],
                    )
                ]
            else:
                authorized_continuation_paths = [
                    continuation_path(
                        "operator-adjudication",
                        conditions=["new-verified-operator-directive"],
                    )
                ]
        incoming_stop = build_stop_metadata(
            requested_stop_scope,
            authority=scope_authority,
            authorized_continuation_paths=authorized_continuation_paths,
        )
        self._stop_metadata = merge_stop_metadata(self._stop_metadata, incoming_stop)
        if self._first_protected_fault is None:
            state_sequence = self._state["state_sequence"] if hasattr(self, "_state") else 0
            self._first_protected_fault = {
                "code": reason,
                "operation": operation,
                "observed_callback_latency_ms": observed_callback_latency_ms,
                "certified_callback_max_ms": certified_callback_max_ms,
                "latched_state_sequence": state_sequence,
            }
        self._add_reason(reason)
        self._protected_fault = True
        self._control_failed = self._control_failed or control_failed
        for child_id in self.child_ids:
            progress = self._progress[child_id]
            if progress["status"] == "pending":
                progress.update(
                    {
                        "status": "terminal",
                        "phase": "terminal",
                        "wait_required": False,
                        "receipt": {
                            "terminal_state": "control-failed",
                            "errors": [f"pool-not-admitted:{reason}"],
                        },
                    }
                )
                child = self._child_state(child_id)
                child["status"] = "control-failed"
                child["child_receipt_sha256"] = canonical_sha256(progress["receipt"])
                if child_id not in self._terminal_order:
                    self._terminal_order.append(child_id)
            elif progress["status"] != "terminal" and progress.get("phase") not in {
                "interrupt",
                "finalize-interrupt",
                "close-interrupt",
                "finalize-close",
                "finalize-control-failed",
            }:
                try:
                    progress.update(self._turns[child_id].request_interrupt(reason))
                except ValueError:
                    self._control_failed = True

    def request_interrupt(
        self,
        reason: str = "operator-request",
        *,
        stop_scope: str = "cohort",
        scope_authority: VerifiedScopeAuthority | None = None,
    ) -> dict[str, Any]:
        if not isinstance(reason, str) or not reason.strip():
            raise NativePoolError("interrupt-reason-invalid")
        if self._state["status"] in {"closed", "control-failed"}:
            return self.progress()
        if scope_authority is None:
            scope_authority = policy_scope_authority(
                "native-pool-explicit-interrupt-v1",
                authorized_scope="cohort",
                source_sha256=canonical_sha256({"reason": reason.strip()}),
            )
        elif (
            STOP_SCOPE_RANK.get(stop_scope, len(STOP_SCOPES))
            > STOP_SCOPE_RANK["cohort"]
            and scope_authority.source_type != "operator-directive"
        ):
            raise NativePoolError("broad-interrupt-requires-operator-directive")
        self._enter_fault(
            f"pool-interrupt:{reason.strip()}",
            control_failed=False,
            requested_stop_scope=stop_scope,
            scope_authority=scope_authority,
        )
        self._refresh_state("interrupt-pending")
        self._decision_for(decision="interrupt", selected_child_id=None, actions=["interrupt"])
        return self.progress()

    def _read_evidence(self, child_id: str) -> None:
        child_contract = next(child for child in self.children if child["child_id"] == child_id)
        try:
            evidence = _normalize_child_evidence(
                self.pool_callbacks["read_child_evidence"](
                    child_id=child_id,
                    state_file=child_contract["state_file"],
                )
            )
            observation = self._ledger.observe(
                child_id=child_id,
                child_state_sha256=evidence["state_sha256"],
                decision_sequence=self._state["state_sequence"] + 1,
                cumulative_usage=evidence["usage"],
            )
            child_state = self._child_state(child_id)
            child_state["child_state_sha256"] = evidence["state_sha256"]
            child_state["last_cumulative_usage"] = self._ledger.latest_for(child_id)
            if child_id not in self._invalidated_read_only_fast_path_children:
                self._dispositions[child_id] = {
                    "session_disposition": evidence["session_disposition"],
                    "artifact_disposition": evidence["artifact_disposition"],
                }
            for reason in evidence["reasons"]:
                self._add_reason(reason)
            budget_reasons = exhausted_budget(observation.aggregate, self.contract["aggregate_hard_budget"])
            if budget_reasons:
                for reason in budget_reasons:
                    self._add_reason(reason)
                self._enter_fault(
                    "aggregate-budget-exhausted",
                    control_failed=False,
                    requested_stop_scope="cohort",
                    scope_policy_rule="cohort-budget",
                )
            if evidence["control_loss"]:
                self._enter_fault(
                    "child-control-loss",
                    control_failed=True,
                    affected_child_id=child_id,
                )
            elif evidence["protected_fault"]:
                first_reason = (
                    evidence["reasons"][0]
                    if evidence["reasons"]
                    else "reason-unavailable"
                )
                self._enter_fault(
                    f"child-protected-fault:{first_reason}",
                    control_failed=False,
                    affected_child_id=child_id,
                )
        except (NativePoolError, PoolAccountingError, TypeError, ValueError) as exc:
            self._enter_fault(
                f"child-evidence-failed:{type(exc).__name__}:{exc}",
                control_failed=True,
                affected_child_id=child_id,
            )

    def _record_poll(self, child_id: str, now_ns: int) -> None:
        child = self._child_state(child_id)
        previous = self._last_poll_ns[child_id]
        if previous is None:
            gap_ms = (now_ns - self._started_ns) / 1_000_000
        else:
            gap_ms = (now_ns - previous) / 1_000_000
        if gap_ms < 0:
            self._enter_fault(
                "nonmonotonic-poll-clock",
                control_failed=True,
                requested_stop_scope="execution-path",
                scope_policy_rule="execution-integrity",
            )
            gap_ms = 0.0
        self._max_poll_gap_ms = max(self._max_poll_gap_ms, gap_ms)
        maximum = (
            self.contract["scheduler"]["poll_interval_ms"]
            + self.contract["scheduler"]["poll_lag_tolerance_ms"]
        )
        if gap_ms > maximum:
            self._enter_fault(
                "maximum-poll-gap-exceeded",
                control_failed=False,
                requested_stop_scope="cohort",
                scope_policy_rule="cohort-control",
            )
        child["last_deadline_ns"] = child["next_deadline_ns"] if child["next_deadline_ns"] is not None else now_ns
        child["next_deadline_ns"] = now_ns + self.contract["scheduler"]["poll_interval_ms"] * 1_000_000
        self._last_poll_ns[child_id] = now_ns
        self._poll_order.append(child_id)
        if not self._first_poll[child_id]:
            self._first_poll[child_id] = True
            self._admission_order.append(child_id)
            if child_id in self._leases:
                try:
                    self._leases[child_id] = self.lease_registry.hold(child["lease_id"])
                except PoolLeaseError as error:
                    self._record_lease_failure(
                        child_id,
                        "hold",
                        "held",
                        error,
                        control_failed=True,
                    )

    def _update_child_progress(self, child_id: str, progress: Mapping[str, Any]) -> None:
        self._progress[child_id] = dict(progress)
        child = self._child_state(child_id)
        phase = str(progress.get("phase"))
        if progress.get("status") == "terminal":
            receipt = progress.get("receipt")
            terminal_state = receipt.get("terminal_state") if isinstance(receipt, Mapping) else None
            child["status"] = "control-failed" if terminal_state == "control-failed" else "closed"
            child["next_deadline_ns"] = None
            child["child_receipt_sha256"] = canonical_sha256(receipt)
            if child_id not in self._terminal_order:
                self._terminal_order.append(child_id)
            if terminal_state == "control-failed":
                self._enter_fault("child-control-turn-failed", control_failed=True)
        elif phase in {"send-input", "mark-dispatched"}:
            child["status"] = "armed"
        elif phase in {"interrupt", "finalize-interrupt", "close-interrupt", "finalize-close"}:
            child["status"] = "interrupt-pending" if phase != "finalize-close" else "interrupt-confirmed"
        elif phase in {"finalize-complete", "close-complete"}:
            child["status"] = "completed"
            child["next_deadline_ns"] = None
        else:
            child["status"] = "running"

    def _invoke_child(self, child_id: str, *, poll: bool = False) -> None:
        turn = self._turns[child_id]
        progress = self._progress[child_id]
        self._callback_count = 0
        self._last_callback_name = None
        self._last_callback_latency_ms = None
        self._callback_fault = None
        self._callback_fault_detail = None
        self._slack_warning_active = False
        started = self._monotonic_ns()
        callback_started_ns = self._callback_ns
        try:
            if progress["status"] == "pending":
                result = turn.step(self._task_inputs[child_id])
            elif poll and progress.get("wait_required"):
                turn.resume_after_wait()
                result = turn.step()
            else:
                result = turn.step()
        finally:
            ended = self._monotonic_ns()
            callback_ns = self._callback_ns - callback_started_ns
            if not self._timing_frozen:
                self._noncallback_invoke_ns += max(
                    0,
                    ended - started - callback_ns,
                )
        if self._callback_count > 1:
            self._enter_fault("more-than-one-adapter-callback-in-step", control_failed=True)
        self._update_child_progress(child_id, result)
        if self._callback_count == 1:
            if (
                self._schedulability_proof is not None
                and self._last_callback_latency_ms is not None
            ):
                self._slack_warning_active = (
                    latency_consumes_slack_fraction(
                        self._schedulability_proof,
                        observed_latency_ms=self._last_callback_latency_ms,
                        warning_fraction=self._slack_warning_fraction,
                    )
                )
            self._read_evidence(child_id)
            if self._last_callback_name == "check":
                if result.get("phase") in {"waiting", "finalize-complete", "interrupt"}:
                    self._record_poll(child_id, ended)
                else:
                    self._enter_fault("child-check-failed", control_failed=True)
            if self._callback_fault:
                detail = self._callback_fault_detail or {}
                self._enter_fault(
                    self._callback_fault,
                    control_failed=False,
                    operation=detail.get("operation"),
                    observed_callback_latency_ms=detail.get("observed_callback_latency_ms"),
                    certified_callback_max_ms=detail.get("certified_callback_max_ms"),
                )
            if child_id in self._read_only_fast_path_children:
                self._deferred_read_only_workspace_check = True
            else:
                try:
                    mutation = self._compare_workspaces(
                        f"after-{child_id}-{self._last_callback_name}"
                    )
                    self._last_mutation_evidence = mutation
                    if not all(
                        mutation[field]
                        for field in (
                            "integration_root_clean",
                            "shared_read_only_clean",
                            "child_worktrees_clean",
                        )
                    ):
                        if self._read_only_fast_path_children:
                            self._invalidate_read_only_fast_path()
                        self._enter_fault(
                            "workspace-mutation-attribution-failed",
                            control_failed=False,
                            requested_stop_scope="execution-path",
                            scope_policy_rule="execution-integrity",
                        )
                    else:
                        self._deferred_read_only_workspace_check = False
                except NativePoolError as exc:
                    if self._read_only_fast_path_children:
                        self._invalidate_read_only_fast_path()
                    self._enter_fault(
                        str(exc),
                        control_failed=True,
                        requested_stop_scope="execution-path",
                        scope_policy_rule="execution-integrity",
                    )

    def _next_lifecycle_child(self, now_ns: int) -> tuple[str | None, bool, float]:
        state_children = self._state["children"]
        due = select_earliest_deadline(state_children, cursor=self._state["scheduler_cursor"])
        if due is not None and due.deadline_ns <= now_ns:
            self._state["scheduler_cursor"] = due.next_cursor
            return due.child_id, True, 0.0

        proposed: str | None = None
        for child_id in self.child_ids:
            progress = self._progress[child_id]
            if progress["status"] == "pending" or (
                progress["status"] != "terminal" and not progress.get("wait_required")
            ):
                proposed = child_id
                break
        if proposed is not None:
            phase = str(self._progress[proposed].get("phase"))
            callback = _callback_name(phase)
            maximum = self._certified_callback_max_ms.get(callback, 0) if callback else 0
            guard = peer_deadline_guard(
                state_children,
                cursor=self._state["scheduler_cursor"],
                proposed_child_id=proposed,
                now_ns=now_ns,
                certified_callback_ms=float(maximum),
                certified_peer_check_ms=float(
                    self._certified_callback_max_ms.get("check", 0)
                ),
                certified_scheduler_overhead_ms=self._certified_scheduler_overhead_ms,
            )
            if guard is not None:
                self._state["scheduler_cursor"] = guard.next_cursor
                return guard.child_id, True, 0.0
            return proposed, False, 0.0
        if due is None:
            return None, False, 0.0
        return None, False, wait_seconds(now_ns, due.deadline_ns)

    def _all_terminal(self) -> bool:
        return all(self._progress[child_id]["status"] == "terminal" for child_id in self.child_ids)

    def _status_after_action(self) -> str:
        if self._protected_fault and not self._all_terminal():
            return "interrupt-pending"
        if self._all_terminal():
            return "control-failed" if self._control_failed else "completed"
        if not all(self._first_poll.values()):
            return "admitting"
        if any(self._progress[child_id]["status"] == "terminal" for child_id in self.child_ids):
            return "draining"
        return "running"

    def _record_lease_failure(
        self,
        child_id: str,
        operation: str,
        target_state: str,
        error: PoolLeaseError,
        *,
        control_failed: bool,
    ) -> str:
        prefix = {
            "acquire": "lease-acquisition-failed",
            "hold": "lease-hold-failed",
            "mark-release-pending": "lease-release-pending-failed",
            "release": "lease-release-failed",
        }[operation]
        error_code, evidence_sha256 = _pool_lease_error_evidence(error)
        reason = (
            f"{prefix}:child={_evidence_identifier(child_id)}:"
            f"lease={_evidence_identifier(self._child_state(child_id)['lease_id'])}:"
            f"target={target_state}:error={error_code}:evidence={evidence_sha256}"
        )
        self._enter_fault(
            reason,
            control_failed=control_failed,
            affected_child_id=child_id,
        )
        return reason

    def _mark_lease_release_pending(
        self,
        child_id: str,
        *,
        terminal_evidence_sha256: str,
        reason: str,
    ) -> bool:
        lease = self._leases.get(child_id)
        if lease is None or lease["lifecycle_state"] in {"released", "release-pending"}:
            return False
        self._leases[child_id] = self.lease_registry.mark_release_pending(
            lease["lease_id"],
            terminal_evidence_sha256=terminal_evidence_sha256,
            reason=reason,
        )
        return True

    def _release_lease(
        self,
        child_id: str,
        *,
        terminal_state: Mapping[str, Any],
        reason: str = "pool-closed",
    ) -> bool:
        lease = self._leases.get(child_id)
        if lease is None or lease["lifecycle_state"] == "released":
            return False
        self._leases[child_id] = self.lease_registry.release(
            lease["lease_id"],
            terminal_state=terminal_state,
            reason=reason,
        )
        return True

    def _release_next(self) -> bool:
        attempted = False
        for child_id in self.child_ids:
            lease = self._leases.get(child_id)
            if lease is None or lease["lifecycle_state"] == "released":
                continue
            attempted = True
            try:
                if self._release_lease(child_id, terminal_state=self._state):
                    return True
            except PoolLeaseError as error:
                self._record_lease_failure(
                    child_id,
                    "release",
                    "released",
                    error,
                    control_failed=True,
                )
        return attempted

    def _finish_control_failed(self) -> None:
        self._compare_deferred_workspace_on_control_failure()
        terminal_hash = self._state["state_sha256"]
        for child_id in self.child_ids:
            try:
                self._mark_lease_release_pending(
                    child_id,
                    terminal_evidence_sha256=terminal_hash,
                    reason="pool-control-failed",
                )
            except PoolLeaseError as error:
                self._record_lease_failure(
                    child_id,
                    "mark-release-pending",
                    "release-pending",
                    error,
                    control_failed=True,
                )
        self._refresh_state("control-failed", freeze_timing=True)
        self._receipt = self._build_receipt()
        self._release_state_lock()

    def _record_crash_cleanup_error(
        self,
        stage: str,
        error: BaseException,
        *,
        child_id: str | None = None,
    ) -> None:
        child = f":{child_id}" if child_id is not None else ""
        self._add_reason(
            f"coordinator-crash-cleanup-error:{stage}{child}:"
            f"{type(error).__name__}:{_sanitize_exception_message(error)}"
        )

    def _seal_crash_state(self, *, increment: bool) -> None:
        self._capture_timing(self._monotonic_ns(), freeze=True)
        aggregate_usage = zero_usage()
        token_values: list[Mapping[str, Any]] = []
        for child in self._state["children"]:
            usage = child.get("last_cumulative_usage")
            if isinstance(usage, Mapping):
                for field in (
                    "tool_calls",
                    "runtime_seconds",
                    "compactions",
                    "full_suite_runs",
                    "mutations",
                ):
                    value = usage.get(field)
                    if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
                        aggregate_usage[field] += value
                tokens = usage.get("tokens")
                if isinstance(tokens, Mapping):
                    token_values.append(tokens)
        token_fields = ("input", "cached_input", "output", "reasoning", "total")
        if len(token_values) == len(self._state["children"]) and all(
            tokens.get("availability") == "available"
            and all(
                isinstance(tokens.get(field), int)
                and not isinstance(tokens.get(field), bool)
                and tokens[field] >= 0
                for field in token_fields
            )
            for tokens in token_values
        ):
            aggregate_usage["tokens"] = {
                "availability": "available",
                **{
                    field: sum(tokens[field] for tokens in token_values)
                    for field in token_fields
                },
                "unavailable_reason": None,
            }
        self._state.update(
            {
                "state_sequence": self._state["state_sequence"] + (1 if increment else 0),
                "status": "control-failed",
                "active_children": [],
                "terminal_children": list(self.child_ids),
                "aggregate_usage": aggregate_usage,
                "pool_wall_seconds": self._pool_wall_ns / 1_000_000_000,
                "worker_seconds": aggregate_usage["runtime_seconds"],
                "poll_overhead_seconds": self._poll_overhead_seconds,
                "lease_bindings": [
                    self._leases[child_id]["lease_sha256"]
                    for child_id in self.child_ids
                    if child_id in self._leases
                ],
                "reasons": list(self._reasons),
                "reason_records": build_reason_records(
                    self._reasons,
                    self._stop_metadata["scope_authority"],
                    detected_by="native-pool-supervision",
                ),
                "first_protected_fault": (
                    dict(self._first_protected_fault)
                    if self._first_protected_fault is not None
                    else None
                ),
                "control_loss_scope": "pool",
                **self._stop_metadata,
            }
        )
        self._state = seal_artifact(self._state, "state_sha256")

    def _persist_crash_state(self) -> bool:
        for stage in ("persist-state", "persist-state-retry"):
            try:
                self._seal_crash_state(increment=False)
                self._persist_state()
                return True
            except BaseException as error:
                self._record_crash_cleanup_error(stage, error)
        return False

    def _classify_crash(
        self,
        original_error: BaseException,
        *,
        crash_reason: str,
        affected_child_ids: Sequence[str],
    ) -> None:
        crash_authority = policy_scope_authority(
            "native-pool-coordinator-crash-v1",
            authorized_scope="execution-path",
            source_sha256=canonical_sha256(
                {
                    "crash_reason": crash_reason,
                    "exception_type": type(original_error).__name__,
                    "affected_child_ids": list(affected_child_ids),
                }
            ),
        )
        self._stop_metadata = merge_stop_metadata(
            self._stop_metadata,
            build_stop_metadata(
                "execution-path",
                authority=crash_authority,
                authorized_continuation_paths=[
                    continuation_path(
                        "alternate-execution-path",
                        conditions=["coordinator-remediated", "independent-validation"],
                    )
                ],
            ),
        )
        if self._first_protected_fault is None:
            self._first_protected_fault = {
                "code": crash_reason,
                "operation": None,
                "observed_callback_latency_ms": None,
                "certified_callback_max_ms": None,
                "latched_state_sequence": self._state["state_sequence"],
            }
        self._add_reason(crash_reason)
        affected = ",".join(affected_child_ids) if affected_child_ids else "none"
        self._add_reason(f"coordinator-crash-affected-children:{affected}")
        self._protected_fault = True
        self._control_failed = True
        self._receipt = None
        self._decision = None
        for child_id in self.child_ids:
            progress = self._progress[child_id]
            child = self._child_state(child_id)
            if progress["status"] != "terminal":
                receipt = {
                    "terminal_state": "control-failed",
                    "errors": [f"coordinator-crash:{type(original_error).__name__}"],
                }
                progress.update(
                    {
                        "status": "terminal",
                        "phase": "terminal",
                        "wait_required": False,
                        "wait_seconds": None,
                        "receipt": receipt,
                    }
                )
                child["child_receipt_sha256"] = canonical_sha256(receipt)
            if child["status"] not in {"closed", "control-failed"}:
                child["status"] = "control-failed"
            child["next_deadline_ns"] = None
            if child_id not in self._terminal_order:
                self._terminal_order.append(child_id)
        self._seal_crash_state(increment=not self._crash_cleanup_started)

    def _cleanup_on_crash(self, original_error: BaseException) -> None:
        """Contain an unhandled coordinator failure without replacing its exception."""
        if self._crash_cleanup_complete:
            return
        affected_child_ids = [
            child_id
            for child_id in self.child_ids
            if self._progress[child_id]["status"] != "terminal"
            or (
                child_id in self._leases
                and self._leases[child_id]["lifecycle_state"] != "released"
            )
        ]
        crash_reason = (
            f"coordinator-crash:{type(original_error).__name__}:"
            f"{_sanitize_exception_message(original_error)}"
        )
        try:
            self._classify_crash(
                original_error,
                crash_reason=crash_reason,
                affected_child_ids=affected_child_ids,
            )
        except BaseException as error:
            self._record_crash_cleanup_error("classify", error)
        self._crash_cleanup_started = True

        terminal_hash = self._state["state_sha256"]
        for child_id in self.child_ids:
            try:
                self._mark_lease_release_pending(
                    child_id,
                    terminal_evidence_sha256=terminal_hash,
                    reason="coordinator-crash",
                )
            except PoolLeaseError as error:
                self._record_lease_failure(
                    child_id,
                    "mark-release-pending",
                    "release-pending",
                    error,
                    control_failed=True,
                )
            except BaseException as error:
                self._record_crash_cleanup_error(
                    "mark-release-pending", error, child_id=child_id
                )

        for child_id in self.child_ids:
            try:
                self._release_lease(
                    child_id,
                    terminal_state=self._state,
                    reason="coordinator-crash",
                )
            except PoolLeaseError as error:
                self._record_lease_failure(
                    child_id,
                    "release",
                    "released",
                    error,
                    control_failed=True,
                )
            except BaseException as error:
                self._record_crash_cleanup_error("release-lease", error, child_id=child_id)

        persisted = self._persist_crash_state()
        try:
            self._release_state_lock()
        except BaseException as error:
            self._record_crash_cleanup_error("release-state-lock", error)
            persisted = self._persist_crash_state()
            try:
                self._release_state_lock()
            except BaseException as retry_error:
                self._record_crash_cleanup_error("release-state-lock-retry", retry_error)
                persisted = self._persist_crash_state()
        leases_contained = all(
            lease["lifecycle_state"] in {"release-pending", "released"}
            for lease in self._leases.values()
        )
        self._crash_cleanup_complete = (
            persisted and self._state_lock_handle is None and leases_contained
        )

    def _build_receipt(self) -> dict[str, Any]:
        child_receipts = []
        dispositions = []
        for child_id in self.child_ids:
            child = self._child_state(child_id)
            receipt_hash = child.get("child_receipt_sha256") or canonical_sha256(
                {"child_id": child_id, "terminal_state": "control-failed", "reason": "not-admitted"}
            )
            child_receipts.append({"child_id": child_id, "receipt_sha256": receipt_hash})
            dispositions.append({"child_id": child_id, **self._dispositions[child_id]})
        lease_evidence = [
            {
                "lease_id": self._leases[child_id]["lease_id"],
                "lease_sha256": self._leases[child_id]["lease_sha256"],
                "lifecycle_state": self._leases[child_id]["lifecycle_state"],
            }
            for child_id in self.child_ids
            if child_id in self._leases
        ]
        clean = all(
            self._last_mutation_evidence[field]
            for field in ("integration_root_clean", "shared_read_only_clean", "child_worktrees_clean")
        )
        accepting = (
            self._state["status"] == "closed"
            and not self._reasons
            and self._first_protected_fault is None
            and self._admission_order == self.child_ids
            and clean
            and len(lease_evidence) == len(self.child_ids)
            and all(item["lifecycle_state"] == "released" for item in lease_evidence)
            and all(
                item["session_disposition"] in {"accepted", "accepted-with-warning"}
                and item["artifact_disposition"] == "accepted"
                for item in dispositions
            )
        )
        accepted_children = sum(
            item["artifact_disposition"] == "accepted" for item in dispositions
        )
        pool_disposition = (
            "accepted"
            if accepting
            else "quarantined"
            if self._protected_fault or self._control_failed
            else "partial"
            if accepted_children
            else "rejected"
        )
        value = seal_artifact(
            {
                "receipt_type": POOL_RECEIPT_TYPE,
                "version": VERSION,
                "schema": POOL_RECEIPT_SCHEMA,
                "pool_id": self.contract["pool_id"],
                "pool_epoch": self.contract["pool_epoch"],
                "contract_sha256": self.contract["contract_sha256"],
                "terminal_state_sha256": self._state["state_sha256"],
                "capability_receipt_sha256": self.contract["capability_receipt_sha256"],
                "admission_order": list(self._admission_order),
                "poll_order": list(self._poll_order),
                "terminal_order": list(self._terminal_order),
                "timing": self._timing_receipt(),
                "child_terminal_receipts": child_receipts,
                "final_aggregate_usage": self._state["aggregate_usage"],
                "pool_wall_seconds": self._state["pool_wall_seconds"],
                "worker_seconds": self._state["worker_seconds"],
                "lease_evidence": lease_evidence,
                "mutation_evidence": dict(self._last_mutation_evidence),
                "reasons": list(self._reasons),
                "reason_records": build_reason_records(
                    self._reasons,
                    self._stop_metadata["scope_authority"],
                    detected_by="native-pool-supervision",
                ),
                "first_protected_fault": (
                    dict(self._first_protected_fault)
                    if self._first_protected_fault is not None
                    else None
                ),
                "child_dispositions": dispositions,
                "pool_disposition": pool_disposition,
                "accepting": accepting,
                **self._stop_metadata,
            },
            "receipt_sha256",
        )
        errors = validate_pool_receipt(value, contract=self.contract, terminal_state=self._state)
        if errors:
            raise NativePoolError("pool-receipt-invalid:" + ";".join(errors))
        return value

    def _contain_state_watermark_failure(self, error: NativePoolError) -> dict[str, Any]:
        self._enter_fault(
            str(error),
            control_failed=False,
            requested_stop_scope="execution-path",
            scope_policy_rule="execution-integrity",
        )
        status = self._status_after_action()
        self._refresh_state(status)
        self._decision_for(decision="interrupt", selected_child_id=None, actions=["interrupt"])
        return self.progress()

    def _step_once(self) -> dict[str, Any]:
        """Advance one deterministic pool step and never sleep."""
        if self._state["status"] == "closed":
            return self.progress()
        if self._state["status"] == "control-failed":
            if self._receipt is None:
                self._finish_control_failed()
                self._decision_for(decision="control-lost", selected_child_id=None, actions=[])
            return self.progress()
        try:
            self._verify_state_watermark()
        except NativePoolError as exc:
            return self._contain_state_watermark_failure(exc)
        if self._consume_control_request():
            self._refresh_state(self._status_after_action())
            self._decision_for(
                decision="interrupt",
                selected_child_id=None,
                actions=["interrupt"],
            )
            return self.progress()
        if self._state["status"] == "created":
            if self._initial_mutation_fault:
                self._enter_fault(
                    "initial-workspace-comparison-failed",
                    control_failed=False,
                    requested_stop_scope="execution-path",
                    scope_policy_rule="execution-integrity",
                )
                self._refresh_state(self._status_after_action())
                self._decision_for(decision="interrupt", selected_child_id=None, actions=["interrupt"])
                return self.progress()
            status = (
                "capability-validated"
                if self.capacity_limits.requires_capability_receipt(
                    self.contract["max_active_workers"]
                )
                else "admitting"
            )
            self._refresh_state(status)
            self._decision_for(decision="continue", selected_child_id=None, actions=["admit"])
            return self.progress()

        if self._state["status"] == "completed":
            if not self._terminal_comparison_complete:
                try:
                    self._last_mutation_evidence = self._compare_workspaces("close")
                    if not all(
                        self._last_mutation_evidence[field]
                        for field in (
                            "integration_root_clean",
                            "shared_read_only_clean",
                            "child_worktrees_clean",
                        )
                    ):
                        if self._read_only_fast_path_children:
                            self._invalidate_read_only_fast_path()
                        self._enter_fault(
                            "terminal-workspace-comparison-failed",
                            control_failed=False,
                            requested_stop_scope="execution-path",
                            scope_policy_rule="execution-integrity",
                        )
                    self._terminal_comparison_complete = True
                except NativePoolError as exc:
                    if self._read_only_fast_path_children:
                        self._invalidate_read_only_fast_path()
                    self._enter_fault(
                        str(exc),
                        control_failed=True,
                        requested_stop_scope="execution-path",
                        scope_policy_rule="execution-integrity",
                    )
                if self._control_failed:
                    self._refresh_state("control-failed")
                    self._finish_control_failed()
                    self._decision_for(decision="control-lost", selected_child_id=None, actions=[])
                    return self.progress()
                self._refresh_state("completed")
                self._decision_for(
                    decision="continue",
                    selected_child_id=None,
                    actions=["release-leases"],
                )
                return self.progress()
            if self._release_next():
                if self._control_failed:
                    self._refresh_state("control-failed")
                    self._finish_control_failed()
                    self._decision_for(
                        decision="control-lost",
                        selected_child_id=None,
                        actions=[],
                    )
                else:
                    self._refresh_state("completed")
                    self._decision_for(
                        decision="continue",
                        selected_child_id=None,
                        actions=["release-leases"],
                    )
                return self.progress()
            self._refresh_state("closed", freeze_timing=True)
            self._receipt = self._build_receipt()
            self._decision_for(decision="complete", selected_child_id=None, actions=["finalize"])
            self._release_state_lock()
            return self.progress()

        if not self._protected_fault:
            pending_child = None
            for index, child_id in enumerate(self.child_ids):
                if self._progress[child_id]["status"] != "pending":
                    continue
                if all(self._first_poll[prior] for prior in self.child_ids[:index]):
                    pending_child = child_id
                break
            if pending_child is not None and pending_child not in self._leases:
                try:
                    self._leases[pending_child] = self.lease_registry.acquire(
                        self.contract, pending_child
                    )
                except PoolLeaseError as exc:
                    self._record_lease_failure(
                        pending_child,
                        "acquire",
                        "acquired",
                        exc,
                        control_failed=False,
                    )
                status = self._status_after_action()
                self._refresh_state(status)
                decision = "interrupt" if self._protected_fault else "continue"
                actions = ["interrupt"] if self._protected_fault else ["admit"]
                self._decision_for(
                    decision=decision,
                    selected_child_id=pending_child,
                    actions=actions,
                )
                return self.progress()

        now_ns = self._monotonic_ns()
        selected, poll, wait_for = self._next_lifecycle_child(now_ns)
        if selected is None:
            if self._all_terminal():
                status = self._status_after_action()
                self._refresh_state(status)
                if status == "control-failed":
                    self._finish_control_failed()
                    self._decision_for(decision="control-lost", selected_child_id=None, actions=[])
                else:
                    self._decision_for(decision="complete", selected_child_id=None, actions=["release-leases"])
                return self.progress()
            self._refresh_state(self._status_after_action())
            self._decision_for(decision="continue", selected_child_id=None, actions=["step"])
            progress = self.progress()
            progress["wait_required"] = True
            progress["wait_seconds"] = wait_for
            return progress

        self._invoke_child(selected, poll=poll)
        status = self._status_after_action()
        self._refresh_state(status)
        if status == "control-failed":
            self._finish_control_failed()
            self._decision_for(decision="control-lost", selected_child_id=selected, actions=[])
            return self.progress()
        decision = (
            "interrupt"
            if status == "interrupt-pending"
            else "complete"
            if status == "completed"
            else "warn"
            if self._reasons or self._slack_warning_active
            else "continue"
        )
        actions = ["interrupt"] if status == "interrupt-pending" else ["release-leases"] if status == "completed" else ["step"]
        self._decision_for(decision=decision, selected_child_id=selected, actions=actions)
        return self.progress()

    def step(self) -> dict[str, Any]:
        """Advance one deterministic pool step and never sleep."""
        self._complete_wait()
        progress = self._step_once()
        if progress["wait_required"] and not self._timing_frozen:
            self._wait_started_ns = self._monotonic_ns()
        return progress

    def run(self) -> dict[str, Any]:
        """Blocking compatibility wrapper; only this method sleeps."""
        crashed = False
        try:
            progress = self.step()
            while progress["status"] not in {"closed", "control-failed"}:
                if progress["wait_required"]:
                    self.pool_callbacks["sleep"](seconds=progress["wait_seconds"])
                progress = self.step()
            if self._receipt is None:
                self._receipt = self._build_receipt()
            return dict(self._receipt)
        except BaseException as error:
            crashed = True
            try:
                self._cleanup_on_crash(error)
            except BaseException:
                # A cleanup defect must not replace the root failure. The
                # finally block still makes one last lock-release attempt.
                pass
            raise
        finally:
            if crashed and self._state_lock_handle is not None:
                try:
                    self._release_state_lock()
                except BaseException:
                    # Cleanup evidence already records the primary lock-release
                    # failure; this guard must never replace the root exception.
                    pass

    def progress(self) -> dict[str, Any]:
        next_deadline = min(
            (
                child["next_deadline_ns"]
                for child in self._state["children"]
                if child["next_deadline_ns"] is not None
            ),
            default=None,
        )
        now = self._monotonic_ns()
        waiting = (
            self._state["status"] not in {"closed", "control-failed"}
            and next_deadline is not None
            and not any(
                progress["status"] == "pending"
                or (progress["status"] != "terminal" and not progress.get("wait_required"))
                for progress in self._progress.values()
            )
        )
        return {
            "status": self._state["status"],
            "wait_required": waiting,
            "wait_seconds": wait_seconds(now, next_deadline) if waiting else None,
            "state": dict(self._state),
            "decision": dict(self._decision) if self._decision is not None else None,
            "receipt": dict(self._receipt) if self._receipt is not None else None,
        }


def run_native_pool(
    contract: Mapping[str, Any],
    child_contracts: Mapping[str, Mapping[str, Any]],
    task_inputs: Mapping[str, str],
    child_callbacks: Mapping[str, Mapping[str, Callable[..., Any]]],
    *,
    pool_callbacks: Mapping[str, Callable[..., Any]],
    lease_registry: PoolLeaseRegistry,
    capability_receipt: Mapping[str, Any] | None = None,
    state_file: Path | str | None = None,
    decision_file: Path | str | None = None,
    control_file: Path | str | None = None,
) -> dict[str, Any]:
    return NativePoolCoordinator(
        contract,
        child_contracts,
        task_inputs,
        child_callbacks,
        pool_callbacks=pool_callbacks,
        lease_registry=lease_registry,
        capability_receipt=capability_receipt,
        state_file=state_file,
        decision_file=decision_file,
        control_file=control_file,
    ).run()
