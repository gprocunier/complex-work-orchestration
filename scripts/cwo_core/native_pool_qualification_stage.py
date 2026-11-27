"""Account for both phases of an original contained pool run."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from copy import deepcopy
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
import stat
import sys
from threading import Condition, get_ident
from time import monotonic
from types import FunctionType
from typing import Any

from .invocation_ledger import LEDGER_FILE, MAX_UNITS, InvocationLedger, add_failure_note, request_sha256
from .native_live_availability import require_registered_contained_pool_live
from .native_pool_contracts import (
    canonical_sha256,
    pool_capacity_limits,
    validate_lease,
    validate_pool_receipt,
    validate_pool_state,
)
from .native_pool_leases import PoolLeaseRegistry, decode_lease_registry
from .native_pool_deferred_context import (
    ContainedPoolSelection,
    DeferredAttestationError,
    DeferredWorkerTurnEvidence,
    ProvisionalWorkerStartup,
    QUALIFICATION_MODEL,
    _ADMISSION_TOKEN,
    _ContainedPoolAdmission,
    _QualificationCalibration,
    _RUNTIME_TOKEN,
    contained_selection_binding,
)
from .native_pool_transaction import (
    AdmittedPoolLaunch,
    NativePoolTransactionError,
    PLAN_VERSION,
    TransactionJournal,
    TransactionRuntime,
    execute_native_pool_transaction,
    validate_transaction_plan,
)
from .native_tool_isolation import _ContainedPoolChild
from .policy_schema import strict_json_loads
from .workspace_capture import Budget, BudgetExhausted, _pin_directory, read_at

_POOL_LIMITS = ("tool_calls", "runtime_seconds")
_LIMITS = ("sessions", *_POOL_LIMITS)
_SETTLEMENT_BYTES = 1_000_000
_CLEANUP_SECONDS = 1.0
_FACTORY_MODULE = "registered_pool_qualification"
_FACTORY_ENTRY = "build_pool_qualification_runtime"
_FACTORY_BYTES = 256_000


@dataclass(frozen=True, slots=True)
class PoolQualificationRun:
    plan: Mapping[str, Any]
    runtime: TransactionRuntime
    journal_path: Path
    fixture_root: Path
    bind_limits: Callable[[PoolQualificationRunLimits], None] | None = None
    cleanup: Callable[[float], bool] | None = None
    contained_selection: ContainedPoolSelection | None = None
    ordinary_policy_children: Mapping[str, _ContainedPoolChild] | None = None


@dataclass(frozen=True, slots=True)
class PoolQualificationAccounting:
    """Original ledger and cutoff selected in the protected parent process."""

    ledger: InvocationLedger
    expires_at: int


def _ledger_root(accounting: PoolQualificationAccounting) -> Path:
    _require(type(accounting) is PoolQualificationAccounting and type(accounting.ledger) is InvocationLedger,
             "protected-accounting-required")
    _require(_positive(accounting.expires_at), "accounting-expiry-invalid")
    root = accounting.ledger.root
    _require(isinstance(root, Path) and root.is_absolute() and root == root.resolve() and root != root.parent,
             "accounting-root-invalid")
    return root


def _require(condition: bool, reason: str) -> None:
    if not condition:
        raise NativePoolTransactionError("pool-qualification-" + reason)


def _positive(value: object) -> bool:
    return type(value) is int and 0 < value <= MAX_UNITS


def _registered_factory_path() -> Path:
    return Path(__file__).resolve().parents[1] / (_FACTORY_MODULE + ".py")


def _registered_factory_source(path: str, digest: str) -> bytes:
    source_path = _registered_factory_path()
    _require(path == str(source_path), "registered-factory-path-required")
    source = _read_registered_source(source_path)
    _require(sha256(source).hexdigest() == digest, "registered-factory-digest-mismatch")
    return source


def _read_registered_source(source_path: Path) -> bytes:
    pinned = _pin_directory(str(source_path.parent))
    _require(pinned is not None, "registered-factory-directory-refused")
    directory, _ = pinned
    try:
        kind, source, info = read_at(directory, source_path.name, _FACTORY_BYTES)
    finally:
        os.close(directory)
    _require(kind == "file" and info is not None and info.st_uid in {0, os.geteuid()}
             and info.st_nlink == 1 and not info.st_mode & 0o022, "registered-factory-source-refused")
    _require(source is not None, "registered-factory-source-refused")
    return source


def select_contained_pool_runtime(plan: Mapping[str, Any], create_runtime: Callable[..., tuple], /,
                                  **factory_inputs: Any) -> ContainedPoolSelection:
    """Check the installed adapter and retain the exact runtime it assembles without effects."""
    require_registered_contained_pool_live()
    _require(factory_inputs.get("ordinary") is not None, "original-ordinary-approval-required")
    module = sys.modules.get(_FACTORY_MODULE)
    _require(module is not None and type(create_runtime) is FunctionType
             and vars(module).get(_FACTORY_ENTRY) is create_runtime,
             "registered-factory-required")
    selected = deepcopy(dict(plan))
    _require(not validate_transaction_plan(selected) and selected["version"] == PLAN_VERSION
             and selected["prelude_session_count"] == 0 and selected["selected_model"] == QUALIFICATION_MODEL,
             "contained-plan-required")
    path = selected["runtime_adapter_path"]
    digest = selected["runtime_adapter_sha256"]
    source = _registered_factory_source(path, digest)
    code = compile(source, path, "exec", dont_inherit=True)
    _require(create_runtime.__code__.co_filename == path and create_runtime.__code__ in code.co_consts,
             "registered-factory-code-mismatch")
    assembled = create_runtime(deepcopy(selected), **factory_inputs)
    _require(type(assembled) is tuple and len(assembled) == 3, "contained-runtime-required")
    runtime, bind_limits, cleanup = assembled
    _require(type(runtime) is TransactionRuntime and callable(bind_limits) and callable(cleanup),
             "contained-runtime-required")
    return ContainedPoolSelection(selected["plan_sha256"], path, digest, runtime, bind_limits, cleanup, _RUNTIME_TOKEN,
                                  factory_inputs.get("ordinary"))


def make_pool_qualification_run(plan: Mapping[str, Any], selection: ContainedPoolSelection, *,
                                journal_path: Path, fixture_root: Path) -> PoolQualificationRun:
    """Carry the registered runtime and its original hooks into accounting."""
    _require(type(selection) is ContainedPoolSelection, "contained-runtime-required")
    contained_selection_binding(selection, plan, selection.runtime)
    return PoolQualificationRun(plan, selection.runtime, journal_path, fixture_root,
                                selection.bind_limits, selection.cleanup, selection)


def _entry_identity(info: os.stat_result) -> tuple[int, int, int]:
    return info.st_dev, info.st_ino, info.st_mode


def _change_mark(info: os.stat_result) -> tuple[int, int, int]:
    return info.st_size, info.st_mtime_ns, info.st_ctime_ns


def _outside_fixtures(path: str | Path, roots: frozenset[Path]) -> bool:
    candidate = Path(path).resolve()
    return not roots.intersection((candidate, *candidate.parents))


@dataclass(frozen=True, slots=True)
class _RunSettlement:
    contract: Mapping[str, Any]
    reservation: Mapping[str, Any]
    policy_document: Mapping[str, Any] | None
    state_path: Path
    state_ancestry: list[tuple[int, int]]
    registry: PoolLeaseRegistry
    registry_path: Path
    registry_lock_path: Path
    registry_ancestry: list[tuple[int, int]]


def _custody(path: Path, reason: str) -> tuple[int, list[tuple[int, int]]]:
    pinned = _pin_directory(str(path.parent))
    _require(pinned is not None, reason)
    directory, _ = pinned
    info = os.fstat(directory)
    if info.st_uid != os.geteuid() or info.st_mode & 0o022:
        os.close(directory)
        _require(False, reason)
    return pinned


def _custody_binding(path: Path) -> list[tuple[int, int]]:
    _require(path.is_absolute() and ".." not in path.parts and path.name != "", "settlement-path-invalid")
    directory, ancestry = _custody(path, "settlement-custody-required")
    os.close(directory)
    return ancestry


def _sync_journal_parent(path: Path) -> None:
    directory, _ = _custody(path, "journal-custody-required")
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def _new_effect_journal(path: Path, transaction_id: str) -> TransactionJournal:
    try:
        path.lstat()
    except FileNotFoundError:
        return TransactionJournal(path, transaction_id)
    raise NativePoolTransactionError("pool-qualification-active-effect-journal-not-fresh")


def _bind_settlement(launch: AdmittedPoolLaunch, roots: frozenset[Path], journal_path: Path) -> _RunSettlement:
    options = launch.keyword_arguments
    registry = options.get("lease_registry")
    _require(type(registry) is PoolLeaseRegistry, "fixture-lease-registry-required")
    state_file = options.get("state_file")
    _require(isinstance(state_file, (str, Path)) and bool(state_file), "settlement-state-file-required")
    state_path = Path(state_file)
    state_ancestry = _custody_binding(state_path)
    state_lock_path = state_path.with_suffix(state_path.suffix + ".lock")
    state_paths = [state_path, state_lock_path, registry.path, registry.lock_path,
                   options.get("decision_file"), options.get("control_file"), journal_path]
    state_paths.extend(child["state_file"] for child in launch.contract["children"])
    _require(all(_outside_fixtures(path, roots) for path in state_paths if path is not None), "fixture-state-overlap")
    _require(registry.lock_path == registry.path.with_suffix(registry.path.suffix + ".lock"), "settlement-lock-path-invalid")
    _require(len({Path(path).resolve() for path in state_paths if path is not None}) == sum(path is not None for path in state_paths),
             "settlement-state-paths-overlap")
    return _RunSettlement(deepcopy(dict(launch.contract)), deepcopy(dict(launch.reservation_receipt)),
                          deepcopy(options.get("policy_document")), state_path, state_ancestry,
                          registry, registry.path, registry.lock_path, _custody_binding(registry.path))


def _private_settlement_file(info: os.stat_result) -> bool:
    return (stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o600 and info.st_uid == os.geteuid()
            and info.st_nlink == 1 and info.st_size <= _SETTLEMENT_BYTES)


def _read_settlement_artifact(path: Path, expected_ancestry: list[tuple[int, int]], reason: str) -> dict[str, Any]:
    directory, ancestry = _custody(path, reason)
    try:
        _require(ancestry == expected_ancestry, reason)
        budget = Budget.start(max_files=1, max_bytes=_SETTLEMENT_BYTES, max_seconds=3, max_entries=1)
        kind, data, before = read_at(directory, path.name, _SETTLEMENT_BYTES, deadline=budget.deadline)
        _require(kind == "file" and data is not None and before is not None and _private_settlement_file(before), reason)
        after = os.stat(path.name, dir_fd=directory, follow_symlinks=False)
        _require(_entry_identity(before) == _entry_identity(after) and _change_mark(before) == _change_mark(after), reason)
        _require(_custody_binding(path) == ancestry and len(data) == after.st_size, reason)
        value = strict_json_loads(data.decode("utf-8"))
        _require(type(value) is dict, reason)
        return value
    except (OSError, BudgetExhausted, ValueError, RecursionError) as exc:
        raise NativePoolTransactionError("pool-qualification-" + reason) from exc
    finally:
        os.close(directory)


def _read_settled_leases(source: _RunSettlement) -> list[dict[str, Any]]:
    registry = source.registry
    _require(registry.path == source.registry_path and registry.lock_path == source.registry_lock_path,
             "settlement-registry-binding-drift")
    reason = "settlement-registry-unreadable"
    value = _read_settlement_artifact(source.registry_path, source.registry_ancestry, reason)
    try:
        return decode_lease_registry(value)
    except (ValueError, RecursionError) as exc:
        raise NativePoolTransactionError("pool-qualification-" + reason) from exc


def _verify_settlement(source: _RunSettlement, launched: Mapping[str, Any]) -> dict[str, Any]:
    state = _read_settlement_artifact(source.state_path, source.state_ancestry, "settlement-state-unreadable")
    contract = source.contract
    errors = validate_pool_state(state, contract=contract)
    _require(not errors and state["status"] == "closed", "settlement-state-invalid:" + ";".join(errors))
    receipt = launched["pool_receipt"]
    errors = validate_pool_receipt(receipt, contract=contract, terminal_state=state,
                                   admission_reservation=source.reservation, dispatch_receipt=launched["dispatch_receipt"],
                                   capacity_limits=pool_capacity_limits(source.policy_document))
    _require(not errors, "settlement-receipt-mismatch:" + ";".join(errors))
    lease_ids = [child["lease_id"] for child in contract["children"]]
    rows = {row["lease_id"]: row for row in _read_settled_leases(source)
            if row["lease_id"] in lease_ids or (row["pool_id"], row["pool_epoch"]) == (contract["pool_id"], contract["pool_epoch"])}
    _require(rows.keys() == set(lease_ids), "settlement-lease-set-mismatch")
    for lease_id in lease_ids:
        row = rows[lease_id]
        errors = validate_lease(row, contract=contract)
        _require(not errors and row["lifecycle_state"] == "released", "settlement-lease-invalid:" + ";".join(errors))
    hashes = [rows[lease_id]["lease_sha256"] for lease_id in lease_ids]
    _require(hashes == state["lease_bindings"] == [item["lease_sha256"] for item in receipt["lease_evidence"]],
             "settlement-lease-receipt-mismatch")
    return {"outcome": "verified", "state_sha256": state["state_sha256"], "released_lease_sha256s": hashes}


def _accepted(result: Mapping[str, Any], plan: Mapping[str, Any]) -> bool:
    launch_result = result.get("launch_result") or {}
    receipt = launch_result.get("pool_receipt") or {}
    return (result.get("accepted") is True and result.get("state") == "ACCEPTED"
            and result.get("transaction_id") == plan["transaction_id"]
            and result.get("plan_sha256") == plan["plan_sha256"]
            and receipt.get("accepting") is True and receipt.get("pool_disposition") == "accepted"
            and set(receipt.get("admission_order", ())) == {child["child_id"] for child in plan["children"]})


@dataclass(frozen=True, slots=True)
class _StageAllowance:
    accounting: PoolQualificationAccounting
    root: Path
    ancestry: list[tuple[int, int]]
    stage_sha256: str
    budget_id: str
    calibration: _QualificationCalibration | None = None
    ordinary: object | None = None

    def check_custody(self) -> None:
        _require(self.accounting.ledger.root == self.root
                 and _custody_binding(self.root / LEDGER_FILE) == self.ancestry, "accounting-custody-drift")


class PoolQualificationRunLimits:
    """One original reservation's durable, one-shot effect gates."""

    def __init__(self, allowance: _StageAllowance, intent: Mapping[str, Any],
                 run: PoolQualificationRun, deadline: float) -> None:
        self._allowance = allowance
        self._intent = intent
        self._deadline = deadline
        self._journal = _new_effect_journal(
            allowance.root / (intent["reservation_id"] + ".qualification-effects.jsonl"), run.plan["transaction_id"])
        self._children = frozenset(child["child_id"] for child in run.plan["children"])
        self._session_cap = intent["amount"]["sessions"]
        self._tool_cap = intent["amount"]["tool_calls"]
        self._condition = Condition()
        self._sessions: dict[str, str | None] = {}
        self._turns: dict[str, str | None] = {}
        self._unconfirmed_dispatch: set[str] = set()
        self._tools: dict[tuple[str, int | str], bool] = {}
        self._overlap_debits: dict[str, list[str]] = {}
        self._tools_released = False
        self._last_hash: str | None = None
        self._closed = False
        self._refusal: str | None = None
        self._record_failed = False
        self._allocating_child: str | None = None
        self._dispatching: tuple[str, int] | None = None
        self._contained_admission: _ContainedPoolAdmission | None = None
        self._provisional_arrivals: set[str] = set()
        self._writer_releases: set[tuple[str, int | str]] = set()

    @property
    def deadline(self) -> float:
        return self._deadline

    @property
    def calibration_only(self) -> bool:
        admission = self._contained_admission
        return admission is not None and admission._calibration is not None

    def _seconds_left(self) -> float:
        accounting = self._allowance.accounting
        signed_seconds = accounting.expires_at - accounting.ledger.current_time()
        return min(self.deadline - monotonic(), signed_seconds)

    def _time_left(self) -> float:
        remaining = self._seconds_left()
        _require(remaining > 0, "run-deadline-expired")
        return remaining

    def remaining(self) -> float:
        """Return the time left under the original deadline, or refuse operation."""
        _require(not self._closed, self._refusal or "run-effects-closed")
        _require(not self._record_failed, "active-effect-journal-refused")
        return self._time_left()

    def _require_intent(self) -> None:
        self._require_effect_authority()
        self._check_intent_custody()
        self._time_left()

    def _require_effect_authority(self) -> None:
        require_registered_contained_pool_live()
        self._allowance.ordinary.require_current()

    def _check_intent_custody(self) -> None:
        self._allowance.check_custody()
        current = self._allowance.accounting.ledger.attempt(self._intent["reservation_id"])
        _require(current == self._intent, "active-reservation-intent-drift")

    def _append(self, event: str, details: Mapping[str, Any], *, before_effect: bool = False) -> str:
        try:
            self._check_intent_custody()
            _require(not self._record_failed, "active-effect-journal-refused")
            prior = self._journal.read()
            _require((prior[-1]["event_sha256"] if prior else None) == self._last_hash,
                     "active-effect-journal-drift")
            previous_time = datetime.fromisoformat(prior[-1]["at"]) if prior else datetime.min.replace(tzinfo=timezone.utc)
        except BaseException:
            self._record_failed = True
            raise
        if before_effect:
            # Acknowledgements and settlement keep recording the original custody after cutoff.
            self._time_left()
        try:
            row = self._journal.append(event_type="qualification-" + event, state="PREPARED", details=details,
                                       now=max(datetime.now(timezone.utc), previous_time))
            _require(row["previous_event_sha256"] == self._last_hash, "active-effect-journal-drift")
            if self._last_hash is None:
                _sync_journal_parent(self._journal.path)
            self._last_hash = row["event_sha256"]
            return self._last_hash
        except BaseException:
            self._record_failed = True
            raise

    def _bind(self, transaction_intent: Mapping[str, Any]) -> None:
        self._append("effects-bound", {"reservation_id": self._intent["reservation_id"],
                     "request_sha256": self._intent["request_sha256"],
                     "transaction_intent_event_sha256": transaction_intent["event_sha256"],
                     "monotonic_deadline": self.deadline,
                     "amount": self._intent["amount"]})

    def before_session(self, child_id: str) -> None:
        """Record a planned session attempt before sending its start RPC."""
        with self._condition:
            self.remaining()
            _require(child_id == self._allocating_child, "session-allocation-not-active")
            _require(child_id in self._children and child_id not in self._sessions, "session-intent-binding-refused")
            _require(len(self._sessions) < self._session_cap, "session-limit-exceeded")
            self._append("session-intent", {"child_id": child_id}, before_effect=True)
            self._sessions[child_id] = None
            self.remaining()

    def ack_session(self, child_id: str, thread_id: str) -> None:
        with self._condition:
            _require(not self._closed, "run-effects-closed")
            _require(child_id in self._sessions and self._sessions[child_id] is None, "session-ack-binding-refused")
            _require(type(thread_id) is str and thread_id and thread_id not in self._sessions.values(),
                     "session-ack-thread-refused")
            self._append("session-ack", {"child_id": child_id, "thread_id": thread_id})
            self._sessions[child_id] = thread_id

    def _require_session(self, child_id: str, thread_id: str) -> None:
        _require(bool(thread_id) and self._sessions.get(child_id) == thread_id, "session-thread-binding-refused")

    def _start_worker(self, starter, child, context):
        self.remaining()
        child_id = child["child_id"]
        self._allocating_child = child_id
        try:
            allocation = starter(child, context)
        finally:
            self._allocating_child = None
        session_id = (allocation.session_id if type(allocation) is ProvisionalWorkerStartup
                      else allocation.get("session_id"))
        self._require_session(child_id, session_id)
        self.remaining()
        return allocation

    def _wrap_send(self, child_id: str, send: Callable[..., Any]) -> Callable[..., Any]:
        def scoped(*args, **kwargs):
            with self._condition:
                self.remaining()
                _require(self._dispatching is None, "turn-dispatch-scope-busy")
                if child_id in self._turns or child_id in self._unconfirmed_dispatch:
                    self._refuse_effect("turn-intent-replay")
                self._dispatching = (child_id, get_ident())
                self._unconfirmed_dispatch.add(child_id)
            try:
                result = send(*args, **kwargs)
                submission = result.get("submission_id") if isinstance(result, Mapping) else result
                with self._condition:
                    if type(submission) is not str or self._turns.get(child_id) != submission:
                        self._refuse_effect("turn-dispatch-ack-binding-refused")
                    self._unconfirmed_dispatch.remove(child_id)
                    self._condition.notify_all()
                self.remaining()
                return result
            finally:
                with self._condition:
                    self._dispatching = None

        return scoped

    def _bind_dispatch(self, launch: AdmittedPoolLaunch) -> AdmittedPoolLaunch:
        _require(launch.child_callbacks.keys() == self._children, "turn-dispatch-callback-set-mismatch")
        callbacks = {}
        for child_id, handlers in launch.child_callbacks.items():
            send = handlers.get("send_input")
            _require(callable(send), "turn-dispatch-callback-required")
            callbacks[child_id] = {**handlers, "send_input": self._wrap_send(child_id, send)}
        return replace(launch, child_callbacks=callbacks)

    def _require_dispatch_scope(self, child_id: str) -> None:
        if self._dispatching != (child_id, get_ident()):
            self._refuse_effect("turn-dispatch-not-active")

    def before_turn(self, child_id: str, thread_id: str) -> None:
        """Record a turn start for the admitted thread before sending its RPC."""
        with self._condition:
            self.remaining()
            self._require_dispatch_scope(child_id)
            self._require_session(child_id, thread_id)
            _require(self._children == self._sessions.keys() and all(self._sessions.values()), "sessions-not-ready")
            _require(child_id not in self._turns, "turn-intent-replay")
            self._append("turn-intent", {"child_id": child_id, "thread_id": thread_id}, before_effect=True)
            self._turns[child_id] = None
            self.remaining()

    def ack_turn(self, child_id: str, thread_id: str, turn_id: str) -> None:
        with self._condition:
            _require(not self._closed, "run-effects-closed")
            self._require_dispatch_scope(child_id)
            self._require_session(child_id, thread_id)
            _require(child_id in self._turns and self._turns[child_id] is None, "turn-ack-binding-refused")
            _require(type(turn_id) is str and bool(turn_id), "turn-ack-id-refused")
            self._append("turn-ack", {"child_id": child_id, "thread_id": thread_id, "turn_id": turn_id})
            self._turns[child_id] = turn_id

    def record_provisional_turn_proof(self, proof: DeferredWorkerTurnEvidence) -> None:
        """Record evidence from this worker's original pending receiver before the writer gate."""
        with self._condition:
            _require(not self.calibration_only, "calibration-writer-held")
            self.remaining()
            admission = self._contained_admission
            if admission is None or type(proof) is not DeferredWorkerTurnEvidence:
                self._refuse_effect("contained-turn-proof-required")
            child_id = proof.startup.child_id
            try:
                admission.record_proof(proof, thread_id=self._sessions.get(child_id), turn_id=self._turns.get(child_id))
                self._append("provisional-turn-proof", {
                    "child_id": child_id, "request_id": proof.request_id, "request_sha256": proof.request_sha256,
                    "turn_id": proof.turn_id, "allocation_intent_event_sha256": proof.startup.allocation_intent_event_sha256,
                    "connection_epoch_sha256": proof.startup.connection_epoch_sha256,
                    "owner_identity_sha256": proof.startup.owner_identity_sha256,
                    "rollout_source_identity_sha256": proof.session_source_identity_sha256,
                    "rollout_boundary_sha256": proof.boundary_sha256,
                })
            except DeferredAttestationError as failure:
                self._refuse_effect(str(failure))
            finally:
                self._condition.notify_all()

    def charge_tool(self, child_id: str, thread_id: str, turn_id: str, request_id: int | str) -> None:
        """Debit an admitted request and wait here before performing its effect."""
        with self._condition:
            _require(not self.calibration_only, "calibration-writer-held")
            self.remaining()
            self._require_session(child_id, thread_id)
            _require(bool(turn_id) and self._turns.get(child_id) == turn_id, "tool-turn-binding-refused")
            _require(type(request_id) in (str, int) and request_id != "", "tool-request-id-refused")
            key = child_id, request_id
            if self._contained_admission is not None:
                self._wait_for_original_pending_cohort(child_id, thread_id, turn_id, request_id)
            self._require_tool_capacity(key)
            try:
                debit = self._append("tool-debit", {"child_id": child_id, "thread_id": thread_id, "turn_id": turn_id,
                                                   "request_id": request_id, "tool_calls": len(self._tools) + 1},
                                     before_effect=True)
                self._tools[key] = False
                self._wait_for_tool_overlap(child_id, debit)
            finally:
                self._condition.notify_all()
            self.remaining()

    def _wait_for_original_pending_cohort(self, child_id: str, thread_id: str, turn_id: str, request_id: int | str) -> None:
        try:
            self._contained_admission.require_proved_request(child_id, thread_id, turn_id, request_id)
        except DeferredAttestationError as failure:
            self._refuse_effect(str(failure))
        if child_id in self._provisional_arrivals:
            self._refuse_effect("contained-pending-callback-replayed")
        if self._dispatching is not None and self._dispatching[1] == get_ident():
            self._refuse_effect("tool-overlap-required")
        self._provisional_arrivals.add(child_id)
        self._condition.notify_all()
        if not self._condition.wait_for(self._provisional_cohort_ready, self.remaining()):
            self._refuse_effect("contained-pending-cohort-deadline-expired")
        self.remaining()

    def _provisional_cohort_ready(self) -> bool:
        return (self._closed or self._record_failed
                or (not self._unconfirmed_dispatch and self._provisional_arrivals == self._children))

    def authorize_writer(self, child_id: str, thread_id: str, turn_id: str, request_id: int | str,
                         request_sha256: str, release: Callable[[], None]) -> None:
        """Release the original writer gate once, while the proved request is still pending."""
        with self._condition:
            _require(not self.calibration_only, "calibration-writer-held")
            self.remaining()
            key = child_id, request_id
            if (self._contained_admission is None or not self._tools_released
                    or self._tools.get(key) is not False or key in self._writer_releases or not callable(release)):
                self._refuse_effect("contained-writer-release-refused")
            try:
                proof = self._contained_admission.require_proved_request(child_id, thread_id, turn_id, request_id)
            except DeferredAttestationError as failure:
                self._refuse_effect(str(failure))
            if proof.request_sha256 != request_sha256:
                self._refuse_effect("contained-writer-callback-drift")
            self._append("writer-release", {"child_id": child_id, "request_id": request_id,
                         "request_sha256": request_sha256, "turn_id": turn_id}, before_effect=True)
            self.remaining()
            self._writer_releases.add(key)
            release()

    def _tool_overlap_ready(self) -> bool:
        return (self._closed or self._record_failed or self._tools_released
                or (not self._unconfirmed_dispatch and self._overlap_debits.keys() == self._children))

    def _wait_for_tool_overlap(self, child_id: str, debit: str) -> None:
        if self._tools_released:
            return
        self._overlap_debits.setdefault(child_id, []).append(debit)
        # The coordinator advances send callbacks serially. Waiting there would
        # prevent the rest of the cohort from dispatching its turns.
        if self._dispatching is not None and self._dispatching[1] == get_ident():
            self._refuse_effect("tool-overlap-required")
        if not self._condition.wait_for(self._tool_overlap_ready, self.remaining()):
            self._refuse_effect("run-deadline-expired")
        self.remaining()
        if not self._tools_released:
            self._append("tool-overlap-release", {"pending_debits": self._overlap_debits}, before_effect=True)
            self.remaining()
            self._tools_released = True

    def _require_tool_capacity(self, key: tuple[str, int | str]) -> None:
        if key in self._tools:
            self._refuse_effect("tool-request-replay")
        if len(self._tools) >= self._tool_cap:
            self._refuse_effect("tool-limit-exceeded")

    def _refuse_effect(self, reason: str) -> None:
        self._refusal = self._refusal or reason
        self._close_locked()
        _require(False, self._refusal)

    def ack_tool(self, child_id: str, thread_id: str, turn_id: str, request_id: int | str) -> None:
        with self._condition:
            _require(not self._closed, "run-effects-closed")
            self._require_session(child_id, thread_id)
            _require(bool(turn_id) and self._turns.get(child_id) == turn_id, "tool-turn-binding-refused")
            _require(type(request_id) in (str, int) and request_id != "", "tool-request-id-refused")
            key = child_id, request_id
            _require(self._tools_released and self._tools.get(key) is False, "tool-ack-binding-refused")
            if self._contained_admission is not None and key not in self._writer_releases:
                self._refuse_effect("contained-writer-release-required")
            self._append("tool-ack", {"child_id": child_id, "thread_id": thread_id, "turn_id": turn_id,
                                     "request_id": request_id})
            self._tools[key] = True

    def _close(self) -> None:
        with self._condition:
            self._close_locked()

    def _close_locked(self) -> None:
        self._closed = True
        self._condition.notify_all()

    def _pending(self) -> dict[str, Any]:
        return {
            "sessions": sorted(child for child, session in self._sessions.items() if session is None),
            "turns": sorted(self._unconfirmed_dispatch | {child for child, turn in self._turns.items() if turn is None}),
            "tools": [{"child_id": child, "request_id": request} for (child, request), acked in self._tools.items() if not acked],
        }

    def _complete(self) -> bool:
        return (self._refusal is None and self._tools_released
                and self._children == self._sessions.keys() == self._turns.keys()
                and {child for child, _ in self._tools} == self._children and not any(self._pending().values()))

    def _calibration_complete(self) -> bool:
        return (self.calibration_only and self._refusal is None and not self._tools and not self._tools_released
                and self._children == self._sessions.keys() == self._turns.keys() and not any(self._pending().values()))


@dataclass(slots=True)
class _ActiveRun:
    limits: PoolQualificationRunLimits
    cleanup: Callable[[float], bool]
    cleanup_confirmed: bool | None = None
    settlement_required: bool = False
    leases_confirmed: bool = False
    end_recorded: bool = False

    def close(self) -> None:
        if self.cleanup_confirmed is not None:
            return
        self.cleanup_confirmed = False
        self.limits._close()
        cutoff = monotonic() + _CLEANUP_SECONDS
        self.cleanup_confirmed = self.cleanup(cutoff) is True and monotonic() <= cutoff

    def _close_for_validation(self, validation: dict[str, Any]) -> None:
        try:
            self.close()
        except Exception as failure:
            validation["qualification_cleanup_error"] = type(failure).__name__

    def validate(self, validate, launched, context):
        # A refused pool can close its unused writer gate before validation.
        if (self.limits._closed and self.limits._refusal is None
                and launched.get("pool_receipt", {}).get("accepting") is False):
            _require(not self.limits._record_failed, "active-effect-journal-refused")
            self.limits._time_left()
        else:
            self.limits.remaining()
        validation = validate(launched, context, before_artifact_checks=self._close_for_validation)
        self.leases_confirmed = validation.get("qualification_settlement", {}).get("outcome") == "verified"
        checks = {"effects_complete": self.limits._complete(), "cleanup_confirmed": self.cleanup_confirmed,
                  "leases_confirmed": self.leases_confirmed, "deadline_satisfied": self.limits._seconds_left() > 0}
        validation["qualification_active_limits"] = checks
        if not all(checks.values()):
            validation.update(accepted=False, atomic_promotion_authorized=False)
        return validation

    def failure_reason(self) -> str | None:
        if self.cleanup_confirmed is not True:
            return "owned runtime cleanup was not confirmed"
        if self.limits._record_failed:
            return "effect intent journal could not be verified"
        if any(self.limits._pending().values()):
            return "one or more effect intents have no exact acknowledgement"
        if self.settlement_required and not self.leases_confirmed:
            return "original pool lease settlement could not be verified"
        return None

    def record_end(self, journal: TransactionJournal) -> None:
        if self.limits._last_hash is None or self.end_recorded:
            return
        terminal = journal.read()[-1]
        self.limits._append("effects-settled", {
            "transaction_last_event_sha256": terminal["event_sha256"],
            "cleanup_confirmed": self.cleanup_confirmed,
            "leases_confirmed": self.leases_confirmed,
            "pending": self.limits._pending(),
            "refusal": self.limits._refusal,
        })
        self.end_recorded = True


def _open_stage_allowance(accounting: PoolQualificationAccounting, root: Path, binding: str,
                          ceiling: Mapping[str, int], runs: Sequence[PoolQualificationRun],
                          roots: frozenset[Path], require_route: Callable[[], None], *,
                          budget_prefix: str = "pool-qualification:") -> _StageAllowance:
    require_route()
    ledger_custody = frozenset({root})
    _require(_outside_fixtures(root, roots) and all(_outside_fixtures(path, ledger_custody) for path in roots),
             "accounting-fixture-overlap")
    _require(all(_outside_fixtures(run.journal_path, ledger_custody) for run in runs), "accounting-journal-overlap")
    allowance = _StageAllowance(accounting, root, _custody_binding(root / LEDGER_FILE), binding, budget_prefix + binding)
    allowance.check_custody()
    ledger = accounting.ledger
    _require(accounting.expires_at > ledger.current_time(), "accounting-expired")
    ledger.open_budget(allowance.budget_id, ceiling, scope_sha256=binding)
    return allowance


def _reserve_run(run: PoolQualificationRun, allowance: _StageAllowance,
                 limits: Mapping[str, int]) -> tuple[dict[str, Any], bytes]:
    allowance.check_custody()
    ledger = allowance.accounting.ledger
    plan = run.plan
    request = {
        "stage_sha256": allowance.stage_sha256,
        "transaction_id": plan["transaction_id"],
        "plan_sha256": plan["plan_sha256"],
        "journal_path": str(run.journal_path),
        "maximum": dict(limits),
    }
    request_bytes = json.dumps(request, sort_keys=True, separators=(",", ":")).encode("utf-8")
    digest = request_sha256(request_bytes)
    return ledger.reserve(
        budget_id=allowance.budget_id,
        request_id="pool-qualification-run:" + canonical_sha256({"transaction_id": plan["transaction_id"]}),
        request_sha256=digest,
        admission_sha256=canonical_sha256({"qualification_run_request_sha256": digest}),
        amount=limits,
        expires_at=allowance.accounting.expires_at,
        refuse_while_unresolved=True,
    ), request_bytes


def _persist_run_intent(journal: TransactionJournal, intent: Mapping[str, Any]) -> dict[str, Any]:
    return journal.append(event_type="qualification-accounting-intent", state="RESERVED",
        details={key: intent[key] for key in ("budget_id", "reservation_id", "request_sha256", "amount")},
        now=datetime.now(timezone.utc))


def _run_accounting_result(result: dict[str, Any], settlement: Mapping[str, Any],
                           intent_event: Mapping[str, Any], *, mode: str) -> dict[str, Any]:
    result["qualification_accounting"] = {
        **{key: settlement[key] for key in ("budget_id", "reservation_id", "request_sha256", "state", "outcome",
                                             "charge", "observed_usage")},
        "mode": mode,
        "intent_event_sha256": intent_event["event_sha256"],
        "journal_last_event_sha256": result["journal_last_event_sha256"],
    }
    return result


def _require_run_journal(journal: TransactionJournal, result: Mapping[str, Any],
                         intent_event: Mapping[str, Any] | None) -> None:
    events = journal.read()
    _require(intent_event is not None and intent_event in events[:-1]
             and events[-1]["event_sha256"] == result["journal_last_event_sha256"],
             "accounting-transaction-journal-mismatch")


def _accounted_run(run: PoolQualificationRun, runtime: TransactionRuntime, allowance: _StageAllowance,
                   limits: Mapping[str, int]) -> dict[str, Any]:
    selection = run.contained_selection
    contained_selection_binding(selection, run.plan, run.runtime)
    _require(run.bind_limits is selection.bind_limits and run.cleanup is selection.cleanup,
             "contained-runtime-hooks-mismatch")
    reservation, request_bytes = _reserve_run(run, allowance, limits)
    return _accounted_active_run(run, runtime, allowance, reservation, request_bytes)


def _active_runtime(run: PoolQualificationRun, original: TransactionRuntime, active: _ActiveRun,
                    journal: TransactionJournal, intent_events: list[dict[str, Any]]) -> TransactionRuntime:
    limits = active.limits

    def prepare(plan):
        limits.remaining()
        limits._require_intent()
        event = _persist_run_intent(journal, limits._intent)
        _sync_journal_parent(journal.path)
        intent_events.append(event)
        limits._bind(event)
        limits.remaining()
        run.bind_limits(limits)
        limits.remaining()
        prepared = original.prepare(plan)
        limits.remaining()
        return prepared

    def start_worker(child, context):
        return limits._start_worker(original.start_worker_session, child, context)

    def bind(plan, allocations, context):
        limits.remaining()
        launch = original.bind_admitted_launch(plan, allocations, context)
        limits.remaining()
        # The admitted entrypoint gives these callbacks to the coordinator in its
        # one-shot admission commit. The embedding runtime keeps its original map.
        launch = limits._bind_dispatch(launch)
        active.settlement_required = True
        return launch

    def validate(launched, context):
        return active.validate(original.validate, launched, context)

    return replace(original, prepare=prepare, start_worker_session=start_worker, bind_admitted_launch=bind, validate=validate)


def _settle_active_run(allowance: _StageAllowance, reservation_id: str, *, failure_reason: str | None,
                       outcome: str) -> dict[str, Any]:
    allowance.check_custody()
    ledger = allowance.accounting.ledger
    try:
        if failure_reason is not None:
            ledger.mark_reconciliation_required(reservation_id, reason=failure_reason)
        else:
            ledger.finish(reservation_id, outcome, reason="qualification run " + outcome + "; full reservation retained")
        return ledger.attempt(reservation_id)
    except BaseException as interruption:
        try:
            allowance.check_custody()
            ledger._settle_pending_intent(reservation_id, interruption)
        except BaseException as secondary:
            add_failure_note(interruption, f"qualification interrupted settlement failed ({type(secondary).__name__})")
        raise


def _close_after_active_failure(active: _ActiveRun, journal: TransactionJournal, failure: BaseException) -> None:
    try:
        active.close()
    except BaseException as secondary:
        add_failure_note(failure, f"qualification cleanup failed ({type(secondary).__name__})")
    try:
        active.record_end(journal)
    except BaseException as secondary:
        active.limits._record_failed = True
        add_failure_note(failure, f"qualification effect evidence failed ({type(secondary).__name__})")


def _record_active_failure(allowance: _StageAllowance, reservation_id: str, active: _ActiveRun,
                           journal: TransactionJournal, failure: BaseException) -> None:
    _close_after_active_failure(active, journal, failure)
    reason = active.failure_reason()
    if reason is None and not isinstance(failure, Exception):
        reason = "qualification was interrupted after invocation intent"
    try:
        _settle_active_run(allowance, reservation_id, failure_reason=reason, outcome="unknown")
    except BaseException as secondary:
        add_failure_note(failure, f"qualification ledger settlement failed ({type(secondary).__name__})")


def _open_active_run(run: PoolQualificationRun, allowance: _StageAllowance, reservation: Mapping[str, Any],
                     request_bytes: bytes) -> _ActiveRun:
    ledger = allowance.accounting.ledger
    reservation_id = reservation["reservation_id"]
    started = monotonic()
    signed_seconds = max(0.0, allowance.accounting.expires_at - ledger.current_time())
    deadline = started + min(reservation["amount"]["runtime_seconds"], signed_seconds)
    try:
        intent = ledger.begin_invocation(reservation_id, request_bytes)
        limits = PoolQualificationRunLimits(allowance, intent, run, deadline)
        _bind_active_admission(run, allowance, limits)
        return _ActiveRun(limits, run.cleanup)
    except BaseException as failure:
        try:
            allowance.check_custody()
            if ledger.attempt(reservation_id)["state"] == "invocation-intent":
                ledger.mark_reconciliation_required(reservation_id, reason="qualification intent setup was interrupted")
        except BaseException as secondary:
            add_failure_note(failure, f"qualification intent settlement failed ({type(secondary).__name__})")
        raise


def _bind_active_admission(run, allowance, limits):
    selection = run.contained_selection
    _require(type(selection) is ContainedPoolSelection and allowance.ordinary is not None
             and selection.ordinary is allowance.ordinary and run.ordinary_policy_children is not None,
             "contained-route-scope-mismatch")
    limits._contained_admission = _ContainedPoolAdmission(
        _ADMISSION_TOKEN, selection=selection, plan=run.plan, journal_path=run.journal_path,
        check_custody=limits._require_intent, check_source=lambda: _check_active_source(selection, limits),
        check_availability=require_registered_contained_pool_live, policy_children=dict(run.ordinary_policy_children),
        deadline=limits.deadline, calibration=allowance.calibration)


def _check_active_source(selection: ContainedPoolSelection, limits: PoolQualificationRunLimits) -> None:
    _registered_factory_source(selection.factory_path, selection.factory_sha256)
    limits._time_left()


def _accounted_active_run(run: PoolQualificationRun, runtime: TransactionRuntime, allowance: _StageAllowance,
                          reservation: Mapping[str, Any], request_bytes: bytes) -> dict[str, Any]:
    reservation_id = reservation["reservation_id"]
    journal = TransactionJournal(run.journal_path, run.plan["transaction_id"])
    active = _open_active_run(run, allowance, reservation, request_bytes)
    intent_events: list[dict[str, Any]] = []
    try:
        bound = _active_runtime(run, runtime, active, journal, intent_events)
        admission = active.limits._contained_admission
        admission.bind_runtime(bound)
        with admission._tool_validation():
            result = execute_native_pool_transaction(run.plan, bound, journal_path=run.journal_path,
                                                     contained_admission=admission)
        intent_event, = intent_events
        _require_run_journal(journal, result, intent_event)
        active.close()
        completed = _completed_active_run(run, result, active, allowance.calibration)
        if completed:
            active.limits._time_left()
        active.record_end(journal)
    except BaseException as failure:
        _record_active_failure(allowance, reservation_id, active, journal, failure)
        raise
    reason = active.failure_reason()
    outcome = "completed" if completed else "failed"
    settlement = _settle_active_run(allowance, reservation_id, failure_reason=reason, outcome=outcome)
    _require(outcome != "completed" or reason is None, "accepted-run-requires-reconciliation")
    expected = ("reconciliation-required", None) if reason else ("terminal", outcome)
    _require((settlement["state"], settlement["outcome"]) == expected and settlement["charge"] == reservation["amount"],
             "accounting-settlement-mismatch")
    result = _run_accounting_result(result, settlement, intent_event, mode="active")
    result["qualification_accounting"].update(effect_journal_path=str(active.limits._journal.path),
                                               effect_journal_last_event_sha256=active.limits._last_hash)
    return result


def _completed_active_run(run, result, active, calibration):
    if calibration is None:
        return _accepted(result, run.plan)
    _require(result.get("calibration_operation_sha256") == calibration.operation_sha256
             and result.get("state") == "CONTAINED" and calibration.result is not None
             and active.cleanup_confirmed is True and active.limits._calibration_complete(),
             "original-calibration-settlement-incomplete")
    calibration.verify_fixture()
    return True
