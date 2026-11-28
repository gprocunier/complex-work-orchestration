"""Own scoped authority for contained pool qualification."""

from __future__ import annotations

from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import InitVar, dataclass
from pathlib import Path
from threading import Lock, get_ident
from time import monotonic
from types import MappingProxyType
from typing import Any, TypeGuard

from .native_pool_admission import NativePoolAdmissionError
from .native_pool_contracts import canonical_sha256
from .native_pool_deferred_attestation import (
    DeferredAttestationError as DeferredAttestationError,
    DeferredWorkerTurnEvidence as DeferredWorkerTurnEvidence,
    ObservedExchangeDigest as ObservedExchangeDigest,
    ProvisionalWorkerStartup as ProvisionalWorkerStartup,
    QUALIFICATION_TOOL as QUALIFICATION_TOOL,
    require_deferred_attestation as require_deferred_attestation,
    require_deferred_deadline as require_deferred_deadline,
)
from .native_tool_isolation import (
    ContainedPoolChildBinding, NativeToolIsolationError, contained_pool_tool_surface, is_contained_pool_tool_policy,
)

QUALIFICATION_MODEL = "gpt-6.2-sol"
QUALIFICATION_EFFORT = "xhigh"
QUALIFICATION_TIER = "default"
QUALIFICATION_PROFILE = "cwo-pool-contained"
QUALIFICATION_SURFACE = "connected-codex"
QUALIFICATION_ADAPTER_VERSION = "pool-contained-v1"

_CONTAINED_POOL_TOKEN = object()
_RUNTIME_TOKEN = object()
_ADMISSION_TOKEN = object()


@dataclass(frozen=True, slots=True)
class _ContainedPoolToolScope:
    children: Mapping[str, ContainedPoolChildBinding]
    model: str
    check_active: Callable[[], None]
    issuer: InitVar[object]

    def __post_init__(self, issuer: object) -> None:
        if issuer is not _CONTAINED_POOL_TOKEN:
            raise NativeToolIsolationError("contained-pool-tool-scope-untrusted")
        object.__setattr__(self, "children", MappingProxyType(dict(self.children)))


_CONTAINED_POOL_SCOPE: ContextVar[_ContainedPoolToolScope | None] = ContextVar("contained_pool_tool_scope", default=None)


@contextmanager
def _contained_pool_tool_validation(scope: _ContainedPoolToolScope) -> Iterator[None]:
    """Keep protected validation within the original synchronous transaction."""
    if type(scope) is not _ContainedPoolToolScope or _CONTAINED_POOL_SCOPE.get() is not None:
        raise NativeToolIsolationError("contained-pool-tool-scope-untrusted")
    token = _CONTAINED_POOL_SCOPE.set(scope)
    try:
        yield
    finally:
        _CONTAINED_POOL_SCOPE.reset(token)


def _active_contained_tool_scope() -> _ContainedPoolToolScope | None:
    scope = _CONTAINED_POOL_SCOPE.get()
    if scope is not None:
        scope.check_active()
    return scope


def contained_pool_tool_validation_active() -> bool:
    return _active_contained_tool_scope() is not None


def contained_pool_child_binding_errors(child: Mapping[str, Any], phase: str, prefix: str) -> list[str]:
    scope = _active_contained_tool_scope()
    if scope is None:
        return []
    child_id = child.get("child_id")
    expected = scope.children.get(child_id) if type(child_id) is str else None
    if expected is None or not _contained_pool_child_binding_matches(child, expected):
        return [f"{prefix}-contained-child-binding-mismatch"]
    if not _contained_pool_phase_matches(child, expected, scope.model, phase):
        return [f"{prefix}-contained-{phase}-binding-mismatch"]
    return []


def _contained_pool_child_binding_matches(child: Mapping[str, Any], expected: ContainedPoolChildBinding) -> bool:
    policy = child.get("tool_policy")
    return (child.get("isolation_class") == "mutable-isolated"
            and child.get("declared_write_paths") == child.get("integration_target_paths") == [expected.write_path]
            and isinstance(policy, Mapping) and is_contained_pool_tool_policy(policy))


def _contained_pool_phase_matches(child: Mapping[str, Any], expected: ContainedPoolChildBinding, model: str, phase: str) -> bool:
    if child.get("requested_model") != model:
        return False
    if phase == "contract":
        return (isinstance(child.get("worktree_identity"), Mapping)
                and canonical_sha256(child["worktree_identity"]) == expected.worktree_identity_sha256)
    if (child.get("worktree") != expected.worktree
            or child.get("worktree_identity_sha256") != expected.worktree_identity_sha256):
        return False
    if phase == "preflight":
        return (child.get("prompt") == expected.prompt
                and child.get("tool_surface") == contained_pool_tool_surface())
    return phase == "render"


@dataclass(frozen=True, slots=True)
class ContainedPoolSelection:
    """Exact runtime returned by the registered contained qualification factory."""

    plan_sha256: str
    factory_path: str
    factory_sha256: str
    runtime: object
    bind_limits: Callable[..., None]
    cleanup: Callable[[float], bool]
    issuer: InitVar[object]
    ordinary: object | None = None

    def __post_init__(self, issuer: object) -> None:
        _require(issuer is _RUNTIME_TOKEN, "contained-runtime-construction-refused")


@dataclass(slots=True)
class QualificationCalibration:
    """Describe the operation used by the original calibration transaction."""
    operation_sha256: str
    drive: Callable[..., object]
    verify_fixture: Callable[[], None]
    result: object | None = None


def contained_selection_binding(
    selection: ContainedPoolSelection, plan: Mapping[str, Any], runtime: object,
) -> str:
    _require(type(selection) is ContainedPoolSelection and selection.runtime is runtime,
             "contained-factory-runtime-mismatch")
    expected = (plan["plan_sha256"], plan["runtime_adapter_path"], plan["runtime_adapter_sha256"])
    _require((selection.plan_sha256, selection.factory_path, selection.factory_sha256) == expected,
             "contained-factory-plan-mismatch")
    return contained_plan_binding(plan)


def contained_plan_binding(plan: Mapping[str, Any]) -> str:
    """Commit to the signed plan's prospective factory selection without issuing it."""
    return canonical_sha256({
        "scope": "stock-codex-contained-pool",
        "plan_sha256": plan["plan_sha256"],
        "runtime_adapter_path": plan["runtime_adapter_path"],
        "runtime_adapter_sha256": plan["runtime_adapter_sha256"],
        "model": QUALIFICATION_MODEL,
        "effort": QUALIFICATION_EFFORT,
        "service_tier": QUALIFICATION_TIER,
        "profile": QUALIFICATION_PROFILE,
    })


class ContainedPoolAdmission:
    """Stage-minted custody for one runtime, transaction and cohort."""

    def __init__(
        self, issuer: object, *, selection: ContainedPoolSelection, plan: Mapping[str, Any],
        journal_path: Path, check_custody: Callable[[], None], check_source: Callable[[], None],
        check_availability: Callable[[], None],
        policy_children: Mapping[str, ContainedPoolChildBinding], deadline: float,
        calibration: QualificationCalibration | None = None,
    ) -> None:
        _require(issuer is _ADMISSION_TOKEN, "contained-admission-construction-refused")
        self._selection = selection
        self._plan = plan
        self._journal_path = journal_path
        self._check_custody = check_custody
        self._check_source = check_source
        self._check_availability = check_availability
        self._cutoff = deadline
        self._children = frozenset(row["child_id"] for row in plan["children"])
        self._claim_lock = Lock()
        self._claimed = False
        self._runtime: object | None = None
        self._startups: dict[str, ProvisionalWorkerStartup] = {}
        self._proofs: dict[str, tuple[DeferredWorkerTurnEvidence, int]] = {}
        self._tool_scope = _ContainedPoolToolScope(policy_children, QUALIFICATION_MODEL, self._check_tool_scope,
                                                    _CONTAINED_POOL_TOKEN)
        self._launch_inputs: tuple[object, ...] | None = None
        self._launch_artifacts_sha256: str | None = None
        self._dispatch_consumed = False
        self._calibration = calibration

    def _guard(self) -> None:
        _require_deadline(self._cutoff, now=monotonic())
        self._check_custody()

    def _check_tool_scope(self) -> None:
        _require(self._claimed, "contained-tool-validation-without-transaction")
        _require_deadline(self._cutoff, now=monotonic())

    def _tool_validation(self):
        self._guard()
        self._check_availability()
        return _contained_pool_tool_validation(self._tool_scope)

    def bind_runtime(self, runtime: object) -> None:
        _require(self._runtime is None, "contained-runtime-already-bound")
        self._runtime = runtime

    def require_transaction(self, plan: Mapping[str, Any], journal_path: str | Path, runtime: object) -> None:
        self._check_availability()
        self._guard()
        _require(plan == self._plan and Path(journal_path) == self._journal_path and runtime is self._runtime,
                 "contained-transaction-binding-mismatch")
        self._check_source()
        with self._claim_lock:
            _require(not self._claimed, "contained-transaction-already-claimed")
            self._claimed = True

    def retain(
        self, startup: object, child: Mapping[str, Any], allocation_id: str, intent_sha256: str,
    ) -> dict[str, Any]:
        self._guard()
        _require(self._claimed and type(startup) is ProvisionalWorkerStartup, "contained-provisional-worker-required")
        child_id = child["child_id"]
        expected = (self._selection.plan_sha256, allocation_id, intent_sha256, child_id,
                    child["worktree_identity_sha256"], QUALIFICATION_MODEL, QUALIFICATION_EFFORT, self._cutoff)
        actual = (startup.plan_sha256, startup.allocation_id, startup.allocation_intent_event_sha256,
                  startup.child_id, startup.worktree_identity_sha256, startup.model, startup.effort, startup.deadline)
        _require(actual == expected and child_id not in self._startups, "contained-provisional-startup-mismatch")
        existing = self._startups.values()
        _require(all((startup.session_id != item.session_id and startup.session_path != item.session_path
                      and startup.owner_identity_sha256 != item.owner_identity_sha256
                      and startup.connection_epoch_sha256 != item.connection_epoch_sha256) for item in existing),
                 "contained-startup-owner-reused")
        self._startups[child_id] = startup
        return {"allocation_id": allocation_id, "allocation_class": "worker", "child_id": child_id,
                "session_id": startup.session_id, "requested_model": startup.model, "actual_model": startup.model,
                "workspace_identity_sha256": startup.worktree_identity_sha256, "outcome": "provisional"}

    def require_launch(self, receipt: object, inputs: tuple[object, ...]) -> None:
        self._guard()
        _require(self._calibration is None, "calibration-productive-launch-refused")
        _require(self._startups.keys() == self._children and isinstance(receipt, Mapping)
                 and receipt.get("execution_surface") == QUALIFICATION_SURFACE
                 and receipt.get("adapter_version") == QUALIFICATION_ADAPTER_VERSION, "contained-cohort-required")
        _require(self._launch_inputs is None, "contained-cohort-already-bound")
        self._launch_inputs = inputs
        self._launch_artifacts_sha256 = _dispatch_artifact_hash(inputs)

    def require_dispatch(self, scope: _ContainedPoolToolScope, inputs: tuple[object, ...], *, consume: bool) -> None:
        self._check_availability()
        self._guard()
        _require(self._calibration is None, "calibration-productive-dispatch-refused")
        _require(scope is self._tool_scope and self._launch_inputs is not None
                 and len(inputs) == len(self._launch_inputs)
                 and all(actual is expected for actual, expected in zip(inputs, self._launch_inputs))
                 and self._launch_artifacts_sha256 == _dispatch_artifact_hash(inputs),
                 "contained-dispatch-original-inputs-required")
        if consume:
            self._check_source()
            _require(not self._dispatch_consumed, "contained-dispatch-already-consumed")
            self._dispatch_consumed = True

    def run_calibration(self, plan, allocations, context, require_release_horizon) -> str:
        self._check_availability()
        self._guard()
        self._check_source()
        calibration = self._calibration
        _require(calibration is not None and self._claimed and not self._dispatch_consumed
                 and self._startups.keys() == self._children and plan == self._plan, "calibration-original-cohort-required")
        self._dispatch_consumed = True
        calibration.result = calibration.drive(plan, allocations, context, require_release_horizon)
        self._guard()
        _require(calibration.result is not None, "calibration-original-observation-required")
        return calibration.operation_sha256

    def record_proof(
        self, proof: DeferredWorkerTurnEvidence, *, thread_id: str | None, turn_id: str | None,
    ) -> None:
        self._guard()
        child_id = proof.startup.child_id
        _require(self._startups.get(child_id) is proof.startup and child_id not in self._proofs
                 and thread_id == proof.startup.session_id and turn_id == proof.turn_id,
                 "contained-turn-proof-binding-mismatch")
        self._proofs[child_id] = proof, get_ident()

    def require_proved_request(self, child_id: str, thread_id: str, turn_id: str,
                               request_id: int | str) -> DeferredWorkerTurnEvidence:
        self._guard()
        entry = self._proofs.get(child_id)
        _require(entry is not None, "contained-turn-proof-before-debit-required")
        proof, receiver = entry
        _require((proof.startup.session_id, proof.turn_id, type(proof.request_id), proof.request_id, receiver)
                 == (thread_id, turn_id, type(request_id), request_id, get_ident()),
                 "contained-turn-proof-before-debit-required")
        return proof

    def require_resolved(self) -> None:
        self._guard()
        _require(self._startups.keys() == self._children == self._proofs.keys(),
                 "contained-provisional-workers-unresolved")


def is_claimed_contained_pool_admission(value: object) -> TypeGuard[ContainedPoolAdmission]:
    return type(value) is ContainedPoolAdmission and value._claimed


def require_contained_pool_dispatch(admission: object, activation: object, inputs: tuple[object, ...], *,
                                    consume: bool = False) -> None:
    scope = _active_contained_tool_scope()
    if scope is None and admission is None:
        return
    if scope is None or type(admission) is not ContainedPoolAdmission or activation is not None:
        raise NativePoolAdmissionError("contained-pool-dispatch-authority-required")
    try:
        admission.require_dispatch(scope, inputs, consume=consume)
    except DeferredAttestationError as failure:
        raise NativePoolAdmissionError(str(failure)) from failure


def _dispatch_artifact_hash(inputs: tuple[object, ...]) -> str:
    reservation, _, contract, request, result, controls, prompts, _, capability, _, _ = inputs
    return canonical_sha256({"reservation": reservation, "contract": contract, "preflight_request": request,
                             "preflight_result": result, "child_contracts": controls, "task_inputs": prompts,
                             "capability_receipt": capability})


_require = require_deferred_attestation
_require_deadline = require_deferred_deadline
