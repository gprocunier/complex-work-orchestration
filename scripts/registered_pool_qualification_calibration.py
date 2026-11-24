"""Run a separately signed, writer-held calibration through the original pool stage."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
from types import MethodType
from typing import Any, Mapping

from cwo_core import native_pool_qualification_stage as stage
from cwo_core.invocation_ledger import InvocationLedger
from cwo_core.native_pool_contracts import POOL_POLL_INTERVAL_MS
from cwo_core.native_pool_transaction import TransactionRuntime
from registered_pool_qualification import build_pool_qualification_runtime
from registered_pool_qualification_capability import (
    CallbackCalibrationError,
    ConnectedPoolCallbackCapability,
    begin_connected_callback_calibration,
    verify_connected_callback_calibration_opportunity,
)


@dataclass(frozen=True, slots=True)
class _CalibrationRequest:
    protected_parent: object
    manifest: dict[str, Any]
    directive: dict[str, Any]


def _require(condition: bool, reason: str) -> None:
    if not condition:
        raise CallbackCalibrationError(reason)


def _registered_parent(runtime: TransactionRuntime):
    from registered_pool_qualification import _PoolParent

    starter = runtime.start_worker_session
    _require(type(starter) is MethodType and type(runtime.prepare) is MethodType, "original-calibration-parent-required")
    owner = starter.__self__
    _require(type(owner) is _PoolParent and starter.__func__ is _PoolParent.start_worker
             and runtime.prepare.__self__ is owner and runtime.prepare.__func__ is _PoolParent.prepare,
             "original-calibration-parent-required")
    return owner


def run_protected_callback_calibration(protected_parent: object, *, plan: Mapping[str, Any], authority_path: Path,
    admission: object, manifest: dict[str, Any], directive: dict[str, Any],
    _campaign_approval: object = None) -> ConnectedPoolCallbackCapability:
    """Measure one signed cohort and return its opaque capability to this controller."""
    stage._require_contained_availability()
    _require(stage._original_campaign_approval(_campaign_approval) and _campaign_approval.parent is protected_parent,
             "signed-campaign-approval-required")
    run, accounting, request = _prepare_calibration(protected_parent, plan, authority_path, admission, manifest, directive)
    accounting = stage.PoolQualificationAccounting(accounting.ledger, accounting.expires_at, _campaign_approval)
    handle = stage.run_contained_pool_callback_calibration(run, accounting=accounting,
        binder=bind_protected_callback_calibration, request=request)
    _require(type(handle) is ConnectedPoolCallbackCapability, "original-calibration-capability-required")
    return handle


def verify_protected_callback_calibration_request(protected_parent: object, *, plan: Mapping[str, Any], authority_path: Path,
    admission: object, manifest: dict[str, Any], directive: dict[str, Any]) -> str:
    """Confirm one signed calibration request without reserving a start or opening a worker."""
    run, accounting, request = _prepare_calibration(protected_parent, plan, authority_path, admission, manifest, directive)
    stage._checked_callback_calibration_binding(bind_protected_callback_calibration)
    operation, _, _ = bind_protected_callback_calibration(run, accounting, request)
    return operation


def _prepare_calibration(protected_parent, plan, authority_path, admission, manifest, directive):
    stage._require_contained_availability()
    from run_native_pool_qualification import ProtectedPoolQualificationParent

    _require(type(protected_parent) is ProtectedPoolQualificationParent and type(manifest) is dict
             and type(directive) is dict and type(manifest.get("expires_at")) is int,
             "original-calibration-request-required")
    selection = stage.select_contained_pool_runtime(plan, build_pool_qualification_runtime,
                                                    authority_path=authority_path, admission=admission)
    parent = _registered_parent(selection.runtime)
    run = stage.make_pool_qualification_run(plan, selection, journal_path=parent.journal.path, fixture_root=parent.fixture_root)
    request = _CalibrationRequest(protected_parent, deepcopy(manifest), deepcopy(directive))
    accounting = stage.PoolQualificationAccounting(InvocationLedger(stage.contained_campaign_ledger_root()),
                                                   request.manifest["expires_at"])
    return run, accounting, request


def bind_protected_callback_calibration(run, accounting, request):
    """Bind the original adapter and signed opportunity before reserving a start."""
    _require(type(request) is _CalibrationRequest and accounting.expires_at == request.manifest["expires_at"],
             "original-calibration-request-required")
    parent = _registered_parent(run.runtime)
    _require(parent.plan == run.plan and parent.journal.path == run.journal_path
             and parent.fixture_root == run.fixture_root, "calibration-adapter-plan-or-paths-drift")
    action = verify_connected_callback_calibration_opportunity(parent, request.protected_parent,
        manifest=request.manifest, directive=request.directive)

    def drive(plan, allocations, context, require_release_horizon):
        parent.bind_calibration_controls(plan, allocations, context)
        require_release_horizon()
        observer = begin_connected_callback_calibration(parent, request.protected_parent,
            manifest=request.manifest, directive=request.directive)
        return _measure_original_controls(parent, observer)

    return action, request.manifest["runtime_seconds"], drive


def _measure_original_controls(parent, observer):
    controls = parent.controls
    _require(parent.limits.calibration_only and controls.keys() == parent.children.keys(),
             "original-writer-held-controls-required")
    for child, control in controls.items():
        _begin_control(parent.limits, observer, child, control)
    _observe_initial_polls(controls, observer)
    _await_original_contexts(controls)
    for control in controls.values():
        observer.observe_callback(control, "interrupt", agent_id=control.worker.thread_id,
                                  message="STOP: native supervisor decision interrupt")
    for control in controls.values():
        _finish_control(observer, control)
    return observer.finalize()


def _binding(control) -> dict[str, Any]:
    return {"state_file": control.contract["state_file"], "control_turn_id": control.contract["control_turn_id"]}


def _begin_control(limits, observer, child, control):
    binding = _binding(control)
    observer.observe_callback(control, "arm", **binding)
    send = limits._wrap_send(child, lambda **kwargs: observer.observe_callback(control, "send_input", **kwargs))
    started = send(agent_id=control.worker.thread_id, message=control.worker.task["prompt"])
    observer.observe_callback(control, "mark_dispatched", submission_id=started["submission_id"], **binding)


def _observe_initial_polls(controls, observer):
    measured = set()
    for _ in controls:
        selected = observer.observe_scheduler()
        child = selected.child_id
        _require(child not in measured, "calibration-scheduler-missed-original-worker")
        result = observer.observe_callback(controls[child], "check", **_binding(controls[child]))
        _require(result.get("decision") == "continue", "calibration-worker-ended-before-interrupt")
        measured.add(child)


def _await_original_contexts(controls):
    # Codex can acknowledge the turn before its initial context is durable.
    first = next(iter(controls.values()))
    while True:
        ready = tuple(control.worker.calibration_context_ready() for control in controls.values())
        if all(ready):
            return
        first.sleep(seconds=POOL_POLL_INTERVAL_MS / 1000)


def _finish_control(observer, control):
    binding = _binding(control)
    # The original polling wait is outside callback and scheduler measurements.
    while True:
        result = observer.observe_callback(control, "check", **binding)
        if result.get("decision") == "complete":
            break
        _require(result.get("decision") == "continue", "calibration-terminal-observation-refused")
        control.sleep(seconds=1.0)
    observer.observe_callback(control, "finalize", control_action="interrupt-confirmed", **binding)
    observer.observe_callback(control, "close", agent_id=control.worker.thread_id)
