"""Measure the writer-held original contained pool controls."""

from __future__ import annotations

from typing import TYPE_CHECKING, Mapping

from cwo_core.native_pool_contracts import POOL_POLL_INTERVAL_MS
from registered_pool_qualification import is_original_pool_parent
from registered_pool_qualification_capability import CallbackCalibrationError, ConnectedCallbackCalibration, ConnectedPoolCallbackCapability

if TYPE_CHECKING:
    import registered_pool_qualification as qualification
    from cwo_core.native_pool_qualification_stage import PoolQualificationRunLimits


def _require(condition: bool, reason: str) -> None:
    if not condition:
        raise CallbackCalibrationError(reason)


def measure_original_controls(
    parent: qualification._PoolParent, observer: ConnectedCallbackCalibration,
) -> ConnectedPoolCallbackCapability:
    _require(is_original_pool_parent(parent) and type(observer) is ConnectedCallbackCalibration,
             "original-writer-held-controls-required")
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


def _binding(control: qualification._WorkerControl) -> dict[str, str]:
    return {"state_file": control.contract["state_file"], "control_turn_id": control.contract["control_turn_id"]}


def _begin_control(
    limits: PoolQualificationRunLimits, observer: ConnectedCallbackCalibration,
    child: str, control: qualification._WorkerControl,
) -> None:
    binding = _binding(control)
    observer.observe_callback(control, "arm", **binding)
    send = limits._wrap_send(child, lambda **kwargs: observer.observe_callback(control, "send_input", **kwargs))
    started = send(agent_id=control.worker.thread_id, message=control.worker.task["prompt"])
    observer.observe_callback(control, "mark_dispatched", submission_id=started["submission_id"], **binding)


def _observe_initial_polls(
    controls: Mapping[str, qualification._WorkerControl], observer: ConnectedCallbackCalibration,
) -> None:
    measured = set()
    for _ in controls:
        selected = observer.observe_scheduler()
        child = selected.child_id
        _require(child not in measured, "calibration-scheduler-missed-original-worker")
        result = observer.observe_callback(controls[child], "check", **_binding(controls[child]))
        _require(result.get("decision") == "continue", "calibration-worker-ended-before-interrupt")
        measured.add(child)


def _await_original_contexts(controls: Mapping[str, qualification._WorkerControl]) -> None:
    # Codex can acknowledge the turn before its initial context is durable.
    first = next(iter(controls.values()))
    while True:
        ready = tuple(control.worker.calibration_context_ready() for control in controls.values())
        if all(ready):
            return
        first.sleep(seconds=POOL_POLL_INTERVAL_MS / 1000)


def _finish_control(observer: ConnectedCallbackCalibration, control: qualification._WorkerControl) -> None:
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
