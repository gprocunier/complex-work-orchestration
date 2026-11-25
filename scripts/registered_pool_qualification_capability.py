"""Measure the original contained control adapter and retain its capability in process."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from math import ceil
import os
from pathlib import Path
import re
from threading import Lock, get_ident
from time import monotonic_ns
from typing import Any, Mapping
from weakref import WeakKeyDictionary

from cwo_core.invocation_ledger import InvocationLedger, MAX_UNITS
from cwo_core.native_authority import canonical_authority_sha256, verify_operator_directive
from cwo_core.native_pool_contracts import (
    CAPABILITY_RECEIPT_SCHEMA,
    CAPABILITY_RECEIPT_TYPE,
    CERTIFIED_CALLBACK_MAX_MS,
    CERTIFIED_SCHEDULER_OVERHEAD_MS,
    POOL_POLL_INTERVAL_MS,
    REQUIRED_CAPABILITY_CALLBACKS,
    canonical_sha256,
    callback_certification_policy_sha256,
    seal_artifact,
    validate_capability_receipt,
)
from cwo_core.native_pool_leases import capture_owner_identity
from cwo_core.native_pool_scheduler import select_earliest_deadline
from cwo_core.workspace_capture import _pin_directory, read_at
from run_native_pool_live_canaries import _measure_action_ms, callback_certification_policy, stats

_CALIBRATION_SCOPE = "contained-pool-callback-calibration-v1"
_CALIBRATION_FIELDS = {"scope", "calibration_plan_sha256", "adapter_scope_sha256", "expires_at", "runtime_seconds"}
_SOURCE_PATHS = (
    "registered_pool_qualification_capability.py",
    "registered_pool_qualification_calibration.py",
    "registered_pool_qualification.py",
    "registered_pool_containment.py",
    "registered_pool_configuration.py",
    "registered_app_server_transport.py",
    "registered_finite_tool_calls.py",
    "registered_server_requests.py",
    "cwo_core/native_pool.py",
    "cwo_core/native_pool_scheduler.py",
    "cwo_core/native_pool_qualification_budget.py",
    "cwo_core/native_pool_qualification_stage.py",
    "cwo_core/supervision/transport/app_server.py",
    "run_native_pool_live_canaries.py",
)
_SHA256 = re.compile(r"[0-9a-f]{64}")
_MAX_SAMPLES = 64
_MAX_SOURCE_BYTES = 2 * 1024 * 1024
_CALLBACK_ORDER = ("arm", "send_input", "mark_dispatched", "check", "interrupt", "finalize", "close")
_TOKEN = object()
_CLAIMS: set[str] = set()
_CLAIMS_LOCK = Lock()
_ISSUED = WeakKeyDictionary()
_ISSUED_LOCK = Lock()


class CallbackCalibrationError(ValueError):
    """An original callback observation or the protected calibration authority differed."""


def _require(condition: bool, reason: str) -> None:
    if not condition:
        raise CallbackCalibrationError(reason)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _digest(value: Any) -> bool:
    return type(value) is str and _SHA256.fullmatch(value) is not None


def _source_digest() -> str:
    root = Path(__file__).resolve().parent
    return canonical_sha256({name: _source_file_sha256(root / name) for name in _SOURCE_PATHS})


def _source_file_sha256(path: Path) -> str:
    pinned = _pin_directory(str(path.parent))
    _require(pinned is not None, "calibration-source-directory-refused")
    directory, _ = pinned
    try:
        kind, source, info = read_at(directory, path.name, _MAX_SOURCE_BYTES)
    finally:
        os.close(directory)
    _require(kind == "file" and source is not None and info is not None and info.st_nlink == 1
             and info.st_uid in (0, os.geteuid()) and not info.st_mode & 0o022, "calibration-source-custody-refused")
    return sha256(source).hexdigest()


def _protected_types():
    # The module is usable on its own before the composed adapter/controller is installed.
    from cwo_core.native_pool_qualification_stage import PoolQualificationRunLimits
    from registered_pool_containment import PoolWorkerContainment
    from registered_pool_qualification import _PoolParent, _WorkerControl
    from run_native_pool_qualification import ProtectedPoolQualificationParent

    return _PoolParent, _WorkerControl, PoolWorkerContainment, PoolQualificationRunLimits, ProtectedPoolQualificationParent


def calibration_action_sha256(manifest: Mapping[str, Any]) -> str:
    """Return the operator directive's exact action digest."""
    return canonical_authority_sha256(dict(manifest))


def callback_adapter_scope_sha256(parent: object) -> str:
    """Bind stock executable, adapter sources, containment selection and requested capacity."""
    from cwo_core.native_pool_deferred_context import QUALIFICATION_MODEL

    parent_type, *_ = _protected_types()
    _require(type(parent) is parent_type and parent.plan["selected_model"] == QUALIFICATION_MODEL,
             "original-calibration-adapter-required")
    return _adapter_scope_sha256(parent.plan, parent.authority, len(parent.children))


def calibration_adapter_scope_sha256(plan: Mapping[str, Any], authority: Mapping[str, Any]) -> str:
    """Commit to the calibration plan and host configuration before measuring it."""
    return _adapter_scope_sha256(plan, authority, len(plan["children"]))


def _adapter_scope_sha256(plan: Mapping[str, Any], authority: Mapping[str, Any], cohort_size: int) -> str:
    from cwo_core.native_pool_deferred_context import (
        QUALIFICATION_ADAPTER_VERSION, QUALIFICATION_EFFORT, QUALIFICATION_MODEL, QUALIFICATION_PROFILE, QUALIFICATION_TIER,
    )

    return canonical_sha256({
        "implementation_sha256": _source_digest(),
        "runtime_adapter_sha256": plan["runtime_adapter_sha256"],
        "adapter_version": QUALIFICATION_ADAPTER_VERSION,
        "host": authority["host"],
        "model": QUALIFICATION_MODEL,
        "effort": QUALIFICATION_EFFORT,
        "service_tier": QUALIFICATION_TIER,
        "profile": QUALIFICATION_PROFILE,
        "cohort_size": cohort_size,
        "control_turn_id": authority["render_request"]["control_turn_id"],
    })


@dataclass(frozen=True, slots=True)
class _CalibrationOpportunity:
    operation_sha256: str
    plan_sha256: str
    scope_sha256: str
    expires_at: int
    runtime_seconds: int
    controller: tuple[tuple[str, Any], ...]


def _verify_opportunity(protected_parent: object, manifest: dict[str, Any], directive: Mapping[str, Any]) -> _CalibrationOpportunity:
    *_, verification_type = _protected_types()
    _require(type(protected_parent) is verification_type, "original-calibration-parent-required")
    _require(type(manifest) is dict and manifest.keys() == _CALIBRATION_FIELDS
             and manifest["scope"] == _CALIBRATION_SCOPE and _digest(manifest["calibration_plan_sha256"])
             and _digest(manifest["adapter_scope_sha256"]), "calibration-opportunity-invalid")
    operation_sha256 = calibration_action_sha256(manifest)
    verified = verify_operator_directive(directive, verification_key=protected_parent.verification_key,
        expected_actor_id=protected_parent.actor_id, expected_identity_source=protected_parent.identity_source,
        expected_action_sha256=operation_sha256)
    issued = datetime.fromisoformat(directive["issued_at"].replace("Z", "+00:00"))
    expires, runtime = manifest["expires_at"], manifest["runtime_seconds"]
    _require(verified.authorized_scope == "complete-task" and directive["parent_receipt_sha256"] is None
             and issued.tzinfo is not None and type(expires) is int and issued.timestamp() <= _now().timestamp() < expires
             and type(runtime) is int and 0 < runtime <= MAX_UNITS, "calibration-opportunity-expired-or-unbounded")
    return _CalibrationOpportunity(operation_sha256, manifest["calibration_plan_sha256"],
                                   manifest["adapter_scope_sha256"], expires, runtime,
                                   tuple(sorted(capture_owner_identity().items())))


def _require_calibration_scope(parent: object, opportunity: _CalibrationOpportunity) -> None:
    parent_type, *_ = _protected_types()
    _require(type(parent) is parent_type, "original-calibration-adapter-required")
    parent._verify_artifacts()
    _require(parent.plan["plan_sha256"] == opportunity.plan_sha256
             and parent.authority.get("mode") == "callback-calibration"
             and callback_adapter_scope_sha256(parent) == opportunity.scope_sha256,
             "calibration-opportunity-binding-mismatch")


def verify_connected_callback_calibration_opportunity(parent: object, protected_parent: object, *,
    manifest: dict[str, Any], directive: Mapping[str, Any]) -> str:
    """Check the selected signed calibration before the protected parent charges a start."""
    opportunity = _verify_opportunity(protected_parent, manifest, directive)
    _require_calibration_scope(parent, opportunity)
    return opportunity.operation_sha256


def _charged_start(parent: object, opportunity: _CalibrationOpportunity) -> tuple[InvocationLedger, str]:
    custody = _active_campaign_start(parent)
    _require_calibration_scope(parent, opportunity)
    _require(parent.limits._intent["amount"]["runtime_seconds"] == opportunity.runtime_seconds,
             "calibration-opportunity-runtime-mismatch")
    return custody


def _require_campaign_cap(ledger: InvocationLedger, budget_id: str) -> None:
    from cwo_core.native_pool_qualification_stage import campaign_start_status

    summary = campaign_start_status(ledger)
    _require(budget_id in summary["budget_ids"] and 1 <= summary["charged"] <= summary["cap"],
             "calibration-campaign-cap-unverified")


def _active_campaign_start(parent: object) -> tuple[InvocationLedger, str]:
    from cwo_core.native_pool_deferred_context import _ContainedPoolAdmission
    from cwo_core.native_pool_qualification_stage import contained_campaign_ledger_root

    parent_type, _, _, limits_type, _ = _protected_types()
    _require(type(parent) is parent_type and type(parent.limits) is limits_type, "original-calibration-stage-required")
    parent.require_effect()
    limits = parent.limits
    admission = limits._contained_admission
    _require(type(admission) is _ContainedPoolAdmission and admission._claimed and admission._plan == parent.plan,
             "original-calibration-stage-required")
    allowance = limits._allowance
    ledger, intent = allowance.accounting.ledger, allowance.campaign_intent
    _require(type(ledger) is InvocationLedger and ledger.root == contained_campaign_ledger_root()
             and type(intent) is dict and intent["state"] == "invocation-intent" and intent["amount"] == {"starts": 1}
             and ledger.attempt(intent["reservation_id"]) == intent, "calibration-campaign-start-not-charged")
    _require_campaign_cap(ledger, intent["budget_id"])
    return ledger, intent["reservation_id"]


def begin_connected_callback_calibration(parent: object, protected_parent: object, *,
                                         manifest: dict[str, Any], directive: Mapping[str, Any]) -> ConnectedCallbackCalibration:
    """Attach measurement to an already charged, separately signed original cohort."""
    opportunity = _verify_opportunity(protected_parent, manifest, directive)
    ledger, reservation = _charged_start(parent, opportunity)
    with _CLAIMS_LOCK:
        _require(opportunity.operation_sha256 not in _CLAIMS and reservation not in _CLAIMS, "calibration-already-claimed")
        _CLAIMS.update((opportunity.operation_sha256, reservation))
    return ConnectedCallbackCalibration(_TOKEN, parent, opportunity, (ledger, reservation))


def _contained_owner(control: object, host_type: type) -> tuple[str, str, int]:
    worker = control.worker
    host = worker.containment
    _require(type(host) is host_type, "original-calibration-host-required")
    receipt = host.receipt()
    observations = [row["observation"] for row in receipt["observations"] if row["stage"] == "appserver-contained"]
    _require(len(observations) == 1, "original-appserver-containment-required")
    original, = observations
    owner = host.owner_identity_sha256
    _require(_digest(owner) and original.get("owner_identity_sha256") == owner
             and original.get("scope") == "worker-only-appserver"
             and original.get("worktree_readonly") is True and original.get("filesystem_ready") is True
             and original.get("network") == "registered-provider-tunnel"
             and original.get("managed_login_projection") is True, "original-appserver-containment-required")
    _require(_digest(receipt["config_sha256"]) and type(receipt["login_slot"]) is int and receipt["login_slot"] > 0,
             "original-host-config-or-login-missing")
    return owner, receipt["config_sha256"], receipt["login_slot"]


def _require_original_thread(control: object, owner: str) -> None:
    from cwo_core.native_pool_deferred_context import (
        ProvisionalWorkerStartup, QUALIFICATION_EFFORT, QUALIFICATION_MODEL, QUALIFICATION_PROFILE,
    )

    worker = control.worker
    startup = worker._startup
    _require(type(startup) is ProvisionalWorkerStartup and startup.owner_identity_sha256 == owner
             and startup.child_id == worker.child_id and startup.session_id == worker.thread_id
             and startup.connection_epoch_sha256 == worker.wire.connection_epoch_sha256
             and (startup.model, startup.effort, startup.profile) == (
                 QUALIFICATION_MODEL, QUALIFICATION_EFFORT, QUALIFICATION_PROFILE),
             "original-calibration-thread-required")


def _terminal_evidence(control: object) -> None:
    worker = control.worker
    terminal = worker._result
    receipt = worker.containment.receipt()
    _require(type(terminal) is dict and terminal.get("terminal", {}).get("status") == "interrupted"
             and type(worker._archived) is dict and receipt.get("cleanup_confirmed") is True and receipt.get("failed") is False,
             "original-interruption-archive-or-cleanup-missing")
    try:
        _, interrupt = worker.wire.exchange("turn/interrupt")
    except (KeyError, TypeError, ValueError) as failure:
        raise CallbackCalibrationError("original-interrupt-exchange-missing") from failure
    _require(_digest(interrupt.get("request_sha256")) and _digest(interrupt.get("response_sha256")),
             "original-interrupt-exchange-missing")
    terminated = [row["observation"] for row in receipt["observations"] if row["stage"] == "appserver-terminated"]
    _require(len(terminated) == 1 and terminated[0].get("child_exit_confirmed") is True
             and terminated[0].get("child_reaped") is True, "original-appserver-exit-unconfirmed")


def _observed_ms(action, ceiling_ms: float, *, on_overrun=None):
    # The legacy collector accepts an optional artificial guard. The contained path never uses it.
    result, elapsed = _measure_action_ms(action)
    if not 0 <= elapsed <= ceiling_ms:
        failure = CallbackCalibrationError("observed-callback-exceeds-certification")
        if on_overrun is not None:
            try:
                on_overrun(elapsed)
            except BaseException:
                failure.add_note("calibration-slow-close-record-failed")
        raise failure
    return result, elapsed


def _observe_close(control, action, ceiling_ms):
    from registered_pool_containment import (
        _CALIBRATION_CLOSE_MAX_US, _CALIBRATION_CLOSE_PHASES, _CALIBRATION_CLOSE_TIMES,
    )

    timings = dict.fromkeys(_CALIBRATION_CLOSE_PHASES)
    token = _CALIBRATION_CLOSE_TIMES.set(timings)

    def record_overrun(elapsed_ms):
        total_us = min(_CALIBRATION_CLOSE_MAX_US, max(0, ceil(elapsed_ms * 1000)))
        control.worker.containment.record("calibration-slow-close", {"total_us": total_us, **timings})

    try:
        return _observed_ms(action, ceiling_ms, on_overrun=record_overrun)
    finally:
        _CALIBRATION_CLOSE_TIMES.reset(token)


class ConnectedCallbackCalibration:
    """One original controller's measurements of original child controls and scheduler."""

    def __init__(self, token, parent, opportunity, custody):
        _require(token is _TOKEN, "calibration-construction-refused")
        self._parent, self._opportunity, self._custody = parent, opportunity, custody
        self._controls = dict(parent.controls)
        _, control_type, host_type, _, _ = _protected_types()
        _require(len(self._controls) in (2, 3) and self._controls.keys() == parent.children.keys()
                 and all(type(control) is control_type and control.worker is parent.workers[key]
                         for key, control in self._controls.items()), "original-calibration-controls-required")
        self._owners = {key: _contained_owner(control, host_type) for key, control in self._controls.items()}
        for child, control in self._controls.items():
            _require_original_thread(control, self._owners[child][0])
        _require(len({owner[0] for owner in self._owners.values()}) == len(self._owners)
                 and len({owner[2] for owner in self._owners.values()}) == len(self._owners),
                 "calibration-reuses-owner-or-login")
        self._samples = {name: {} for name in REQUIRED_CAPABILITY_CALLBACKS}
        self._scheduler_samples: list[float] = []
        self._poll_deadlines: dict[str, int] = {}
        self._cursor = 0
        self._selected_child = None
        self._thread = get_ident()
        self._finished = False
        self._failed = False

    def _verify(self) -> None:
        _require(not self._finished and not self._failed and self._thread == get_ident()
                 and _now().timestamp() < self._opportunity.expires_at
                 and tuple(sorted(capture_owner_identity().items())) == self._opportunity.controller,
                 "calibration-closed-expired-or-owner-changed")
        _require(_active_campaign_start(self._parent) == self._custody, "calibration-campaign-custody-changed")

    def observe_callback(self, control: object, name: str, /, **arguments):
        """Invoke and time a known callback using its original bound control."""
        self._verify()
        _, control_type, host_type, _, _ = _protected_types()
        _require(type(control) is control_type and name in self._samples, "original-calibration-callback-required")
        child = control.worker.child_id
        _require(self._controls.get(child) is control and self._parent.controls.get(child) is control
                 and self._owners[child] == _contained_owner(control, host_type), "calibration-control-custody-changed")
        _require_original_thread(control, self._owners[child][0])
        self._require_next_callback(child, name)
        bucket = self._samples[name].setdefault(child, [])
        _require(len(bucket) < _MAX_SAMPLES, "calibration-sample-bound-exceeded")
        callback = vars(control_type)[name].__get__(control, control_type)

        def action():
            return callback(**arguments)

        ceiling = CERTIFIED_CALLBACK_MAX_MS[name]
        try:
            if name == "close":
                result, elapsed = _observe_close(control, action, ceiling)
            else:
                result, elapsed = _observed_ms(action, ceiling)
        except BaseException:
            self._failed = True
            raise
        bucket.append(elapsed)
        if name == "check":
            self._poll_deadlines[child] = monotonic_ns() + POOL_POLL_INTERVAL_MS * 1_000_000
            self._selected_child = None
        return result

    def _require_next_callback(self, child: str, name: str) -> None:
        previous = {operation for operation, samples in self._samples.items() if child in samples}
        order = _CALLBACK_ORDER
        if name == "check":
            _require(set(order[:3]) <= previous and "close" not in previous, "calibration-callback-order-refused")
            if "interrupt" not in previous:
                _require(self._selected_child == child, "calibration-check-without-original-scheduler-selection")
            return
        _require(previous == set(order[:order.index(name)]), "calibration-callback-order-refused")

    def observe_scheduler(self):
        """Select a real armed worker with the production EDF algorithm and clock."""
        self._verify()
        now = monotonic_ns()
        controls = self._controls
        _require(self._selected_child is None and len(self._scheduler_samples) < _MAX_SAMPLES
                 and all(type(control.worker._start_ns) is int and 0 < control.worker._start_ns <= now
                         for control in controls.values()),
                 "active-original-scheduler-cohort-required")
        candidates = [self._scheduler_candidate(child, control) for child, control in controls.items()]
        try:
            selected, elapsed = _observed_ms(lambda: select_earliest_deadline(candidates, cursor=self._cursor),
                                              CERTIFIED_SCHEDULER_OVERHEAD_MS)
            _require(selected is not None, "original-scheduler-selection-required")
        except BaseException:
            self._failed = True
            raise
        self._scheduler_samples.append(elapsed)
        self._cursor = selected.next_cursor
        self._selected_child = selected.child_id
        return selected

    def _scheduler_candidate(self, child: str, control: object) -> dict[str, Any]:
        deadline = None
        if control.worker.wire.terminal is None:
            deadline = self._poll_deadlines.get(child, control.worker._start_ns + POOL_POLL_INTERVAL_MS * 1_000_000)
        return {"child_id": child, "next_deadline_ns": deadline}

    def finalize(self) -> ConnectedPoolCallbackCapability:
        """Issue the existing receipt shape after genuine contained observations settle."""
        self._verify()
        _require(self._selected_child is None and self._scheduler_samples
                 and all(by_child.keys() == self._controls.keys() for by_child in self._samples.values()),
                 "complete-original-callback-coverage-required")
        _require(_charged_start(self._parent, self._opportunity) == self._custody, "calibration-final-custody-changed")
        _, _, host_type, _, _ = _protected_types()
        for child, control in self._controls.items():
            _require(self._parent.controls.get(child) is control and self._owners[child] == _contained_owner(control, host_type),
                     "calibration-control-custody-changed")
            _terminal_evidence(control)
        self._finished = True
        receipt = self._receipt()
        return ConnectedPoolCallbackCapability(_TOKEN, self._opportunity, self._custody, receipt)

    def _receipt(self) -> dict[str, Any]:
        from cwo_core.native_pool_deferred_context import QUALIFICATION_ADAPTER_VERSION, QUALIFICATION_SURFACE

        measured = _now()
        expiry = min(measured + timedelta(minutes=55), datetime.fromtimestamp(self._opportunity.expires_at, timezone.utc))
        samples = {key: [sample for child in rows.values() for sample in child] for key, rows in self._samples.items()}
        certification = callback_certification_policy()
        receipt = seal_artifact({
            "receipt_type": CAPABILITY_RECEIPT_TYPE, "version": 1, "schema": CAPABILITY_RECEIPT_SCHEMA,
            "adapter_id": "native-multi-agent-v1", "adapter_version": QUALIFICATION_ADAPTER_VERSION,
            "execution_surface": QUALIFICATION_SURFACE, "host_identity": dict(self._opportunity.controller),
            "control_turn_id": self._parent.authority["render_request"]["control_turn_id"],
            "measured_at": measured.isoformat(), "expires_at": expiry.isoformat(),
            "sample_count": min(map(len, samples.values())), "requested_cap": len(self._controls),
            "clock": "monotonic_ns", "callbacks": {name: stats(values) for name, values in samples.items()},
            "scheduler_overhead": stats(self._scheduler_samples),
            "certification": {**certification, "policy_sha256": callback_certification_policy_sha256(certification),
                              "adapter_implementation_sha256": _source_digest()},
            "capabilities": {"interrupt": True, "close": True, "wait": True, "trusted_telemetry": True},
            "attestation_source": "trusted-control-plane-session-metadata", "validation_outcome": "accepted",
        }, "receipt_sha256")
        _require(not validate_capability_receipt(receipt, now=measured), "measured-callback-receipt-invalid")
        return receipt


class ConnectedPoolCallbackCapability:
    """An in-process handle. A receipt projection grants no calibration authority."""

    __slots__ = ("__weakref__",)

    def __init__(self, token, opportunity, custody, receipt):
        _require(token is _TOKEN, "connected-capability-construction-refused")
        with _ISSUED_LOCK:
            _ISSUED[self] = opportunity, custody, deepcopy(receipt)

    def __reduce__(self):
        raise CallbackCalibrationError("connected-capability-cannot-be-copied")


def require_connected_callback_capability(value: object, parent: object, opportunity_sha256: str | None) -> dict[str, Any]:
    """Verify the attached observation for a later original, explicitly bound run."""
    _require(type(value) is ConnectedPoolCallbackCapability, "original-connected-capability-required")
    with _ISSUED_LOCK:
        issued = _ISSUED.get(value)
    _require(issued is not None, "original-connected-capability-required")
    opportunity, (ledger, reservation), receipt = issued
    _require(opportunity.operation_sha256 == opportunity_sha256 and callback_adapter_scope_sha256(parent) == opportunity.scope_sha256
             and parent.authority.get("capability_opportunity_sha256") == opportunity_sha256
             and tuple(sorted(capture_owner_identity().items())) == opportunity.controller,
             "connected-capability-scope-or-owner-drift")
    parent._verify_artifacts()
    charged = ledger.attempt(reservation)
    _require(charged["state"] == "terminal" and charged["outcome"] == "completed" and charged["charge"] == {"starts": 1},
             "calibration-campaign-start-unsettled")
    _require_campaign_cap(ledger, charged["budget_id"])
    _require(not validate_capability_receipt(receipt, now=_now())
             and receipt["certification"]["adapter_implementation_sha256"] == _source_digest(),
             "connected-capability-receipt-stale-or-changed")
    return deepcopy(receipt)
