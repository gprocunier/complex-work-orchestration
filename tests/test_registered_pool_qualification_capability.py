from contextlib import ExitStack
from copy import copy, deepcopy
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
from time import monotonic_ns
from types import ModuleType, SimpleNamespace
import unittest
from unittest import mock

from cwo_core import native_pool_qualification_stage as stage
from cwo_core.invocation_ledger import InvocationLedger, request_sha256
from cwo_core.native_authority import AuthorityProvenanceError
from cwo_core.native_pool_contracts import validate_capability_receipt
import registered_pool_qualification_capability as capability

_CAMPAIGN = "native-pool-contained-qualification"
_KEY = b"local inert calibration test signing key"


def _digest(text):
    return hashlib.sha256(text.encode()).hexdigest()


def _signed(manifest):
    value = {
        "directive_id": "inert-calibration", "version": 1, "actor_id": "test-operator",
        "identity_source": "fixture", "authorized_scope": "complete-task", "parent_receipt_sha256": None,
        "issued_at": datetime.now(timezone.utc).isoformat(), "nonce": "test",
        "action_sha256": capability.calibration_action_sha256(manifest),
    }
    value["signature"] = hmac.new(_KEY, json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(),
                                  hashlib.sha256).hexdigest()
    return value


class _Host:
    def __init__(self, slot):
        self.owner_identity_sha256 = _digest(f"owner-{slot}")
        self.slot = slot
        self.closed = False

    def receipt(self):
        rows = [{"stage": "appserver-contained", "observation": {
            "owner_identity_sha256": self.owner_identity_sha256, "scope": "worker-only-appserver",
            "worktree_readonly": True, "filesystem_ready": True, "network": "registered-provider-tunnel",
            "managed_login_projection": True,
        }}]
        if self.closed:
            rows.append({"stage": "appserver-terminated", "observation": {"child_exit_confirmed": True, "child_reaped": True}})
        return {"observations": rows, "config_sha256": _digest(f"config-{self.slot}"), "login_slot": self.slot,
                "cleanup_confirmed": self.closed, "failed": False}


class _Wire:
    def __init__(self, slot):
        self.connection_epoch_sha256 = _digest(f"epoch-{slot}")
        self.terminal = None
        self.interrupted = False

    def exchange(self, method):
        if not self.interrupted or method != "turn/interrupt":
            raise KeyError(method)
        return {}, {"request_sha256": _digest("interrupt"), "response_sha256": _digest("ack")}


class _Startup(SimpleNamespace):
    pass


class _Control:
    def __init__(self, slot):
        self._called = []
        host, wire = _Host(slot), _Wire(slot)
        child_id, thread_id = f"worker-{slot}", f"thread-{slot}"
        self.worker = SimpleNamespace(containment=host, wire=wire, child_id=child_id, thread_id=thread_id,
            _archived=None, _result=None, _start_ns=None,
            _startup=_Startup(child_id=child_id, session_id=thread_id,
                              model="gpt-6.2-sol", effort="xhigh", profile="cwo-pool-contained",
                              owner_identity_sha256=host.owner_identity_sha256, connection_epoch_sha256=wire.connection_epoch_sha256))

    def arm(self, **_binding):
        self._called.append("arm")

    def send_input(self, **_binding):
        self._called.append("send_input")
        self.worker._start_ns = monotonic_ns()
        return {"submission_id": "original-inert-turn"}

    def mark_dispatched(self, **_binding):
        self._called.append("mark_dispatched")

    def check(self, **_binding):
        self._called.append("check")
        return {"decision": "continue" if self.worker.wire.terminal is None else "complete"}

    def interrupt(self, **_binding):
        self._called.append("interrupt")
        self.worker.wire.interrupted = True
        self.worker.wire.terminal = "interrupted"
        self.worker._result = {"terminal": {"status": "interrupted"}}

    def finalize(self, **_binding):
        self._called.append("finalize")

    def close(self, **_binding):
        self._called.append("close")
        self.worker._archived = {"request_sha256": _digest("archive")}
        self.worker.containment.closed = True


class _Admission(SimpleNamespace):
    pass


class _Limits(SimpleNamespace):
    pass


class _Parent:
    def __init__(self, ledger, row, size):
        self.plan = {"plan_sha256": _digest(f"calibration-{size}"), "selected_model": "gpt-6.2-sol",
                     "runtime_adapter_sha256": _digest("adapter")}
        self.authority = {"mode": "callback-calibration", "host": {"executable_sha256": _digest("stock-executable")},
                          "render_request": {"control_turn_id": "original-pool-turn"}}
        self.limits = _Limits(_intent={"amount": {"runtime_seconds": 60}},
            _allowance=SimpleNamespace(accounting=SimpleNamespace(ledger=ledger), campaign_intent=row),
            _contained_admission=_Admission(_claimed=True, _plan=self.plan))
        self.controls = {f"worker-{slot}": _Control(slot) for slot in range(1, size + 1)}
        self.children = dict.fromkeys(self.controls)
        self.workers = {child: control.worker for child, control in self.controls.items()}

    def require_effect(self):
        pass

    def _verify_artifacts(self):
        pass


class _ProtectedParent:
    verification_key = _KEY
    actor_id = "test-operator"
    identity_source = "fixture"


def _fixture(size, root, stack):
    stack.enter_context(mock.patch.object(stage, "contained_campaign_ledger_root", return_value=root))
    context = ModuleType("cwo_core.native_pool_deferred_context")
    context.QUALIFICATION_ADAPTER_VERSION = "pool-contained-v1"
    context.QUALIFICATION_SURFACE = "connected-codex"
    context.QUALIFICATION_MODEL = "gpt-6.2-sol"
    context.QUALIFICATION_EFFORT = "xhigh"
    context.QUALIFICATION_TIER = "default"
    context.QUALIFICATION_PROFILE = "cwo-pool-contained"
    context.ProvisionalWorkerStartup = _Startup
    context._ContainedPoolAdmission = _Admission
    stack.enter_context(mock.patch.dict(sys.modules, {stage.__name__: stage, context.__name__: context}))
    stack.enter_context(mock.patch.object(capability, "_protected_types",
        return_value=(_Parent, _Control, _Host, _Limits, _ProtectedParent)))
    stack.enter_context(mock.patch.object(capability, "_source_digest", return_value=_digest("installed-sources")))
    stack.enter_context(mock.patch.object(capability, "_CLAIMS", set()))
    ledger = InvocationLedger(root)
    ledger.open_budget(_CAMPAIGN, {"starts": 20}, scope_sha256=stage.CAMPAIGN_SCOPE_SHA256)
    payload = b"original calibration start"
    expiry = int((datetime.now(timezone.utc) + timedelta(minutes=5)).timestamp())
    reserved = ledger.reserve(budget_id=_CAMPAIGN, request_id="measured-cohort", request_sha256=request_sha256(payload),
                               admission_sha256=_digest("original-admission"), amount={"starts": 1}, expires_at=expiry)
    reservation_id = reserved["reservation_id"]
    intent = ledger.begin_invocation(reservation_id, payload)
    parent = _Parent(ledger, intent, size)
    manifest = {"scope": "contained-pool-callback-calibration-v1", "calibration_plan_sha256": parent.plan["plan_sha256"],
                "adapter_scope_sha256": capability.callback_adapter_scope_sha256(parent), "expires_at": expiry,
                "runtime_seconds": 60}
    return parent, ledger, reservation_id, manifest


def _run_original_controls(calibration, parent):
    for control in parent.controls.values():
        for name in ("arm", "send_input", "mark_dispatched"):
            calibration.observe_callback(control, name)
    for _ in parent.controls:
        selected = calibration.observe_scheduler()
        calibration.observe_callback(parent.controls[selected.child_id], "check")
    for control in parent.controls.values():
        for name in ("interrupt", "finalize", "close"):
            calibration.observe_callback(control, name)


class ConnectedCallbackCapabilityTests(unittest.TestCase):
    def test_raw_receipt_and_observation_dicts_disclose_no_capability(self):
        for value in ({"callbacks": {"check": {"max_ms": 0}}}, object.__new__(capability.ConnectedPoolCallbackCapability)):
            with self.assertRaisesRegex(capability.CallbackCalibrationError, "original-connected-capability-required"):
                capability.require_connected_callback_capability(value, None, None)

    def test_benchmark_cannot_be_constructed_from_authored_samples(self):
        with self.assertRaisesRegex(capability.CallbackCalibrationError, "calibration-construction-refused"):
            capability.ConnectedCallbackCalibration(None, None, None, {})

    def test_measures_original_controls_and_scheduler_for_both_sizes(self):
        for size in (2, 3):
            with self.subTest(size=size), TemporaryDirectory() as temporary, ExitStack() as stack:
                parent, ledger, reservation_id, manifest = _fixture(size, Path(temporary), stack)
                opener = _ProtectedParent()
                directive = _signed(manifest)
                action = capability.verify_connected_callback_calibration_opportunity(parent, opener,
                    manifest=manifest, directive=directive)
                self.assertEqual(action, capability.calibration_action_sha256(manifest))
                calibration = capability.begin_connected_callback_calibration(parent, opener, manifest=manifest,
                                                                                directive=directive)
                _run_original_controls(calibration, parent)
                handle = calibration.finalize()
                with self.assertRaisesRegex(capability.CallbackCalibrationError, "calibration-already-claimed"):
                    capability.begin_connected_callback_calibration(parent, opener, manifest=manifest, directive=directive)
                productive = copy(parent)
                productive.plan = {**parent.plan, "plan_sha256": _digest("separate-productive-plan")}
                productive.authority = {**parent.authority, "mode": "qualification", "capability_opportunity_sha256": action}
                with self.assertRaisesRegex(capability.CallbackCalibrationError, "calibration-campaign-start-unsettled"):
                    capability.require_connected_callback_capability(handle, productive, action)
                ledger.finish(reservation_id, "completed", reason="inert original callbacks settled")
                receipt = capability.require_connected_callback_capability(handle, productive, action)
                self.assertEqual(validate_capability_receipt(receipt), [])
                self.assertEqual(receipt["sample_count"], size)
                self.assertEqual(receipt["requested_cap"], size)
                self.assertTrue(all(control._called == list(capability._CALLBACK_ORDER) for control in parent.controls.values()))
                self.assertEqual(ledger.summary(_CAMPAIGN)["charged"], {"starts": 1})
                with self.assertRaisesRegex(capability.CallbackCalibrationError, "cannot-be-copied"):
                    copy(handle)
                changed = copy(productive)
                changed.authority = deepcopy(productive.authority)
                changed.authority["host"]["executable_sha256"] = _digest("different-executable")
                with self.assertRaisesRegex(capability.CallbackCalibrationError, "scope-or-owner-drift"):
                    capability.require_connected_callback_capability(handle, changed, action)
                receipt["sample_count"] = 100
                self.assertEqual(capability.require_connected_callback_capability(handle, productive, action)["sample_count"], size)

    def test_unsigned_opportunity_and_missing_samples_fail_closed(self):
        with TemporaryDirectory() as temporary, ExitStack() as stack:
            parent, _, _, manifest = _fixture(2, Path(temporary), stack)
            directive = _signed(manifest)
            modified = {**manifest, "runtime_seconds": 61}
            with self.assertRaises(AuthorityProvenanceError):
                capability.begin_connected_callback_calibration(parent, _ProtectedParent(), manifest=modified, directive=directive)
            calibration = capability.begin_connected_callback_calibration(parent, _ProtectedParent(), manifest=manifest,
                                                                            directive=directive)
            with self.assertRaisesRegex(capability.CallbackCalibrationError, "complete-original-callback-coverage-required"):
                calibration.finalize()

    def test_rejects_a_replaced_control_and_requires_observed_cleanup(self):
        with TemporaryDirectory() as temporary, ExitStack() as stack:
            parent, _, _, manifest = _fixture(2, Path(temporary), stack)
            calibration = capability.begin_connected_callback_calibration(parent, _ProtectedParent(), manifest=manifest,
                                                                            directive=_signed(manifest))
            with self.assertRaisesRegex(capability.CallbackCalibrationError, "control-custody-changed"):
                calibration.observe_callback(_Control(1), "arm")
            _run_original_controls(calibration, parent)
            parent.workers["worker-1"].containment.closed = False
            with self.assertRaisesRegex(capability.CallbackCalibrationError, "archive-or-cleanup-missing"):
                calibration.finalize()

    def test_failed_or_absent_charge_cannot_start_measurement(self):
        with TemporaryDirectory() as temporary, ExitStack() as stack:
            parent, ledger, reservation_id, manifest = _fixture(2, Path(temporary), stack)
            ledger.finish(reservation_id, "failed", reason="inert charged calibration failed")
            with self.assertRaisesRegex(capability.CallbackCalibrationError, "campaign-start-not-charged"):
                capability.begin_connected_callback_calibration(parent, _ProtectedParent(), manifest=manifest,
                                                                 directive=_signed(manifest))
