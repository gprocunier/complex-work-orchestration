"""Exercise the signed calibration driver and original adapter on inert pipes."""

from contextlib import ExitStack
import json
from pathlib import Path
from threading import Event
from time import time
import unittest
from unittest import mock

from cwo_core import beads, native_live_availability as availability
from cwo_core import native_pool_qualification_stage as stage
from cwo_core import native_pool_transaction as transaction
from cwo_core.invocation_ledger import InvocationLedger
from cwo_core.maintenance_authority import sign_controller_directive
from cwo_core.native_pool_contracts import validate_capability_receipt
from cwo_core.native_pool_qualification_fixtures import fixed_pool_qualification_cohorts
from prepare_native_pool_qualification import _materialize_fixtures, _prepare
import registered_pool_containment as host
import registered_pool_qualification as adapter
import registered_pool_qualification_calibration as driver
import registered_pool_qualification_capability as capability
import run_native_pool_qualification as controller

from tests.test_native_pool_qualification_stage import _qualification_effect_events, _run_attempt
from tests.test_registered_pool_qualification import _InertContainment, _pool_test_directory
from tests.test_registered_pool_qualification_capability import _KEY, _digest, _signed
from tests.test_registered_pool_qualification_e2e import _FixtureBeads, _seal_run


class _CalibrationPeer(_InertContainment):
    def __init__(self, **settings):
        super().__init__(**settings)
        self.slot = int(self.worktree.name.rsplit("-", 1)[1])
        self.marker = "calibration has no accepted task marker"
        self.existing = self.slot == 2
        self.behavior = "calibration"
        self.closed = False

    def _observe(self, stage, *, readonly, network, login):
        super()._observe(stage, readonly=readonly, network=network, login=login)
        if stage == "appserver-contained":
            self.observations[-1]["observation"].update(scope="worker-only-appserver",
                                                         owner_identity_sha256=self.owner_identity_sha256)

    def close(self):
        result = super().close()
        if result["cleanup_confirmed"] and not self.closed:
            self.closed = True
            self.observations.append({"stage": "appserver-terminated",
                                      "observation": {"child_exit_confirmed": True, "child_reaped": True}})
        return result

    def receipt(self):
        return {**super().receipt(), "config_sha256": _digest(f"inert-config-{self.slot}"), "login_slot": self.slot,
                "cleanup_confirmed": self.closed, "failed": False}

    def run_writer(self, *args, **kwargs):
        raise AssertionError("calibration invoked a fixture writer")


class SignedCalibrationPipeTests(unittest.TestCase):
    def test_both_cohort_sizes_charge_once_and_archive_original_interrupts(self):
        for cohort in fixed_pool_qualification_cohorts():
            with self.subTest(size=cohort["size"]), _pool_test_directory() as temporary, ExitStack() as stack:
                self._run_calibration(Path(temporary), stack, cohort)

    def test_waits_for_durable_context(self):
        published = set()
        context_counts_at_interrupt = []
        capture = adapter._PoolWorker._capture_active_rollout
        observe = capability.ConnectedCallbackCalibration.observe_callback

        def capture_before_context(worker, **kwargs):
            boundary, rows = capture(worker, **kwargs)
            if worker.turn_id and worker.wire.terminal is None and worker.child_id not in published:
                self.assertFalse(any(row["type"] == "turn_context" for row in rows))
                record = {"type": "turn_context", "payload": {"turn_id": worker.turn_id,
                          "model": adapter.MODEL, "effort": adapter.EFFORT}}
                with worker._rollout.open("a", encoding="utf-8") as stream:
                    stream.write(json.dumps(record) + "\n")
                published.add(worker.child_id)
            return boundary, rows

        def capture_interrupt(calibration, control, name, **arguments):
            if name == "interrupt":
                context_counts_at_interrupt.append(len(published))
            return observe(calibration, control, name, **arguments)

        with _pool_test_directory() as temporary, ExitStack() as stack:
            stack.enter_context(mock.patch.object(adapter._PoolWorker, "_capture_active_rollout", capture_before_context))
            stack.enter_context(mock.patch.object(capability.ConnectedCallbackCalibration, "observe_callback", capture_interrupt))
            self._run_calibration(Path(temporary), stack, fixed_pool_qualification_cohorts()[0],
                                  peer_behavior="deferred-context")
        self.assertEqual(context_counts_at_interrupt, [2, 2])

    def test_waits_for_owned_empty_rollout(self):
        capture = adapter._PoolWorker._capture_active_rollout

        for fault, reason in ((None, None), ("replaced", "calibration-rollout-replaced"),
                              ("shared-write", "rollout-custody")):
            published = set()

            def capture_empty(worker, **kwargs):
                if fault == "shared-write" and worker.turn_id and worker.login_slot == 1:
                    worker._rollout.chmod(0o620)
                boundary, rows = capture(worker, **kwargs)
                if worker.turn_id is None or worker.child_id in published:
                    return boundary, rows
                records = []
                target = worker._rollout
                if worker.login_slot == 1:
                    self.assertEqual(rows, [])
                    self.assertEqual(boundary["byte_offset"], 0)
                    records.append({"type": "session_meta", "payload": {"id": worker.thread_id,
                                    "cwd": str(worker.worktree), "history_mode": "legacy"}})
                    if fault == "replaced":
                        target = target.with_suffix(".replacement")
                        target.touch(mode=0o600)
                records.append({"type": "turn_context", "payload": {"turn_id": worker.turn_id,
                                "model": adapter.MODEL, "effort": adapter.EFFORT}})
                with target.open("a", encoding="utf-8") as stream:
                    for record in records:
                        stream.write(json.dumps(record) + "\n")
                if target != worker._rollout:
                    target.replace(worker._rollout)
                published.add(worker.child_id)
                return boundary, rows

            with self.subTest(fault=fault), _pool_test_directory() as temporary, ExitStack() as stack:
                stack.enter_context(mock.patch.object(adapter._PoolWorker, "_capture_active_rollout", capture_empty))
                if reason is not None:
                    stack.enter_context(self.assertRaisesRegex(adapter.PoolQualificationAdapterError, reason))
                self._run_calibration(Path(temporary), stack, fixed_pool_qualification_cohorts()[0],
                                      peer_behavior="deferred-empty")

    def test_local_interrupt_revokes_an_original_pending_calibration_reply(self):
        waiting = Event()
        revoked = Event()
        finished = Event()
        commit_reply = adapter._WorkerWire._commit_callback_reply
        cancel_turn = adapter.RegisteredServerRequests.cancel_turn

        def delayed_reply(wire, *args, **kwargs):
            if wire.factory.login_slot != 1:
                return commit_reply(wire, *args, **kwargs)
            waiting.set()
            try:
                self.assertTrue(revoked.wait(3), "original interrupt did not revoke the held callback")
                return commit_reply(wire, *args, **kwargs)
            finally:
                finished.set()

        def cancel_after_ingress(registry, thread_id, turn_id):
            result = cancel_turn(registry, thread_id, turn_id)
            if registry.server.factory.login_slot == 1:
                self.assertTrue(waiting.wait(3), "inert peer did not send the original callback")
                revoked.set()
                self.assertTrue(finished.wait(3), "held callback did not settle after the interrupt")
            return result

        with _pool_test_directory() as temporary, ExitStack() as stack:
            stack.enter_context(mock.patch.object(adapter._WorkerWire, "_commit_callback_reply", delayed_reply))
            stack.enter_context(mock.patch.object(adapter.RegisteredServerRequests, "cancel_turn", cancel_after_ingress))
            self._run_calibration(Path(temporary), stack, fixed_pool_qualification_cohorts()[0])

    def test_local_interrupt_can_precede_an_already_sent_refusals_completion(self):
        self._run_with_delayed_completion(malformed=False)

    def test_malformed_refusal_completion_still_fails_after_local_interrupt(self):
        self._run_with_delayed_completion(malformed=True)

    def _run_with_delayed_completion(self, *, malformed):
        waiting = Event()
        revoked = Event()
        observed = Event()
        refusals = []
        observe_completion = adapter._WorkerWire._observe_completion
        cancel_turn = adapter.RegisteredServerRequests.cancel_turn
        observe_initial_polls = driver._observe_initial_polls

        def delayed_completion(wire, params, item):
            if wire.factory.login_slot != 1 or item.get("type") != "dynamicToolCall":
                return observe_completion(wire, params, item)
            waiting.set()
            self.assertTrue(revoked.wait(3), "original interrupt did not revoke the turn")
            try:
                if malformed:
                    item = {**item, "status": "completed"}
                observe_completion(wire, params, item)
                self.assertFalse(wire.factory.calibration_writer_refused())
            except adapter.PoolQualificationAdapterError as failure:
                refusals.append(str(failure))
                raise
            finally:
                observed.set()

        def join_before_interrupt(controls, observer):
            observe_initial_polls(controls, observer)
            # Let the peer read the original refusal before the measured
            # interrupt. Its completion is still held at the original reader.
            self.assertTrue(waiting.wait(3), "inert peer did not complete the original refusal")

        def cancel_before_completion(registry, thread_id, turn_id):
            if registry.server.factory.login_slot != 1:
                return cancel_turn(registry, thread_id, turn_id)
            self.assertTrue(waiting.is_set(), "original completion was not held before the interrupt")
            result = cancel_turn(registry, thread_id, turn_id)
            revoked.set()
            self.assertTrue(observed.wait(3), "the revoked completion was not observed")
            return result

        with _pool_test_directory() as temporary, ExitStack() as stack:
            stack.enter_context(mock.patch.object(adapter._WorkerWire, "_observe_completion", delayed_completion))
            stack.enter_context(mock.patch.object(adapter.RegisteredServerRequests, "cancel_turn", cancel_before_completion))
            stack.enter_context(mock.patch.object(driver, "_observe_initial_polls", join_before_interrupt))
            self._run_calibration(Path(temporary), stack, fixed_pool_qualification_cohorts()[0],
                                  expect_wire_failure=malformed)
        self.assertEqual(refusals, ["pool-qualification-adapter-revoked-calibration-completion-drift"] if malformed else [])

    def _run_calibration(self, root, stack, cohort, *, expect_wire_failure=False, peer_behavior="calibration"):
        peers = []

        class Peer(_CalibrationPeer):
            def __init__(self, **settings):
                super().__init__(**settings)
                self.behavior = peer_behavior
                peers.append(self)

        def require_inert_scope():
            self.assertIs(host.PoolWorkerContainment, Peer)
            self.assertIs(availability.POOL_QUALIFICATION_AVAILABLE, False)

        stack.enter_context(mock.patch.object(host, "PoolWorkerContainment", Peer))
        stack.enter_context(mock.patch.object(availability, "POOL_QUALIFICATION_AVAILABLE", False))
        for module in (availability, stage, transaction):
            stack.enter_context(mock.patch.object(module, "require_pool_qualification", require_inert_scope))
        bd = _FixtureBeads()
        stack.enter_context(mock.patch.object(beads, "require_bd", lambda: None))
        stack.enter_context(mock.patch.object(beads.subprocess, "run", bd.run))
        prep = _prepare(1, {"sessions": 3, "tool_calls": 60, "runtime_seconds": 60})
        _materialize_fixtures(root / "fixtures", prep)
        size = cohort["size"]
        fixture = root / "fixtures" / f"n{size}" / "run-1"
        run, admission, authority_path = _seal_run(root / "selected", cohort, fixture, bd,
            mode="callback-calibration", with_authority=True)
        ledger_root = root / "accounting"
        ledger_root.mkdir(mode=0o700)
        stack.enter_context(mock.patch.object(stage, "contained_campaign_ledger_root", return_value=ledger_root))
        ledger = InvocationLedger(ledger_root)
        ledger.open_budget(stage.CAMPAIGN_BUDGET_ID, {"starts": 20}, scope_sha256=stage.CAMPAIGN_SCOPE_SHA256)
        expires = int(time()) + 300
        original_parent = run.runtime.start_worker_session.__self__
        manifest = {"scope": "contained-pool-callback-calibration-v1", "calibration_plan_sha256": run.plan["plan_sha256"],
                    "adapter_scope_sha256": capability.callback_adapter_scope_sha256(original_parent),
                    "expires_at": expires, "runtime_seconds": 60}
        protected = controller.ProtectedPoolQualificationParent(request_path=authority_path, verification_key=_KEY,
            actor_id="test-operator", identity_source="fixture", admissions=(admission,),
            factory=driver.build_pool_qualification_runtime)
        request = {"plan": run.plan, "authority_path": authority_path, "admission": admission,
                   "manifest": manifest, "directive": _signed(manifest)}
        self.assertEqual(driver.verify_protected_callback_calibration_request(protected, **request),
                         capability.calibration_action_sha256(manifest))
        self.assertFalse(peers)
        self.assertEqual(ledger.summary(stage.CAMPAIGN_BUDGET_ID)["charged"], {"starts": 0})

        signed_stage = {"schema": controller.APPROVAL_SCOPE, "preparation": prep, "runs": [],
                        "stage_binding_sha256": _digest("inert stage binding"), "expires_at": expires,
                        "calibrations": [{**request, "admission": None, "authority_path": str(authority_path),
                                          "journal_path": str(run.journal_path), "fixture_root": str(run.fixture_root)}]}
        directive = sign_controller_directive(verification_key=_KEY, actor_id="test-operator", identity_source="fixture",
            action_sha256=controller.qualification_action_sha256(signed_stage), directive_id="inert containing campaign")
        _, approval = controller._approved_campaign({"manifest": signed_stage, "directive": directive}, protected)
        request["_campaign_approval"] = approval

        if expect_wire_failure:
            with self.assertRaisesRegex((adapter.PoolQualificationAdapterError, adapter.AppServerError),
                                        "worker-wire-no-longer-available|pool-qualification-original-wire-failed"):
                driver.run_protected_callback_calibration(protected, **request)
        else:
            handle = driver.run_protected_callback_calibration(protected, **request)
            self.assertIs(type(handle), capability.ConnectedPoolCallbackCapability)
            _, _, receipt = capability._ISSUED[handle]
            self.assertEqual(validate_capability_receipt(receipt), [])
            self.assertEqual(receipt["sample_count"], size)
        self.assertTrue(all(peer.closed and peer.process.poll() == 0 for peer in peers))
        self.assertEqual(len(peers), size)
        self.assertFalse(tuple(fixture.glob("*/result-*.txt")))
        self.assertEqual(ledger.summary(stage.CAMPAIGN_BUDGET_ID)["charged"], {"starts": 1})
        accounting = stage.PoolQualificationAccounting(ledger, expires)
        self.assertEqual(_run_attempt(run, accounting)["outcome"], "unknown" if expect_wire_failure else "completed")
        events = [row["event_type"] for row in _qualification_effect_events(run, accounting)]
        self.assertNotIn("qualification-tool-debit", events)
        self.assertNotIn("qualification-writer-release", events)
