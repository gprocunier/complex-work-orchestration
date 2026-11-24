from contextlib import ExitStack
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest import mock

from cwo_core import native_live_availability as availability
from cwo_core import native_pool_qualification_stage as stage
from cwo_core.native_live_availability import NativeLiveUnavailable
from cwo_core.native_pool_transaction import NativePoolTransactionError, TransactionJournal
import registered_pool_qualification_calibration as calibration
import registered_pool_qualification_capability as capability

from tests.test_native_pool_contained_stage import _registered_fixture
from tests.test_native_pool_qualification_stage import _qualification_effect_events
from tests.test_registered_pool_qualification_capability import _ProtectedParent, _fixture, _signed


class CallbackCalibrationDriverTests(unittest.TestCase):
    def test_source_hold_precedes_requests_and_signed_stage_inputs(self):
        request = mock.MagicMock()
        with self.assertRaisesRegex(NativeLiveUnavailable, "native-pool-qualification-unavailable"):
            calibration.run_protected_callback_calibration(request, plan=request, authority_path=request,
                admission=request, manifest=request, directive=request)
        self.assertEqual(request.mock_calls, [])

    @mock.patch.object(availability, "REGISTERED_N1_LIVE_AVAILABLE", True)
    @mock.patch.object(availability, "POOL_QUALIFICATION_AVAILABLE", True)
    def test_signed_stage_charges_before_original_allocation_and_keeps_writer_held(self):
        with TemporaryDirectory() as temporary, ExitStack() as stack:
            launches = []
            _, (run, other), accounting = _registered_fixture(Path(temporary), stack, original_launches=launches)
            request = calibration._CalibrationRequest(object(),
                {"expires_at": accounting.expires_at, "runtime_seconds": 60}, {})
            marker = object()
            journal = TransactionJournal(run.journal_path, run.plan["transaction_id"])
            parent = SimpleNamespace(plan=run.plan, journal=journal, fixture_root=run.fixture_root)

            def bind_controls(plan, allocations, _context):
                self.assertEqual(plan, run.plan)
                self.assertEqual(accounting.ledger.summary(stage.CAMPAIGN_BUDGET_ID)["charged"], {"starts": 1})
                self.assertEqual(len(allocations), 2)
                self.assertTrue(all(row["outcome"] == "provisional" for row in allocations))
                parent.allocations = allocations
                parent.limits, = run.bind_limits.__self__
                self.assertTrue(parent.limits.calibration_only)

            def measure_controls(parent, _observer):
                for row in parent.allocations:
                    child_id, session = row["child_id"], row["session_id"]
                    turn = f"turn-{child_id}"

                    def original_send():
                        parent.limits.before_turn(child_id, session)
                        parent.limits.ack_turn(child_id, session, turn)
                        return {"submission_id": turn}

                    self.assertEqual(parent.limits._wrap_send(child_id, original_send)(), {"submission_id": turn})
                    writer = mock.Mock()
                    with self.assertRaisesRegex(NativePoolTransactionError, "calibration-writer-held"):
                        parent.limits.charge_tool(child_id, session, turn, 1)
                    with self.assertRaisesRegex(NativePoolTransactionError, "calibration-writer-held"):
                        parent.limits.authorize_writer(child_id, session, turn, 1, "a" * 64, writer)
                    writer.assert_not_called()
                return marker

            parent.bind_calibration_controls = bind_controls
            stack.enter_context(mock.patch.object(calibration, "_registered_parent", return_value=parent))
            stack.enter_context(mock.patch.object(calibration, "verify_connected_callback_calibration_opportunity",
                                                   return_value="b" * 64))
            stack.enter_context(mock.patch.object(calibration, "begin_connected_callback_calibration"))
            stack.enter_context(mock.patch.object(calibration, "_measure_original_controls", side_effect=measure_controls))

            handle = stage.run_contained_pool_callback_calibration(run, accounting=accounting,
                binder=calibration.bind_protected_callback_calibration, request=request)
            self.assertIs(handle, marker)
            self.assertEqual(journal.current_state, "CONTAINED")
            self.assertIn("qualification-calibration-observed", [row["event_type"] for row in journal.read()])
            events = _qualification_effect_events(run, accounting)
            self.assertNotIn("qualification-tool-debit", [row["event_type"] for row in events])
            self.assertFalse(tuple(run.fixture_root.glob("*/result-*.txt")))
            self.assertFalse(launches[0].keyword_arguments["lease_registry"].path.exists())
            self.assertFalse(other.journal_path.exists())
            summary = accounting.ledger.summary(stage.CAMPAIGN_BUDGET_ID)
            self.assertEqual(summary["charged"], {"starts": 1})
            self.assertEqual(summary["attempts_by_state"]["terminal"], 1)

    @mock.patch.object(availability, "REGISTERED_N1_LIVE_AVAILABLE", True)
    @mock.patch.object(availability, "POOL_QUALIFICATION_AVAILABLE", True)
    def test_unverified_operation_leaves_budget_and_journals_untouched(self):
        with TemporaryDirectory() as temporary, ExitStack() as stack:
            _, (run, _), accounting = _registered_fixture(Path(temporary), stack)
            request = calibration._CalibrationRequest(object(), {"expires_at": accounting.expires_at}, {})
            parent = SimpleNamespace(plan=run.plan, journal=TransactionJournal(run.journal_path, run.plan["transaction_id"]),
                                     fixture_root=run.fixture_root)
            stack.enter_context(mock.patch.object(calibration, "_registered_parent", return_value=parent))
            stack.enter_context(mock.patch.object(calibration, "verify_connected_callback_calibration_opportunity",
                                                   side_effect=capability.CallbackCalibrationError("bad calibration signature")))
            with self.assertRaisesRegex(capability.CallbackCalibrationError, "bad calibration signature"):
                stage.run_contained_pool_callback_calibration(run, accounting=accounting,
                    binder=calibration.bind_protected_callback_calibration, request=request)
            self.assertFalse(run.journal_path.exists())
            self.assertEqual(accounting.ledger.summary(stage.CAMPAIGN_BUDGET_ID)["charged"], {"starts": 0})

    def test_driver_times_original_control_order_and_waits_for_interrupt_before_archive(self):
        with TemporaryDirectory() as temporary, ExitStack() as stack:
            parent, _, _, manifest = _fixture(3, Path(temporary), stack)
            parent.limits.calibration_only = True
            bound = []

            def wrap_send(child, send):
                bound.append(child)
                return send

            parent.limits._wrap_send = wrap_send
            for child, control in parent.controls.items():
                control.contract = {"state_file": child, "control_turn_id": f"control-{child}"}
                control.worker.task = {"prompt": "inert fixed task"}
            observer = capability.begin_connected_callback_calibration(parent, _ProtectedParent(), manifest=manifest,
                                                                         directive=_signed(manifest))
            handle = calibration._measure_original_controls(parent, observer)
            self.assertIs(type(handle), capability.ConnectedPoolCallbackCapability)
            self.assertEqual(bound, list(parent.controls))
            for control in parent.controls.values():
                self.assertEqual(control._called, ["arm", "send_input", "mark_dispatched", "check", "interrupt",
                                                   "check", "finalize", "close"])
