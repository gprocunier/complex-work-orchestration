"""The database-identity preview hold survives independent N1/pool restoration."""
from __future__ import annotations

from contextlib import ExitStack
from pathlib import Path
import subprocess
import sys
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import run_native_pool_activation_preview as V  # noqa: E402

A = V.live_availability


class FakeBoundaryReached(RuntimeError):
    """Intercept a local read; no claim, RPC or Beads effect is available."""


class R1ActivationPreviewHoldTests(unittest.TestCase):
    def test_r1_dedicated_w06_hold_ships_off(self):
        code = ("import sys; sys.path.insert(0, " + repr(str(ROOT / "scripts")) + "); "
                "import run_native_pool_activation_preview as v; print(v.LIVE_ACTIVATION_AVAILABLE)")
        result = subprocess.run([sys.executable, "-I", "-c", code], capture_output=True, text=True, check=True)
        self.assertEqual(result.stdout, "False\n")

    def test_r1_entry_holds_precede_reads_and_claims_with_all_on_fake_control(self):
        control = Path("/EXAMPLE/control")
        plan = {"profile": "n2-read-only", "control_root": str(control)}
        effects = ("acquire_activation_claim", "NativeActivationLedgerStore", "BeadsClaimAdapter",
                   "reserve_pool_cohort", "AppServer", "run_admitted_native_pool")
        with ExitStack() as stack:
            spies = [stack.enter_context(mock.patch.object(V, name, side_effect=AssertionError(name)))
                     for name in effects]
            directory = stack.enter_context(mock.patch.object(V, "ensure_private_directory", return_value=control))
            load = stack.enter_context(mock.patch.object(V, "load_activation_plan", return_value=plan))
            approval = stack.enter_context(mock.patch.object(V, "read_private_json", side_effect=FakeBoundaryReached))
            # The first two cases must refuse even before reading the profile.
            for preview, n1, pool, reads in ((False, True, True, 0), (True, False, True, 0),
                                              (True, True, False, 1)):
                with self.subTest(preview=preview, n1=n1, pool=pool), \
                     mock.patch.object(V, "LIVE_ACTIVATION_AVAILABLE", preview), \
                     mock.patch.multiple(A, N1_LIVE_AVAILABLE=n1, POOL_LIVE_AVAILABLE=pool), \
                     self.assertRaisesRegex(V.LiveActivationUnavailable, "database-identity hold"):
                    V.run_live_activation(control / "plan", control / "approval", control_root=control,
                                          actor_id="EXAMPLE-operator", identity_source="EXAMPLE-session")
                self.assertEqual((directory.call_count, load.call_count, approval.call_count), (reads, reads, 0))
                directory.reset_mock()
                load.reset_mock()
            with mock.patch.object(V, "LIVE_ACTIVATION_AVAILABLE", True), \
                 mock.patch.multiple(A, N1_LIVE_AVAILABLE=True, POOL_LIVE_AVAILABLE=True), \
                 self.assertRaises(FakeBoundaryReached):
                V.run_live_activation(control / "plan", control / "approval", control_root=control,
                                      actor_id="EXAMPLE-operator", identity_source="EXAMPLE-session")
            self.assertEqual((directory.call_count, load.call_count, approval.call_count), (1, 1, 1))
            for spy in spies:
                spy.assert_not_called()

    def test_r1_server_rechecks_dedicated_and_shared_holds_with_all_on_fake_control(self):
        with mock.patch.object(V, "AppServer", return_value=object()) as launch:
            for preview, n1, pool in ((False, True, True), (True, False, True), (True, True, False)):
                with self.subTest(preview=preview, n1=n1, pool=pool), \
                     mock.patch.object(V, "LIVE_ACTIVATION_AVAILABLE", preview), \
                     mock.patch.multiple(A, N1_LIVE_AVAILABLE=n1, POOL_LIVE_AVAILABLE=pool), \
                     self.assertRaises(V.LiveActivationUnavailable):
                    V._start_activation_server("n2-read-only")
            launch.assert_not_called()
            with mock.patch.object(V, "LIVE_ACTIVATION_AVAILABLE", True), \
                 mock.patch.multiple(A, N1_LIVE_AVAILABLE=True, POOL_LIVE_AVAILABLE=True):
                self.assertIs(V._start_activation_server("n2-read-only"), launch.return_value)
            launch.assert_called_once_with()

    def test_r1_closure_rechecks_before_plan_or_beads_reads_with_all_on_fake_control(self):
        def read_plan(key):
            if key == "profile":
                return "n2-read-only"
            raise FakeBoundaryReached(key)

        plan = mock.MagicMock()
        plan.__getitem__.side_effect = read_plan
        adapter = mock.Mock()
        for preview, n1, pool, reads in ((False, True, True, 0), (True, False, True, 0),
                                       (True, True, False, 1)):
            with self.subTest(preview=preview, n1=n1, pool=pool), \
                 mock.patch.object(V, "LIVE_ACTIVATION_AVAILABLE", preview), \
                 mock.patch.multiple(A, N1_LIVE_AVAILABLE=n1, POOL_LIVE_AVAILABLE=pool), \
                 self.assertRaises(V.LiveActivationUnavailable):
                V._close_accepted_activation_beads(plan, {}, {}, adapter, pool_receipt_sha256="0" * 64)
            self.assertEqual(plan.__getitem__.call_count, reads)
            plan.reset_mock()
        adapter.assert_not_called()
        self.assertEqual(adapter.mock_calls, [])
        with mock.patch.object(V, "LIVE_ACTIVATION_AVAILABLE", True), \
             mock.patch.multiple(A, N1_LIVE_AVAILABLE=True, POOL_LIVE_AVAILABLE=True), \
             self.assertRaisesRegex(FakeBoundaryReached, "tasks"):
            V._close_accepted_activation_beads(plan, {}, {}, adapter, pool_receipt_sha256="0" * 64)
        self.assertEqual(plan.__getitem__.call_args_list, [mock.call("profile"), mock.call("tasks")])
        self.assertEqual(adapter.mock_calls, [])

    def test_minor2_thread_rechecks_each_hold_before_intent_rpc_or_binding(self):
        ledger, server = mock.Mock(), mock.Mock()
        ledger.load.return_value = {"profile": "n2-read-only"}
        ledger.allocation_intent.return_value = "EXAMPLE-allocation"
        server.start_thread.return_value = ({"thread": {"id": "EXAMPLE-thread"}}, .1)
        transport = V.ActivationLedgerTransport(server, ledger, pending_allocation_intents={"worker": "EXAMPLE-pending"})
        for preview, n1, pool, reads in ((False, True, True, 0), (True, False, True, 0), (True, True, False, 1)):
            with self.subTest(preview=preview, n1=n1, pool=pool), \
                    mock.patch.object(V, "LIVE_ACTIVATION_AVAILABLE", preview), \
                    mock.patch.multiple(A, N1_LIVE_AVAILABLE=n1, POOL_LIVE_AVAILABLE=pool), \
                    self.assertRaises(V.LiveActivationUnavailable):
                transport.start_thread(Path('/EXAMPLE/worker'), mutable=False, role='worker')
            self.assertEqual(ledger.mock_calls, [mock.call.load()] * reads)
            self.assertEqual(server.mock_calls, [])
            self.assertEqual(transport.pending_allocation_intents, {"worker": "EXAMPLE-pending"})
            self.assertEqual(transport.thread_roles, {})
            ledger.reset_mock()
        transport.pending_allocation_intents.clear()
        order = mock.Mock()
        order.attach_mock(ledger, 'ledger')
        order.attach_mock(server, 'server')
        with mock.patch.object(V, "LIVE_ACTIVATION_AVAILABLE", True), \
                mock.patch.multiple(A, N1_LIVE_AVAILABLE=True, POOL_LIVE_AVAILABLE=True):
            self.assertEqual(transport.start_thread(Path('/EXAMPLE/worker'), mutable=False, role='worker'), server.start_thread.return_value)
        self.assertEqual(order.mock_calls, [mock.call.ledger.load(), mock.call.ledger.allocation_intent('worker'),
            mock.call.server.start_thread(Path('/EXAMPLE/worker'), mutable=False, role='worker', permitted_tools=None, allowlist_parameter=None),
            mock.call.ledger.bind_thread('EXAMPLE-allocation', 'worker', 'EXAMPLE-thread')])
        self.assertEqual(transport.thread_roles, {'EXAMPLE-thread': 'worker'})

    def test_minor2_admitted_thread_turn_rechecks_hold_flips_before_intent_or_rpc(self):
        ledger, server = mock.Mock(), mock.Mock()
        ledger.load.return_value = {"profile": "n2-read-only"}
        server.start_thread.return_value = ({"thread": {"id": "EXAMPLE-thread"}}, .1)
        ledger.turn_intent.return_value = 'EXAMPLE-intent'
        server.start_turn.return_value = ({'id': 'EXAMPLE-turn'}, .2)
        transport = V.ActivationLedgerTransport(server, ledger)
        with mock.patch.object(V, "LIVE_ACTIVATION_AVAILABLE", True), \
                mock.patch.multiple(A, N1_LIVE_AVAILABLE=True, POOL_LIVE_AVAILABLE=True):
            transport.start_thread(Path('/EXAMPLE/worker'), mutable=False, role='worker')
        ledger.reset_mock()
        server.reset_mock()
        for preview, n1, pool, reads in ((False, True, True, 0), (True, False, True, 0), (True, True, False, 1)):
            with self.subTest(preview=preview, n1=n1, pool=pool), \
                    mock.patch.object(V, "LIVE_ACTIVATION_AVAILABLE", preview), \
                    mock.patch.multiple(A, N1_LIVE_AVAILABLE=n1, POOL_LIVE_AVAILABLE=pool), \
                    self.assertRaises(V.LiveActivationUnavailable):
                transport.start_turn('EXAMPLE-thread', 'EXAMPLE prompt')
            self.assertEqual(ledger.mock_calls, [mock.call.load()] * reads)
            self.assertEqual(server.mock_calls, [])
            self.assertEqual(transport.thread_roles, {'EXAMPLE-thread': 'worker'})
            ledger.reset_mock()
        order = mock.Mock()
        order.attach_mock(ledger, 'ledger')
        order.attach_mock(server, 'server')
        with mock.patch.object(V, "LIVE_ACTIVATION_AVAILABLE", True), \
                mock.patch.multiple(A, N1_LIVE_AVAILABLE=True, POOL_LIVE_AVAILABLE=True):
            self.assertEqual(transport.start_turn('EXAMPLE-thread', 'EXAMPLE prompt'), server.start_turn.return_value)
        self.assertEqual(order.mock_calls, [mock.call.ledger.load(),
            mock.call.ledger.turn_intent('worker', 'EXAMPLE-thread', 'EXAMPLE prompt'),
            mock.call.server.start_turn('EXAMPLE-thread', 'EXAMPLE prompt', timeout=30, ambiguity_timeout=5),
            mock.call.ledger.bind_turn('worker', 'EXAMPLE-intent', 'EXAMPLE-turn')])
        # A single-worker profile still needs N1, but does not borrow the pool gate.
        ledger.load.return_value = {'profile': 'n1-read-only'}
        with mock.patch.object(V, "LIVE_ACTIVATION_AVAILABLE", True), \
                mock.patch.multiple(A, N1_LIVE_AVAILABLE=True, POOL_LIVE_AVAILABLE=False):
            transport.start_turn('EXAMPLE-thread', 'EXAMPLE prompt')

    def test_minor2_worker_contract_rechecks_before_reads_rpc_or_artifact_effects(self):
        transport, server = mock.Mock(), mock.Mock()
        def only_profile(key):
            if key == 'profile':
                return 'n2-read-only'
            raise FakeBoundaryReached(key)
        held_plan = mock.MagicMock()
        held_plan.__getitem__.side_effect = only_profile
        with ExitStack() as stack:
            capture = stack.enter_context(mock.patch.object(V, 'capture_server_tool_surface'))
            write = stack.enter_context(mock.patch.object(V, 'write_private_artifact'))
            contract = stack.enter_context(mock.patch.object(V, 'build_control_turn_contract', return_value={'EXAMPLE': 'contract'}))
            adapter = stack.enter_context(mock.patch.object(V, 'ActivationThreadAdapter', return_value=object()))
            stack.enter_context(mock.patch.object(V, 'require_unchanged_tool_surface'))
            stack.enter_context(mock.patch.object(V, 'fixed_activation_tool_trace', return_value={}))
            for preview, n1, pool, reads in ((False, True, True, 0), (True, False, True, 0), (True, True, False, 1)):
                with self.subTest(preview=preview, n1=n1, pool=pool), \
                        mock.patch.object(V, 'LIVE_ACTIVATION_AVAILABLE', preview), \
                        mock.patch.multiple(A, N1_LIVE_AVAILABLE=n1, POOL_LIVE_AVAILABLE=pool), \
                        self.assertRaises(V.LiveActivationUnavailable):
                    V._write_worker_contracts(held_plan, {}, transport, server)
                self.assertEqual(held_plan.__getitem__.call_args_list, [mock.call('profile')] * reads)
                held_plan.reset_mock()
                for effect in (capture, write, contract, adapter, transport, server):
                    self.assertEqual(effect.mock_calls, [])
            surface = {'server_allowlist_supported': False}
            capture.return_value = surface
            task = dict(bead_id='EXAMPLE-bead', child_id='EXAMPLE-child', packet_id='EXAMPLE-packet',
                packet_sha256='1' * 64, attempt_nonce='EXAMPLE-nonce', ordinal=1,
                prompt='EXAMPLE prompt', expected_token='EXAMPLE token', worktree='/EXAMPLE/worker',
                role='worker', isolation_class='read-only', tool_policy={}, tool_surface=surface,
                completion_evidence_policy={}, declared_write_paths=[], integration_target_paths=[],
                lease_id='EXAMPLE-lease', hard_budget={}, prompt_preflight={})
            fields = ('work_unit_id', 'candidate_sha256', 'work_estimate_sha256', 'worker_commitment_sha256',
                      'lease_scope_sha256', 'worktree_identity_sha256', 'requested_model', 'admitted_child_sha256')
            binding = {'bead_id': task['bead_id'], **dict.fromkeys(fields, 'EXAMPLE-binding')}
            reservation = {'claims': [{'bead_id': task['bead_id'], 'owned': True, 'claim_sha256': '2' * 64}], 'child_bindings': [binding]}
            plan = {'profile': 'n2-read-only', 'paths': {'records': '/EXAMPLE/records'}, 'activation_id': 'EXAMPLE-activation', 'tasks': [task]}
            transport.start_thread.return_value = ({'thread': {'id': 'EXAMPLE-thread'}}, .1)
            with mock.patch.object(V, 'LIVE_ACTIVATION_AVAILABLE', True), \
                    mock.patch.multiple(A, N1_LIVE_AVAILABLE=True, POOL_LIVE_AVAILABLE=True):
                children, contracts, adapters = V._write_worker_contracts(plan, reservation, transport, server)
            self.assertEqual(len(children), 1)
            self.assertEqual(children[0]['session_id'], 'EXAMPLE-thread')
            self.assertEqual(contracts, {'EXAMPLE-child': contract.return_value})
            self.assertEqual(adapters, {'EXAMPLE-child': adapter.return_value})
            self.assertEqual(write.call_count, 2)
            self.assertEqual(capture.call_count, 2)
            transport.start_thread.assert_called_once_with(Path('/EXAMPLE/worker'), mutable=False, role='worker')
