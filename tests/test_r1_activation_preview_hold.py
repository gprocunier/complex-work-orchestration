"""The retired activation preview refuses before access to effectful inputs."""

from __future__ import annotations

from contextlib import ExitStack, redirect_stderr, redirect_stdout
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import run_native_pool_activation_preview as V  # noqa: E402
import run_native_pool_live_canaries as campaign  # noqa: E402

A = V.live_availability


class R1ActivationPreviewHoldTests(unittest.TestCase):
    def enable_former_switches(self):
        self.enterContext(mock.patch.object(V, "LIVE_ACTIVATION_AVAILABLE", True))
        self.enterContext(mock.patch.multiple(A, N1_LIVE_AVAILABLE=True, POOL_LIVE_AVAILABLE=True))

    def test_retired_preview_refuses_even_when_the_old_switches_are_on(self):
        self.enable_former_switches()
        with mock.patch.object(V, "AppServer", return_value=object()) as launch:
            with self.assertRaises(V.LiveActivationUnavailable):
                V._start_activation_server("n2-read-only")
            launch.assert_not_called()

    def test_standalone_calibration_is_absent_from_installed_sources(self):
        self.assertIsNone(importlib.util.find_spec("cwo_core.supervision.calibration"))
        self.assertFalse(hasattr(campaign, "calibration"))
        self.assertFalse(hasattr(campaign, "_run_calibration"))

    def test_r1_dedicated_w06_hold_ships_off(self):
        code = ("import sys; sys.path.insert(0, " + repr(str(ROOT / "scripts")) + "); "
                "import run_native_pool_activation_preview as v; print(v.LIVE_ACTIVATION_AVAILABLE)")
        result = subprocess.run([sys.executable, "-I", "-c", code], capture_output=True, text=True, check=True)
        self.assertEqual(result.stdout, "False\n")

    def test_r1_entry_holds_precede_reads_and_claims_with_all_on_fake_control(self):
        from cwo_core import native_activation_preview as preview

        self.enable_former_switches()
        control = Path("/EXAMPLE/control")
        with ExitStack() as stack:
            activation = ("ensure_private_directory", "load_activation_plan", "acquire_activation_claim")
            spies = [stack.enter_context(mock.patch.object(preview, name)) for name in activation]
            spies.extend(stack.enter_context(mock.patch.object(V, name)) for name in ("AppServer", "activation_dry_run"))
            with self.assertRaisesRegex(V.LiveActivationUnavailable, "database-identity hold"):
                V.run_live_activation(control / "plan", control / "approval", control_root=control,
                                      actor_id="EXAMPLE-operator", identity_source="EXAMPLE-session")
            for spy in spies:
                spy.assert_not_called()

    def test_cli_retains_the_exact_refusal_with_former_switches_on(self):
        self.enable_former_switches()
        expected = (
            "live activation is unavailable: the database-identity hold or its native N1/pool route is held in installed source. "
            "Nothing was claimed, started or written. "
            "keygen, prepare, approve and run --dry-run remain available."
        )
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = V.main(["run", "--control-root", "/EXAMPLE/control", "--prepared", "/EXAMPLE/plan",
                           "--approval", "/EXAMPLE/approval", "--operator-id", "EXAMPLE-operator",
                           "--identity-source", "EXAMPLE-session", "--enable-tech-preview"])
        self.assertEqual(code, 1)
        self.assertEqual(stdout.getvalue(), "")
        self.assertEqual(json.loads(stderr.getvalue()), {
            "status": "rejected",
            "failure_class": "LiveActivationUnavailable",
            "failure_message": expected,
            "failure_message_sha256": hashlib.sha256(expected.encode()).hexdigest(),
        })

    def test_r1_closure_rechecks_before_plan_or_beads_reads_with_all_on_fake_control(self):
        self.enable_former_switches()
        plan, reservation, receipt, adapter = (mock.MagicMock() for _ in range(4))
        with self.assertRaises(V.LiveActivationUnavailable):
            V._close_accepted_activation_beads(plan, reservation, receipt, adapter, pool_receipt_sha256="0" * 64)
        for value in (plan, reservation, receipt, adapter):
            self.assertEqual(value.mock_calls, [])

    def test_retired_transport_refuses_thread_start_before_intent_rpc_or_binding(self):
        self.enable_former_switches()
        ledger, server = mock.Mock(), mock.Mock()
        pending = {"worker": "EXAMPLE-pending"}
        transport = V.ActivationLedgerTransport(server, ledger, pending_allocation_intents=pending)
        with self.assertRaises(V.LiveActivationUnavailable):
            transport.start_thread(Path("/EXAMPLE/worker"), mutable=False, role="worker")
        self.assertEqual(ledger.mock_calls, [])
        self.assertEqual(server.mock_calls, [])
        self.assertEqual(transport.pending_allocation_intents, pending)
        self.assertEqual(transport.thread_roles, {})

    def test_retired_transport_refuses_turn_start_before_intent_or_rpc(self):
        self.enable_former_switches()
        ledger, server = mock.Mock(), mock.Mock()
        transport = V.ActivationLedgerTransport(server, ledger)
        transport.thread_roles["EXAMPLE-thread"] = "worker"
        with self.assertRaises(V.LiveActivationUnavailable):
            transport.start_turn("EXAMPLE-thread", "EXAMPLE prompt")
        self.assertEqual(ledger.mock_calls, [])
        self.assertEqual(server.mock_calls, [])
        self.assertEqual(transport.thread_roles, {"EXAMPLE-thread": "worker"})

    def test_retired_worker_contract_refuses_before_reads_rpc_or_artifact_effects(self):
        self.enable_former_switches()
        inputs = tuple(mock.MagicMock() for _ in range(4))
        with self.assertRaises(V.LiveActivationUnavailable):
            V._write_worker_contracts(*inputs)
        for value in inputs:
            self.assertEqual(value.mock_calls, [])


if __name__ == "__main__":
    unittest.main()
