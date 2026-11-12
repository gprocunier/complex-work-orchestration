"""Receipt compatibility using current code and inactive policy input."""

import os
import socket
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import prepare_native_worker as native
from tests import test_native_worker_planning as fixture
from tests.historical_policy_fixtures import historical_v2_policy
from tests.native_precommit_fixtures import (
    MODEL as HISTORICAL_MODEL,
    issue_accepting_precommit_receipt,
)
from tests.private_workspace_fixtures import copy_context_files


class TestReceiptReservationCompatibility(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="cwo-receipt-compatibility-")
        self.addCleanup(temp.cleanup)
        self.temporary = Path(temp.name)
        self.root = self.temporary / "artifacts"
        self.workspace = copy_context_files(
            fixture.ROOT, self.temporary / "workspace", fixture.PATHS
        )
        self.enterContext(mock.patch.dict(os.environ, {
            "CWO_TEMP_ROOT": str(self.root),
            "CWO_PRECOMMIT_REGISTRY_ROOT": str(self.root / "registry"),
        }))
        self.enterContext(mock.patch.object(
            socket, "socket",
            side_effect=AssertionError("receipt fixture must not open sockets"),
        ))
        self.enterContext(mock.patch.object(
            socket, "create_connection",
            side_effect=AssertionError("receipt fixture must not connect to services"),
        ))
        self.dispatch = self.enterContext(mock.patch.object(
            native, "require_native_operative_dispatch",
            side_effect=AssertionError("receipt fixture must not request operative dispatch"),
        ))

    def _artifacts(self):
        return {
            path.relative_to(self.temporary).as_posix(): path.read_bytes()
            for path in self.temporary.rglob("*") if path.is_file()
        }

    def test_historical_receipts_reach_reservation_but_cannot_authorize_current_build(self):
        current_policy = native.load_policy("native-worker-execution")
        self.assertEqual(current_policy["task_selected_routing"]["status"], "active")
        with historical_v2_policy() as historical:
            selected = historical["task_selected_routing"]
            self.assertEqual(selected["status"], "inactive-prospective")
            self.assertIs(selected["activation"]["active"], False)
            self.assertIs(selected["activation"]["dispatch_authority"], False)
            plan = fixture.plan()
            self.assertEqual(plan["requested_model"], HISTORICAL_MODEL)
            estimates = {
                key: plan["estimates"][key]
                for key in (
                    "tool_calls_p50", "tool_calls_p90",
                    "runtime_seconds_p50", "runtime_seconds_p90",
                )
            }
            cases = []
            for index in range(2):
                packet_id = f"w20-receipt-compatibility-{index}"
                receipt = issue_accepting_precommit_receipt(
                    work_plan=plan,
                    packet_id=packet_id,
                    artifact_root=self.root / str(index),
                    workdir=self.workspace,
                    estimates=estimates,
                    model=HISTORICAL_MODEL,
                )
                self.assertEqual(native.validate_precommit_receipt(
                    receipt, plan, operative_routing=None,
                    expected_packet_id=packet_id, live=True, require_accepting=True,
                ), [], "both controls must have genuinely valid receipts")
                cases.append(dict(
                    bead_id=plan["bead_id"],
                    lane="implementation",
                    workdir=str(self.workspace),
                    allowed_paths=fixture.PATHS,
                    acceptance_checks=fixture.CHECKS,
                    work_plan=plan,
                    precommit_receipt=receipt,
                    packet_id=packet_id,
                    budget_overrides=fixture.BUDGET,
                    requested_model=HISTORICAL_MODEL,
                ))
            self.assertNotEqual(
                cases[0]["precommit_receipt"]["receipt_sha256"],
                cases[1]["precommit_receipt"]["receipt_sha256"],
            )
            with (
                mock.patch.object(native, "reserve_precommit_receipt",
                                  wraps=native.reserve_precommit_receipt) as reserve,
                mock.patch.object(native, "_build_native_worker_packet_unreserved",
                                  wraps=native._build_native_worker_packet_unreserved) as body,
                mock.patch.object(native, "commit_precommit_receipt_reservation",
                                  wraps=native.commit_precommit_receipt_reservation) as commit,
                mock.patch.object(native, "release_precommit_receipt_reservation",
                                  wraps=native.release_precommit_receipt_reservation) as release,
            ):
                packet = native.build_native_worker_packet(**cases[0])
                reserve.assert_called_once_with(cases[0]["precommit_receipt"], mock.ANY)
                body.assert_called_once_with(**cases[0])
                commit.assert_called_once()
                release.assert_not_called()
                self.assertEqual(packet["packet_id"], cases[0]["packet_id"])
                self.assertEqual(packet["precommit_receipt"], cases[0]["precommit_receipt"])
                self.assertEqual(packet["stage"], "precommit-validated")
                self.assertIs(packet["operative_dispatch_authorized"], False)
                self.assertNotIn("release_evidence", packet)

        # Only the fixture policy ended. Receipt 1 was issued and validated,
        # but never reserved, built, committed or otherwise spent.
        self.assertEqual(native.load_policy("native-worker-execution"), current_policy)
        refusal = native.nonoperative_model_refusal(HISTORICAL_MODEL)
        self.assertIsInstance(refusal, str)
        self.assertIn("historical-nonoperative", refusal)
        before = self._artifacts()
        with (
            mock.patch.object(
                subprocess, "Popen",
                side_effect=AssertionError("current refusal must not start subprocesses"),
            ) as processes,
            mock.patch.object(native, "validate_precommit_receipt",
                              wraps=native.validate_precommit_receipt) as validate,
            mock.patch.object(native, "reserve_precommit_receipt",
                              wraps=native.reserve_precommit_receipt) as reserve,
            mock.patch.object(native, "_build_native_worker_packet_unreserved",
                              wraps=native._build_native_worker_packet_unreserved) as body,
        ):
            with self.assertRaises(SystemExit) as raised:
                native.build_native_worker_packet(**cases[1])
            self.assertEqual(str(raised.exception), refusal)
            validate.assert_not_called()
            reserve.assert_not_called()
            body.assert_not_called()
        self.assertEqual(self._artifacts(), before)
        self.dispatch.assert_not_called()
        processes.assert_not_called()


if __name__ == "__main__":
    unittest.main()
