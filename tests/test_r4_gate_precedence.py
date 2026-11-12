"""Direct gate sites refuse before member work or campaign input reads."""
from __future__ import annotations

from pathlib import Path
import sys
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from cwo_core import native_live_availability as A  # noqa: E402
import registered_native_pool_host as P  # noqa: E402
import run_native_pool_live_canaries as C  # noqa: E402


class FakeReadReached(RuntimeError):
    """The first campaign input read, intercepted before any filesystem setup."""


class R4GatePrecedenceTests(unittest.TestCase):
    def test_r4_C13_pool_member_hold_precedes_workflow_run_with_positive_control(self):
        workflow = mock.Mock()
        with mock.patch.multiple(A, N1_LIVE_AVAILABLE=True, POOL_LIVE_AVAILABLE=False):
            for controlled in (False, True):
                with self.subTest(controlled=controlled), \
                     self.assertRaisesRegex(A.NativeLiveUnavailable, "native-pool-live-unavailable"):
                    P.RegisteredNativePoolHost._run_member(workflow, controlled=controlled)
        self.assertEqual(workflow.mock_calls, [])
        with mock.patch.multiple(A, N1_LIVE_AVAILABLE=True, POOL_LIVE_AVAILABLE=True):
            result = P.RegisteredNativePoolHost._run_member(workflow)
        self.assertEqual(result.status, "completed")
        workflow.run.assert_called_once_with(controlled_failure=False)

    def test_r4_C18_campaign_claim_hold_precedes_input_reads_and_setup_with_positive_control(self):
        inputs = mock.Mock()
        path = Path("/EXAMPLE/never-created")
        options = dict(launch_claim_sha256="0" * 64, output=path, authorization_state=path,
                       steering_registry=path, allocation_ledger=path, claim_root=path, registry_root=path)
        with mock.patch.object(type(inputs), "authorization", new_callable=mock.PropertyMock,
                               create=True, side_effect=FakeReadReached) as read, \
             mock.patch.object(C, "_private_control_directory", side_effect=AssertionError) as directory, \
             mock.patch.object(C, "_open_private_control_lock", side_effect=AssertionError) as lock, \
             mock.patch.object(C, "_write_exclusive_private_bytes", side_effect=AssertionError) as write:
            with mock.patch.multiple(A, N1_LIVE_AVAILABLE=True, POOL_LIVE_AVAILABLE=True,
                                     CAMPAIGN_LIVE_AVAILABLE=False), \
                 self.assertRaisesRegex(A.NativeLiveUnavailable, "native-campaign-live-unavailable"):
                C.acquire_global_campaign_claim(inputs, **options)
            read.assert_not_called()
            with mock.patch.multiple(A, N1_LIVE_AVAILABLE=True, POOL_LIVE_AVAILABLE=True,
                                     CAMPAIGN_LIVE_AVAILABLE=True), self.assertRaises(FakeReadReached):
                C.acquire_global_campaign_claim(inputs, **options)
            read.assert_called_once_with()
            directory.assert_not_called()
            lock.assert_not_called()
            write.assert_not_called()
