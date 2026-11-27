"""Campaign gate refuses before input reads or custody setup."""
from __future__ import annotations

from pathlib import Path
import sys
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from cwo_core import native_live_availability as A  # noqa: E402
import run_native_pool_live_canaries as C  # noqa: E402


class FakeReadReached(RuntimeError):
    """The first campaign input read, intercepted before any filesystem setup."""


class R4GatePrecedenceTests(unittest.TestCase):
    def test_r4_C18_campaign_claim_refuses_before_input_reads_and_setup(self):
        inputs = mock.Mock()
        path = Path("/EXAMPLE/never-created")
        options = dict(launch_claim_sha256="0" * 64, output=path, authorization_state=path,
                       steering_registry=path, allocation_ledger=path, claim_root=path, registry_root=path)
        with mock.patch.object(type(inputs), "authorization", new_callable=mock.PropertyMock,
                               create=True, side_effect=FakeReadReached) as read, \
             mock.patch.object(C, "_private_control_directory", side_effect=AssertionError) as directory, \
             mock.patch.object(C, "_open_private_control_lock", side_effect=AssertionError) as lock, \
             mock.patch.object(C, "write_private_artifact", side_effect=AssertionError) as write:
            with mock.patch.multiple(A, N1_LIVE_AVAILABLE=True, POOL_LIVE_AVAILABLE=True,
                                     CAMPAIGN_LIVE_AVAILABLE=False), \
                 self.assertRaisesRegex(A.NativeLiveUnavailable, "native-campaign-live-unavailable"):
                C.acquire_global_campaign_claim(inputs, **options)
            read.assert_not_called()
            with mock.patch.multiple(A, N1_LIVE_AVAILABLE=True, POOL_LIVE_AVAILABLE=True,
                                     CAMPAIGN_LIVE_AVAILABLE=True), \
                 self.assertRaisesRegex(C.LegacyNativePoolExecutionRetired, "^legacy-pool-execution-retired$"):
                C.acquire_global_campaign_claim(inputs, **options)
            read.assert_not_called()
            directory.assert_not_called()
            lock.assert_not_called()
            write.assert_not_called()
