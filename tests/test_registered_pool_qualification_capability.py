"""Check the original in-process authority boundary for contained callbacks."""

import unittest

import registered_pool_qualification_capability as capability


class ConnectedCallbackCapabilityTests(unittest.TestCase):
    def test_raw_receipt_and_observation_dicts_disclose_no_capability(self):
        for value in ({"callbacks": {"check": {"max_ms": 0}}}, object.__new__(capability.ConnectedPoolCallbackCapability)):
            with self.assertRaisesRegex(capability.CallbackCalibrationError, "original-connected-capability-required"):
                capability.require_connected_callback_capability(value, None, None)

    def test_benchmark_cannot_be_constructed_from_authored_samples(self):
        with self.assertRaisesRegex(capability.CallbackCalibrationError, "calibration-construction-refused"):
            capability.ConnectedCallbackCalibration(None, None, None, {})
