"""Temporary hosted CI aggregate failure control."""
import unittest


class HostedShardFailureProbeTests(unittest.TestCase):
    def test_intentional_hosted_shard_failure(self):
        self.fail('Intentional hosted shard failure control')
