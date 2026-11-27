"""Signed serial pool profile checks at the retained validation boundary."""

import copy
import unittest

from tests import test_registered_native_pool_host as F


class PoolProfileTests(unittest.TestCase):
    cohort = F.PoolTests.cohort
    assert_source_retained = F.PoolTests.assert_source_retained

    def test_r2_unsupported_input_capability_refuses_at_actual_host_before_startup(self):
        """An authentic parent signature cannot invent registered input support."""
        self.cohort(2)
        member = self.fixtures[1]
        plan, operation, _ = copy.deepcopy(member.workflow.config.native_bundle)
        plan['registered_n1']['pre_effect']['input_capability'] = 'EXAMPLE_UNSUPPORTED_INPUT'
        directive = member.fixture.authority.reseal(plan, operation)
        member.workflow.config.native_bundle = [plan, operation, directive]
        with self.assertRaisesRegex(ValueError, 'unsupported input'):
            self.host.run(self.config.request('validate-only'))
        self.assertFalse(list(self.state.iterdir()))
        self.assertFalse(self.ledger.root.exists())
        for fixture in self.fixtures:
            self.assertFalse(fixture.case.ledger.root.exists())
            self.assertFalse(fixture.case.host.worker.joinpath('result.txt').exists())
            self.assertFalse(hasattr(fixture.fixture, 'spawned'))
            F.N.assert_no_native_births(self, fixture.fixture)
