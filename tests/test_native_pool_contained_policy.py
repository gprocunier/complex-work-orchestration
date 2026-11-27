import unittest

from cwo_core import native_tool_isolation as tools


class ContainedPoolPolicyTests(unittest.TestCase):
    def test_rendered_contained_policy_grants_no_ordinary_validation_authority(self):
        policy = tools.contained_pool_tool_policy()
        surface = tools.contained_pool_tool_surface()
        self.assertEqual(policy["permitted_tools"], ["cwo_finite.write_selected_fixture"])
        self.assertFalse(surface["server_allowlist_supported"])
        self.assertIsNone(surface["effective_allowlist"])
        self.assertIsNone(surface["allowlist_parameter"])
        self.assertRegex(";".join(tools.validate_tool_policy(policy)), "unproven-permitted-tool-expansion")
        self.assertRegex(";".join(tools.validate_tool_surface_snapshot(surface, policy)), "unproven-permitted-tool-expansion")
