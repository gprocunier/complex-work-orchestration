from contextlib import ExitStack
from copy import deepcopy
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest import mock

from cwo_core import native_live_availability as availability
from cwo_core import native_pool_qualification_stage as stage
from cwo_core import native_tool_isolation as tools
from cwo_core.native_pool_admission import NativePoolAdmissionError
from cwo_core.native_pool_admitted import run_admitted_native_pool
from cwo_core.native_pool_preflight import run_pool_preflight
from cwo_core.native_pool_qualification_fixtures import (
    contained_pool_qualification_prompt_preflight,
    fixed_pool_qualification_cohorts,
)

from tests.test_native_pool_contained_stage import _registered_fixture


class ContainedPoolPolicyTests(unittest.TestCase):
    def test_fixed_prompt_preparation_keeps_original_expansion_held(self):
        policy = tools.contained_pool_tool_policy()
        for cohort in fixed_pool_qualification_cohorts():
            for task in cohort["tasks"]:
                prompt = task["prompt"]
                with self.assertRaisesRegex(tools.NativeToolIsolationError, "unproven-permitted-tool-expansion"):
                    tools.prompt_preflight(prompt, policy)
                evidence = contained_pool_qualification_prompt_preflight(prompt)
                self.assertTrue(evidence["accepted"])
                self.assertEqual(evidence["tool_policy_sha256"], tools.canonical_sha256(policy))
                self.assertIsNone(tools._active_contained_tool_scope())
                with self.assertRaisesRegex(tools.NativeToolIsolationError, "unproven-permitted-tool-expansion"):
                    tools.prompt_preflight(prompt, policy)
                with self.assertRaisesRegex(tools.NativeToolIsolationError, "qualification-prompt-invalid"):
                    contained_pool_qualification_prompt_preflight(prompt + "\n")

    def test_rendered_contained_policy_grants_no_ordinary_validation_authority(self):
        policy = tools.contained_pool_tool_policy()
        surface = tools.contained_pool_tool_surface()
        self.assertEqual(policy["permitted_tools"], ["cwo_finite.finite_command"])
        self.assertFalse(surface["server_allowlist_supported"])
        self.assertIsNone(surface["effective_allowlist"])
        self.assertIsNone(surface["allowlist_parameter"])
        self.assertRegex(";".join(tools.validate_tool_policy(policy)), "unproven-permitted-tool-expansion")
        self.assertRegex(";".join(tools.validate_tool_surface_snapshot(surface, policy)), "unproven-permitted-tool-expansion")

    @mock.patch.object(availability, "N1_LIVE_AVAILABLE", True)
    @mock.patch.object(availability, "POOL_QUALIFICATION_AVAILABLE", True)
    def test_ordinary_preflight_and_dispatch_refuse_rendered_contained_artifacts(self):
        with TemporaryDirectory() as temporary, ExitStack() as stack:
            originals = []
            _registered_fixture(Path(temporary), stack, original_launches=originals)
            launch = originals[0]
            options = launch.keyword_arguments
            result = run_pool_preflight(launch.preflight_request, policy_document=options["policy_document"])
            self.assertTrue(launch.preflight_result["accepted"])
            self.assertFalse(result["accepted"])
            self.assertIn("tools.policy", [finding["rule_id"] for finding in result["findings"]])
            with self.assertRaisesRegex(NativePoolAdmissionError, "admitted-launch-contract-invalid"):
                run_admitted_native_pool(launch.reservation_receipt, launch.admission_capability, launch.contract,
                    launch.preflight_request, launch.preflight_result, launch.child_contracts, launch.task_inputs,
                    launch.child_callbacks, **options)
            with self.assertRaisesRegex(NativePoolAdmissionError, "contained-pool-dispatch-authority-required"):
                run_admitted_native_pool(launch.reservation_receipt, launch.admission_capability, launch.contract,
                    launch.preflight_request, launch.preflight_result, launch.child_contracts, launch.task_inputs,
                    launch.child_callbacks, _contained_admission={"scope": "contained"}, **options)
            self.assertFalse(options["lease_registry"].path.exists())

    @mock.patch.object(availability, "N1_LIVE_AVAILABLE", True)
    @mock.patch.object(availability, "POOL_QUALIFICATION_AVAILABLE", True)
    def test_scoped_preflight_rejects_wrong_model_registration_and_source(self):
        with TemporaryDirectory() as temporary, ExitStack() as stack:
            originals = []
            _, runs, _ = _registered_fixture(Path(temporary), stack, original_launches=originals)
            launch = originals[0]
            scope = tools._ContainedPoolToolScope(stage._contained_policy_children(runs[0]), "gpt-6.2-sol",
                                                 lambda: None, tools._CONTAINED_POOL_TOKEN)
            with tools._contained_pool_tool_validation(scope):
                policy = launch.keyword_arguments["policy_document"]
                self.assertEqual(run_pool_preflight(launch.preflight_request, policy_document=policy), launch.preflight_result)
                for field, value in (("requested_model", "wrong-model"),
                                     ("worktree_identity_sha256", "a" * 64),
                                     ("declared_write_paths", ["unowned.txt"])):
                    request = deepcopy(launch.preflight_request)
                    request["children"][0][field] = value
                    result = run_pool_preflight(request, policy_document=policy)
                    self.assertFalse(result["accepted"], field)
                tool_policy = tools.contained_pool_tool_policy()
                with self.assertRaisesRegex(tools.NativeToolIsolationError, "contained-pool-tool-surface-mismatch"):
                    tools.build_tool_surface_snapshot(tool_policy, source="caller-claimed", server_allowlist_supported=False,
                                                      allowlist_parameter=None, effective_allowlist=None)
                with self.assertRaisesRegex(tools.NativeToolIsolationError, "contained-pool-tool-surface-mismatch"):
                    tools.build_tool_surface_snapshot(tool_policy, source=tools.CONTAINED_POOL_SURFACE_SOURCE,
                        server_allowlist_supported=True, allowlist_parameter="tools", effective_allowlist=tool_policy["permitted_tools"])
                tool_policy["permitted_tools"] = ["cwo_finite.other"]
                self.assertRegex(";".join(tools.validate_tool_policy(tool_policy)), "unproven-permitted-tool-expansion")
