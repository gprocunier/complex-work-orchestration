"""Canonical native policy shape checks and independent typed consumer contracts."""

from __future__ import annotations

import json
import sys
import unittest
from copy import deepcopy
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from cwo_core import (  # noqa: E402
    native_containment as containment,
    native_pool_capacity as capacity,
    native_pool_config as pool_config,
    native_release as release,
    operative_routing as operative,
    policy,
    policy_schema as ps,
    routing,
)
from tests.test_policy_schema import malformed_policy  # noqa: E402

FILENAME = "native-worker-execution.yaml"
SCHEMA_NAME = "native-worker-execution-policy.schema.json"


def _changed(document, path, value):
    changed = deepcopy(document)
    parent = changed
    for key in path[:-1]:
        parent = parent[key]
    parent[path[-1]] = value
    return changed


class NativePolicyRuntimeValidationTests(unittest.TestCase):
    def setUp(self):
        policy.clear_policy_cache()
        ps.clear_schema_cache()
        self.addCleanup(policy.clear_policy_cache)
        self.addCleanup(ps.clear_schema_cache)
        self.document = json.loads((ROOT / "policy" / FILENAME).read_text(encoding="utf-8"))

    def assert_schema_refusal(self, call, field):
        with self.assertRaises(ps.PolicySchemaError) as stopped:
            call()
        self.assertIs(type(stopped.exception), ps.PolicySchemaError)
        message = str(stopped.exception)
        self.assertIn(f"policy/{FILENAME} does not match schemas/{SCHEMA_NAME}", message)
        self.assertIn(field, message)
        self.assertNotIn("malformed policy: precommit_containment", message)
        return message

    def assert_current_policy(self):
        self.assertEqual(len(self.document), 43)
        self.assertEqual(policy.load_policy("native-worker-execution"), self.document)
        self.assertEqual(policy.load_policy(FILENAME), self.document)
        self.assertEqual(release._policy(), release._policy(self.document))
        self.assertTrue(release.validate_native_release_evidence({}))
        self.assertEqual(capacity.load_pool_capacity(), capacity.load_pool_capacity(self.document))
        self.assertEqual(capacity.operative_pool_policy(), self.document)
        self.assertEqual(pool_config._pool_policy(None), self.document["native_supervision_pool"])
        self.assertIs(containment.native_operative_containment()["evidence_required"], True)
        self.assertEqual(operative._policy_bundle()[0], self.document)
        error = containment.containment_error("native-dispatch")
        self.assertEqual(
            error,
            f"{containment.CONTAINMENT_ERROR}: native-dispatch is blocked by "
            f"{containment.CONTAINMENT_REASON} until {containment.CONTAINMENT_RELEASE}",
        )
        with self.assertRaises(SystemExit) as stopped:
            containment.require_native_operative_dispatch("native-dispatch")
        self.assertEqual(str(stopped.exception), error)
        self.assertIn("historical-nonoperative", operative.nonoperative_model_refusal(operative.SPARK_MODEL))

    def test_current_policy_and_canonical_alias_share_one_cache_entry(self):
        self.assert_current_policy()
        policy.clear_policy_cache()
        first = policy.load_policy("native-worker-execution")
        self.assertEqual(policy.load_policy(FILENAME), first)
        self.assertEqual(policy._load_policy_cached.cache_info().currsize, 1)
        first["version"] = True
        self.assertEqual(policy.load_policy(FILENAME), self.document)

    def test_shape_refusal_precedes_pure_metadata_consumers(self):
        cases = (
            (("version",), True),
            (("version",), 1.0),
            (("version",), "1"),
            (("precommit_containment", "active"), 1),
            (("native_release_evidence", "canary_source_mutation_authorized"), 0),
            (("precommit_supervision", "poll_interval_ms"), False),
            (("native_supervision_pool", "scheduler"), []),
            (("native_supervision_pool", "capacity", "hard_max_active_workers"), True),
            (("required_capabilities",), {}),
            (("required_capabilities",), [False]),
            (("packet_v3", "phases", "review", "mutation_deadline_seconds"), "30"),
            (("task_selected_routing", "activation", "active"), 1),
            (("task_selected_routing", "operative_roles"), {"new-model": False}),
            (("zz_unexpected",), True),
            (("precommit_containment", "zz_unexpected"), True),
        )
        readers = (
            lambda: policy.load_policy("native-worker-execution"),
            lambda: policy.load_policy(FILENAME),
            containment.native_operative_containment,
            release._policy,
            capacity.load_pool_capacity,
            capacity.operative_pool_policy,
            lambda: pool_config._pool_policy(None),
            lambda: operative.nonoperative_model_refusal(operative.SPARK_MODEL),
        )
        for path, value in cases:
            with self.subTest(path=path, value=value):
                self.assert_current_policy()
                with malformed_policy("native-worker-execution", raw=json.dumps(_changed(self.document, path, value))):
                    for reader in readers:
                        with self.subTest(reader=reader):
                            self.assert_schema_refusal(reader, "$." + ".".join(path))

    def test_schema_refusal_stops_evidence_and_downstream_routing(self):
        self.assert_current_policy()
        document = _changed(self.document, ("precommit_containment", "active"), 1)
        with malformed_policy("native-worker-execution", raw=json.dumps(document)):
            with mock.patch.object(containment, "validate_native_release_evidence") as evidence, \
                    mock.patch.object(routing, "load_policy") as downstream, \
                    mock.patch.object(routing, "resolve_operative_route") as resolver:
                evidence_stub = {"release_state": "operative-authorized"}
                error = containment.containment_error("native-dispatch", release_evidence=evidence_stub)
                self.assertTrue(error.startswith(f"{containment.CONTAINMENT_ERROR}: containment policy unavailable or invalid:"))
                self.assertIn(f"policy/{FILENAME}", error)
                self.assertIn("$.precommit_containment.active", error)
                with self.assertRaises(SystemExit) as stopped:
                    containment.require_native_operative_dispatch("native-dispatch", release_evidence=evidence_stub)
                self.assertEqual(str(stopped.exception), error)
                self.assert_schema_refusal(lambda: routing.classify_work("Fix the typo in README"), "$.precommit_containment.active")
            evidence.assert_not_called()
            downstream.assert_not_called()
            resolver.assert_not_called()


    def test_direct_mapping_guards_keep_value_errors(self):
        cases = (
            (containment.native_operative_containment, ("precommit_containment", "active"), 1, "malformed policy: precommit_containment.active"),
            (release._policy, ("native_release_evidence", "canary_source_mutation_authorized"), 0, "native_release_evidence.canary_source_mutation_authorized"),
            (operative._task_selected_policy, ("task_selected_routing", "activation", "active"), 1, "task selected routing activation is invalid"),
        )
        self.assert_current_policy()
        for reader, path, value, fragment in cases:
            document = _changed(self.document, path, value)
            with self.subTest(reader=reader, path=path):
                with self.assertRaises(ValueError) as stopped:
                    reader(document)
                self.assertIn(fragment, str(stopped.exception))
                with malformed_policy("native-worker-execution", raw=json.dumps(document)):
                    self.assert_schema_refusal(lambda: reader(policy.load_policy("native-worker-execution")), "$." + ".".join(path))


    def test_optional_empty_and_dynamic_shapes_do_not_gain_typed_clearance(self):
        self.assert_current_policy()
        document = {
            "version": 1,
            "packet_v3": {"phases": {"other-phase": {"mutation_deadline_seconds": None}}},
            "lane_budgets": {"other-lane": {}},
            "work_sizing": {"enforcement": {"other-variant": {"task_class_policy": {"other-class": {}}}}},
            "task_selected_routing": {"operative_roles": {"other-model": "metadata-only"}},
            "required_capabilities": [],
            "scope": "",
        }
        with malformed_policy("native-worker-execution", raw=json.dumps(document)):
            self.assertEqual(policy.load_policy("native-worker-execution"), document)
            with self.assertRaises(ValueError) as stopped:
                containment.native_operative_containment()
            self.assertIn("malformed policy: precommit_containment must be an object", str(stopped.exception))
            with self.assertRaises(ValueError) as stopped:
                release._policy()
            self.assertIn("native_release_evidence policy must be an object", str(stopped.exception))
            with self.assertRaises(capacity.NativePoolCapacityPolicyError) as stopped:
                capacity.load_pool_capacity()
            self.assertEqual(str(stopped.exception), "native-supervision-pool-policy-missing")

    def test_shape_valid_zero_capacity_keeps_typed_domain_refusal(self):
        self.assert_current_policy()
        path = ("native_supervision_pool", "capacity", "hard_max_active_workers")
        document = _changed(self.document, path, 0)
        with malformed_policy("native-worker-execution", raw=json.dumps(document)):
            self.assertEqual(policy.load_policy("native-worker-execution"), document)
            for source in (document, None):
                with self.subTest(explicit_mapping=source is not None):
                    with self.assertRaises(capacity.NativePoolCapacityPolicyError) as stopped:
                        capacity.load_pool_capacity(source)
                    self.assertEqual(str(stopped.exception), "native-supervision-pool-capacity-policy-invalid:hard_max_active_workers")


    def test_public_release_validator_preserves_schema_refusal_list(self):
        self.assert_current_policy()
        path = ("native_release_evidence", "canary_source_mutation_authorized")
        document = _changed(self.document, path, 0)
        with malformed_policy("native-worker-execution", raw=json.dumps(document)):
            message = self.assert_schema_refusal(release._policy, "$." + ".".join(path))
            self.assertEqual(release.validate_native_release_evidence({}), [message])


if __name__ == "__main__":
    unittest.main()
