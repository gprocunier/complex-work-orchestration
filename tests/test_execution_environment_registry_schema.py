"""Unregistered schema preparation; mapping below exists only inside each test."""

from __future__ import annotations

import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from cwo_core import policy, policy_schema as ps  # noqa: E402
from cwo_core.harness import (  # noqa: E402
    execution_environment_registry,
    validate_execution_environment_registry,
)

NAME = "execution-environments"
FILENAME = f"{NAME}.yaml"
SCHEMA = "execution-environments.schema.json"
PROFILE = ("profiles", "connected-codex")
BINDING = PROFILE + ("role_bindings", "architect")
ROUTING = PROFILE + ("operative_routing",)
CONSTRAINTS = PROFILE + ("constraints",)
_DELETE = object()


class ExecutionEnvironmentRegistrySchemaTests(unittest.TestCase):
    def setUp(self) -> None:
        self.document = policy.load_json_compatible_yaml(ROOT / "policy" / FILENAME)
        policy.clear_policy_cache()
        ps.clear_schema_cache()
        self.addCleanup(policy.clear_policy_cache)
        self.addCleanup(ps.clear_schema_cache)
        registration = mock.patch.dict(ps.POLICY_SCHEMAS, {FILENAME: SCHEMA})
        registration.start()
        self.addCleanup(registration.stop)

    def assert_valid(self, document: Any) -> None:
        before = copy.deepcopy(document)
        self.assertIsNone(ps.validate_policy_document(FILENAME, document))
        self.assertEqual(document, before)

    def assert_rejected(self, path: tuple[str, ...], replacement: Any, fragment: str) -> None:
        self.assert_valid(self.document)
        candidate = copy.deepcopy(self.document)
        if not path:
            candidate = replacement
        else:
            parent = candidate
            for key in path[:-1]:
                parent = parent[key]
            if replacement is _DELETE:
                del parent[path[-1]]
            else:
                parent[path[-1]] = replacement
        with self.assertRaises(ps.PolicySchemaError) as raised:
            ps.validate_policy_document(FILENAME, candidate)
        message = str(raised.exception)
        self.assertIn(FILENAME, message)
        self.assertIn(SCHEMA, message)
        self.assertIn(fragment, message)

    def test_current_document_and_existing_repository_contract(self) -> None:
        self.assertEqual(ps.schema_errors(ps.load_policy_schema(SCHEMA)), [])
        self.assert_valid(self.document)
        for name in (NAME, FILENAME):
            with self.subTest(name=name):
                self.assertEqual(policy.load_policy(name), self.document)
        self.assertEqual(execution_environment_registry(), self.document)
        self.assertEqual(validate_execution_environment_registry(), [])

    def test_version_and_document_marker(self) -> None:
        for value in (True, False, 1.0, "1", 0, 2, None):
            with self.subTest(value=value):
                self.assert_rejected(("version",), value, "$.version")
        self.assert_rejected(("schema",), "yaml", "$.schema")
        self.assert_rejected(("schema",), True, "expected string")
        self.assert_rejected(PROFILE + ("mode",), "unknown", "must be one of")

    def test_required_structural_fields(self) -> None:
        paths = [(key,) for key in ("version", "schema", "profiles")]
        paths += [PROFILE + (key,) for key in (
            "display_name", "mode", "default_harness", "allowed_harnesses",
            "allowed_providers", "role_bindings", "constraints",
        )]
        paths += [CONSTRAINTS + (key,) for key in (
            "network", "external_contracting", "beads_required", "repo_write_requires", "secret_handling",
        )]
        paths.append(BINDING + ("harness",))
        for path in paths:
            with self.subTest(path=path):
                self.assert_rejected(path, _DELETE, f"missing required field {path[-1]!r}")

    def test_known_records_are_closed(self) -> None:
        for path in ((), PROFILE, BINDING, ROUTING, CONSTRAINTS):
            with self.subTest(path=path):
                self.assert_rejected(path + ("zz_unexpected",), False, "zz_unexpected: unexpected field")

    def test_malformed_containers(self) -> None:
        paths = [(), ("profiles",), PROFILE, PROFILE + ("role_bindings",), BINDING, ROUTING, CONSTRAINTS]
        for path in paths:
            for value in (None, [], True, "object", 1):
                with self.subTest(path=path, value=value):
                    self.assert_rejected(path, value, "expected object")

    def test_known_string_fields(self) -> None:
        paths = [PROFILE + (key,) for key in ("display_name", "mode", "default_harness", "notes")]
        paths += [CONSTRAINTS + (key,) for key in (
            "network", "external_contracting", "repo_write_requires", "secret_handling",
            "execution_lifecycle_owner", "concurrent_bead_execution",
        )]
        paths += [ROUTING + (key,) for key in ("primary_executor", "primary_model")]
        paths += [BINDING + (key,) for key in (
            "harness", "executor", "agent", "model", "variant", "model_profile", "access_profile",
        )]
        for path in paths:
            for value in (False, 7, [], {}):
                with self.subTest(path=path, value=value):
                    self.assert_rejected(path, value, "expected string")

    def test_allowlists_and_fallbacks_are_string_arrays(self) -> None:
        for path in (
            PROFILE + ("allowed_harnesses",), PROFILE + ("allowed_providers",),
            ROUTING + ("approved_fallback_executors",),
        ):
            for value in ("codex_cli", {}, True, None):
                with self.subTest(path=path, container=value):
                    self.assert_rejected(path, value, "expected array")
            for value in (7, False, None, {}, []):
                with self.subTest(path=path, item=value):
                    self.assert_rejected(path, [value], "expected string")

    def test_exact_booleans(self) -> None:
        for path in (CONSTRAINTS + ("beads_required",), ROUTING + ("live_evidence_required",)):
            for value in (0, 1, "false", None, [], {}):
                with self.subTest(path=path, value=value):
                    self.assert_rejected(path, value, "expected boolean")

    def test_optional_and_empty_shapes_remain_valid(self) -> None:
        document = copy.deepcopy(self.document)
        profile = document["profiles"]["connected-codex"]
        profile.pop("notes")
        profile.pop("operative_routing")
        profile["constraints"].pop("execution_lifecycle_owner")
        profile["constraints"].pop("concurrent_bead_execution")
        profile["allowed_harnesses"] = []
        profile["allowed_providers"] = []
        profile["role_bindings"] = {"new-role": {"harness": "new-harness"}}
        profile["mode"] = "manual"
        document["profiles"] = {"new-environment": profile}
        self.assert_valid(document)
        profile["role_bindings"] = {}
        self.assert_valid(document)
        profile["operative_routing"] = {}
        self.assert_valid(document)
        profile["operative_routing"] = {"approved_fallback_executors": [], "live_evidence_required": False}
        self.assert_valid(document)
        profile["constraints"]["beads_required"] = False
        profile["display_name"] = ""
        self.assert_valid(document)
        document["profiles"] = {}
        self.assert_valid(document)

    def test_optional_binding_selectors_can_be_missing_or_null(self) -> None:
        for key in ("executor", "agent", "model", "variant", "model_profile", "access_profile"):
            for missing in (False, True):
                with self.subTest(key=key, missing=missing):
                    document = copy.deepcopy(self.document)
                    binding = document["profiles"]["connected-codex"]["role_bindings"]["architect"]
                    if missing:
                        binding.pop(key, None)
                    else:
                        binding[key] = None
                    self.assert_valid(document)

    def test_historical_routing_metadata_fields_are_optional(self) -> None:
        for key in ("primary_executor", "primary_model", "approved_fallback_executors", "live_evidence_required"):
            document = copy.deepcopy(self.document)
            del document["profiles"]["connected-codex"]["operative_routing"][key]
            with self.subTest(key=key):
                self.assert_valid(document)

    def test_test_only_registration_at_canonical_loader(self) -> None:
        # This fixture demonstrates a future boundary, not production registration.
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / FILENAME
            path.write_text(json.dumps(self.document), encoding="utf-8")
            with mock.patch.object(policy, "POLICY_DIR", Path(tmpdir)):
                for read in (
                    lambda: policy.load_policy(NAME),
                    lambda: policy.load_policy(FILENAME),
                    execution_environment_registry,
                ):
                    policy.clear_policy_cache()
                    self.assertEqual(read(), self.document)
                malformed = copy.deepcopy(self.document)
                malformed["profiles"]["connected-codex"]["constraints"]["beads_required"] = "false"
                path.write_text(json.dumps(malformed), encoding="utf-8")
                for read in (
                    lambda: policy.load_policy(NAME),
                    lambda: policy.load_policy(FILENAME),
                    execution_environment_registry,
                ):
                    policy.clear_policy_cache()
                    with self.assertRaises(ps.PolicySchemaError) as raised:
                        read()
                    self.assertIn("constraints.beads_required", str(raised.exception))
                    self.assertEqual(policy._load_policy_cached.cache_info().currsize, 0)


if __name__ == "__main__":
    unittest.main()
