"""Whole-document component; loader registration below is TEST ONLY."""

from __future__ import annotations

import copy
import json
import sys
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from cwo_core import harness, policy, policy_schema as ps  # noqa: E402

FILENAME = "model-profiles.yaml"
SCHEMA_NAME = "model-profiles.schema.json"


@contextmanager
def _test_only_registration():
    """TEST ONLY: exercise the proposed mapping without changing production registration."""
    with mock.patch.dict(ps.POLICY_SCHEMAS, {FILENAME: SCHEMA_NAME}):
        yield


@contextmanager
def _test_only_policy(document):
    """TEST ONLY: disposable canonical-loader input and temporary schema mapping."""
    with tempfile.TemporaryDirectory() as directory:
        policy_dir = Path(directory)
        (policy_dir / FILENAME).write_text(json.dumps(document), encoding="utf-8")
        policy.clear_policy_cache()
        try:
            with _test_only_registration(), mock.patch.object(policy, "POLICY_DIR", policy_dir):
                yield
        finally:
            policy.clear_policy_cache()


def _replace(document, path, value):
    result = copy.deepcopy(document)
    if not path:
        return copy.deepcopy(value)
    parent = result
    for step in path[:-1]:
        parent = parent[step]
    parent[path[-1]] = copy.deepcopy(value)
    return result


def _locations(value, schema, path=()):
    """Locate actual values, including heterogeneous optional profile metadata."""
    yield path, value, schema
    if type(value) is dict:
        properties = schema.get("properties", {})
        extra = schema["additionalProperties"]
        for key, item in value.items():
            child = properties.get(key, extra)
            if type(child) is dict:
                yield from _locations(item, child, path + (key,))
    elif type(value) is list:
        for index, item in enumerate(value):
            yield from _locations(item, schema["items"], path + (index,))


class ModelProfileRegistrySchemaTests(unittest.TestCase):
    def setUp(self):
        self.schema = ps.load_policy_schema(SCHEMA_NAME)
        self.document = json.loads((ROOT / "policy" / FILENAME).read_text(encoding="utf-8"))
        self.assertEqual(ps.schema_errors(self.schema), [])
        self.assertEqual(ps.validate_instance(self.document, self.schema), [])
        # Visit each schema node once, including fields present only on later profiles.
        seen = set()
        self.locations = []
        for location in _locations(self.document, self.schema):
            identity = id(location[2])
            if identity not in seen:
                seen.add(identity)
                self.locations.append(location)

    def assert_valid(self, document):
        with _test_only_registration():
            ps.validate_policy_document(FILENAME, document)

    def assert_rejected(self, document, *fragments):
        with _test_only_registration():
            # A real valid policy must pass the same boundary before every negative.
            ps.validate_policy_document(FILENAME, self.document)
            with self.assertRaises(ps.PolicySchemaError) as raised:
                ps.validate_policy_document(FILENAME, document)
        message = str(raised.exception)
        self.assertIn(f"policy/{FILENAME}", message)
        for fragment in fragments:
            self.assertIn(fragment, message)

    def test_real_document_and_schema_load_unchanged(self):
        self.assert_valid(self.document)
        before = (ROOT / "policy" / FILENAME).read_bytes()
        with _test_only_policy(self.document):
            self.assertEqual(policy.load_policy("model-profiles"), self.document)
            self.assertEqual(policy.load_policy(FILENAME), self.document)
            self.assertEqual(harness.model_profile_registry(), self.document)
            self.assertEqual(harness.model_profiles(), self.document["profiles"])
            key = next(key for key, value in self.document["profiles"].items() if "precision" not in value)
            self.assertEqual(harness.model_profile(key)["key"], key)
            projected = harness.sanitized_model_profile(key)
            self.assertIsNone(projected["precision"])
            self.assertEqual(projected["request_options"], {})
            self.assertEqual(projected["required_vllm_flags"], [])
        self.assertEqual((ROOT / "policy" / FILENAME).read_bytes(), before)

    def test_version_requires_integer_tokens_without_new_value_bounds(self):
        for value in (True, False, 1.0, 1.5, "1", None):
            with self.subTest(version=value):
                self.assert_rejected(_replace(self.document, ("version",), value), "version", "expected integer")
        for value in (-1, 0, 2):
            with self.subTest(integer_version=value):
                self.assert_valid(_replace(self.document, ("version",), value))

    def test_each_present_schema_node_has_strict_types(self):
        wrong = {"object": [], "array": {}, "string": 7, "integer": True, "boolean": 1}
        for path, value, node in self.locations:
            with self.subTest(path=path):
                self.assert_rejected(_replace(self.document, path, wrong[node["type"]]), "expected")
                self.assert_rejected(_replace(self.document, path, None), "found null")

    def test_closed_objects_and_required_fields(self):
        for path, value, node in self.locations:
            if node["type"] != "object":
                continue
            if node["additionalProperties"] is False:
                with self.subTest(path=path, mutation="extra"):
                    changed = copy.deepcopy(value)
                    changed["zz_unexpected"] = True
                    self.assert_rejected(_replace(self.document, path, changed), "zz_unexpected: unexpected field")
            for name in node.get("required", []):
                with self.subTest(path=path, missing=name):
                    changed = copy.deepcopy(value)
                    del changed[name]
                    self.assert_rejected(_replace(self.document, path, changed), f"missing required field {name!r}")

    def test_optional_fields_remain_optional(self):
        for path, value, node in self.locations:
            if node["type"] != "object":
                continue
            for name in set(value) - set(node.get("required", [])):
                with self.subTest(path=path, optional=name):
                    changed = copy.deepcopy(value)
                    del changed[name]
                    self.assert_valid(_replace(self.document, path, changed))

    def test_arrays_keep_existing_item_empty_and_duplicate_behavior(self):
        for path, value, node in self.locations:
            if node["type"] != "array":
                continue
            with self.subTest(path=path):
                self.assert_rejected(_replace(self.document, path, [7]), f"expected {node['items']['type']}")
                if node.get("minItems", 0):
                    self.assert_rejected(_replace(self.document, path, []), "at least 1 items")
                else:
                    self.assert_valid(_replace(self.document, path, []))
                self.assert_valid(_replace(self.document, path, [value[0], value[0]]))

    def test_existing_constants_and_enums(self):
        for path, value, node in self.locations:
            with self.subTest(path=path):
                if "const" in node:
                    self.assert_rejected(_replace(self.document, path, "zz_other"), "must equal")
                if "enum" in node:
                    self.assert_rejected(_replace(self.document, path, "zz_other"), "must be one of")

    def test_dynamic_maps_and_metadata_do_not_pin_current_values(self):
        profile = next(iter(self.document["profiles"].values()))
        changed = copy.deepcopy(self.document)
        changed["profiles"]["new-profile"] = copy.deepcopy(profile)
        self.assert_valid(changed)
        changed = copy.deepcopy(self.document)
        changed["browser_attestation_defaults"]["new-reviewer"] = {
            "model_label": "Other label", "reasoning_label": "Other reasoning",
        }
        self.assert_valid(changed)
        self.assert_valid(_replace(self.document, ("profiles",), {}))
        self.assert_valid(_replace(self.document, ("browser_attestation_defaults",), {}))
        self.assert_valid(_replace(self.document, ("browser_attestation_defaults",), {"new-reviewer": {}}))
        for path, value, node in self.locations:
            if node["type"] == "string" and "const" not in node and "enum" not in node:
                with self.subTest(path=path):
                    self.assert_valid(_replace(self.document, path, "different declared metadata"))
                    if not node.get("minLength", 0):
                        self.assert_valid(_replace(self.document, path, ""))
                    else:
                        self.assert_rejected(_replace(self.document, path, ""), "at least 1 characters")
            elif node["type"] == "object" and path and path[-1] in ("request_options", "chat_template_kwargs"):
                self.assert_valid(_replace(self.document, path, {}))

    def test_test_only_loader_registration_rejects_malformed_configuration(self):
        """Expected future integration behavior; this fixture is not production mapping."""
        profile_key = next(iter(self.document["profiles"]))
        variants = [
            (("version",), True),
            (("profiles",), []),
            (("profiles", profile_key, "limits"), [1]),
        ]
        options_key = next(key for key, value in self.document["profiles"].items() if "request_options" in value)
        variants.append((("profiles", options_key, "request_options"), {"zz_unexpected": True}))
        consumers = (
            lambda: policy.load_policy("model-profiles"),
            lambda: policy.load_policy(FILENAME),
            harness.model_profile_registry,
            harness.model_profiles,
            lambda: harness.model_profile(profile_key),
            lambda: harness.sanitized_model_profile(profile_key),
        )
        for path, value in variants:
            for consumer in consumers:
                with self.subTest(path=path, consumer=consumer):
                    with _test_only_policy(self.document):
                        self.assertTrue(consumer())
                    with _test_only_policy(_replace(self.document, path, value)):
                        with self.assertRaises(ps.PolicySchemaError) as raised:
                            consumer()
                        self.assertIn(f"policy/{FILENAME}", str(raised.exception))


if __name__ == "__main__":
    unittest.main()
