"""Executor metadata preparation; schema registration in this file is test-only."""

from __future__ import annotations

import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any, Iterator
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from cwo_core import policy, policy_schema as ps  # noqa: E402

FILENAME = "executor-registry.yaml"
SCHEMA_NAME = "executor-registry.schema.json"


def _nodes(value: Any, path: tuple[str | int, ...] = ()) -> Iterator[tuple[tuple[str | int, ...], Any]]:
    """Every current container and leaf, retaining its document path."""
    yield path, value
    if type(value) is dict:
        for key, child in value.items():
            yield from _nodes(child, path + (key,))
    elif type(value) is list:
        for index, child in enumerate(value):
            yield from _nodes(child, path + (index,))


def _replaced(document: Any, path: tuple[str | int, ...], value: Any) -> Any:
    if not path:
        return copy.deepcopy(value)
    result = copy.deepcopy(document)
    parent = result
    for key in path[:-1]:
        parent = parent[key]
    parent[path[-1]] = copy.deepcopy(value)
    return result


class ExecutorRegistrySchemaTests(unittest.TestCase):
    """Real validator calls with temporary registration, never a production claim."""

    def setUp(self) -> None:
        self.document = ps.strict_json_loads((ROOT / "policy" / FILENAME).read_text(encoding="utf-8"))
        ps.clear_schema_cache()
        policy.clear_policy_cache()
        self.addCleanup(ps.clear_schema_cache)
        self.addCleanup(policy.clear_policy_cache)
        # The production map is deliberately unchanged by this component.
        self.enterContext(mock.patch.object(
            ps, "POLICY_SCHEMAS", {**ps.POLICY_SCHEMAS, FILENAME: SCHEMA_NAME},
        ))
        self.schema = ps.load_policy_schema(SCHEMA_NAME)

    def validate(self, document: Any) -> None:
        ps.validate_policy_document(FILENAME, document)

    def assert_bad(self, path: tuple[str | int, ...], value: Any, fragment: str) -> None:
        # Each negative first proves the actual current document is accepted.
        self.validate(self.document)
        with self.assertRaises(ps.PolicySchemaError) as raised:
            self.validate(_replaced(self.document, path, value))
        message = str(raised.exception)
        self.assertIn(FILENAME, message)
        self.assertIn(SCHEMA_NAME, message)
        self.assertIn(fragment, message)

    def test_current_document_and_supported_schema(self) -> None:
        self.assertEqual(ps.schema_errors(self.schema), [])
        self.validate(self.document)
        self.assertEqual(policy.load_policy("executor-registry"), self.document)
        self.assertEqual(policy.load_policy(FILENAME), self.document)

    def test_document_header_and_required_fields(self) -> None:
        for value in (True, False, 2.0, "2", None, [], {}):
            with self.subTest(version=value):
                self.assert_bad(("version",), value, "version")
        self.assert_bad(("version",), 3, "must equal 2")
        self.assert_bad(("schema",), "yaml", "must equal")
        for field in ("version", "schema", "aliases", "executors"):
            self.validate(self.document)
            document = copy.deepcopy(self.document)
            del document[field]
            with self.subTest(missing=field), self.assertRaises(ps.PolicySchemaError) as raised:
                self.validate(document)
            self.assertIn(f"missing required field {field!r}", str(raised.exception))

    def test_every_current_node_has_a_structural_type(self) -> None:
        for path, value in _nodes(self.document):
            if type(value) is dict:
                replacement = []
            elif type(value) is list:
                replacement = {}
            elif type(value) is bool:
                replacement = "false"
            elif type(value) is int:
                replacement = True
            elif type(value) is str:
                replacement = 7
            else:
                self.fail(f"unaccounted current JSON type at {path!r}")
            with self.subTest(path=path):
                self.assert_bad(path, replacement, "expected")
            if type(value) is int:
                with self.subTest(path=path, replacement="integral float"):
                    self.assert_bad(path, float(value), "expected integer")

    def test_dynamic_map_values_are_typed(self) -> None:
        self.assert_bad(("aliases", "new-alias"), False, "new-alias")
        self.assert_bad(("executors", "new-executor"), [], "new-executor")

    def test_known_objects_are_closed(self) -> None:
        for path, value in _nodes(self.document):
            if type(value) is not dict:
                continue
            node = self.schema
            for step in path:
                if type(step) is int:
                    node = node["items"]
                else:
                    node = node.get("properties", {}).get(step, node.get("additionalProperties"))
            if node.get("additionalProperties") is not False:
                continue
            with self.subTest(path=path):
                self.assert_bad(path + ("zz_unexpected",), True, "zz_unexpected: unexpected field")

    def test_common_entry_fields_are_required(self) -> None:
        entry_schema = self.schema["properties"]["executors"]["additionalProperties"]
        key = next(iter(self.document["executors"]))
        for field in entry_schema["required"]:
            self.validate(self.document)
            document = copy.deepcopy(self.document)
            del document["executors"][key][field]
            with self.subTest(field=field), self.assertRaises(ps.PolicySchemaError) as raised:
                self.validate(document)
            self.assertIn(f"missing required field {field!r}", str(raised.exception))

    def test_flags_require_exact_booleans(self) -> None:
        for path, value in _nodes(self.document):
            if type(value) is bool:
                for replacement in ("false", 0, 1, None):
                    with self.subTest(path=path, replacement=replacement):
                        self.assert_bad(path, replacement, "expected boolean")

    def test_string_arrays_reject_scalars_and_nonstring_items(self) -> None:
        for path, value in _nodes(self.document):
            if type(value) is list:
                for replacement in ("architecture", [False], [7], [None], [""]):
                    with self.subTest(path=path, replacement=replacement):
                        self.assert_bad(path, replacement, str(path[-1]))

    def test_optional_fields_and_empty_arrays_remain_valid(self) -> None:
        entry_schema = self.schema["properties"]["executors"]["additionalProperties"]
        document = copy.deepcopy(self.document)
        required = set(entry_schema["required"])
        for entry in document["executors"].values():
            for field in set(entry) - required:
                del entry[field]
        self.validate(document)
        for path, value in _nodes(self.document):
            if type(value) is list:
                with self.subTest(array=path):
                    self.validate(_replaced(self.document, path, []))
                    if value:
                        self.validate(_replaced(self.document, path, value + [value[0]]))

    def test_dynamic_names_and_metadata_are_not_rosters_or_model_pins(self) -> None:
        entry = copy.deepcopy(next(iter(self.document["executors"].values())))
        entry.update(
            display_name="", role="additional-role", model_label="example-model",
            model_role="additional-model-role", allowed_task_classes=["additional-task"],
            capabilities=["additional-capability"], local_profile="example-local",
            model_profile="example-profile", allowed_risks=["critical"],
        )
        document = {
            "version": 2, "schema": "json-compatible-yaml",
            "aliases": {"additional-alias": "additional-executor"},
            "executors": {"additional-executor": entry},
        }
        self.validate(document)
        self.validate({**document, "aliases": {}, "executors": {}})

    def test_transport_variants_keep_optional_fields_and_empty_strings(self) -> None:
        for key, entry in self.document["executors"].items():
            if "transport" not in entry:
                continue
            path = ("executors", key, "transport")
            with self.subTest(executor=key):
                self.validate(_replaced(self.document, path, {"kind": entry["transport"]["kind"]}))
                self.validate(_replaced(self.document, path + ("api_key_env",), ""))

    def test_numeric_bounds_do_not_impose_upper_quotas(self) -> None:
        for path, value in _nodes(self.document):
            if type(value) is not int or path == ("version",):
                continue
            with self.subTest(path=path):
                self.assert_bad(path, -1, "must be at least")
                self.validate(_replaced(self.document, path, value + 100000))

    def test_current_alias_and_unknown_executor_behavior(self) -> None:
        self.validate(self.document)
        for alias in self.document["aliases"]:
            canonical = policy.resolve_executor_key(alias, self.document)
            self.assertIn(canonical, self.document["executors"])
            actual = policy.executor_config(alias, self.document)
            self.assertEqual(actual["key"], canonical)
            self.assertEqual(actual["requested_key"], alias)
        self.assertEqual(policy.resolve_executor_key("missing-executor", self.document), "missing-executor")
        with self.assertRaisesRegex(SystemExit, "unknown executor"):
            policy.executor_config("missing-executor", self.document)

    def test_future_registered_loader_refuses_before_metadata_consumers(self) -> None:
        # Exercise prospective canonical enforcement only under the test registration.
        with tempfile.TemporaryDirectory() as tmpdir:
            directory = Path(tmpdir)
            path = directory / FILENAME
            with mock.patch.object(policy, "POLICY_DIR", directory):
                path.write_text(json.dumps(self.document), encoding="utf-8")
                policy.clear_policy_cache()
                self.assertEqual(policy.load_policy("executor-registry"), self.document)
                for key, entry in self.document["executors"].items():
                    self.assertIs(policy.executor_external(key), entry["external"])
                    self.assertEqual(policy.executor_config(key)["display_name"], entry["display_name"])
                malformed = copy.deepcopy(self.document)
                key = next(iter(malformed["executors"]))
                malformed["executors"][key]["external"] = "false"
                path.write_text(json.dumps(malformed), encoding="utf-8")
                policy.clear_policy_cache()
                calls = (
                    lambda: policy.load_policy(FILENAME),
                    lambda: policy.executor_config(key),
                    lambda: policy.executor_external(key),
                )
                for index, call in enumerate(calls):
                    with self.subTest(consumer=index), self.assertRaises(ps.PolicySchemaError) as raised:
                        call()
                    self.assertIn("external: expected boolean", str(raised.exception))
                    self.assertEqual(policy._load_policy_cached.cache_info().currsize, 0)


if __name__ == "__main__":
    unittest.main()
